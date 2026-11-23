package exclusionjournal

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

const (
	releaseFile     = ".release"
	releaseScratch  = ".release-scratch"
	releaseDetached = ".release-backing"
	releasePrefix   = 4 + 16 + 16 + 8 + 32
	releaseMax      = releasePrefix + bundleHeader + 6*9 + sha256.Size
)

type sourceReleasePhase uint8

const (
	releaseBackingPending sourceReleasePhase = iota
	releaseBackingGone
	releaseBackingDurable
	releaseMarkerClearing
	releaseMarkerGone
)

type sourceRelease struct {
	sourceIncarnation
	name, alias   string
	manifest      SourceManifestV1
	record        []byte
	markerFile    filelock.IdentityV1
	unlinkRefusal error
	phase         sourceReleasePhase
	reopened      bool
	pending       bool
}

// ReleaseUnpublishedSourceV1 holds the source charge through durable removal (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func (o *SourceOwnerV1) ReleaseUnpublishedSourceV1(account *mdbx.OperationAccount, p *PreparedSourceV1, neverReferenced bool) error {
	return o.operation(account, func() error {
		if err := o.releaseAdmission(p, neverReferenced); err != nil {
			return err
		}
		return o.withRoot(o.bindRoot, func(r *sourceRoot) error {
			d := o.release
			if d == nil {
				var err error
				d, err = o.admitRelease(r, p)
				if err != nil {
					return err
				}
			}
			return o.continueRelease(r, d, make([]byte, scratchBytes))
		})
	})
}

// releaseAdmission checks the handle before reporting a competing release.
func (o *SourceOwnerV1) releaseAdmission(p *PreparedSourceV1, proof bool) error {
	if !proof || !o.hasReleaseAuthority(p) {
		return ErrIntegrityV1
	}
	if p != nil && o.release != nil && o.release.name != p.name {
		return ErrBusyV1
	}
	return nil
}

// hasReleaseAuthority accepts a live issued handle or reopened release authority.
func (o *SourceOwnerV1) hasReleaseAuthority(p *PreparedSourceV1) bool {
	if p == nil {
		return o.release != nil && o.release.reopened
	}
	return p.incarnation != nil && p.incarnation.issued && o.live[p.name] == p.incarnation
}

// admitRelease checks the actual stage before qualifying the backing or writing intent.
func (o *SourceOwnerV1) admitRelease(r *sourceRoot, p *PreparedSourceV1) (*sourceRelease, error) {
	if err := requireReleaseVacancy(r, releaseDetached, ErrIntegrityV1); err != nil {
		return nil, err
	}
	d := &sourceRelease{name: p.name, sourceIncarnation: *p.incarnation, manifest: p.manifest}
	if o.debt.file == d.file {
		d.alias = o.debt.leaf
	} else if info, _ := o.stage.File.Stat(); sameSourceFile(info, d.file) {
		d.alias = o.stage.File.Name()
	}
	entries, err := o.sourceEntries(r)
	if err != nil {
		return nil, err
	}
	if err := o.initialReleaseStage(r, d, entries); err != nil {
		return nil, err
	}
	o.resolvePublications(r)
	used, err := o.censusFiles(r, entries, d.alias == "")
	if err := used.admissionError(err); err != nil {
		o.rememberPublicStage(r, used, false)
		return nil, err
	}
	o.retainIndependentReleaseStage(r, d, used)
	d.record = o.releaseRecord(d)
	return d, nil
}

// initialReleaseStage checks a same-key conflict before ordinary backing admission.
func (o *SourceOwnerV1) initialReleaseStage(r *sourceRoot, d *sourceRelease, entries []os.DirEntry) error {
	if err := d.checkReleaseStageConflict(r, entries); err != nil {
		return err
	}
	if stage, _, scanErr := o.censusStage(r, entries); scanErr == nil {
		if err := d.admitSampledAlias(stage); err != nil {
			return err
		}
		o.rebindReleaseAlias(r, d, stage)
		if stage.name == "" && d.alias == "" && cmp.Or(o.observedStage, o.debt.name) == d.name {
			_ = o.retireStageWitness(r)
			return ErrBusyV1
		}
	}
	return nil
}

// checkReleaseStageConflict refuses an independent same-key stage before checking the observed alias.
func (d *sourceRelease) checkReleaseStageConflict(r *sourceRoot, entries []os.DirEntry) error {
	for _, entry := range entries {
		leaf := entry.Name()
		if !samePublicStage(leaf, d.name) && leaf != heldStagePrefix+d.name {
			continue
		}
		if info, err := sourceEntryInfo(r, leaf, nil); err == nil && !sameSourceFile(info, d.file) {
			return ErrBusyV1
		}
	}
	return d.observePriorAlias(r)
}

func (o *SourceOwnerV1) releaseRecord(d *sourceRelease) []byte {
	root := filelock.FileIdentityV1(o.info)
	record := append(make([]byte, 0, releaseMax), 'S', 'R', 'V', 1)
	record, _ = binary.Append(record, binary.LittleEndian, [...]uint64{root[0], root[1], d.file[0], d.file[1], d.size})
	record = append(record, d.footer[:]...)
	record = append(record, d.manifest.header(o.id)...)
	digest := sha256.Sum256(record)
	return append(record, digest[:]...)
}

// readRelease binds bounded record bytes to the named inode.
func readRelease(r *sourceRoot, leaf string) ([]byte, filelock.IdentityV1, error) {
	f, err := openSourceFile(r, leaf, nil)
	if err != nil {
		return nil, filelock.IdentityV1{}, err
	}
	defer f.Close()
	return readReleaseFile(f)
}

// readReleaseFile reads one record and refuses an empty or overlong file.
func readReleaseFile(f *os.File) ([]byte, filelock.IdentityV1, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, filelock.IdentityV1{}, ErrIntegrityV1
	}
	record := make([]byte, releaseMax+1)
	n, err := f.ReadAt(record, 0)
	if n == 0 || !errors.Is(err, io.EOF) {
		return nil, filelock.IdentityV1{}, ErrIntegrityV1
	}
	return record[:n], filelock.FileIdentityV1(info), nil
}

func (o *SourceOwnerV1) decodeRelease(record []byte) (*sourceRelease, error) {
	if len(record) < releasePrefix+bundleHeader+sha256.Size || !bytes.Equal(record[:4], []byte{'S', 'R', 'V', 1}) {
		return nil, ErrIntegrityV1
	}
	end := len(record) - sha256.Size
	if sha256.Sum256(record[:end]) != [sha256.Size]byte(record[end:]) {
		return nil, ErrIntegrityV1
	}
	var identity [5]uint64
	_, _ = binary.Decode(record[4:], binary.LittleEndian, &identity)
	if filelock.FileIdentityV1(o.info) != (filelock.IdentityV1{identity[0], identity[1]}) {
		return nil, ErrIdentityV1
	}
	m, size, err := o.releaseManifest(record[releasePrefix:end])
	if err != nil {
		return nil, err
	}
	d := &sourceRelease{name: m.name(o.id), manifest: m, record: record, reopened: true}
	d.file = filelock.IdentityV1{identity[2], identity[3]}
	d.size = identity[4]
	copy(d.footer[:], record[44:releasePrefix])
	if size != d.size || d.file == (filelock.IdentityV1{}) {
		return nil, ErrIntegrityV1
	}
	return d, nil
}

func (o *SourceOwnerV1) releaseManifest(header []byte) (SourceManifestV1, uint64, error) {
	const identityOffset = bundleHeader - 66
	var m SourceManifestV1
	if !bytes.Equal(header[:4], []byte{'S', 'C', 'V', 1}) {
		return m, 0, ErrIntegrityV1
	}
	if !bytes.Equal(header[4:identityOffset], m.header(o.id)[4:identityOffset]) {
		return m, 0, ErrIdentityV1
	}
	copy(m.Identity[:], header[identityOffset:])
	copy(m.AcquiredDigest[:], header[identityOffset+32:])
	m.Class = CaptureClassV1(header[bundleHeader-2])
	count := int(header[bundleHeader-1])
	if len(header) != bundleHeader+9*count {
		return m, 0, ErrIntegrityV1
	}
	for offset := bundleHeader; offset < len(header); offset += 9 {
		m.Parts = append(m.Parts, SourcePartSpecV1{PartKindV1(header[offset]), binary.LittleEndian.Uint64(header[offset+1:])})
	}
	size, err := m.SizeV1()
	return m, size, err
}

// releaseLocation observes canonical first, then private, before admitting either.
func (d *sourceRelease) releaseLocation(r *sourceRoot) (string, error) {
	if d == nil {
		return "", requireReleaseVacancy(r, releaseDetached, ErrIntegrityV1)
	}
	canonical, err := d.observeBacking(r, d.name)
	if err != nil {
		return "", err
	}
	private, err := d.observeBacking(r, releaseDetached)
	if err != nil {
		return "", err
	}
	if canonical && private {
		return "", ErrIdentityV1
	}
	if canonical {
		return d.name, nil
	}
	if private {
		return releaseDetached, nil
	}
	return "", nil
}

// observeBacking checks shape, identity and extent in that order.
func (d *sourceRelease) observeBacking(r *sourceRoot, leaf string) (bool, error) {
	info, err := sourceEntryInfo(r, leaf, nil)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, ErrIntegrityV1
	case !sameSourceFile(info, d.file):
		return false, ErrIdentityV1
	case sourceFileSize(info) != d.size:
		return false, ErrIntegrityV1
	}
	return true, nil
}

// requireReleaseVacancy requires observed absence at the specified leaf.
func requireReleaseVacancy(r *sourceRoot, leaf string, refusal error) error {
	if _, err := r.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
		return refusal
	}
	return nil
}

// qualifyReleaseBacking matches the full original capture against its record.
func (o *SourceOwnerV1) qualifyReleaseBacking(f *os.File, d *sourceRelease, scratch []byte) error {
	_, err := o.qualify(f, d.manifest, d.size, scratch, &d.sourceIncarnation, ErrIntegrityV1)
	return err
}

// openRelease binds the actual marker inode and its bounded record.
func (o *SourceOwnerV1) openRelease(r *sourceRoot) error {
	record, marker, err := readRelease(r, releaseFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrIntegrityV1
	}
	d, err := o.decodeRelease(record)
	if err != nil {
		return err
	}
	d.markerFile, o.release = marker, d
	return nil
}

func (o *SourceOwnerV1) clearReleaseScratch(r *sourceRoot) error {
	info, err := sourceEntryInfo(r, releaseScratch, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Size() > releaseMax {
		return ErrIntegrityV1
	}
	if err := o.ops.remove(r.Root, releaseScratch); err != nil {
		return err
	}
	return o.ops.dirSync(r.pin)
}

// persistRelease installs an exact, synced record before authorizing backing work.
func (o *SourceOwnerV1) persistRelease(r *sourceRoot, d *sourceRelease, backing *os.File, scratch []byte) error {
	if leaf, err := d.releaseLocation(r); err != nil || leaf != d.name || backing == nil {
		return cmp.Or(err, ErrIdentityV1)
	}
	if err := o.qualifyReleaseBacking(backing, d, scratch); err != nil {
		return err
	}
	if err := o.clearReleaseScratch(r); err != nil {
		return err
	}
	if _, err := o.space(r, uint64(len(d.record)), sourceDebt{}); err != nil {
		return err
	}
	id, err := o.writeRelease(r, d.record)
	if err != nil {
		return err
	}
	return o.publishRelease(r, d, id)
}

// publishRelease removes scratch only after verifying the named marker.
func (o *SourceOwnerV1) publishRelease(r *sourceRoot, d *sourceRelease, id filelock.IdentityV1) error {
	pin, err := openSourceFile(r, releaseScratch, nil, id)
	if err != nil {
		return ErrIntegrityV1
	}
	defer pin.Close()
	record, _, err := readReleaseFile(pin)
	if err != nil || !bytes.Equal(record, d.record) {
		return ErrIntegrityV1
	}
	if err := o.linkReleaseRecord(r, d, id); err != nil {
		return err
	}
	if err := d.verifyPinnedMarker(r, pin); err != nil {
		return err
	}
	if present, err := d.checkReleaseScratch(r); err != nil || !present {
		return err
	}
	return o.ops.remove(r.Root, releaseScratch)
}

// linkReleaseRecord retains an indeterminate or positively visible publication.
func (o *SourceOwnerV1) linkReleaseRecord(r *sourceRoot, d *sourceRelease, id filelock.IdentityV1) error {
	linkErr := o.ops.namespace((*sourceRoot).Link, r, releaseScratch, releaseFile)
	visibility, err := observeLink(r, releaseFile, id, linkErr)
	if linkErr == nil && (any(err) == any(ErrIdentityV1) || any(err) == any(ErrIntegrityV1)) {
		return ErrIntegrityV1
	}
	if visibility != sourceNotVisible {
		d.markerFile, d.pending, o.release = id, visibility == sourceIndeterminate, d
	}
	return err
}

// writeRelease qualifies, syncs and closes the new scratch record.
func (o *SourceOwnerV1) writeRelease(r *sourceRoot, record []byte) (filelock.IdentityV1, error) {
	f, err := r.OpenFile(releaseScratch, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return filelock.IdentityV1{}, err
	}
	defer f.Close()
	w := sourceFileWriter{o: o, file: f}
	if _, err := w.Write(record); err != nil {
		return filelock.IdentityV1{}, err
	}
	actual, id, err := readReleaseFile(f)
	if err != nil || !bytes.Equal(actual, record) {
		return filelock.IdentityV1{}, ErrIntegrityV1
	}
	return id, cmp.Or(o.ops.chmod(f, 0o600), o.finishFile(f))
}

// continueRelease returns the charge after durable backing and marker removal.
func (o *SourceOwnerV1) continueRelease(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if d.phase < releaseBackingDurable {
		if err := o.syncReleasedBacking(r, d, scratch); err != nil {
			return err
		}
	}
	if err := o.clearReleaseMarker(r, d); err != nil {
		return err
	}
	if err := o.syncBoundRoot(r); err != nil {
		return err
	}
	if present, err := o.releaseBoundary(r, d); err != nil || present {
		return cmp.Or(err, ErrIntegrityV1)
	}
	delete(o.live, d.name)
	o.release = nil
	return nil
}

// clearReleaseMarker removes a matching release record only after the backing name is observed absent.
func (o *SourceOwnerV1) clearReleaseMarker(r *sourceRoot, d *sourceRelease) error {
	present, err := o.releaseBoundary(r, d)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if removed, err := o.removeReleaseScratch(r, d); err != nil {
		return err
	} else if removed {
		if present, err := o.releaseBoundary(r, d); err != nil || !present {
			return cmp.Or(err, ErrIntegrityV1)
		}
	}
	return o.unlinkReleaseMarker(r, d)
}

// unlinkReleaseMarker preserves the reached marker state on a removal error.
func (o *SourceOwnerV1) unlinkReleaseMarker(r *sourceRoot, d *sourceRelease) error {
	d.phase = releaseMarkerClearing
	err := o.ops.remove(r.Root, releaseFile)
	if err == nil {
		d.phase = releaseMarkerGone
		return nil
	}
	_, observeErr := r.Lstat(releaseFile)
	switch {
	case errors.Is(observeErr, os.ErrNotExist):
		d.phase = releaseMarkerGone
	case observeErr == nil:
		d.phase = releaseBackingDurable
	}
	return err
}

// checkMarker compares both the record bytes and inode identity.
func (d *sourceRelease) checkMarker(record []byte, id filelock.IdentityV1, err error) (bool, error) {
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || id != d.markerFile || !bytes.Equal(record, d.record) {
		return false, ErrIntegrityV1
	}
	return true, nil
}

// requireMarker confirms that the named marker is the expected record.
func (d *sourceRelease) requireMarker(r *sourceRoot) error {
	present, err := d.checkMarker(readRelease(r, releaseFile))
	if err != nil || !present {
		return ErrIntegrityV1
	}
	return nil
}

// checkReleaseScratch verifies the ownership of a scratch alias.
func (d *sourceRelease) checkReleaseScratch(r *sourceRoot) (bool, error) {
	info, err := sourceEntryInfo(r, releaseScratch, nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !sameSourceFile(info, d.markerFile) {
		return false, ErrIntegrityV1
	}
	return true, nil
}

// removeReleaseScratch verifies the named record before unlinking its alias.
func (o *SourceOwnerV1) removeReleaseScratch(r *sourceRoot, d *sourceRelease) (bool, error) {
	present, err := d.checkReleaseScratch(r)
	if err != nil || !present {
		return false, err
	}
	if err := d.requireMarker(r); err != nil {
		return false, err
	}
	return true, o.ops.remove(r.Root, releaseScratch)
}

// syncReleaseIntent holds the marker across directory sync and checks its name again.
func (o *SourceOwnerV1) syncReleaseIntent(r *sourceRoot, d *sourceRelease) error {
	marker, err := openSourceFile(r, releaseFile, nil, d.markerFile)
	if err != nil {
		return ErrIntegrityV1
	}
	defer marker.Close()
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	err = d.verifyPinnedMarker(r, marker)
	_ = marker.Close()
	return cmp.Or(o.currentRoot(), err)
}

// verifyPinnedMarker verifies the named inode against its held descriptor and record.
func (d *sourceRelease) verifyPinnedMarker(r *sourceRoot, marker *os.File) error {
	info, err := sourceEntryInfo(r, releaseFile, nil)
	if err != nil || !sameSourceFile(info, d.markerFile) {
		return ErrIntegrityV1
	}
	present, err := d.checkMarker(readReleaseFile(marker))
	if err != nil || !present {
		return ErrIntegrityV1
	}
	return nil
}

// releaseIntent publishes an absent unconfirmed record or verifies the existing one.
func (o *SourceOwnerV1) releaseIntent(r *sourceRoot, d *sourceRelease, backing *os.File, scratch []byte) error {
	unpublished := o.release == nil
	absentUnconfirmed := d.pending && requireReleaseVacancy(r, releaseFile, ErrIntegrityV1) == nil
	if absentUnconfirmed {
		if _, err := o.sampleReleaseStage(r, d); err != nil {
			return err
		}
	}
	if unpublished || absentUnconfirmed {
		if err := o.persistRelease(r, d, backing, scratch); err != nil {
			return err
		}
	}
	if err := o.syncReleaseIntent(r, d); err != nil {
		return err
	}
	d.pending = false
	return nil
}

// syncReleasedBacking records durability only after the backing has been consumed.
func (o *SourceOwnerV1) syncReleasedBacking(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	var backing *os.File
	if d.phase == releaseBackingPending && d.unlinkRefusal == nil {
		if !o.releaseDescriptorsFit() {
			return ErrCapacityV1
		}
		backing, _ = r.pinFile(d.name, d.file)
		defer backing.Close()
	}
	if err := o.releaseIntent(r, d, backing, scratch); err != nil {
		return err
	}
	if d.unlinkRefusal != nil {
		return d.unlinkRefusal
	}
	if err := o.consumeReleaseBacking(r, d, backing, scratch); err != nil {
		return err
	}
	if err := o.syncBoundRoot(r); err != nil {
		return err
	}
	d.phase = releaseBackingDurable
	o.discardReleaseAlias(d)
	return nil
}

// releaseDescriptorsFit allows two root descriptors, the backing and a transient descriptor.
func (o *SourceOwnerV1) releaseDescriptorsFit() bool {
	needed := uint64(4)
	if o.stage.File != nil {
		needed++
	}
	if o.stage.Quota != nil {
		needed++
	}
	return needed <= o.limits.Descriptors
}

// consumeReleaseBacking moves identified public backing before unlinking it.
func (o *SourceOwnerV1) consumeReleaseBacking(r *sourceRoot, d *sourceRelease, backing *os.File, scratch []byte) error {
	if d.phase == releaseBackingGone {
		return nil
	}
	leaf, stage, err := o.releaseBeforeMove(r, d)
	if err != nil {
		return err
	}
	if leaf == d.name {
		if backing == nil {
			return ErrIdentityV1
		}
		if err := o.ops.namespace((*sourceRoot).renameExclusive, r, d.name, releaseDetached); err != nil {
			return err
		}
	}
	_ = backing.Close()
	return o.unlinkReleasedBacking(r, d, stage, scratch)
}

// releaseBeforeMove preserves the location and alias guards across scratch cleanup.
func (o *SourceOwnerV1) releaseBeforeMove(r *sourceRoot, d *sourceRelease) (string, sourceDebt, error) {
	leaf, stage, err := o.releaseMoveState(r, d)
	if err != nil {
		return "", sourceDebt{}, err
	}
	removed, err := o.removeReleaseScratch(r, d)
	if err != nil || !removed {
		return leaf, stage, err
	}
	return o.releaseMoveState(r, d)
}

// releaseMoveState qualifies the current marker, backing locations and stage.
func (o *SourceOwnerV1) releaseMoveState(r *sourceRoot, d *sourceRelease) (string, sourceDebt, error) {
	leaf, err := d.releaseLocation(r)
	if err != nil || leaf == "" {
		return "", sourceDebt{}, cmp.Or(err, ErrIdentityV1)
	}
	if err := d.requireMarker(r); err != nil {
		return "", sourceDebt{}, err
	}
	stage, err := o.sampleReleaseStage(r, d)
	if err != nil {
		return "", sourceDebt{}, err
	}
	if err := o.currentRoot(); err != nil {
		return "", sourceDebt{}, err
	}
	o.rebindReleaseAlias(r, d, stage)
	return leaf, stage, nil
}

// sampleReleaseStage binds a possible alias to its observed public or held spelling.
func (o *SourceOwnerV1) sampleReleaseStage(r *sourceRoot, d *sourceRelease) (sourceDebt, error) {
	entries, err := o.sourceEntries(r)
	if err != nil {
		return sourceDebt{}, err
	}
	if err := d.checkReleaseStageConflict(r, entries); err != nil {
		return sourceDebt{}, err
	}
	stage, _, err := o.censusStage(r, entries)
	if err != nil {
		return stage, err
	}
	return stage, d.admitSampledAlias(stage)
}

// admitSampledAlias admits a shared alias only at a spelling the protected name can restore.
func (d *sourceRelease) admitSampledAlias(stage sourceDebt) error {
	switch {
	case stage.name == "":
		return nil
	case stage.file != d.file && stage.name == d.name:
		return ErrBusyV1
	case stage.file == d.file && !stage.held() && stage.leaf != publicStagePrefix+stage.name:
		return ErrIdentityV1
	}
	return nil
}

// observePriorAlias refuses a replaced or unobservable stage slot.
func (d *sourceRelease) observePriorAlias(r *sourceRoot) error {
	if d.alias == "" {
		return nil
	}
	info, err := r.Lstat(d.alias)
	if errors.Is(err, os.ErrNotExist) || err == nil && sameSourceFile(info, d.file) {
		return nil
	}
	return ErrIdentityV1
}

// rebindReleaseAlias retires a withdrawn alias or tracks its newly sampled leaf.
func (o *SourceOwnerV1) rebindReleaseAlias(r *sourceRoot, d *sourceRelease, stage sourceDebt) {
	if stage.name != "" && stage.file == d.file {
		d.alias = stage.leaf
		if o.debt.file == d.file {
			o.debt.name, o.debt.leaf = stage.name, stage.leaf
		}
		if info, _ := o.stage.File.Stat(); sameSourceFile(info, d.file) {
			o.observedStage = ""
		}
		return
	}
	if d.alias != "" && requireReleaseVacancy(r, d.alias, ErrIdentityV1) == nil {
		o.forgetReleaseStage(d)
	}
}

// forgetReleaseStage retires the stage that shares the released capture.
func (o *SourceOwnerV1) forgetReleaseStage(d *sourceRelease) {
	d.alias = ""
	if o.debt.file == d.file {
		o.debt = sourceDebt{}
	}
	if info, _ := o.stage.File.Stat(); sameSourceFile(info, d.file) {
		o.stage.Clear()
		o.observedStage = ""
	}
}

// discardReleaseAlias returns shared stage custody after its directory sync.
func (o *SourceOwnerV1) discardReleaseAlias(d *sourceRelease) {
	o.forgetReleaseStage(d)
	if o.pendingStage.file == d.file {
		o.pendingStage = sourceDebt{}
		o.stage.ClearQuota()
	}
}

// retainIndependentReleaseStage records a surviving public stage for its own Prepare.
func (o *SourceOwnerV1) retainIndependentReleaseStage(r *sourceRoot, d *sourceRelease, used sourceUsage) {
	stage := used.stage
	if stage.name == "" || stage.file == d.file || stage.held() || o.debt.name != "" {
		return
	}
	if o.adoptStage(r, used) != nil {
		o.observedStage = stage.name
	}
}

// releaseBoundary checks point observations and the bounded listing before marker effects.
func (o *SourceOwnerV1) releaseBoundary(r *sourceRoot, d *sourceRelease) (bool, error) {
	if requireReleaseVacancy(r, d.name, ErrIdentityV1) != nil || requireReleaseVacancy(r, releaseDetached, ErrIdentityV1) != nil {
		return false, ErrIdentityV1
	}
	listed, stageErr, err := o.finalReleaseListing(r, d)
	if err != nil {
		return false, err
	}
	present, err := d.checkMarker(readRelease(r, releaseFile))
	if err != nil || present != listed || !d.acceptMarkerPresence(present) {
		return false, ErrIntegrityV1
	}
	return present, stageErr
}

// acceptMarkerPresence checks the reached phase and records a resolved marker observation.
func (d *sourceRelease) acceptMarkerPresence(present bool) bool {
	switch d.phase {
	case releaseMarkerClearing:
		if present {
			d.phase = releaseBackingDurable
		} else {
			d.phase = releaseMarkerGone
		}
		return true
	case releaseMarkerGone:
		return !present
	default:
		return present
	}
}

// finalReleaseListing detects backing reappearance before reporting marker or stage state.
func (o *SourceOwnerV1) finalReleaseListing(r *sourceRoot, d *sourceRelease) (bool, error, error) {
	entries, err := o.sourceEntries(r)
	if err != nil {
		return false, nil, err
	}
	var marker bool
	var stageErr error
	for _, entry := range entries {
		leaf := entry.Name()
		if d.listedBacking(r, leaf) {
			return false, nil, ErrIdentityV1
		}
		if leaf == releaseFile {
			marker = true
		}
		if samePublicStage(leaf, d.name) || leaf == heldStagePrefix+d.name {
			_, err := sourceEntryInfo(r, leaf, ErrIntegrityV1)
			stageErr = cmp.Or(stageErr, err, ErrBusyV1)
		}
	}
	return marker, stageErr, nil
}

// listedBacking distinguishes an alternate spelling of a backing address from a separate name.
func (d *sourceRelease) listedBacking(r *sourceRoot, leaf string) bool {
	for _, address := range [...]string{d.name, releaseDetached} {
		if leaf == address || strings.EqualFold(leaf, address) && requireReleaseVacancy(r, address, ErrIdentityV1) != nil {
			return true
		}
	}
	return false
}

// requireDetached checks that neither the location pair nor marker was replaced.
func (d *sourceRelease) requireDetached(r *sourceRoot) error {
	if leaf, err := d.releaseLocation(r); err != nil || leaf != releaseDetached {
		return cmp.Or(err, ErrIdentityV1)
	}
	return d.requireMarker(r)
}

// unlinkReleasedBacking qualifies the detached file and observes links on the same descriptor.
func (o *SourceOwnerV1) unlinkReleasedBacking(r *sourceRoot, d *sourceRelease, stage sourceDebt, scratch []byte) error {
	leaf, err := d.releaseLocation(r)
	if err != nil || leaf != releaseDetached {
		return o.restoreReleasedBacking(r, d, cmp.Or(err, ErrIdentityV1))
	}
	if err := d.requireMarker(r); err != nil {
		return err
	}
	f, err := openSourceFile(r, releaseDetached, nil, d.file)
	if err != nil {
		return o.restoreReleasedBacking(r, d, err)
	}
	defer f.Close()
	if err := o.qualifyReleaseBacking(f, d, scratch); err != nil {
		return o.restoreReleasedBacking(r, d, err)
	}
	if err := o.unlinkReleaseAlias(r, d, f, stage); err != nil {
		return err
	}
	if err := o.authorizeReleaseUnlink(r, d, f, 1); err != nil {
		return err
	}
	removeErr := o.ops.remove(r.Root, releaseDetached)
	links, statErr := sourceLinks(f)
	return cmp.Or(removeErr, d.afterReleaseUnlink(r, links, statErr))
}

// restoreReleasedBacking restores only to a positively vacant canonical name.
func (o *SourceOwnerV1) restoreReleasedBacking(r *sourceRoot, d *sourceRelease, cause error) error {
	canonical := requireReleaseVacancy(r, d.name, ErrIdentityV1)
	if _, err := r.Lstat(releaseDetached); canonical != nil || err != nil {
		return cause
	}
	if o.currentRoot() != nil {
		return cause
	}
	if err := o.ops.namespace((*sourceRoot).renameExclusive, r, releaseDetached, d.name); err == nil {
		_ = o.ops.dirSync(r.pin)
	}
	return cause
}

// sourceLinks returns a positive observation of the held descriptor's link count.
func sourceLinks(f *os.File) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		return 0, ErrUnavailableV1
	}
	return uint64(stat.Nlink), nil
}

// authorizeReleaseUnlink requires intact locations, marker and expected links.
func (o *SourceOwnerV1) authorizeReleaseUnlink(r *sourceRoot, d *sourceRelease, f *os.File, want uint64) error {
	if err := d.requireDetached(r); err != nil {
		return err
	}
	links, err := sourceLinks(f)
	if err != nil || links != want {
		return o.restoreReleasedBacking(r, d, cmp.Or(err, ErrIdentityV1))
	}
	return o.currentRoot()
}

// unlinkReleaseAlias removes only a positively sampled and protected staging alias.
func (o *SourceOwnerV1) unlinkReleaseAlias(r *sourceRoot, d *sourceRelease, f *os.File, stage sourceDebt) error {
	present, err := d.releaseAliasPresent(r, stage)
	if err != nil || !present {
		return err
	}
	if err := o.authorizeReleaseUnlink(r, d, f, 2); err != nil {
		return err
	}
	if err := o.protectReleaseAlias(r, d, &stage); err != nil {
		return err
	}
	if err := o.authorizeReleaseUnlink(r, d, f, 2); err != nil {
		return err
	}
	err = o.ops.remove(r.Root, stage.leaf)
	if requireReleaseVacancy(r, stage.leaf, ErrIdentityV1) == nil {
		o.forgetReleaseStage(d)
	}
	return err
}

// releaseAliasPresent reobserves the sampled staging inode before claiming it.
func (d *sourceRelease) releaseAliasPresent(r *sourceRoot, stage sourceDebt) (bool, error) {
	if stage.name == "" || stage.file != d.file {
		return false, d.refuseUnsampledAlias(r)
	}
	info, err := sourceEntryInfo(r, stage.leaf, nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, d.refuseUnsampledAlias(r)
	}
	if err != nil || !sameSourceFile(info, d.file) {
		return false, ErrIdentityV1
	}
	return true, nil
}

// refuseUnsampledAlias checks occupied same-key slots without accepting a new spelling.
func (d *sourceRelease) refuseUnsampledAlias(r *sourceRoot) error {
	for _, leaf := range [...]string{heldStagePrefix + d.name, publicStagePrefix + d.name} {
		info, err := sourceEntryInfo(r, leaf, nil)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil || sameSourceFile(info, d.file):
			return ErrIdentityV1
		default:
			return ErrBusyV1
		}
	}
	return nil
}

// protectReleaseAlias claims the sampled public alias before it can be unlinked.
func (o *SourceOwnerV1) protectReleaseAlias(r *sourceRoot, d *sourceRelease, stage *sourceDebt) error {
	if stage.held() {
		return nil
	}
	if err := o.retainStage(r, *stage); err != nil {
		return err
	}
	if err := o.claimStage(r, stage); err != nil {
		return err
	}
	d.alias = stage.leaf
	if o.debt.file == d.file {
		o.debt.leaf = stage.leaf
	}
	return nil
}

// afterReleaseUnlink records zero links or keeps retry authority pinned to the private entry.
func (d *sourceRelease) afterReleaseUnlink(r *sourceRoot, links uint64, statErr error) error {
	if statErr == nil && links == 0 {
		d.phase = releaseBackingGone
		return nil
	}
	refusal := cmp.Or(statErr, ErrIdentityV1)
	info, err := sourceEntryInfo(r, releaseDetached, nil)
	if err != nil || !sameSourceFile(info, d.file) {
		d.unlinkRefusal = refusal
	}
	return refusal
}

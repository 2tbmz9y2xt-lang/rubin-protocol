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

type releasePhase uint8

const (
	releaseBackingPending releasePhase = iota
	releaseBackingGone
	releaseBackingDurable
	releaseMarkerClearing
)

type sourceRelease struct {
	sourceIncarnation
	name          string
	manifest      SourceManifestV1
	record        []byte
	reopened      bool
	pending       bool
	phase         releasePhase
	unlinkFailure error
	markerFile    filelock.IdentityV1
}

// ReleaseUnpublishedSourceV1 holds the source charge through durable removal (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func (o *SourceOwnerV1) ReleaseUnpublishedSourceV1(account *mdbx.OperationAccount, p *PreparedSourceV1, neverReferenced bool) error {
	return o.operation(account, func() error {
		if err := o.releaseAdmission(p, neverReferenced); err != nil {
			return err
		}
		return o.withRoot(o.bindRoot, func(r *sourceRoot) error {
			scratch := make([]byte, scratchBytes)
			d := o.release
			if d == nil {
				if err := o.releaseCensus(r); err != nil {
					return err
				}
				d = &sourceRelease{name: p.name, sourceIncarnation: *p.incarnation, manifest: p.manifest}
				if o.debt.matchesKey(p.name) && d.sharedStageKey(o.debt) == "" {
					return ErrBusyV1
				}
				d.record = o.releaseRecord(d)
			}
			return o.continueRelease(r, d, scratch)
		})
	})
}

func (o *SourceOwnerV1) releaseCensus(r *sourceRoot) error {
	if r.releaseScanned {
		return nil
	}
	_, err := o.census(r, false)
	r.releaseScanned = err == nil
	return err
}

func (d sourceDebt) matchesKey(name string) bool { return strings.EqualFold(d.name, name) }

func (o *SourceOwnerV1) releaseAdmission(p *PreparedSourceV1, proof bool) error {
	if !proof || !o.hasReleaseAuthority(p) {
		return ErrIntegrityV1
	}
	if p != nil && o.release != nil && o.release.name != p.name {
		return ErrBusyV1
	}
	return nil
}

func (o *SourceOwnerV1) hasReleaseAuthority(p *PreparedSourceV1) bool {
	if p == nil {
		return o.release != nil && o.release.reopened
	}
	return p.incarnation != nil && o.live[p.name] == p.incarnation
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

func readRelease(r *sourceRoot) ([]byte, filelock.IdentityV1, error) {
	f, err := openSourceFile(r, releaseFile, nil)
	if err != nil {
		return nil, filelock.IdentityV1{}, err
	}
	defer f.Close()
	return readReleaseFile(f)
}

func readReleaseFile(f *os.File) ([]byte, filelock.IdentityV1, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, filelock.IdentityV1{}, ErrIntegrityV1
	}
	record := make([]byte, releaseMax+1)
	n, err := io.ReadFull(f, record)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
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

func (o *SourceOwnerV1) releaseBacking(r *sourceRoot, d *sourceRelease, scratch []byte) (bool, error) {
	name, err := d.pinnedLocation(r)
	if err != nil || name == "" {
		return false, err
	}
	f := r.backingPin
	if name != d.name || f == nil {
		f, err = openSourceFile(r, name, nil)
		if err != nil {
			return false, err
		}
		defer f.Close()
	}
	_, err = o.qualify(f, d.manifest, d.size, scratch, &d.sourceIncarnation, ErrIdentityV1)
	return true, err
}

// location checks the public name before the private name for a pending intent.
func (d *sourceRelease) location(r *sourceRoot) (string, error) {
	if d == nil {
		if r.requireVacant(releaseDetached, ErrIntegrityV1) != nil {
			return "", ErrIntegrityV1
		}
		return "", nil
	}
	var location string
	for _, name := range [...]string{d.name, releaseDetached} {
		info, err := sourceEntryInfo(r, name, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", ErrIntegrityV1
		}
		if err := d.match(info); err != nil {
			return "", err
		}
		if location != "" {
			return "", ErrIdentityV1
		}
		location = name
	}
	return location, nil
}

func (d *sourceRelease) pinnedLocation(r *sourceRoot) (string, error) {
	name, err := d.location(r)
	if name == d.name {
		return name, r.backingErr
	}
	return name, err
}

func (inc *sourceIncarnation) match(info os.FileInfo) error {
	if filelock.FileIdentityV1(info) != inc.file {
		return ErrIdentityV1
	}
	if uint64(max(info.Size(), 0)) != inc.size {
		return ErrIntegrityV1
	}
	return nil
}

func (o *SourceOwnerV1) openRelease(r *sourceRoot) error {
	record, id, err := readRelease(r)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrIntegrityV1
	}
	o.release, err = o.decodeRelease(record)
	if err != nil {
		return err
	}
	o.release.markerFile = id
	return nil
}

// releaseScratchAlias recognizes the second name of the visible marker.
func releaseScratchAlias(r *sourceRoot) (bool, error) {
	scratch, err := sourceEntryInfo(r, releaseScratch, nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	marker, markerErr := sourceEntryInfo(r, releaseFile, nil)
	if err != nil || markerErr != nil || !os.SameFile(scratch, marker) {
		return false, ErrIntegrityV1
	}
	return true, nil
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

func (o *SourceOwnerV1) persistRelease(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if present, err := o.releaseBacking(r, d, scratch); err != nil || !present {
		return cmp.Or(err, ErrIdentityV1)
	}
	if err := o.checkStage(r, d, true); err != nil {
		return err
	}
	if err := o.clearReleaseScratch(r); err != nil {
		return err
	}
	if _, err := o.space(r, uint64(len(d.record)), nil); err != nil {
		return err
	}
	id, err := o.writeRelease(r, d.record)
	if err != nil {
		return err
	}
	return o.publishMarker(r, d, id)
}

func (o *SourceOwnerV1) publishMarker(r *sourceRoot, d *sourceRelease, id filelock.IdentityV1) error {
	pin, err := r.pinFile(releaseScratch, nil, &id)
	if err != nil {
		return err
	}
	visibility, err := o.linkVisible(r, releaseScratch, releaseFile, id)
	if visibility != sourceNotVisible {
		d.markerFile = id
		d.pending = visibility == sourceIndeterminate
		o.release = d
	}
	if err != nil {
		_ = pin.Close()
		return err
	}
	present, err := o.syncedMarker(r, d, pin)
	if err == nil && !present {
		return ErrIntegrityV1
	}
	return err
}

func (o *SourceOwnerV1) writeRelease(r *sourceRoot, record []byte) (filelock.IdentityV1, error) {
	f, err := r.OpenFile(releaseScratch, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return filelock.IdentityV1{}, err
	}
	defer f.Close()
	w := sourceFileWriter{o: o, file: f}
	if _, err := w.Write(record); err != nil {
		return filelock.IdentityV1{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return filelock.IdentityV1{}, err
	}
	return filelock.FileIdentityV1(info), cmp.Or(o.ops.chmod(f, 0o600), o.finishFile(f))
}

func (o *SourceOwnerV1) continueRelease(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if err := o.syncReleasedBacking(r, d, scratch); err != nil {
		return err
	}
	if err := o.clearReleaseMarker(r, d); err != nil {
		return err
	}
	if err := o.syncBoundRoot(r); err != nil {
		return err
	}
	if !d.backingAbsent(r) {
		return ErrIdentityV1
	}
	if r.requireVacant(releaseFile, ErrIntegrityV1) != nil {
		return ErrIntegrityV1
	}
	if err := o.checkStage(r, d, false); err != nil {
		return err
	}
	delete(o.live, d.name)
	o.release = nil
	return nil
}

// clearReleaseMarker removes a matching release record only after the backing name is observed absent.
func (o *SourceOwnerV1) clearReleaseMarker(r *sourceRoot, d *sourceRelease) error {
	if !d.backingAbsent(r) {
		return ErrIdentityV1
	}
	present, err := d.checkMarker(readRelease(r))
	if err != nil {
		return err
	}
	if !present && d.phase != releaseMarkerClearing {
		return ErrIntegrityV1
	}
	if err := o.checkStage(r, d, false); err != nil || !present {
		return err
	}
	if err := o.removeMarkerAlias(r); err != nil {
		return err
	}
	d.phase = releaseMarkerClearing
	return o.ops.remove(r.Root, releaseFile)
}

// removeMarkerAlias clears the temporary name only when it shares the visible marker inode.
func (o *SourceOwnerV1) removeMarkerAlias(r *sourceRoot) error {
	alias, err := releaseScratchAlias(r)
	if err != nil || !alias {
		return err
	}
	return o.ops.remove(r.Root, releaseScratch)
}

func (d *sourceRelease) backingAbsent(r *sourceRoot) bool {
	return r.requireVacant(d.name, ErrIdentityV1) == nil && r.requireVacant(releaseDetached, ErrIdentityV1) == nil
}

func (d *sourceRelease) checkMarker(record []byte, id filelock.IdentityV1, err error) (bool, error) {
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !bytes.Equal(record, d.record) || id != d.markerFile {
		return false, ErrIntegrityV1
	}
	return true, nil
}

func (d *sourceRelease) pinnedMarker(r *sourceRoot, pin *os.File) (bool, error) {
	named, err := sourceEntryInfo(r, releaseFile, nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || filelock.FileIdentityV1(named) != d.markerFile {
		return false, ErrIntegrityV1
	}
	return d.checkMarker(readReleaseFile(pin))
}

func (o *SourceOwnerV1) syncedMarker(r *sourceRoot, d *sourceRelease, pin *os.File) (bool, error) {
	if err := o.ops.dirSync(r.pin); err != nil {
		_ = pin.Close()
		return false, err
	}
	present, err := d.pinnedMarker(r, pin)
	_ = pin.Close()
	return present, cmp.Or(o.currentRoot(), err)
}

// releaseIntent qualifies the visible record before its backing can be detached.
func (o *SourceOwnerV1) releaseIntent(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if o.release == nil {
		return o.persistRelease(r, d, scratch)
	}
	pin, err := openSourceFile(r, releaseFile, nil)
	if err != nil {
		pin, _ = openSourceFile(r, releaseScratch, nil)
	}
	present, err := o.syncedMarker(r, d, pin)
	if err != nil || present {
		return err
	}
	if !d.pending {
		return ErrIntegrityV1
	}
	return o.persistRelease(r, d, scratch)
}

func (o *SourceOwnerV1) syncReleasedBacking(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if d.phase >= releaseBackingDurable {
		return nil
	}
	r.backingPin, r.backingErr = r.pinFile(d.name, ErrIdentityV1, &d.file)
	defer r.backingPin.Close()
	if err := o.releaseIntent(r, d, scratch); err != nil {
		return err
	}
	d.pending = false
	if d.unlinkFailure != nil {
		return d.unlinkFailure
	}
	name, err := d.pinnedLocation(r)
	if err != nil {
		return err
	}
	if err := o.detachBacking(r, d, name, scratch); err != nil {
		return err
	}
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	d.phase = releaseBackingDurable
	return nil
}

func (d *sourceRelease) canonicalVacant(r *sourceRoot) error {
	if d == nil {
		return nil
	}
	_, err := r.Lstat(d.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrIntegrityV1
	}
	_, err = d.location(r)
	return cmp.Or(err, ErrIdentityV1)
}

func (o *SourceOwnerV1) detachBacking(r *sourceRoot, d *sourceRelease, name string, scratch []byte) error {
	if err := o.checkStage(r, d, name != ""); err != nil {
		return err
	}
	if err := o.removeMarkerAlias(r); err != nil {
		return err
	}
	if (name != "") != (d.phase == releaseBackingPending) {
		return ErrIdentityV1
	}
	if name == "" {
		return nil
	}
	if name != releaseDetached {
		if err := o.ops.namespace(detachSource, r, name, releaseDetached); err != nil {
			return err
		}
	}
	return o.unlinkDetached(r, d, scratch)
}

// checkStage preserves an independent stage for the same capture.
func (o *SourceOwnerV1) checkStage(r *sourceRoot, d *sourceRelease, backingPresent bool) error {
	if err := o.releaseCensus(r); err != nil {
		return err
	}
	key := d.name
	if o.debt.matchesKey(key) {
		key = o.debt.name
	}
	stage, err := r.stageAlias(key)
	switch {
	case err == nil && (!backingPresent || stage.file != d.file):
		return ErrBusyV1
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return ErrIntegrityV1
	}
	if !backingPresent {
		return nil
	}
	observed := d.sharedStageKey(o.debt)
	if key := cmp.Or(observed, d.name); stage.name != key {
		stage, err = r.stageAlias(key)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || observed != "" && stage.file != d.file || stage.file == d.file && !stage.held && !validHeldStageKey(observed) {
		return ErrIdentityV1
	}
	return nil
}

func (r *sourceRoot) stageAlias(key string) (sourceDebt, error) {
	stage := sourceDebt{name: key, held: true}
	info, err := sourceEntryInfo(r, stage.leaf(), nil)
	if errors.Is(err, os.ErrNotExist) {
		stage.held = false
		info, err = sourceEntryInfo(r, stage.leaf(), nil)
	} else if err == nil {
		err = r.requireVacant(publicStagePrefix+key, syscall.EEXIST)
	}
	stage.file = filelock.FileIdentityV1(info)
	return stage, err
}

// unlinkDetached pins and qualifies the private file before removing its last link.
func (o *SourceOwnerV1) unlinkDetached(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if err := d.canonicalVacant(r); err != nil {
		return err
	}
	f, err := openSourceFile(r, releaseDetached, nil)
	_ = r.backingPin.Close()
	if err != nil {
		return o.restoreBacking(r, d, err)
	}
	defer f.Close()
	if _, err := o.qualify(f, d.manifest, d.size, scratch, &d.sourceIncarnation, ErrIntegrityV1); err != nil {
		return o.restoreBacking(r, d, err)
	}
	if err := o.singleBackingLink(r, d, f); err != nil {
		return err
	}
	removeErr := o.ops.remove(r.Root, releaseDetached)
	links, statErr := sourceLinks(f)
	return cmp.Or(removeErr, d.afterUnlink(r, links, statErr))
}

// restoreBacking preserves the qualification error if the canonical slot was refilled.
func (o *SourceOwnerV1) restoreBacking(r *sourceRoot, d *sourceRelease, cause error) error {
	if err := o.ops.namespace(detachSource, r, releaseDetached, d.name); err == nil {
		_ = o.ops.dirSync(r.pin)
	}
	return cause
}

func sourceLinks(f *os.File) (uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, ErrUnavailableV1
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, ErrUnavailableV1
	}
	return uint64(stat.Nlink), nil
}

func (d *sourceRelease) sharedStageKey(debt sourceDebt) string {
	if debt.backing != "" && debt.file == d.file {
		return debt.name
	}
	return ""
}

func (o *SourceOwnerV1) requireBackingLinks(r *sourceRoot, d *sourceRelease, f *os.File, want uint64) error {
	links, err := sourceLinks(f)
	if err == nil && links == want {
		return nil
	}
	return o.restoreBacking(r, d, cmp.Or(err, ErrIdentityV1))
}

// singleBackingLink retires the shared stage charge once the backing has exactly one link.
func (o *SourceOwnerV1) singleBackingLink(r *sourceRoot, d *sourceRelease, f *os.File) error {
	if err := o.dropReleaseAlias(r, d, f); err != nil {
		return err
	}
	if err := o.requireBackingLinks(r, d, f, 1); err != nil {
		return err
	}
	if d.sharedStageKey(o.debt) != "" {
		if !o.debt.unlinkTried {
			return o.restoreBacking(r, d, ErrIdentityV1)
		}
		o.debt = sourceDebt{}
	}
	return nil
}

func (o *SourceOwnerV1) dropReleaseAlias(r *sourceRoot, d *sourceRelease, f *os.File) error {
	observed := d.sharedStageKey(o.debt)
	stage, err := r.stageAlias(cmp.Or(observed, d.name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || stage.file != d.file {
		return o.restoreBacking(r, d, ErrIdentityV1)
	}
	if err := o.requireBackingLinks(r, d, f, 2); err != nil {
		return err
	}
	if !stage.held && !validHeldStageKey(observed) {
		return ErrIdentityV1
	}
	if o.debt.name != "" && o.debt.name != stage.name {
		return ErrBusyV1
	}
	stage.staging, stage.backing, stage.size = true, d.name, d.size
	o.debt = stage
	if err := o.unlinkStage(r, &o.debt); err != nil {
		return err
	}
	o.debt.removed = true
	return d.canonicalVacant(r)
}

// afterUnlink allows another unlink only while the original private entry is identifiable.
func (d *sourceRelease) afterUnlink(r *sourceRoot, links uint64, err error) error {
	if err == nil && links == 0 {
		d.phase = releaseBackingGone
		return nil
	}
	failure := cmp.Or(err, ErrIdentityV1)
	info, statErr := sourceEntryInfo(r, releaseDetached, nil)
	if statErr != nil || filelock.FileIdentityV1(info) != d.file {
		d.unlinkFailure = failure
	}
	return failure
}

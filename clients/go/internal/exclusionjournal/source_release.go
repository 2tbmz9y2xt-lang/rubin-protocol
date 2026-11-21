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
	releaseFile    = ".release"
	releaseScratch = ".release-scratch"
	releasePrefix  = 4 + 16 + 16 + 8 + 32
	releaseMax     = releasePrefix + bundleHeader + 6*9 + sha256.Size
)

const releaseDetached = ".release-backing"

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
				if _, err := o.census(r, false); err != nil {
					return err
				}
				d = &sourceRelease{name: p.name, sourceIncarnation: *p.incarnation, manifest: p.manifest}
				if o.debt.matchesKey(p.name) && o.debt.sharedKey(d.file) == "" {
					return ErrBusyV1
				}
				d.record = o.releaseRecord(d)
			}
			return o.continueRelease(r, d, scratch)
		})
	})
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
	info, statErr := f.Stat()
	record := make([]byte, releaseMax+1)
	n, err := f.ReadAt(record, 0)
	if statErr != nil || n == 0 || !errors.Is(err, io.EOF) {
		return nil, filelock.IdentityV1{}, ErrIntegrityV1
	}
	return record[:n], filelock.FileIdentityV1(info), nil
}

func (o *SourceOwnerV1) decodeRelease(record []byte, marker filelock.IdentityV1) (*sourceRelease, error) {
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
	d := &sourceRelease{name: m.name(o.id), manifest: m, record: record, reopened: true, markerFile: marker}
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
	name, err := d.location(r, r.backingErr)
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

func (d *sourceRelease) location(r *sourceRoot, canonicalPinErr error) (string, error) {
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
		if err := d.match(info); err != nil {
			return "", err
		}
		if location != "" {
			return "", ErrIdentityV1
		}
		location = name
	}
	if location == d.name {
		return location, canonicalPinErr
	}
	return location, nil
}

func (inc *sourceIncarnation) match(info os.FileInfo) error {
	switch {
	case info == nil:
		return ErrIntegrityV1
	case filelock.FileIdentityV1(info) != inc.file:
		return ErrIdentityV1
	case uint64(max(info.Size(), 0)) != inc.size:
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
	o.release, err = o.decodeRelease(record, id)
	return err
}

func (r *sourceRoot) checkMarkerAlias(remove func(*os.Root, string) error) error {
	scratch, err := sourceEntryInfo(r, releaseScratch, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	marker, _ := sourceEntryInfo(r, releaseFile, nil)
	if !os.SameFile(scratch, marker) {
		return ErrIntegrityV1
	}
	if remove != nil {
		return remove(r.Root, releaseScratch)
	}
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
	return o.writeRelease(r, d)
}

func (o *SourceOwnerV1) publishMarker(r *sourceRoot, d *sourceRelease, id filelock.IdentityV1) error {
	pin, err := r.pinFile(releaseScratch, nil, &id)
	if err != nil {
		return err
	}
	if record, _, err := readReleaseFile(pin); err != nil || !bytes.Equal(record, d.record) {
		_ = pin.Close()
		return ErrIntegrityV1
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

func (o *SourceOwnerV1) writeRelease(r *sourceRoot, d *sourceRelease) error {
	f, err := r.OpenFile(releaseScratch, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := sourceFileWriter{o: o, file: f}
	if _, err := w.Write(d.record); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := cmp.Or(o.ops.chmod(f, 0o600), o.finishFile(f)); err != nil {
		return err
	}
	return o.publishMarker(r, d, filelock.FileIdentityV1(info))
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
	if err != nil || !present {
		return err
	}
	if err := r.checkMarkerAlias(o.ops.remove); err != nil {
		return err
	}
	d.phase = releaseMarkerClearing
	return o.ops.remove(r.Root, releaseFile)
}

func (o *SourceOwnerV1) releaseBoundary(r *sourceRoot, d *sourceRelease) (bool, error) {
	if r.requireVacant(d.name, ErrIdentityV1) != nil || r.requireVacant(releaseDetached, ErrIdentityV1) != nil {
		return false, ErrIdentityV1
	}
	return o.checkNames(r, d.name, nil, nil)
}

func (d *sourceRelease) confirmMarker(r *sourceRoot, expected bool, scanErr error) (bool, error) {
	if d != nil {
		present, err := d.checkMarker(readRelease(r))
		switch {
		case err != nil || !present && d.phase != releaseMarkerClearing:
			return false, ErrIntegrityV1
		case expected != present:
			return false, cmp.Or(scanErr, ErrIntegrityV1)
		}
	}
	return expected, scanErr
}

func (o *SourceOwnerV1) checkNames(r *sourceRoot, name string, publishing error, moving *sourceRelease) (markerListed bool, err error) {
	entries, err := o.entries(r, publishing)
	final := publishing == nil && moving == nil
	for _, entry := range entries {
		leaf := entry.Name()
		switch leaf {
		case releaseFile:
			markerListed = true
		case name, releaseDetached:
			if final {
				return false, ErrIdentityV1
			}
		}
		if key, matches := boundaryStage(leaf, name, final); matches {
			if moving != nil {
				err = cmp.Or(err, moving.stageAt(r, key, o.debt.sharedKey(moving.file), true, ErrIntegrityV1, ErrBusyV1))
			} else {
				_, obsErr := sourceEntryInfo(r, leaf, ErrIntegrityV1)
				err = cmp.Or(err, publishing, obsErr, ErrBusyV1)
			}
		}
	}
	return o.release.confirmMarker(r, markerListed, err)
}

func boundaryStage(leaf, name string, final bool) (string, bool) {
	key, public := strings.CutPrefix(leaf, publicStagePrefix)
	return key, public && strings.EqualFold(key, name) || final && leaf == heldStagePrefix+name
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

func (o *SourceOwnerV1) syncedMarker(r *sourceRoot, d *sourceRelease, pin *os.File) (present bool, err error) {
	if err := o.ops.dirSync(r.pin); err != nil {
		_ = pin.Close()
		return false, err
	}
	named, statErr := sourceEntryInfo(r, releaseFile, nil)
	if statErr == nil && filelock.FileIdentityV1(named) == d.markerFile {
		present, err = d.checkMarker(readReleaseFile(pin))
	} else if !errors.Is(statErr, os.ErrNotExist) {
		err = ErrIntegrityV1
	}
	_ = pin.Close()
	return present, cmp.Or(o.currentRoot(), err)
}

func (o *SourceOwnerV1) releaseIntent(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if o.release != nil {
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
	name, err := d.location(r, r.backingErr)
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

func (d *sourceRelease) checkDetachedIntent(r *sourceRoot) error {
	if d != nil {
		switch _, err := r.Lstat(d.name); {
		case err == nil:
			_, err = d.location(r, nil)
			return cmp.Or(err, ErrIdentityV1)
		case !errors.Is(err, os.ErrNotExist):
			return ErrIntegrityV1
		}
	}
	_, err := d.confirmMarker(r, true, nil)
	return err
}

func (o *SourceOwnerV1) detachBacking(r *sourceRoot, d *sourceRelease, name string, scratch []byte) error {
	if err := o.checkStage(r, d, name != ""); err != nil {
		return err
	}
	if err := r.checkMarkerAlias(o.ops.remove); err != nil {
		return err
	}
	if (name != "") != (d.phase == releaseBackingPending) {
		return ErrIdentityV1
	}
	switch name {
	case "":
		return nil
	case d.name:
		if _, err := o.checkNames(r, name, nil, d); err != nil {
			return err
		}
		if err := o.ops.namespace(detachSource, r, name, releaseDetached); err != nil {
			return err
		}
	}
	return o.unlinkDetached(r, d, scratch)
}

func (o *SourceOwnerV1) checkStage(r *sourceRoot, d *sourceRelease, backingPresent bool) error {
	if _, err := o.census(r, false); err != nil {
		return err
	}
	key := d.name
	if o.debt.matchesKey(key) {
		key = o.debt.name
	}
	observed := o.debt.sharedKey(d.file)
	err := d.stageAt(r, key, observed, backingPresent, ErrIntegrityV1, ErrBusyV1)
	if err == nil && backingPresent && observed != "" && observed != key {
		return d.stageAt(r, observed, observed, true, ErrIdentityV1, ErrIdentityV1)
	}
	return err
}

func (d *sourceRelease) stageAt(r *sourceRoot, key, observed string, backingPresent bool, malformed, conflict error) error {
	stage, err := r.stageAlias(key)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil && !errors.Is(err, syscall.EEXIST):
		return malformed
	case !backingPresent || stage.file != d.file:
		return conflict
	case err != nil || !stage.claimable(observed):
		return ErrIdentityV1
	}
	return nil
}

func (stage sourceDebt) claimable(observed string) bool {
	return stage.held || stage.name == observed && validHeldStageKey(observed)
}

func (r *sourceRoot) stageAlias(key string) (sourceDebt, error) {
	stage := sourceDebt{name: key, held: true}
	info, err := sourceEntryInfo(r, stage.leaf(), nil)
	if errors.Is(err, os.ErrNotExist) {
		stage.held = false
		info, err = sourceEntryInfo(r, stage.leaf(), nil)
	} else if err == nil {
		public, publicErr := sourceEntryInfo(r, publicStagePrefix+key, nil)
		if !errors.Is(publicErr, os.ErrNotExist) {
			return sourceDebt{name: key, file: filelock.FileIdentityV1(public)}, cmp.Or[error](publicErr, syscall.EEXIST)
		}
	}
	stage.file = filelock.FileIdentityV1(info)
	return stage, err
}

func (o *SourceOwnerV1) unlinkDetached(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if err := d.checkDetachedIntent(r); err != nil {
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

func (o *SourceOwnerV1) restoreBacking(r *sourceRoot, d *sourceRelease, cause error) error {
	if err := o.ops.namespace(detachSource, r, releaseDetached, d.name); err == nil {
		_ = o.ops.dirSync(r.pin)
	}
	return cause
}

func sourceLinks(f *os.File) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &stat); err != nil {
		return 0, ErrUnavailableV1
	}
	return uint64(stat.Nlink), nil
}

func (debt sourceDebt) sharedKey(file filelock.IdentityV1) string {
	if debt.backing != "" && debt.file == file {
		return debt.name
	}
	return ""
}

func (o *SourceOwnerV1) authorizeUnlink(r *sourceRoot, d *sourceRelease, f *os.File, wantLinks uint64) error {
	links, err := sourceLinks(f)
	if err != nil || links != wantLinks {
		return o.restoreBacking(r, d, cmp.Or(err, ErrIdentityV1))
	}
	return d.checkDetachedIntent(r)
}

func (o *SourceOwnerV1) singleBackingLink(r *sourceRoot, d *sourceRelease, f *os.File) error {
	if err := o.dropReleaseAlias(r, d, f); err != nil {
		return err
	}
	if err := o.authorizeUnlink(r, d, f, 1); err != nil {
		return err
	}
	if o.debt.sharedKey(d.file) != "" {
		o.stage.Clear()
		o.debt = sourceDebt{}
	}
	return nil
}

func (o *SourceOwnerV1) dropReleaseAlias(r *sourceRoot, d *sourceRelease, f *os.File) error {
	observed := o.debt.sharedKey(d.file)
	stage, err := r.stageAlias(cmp.Or(observed, d.name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || stage.file != d.file {
		return o.restoreBacking(r, d, ErrIdentityV1)
	}
	if err := o.authorizeUnlink(r, d, f, 2); err != nil {
		return err
	}
	if !stage.claimable(observed) {
		return ErrIdentityV1
	}
	if o.debt.hasOtherName(stage.name) {
		return ErrBusyV1
	}
	stage.staging, stage.backing, stage.size = true, d.name, d.size
	o.debt = stage
	if err := o.unlinkStage(r, &o.debt); err != nil {
		return err
	}
	o.debt.removed = true
	return d.checkDetachedIntent(r)
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

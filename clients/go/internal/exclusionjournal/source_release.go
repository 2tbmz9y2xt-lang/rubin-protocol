package exclusionjournal

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
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

type sourceRelease struct {
	sourceIncarnation
	name           string
	manifest       SourceManifestV1
	record         []byte
	reopened       bool
	pending        bool
	backingSynced  bool
	clearAttempted bool
	unlinked       bool
	unlinkFailure  error
	markerFile     filelock.IdentityV1
}

// ReleaseUnpublishedSourceV1 holds the source charge through durable removal (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func (o *SourceOwnerV1) ReleaseUnpublishedSourceV1(account *mdbx.OperationAccount, p *PreparedSourceV1, neverReferenced bool) error {
	return o.operation(account, func() error {
		if err := o.releaseAdmission(p, neverReferenced); err != nil {
			return err
		}
		return o.withRoot(o.bindRoot, func(r *sourceRoot) error {
			scratch := make([]byte, scratchBytes)
			if o.release == nil {
				if _, err := o.census(r); err != nil {
					return err
				}
				if o.debt.name == p.name && !o.debt.alias {
					return ErrBusyV1
				}
				d := &sourceRelease{name: p.name, sourceIncarnation: *p.incarnation, manifest: p.manifest}
				d.record = o.releaseRecord(d)
				if err := o.persistRelease(r, d, scratch); err != nil {
					return err
				}
			}
			return o.continueRelease(r, scratch)
		})
	})
}

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
	info, err := f.Stat()
	if err != nil {
		return nil, filelock.IdentityV1{}, err
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
	name, err := d.location(r)
	if err != nil || name == "" {
		return false, err
	}
	f, err := openSourceFile(r, name, nil)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = o.qualify(f, d.manifest, d.size, scratch, &d.sourceIncarnation, ErrIdentityV1)
	return true, err
}

// location checks the public name before the private name for a pending intent.
func (d *sourceRelease) location(r *sourceRoot) (string, error) {
	if d == nil {
		if _, err := r.Lstat(releaseDetached); !errors.Is(err, os.ErrNotExist) {
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
		if _, err := o.release.location(r); err != nil {
			return err
		}
		return o.clearReleaseScratch(r)
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
	if err := o.clearReleaseScratch(r); err != nil {
		return err
	}
	if err := o.space(r, uint64(len(d.record)), sourceDebt{}); err != nil {
		return err
	}
	id, err := o.writeRelease(r, d.record)
	if err != nil {
		return err
	}
	visibility, err := o.linkVisible(r, releaseScratch, releaseFile, id)
	if visibility != sourceNotVisible {
		d.markerFile = id
		d.pending = visibility == sourceIndeterminate
		o.release = d
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

func (o *SourceOwnerV1) continueRelease(r *sourceRoot, scratch []byte) error {
	d := o.release
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
	if err := d.checkStage(r); err != nil {
		return err
	}
	if o.debt.name == d.name && o.debt.file == d.file {
		o.debt = sourceDebt{}
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
	present, err := d.marker(r)
	if err != nil {
		return err
	}
	if !present && !d.clearAttempted {
		return ErrIntegrityV1
	}
	if err := d.checkStage(r); err != nil || !present {
		return err
	}
	if err := o.removeMarkerAlias(r); err != nil {
		return err
	}
	d.clearAttempted = true
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
	for _, name := range [...]string{d.name, releaseDetached} {
		if _, err := r.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func (d *sourceRelease) marker(r *sourceRoot) (bool, error) {
	record, id, err := readRelease(r)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !bytes.Equal(record, d.record) || id != d.markerFile {
		return false, ErrIntegrityV1
	}
	return true, nil
}

// releaseIntent syncs the named record and verifies it against the saved bytes.
func (o *SourceOwnerV1) releaseIntent(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if err := o.syncBoundRoot(r); err != nil {
		return err
	}
	present, err := d.marker(r)
	if err != nil || present {
		return err
	}
	if !d.pending {
		return ErrIntegrityV1
	}
	if err := o.persistRelease(r, d, scratch); err != nil {
		return err
	}
	return o.releaseIntent(r, d, scratch)
}

func (o *SourceOwnerV1) syncReleasedBacking(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if d.backingSynced {
		return nil
	}
	if err := o.releaseIntent(r, d, scratch); err != nil {
		return err
	}
	d.pending = false
	if d.unlinkFailure != nil {
		return d.unlinkFailure
	}
	name, err := d.location(r)
	if err != nil {
		return err
	}
	if err := o.detachBacking(r, d, name, scratch); err != nil {
		return err
	}
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	d.backingSynced = true
	return nil
}

func (o *SourceOwnerV1) detachBacking(r *sourceRoot, d *sourceRelease, name string, scratch []byte) error {
	if err := d.checkStage(r); err != nil {
		return err
	}
	if err := o.removeMarkerAlias(r); err != nil {
		return err
	}
	if (name == "") != d.unlinked {
		return ErrIdentityV1
	}
	if d.unlinked {
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
func (d *sourceRelease) checkStage(r *sourceRoot) error {
	info, err := sourceEntryInfo(r, ".staging-"+d.name, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrIntegrityV1
	}
	if filelock.FileIdentityV1(info) != d.file {
		return ErrBusyV1
	}
	return nil
}

// unlinkDetached pins and qualifies the private file before removing its last link.
func (o *SourceOwnerV1) unlinkDetached(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	f, err := openSourceFile(r, releaseDetached, nil)
	if err != nil {
		return o.restoreBacking(r, d, err)
	}
	defer f.Close()
	if _, err := o.qualify(f, d.manifest, d.size, scratch, &d.sourceIncarnation, ErrIntegrityV1); err != nil {
		return o.restoreBacking(r, d, err)
	}
	if err := o.singleBackingLink(r, d, f); err != nil {
		return o.restoreBacking(r, d, err)
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
	return sourceInfoLinks(info)
}

func sourceInfoLinks(info os.FileInfo) (uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, ErrUnavailableV1
	}
	return uint64(stat.Nlink), nil
}

func requireSourceLinks(f *os.File, want uint64) error {
	links, err := sourceLinks(f)
	if err == nil && links != want {
		return ErrIdentityV1
	}
	return err
}

// singleBackingLink removes only a qualified staging alias before the last unlink.
func (o *SourceOwnerV1) singleBackingLink(r *sourceRoot, d *sourceRelease, f *os.File) error {
	name := ".staging-" + d.name
	info, err := sourceEntryInfo(r, name, nil)
	if errors.Is(err, os.ErrNotExist) {
		return requireSourceLinks(f, 1)
	}
	if err != nil || filelock.FileIdentityV1(info) != d.file {
		return ErrIdentityV1
	}
	if err := requireSourceLinks(f, 2); err != nil {
		return err
	}
	if err := o.ops.remove(r.Root, name); err != nil {
		return err
	}
	return requireSourceLinks(f, 1)
}

// afterUnlink records only the observed link count on the held descriptor.
func (d *sourceRelease) afterUnlink(r *sourceRoot, links uint64, err error) error {
	if err != nil {
		d.unlinkFailure = err
		return err
	}
	if links == 0 {
		d.unlinked = true
		return nil
	}
	info, statErr := sourceEntryInfo(r, releaseDetached, nil)
	if statErr != nil || filelock.FileIdentityV1(info) != d.file {
		d.unlinkFailure = ErrIdentityV1
	}
	return ErrIdentityV1
}

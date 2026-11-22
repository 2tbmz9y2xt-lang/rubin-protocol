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
	releaseFile    = ".release"
	releaseScratch = ".release-scratch"
	releasePrefix  = 4 + 16 + 16 + 8 + 32
	releaseMax     = releasePrefix + bundleHeader + 6*9 + sha256.Size
)

type sourceRelease struct {
	sourceIncarnation
	name          string
	manifest      SourceManifestV1
	record        []byte
	reopened      bool
	pending       bool
	backingSynced bool
}

// ReleaseUnpublishedSourceV1 holds the source charge through durable removal (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func (o *SourceOwnerV1) ReleaseUnpublishedSourceV1(account *mdbx.OperationAccount, p *PreparedSourceV1, neverReferenced bool) error {
	return o.operation(account, func() error {
		if err := o.releaseAdmission(p, neverReferenced); err != nil {
			if any(err) == any(ErrBusyV1) && o.debt.name == "" && o.stage.File != nil {
				_ = o.withRoot(o.bindRoot, o.retireStageWitness)
			}
			return err
		}
		return o.withRoot(o.bindRoot, func(r *sourceRoot) error {
			scratch := make([]byte, scratchBytes)
			if o.release == nil {
				if err := o.releaseCensus(r); err != nil {
					return err
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
	if p != nil && (cmp.Or(o.debt.name, o.pendingStage.name, o.observedStage) != "" || o.release != nil && o.release.name != p.name) {
		return ErrBusyV1
	}
	return nil
}

func (o *SourceOwnerV1) hasReleaseAuthority(p *PreparedSourceV1) bool {
	if p == nil {
		return o.release != nil && o.release.reopened
	}
	return p.incarnation != nil && p.incarnation.issued && o.live[p.name] == p.incarnation
}

func (o *SourceOwnerV1) releaseCensus(r *sourceRoot) error {
	used, err := o.census(r, true)
	err = used.admissionError(err)
	if err == nil && used.stage.held() {
		return ErrIntegrityV1
	}
	if err != nil || o.limits.Descriptors < 5 {
		o.rememberPublicStage(r, used, false)
	} else if o.adoptStage(r, used) != nil {
		o.observedStage = used.stage.name
	}
	return err
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

func readRelease(r *sourceRoot) ([]byte, error) {
	f, err := openSourceFile(r, releaseFile, nil)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	record := make([]byte, releaseMax+1)
	n, err := io.ReadFull(f, record)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, ErrIntegrityV1
	}
	return record[:n], nil
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
	f, err := openSourceFile(r, d.name, nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrIdentityV1
	}
	defer f.Close()
	_, err = o.qualify(f, d.manifest, d.size, scratch, &d.sourceIncarnation, ErrIdentityV1)
	return true, err
}

func (o *SourceOwnerV1) openRelease(r *sourceRoot) error {
	record, err := readRelease(r)
	if errors.Is(err, os.ErrNotExist) {
		return o.clearReleaseScratch(r)
	}
	if err != nil {
		return ErrIntegrityV1
	}
	o.release, err = o.decodeRelease(record)
	return err
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
	if _, err := o.space(r, uint64(len(d.record)), sourceDebt{}); err != nil {
		return err
	}
	if err := o.writeRelease(r, d.record); err != nil {
		return err
	}
	possiblyVisible, err := o.renameVisible(r, releaseScratch, releaseFile)
	if possiblyVisible {
		d.pending = err != nil
		o.release = d
	}
	return err
}

func (o *SourceOwnerV1) writeRelease(r *sourceRoot, record []byte) error {
	f, err := r.OpenFile(releaseScratch, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := sourceFileWriter{o: o, file: f}
	if _, err := w.Write(record); err != nil {
		return err
	}
	return cmp.Or(o.ops.chmod(f, 0o600), o.finishFile(f))
}

func (o *SourceOwnerV1) continueRelease(r *sourceRoot, scratch []byte) error {
	d := o.release
	if !d.backingSynced {
		if err := o.removeReleasedBacking(r, d, scratch); err != nil {
			return err
		}
		d.backingSynced = true
	}
	if err := o.clearReleaseMarker(r, d); err != nil {
		return err
	}
	if err := o.syncBoundRoot(r); err != nil {
		return err
	}
	if _, err := r.Lstat(d.name); !errors.Is(err, os.ErrNotExist) {
		return ErrIdentityV1
	}
	delete(o.live, d.name)
	o.release = nil
	return nil
}

// clearReleaseMarker removes a matching release record only after the backing name is observed absent.
func (o *SourceOwnerV1) clearReleaseMarker(r *sourceRoot, d *sourceRelease) error {
	if _, err := r.Lstat(d.name); !errors.Is(err, os.ErrNotExist) {
		return ErrIdentityV1
	}
	present, err := d.marker(r)
	if err != nil || !present {
		return err
	}
	return o.ops.remove(r.Root, releaseFile)
}

func (d *sourceRelease) marker(r *sourceRoot) (bool, error) {
	record, err := readRelease(r)
	if !errors.Is(err, os.ErrNotExist) && !bytes.Equal(record, d.record) {
		return false, ErrIntegrityV1
	}
	return err == nil, nil
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

func (o *SourceOwnerV1) removeReleasedBacking(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if err := o.releaseIntent(r, d, scratch); err != nil {
		return err
	}
	d.pending = false
	present, err := o.releaseBacking(r, d, scratch)
	if err != nil {
		return err
	}
	if present {
		if err := o.ops.remove(r.Root, d.name); err != nil {
			return err
		}
	}
	return o.ops.dirSync(r.pin)
}

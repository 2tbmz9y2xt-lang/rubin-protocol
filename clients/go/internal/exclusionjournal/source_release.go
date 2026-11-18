package exclusionjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
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
	name     string
	size     uint64
	file     filelock.IdentityV1
	footer   [32]byte
	manifest SourceManifestV1
	record   []byte
	reopened bool
	cleared  bool
}

// ReleaseUnpublishedSourceV1 removes an unpublished incarnation and holds its charge through directory sync.
func (o *SourceOwnerV1) ReleaseUnpublishedSourceV1(account *mdbx.OperationAccount, p *PreparedSourceV1, neverReferenced bool) error {
	return o.operation(account, func() error {
		if err := o.releaseAdmission(p, neverReferenced); err != nil {
			return err
		}
		r, err := o.root(false)
		if err != nil {
			return err
		}
		defer r.Close()
		scratch := make([]byte, scratchBytes)
		if o.release == nil {
			if err := o.beginRelease(r, p, scratch); err != nil {
				return err
			}
		}
		return o.continueRelease(r, scratch)
	})
}

func (o *SourceOwnerV1) releaseAdmission(p *PreparedSourceV1, proof bool) error {
	if !proof || !o.hasReleaseAuthority(p) {
		return ErrIntegrityV1
	}
	if p != nil && (o.debt != nil || o.release != nil && o.release.name != p.name) {
		return ErrBusyV1
	}
	return nil
}

func (o *SourceOwnerV1) hasReleaseAuthority(p *PreparedSourceV1) bool {
	if p == nil {
		return o.release != nil && o.release.reopened
	}
	return p.owner == o && p.incarnation != nil && o.live[p.name] == p.incarnation
}

func (o *SourceOwnerV1) beginRelease(r *sourceRoot, p *PreparedSourceV1, scratch []byte) error {
	if _, _, err := o.census(r); err != nil {
		return err
	}
	size, _ := p.manifest.SizeV1()
	d := &sourceRelease{name: p.name, size: size, file: p.incarnation.file, manifest: p.manifest}
	footer, present, err := o.releaseDigest(r, d, scratch)
	if err != nil {
		return err
	}
	if !present {
		return ErrIdentityV1
	}
	d.footer = footer
	d.record = o.releaseRecord(d)
	return o.persistRelease(r, d)
}

func (o *SourceOwnerV1) releaseRecord(d *sourceRelease) []byte {
	root := filelock.FileIdentityV1(o.info)
	record := append(make([]byte, 0, releaseMax), 'S', 'R', 'V', 1)
	for _, field := range [...]uint64{root[0], root[1], d.file[0], d.file[1], d.size} {
		record = binary.LittleEndian.AppendUint64(record, field)
	}
	record = append(record, d.footer[:]...)
	record = append(record, d.manifest.header(o.id)...)
	digest := sha256.Sum256(record)
	return append(record, digest[:]...)
}

func readRelease(r *sourceRoot) ([]byte, error) {
	f, err := r.OpenFile(releaseFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > releaseMax {
		return nil, ErrIntegrityV1
	}
	record, err := io.ReadAll(io.LimitReader(f, releaseMax+1))
	if err != nil || len(record) > releaseMax {
		return nil, ErrIntegrityV1
	}
	return record, nil
}

func (o *SourceOwnerV1) decodeRelease(record []byte) (*sourceRelease, error) {
	if len(record) < releasePrefix+bundleHeader+sha256.Size || !bytes.Equal(record[:4], []byte{'S', 'R', 'V', 1}) {
		return nil, ErrIntegrityV1
	}
	end := len(record) - sha256.Size
	digest := sha256.Sum256(record[:end])
	if !bytes.Equal(digest[:], record[end:]) {
		return nil, ErrIntegrityV1
	}
	if filelock.FileIdentityV1(o.info) != releaseIdentity(record[4:]) {
		return nil, ErrIdentityV1
	}
	header := record[releasePrefix:end]
	m, err := o.releaseManifest(header)
	if err != nil {
		return nil, err
	}
	d := &sourceRelease{name: m.name(o.id), manifest: m, file: releaseIdentity(record[20:]), size: binary.LittleEndian.Uint64(record[36:]), record: record, reopened: true}
	copy(d.footer[:], record[44:releasePrefix])
	if size, _ := m.SizeV1(); size != d.size || d.file == (filelock.IdentityV1{}) {
		return nil, ErrIntegrityV1
	}
	return d, nil
}

func releaseIdentity(record []byte) filelock.IdentityV1 {
	return filelock.IdentityV1{binary.LittleEndian.Uint64(record), binary.LittleEndian.Uint64(record[8:])}
}

func (o *SourceOwnerV1) releaseManifest(header []byte) (SourceManifestV1, error) {
	const identityOffset = bundleHeader - 66
	var m SourceManifestV1
	if !bytes.Equal(header[:4], []byte{'S', 'C', 'V', 1}) {
		return m, ErrIntegrityV1
	}
	if !bytes.Equal(header[4:identityOffset], m.header(o.id)[4:identityOffset]) {
		return m, ErrIdentityV1
	}
	copy(m.Identity[:], header[identityOffset:])
	copy(m.AcquiredDigest[:], header[identityOffset+32:])
	m.Class = CaptureClassV1(header[bundleHeader-2])
	count := int(header[bundleHeader-1])
	if count > 6 || len(header) != bundleHeader+9*count {
		return m, ErrIntegrityV1
	}
	for offset := bundleHeader; offset < len(header); offset += 9 {
		m.Parts = append(m.Parts, SourcePartSpecV1{PartKindV1(header[offset]), binary.LittleEndian.Uint64(header[offset+1:])})
	}
	_, err := m.SizeV1()
	return m, err
}

func (o *SourceOwnerV1) releaseDigest(r *sourceRoot, d *sourceRelease, scratch []byte) ([32]byte, bool, error) {
	var zero [32]byte
	f, err := r.OpenFile(d.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, ErrIdentityV1
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || filelock.FileIdentityV1(info) != d.file || info.Size() != int64(min(d.size, math.MaxInt64)) {
		return zero, false, ErrIdentityV1
	}
	footer, err := o.qualify(f, d.manifest, scratch)
	return footer, true, err
}

func (o *SourceOwnerV1) releaseBacking(r *sourceRoot, d *sourceRelease, scratch []byte) (bool, error) {
	footer, present, err := o.releaseDigest(r, d, scratch)
	if err == nil && present && footer != d.footer {
		return false, ErrIntegrityV1
	}
	return present, err
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
	info, err := r.Lstat(releaseScratch)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > releaseMax {
		return ErrIntegrityV1
	}
	if err := o.ops.remove(r.Root, releaseScratch); err != nil {
		return err
	}
	return o.ops.dirSync(r)
}

func (o *SourceOwnerV1) persistRelease(r *sourceRoot, d *sourceRelease) error {
	if err := o.space(r, uint64(len(d.record))); err != nil {
		return err
	}
	if err := o.clearReleaseScratch(r); err != nil {
		return err
	}
	if err := o.writeRelease(r, d.record); err != nil {
		return err
	}
	err := o.ops.rename(r.Root, releaseScratch, releaseFile)
	if _, statErr := r.Lstat(releaseFile); err == nil || !errors.Is(statErr, os.ErrNotExist) {
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
	return o.finishFile(f)
}

func (o *SourceOwnerV1) continueRelease(r *sourceRoot, scratch []byte) error {
	d := o.release
	if !d.cleared {
		if err := o.removeReleasedBacking(r, d, scratch); err != nil {
			return err
		}
		err := o.ops.remove(r.Root, releaseFile)
		if err != nil {
			_, statErr := r.Lstat(releaseFile)
			d.cleared = errors.Is(statErr, os.ErrNotExist)
			return err
		}
		d.cleared = true
	}
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	if _, err := r.Lstat(d.name); !errors.Is(err, os.ErrNotExist) {
		return ErrIdentityV1
	}
	delete(o.live, d.name)
	o.release = nil
	return nil
}

func (o *SourceOwnerV1) removeReleasedBacking(r *sourceRoot, d *sourceRelease, scratch []byte) error {
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	if err := o.currentRoot(); err != nil {
		return err
	}
	record, err := readRelease(r)
	if err != nil || !bytes.Equal(record, d.record) {
		return ErrIntegrityV1
	}
	present, err := o.releaseBacking(r, d, scratch)
	if err != nil {
		return err
	}
	if present {
		if err := o.ops.remove(r.Root, d.name); err != nil {
			return err
		}
	}
	return o.ops.dirSync(r)
}

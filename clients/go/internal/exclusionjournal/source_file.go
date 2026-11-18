package exclusionjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"os"
	"slices"
	"syscall"
)

type sourceFS struct {
	statfs          func(int, *syscall.Statfs_t) error
	write           func(*os.File, []byte) (int, error)
	fileSync, close func(*os.File) error
	rename          func(*os.Root, string, string) error
	remove          func(*os.Root, string) error
	dirSync         func(*sourceRoot) error
}
type sourceDebt struct {
	name                      string
	size                      uint64
	staging, removed, release bool
}

var realSourceFS = sourceFS{statfs: syscall.Fstatfs, write: (*os.File).Write, fileSync: (*os.File).Sync, close: (*os.File).Close, rename: (*os.Root).Rename, remove: (*os.Root).Remove, dirSync: syncSourceRoot}

type sourceRoot struct {
	*os.Root
	pin *os.File
}

func (r *sourceRoot) Close() error { return errors.Join(r.pin.Close(), r.Root.Close()) }

// root anchors every source effect to checked parent and source-directory descriptors.
func (o *SourceOwnerV1) root(create bool) (*sourceRoot, error) {
	parent, err := os.OpenRoot(o.dir)
	if err != nil {
		return nil, ErrIdentityV1
	}
	defer parent.Close()
	parentInfo, err := parent.Stat(".")
	if err != nil || !os.SameFile(o.parent, parentInfo) {
		return nil, ErrIdentityV1
	}
	if create {
		if err := createSourceRoot(parent); err != nil {
			return nil, err
		}
	}
	return o.bindRoot(parent)
}

// createSourceRoot durably creates only the fixed protected child.
func createSourceRoot(parent *os.Root) error {
	if err := parent.Mkdir(sourceDirectory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	f, err := parent.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// bindRoot checks the actual descriptor against the original admitted directory.
func (o *SourceOwnerV1) bindRoot(parent *os.Root) (*sourceRoot, error) {
	leaf, err := sourceRootInfo(parent)
	if err != nil {
		return nil, err
	}
	r, err := parent.OpenRoot(sourceDirectory)
	if err != nil {
		return nil, ErrUnavailableV1
	}
	info, err := r.Stat(".")
	if err != nil || !os.SameFile(leaf, info) {
		_ = r.Close()
		return nil, ErrIdentityV1
	}
	if o.info != nil && !os.SameFile(o.info, info) {
		_ = r.Close()
		return nil, ErrIdentityV1
	}
	o.info = info
	pin, err := r.Open(".")
	if err != nil {
		_ = r.Close()
		return nil, ErrUnavailableV1
	}
	return &sourceRoot{Root: r, pin: pin}, nil
}

// sourceRootInfo rejects a link, non-directory or unprotected root before opening it.
func sourceRootInfo(parent *os.Root) (os.FileInfo, error) {
	info, err := parent.Lstat(sourceDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, ErrIdentityV1
	}
	return info, nil
}

// openSourceRoot binds the new owner only after a complete bounded directory census.
func (o *SourceOwnerV1) openSourceRoot() error {
	r, err := o.root(true)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	_, _, err = o.census(r)
	return err
}

// syncSourceRoot synchronizes the same directory inode used for anchored effects.
func syncSourceRoot(r *sourceRoot) error { return r.pin.Sync() }

// census includes every reached file owner and any unlinked release-only debt.
func (o *SourceOwnerV1) census(r *sourceRoot) (uint64, uint64, error) {
	entries, err := o.censusEntries(r)
	if err != nil {
		return 0, 0, err
	}
	var count, size uint64
	for _, entry := range entries {
		n, err := o.censusFile(r, entry.Name(), size)
		if err != nil {
			return 0, 0, err
		}
		size += n
		count++
	}
	if o.debt != nil && o.debt.removed {
		if o.debt.size > o.limits.Bytes-size {
			return 0, 0, ErrCapacityV1
		}
		count++
		size += o.debt.size
	}
	if count > o.limits.Files {
		return 0, 0, ErrCapacityV1
	}
	return count, size, nil
}

// censusEntries bounds directory metadata before enumerating retained owners.
func (o *SourceOwnerV1) censusEntries(r *sourceRoot) ([]os.DirEntry, error) {
	f, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if o.limits.Scans > math.MaxInt {
		return nil, ErrCapacityV1
	}
	entries, err := f.ReadDir(int(o.limits.Scans))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if uint64(len(entries)) >= o.limits.Scans {
		return nil, ErrCapacityV1
	}
	return entries, nil
}

// censusFile adds only regular finite backing and preserves any reached staging owner.
func (o *SourceOwnerV1) censusFile(r *sourceRoot, name string, retained uint64) (uint64, error) {
	info, err := r.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return 0, ErrIntegrityV1
	}
	size := info.Size()
	if size < 0 {
		return 0, ErrIntegrityV1
	}
	if err := o.censusEntry(name, uint64(size)); err != nil {
		return 0, err
	}
	if uint64(size) > o.limits.Bytes-retained {
		return 0, ErrCapacityV1
	}
	return uint64(size), nil
}

// censusEntry recognizes retained files and the one charged staging owner without deleting anything.
func (o *SourceOwnerV1) censusEntry(name string, size uint64) error {
	staging := len(name) == 73 && name[:9] == ".staging-"
	if staging {
		name = name[9:]
	}
	decoded, err := hex.DecodeString(name)
	switch {
	case err != nil, len(decoded) != 32:
		return ErrIntegrityV1
	}
	if !staging {
		return nil
	}
	if o.debt != nil && o.debt.name != name {
		return ErrBusyV1
	}
	if o.debt == nil {
		o.debt = &sourceDebt{name: name, size: size, staging: true}
	}
	return nil
}

// space qualifies descriptor-bound finite available bytes before the first payload read.
func (o *SourceOwnerV1) space(r *sourceRoot, required uint64) error {
	var stat syscall.Statfs_t
	if err := o.ops.statfs(int(r.pin.Fd()), &stat); err != nil {
		return ErrCapacityV1
	}
	if stat.Bsize <= 0 || stat.Bavail > math.MaxUint64/uint64(stat.Bsize) {
		return ErrCapacityV1
	}
	if required > math.MaxUint64-o.limits.Overhead || uint64(stat.Bavail)*uint64(stat.Bsize) < required+o.limits.Overhead {
		return ErrCapacityV1
	}
	current, err := os.Lstat(o.dir + string(os.PathSeparator) + sourceDirectory)
	if err != nil || !os.SameFile(o.info, current) {
		return ErrCapacityV1
	}
	return nil
}

// assurance checks only the closed private framing of opaque original assurance payloads.
func assurance(part SourcePartV1) error {
	var field [8]byte
	switch n, err := part.ReadAt(field[:1], 0); {
	case n != 1, err != nil:
		return ErrIntegrityV1
	}
	if field[0] == 1 && part.Length == 1 {
		return nil
	}
	if field[0] != 2 {
		return ErrIntegrityV1
	}
	offset := uint64(1)
	for range 4 {
		next, err := assuranceField(part, offset)
		if err != nil {
			return err
		}
		offset = next
	}
	if offset != part.Length {
		return ErrIntegrityV1
	}
	return nil
}

// assuranceField consumes one nonempty opaque conditional field with checked framing.
func assuranceField(part SourcePartV1, offset uint64) (uint64, error) {
	if offset > math.MaxInt64 || offset > part.Length || part.Length-offset < 8 {
		return 0, ErrIntegrityV1
	}
	var field [8]byte
	if n, err := part.ReadAt(field[:], int64(offset)); n != 8 || err != nil {
		return 0, ErrIntegrityV1
	}
	length := binary.LittleEndian.Uint64(field[:])
	offset += 8
	if length == 0 || length > part.Length-offset {
		return 0, ErrIntegrityV1
	}
	return offset + length, nil
}

// stream checks the exact exporter and acquisition digest while retaining original payload owners.
func stream(m SourceManifestV1, producer SourceExporterV1, dst io.Writer) error {
	acquired := sha256.New()
	scratch := make([]byte, scratchBytes/2)
	err := export(m, producer, func(part SourcePartV1) error {
		if part.Kind == OriginalAssuranceV1 {
			if err := assurance(part); err != nil {
				return err
			}
		}
		out := dst
		if part.Kind == AcquiredBlockBytesV1 {
			out = io.MultiWriter(dst, acquired)
		}
		return copyPart(part, out, scratch)
	})
	if err != nil {
		return err
	}
	if m.Class == RecoveryCoreImpossibleV1 && !bytes.Equal(acquired.Sum(nil), m.AcquiredDigest[:]) {
		return ErrIntegrityV1
	}
	return nil
}

// qualify reads and verifies the actual complete file before any foreign visitor sees it.
func (o *SourceOwnerV1) qualify(f *os.File, m SourceManifestV1) error {
	actual, size, err := o.sourceFileHeader(f, m)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, _ = hash.Write(actual)
	if err := stream(m, fileExporter(f, m, len(actual)), hash); err != nil {
		return err
	}
	var footer [32]byte
	if _, err = f.ReadAt(footer[:], size-32); err != nil || !bytes.Equal(hash.Sum(nil), footer[:]) {
		return ErrIntegrityV1
	}
	return nil
}

// sourceFileHeader checks complete file size and every fixed manifest field before payload reads.
func (o *SourceOwnerV1) sourceFileHeader(f *os.File, m SourceManifestV1) ([]byte, int64, error) {
	size, err := m.SizeV1()
	if err != nil || size > math.MaxInt64 {
		return nil, 0, ErrIntegrityV1
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(size) {
		return nil, 0, ErrIntegrityV1
	}
	header := m.header(o.id)
	actual := make([]byte, len(header))
	if _, err = f.ReadAt(actual, 0); err != nil || !bytes.Equal(actual, header) {
		return nil, 0, ErrIntegrityV1
	}
	return actual, int64(size), nil
}

// fileExporter retains the file only inside its enclosing qualified source operation.
func fileExporter(f *os.File, m SourceManifestV1, header int) SourceExporterV1 {
	return func(visit func(SourcePartV1) error) error {
		offset := int64(header)
		for _, spec := range m.Parts {
			if spec.Length > math.MaxInt64 {
				return ErrIntegrityV1
			}
			base := offset
			part := SourcePartV1{Kind: spec.Kind, Length: spec.Length, ReadAt: func(dst []byte, off int64) (int, error) { return f.ReadAt(dst, base+off) }}
			if err := visitPart(part, visit); err != nil {
				return err
			}
			offset += int64(spec.Length)
		}
		return nil
	}
}

// WithCapturedSourceV1 freshly opens and qualifies original identity, version, lengths and bytes on every use.
// Missing or corrupt backing refuses as unavailable or integrity with the retained owner unchanged.
func (o *SourceOwnerV1) WithCapturedSourceV1(account OperationAccountV1, m SourceManifestV1, visit func(SourcePartV1) error) error {
	return o.withFiles(account, m, func(r *sourceRoot) error {
		if o.debt != nil && o.debt.name == m.name(o.id) {
			return ErrBusyV1
		}
		f, err := r.OpenFile(m.name(o.id), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrUnavailableV1
		}
		defer f.Close()
		if err := o.qualify(f, m); err != nil {
			return err
		}
		return export(m, fileExporter(f, m, len(m.header(o.id))), visit)
	})
}

// withFiles shares one source borrow/account with the bounded anchored filesystem operation.
func (o *SourceOwnerV1) withFiles(account OperationAccountV1, m SourceManifestV1, use func(*sourceRoot) error) error {
	return o.operation(account, func() error {
		if err := o.admitManifest(m); err != nil {
			return err
		}
		r, err := o.root(false)
		if err != nil {
			return err
		}
		defer r.Close()
		if _, _, err = o.census(r); err != nil {
			return err
		}
		return use(r)
	})
}

// reconcile returns disk charges only after unlink and parent synchronization both succeed.
func (o *SourceOwnerV1) reconcile(r *sourceRoot) error {
	d := o.debt
	if d == nil {
		return nil
	}
	if !d.removed {
		name := d.name
		if d.staging {
			name = ".staging-" + name
		}
		if err := o.ops.remove(r.Root, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		d.removed = true
	}
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	o.debt = nil
	return nil
}

// PrepareSourceV1 returns a resource owner only after qualified bytes, file sync/close, publication and parent sync.
// It grants no journal reference or transfer; refusal retains reached backing and the caller's original inputs.
func (o *SourceOwnerV1) PrepareSourceV1(account OperationAccountV1, m SourceManifestV1, producer SourceExporterV1) (prepared *PreparedSourceV1, err error) {
	err = o.withFiles(account, m, func(r *sourceRoot) error {
		size, _ := m.SizeV1()
		name := m.name(o.id)
		if e := o.retrySource(r, name); e != nil {
			return e
		}
		if f, openErr := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0); openErr == nil {
			defer f.Close()
			return o.reuse(r, f, m, producer, &prepared)
		} else if !errors.Is(openErr, os.ErrNotExist) {
			return ErrIntegrityV1
		}
		if e := o.admitCapture(r, size); e != nil {
			return e
		}
		if e := o.publish(r, m, producer, size); e != nil {
			return e
		}
		prepared = o.prepared(m)
		return nil
	})
	return prepared, err
}

// retrySource completes only this immutable source's cleanup or same-file durability reconciliation.
func (o *SourceOwnerV1) retrySource(r *sourceRoot, name string) error {
	if o.debt == nil {
		return nil
	}
	if o.debt.name != name || o.debt.release {
		return ErrBusyV1
	}
	if o.debt.staging || o.debt.removed {
		return o.reconcile(r)
	}
	_, err := r.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		o.debt.staging = true
		return o.reconcile(r)
	}
	if err != nil {
		return ErrUnavailableV1
	}
	return nil
}

// admitCapture counts retained owners before new disk effects or payload reads.
func (o *SourceOwnerV1) admitCapture(r *sourceRoot, size uint64) error {
	count, retained, err := o.census(r)
	if err != nil {
		return err
	}
	if count >= o.limits.Files || size > o.limits.Bytes-retained {
		return ErrCapacityV1
	}
	return o.space(r, size)
}

// prepared copies the finite manifest rather than retaining caller metadata.
func (o *SourceOwnerV1) prepared(m SourceManifestV1) *PreparedSourceV1 {
	m.Parts = slices.Clone(m.Parts)
	return &PreparedSourceV1{owner: o, manifest: m, name: m.name(o.id)}
}

// publish keeps a charged cleanup or reconciliation owner through every failure and panic.
func (o *SourceOwnerV1) publish(r *sourceRoot, m SourceManifestV1, producer SourceExporterV1, size uint64) (err error) {
	name := m.name(o.id)
	f, err := r.OpenFile(".staging-"+name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	o.debt = &sourceDebt{name: name, size: size, staging: true}
	defer func() {
		_ = f.Close()
		if o.debt != nil && o.debt.staging {
			if cleanup := o.reconcile(r); cleanup != nil {
				err = errors.Join(err, cleanup)
			}
		}
	}()
	if err := o.writeBundle(f, m, producer); err != nil {
		return err
	}
	if err := o.finishFile(f); err != nil {
		return err
	}
	if err := o.publishName(r, name); err != nil {
		return err
	}
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	o.debt = nil
	return nil
}

// finishFile ends file durability before identity publication or parent synchronization.
func (o *SourceOwnerV1) finishFile(f *os.File) error {
	if err := o.ops.fileSync(f); err != nil {
		return err
	}
	return o.ops.close(f)
}

// writeBundle qualifies the complete emitted file before its first durability effect.
func (o *SourceOwnerV1) writeBundle(f *os.File, m SourceManifestV1, producer SourceExporterV1) error {
	hash := sha256.New()
	out := io.MultiWriter(sourceFileWriter{o: o, file: f}, hash)
	if _, err := out.Write(m.header(o.id)); err != nil {
		return err
	}
	if err := stream(m, producer, out); err != nil {
		return err
	}
	if _, err := o.ops.write(f, hash.Sum(nil)); err != nil {
		return err
	}
	return o.qualify(f, m)
}

type sourceFileWriter struct {
	o    *SourceOwnerV1
	file *os.File
}

// Write retains the actual file owner and propagates partial writes unchanged.
func (w sourceFileWriter) Write(data []byte) (int, error) { return w.o.ops.write(w.file, data) }

// publishName retains ambiguous post-rename backing for exact same-identity reconciliation.
func (o *SourceOwnerV1) publishName(r *sourceRoot, name string) error {
	err := o.ops.rename(r.Root, ".staging-"+name, name)
	if err == nil {
		o.debt.staging = false
		return nil
	}
	if _, statErr := r.Lstat(name); !errors.Is(statErr, os.ErrNotExist) {
		o.debt.staging = false
	}
	return err
}

type compareSourceWriter struct {
	file    *os.File
	offset  int64
	scratch []byte
}

// Write compares the immutable input to existing backing without overwriting or a second file.
func (w *compareSourceWriter) Write(data []byte) (int, error) {
	scratch := w.scratch[:len(data)]
	if _, err := w.file.ReadAt(scratch, w.offset); err != nil || !bytes.Equal(data, scratch) {
		return 0, ErrIntegrityV1
	}
	w.offset += int64(len(data))
	return len(data), nil
}

// reuse reconciles the existing same-identity file against the same immutable export and completes durability.
func (o *SourceOwnerV1) reuse(r *sourceRoot, f *os.File, m SourceManifestV1, producer SourceExporterV1, result **PreparedSourceV1) error {
	if err := o.qualify(f, m); err != nil {
		return err
	}
	if err := stream(m, producer, &compareSourceWriter{file: f, offset: int64(len(m.header(o.id))), scratch: make([]byte, scratchBytes/2)}); err != nil {
		return err
	}
	if err := o.finishFile(f); err != nil {
		return err
	}
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	o.debt = nil
	*result = o.prepared(m)
	return nil
}

// ReleaseUnpublishedSourceV1 requires positive never-referenced reconciliation and no live export.
// Failed unlink or parent sync retains a charged release-only owner and blocks preparation.
func (o *SourceOwnerV1) ReleaseUnpublishedSourceV1(account OperationAccountV1, p *PreparedSourceV1, neverReferenced bool) error {
	return o.operation(account, func() error {
		if err := o.releaseAdmission(p, neverReferenced); err != nil {
			return err
		}
		r, err := o.root(false)
		if err != nil {
			return err
		}
		defer r.Close()
		size, err := p.manifest.SizeV1()
		if err != nil {
			return err
		}
		if o.debt == nil {
			o.debt = &sourceDebt{name: p.name, size: size, release: true}
		}
		if err := o.reconcile(r); err != nil {
			return err
		}
		p.released = true
		return nil
	})
}

// releaseAdmission preserves prepared-owner refusal before release-only debt admission.
func (o *SourceOwnerV1) releaseAdmission(p *PreparedSourceV1, neverReferenced bool) error {
	if p == nil || p.owner != o || p.released || !neverReferenced {
		return ErrIntegrityV1
	}
	if o.debt != nil && (o.debt.name != p.name || !o.debt.release) {
		return ErrBusyV1
	}
	return nil
}

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
	"syscall"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
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
	name             string
	size             uint64
	staging, removed bool
}

var realSourceFS = sourceFS{statfs: syscall.Fstatfs, write: (*os.File).Write, fileSync: (*os.File).Sync, close: (*os.File).Close, rename: (*os.Root).Rename, remove: (*os.Root).Remove, dirSync: syncSourceRoot}

type sourceRoot struct {
	*os.Root
	pin *os.File
}

func (r *sourceRoot) Close() error { return errors.Join(r.pin.Close(), r.Root.Close()) }

func (o *SourceOwnerV1) root(create bool) (*sourceRoot, error) {
	parent, err := o.parentRoot()
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if create {
		if err := createSourceRoot(parent); err != nil {
			return nil, err
		}
	}
	return o.bindRoot(parent)
}

func (o *SourceOwnerV1) parentRoot() (*os.Root, error) {
	parent, err := os.OpenRoot(o.dir)
	if err != nil {
		return nil, ErrIdentityV1
	}
	info, err := parent.Stat(".")
	if err != nil || o.parent != filelock.FileIdentityV1(info) {
		_ = parent.Close()
		return nil, ErrIdentityV1
	}
	return parent, nil
}

// currentRoot checks that the held roots remain reachable through their admitted names.
func (o *SourceOwnerV1) currentRoot() error {
	parent, err := o.parentRoot()
	if err != nil {
		return err
	}
	defer parent.Close()
	leaf, err := sourceRootInfo(parent)
	if err != nil || !os.SameFile(leaf, o.info) {
		return ErrIdentityV1
	}
	current, err := os.Lstat(o.dir)
	if err != nil || !current.IsDir() || o.parent != filelock.FileIdentityV1(current) {
		return ErrIdentityV1
	}
	return nil
}

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

func (o *SourceOwnerV1) bindRoot(parent *os.Root) (*sourceRoot, error) {
	leaf, err := sourceRootInfo(parent)
	if err != nil {
		return nil, err
	}
	r, err := parent.OpenRoot(sourceDirectory)
	if err != nil {
		return nil, ErrUnavailableV1
	}
	pin, err := r.Open(".")
	if err != nil {
		_ = r.Close()
		return nil, ErrUnavailableV1
	}
	root := &sourceRoot{Root: r, pin: pin}
	held, err := pin.Stat()
	if err != nil || !os.SameFile(leaf, held) || o.info != nil && !os.SameFile(o.info, held) {
		_ = root.Close()
		return nil, ErrIdentityV1
	}
	o.info = held
	return root, nil
}

func sourceRootInfo(parent *os.Root) (os.FileInfo, error) {
	info, err := parent.Lstat(sourceDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, ErrIdentityV1
	}
	return info, nil
}

func (o *SourceOwnerV1) openSourceRoot() error {
	r, err := o.root(true)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	if err := o.openRelease(r); err != nil {
		return err
	}
	if _, _, err = o.census(r); err != nil {
		return err
	}
	if o.release != nil {
		if err := o.admitManifest(o.release.manifest); err != nil {
			return err
		}
		_, err = o.releaseBacking(r, o.release, make([]byte, scratchBytes))
	}
	return err
}

func syncSourceRoot(r *sourceRoot) error { return r.pin.Sync() }

// census includes every reached file owner and any unlinked release-only debt.
func (o *SourceOwnerV1) census(r *sourceRoot) (uint64, uint64, error) {
	entries, err := o.censusEntries(r)
	if err != nil {
		return 0, 0, err
	}
	var count, size uint64
	releasePresent := false
	for _, entry := range entries {
		name := entry.Name()
		if name == releaseFile || name == releaseScratch {
			if name == releaseFile && o.release == nil {
				return 0, 0, ErrIntegrityV1
			}
			continue
		}
		n, err := o.censusFile(r, name, size)
		if err != nil {
			return 0, 0, err
		}
		size += n
		count++
		releasePresent = releasePresent || o.release != nil && name == o.release.name
	}
	count, size = o.includeAbsent(count, size, releasePresent)
	if count > o.limits.Files || size > o.limits.Bytes {
		return 0, 0, ErrCapacityV1
	}
	return count, size, nil
}

func (o *SourceOwnerV1) includeAbsent(count, size uint64, releasePresent bool) (uint64, uint64) {
	if o.debt != nil && o.debt.removed {
		if o.debt.size > o.limits.Bytes-size {
			return count, math.MaxUint64
		}
		count++
		size += o.debt.size
	}
	if o.release != nil && !releasePresent {
		if o.release.size > o.limits.Bytes-size {
			return count, math.MaxUint64
		}
		count++
		size += o.release.size
	}
	return count, size
}

func (o *SourceOwnerV1) censusEntries(r *sourceRoot) ([]os.DirEntry, error) {
	f, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(int(o.limits.Scans))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if uint64(len(entries)) >= o.limits.Scans {
		return nil, ErrCapacityV1
	}
	return entries, nil
}

func (o *SourceOwnerV1) censusFile(r *sourceRoot, name string, retained uint64) (uint64, error) {
	info, err := r.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
		return 0, ErrIntegrityV1
	}
	size := uint64(info.Size())
	if err := o.censusEntry(name, size); err != nil {
		return 0, err
	}
	if size > o.limits.Bytes-retained {
		return 0, ErrCapacityV1
	}
	return size, nil
}

func (o *SourceOwnerV1) censusEntry(name string, size uint64) error {
	staging := len(name) == 73 && name[:9] == ".staging-"
	if staging {
		name = name[9:]
	}
	decoded, err := hex.DecodeString(name)
	if err != nil || len(decoded) != 32 {
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
	} else if !o.debt.removed {
		o.debt.staging = true
		o.debt.size = size
	}
	return nil
}

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
	if o.currentRoot() != nil {
		return ErrCapacityV1
	}
	return nil
}

func assurance(part SourcePartV1) error {
	var field [8]byte
	if n, err := part.ReadAt(field[:1], 0); n != 1 || err != nil {
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

func stream(m SourceManifestV1, produce func(func(SourcePartV1) error) error, dst io.Writer, scratch []byte) error {
	acquired := sha256.New()
	err := produce(func(part SourcePartV1) error {
		if part.Kind == OriginalAssuranceV1 {
			if err := assurance(part); err != nil {
				return err
			}
		}
		if part.Kind == AcquiredBlockBytesV1 {
			return copyPart(part, io.MultiWriter(dst, acquired), scratch)
		}
		return copyPart(part, dst, scratch)
	})
	if err != nil {
		return err
	}
	if m.Class == RecoveryCoreImpossibleV1 && !bytes.Equal(acquired.Sum(nil), m.AcquiredDigest[:]) {
		return ErrIntegrityV1
	}
	return nil
}

func (o *SourceOwnerV1) qualify(f *os.File, m SourceManifestV1, scratch []byte) ([32]byte, error) {
	var footer [32]byte
	actual, size, err := o.sourceFileHeader(f, m)
	if err != nil {
		return footer, err
	}
	hash := sha256.New()
	_, _ = hash.Write(actual)
	if err := stream(m, fileExporter(f, m, len(actual)), hash, scratch); err != nil {
		return footer, err
	}
	if _, err = f.ReadAt(footer[:], size-32); err != nil || !bytes.Equal(hash.Sum(nil), footer[:]) {
		return [32]byte{}, ErrIntegrityV1
	}
	return footer, nil
}

func (o *SourceOwnerV1) sourceFileHeader(f *os.File, m SourceManifestV1) ([]byte, int64, error) {
	size, err := m.SizeV1()
	if err != nil {
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

func fileExporter(f *os.File, m SourceManifestV1, header int) func(func(SourcePartV1) error) error {
	return func(visit func(SourcePartV1) error) error {
		offset := int64(header)
		for _, spec := range m.Parts {
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

// WithCapturedSourceV1 opens and qualifies the retained file before visiting its parts.
func (o *SourceOwnerV1) WithCapturedSourceV1(account *mdbx.OperationAccount, m SourceManifestV1, visit func(SourcePartV1) error) error {
	return o.withFiles(account, m, func(r *sourceRoot, m SourceManifestV1, _, _ uint64) error {
		name := m.name(o.id)
		if o.debt != nil && o.debt.name == name || o.release != nil && o.release.name == name {
			return ErrBusyV1
		}
		if visit == nil {
			return ErrIntegrityV1
		}
		f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrUnavailableV1
		}
		defer f.Close()
		if _, err := o.qualify(f, m, make([]byte, scratchBytes)); err != nil {
			return err
		}
		return fileExporter(f, m, len(m.header(o.id)))(visit)
	})
}

func (o *SourceOwnerV1) withFiles(account *mdbx.OperationAccount, m SourceManifestV1, use func(*sourceRoot, SourceManifestV1, uint64, uint64) error) error {
	return o.withManifest(account, m, func(r *sourceRoot, m SourceManifestV1) error {
		count, size, err := o.census(r)
		if err != nil {
			return err
		}
		return use(r, m, count, size)
	})
}

// reconcile returns disk charges only after unlink and parent synchronization both succeed.
func (o *SourceOwnerV1) reconcile(r *sourceRoot) error {
	d := o.debt
	if d == nil {
		return nil
	}
	if !d.removed {
		name := ".staging-" + d.name
		if info, err := r.Lstat(name); err == nil && info.Mode().IsRegular() {
			d.size = uint64(info.Size())
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

// PrepareSourceV1 returns an incarnation handle after qualifying and durably publishing the source.
func (o *SourceOwnerV1) PrepareSourceV1(account *mdbx.OperationAccount, m SourceManifestV1, producer SourceExporterV1) (prepared *PreparedSourceV1, err error) {
	err = o.withFiles(account, m, func(r *sourceRoot, m SourceManifestV1, count, retained uint64) error {
		prepared, err = o.prepare(r, m, count, retained, func(visit func(SourcePartV1) error) error {
			return o.export(account, m, producer, visit)
		})
		return err
	})
	return prepared, err
}

func (o *SourceOwnerV1) prepare(r *sourceRoot, m SourceManifestV1, count, retained uint64, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	name := m.name(o.id)
	if o.release != nil || o.debt != nil && o.debt.name != name {
		return nil, ErrBusyV1
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		defer f.Close()
		return o.reuse(r, f, m, produce)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrIntegrityV1
	}
	size, _ := m.SizeV1()
	if d := o.debt; d != nil && (d.removed || d.staging && stagingExists(r, name)) {
		count--
		retained -= d.size
	}
	if count >= o.limits.Files || size > o.limits.Bytes-retained {
		return nil, ErrCapacityV1
	}
	if err := o.space(r, size); err != nil {
		return nil, err
	}
	return o.publish(r, m, produce, size)
}

func stagingExists(r *sourceRoot, name string) bool {
	_, err := r.Lstat(".staging-" + name)
	return err == nil
}

func (o *SourceOwnerV1) prepared(r *sourceRoot, m SourceManifestV1, file filelock.IdentityV1) (*PreparedSourceV1, error) {
	name := m.name(o.id)
	info, err := r.Lstat(name)
	if err != nil || file != filelock.FileIdentityV1(info) || o.currentRoot() != nil {
		return nil, ErrIdentityV1
	}
	o.debt = nil
	if o.live == nil {
		o.live = make(map[string]*sourceIncarnation)
	}
	token := o.live[name]
	if token == nil || token.file != file {
		token = &sourceIncarnation{file: file}
		o.live[name] = token
	}
	return &PreparedSourceV1{owner: o, manifest: m, name: name, incarnation: token}, nil
}

func (o *SourceOwnerV1) publish(r *sourceRoot, m SourceManifestV1, produce func(func(SourcePartV1) error) error, size uint64) (_ *PreparedSourceV1, err error) {
	name := m.name(o.id)
	w := &sourceFileWriter{o: o}
	defer func() {
		if w.file != nil {
			_ = w.file.Close()
		}
		if w.file != nil && o.debt != nil && o.debt.staging {
			if cleanup := o.reconcile(r); cleanup != nil {
				err = errors.Join(err, cleanup)
			}
		}
	}()
	if err := o.writeBundle(r, w, m, produce, size); err != nil {
		return nil, err
	}
	info, err := w.file.Stat()
	if err != nil {
		return nil, err
	}
	if err := o.finishFile(w.file); err != nil {
		return nil, err
	}
	if err := o.publishName(r, name); err != nil {
		return nil, err
	}
	if err := o.ops.dirSync(r); err != nil {
		return nil, err
	}
	return o.prepared(r, m, filelock.FileIdentityV1(info))
}

func (o *SourceOwnerV1) finishFile(f *os.File) error {
	if err := o.ops.fileSync(f); err != nil {
		return err
	}
	return o.ops.close(f)
}

func (o *SourceOwnerV1) writeBundle(r *sourceRoot, w *sourceFileWriter, m SourceManifestV1, produce func(func(SourcePartV1) error) error, size uint64) error {
	scratch := make([]byte, scratchBytes)
	hash := sha256.New()
	out := io.MultiWriter(w, hash)
	lazy := func(visit func(SourcePartV1) error) error {
		return produce(func(part SourcePartV1) error {
			if w.file == nil {
				if err := o.startBundle(r, w, out, m, size); err != nil {
					return err
				}
			}
			return visit(part)
		})
	}
	if err := stream(m, lazy, out, scratch); err != nil {
		return err
	}
	if _, err := w.Write(hash.Sum(nil)); err != nil {
		return err
	}
	_, err := o.qualify(w.file, m, scratch)
	return err
}

func (o *SourceOwnerV1) startBundle(r *sourceRoot, w *sourceFileWriter, out io.Writer, m SourceManifestV1, size uint64) error {
	if err := o.reconcile(r); err != nil {
		return err
	}
	name := m.name(o.id)
	f, err := r.OpenFile(".staging-"+name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	w.file = f
	o.debt = &sourceDebt{name: name, size: size, staging: true}
	_, err = out.Write(m.header(o.id))
	return err
}

type sourceFileWriter struct {
	o    *SourceOwnerV1
	file *os.File
}

func (w sourceFileWriter) Write(data []byte) (int, error) {
	n, err := w.o.ops.write(w.file, data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (o *SourceOwnerV1) publishName(r *sourceRoot, name string) error {
	if _, err := r.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return ErrIntegrityV1
	}
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

func (w *compareSourceWriter) Write(data []byte) (int, error) {
	scratch := w.scratch[:len(data)]
	if _, err := w.file.ReadAt(scratch, w.offset); err != nil || !bytes.Equal(data, scratch) {
		return 0, ErrIntegrityV1
	}
	w.offset += int64(len(data))
	return len(data), nil
}

func (o *SourceOwnerV1) reuse(r *sourceRoot, f *os.File, m SourceManifestV1, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	scratch := make([]byte, scratchBytes)
	if _, err := o.qualify(f, m, scratch); err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	w := &compareSourceWriter{file: f, offset: int64(len(m.header(o.id))), scratch: scratch[scratchBytes/2:]}
	if err := stream(m, produce, w, scratch[:scratchBytes/2]); err != nil {
		return nil, err
	}
	if err := o.finishFile(f); err != nil {
		return nil, err
	}
	if err := o.ops.dirSync(r); err != nil {
		return nil, err
	}
	return o.prepared(r, m, filelock.FileIdentityV1(info))
}

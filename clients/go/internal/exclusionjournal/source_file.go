package exclusionjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/bits"
	"os"
	"strings"
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

type sourceUsage struct {
	files, bytes uint64
	stage        *sourceDebt
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
	leaf, _ := sourceRootInfo(parent)
	if !os.SameFile(leaf, o.info) {
		return ErrIdentityV1
	}
	current, err := os.Lstat(o.dir)
	if err != nil || o.parent != filelock.FileIdentityV1(current) {
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
	held, _ := pin.Stat()
	if !os.SameFile(leaf, held) || held.Mode() != leaf.Mode() || o.info != nil && !os.SameFile(o.info, held) {
		_ = root.Close()
		return nil, ErrIdentityV1
	}
	o.info = held
	return root, nil
}

func sourceRootInfo(parent *os.Root) (os.FileInfo, error) {
	info, err := parent.Lstat(sourceDirectory)
	if err != nil || info.Mode() != os.ModeDir|0o700 {
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
	if _, err = o.census(r); err != nil {
		return err
	}
	if o.release != nil {
		if !o.manifestFits(o.release.manifest, o.release.size) {
			return ErrCapacityV1
		}
		_, err = o.releaseBacking(r, o.release, make([]byte, scratchBytes))
	}
	return err
}

func syncSourceRoot(r *sourceRoot) error { return r.pin.Sync() }

// syncBoundRoot makes namespace changes durable and verifies current root reachability.
func (o *SourceOwnerV1) syncBoundRoot(r *sourceRoot) error {
	if err := o.ops.dirSync(r); err != nil {
		return err
	}
	return o.currentRoot()
}

// census accounts for retained files and pending cleanup.
func (o *SourceOwnerV1) census(r *sourceRoot) (sourceUsage, error) {
	f, err := r.Open(".")
	if err != nil {
		return sourceUsage{}, err
	}
	entries, err := f.ReadDir(int(min(o.limits.Scans, math.MaxInt)))
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return sourceUsage{}, err
	}
	if uint64(len(entries)) >= o.limits.Scans {
		return sourceUsage{}, ErrCapacityV1
	}
	return o.censusFiles(r, entries)
}

func (o *SourceOwnerV1) censusFiles(r *sourceRoot, entries []os.DirEntry) (sourceUsage, error) {
	var used sourceUsage
	missing, absentRelease := len(o.live), o.release
	for _, entry := range entries {
		name := entry.Name()
		switch name {
		case releaseFile, releaseScratch:
			if name == releaseFile && o.release == nil {
				return sourceUsage{}, ErrIntegrityV1
			}
			continue
		}
		if err := o.censusFile(r, name, &used, &missing); err != nil {
			return sourceUsage{}, err
		}
		if absentRelease != nil && name == absentRelease.name {
			absentRelease = nil
		}
	}
	return o.includeAbsent(used, missing, absentRelease)
}

func (o *SourceOwnerV1) includeAbsent(used sourceUsage, missing int, absentRelease *sourceRelease) (sourceUsage, error) {
	var absentBytes uint64
	if o.debt != nil && o.debt.removed {
		used.files++
		absentBytes = o.debt.size
		used.stage = o.debt
	}
	if absentRelease != nil {
		used.files++
		absentBytes += absentRelease.size
		if o.live[absentRelease.name] != nil {
			missing--
		}
	}
	if absentBytes > o.limits.Bytes-used.bytes || used.files > o.limits.Files {
		return sourceUsage{}, ErrCapacityV1
	}
	if missing != 0 {
		return sourceUsage{}, ErrIntegrityV1
	}
	used.bytes += absentBytes
	return used, nil
}

func (o *SourceOwnerV1) censusFile(r *sourceRoot, name string, used *sourceUsage, missing *int) error {
	info, err := sourceEntryInfo(r, name)
	if err != nil {
		return ErrIntegrityV1
	}
	size := uint64(max(info.Size(), 0))
	if token := o.live[name]; token != nil {
		if token.file != filelock.FileIdentityV1(info) {
			return ErrIdentityV1
		}
		if size != token.size {
			return ErrIntegrityV1
		}
		*missing -= 1
	}
	if err := o.censusEntry(name, size, used); err != nil {
		return err
	}
	if size > o.limits.Bytes-used.bytes {
		return ErrCapacityV1
	}
	used.files++
	used.bytes += size
	return nil
}

// openSourceFile opens a named entry without following links or blocking on non-regular objects.
func openSourceFile(r *sourceRoot, name string) (*os.File, error) {
	return r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func sourceEntryInfo(r *sourceRoot, name string) (os.FileInfo, error) {
	info, err := r.Lstat(name)
	if err == nil && (!info.Mode().IsRegular() || info.Size() < 0) {
		return nil, ErrIntegrityV1
	}
	return info, err
}

func (o *SourceOwnerV1) censusEntry(name string, size uint64, used *sourceUsage) error {
	name, staging := strings.CutPrefix(name, ".staging-")
	decoded, err := hex.DecodeString(name)
	if err != nil || len(decoded) != 32 {
		return ErrIntegrityV1
	}
	if !staging {
		return nil
	}
	if d := o.debt; d != nil {
		if d.name != name {
			return ErrBusyV1
		}
		if d.removed {
			return ErrIntegrityV1
		}
	}
	o.debt = &sourceDebt{name: name, size: size, staging: true}
	used.stage = o.debt
	return nil
}

func (o *SourceOwnerV1) space(r *sourceRoot, required uint64) error {
	var stat syscall.Statfs_t
	err := o.ops.statfs(int(r.pin.Fd()), &stat)
	overflow, available := bits.Mul64(uint64(stat.Bavail), sourceSpaceUnit(&stat))
	if err != nil || overflow != 0 || available < required+o.limits.Overhead || o.currentRoot() != nil {
		return ErrCapacityV1
	}
	return nil
}

func assurance(part SourcePartV1) error {
	var field [8]byte
	if n, err := part.ReadAt(field[:1], 0); n != 1 || err != nil {
		return ErrIntegrityV1
	}
	offset := uint64(1)
	if field[0] != 1 {
		if field[0] != 2 {
			return ErrIntegrityV1
		}
		for range 4 {
			next, err := assuranceField(part, offset)
			if err != nil {
				return err
			}
			offset = next
		}
	}
	if offset != part.Length {
		return ErrIntegrityV1
	}
	return nil
}

func assuranceField(part SourcePartV1, offset uint64) (uint64, error) {
	if part.Length-offset < 8 {
		return 0, ErrIntegrityV1
	}
	var field [8]byte
	if n, err := part.ReadAt(field[:], int64(min(offset, math.MaxInt64))); n != 8 || err != nil {
		return 0, ErrIntegrityV1
	}
	length := binary.LittleEndian.Uint64(field[:])
	offset += 8
	if length == 0 || length > part.Length-offset {
		return 0, ErrIntegrityV1
	}
	return offset + length, nil
}

func stream(m SourceManifestV1, produce func(func(SourcePartV1) error) error, dst io.Writer, scratch []byte, start func() error) error {
	var digest [sha256.Size]byte
	err := produce(func(part SourcePartV1) error {
		if start != nil {
			if err := start(); err != nil {
				return err
			}
			start = nil
		}
		if part.Kind == OriginalAssuranceV1 {
			if err := assurance(part); err != nil {
				return err
			}
		}
		if part.Kind == AcquiredBlockBytesV1 {
			acquired := sha256.New()
			err := copyPart(part, io.MultiWriter(dst, acquired), scratch)
			copy(digest[:], acquired.Sum(nil))
			return err
		}
		return copyPart(part, dst, scratch)
	})
	if err != nil {
		return err
	}
	if digest != m.AcquiredDigest {
		return ErrIntegrityV1
	}
	return nil
}

func (o *SourceOwnerV1) qualify(f *os.File, m SourceManifestV1, size uint64, scratch []byte, expected *sourceIncarnation, shapeError error) (sourceIncarnation, error) {
	var observed sourceIncarnation
	file, actual, err := o.sourceFileHeader(f, m, size, expected, shapeError)
	if err != nil {
		return observed, err
	}
	observed.file = file
	observed.size = size
	hash := sha256.New()
	_, _ = hash.Write(actual)
	if err := stream(m, fileExporter(f, m, len(actual)), hash, scratch, nil); err != nil {
		return observed, err
	}
	_, err = f.ReadAt(observed.footer[:], int64(min(size, math.MaxInt64))-sha256.Size)
	if err != nil || !bytes.Equal(hash.Sum(nil), observed.footer[:]) || expected != nil && observed.footer != expected.footer {
		return observed, ErrIntegrityV1
	}
	return observed, nil
}

func (o *SourceOwnerV1) sourceFileHeader(f *os.File, m SourceManifestV1, size uint64, expected *sourceIncarnation, shapeError error) (filelock.IdentityV1, []byte, error) {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(min(size, math.MaxInt64)) {
		return filelock.IdentityV1{}, nil, shapeError
	}
	file := filelock.FileIdentityV1(info)
	if expected != nil && file != expected.file {
		return file, nil, ErrIdentityV1
	}
	header := m.header(o.id)
	actual := make([]byte, len(header))
	if _, err = f.ReadAt(actual, 0); err != nil || !bytes.Equal(actual, header) {
		return file, nil, ErrIntegrityV1
	}
	return file, actual, nil
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
			offset += int64(min(spec.Length, math.MaxInt64))
		}
		return nil
	}
}

// WithCapturedSourceV1 opens and qualifies the retained file before visiting its parts.
func (o *SourceOwnerV1) WithCapturedSourceV1(account *mdbx.OperationAccount, m SourceManifestV1, visit func(SourcePartV1) error) error {
	return o.withFiles(account, m, false, func(r *sourceRoot, m SourceManifestV1, size uint64, _ sourceUsage) error {
		name := m.name(o.id)
		if o.debt != nil && o.debt.name == name || o.release != nil && o.release.name == name {
			return ErrBusyV1
		}
		if visit == nil {
			return ErrIntegrityV1
		}
		f, err := openSourceFile(r, name)
		if err != nil {
			return ErrUnavailableV1
		}
		defer f.Close()
		if _, err := o.qualify(f, m, size, make([]byte, scratchBytes), o.live[name], ErrIntegrityV1); err != nil {
			return err
		}
		return fileExporter(f, m, len(m.header(o.id)))(visit)
	})
}

func (o *SourceOwnerV1) withFiles(account *mdbx.OperationAccount, m SourceManifestV1, preparing bool, use func(*sourceRoot, SourceManifestV1, uint64, sourceUsage) error) error {
	return o.withManifest(account, m, preparing, func(r *sourceRoot, m SourceManifestV1, size uint64) error {
		used, err := o.census(r)
		if err != nil {
			return err
		}
		return use(r, m, size, used)
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
		if info, err := sourceEntryInfo(r, name); err == nil {
			d.size = uint64(max(info.Size(), 0))
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
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
	err = o.withFiles(account, m, true, func(r *sourceRoot, m SourceManifestV1, size uint64, used sourceUsage) error {
		prepared, err = o.prepare(r, m, size, used, func(visit func(SourcePartV1) error) error {
			return o.export(account, m, producer, visit)
		})
		return err
	})
	return prepared, err
}

func (o *SourceOwnerV1) prepare(r *sourceRoot, m SourceManifestV1, size uint64, used sourceUsage, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	name := m.name(o.id)
	if o.debt != nil && o.debt.name != name {
		return nil, ErrBusyV1
	}
	f, err := openSourceFile(r, name)
	if err == nil {
		defer f.Close()
		return o.reuse(r, f, m, name, size, used.stage, produce)
	}
	if !errors.Is(err, os.ErrNotExist) || o.live[name] != nil {
		return nil, ErrIntegrityV1
	}
	if err := o.admitPublication(r, size, used); err != nil {
		return nil, err
	}
	return o.publish(r, m, name, produce, size)
}

func (o *SourceOwnerV1) admitPublication(r *sourceRoot, size uint64, used sourceUsage) error {
	if used.stage != nil {
		used.files--
		used.bytes -= used.stage.size
	}
	if used.files >= o.limits.Files || size > o.limits.Bytes-used.bytes {
		return ErrCapacityV1
	}
	return o.space(r, size)
}

func (o *SourceOwnerV1) prepared(r *sourceRoot, m SourceManifestV1, name string, observed sourceIncarnation) (*PreparedSourceV1, error) {
	if err := o.ops.dirSync(r); err != nil {
		return nil, err
	}
	info, err := r.Lstat(name)
	if err != nil || observed.file != filelock.FileIdentityV1(info) || o.currentRoot() != nil {
		return nil, ErrIdentityV1
	}
	o.debt = nil
	token := o.live[name]
	if token == nil {
		token = &observed
		o.live[name] = token
	}
	return &PreparedSourceV1{manifest: m, name: name, incarnation: token}, nil
}

func (o *SourceOwnerV1) publish(r *sourceRoot, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64) (_ *PreparedSourceV1, err error) {
	w := &sourceFileWriter{o: o}
	defer func() {
		if w.file == nil {
			return
		}
		_ = w.file.Close()
		if o.debt != nil && o.debt.staging {
			if cleanup := o.reconcile(r); cleanup != nil {
				err = errors.Join(err, cleanup)
			}
		}
	}()
	observed, err := o.writeBundle(r, w, m, name, produce, size)
	if err != nil {
		return nil, err
	}
	if err := o.finishFile(w.file); err != nil {
		return nil, err
	}
	visible, err := o.renameVisible(r, ".staging-"+name, name)
	o.debt.staging = !visible
	if err != nil {
		return nil, err
	}
	return o.prepared(r, m, name, observed)
}

func (o *SourceOwnerV1) finishFile(f *os.File) error {
	if err := o.ops.fileSync(f); err != nil {
		return err
	}
	return o.ops.close(f)
}

func (o *SourceOwnerV1) writeBundle(r *sourceRoot, w *sourceFileWriter, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64) (sourceIncarnation, error) {
	scratch := make([]byte, scratchBytes)
	hash := sha256.New()
	out := io.MultiWriter(w, hash)
	start := func() error { return o.startBundle(r, w, out, m, name, size) }
	if err := stream(m, produce, out, scratch, start); err != nil {
		return sourceIncarnation{}, err
	}
	if _, err := w.Write(hash.Sum(nil)); err != nil {
		return sourceIncarnation{}, err
	}
	return o.qualify(w.file, m, size, scratch, nil, ErrIntegrityV1)
}

func (o *SourceOwnerV1) startBundle(r *sourceRoot, w *sourceFileWriter, out io.Writer, m SourceManifestV1, name string, size uint64) error {
	if err := o.reconcile(r); err != nil {
		return err
	}
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

func (o *SourceOwnerV1) renameVisible(r *sourceRoot, from, to string) (bool, error) {
	if _, err := r.Lstat(to); !errors.Is(err, os.ErrNotExist) {
		return false, ErrIntegrityV1
	}
	err := o.ops.rename(r.Root, from, to)
	if err == nil {
		return true, nil
	}
	_, statErr := r.Lstat(to)
	return !errors.Is(statErr, os.ErrNotExist), err
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

func (o *SourceOwnerV1) reuse(r *sourceRoot, f *os.File, m SourceManifestV1, name string, size uint64, stage *sourceDebt, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	scratch := make([]byte, scratchBytes)
	observed, err := o.qualify(f, m, size, scratch, o.live[name], ErrIntegrityV1)
	if err != nil {
		return nil, err
	}
	w := &compareSourceWriter{file: f, offset: int64(len(m.header(o.id))), scratch: scratch[scratchBytes/2:]}
	var start func() error
	if stage != nil {
		start = func() error { return o.reconcile(r) }
	}
	if err := stream(m, produce, w, scratch[:scratchBytes/2], start); err != nil {
		return nil, err
	}
	if err := o.finishFile(f); err != nil {
		return nil, err
	}
	return o.prepared(r, m, name, observed)
}

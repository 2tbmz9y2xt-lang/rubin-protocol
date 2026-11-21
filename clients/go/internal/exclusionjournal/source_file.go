package exclusionjournal

import (
	"bytes"
	"cmp"
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
	"golang.org/x/sys/unix"
)

type sourceFS struct {
	statfs          func(int, *syscall.Statfs_t) error
	write           func(*os.File, []byte) (int, error)
	fileSync, close func(*os.File) error
	chmod           func(*os.File, os.FileMode) error
	rename          func(*os.Root, string, string) error
	remove          func(*os.Root, string) error
	dirSync         func(*os.File) error
}
type sourceDebt struct {
	name             string
	size             uint64
	staging, removed bool
}

type sourceUsage struct {
	files, bytes uint64
	stage        sourceDebt
}

var realSourceFS = sourceFS{statfs: syscall.Fstatfs, write: (*os.File).Write, fileSync: (*os.File).Sync, close: (*os.File).Close, chmod: (*os.File).Chmod, rename: (*os.Root).Rename, remove: (*os.Root).Remove, dirSync: (*os.File).Sync}

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
	if o.debt.removed {
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
	info, err := sourceEntryInfo(r, name, nil)
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

// openSourceFile checks that a nonblocking, no-follow open pins the observed regular file.
func openSourceFile(r *sourceRoot, name string, unobserved error) (*os.File, error) {
	named, err := sourceEntryInfo(r, name, unobserved)
	if err != nil {
		return nil, err
	}
	f, err := openSourceAt(int(r.pin.Fd()), name, unix.O_NONBLOCK)
	if err != nil {
		return nil, ErrUnavailableV1
	}
	if info, _ := f.Stat(); !os.SameFile(named, info) {
		_ = f.Close()
		return nil, ErrIntegrityV1
	}
	return f, nil
}

func openSourceAt(parent int, name string, flags int) (*os.File, error) {
	fd, err := -1, error(unix.EINTR)
	for errors.Is(err, unix.EINTR) {
		fd, err = unix.Openat(parent, name, flags|unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func sourceEntryInfo(r *sourceRoot, name string, unobserved error) (os.FileInfo, error) {
	info, err := r.Lstat(name)
	if err != nil {
		return nil, cmp.Or(unobserved, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return nil, ErrIntegrityV1
	}
	return info, nil
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
	if d := o.debt; d.name != "" {
		if d.name != name {
			return ErrBusyV1
		}
		if d.removed {
			return ErrIntegrityV1
		}
	}
	o.debt = sourceDebt{name: name, size: size, staging: true}
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
	if err := readPartAt(part, field[:1], 0); err != nil {
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
	if err := readPartAt(part, field[:], offset); err != nil {
		return 0, ErrIntegrityV1
	}
	length := binary.LittleEndian.Uint64(field[:])
	offset += 8
	if length == 0 || length > part.Length-offset {
		return 0, ErrIntegrityV1
	}
	return offset + length, nil
}

func stream(m SourceManifestV1, produce func(func(SourcePartV1) error) error, dst io.Writer, scratch []byte, start func() error, checkAssurance bool) error {
	var digest [sha256.Size]byte
	err := produce(func(part SourcePartV1) error {
		if start != nil {
			if err := start(); err != nil {
				return err
			}
			start = nil
		}
		if checkAssurance && part.Kind == OriginalAssuranceV1 {
			if err := assurance(part); err != nil {
				return err
			}
		}
		out := dst
		if part.Kind == AcquiredBlockBytesV1 {
			acquired := sha256.New()
			out = io.MultiWriter(dst, acquired)
			defer func() { copy(digest[:], acquired.Sum(nil)) }()
		}
		return copyPart(part, out, scratch)
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
	return o.qualifyWindows(f, m, size, scratch, expected, shapeError, nil)
}

// qualifyWindows binds the optional window digests to the bytes used for the footer check.
func (o *SourceOwnerV1) qualifyWindows(f *os.File, m SourceManifestV1, size uint64, scratch []byte, expected *sourceIncarnation, shapeError error, windows *sourceWindows) (sourceIncarnation, error) {
	var observed sourceIncarnation
	file, actual, err := o.sourceFileHeader(f, m, size, expected, shapeError)
	if err != nil {
		return observed, err
	}
	observed.file = file
	observed.size = size
	hash := sha256.New()
	_, _ = hash.Write(actual)
	var out io.Writer = hash
	if windows != nil {
		out = io.MultiWriter(hash, windows)
	}
	if err := stream(m, fileExporter(f, m, len(actual)), out, scratch, nil, windows == nil); err != nil {
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
	if err != nil || info.Size() != int64(min(size, math.MaxInt64)) {
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

// WithCapturedSourceV1 qualifies retained bytes before visiting (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
func (o *SourceOwnerV1) WithCapturedSourceV1(account *mdbx.OperationAccount, m SourceManifestV1, visit func(SourcePartV1) error) error {
	return o.withFiles(account, m, false, func(r *sourceRoot, m SourceManifestV1, size uint64, _ sourceUsage) error {
		name := m.name(o.id)
		if o.debt.name == name || o.release != nil && o.release.name == name {
			return ErrBusyV1
		}
		if visit == nil {
			return ErrIntegrityV1
		}
		f, err := openSourceFile(r, name, ErrUnavailableV1)
		if err != nil {
			return err
		}
		defer f.Close()
		windows := newSourceWindows(m)
		if _, err := o.qualifyWindows(f, m, size, windows.scratch, o.live[name], ErrIntegrityV1, windows); err != nil {
			return err
		}
		return windows.deliver(f, m, len(m.header(o.id)), visit)
	})
}

type sourceWindows struct {
	hashes  [][sha256.Size]byte
	scratch []byte
	failure error
}

func newSourceWindows(m SourceManifestV1) *sourceWindows {
	var count uint64
	for _, part := range m.Parts {
		count += sourceWindowCount(part.Length)
	}
	return &sourceWindows{hashes: make([][sha256.Size]byte, 0, count), scratch: make([]byte, scratchBytes)}
}

func sourceWindowCount(length uint64) uint64 {
	return (length + scratchBytes - 1) / scratchBytes
}

func (w *sourceWindows) Write(b []byte) (int, error) {
	w.hashes = append(w.hashes, sha256.Sum256(b))
	return len(b), nil
}

func (w *sourceWindows) deliver(f *os.File, m SourceManifestV1, header int, visit func(SourcePartV1) error) error {
	var parts [6]SourcePartV1
	hashes, base := w.hashes, int64(header)
	for i, spec := range m.Parts {
		n := sourceWindowCount(spec.Length)
		section := io.NewSectionReader(f, base, int64(min(spec.Length, math.MaxInt64)))
		parts[i] = w.part(section, spec, hashes[:n])
		hashes, base = hashes[n:], base+section.Size()
		if spec.Kind == OriginalAssuranceV1 {
			if err := w.checkAssurance(parts[i]); err != nil {
				return err
			}
		}
	}
	for _, part := range parts[:len(m.Parts)] {
		err := visitPart(part, visit)
		if err := cmp.Or(w.failure, err); err != nil {
			return err
		}
	}
	return nil
}

func (w *sourceWindows) checkAssurance(part SourcePartV1) error {
	if part.Length > 1 && part.Length <= uint64(len(w.scratch)) {
		data := w.scratch[:part.Length]
		if err := readPartAt(part, data, 0); err != nil {
			return err
		}
		part.ReadAt = bytes.NewReader(data).ReadAt
	}
	return assurance(part)
}

func (w *sourceWindows) part(section *io.SectionReader, spec SourcePartSpecV1, hashes [][sha256.Size]byte) SourcePartV1 {
	return SourcePartV1{Kind: spec.Kind, Length: spec.Length, ReadAt: func(dst []byte, off int64) (int, error) {
		if w.failure != nil {
			return 0, w.failure
		}
		copied := 0
		for len(dst) > 0 {
			index := off / scratchBytes
			start := index * scratchBytes
			buf := w.scratch[:min(int64(scratchBytes), section.Size()-start)]
			n, err := section.ReadAt(buf, start)
			if n != len(buf) || err != nil || sha256.Sum256(buf) != hashes[index] {
				w.failure = ErrIntegrityV1
				return copied, w.failure
			}
			n = copy(dst, buf[off-start:])
			dst, off, copied = dst[n:], off+int64(n), copied+n
		}
		return copied, nil
	}}
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
	d := &o.debt
	if d.name == "" {
		return nil
	}
	if !d.removed {
		name := ".staging-" + d.name
		if info, err := sourceEntryInfo(r, name, nil); err == nil {
			d.size = uint64(max(info.Size(), 0))
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := o.ops.remove(r.Root, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		d.removed = true
	}
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	o.debt = sourceDebt{}
	return nil
}

// PrepareSourceV1 returns a handle after durable publication (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
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
	if o.debt.name != "" && o.debt.name != name {
		return nil, ErrBusyV1
	}
	f, err := openSourceFile(r, name, nil)
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
	if used.stage.name != "" {
		used.files--
		used.bytes -= used.stage.size
	}
	if used.files >= o.limits.Files || size > o.limits.Bytes-used.bytes {
		return ErrCapacityV1
	}
	return o.space(r, size)
}

func (o *SourceOwnerV1) prepared(r *sourceRoot, m SourceManifestV1, name string, observed sourceIncarnation) (*PreparedSourceV1, error) {
	if err := o.ops.dirSync(r.pin); err != nil {
		return nil, err
	}
	info, err := r.Lstat(name)
	if err != nil || observed.file != filelock.FileIdentityV1(info) || o.currentRoot() != nil {
		return nil, ErrIdentityV1
	}
	o.debt = sourceDebt{}
	token := cmp.Or(o.live[name], &observed)
	o.live[name] = token
	return &PreparedSourceV1{manifest: m, name: name, incarnation: token}, nil
}

func (o *SourceOwnerV1) publish(r *sourceRoot, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64) (_ *PreparedSourceV1, err error) {
	w := &sourceFileWriter{o: o}
	defer func() {
		if w.file == nil {
			return
		}
		_ = w.file.Close()
		if o.debt.staging {
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
	start := func() error {
		if err := o.reconcile(r); err != nil {
			return err
		}
		f, err := r.OpenFile(".staging-"+name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		w.file = f
		o.debt = sourceDebt{name: name, size: size, staging: true}
		_, err = out.Write(m.header(o.id))
		return cmp.Or(err, o.ops.chmod(f, 0o600))
	}
	if err := stream(m, produce, out, scratch, start, true); err != nil {
		return sourceIncarnation{}, err
	}
	if _, err := w.Write(hash.Sum(nil)); err != nil {
		return sourceIncarnation{}, err
	}
	return o.qualify(w.file, m, size, scratch, nil, ErrIntegrityV1)
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

func (o *SourceOwnerV1) reuse(r *sourceRoot, f *os.File, m SourceManifestV1, name string, size uint64, stage sourceDebt, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	scratch := make([]byte, scratchBytes)
	observed, err := o.qualify(f, m, size, scratch, o.live[name], ErrIntegrityV1)
	if err != nil {
		return nil, err
	}
	w := &compareSourceWriter{file: f, offset: int64(len(m.header(o.id))), scratch: scratch[scratchBytes/2:]}
	var start func() error
	if stage.name != "" {
		start = func() error { return o.reconcile(r) }
	}
	if err := stream(m, produce, w, scratch[:scratchBytes/2], start, true); err != nil {
		return nil, err
	}
	if err := o.finishFile(f); err != nil {
		return nil, err
	}
	return o.prepared(r, m, name, observed)
}

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
	namespace       func(sourceNameOp, *sourceRoot, string, string) error
	remove          func(*os.Root, string) error
	dirSync         func(*os.File) error
}
type sourceDebt struct {
	name, backing     string
	size              uint64
	file              filelock.IdentityV1
	staging, removed  bool
	unlinkTried, held bool
}

const (
	publicStagePrefix = ".staging-"
	heldStagePrefix   = ".stage-hold-"
)

func (d sourceDebt) leaf() string {
	if d.held {
		return heldStagePrefix + d.name
	}
	return publicStagePrefix + d.name
}

func stageSlotVacant(r *sourceRoot, key string, occupied error) error {
	_, err := r.Lstat(publicStagePrefix + key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return cmp.Or(err, occupied)
}

type sourceUsage struct {
	files, bytes              uint64
	stage                     sourceDebt
	stageBacked, stageCharged bool
}

type sourceNameOp func(*sourceRoot, string, string) error

// run applies the selected operation inside the pinned source directory.
func (op sourceNameOp) run(r *sourceRoot, from, to string) error {
	return op(r, from, to)
}

func linkSource(r *sourceRoot, from, to string) error { return r.Link(from, to) }

func detachSource(r *sourceRoot, from, to string) error {
	return renameSourceExclusive(int(r.pin.Fd()), from, to)
}

var realSourceFS = sourceFS{statfs: syscall.Fstatfs, write: (*os.File).Write, fileSync: (*os.File).Sync, close: (*os.File).Close, chmod: (*os.File).Chmod, namespace: sourceNameOp.run, remove: (*os.Root).Remove, dirSync: (*os.File).Sync}

func (o *SourceOwnerV1) census(r *sourceRoot, reopening bool) (sourceUsage, error) {
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
	return o.censusFiles(r, entries, reopening)
}

func (o *SourceOwnerV1) censusFiles(r *sourceRoot, entries []os.DirEntry, reopening bool) (sourceUsage, error) {
	var used sourceUsage
	missing, absentRelease := len(o.live), o.release
	backing, err := absentRelease.location(r)
	if err != nil {
		return sourceUsage{}, err
	}
	if err := o.censusStages(r, entries, reopening, &used); err != nil {
		return sourceUsage{}, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if isStageLeaf(name) {
			continue
		}
		if err := o.countEntry(r, name, backing, &used, &missing); err != nil {
			return sourceUsage{}, err
		}
		if name == backing {
			absentRelease = nil
		}
	}
	return o.includeAbsent(used, missing, absentRelease)
}

func isStageLeaf(name string) bool {
	return strings.HasPrefix(name, publicStagePrefix) || strings.HasPrefix(name, heldStagePrefix)
}

func (o *SourceOwnerV1) censusStages(r *sourceRoot, entries []os.DirEntry, reopening bool, used *sourceUsage) error {
	if err := o.admitHeldStage(r, entries, reopening); err != nil {
		return err
	}
	for _, entry := range entries {
		if !isStageLeaf(entry.Name()) {
			continue
		}
		info, err := sourceEntryInfo(r, entry.Name(), nil)
		if err != nil {
			return ErrIntegrityV1
		}
		if err := o.censusStage(entry.Name(), info); err != nil {
			return err
		}
		used.stage = o.debt
	}
	return nil
}

func (o *SourceOwnerV1) admitHeldStage(r *sourceRoot, entries []os.DirEntry, reopening bool) error {
	seen := false
	for _, entry := range entries {
		key, held := strings.CutPrefix(entry.Name(), heldStagePrefix)
		if !held {
			continue
		}
		if seen || !validHeldStageKey(key) {
			return ErrIntegrityV1
		}
		seen = true
		if !reopening && o.debt.name != key {
			return ErrIdentityV1
		}
		if err := stageSlotVacant(r, key, syscall.EEXIST); err != nil {
			return err
		}
	}
	return nil
}

func validHeldStageKey(key string) bool {
	return strings.ToLower(key) == key && validSourceKey(key)
}

func (o *SourceOwnerV1) countEntry(r *sourceRoot, name, backing string, used *sourceUsage, missing *int) error {
	logical := name
	switch name {
	case releaseFile:
		if o.release == nil {
			return ErrIntegrityV1
		}
		_, err := releaseScratchAlias(r)
		return err
	case releaseScratch:
		return nil
	case releaseDetached:
		if backing != releaseDetached {
			return ErrIntegrityV1
		}
		logical = o.release.name
	}
	info, err := sourceEntryInfo(r, name, nil)
	if err != nil {
		return ErrIntegrityV1
	}
	return o.censusFile(logical, info, used, missing)
}

func (d *sourceDebt) stageCharge(used *sourceUsage, absentRelease *sourceRelease) uint64 {
	if d.name == "" {
		return 0
	}
	if d.unlinkTried && used.stage.name == "" {
		d.removed = true
	}
	used.stage = *d
	if used.stageBacked || absentRelease != nil && d.backing == absentRelease.name && d.file == absentRelease.file {
		return 0
	}
	used.files++
	used.stageCharged = true
	return d.size
}

func (o *SourceOwnerV1) includeAbsent(used sourceUsage, missing int, absentRelease *sourceRelease) (sourceUsage, error) {
	absentBytes := o.debt.stageCharge(&used, absentRelease)
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

func (o *SourceOwnerV1) censusFile(logical string, info os.FileInfo, used *sourceUsage, missing *int) error {
	size := uint64(max(info.Size(), 0))
	if token := o.live[logical]; token != nil {
		if err := token.match(info); err != nil {
			return err
		}
		*missing -= 1
	}
	if !validSourceKey(logical) {
		return ErrIntegrityV1
	}
	o.debt.observeBacking(logical, info, used)
	if size > o.limits.Bytes-used.bytes {
		return ErrCapacityV1
	}
	used.files++
	used.bytes += size
	return nil
}

// observeBacking attributes a stage alias to an already charged file.
func (d *sourceDebt) observeBacking(name string, info os.FileInfo, used *sourceUsage) {
	if d.name == "" || d.file != filelock.FileIdentityV1(info) {
		return
	}
	if used.stage.name != "" && (d.backing == "" || name == d.name) {
		d.backing = name
	}
	if name == d.backing {
		used.stageBacked = true
	}
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

func validSourceKey(name string) bool {
	decoded, err := hex.DecodeString(name)
	return err == nil && len(decoded) == sha256.Size
}

func (o *SourceOwnerV1) censusStage(leaf string, info os.FileInfo) error {
	name, held := strings.CutPrefix(leaf, heldStagePrefix)
	if !held {
		name = strings.TrimPrefix(leaf, publicStagePrefix)
	}
	if !validSourceKey(name) {
		return ErrIntegrityV1
	}
	file := filelock.FileIdentityV1(info)
	if err := o.debt.matchStage(name, file, held); err != nil {
		return err
	}
	o.debt = sourceDebt{name: name, size: uint64(max(info.Size(), 0)), file: file, staging: true, held: held}
	return nil
}

func (d sourceDebt) matchStage(name string, file filelock.IdentityV1, held bool) error {
	switch {
	case d.name == "":
		return nil
	case d.name != name:
		return ErrBusyV1
	case d.held && !held:
		return ErrIdentityV1
	case d.removed:
		return ErrIntegrityV1
	case d.file != (filelock.IdentityV1{}) && d.file != file:
		return ErrIdentityV1
	default:
		return nil
	}
}

func (o *SourceOwnerV1) space(r *sourceRoot, required uint64, stage sourceDebt) (bool, error) {
	var stat syscall.Statfs_t
	err := o.ops.statfs(int(r.pin.Fd()), &stat)
	overflow, available := bits.Mul64(uint64(stat.Bavail), sourceSpaceUnit(&stat))
	if err != nil || overflow != 0 || o.currentRoot() != nil {
		return false, ErrCapacityV1
	}
	full := required + o.limits.Overhead
	if available >= full {
		return false, nil
	}
	if full-available > min(required, stage.diskCredit(r)) {
		return false, ErrCapacityV1
	}
	return true, nil
}

// diskCredit bounds how much space removing this stage might reclaim.
func (d sourceDebt) diskCredit(r *sourceRoot) uint64 {
	if d.name == "" || d.removed || d.backing != "" {
		return 0
	}
	info, err := sourceEntryInfo(r, d.leaf(), nil)
	if err != nil || d.file != filelock.FileIdentityV1(info) {
		return 0
	}
	return min(d.size, uint64(max(info.Size(), 0)), singleLinkAllocatedBytes(info))
}

func singleLinkAllocatedBytes(info os.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil || st.Nlink != 1 || st.Blocks <= 0 {
		return 0
	}
	overflow, allocated := bits.Mul64(uint64(st.Blocks), 512)
	if overflow != 0 {
		return 0
	}
	return allocated
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
	if err != nil {
		return filelock.IdentityV1{}, nil, shapeError
	}
	file := filelock.FileIdentityV1(info)
	if expected != nil && file != expected.file {
		return file, nil, ErrIdentityV1
	}
	if info.Size() != int64(min(size, math.MaxInt64)) {
		return file, nil, shapeError
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

// newSourceWindows allocates only the windows required by this admitted manifest.
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

// Write records one part-relative copy window.
func (w *sourceWindows) Write(b []byte) (int, error) {
	w.hashes = append(w.hashes, sha256.Sum256(b))
	return len(b), nil
}

// deliver checks assurance through the verified reader before exposing any part.
func (w *sourceWindows) deliver(f *os.File, m SourceManifestV1, header int, visit func(SourcePartV1) error) error {
	var parts [6]SourcePartV1
	hashes, base := w.hashes, int64(header)
	for i, spec := range m.Parts {
		n := sourceWindowCount(spec.Length)
		parts[i] = w.part(f, base, spec, hashes[:n])
		hashes, base = hashes[n:], base+int64(min(spec.Length, math.MaxInt64))
		if spec.Kind == OriginalAssuranceV1 {
			if err := assurance(parts[i]); err != nil {
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

// part copies only ranges backed by a matching complete window.
func (w *sourceWindows) part(f *os.File, base int64, spec SourcePartSpecV1, hashes [][sha256.Size]byte) SourcePartV1 {
	return SourcePartV1{Kind: spec.Kind, Length: spec.Length, ReadAt: func(dst []byte, off int64) (int, error) {
		if w.failure != nil {
			return 0, w.failure
		}
		copied := 0
		for len(dst) > 0 {
			index := off / scratchBytes
			start := index * scratchBytes
			buf := w.scratch[:min(int64(scratchBytes), int64(min(spec.Length, math.MaxInt64))-start)]
			n, err := f.ReadAt(buf, base+start)
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
		used, err := o.census(r, false)
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
		if err := o.unlinkStage(r, d); err != nil {
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

func (o *SourceOwnerV1) unlinkStage(r *sourceRoot, d *sourceDebt) error {
	if !d.held {
		if err := o.claimStage(r, d); err != nil {
			return err
		}
	}
	info, err := sourceEntryInfo(r, d.leaf(), nil)
	if err != nil {
		return err
	}
	if d.file != (filelock.IdentityV1{}) && d.file != filelock.FileIdentityV1(info) {
		return ErrIdentityV1
	}
	d.file = filelock.FileIdentityV1(info)
	d.size = uint64(max(info.Size(), 0))
	d.unlinkTried = true
	return o.ops.remove(r.Root, d.leaf())
}

func (o *SourceOwnerV1) claimStage(r *sourceRoot, d *sourceDebt) error {
	err := o.moveStage(r, d)
	if err != nil && d.held {
		_ = o.restoreStage(r, d)
	}
	return err
}

func (o *SourceOwnerV1) moveStage(r *sourceRoot, d *sourceDebt) error {
	pin, err := openSourceFile(r, d.leaf(), nil)
	if err != nil {
		return err
	}
	defer pin.Close()
	info, err := pin.Stat()
	if err != nil {
		return err
	}
	if filelock.FileIdentityV1(info) != d.file {
		return ErrIdentityV1
	}
	if err := o.ops.namespace(detachSource, r, d.leaf(), heldStagePrefix+d.name); err != nil {
		return err
	}
	d.held = true
	moved, err := sourceEntryInfo(r, d.leaf(), nil)
	if err == nil && os.SameFile(info, moved) {
		return nil
	}
	return cmp.Or(err, ErrIdentityV1)
}

func (o *SourceOwnerV1) restoreStage(r *sourceRoot, d *sourceDebt) error {
	if err := o.ops.namespace(detachSource, r, d.leaf(), publicStagePrefix+d.name); err != nil {
		return err
	}
	d.held = false
	return o.syncBoundRoot(r)
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
	recheckSpace, err := o.admitPublication(r, size, used)
	if err != nil {
		return nil, err
	}
	return o.publish(r, m, name, produce, size, recheckSpace)
}

func (o *SourceOwnerV1) admitPublication(r *sourceRoot, size uint64, used sourceUsage) (bool, error) {
	if used.stageCharged {
		used.files--
		used.bytes -= used.stage.size
	}
	if used.files >= o.limits.Files || size > o.limits.Bytes-used.bytes {
		return false, ErrCapacityV1
	}
	return o.space(r, size, used.stage)
}

func (o *SourceOwnerV1) prepared(r *sourceRoot, m SourceManifestV1, name string, observed sourceIncarnation) (*PreparedSourceV1, error) {
	if err := o.ops.dirSync(r.pin); err != nil {
		return nil, err
	}
	info, err := r.Lstat(name)
	if err != nil || observed.file != filelock.FileIdentityV1(info) || o.currentRoot() != nil {
		return nil, ErrIdentityV1
	}
	if stageSlotVacant(r, name, ErrIdentityV1) != nil {
		o.debt = sourceDebt{}
		return nil, ErrIdentityV1
	}
	o.debt = sourceDebt{}
	token := cmp.Or(o.live[name], &observed)
	o.live[name] = token
	return &PreparedSourceV1{manifest: m, name: name, incarnation: token}, nil
}

func (o *SourceOwnerV1) publish(r *sourceRoot, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64, recheckSpace bool) (_ *PreparedSourceV1, err error) {
	w := &sourceFileWriter{o: o}
	defer func() {
		if w.file == nil {
			return
		}
		defer w.file.Close()
		if o.debt.staging {
			if cleanup := o.reconcile(r); cleanup != nil {
				err = errors.Join(err, cleanup)
			}
		}
	}()
	observed, err := o.writeBundle(r, w, m, name, produce, size, recheckSpace)
	if err != nil {
		return nil, err
	}
	if err := o.finishFile(w.file); err != nil {
		return nil, err
	}
	if stageSlotVacant(r, name, ErrIdentityV1) != nil {
		return nil, ErrIdentityV1
	}
	visibility, err := o.linkVisible(r, o.debt.leaf(), name, observed.file)
	o.debt.staging = visibility == sourceNotVisible
	o.debt.unlinkTried = visibility == sourceAliasRemoval
	if visibility == sourceVisible || o.debt.unlinkTried {
		o.debt.backing = name
	}
	if err != nil {
		return nil, err
	}
	o.debt.removed = true
	return o.prepared(r, m, name, observed)
}

func (o *SourceOwnerV1) finishFile(f *os.File) error {
	if err := o.ops.fileSync(f); err != nil {
		return err
	}
	return o.ops.close(f)
}

func (o *SourceOwnerV1) writeBundle(r *sourceRoot, w *sourceFileWriter, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64, recheckSpace bool) (sourceIncarnation, error) {
	scratch := make([]byte, scratchBytes)
	hash := sha256.New()
	out := io.MultiWriter(w, hash)
	start := func() error {
		if err := o.reconcile(r); err != nil {
			return err
		}
		if recheckSpace {
			if _, err := o.space(r, size, sourceDebt{}); err != nil {
				return err
			}
		}
		f, err := r.OpenFile(heldStagePrefix+name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		w.file = f
		o.debt = sourceDebt{name: name, staging: true, held: true}
		info, err := f.Stat()
		if err != nil {
			return err
		}
		o.debt.file = filelock.FileIdentityV1(info)
		_, err = out.Write(m.header(o.id))
		return cmp.Or(err, o.ops.chmod(f, 0o600))
	}
	if err := stream(m, produce, out, scratch, start, true); err != nil {
		return sourceIncarnation{}, err
	}
	written := [sha256.Size]byte(hash.Sum(nil))
	if _, err := w.Write(written[:]); err != nil {
		return sourceIncarnation{}, err
	}
	observed, err := o.qualify(w.file, m, size, scratch, nil, ErrIntegrityV1)
	if err == nil && observed.footer != written {
		err = ErrIntegrityV1
	}
	return observed, err
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

type sourceVisibility uint8

const (
	sourceNotVisible sourceVisibility = iota
	sourceVisible
	sourceIndeterminate
	sourceAliasRemoval
)

// linkVisible qualifies the destination before removing the source alias.
func (o *SourceOwnerV1) linkVisible(r *sourceRoot, from, to string, expected filelock.IdentityV1) (sourceVisibility, error) {
	err := o.ops.namespace(linkSource, r, from, to)
	if errors.Is(err, os.ErrExist) {
		return sourceNotVisible, ErrIntegrityV1
	}
	info, statErr := r.Lstat(to)
	if errors.Is(statErr, os.ErrNotExist) {
		return sourceNotVisible, cmp.Or(err, ErrIntegrityV1)
	}
	if statErr != nil {
		return sourceIndeterminate, cmp.Or(err, statErr)
	}
	if !info.Mode().IsRegular() || filelock.FileIdentityV1(info) != expected {
		return sourceNotVisible, cmp.Or(err, ErrIntegrityV1)
	}
	if err != nil {
		return sourceVisible, err
	}
	source, _ := r.Lstat(from)
	if !os.SameFile(info, source) {
		return sourceVisible, ErrIdentityV1
	}
	return sourceAliasRemoval, o.ops.remove(r.Root, from)
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
	compared := sha256.New()
	_, _ = compared.Write(m.header(o.id))
	if err := stream(m, produce, io.MultiWriter(w, compared), scratch[:scratchBytes/2], start, true); err != nil {
		return nil, err
	}
	if !bytes.Equal(compared.Sum(nil), observed.footer[:]) {
		return nil, ErrIntegrityV1
	}
	if err := o.finishFile(f); err != nil {
		return nil, err
	}
	return o.prepared(r, m, name, observed)
}

package exclusionjournal

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
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

type sourceNamespace func(*sourceRoot, string, string) error

const (
	publicStagePrefix = ".staging-"
	heldStagePrefix   = ".stage-hold-"
)

type sourceFS struct {
	statfs          func(int, *syscall.Statfs_t) error
	write           func(*os.File, []byte) (int, error)
	fileSync, close func(*os.File) error
	chmod           func(*os.File, os.FileMode) error
	namespace       func(sourceNamespace, *sourceRoot, string, string) error
	remove          func(*os.Root, string) error
	dirSync         func(*os.File) error
}
type sourceDebt struct {
	name, leaf, shared             string
	file                           filelock.IdentityV1
	size, observed, qualified      uint64
	unlinkTried, removed, unfunded bool
}

type sourceUsage struct {
	files, bytes        uint64
	stage, pendingStage sourceDebt
	releaseMissing      int
	releaseMismatch     error
}

var realSourceFS = sourceFS{statfs: syscall.Fstatfs, write: (*os.File).Write, fileSync: (*os.File).Sync, close: (*os.File).Close, chmod: (*os.File).Chmod, namespace: runSourceNamespace, remove: (*os.Root).Remove, dirSync: (*os.File).Sync}

func runSourceNamespace(op sourceNamespace, r *sourceRoot, from, to string) error {
	return op(r, from, to)
}

// sourceEntries bounds namespace observation by all entries in the held root.
func (o *SourceOwnerV1) sourceEntries(r *sourceRoot) ([]os.DirEntry, error) {
	f, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := f.ReadDir(int(min(o.limits.Scans, math.MaxInt)))
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if uint64(len(entries)) >= o.limits.Scans {
		return nil, ErrCapacityV1
	}
	return entries, nil
}

func (o *SourceOwnerV1) census(r *sourceRoot) (sourceUsage, error) {
	entries, err := o.sourceEntries(r)
	if err != nil {
		return sourceUsage{}, err
	}
	o.resolvePublications(r)
	return o.censusFiles(r, entries)
}

// censusFiles charges named captures and stage custody from one bounded listing.
func (o *SourceOwnerV1) censusFiles(r *sourceRoot, entries []os.DirEntry) (sourceUsage, error) {
	stage, err := censusStage(r, entries)
	if err != nil {
		return sourceUsage{}, err
	}
	stage, pending, err := o.matchStage(r, stage)
	if err != nil {
		return sourceUsage{}, err
	}
	used := sourceUsage{stage: stage, pendingStage: pending}
	if err := o.chargeBindings(&used); err != nil {
		return sourceUsage{}, err
	}
	return o.censusCaptures(r, entries, used)
}

// chargeBindings retains the admitted charge of each bound logical capture.
func (o *SourceOwnerV1) chargeBindings(used *sourceUsage) error {
	for _, backing := range o.live {
		if err := o.charge(used, backing.size); err != nil {
			return err
		}
		if backing.issued {
			used.releaseMissing++
		}
	}
	return nil
}

// censusCaptures checks named backing and tracks the existing release intent.
func (o *SourceOwnerV1) censusCaptures(r *sourceRoot, entries []os.DirEntry, used sourceUsage) (sourceUsage, error) {
	absentRelease := o.release
	for _, entry := range entries {
		name := entry.Name()
		if name == releaseFile && o.release == nil {
			return sourceUsage{}, ErrIntegrityV1
		}
		if nonCaptureName(name) {
			continue
		}
		if err := o.censusCapture(r, name, &used); err != nil {
			return sourceUsage{}, err
		}
		if absentRelease != nil && name == absentRelease.name {
			absentRelease = nil
		}
	}
	return o.finishCensus(used, absentRelease)
}

func nonCaptureName(name string) bool {
	return strings.HasPrefix(name, publicStagePrefix) || strings.HasPrefix(name, heldStagePrefix) ||
		name == releaseFile || name == releaseScratch
}

// finishCensus includes unlinked charges until their custody is retired.
func (o *SourceOwnerV1) finishCensus(used sourceUsage, absentRelease *sourceRelease) (sourceUsage, error) {
	if absentRelease != nil {
		backing := o.live[absentRelease.name]
		if backing == nil {
			if err := o.charge(&used, absentRelease.size); err != nil {
				return sourceUsage{}, err
			}
		} else if backing.issued {
			used.releaseMissing--
		}
	}
	for _, stage := range [...]sourceDebt{used.stage, used.pendingStage} {
		if stage.name != "" && stage.shared == "" {
			if err := o.charge(&used, stage.size); err != nil {
				return sourceUsage{}, err
			}
		}
	}
	return used, nil
}

func (used sourceUsage) releaseBindingError() error {
	if used.releaseMismatch != nil {
		return used.releaseMismatch
	}
	if used.releaseMissing != 0 {
		return ErrIntegrityV1
	}
	return nil
}

func (o *SourceOwnerV1) charge(used *sourceUsage, size uint64) error {
	if size > o.limits.Bytes-used.bytes || used.files >= o.limits.Files {
		return ErrCapacityV1
	}
	used.files++
	used.bytes += size
	return nil
}

// censusCapture keeps a bound charge on its logical name and observes stage aliases by inode.
func (o *SourceOwnerV1) censusCapture(r *sourceRoot, name string, used *sourceUsage) error {
	if !sourceHexKey(name) {
		return ErrIntegrityV1
	}
	info, err := sourceEntryInfo(r, name, nil)
	if err != nil {
		return ErrIntegrityV1
	}
	id := filelock.FileIdentityV1(info)
	backing := o.live[name]
	if backing == nil || backing.file == id {
		used.stage.observeAlias(name, id, "")
		used.pendingStage.observeAlias(name, id, cmp.Or(o.pendingStage.shared, o.debt.shared))
	}
	if backing != nil {
		used.matchReleasedCapture(backing, id, uint64(info.Size()))
		return nil
	}
	return o.charge(used, uint64(info.Size()))
}

// matchReleasedCapture keeps the established checks for previously issued captures.
func (used *sourceUsage) matchReleasedCapture(backing *sourceIncarnation, id filelock.IdentityV1, size uint64) {
	if !backing.issued {
		return
	}
	used.releaseMissing--
	switch {
	case used.releaseMismatch != nil:
	case backing.file != id:
		used.releaseMismatch = ErrIdentityV1
	case backing.size != size:
		used.releaseMismatch = ErrIntegrityV1
	}
}

func (d *sourceDebt) observeAlias(name string, id filelock.IdentityV1, previous string) {
	if d.name != "" && d.file == id && (!d.removed || name == previous) {
		d.shared = name
	}
}

// resolvePublications keeps unconfirmed capture bindings until absence or exact identity is proved.
func (o *SourceOwnerV1) resolvePublications(r *sourceRoot) {
	for name, backing := range o.live {
		if !backing.uncertain {
			continue
		}
		info, err := r.Lstat(name)
		switch {
		case errors.Is(err, os.ErrNotExist):
			delete(o.live, name)
		case err == nil && sameSourceFile(info, backing.file):
			backing.uncertain = false
		}
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

func sameSourceFile(info os.FileInfo, expected filelock.IdentityV1) bool {
	return info != nil && info.Mode().IsRegular() && filelock.FileIdentityV1(info) == expected
}

func sourceHexKey(name string) bool {
	if len(name) != sha256.Size*2 {
		return false
	}
	var decoded [sha256.Size]byte
	_, err := hex.Decode(decoded[:], []byte(name))
	return err == nil
}

func (d sourceDebt) held() bool { return strings.HasPrefix(d.leaf, heldStagePrefix) }

// censusStage observes the one staging slot and rejects ambiguous custody before changes.
func censusStage(r *sourceRoot, entries []os.DirEntry) (sourceDebt, error) {
	var stage sourceDebt
	for _, entry := range entries {
		next, err := readStageEntry(r, entry.Name())
		if err != nil {
			return sourceDebt{}, err
		}
		if next.name == "" {
			continue
		}
		if stage.name != "" {
			return sourceDebt{}, stageCollision(stage, next)
		}
		stage = next
	}
	return stage, nil
}

func readStageEntry(r *sourceRoot, leaf string) (sourceDebt, error) {
	name, public := strings.CutPrefix(leaf, publicStagePrefix)
	if !public {
		var held bool
		name, held = strings.CutPrefix(leaf, heldStagePrefix)
		if !held {
			return sourceDebt{}, nil
		}
	}
	key := strings.ToLower(name)
	if !sourceHexKey(name) || !public && key != name {
		return sourceDebt{}, ErrIntegrityV1
	}
	info, err := sourceEntryInfo(r, leaf, ErrIntegrityV1)
	if err != nil {
		return sourceDebt{}, err
	}
	size := uint64(info.Size())
	return sourceDebt{name: key, leaf: leaf, size: size, observed: size, file: filelock.FileIdentityV1(info)}, nil
}

func stageCollision(first, second sourceDebt) error {
	if first.name == second.name && first.held() != second.held() {
		return syscall.EEXIST
	}
	return ErrBusyV1
}

// matchStage keeps the original identity and unretired charge across retries.
func (o *SourceOwnerV1) matchStage(r *sourceRoot, next sourceDebt) (sourceDebt, sourceDebt, error) {
	d := o.debt
	pending := o.pendingStage
	pending.shared = ""
	switch {
	case d.name == "":
		return next, pending, nil
	case d.stageAbsent(r, next):
		d.removed = true
		d.shared = ""
		return next, d, nil
	case next.name == "" && d.unfunded:
		return next, pending, nil
	}
	if err := d.matchStageIncarnation(next); err != nil {
		return sourceDebt{}, sourceDebt{}, err
	}
	next.qualified, next.unlinkTried = d.qualified, d.unlinkTried
	next.size = max(next.size, next.qualified)
	return next, pending, nil
}

// matchStageIncarnation checks that observed staging still represents the owed custody.
func (d sourceDebt) matchStageIncarnation(next sourceDebt) error {
	switch {
	case next.name == "":
		return ErrIdentityV1
	case d.name != next.name:
		return ErrBusyV1
	case d.held() && !next.held():
		return ErrIdentityV1
	case d.file != (filelock.IdentityV1{}) && d.file != next.file:
		return ErrIdentityV1
	}
	return nil
}

func (d sourceDebt) stageAbsent(r *sourceRoot, next sourceDebt) bool {
	if !d.unlinkTried || next.leaf == d.leaf {
		return false
	}
	_, err := r.Lstat(d.leaf)
	return errors.Is(err, os.ErrNotExist)
}

// space grants provisional credit only against an observed single-link stage.
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

func (d sourceDebt) diskCredit(r *sourceRoot) uint64 {
	if d.name == "" || d.removed || d.shared != "" {
		return 0
	}
	info, err := sourceEntryInfo(r, d.leaf, nil)
	if err != nil || d.file != filelock.FileIdentityV1(info) {
		return 0
	}
	return min(d.observed, uint64(info.Size()), singleLinkAllocatedBytes(info))
}

// singleLinkAllocatedBytes converts known exclusive allocations to bytes without overflow.
func singleLinkAllocatedBytes(info os.FileInfo) uint64 {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil || st.Nlink != 1 || st.Blocks <= 0 || uint64(st.Blocks) > math.MaxUint64/512 {
		return 0
	}
	return uint64(st.Blocks) * 512
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
		*windows = newSourceWindows(m)
		scratch = windows.scratch
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
	return o.withFiles(account, m, false, func(r *sourceRoot, m SourceManifestV1, size uint64, used sourceUsage) error {
		if err := used.releaseBindingError(); err != nil {
			return err
		}
		return o.readCapture(r, m, size, visit)
	})
}

// readCapture qualifies the named incarnation before exposing verified bytes.
func (o *SourceOwnerV1) readCapture(r *sourceRoot, m SourceManifestV1, size uint64, visit func(SourcePartV1) error) error {
	name := m.name(o.id)
	switch {
	case o.debt.name == name, o.pendingStage.name == name, o.release != nil && o.release.name == name:
		return ErrBusyV1
	case visit == nil:
		return ErrIntegrityV1
	}
	expected := o.live[name]
	unobserved := ErrUnavailableV1
	if expected != nil {
		unobserved = ErrIntegrityV1
	}
	f, err := openSourceFile(r, name, unobserved)
	if err != nil {
		return err
	}
	defer f.Close()
	var windows sourceWindows
	if _, err := o.qualifyWindows(f, m, size, nil, expected, ErrIntegrityV1, &windows); err != nil {
		return err
	}
	return windows.deliver(f, m, len(m.header(o.id)), visit)
}

type sourceWindows struct {
	hashes  [][sha256.Size]byte
	scratch []byte
	failure error
}

func newSourceWindows(m SourceManifestV1) sourceWindows {
	var count uint64
	for _, part := range m.Parts {
		count += sourceWindowCount(part.Length)
	}
	return sourceWindows{hashes: make([][sha256.Size]byte, 0, count), scratch: make([]byte, scratchBytes)}
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
		if err := o.adoptStage(r, used); err != nil {
			return err
		}
		return use(r, m, size, used)
	})
}

// adoptStage takes a public pin or recognizes the same inode in protected custody.
func (o *SourceOwnerV1) adoptStage(r *sourceRoot, used sourceUsage) error {
	stage := used.stage
	switch {
	case stage.name == "" && o.debt.unfunded:
		return nil
	case stage.name == "", stage.held():
		o.stage.Clear()
	default:
		if err := o.retainStage(r, stage); err != nil {
			return err
		}
	}
	o.debt, o.pendingStage = stage, used.pendingStage
	return nil
}

// retainStage pins a read-only staging incarnation under the Store's source claim.
func (o *SourceOwnerV1) retainStage(r *sourceRoot, stage sourceDebt) error {
	if o.limits.Descriptors < 5 {
		return ErrCapacityV1
	}
	if o.stage.File != nil {
		info, _ := o.stage.File.Stat()
		if !sameSourceFile(info, stage.file) {
			return ErrIdentityV1
		}
		return nil
	}
	var err error
	o.stage.File, err = r.pinFile(stage.leaf, stage.file)
	return err
}

// reconcile returns disk charges only after unlink and parent synchronization both succeed.
func (o *SourceOwnerV1) reconcile(r *sourceRoot) error {
	if err := o.syncStageRemoval(r); err != nil || o.debt.name == "" || o.debt.unfunded {
		return err
	}
	if err := o.unlinkStage(r); err != nil {
		return err
	}
	return o.syncStageRemoval(r)
}

// syncStageRemoval retires the unlinked charge after durable directory sync.
func (o *SourceOwnerV1) syncStageRemoval(r *sourceRoot) error {
	if o.pendingStage.name == "" {
		return nil
	}
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	o.pendingStage = sourceDebt{}
	return nil
}

// unlinkStage targets only a created or matched protected leaf.
func (o *SourceOwnerV1) unlinkStage(r *sourceRoot) error {
	d := &o.debt
	if !d.held() {
		if err := o.claimStage(r, d); err != nil {
			return err
		}
	}
	info, err := sourceEntryInfo(r, d.leaf, nil)
	if err != nil {
		return err
	}
	if d.file != (filelock.IdentityV1{}) && !sameSourceFile(info, d.file) {
		return ErrIdentityV1
	}
	d.size = max(d.qualified, uint64(info.Size()))
	d.unlinkTried = true
	if err := o.ops.remove(r.Root, d.leaf); err != nil {
		return err
	}
	if _, err := r.Lstat(d.leaf); !errors.Is(err, os.ErrNotExist) {
		return ErrIdentityV1
	}
	d.removed = true
	o.pendingStage, o.debt = *d, sourceDebt{}
	return nil
}

// claimStage transfers only the pinned public incarnation into protected custody.
func (o *SourceOwnerV1) claimStage(r *sourceRoot, d *sourceDebt) error {
	info, err := sourceEntryInfo(r, d.leaf, nil)
	if err != nil || o.stage.File == nil || !sameSourceFile(info, d.file) {
		return ErrIdentityV1
	}
	held := heldStagePrefix + d.name
	if err := o.ops.namespace((*sourceRoot).renameExclusive, r, d.leaf, held); err != nil {
		return err
	}
	info, err = sourceEntryInfo(r, held, ErrIdentityV1)
	if err != nil || !sameSourceFile(info, d.file) {
		if o.ops.namespace((*sourceRoot).renameExclusive, r, held, d.leaf) == nil {
			_ = o.ops.dirSync(r.pin)
		}
		return cmp.Or(err, ErrIdentityV1)
	}
	d.leaf = held
	o.stage.Clear()
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
	if err := used.releaseBindingError(); err != nil {
		return nil, err
	}
	name := m.name(o.id)
	if o.debt.otherKey(name) || o.pendingStage.otherKey(name) {
		return nil, ErrBusyV1
	}
	f, err := openSourceFile(r, name, nil)
	if err == nil {
		defer f.Close()
		return o.reuse(r, f, m, name, size, produce)
	}
	if !errors.Is(err, os.ErrNotExist) || o.live[name] != nil {
		return nil, ErrIntegrityV1
	}
	recheck, err := o.admitPublication(r, size, used)
	if err != nil {
		return nil, err
	}
	return o.publish(r, m, name, produce, size, recheck)
}

func (d sourceDebt) otherKey(name string) bool { return d.name != "" && d.name != name }

// admitPublication projects replacement of an independently charged stage.
func (o *SourceOwnerV1) admitPublication(r *sourceRoot, size uint64, used sourceUsage) (bool, error) {
	for _, stage := range [...]sourceDebt{used.stage, used.pendingStage} {
		if stage.name != "" && stage.shared == "" {
			used.files--
			used.bytes -= stage.size
		}
	}
	if used.files >= o.limits.Files || size > o.limits.Bytes-used.bytes {
		return false, ErrCapacityV1
	}
	return o.space(r, size, used.stage)
}

// prepared syncs, checks the live binding, then issues its handle.
func (o *SourceOwnerV1) prepared(r *sourceRoot, pin *os.File, m SourceManifestV1, name string, scratch []byte) (*PreparedSourceV1, error) {
	if err := o.ops.dirSync(r.pin); err != nil {
		return nil, err
	}
	o.pendingStage = sourceDebt{}
	token := o.live[name]
	info, err := r.Lstat(name)
	if err != nil || !sameSourceFile(info, token.file) || o.currentRoot() != nil {
		return nil, ErrIdentityV1
	}
	if _, err := o.qualify(pin, m, token.size, scratch, token, ErrIntegrityV1); err != nil {
		return nil, err
	}
	if err := o.captureSlot(r, name); err != nil {
		return nil, err
	}
	o.clearUnfundedStage(name)
	token.issued = true
	return &PreparedSourceV1{manifest: m, name: name, incarnation: token}, nil
}

// clearUnfundedStage retires an observed empty slot after successful reconciliation.
func (o *SourceOwnerV1) clearUnfundedStage(name string) {
	if o.debt.unfunded && o.debt.name == name {
		o.debt = sourceDebt{}
	}
}

// captureSlot checks public staging spellings without claiming or changing them.
func (o *SourceOwnerV1) captureSlot(r *sourceRoot, name string) error {
	entries, err := o.sourceEntries(r)
	if err == ErrCapacityV1 {
		return err
	}
	if err != nil {
		return ErrIdentityV1
	}
	for _, entry := range entries {
		key, public := strings.CutPrefix(entry.Name(), publicStagePrefix)
		if public && sourceHexKey(key) && strings.EqualFold(name, key) {
			return ErrIdentityV1
		}
	}
	return nil
}

// publish keeps known capture custody apart from its temporary service alias.
func (o *SourceOwnerV1) publish(r *sourceRoot, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64, recheck bool) (_ *PreparedSourceV1, err error) {
	w := &sourceFileWriter{o: o}
	cleanup := true
	defer o.closeStagedWrite(r, w, &cleanup, &err)
	scratch := make([]byte, scratchBytes)
	observed, err := o.writeBundle(r, w, m, name, produce, size, recheck, scratch)
	if err != nil {
		return nil, err
	}
	o.debt.size, o.debt.observed, o.debt.qualified = observed.size, observed.size, observed.size
	pin, err := o.finishPinned(r, o.debt.leaf, w.file, observed.file)
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	if err := o.captureSlot(r, name); err != nil {
		cleanup = false
		return nil, err
	}
	if info, _ := r.Lstat(o.debt.leaf); !sameSourceFile(info, observed.file) {
		cleanup = false
		return nil, ErrIdentityV1
	}
	cleanup = false
	visibility, err := o.linkCapture(r, name, &observed)
	cleanup = visibility == sourceNotVisible
	if err != nil {
		return nil, err
	}
	if err := o.unlinkStage(r); err != nil {
		return nil, err
	}
	return o.prepared(r, pin, m, name, scratch)
}

// closeStagedWrite closes the write handle and reconciles disposable staging.
func (o *SourceOwnerV1) closeStagedWrite(r *sourceRoot, w *sourceFileWriter, cleanup *bool, result *error) {
	if w.file == nil {
		return
	}
	_ = w.file.Close()
	if *cleanup {
		if err := o.reconcile(r); err != nil {
			*result = errors.Join(*result, err)
		}
	}
}

func (o *SourceOwnerV1) finishFile(f *os.File) error {
	if err := o.ops.fileSync(f); err != nil {
		return err
	}
	return o.ops.close(f)
}

// finishPinned keeps a read-only reference through close and namespace handoff.
func (o *SourceOwnerV1) finishPinned(r *sourceRoot, name string, f *os.File, id filelock.IdentityV1) (*os.File, error) {
	pin, pinErr := r.pinFile(name, id)
	err := cmp.Or(o.finishFile(f), pinErr)
	if err != nil {
		_ = pin.Close()
		return nil, err
	}
	return pin, nil
}

// startBundle retires old custody before any newly funded content operation.
func (o *SourceOwnerV1) startBundle(r *sourceRoot, w *sourceFileWriter, name string, size uint64, recheck bool) error {
	if err := o.reconcile(r); err != nil {
		return err
	}
	if recheck {
		if _, err := o.space(r, size, sourceDebt{}); err != nil {
			return err
		}
	}
	leaf := heldStagePrefix + name
	f, err := r.OpenFile(leaf, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	w.file = f
	o.debt = sourceDebt{name: name, leaf: leaf, size: size}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	o.debt.file = filelock.FileIdentityV1(info)
	o.debt.size = uint64(info.Size())
	return nil
}

// writeBundle verifies the persisted footer against independently hashed producer bytes.
func (o *SourceOwnerV1) writeBundle(r *sourceRoot, w *sourceFileWriter, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64, recheck bool, scratch []byte) (sourceIncarnation, error) {
	hash := sha256.New()
	out := io.MultiWriter(w, hash)
	start := func() error {
		if err := o.startBundle(r, w, name, size, recheck); err != nil {
			return err
		}
		_, err := out.Write(m.header(o.id))
		return cmp.Or(err, o.ops.chmod(w.file, 0o600))
	}
	if err := stream(m, produce, out, scratch, start, true); err != nil {
		return sourceIncarnation{}, err
	}
	expected := sourceIncarnation{file: o.debt.file, size: size, footer: [sha256.Size]byte(hash.Sum(nil))}
	if _, err := w.Write(expected.footer[:]); err != nil {
		return sourceIncarnation{}, err
	}
	return o.qualify(w.file, m, size, scratch, &expected, ErrIntegrityV1)
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
)

// linkCapture binds the qualified original before the namespace result is known.
func (o *SourceOwnerV1) linkCapture(r *sourceRoot, name string, observed *sourceIncarnation) (sourceVisibility, error) {
	observed.uncertain = true
	o.live[name] = observed
	err := o.ops.namespace((*sourceRoot).Link, r, o.debt.leaf, name)
	visibility, out := observeLink(r, name, observed.file, err)
	switch visibility {
	case sourceNotVisible:
		delete(o.live, name)
	case sourceVisible:
		o.debt.shared = name
		observed.uncertain = false
	}
	return visibility, out
}

func observeLink(r *sourceRoot, name string, id filelock.IdentityV1, err error) (sourceVisibility, error) {
	if errors.Is(err, os.ErrExist) {
		return sourceNotVisible, ErrIntegrityV1
	}
	info, statErr := r.Lstat(name)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		return sourceNotVisible, cmp.Or(err, ErrIntegrityV1)
	case statErr != nil:
		return sourceIndeterminate, cmp.Or(err, statErr)
	case !sameSourceFile(info, id):
		return sourceNotVisible, cmp.Or(err, ErrIdentityV1)
	}
	return sourceVisible, err
}

// renameVisible retains the existing release marker publication observation.
func (o *SourceOwnerV1) renameVisible(r *sourceRoot, from, to string) (bool, error) {
	if _, err := r.Lstat(to); !errors.Is(err, os.ErrNotExist) {
		return false, ErrIntegrityV1
	}
	err := o.ops.namespace((*sourceRoot).Rename, r, from, to)
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
	digest  hash.Hash
}

func (w *compareSourceWriter) Write(data []byte) (int, error) {
	scratch := w.scratch[:len(data)]
	if _, err := w.file.ReadAt(scratch, w.offset); err != nil || !bytes.Equal(data, scratch) {
		return 0, ErrIntegrityV1
	}
	w.offset += int64(len(data))
	return w.digest.Write(data)
}

// verifyDigest checks the independently accumulated producer digest.
func (w *compareSourceWriter) verifyDigest(expected [sha256.Size]byte) error {
	if [sha256.Size]byte(w.digest.Sum(nil)) != expected {
		return ErrIntegrityV1
	}
	return nil
}

// reuse compares the producer with the initial qualified binding before durable handoff.
func (o *SourceOwnerV1) reuse(r *sourceRoot, f *os.File, m SourceManifestV1, name string, size uint64, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	scratch := make([]byte, scratchBytes)
	observed, err := o.qualify(f, m, size, scratch, o.live[name], ErrIntegrityV1)
	if err != nil {
		return nil, err
	}
	o.live[name] = cmp.Or(o.live[name], &observed)
	if err := o.compareBundle(r, f, m, observed, produce, scratch); err != nil {
		return nil, err
	}
	pin, err := o.finishPinned(r, name, f, observed.file)
	if err != nil {
		return nil, err
	}
	defer pin.Close()
	return o.prepared(r, pin, m, name, scratch)
}

// compareBundle hashes the matching producer stream before requalifying the file.
func (o *SourceOwnerV1) compareBundle(r *sourceRoot, f *os.File, m SourceManifestV1, observed sourceIncarnation, produce func(func(SourcePartV1) error) error, scratch []byte) error {
	header := m.header(o.id)
	compared := sha256.New()
	_, _ = compared.Write(header)
	w := &compareSourceWriter{file: f, offset: int64(len(header)), scratch: scratch[scratchBytes/2:], digest: compared}
	start := func() error { return o.reconcile(r) }
	if err := stream(m, produce, w, scratch[:scratchBytes/2], start, true); err != nil {
		return err
	}
	if err := w.verifyDigest(observed.footer); err != nil {
		return err
	}
	_, err := o.qualify(f, m, observed.size, scratch, &observed, ErrIntegrityV1)
	return err
}

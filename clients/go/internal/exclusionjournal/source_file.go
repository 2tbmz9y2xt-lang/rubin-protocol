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
	name, leaf                string
	file                      filelock.IdentityV1
	binding                   *sourceIncarnation
	size, observed, qualified uint64
	shared, unlinkTried       bool
}

type sourceUsage struct {
	files, bytes, captureFiles, captureBytes             uint64
	visitedBytes, aliasBytes, stageCovered, quotaCovered uint64
	stage, pendingStage                                  sourceDebt
	quota                                                os.FileInfo
	releaseMissing                                       int
	stageErr, visitErr                                   error
	stageReached, overBytes, forRelease, completeCharge  bool
	entries                                              []os.DirEntry
}

var realSourceFS = sourceFS{statfs: syscall.Fstatfs, write: (*os.File).Write, fileSync: (*os.File).Sync, close: (*os.File).Close, chmod: (*os.File).Chmod, namespace: runSourceNamespace, remove: (*os.Root).Remove, dirSync: (*os.File).Sync}

func runSourceNamespace(op sourceNamespace, r *sourceRoot, from, to string) error {
	return op(r, from, to)
}

func (o *SourceOwnerV1) sourceEntries(r *sourceRoot) ([]os.DirEntry, error) {
	f, err := openSourceAt(int(r.pin.Fd()), ".", unix.O_DIRECTORY)
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

func (o *SourceOwnerV1) census(r *sourceRoot, forRelease bool) (sourceUsage, error) {
	entries, err := o.sourceEntries(r)
	if err != nil {
		return sourceUsage{}, err
	}
	o.resolvePublications(r)
	used, err := o.censusFiles(r, entries, forRelease)
	if used.stageReached && used.stage.held() && o.debt.file == used.stage.file {
		o.debt.leaf = used.stage.leaf
		o.stage.Clear()
	}
	used.entries = entries
	return used, err
}

func (o *SourceOwnerV1) censusFiles(r *sourceRoot, entries []os.DirEntry, forRelease bool) (sourceUsage, error) {
	if o.debt.unlinkTried {
		_ = o.observeStageRemoval(r)
	}
	stage, prefix, stopErr := censusStage(r, entries)
	if stopErr != nil && stage.held() {
		return sourceUsage{}, stopErr
	}
	stageErr := o.debt.qualifyStage(&stage)
	used := o.stagingUsage(stage)
	used.forRelease, used.stageErr = forRelease, stageErr
	o.chargeBindings(&used)
	used, err := o.censusCaptures(r, entries[:prefix], used, stopErr)
	if stopErr != nil && strings.HasPrefix(entries[prefix].Name(), heldStagePrefix) {
		return sourceUsage{stage: stage, stageReached: used.stageReached}, stopErr
	}
	return used, err
}

func (o *SourceOwnerV1) stagingUsage(stage sourceDebt) sourceUsage {
	used := sourceUsage{stage: stage, pendingStage: o.pendingStage}
	used.pendingStage.shared = false
	if info, _ := o.stage.Quota.Stat(); used.pendingStage.binding == nil && sameSourceFile(info, used.pendingStage.file) {
		used.quota = info
	}
	return used
}

// chargeBindings reserves space for bound captures, including missing files.
func (o *SourceOwnerV1) chargeBindings(used *sourceUsage) {
	for _, backing := range o.live {
		if backing.issued {
			used.releaseMissing++
			if used.forRelease {
				continue
			}
		}
		size, _ := used.bindingCharge(backing)
		if used.stage.binding == backing {
			used.coverQuota(backing.file, size, true)
		}
		o.charge(used, size)
	}
}

func (used *sourceUsage) bindingCharge(backing *sourceIncarnation) (uint64, bool) {
	size, shared := backing.size, false
	for _, stage := range [...]*sourceDebt{&used.stage, &used.pendingStage} {
		if stage.binding == backing {
			size, shared, stage.shared = max(size, stage.size), true, true
		}
	}
	return size, shared
}

func (o *SourceOwnerV1) censusCaptures(r *sourceRoot, entries []os.DirEntry, used sourceUsage, stopErr error) (sourceUsage, error) {
	absentRelease := o.release
	for _, entry := range entries {
		name := entry.Name()
		if err := o.censusEntry(r, name, &used); err != nil {
			return used, cmp.Or(used.visitErr, err)
		}
		if stopErr != nil && used.visitErr != nil {
			return used, used.visitErr
		}
		if absentRelease != nil && name == absentRelease.name {
			absentRelease = nil
		}
	}
	if stopErr != nil {
		return used, stopErr
	}
	return o.finishCensus(used, absentRelease)
}

func (o *SourceOwnerV1) censusEntry(r *sourceRoot, name string, used *sourceUsage) error {
	switch name {
	case used.stage.leaf:
		if used.stageErr != nil {
			return used.stageErr
		}
		if cmp.Or(o.observedStage, used.stage.name) != used.stage.name {
			return ErrBusyV1
		}
		used.stageReached = used.visitErr == nil
		size := used.stage.size - used.aliasBytes
		if used.forRelease {
			size = used.stage.observed
			o.charge(used, size)
		}
		o.visitCensusBytes(used, size, 0, false)
	case releaseFile:
		if o.release == nil {
			return ErrIntegrityV1
		}
	case releaseScratch:
	default:
		return o.censusCapture(r, name, used)
	}
	return nil
}

func (o *SourceOwnerV1) finishCensus(used sourceUsage, absentRelease *sourceRelease) (sourceUsage, error) {
	if !used.forRelease {
		if absentRelease != nil {
			if backing := o.live[absentRelease.name]; backing == nil {
				o.charge(&used, absentRelease.size)
			} else if backing.issued {
				used.releaseMissing--
			}
		}
		used.captureFiles, used.captureBytes = used.files, used.bytes
		o.chargeStages(&used)
	}
	if used.overBytes || used.files > o.limits.Files || any(used.visitErr) == any(ErrCapacityV1) {
		return used, ErrCapacityV1
	}
	return used, used.stageErr
}

// chargeStages counts shared backing once (RUBIN_COMPACT_BLOCKS.md Section 10).
func (o *SourceOwnerV1) chargeStages(used *sourceUsage) {
	stage, pending := used.stage, used.pendingStage
	if used.quota != nil {
		pending.size = max(pending.size, sourceFileSize(used.quota))
		if stage.file == pending.file {
			pending.size = max(pending.size, stage.size)
			stage = sourceDebt{}
		}
		pending.size -= min(pending.size, used.quotaCovered)
		if pending.shared {
			o.chargeBytes(used, pending.size)
		}
	}
	stage.size -= min(stage.size, used.stageCovered)
	for _, stage := range [...]sourceDebt{stage, pending} {
		if stage.name != "" && !stage.shared {
			o.charge(used, stage.size)
		}
	}
}

func (used sourceUsage) admissionError(err error) error {
	if err := cmp.Or(used.visitErr, err); err != nil {
		return err
	}
	if used.releaseMissing != 0 {
		return ErrIntegrityV1
	}
	return nil
}

func (o *SourceOwnerV1) charge(used *sourceUsage, size uint64) {
	o.chargeBytes(used, size)
	used.files++
}

func (o *SourceOwnerV1) chargeBytes(used *sourceUsage, size uint64) {
	if size > o.limits.Bytes-used.bytes {
		used.overBytes = true
		return
	}
	used.bytes += size
}

// visitCensusBytes charges entries in directory order until the first refusal.
func (o *SourceOwnerV1) visitCensusBytes(used *sourceUsage, size, aliasBytes uint64, alias bool) {
	if used.visitErr != nil || used.completeCharge {
		return
	}
	if covered := min(aliasBytes, used.stage.size); alias && !used.forRelease && covered > used.aliasBytes {
		if used.stageReached {
			size -= covered - used.aliasBytes
		}
		used.aliasBytes = covered
	}
	if size > o.limits.Bytes-used.visitedBytes {
		used.visitErr = ErrCapacityV1
		return
	}
	used.visitedBytes += size
}

func (o *SourceOwnerV1) censusCapture(r *sourceRoot, name string, used *sourceUsage) error {
	if !sourceHexKey(name) {
		return ErrIntegrityV1
	}
	info, err := sourceEntryInfo(r, name, nil)
	if err != nil {
		return ErrIntegrityV1
	}
	id := filelock.FileIdentityV1(info)
	size := sourceFileSize(info)
	backing := o.live[name]
	if backing != nil && backing.issued {
		used.observeIssuedCapture(backing, id, size)
	}
	if backing == nil {
		o.chargeNamedCapture(used, nil, id, size)
	} else {
		o.chargeBoundCapture(used, backing, id, size)
	}
	return nil
}

func (o *SourceOwnerV1) chargeNamedCapture(used *sourceUsage, backing *sourceIncarnation, id filelock.IdentityV1, size uint64) {
	o.visitCensusBytes(used, size, size, id == used.stage.file)
	o.charge(used, size)
	used.coverQuota(id, size, true)
	if backing != nil && backing.file != id {
		backing = nil
	}
	used.stage.observeAlias(id, backing)
}

func (o *SourceOwnerV1) chargeBoundCapture(used *sourceUsage, backing *sourceIncarnation, id filelock.IdentityV1, size uint64) {
	reserved, shared := used.bindingCharge(backing)
	if used.forRelease && backing.issued || shared && id != backing.file {
		o.chargeNamedCapture(used, backing, id, size)
		return
	}
	excess := size - min(size, reserved)
	if !shared && backing.issued && !used.completeCharge {
		excess = 0
	}
	o.chargeReservedCapture(used, backing, id, size, reserved, excess)
}

func (o *SourceOwnerV1) chargeReservedCapture(used *sourceUsage, backing *sourceIncarnation, id filelock.IdentityV1, size, reserved, excess uint64) {
	if !used.forRelease {
		size = max(size, backing.size)
	}
	matches := id == backing.file
	extent, covered := excess, excess
	if matches {
		extent = size
		covered += reserved
		used.stage.observeAlias(id, backing)
	} else if id == used.stage.file {
		used.stageCovered = max(used.stageCovered, extent)
	}
	o.visitCensusBytes(used, size, extent, id == used.stage.file)
	o.chargeBytes(used, excess)
	used.coverQuota(id, covered, matches)
}

func (used *sourceUsage) coverQuota(id filelock.IdentityV1, size uint64, full bool) {
	if used.quota != nil && used.pendingStage.file == id {
		used.pendingStage.shared = used.pendingStage.shared || full
		used.quotaCovered = max(used.quotaCovered, size)
	}
}

func (used *sourceUsage) observeIssuedCapture(backing *sourceIncarnation, id filelock.IdentityV1, size uint64) {
	used.releaseMissing--
	switch {
	case used.visitErr != nil:
	case backing.file != id:
		used.visitErr = ErrIdentityV1
	case backing.size != size:
		used.visitErr = ErrIntegrityV1
	}
}

func (d *sourceDebt) observeAlias(id filelock.IdentityV1, backing *sourceIncarnation) {
	if d.name != "" && d.file == id {
		if d.shared {
			backing = cmp.Or(d.binding, backing)
		}
		d.shared, d.binding = true, backing
	}
}

// resolvePublications drops missing captures and confirms matching inodes.
func (o *SourceOwnerV1) resolvePublications(r *sourceRoot) {
	for name, backing := range o.live {
		if !backing.uncertain {
			continue
		}
		info, err := r.Lstat(name)
		switch {
		case errors.Is(err, os.ErrNotExist):
			o.forgetPublication(name, backing)
		case err == nil && sameSourceFile(info, backing.file):
			backing.uncertain = false
		}
	}
}

func (o *SourceOwnerV1) forgetPublication(name string, backing *sourceIncarnation) {
	delete(o.live, name)
	if o.debt.binding == backing {
		o.debt.binding, o.debt.shared = nil, false
	}
}

// openSourceFile checks that a nonblocking, no-follow open pins the observed regular file.
func openSourceFile(r *sourceRoot, name string, unobserved error, expected ...filelock.IdentityV1) (*os.File, error) {
	named, err := sourceEntryInfo(r, name, unobserved)
	if err != nil || len(expected) != 0 && !sameSourceFile(named, expected[0]) {
		return nil, cmp.Or(err, ErrIdentityV1)
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

func sourceFileSize(info os.FileInfo) uint64 {
	return uint64(max(0, info.Size()))
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

// censusStage returns the valid prefix and the first staging error.
func censusStage(r *sourceRoot, entries []os.DirEntry) (sourceDebt, int, error) {
	var stage sourceDebt
	for i, entry := range entries {
		next, err := readStageEntry(r, entry.Name())
		if err != nil {
			return stage, i, err
		}
		if next.name == "" {
			continue
		}
		if stage.name != "" {
			if stage.name == next.name && stage.held() != next.held() {
				return stage, i, syscall.EEXIST
			}
			return stage, i, ErrBusyV1
		}
		stage = next
	}
	return stage, len(entries), nil
}

func readStageEntry(r *sourceRoot, leaf string) (sourceDebt, error) {
	name, public := strings.CutPrefix(leaf, publicStagePrefix)
	if !public {
		name, _ = strings.CutPrefix(leaf, heldStagePrefix)
		if name == leaf {
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
	size := sourceFileSize(info)
	return sourceDebt{name: key, leaf: leaf, size: size, observed: size, file: filelock.FileIdentityV1(info)}, nil
}

func (d sourceDebt) qualifyStage(next *sourceDebt) error {
	switch {
	case d.name == "":
	case next.name == "":
		return ErrIdentityV1
	case d.name != next.name:
		return ErrBusyV1
	case d.held() && !next.held():
		return ErrIdentityV1
	case d.file != (filelock.IdentityV1{}) && d.file != next.file:
		return ErrIdentityV1
	default:
		next.binding, next.qualified, next.unlinkTried = d.binding, d.qualified, d.unlinkTried
		next.size = max(next.size, next.qualified)
	}
	return nil
}

// space caps staging credit at the smaller allocation observed around statfs.
func (o *SourceOwnerV1) space(r *sourceRoot, required uint64, stage sourceDebt) (bool, error) {
	credit := stage.diskCredit(r, required)
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
	if full-available > min(credit, stage.diskCredit(r, required)) {
		return false, ErrCapacityV1
	}
	return true, nil
}

func (d sourceDebt) diskCredit(r *sourceRoot, required uint64) uint64 {
	if d.name == "" || d.shared {
		return 0
	}
	info, err := sourceEntryInfo(r, d.leaf, nil)
	if err != nil {
		return 0
	}
	return d.allocationCredit(info, required)
}

func (d sourceDebt) allocationCredit(info os.FileInfo, required uint64) uint64 {
	if d.file != filelock.FileIdentityV1(info) {
		return 0
	}
	return min(required, d.observed, sourceFileSize(info), singleLinkAllocatedBytes(info))
}

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
	if expected != nil {
		if file != expected.file {
			return file, nil, ErrIdentityV1
		}
		if size != expected.size {
			return file, nil, shapeError
		}
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
		switch {
		case o.debt.name == name, o.pendingStage.name == name, o.observedStage == name, o.release != nil && o.release.name == name:
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
	})
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
		_ = o.retireStageWitness(r)
		used, err := o.census(r, false)
		err = used.admissionError(err)
		adopt := preparing || used.stage.name == m.name(o.id)
		if err == nil && adopt {
			err = o.adoptStage(r, used)
		}
		if err != nil || !adopt {
			o.rememberPublicStage(r, used, err == nil)
		}
		if err != nil {
			return err
		}
		return use(r, m, size, used)
	})
}

// rememberPublicStage records a public stage without claiming it.
func (o *SourceOwnerV1) rememberPublicStage(r *sourceRoot, used sourceUsage, funded bool) {
	stage := used.stage
	if !used.stageReached || stage.held() || o.debt.name != "" || o.observedStage != "" {
		return
	}
	if funded || o.stageWitnessFits(r, stage, used.entries) {
		o.retainStageWitness(r, stage)
	}
	o.observedStage = stage.name
}

func (o *SourceOwnerV1) retainStageWitness(r *sourceRoot, stage sourceDebt) {
	if o.retainStage(r, stage) == nil {
		if info, err := o.stage.File.Stat(); err != nil || sourceFileSize(info) != stage.observed {
			o.stage.Clear()
		}
	}
}

// stageWitnessFits charges the full bounded listing without changing the admission error.
func (o *SourceOwnerV1) stageWitnessFits(r *sourceRoot, stage sourceDebt, entries []os.DirEntry) bool {
	stage.shared, stage.binding = false, nil
	reserved := o.stagingUsage(stage)
	reserved.completeCharge = true
	o.chargeBindings(&reserved)
	absentRelease := o.release
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case sourceHexKey(name):
			if o.censusCapture(r, name, &reserved) != nil {
				return false
			}
		case name == stage.leaf:
		case strings.HasPrefix(name, publicStagePrefix), strings.HasPrefix(name, heldStagePrefix):
			return false
		}
		if absentRelease != nil && name == absentRelease.name {
			absentRelease = nil
		}
	}
	_, err := o.finishCensus(reserved, absentRelease)
	return err == nil
}

// retireStageWitness closes the pin when the name no longer identifies its file.
func (o *SourceOwnerV1) retireStageWitness(r *sourceRoot) error {
	if pin := o.stage.File; pin != nil && o.debt.name == "" {
		pinned, pinErr := pin.Stat()
		named, err := r.Lstat(pin.Name())
		if pinErr != nil || errors.Is(err, os.ErrNotExist) || err == nil && !os.SameFile(pinned, named) {
			o.stage.Clear()
		}
	}
	return nil
}

func (o *SourceOwnerV1) adoptStage(r *sourceRoot, used sourceUsage) error {
	stage := used.stage
	if stage.name != "" && !stage.held() {
		if err := o.retainStage(r, stage); err != nil {
			return err
		}
		o.observedStage = ""
	} else if stage.held() {
		if o.debt.name == "" && o.pendingStage.name != "" {
			return ErrIdentityV1
		}
		o.stage.Clear()
	}
	o.debt = stage
	return nil
}

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
	if o.observedStage != "" {
		return ErrIdentityV1
	}
	var err error
	o.stage.File, err = r.pinFile(stage.leaf, stage.file)
	return err
}

// reconcile returns disk charges only after unlink and parent synchronization both succeed.
func (o *SourceOwnerV1) reconcile(r *sourceRoot) error {
	if err := o.syncStageRemoval(r, false); err != nil || o.debt.name == "" {
		return err
	}
	if err := o.unlinkStage(r); err != nil {
		return err
	}
	return o.syncStageRemoval(r, false)
}

// syncStageRemoval releases quota after the directory sync succeeds.
func (o *SourceOwnerV1) syncStageRemoval(r *sourceRoot, handoff bool) error {
	if !handoff && o.pendingStage.name == "" {
		return nil
	}
	if err := o.ops.dirSync(r.pin); err != nil {
		return err
	}
	o.pendingStage = sourceDebt{}
	o.stage.ClearQuota()
	return nil
}

func (o *SourceOwnerV1) unlinkStage(r *sourceRoot) error {
	d := &o.debt
	if !d.held() {
		if err := o.claimStage(r, d); err != nil {
			return err
		}
	}
	info, err := sourceEntryInfo(r, d.leaf, nil)
	if err != nil || d.file != (filelock.IdentityV1{}) && !sameSourceFile(info, d.file) {
		return cmp.Or(err, ErrIdentityV1)
	}
	d.size = max(d.qualified, sourceFileSize(info))
	return o.removeStage(r, d)
}

func (o *SourceOwnerV1) removeStage(r *sourceRoot, d *sourceDebt) error {
	if d.shared && d.binding == nil && o.stage.Quota == nil {
		pin, err := r.pinFile(d.leaf, d.file)
		if err != nil {
			return err
		}
		o.stage.Quota = pin
	}
	d.unlinkTried = true
	err := o.ops.remove(r.Root, d.leaf)
	return cmp.Or(err, o.observeStageRemoval(r))
}

// observeStageRemoval resolves an attempted unlink against the protected name.
func (o *SourceOwnerV1) observeStageRemoval(r *sourceRoot) error {
	d := &o.debt
	info, observed := r.Lstat(d.leaf)
	switch {
	case errors.Is(observed, os.ErrNotExist):
		o.pendingStage, o.debt = *d, sourceDebt{}
		return nil
	case sameSourceFile(info, d.file):
		d.unlinkTried = false
		o.stage.ClearQuota()
	}
	return ErrIdentityV1
}

// claimStage verifies the pinned inode after renaming it.
func (o *SourceOwnerV1) claimStage(r *sourceRoot, d *sourceDebt) error {
	if info, err := sourceEntryInfo(r, d.leaf, nil); err != nil || o.stage.File == nil || !sameSourceFile(info, d.file) {
		return ErrIdentityV1
	}
	held := heldStagePrefix + d.name
	if err := o.ops.namespace((*sourceRoot).renameExclusive, r, d.leaf, held); err != nil {
		return err
	}
	info, err := sourceEntryInfo(r, held, ErrIdentityV1)
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
	name := m.name(o.id)
	if stage := cmp.Or(o.debt.name, o.observedStage, o.pendingStage.name); stage != "" && stage != name {
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

func (o *SourceOwnerV1) admitPublication(r *sourceRoot, size uint64, used sourceUsage) (bool, error) {
	if used.captureFiles >= o.limits.Files || size > o.limits.Bytes-used.captureBytes {
		return false, ErrCapacityV1
	}
	return o.space(r, size, used.stage)
}

func (o *SourceOwnerV1) prepared(r *sourceRoot, pin *os.File, m SourceManifestV1, name string, scratch []byte) (*PreparedSourceV1, error) {
	if err := o.syncStageRemoval(r, true); err != nil {
		return nil, err
	}
	token := o.live[name]
	info, err := r.Lstat(name)
	if err != nil || !sameSourceFile(info, token.file) || o.currentRoot() != nil {
		return nil, ErrIdentityV1
	}
	if _, err := o.qualify(pin, m, token.size, scratch, token, ErrIntegrityV1); err != nil {
		return nil, err
	}
	if err := o.finalCaptureName(r, name, token); err != nil {
		return nil, err
	}
	if o.observedStage == name {
		o.observedStage = ""
		o.stage.Clear()
	}
	token.issued = true
	return &PreparedSourceV1{manifest: m, name: name, incarnation: token}, nil
}

func (o *SourceOwnerV1) finalCaptureName(r *sourceRoot, name string, token *sourceIncarnation) error {
	present, err := o.captureSlot(r, name)
	if err != nil || !present {
		return cmp.Or(err, ErrIdentityV1)
	}
	info, err := r.Lstat(name)
	if err != nil || !sameSourceFile(info, token.file) {
		return ErrIdentityV1
	}
	if sourceFileSize(info) != token.size {
		return ErrIntegrityV1
	}
	return o.currentRoot()
}

// captureSlot rejects same-key staging names regardless of hex case.
func (o *SourceOwnerV1) captureSlot(r *sourceRoot, name string) (bool, error) {
	entries, err := o.sourceEntries(r)
	if any(err) == any(ErrCapacityV1) {
		return false, err
	}
	if err != nil {
		return false, ErrIdentityV1
	}
	present := false
	for _, entry := range entries {
		leaf := entry.Name()
		present = present || leaf == name
		if samePublicStage(leaf, name) {
			return false, ErrIdentityV1
		}
	}
	if _, err := r.Lstat(publicStagePrefix + name); !errors.Is(err, os.ErrNotExist) {
		return false, ErrIdentityV1
	}
	return present, nil
}

func samePublicStage(leaf, name string) bool {
	key, public := strings.CutPrefix(leaf, publicStagePrefix)
	return public && sourceHexKey(key) && strings.EqualFold(name, key)
}

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
	if _, err := o.captureSlot(r, name); err != nil {
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

// finishPinned pins the inode before closing the writer.
func (o *SourceOwnerV1) finishPinned(r *sourceRoot, name string, f *os.File, id filelock.IdentityV1) (*os.File, error) {
	pin, pinErr := r.pinFile(name, id)
	err := cmp.Or(o.finishFile(f), pinErr)
	if err != nil {
		_ = pin.Close()
		return nil, err
	}
	return pin, nil
}

// writeBundle verifies the file against the producer digest.
func (o *SourceOwnerV1) writeBundle(r *sourceRoot, w *sourceFileWriter, m SourceManifestV1, name string, produce func(func(SourcePartV1) error) error, size uint64, recheck bool, scratch []byte) (sourceIncarnation, error) {
	hash := sha256.New()
	out := io.MultiWriter(w, hash)
	start := func() error {
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
		o.debt.size = sourceFileSize(info)
		_, err = out.Write(m.header(o.id))
		return cmp.Or(err, o.ops.chmod(f, 0o600))
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

// linkCapture records the inode before attempting the link.
func (o *SourceOwnerV1) linkCapture(r *sourceRoot, name string, observed *sourceIncarnation) (sourceVisibility, error) {
	observed.uncertain = true
	o.live[name] = observed
	o.debt.binding, o.debt.shared = observed, true
	err := o.ops.namespace((*sourceRoot).Link, r, o.debt.leaf, name)
	visibility, out := observeLink(r, name, observed.file, err)
	switch {
	case visibility == sourceNotVisible:
		o.forgetPublication(name, observed)
	case err == nil || visibility == sourceVisible:
		observed.uncertain = false
	}
	return visibility, out
}

func observeLink(r *sourceRoot, name string, id filelock.IdentityV1, err error) (sourceVisibility, error) {
	disagrees := sourceIndeterminate
	if err != nil {
		disagrees = sourceNotVisible
	}
	info, statErr := r.Lstat(name)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		return disagrees, cmp.Or(err, ErrIntegrityV1)
	case statErr != nil:
		return sourceIndeterminate, cmp.Or(err, statErr)
	case !sameSourceFile(info, id):
		if errors.Is(err, os.ErrExist) {
			err = ErrIntegrityV1
		}
		return disagrees, cmp.Or(err, ErrIdentityV1)
	}
	return sourceVisible, err
}

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

func (o *SourceOwnerV1) reuse(r *sourceRoot, f *os.File, m SourceManifestV1, name string, size uint64, produce func(func(SourcePartV1) error) error) (*PreparedSourceV1, error) {
	scratch := make([]byte, scratchBytes)
	observed, err := o.qualify(f, m, size, scratch, o.live[name], ErrIntegrityV1)
	if err != nil {
		return nil, err
	}
	o.live[name] = cmp.Or(o.live[name], &observed)
	if o.debt.name == name && o.debt.file == observed.file {
		o.debt.binding = o.live[name]
	}
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

// compareBundle checks the file again after the producer returns.
func (o *SourceOwnerV1) compareBundle(r *sourceRoot, f *os.File, m SourceManifestV1, observed sourceIncarnation, produce func(func(SourcePartV1) error) error, scratch []byte) error {
	header := m.header(o.id)
	compared := sha256.New()
	_, _ = compared.Write(header)
	w := &compareSourceWriter{file: f, offset: int64(len(header)), scratch: scratch[scratchBytes/2:], digest: compared}
	start := func() error { return o.reconcile(r) }
	if err := stream(m, produce, w, scratch[:scratchBytes/2], start, true); err != nil {
		return err
	}
	if [sha256.Size]byte(compared.Sum(nil)) != observed.footer {
		return ErrIntegrityV1
	}
	_, err := o.qualify(f, m, observed.size, scratch, &observed, ErrIntegrityV1)
	return err
}

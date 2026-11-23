package exclusionjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
	"golang.org/x/sys/unix"
)

func sourceModes(t *testing.T, modes []string, run func(*testing.T, string)) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) { run(t, mode) })
	}
}

func sourceEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, sourceDirectory))
	sourceMust(t, err)
	return entries
}

func sourceSize(t *testing.T, m SourceManifestV1) uint64 {
	t.Helper()
	size, err := m.SizeV1()
	sourceMust(t, err)
	return size
}

func sourceRetryAfterFault(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte) {
	t.Helper()
	o.ops = realSourceFS
	sourcePrepareAndRead(t, o, m, parts)
}

func sourceRetryAndRead(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, binding *sourceIncarnation) {
	t.Helper()
	sourceFailIf(t, binding == nil || sourcePrepare(t, o, m, parts).incarnation != binding, "retry changed the qualified capture")
	sourceRead(t, o, m, parts)
}

func sourceBundleLimits() (SourceManifestV1, [][]byte, SourceLimitsV1) {
	m, parts := sourceBundle(1, false)
	return m, parts, sourceLimits()
}

func sourceSizedBundle(t *testing.T) (SourceManifestV1, [][]byte, uint64, SourceLimitsV1) {
	t.Helper()
	m, parts, limits := sourceBundleLimits()
	return m, parts, sourceSize(t, m), limits
}

func sourceAbsent(t *testing.T, root string, names ...string) {
	t.Helper()
	for _, name := range names {
		sourcePresence(t, root, name, false)
	}
}

func withSourceEntries(t *testing.T, o *SourceOwnerV1, use func(*sourceRoot, []os.DirEntry)) {
	t.Helper()
	sourceMust(t, o.withRoot(o.bindRoot, func(r *sourceRoot) error {
		entries, err := o.sourceEntries(r)
		sourceMust(t, err)
		use(r, entries)
		return nil
	}))
}

func sourceEntriesByName(entries []os.DirEntry) map[string]os.DirEntry {
	result := make(map[string]os.DirEntry, len(entries))
	for _, entry := range entries {
		result[entry.Name()] = entry
	}
	return result
}

func sourceHeld(t *testing.T, o *SourceOwnerV1) func(string) {
	state := func() (held []string) {
		entries, err := os.ReadDir(filepath.Join(o.dir, sourceDirectory))
		for _, entry := range entries {
			info, infoErr := entry.Info()
			sourceFailIf(t, infoErr != nil, "source entry %s vanished: %v", entry.Name(), infoErr)
			data, readErr := os.ReadFile(filepath.Join(o.dir, sourceDirectory, entry.Name()))
			held = append(held, fmt.Sprintf("%s %d %v %s", entry.Name(), info.Sys().(*syscall.Stat_t).Ino, readErr, data))
		}
		for name, token := range o.live {
			held = append(held, fmt.Sprintf("%s %p %v", name, token, *token))
		}
		slices.Sort(held)
		return append(held, fmt.Sprint(err, o.debt, o.pendingStage, o.release))
	}
	before := state()
	return func(action string) {
		t.Helper()
		sourceFailIf(t, !slices.Equal(before, state()), "%s changed source entries or charges", action)
	}
}

func sourcePrepareRefusal(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, _ [][]byte, want error) {
	t.Helper()
	held := sourceHeld(t, o)
	sourcePrepareResult(t, o, m, refusedSourceProducer(t), want)
	held("refused source preparation")
}

func sourceKeyOnlyRetry(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte) {
	t.Helper()
	ops := o.ops
	sourceFault(o, "rename", ErrIdentityV1, func() { t.Fatal("key-only retry reached namespace mutation") })
	defer func() { o.ops = ops }()
	sourcePrepareRefusal(t, o, m, parts, ErrIdentityV1)
	sourceFailIf(t, o.observedStage != m.name(o.id) || o.stage.File != nil, "refusal did not retain only the staging key")
}

var sourceLookupFaults sync.Map

func sourceLookupOnce(t *testing.T, key [2]string, fault any) {
	sourceLookupFaults.Store(key, fault)
	t.Cleanup(func() { sourceLookupFaults.Delete(key) })
}

func (r *sourceRoot) Lstat(leaf string) (os.FileInfo, error) {
	switch fault, _ := sourceLookupFaults.LoadAndDelete([2]string{r.Name(), leaf}); action := fault.(type) {
	case func(*sourceRoot):
		action(r)
	case struct{}:
		return nil, &os.PathError{Op: "lstat", Path: leaf, Err: syscall.EIO}
	}
	return r.Root.Lstat(leaf)
}

func refusedSourceProducer(t *testing.T) SourceExporterV1 {
	return func(*SourceOperationV1, func(SourcePartV1) error) error {
		t.Fatal("refused preparation entered the producer")
		return ErrIntegrityV1
	}
}

func sourceFault(o *SourceOwnerV1, stage string, cause error, observe func()) {
	fail := func() error {
		if observe != nil {
			observe()
		}
		o.ops = realSourceFS
		return cause
	}
	fileOp := func(*os.File) error { return fail() }
	switch stage {
	case "write":
		o.ops.write = func(*os.File, []byte) (int, error) { return 0, fail() }
	case "file-sync", "scratch-sync":
		o.ops.fileSync = fileOp
	case "close":
		o.ops.close = fileOp
	case "chmod":
		o.ops.chmod = func(*os.File, os.FileMode) error { return fail() }
	case "rename":
		o.ops.namespace = func(sourceNamespace, *sourceRoot, string, string) error { return fail() }
	case "parent-sync":
		o.ops.dirSync = fileOp
	case "unlink", "unlink-reopen-competing-prepare":
		o.ops.remove = func(*os.Root, string) error { return fail() }
	case "statfs":
		o.ops.statfs = func(int, *syscall.Statfs_t) error { return fail() }
	}
}

func renameSourceFault(t *testing.T, cause error, published, unobserved bool) func(sourceNamespace, *sourceRoot, string, string) error {
	return func(op sourceNamespace, r *sourceRoot, from, to string) error {
		if published {
			sourceMust(t, op(r, from, to))
		}
		if unobserved {
			sourceMust(t, r.Close())
		}
		return cause
	}
}

func TestSourceCodecCorpus(t *testing.T) {
	for _, class := range []byte{1, 3} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			s, o, dir, m, parts := sourceBundleScene(t, class, true)
			p := sourcePrepare(t, o, m, parts)
			path := filepath.Join(dir, sourceDirectory, p.name)
			image := sourceReadFile(t, path)
			o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
			refuse := func(b []byte) {
				sourceMust(t, os.WriteFile(path, b, 0o600))
				sourceReadRefusal(t, o, m, ErrIntegrityV1, fmt.Sprintf("malformed source length %d", len(b)))
				sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), b), "malformed source length %d changed", len(b))
			}
			for n := range image {
				refuse(image[:n])
				changed := slices.Clone(image)
				changed[n] ^= 1
				refuse(changed)
			}
			refuse(append(slices.Clone(image), 0))
			refuse(sourceResealed(image, bundleHeader-66))
			sourceMust(t, os.WriteFile(path, image, 0o600))
			sourceRead(t, o, m, parts)
		})
	}
}

func sourceResealed(image []byte, offset int) []byte {
	changed, end := slices.Clone(image), len(image)-sha256.Size
	changed[offset] ^= 1
	if offset < end {
		footer := sha256.Sum256(changed[:end])
		copy(changed[end:], footer[:])
	}
	return changed
}

func TestSourceManifestRefusals(t *testing.T) {
	rows := []struct {
		name  string
		class byte
		edit  func(*SourceManifestV1)
	}{
		{"unknown-class", 1, func(m *SourceManifestV1) { m.Class, m.Parts = 4, nil }},
		{"zero-class", 1, func(m *SourceManifestV1) { m.Class = 0 }},
		{"missing-part", 1, func(m *SourceManifestV1) { m.Parts = m.Parts[:5] }},
		{"extra-part", 1, func(m *SourceManifestV1) { m.Parts = append(m.Parts, m.Parts[0]) }},
		{"duplicate-part", 1, func(m *SourceManifestV1) { m.Parts[1].Kind = m.Parts[0].Kind }},
		{"reordered-part", 1, func(m *SourceManifestV1) { m.Parts[1], m.Parts[2] = m.Parts[2], m.Parts[1] }},
		{"unknown-part", 1, func(m *SourceManifestV1) { m.Parts[1].Kind = 255 }},
		{"empty-body", 1, func(m *SourceManifestV1) { m.Parts[0].Length = 0 }},
		{"overflow-length", 1, func(m *SourceManifestV1) { m.Parts[0].Length = math.MaxUint64 }},
		{"overflow-total", 1, func(m *SourceManifestV1) { m.Parts[0].Length = math.MaxInt64 - uint64(bundleHeader+32) - 9 }},
		{"empty-identity", 1, func(m *SourceManifestV1) { m.Identity = [32]byte{} }},
		{"foreign-digest", 1, func(m *SourceManifestV1) { m.AcquiredDigest = [32]byte{1} }},
		{"missing-acquired", 3, func(m *SourceManifestV1) { m.Parts = m.Parts[1:] }},
		{"bound-substitution", 3, func(m *SourceManifestV1) { m.Parts[0].Kind = 1 }},
		{"result-substitution", 3, func(m *SourceManifestV1) { m.Parts[0].Kind = 2 }},
		{"missing-digest", 3, func(m *SourceManifestV1) { m.AcquiredDigest = [32]byte{} }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_, o, _, m, parts := sourceBundleScene(t, row.class, false)
			row.edit(&m)
			sourcePrepareRefusal(t, o, m, parts, ErrIntegrityV1)
		})
	}
}

func TestSourcePartAndAssuranceRefusals(t *testing.T) {
	t.Run("producer-end-reads", testSourceProducerEndReads)
	invalidAssurance := map[string][]byte{
		"full-extra":        {1, 1},
		"conditional-short": {2, 1},
		"conditional-zero":  append([]byte{2}, make([]byte, 32)...),
		"unknown-assurance": {9},
	}
	sourceModes(t, []string{"short", "extra", "reorder", "length", "unreadable", "full-extra", "conditional-short", "conditional-zero", "unknown-assurance", "digest-substitution", "nil-producer", "missing-callback", "nil-reader", "ignored-refusal", "nested-delivery"}, func(t *testing.T, mode string) {
		class := map[bool]byte{false: 3, true: 1}[mode == "short" || mode == "unreadable" || mode == "length"]
		_, o, dir, m, parts := sourceBundleScene(t, class, false)
		if assurance := invalidAssurance[mode]; assurance != nil {
			parts[3], m.Parts[3].Length = assurance, uint64(len(assurance))
		}
		if mode == "digest-substitution" {
			parts[0] = slices.Clone(m.AcquiredDigest[:])
			m.Parts[0].Length = uint64(len(parts[0]))
		}
		var late func(SourcePartV1) error
		nested := false
		producer := SourceExporterV1(func(op *SourceOperationV1, v func(SourcePartV1) error) error {
			if mode == "ignored-refusal" {
				late = v
			}
			return sourceExportParts(op, m, parts, func(p SourcePartV1) error {
				if mode == "nested-delivery" && p.Kind == AcquiredBlockBytesV1 {
					read := p.ReadAt
					p.ReadAt = func(dst []byte, off int64) (int, error) {
						sourceWantError(t, v(sourceMemoryPart(ExpectedHeaderPathV1, parts[1])), ErrIntegrityV1, "nested source delivery")
						n, err := read(dst, off)
						nested = err == nil && n == len(dst)
						return n, err
					}
				}
				return sourceAlteredPart(mode, p, v)
			})
		})
		switch mode {
		case "nil-producer":
			producer = nil
		case "missing-callback":
			producer = func(*SourceOperationV1, func(SourcePartV1) error) error { return nil }
		}
		sourceAccount(t, func(a *mdbx.OperationAccount) {
			if mode == "length" || mode == "nil-reader" || mode == "missing-callback" {
				calls := 0
				err := o.WithSourceExportV1(a, m, producer, func(SourcePartV1) error { calls++; return nil })
				sourceFailIf(t, any(err) != any(ErrIntegrityV1) || calls != 0, "declared length refusal: %v/%d", err, calls)
			}
			p, err := o.PrepareSourceV1(a, m, producer)
			sourceFailIf(t, p != nil || any(err) != any(ErrIntegrityV1), "part refusal: %v/%v", p, err)
		})
		sourceFailIf(t, mode == "nested-delivery" && !nested, "admitted read did not finish after nested refusal")
		if mode == "ignored-refusal" {
			sourceFailIf(t, late == nil, "producer did not receive a source callback")
			sourceWantError(t, late(SourcePartV1{}), ErrUnavailableV1, "expired callback")
		}
		sourceFailIf(t, len(sourceEntries(t, dir)) != 0 || o.debt.name != "", "part refusal lost cleanup ownership")
	})
}

func sourceAlteredPart(mode string, p SourcePartV1, visit func(SourcePartV1) error) error {
	switch mode {
	case "nil-reader":
		p.ReadAt = nil
	case "ignored-refusal":
		_ = visit(SourcePartV1{})
	case "reorder":
		p.Kind = BoundBodyV1
	case "length":
		p.Length++
	case "short", "unreadable":
		if p.Kind == BoundBodyV1 {
			read := p.ReadAt
			p.ReadAt = func(dst []byte, off int64) (int, error) {
				n, err := read(dst, off)
				if mode == "short" {
					return n - 1, err
				}
				return n, io.ErrUnexpectedEOF
			}
		}
	case "extra":
		if err := visit(p); err != nil || p.Kind != AcquisitionPositionV1 {
			return err
		}
	}
	return visit(p)
}

func TestSourceDurabilityFailures(t *testing.T) {
	for _, stage := range []string{"write", "chmod", "file-sync", "close", "rename", "parent-sync", "statfs"} {
		sourceModes(t, []string{stage + "/reopenfalse", stage + "/reopentrue"}, func(t *testing.T, mode string) {
			s, o, dir, m, parts := sourceBundleScene(t, 1, false)
			path := filepath.Join(dir, "policy-control")
			original := sourceReadFile(t, path)
			cause, failed := errors.New("filesystem refusal"), false
			sourceFault(o, stage, cause, func() {
				sourceWantError(t, s.Close(), policycontrol.ErrBusy, "close in source I/O")
				failed = true
			})
			want := map[bool]error{false: cause, true: ErrCapacityV1}[stage == "statfs"]
			sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
			sourceFailIf(t, !failed, "durability operation did not reach %s", stage)
			if stage == "parent-sync" {
				binding := o.live[m.name(o.id)]
				sourceFailIf(t, binding == nil || binding.issued || o.pendingStage.name == "" || len(sourceEntries(t, dir)) != 1, "linked backing lost its owner")
			}
			sourceFailIf(t, stage != "parent-sync" && (o.debt.name != "" || len(sourceEntries(t, dir)) != 0), "unpublished cleanup was not completed")
			if mode == stage+"/reopentrue" {
				o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
			}
			sourcePrepareAndRead(t, o, m, parts)
			sourceFailIf(t, !bytes.Equal(original, sourceReadFile(t, path)), "source operation changed control bytes")
		})
	}
}

func TestSourcePartialCleanupRetry(t *testing.T) {
	sourceModes(t, []string{"before-claim", "late-claim", "unobservable-claim", "restored", "restore-collision"}, testSourceClaimFault)
	sourceModes(t, []string{"exact", "fully-funded", "first-short", "second-short", "second-error", "unlink-error", "late-unlink-error", "sync-error", "unfunded", "open-file"}, testSourcePhysicalRetry)
	sourceModes(t, []string{"sparse", "linked", "replaced", "clamped", "allocation-growth"}, testSourcePhysicalCreditBounds)
	sourceModes(t, []string{"pending-sync", "pending-late-unlink"}, testSourcePendingStageProgress)
	sourceModes(t, []string{"bound-sync", "bound-late-unlink", "bound-disjoint", "bound-issued"}, testSourcePendingAliasCharge)
	sourceModes(t, []string{"bound-reopen-alias-first", "bound-reopen-alias-last", "quota-sync", "quota-late-unlink", "quota-refused-unlink", "quota-refused-unlink-walk", "quota-reuse", "quota-overlap", "quota-replaced-observation", "quota-partial", "quota-unfunded", "quota-stage-alias"}, testSourceReopenedAliasCharge)
	t.Run("pending-independent-alias-key", testSourcePendingIndependentCharge)
	t.Run("allocation-domain", testSourceAllocationDomain)
	t.Run("write-no-space", testSourceWriteNoSpace)
	m, parts := sourceBundle(1, false)
	parts[0] = bytes.Repeat([]byte{42}, 70000)
	m.Parts[0].Length = 70000
	limits := sourceLimits()
	limits.Bytes, _ = m.SizeV1()
	limits.Files = 1
	_, o, dir := sourceScene(t, limits)
	cause, cleanup := errors.New("partial write"), errors.New("unlink refusal")
	o.ops.remove = func(*os.Root, string) error { return cleanup }
	writes := 0
	o.ops.write = func(f *os.File, data []byte) (int, error) {
		writes++
		if writes == 3 {
			return 0, cause
		}
		return f.Write(data)
	}
	later := errors.New("later producer error")
	producer := func(op *SourceOperationV1, v func(SourcePartV1) error) error {
		_ = sourceExportParts(op, m, parts, v)
		return fmt.Errorf("producer result: %w", later)
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		p, err := o.PrepareSourceV1(a, m, producer)
		sourceFailIf(t, p != nil || !errors.Is(err, cause) || !errors.Is(err, cleanup) || errors.Is(err, later) || o.debt.name == "" || !o.debt.held(),
			"partial owner: %v/%v %+v", p, err, o.debt)
	})
	staging := filepath.Join(dir, sourceDirectory, ".stage-hold-"+m.name(o.id))
	info, err := os.Stat(staging)
	sourceFailIf(t, err != nil || info.Size() <= 0 || info.Size() >= 70000, "partial size: %v/%v", info, err)
	testSourceUnfundedBacking(t, o, m, parts, staging)
	sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
	o.ops = realSourceFS
	root, stage := filepath.Dir(staging), filepath.Base(staging)
	calls := 0
	o.ops.statfs = func(fd int, stat *syscall.Statfs_t) error {
		calls++
		sourcePresence(t, root, stage, true)
		sourceMust(t, syscall.Fstatfs(fd, stat))
		stat.Bavail = 0
		return nil
	}
	sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	sourceFailIf(t, calls != 1, "space refusal: checks=%d", calls)
	sourcePresence(t, root, m.name(o.id), false)
	o.ops = realSourceFS
	sourcePrepareAndRead(t, o, m, parts)
	sourcePresence(t, root, stage, false)
}

type sourceTestPaths struct {
	dir, root, key, capture, stage, held string
}

func sourcePaths(dir, key string) sourceTestPaths {
	root := filepath.Join(dir, sourceDirectory)
	return sourceTestPaths{
		dir:     dir,
		root:    root,
		key:     key,
		capture: filepath.Join(root, key),
		stage:   filepath.Join(root, ".staging-"+key),
		held:    filepath.Join(root, ".stage-hold-"+key),
	}
}

func sourceCaptureScene(t *testing.T, limits SourceLimitsV1, m SourceManifestV1) (*policycontrol.Store, *SourceOwnerV1, sourceTestPaths) {
	t.Helper()
	s, o, dir := sourceScene(t, limits)
	return s, o, sourcePaths(dir, m.name(o.id))
}

func sourcePreparedScene(t *testing.T, limits SourceLimitsV1, m SourceManifestV1, parts [][]byte) (*policycontrol.Store, *SourceOwnerV1, sourceTestPaths, *PreparedSourceV1) {
	t.Helper()
	s, o, paths := sourceCaptureScene(t, limits, m)
	return s, o, paths, sourcePrepare(t, o, m, parts)
}

func testSourceClaimFault(t *testing.T, mode string) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	anchor := sourceForeign(m)
	sourcePrepare(t, o, anchor, parts)
	paths := sourcePaths(dir, m.name(o.id))
	public, held := ".staging-"+strings.ToUpper(paths.key), ".stage-hold-"+paths.key
	path := filepath.Join(paths.root, public)
	data := []byte("public staging")
	original := writeSourceEntry(t, path, data)
	cause := errors.New("stage claim stopped")
	want := cause
	if mode == "restored" || mode == "restore-collision" {
		want = ErrIdentityV1
		o.ops.namespace = sourceReplacementClaim(t, dir, public, held, mode == "restore-collision")
	} else {
		o.ops.namespace = renameSourceFault(t, cause, mode != "before-claim", mode == "unobservable-claim")
	}
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
	sourcePresence(t, paths.root, paths.key, false)
	o.ops = realSourceFS
	if mode == "restored" || mode == "restore-collision" {
		checkSourceRestoredClaim(t, o, m, parts, dir, public, held, mode == "restore-collision")
	} else {
		reached := map[bool]string{true: public, false: held}[mode == "before-claim"]
		pin := o.stage.File
		sourceRead(t, o, anchor, parts)
		if reached == held {
			checkSourcePinClosed(t, pin, o.stage.File)
		}
		path := filepath.Join(paths.root, reached)
		sourceUnchangedEntry(t, path, original, data)
		assertSourceReleaseCharge(t, o, m, 2, sourceSize(t, anchor)+uint64(len(data)))
	}
	sourcePrepareAndRead(t, o, m, parts)
	sourceAbsent(t, paths.root, public, held)
}

func sourceReplacementClaim(t *testing.T, dir, public, held string, collision bool) func(sourceNamespace, *sourceRoot, string, string) error {
	t.Helper()
	root := filepath.Join(dir, sourceDirectory)
	return func(op sourceNamespace, r *sourceRoot, from, to string) error {
		switch from {
		case public:
			sourceMust(t, os.Rename(filepath.Join(root, public), filepath.Join(dir, "pinned-original")))
			sourceMust(t, os.WriteFile(filepath.Join(root, public), []byte("different inode"), 0o600))
		case held:
			if collision {
				sourceMust(t, os.WriteFile(filepath.Join(root, public), []byte("occupied public leaf"), 0o600))
			}
		}
		return op(r, from, to)
	}
}

func checkSourceRestoredClaim(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, dir, public, held string, collision bool) {
	t.Helper()
	root := filepath.Join(dir, sourceDirectory)
	moved := map[bool]string{true: held, false: public}[collision]
	sourcePresence(t, root, held, collision)
	sourceFailIf(t, string(sourceReadFile(t, filepath.Join(root, moved))) != "different inode", "claim changed replacement bytes")
	want := ErrIdentityV1
	if collision {
		want = syscall.EEXIST
		sourceFailIf(t, string(sourceReadFile(t, filepath.Join(root, public))) != "occupied public leaf", "restore replaced public leaf")
	}
	sourcePrepareRefusal(t, o, m, parts, want)
	sourceMust(t, os.Remove(filepath.Join(root, moved)))
	if collision {
		sourceMust(t, os.Remove(filepath.Join(root, public)))
	}
	sourceMust(t, os.Rename(filepath.Join(dir, "pinned-original"), filepath.Join(root, public)))
}

type sourceSpaceFixture struct {
	o               *SourceOwnerV1
	m               SourceManifestV1
	parts           [][]byte
	stage           string
	info            os.FileInfo
	size, allocated uint64
	logical         uint64
}

func sourceSpaceScene(t *testing.T, mode string) sourceSpaceFixture {
	t.Helper()
	m, parts, limits := sourceBundleLimits()
	parts[0] = bytes.Repeat([]byte{41}, 90_000)
	m.Parts[0].Length = uint64(len(parts[0]))
	size := sourceSize(t, m)
	s, o, dir := sourceScene(t, limits)
	stage := filepath.Join(dir, sourceDirectory, ".staging-"+m.name(o.id))
	length := uint64(16384)
	var data []byte
	switch mode {
	case "clamped":
		length = size * 2
		data = make([]byte, length)
		for i := 0; i < len(data); i += sha256.Size {
			block := sha256.Sum256([]byte(strconv.Itoa(i)))
			copy(data[i:], block[:])
		}
	case "sparse", "allocation-growth":
	default:
		data = bytes.Repeat([]byte{19}, int(length))
	}
	sourceMust(t, os.WriteFile(stage, data, 0o600))
	if data == nil {
		sourceMust(t, os.Truncate(stage, int64(length)))
	}
	if mode == "linked" {
		sourceMust(t, os.Link(stage, filepath.Join(dir, "second-link")))
	}
	info := sourceLstat(t, stage)
	allocated := uint64(info.Sys().(*syscall.Stat_t).Blocks) * 512
	o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), limits, nil)
	return sourceSpaceFixture{o: o, m: m, parts: parts, stage: stage, info: info, size: size, allocated: allocated, logical: length}
}

func testSourcePhysicalRetry(t *testing.T, mode string) {
	scene := sourceSpaceScene(t, mode)
	o := scene.o
	full := scene.size + o.limits.Overhead
	credit := min(scene.logical, scene.allocated, scene.size)
	sourceFailIf(t, credit < 2, "staging allocation is too small: %d bytes", credit)
	cause := errors.New("staging operation stopped")
	pin := o.stage.File
	var other *os.File
	if mode == "open-file" {
		var err error
		other, err = os.Open(scene.stage)
		sourceMust(t, err)
		defer other.Close()
	}
	checks := 0
	o.ops.statfs = func(fd int, stat *syscall.Statfs_t) error {
		checks++
		var held syscall.Stat_t
		sourceMust(t, syscall.Fstat(fd, &held))
		root := o.info.Sys().(*syscall.Stat_t)
		sourceFailIf(t, held.Dev != root.Dev || held.Ino != root.Ino, "space check used a different source directory")
		if checks == 1 {
			sourceUnchangedEntry(t, scene.stage, scene.info)
			sourceStatfsFixture(stat, 1, sourceInitialSpace(mode, full, credit))
			return nil
		}
		return sourceSecondSpace(t, scene, pin, other, stat, mode, full, cause)
	}
	switch mode {
	case "unlink-error", "late-unlink-error":
		o.ops.remove = func(r *os.Root, name string) error {
			if mode == "late-unlink-error" {
				sourceMust(t, r.Remove(name))
			}
			return cause
		}
	case "sync-error":
		o.ops.dirSync = func(*os.File) error { return cause }
	}
	testSourcePhysicalResult(t, scene, mode, cause, &checks)
}

func sourceInitialSpace(mode string, full, credit uint64) uint64 {
	switch mode {
	case "fully-funded":
		return full
	case "first-short":
		return full - credit - 1
	}
	return full - credit
}

func sourceSecondSpace(t *testing.T, scene sourceSpaceFixture, pin, other *os.File, stat *syscall.Statfs_t, mode string, full uint64, cause error) error {
	t.Helper()
	root, name := filepath.Dir(scene.stage), scene.m.name(scene.o.id)
	sourceAbsent(t, root, filepath.Base(scene.stage), ".stage-hold-"+name, name)
	checkSourcePinClosed(t, pin, scene.o.stage.File)
	sourceFailIf(t, scene.o.debt.name != "" || scene.o.pendingStage.name != "", "physical recheck preceded stage retirement")
	switch mode {
	case "second-error":
		return cause
	case "open-file":
		checkSourcePinned(t, other, scene.info)
		full--
	case "second-short":
		full--
	}
	sourceStatfsFixture(stat, 1, full)
	return nil
}

func testSourcePhysicalResult(t *testing.T, scene sourceSpaceFixture, mode string, cause error, checks *int) {
	t.Helper()
	o, m, parts := scene.o, scene.m, scene.parts
	if mode == "unfunded" || mode == "first-short" {
		pin := o.stage.File
		if mode == "unfunded" {
			testSourceUnfundedBacking(t, o, m, parts, scene.stage)
		} else {
			sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
		}
		sourceFailIf(t, *checks != 1, "preliminary refusal probed space %d times", *checks)
		sourceUnchangedEntry(t, scene.stage, scene.info)
		info, err := pin.Stat()
		sourceFailIf(t, err != nil || pin != o.stage.File || !os.SameFile(info, scene.info), "refusal lost the staging pin")
		assertSourceReleaseCharge(t, o, m, 1, scene.logical)
		sourceRetryAfterFault(t, o, m, parts)
		checkSourcePinClosed(t, pin, o.stage.File)
		return
	}
	reads, writes, calls := 0, 0, 0
	o.ops.write = func(f *os.File, data []byte) (int, error) { writes++; return f.Write(data) }
	produce := sourceMappedProducer(m, parts, func(part SourcePartV1, visit func(SourcePartV1) error) error {
		read := part.ReadAt
		part.ReadAt = func(dst []byte, off int64) (int, error) { reads++; return read(dst, off) }
		return visit(part)
	})
	want := map[string]error{"second-short": ErrCapacityV1, "second-error": ErrCapacityV1, "open-file": ErrCapacityV1, "unlink-error": cause, "late-unlink-error": cause, "sync-error": cause}[mode]
	sourcePrepareResult(t, o, m, func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		calls++
		return produce(op, visit)
	}, want)
	probes := map[bool]int{true: 1, false: 2}[mode == "fully-funded" || any(want) == any(cause)]
	sourceFailIf(t, *checks != probes || calls != 1, "retry probes=%d and producers=%d, want %d and one", *checks, calls, probes)
	testSourcePhysicalOutcome(t, scene, mode, want, reads, writes)
}

func testSourcePhysicalOutcome(t *testing.T, scene sourceSpaceFixture, mode string, want error, reads, writes int) {
	t.Helper()
	o, m, parts := scene.o, scene.m, scene.parts
	root, name := filepath.Dir(scene.stage), m.name(o.id)
	o.ops = realSourceFS
	if want == nil {
		sourceFailIf(t, reads == 0 || writes == 0, "funded retry did not retain produced bytes")
		sourceRead(t, o, m, parts)
		return
	}
	sourceFailIf(t, reads != 0 || writes != 0, "refused retry reached producer reads or file writes")
	sourceAbsent(t, root, name, filepath.Base(scene.stage))
	sourcePresence(t, root, ".stage-hold-"+name, mode == "unlink-error")
	if mode == "sync-error" || mode == "unlink-error" || mode == "late-unlink-error" {
		assertSourceReleaseCharge(t, o, m, 1, scene.logical)
	} else {
		assertSourceReleaseCharge(t, o, m, 0, 0)
	}
	if mode == "sync-error" {
		o.ops.statfs = func(_ int, stat *syscall.Statfs_t) error {
			sourceStatfsFixture(stat, 1, scene.size+o.limits.Overhead-1)
			return nil
		}
		sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	}
	sourceRetryAfterFault(t, o, m, parts)
}

type sourceAllocationInfo struct {
	os.FileInfo
	stat any
}

func (i sourceAllocationInfo) Sys() any { return i.stat }

func testSourceAllocationDomain(t *testing.T) {
	tests := []struct {
		stat any
		want uint64
	}{
		{nil, 0},
		{(*syscall.Stat_t)(nil), 0},
		{&syscall.Stat_t{Nlink: 2, Blocks: 3}, 0},
		{&syscall.Stat_t{Nlink: 1, Blocks: -1}, 0},
		{&syscall.Stat_t{Nlink: 1, Blocks: math.MaxInt64}, 0},
		{&syscall.Stat_t{Nlink: 1, Blocks: 3}, 1536},
	}
	for _, row := range tests {
		got := singleLinkAllocatedBytes(sourceAllocationInfo{stat: row.stat})
		sourceFailIf(t, got != row.want, "allocated bytes for %#v: %d, want %d", row.stat, got, row.want)
	}
}

func testSourceWriteNoSpace(t *testing.T) {
	scene := sourceSpaceScene(t, "write-no-space")
	o, m, parts := scene.o, scene.m, scene.parts
	writes := 0
	o.ops.write = func(*os.File, []byte) (int, error) {
		writes++
		return 0, syscall.ENOSPC
	}
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), syscall.ENOSPC)
	sourceFailIf(t, writes != 1, "write shortage was not reached")
	assertSourceReleaseCharge(t, o, m, 0, 0)
	sourceRetryAfterFault(t, o, m, parts)
}

func testSourcePhysicalCreditBounds(t *testing.T, mode string) {
	scene := sourceSpaceScene(t, mode)
	o, m, parts := scene.o, scene.m, scene.parts
	if mode == "clamped" {
		checkSourceClampedAllocation(t, scene)
	}
	var moved string
	checks := 0
	o.ops.statfs = func(_ int, stat *syscall.Statfs_t) error {
		checks++
		available := scene.size + o.limits.Overhead - 1
		switch mode {
		case "sparse":
			sourceFailIf(t, scene.allocated >= scene.logical, "sparse fixture did not expose a logical/allocated gap")
			available -= scene.allocated
		case "replaced":
			moved = filepath.Join(o.dir, "original-stage")
			sourceMust(t, os.Rename(scene.stage, moved))
			sourceMust(t, os.WriteFile(scene.stage, []byte("different physical allocation"), 0o600))
		case "clamped":
			available -= scene.size
		case "allocation-growth":
			available -= scene.allocated
			sourceGrowStageAllocation(t, scene)
		}
		sourceStatfsFixture(stat, 1, available)
		return nil
	}
	if mode == "replaced" || mode == "allocation-growth" {
		sourcePrepareResult(t, o, m, refusedSourceProducer(t), ErrCapacityV1)
		if mode == "replaced" {
			sourceMust(t, os.Remove(scene.stage))
			sourceMust(t, os.Rename(moved, scene.stage))
		}
	} else {
		sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	}
	sourceFailIf(t, checks != 1, "credit refusal used %d space probes", checks)
	sourceUnchangedEntry(t, scene.stage, scene.info)
	sourceRetryAfterFault(t, o, m, parts)
}

func sourceGrowStageAllocation(t *testing.T, scene sourceSpaceFixture) {
	t.Helper()
	f, err := os.OpenFile(scene.stage, os.O_WRONLY, 0)
	sourceMust(t, err)
	defer f.Close()
	data := bytes.Repeat([]byte{27}, int(scene.logical))
	n, err := f.WriteAt(data, 0)
	sourceMust(t, err)
	sourceFailIf(t, n != len(data), "stage allocation wrote %d bytes, want %d", n, len(data))
	sourceMust(t, f.Sync())
	info := sourceLstat(t, scene.stage)
	allocated := uint64(info.Sys().(*syscall.Stat_t).Blocks) * 512
	sourceFailIf(t, !os.SameFile(info, scene.info) || allocated <= scene.allocated, "stage allocation did not grow on the same inode")
}

func testSourcePendingStageProgress(t *testing.T, mode string) {
	_, o, dir, first, parts := sourceBundleScene(t, 1, false)
	next := sourceForeign(first)
	root := filepath.Join(dir, sourceDirectory)
	a, b := first.name(o.id), next.name(o.id)
	firstLeaf, nextLeaf := ".staging-"+a, ".staging-"+b
	old, current := []byte{1, 2}, []byte{3}
	original := writeSourceEntry(t, filepath.Join(root, firstLeaf), old)
	sourceReadRefusal(t, o, next, ErrUnavailableV1, "read of an absent disjoint capture")
	checkSourceStageWitness(t, o, original)
	cause := sourceRetirementFault(t, o, heldStagePrefix+a, mode == "pending-late-unlink", false, nil)
	sourcePrepareResult(t, o, first, sourceProducer(first, parts), cause)
	sourceAbsent(t, root, firstLeaf, ".stage-hold-"+a)
	nextPath := filepath.Join(root, nextLeaf)
	sourceMust(t, os.WriteFile(nextPath, current, 0o600))
	sourcePrepareResult(t, o, first, refusedSourceProducer(t), ErrBusyV1)
	checkSourceIncomingPendingStage(t, o, first, next, parts, nextPath, cause, uint64(len(old)+len(current)))
	sourceRetryAfterFault(t, o, next, parts)
	sourcePresence(t, root, nextLeaf, false)
	assertSourceReleaseCharge(t, o, next, 1, sourceSize(t, next))
}

func checkSourceIncomingPendingStage(t *testing.T, o *SourceOwnerV1, first, next SourceManifestV1, parts [][]byte, path string, cause error, size uint64) {
	t.Helper()
	original := sourceLstat(t, path)
	assertSourceReleaseCharge(t, o, first, 2, size)
	producerCalls := 0
	o.ops.dirSync = func(*os.File) error {
		sourceFailIf(t, producerCalls != 1 || o.pendingStage.name != first.name(o.id), "retirement sync occurred without the funded producer and pending stage")
		sourceUnchangedEntry(t, path, original)
		return cause
	}
	sourcePrepareResult(t, o, next, func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		producerCalls++
		return sourceExportParts(op, next, parts, visit)
	}, cause)
	assertSourceReleaseCharge(t, o, first, 2, size)
	sourceUnchangedEntry(t, path, original)
}

func testSourcePendingAliasCharge(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	other := sourceForeign(m)
	limits.Files = map[bool]uint64{false: 1, true: 2}[mode == "bound-disjoint"]
	limits.Bytes = limits.Files * size
	_, o, paths := sourceCaptureScene(t, limits, m)
	saved := filepath.Join(paths.dir, "retained-capture")
	var issued *PreparedSourceV1
	switch mode {
	case "bound-disjoint":
		sourcePrepare(t, o, other, parts)
	case "bound-issued":
		issued = sourcePrepare(t, o, m, parts)
		sourceMust(t, os.Link(paths.capture, paths.stage))
	}
	held := heldStagePrefix + paths.key
	cause := sourceRetirementFault(t, o, held, mode != "bound-sync" && mode != "bound-issued", false, func() {
		sourcePresence(t, paths.root, held, false)
		sourceMust(t, os.Rename(paths.capture, saved))
	})
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
	o.ops = realSourceFS
	original, image := sourceLstat(t, saved), sourceReadFile(t, saved)
	binding := o.live[paths.key]
	sourceFailIf(t, uint64(len(image)) != size, "displaced capture changed length")
	sourceFailIf(t, binding == nil || binding.file != filelock.FileIdentityV1(original) || binding.size != size || binding.uncertain ||
		binding.issued != (issued != nil) ||
		binding.footer != sha256.Sum256(image[:len(image)-sha256.Size]), "stage retirement changed the qualified capture")
	sourcePresence(t, paths.root, paths.key, false)
	checkSourcePendingAliasAdmission(t, o, m, other, parts, paths.root, image, mode)

	sourceMust(t, os.Rename(saved, paths.capture))
	sourceFailIf(t, issued != nil && binding != issued.incarnation, "retry lost the issued incarnation")
	sourceRetryAndRead(t, o, m, parts, binding)
	sourceUnchangedEntry(t, paths.capture, original)
	assertSourceReleaseCharge(t, o, m, limits.Files, limits.Bytes)
}

func testSourceReopenedAliasCharge(t *testing.T, mode string) {
	capture, parts, limits := sourceBundleLimits()
	anchor, anchorParts := capture, parts
	quotaCase := strings.HasPrefix(mode, "quota-")
	if quotaCase {
		anchor, anchorParts = sourceForeign(capture), slices.Clone(parts)
		anchor.Parts = slices.Clone(anchor.Parts)
		anchorParts[0] = append(slices.Clone(parts[0]), 1)
		anchor.Parts[0].Length++
	}
	limits.Files, limits.Bytes = 2, sourceSize(t, anchor)+sourceSize(t, capture)
	s, o, paths, _ := sourcePreparedScene(t, limits, anchor, anchorParts)
	if mode == "quota-reuse" {
		sourcePrepare(t, o, capture, parts)
	}
	key := capture.name(o.id)
	held := heldStagePrefix + key
	path, stage := paths.capture, filepath.Join(paths.root, publicStagePrefix+key)
	original, image := sourceLstat(t, path), sourceReadFile(t, path)
	aliasDigit := map[bool]string{true: "0", false: "f"}[mode == "bound-reopen-alias-first"]
	alias := filepath.Join(paths.root, strings.Repeat(aliasDigit, 64))
	if !quotaCase {
		sourceMust(t, os.Link(path, alias))
		sourceUnchangedEntry(t, alias, original)
	}
	sourceMust(t, os.Link(path, stage))
	s = sourceReopenStore(t, s, paths.dir)
	o = sourceOpen(t, s, sourceID(), limits, nil)
	public := o.stage.File
	cause := sourceRetirementFault(t, o, held, mode == "quota-late-unlink", mode == "quota-partial",
		func() { sourceAbsent(t, paths.root, filepath.Base(stage), held) })
	if strings.HasPrefix(mode, "quota-refused-unlink") {
		o.ops = realSourceFS
		o.ops.remove = func(r *os.Root, _ string) error { sourceMust(t, r.Close()); return cause }
	}
	sourcePrepareResult(t, o, capture, sourceProducer(capture, parts), cause)
	if !quotaCase {
		binding := o.live[key]
		o.ops = realSourceFS
		sourceReadRefusal(t, o, capture, ErrBusyV1, "shared stage unlink still owes sync")
		checkSourceAliasCharge(t, o, limits.Bytes, false)
		sourceRetryAndRead(t, o, capture, parts, binding)
		sourceUnchangedEntry(t, path, original)
		sourceUnchangedEntry(t, alias, original, image)
		assertSourceReleaseCharge(t, o, capture, 2, limits.Bytes)
		return
	}
	quota := o.stage.Quota
	checkSourcePinClosed(t, public, o.stage.File)
	sourceFailIf(t, quota == nil || !slices.Equal(sourceOpenFileModes(t, original), []int{unix.O_RDONLY}), "retirement did not retain the read-only original")
	for _, effect := range []string{"parent-sync", "rename", "unlink"} {
		sourceFault(o, effect, cause, func() { t.Fatal("quota read reached a namespace effect") })
	}
	switch mode {
	case "quota-refused-unlink", "quota-refused-unlink-walk":
		lookup := [2]string{filepath.Join(o.dir, sourceDirectory), held}
		if mode == "quota-refused-unlink-walk" {
			sourceLookupOnce(t, lookup, struct{}{})
		}
		sourceRead(t, o, anchor, anchorParts)
		_, armed := sourceLookupFaults.Load(lookup)
		sourceFailIf(t, armed, "protected stage lookup did not consume the fault")
		checkSourcePinClosed(t, quota, o.stage.Quota)
		sourceFailIf(t, o.debt.unlinkTried, "observed staging inode still has an unresolved unlink")
		sourceUnchangedEntry(t, filepath.Join(paths.root, held), original, image)
		sourceRetryAfterFault(t, o, capture, parts)
	case "quota-overlap", "quota-replaced-observation", "quota-partial", "quota-unfunded":
		checkSourceQuotaOverlap(t, s, o, mode, capture, anchor, parts, anchorParts, path, original, quota, cause)
	case "quota-stage-alias":
		checkSourceQuotaStageAlias(t, o, capture, parts, path, quota)
	default:
		sourceRead(t, o, anchor, anchorParts)
		o.ops = realSourceFS
		sourceMust(t, os.Link(path, alias))
		sourceReadRefusal(t, o, anchor, ErrCapacityV1, "another canonical name")
		sourceMust(t, os.Remove(alias))
		if mode == "quota-sync" {
			saved := filepath.Join(o.dir, "original-anchor")
			sourceMust(t, os.Rename(path, saved))
			assertSourceReleaseCharge(t, o, anchor, 1, uint64(len(image)))
			sourceMust(t, os.WriteFile(path, image, 0o600))
			sourceReadRefusal(t, o, anchor, ErrCapacityV1, "independent capture occupant")
			sourceMust(t, os.Remove(path))
			sourceMust(t, os.Rename(saved, path))
		}
		sourcePrepareAndRead(t, o, capture, parts)
		checkSourcePinClosed(t, quota, o.stage.Quota)
	}
}

func checkSourceQuotaOverlap(t *testing.T, s *policycontrol.Store, o *SourceOwnerV1, mode string, capture, anchor SourceManifestV1, parts, anchorParts [][]byte, path string, original os.FileInfo, quota *os.File, cause error) {
	next := sourceForeign(sourceForeign(capture))
	root := filepath.Dir(path)
	stage := filepath.Join(root, publicStagePrefix+next.name(o.id))
	info := writeSourceEntry(t, stage, []byte{1})
	switch mode {
	case "quota-unfunded":
		sourceMust(t, os.Truncate(stage, original.Size()))
		sourceReadRefusal(t, o, anchor, ErrCapacityV1, "pending quota and unfunded stage")
		sourceFailIf(t, o.stage.File != nil || o.stage.Quota != quota, "refused observation changed held descriptors")
		sourceMust(t, os.Truncate(stage, 1))
		sourcePrepareRefusal(t, o, next, parts, ErrIdentityV1)
		sourceUnchangedEntry(t, stage, info, []byte{1})
		sourceRead(t, o, anchor, anchorParts)
		return
	case "quota-partial":
		extra := filepath.Join(root, strings.Repeat("e", 64))
		sourceMust(t, os.WriteFile(extra, nil, 0o600))
		sourceReadRefusal(t, o, anchor, ErrCapacityV1, "independent canonical name")
		sourceMust(t, os.Remove(extra))
		sourceKeyOnlyRetry(t, o, next, parts)
		sourceUnchangedEntry(t, stage, info, []byte{1})
		sourceFailIf(t, o.stage.Quota != quota, "key-only retry changed the pending quota pin")
		fresh := sourceOpen(t, sourceReopenStore(t, s, o.dir), sourceID(), o.limits, nil)
		checkSourcePinClosed(t, quota, o.stage.Quota)
		sourceUnchangedEntry(t, path, original)
		sourceRead(t, fresh, anchor, anchorParts)
		sourcePrepareAndRead(t, fresh, next, parts)
		assertSourceReleaseCharge(t, fresh, anchor, 2, o.limits.Bytes)
		return
	default:
		sourceRead(t, o, anchor, anchorParts, func() {
			count := len(sourceOpenFileModes(t, sourceLstat(t, root))) + len(sourceOpenFileModes(t, original)) + len(sourceOpenFileModes(t, info))
			sourceFailIf(t, count != 5, "source read held %d descriptors, want five", count)
			sourceWantError(t, s.Close(), policycontrol.ErrBusy, "close during overlapping read")
		})
	}
	pin := checkSourceStageWitness(t, o, info)
	active := mode == "quota-overlap"
	if active {
		sourcePrepareResult(t, o, capture, refusedSourceProducer(t), ErrBusyV1)
	}
	moved := filepath.Join(o.dir, "held-public-stage")
	sourceMust(t, os.Rename(stage, moved))
	sourceMust(t, os.WriteFile(stage, []byte{2}, 0o600))
	if active {
		sourcePrepareRefusal(t, o, next, parts, ErrIdentityV1)
		sourceFailIf(t, o.stage.File != pin || o.stage.Quota != quota, "substitution changed the held descriptors")
		sourceMust(t, os.Rename(moved, stage))
		moved = stage
		checkSourceIncomingPendingStage(t, o, capture, next, parts, stage, cause, uint64(original.Size())+1)
		sourceFailIf(t, o.stage.File != pin || o.stage.Quota != quota, "failed sync changed the held descriptors")
		sourceMust(t, s.Close())
	} else {
		unchanged := sourceHeld(t, o)
		sourceRead(t, o, anchor, anchorParts, func() {
			checkSourcePinClosed(t, pin, o.stage.File)
			held, err := quota.Stat()
			sourceFailIf(t, err != nil || o.stage.Quota != quota || !os.SameFile(held, original), "stage loss changed the pending quota: %v", err)
		})
		unchanged("disjoint read after loss of the staging name")
		sourcePrepareRefusal(t, o, next, parts, ErrIdentityV1)
		sourceMust(t, os.Remove(stage))
		sourceRetryAfterFault(t, o, next, parts)
	}
	sourceUnchangedEntry(t, moved, info, []byte{1})
	checkSourcePinClosed(t, pin, o.stage.File)
	checkSourcePinClosed(t, quota, o.stage.Quota)
}

func checkSourceQuotaStageAlias(t *testing.T, o *SourceOwnerV1, capture SourceManifestV1, parts [][]byte, path string, quota *os.File) {
	next := sourceForeign(sourceForeign(capture))
	other := sourceForeign(next)
	root := filepath.Dir(path)
	_, _, donor, _ := sourcePreparedScene(t, sourceLimits(), other, parts)
	sourceMust(t, os.WriteFile(filepath.Join(root, donor.key), sourceReadFile(t, donor.capture), 0o600))
	stage := filepath.Join(root, publicStagePrefix+next.name(o.id))
	sourceMust(t, os.Rename(path, stage))
	sourceRead(t, o, other, parts)
	original := sourceLstat(t, stage)
	large := next
	large.Parts = slices.Clone(large.Parts)
	large.Parts[0].Length += 2
	sourcePrepareResult(t, o, large, refusedSourceProducer(t), ErrCapacityV1)
	sourceUnchangedEntry(t, stage, original)
	sourceRetryAfterFault(t, o, next, parts)
	sourceRead(t, o, other, parts)
	checkSourcePinClosed(t, quota, o.stage.Quota)
	assertSourceReleaseCharge(t, o, other, 2, 2*sourceSize(t, next))
}

func sourceRetirementFault(t *testing.T, o *SourceOwnerV1, held string, late, closeRoot bool, after func()) error {
	t.Helper()
	cause := errors.New("stage retirement stopped")
	if !late && !closeRoot {
		sourceFault(o, "parent-sync", cause, after)
		return cause
	}
	sourceFault(o, "unlink", cause, after)
	fail := o.ops.remove
	o.ops.remove = func(r *os.Root, leaf string) error {
		sourceFailIf(t, leaf != held, "stage retirement selected %q", leaf)
		sourceMust(t, r.Remove(leaf))
		if closeRoot {
			sourceMust(t, r.Close())
		}
		return fail(r, leaf)
	}
	return cause
}

func checkSourcePendingAliasAdmission(t *testing.T, o *SourceOwnerV1, m, other SourceManifestV1, parts [][]byte, root string, image []byte, mode string) {
	t.Helper()
	switch mode {
	case "bound-disjoint":
		sourceRead(t, o, other, parts)
	case "bound-late-unlink":
		sourceReadRefusal(t, o, m, ErrBusyV1, "unlinked alias before sync")
	case "bound-issued":
		sourceReadRefusal(t, o, m, ErrIntegrityV1, "missing issued capture")
	}
	name := m.name(o.id)
	sourcePrepareResult(t, o, m, refusedSourceProducer(t), ErrIntegrityV1)
	if mode != "bound-sync" {
		return
	}
	sourceReadRefusal(t, o, m, ErrBusyV1, "unsynced capture alias")
	sourcePrepareRefusal(t, o, other, parts, ErrBusyV1)
	sourceFault(o, "rename", ErrCapacityV1, func() { t.Fatal("an independent occupant reached namespace mutation") })
	defer func() { o.ops = realSourceFS }()
	for _, leaf := range []string{publicStagePrefix + name, name} {
		path := filepath.Join(root, leaf)
		sourceMust(t, os.WriteFile(path, image, 0o600))
		sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
		sourceMust(t, os.Remove(path))
	}
}

func testSourcePendingIndependentCharge(t *testing.T) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Files, limits.Bytes = 2, size+1
	_, o, paths, p := sourcePreparedScene(t, limits, m, parts)
	sourceMust(t, os.WriteFile(paths.stage, []byte{1}, 0o600))
	cause := sourceRetirementFault(t, o, heldStagePrefix+p.name, true, false, nil)
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
	o.ops = realSourceFS
	other := filepath.Join(paths.root, sourceForeign(m).name(o.id))
	sourceMust(t, os.WriteFile(other, nil, 0o600))
	sourceReadRefusal(t, o, m, ErrCapacityV1, "independent pending stage and another capture")
	sourceMust(t, os.Remove(other))
	assertSourceReleaseCharge(t, o, m, 2, size+1)
	sourceRetryAndRead(t, o, m, parts, p.incarnation)
}

func checkSourceClampedAllocation(t *testing.T, scene sourceSpaceFixture) {
	t.Helper()
	stat := *scene.info.Sys().(*syscall.Stat_t)
	stat.Blocks = int64(scene.size/512) + 2
	info := sourceAllocationInfo{FileInfo: scene.info, stat: &stat}
	large := min(scene.logical, uint64(stat.Blocks)*512)
	sourceFailIf(t, large <= scene.size, "controlled allocation %d does not exceed capture size %d", large, scene.size)
	d := scene.o.debt
	sourceFailIf(t, d.allocationCredit(info, scene.logical) != large, "stage allocation did not credit %d bytes", large)
	credit := d.allocationCredit(info, scene.size)
	sourceFailIf(t, credit != scene.size, "stage credit is %d bytes, want %d", credit, scene.size)
}

func sourceBackingCharge(parts [][]byte) uint64 {
	var total uint64
	for _, part := range parts {
		total += uint64(cap(part))
	}
	return total
}

func testSourceUnfundedBacking(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, staging string) {
	t.Helper()
	before, beforeErr := os.ReadFile(staging)
	entries, delivered := 0, 0
	producer := func(op *SourceOperationV1, v func(SourcePartV1) error) error {
		entries++
		sourcePresence(t, filepath.Dir(staging), filepath.Base(staging), beforeErr == nil)
		return sourceExportParts(op, m, parts, func(p SourcePartV1) error { delivered++; return v(p) })
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-o.limits.WorkingBytesV1()-sourceBackingCharge(parts)+1, func() error {
			p, err := o.PrepareSourceV1(a, m, producer)
			sourceFailIf(t, p != nil || !mdbx.IsOperationReservationCapacity(err) || entries != 1 || delivered != 0,
				"unfunded source: %v/%v producer=%d delivered=%d", p, err, entries, delivered)
			return nil
		}))
	})
	after, afterErr := os.ReadFile(staging)
	sourceFailIf(t, (beforeErr == nil) != (afterErr == nil) || !bytes.Equal(before, after), "unfunded source changed staged bytes")
}

func TestSourceReleaseOnlyRetry(t *testing.T) {
	t.Run("stage-spelling", testSourceReleaseSpelling)
	t.Run("unfunded-independent-stage", testSourceReleaseUnfundedStage)
	sourceModes(t, []string{"descriptor-five-live", "descriptor-six-live", "descriptor-five-gone"}, testSourceReleaseDescriptorOverlap)
	t.Run("final-stage", testSourceFinalStage)
	t.Run("canonical-refilled", testSourceRefilledCanonical)
	t.Run("published-bytes-changed", testSourcePublishedMarkerBytes)
	t.Run("unpublished-link-result", testSourceUnpublishedLinkResult)
	t.Run("final-observation", testSourceFinalObservations)
	t.Run("matching-marker-after-clear", testSourceMatchingMarkerAfterClear)
	t.Run("marker-clear-observation", func(t *testing.T) {
		sourceModes(t, []string{"present-then-missing", "lookup-error-then-present", "lookup-error-then-absent", "absent-then-reappears"}, testSourceMarkerClearObservation)
	})
	t.Run("recover-held-stage", testSourceRecoverHeldReleaseStage)
	t.Run("expired-handle", testSourceExpiredReleaseHandle)
	t.Run("last-link-retry", testSourceLastLinkRetryProof)
	sourceModes(t, []string{"published-marker-pin", "retry-marker-pin"}, func(t *testing.T, mode string) {
		_, o, dir, _, _, p := sourcePreparedBundle(t)
		if mode == "retry-marker-pin" {
			sourceReleaseWithFault(t, o, p, "intent-sync", syscall.EIO)
			o.ops = realSourceFS
		}
		path := filepath.Join(dir, sourceDirectory, releaseFile)
		backing := sourceLstat(t, filepath.Join(dir, sourceDirectory, p.name))
		var markerHeld, backingAtSync, backingAtDetach bool
		o.ops.dirSync = func(f *os.File) error {
			o.ops.dirSync = (*os.File).Sync
			markerHeld = sourceReleaseHasOpenFile(t, sourceLstat(t, path))
			backingAtSync = sourceReleaseHasOpenFile(t, backing)
			return f.Sync()
		}
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			if to == releaseDetached {
				backingAtDetach = sourceReleaseHasOpenFile(t, backing)
			}
			return op(r, from, to)
		}
		sourceReleaseResult(t, o, p, true, nil)
		sourceFailIf(t, !markerHeld, "release used the marker without holding it through directory sync")
		sourceFailIf(t, !backingAtSync || !backingAtDetach, "release lost its backing before detachment (sync %v, detach %v)", backingAtSync, backingAtDetach)
		sourceFailIf(t, sourceReleaseHasOpenFile(t, backing), "completed release retained the backing descriptor")
	})
	sourceModes(t, []string{"marker-after-final-sync", "marker-and-stage-after-final-sync"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		marker := filepath.Join(root, releaseFile)
		markerData := []byte("independent marker")
		var markerInfo os.FileInfo
		o.ops.remove = func(r *os.Root, name string) error {
			if err := r.Remove(name); err != nil {
				return err
			}
			if name == releaseFile {
				o.ops.dirSync = func(pin *os.File) error {
					if err := pin.Sync(); err != nil {
						return err
					}
					if mode == "marker-and-stage-after-final-sync" {
						sourceMust(t, os.WriteFile(filepath.Join(root, publicStagePrefix+p.name), []byte{42}, 0o600))
					}
					markerInfo = writeSourceEntry(t, marker, markerData)
					return nil
				}
			}
			return nil
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourceUnchangedEntry(t, marker, markerInfo, markerData)
		size, err := m.SizeV1()
		sourceMust(t, err)
		if mode == "marker-and-stage-after-final-sync" {
			assertSourceReleaseCharge(t, o, m, 2, size+1)
		} else {
			assertSourceReleaseCharge(t, o, m, 1, size)
		}
	})
	t.Run("protected-stage-alias", func(t *testing.T) {
		_, o, dir, m, _, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		public, held := ".staging-"+p.name, ".stage-hold-"+p.name
		before := sourceLstat(t, filepath.Join(root, p.name))
		sourceMust(t, os.Link(filepath.Join(root, p.name), filepath.Join(root, public)))
		o.ops.remove = func(r *os.Root, name string) error {
			sourceFailIf(t, name == public, "release tried to remove the public stage")
			if name == held {
				sourceUnchangedEntry(t, filepath.Join(root, held), before)
				return syscall.EIO
			}
			return r.Remove(name)
		}
		sourceReleaseResult(t, o, p, true, syscall.EIO)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePresence(t, root, public, false)
		sourcePresence(t, root, p.name, false)
		sourceUnchangedEntry(t, filepath.Join(root, releaseDetached), before)
		sourceUnchangedEntry(t, filepath.Join(root, held), before)
		assertSourceReleaseCharge(t, o, m, 1, uint64(before.Size()))
		o.ops = realSourceFS
		sourceReleaseResult(t, o, p, true, nil)
		sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "release left a stage or marker")
	})
	t.Run("marker-lost-before-clear", func(t *testing.T) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		o.ops.remove = func(r *os.Root, name string) error {
			if name == releaseDetached {
				o.ops.dirSync = func(pin *os.File) error {
					o.ops.dirSync = (*os.File).Sync
					sourceMust(t, os.Remove(filepath.Join(root, releaseFile)))
					return pin.Sync()
				}
			}
			return r.Remove(name)
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
		size, err := m.SizeV1()
		sourceMust(t, err)
		assertSourceReleaseCharge(t, o, m, 1, size)
		sourcePresence(t, root, releaseFile, false)
		sourcePresence(t, root, releaseDetached, false)
		sourcePresence(t, root, p.name, false)
	})
	t.Run("proved-marker-disappears", func(t *testing.T) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		sourceReleaseWithFault(t, o, p, "rename-visible", syscall.EIO)
		o.ops = realSourceFS
		root := filepath.Join(dir, sourceDirectory)
		checkBacking := sourcePreservedEntry(t, filepath.Join(root, p.name))
		checkScratch := sourcePreservedEntry(t, filepath.Join(root, releaseScratch))
		sourceMust(t, os.Remove(filepath.Join(root, releaseFile)))
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
		checkBacking()
		checkScratch()
		sourcePresence(t, root, releaseFile, false)
		size, err := m.SizeV1()
		sourceMust(t, err)
		assertSourceReleaseCharge(t, o, m, 1, size)
	})
	t.Run("previously-unlinked-alias", func(t *testing.T) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		sourceMust(t, os.Link(filepath.Join(root, p.name), filepath.Join(root, ".staging-"+p.name)))
		cause := errors.New("stage directory sync")
		sourceFault(o, "parent-sync", cause, nil)
		sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
		sourcePresence(t, root, ".staging-"+p.name, false)
		sourceReleaseResult(t, o, p, true, nil)
		sourcePrepareAndRead(t, o, sourceForeign(m), parts)
	})
	t.Run("reopened-marker-identity", func(t *testing.T) {
		s, o, dir, m, _, p := sourcePreparedBundle(t)
		sourceReleaseWithFault(t, o, p, "intent-sync", errors.New("intent"))
		fresh := sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		root := filepath.Join(dir, sourceDirectory)
		marker := filepath.Join(root, releaseFile)
		record := sourceReadFile(t, marker)
		sourceMust(t, os.Rename(marker, filepath.Join(t.TempDir(), "initial")))
		sourceMust(t, os.WriteFile(marker, record, 0o600))
		replacement := sourceLstat(t, marker)
		sourceReleaseResult(t, fresh, nil, true, ErrIntegrityV1)
		sourcePrepareResult(t, fresh, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourceFailIf(t, !os.SameFile(replacement, sourceLstat(t, marker)), "release cleared replacement marker")
		sourcePresence(t, root, p.name, true)
	})
	t.Run("distinct-scratch-before-clear", func(t *testing.T) {
		_, o, dir, m, _, p := sourcePreparedBundle(t)
		sourceReleaseWithFault(t, o, p, "marker-clear", errors.New("marker clear"))
		o.ops = realSourceFS
		root := filepath.Join(dir, sourceDirectory)
		marker, scratch := filepath.Join(root, releaseFile), filepath.Join(root, releaseScratch)
		record := sourceReadFile(t, marker)
		sourceMust(t, os.WriteFile(scratch, record, 0o600))
		sourceReadRefusal(t, o, m, ErrIntegrityV1, "distinct marker scratch")
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, marker), record) || !bytes.Equal(sourceReadFile(t, scratch), record), "release cleared a distinct marker or scratch")
		size, err := m.SizeV1()
		sourceMust(t, err)
		sourceFailIf(t, o.release == nil || o.release.size != size || o.live[p.name] != p.incarnation, "refused clear returned capture charge")
	})
	sourceModes(t, []string{"backing-after-scratch", "private-after-scratch", "stage-after-scratch"}, func(t *testing.T, mode string) {
		s, o, dir, m, parts, p := sourcePreparedBundle(t)
		sourceReleaseWithFault(t, o, p, "marker-clear", syscall.EIO)
		o.ops = realSourceFS
		root := filepath.Join(dir, sourceDirectory)
		marker := filepath.Join(root, releaseFile)
		keepMarker := sourcePreservedEntry(t, marker)
		sourceMust(t, os.Link(marker, filepath.Join(root, releaseScratch)))
		leaf, want := p.name, ErrIdentityV1
		if mode == "private-after-scratch" {
			leaf = releaseDetached
		}
		if mode == "stage-after-scratch" {
			leaf, want = publicStagePrefix+p.name, ErrBusyV1
		}
		path := filepath.Join(root, leaf)
		o.ops.remove = func(r *os.Root, name string) error {
			if err := r.Remove(name); err != nil || name != releaseScratch {
				return err
			}
			return os.WriteFile(path, []byte("independent"), 0o600)
		}
		sourceReleaseResult(t, o, p, true, want)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		keepMarker()
		keepEntry := sourcePreservedEntry(t, path)
		sourcePresence(t, root, releaseScratch, false)
		o.ops = realSourceFS
		sourceReleaseResult(t, o, p, true, want)
		keepEntry()
		keepMarker()
		sourceMust(t, os.Remove(path))
		if mode != "stage-after-scratch" {
			o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
			p = nil
		}
		size, err := m.SizeV1()
		sourceMust(t, err)
		assertSourceReleaseCharge(t, o, m, 1, size)
		sourceReleaseResult(t, o, p, true, nil)
		sourcePresence(t, root, releaseFile, false)
		sourcePrepareAndRead(t, o, sourceForeign(m), parts)
	})
	t.Run("pending-independent-stage", func(t *testing.T) {
		for _, fault := range []string{"intent-sync", "unlink", "unlink-sync", "marker-clear", "unlink-sync-after-alias", "marker-clear-after-alias", "uppercase-intent-sync", "uppercase-marker-clear"} {
			t.Run(fault, func(t *testing.T) {
				s, o, dir, m, parts, p := sourcePreparedBundle(t)
				root := filepath.Join(dir, sourceDirectory)
				key := p.name
				stage, upper := strings.CutPrefix(fault, "uppercase-")
				if upper {
					key = strings.ToUpper(key)
				}
				temp := filepath.Join(root, publicStagePrefix+key)
				stage, alias := strings.CutSuffix(stage, "-after-alias")
				if alias {
					sourceMust(t, os.Link(filepath.Join(root, p.name), temp))
				}
				sourceReleaseWithFault(t, o, p, stage, errors.New("pending"))
				sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
				sourceMust(t, os.WriteFile(temp, []byte("independent"), 0o600))
				o.ops = realSourceFS
				sourceReleaseResult(t, o, p, true, ErrBusyV1)
				sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
				sourcePresence(t, root, releaseFile, true)
				sourcePresence(t, root, p.name, stage == "intent-sync")
				sourcePresence(t, root, releaseDetached, stage == "unlink")
				size, err := m.SizeV1()
				sourceMust(t, err)
				assertSourceReleaseCharge(t, o, m, 2, size+11)
				sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
				fresh := sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
				sourceReleaseResult(t, fresh, nil, true, ErrBusyV1)
				sourcePrepareResult(t, fresh, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
				assertSourceReleaseCharge(t, fresh, m, 2, size+11)
				sourceFailIf(t, !bytes.Equal(sourceReadFile(t, temp), []byte("independent")), "release changed independent stage")
				if upper && stage == "marker-clear" {
					sourceMust(t, os.Remove(temp))
					sourceReleaseResult(t, fresh, nil, true, nil)
					sourcePresence(t, root, releaseFile, false)
				}
			})
		}
	})
	t.Run("detached", testSourceDetachedRelease)
	t.Run("replaced-before-detach", testSourceRestoreWithoutReplacement)
	t.Run("restore-acknowledgement", testSourceRestoreAcknowledgement)
	t.Run("unowned-private-names", testSourcePrivateNames)
	t.Run("pending-census", testSourcePendingCensus)
	t.Run("backing-links", testSourceBackingLinks)
	t.Run("marker-collision", testSourceMarkerCollision)
	sourceModes(t, []string{"write", "chmod", "file-sync", "close", "rename", "rename-visible", "intent-sync", "unlink", "unlink-reopen-competing-prepare", "unlink-sync", "marker-clear", "final-sync"}, testSourceReleaseStage)
	sourceModes(t, []string{"changed-content", "changed-inode", "linked-backing"}, testSourceReleaseIncarnation)
	t.Run("scratch-link", func(t *testing.T) {
		s, o, dir, _, _, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		path, marker, scratch := filepath.Join(root, p.name), filepath.Join(root, releaseFile), filepath.Join(root, releaseScratch)
		original := sourceReadFile(t, path)
		cause := errors.New("source unlink refusal")
		sourceReleaseWithFault(t, o, p, "intent-sync", cause)
		sourceMust(t, os.Rename(marker, scratch))
		record := sourceReadFile(t, scratch)
		s = sourceReopenStore(t, s, dir)
		for _, target := range []string{releaseScratch, "absent"} {
			sourceMust(t, os.Symlink(target, marker))
			sourceOpen(t, s, sourceID(), sourceLimits(), ErrIntegrityV1)
			sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), original) || !bytes.Equal(sourceReadFile(t, scratch), record), "marker link to %s changed backing or scratch", target)
			sourceMust(t, os.Remove(marker))
		}
		sourceMust(t, os.Rename(scratch, marker))
		fresh := sourceOpen(t, s, sourceID(), sourceLimits(), nil)
		sourceReleaseResult(t, fresh, nil, true, nil)
		sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "qualified release left backing")
	})
	sourceModes(t, []string{"backing-reappears/canonical", "backing-reappears/private"}, func(t *testing.T, mode string) {
		s, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		path, marker := filepath.Join(root, p.name), filepath.Join(root, releaseFile)
		heldFile, err := os.Open(path)
		sourceMust(t, err)
		defer heldFile.Close()
		if mode == "backing-reappears/private" {
			path = filepath.Join(root, releaseDetached)
		}
		entry := []byte("entry at the released name")
		unlinks := 0
		o.ops.remove = func(r *os.Root, name string) error {
			if name == releaseDetached {
				unlinks++
				o.ops.dirSync = func(pin *os.File) error {
					o.ops.dirSync = (*os.File).Sync
					err := pin.Sync()
					sourceMust(t, os.WriteFile(path, entry, 0o600))
					return err
				}
			}
			return r.Remove(name)
		}
		sourceReleaseResult(t, o, p, true, ErrIdentityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
		sourceFailIf(t, o.release == nil || o.live[p.name] != p.incarnation, "refused marker removal returned the release charge")
		record := o.release.record
		info, err := os.Lstat(path)
		sourceMust(t, err)
		unchanged := func(want []byte, message string) {
			t.Helper()
			now, err := os.Lstat(path)
			got, markerErr := os.ReadFile(marker)
			sourceFailIf(t, err != nil || !os.SameFile(info, now) || !bytes.Equal(sourceReadFile(t, path), entry) || markerErr != nil || !bytes.Equal(got, want),
				"%s changed the entry or marker: %v", message, markerErr)
			sourceFailIf(t, unlinks != 1, "%s: backing unlinks=%d, want 1", message, unlinks)
		}
		unchanged(record, "refused marker removal")
		sourceMust(t, os.WriteFile(marker, []byte{1}, 0o600))
		sourceReleaseResult(t, o, p, true, ErrIdentityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		unchanged([]byte{1}, "retry with a differing marker")
		sourceMust(t, os.WriteFile(marker, record, 0o600))
		sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), ErrIdentityV1)
		unchanged(record, "fresh open")
	})
	sourceModes(t, []string{"scratch-sync", "pending-absent", "pending-visible", "clear-present", "clear-absent"}, testSourceReleaseInconclusive)
}

func testSourceReleaseUnfundedStage(t *testing.T) {
	m, parts, _, limits := sourceSizedBundle(t)
	stageManifest, retained := sourceForeign(m), sourceForeign(sourceForeign(m))
	limits.Files = 2
	s, _, paths, _ := sourcePreparedScene(t, limits, retained, parts)
	s = sourceReopenStore(t, s, paths.dir)
	o := sourceOpen(t, s, sourceID(), limits, nil)
	p := sourcePrepare(t, o, m, parts)
	stage := filepath.Join(paths.root, publicStagePrefix+stageManifest.name(o.id))
	stageInfo := writeSourceEntry(t, stage, []byte{17})
	backing := sourcePreservedEntry(t, filepath.Join(paths.root, p.name))
	retainedInfo, retainedBytes := sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
	o.ops.namespace = func(sourceNamespace, *sourceRoot, string, string) error {
		t.Fatal("unfunded stage reached a namespace operation")
		return nil
	}
	o.ops.write = func(*os.File, []byte) (int, error) {
		t.Fatal("unfunded release wrote a record")
		return 0, nil
	}
	o.ops.remove = func(*os.Root, string) error {
		t.Fatal("unfunded stage reached removal")
		return nil
	}
	sourceReleaseResult(t, o, p, true, ErrCapacityV1)
	withdrawn := filepath.Join(paths.dir, "withdrawn-capture")
	sourceMust(t, os.Rename(paths.capture, withdrawn))
	sourcePrepareResult(t, o, stageManifest, refusedSourceProducer(t), ErrIdentityV1)
	sourceFailIf(t, o.stage.File != nil || o.observedStage != stageManifest.name(o.id), "unfunded stage acquired a pin or lost its key")
	sourceUnchangedEntry(t, stage, stageInfo, []byte{17})
	sourceUnchangedEntry(t, withdrawn, retainedInfo, retainedBytes)
	backing()
	sourceAbsent(t, paths.root, releaseFile, releaseDetached, releaseScratch)
	fresh := sourceOpen(t, sourceReopenStore(t, s, paths.dir), sourceID(), limits, nil)
	sourcePrepareAndRead(t, fresh, stageManifest, parts)
	sourceRead(t, fresh, m, parts)
}

func testSourceReleaseDescriptorOverlap(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	retained, stageManifest := sourceForeign(m), sourceForeign(sourceForeign(m))
	if mode == "descriptor-six-live" {
		limits.Descriptors = 6
	}
	s, _, paths, _ := sourcePreparedScene(t, limits, retained, parts)
	o := sourceOpen(t, sourceReopenStore(t, s, paths.dir), sourceID(), limits, nil)
	p := sourcePrepare(t, o, m, parts)
	backing := filepath.Join(paths.root, p.name)
	backingInfo := sourceLstat(t, backing)
	keepBacking, keepRetained := sourcePreservedEntry(t, backing), sourcePreservedEntry(t, paths.capture)
	retainedInfo := sourceLstat(t, paths.capture)
	key := stageManifest.name(o.id)
	stage := filepath.Join(paths.root, publicStagePrefix+key)
	sourceMust(t, os.Link(paths.capture, stage))
	cause := sourceRetirementFault(t, o, heldStagePrefix+key, false, false, func() {
		sourceAbsent(t, paths.root, publicStagePrefix+key, heldStagePrefix+key)
	})
	sourcePrepareResult(t, o, stageManifest, sourceProducer(stageManifest, parts), cause)
	o.ops = realSourceFS
	quota := checkSourcePinned(t, o.stage.Quota, retainedInfo)
	if mode == "descriptor-five-gone" {
		sourceReleaseWithFault(t, o, p, "unlink-sync", syscall.EIO)
		sourcePrepareResult(t, o, stageManifest, refusedSourceProducer(t), ErrBusyV1)
		o.ops = realSourceFS
		sourceAbsent(t, paths.root, p.name, releaseDetached, releaseScratch)
	}
	stageInfo := writeSourceEntry(t, stage, []byte{17})
	sourceRead(t, o, retained, parts)
	pin := checkSourceStageWitness(t, o, stageInfo)
	checkSourceReleaseDescriptorOverlap(t, o, p, mode, backingInfo, retainedInfo, stageInfo)
	sourceRead(t, o, retained, parts, func() {
		sourceFailIf(t, o.stage.File != pin || o.stage.Quota != quota, "release changed a staging descriptor")
	})
	keepRetained()
	sourceUnchangedEntry(t, stage, stageInfo, []byte{17})
	if mode == "descriptor-five-live" {
		keepBacking()
		sourceAbsent(t, paths.root, releaseFile, releaseDetached, releaseScratch)
		assertSourceReleaseCharge(t, o, retained, 3, 2*size+1)
	} else {
		sourceAbsent(t, paths.root, p.name, releaseFile, releaseDetached, releaseScratch)
		assertSourceReleaseCharge(t, o, retained, 2, size+1)
	}
	sourcePrepareAndRead(t, o, stageManifest, parts)
	checkSourcePinClosed(t, pin, o.stage.File)
	checkSourcePinClosed(t, quota, o.stage.Quota)
	if mode == "descriptor-five-live" {
		sourceReleaseResult(t, o, p, true, nil)
	}
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
}

func checkSourceReleaseDescriptorOverlap(t *testing.T, o *SourceOwnerV1, p *PreparedSourceV1, mode string, backing, quota, stage os.FileInfo) {
	t.Helper()
	root := filepath.Join(o.dir, sourceDirectory)
	rootInfo := sourceLstat(t, root)
	wantPeak, want := 6, error(nil)
	switch mode {
	case "descriptor-five-live":
		wantPeak, want = 0, ErrCapacityV1
	case "descriptor-five-gone":
		wantPeak = 5
	}
	peak := 0
	o.ops.write = func(f *os.File, data []byte) (int, error) {
		sourceFailIf(t, mode != "descriptor-six-live", "release wrote a scratch record without backing admission")
		return f.Write(data)
	}
	o.ops.dirSync = func(pin *os.File) error {
		o.ops.dirSync = (*os.File).Sync
		marker := sourceLstat(t, filepath.Join(root, releaseFile))
		infos := []os.FileInfo{rootInfo, marker, quota, stage}
		if mode != "descriptor-five-gone" {
			infos = append(infos, backing)
		}
		for _, info := range infos {
			peak += len(sourceOpenFileModes(t, info))
		}
		sourceFailIf(t, peak != wantPeak, "release held %d descriptors at marker sync, want %d", peak, wantPeak)
		return pin.Sync()
	}
	sourceReleaseResult(t, o, p, true, want)
	sourceFailIf(t, peak != wantPeak, "release observed a marker sync peak of %d, want %d", peak, wantPeak)
	o.ops = realSourceFS
}

func testSourcePublishedMarkerBytes(t *testing.T) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	canonical := filepath.Join(root, p.name)
	marker, scratch := filepath.Join(root, releaseFile), filepath.Join(root, releaseScratch)
	keepBacking := sourcePreservedEntry(t, canonical)
	var original, changed []byte
	var markerInode os.FileInfo
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
		sourceFailIf(t, from != releaseScratch || to != releaseFile, "changed record authorized a name move")
		original = sourceReadFile(t, scratch)
		markerInode = sourceLstat(t, scratch)
		sourceMust(t, op(r, from, to))
		changed = slices.Clone(original)
		changed[len(changed)-1] ^= 1
		return os.WriteFile(marker, changed, 0o600)
	}
	o.ops.remove = func(*os.Root, string) error {
		t.Fatal("changed named marker authorized a removal")
		return nil
	}
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
	keepBacking()
	sourceUnchangedEntry(t, marker, markerInode, changed)
	sourceUnchangedEntry(t, scratch, markerInode, changed)
	sourcePresence(t, root, releaseDetached, false)
	assertSourceReleaseCharge(t, o, m, 1, sourceSize(t, m))
	sourceMust(t, os.WriteFile(marker, original, 0o600))
	o.ops = realSourceFS
	sourceReleaseResult(t, o, p, true, nil)
	sourcePrepareAndRead(t, o, sourceForeign(m), parts)
}

func testSourceUnpublishedLinkResult(t *testing.T) {
	sourceModes(t, []string{"absent", "absent-raw", "distinct", "distinct-raw"}, func(t *testing.T, mode string) {
		_, o, _, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(o.dir, sourceDirectory)
		marker := filepath.Join(root, releaseFile)
		keepBacking := sourcePreservedEntry(t, filepath.Join(root, p.name))
		noEffect := mode == "absent-raw"
		var observedAbsent bool
		var scratch os.FileInfo
		var record []byte
		want := error(ErrIntegrityV1)
		if noEffect || mode == "distinct-raw" {
			want = syscall.EIO
		}
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			sourceFailIf(t, from != releaseScratch || to != releaseFile, "unpublished record authorized another name operation")
			scratch, record = sourceLstat(t, filepath.Join(root, from)), sourceReadFile(t, filepath.Join(root, from))
			if noEffect {
				sourceLookupOnce(t, [2]string{root, to}, func(bound *sourceRoot) {
					_, err := bound.Root.Lstat(to)
					sourceFailIf(t, !errors.Is(err, os.ErrNotExist), "marker lookup returned %v, want absence", err)
					observedAbsent = true
				})
				return syscall.EIO
			}
			sourceMust(t, op(r, from, to))
			sourceMust(t, r.Remove(to))
			if mode != "absent" {
				sourceMust(t, os.WriteFile(marker, []byte("independent marker"), 0o600))
			}
			if mode == "distinct-raw" {
				return syscall.EIO
			}
			return nil
		}
		sourceReleaseResult(t, o, p, true, want)
		if mode == "absent" || noEffect {
			sourceRead(t, o, m, parts)
			sourcePresence(t, root, releaseFile, false)
		} else {
			sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrIntegrityV1)
			sourceFailIf(t, !bytes.Equal(sourceReadFile(t, marker), []byte("independent marker")), "foreign marker changed")
		}
		keepBacking()
		sourceUnchangedEntry(t, filepath.Join(root, releaseScratch), scratch, record)
		sourcePresence(t, root, releaseDetached, false)
		if noEffect {
			sourceFailIf(t, !observedAbsent, "release did not observe the absent marker")
			o.ops = realSourceFS
			sourceReleaseResult(t, o, p, true, nil)
			sourceAbsent(t, root, p.name, releaseFile, releaseScratch, releaseDetached)
			sourcePrepareAndRead(t, o, sourceForeign(m), parts)
		}
	})
}

func testSourceFinalObservations(t *testing.T) {
	for _, phase := range []string{"before-clear", "before-return"} {
		t.Run(phase, func(t *testing.T) {
			t.Run("listed-alternate-canonical", func(t *testing.T) {
				testSourceAlternateFinalBacking(t, phase)
			})
			sourceModes(t, []string{"sync-acknowledgement-live", "sync-acknowledgement-reopen"}, func(t *testing.T, mode string) {
				testSourceFinalSyncAcknowledgement(t, phase, mode)
			})
			sourceModes(t, []string{"listed-canonical", "canonical-unavailable", "private-unavailable"}, func(t *testing.T, mode string) {
				_, o, _, m, parts, p := sourcePreparedBundle(t)
				root := filepath.Join(o.dir, sourceDirectory)
				var reached bool
				var entry os.FileInfo
				refilled := filepath.Join(root, p.name)
				watchSourceFinalObservation(t, o, phase, func() error {
					reached = true
					switch mode {
					case "listed-canonical":
						sourceLookupOnce(t, [2]string{root, releaseDetached}, func(*sourceRoot) {
							entry = writeSourceEntry(t, refilled, []byte("refilled after the canonical lookup"))
						})
					case "canonical-unavailable":
						sourceLookupOnce(t, [2]string{root, p.name}, struct{}{})
					case "private-unavailable":
						sourceLookupOnce(t, [2]string{root, releaseDetached}, struct{}{})
					}
					return nil
				})
				sourceReleaseResult(t, o, p, true, ErrIdentityV1)
				sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
				sourceFailIf(t, !reached, "release did not reach the selected directory sync")
				sourcePresence(t, root, releaseFile, phase == "before-clear")
				if mode == "listed-canonical" {
					sourceUnchangedEntry(t, refilled, entry, []byte("refilled after the canonical lookup"))
					sourceMust(t, os.Remove(refilled))
				}
				assertSourceReleaseCharge(t, o, m, 1, sourceSize(t, m))
				sourceReleaseResult(t, o, p, true, nil)
				sourcePrepareAndRead(t, o, sourceForeign(m), parts)
			})
		})
	}
}

func watchSourceFinalObservation(t *testing.T, o *SourceOwnerV1, phase string, observe func() error) {
	t.Helper()
	arm := releaseFile
	if phase == "before-clear" {
		arm = releaseDetached
	}
	o.ops.remove = func(r *os.Root, leaf string) error {
		err := r.Remove(leaf)
		if err != nil || leaf != arm {
			return err
		}
		o.ops.dirSync = func(pin *os.File) error {
			o.ops.dirSync = (*os.File).Sync
			sourceMust(t, pin.Sync())
			return observe()
		}
		return nil
	}
}

func testSourceAlternateFinalBacking(t *testing.T, phase string) {
	_, o, _, m, parts, p := sourcePreparedBundle(t)
	paths := sourcePaths(o.dir, p.name)
	marker := filepath.Join(paths.root, releaseFile)
	leaf := strings.ToUpper(p.name)
	sourceFailIf(t, leaf == p.name, "fixture needs an alternate backing spelling")
	refilled := filepath.Join(paths.root, leaf)
	data := []byte("alternate backing spelling")
	beforeClear := phase == "before-clear"
	var aliases bool
	var entry os.FileInfo
	var keepMarker func()
	watchSourceFinalObservation(t, o, phase, func() error {
		if beforeClear {
			keepMarker = sourcePreservedEntry(t, marker)
		}
		sourceLookupOnce(t, [2]string{paths.root, releaseDetached}, func(*sourceRoot) {
			entry = writeSourceEntry(t, refilled, data)
			canonical, err := os.Lstat(paths.capture)
			if !errors.Is(err, os.ErrNotExist) {
				sourceMust(t, err)
				sourceFailIf(t, !os.SameFile(entry, canonical), "alternate spelling resolved to a different file")
				aliases = true
			}
		})
		return nil
	})
	remove := o.ops.remove
	o.ops.remove = func(r *os.Root, leaf string) error {
		sourceFailIf(t, aliases && leaf == releaseFile, "an alternate backing address allowed marker removal")
		return remove(r, leaf)
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		err := o.ReleaseUnpublishedSourceV1(a, p, true)
		sourceFailIf(t, entry == nil, "release did not reach the alternate backing observation")
		want := map[bool]error{true: ErrIdentityV1}[aliases]
		sourceWantError(t, err, want, "release with alternate backing spelling")
	})
	if aliases {
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
	} else {
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	}
	sourcePresence(t, paths.root, releaseFile, aliases && beforeClear)
	if aliases && beforeClear {
		keepMarker()
	}
	sourceUnchangedEntry(t, refilled, entry, data)
	found := slices.ContainsFunc(sourceEntries(t, paths.dir), func(e os.DirEntry) bool { return e.Name() == leaf })
	sourceFailIf(t, !found, "alternate backing spelling disappeared")
	if aliases {
		sourceMust(t, os.Remove(refilled))
		assertSourceReleaseCharge(t, o, m, 1, sourceSize(t, m))
		o.ops = realSourceFS
		sourceReleaseResult(t, o, p, true, nil)
	}
	sourcePrepareAndRead(t, o, sourceForeign(m), parts)
}

func testSourceFinalSyncAcknowledgement(t *testing.T, phase, mode string) {
	s, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	rootInfo := sourceLstat(t, root)
	marker := filepath.Join(root, releaseFile)
	key := p.name
	foreign, size := sourceForeign(m), sourceSize(t, m)
	beforeClear := phase == "before-clear"
	var synced bool
	watchSourceFinalObservation(t, o, phase, func() error {
		synced = true
		return syscall.EIO
	})
	var keepMarker func()
	unlinks, clears := 0, 0
	remove := o.ops.remove
	countRemove := func(r *os.Root, leaf string) error {
		switch leaf {
		case releaseDetached:
			unlinks++
			if unlinks == 1 {
				keepMarker = sourcePreservedEntry(t, marker)
			}
		case releaseFile:
			clears++
		}
		return remove(r, leaf)
	}
	o.ops.remove = countRemove
	sourceReleaseResult(t, o, p, true, syscall.EIO)
	sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
	sourceFailIf(t, !synced, "release did not report the error after directory sync")
	wantClears := map[bool]int{false: 1}[beforeClear]
	sourceFailIf(t, unlinks != 1 || clears != wantClears, "sync refusal backing unlinks=%d, marker clears=%d, want 1/%d", unlinks, clears, wantClears)
	sourcePresence(t, root, releaseFile, beforeClear)
	if beforeClear {
		keepMarker()
	}
	sourceAbsent(t, root, key, releaseDetached, releaseScratch)
	assertSourceReleaseCharge(t, o, m, 1, size)
	if mode == "sync-acknowledgement-reopen" {
		o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		p = nil
		if !beforeClear {
			sourceReleaseResult(t, o, nil, true, ErrIntegrityV1)
			assertSourceReleaseCharge(t, o, m, 0, 0)
			sourcePrepareAndRead(t, o, foreign, parts)
			return
		}
		sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
		keepMarker()
		assertSourceReleaseCharge(t, o, m, 1, size)
		remove, o.ops.remove = o.ops.remove, countRemove
	}
	syncsBeforeClear, syncsAfterClear := 0, 0
	o.ops.dirSync = func(pin *os.File) error {
		info, err := pin.Stat()
		sourceMust(t, err)
		sourceFailIf(t, !os.SameFile(info, rootInfo), "release retry synced a different directory")
		sourceMust(t, pin.Sync())
		_, err = os.Lstat(marker)
		if errors.Is(err, os.ErrNotExist) {
			syncsAfterClear++
		} else {
			sourceMust(t, err)
			syncsBeforeClear++
		}
		return nil
	}
	sourceReleaseResult(t, o, p, true, nil)
	sourceFailIf(t, (syncsBeforeClear != 0) != beforeClear, "release retry synced with marker present %d times, want presence=%t", syncsBeforeClear, beforeClear)
	sourceFailIf(t, syncsAfterClear != 1, "release retry synced after marker clearance %d times, want 1", syncsAfterClear)
	sourceFailIf(t, unlinks != 1 || clears != 1, "release retry backing unlinks=%d, marker clears=%d, want 1/1", unlinks, clears)
	sourceAbsent(t, root, key, releaseDetached, releaseScratch, releaseFile)
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	sourcePrepareAndRead(t, o, foreign, parts)
}

func testSourceRecoverHeldReleaseStage(t *testing.T) {
	s, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	canonical, held := filepath.Join(root, p.name), filepath.Join(root, heldStagePrefix+p.name)
	public := filepath.Join(root, publicStagePrefix+p.name)
	sourceReleaseWithFault(t, o, p, "intent-sync", syscall.EIO)
	original := sourceReadFile(t, canonical)
	sourceMust(t, os.Link(canonical, held))
	corrupt := sourceResealed(original, len(original)-sha256.Size-1)
	sourceMust(t, os.WriteFile(canonical, corrupt, 0o600))
	keepBacking := sourcePreservedEntry(t, canonical)
	keepHeld := sourcePreservedEntry(t, held)
	keepMarker := sourcePreservedEntry(t, filepath.Join(root, releaseFile))
	s = sourceReopenStore(t, s, dir)
	ops := realSourceFS
	defer func() { realSourceFS = ops }()
	realSourceFS.namespace = func(sourceNamespace, *sourceRoot, string, string) error {
		t.Fatal("corrupt backing authorized stage restoration")
		return nil
	}
	sourceOpen(t, s, sourceID(), sourceLimits(), ErrIntegrityV1)
	sourcePresence(t, root, filepath.Base(public), false)
	keepBacking()
	keepHeld()
	keepMarker()
	sourceMust(t, os.WriteFile(canonical, original, 0o600))
	inode := sourceLstat(t, held)
	realSourceFS = ops
	fresh := sourceOpen(t, s, sourceID(), sourceLimits(), nil)
	sourcePrepareResult(t, fresh, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
	sourceUnchangedEntry(t, public, inode, original)
	sourcePresence(t, root, filepath.Base(held), false)
	assertSourceReleaseCharge(t, fresh, m, 1, sourceSize(t, m))
	sourceReleaseResult(t, fresh, nil, true, nil)
	sourcePrepareAndRead(t, fresh, sourceForeign(m), parts)
}

func testSourceMatchingMarkerAfterClear(t *testing.T) {
	sourceModes(t, []string{"remains", "reappears", "reappears-with-backing"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		marker := filepath.Join(root, releaseFile)
		saved := filepath.Join(dir, "marker-link")
		var before, refilled os.FileInfo
		var record []byte
		clears := 0
		o.ops.remove = func(r *os.Root, leaf string) error {
			if leaf != releaseFile {
				return r.Remove(leaf)
			}
			clears++
			before, record = sourceLstat(t, marker), sourceReadFile(t, marker)
			if mode == "remains" {
				return nil
			}
			sourceMust(t, os.Link(marker, saved))
			sourceMust(t, r.Remove(leaf))
			o.ops.dirSync = func(pin *os.File) error {
				o.ops.dirSync = (*os.File).Sync
				sourceMust(t, pin.Sync())
				sourceMust(t, os.Rename(saved, marker))
				if mode == "reappears-with-backing" {
					refilled = writeSourceEntry(t, filepath.Join(root, p.name), []byte("reappeared backing"))
				}
				return nil
			}
			return nil
		}
		want := error(ErrIntegrityV1)
		if mode == "reappears-with-backing" {
			want = ErrIdentityV1
		}
		sourceReleaseResult(t, o, p, true, want)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourceUnchangedEntry(t, marker, before, record)
		if mode == "reappears-with-backing" {
			path := filepath.Join(root, p.name)
			sourceUnchangedEntry(t, path, refilled, []byte("reappeared backing"))
			sourceMust(t, os.Remove(path))
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourceFailIf(t, clears != 1, "retry attempted to remove a reappeared marker")
		assertSourceReleaseCharge(t, o, m, 1, sourceSize(t, m))
		sourceMust(t, os.Remove(marker))
		sourceReleaseResult(t, o, p, true, nil)
		sourcePrepareAndRead(t, o, sourceForeign(m), parts)
	})
}

func testSourceMarkerClearObservation(t *testing.T, mode string) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(o.dir, sourceDirectory)
	marker, saved := filepath.Join(root, releaseFile), filepath.Join(dir, "saved-marker")
	foreign, size := sourceForeign(m), sourceSize(t, m)
	lookup := [2]string{root, releaseFile}
	lookupFault := strings.HasPrefix(mode, "lookup-error-")
	removed := mode == "lookup-error-then-absent" || mode == "absent-then-reappears"
	var original os.FileInfo
	var record []byte
	unlinks, clears := 0, 0
	o.ops.remove = func(r *os.Root, leaf string) error {
		switch leaf {
		case releaseDetached:
			unlinks++
		case releaseFile:
			clears++
			if clears == 1 {
				original, record = sourceLstat(t, marker), sourceReadFile(t, marker)
				if removed {
					sourceMust(t, os.Link(marker, saved))
					sourceMust(t, r.Remove(leaf))
				}
				if lookupFault {
					sourceLookupOnce(t, lookup, struct{}{})
				}
				return syscall.EIO
			}
		}
		return r.Remove(leaf)
	}
	keepPending := func(markerPresent bool) {
		t.Helper()
		sourceFailIf(t, unlinks != 1 || clears != 1, "pending release backing unlinks=%d, marker clears=%d", unlinks, clears)
		sourceAbsent(t, root, p.name, releaseDetached, releaseScratch)
		if markerPresent {
			sourceUnchangedEntry(t, marker, original, record)
		} else {
			sourcePresence(t, root, releaseFile, false)
			sourceUnchangedEntry(t, saved, original, record)
		}
	}
	sourceReleaseResult(t, o, p, true, syscall.EIO)
	sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
	keepPending(!removed)
	_, faultArmed := sourceLookupFaults.Load(lookup)
	sourceFailIf(t, faultArmed, "marker clearance did not consume the lookup error")
	assertSourceReleaseCharge(t, o, m, 1, size)
	if lookupFault {
		stage := filepath.Join(root, publicStagePrefix+strings.ToUpper(p.name))
		data := []byte("independent stage")
		independent := writeSourceEntry(t, stage, data)
		var markerObserved bool
		sourceLookupOnce(t, lookup, func(*sourceRoot) { markerObserved = true })
		sourceReleaseResult(t, o, p, true, ErrBusyV1)
		sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
		sourceFailIf(t, !markerObserved, "stage refusal did not observe the marker leaf")
		keepPending(!removed)
		sourceUnchangedEntry(t, stage, independent, data)
		assertSourceReleaseCharge(t, o, m, 2, size+uint64(len(data)))
		sourceMust(t, os.Remove(stage))
	}
	from, to := marker, saved
	if removed {
		from, to = saved, marker
	}
	sourceMust(t, os.Rename(from, to))
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
	keepPending(removed)
	assertSourceReleaseCharge(t, o, m, 1, size)
	if removed {
		sourceMust(t, os.Remove(marker))
	} else {
		sourceMust(t, os.Rename(saved, marker))
	}
	sourceReleaseResult(t, o, p, true, nil)
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	wantClears := map[bool]int{false: 2, true: 1}[removed]
	sourceFailIf(t, unlinks != 1 || clears != wantClears, "release retry backing unlinks=%d, marker clears=%d, want 1/%d", unlinks, clears, wantClears)
	sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "release retry left source entries")
	sourcePrepareAndRead(t, o, foreign, parts)
}

func testSourceLastLinkRetryProof(t *testing.T) {
	sourceModes(t, []string{"exact", "nominal-no-unlink", "absent", "foreign", "nonregular", "unavailable"}, func(t *testing.T, mode string) {
		s, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(o.dir, sourceDirectory)
		private, saved := filepath.Join(root, releaseDetached), filepath.Join(dir, "unlinked-backing")
		inode := sourceLstat(t, filepath.Join(root, p.name))
		original := sourceReadFile(t, filepath.Join(root, p.name))
		var replaced os.FileInfo
		calls := 0
		o.ops.remove = func(r *os.Root, leaf string) error {
			if leaf != releaseDetached {
				return r.Remove(leaf)
			}
			calls++
			sourceUnchangedEntry(t, private, inode, original)
			switch mode {
			case "nominal-no-unlink":
				return nil
			case "absent", "foreign", "nonregular":
				sourceMust(t, os.Rename(private, saved))
				if mode == "foreign" {
					replaced = writeSourceEntry(t, private, []byte("foreign inode"))
				}
				if mode == "nonregular" {
					sourceMust(t, syscall.Mkfifo(private, 0o600))
					replaced = sourceLstat(t, private)
				}
			case "unavailable":
				sourceLookupOnce(t, [2]string{root, releaseDetached}, struct{}{})
			}
			return syscall.EIO
		}
		first := error(syscall.EIO)
		if mode == "nominal-no-unlink" {
			first = ErrIdentityV1
		}
		sourceReleaseResult(t, o, p, true, first)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePresence(t, root, releaseFile, true)
		sourcePresence(t, root, p.name, false)
		sourceFailIf(t, calls != 1, "release did not reach the private unlink")
		o.ops = realSourceFS
		if mode != "exact" && mode != "nominal-no-unlink" {
			switch mode {
			case "foreign":
				sourceUnchangedEntry(t, private, replaced, []byte("foreign inode"))
				sourceMust(t, os.Remove(private))
			case "nonregular":
				sourceUnchangedEntry(t, private, replaced)
				sourceFailIf(t, sourceLstat(t, private).Mode()&os.ModeNamedPipe == 0, "private FIFO was consumed")
				sourceMust(t, os.Remove(private))
			}
			if mode != "unavailable" {
				sourceMust(t, os.Rename(saved, private))
			}
			sourceUnchangedEntry(t, private, inode, original)
			sourceReleaseResult(t, o, p, true, ErrIdentityV1)
			sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
			assertSourceReleaseCharge(t, o, m, 1, sourceSize(t, m))
			o, p = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil), nil
			sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		}
		sourceReleaseResult(t, o, p, true, nil)
		sourcePrepareAndRead(t, o, sourceForeign(m), parts)
	})
}

func testSourceExpiredReleaseHandle(t *testing.T) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	sibling := sourcePrepare(t, o, m, parts)
	sourceFailIf(t, sibling.incarnation != p.incarnation, "two handles did not identify one retained capture")
	sourceReleaseWithFault(t, o, p, "marker-clear", syscall.EIO)
	sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
	o.ops = realSourceFS
	sourceReleaseResult(t, o, sibling, true, nil)
	replacement := sourcePrepare(t, o, m, parts)
	path := filepath.Join(dir, sourceDirectory, p.name)
	preserve := sourcePreservedEntry(t, path)
	sourceFailIf(t, replacement.incarnation == p.incarnation, "replacement reused the settled release handle")
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	sourceRead(t, o, m, parts)
	preserve()
}

func testSourceFinalStage(t *testing.T) {
	sourceModes(t, []string{"before-detach/missing-marker", "before-detach/changed-marker", "before-detach/missing-marker-with-alias"}, func(t *testing.T, mode string) {
		s, o, dir, m, _, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		marker, saved := filepath.Join(root, releaseFile), filepath.Join(dir, "saved-marker")
		alias := filepath.Join(root, publicStagePrefix+strings.ToUpper(p.name))
		keepBacking := sourcePreservedEntry(t, filepath.Join(root, p.name))
		sourceReleaseWithFault(t, o, p, "rename-visible", syscall.EIO)
		o.ops = realSourceFS
		o.ops.remove = func(r *os.Root, leaf string) error {
			if err := r.Remove(leaf); err != nil {
				return err
			}
			if leaf == releaseScratch {
				sourceMust(t, os.Rename(marker, saved))
				if mode == "before-detach/changed-marker" {
					sourceMust(t, os.WriteFile(marker, sourceReadFile(t, saved), 0o600))
				}
				if mode == "before-detach/missing-marker-with-alias" {
					sourceMust(t, os.Link(filepath.Join(root, p.name), alias))
				}
			}
			return nil
		}
		o.ops.namespace = func(_ sourceNamespace, _ *sourceRoot, from, to string) error {
			t.Fatalf("release attempted to move %q to %q without its marker", from, to)
			return syscall.EIO
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		keepBacking()
		sourcePresence(t, root, releaseDetached, false)
		sourcePresence(t, root, releaseFile, mode == "before-detach/changed-marker")
		if mode == "before-detach/missing-marker-with-alias" {
			sourceUnchangedEntry(t, alias, sourceLstat(t, filepath.Join(root, p.name)))
			sourceMust(t, os.Remove(alias))
		}
		sourceMust(t, os.Rename(saved, marker))
		fresh := sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		sourceReleaseResult(t, fresh, nil, true, nil)
		sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "reopened release retained entries")
	})
	sourceModes(t, []string{"before-detach/mixed-case", "before-detach/scan-limit", "before-detach/held-lowercase", "before-detach/held-mixed-case"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		keepBacking := sourcePreservedEntry(t, filepath.Join(root, p.name))
		names := []string{publicStagePrefix + strings.ToUpper(p.name[:32]) + p.name[32:]}
		var keepHeld func()
		if strings.Contains(mode, "/held-") {
			public, held := publicStagePrefix+p.name, heldStagePrefix+p.name
			sourceMust(t, os.Link(filepath.Join(root, p.name), filepath.Join(root, public)))
			o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
				sourceFailIf(t, from != public || to != held, "unexpected staging transfer %q to %q", from, to)
				sourceMust(t, op(r, from, to))
				return syscall.EIO
			}
			sourcePrepareResult(t, o, m, sourceProducer(m, parts), syscall.EIO)
			keepHeld = sourcePreservedEntry(t, filepath.Join(root, held))
			if strings.HasSuffix(mode, "lowercase") {
				names[0] = public
			}
		}
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			sourceFailIf(t, to == releaseDetached, "release attempted to move the backing")
			return op(r, from, to)
		}
		scanLimit := strings.HasSuffix(mode, "scan-limit")
		want := ErrBusyV1
		if scanLimit {
			want = ErrCapacityV1
		}
		var keepMarker func()
		o.ops.dirSync = func(pin *os.File) error {
			sourceMust(t, pin.Sync())
			o.ops.dirSync = (*os.File).Sync
			keepMarker = sourcePreservedEntry(t, filepath.Join(root, releaseFile))
			if scanLimit {
				names = make([]string, int(o.limits.Scans)-len(sourceEntries(t, dir)))
				for i := range names {
					names[i] = fmt.Sprintf("%064x", i)
				}
			}
			for _, leaf := range names {
				sourceMust(t, os.WriteFile(filepath.Join(root, leaf), []byte{42}, 0o600))
			}
			return nil
		}
		sourceReleaseResult(t, o, p, true, want)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		keepBacking()
		keepMarker()
		if keepHeld != nil {
			keepHeld()
		}
		sourcePresence(t, root, releaseDetached, false)
		for _, leaf := range names {
			path := filepath.Join(root, leaf)
			sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), []byte{42}), "release changed %q", leaf)
			sourceMust(t, os.Remove(path))
		}
		size, err := m.SizeV1()
		sourceMust(t, err)
		assertSourceReleaseCharge(t, o, m, 1, size)
		o.ops = realSourceFS
		sourceReleaseResult(t, o, p, true, nil)
	})
	sourceModes(t, []string{"observed-alias-changed-case", "observed-alias-changed-key"}, func(t *testing.T, mode string) {
		_, o, dir, m, _, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		backing := filepath.Join(root, p.name)
		lower := filepath.Join(root, publicStagePrefix+p.name)
		key := strings.ToUpper(p.name[:32]) + p.name[32:]
		if mode == "observed-alias-changed-key" {
			key = sourceForeign(m).name(o.id)
		}
		renamed := filepath.Join(root, publicStagePrefix+key)
		sourceMust(t, os.Link(backing, lower))
		sourceReadRefusal(t, o, m, ErrBusyV1, "observed stage")
		aside := filepath.Join(dir, "alias")
		sourceMust(t, os.Rename(lower, aside))
		sourceMust(t, os.Rename(aside, renamed))
		if mode == "observed-alias-changed-key" {
			sourceReleaseResult(t, o, p, true, nil)
			sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "release retained renamed alias or backing")
			assertSourceReleaseCharge(t, o, m, 0, 0)
			return
		}
		keepBacking, keepStage := sourcePreservedEntry(t, backing), sourcePreservedEntry(t, renamed)
		sourceReleaseResult(t, o, p, true, ErrIdentityV1)
		keepBacking()
		keepStage()
		sourcePresence(t, root, releaseFile, false)
		sourcePresence(t, root, releaseScratch, false)
		assertSourceReleaseCharge(t, o, m, 1, uint64(sourceLstat(t, backing).Size()))
	})
	for _, phase := range []string{"before-clear", "before-return"} {
		t.Run(phase, func(t *testing.T) {
			sourceModes(t, []string{"mixed-case", "scan-limit", "canonical", "detached"}, func(t *testing.T, mode string) {
				_, o, dir, m, parts, p := sourcePreparedBundle(t)
				root := filepath.Join(dir, sourceDirectory)
				beforeClear := phase == "before-clear"
				key := strings.ToUpper(p.name[:32]) + p.name[32:]
				sourceFailIf(t, key == p.name, "fixture needs an alternate stage spelling")
				names := []string{publicStagePrefix + key}
				want := ErrBusyV1
				switch mode {
				case "canonical":
					names, want = []string{p.name}, ErrIdentityV1
				case "detached":
					names, want = []string{releaseDetached}, ErrIdentityV1
				case "scan-limit":
					want = ErrCapacityV1
					count := int(o.limits.Scans)
					if beforeClear {
						count--
					}
					names = make([]string, count)
					for i := range names {
						names[i] = fmt.Sprintf("%064x", i)
					}
				}
				var marker []byte
				o.ops.dirSync = func(pin *os.File) error {
					sourceMust(t, pin.Sync())
					_, err := os.Lstat(filepath.Join(root, releaseFile))
					if err == nil {
						marker = sourceReadFile(t, filepath.Join(root, releaseFile))
					}
					_, backing := os.Lstat(filepath.Join(root, p.name))
					if !errors.Is(backing, os.ErrNotExist) || beforeClear != (err == nil) {
						return nil
					}
					o.ops.dirSync = (*os.File).Sync
					for _, name := range names {
						sourceMust(t, os.WriteFile(filepath.Join(root, name), []byte{42}, 0o600))
					}
					return nil
				}
				sourceReleaseResult(t, o, p, true, want)
				sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
				sourcePresence(t, root, releaseFile, beforeClear)
				if beforeClear {
					sourceFailIf(t, !bytes.Equal(marker, sourceReadFile(t, filepath.Join(root, releaseFile))), "release marker changed")
				}
				for _, name := range names {
					path := filepath.Join(root, name)
					sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), []byte{42}), "release changed entry %q", name)
					sourceMust(t, os.Remove(path))
				}
				size, err := m.SizeV1()
				sourceMust(t, err)
				assertSourceReleaseCharge(t, o, m, 1, size)
				sourceReleaseResult(t, o, p, true, nil)
				sourcePrepareAndRead(t, o, sourceForeign(m), parts)
			})
		})
	}
}

func testSourceReleaseSpelling(t *testing.T) {
	t.Run("withdrawn-alias-with-independent-stage", testSourceWithdrawnReleaseAlias)
	sourceModes(t, []string{"same-key-replaced-alias", "pending-same-key-replaced-alias"}, testSourceReplacedSameKeyAlias)
	sourceModes(t, []string{"unqualified-cross-key", "unqualified-lowercase-cross-key"}, func(t *testing.T, mode string) {
		_, o, dir, m, _, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		backing := filepath.Join(root, p.name)
		key := sourceForeign(m).name(o.id)
		if mode == "unqualified-cross-key" {
			key = strings.ToUpper(key)
		}
		stage := filepath.Join(root, publicStagePrefix+key)
		sourceReleaseWithFault(t, o, p, "intent-sync", syscall.EIO)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourceMust(t, os.Link(backing, stage))
		assertSourceReleaseCharge(t, o, m, 1, sourceSize(t, m))
		unchanged := sourcePreservedEntry(t, backing)
		o.ops.dirSync = func(pin *os.File) error {
			o.ops.dirSync = (*os.File).Sync
			sourceMust(t, pin.Sync())
			sourceMust(t, os.Remove(stage))
			return os.Symlink(p.name, stage)
		}
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			sourceFailIf(t, to == releaseDetached, "unqualified stage allowed backing detachment")
			return op(r, from, to)
		}
		sourceReleaseResult(t, o, p, true, ErrIdentityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		unchanged()
		sourcePresence(t, root, releaseFile, true)
		sourcePresence(t, root, releaseDetached, false)
		target, err := os.Readlink(stage)
		sourceMust(t, err)
		sourceFailIf(t, target != p.name, "stage link target changed to %q", target)
	})
	sourceModes(t, []string{"mixed-alias", "mixed-alias-another-name", "same-key-file", "same-key-before-content", "pending-absent-file", "pending-cross-key", "pending-cross-key-live", "pending-cross-key-paired", "late-alias", "late-alias-live", "unrelated-file", "fresh-mixed-file"}, func(t *testing.T, mode string) {
		s, o, dir, m, parts, p := sourcePreparedBundle(t)
		lateAlias := strings.HasPrefix(mode, "late-alias")
		crossKey := strings.HasPrefix(mode, "pending-cross-key")
		root := filepath.Join(dir, sourceDirectory)
		key := sourceForeign(m).name(o.id)
		if strings.HasPrefix(mode, "same-key-") || mode == "pending-absent-file" {
			key = p.name
		}
		key = strings.ToUpper(key[:32]) + key[32:]
		sourceFailIf(t, key == strings.ToLower(key) || key == strings.ToUpper(key), "fixture needs both cases of hex letters")
		if lateAlias {
			key = p.name
		}
		stage := filepath.Join(root, publicStagePrefix+key)
		size, err := m.SizeV1()
		sourceMust(t, err)
		if crossKey || lateAlias {
			fault := "intent-sync"
			if mode == "pending-cross-key-paired" {
				fault = "rename-visible"
			}
			sourceReleaseWithFault(t, o, p, fault, syscall.EIO)
			o.ops = realSourceFS
		}
		if mode == "pending-absent-file" {
			sourceReleaseWithFault(t, o, p, "pending-absent", syscall.EIO)
			sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
			o.ops = realSourceFS
			sourcePresence(t, root, releaseScratch, true)
			sourcePresence(t, root, releaseFile, false)
		}
		files, used, want := uint64(1), size, ErrIdentityV1
		switch mode {
		case "same-key-file", "same-key-before-content", "pending-absent-file", "unrelated-file", "fresh-mixed-file":
			sourceMust(t, os.WriteFile(stage, []byte{17}, 0o600))
			files, used, want = 2, size+1, ErrBusyV1
			if mode == "same-key-before-content" {
				path := filepath.Join(root, p.name)
				data := sourceReadFile(t, path)
				data[len(data)-1] ^= 1
				sourceMust(t, os.WriteFile(path, data, 0o600))
			}
		case "late-alias", "late-alias-live":
			o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
				sourceFailIf(t, from != p.name || to != releaseDetached, "unexpected namespace operation on a late stage")
				sourceMust(t, op(r, from, to))
				return r.Link(to, publicStagePrefix+key)
			}
		default:
			sourceMust(t, os.Link(filepath.Join(root, p.name), stage))
		}
		if mode == "mixed-alias-another-name" {
			sourceMust(t, os.Link(stage, filepath.Join(root, key)))
			files, used = 2, 2*size
		}
		if mode == "same-key-file" {
			sourceReadRefusal(t, o, m, ErrBusyV1, "stage with alternate key spelling")
		}
		if mode == "unrelated-file" || mode == "fresh-mixed-file" {
			preserved := sourcePreservedEntry(t, stage)
			if mode == "fresh-mixed-file" {
				o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
				assertSourceReleaseCharge(t, o, m, 2, size+1)
			} else {
				sourceReleaseResult(t, o, p, true, nil)
				assertSourceReleaseCharge(t, o, m, 1, 1)
			}
			checkSourceIndependentSpelling(t, o, m, parts, stage, preserved)
			if mode == "fresh-mixed-file" {
				sourceRead(t, o, m, parts)
			}
			return
		}
		if !lateAlias {
			var unchanged func(string)
			if crossKey || mode == "same-key-before-content" {
				alias := sourcePreservedEntry(t, stage)
				backing := sourcePreservedEntry(t, filepath.Join(root, p.name))
				var marker func()
				var scratch func()
				if crossKey {
					marker = sourcePreservedEntry(t, filepath.Join(root, releaseFile))
					assertSourceReleaseCharge(t, o, m, files, used)
					if mode == "pending-cross-key-paired" {
						scratch = sourcePreservedEntry(t, filepath.Join(root, releaseScratch))
					}
				}
				unchanged = func(string) {
					if marker != nil {
						marker()
					}
					if scratch != nil {
						scratch()
					}
					alias()
					backing()
				}
			} else {
				assertSourceReleaseCharge(t, o, m, files, used)
				unchanged = sourceHeld(t, o)
			}
			o.ops.namespace = func(sourceNamespace, *sourceRoot, string, string) error {
				t.Fatal("refused release changed a name")
				return nil
			}
			o.ops.remove = func(*os.Root, string) error {
				t.Fatal("refused release removed a name")
				return nil
			}
			o.ops.write = func(*os.File, []byte) (int, error) {
				t.Fatal("refused release wrote a marker")
				return 0, nil
			}
			sourceReleaseResult(t, o, p, true, want)
			if crossKey || mode == "pending-absent-file" {
				sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
			}
			unchanged("refused release")
			assertSourceReleaseCharge(t, o, m, files, used)
		} else {
			preserved := sourcePreservedEntry(t, filepath.Join(root, releaseFile))
			before := sourceLstat(t, filepath.Join(root, p.name))
			sourceReleaseResult(t, o, p, true, want)
			sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
			sourceUnchangedEntry(t, filepath.Join(root, releaseDetached), before)
			sourceUnchangedEntry(t, stage, before)
			preserved()
		}
		o.ops = realSourceFS
		if mode == "pending-absent-file" {
			sourceMust(t, os.Remove(stage))
			sourceReleaseResult(t, o, p, true, nil)
			sourceAbsent(t, root, p.name, releaseFile, releaseDetached, releaseScratch)
			sourcePrepareAndRead(t, o, sourceForeign(m), parts)
		}
		if crossKey || lateAlias {
			original := sourceLstat(t, stage)
			if mode == "pending-cross-key-paired" {
				marker := sourcePreservedEntry(t, filepath.Join(root, releaseFile))
				scratch := sourcePreservedEntry(t, filepath.Join(root, releaseScratch))
				s = sourceReopenStore(t, s, dir)
				sourceOpen(t, s, sourceID(), sourceLimits(), ErrIdentityV1)
				marker()
				scratch()
				sourceUnchangedEntry(t, stage, original)
			}
			sourceMust(t, os.Remove(stage))
			if !strings.HasSuffix(mode, "-live") {
				if mode != "pending-cross-key-paired" {
					s = sourceReopenStore(t, s, dir)
				}
				o = sourceOpen(t, s, sourceID(), sourceLimits(), nil)
				p = nil
			}
			sourceReleaseResult(t, o, p, true, nil)
			sourceFailIf(t, sourceReleaseHasOpenFile(t, original), "completed release kept the backing descriptor")
			sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "resumed release retained an entry")
			sourcePrepareAndRead(t, o, sourceForeign(m), parts)
		}
	})
}

func testSourceReplacedSameKeyAlias(t *testing.T, mode string) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(o.dir, sourceDirectory)
	backing := filepath.Join(root, p.name)
	stage := filepath.Join(root, publicStagePrefix+p.name)
	saved := filepath.Join(dir, "original-stage")
	original, data := sourceLstat(t, backing), sourceReadFile(t, backing)
	sourceMust(t, os.Link(backing, stage))
	sourceReadRefusal(t, o, m, ErrBusyV1, "readback with shared stage")
	pending := mode == "pending-same-key-replaced-alias"
	replacement := []byte("independent stage")
	var independent os.FileInfo
	replaceStage := func() {
		sourceMust(t, os.Rename(stage, saved))
		independent = writeSourceEntry(t, stage, replacement)
		sourceFailIf(t, os.SameFile(original, independent), "replacement stage shares the backing inode")
	}
	var keepMarker func()
	if pending {
		o.ops.dirSync = func(pin *os.File) error {
			o.ops.dirSync = (*os.File).Sync
			sourceMust(t, pin.Sync())
			keepMarker = sourcePreservedEntry(t, filepath.Join(root, releaseFile))
			replaceStage()
			return nil
		}
	} else {
		replaceStage()
		o.ops.write = func(*os.File, []byte) (int, error) {
			t.Fatal("release attempted a marker write with an independent stage")
			return 0, syscall.EIO
		}
	}
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
		if pending && independent == nil && from == releaseScratch && to == releaseFile {
			return op(r, from, to)
		}
		t.Fatal("release attempted a namespace transfer with an independent stage")
		return syscall.EIO
	}
	o.ops.remove = func(r *os.Root, leaf string) error {
		if pending && independent == nil && leaf == releaseScratch {
			return r.Remove(leaf)
		}
		t.Fatal("release attempted removal with an independent stage")
		return syscall.EIO
	}
	sourceReleaseResult(t, o, p, true, ErrBusyV1)
	if pending {
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourceFailIf(t, keepMarker == nil, "release did not reach marker directory sync")
		keepMarker()
	} else {
		sourceReadRefusal(t, o, m, ErrIdentityV1, "readback with replaced stage")
		sourcePresence(t, root, releaseFile, false)
	}
	sourceUnchangedEntry(t, backing, original, data)
	sourceUnchangedEntry(t, saved, original, data)
	sourceUnchangedEntry(t, stage, independent, replacement)
	sourceAbsent(t, root, releaseDetached, releaseScratch)
	sourceMust(t, os.Remove(stage))
	sourceMust(t, os.Rename(saved, stage))
	sourceUnchangedEntry(t, stage, original, data)
	if pending {
		assertSourceReleaseCharge(t, o, m, 1, sourceSize(t, m))
	}
	o.ops = realSourceFS
	sourceReleaseResult(t, o, p, true, nil)
	sourceAbsent(t, root, p.name, filepath.Base(stage), releaseFile, releaseDetached, releaseScratch)
	sourcePrepareAndRead(t, o, sourceForeign(m), parts)
}

func checkSourceIndependentSpelling(t *testing.T, o *SourceOwnerV1, wrong SourceManifestV1, parts [][]byte, stage string, preserved func()) {
	t.Helper()
	leaf := filepath.Base(stage)
	found := slices.ContainsFunc(sourceEntries(t, o.dir), func(e os.DirEntry) bool { return e.Name() == leaf })
	sourceFailIf(t, !found, "legacy stage spelling changed")
	preserved()
	o.ops.namespace = func(sourceNamespace, *sourceRoot, string, string) error {
		t.Fatal("wrong capture key changed a stage name")
		return nil
	}
	var result error
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		_, result = o.PrepareSourceV1(a, wrong, refusedSourceProducer(t))
	})
	preserved()
	o.ops = realSourceFS
	sourcePrepareAndRead(t, o, sourceForeign(wrong), parts)
	sourceWantError(t, result, ErrBusyV1, "wrong capture key")
	sourcePresence(t, filepath.Dir(stage), leaf, false)
}

func testSourceWithdrawnReleaseAlias(t *testing.T) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	backing := filepath.Join(root, p.name)
	other := sourceForeign(m)
	stage := filepath.Join(root, publicStagePrefix+other.name(o.id))
	sourceMust(t, os.Link(backing, stage))
	sourceRead(t, o, m, parts)
	keepBacking := sourcePreservedEntry(t, backing)
	o.ops.dirSync = func(pin *os.File) error {
		o.ops.dirSync = (*os.File).Sync
		sourceMust(t, pin.Sync())
		return os.Remove(stage)
	}
	detaches := 0
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
		if to == releaseDetached {
			detaches++
			return syscall.EIO
		}
		return op(r, from, to)
	}
	sourceReleaseResult(t, o, p, true, syscall.EIO)
	sourcePrepareResult(t, o, other, refusedSourceProducer(t), ErrBusyV1)
	sourceFailIf(t, detaches != 1, "detach attempts=%d, want 1", detaches)
	keepBacking()
	sourceAbsent(t, root, filepath.Base(stage), releaseDetached)
	sourcePresence(t, root, releaseFile, true)

	independent := []byte("independent staging")
	staged := writeSourceEntry(t, stage, independent)
	o.ops = realSourceFS
	sourceReleaseResult(t, o, p, true, nil)
	sourceUnchangedEntry(t, stage, staged, independent)
	sourceAbsent(t, root, p.name, releaseFile, releaseDetached, releaseScratch)
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(independent)))
	sourcePrepareResult(t, o, m, refusedSourceProducer(t), ErrBusyV1)
	sourceUnchangedEntry(t, stage, staged, independent)
	sourcePrepareAndRead(t, o, other, parts)
}

func testSourceRefilledCanonical(t *testing.T) {
	t.Run("qualified-canonical", func(t *testing.T) {
		_, o, dir, m, _, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		path := filepath.Join(root, p.name)
		original := sourcePreservedEntry(t, path)
		held := filepath.Join(t.TempDir(), "original")
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			if to != releaseDetached {
				return op(r, from, to)
			}
			sourceMust(t, os.Rename(path, held))
			sourceMust(t, os.Mkdir(path, 0o700))
			sourceMust(t, op(r, from, to))
			return os.Rename(held, path)
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		original()
		sourceFailIf(t, !sourceLstat(t, filepath.Join(root, releaseDetached)).IsDir(), "release changed the detached directory")
		sourcePresence(t, root, releaseFile, true)
	})
	sourceModes(t, []string{"detach", "stage-claim", "stage-unlink"}, func(t *testing.T, phase string) {
		s, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		canonical := filepath.Join(root, p.name)
		original := sourceLstat(t, canonical)
		contents := sourceReadFile(t, canonical)
		sourceMust(t, os.Link(canonical, filepath.Join(root, publicStagePrefix+p.name)))
		var keepMarker func()
		refill := func() {
			sourceMust(t, syscall.Mkfifo(canonical, 0o600))
			keepMarker = sourcePreservedEntry(t, filepath.Join(root, releaseFile))
		}
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			err := op(r, from, to)
			if err == nil && (phase == "detach" && to == releaseDetached || phase == "stage-claim" && to == heldStagePrefix+p.name) {
				refill()
			}
			return err
		}
		o.ops.remove = func(r *os.Root, name string) error {
			err := r.Remove(name)
			if err == nil && phase == "stage-unlink" && name == heldStagePrefix+p.name {
				refill()
			}
			return err
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		foreign := sourceForeign(m)
		sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
		sourceFailIf(t, keepMarker == nil, "release did not reach the selected namespace operation")
		keepMarker()
		backing := filepath.Join(root, releaseDetached)
		sourceUnchangedEntry(t, backing, original)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, backing), contents), "release changed detached bytes")
		sourceFailIf(t, sourceLstat(t, canonical).Mode()&os.ModeNamedPipe == 0, "release changed the refilled name")
		sourcePresence(t, root, publicStagePrefix+p.name, phase == "detach")
		sourcePresence(t, root, heldStagePrefix+p.name, phase == "stage-claim")
		sourceMust(t, os.Remove(canonical))
		fresh := sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		sourcePrepareResult(t, fresh, foreign, refusedSourceProducer(t), ErrBusyV1)
		size, err := m.SizeV1()
		sourceMust(t, err)
		assertSourceReleaseCharge(t, fresh, m, 1, size)
		sourceReleaseResult(t, fresh, nil, true, nil)
		sourcePrepareAndRead(t, fresh, foreign, parts)
	})
}

func testSourceRestoreWithoutReplacement(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		t.Run(fmt.Sprint(occupied), func(t *testing.T) {
			_, o, dir, m, _, p := sourcePreparedBundle(t)
			root := filepath.Join(dir, sourceDirectory)
			path := filepath.Join(root, p.name)
			held := filepath.Join(t.TempDir(), "qualified")
			data := sourceReadFile(t, path)
			var moved os.FileInfo
			var restorePin *os.File
			var keepState func(string)
			var restored bool
			restoreCalls, restoreSyncs := 0, 0
			o.ops.dirSync = func(pin *os.File) error {
				if restorePin != nil {
					sourceFailIf(t, pin != restorePin, "restoration synced a different directory descriptor")
					sourceMust(t, pin.Sync())
					restoreSyncs++
					return nil
				}
				return pin.Sync()
			}
			o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
				switch {
				case to == releaseDetached:
					sourceMust(t, os.Rename(path, held))
					sourceMust(t, os.WriteFile(path, data, 0o600))
					moved = sourceLstat(t, path)
				case from == releaseDetached:
					sourceFailIf(t, to != p.name, "restoration attempted destination %q", to)
					restoreCalls++
					restorePin = r.pin
					if occupied {
						sourceMust(t, os.WriteFile(path, []byte("occupied"), 0o600))
					}
					err := op(r, from, to)
					restored = err == nil
					keepState = sourceHeld(t, o)
					return err
				}
				return op(r, from, to)
			}
			sourceReleaseResult(t, o, p, true, ErrIdentityV1)
			sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
			sourceFailIf(t, restoreCalls != 1 || restored == occupied, "restoration calls=%d, restored=%t, occupied=%t", restoreCalls, restored, occupied)
			wantSyncs := map[bool]int{false: 1}[occupied]
			sourceFailIf(t, restoreSyncs != wantSyncs, "restoration directory syncs=%d, want %d", restoreSyncs, wantSyncs)
			keepState("refused release and preparation")
			where := path
			if occupied {
				where = filepath.Join(root, releaseDetached)
				sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), []byte("occupied")), "restore replaced occupied name")
			}
			sourceFailIf(t, !os.SameFile(moved, sourceLstat(t, where)) || !bytes.Equal(sourceReadFile(t, where), data), "qualified refusal changed moved file")
			sourcePresence(t, root, releaseDetached, occupied)
			sourcePresence(t, root, releaseFile, true)
		})
	}
}

func testSourcePrivateNames(t *testing.T) {
	for _, mode := range []string{"standalone-private", "standalone-private-with-scratch", "different-marker-scratch"} {
		t.Run(mode, func(t *testing.T) {
			s, o, dir, _, _, p := sourcePreparedBundle(t)
			root := filepath.Join(dir, sourceDirectory)
			name := releaseDetached
			if mode == "standalone-private-with-scratch" {
				scratch := filepath.Join(root, releaseScratch)
				sourceMust(t, os.WriteFile(scratch, []byte("unpublished"), 0o600))
				defer sourcePreservedEntry(t, scratch)()
			}
			if mode == "different-marker-scratch" {
				sourceReleaseWithFault(t, o, p, "intent-sync", errors.New("deferred"))
				name = releaseScratch
			}
			path := filepath.Join(root, name)
			sourceMust(t, os.WriteFile(path, []byte("preserve"), 0o600))
			info := sourceLstat(t, path)
			s = sourceReopenStore(t, s, dir)
			if mode == "different-marker-scratch" {
				bounded := sourceLimits()
				bounded.Files, bounded.Scans = 1, 3
				sourceOpen(t, s, sourceID(), bounded, ErrCapacityV1)
				sourceUnchangedEntry(t, path, info)
			}
			sourceOpen(t, s, sourceID(), sourceLimits(), ErrIntegrityV1)
			sourceFailIf(t, !os.SameFile(info, sourceLstat(t, path)) || !bytes.Equal(sourceReadFile(t, path), []byte("preserve")), "private name changed on refusal")
			sourcePresence(t, root, p.name, true)
		})
	}
}

func testSourceRestoreAcknowledgement(t *testing.T) {
	sourceModes(t, []string{"before-restore", "after-restore"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		canonical, private := filepath.Join(root, p.name), filepath.Join(root, releaseDetached)
		backing, record := sourceLstat(t, canonical), sourceReadFile(t, canonical)
		extra := filepath.Join(dir, "extra-backing-link")
		sourceMust(t, os.Link(canonical, extra))
		other := sourceForeign(m)
		otherPath := filepath.Join(root, publicStagePrefix+other.name(o.id))
		stage := writeSourceEntry(t, otherPath, []byte("independent"))
		calls := 0
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			if from != releaseDetached {
				return op(r, from, to)
			}
			calls++
			if mode == "after-restore" {
				sourceMust(t, op(r, from, to))
			}
			return syscall.EIO
		}
		sourceReleaseResult(t, o, p, true, ErrIdentityV1)
		sourcePrepareResult(t, o, other, refusedSourceProducer(t), ErrBusyV1)
		restored := mode == "after-restore"
		sourcePresence(t, root, releaseDetached, !restored)
		sourcePresence(t, root, p.name, restored)
		if restored {
			sourceUnchangedEntry(t, canonical, backing, record)
		} else {
			sourceUnchangedEntry(t, private, backing, record)
		}
		sourceFailIf(t, calls != 1, "restore attempts=%d, want 1", calls)
		sourcePresence(t, root, releaseFile, true)
		sourceUnchangedEntry(t, otherPath, stage, []byte("independent"))
		assertSourceReleaseCharge(t, o, m, 2, sourceSize(t, m)+uint64(len("independent")))
		sourceMust(t, os.Remove(extra))
		o.ops = realSourceFS
		sourceReleaseResult(t, o, p, true, nil)
		sourceUnchangedEntry(t, otherPath, stage, []byte("independent"))
		sourcePrepareAndRead(t, o, other, parts)
	})
}

func testSourceDetachedRelease(t *testing.T) {
	sourceModes(t, []string{"marker-missing", "marker-different", "marker-missing-with-alias", "marker-missing-after-claim"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		marker, saved := filepath.Join(root, releaseFile), filepath.Join(dir, "saved-marker")
		backing := sourceLstat(t, filepath.Join(root, p.name))
		data := sourceReadFile(t, filepath.Join(root, p.name))
		alias := publicStagePrefix + p.name
		boundary := releaseDetached
		if mode == "marker-missing-after-claim" {
			boundary = heldStagePrefix + p.name
		}
		hasAlias := mode == "marker-missing-with-alias" || mode == "marker-missing-after-claim"
		if hasAlias {
			sourceMust(t, os.Link(filepath.Join(root, p.name), filepath.Join(root, alias)))
		}
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			if err := op(r, from, to); err != nil {
				return err
			}
			if to == boundary {
				sourceMust(t, os.Rename(marker, saved))
				if mode == "marker-different" {
					sourceMust(t, os.WriteFile(marker, sourceReadFile(t, saved), 0o600))
				}
			}
			return nil
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		detached := filepath.Join(root, releaseDetached)
		sourceUnchangedEntry(t, detached, backing)
		sourceFailIf(t, !bytes.Equal(data, sourceReadFile(t, detached)), "release changed detached contents")
		if hasAlias {
			if mode == "marker-missing-after-claim" {
				sourcePresence(t, root, alias, false)
				alias = boundary
			}
			sourceUnchangedEntry(t, filepath.Join(root, alias), backing)
		}
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
		sourcePresence(t, root, releaseFile, mode == "marker-different")
		sourceMust(t, os.Rename(saved, marker))
		o.ops = realSourceFS
		sourceReleaseResult(t, o, p, true, nil)
		sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "retry left pending entries")
		sourcePrepareAndRead(t, o, sourceForeign(m), parts)
	})
	for _, stage := range []string{"before-detach", "after-detach", "before-unlink", "after-unlink"} {
		for _, reopen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reopen=%t", stage, reopen), func(t *testing.T) {
				s, o, dir, m, parts, p := sourcePreparedBundle(t)
				root := filepath.Join(dir, sourceDirectory)
				size, err := m.SizeV1()
				sourceMust(t, err)
				cause := syscall.EIO
				o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
					if to == releaseDetached {
						switch stage {
						case "before-detach":
							return cause
						case "after-detach":
							sourceMust(t, op(r, from, to))
							return cause
						}
					}
					return op(r, from, to)
				}
				o.ops.remove = func(r *os.Root, name string) error {
					if name == releaseDetached {
						switch stage {
						case "before-unlink":
							return cause
						case "after-unlink":
							sourceMust(t, r.Remove(name))
							return cause
						}
					}
					return r.Remove(name)
				}
				sourceReleaseResult(t, o, p, true, cause)
				sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
				sourcePresence(t, root, p.name, stage == "before-detach")
				sourcePresence(t, root, releaseDetached, stage == "after-detach" || stage == "before-unlink")
				sourcePresence(t, root, releaseFile, true)
				marker := filepath.Join(root, releaseFile)
				markerInfo := sourceLstat(t, marker)
				record := slices.Clone(o.release.record)
				sourceFailIf(t, !bytes.Equal(sourceReadFile(t, marker), record), "unlink fault altered its intent")
				assertSourceReleaseCharge(t, o, m, 1, size)
				o.ops = realSourceFS
				if stage == "after-unlink" && !reopen {
					o.ops.remove = func(r *os.Root, name string) error {
						if name == releaseDetached {
							t.Fatal("retry repeated a proved backing unlink")
						}
						return r.Remove(name)
					}
				}
				if reopen {
					o, p = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil), nil
					sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
					sourceUnchangedEntry(t, marker, markerInfo)
					sourceFailIf(t, !bytes.Equal(sourceReadFile(t, marker), record), "reopen altered pending intent")
				}
				assertSourceReleaseCharge(t, o, m, 1, size)
				sourceReleaseResult(t, o, p, true, nil)
				sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "release retry left source entries")
				sourcePrepareAndRead(t, o, sourceForeign(m), parts)
			})
		}
	}
}

func testSourcePendingCensus(t *testing.T) {
	for _, mode := range []string{"short", "foreign", "foreign-short", "foreign-with-scratch", "fifo", "private-short", "private-foreign", "private-foreign-short", "private-fifo", "private-with-fifo", "private-with-foreign", "private-first-qualified-pair", "canonical-first-qualified-pair", "mixed-canonical-fifo", "mixed-private-fifo"} {
		t.Run(mode, func(t *testing.T) {
			s, o, dir, m, _, p := sourcePreparedBundle(t)
			root := filepath.Join(dir, sourceDirectory)
			path := filepath.Join(root, p.name)
			marker := filepath.Join(root, releaseFile)
			where := "intent-sync"
			mixed := strings.HasPrefix(mode, "mixed-")
			if strings.HasPrefix(mode, "private-") || mixed {
				where = "unlink"
			}
			original := sourceReadFile(t, path)
			sourceReleaseWithFault(t, o, p, where, errors.New("pending"))
			checkMarker := sourcePreservedEntry(t, marker)
			if mode == "private-short" || mode == "private-foreign" || mode == "private-foreign-short" || mode == "private-fifo" {
				path = filepath.Join(root, releaseDetached)
			}
			want := ErrIntegrityV1
			switch mode {
			case "short", "private-short":
				sourceMust(t, os.Truncate(path, 1))
			case "foreign", "foreign-short", "foreign-with-scratch", "private-foreign", "private-foreign-short":
				if mode == "foreign-with-scratch" {
					path := filepath.Join(root, releaseScratch)
					sourceMust(t, os.WriteFile(path, []byte("independent"), 0o600))
					defer sourcePreservedEntry(t, path)()
				}
				sourceMust(t, os.Rename(path, filepath.Join(t.TempDir(), "prior")))
				if strings.HasSuffix(mode, "foreign-short") {
					original = original[:1]
				}
				sourceMust(t, os.WriteFile(path, original, 0o600))
				want = ErrIdentityV1
			case "fifo", "private-fifo", "private-with-fifo":
				if mode != "private-with-fifo" {
					sourceMust(t, os.Remove(path))
				}
				sourceMust(t, syscall.Mkfifo(path, 0o600))
			case "private-with-foreign":
				sourceMust(t, os.WriteFile(path, original, 0o600))
				want = ErrIdentityV1
			case "private-first-qualified-pair":
				sourceMust(t, os.Link(filepath.Join(root, releaseDetached), path))
				want = ErrIdentityV1
			case "canonical-first-qualified-pair":
				sourceMust(t, os.Link(path, filepath.Join(root, releaseDetached)))
				want = ErrIdentityV1
			case "mixed-canonical-fifo", "mixed-private-fifo":
				want = sourceMixedPendingBacking(t, o, path, original, mode)
			}
			checkBacking := sourcePreservedEntry(t, path)
			detached := filepath.Join(root, releaseDetached)
			privatePresent := where == "unlink" || mode == "canonical-first-qualified-pair"
			if privatePresent {
				defer sourcePreservedEntry(t, detached)()
			}
			sourceWantError(t, o.ReleaseUnpublishedSourceV1(nil, p, true), ErrCapacityV1, "unfunded release")
			sourceReleaseResult(t, o, p, true, want)
			sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
			size, err := m.SizeV1()
			sourceMust(t, err)
			withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
				for range 2 {
					_, err := o.censusFiles(r, entries, false)
					sourceWantError(t, err, want, "pending locations in listing order")
					slices.Reverse(entries)
				}
			})
			sourceReadRefusal(t, o, m, want, "pending census")
			sourceFailIf(t, o.release == nil || o.release.size != size || o.live[p.name] != p.incarnation, "invalid backing consumed charge")
			sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), want)
			checkBacking()
			checkMarker()
			sourcePresence(t, root, releaseDetached, privatePresent)
		})
	}
}

func sourceMixedPendingBacking(t *testing.T, o *SourceOwnerV1, canonical string, original []byte, mode string) error {
	t.Helper()
	private := filepath.Join(filepath.Dir(canonical), releaseDetached)
	sourceMust(t, os.Rename(private, filepath.Join(t.TempDir(), "original-backing")))
	o.ops.namespace = func(sourceNamespace, *sourceRoot, string, string) error {
		t.Fatal("invalid backing pair reached a namespace operation")
		return nil
	}
	o.ops.remove = func(*os.Root, string) error {
		t.Fatal("invalid backing pair reached removal")
		return nil
	}
	if mode == "mixed-canonical-fifo" {
		sourceMust(t, syscall.Mkfifo(canonical, 0o600))
		sourceMust(t, os.WriteFile(private, original, 0o600))
		return ErrIntegrityV1
	}
	sourceMust(t, os.WriteFile(canonical, original, 0o600))
	sourceMust(t, syscall.Mkfifo(private, 0o600))
	return ErrIdentityV1
}

func testSourceBackingLinks(t *testing.T) {
	sourceModes(t, []string{"third-link-before-claim", "third-link-after-claim"}, testSourceThirdStageLink)
	sourceModes(t, []string{"alias-remove-before", "alias-remove-after"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root, key := filepath.Join(dir, sourceDirectory), sourceForeign(m).name(o.id)
		held := heldStagePrefix + key
		sourceMust(t, os.Link(filepath.Join(root, p.name), filepath.Join(root, publicStagePrefix+key)))
		o.ops.remove = func(r *os.Root, name string) error {
			if name != held {
				return r.Remove(name)
			}
			if mode == "alias-remove-after" {
				sourceMust(t, r.Remove(name))
			}
			return syscall.EIO
		}
		sourceReleaseResult(t, o, p, true, syscall.EIO)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePresence(t, root, held, mode == "alias-remove-before")
		sourcePresence(t, root, releaseDetached, true)
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
		size, err := m.SizeV1()
		sourceMust(t, err)
		assertSourceReleaseCharge(t, o, m, 1, size)
		o.ops = realSourceFS
		sourceReleaseResult(t, o, p, true, nil)
		assertSourceReleaseCharge(t, o, m, 0, 0)
	})
	sourceModes(t, []string{"extra", "after-unlink", "late-unlink-error", "stage-alias", "other-key-alias", "stage-distinct"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		original := filepath.Join(root, p.name)
		stage := filepath.Join(root, ".staging-"+p.name)
		unexpected := filepath.Join(t.TempDir(), "extra")
		lost := syscall.EIO
		want := ErrIdentityV1
		switch mode {
		case "extra":
			sourceMust(t, os.Link(original, unexpected))
		case "after-unlink", "late-unlink-error":
			if mode == "late-unlink-error" {
				want = lost
			}
			o.ops.remove = func(r *os.Root, name string) error {
				if name == releaseDetached {
					sourceMust(t, os.Link(filepath.Join(root, name), unexpected))
					if mode == "late-unlink-error" {
						sourceMust(t, r.Remove(name))
						return lost
					}
				}
				return r.Remove(name)
			}
		case "stage-alias", "other-key-alias":
			if mode == "other-key-alias" {
				stage = filepath.Join(root, publicStagePrefix+sourceForeign(m).name(o.id))
			}
			sourceMust(t, os.Link(original, stage))
			f, err := os.Open(original)
			sourceMust(t, err)
			defer f.Close()
			var st syscall.Stat_t
			removed := false
			o.ops.remove = func(r *os.Root, name string) error {
				if name == releaseDetached {
					sourceMust(t, syscall.Fstat(int(f.Fd()), &st))
					sourceFailIf(t, st.Nlink != 1, "backing links before unlink: %d", st.Nlink)
					removed = true
				}
				return r.Remove(name)
			}
			sourceReleaseResult(t, o, p, true, nil)
			sourceMust(t, syscall.Fstat(int(f.Fd()), &st))
			sourceFailIf(t, !removed || st.Nlink != 0, "released backing links: %d", st.Nlink)
			sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "removed capture retained staging alias")
			return
		case "stage-distinct":
			sourceMust(t, os.WriteFile(stage, []byte{1}, 0o600))
			sourceReleaseResult(t, o, p, true, ErrBusyV1)
			sourcePresence(t, root, releaseFile, false)
			sourceFailIf(t, !bytes.Equal(sourceReadFile(t, stage), []byte{1}), "independent stage changed")
			return
		}
		sourceReleaseResult(t, o, p, true, want)
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourcePresence(t, root, p.name, mode == "extra")
		sourcePresence(t, root, releaseDetached, false)
		sourcePresence(t, root, releaseFile, true)
		sourcePresence(t, filepath.Dir(unexpected), filepath.Base(unexpected), true)
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
		size, err := m.SizeV1()
		sourceMust(t, err)
		assertSourceReleaseCharge(t, o, m, 1, size)
		if mode != "extra" {
			sourceReleaseResult(t, o, p, true, ErrIdentityV1)
		}
	})
}

func testSourceThirdStageLink(t *testing.T, mode string) {
	_, o, _, m, parts, p := sourcePreparedBundle(t)
	paths := sourcePaths(o.dir, p.name)
	extra := filepath.Join(paths.dir, "third-link")
	backing, contents := sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
	sourceMust(t, os.Link(paths.capture, paths.stage))
	sourceReadRefusal(t, o, m, ErrBusyV1, "admitted source alias")
	checkSourcePinned(t, o.stage.File, backing)
	afterClaim := mode == "third-link-after-claim"
	if !afterClaim {
		sourceMust(t, os.Link(paths.capture, extra))
	}
	keepMarker := watchSourceThirdStageLink(t, o, paths, extra, afterClaim)
	sourceReleaseResult(t, o, p, true, ErrIdentityV1)
	sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
	keepMarker()
	sourceUnchangedEntry(t, paths.capture, backing, contents)
	sourceUnchangedEntry(t, extra, backing, contents)
	sourcePresence(t, paths.root, releaseDetached, false)
	sourcePresence(t, paths.root, filepath.Base(paths.stage), !afterClaim)
	sourcePresence(t, paths.root, filepath.Base(paths.held), afterClaim)
	stage := paths.stage
	if afterClaim {
		stage = paths.held
	}
	sourceUnchangedEntry(t, stage, backing, contents)
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(contents)))
	sourceMust(t, os.Remove(extra))
	o.ops = realSourceFS
	sourceReleaseResult(t, o, p, true, nil)
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	sourceFailIf(t, len(sourceEntries(t, paths.dir)) != 0, "release retry retained a backing or stage")
	sourcePrepareAndRead(t, o, sourceForeign(m), parts)
}

func watchSourceThirdStageLink(t *testing.T, o *SourceOwnerV1, paths sourceTestPaths, extra string, afterClaim bool) func() {
	t.Helper()
	var keepMarker func()
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
		if to == releaseDetached {
			keepMarker = sourcePreservedEntry(t, filepath.Join(paths.root, releaseFile))
		}
		if to != filepath.Base(paths.held) {
			return op(r, from, to)
		}
		sourceFailIf(t, !afterClaim, "three links reached stage claim")
		sourceMust(t, op(r, from, to))
		return os.Link(paths.held, extra)
	}
	o.ops.remove = func(r *os.Root, leaf string) error {
		sourceFailIf(t, leaf == filepath.Base(paths.stage) || leaf == filepath.Base(paths.held) || leaf == releaseDetached, "three links reached removal of %q", leaf)
		return r.Remove(leaf)
	}
	return func() {
		sourceFailIf(t, keepMarker == nil, "release did not reach detachment")
		keepMarker()
	}
}

func testSourceMarkerCollision(t *testing.T) {
	t.Run("changed-record", func(t *testing.T) {
		s, o, dir, m, parts, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		backing := sourcePreservedEntry(t, filepath.Join(root, p.name))
		var written os.FileInfo
		var image []byte
		o.ops.write = func(f *os.File, record []byte) (int, error) {
			image = slices.Clone(record)
			image[len(image)-1] ^= 1
			var err error
			written, err = f.Stat()
			sourceMust(t, err)
			return f.Write(image)
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		path := filepath.Join(root, releaseScratch)
		sourceUnchangedEntry(t, path, written)
		sourceFailIf(t, !bytes.Equal(image, sourceReadFile(t, path)), "scratch record changed after refusal")
		sourcePresence(t, root, releaseFile, false)
		backing()
		fresh := sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		sourcePresence(t, root, releaseScratch, false)
		sourceRead(t, fresh, m, parts)
	})
	t.Run("changed-scratch", func(t *testing.T) {
		_, o, dir, _, _, p := sourcePreparedBundle(t)
		root := filepath.Join(dir, sourceDirectory)
		scratch := filepath.Join(root, releaseScratch)
		replacement := filepath.Join(dir, "replacement")
		sourceMust(t, os.WriteFile(replacement, []byte("independent record"), 0o600))
		info := sourceLstat(t, replacement)
		o.ops.close = func(f *os.File) error {
			sourceMust(t, f.Close())
			return os.Rename(replacement, scratch)
		}
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourceUnchangedEntry(t, scratch, info)
		sourcePresence(t, root, releaseFile, false)
		sourcePresence(t, root, p.name, true)
	})
	_, o, dir, _, _, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	var inserted os.FileInfo
	preserved := []byte("existing marker")
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
		if to == releaseFile {
			path := filepath.Join(root, to)
			sourceMust(t, os.WriteFile(path, preserved, 0o600))
			inserted = sourceLstat(t, path)
		}
		return op(r, from, to)
	}
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	path := filepath.Join(root, releaseFile)
	sourceFailIf(t, !os.SameFile(inserted, sourceLstat(t, path)) || !bytes.Equal(preserved, sourceReadFile(t, path)) || o.release != nil, "occupied release name changed or granted release")
	sourcePresence(t, root, p.name, true)
}

func testSourceReleaseInconclusive(t *testing.T, stage string) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	size := uint64(len(sourceReadFile(t, filepath.Join(root, p.name))))
	cause := errors.New("release observation unavailable")
	markerPresent := stage == "pending-visible" || stage == "clear-present"
	reclaimed := map[string]int{"scratch-sync": 1, "pending-absent": 2}[stage]
	foreign := sourceForeign(m)
	pending, backing := sourceReleaseWithFault(t, o, p, stage, cause)
	if pending {
		sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
	}
	sourcePresence(t, root, p.name, backing)
	sourcePresence(t, root, releaseFile, markerPresent)
	sourcePresence(t, root, releaseScratch, reclaimed != 0 || stage == "pending-visible")
	if pending {
		sourcePrepareRefusal(t, o, foreign, parts, ErrBusyV1)
	}
	assertSourceReleaseCharge(t, o, m, 1, size)
	o.ops = realSourceFS
	intent := uint64(len(o.releaseRecord(&sourceRelease{name: p.name, sourceIncarnation: *p.incarnation, manifest: p.manifest})))
	o.ops.statfs = func(_ int, stat *syscall.Statfs_t) error {
		_, err := os.Lstat(filepath.Join(root, releaseScratch))
		sourceStatfsFixture(stat, 1, intent+o.limits.Overhead-map[bool]uint64{true: 1}[err == nil])
		return nil
	}
	if markerPresent {
		path := filepath.Join(root, releaseFile)
		record := sourceReadFile(t, path)
		sourceMust(t, os.WriteFile(path, []byte{1}, 0o600))
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
		sourcePresence(t, root, p.name, backing)
		assertSourceReleaseCharge(t, o, m, 1, size)
		sourceMust(t, os.WriteFile(path, record, 0o600))
	}
	renames, unlinks, syncs := 0, 0, 0
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
		if to == releaseFile {
			renames++
		}
		return op(r, from, to)
	}
	o.ops.remove = func(r *os.Root, name string) error {
		if name == releaseDetached {
			unlinks++
		}
		return r.Remove(name)
	}
	o.ops.dirSync = func(pin *os.File) error { syncs++; return pin.Sync() }
	sourceReleaseResult(t, o, p, true, nil)
	wantRenames, wantUnlinks, wantSyncs := min(reclaimed, 1), 1, 3+min(reclaimed, 1)
	if !backing {
		wantUnlinks, wantSyncs = 0, 1
	}
	sourceFailIf(t, renames != wantRenames || unlinks != wantUnlinks || syncs != wantSyncs, "release retry rename/unlink/sync=%d/%d/%d, want %d/%d/%d", renames, unlinks, syncs, wantRenames, wantUnlinks, wantSyncs)
	o.ops = realSourceFS
	sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "resumed release left backing")
	assertSourceReleaseCharge(t, o, m, 0, 0)
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	sourcePrepareAndRead(t, o, foreign, parts)
}

func assertSourceReleaseCharge(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, files, size uint64) {
	t.Helper()
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceMust(t, o.withManifest(a, m, false, func(r *sourceRoot, _ SourceManifestV1, _ uint64) error {
			used, err := o.census(r, false)
			sourceMust(t, err)
			sourceFailIf(t, used.files != files || used.bytes != size, "source charge: %d files/%d bytes, want %d/%d", used.files, used.bytes, files, size)
			return nil
		}))
	})
}

func testSourceReleaseIncarnation(t *testing.T, mode string) {
	s, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	path, marker := filepath.Join(root, p.name), filepath.Join(root, releaseFile)
	original := sourceReadFile(t, path)
	changed := slices.Clone(original)
	if mode == "changed-content" {
		changed = sourceResealed(original, len(original)-sha256.Size-1)
		sourceMust(t, os.WriteFile(path, changed, 0o600))
		sourcePrepareRefusal(t, o, m, parts, ErrIntegrityV1)
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), changed), "refused release changed original backing")
		sourceFailIf(t, len(sourceEntries(t, dir)) != 1, "refused release created intent")
		sourceMust(t, os.WriteFile(path, original, 0o600))
	}
	cause := errors.New("source unlink refusal")
	sourceReleaseWithFault(t, o, p, "intent-sync", cause)
	o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
	record := sourceReadFile(t, marker)
	want := ErrIntegrityV1
	if mode != "changed-content" {
		moved := map[bool]string{false: filepath.Join(t.TempDir(), "original"), true: filepath.Join(root, "moved")}[mode == "linked-backing"]
		o.ops.dirSync = func(pin *os.File) error {
			o.ops.dirSync = (*os.File).Sync
			sourceMust(t, pin.Sync())
			sourceMust(t, os.Rename(path, moved))
			if mode == "linked-backing" {
				return os.Symlink("moved", path)
			}
			return os.WriteFile(path, changed, 0o600)
		}
		if mode == "changed-inode" {
			want = ErrIdentityV1
		}
	} else {
		for _, offset := range []int{3, len(record) - 1, 4, 36, releasePrefix + 3, releasePrefix + 4, releasePrefix + bundleHeader - 1} {
			markerErr := map[bool]error{false: ErrIntegrityV1, true: ErrIdentityV1}[offset == 4 || offset == releasePrefix+4]
			release, err := o.decodeRelease(sourceResealed(record, offset))
			sourceFailIf(t, release != nil || any(err) != any(markerErr), "release marker offset %d: %v/%v, want %v", offset, release, err, markerErr)
		}
		sourceMust(t, os.WriteFile(path, changed, 0o600))
	}
	sourceReleaseResult(t, o, nil, true, want)
	sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
	sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), changed) || !bytes.Equal(sourceReadFile(t, marker), record),
		"refused release changed backing or intent")
	if mode == "linked-backing" {
		sourceMust(t, os.Symlink("absent", filepath.Join(root, "dangling")))
		if os.Geteuid() != 0 {
			sourceMust(t, os.WriteFile(filepath.Join(root, "unreadable"), nil, 0))
		}
		sourceMust(t, o.withRoot(o.bindRoot, func(r *sourceRoot) error {
			for name, want := range map[string]error{p.name: ErrIntegrityV1, "dangling": ErrIntegrityV1, "unreadable": ErrUnavailableV1, "absent": ErrUnavailableV1} {
				_, err := openSourceFile(r, name, ErrUnavailableV1)
				sourceWantError(t, err, want, "open of "+name)
			}
			return nil
		}))
	}
}

func testSourceReleaseStage(t *testing.T, stage string) {
	m, parts := sourceBundle(1, false)
	size, err := m.SizeV1()
	sourceMust(t, err)
	limits, spare := sourceLimits(), stage == "unlink-reopen-competing-prepare"
	limits.Files = map[bool]uint64{false: 1, true: 2}[spare]
	limits.Bytes = limits.Files * size
	s, o, dir := sourceScene(t, limits)
	p := sourcePrepare(t, o, m, parts)
	root := filepath.Join(dir, sourceDirectory)
	originalSize := uint64(len(sourceReadFile(t, filepath.Join(root, p.name))))
	foreign, held := sourceForeign(m), sourceHeld(t, o)
	sourceReleaseResult(t, o, p, false, ErrIntegrityV1)
	sourceReleaseResult(t, o, nil, true, ErrIntegrityV1)
	held("refused release")
	cause := errors.New("release refusal")
	visible, backing := sourceReleaseWithFault(t, o, p, stage, cause)
	if visible {
		sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
		sourcePrepareRefusal(t, o, foreign, parts, ErrBusyV1)
	}
	if stage == "final-sync" {
		o.ops.dirSync = func(*os.File) error { return cause }
		sourceReleaseResult(t, o, p, true, cause)
		sourcePrepareResult(t, o, foreign, refusedSourceProducer(t), ErrBusyV1)
	}
	store := sourceReopenStore(t, s, dir)
	backingName := p.name
	if stage == "unlink" || spare {
		backingName = releaseDetached
		sourcePresence(t, root, p.name, false)
	}
	if spare {
		narrow, record, backed := limits, sourceReadFile(t, filepath.Join(root, releaseFile)), sourceReadFile(t, filepath.Join(root, backingName))
		narrow.Scans = 6*3 + 2*limits.Files + 1
		sourceOpen(t, store, sourceID(), narrow, ErrCapacityV1)
		sourceFailIf(t, !bytes.Equal(record, sourceReadFile(t, filepath.Join(root, releaseFile))) || !bytes.Equal(backed, sourceReadFile(t, filepath.Join(root, backingName))), "over-limit reopen changed the release marker or backing")
	}
	if !backing && stage != "final-sync" {
		extra, narrow, record := filepath.Join(root, fmt.Sprintf("%064x", 0)), limits, sourceReadFile(t, filepath.Join(root, releaseFile))
		narrow.Files = 2
		sourceMust(t, os.WriteFile(extra, []byte{1}, 0o600))
		sourceOpen(t, store, sourceID(), narrow, ErrCapacityV1)
		sourceFailIf(t, !bytes.Equal(record, sourceReadFile(t, filepath.Join(root, releaseFile))) || !bytes.Equal(sourceReadFile(t, extra), []byte{1}), "over-limit reopen changed the release marker or retained file")
		sourceMust(t, os.Remove(extra))
	}
	fresh := sourceOpen(t, store, sourceID(), limits, nil)
	if visible && stage != "final-sync" {
		sourcePrepareResult(t, fresh, foreign, refusedSourceProducer(t), ErrBusyV1)
	}
	var oversized SourceManifestV1
	if spare {
		sourcePrepareRefusal(t, fresh, foreign, parts, ErrBusyV1)
		oversized = foreign
		oversized.Parts = slices.Clone(foreign.Parts)
		oversized.Parts[0].Length += limits.Bytes + 1 - size
		overSize, err := oversized.SizeV1()
		sourceFailIf(t, err != nil || overSize != limits.Bytes+1, "oversized manifest: %d/%v", overSize, err)
		sourcePrepareRefusal(t, fresh, oversized, parts, ErrBusyV1)
		sourceReadRefusal(t, fresh, m, ErrBusyV1, "release-only readback")
	}
	sourcePresence(t, root, backingName, backing)
	sourcePresence(t, root, releaseFile, visible && stage != "final-sync")
	sourcePresence(t, root, releaseScratch, false)
	switch {
	case !visible:
		sourceReleaseResult(t, fresh, nil, true, ErrIntegrityV1)
		sourceRead(t, fresh, m, parts)
		sourceReleaseResult(t, fresh, sourcePrepare(t, fresh, m, parts), true, nil)
	case stage == "final-sync":
		sourceReleaseResult(t, fresh, nil, true, ErrIntegrityV1)
	default:
		assertSourceReleaseCharge(t, fresh, m, 1, originalSize)
		sourcePrepareRefusal(t, fresh, foreign, parts, ErrBusyV1)
		sourceReleaseResult(t, fresh, nil, true, nil)
	}
	sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "released backing or record remained")
	sourcePrepare(t, fresh, foreign, parts)
	if spare {
		sourcePrepareRefusal(t, fresh, oversized, parts, ErrCapacityV1)
		sourcePrepare(t, fresh, m, parts)
	}
}

func sourceReleaseWithFault(t *testing.T, o *SourceOwnerV1, p *PreparedSourceV1, stage string, cause error) (pending, backing bool) {
	t.Helper()
	defer sourceReleaseResult(t, o, p, true, cause)
	switch stage {
	case "write", "chmod", "file-sync", "close", "rename", "scratch-sync":
		sourceFault(o, stage, cause, nil)
		return false, true
	case "unlink", "unlink-reopen-competing-prepare":
		o.ops.remove = func(r *os.Root, leaf string) error {
			if leaf == releaseDetached {
				return cause
			}
			return r.Remove(leaf)
		}
		return true, true
	case "rename-visible":
		o.ops.namespace = renameSourceFault(t, cause, true, false)
		return true, true
	case "pending-absent", "pending-visible":
		o.ops.namespace = renameSourceFault(t, cause, stage == "pending-visible", true)
		return true, true
	case "marker-clear", "clear-present", "clear-absent":
		o.ops.remove = func(r *os.Root, name string) error {
			if name != releaseFile {
				return r.Remove(name)
			}
			if stage == "clear-absent" {
				sourceMust(t, r.Remove(name))
			}
			if stage != "marker-clear" {
				sourceMust(t, r.Close())
			}
			return cause
		}
		return true, false
	}
	calls, failAt := 0, map[string]int{"intent-sync": 1, "unlink-sync": 2, "final-sync": 3}[stage]
	o.ops.dirSync = func(pin *os.File) error {
		calls++
		if calls == failAt {
			return cause
		}
		return pin.Sync()
	}
	return true, stage == "intent-sync"
}

func sourceReleaseHasOpenFile(t *testing.T, info os.FileInfo) bool {
	t.Helper()
	return len(sourceOpenFileModes(t, info)) != 0
}

func sourcePreservedEntry(t *testing.T, name string) func() {
	t.Helper()
	info := sourceLstat(t, name)
	var data []byte
	if info.Mode().IsRegular() {
		data = sourceReadFile(t, name)
	}
	return func() {
		t.Helper()
		sourceUnchangedEntry(t, name, info)
		if info.Mode().IsRegular() {
			sourceFailIf(t, !bytes.Equal(data, sourceReadFile(t, name)), "refusal changed bytes at %s", name)
		}
	}
}

func sourcePresence(t *testing.T, root, name string, present bool) {
	t.Helper()
	_, err := os.Lstat(filepath.Join(root, name))
	sourceFailIf(t, present && err != nil || !present && !errors.Is(err, os.ErrNotExist), "source path %q present=%t: %v", name, present, err)
}

func sourceReleaseResult(t *testing.T, o *SourceOwnerV1, p *PreparedSourceV1, proof bool, want error) {
	t.Helper()
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceWantError(t, o.ReleaseUnpublishedSourceV1(a, p, proof), want, "source release")
	})
}

func TestSourceReopenRequiresDirectorySync(t *testing.T) {
	s, _, dir, m, parts, _ := sourcePreparedBundle(t)
	opened := sourceReopenStore(t, s, dir)
	child, err := os.Stat(filepath.Join(dir, sourceDirectory))
	sourceMust(t, err)
	saved := realSourceFS
	defer func() { realSourceFS = saved }()
	calls := 0
	cause := errors.New("source directory sync")
	realSourceFS.dirSync = func(pin *os.File) error {
		calls++
		info, err := pin.Stat()
		sourceFailIf(t, err != nil || !os.SameFile(child, info), "source directory pin: %v", err)
		return cause
	}
	sourceOpen(t, opened, sourceID(), sourceLimits(), cause)
	sourceFailIf(t, calls != 1, "reopened directory sync calls=%d", calls)
	realSourceFS = saved
	fresh := sourceOpen(t, opened, sourceID(), sourceLimits(), nil)
	path := filepath.Join(dir, sourceDirectory, m.name(sourceID()))
	original := sourceReadFile(t, path)
	corrupt := slices.Clone(original)
	corrupt[len(corrupt)-1] ^= 1
	sourceMust(t, os.WriteFile(path, corrupt, 0o600))
	sourcePrepareRefusal(t, fresh, m, parts, ErrIntegrityV1)
	sourceMust(t, os.WriteFile(path, original, 0o600))
	sourcePrepareAndRead(t, fresh, m, parts)
}

func TestSourceNoOverwriteAndDistinctCopies(t *testing.T) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	path := filepath.Join(dir, sourceDirectory, p.name)
	original := sourceReadFile(t, path)
	changed := slices.Clone(parts)
	changed[0] = slices.Clone(parts[0])
	changed[0][0] ^= 1
	for _, length := range []bool{false, true} {
		incoming := slices.Clone(changed)
		manifest := m
		if length {
			incoming[0] = append(incoming[0], 1)
			manifest.Parts = slices.Clone(m.Parts)
			manifest.Parts[0].Length++
		}
		sourcePrepareResult(t, o, manifest, sourceProducer(manifest, incoming), ErrIntegrityV1)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), original) || len(sourceEntries(t, dir)) != 1,
			"same identity changed bytes or created another file")
	}
	accepted, acceptedParts := sourceBundle(2, false)
	acceptedSource := sourcePrepare(t, o, accepted, acceptedParts)
	sourceFailIf(t, p.name == acceptedSource.name, "distinct capture classes share identity")
	sourceRead(t, o, accepted, acceptedParts)
	staging := filepath.Join(filepath.Dir(path), ".staging-"+p.name)
	sourceMust(t, os.WriteFile(staging, original[:1], 0o600))
	testSourceUnfundedBacking(t, o, m, parts, staging)
	producer := sourceMappedProducer(m, parts, func(part SourcePartV1, visit func(SourcePartV1) error) error {
		return sourceAlteredPart("length", part, visit)
	})
	sourcePrepareResult(t, o, m, producer, ErrIntegrityV1)
	sourceFailIf(t, !bytes.Equal(original[:1], sourceReadFile(t, staging)) || !bytes.Equal(original, sourceReadFile(t, path)), "refused reuse changed backing")
	sourcePrepare(t, o, m, parts)
	sourcePresence(t, filepath.Dir(staging), filepath.Base(staging), false)
	sourceRead(t, o, m, parts)
	t.Run("acquired-copy", func(t *testing.T) {
		const common = "010000000000000000000000000000000000000000000000000000000000000000000000dc6c2a3fd574b0f69ddd16d999b2ed94cdc20a399ef12b0d84eb8cd67d5a22021b04000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000010100000002010000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000521ec18851e17bbba961bc46c70baf03ee67ebdea11a8306de39c15a90e9d2e500"
		s, o, dir := sourceScene(t, sourceLimits())
		one, first := acquiredSourceFrame(t, common+"0142", 237, "115b308a43ffbe3e33feef20751954bbe327086396dfc5ffb3804674af89a30c")
		two, second := acquiredSourceFrame(t, common+"024243", 238, "5be9beac7d666b77658007d0cb47c6ed4c7adc3183ea51e563587bd85b5d662e")
		a, b := sourcePrepare(t, o, one, first), sourcePrepare(t, o, two, second)
		sourceFailIf(t, a.name == b.name || !bytes.Equal(first[0][:235], second[0][:235]),
			"acquired copies did not retain distinct suffixes and a common frame prefix")
		o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		sourceRead(t, o, one, first)
		sourceRead(t, o, two, second)
	})
	t.Run("name-occupied-during-export", func(t *testing.T) {
		_, owner, dir := sourceScene(t, sourceLimits())
		root := filepath.Join(dir, sourceDirectory)
		path := filepath.Join(root, p.name)
		producer := sourceAfterFirstPart(m, changed, func() error {
			sourcePresence(t, root, ".stage-hold-"+p.name, true)
			return os.WriteFile(path, original, 0o600)
		})
		sourcePrepareResult(t, owner, m, producer, ErrIntegrityV1)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), original) || len(sourceEntries(t, dir)) != 1 || owner.debt.name != "",
			"name collision changed existing bytes or retained staging")
	})
	t.Run("stale-prepared", func(t *testing.T) {
		_, owner, dir := sourceScene(t, sourceLimits())
		a, b := sourcePrepare(t, owner, m, parts), sourcePrepare(t, owner, m, parts)
		copied := *b
		sourceReleaseResult(t, owner, a, true, nil)
		replacement, held := sourcePrepare(t, owner, m, parts), sourceHeld(t, owner)
		for _, old := range []*PreparedSourceV1{b, &copied} {
			sourceReleaseResult(t, owner, old, true, ErrIntegrityV1)
			held("stale release")
			sourceRead(t, owner, m, parts)
		}
		sourceReleaseResult(t, owner, replacement, true, nil)
		sourcePresence(t, filepath.Join(dir, sourceDirectory), replacement.name, false)
	})
	t.Run("written-digest", testSourceWrittenDigest)
	t.Run("producer-digest", testSourceComparedDigest)
	t.Run("requalify-after-producer", testSourceRequalifyAfterProducer)
	sourceModes(t, []string{"at-link-destination-collision", "at-link-destination-io-error"}, testSourceLinkCollision)
	sourceModes(t, []string{"publication-acknowledgement", "publication-separate-destination", "publication-late-eio"}, testSourcePublicationAcknowledgement)
	sourceModes(t, []string{"link-visible-exists", "link-unavailable-exists"}, testSourceLinkExists)
	sourceModes(t, []string{"fresh-pin", "reuse-pin", "fresh-scan-limit", "reuse-scan-limit", "final-name-missing", "final-name-identity", "final-name-size", "final-name-content"}, testSourceFinalPin)
}

func acquiredSourceFrame(t *testing.T, encoded string, size int, want string) (SourceManifestV1, [][]byte) {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	digest := sha256.Sum256(raw)
	sourceFailIf(t, err != nil || len(raw) != size || hex.EncodeToString(digest[:]) != want, "acquired frame length or digest: %d/%x", len(raw), digest)
	m, parts := sourceBundle(3, false)
	parts[0], m.Parts[0].Length, m.AcquiredDigest = raw, uint64(size), digest
	return m, parts
}

func TestSourceCapacityBeforeCopy(t *testing.T) {
	m, _ := sourceBundle(1, false)
	size, err := m.SizeV1()
	sourceMust(t, err)
	required := size + sourceLimits().Overhead
	statfs := map[string]struct {
		unit, available uint64
		err             error
	}{
		"statfs-exact-fit": {1, required, nil},
		"statfs-space":     {1, required - 1, nil},
		"statfs-error":     {1, required, io.ErrUnexpectedEOF},
		"statfs-zero":      {0, math.MaxUint64, nil},
		"statfs-overflow":  {2, math.MaxUint64, nil},
	}
	sourceModes(t, []string{"statfs-exact-fit", "bytes", "files", "scans", "statfs-error", "statfs-zero", "statfs-overflow", "statfs-space", "census-name", "census-link", "census-staging", "census-files", "census-bytes", "census-scans"}, func(t *testing.T, mode string) {
		m, parts := sourceBundle(1, false)
		limits := sourceLimits()
		switch mode {
		case "bytes":
			limits.Bytes = size - 1
		case "files":
			limits.Files = 1
		case "scans":
			limits.Scans = 6*3 + 2*limits.Files + 1
		}
		s, o, dir := sourceScene(t, limits)
		want := ErrCapacityV1
		root := filepath.Join(dir, sourceDirectory)
		switch mode {
		case "census-name":
			sourceMust(t, os.WriteFile(filepath.Join(root, "invalid"), nil, 0o600))
			want = ErrIntegrityV1
		case "census-link":
			sourceMust(t, os.Symlink(".", filepath.Join(root, fmt.Sprintf("%064x", 0))))
			want = ErrIntegrityV1
		case "census-staging", "census-files", "census-bytes", "census-scans":
			count := map[string]int{"census-staging": 2, "census-files": 9, "census-bytes": 1, "census-scans": 64}[mode]
			for n := range count {
				name := fmt.Sprintf("%064x", n)
				if mode == "census-scans" && n == 0 {
					name = "invalid"
				}
				if mode == "census-staging" {
					name = ".staging-" + name
					want = ErrBusyV1
				}
				path := filepath.Join(root, name)
				sourceMust(t, os.WriteFile(path, nil, 0o600))
				sourceMust(t, os.Truncate(path, map[bool]int64{true: int64(limits.Bytes) + 1}[mode == "census-bytes"]))
			}
			if mode == "census-staging" {
				sourcePrepareResult(t, o, m, nil, ErrBusyV1)
			}
		case "files":
			sourcePrepare(t, o, m, parts)
			m.Identity[1]++
		case "scans":
			existing, data := sourceBundle(3, false)
			sourcePrepare(t, o, existing, data)
		}
		if sample, ok := statfs[mode]; ok {
			o.ops.statfs = func(_ int, s *syscall.Statfs_t) error {
				sourceStatfsFixture(s, sample.unit, sample.available)
				return sample.err
			}
		}
		if mode == "statfs-exact-fit" {
			sourcePrepareAndRead(t, o, m, parts)
			return
		}
		sourcePrepareRefusal(t, o, m, parts, want)
		if mode == "census-files" {
			held := sourceHeld(t, o)
			s = sourceReopenStore(t, s, dir)
			for files := uint64(8); files <= 9; files++ {
				limits.Files, limits.Scans = files, 10
				sourceOpen(t, s, sourceID(), limits, map[bool]error{true: ErrCapacityV1}[files == 8])
			}
			held("admission")
		}
	})
}

func sourceForeign(m SourceManifestV1) SourceManifestV1 { m.Identity[0]++; return m }

func sourceStatfsFixture(stat *syscall.Statfs_t, unit, available uint64) {
	stat.Bsize = 4096
	stat.Bavail = available
	if runtime.GOOS == "linux" {
		reflect.ValueOf(stat).Elem().FieldByName("Frsize").SetInt(int64(unit))
	} else {
		reflect.ValueOf(stat).Elem().FieldByName("Bsize").SetUint(unit)
	}
}

func TestSourceLimitsAndIdentity(t *testing.T) {
	t.Run("source-directory-mode", func(t *testing.T) {
		s, dir := sourceStore(t)
		root := filepath.Join(dir, sourceDirectory)
		init := filepath.Join(dir, ".source-captures-v1.init")
		var closed *mdbx.OperationAccount
		sourceAccount(t, func(a *mdbx.OperationAccount) { closed = a })
		refused := func() {
			for _, a := range []*mdbx.OperationAccount{{}, closed} {
				owner, err := NewSourceOwnerV1(s, sourceID(), sourceLimits(), a)
				sourceFailIf(t, owner != nil || any(err) != any(a.WithReservation(0, func() error { t.Fatal("refused account ran"); return nil })), "owner with a refused account: %v/%v", owner, err)
			}
		}
		refused()
		sourcePresence(t, dir, sourceDirectory, false)
		sourceMust(t, os.Mkdir(root, 0o700))
		sourceMust(t, os.Mkdir(init, 0o700))
		original, scratch := sourceLstat(t, root), sourceLstat(t, init)
		parent, err := os.Open(dir)
		sourceMust(t, err)
		sourceFailIf(t, !errors.Is(renameSourceAt(int(parent.Fd()), sourceInitDirectory, sourceDirectory), os.ErrExist), "exclusive directory publication replaced the destination")
		sourceMust(t, parent.Close())
		for _, mode := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
			sourceMust(t, os.Chmod(root, mode|0o700))
			sourceOpen(t, s, sourceID(), sourceLimits(), ErrIdentityV1)
			sourceFailIf(t, sourceLstat(t, root).Mode() != os.ModeDir|mode|0o700, "refusal changed source directory mode")
			sourceUnchangedEntry(t, init, scratch)
		}
		sourceMust(t, os.Chmod(root, 0o700))
		o := sourceOpen(t, s, sourceID(), sourceLimits(), nil)
		sourceUnchangedEntry(t, root, original)
		sourceUnchangedEntry(t, init, scratch)
		m, parts := sourceBundle(1, false)
		_, held := sourcePrepare(t, o, m, parts), sourceHeld(t, o)
		refused()
		held("refused account")
		for _, mode := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
			sourceMust(t, os.Chmod(root, mode|0o700))
			sourcePrepareRefusal(t, o, m, parts, ErrIdentityV1)
		}
		sourceMust(t, os.Chmod(root, 0o700))
		sourceRead(t, o, m, parts)
	})
	s, o, _, m, parts := sourceBundleScene(t, 1, false)
	_, held := sourcePrepare(t, o, m, parts), sourceHeld(t, o)
	for _, field := range []string{"Bytes", "Files", "Scans", "RAM", "Headers", "Descriptors", "Overhead"} {
		for _, value := range []uint64{0, math.MaxUint64} {
			limits := sourceLimits()
			reflect.ValueOf(&limits).Elem().FieldByName(field).SetUint(value)
			sourceOpen(t, s, sourceID(), limits, ErrCapacityV1)
		}
	}
	for _, field := range []string{"InstallationID", "ChainID", "GenesisHash", "Profile"} {
		wrong := sourceID()
		v := reflect.ValueOf(&wrong).Elem().FieldByName(field)
		if v.Kind() == reflect.Array {
			v = v.Index(0)
		}
		v.SetUint(99)
		sourceOpen(t, s, wrong, sourceLimits(), ErrIdentityV1)
	}
	held("invalid admission")
}

func writeSourceEntry(t *testing.T, path string, data []byte) os.FileInfo {
	t.Helper()
	sourceMust(t, os.WriteFile(path, data, 0o600))
	return sourceLstat(t, path)
}

func sourceLstat(t *testing.T, name string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(name)
	sourceMust(t, err)
	return info
}

func sourceUnchangedEntry(t *testing.T, name string, original os.FileInfo, content ...[]byte) {
	t.Helper()
	info := sourceLstat(t, name)
	sourceFailIf(t, !os.SameFile(original, info) || info.Mode() != original.Mode(), "source entry %s changed", name)
	if len(content) != 0 {
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, name), content[0]), "source entry %s changed bytes", name)
	}
}

func TestSourceInitializationRefusesOccupiedName(t *testing.T) {
	s, dir := sourceStore(t)
	const name = ".source-captures-v1.init"
	init := filepath.Join(dir, name)
	sourceModes(t, []string{"file", "link", "nonempty"}, func(t *testing.T, shape string) {
		backing := init
		switch shape {
		case "link":
			backing = filepath.Join(dir, "target")
			sourceMust(t, os.Symlink(backing, init))
		case "nonempty":
			sourceMust(t, os.Mkdir(init, 0o700))
			backing = filepath.Join(init, "backing")
		}
		data := []byte("retained")
		sourceMust(t, os.WriteFile(backing, data, 0o600))
		original := sourceLstat(t, init)
		sourceOpen(t, s, sourceID(), sourceLimits(), ErrIdentityV1)
		sourcePresence(t, dir, sourceDirectory, false)
		sourceUnchangedEntry(t, init, original)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, backing), data), "refusal changed backing bytes")
		sourceMust(t, os.RemoveAll(init))
	})
	sourceOpen(t, s, sourceID(), sourceLimits(), nil)
	sourcePresence(t, dir, name, false)
}

func TestSourceSharedCaptureBudget(t *testing.T) {
	t.Run("live-length", func(t *testing.T) {
		m, parts := sourceBundle(1, false)
		size, err := m.SizeV1()
		sourceMust(t, err)
		limits := sourceLimits()
		limits.Bytes, limits.Files = 2*size-1, 2
		_, o, dir := sourceScene(t, limits)
		p := sourcePrepare(t, o, m, parts)
		path := filepath.Join(dir, sourceDirectory, p.name)
		data := sourceReadFile(t, path)
		sourceMust(t, os.Truncate(path, int64(len(data))-1))
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrIntegrityV1)
		sourceMust(t, os.WriteFile(path, data, 0o600))
		sourceRead(t, o, m, parts)
		sourceFailIf(t, sourcePrepare(t, o, m, parts).incarnation != p.incarnation, "retained source token changed")
	})
	t.Run("counted-name-lost", func(t *testing.T) {
		_, o, dir, m, parts, p := sourcePreparedBundle(t)
		path, moved := filepath.Join(dir, sourceDirectory, p.name), filepath.Join(dir, "counted")
		sourceAccount(t, func(a *mdbx.OperationAccount) {
			sourceMust(t, o.withFiles(a, m, true, func(r *sourceRoot, admitted SourceManifestV1, size uint64, used sourceUsage) error {
				sourceFailIf(t, used.files != 1 || used.bytes != size, "live file was not counted: %+v", used)
				sourceMust(t, os.Rename(path, moved))
				calls := 0
				prepared, err := o.prepare(r, admitted, size, used, func(visit func(SourcePartV1) error) error {
					calls++
					return o.export(a, admitted, sourceProducer(admitted, parts), visit)
				})
				sourceWantError(t, err, ErrIntegrityV1, "counted backing absent at open")
				sourceFailIf(t, prepared != nil || calls != 0 || o.live[p.name] != p.incarnation, "counted absence: handle=%v calls=%d", prepared, calls)
				return nil
			}))
		})
		sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "replacement after counted backing disappeared")
		sourceMust(t, os.Rename(moved, path))
		sourceRead(t, o, m, parts)
		sourceFailIf(t, sourcePrepare(t, o, m, parts).incarnation != p.incarnation, "retained source token changed")
	})
	sourceModes(t, []string{"exact", "files", "bytes"}, func(t *testing.T, mode string) {
		first, one := sourceBundle(1, false)
		second, two := sourceBundle(3, false)
		a, errA := first.SizeV1()
		b, errB := second.SizeV1()
		sourceMust(t, errors.Join(errA, errB))
		limits := sourceLimits()
		limits.Bytes, limits.Files = a+b, 2
		switch mode {
		case "files":
			limits.Bytes = a + 2*b
		case "bytes":
			limits.Bytes, limits.Files = a+b-1, 3
		}
		limits.Scans = 6*3 + 2*limits.Files + 2
		_, o, dir := sourceScene(t, limits)
		original := sourcePrepare(t, o, first, one)
		attempt := second
		if mode != "bytes" {
			sourcePrepare(t, o, second, two)
			attempt.Identity[0]++
		}
		sourcePrepareRefusal(t, o, attempt, two, ErrCapacityV1)
		if mode == "files" {
			path, moved := filepath.Join(dir, sourceDirectory, original.name), filepath.Join(dir, "moved")
			sourceMust(t, os.Rename(path, moved))
			sourcePrepareRefusal(t, o, attempt, two, ErrIntegrityV1)
			sourceMust(t, os.WriteFile(path, sourceReadFile(t, moved), 0o600))
			sourcePrepareRefusal(t, o, attempt, two, ErrIdentityV1)
			sourceMust(t, os.Remove(path))
			sourceMust(t, os.Rename(moved, path))
		}
		sourceRead(t, o, first, one)
		if mode != "bytes" {
			sourceRead(t, o, second, two)
		}
	})
}

func TestSourcePositiveInsufficientLimits(t *testing.T) {
	exact := sourceLimits()
	exact.RAM = 65536 + 4096 + 512*exact.Scans + 32*(exact.Bytes/65536+6) + 1024 + 168*exact.Files
	s, o, _ := sourceScene(t, exact)
	ram, descriptors, held := exact, exact, sourceHeld(t, o)
	ram.RAM, descriptors.Descriptors = ram.RAM-1, 3
	extreme := exact
	extreme.RAM, extreme.Bytes, extreme.Scans = math.MaxInt64-1, math.MaxInt64-1, uint64(math.MaxInt-65536-4096)/512
	combined := extreme
	combined.Bytes = 1
	for _, limits := range []SourceLimitsV1{ram, descriptors, extreme, combined} {
		sourceOpen(t, s, sourceID(), limits, ErrCapacityV1)
	}
	held("insufficient limits")
}

func TestSourceBoundedMaximumCopy(t *testing.T) {
	m, parts := sourceBundle(1, false)
	parts[0] = bytes.Repeat([]byte{19}, 256<<10)
	m.Parts[0].Length = uint64(len(parts[0]))
	size, err := m.SizeV1()
	sourceMust(t, err)
	limits := sourceLimits()
	limits.Bytes = size
	_, o, dir := sourceScene(t, limits)
	testSourceUnfundedBacking(t, o, m, parts, filepath.Join(dir, sourceDirectory, ".staging-"+m.name(o.id)))
	maximum := 0
	funded := mdbx.TreeLaneMaxBytes - (65536 + 4096 + 64*512 + 32*(o.limits.Bytes/65536+6)) - sourceBackingCharge(parts)
	producer := sourceMappedProducer(m, parts, func(part SourcePartV1, visit func(SourcePartV1) error) error {
		read := part.ReadAt
		part.ReadAt = func(dst []byte, off int64) (int, error) { maximum = max(maximum, len(dst)); return read(dst, off) }
		return visit(part)
	})
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceMust(t, a.WithReservation(funded, func() error {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			p, err := o.PrepareSourceV1(a, m, producer)
			runtime.ReadMemStats(&after)
			sourceFailIf(t, err != nil || p == nil, "maximum capture: %v/%v", p, err)
			sourceFailIf(t, after.TotalAlloc-before.TotalAlloc >= 2*65536, "prepare heap allocation: %d bytes", after.TotalAlloc-before.TotalAlloc)
			limitErr := a.WithReservation(mdbx.TreeLaneMaxBytes-funded+1, func() error { t.Fatal("caller funding was released"); return nil })
			sourceFailIf(t, !mdbx.IsOperationReservationCapacity(limitErr), "caller charge: %v", limitErr)
			return a.WithReservation(mdbx.TreeLaneMaxBytes-funded, func() error { return nil })
		}))
	})
	sourceFailIf(t, maximum == 0 || maximum > 65536, "copy scratch=%d", maximum)
	sourceRead(t, o, m, parts)
	maximum = 0
	sourcePrepareResult(t, o, m, producer, nil)
	sourceFailIf(t, maximum <= 0, "reuse did not read source parts")
	sourceFailIf(t, maximum > 32768, "reuse copy scratch=%d", maximum)
}

func TestSourceStagingRestartAndAmbiguousRename(t *testing.T) {
	sourceModes(t, []string{"staging", "renamed", "unobserved-renamed", "unobserved-staged"}, func(t *testing.T, mode string) {
		s, o, dir, m, parts := sourceBundleScene(t, 1, false)
		cause := errors.New("rename observation")
		if mode != "staging" {
			o.ops.namespace = renameSourceFault(t, cause, mode != "unobserved-staged", mode != "renamed")
			o.ops.remove = func(_ *os.Root, name string) error { return os.Remove(filepath.Join(dir, sourceDirectory, name)) }
			sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
			sourceFailIf(t, o.debt.name == "" || !o.debt.held(), "ambiguous publication debt: %+v", o.debt)
			count := map[bool]int{true: 1, false: 2}[mode == "unobserved-staged"]
			sourceFailIf(t, len(sourceEntries(t, dir)) != count, "ambiguous publication lost backing or staging")
		} else {
			sourceMust(t, os.WriteFile(filepath.Join(dir, sourceDirectory, ".staging-"+m.name(o.id)), []byte{1, 2, 3}, 0o600))
		}
		if mode == "unobserved-renamed" || mode == "unobserved-staged" {
			o.ops = realSourceFS
			sourcePrepareAndRead(t, o, m, parts)
			sourceFailIf(t, len(sourceEntries(t, dir)) != 1, "same identity retry retained staging")
		}
		fresh := sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		if mode == "staging" || mode == "renamed" {
			sourceReadRefusal(t, fresh, m, ErrBusyV1, "staging owner readback")
			sourcePrepareRefusal(t, fresh, sourceForeign(m), parts, ErrBusyV1)
		}
		sourcePrepareAndRead(t, fresh, m, parts)
	})
	sourceModes(t, []string{"occupied", "scan-limit", "unavailable"}, testSourcePreLinkSlot)
	sourceModes(t, []string{"during-link", "final-reuse", "pre-link-prefix-case", "final-prefix-case"}, testSourceIncomingStage)
	sourceModes(t, []string{"final-slot", "producer-error", "producer-panic"}, testSourcePendingBinding)
	sourceModes(t, []string{"foreign-file", "foreign-short", "foreign-shape"}, testSourceIndeterminateBinding)
	sourceModes(t, []string{"held-only", "held-alias", "legacy-public"}, testSourceStageRestart)
	sourceModes(t, []string{"upper-held", "extra-held", "shared-collision", "distinct-collision"}, testSourceStageRestartRefusal)
	sourceModes(t, []string{"before-restore", "after-restore", "restore-sync"}, testSourceStageRestoreFault)
	t.Run("restore-ambiguous", testSourceRestoredStageCensus)
	t.Run("descriptor-budget", testSourceStageDescriptorBudget)
	t.Run("charged-logical-names", testSourceChargedLogicalNames)
	t.Run("grown-pending-backing", testSourceGrownPendingBacking)
	sourceModes(t, []string{"foreign-with-held", "foreign-with-pending", "foreign-with-small-alias", "foreign-with-large-alias"}, testSourceForeignBackingCharge)
	t.Run("clean-reopen-occupancy", testSourceCleanReopenOccupancy)
	sourceModes(t, []string{"release-file-cap", "release-byte-cap", "release-file-cap-present", "release-byte-cap-present", "release-file-cap-direct", "release-byte-cap-direct", "release-independent-file-cap", "release-independent-byte-cap"}, testSourceReleaseStageCharge)
	sourceModes(t, []string{"release-issued-size", "issued-size-pin-cap"}, testSourceIssuedSizePriority)
	sourceModes(t, []string{"issued-name-file-cap", "issued-name-pin-cap"}, testSourceIssuedNamePriority)
	sourceModes(t, []string{"prepare-observed-stage", "read-observed-stage", "prepare-observed-bytes", "read-observed-bytes"}, testSourceRefusedStageObservation)
	sourceModes(t, []string{"prepare-second-stage", "read-second-stage", "prepare-malformed-stage", "read-malformed-stage"}, testSourceRefusedStageShape)
	sourceModes(t, []string{"prepare-stage-order", "read-stage-order", "release-stage-order", "bytes-before-second-stage", "invalid-name-before-second-stage", "active-stage-order", "active-stage-bytes"}, testSourceStageRefusalOrder)
	sourceModes(t, []string{"ordinary-prepare", "ordinary-read", "ordinary-release", "ordinary-open", "ordinary-open-alias"}, testSourceOrdinaryRefusalOrder)
	sourceModes(t, []string{"unissued-with-stage", "unissued-release-order"}, testSourceUnissuedRefusalOrder)
	sourceModes(t, []string{"observed-same-inode", "observed-replacement"}, testSourceObservedStageCustody)
	sourceModes(t, []string{"witness-retained", "witness-replaced", "witness-close", "witness-producer", "disjoint-four", "disjoint-first-four"}, testSourceStageWitness)
	sourceModes(t, []string{"witness-malformed-alias", "witness-malformed-cross-key", "witness-malformed-separate"}, testSourcePartialAliasWitness)
	sourceModes(t, []string{"witness-grown-files", "witness-grown-bytes"}, testSourceGrownAliasWitness)
	sourceModes(t, []string{"release-missing-backing", "release-without-stage-pin", "release-with-funded-stage", "release-with-unreadable-stage"}, testSourceReleaseStageCompatibility)
}

func testSourceIndeterminateBinding(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Bytes = 2*size + 1
	_, o, paths := sourceCaptureScene(t, limits, m)
	anchor := sourceForeign(m)
	if mode == "foreign-short" {
		sourcePrepare(t, o, anchor, parts)
	}
	cause := errors.New("publication observation stopped")
	o.ops.namespace = renameSourceFault(t, cause, false, true)
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
	o.ops = realSourceFS
	expected := o.live[paths.key]
	sourceFailIf(t, expected == nil || !expected.uncertain || expected.issued, "indeterminate publication lost its qualified binding")
	before, original := sourceLstat(t, paths.held), sourceReadFile(t, paths.held)
	want := ErrIntegrityV1
	switch mode {
	case "foreign-file":
		want = ErrIdentityV1
		sourceMust(t, os.WriteFile(paths.capture, sourceResealed(original, len(m.header(o.id))), 0o600))
		assertSourceReleaseCharge(t, o, m, 2, 2*uint64(len(original)))
	case "foreign-short":
		sourceMust(t, os.WriteFile(paths.capture, []byte{1}, 0o600))
		sourceRead(t, o, anchor, parts)
		assertSourceReleaseCharge(t, o, m, 3, limits.Bytes)
	default:
		sourceMust(t, os.Mkdir(paths.capture, 0o700))
	}
	foreign := sourceLstat(t, paths.capture)
	sourcePrepareRefusal(t, o, m, parts, want)
	sourceUnchangedEntry(t, paths.capture, foreign)
	sourceUnchangedEntry(t, paths.held, before)
	sourceFailIf(t, o.live[paths.key] != expected || !bytes.Equal(sourceReadFile(t, paths.held), original), "refusal changed qualified binding or staged bytes")
	sourceMust(t, os.Remove(paths.capture))
	sourcePrepareAndRead(t, o, m, parts)
}

func testSourceCleanReopenOccupancy(t *testing.T) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Files, limits.Bytes = 1, size
	s, _, paths, original := sourcePreparedScene(t, limits, m, parts)
	fresh := sourceOpen(t, sourceReopenStore(t, s, paths.dir), sourceID(), limits, nil)
	sourceFailIf(t, fresh.stage.File != nil || len(sourceEntries(t, paths.dir)) != 1, "clean reopen retained a staging slot")
	sourcePrepareRefusal(t, fresh, sourceForeign(m), parts, ErrCapacityV1)
	assertSourceReleaseCharge(t, fresh, m, 1, size)
	sourceReleaseResult(t, fresh, original, true, ErrIntegrityV1)
	sourcePrepareAndRead(t, fresh, m, parts)
}

func testSourceStageRestart(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Files, limits.Bytes = 1, size
	s, o, paths := sourceCaptureScene(t, limits, m)
	data := []byte("retained staging bytes")
	held, public := ".stage-hold-"+paths.key, ".staging-"+paths.key
	leaf := held
	var old *PreparedSourceV1
	if mode == "held-alias" {
		old = sourcePrepare(t, o, m, parts)
		data = sourceReadFile(t, paths.capture)
		sourceMust(t, os.Link(paths.capture, paths.held))
	} else {
		if mode == "legacy-public" {
			public = ".staging-" + strings.ToUpper(paths.key)
			leaf = public
		}
		sourceMust(t, os.WriteFile(filepath.Join(paths.root, leaf), data, 0o600))
	}
	original := sourceLstat(t, filepath.Join(paths.root, leaf))
	fresh := sourceOpen(t, sourceReopenStore(t, s, paths.dir), sourceID(), limits, nil)
	sourcePresence(t, paths.root, held, false)
	sourceUnchangedEntry(t, filepath.Join(paths.root, public), original, data)
	testSourceReopenedPin(t, fresh, m, parts, old, public, original, uint64(len(data)))
}

func testSourceReopenedPin(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, old *PreparedSourceV1, public string, original os.FileInfo, charged uint64) {
	t.Helper()
	pin := checkSourcePinned(t, o.stage.File, original)
	sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrBusyV1)
	assertSourceReleaseCharge(t, o, m, 1, charged)
	if old != nil {
		sourceReleaseResult(t, o, old, true, ErrIntegrityV1)
	}
	got := sourcePrepare(t, o, m, parts)
	sourceFailIf(t, old != nil && got.incarnation == old.incarnation, "reopen reused a process-local token")
	checkSourcePinClosed(t, pin, o.stage.File)
	sourcePresence(t, filepath.Join(o.dir, sourceDirectory), public, false)
	sourceRead(t, o, m, parts)
}

func testSourceStageRestartRefusal(t *testing.T, mode string) {
	s, o, dir, m, _ := sourceBundleScene(t, 1, false)
	paths := sourcePaths(dir, m.name(o.id))
	held, other := ".stage-hold-"+paths.key, ".staging-"+paths.key
	if mode == "upper-held" {
		held = ".stage-hold-" + strings.ToUpper(paths.key)
	}
	if mode == "extra-held" {
		other = ".stage-hold-" + sourceForeign(m).name(o.id)
	}
	sourceMust(t, os.WriteFile(filepath.Join(paths.root, held), []byte("held"), 0o600))
	if mode == "shared-collision" {
		sourceMust(t, os.Link(filepath.Join(paths.root, held), filepath.Join(paths.root, other)))
	} else {
		sourceMust(t, os.WriteFile(filepath.Join(paths.root, other), []byte("separate"), 0o600))
	}
	unchanged := sourceHeld(t, o)
	want := map[string]error{"upper-held": ErrIntegrityV1, "extra-held": ErrBusyV1, "shared-collision": syscall.EEXIST, "distinct-collision": syscall.EEXIST}[mode]
	sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), want)
	unchanged("refused stage restore")
}

func testSourceStageRestoreFault(t *testing.T, mode string) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	paths := sourcePaths(dir, m.name(o.id))
	held, public := ".stage-hold-"+paths.key, ".staging-"+paths.key
	originalBytes := []byte("staging before reopening")
	original := writeSourceEntry(t, paths.held, originalBytes)
	s = sourceReopenStore(t, s, dir)
	saved := realSourceFS
	defer func() { realSourceFS = saved }()
	cause := errors.New("restore I/O stopped")
	if mode == "restore-sync" {
		calls := 0
		realSourceFS.dirSync = func(pin *os.File) error {
			calls++
			if calls == 2 {
				return cause
			}
			return pin.Sync()
		}
	} else {
		rename := renameSourceFault(t, cause, mode == "after-restore", false)
		realSourceFS.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			sourceFailIf(t, reflect.ValueOf(op).Pointer() != reflect.ValueOf((*sourceRoot).renameExclusive).Pointer(), "restore did not select exclusive rename")
			sourceFailIf(t, from != held, "restore source is %q, want %q", from, held)
			sourceFailIf(t, to != public, "restore destination is %q, want %q", to, public)
			return rename(op, r, from, to)
		}
	}
	sourceOpen(t, s, sourceID(), sourceLimits(), cause)
	reached := map[bool]string{true: held, false: public}[mode == "before-restore"]
	sourceUnchangedEntry(t, filepath.Join(paths.root, reached), original, originalBytes)
	sourceFailIf(t, len(sourceOpenFileModes(t, original)) != 0, "failed restore retained its descriptor")
	realSourceFS = saved
	fresh := sourceOpen(t, s, sourceID(), sourceLimits(), nil)
	sourceUnchangedEntry(t, filepath.Join(paths.root, public), original)
	sourcePrepareAndRead(t, fresh, m, parts)
}

func testSourceRestoredStageCensus(t *testing.T) {
	s, o, dir, m, _ := sourceBundleScene(t, 1, false)
	paths := sourcePaths(dir, m.name(o.id))
	data := []byte("restored stage")
	original := writeSourceEntry(t, paths.held, data)
	otherKey := strings.ToUpper(paths.key)
	if _, err := os.Lstat(filepath.Join(paths.root, ".stage-hold-"+otherKey)); !errors.Is(err, os.ErrNotExist) {
		sourceMust(t, err)
		otherKey = sourceForeign(m).name(o.id)
	}
	other := filepath.Join(paths.root, ".staging-"+otherKey)
	extra := []byte("separate stage")
	s = sourceReopenStore(t, s, dir)
	saved := realSourceFS
	defer func() { realSourceFS = saved }()
	var incoming os.FileInfo
	syncs := 0
	realSourceFS.dirSync = func(pin *os.File) error {
		syncs++
		if syncs == 2 {
			sourceUnchangedEntry(t, paths.stage, original)
			incoming = writeSourceEntry(t, other, extra)
		}
		return pin.Sync()
	}
	sourceOpen(t, s, sourceID(), sourceLimits(), ErrBusyV1)
	sourceFailIf(t, syncs != 2 || incoming == nil, "restored-stage validation reached %d directory syncs", syncs)
	sourcePresence(t, paths.root, filepath.Base(paths.held), false)
	sourceUnchangedEntry(t, paths.stage, original, data)
	sourceUnchangedEntry(t, other, incoming, extra)
	sourceFailIf(t, len(sourceOpenFileModes(t, original)) != 0, "refused restoration retained the stage pin")
}

func testSourceStageDescriptorBudget(t *testing.T) {
	m, parts, limits := sourceBundleLimits()
	limits.Descriptors = 4
	s, o, paths, _ := sourcePreparedScene(t, limits, m, parts)
	sourceRead(t, o, m, parts)
	original := writeSourceEntry(t, paths.stage, []byte("stage"))
	sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	fresh := sourceReopenStore(t, s, paths.dir)
	sourceOpen(t, fresh, sourceID(), limits, ErrCapacityV1)
	sourceUnchangedEntry(t, paths.stage, original)
	limits.Descriptors = 5
	owner := sourceOpen(t, fresh, sourceID(), limits, nil)
	pin := checkSourcePinned(t, owner.stage.File, original)
	sourcePrepareAndRead(t, owner, m, parts)
	checkSourcePinClosed(t, pin, owner.stage.File)
}

func testSourceChargedLogicalNames(t *testing.T) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Files, limits.Bytes = 3, 2*size
	_, o, paths := sourceCaptureScene(t, limits, m)
	alias := filepath.Join(paths.root, sourceForeign(m).name(o.id))
	sourceLeaveUnissued(t, o, m, parts, paths.stage, []byte{1})
	original := sourceReadFile(t, paths.capture)
	sourceMust(t, os.Link(paths.capture, alias))
	sourceMust(t, os.Truncate(paths.capture, 1))
	sourceFault(o, "statfs", ErrCapacityV1, func() { t.Fatal("one-byte quota overrun reached disk admission") })
	sourcePrepareRefusal(t, o, sourceForeign(sourceForeign(m)), parts, ErrCapacityV1)
	checkSourceAliasCharge(t, o, size+1, false)
	sourceMust(t, os.Remove(alias))
	sourceMust(t, os.WriteFile(paths.capture, original, 0o600))
	sourceRetryAfterFault(t, o, m, parts)
}

func checkSourceAliasCharge(t *testing.T, o *SourceOwnerV1, size uint64, foreignAlias bool) {
	t.Helper()
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		for range 2 {
			used, err := o.censusFiles(r, entries, false)
			sourceMust(t, used.admissionError(err))
			sourceFailIf(t, used.files != 2 || used.bytes != size, "census charged %d files/%d bytes, want 2/%d", used.files, used.bytes, size)
			sourceFailIf(t, foreignAlias && used.stage.binding != nil, "foreign alias inherited the qualified capture")
			slices.Reverse(entries)
		}
	})
}

func testSourceGrownPendingBacking(t *testing.T) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Files, limits.Bytes = 2, 2*size
	_, o, paths := sourceCaptureScene(t, limits, m)
	cause := errors.New("publication directory sync stopped")
	sourceFault(o, "parent-sync", cause, nil)
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
	sourceMust(t, o.withRoot(o.bindRoot, func(r *sourceRoot) error { return o.syncStageRemoval(r, false) }))
	bound := o.live[paths.key]
	info := sourceLstat(t, paths.capture)
	sourceFailIf(t, bound == nil || bound.issued || bound.size != size || bound.file != filelock.FileIdentityV1(info), "fixture lacks its qualified publication")
	expected := *bound
	sourceMust(t, os.Truncate(paths.capture, int64(limits.Bytes)))
	data := sourceReadFile(t, paths.capture)
	sourceFault(o, "statfs", ErrCapacityV1, func() { t.Fatal("logical capacity refusal reached physical admission") })
	sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrCapacityV1)
	assertSourceReleaseCharge(t, o, m, 1, limits.Bytes)
	sourceFailIf(t, o.live[paths.key] != bound || *bound != expected, "census changed the original backing proof")
	sourceUnchangedEntry(t, paths.capture, info, data)
}

func testSourceForeignBackingCharge(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	extent := map[bool]uint64{false: 1, true: size + 1}[mode == "foreign-with-large-alias"]
	limits.Files, limits.Bytes = 2, size+extent
	_, o, paths := sourceCaptureScene(t, limits, m)
	retirement := map[string]string{"foreign-with-held": "unlink", "foreign-with-pending": "parent-sync"}[mode]
	cause := errors.New("retained stage retirement stopped")
	if retirement != "" {
		sourceFault(o, retirement, cause, nil)
		sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
	} else {
		sourceLeaveUnissued(t, o, m, parts, paths.stage, nil)
	}
	saved, binding := filepath.Join(paths.dir, "retained-file"), o.live[paths.key]
	sourceMust(t, os.Rename(paths.capture, saved))
	original, data := sourceLstat(t, saved), bytes.Repeat([]byte{1}, int(extent))
	sourceFailIf(t, binding == nil || binding.file != filelock.FileIdentityV1(original) || binding.size != size, "retirement lost the qualified capture")
	foreign := writeSourceEntry(t, paths.capture, data)
	held := retirement == "unlink"
	if !held {
		sourceMust(t, os.Link(paths.capture, paths.stage))
	}
	checkSourceAliasCharge(t, o, size+extent, !held)
	sourceReadRefusal(t, o, sourceForeign(m), ErrUnavailableV1, "disjoint read beside foreign backing")
	if !held {
		sourceUnchangedEntry(t, paths.stage, foreign, data)
		sourceMust(t, os.Remove(paths.stage))
	}
	sourceUnchangedEntry(t, paths.capture, foreign, data)
	sourceMust(t, os.Rename(saved, paths.capture))
	sourceRetryAndRead(t, o, m, parts, binding)
}

func testSourceReleaseStageCharge(t *testing.T, mode string) {
	m, parts, limits := sourceBundleLimits()
	if strings.Contains(mode, "file-cap") {
		limits.Files = 1
	} else {
		limits.Bytes = sourceSize(t, m)
	}
	_, o, paths, p := sourcePreparedScene(t, limits, m, parts)
	original, data := sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
	if strings.Contains(mode, "-independent-") {
		separate := writeSourceEntry(t, paths.stage, []byte{1})
		keep := sourceHeld(t, o)
		checkSourceReleaseRefusal(t, o, p, ErrBusyV1)
		keep("independent same-key stage refused release")
		sourceUnchangedEntry(t, paths.stage, separate, []byte{1})
		sourceUnchangedEntry(t, paths.capture, original, data)
		sourceAbsent(t, paths.root, releaseFile, releaseScratch, releaseDetached)
		return
	}
	sourceMust(t, os.Link(paths.capture, paths.stage))
	sourceReadRefusal(t, o, m, ErrBusyV1, "readback with a same-key alias")
	pin := checkSourcePinned(t, o.stage.File, original)
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(data)))
	if strings.HasSuffix(mode, "-present") {
		reused := sourcePrepare(t, o, m, parts)
		sourceFailIf(t, reused.incarnation != p.incarnation, "alias cleanup replaced the issued incarnation")
		sourcePresence(t, paths.root, filepath.Base(paths.stage), false)
		checkSourcePinClosed(t, pin, o.stage.File)
		sourceRead(t, o, m, parts)
		sourceReleaseResult(t, o, p, true, nil)
		return
	}
	if !strings.HasSuffix(mode, "-direct") {
		sourceMust(t, os.Remove(paths.stage))
	}
	sourceReleaseResult(t, o, p, true, nil)
	sourceAbsent(t, paths.root, p.name, filepath.Base(paths.stage), heldStagePrefix+p.name, releaseFile, releaseScratch, releaseDetached)
	checkSourcePinClosed(t, pin, o.stage.File)
	assertSourceReleaseCharge(t, o, m, 0, 0)
	sourcePrepareAndRead(t, o, sourceForeign(m), parts)
}

func testSourceIssuedSizePriority(t *testing.T, mode string) {
	m, parts, limits := sourceBundleLimits()
	var censusWant error
	if mode == "release-issued-size" {
		limits.Files = 1
		censusWant = ErrCapacityV1
	} else {
		limits.Files, limits.Descriptors = 2, 4
	}
	_, o, paths, p := sourcePreparedScene(t, limits, m, parts)
	original, image := sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
	sourceMust(t, os.Truncate(paths.capture, original.Size()-1))
	stage := ".staging-" + p.name
	independent := writeSourceEntry(t, paths.stage, []byte{1})
	checkSourceReleaseCensusOrder(t, o, stage, uint64(original.Size()), censusWant)
	before := sourceHeld(t, o)
	sourcePrepareRefusal(t, o, m, parts, ErrIntegrityV1)
	sourceReadRefusal(t, o, m, ErrIntegrityV1, "issued backing size")
	before("issued backing admission")
	checkSourceReleaseRefusal(t, o, p, ErrBusyV1)
	before("size refusal with independent same-key stage")
	sourceAbsent(t, paths.root, releaseFile, releaseScratch)
	sourceUnchangedEntry(t, paths.capture, original, image[:len(image)-1])
	sourceUnchangedEntry(t, paths.stage, independent, []byte{1})
}

func testSourceIssuedNamePriority(t *testing.T, mode string) {
	m, parts, limits := sourceBundleLimits()
	limits.Files, limits.Descriptors = 2, 4
	var censusWant error
	absentWant := ErrIntegrityV1
	if mode == "issued-name-file-cap" {
		limits.Files = 1
		censusWant, absentWant = ErrCapacityV1, ErrCapacityV1
	}
	_, o, paths, p := sourcePreparedScene(t, limits, m, parts)
	displaced := filepath.Join(paths.dir, "retained-file")
	original := sourceLstat(t, paths.capture)
	sourceMust(t, os.WriteFile(paths.stage, []byte{1}, 0o600))
	t.Run("present", func(t *testing.T) {
		checkSourceStageAdmission(t, o, m, parts, censusWant, ErrCapacityV1)
	})
	sourceMust(t, os.Rename(paths.capture, displaced))
	t.Run("absent", func(t *testing.T) {
		checkSourceStageAdmission(t, o, m, parts, censusWant, absentWant)
	})
	sourceMust(t, os.Rename(displaced, paths.capture))
	sourceUnchangedEntry(t, paths.capture, original)
	sourceMust(t, os.Remove(paths.stage))
	sourceRetryAndRead(t, o, m, parts, p.incarnation)
}

func checkSourceStageAdmission(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, censusWant, want error) {
	t.Helper()
	before := sourceHeld(t, o)
	sourceMust(t, o.withRoot(o.bindRoot, func(r *sourceRoot) error {
		_, err := o.census(r, false)
		sourceWantError(t, err, censusWant, "logical stage admission")
		return nil
	}))
	sourcePrepareRefusal(t, o, m, parts, want)
	sourceReadRefusal(t, o, m, want, "readback with independent stage")
	sourceFailIf(t, o.stage.File != nil, "refused source admission retained a stage pin")
	before("independent stage admission")
}

func checkSourceReleaseCensusOrder(t *testing.T, o *SourceOwnerV1, stage string, size uint64, censusWant error) bool {
	t.Helper()
	wantFiles, wantBytes := uint64(2), size+1
	var stageFirst bool
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		sourceFailIf(t, len(entries) != 2, "release census fixture has %d entries, want 2", len(entries))
		stageFirst = entries[0].Name() == stage
		for range 2 {
			used, err := o.censusFiles(r, entries, false)
			sourceWantError(t, err, censusWant, "logical stage charge")
			sourceWantError(t, used.admissionError(err), ErrIntegrityV1, "observed issued backing size")
			sourceFailIf(t, used.files != wantFiles || used.bytes != wantBytes, "census retained %d files/%d bytes, want %d/%d", used.files, used.bytes, wantFiles, wantBytes)
			visited := entries[0].Name() == stage
			sourceFailIf(t, used.stageReached != visited, "stage visited before mismatch = %t, want %t", used.stageReached, visited)
			release, err := o.censusFiles(r, entries, true)
			sourceWantError(t, err, censusWant, "release file capacity")
			sourceWantError(t, release.admissionError(err), ErrIntegrityV1, "observed issued backing size at release")
			sourceFailIf(t, release.files != 2 || release.bytes != size || release.stageReached != visited,
				"release census counted %d files/%d bytes, visited stage %t", release.files, release.bytes, release.stageReached)
			slices.Reverse(entries)
		}
	})
	return stageFirst
}

func testSourceRefusedStageObservation(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	switch mode {
	case "prepare-observed-bytes":
		limits.Bytes = size + 1
	case "read-observed-bytes":
		limits.Bytes = 2 * size
	default:
		limits.Files = 2
	}
	_, o, paths, p := sourcePreparedScene(t, limits, m, parts)
	original, image := sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
	extra := sourceForeign(m).name(o.id)
	sourceMust(t, os.WriteFile(filepath.Join(paths.root, extra), image, 0o600))
	sourceMust(t, os.WriteFile(paths.stage, []byte{1}, 0o600))
	visited := checkSourceRefusedVisitOrder(t, o, p.name, extra, filepath.Base(paths.stage), mode == "prepare-observed-bytes")
	if strings.HasPrefix(mode, "prepare-") {
		sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	} else {
		sourceReadRefusal(t, o, m, ErrCapacityV1, "observed independent stage")
	}
	sourceMust(t, os.Remove(filepath.Join(paths.root, extra)))
	if visited {
		sourceKeyOnlyRetry(t, o, m, parts)
	}
	sourceMust(t, os.Remove(paths.stage))
	reachedLeaf := ""
	if visited {
		reachedLeaf = filepath.Base(paths.stage)
	}
	checkSourceReleaseAfterScan(t, o, p, reachedLeaf)
	if visited {
		sourceUnchangedEntry(t, paths.capture, original, image)
		sourceRetryAndRead(t, o, m, parts, p.incarnation)
		sourceReleaseResult(t, o, p, true, nil)
	}
}

func checkSourceReleaseAfterScan(t *testing.T, o *SourceOwnerV1, p *PreparedSourceV1, reachedLeaf string) {
	t.Helper()
	if reachedLeaf == publicStagePrefix+p.name {
		checkSourceReleaseRefusal(t, o, p, ErrBusyV1)
		return
	}
	sourceReleaseResult(t, o, p, true, nil)
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
}

func checkSourceReleaseRefusal(t *testing.T, o *SourceOwnerV1, p *PreparedSourceV1, want error) {
	t.Helper()
	statfs := o.ops.statfs
	sourceFault(o, "statfs", ErrCapacityV1, func() { t.Fatal("refused release reached marker admission") })
	sourceReleaseResult(t, o, p, true, want)
	o.ops.statfs = statfs
}

func checkSourceRefusedVisitOrder(t *testing.T, o *SourceOwnerV1, backing, extra, stage string, earlyByteRefusal bool) bool {
	t.Helper()
	var visited bool
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		observed := sourceEntriesByName(entries)
		stagePosition := slices.IndexFunc(entries, func(entry os.DirEntry) bool { return entry.Name() == stage })
		sourceFailIf(t, len(entries) != 3 || stagePosition < 0, "observed stage fixture has an unexpected directory listing")
		visited = !earlyByteRefusal || stagePosition < 2
		for _, order := range [][3]string{{extra, stage, backing}, {backing, extra, stage}} {
			used, err := o.censusFiles(r, []os.DirEntry{observed[order[0]], observed[order[1]], observed[order[2]]}, false)
			sourceWantError(t, err, ErrCapacityV1, "independent objects exceed logical capacity")
			want := !earlyByteRefusal || order[1] == stage
			sourceFailIf(t, used.stageReached != want, "directory order %v visited stage %t, want %t", order, used.stageReached, want)
		}
	})
	return visited
}

func testSourceRefusedStageShape(t *testing.T, mode string) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	root := filepath.Join(dir, sourceDirectory)
	stage, other := ".staging-"+p.name, ".staging-"+sourceForeign(m).name(o.id)
	want := ErrBusyV1
	if strings.HasSuffix(mode, "malformed-stage") {
		other, want = ".staging-invalid", ErrIntegrityV1
	}
	sourceMust(t, os.WriteFile(filepath.Join(root, stage), []byte{1}, 0o600))
	sourceMust(t, os.WriteFile(filepath.Join(root, other), []byte{2}, 0o600))
	reachedLeaf := checkSourceStageShapeOrder(t, o, stage, other, want)
	if strings.HasPrefix(mode, "prepare-") {
		sourcePrepareRefusal(t, o, m, parts, want)
	} else {
		sourceReadRefusal(t, o, m, want, "refused staging shape")
	}
	sourceMust(t, os.Remove(filepath.Join(root, stage)))
	sourceMust(t, os.Remove(filepath.Join(root, other)))
	checkSourceReleaseAfterScan(t, o, p, reachedLeaf)
}

func checkSourceStageShapeOrder(t *testing.T, o *SourceOwnerV1, stage, other string, want error) string {
	t.Helper()
	var reachedLeaf string
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		first := slices.IndexFunc(entries, func(entry os.DirEntry) bool { return entry.Name() == stage })
		second := slices.IndexFunc(entries, func(entry os.DirEntry) bool { return entry.Name() == other })
		sourceFailIf(t, len(entries) != 3 || first < 0 || second < 0, "staging shape fixture has an unexpected directory listing")
		if any(want) == any(ErrBusyV1) || first < second {
			reachedLeaf = entries[min(first, second)].Name()
		}
		order := slices.Clone(entries)
		for i := range 2 {
			expectedStage := order[min(first, second)].Name()
			wantReached := any(want) == any(ErrBusyV1) || expectedStage == stage
			used, err := o.censusFiles(r, order, false)
			sourceWantError(t, err, want, "refused staging shape in directory order")
			sourceFailIf(t, used.stageReached != wantReached || wantReached && used.stage.leaf != expectedStage,
				"staging shape order %d observed stage %q with visitation %t, want %q/%t", i, used.stage.leaf, used.stageReached, expectedStage, wantReached)
			order[first], order[second] = order[second], order[first]
		}
	})
	return reachedLeaf
}

func testSourceStageRefusalOrder(t *testing.T, mode string) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	root := filepath.Join(dir, sourceDirectory)
	name, want := "invalid-entry", ErrIntegrityV1
	active := strings.HasPrefix(mode, "active-")
	stages := [2]string{publicStagePrefix + m.name(o.id), publicStagePrefix + sourceForeign(m).name(o.id)}
	if active {
		path := filepath.Join(root, stages[0])
		sourceMust(t, os.WriteFile(path, []byte{1}, 0o600))
		sourcePrepareResult(t, o, sourceForeign(m), refusedSourceProducer(t), ErrBusyV1)
		sourceMust(t, os.Rename(path, filepath.Join(dir, "active-stage")))
		stages = [2]string{stages[1], ".staging-invalid"}
	}
	var p *PreparedSourceV1
	switch mode {
	case "bytes-before-second-stage", "active-stage-bytes":
		name, want = m.name(o.id), ErrCapacityV1
	case "invalid-name-before-second-stage", "active-stage-order":
	default:
		p = sourcePrepare(t, o, m, parts)
		name, want = p.name, ErrIdentityV1
	}
	path, displaced := filepath.Join(root, name), filepath.Join(dir, "retained-file")
	var original os.FileInfo
	if p == nil {
		sourceMust(t, os.WriteFile(path, nil, 0o600))
		if errors.Is(want, ErrCapacityV1) {
			sourceMust(t, os.Truncate(path, int64(o.limits.Bytes)+1))
		}
	} else {
		original = sourceLstat(t, path)
		image := sourceReadFile(t, path)
		sourceMust(t, os.Rename(path, displaced))
		sourceMust(t, os.WriteFile(path, image, 0o600))
		sourceFailIf(t, os.SameFile(original, sourceLstat(t, path)), "replacement shares the original inode")
	}
	for _, stage := range stages {
		sourceMust(t, os.WriteFile(filepath.Join(root, stage), []byte{1}, 0o600))
	}
	reachedLeaf, want := checkSourceStageRefusalOrder(t, o, name, stages, want)
	if p == nil {
		sourcePrepareRefusal(t, o, m, parts, want)
		return
	}
	switch mode {
	case "prepare-stage-order":
		sourcePrepareRefusal(t, o, m, parts, want)
	case "read-stage-order":
		sourceReadRefusal(t, o, m, want, "capture and staging order")
	case "release-stage-order":
		checkSourceReleaseRefusal(t, o, p, ErrBusyV1)
		reachedLeaf = ""
	}
	sourceAbsent(t, root, releaseFile, releaseScratch)
	for _, stage := range stages {
		sourceMust(t, os.Remove(filepath.Join(root, stage)))
	}
	sourceMust(t, os.Remove(path))
	sourceMust(t, os.Rename(displaced, path))
	sourceUnchangedEntry(t, path, original)
	checkSourceReleaseAfterScan(t, o, p, reachedLeaf)
}

func testSourceOrdinaryRefusalOrder(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Bytes = size
	s, o, paths, p := sourcePreparedScene(t, limits, m, parts)
	stage, bad := publicStagePrefix+p.name, "invalid-entry"
	aliased := mode == "ordinary-open-alias"
	if aliased {
		sourceMust(t, os.Link(paths.capture, paths.stage))
	} else {
		sourceMust(t, os.WriteFile(paths.stage, []byte{1}, 0o600))
	}
	sourceMust(t, os.WriteFile(filepath.Join(paths.root, bad), nil, 0o600))
	want := ErrIntegrityV1
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		sourceFailIf(t, len(entries) != 3, "ordinary order fixture has %d entries", len(entries))
		if entries[2].Name() == bad && !aliased {
			want = ErrCapacityV1
		}
		checkSourceOrdinaryOrders(t, o, r, entries, p.name, stage, bad, aliased)
	})
	before := sourceHeld(t, o)
	switch mode {
	case "ordinary-prepare":
		sourcePrepareRefusal(t, o, m, parts, want)
	case "ordinary-read":
		sourceReadRefusal(t, o, m, want, "ordinary file refusal")
	case "ordinary-release":
		checkSourceReleaseRefusal(t, o, p, ErrBusyV1)
	default:
		sourceOpen(t, sourceReopenStore(t, s, paths.dir), sourceID(), limits, want)
	}
	before("ordinary census refusal")
}

func checkSourceOrdinaryOrders(t *testing.T, o *SourceOwnerV1, r *sourceRoot, entries []os.DirEntry, backing, stage, bad string, aliased bool) {
	t.Helper()
	byName := sourceEntriesByName(entries)
	for _, order := range [][3]string{{backing, stage, bad}, {stage, backing, bad}, {bad, backing, stage}} {
		for _, release := range []bool{false, true} {
			want := ErrIntegrityV1
			if order[0] != bad && (!aliased || release) {
				want = ErrCapacityV1
			}
			ordered := []os.DirEntry{byName[order[0]], byName[order[1]], byName[order[2]]}
			used, err := o.censusFiles(r, ordered, release)
			sourceWantError(t, err, want, "first ordinary census refusal")
			sourceWantError(t, used.admissionError(err), want, "first ordinary admission refusal")
		}
	}
}

func testSourceUnissuedRefusalOrder(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Files, limits.Bytes = 2, 2*size
	_, o, paths, issued := sourcePreparedScene(t, limits, m, parts)
	retained := sourceForeign(m)
	u, x := retained.name(o.id), sourceForeign(retained).name(o.id)
	sourceLeaveUnissued(t, o, retained, parts, filepath.Join(paths.root, publicStagePrefix+u), nil)
	sourceMust(t, os.WriteFile(filepath.Join(paths.root, x), nil, 0o600))
	sourceMust(t, os.Truncate(filepath.Join(paths.root, x), int64(size)+1))
	release := mode == "unissued-release-order"
	other := publicStagePrefix + x
	if release {
		other = "invalid-entry"
	} else {
		sourceMust(t, os.Truncate(filepath.Join(paths.root, u), 1))
	}
	sourceMust(t, os.WriteFile(filepath.Join(paths.root, other), []byte{1}, 0o600))
	want, reached := checkSourceUnissuedRefusalOrder(t, o, [4]string{u, x, other, issued.name}, release)
	if release {
		before := sourceHeld(t, o)
		checkSourceReleaseRefusal(t, o, issued, want)
		before("release prefix refusal")
		sourceAbsent(t, paths.root, releaseFile, releaseScratch)
		return
	}
	sourceReadRefusal(t, o, m, ErrCapacityV1, "shortened unissued capture charge")
	sourceMust(t, os.Remove(filepath.Join(paths.root, x)))
	sourceMust(t, os.Remove(filepath.Join(paths.root, other)))
	reachedLeaf := ""
	if reached {
		reachedLeaf = other
	}
	checkSourceReleaseAfterScan(t, o, issued, reachedLeaf)
}

func checkSourceUnissuedRefusalOrder(t *testing.T, o *SourceOwnerV1, names [4]string, release bool) (want error, reached bool) {
	t.Helper()
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		byName := sourceEntriesByName(entries)
		u, x, other, issued := byName[names[0]], byName[names[1]], byName[names[2]], byName[names[3]]
		before := func(entry os.DirEntry) bool { return slices.Index(entries, entry) < slices.Index(entries, other) }
		beforeLimit := before(x) && (before(u) || before(issued))
		want, reached = ErrCapacityV1, !beforeLimit
		early := ErrCapacityV1
		order := []os.DirEntry{other, u, x, issued}
		if release {
			if reached {
				want = ErrIntegrityV1
			}
			early = ErrIntegrityV1
			order = []os.DirEntry{x, other, u, issued}
		}
		used, err := o.censusFiles(r, order, release)
		sourceWantError(t, used.admissionError(err), early, "first reached release or stage result")
		sourceFailIf(t, used.stageReached == release, "first stage eligibility is wrong")
		used, err = o.censusFiles(r, []os.DirEntry{u, x, other, issued}, release)
		sourceWantError(t, used.admissionError(err), ErrCapacityV1, "reached unissued charge")
		sourceFailIf(t, used.stageReached, "byte refusal reached a later stage")
	})
	return want, reached
}

func checkSourceStageRefusalOrder(t *testing.T, o *SourceOwnerV1, bad string, stages [2]string, firstErr error) (string, error) {
	t.Helper()
	var reachedLeaf string
	want := ErrBusyV1
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		observation := sourceEntriesByName(entries)
		sourceFailIf(t, len(entries) != 3 || observation[bad] == nil || observation[stages[0]] == nil || observation[stages[1]] == nil,
			"stage order fixture has an unexpected directory listing")
		if entries[0].Name() != bad {
			reachedLeaf = entries[0].Name()
		}
		if entries[2].Name() != bad {
			want = firstErr
		}
		captureFirst := []os.DirEntry{observation[bad], observation[stages[0]], observation[stages[1]]}
		stagesFirst := []os.DirEntry{observation[stages[0]], observation[stages[1]], observation[bad]}
		for _, release := range []bool{false, true} {
			used, err := o.censusFiles(r, captureFirst, release)
			sourceWantError(t, used.admissionError(err), firstErr, "first physical capture refusal")
			sourceFailIf(t, used.stageReached, "stage observed after an earlier physical refusal")
			used, err = o.censusFiles(r, stagesFirst, release)
			sourceWantError(t, used.admissionError(err), ErrBusyV1, "first staging refusal")
			sourceFailIf(t, used.stageReached != (o.debt.name == "") || used.stage.leaf != stages[0], "first staging observation was wrong")
		}
		if o.debt.name != "" {
			_, err := o.censusFiles(r, []os.DirEntry{stagesFirst[0], captureFirst[0]}, false)
			sourceWantError(t, err, ErrBusyV1, "active key before ordinary error")
			_, err = o.censusFiles(r, captureFirst[:1], false)
			sourceWantError(t, err, firstErr, "ordinary error before missing active stage")
			_, err = o.censusFiles(r, nil, false)
			sourceWantError(t, err, ErrIdentityV1, "missing active stage")
			want = map[string]error{bad: firstErr, stages[0]: ErrBusyV1, stages[1]: ErrIntegrityV1}[entries[0].Name()]
		}
	})
	return reachedLeaf, want
}

func testSourceObservedStageCustody(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Bytes = size + 1
	_, o, paths, _ := sourcePreparedScene(t, limits, m, parts)
	original := writeSourceEntry(t, paths.stage, []byte{1, 2})
	sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	if mode == "observed-replacement" {
		sourceMust(t, os.Rename(paths.stage, filepath.Join(paths.dir, "previous-stage")))
	}
	current := writeSourceEntry(t, paths.stage, []byte{3})
	sourceFailIf(t, os.SameFile(original, current) != (mode == "observed-same-inode"), "stage fixture has the wrong identity")
	sourceKeyOnlyRetry(t, o, m, parts)
	sourceUnchangedEntry(t, paths.stage, current, []byte{3})
	sourceMust(t, os.Remove(paths.stage))
	sourceRetryAfterFault(t, o, m, parts)
}

func testSourceStageWitness(t *testing.T, mode string) {
	first, parts, size, limits := sourceSizedBundle(t)
	second := sourceForeign(first)
	limits.Files, limits.Bytes = 3, 2*size+1
	if strings.HasSuffix(mode, "-four") {
		limits.Descriptors = 4
	}
	s, o, paths, p := sourcePreparedScene(t, limits, first, parts)
	sourcePrepare(t, o, second, parts)
	leaf := ".staging-" + p.name
	data := []byte{1}
	original := writeSourceEntry(t, paths.stage, data)
	if mode == "disjoint-four" {
		extra := filepath.Join(paths.root, sourceForeign(second).name(o.id))
		sourceMust(t, os.WriteFile(extra, nil, 0o600))
		sourcePrepareRefusal(t, o, first, parts, ErrCapacityV1)
		sourceMust(t, os.Remove(extra))
	}
	sourceRead(t, o, second, parts)
	if limits.Descriptors == 4 {
		sourceFailIf(t, o.stage.File != nil || o.observedStage != p.name, "disjoint read lost the unpinned staging observation")
		if mode == "disjoint-four" {
			sourceUnchangedEntry(t, paths.stage, original)
			sourcePrepareRefusal(t, o, first, parts, ErrCapacityV1)
		}
		sourceMust(t, os.Remove(paths.stage))
		checkSourceReleaseRefusal(t, o, p, ErrBusyV1)
		sourceRead(t, o, second, parts)
		return
	}
	pin := checkSourceStageWitness(t, o, original)
	if mode == "witness-producer" {
		cause := errors.New("producer stopped after retiring observed stage")
		produce := sourceAfterFirstPart(first, parts, func() error {
			sourcePresence(t, paths.root, leaf, false)
			checkSourcePinClosed(t, pin, o.stage.File)
			return cause
		})
		sourcePrepareResult(t, o, first, produce, cause)
		sourceRead(t, o, first, parts)
		sourceReleaseResult(t, o, p, true, nil)
		return
	}
	if mode == "witness-close" {
		sourceMust(t, s.Close())
		checkSourcePinClosed(t, pin, o.stage.File)
		sourceUnchangedEntry(t, paths.stage, original)
		return
	}
	if mode == "witness-replaced" {
		previous := filepath.Join(paths.dir, "previous-stage")
		sourceMust(t, os.Rename(paths.stage, previous))
		replacement := writeSourceEntry(t, paths.stage, data)
		sourceRead(t, o, second, parts)
		checkSourcePinClosed(t, pin, o.stage.File)
		sourceFault(o, "rename", ErrIdentityV1, func() { t.Fatal("replacement reached namespace mutation after witness retirement") })
		sourcePrepareRefusal(t, o, first, parts, ErrIdentityV1)
		sourceUnchangedEntry(t, paths.stage, replacement)
		checkSourceReleaseRefusal(t, o, p, ErrBusyV1)
		sourceMust(t, os.Remove(paths.stage))
		sourceRetryAfterFault(t, o, first, parts)
		sourceUnchangedEntry(t, previous, original, data)
		return
	}
	sourceRead(t, o, second, parts, func() {
		sourceWantError(t, s.Close(), policycontrol.ErrBusy, "close during disjoint read")
		sourceFailIf(t, checkSourceStageWitness(t, o, original) != pin, "refused close replaced the staging witness")
	})
	sourceUnchangedEntry(t, paths.stage, original, data)
	reused := sourcePrepare(t, o, first, parts)
	sourceFailIf(t, reused.incarnation != p.incarnation, "funded witness did not preserve the issued incarnation")
	checkSourcePinClosed(t, pin, o.stage.File)
	sourcePresence(t, paths.root, leaf, false)
	sourceRead(t, o, first, parts)
	sourceReleaseResult(t, o, reused, true, nil)
}

func testSourcePartialAliasWitness(t *testing.T, mode string) {
	m, parts, limits := sourceBundleLimits()
	limits.Files = 1
	crossKey := mode == "witness-malformed-cross-key"
	if crossKey {
		limits.Files++
	}
	_, o, paths, backing := sourcePreparedScene(t, limits, m, parts)
	target, p := m, backing
	if crossKey {
		target = sourceForeign(m)
		p = sourcePrepare(t, o, target, parts)
	}
	leaf, malformed := ".staging-"+p.name, "invalid-entry"
	path, stage := paths.capture, filepath.Join(paths.root, leaf)
	capture := sourceLstat(t, path)
	aliased := mode != "witness-malformed-separate"
	if aliased {
		sourceMust(t, os.Link(path, stage))
	} else {
		sourceMust(t, os.WriteFile(stage, []byte{1}, 0o600))
	}
	sourceMust(t, os.WriteFile(filepath.Join(paths.root, malformed), nil, 0o600))
	original := sourceLstat(t, stage)
	reached := checkSourcePartialAliasOrders(t, o, backing.name, leaf, malformed, aliased)
	sourcePrepareRefusal(t, o, target, parts, ErrIntegrityV1)
	var pin *os.File
	if reached && aliased {
		pin = checkSourceStageWitness(t, o, original)
	} else {
		sourceFailIf(t, o.stage.File != nil, "refusal retained an unreached or unfunded stage")
	}
	sourceMust(t, os.Remove(filepath.Join(paths.root, malformed)))
	if aliased {
		sourcePrepareAndRead(t, o, target, parts)
		sourceFailIf(t, o.live[p.name] != p.incarnation, "alias retry changed the issued incarnation")
		sourcePresence(t, paths.root, leaf, false)
		if pin != nil {
			checkSourcePinClosed(t, pin, o.stage.File)
		}
		if crossKey {
			sourceUnchangedEntry(t, path, capture)
			sourceRead(t, o, m, parts)
		}
		return
	}
	sourcePrepareRefusal(t, o, target, parts, ErrCapacityV1)
	sourceUnchangedEntry(t, stage, original)
}

func checkSourcePartialAliasOrders(t *testing.T, o *SourceOwnerV1, name, stage, malformed string, aliased bool) (reached bool) {
	t.Helper()
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		byName := sourceEntriesByName(entries)
		sourceFailIf(t, byName[name] == nil || byName[stage] == nil || byName[malformed] == nil, "unexpected directory entries")
		before := []os.DirEntry{byName[stage], byName[malformed], byName[name]}
		after := []os.DirEntry{byName[name], byName[stage], byName[malformed]}
		for _, entry := range entries {
			if key := entry.Name(); key != name && key != stage && key != malformed {
				before, after = append(before, entry), append(after, entry)
			}
		}
		for i, order := range [][]os.DirEntry{before, after} {
			used, err := o.censusFiles(r, order, false)
			sourceWantError(t, err, ErrIntegrityV1, "malformed capture name")
			sourceFailIf(t, !used.stageReached || used.stage.shared != (i == 1 && aliased), "order %d did not observe the expected staging or capture", i)
			sourceFailIf(t, o.stageWitnessFits(r, used.stage, order) != aliased, "order %d counted the stage against the wrong file", i)
		}
		used, _ := o.censusFiles(r, before, false)
		path, displaced := filepath.Join(o.dir, sourceDirectory, name), filepath.Join(o.dir, "displaced-capture")
		sourceMust(t, os.Rename(path, displaced))
		sourceFailIf(t, o.stageWitnessFits(r, used.stage, before), "an absent backing funded a stage alias")
		sourceMust(t, os.Rename(displaced, path))
		entries, err := o.sourceEntries(r)
		sourceMust(t, err)
		first := slices.IndexFunc(entries, func(e os.DirEntry) bool { return e.Name() == stage || e.Name() == malformed })
		sourceFailIf(t, first < 0, "staging and malformed entries are absent")
		reached = entries[first].Name() == stage
	})
	return reached
}

func testSourceGrownAliasWitness(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	limits.Files = 1
	byteLimited := mode == "witness-grown-bytes"
	if byteLimited {
		limits.Bytes = size
	}
	_, o, paths := sourceCaptureScene(t, limits, m)
	sourceLeaveUnissued(t, o, m, parts, paths.stage, nil)
	if !byteLimited {
		o = sourceOpen(t, sourceReopenStore(t, o.store, paths.dir), sourceID(), limits, nil)
		sourceRead(t, o, m, parts)
	}
	binding := o.live[paths.key]
	sourceFailIf(t, byteLimited != (binding != nil) || binding != nil && binding.issued, "capture has the wrong live binding")
	image := sourceReadFile(t, paths.capture)
	sourceMust(t, os.WriteFile(paths.capture, append(slices.Clone(image), 1), 0o600))
	sourceMust(t, os.Link(paths.capture, paths.stage))
	extra := filepath.Join(paths.root, sourceForeign(m).name(o.id))
	sourceMust(t, os.WriteFile(extra, nil, 0o600))
	original := sourceLstat(t, paths.stage)
	reached := !byteLimited || checkSourceUnfundedGrownWitness(t, o, paths.key)
	sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	sourceMust(t, os.Remove(extra))
	sourceMust(t, os.WriteFile(paths.capture, image, 0o600))
	if reached {
		sourceKeyOnlyRetry(t, o, m, parts)
		sourceUnchangedEntry(t, paths.stage, original, image)
		fresh := sourceOpen(t, sourceReopenStore(t, o.store, paths.dir), sourceID(), limits, nil)
		testSourceReopenedPin(t, fresh, m, parts, nil, filepath.Base(paths.stage), original, size)
		sourceUnchangedEntry(t, paths.capture, original, image)
		return
	}
	sourceFailIf(t, o.stage.File != nil || o.observedStage != "", "unreached stage retained a key or descriptor")
	sourceRetryAndRead(t, o, m, parts, binding)
	sourcePresence(t, paths.root, filepath.Base(paths.stage), false)
}

func sourceLeaveUnissued(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, stage string, data []byte) {
	t.Helper()
	o.ops.dirSync = func(pin *os.File) error {
		sourceMust(t, os.WriteFile(stage, data, 0o600))
		return pin.Sync()
	}
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), ErrIdentityV1)
	o.ops = realSourceFS
	sourceMust(t, os.Remove(stage))
}

func checkSourceUnfundedGrownWitness(t *testing.T, o *SourceOwnerV1, backing string) (reached bool) {
	t.Helper()
	stage := publicStagePrefix + backing
	withSourceEntries(t, o, func(r *sourceRoot, entries []os.DirEntry) {
		stageIndex := slices.IndexFunc(entries, func(entry os.DirEntry) bool { return entry.Name() == stage })
		backingIndex := slices.IndexFunc(entries, func(entry os.DirEntry) bool { return entry.Name() == backing })
		sourceFailIf(t, stageIndex < 0 || backingIndex < 0, "missing grown stage or backing")
		reached = stageIndex < backingIndex
		for _, wantReached := range [2]bool{reached, !reached} {
			used, err := o.censusFiles(r, entries, false)
			sourceWantError(t, used.admissionError(err), ErrCapacityV1, "grown stage at exact byte limit")
			sourceFailIf(t, used.stageReached != wantReached, "grown stage reached = %t, want %t", used.stageReached, wantReached)
			sourceFailIf(t, wantReached && o.stageWitnessFits(r, used.stage, entries), "byte limit funded a grown stage witness")
			entries[stageIndex], entries[backingIndex] = entries[backingIndex], entries[stageIndex]
		}
	})
	return reached
}

func checkSourcePinned(t *testing.T, pin *os.File, original os.FileInfo) *os.File {
	t.Helper()
	info, err := pin.Stat()
	sourceFailIf(t, err != nil || !os.SameFile(info, original), "descriptor does not hold the observed inode: %v", err)
	return pin
}

func checkSourceStageWitness(t *testing.T, o *SourceOwnerV1, original os.FileInfo) *os.File {
	t.Helper()
	pin := checkSourcePinned(t, o.stage.File, original)
	flags, err := unix.FcntlInt(pin.Fd(), unix.F_GETFL, 0)
	sourceMust(t, err)
	sourceFailIf(t, flags&unix.O_ACCMODE != unix.O_RDONLY || o.debt.name != "", "stage witness acquired write access or custody")
	return pin
}

func checkSourcePinClosed(t *testing.T, pin, current *os.File) {
	t.Helper()
	_, err := pin.Stat()
	sourceFailIf(t, !errors.Is(err, os.ErrClosed) || current != nil, "retired source pin is open: %v", err)
}

func testSourceReleaseStageCompatibility(t *testing.T, mode string) {
	m, parts, limits := sourceBundleLimits()
	limits.Files, limits.Descriptors = 2, 4
	want := error(nil)
	if mode == "release-missing-backing" {
		limits.Files, want = 1, ErrIntegrityV1
	}
	if mode == "release-with-funded-stage" || mode == "release-with-unreadable-stage" {
		limits.Descriptors = 5
	}
	_, o, paths, p := sourcePreparedScene(t, limits, m, parts)
	other := sourceForeign(m)
	stage := filepath.Join(paths.root, publicStagePrefix+other.name(o.id))
	if want != nil {
		sourceMust(t, os.Rename(filepath.Join(paths.root, p.name), filepath.Join(paths.dir, "absent-backing")))
	}
	stageMode := map[bool]os.FileMode{false: 0o600, true: 0o200}[mode == "release-with-unreadable-stage"]
	sourceMust(t, os.WriteFile(stage, []byte{1}, stageMode))
	original := sourceLstat(t, stage)
	_, readErr := os.ReadFile(stage)
	sourceFailIf(t, readErr != nil && (stageMode != 0o200 || !errors.Is(readErr, os.ErrPermission)), "stage read probe returned %v", readErr)
	o.ops.remove = func(r *os.Root, leaf string) error {
		sourceFailIf(t, leaf == filepath.Base(stage), "release attempted to remove staging")
		return r.Remove(leaf)
	}
	if want == nil {
		unchanged := sourceHeld(t, o)
		forged := *p
		incarnation := *p.incarnation
		forged.incarnation = &incarnation
		sourceReleaseResult(t, o, p, false, ErrIntegrityV1)
		sourceReleaseResult(t, o, &forged, true, ErrIntegrityV1)
		unchanged("release refused missing authority")
	}
	sourceReleaseResult(t, o, p, true, want)
	sourceUnchangedEntry(t, stage, original)
	sourceMust(t, os.Chmod(stage, 0o600))
	sourceFailIf(t, !bytes.Equal(sourceReadFile(t, stage), []byte{1}), "release changed stage bytes")
	sourceAbsent(t, paths.root, p.name, releaseFile, releaseScratch)
	if limits.Descriptors == 5 && readErr == nil {
		pin := checkSourcePinned(t, o.stage.File, original)
		o.ops = realSourceFS
		sourcePrepareRefusal(t, o, m, parts, ErrBusyV1)
		sourcePrepareAndRead(t, o, other, parts)
		checkSourcePinClosed(t, pin, o.stage.File)
		return
	}
	sourceFailIf(t, o.stage.File != nil || o.debt.name != "", "release took unfunded stage custody")
	if want == nil {
		sourceFault(o, "rename", ErrIdentityV1, func() { t.Fatal("refused prepare attempted a namespace operation") })
		prepareErr := map[bool]error{false: ErrCapacityV1, true: ErrIdentityV1}[readErr != nil]
		sourcePrepareRefusal(t, o, other, parts, prepareErr)
	}
}

func testSourcePreLinkSlot(t *testing.T, mode string) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	paths := sourcePaths(dir, m.name(o.id))
	incoming := filepath.Join(paths.root, ".staging-"+strings.ToUpper(paths.key))
	stageBytes := []byte("separate public stage")
	var qualified, original os.FileInfo
	var opened *sourceRoot
	var qualifiedBytes []byte
	if mode == "unavailable" {
		sourceLookupOnce(t, [2]string{paths.root, filepath.Base(paths.held)}, func(r *sourceRoot) { opened = r })
	}
	links := 0
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error { links++; return op(r, from, to) }
	o.ops.close = func(f *os.File) error {
		sourceMust(t, f.Close())
		qualified, qualifiedBytes = sourceLstat(t, paths.held), sourceReadFile(t, paths.held)
		switch mode {
		case "occupied":
			original = writeSourceEntry(t, incoming, stageBytes)
		case "scan-limit":
			return sourceSlotFill(paths.root, o.limits.Scans-1, os.Mkdir)
		case "unavailable":
			sourceFailIf(t, opened == nil, "qualified stage did not reach the root lookup")
			sourceMust(t, opened.pin.Close())
		}
		return nil
	}
	want := map[bool]error{true: ErrCapacityV1, false: ErrIdentityV1}[mode == "scan-limit"]
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
	sourceFailIf(t, links != 0 || qualified == nil, "pre-link refusal reached namespace operation or omitted the private file")
	sourcePresence(t, paths.root, paths.key, false)
	sourceUnchangedEntry(t, paths.held, qualified, qualifiedBytes)
	sourceFailIf(t, o.debt.size != uint64(len(qualifiedBytes)), "private stage lost original charge")
	if mode == "occupied" {
		sourceUnchangedEntry(t, incoming, original, stageBytes)
		sourceFailIf(t, os.SameFile(qualified, original) || uint64(qualified.Size()) != o.debt.size, "occupied slot changed the private stage debt or shared its inode")
		sourcePrepareRefusal(t, o, m, parts, syscall.EEXIST)
		sourcePrepareRefusal(t, o, sourceForeign(m), parts, syscall.EEXIST)
		sourceUnchangedEntry(t, incoming, original, stageBytes)
		sourceMust(t, os.Remove(incoming))
	}
	if mode == "scan-limit" {
		sourceMust(t, sourceSlotFill(paths.root, o.limits.Scans-1, func(path string, _ os.FileMode) error { return os.Remove(path) }))
	}
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(qualifiedBytes)))
	sourceRetryAfterFault(t, o, m, parts)
}

func sourceSlotFill(root string, count uint64, apply func(string, os.FileMode) error) error {
	for i := range count {
		if err := apply(filepath.Join(root, fmt.Sprintf("entry-%d", i)), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func testSourceIncomingStage(t *testing.T, mode string) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	paths := sourcePaths(dir, m.name(o.id))
	stage := filepath.Join(paths.root, ".staging-"+strings.ToUpper(paths.key))
	prefixCase := strings.HasSuffix(mode, "prefix-case")
	want := ErrIdentityV1
	if prefixCase {
		stage = filepath.Join(paths.root, ".STAGING-"+paths.key)
		if _, err := os.Lstat(filepath.Join(dir, strings.ToUpper(sourceDirectory))); errors.Is(err, os.ErrNotExist) {
			want = nil
		} else {
			sourceMust(t, err)
		}
	}
	data := []byte("separate staging content")
	var original, incoming os.FileInfo
	var image []byte
	arrive := func() { incoming = writeSourceEntry(t, stage, data) }
	switch mode {
	case "pre-link-prefix-case":
		o.ops.close = func(f *os.File) error {
			sourceMust(t, f.Close())
			arrive()
			return nil
		}
	case "during-link":
		o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
			original, image = sourceLstat(t, paths.held), sourceReadFile(t, paths.held)
			arrive()
			return op(r, from, to)
		}
	default:
		sourcePrepare(t, o, m, parts)
		original, image = sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
		o.ops.dirSync = func(pin *os.File) error { arrive(); return pin.Sync() }
	}
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
	sourceUnchangedEntry(t, stage, incoming, data)
	if prefixCase {
		sourceMust(t, os.Remove(stage))
	} else {
		sourceUnchangedEntry(t, paths.capture, original, image)
		assertSourceReleaseCharge(t, o, m, 2, uint64(len(image)+len(data)))
	}
	sourceRetryAfterFault(t, o, m, parts)
	sourcePresence(t, paths.root, filepath.Base(stage), false)
}

func testSourcePendingBinding(t *testing.T, mode string) {
	m, parts, size, limits := sourceSizedBundle(t)
	extra := []byte("separate stage")
	limits.Files, limits.Bytes = 2, size+uint64(len(extra))
	_, o, paths := sourceCaptureScene(t, limits, m)
	cause := errors.New("retained capture directory sync")
	want := cause
	o.ops.dirSync = func(*os.File) error { return cause }
	if mode == "final-slot" {
		want = ErrIdentityV1
		o.ops.dirSync = func(pin *os.File) error {
			sourceMust(t, os.WriteFile(paths.stage, extra, 0o600))
			return pin.Sync()
		}
	}
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
	o.ops = realSourceFS
	original, image := sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
	binding := o.live[paths.key]
	sourceFailIf(t, binding == nil || binding.issued, "refused publication lost its unissued binding")
	if mode == "final-slot" {
		sourceFailIf(t, !bytes.Equal(extra, sourceReadFile(t, paths.stage)), "publication changed independent stage")
		assertSourceReleaseCharge(t, o, m, 2, size+uint64(len(extra)))
		sourceMust(t, os.Remove(paths.stage))
	} else {
		testSourceProducerRefusesAfterCleanup(t, o, m, parts, paths.stage, extra, mode)
	}
	testSourceBoundChanges(t, o, m, parts, paths.capture, image)
	sourceUnchangedEntry(t, paths.capture, original)
	sourceRetryAndRead(t, o, m, parts, binding)
}

func testSourceProducerRefusesAfterCleanup(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, stage string, extra []byte, mode string) {
	t.Helper()
	sourceMust(t, os.WriteFile(stage, extra, 0o600))
	cause := errors.New("producer stopped after staging cleanup")
	produce := sourceAfterFirstPart(m, parts, func() error {
		sourcePresence(t, filepath.Dir(stage), filepath.Base(stage), false)
		sourceFailIf(t, o.debt.name != "" || o.pendingStage.name != "", "producer ran before staging debt was durably retired")
		if mode == "producer-panic" {
			panic(cause)
		}
		return cause
	})
	if mode == "producer-error" {
		sourcePrepareResult(t, o, m, produce, cause)
	} else {
		caught := catchSourcePanic(func() { sourcePrepareResult(t, o, m, produce, nil) })
		sourceFailIf(t, caught != any(cause), "producer panic changed: %v", caught)
	}
	sourcePresence(t, filepath.Dir(stage), filepath.Base(stage), false)
}

func testSourceBoundChanges(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, path string, image []byte) {
	t.Helper()
	sourceMust(t, os.WriteFile(path, sourceResealed(image, len(m.header(o.id))), 0o600))
	changed := slices.Clone(parts)
	changed[0] = slices.Clone(parts[0])
	changed[0][0] ^= 1
	before := sourceHeld(t, o)
	calls := 0
	sourcePrepareResult(t, o, m, func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		calls++
		return sourceExportParts(op, m, changed, visit)
	}, ErrIntegrityV1)
	sourceFailIf(t, calls != 0, "resealed file entered the producer")
	before("resealed capture refusal")
	sourceMust(t, os.Truncate(path, 1))
	sourcePrepareRefusal(t, o, sourceForeign(m), parts, ErrCapacityV1)
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(image)))
	sourceMust(t, os.WriteFile(path, image, 0o600))
}

func TestSourceDirectoryChangeBeforeCopy(t *testing.T) {
	t.Run("moved-during-export", func(t *testing.T) {
		t.Run("publish", func(t *testing.T) { testSourceMovedDuringExport(t, false) })
		t.Run("reuse", func(t *testing.T) { testSourceMovedDuringExport(t, true) })
	})
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	sourcePath := filepath.Join(dir, sourceDirectory)
	retained := filepath.Join(dir, "retained")
	o.ops.statfs = func(fd int, stat *syscall.Statfs_t) error {
		sourceMust(t, syscall.Fstatfs(fd, stat))
		sourceMust(t, os.Rename(sourcePath, retained))
		return os.Mkdir(sourcePath, 0o700)
	}
	sourcePrepareRefusal(t, o, m, parts, ErrCapacityV1)
	sourcePrepareRefusal(t, o, m, parts, ErrIdentityV1)
	sourceMust(t, os.Remove(sourcePath))
	sourcePrepareRefusal(t, o, m, parts, ErrIdentityV1)
	sourceMust(t, os.Rename(retained, sourcePath))
	o.ops = realSourceFS
	sourcePrepare(t, o, m, parts)
}

func TestSourceInstallationChangeDuringPrepare(t *testing.T) {
	sourceModes(t, []string{"missing", "replaced"}, func(t *testing.T, mode string) {
		_, o, dir, m, parts := sourceBundleScene(t, 1, false)
		held := sourceHeld(t, o)
		moved := filepath.Join(t.TempDir(), "original")
		source, retained := filepath.Join(dir, sourceDirectory), filepath.Join(moved, sourceDirectory)
		o.ops.statfs = func(fd int, stat *syscall.Statfs_t) error {
			sourceMust(t, syscall.Fstatfs(fd, stat))
			sourceMust(t, os.Rename(dir, moved))
			if mode == "replaced" {
				sourceMust(t, os.Mkdir(dir, 0o700))
				sourceMust(t, os.Rename(retained, source))
			}
			return nil
		}
		sourcePrepareResult(t, o, m, func(*SourceOperationV1, func(SourcePartV1) error) error {
			t.Fatal("producer entered after installation changed")
			return nil
		}, ErrCapacityV1)
		err := o.withRoot(o.bindRoot, func(*sourceRoot) error {
			t.Fatal("used a root after installation changed")
			return nil
		})
		sourceWantError(t, err, ErrIdentityV1, "reopen installation")
		if mode == "replaced" {
			sourceMust(t, os.Rename(source, retained))
			sourceMust(t, os.Remove(dir))
		}
		sourceMust(t, os.Rename(moved, dir))
		held("refused preparation")
		o.ops = realSourceFS
		sourcePrepareAndRead(t, o, m, parts)
	})
}

func TestSourceRefusesUnusableDirectoryHandle(t *testing.T) {
	sourceModes(t, []string{"closed", "replacement"}, func(t *testing.T, mode string) {
		_, o, _, m, parts := sourceBundleScene(t, 1, false)
		held := sourceHeld(t, o)
		want := ErrUnavailableV1
		if mode == "replacement" {
			want = ErrIdentityV1
		}
		err := o.withRoot(func(parent *os.Root) (*os.Root, error) {
			if mode == "replacement" {
				return parent.OpenRoot(".")
			}
			r, err := o.bindRoot(parent)
			sourceMust(t, err)
			sourceMust(t, r.Close())
			return r, nil
		}, func(*sourceRoot) error {
			t.Fatal("used an unavailable or unrelated directory handle")
			return nil
		})
		sourceWantError(t, err, want, "pin source directory")
		held("refused directory handle")
		sourcePrepareAndRead(t, o, m, parts)
	})
}

func testSourceMovedDuringExport(t *testing.T, reuse bool) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	var token *sourceIncarnation
	if reuse {
		token = sourcePrepare(t, o, m, parts).incarnation
	}
	root, moved := filepath.Join(dir, sourceDirectory), filepath.Join(dir, "moved")
	producer := sourceAfterFirstPart(m, parts, func() error {
		sourceMust(t, os.Rename(root, moved))
		return os.Mkdir(root, 0o700)
	})
	sourcePrepareResult(t, o, m, producer, ErrIdentityV1)
	name := m.name(o.id)
	binding := o.live[name]
	sourceFailIf(t, binding == nil || reuse && binding != token || !reuse && binding.issued || o.debt.name != "" || o.pendingStage.name != "",
		"moved root changed the retained owner: token=%v debt=%+v", o.live[name], o.debt)
	sourcePresence(t, moved, name, true)
	sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "replacement directory acquired backing")
	sourceMust(t, os.Remove(root))
	sourceMust(t, os.Rename(moved, root))
	sourcePrepareAndRead(t, o, m, parts)
}

func TestSourceOperationAuthorityAdmission(t *testing.T) {
	t.Run("second-owner-in-export", func(t *testing.T) {
		s, o, dir, m, parts := sourceBundleScene(t, 1, false)
		alias := s
		producer := sourceAfterFirstPart(m, parts, func() error {
			root, stage := filepath.Join(dir, sourceDirectory), ".stage-hold-"+m.name(o.id)
			sourcePresence(t, root, stage, true)
			sourceOpen(t, alias, sourceID(), sourceLimits(), ErrBusyV1)
			sourcePresence(t, root, stage, true)
			copied := reflect.New(reflect.TypeFor[SourceOwnerV1]())
			copied.Elem().Set(reflect.ValueOf(o).Elem())
			sourcePrepareRefusal(t, copied.Interface().(*SourceOwnerV1), m, parts, ErrIdentityV1)
			return nil
		})
		sourcePrepareResult(t, o, m, producer, nil)
		sourceRead(t, o, m, parts)
	})
	s, o, _, m, parts, p := sourcePreparedBundle(t)
	held := sourceHeld(t, o)
	check := func(a *mdbx.OperationAccount, want error) {
		calls := 0
		producer := func(op *SourceOperationV1, v func(SourcePartV1) error) error {
			calls++
			return sourceExportParts(op, m, parts, v)
		}
		visitor := func(SourcePartV1) error { calls++; return nil }
		prepared, err := o.PrepareSourceV1(a, m, producer)
		for _, err := range []error{err, o.WithSourceExportV1(a, m, producer, visitor), o.WithCapturedSourceV1(a, m, visitor), o.ReleaseUnpublishedSourceV1(a, p, true)} {
			sourceFailIf(t, any(err) != any(want), "authority admission=%v, want %v", err, want)
		}
		sourceFailIf(t, prepared != nil || calls != 0, "refused authority: handle=%v calls=%d", prepared, calls)
		held("refused authority")
	}
	check(nil, ErrCapacityV1)
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceMust(t, o.WithCapturedSourceV1(a, m, func(SourcePartV1) error { check(nil, ErrBusyV1); check(a, ErrBusyV1); return nil }))
	})
	var closed *mdbx.OperationAccount
	unexpected := func() error { t.Fatal("unfunded reservation ran"); return nil }
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		closed = a
		sourceMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-o.limits.WorkingBytesV1()+1, func() error {
			check(a, a.WithReservation(o.limits.WorkingBytesV1(), unexpected))
			return nil
		}))
	})
	for _, a := range []*mdbx.OperationAccount{{}, closed} {
		check(a, a.WithReservation(0, unexpected))
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		tx, err := s.Begin()
		sourceMust(t, err)
		check(a, policycontrol.ErrBusy)
		_, err = tx.Abort()
		sourceMust(t, err)
		sourceMust(t, s.Close())
		check(a, policycontrol.ErrClosed)
		o = nil
		check(a, ErrIdentityV1)
	})
}

func TestSourcePreparationPanicRetainsCleanup(t *testing.T) {
	s, o, _, m, parts := sourceBundleScene(t, 1, false)
	original := slices.Clone(parts[0])
	cause, cleanup := errors.New("export panic"), errors.New("cleanup refusal")
	cleanupCalls := 0
	o.ops.remove = func(*os.Root, string) error {
		cleanupCalls++
		sourceWantError(t, s.Close(), policycontrol.ErrBusy, "cleanup lost authority")
		return cleanup
	}
	producer := sourceAfterFirstPart(m, parts, func() error { panic(cause) })
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		caught := catchSourcePanic(func() { _, _ = o.PrepareSourceV1(a, m, producer) })
		sourceFailIf(t, caught != any(cause) || o.debt.name == "" || !o.debt.held() || !bytes.Equal(parts[0], original) || cleanupCalls != 1,
			"panic owner: %v %+v, cleanup calls=%d", caught, o.debt, cleanupCalls)
		sourceMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil }))
	})
	o.ops = realSourceFS
	sourcePrepareAndRead(t, o, m, parts)
}

func TestSourceCreatedModesIgnoreUmask(t *testing.T) {
	s, dir := sourceStore(t)
	m, parts := sourceBundle(1, false)
	root := filepath.Join(dir, sourceDirectory)
	const init = ".source-captures-v1.init"
	scratch := filepath.Join(dir, init)
	sourceMust(t, os.Mkdir(scratch, 0o700))
	interrupted, err := os.Open(scratch)
	sourceMust(t, err)
	defer interrupted.Close()
	prior := sourceLstat(t, scratch)
	sourceMust(t, interrupted.Chmod(0))
	old := syscall.Umask(0o400)
	t.Cleanup(func() { syscall.Umask(old) })
	o := sourceOpen(t, s, sourceID(), sourceLimits(), nil)
	sourcePresence(t, dir, init, false)
	sourceFailIf(t, os.SameFile(prior, sourceLstat(t, root)), "source initialization reused the interrupted directory")
	p, cause := sourcePrepare(t, o, m, parts), errors.New("intent sync refusal")
	sourceRead(t, o, m, parts)
	sourceReleaseWithFault(t, o, p, "intent-sync", cause)
	for name, mode := range map[string]os.FileMode{".": os.ModeDir | 0o700, p.name: 0o600, releaseFile: 0o600} {
		info, err := os.Lstat(filepath.Join(root, name))
		sourceFailIf(t, err != nil || info.Mode() != mode, "created %s: %v %v, want %v", name, err, info, mode)
	}
	sourceReleaseResult(t, sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil), nil, true, nil)
	sourceFailIf(t, len(sourceEntries(t, dir)) != 0, "resumed release left backing")
}

func testSourcePublicationAcknowledgement(t *testing.T, mode string) {
	m, parts, limits := sourceBundleLimits()
	limits.Files = 1
	want := ErrIntegrityV1
	if mode == "publication-separate-destination" {
		limits.Files, want = 2, ErrIdentityV1
	}
	_, o, paths := sourceCaptureScene(t, limits, m)
	stage := ".stage-hold-" + paths.key
	displaced := filepath.Join(paths.dir, "acknowledged-backing")
	var qualified, separate os.FileInfo
	var image []byte
	data := []byte("separate destination")
	calls := 0
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error {
		calls++
		sourceFailIf(t, reflect.ValueOf(op).Pointer() != reflect.ValueOf((*sourceRoot).Link).Pointer(), "publication did not select Link")
		sourceFailIf(t, from != stage, "publication source is %q, want %q", from, stage)
		sourceFailIf(t, to != paths.key, "publication destination is %q, want %q", to, paths.key)
		qualified, image = sourceLstat(t, paths.held), sourceReadFile(t, paths.held)
		sourceMust(t, op(r, from, to))
		sourceUnchangedEntry(t, paths.capture, qualified)
		sourceMust(t, os.Rename(paths.capture, displaced))
		if mode == "publication-late-eio" {
			return syscall.EIO
		}
		if mode == "publication-separate-destination" {
			separate = writeSourceEntry(t, paths.capture, data)
		}
		return nil
	}
	if mode == "publication-late-eio" {
		sourcePrepareResult(t, o, m, sourceProducer(m, parts), syscall.EIO)
		sourceAbsent(t, paths.root, paths.key, stage)
		sourceRetryAfterFault(t, o, m, parts)
		sourceUnchangedEntry(t, displaced, qualified, image)
		return
	}
	sourceFault(o, "unlink", ErrIdentityV1, func() { t.Fatal("acknowledged publication attempted cleanup") })
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
	sourceFailIf(t, calls != 1, "publication reached %d namespace calls, want 1", calls)
	sourceUnchangedEntry(t, paths.held, qualified)
	size := uint64(len(image))
	if separate == nil {
		sourcePresence(t, paths.root, paths.key, false)
		assertSourceReleaseCharge(t, o, m, 1, size)
	} else {
		sourceUnchangedEntry(t, paths.capture, separate, data)
		assertSourceReleaseCharge(t, o, m, 2, size+uint64(len(data)))
	}
	bound := o.live[paths.key]
	sourceFailIf(t, bound == nil || bound.issued || bound.uncertain || bound.size != size, "acknowledged publication lost its qualified binding or charge")
	sourceFailIf(t, bound.file != filelock.FileIdentityV1(qualified) || bound.footer != sha256.Sum256(image[:len(image)-sha256.Size]), "acknowledged publication changed the bound file or footer")
	sourceFailIf(t, o.debt.leaf != stage || !bytes.Equal(sourceReadFile(t, paths.held), image), "acknowledged publication did not preserve stage custody")
	sourceMust(t, os.Rename(displaced, paths.capture))
	o.ops = realSourceFS
	sourceRetryAndRead(t, o, m, parts, bound)
	sourceUnchangedEntry(t, paths.capture, qualified)
	sourcePresence(t, paths.root, stage, false)
}

func testSourceLinkExists(t *testing.T, mode string) {
	m, parts, limits := sourceBundleLimits()
	limits.Files = 1
	_, o, paths := sourceCaptureScene(t, limits, m)
	cause := fmt.Errorf("link acknowledgement: %w", syscall.EEXIST)
	unavailable := mode == "link-unavailable-exists"
	o.ops.namespace = renameSourceFault(t, cause, true, unavailable)
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
	image, info := sourceReadFile(t, paths.capture), sourceLstat(t, paths.capture)
	sourceUnchangedEntry(t, paths.held, info)
	bound := o.live[paths.key]
	sourceFailIf(t, bound == nil || bound.issued || bound.uncertain != unavailable, "link error lost its unissued binding")
	sourceFailIf(t, bound.file != filelock.FileIdentityV1(info) || bound.size != uint64(len(image)) ||
		bound.footer != sha256.Sum256(image[:len(image)-sha256.Size]), "link error changed the qualified backing")
	o.ops = realSourceFS
	if unavailable {
		lookup := [2]string{paths.root, paths.key}
		sourceLookupOnce(t, lookup, struct{}{})
		sourceFailIf(t, sourcePrepare(t, o, m, parts).incarnation != bound, "retry changed the qualified capture")
		_, armed := sourceLookupFaults.Load(lookup)
		sourceFailIf(t, armed, "publication lookup did not consume the fault")
		saved := filepath.Join(paths.dir, "original-capture")
		sourceMust(t, os.Rename(paths.capture, saved))
		sourcePrepareResult(t, o, m, refusedSourceProducer(t), ErrIntegrityV1)
		sourceUnchangedEntry(t, saved, info, image)
		sourceMust(t, os.Rename(saved, paths.capture))
	}
	sourceRetryAndRead(t, o, m, parts, bound)
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(image)))
	sourceUnchangedEntry(t, paths.capture, info)
	sourcePresence(t, filepath.Dir(paths.held), filepath.Base(paths.held), false)
}

func sourceOpenFileModes(t *testing.T, info os.FileInfo) []int {
	t.Helper()
	original := info.Sys().(*syscall.Stat_t)
	entries, err := os.ReadDir("/dev/fd")
	sourceMust(t, err)
	var modes []int
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		var held syscall.Stat_t
		if err == nil && syscall.Fstat(fd, &held) == nil && held.Dev == original.Dev && held.Ino == original.Ino {
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			sourceMust(t, err)
			modes = append(modes, flags&unix.O_ACCMODE)
		}
	}
	return modes
}

func testSourceLinkCollision(t *testing.T, mode string) {
	_, incumbent, dir, m, parts, prepared := sourcePreparedBundle(t)
	from := filepath.Join(dir, sourceDirectory, prepared.name)
	original, image := sourceLstat(t, from), sourceReadFile(t, from)
	_, target, targetDir := sourceScene(t, sourceLimits())
	root := filepath.Join(targetDir, sourceDirectory)
	final := filepath.Join(root, prepared.name)
	ioFailure := mode == "at-link-destination-io-error"
	want := ErrIntegrityV1
	if ioFailure {
		want = syscall.EIO
	}
	links := 0
	target.ops.namespace = func(op sourceNamespace, r *sourceRoot, source, destination string) error {
		links++
		sourceMust(t, os.Link(from, final))
		if ioFailure {
			private := sourceLstat(t, filepath.Join(root, ".stage-hold-"+prepared.name))
			sourceFailIf(t, os.SameFile(private, original), "destination shares the qualified stage inode")
			return syscall.EIO
		}
		return op(r, source, destination)
	}
	sourcePrepareResult(t, target, m, sourceProducer(m, parts), want)
	sourceFailIf(t, links != 1, "destination observation reached %d namespace calls", links)
	sourceUnchangedEntry(t, final, original)
	sourceUnchangedEntry(t, from, original)
	sourceFailIf(t, !bytes.Equal(sourceReadFile(t, final), image) || target.live[prepared.name] != nil, "refused link changed or bound the destination")
	sourcePresence(t, root, ".stage-hold-"+prepared.name, false)
	sourceRead(t, incumbent, m, parts)
	sourceRetryAfterFault(t, target, m, parts)
}

func testSourceWrittenDigest(t *testing.T) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	size := sourceSize(t, m)
	syncs, links := 0, 0
	o.ops.fileSync = func(f *os.File) error { syncs++; return f.Sync() }
	o.ops.namespace = func(op sourceNamespace, r *sourceRoot, from, to string) error { links++; return op(r, from, to) }
	o.ops.write = func(f *os.File, data []byte) (int, error) {
		info, err := f.Stat()
		sourceMust(t, err)
		if uint64(info.Size()) != size-sha256.Size {
			return f.Write(data)
		}
		image := make([]byte, size)
		_, err = f.ReadAt(image[:info.Size()], 0)
		sourceMust(t, err)
		image = sourceResealed(image, len(m.header(o.id)))
		_, err = f.WriteAt(image[:info.Size()], 0)
		sourceMust(t, err)
		return f.Write(image[info.Size():])
	}
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), ErrIntegrityV1)
	sourceFailIf(t, syncs != 0 || links != 0 || len(sourceEntries(t, dir)) != 0, "write digest refusal crossed the file handoff")
	sourceRetryAfterFault(t, o, m, parts)
}

func testSourceComparedDigest(t *testing.T) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	path := filepath.Join(dir, sourceDirectory, p.name)
	image := sourceReadFile(t, path)
	f, err := os.Open(path)
	sourceMust(t, err)
	defer f.Close()
	checkSourceComparison(t, o, m, parts, image, f)
	changed := slices.Clone(parts)
	changed[0] = slices.Clone(parts[0])
	changed[0][0] ^= 1
	held := sourceHeld(t, o)
	sourcePrepareResult(t, o, m, sourceProducer(m, changed), ErrIntegrityV1)
	held("refused file-backed comparison")
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(image)))
	sourceRetryAndRead(t, o, m, parts, p.incarnation)
}

func checkSourceComparison(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, image []byte, f *os.File) {
	t.Helper()
	canonical := m.header(o.id)
	for _, part := range parts {
		canonical = append(canonical, part...)
	}
	sourceFailIf(t, !bytes.Equal(canonical, image[:len(image)-sha256.Size]), "comparison fixture differs from the producer bytes")
	info, err := f.Stat()
	sourceMust(t, err)
	expected := sourceIncarnation{file: filelock.FileIdentityV1(info), size: uint64(len(image)), footer: sha256.Sum256(canonical)}
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceMust(t, o.withManifest(a, m, false, func(r *sourceRoot, m SourceManifestV1, _ uint64) error {
			producer := sourceProducer(m, parts)
			produce := func(visit func(SourcePartV1) error) error { return o.export(a, m, producer, visit) }
			scratch := make([]byte, scratchBytes)
			sourceWantError(t, o.compareBundle(r, f, m, expected, produce, scratch), nil, "matching comparison digest")
			expected.file = filelock.IdentityV1{}
			sourceWantError(t, o.compareBundle(r, f, m, expected, produce, scratch), ErrIdentityV1, "independent requalification result")
			expected.footer = sha256.Sum256([]byte("different producer digest"))
			sourceWantError(t, o.compareBundle(r, f, m, expected, produce, scratch), ErrIntegrityV1, "comparison digest precedes requalification")
			return nil
		}))
	})
}

func testSourceRequalifyAfterProducer(t *testing.T) {
	_, o, dir, m, parts, p := sourcePreparedBundle(t)
	path := filepath.Join(dir, sourceDirectory, p.name)
	image := sourceReadFile(t, path)
	original := sourceLstat(t, path)
	changed := sourceResealed(image, len(m.header(o.id)))
	syncs := 0
	o.ops.fileSync = func(f *os.File) error { syncs++; return f.Sync() }
	produce := func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		if err := sourceExportParts(op, m, parts, visit); err != nil {
			return err
		}
		return os.WriteFile(path, changed, 0o600)
	}
	sourcePrepareResult(t, o, m, produce, ErrIntegrityV1)
	sourceUnchangedEntry(t, path, original)
	sourceFailIf(t, syncs != 0 || !bytes.Equal(sourceReadFile(t, path), changed), "requalification refusal crossed the handoff or changed backing")
	sourceMust(t, os.WriteFile(path, image, 0o600))
	sourceRetryAfterFault(t, o, m, parts)
}

func testSourceFinalPin(t *testing.T, mode string) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	late := strings.HasPrefix(mode, "final-name-")
	var issued *sourceIncarnation
	if late || strings.HasPrefix(mode, "reuse-") {
		issued = sourcePrepare(t, o, m, parts).incarnation
	}
	paths := sourcePaths(dir, m.name(o.id))
	if strings.HasSuffix(mode, "-scan-limit") {
		o.ops.dirSync = func(pin *os.File) error {
			sourceMust(t, pin.Sync())
			return sourceSlotFill(paths.root, o.limits.Scans-1, os.Mkdir)
		}
		sourcePrepareResult(t, o, m, sourceProducer(m, parts), ErrCapacityV1)
		sourceMust(t, sourceSlotFill(paths.root, o.limits.Scans-1, func(path string, _ os.FileMode) error { return os.Remove(path) }))
		sourceRetryAfterFault(t, o, m, parts)
		return
	}
	var original, replacement os.FileInfo
	var image []byte
	var unchanged func(string)
	var restore func()
	saved := filepath.Join(dir, "original-capture")
	changedContent := mode == "final-name-content"
	change := func(*sourceRoot) {
		restore = func() { sourceMust(t, os.WriteFile(paths.capture, image, 0o600)) }
		switch mode {
		case "final-name-content":
			sourceMust(t, os.WriteFile(paths.capture, sourceResealed(image, len(m.header(o.id))), 0o600))
		case "final-name-size":
			sourceMust(t, os.Truncate(paths.capture, 1))
		default:
			sourceMust(t, os.Rename(paths.capture, saved))
			if mode == "final-name-identity" {
				sourceMust(t, os.WriteFile(paths.capture, image, 0o600))
			}
			restore = func() { sourceMust(t, os.Rename(saved, paths.capture)) }
		}
		unchanged = sourceHeld(t, o)
	}
	o.ops.dirSync = func(pin *os.File) error {
		original, image = sourceLstat(t, paths.capture), sourceReadFile(t, paths.capture)
		if late {
			sourceLookupOnce(t, [2]string{paths.root, filepath.Base(paths.stage)}, func(r *sourceRoot) {
				if changedContent {
					change(r)
					return
				}
				sourceLookupOnce(t, [2]string{paths.root, paths.key}, change)
			})
			return pin.Sync()
		}
		sourceMust(t, os.Remove(paths.capture))
		modes := sourceOpenFileModes(t, original)
		sourceFailIf(t, !slices.Equal(modes, []int{unix.O_RDONLY}), "final sync held file modes %v, want one read-only descriptor", modes)
		replacement = writeSourceEntry(t, paths.capture, image)
		sourceFailIf(t, os.SameFile(original, replacement), "final replacement acquired the original inode")
		return pin.Sync()
	}
	want := map[bool]error{true: ErrIntegrityV1, false: ErrIdentityV1}[mode == "final-name-size" || changedContent]
	sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
	sourceFailIf(t, original == nil || len(sourceOpenFileModes(t, original)) != 0, "handoff retained a descriptor after refusal")
	o.ops = realSourceFS
	if late {
		sourceFailIf(t, unchanged == nil, "handoff did not check the public staging name")
		retryErr := map[bool]error{true: ErrIdentityV1, false: ErrIntegrityV1}[mode == "final-name-identity"]
		sourcePrepareResult(t, o, m, refusedSourceProducer(t), retryErr)
		unchanged("final name refusal and retry")
		assertSourceReleaseCharge(t, o, m, 1, uint64(len(image)))
		restore()
		sourceRetryAndRead(t, o, m, parts, issued)
		sourceUnchangedEntry(t, paths.capture, original, image)
		return
	}
	sourceUnchangedEntry(t, paths.capture, replacement, image)
	sourcePrepareRefusal(t, o, m, parts, ErrIdentityV1)
	assertSourceReleaseCharge(t, o, m, 1, uint64(len(image)))
}

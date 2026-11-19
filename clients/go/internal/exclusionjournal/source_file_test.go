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
	"syscall"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

func sourceEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, sourceDirectory))
	sourceMust(t, err)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func sourceFileCount(t *testing.T, dir string, want int, message string) {
	t.Helper()
	count := len(sourceEntries(t, dir))
	sourceFailIf(t, count != want, "%s: got %d files, want %d", message, count, want)
}

func sourcePrepareRefusal(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, want error) {
	t.Helper()
	calls := 0
	sourcePrepareResult(t, o, m, func(op *SourceOperationV1, v func(SourcePartV1) error) error {
		calls++
		return sourceExportParts(op, m, parts, v)
	}, want)
	sourceFailIf(t, calls != 0, "refused source preparation entered producer %d times", calls)
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
	case "file-sync":
		o.ops.fileSync = fileOp
	case "close":
		o.ops.close = fileOp
	case "rename":
		o.ops.rename = func(*os.Root, string, string) error { return fail() }
	case "parent-sync":
		o.ops.dirSync = func(*sourceRoot) error { return fail() }
	case "unlink":
		o.ops.remove = func(*os.Root, string) error { return fail() }
	case "statfs":
		o.ops.statfs = func(int, *syscall.Statfs_t) error { return fail() }
	}
}

func TestSourceCodecCorpus(t *testing.T) {
	for _, class := range []byte{1, 3} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			s, o, dir, m, parts := sourceBundleScene(t, class, true)
			p := sourcePrepare(t, o, m, parts)
			path := filepath.Join(dir, sourceDirectory, p.name)
			image := sourceReadFile(t, path)
			o = sourceReopen(t, s, dir, sourceLimits())
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
			sourceMust(t, os.WriteFile(path, image, 0o600))
			sourceRead(t, o, m, parts)
		})
	}
}

func TestSourceManifestRefusals(t *testing.T) {
	rows := []struct {
		name  string
		class byte
		edit  func(*SourceManifestV1)
	}{
		{"unknown-class", 1, func(m *SourceManifestV1) { m.Class = 4 }},
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
			_, o, dir, m, parts := sourceBundleScene(t, row.class, false)
			row.edit(&m)
			sourcePrepareRefusal(t, o, m, parts, ErrIntegrityV1)
			sourceFileCount(t, dir, 0, "manifest refusal published bytes")
		})
	}
}

func TestSourcePartAndAssuranceRefusals(t *testing.T) {
	for _, mode := range []string{"short", "extra", "reorder", "length", "unreadable", "full-extra", "conditional-short", "conditional-zero", "unknown-assurance", "digest-substitution", "nil-producer", "missing-callback", "nil-reader", "ignored-refusal", "nested-delivery"} {
		t.Run(mode, func(t *testing.T) {
			class := byte(3)
			if mode == "short" || mode == "unreadable" || mode == "length" {
				class = 1
			}
			_, o, dir, m, parts := sourceBundleScene(t, class, false)
			switch mode {
			case "full-extra":
				parts[3] = []byte{1, 1}
			case "conditional-short":
				parts[3] = []byte{2, 1}
			case "conditional-zero":
				parts[3] = append([]byte{2}, make([]byte, 32)...)
			case "unknown-assurance":
				parts[3] = []byte{9}
			case "digest-substitution":
				parts[0] = slices.Clone(m.AcquiredDigest[:])
			}
			for i := range parts {
				m.Parts[i].Length = uint64(len(parts[i]))
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
			sourceAccount(t, func(a *mdbx.OperationAccount) error {
				if mode == "length" || mode == "nil-reader" || mode == "missing-callback" {
					calls := 0
					err := o.WithSourceExportV1(a, m, producer, func(SourcePartV1) error { calls++; return nil })
					sourceFailIf(t, any(err) != any(ErrIntegrityV1) || calls != 0, "declared length refusal: %v/%d", err, calls)
				}
				p, err := o.PrepareSourceV1(a, m, producer)
				sourceFailIf(t, p != nil || any(err) != any(ErrIntegrityV1), "part refusal: %v/%v", p, err)
				return nil
			})
			sourceFailIf(t, mode == "nested-delivery" && !nested, "admitted read did not finish after nested refusal")
			if late != nil {
				sourceWantError(t, late(SourcePartV1{}), ErrUnavailableV1, "expired callback")
			}
			sourceFailIf(t, len(sourceEntries(t, dir)) != 0 || o.debt != nil, "part refusal lost cleanup ownership")
		})
	}
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
	for _, stage := range []string{"write", "file-sync", "close", "rename", "parent-sync", "statfs"} {
		for _, reopen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reopen%v", stage, reopen), func(t *testing.T) {
				s, o, dir, m, parts := sourceBundleScene(t, 1, false)
				path := filepath.Join(dir, "policy-control")
				original := sourceReadFile(t, path)
				cause := errors.New("filesystem refusal")
				failed := false
				sourceFault(o, stage, cause, func() {
					sourceWantError(t, s.Close(), policycontrol.ErrBusy, "close in source I/O")
					failed = true
				})
				want := cause
				if stage == "statfs" {
					want = ErrCapacityV1
				}
				sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
				sourceFailIf(t, !failed, "durability operation did not reach %s", stage)
				sourceFailIf(t, stage == "parent-sync" && (o.debt == nil || o.debt.staging || len(sourceEntries(t, dir)) != 1), "renamed backing lost its owner")
				sourceFailIf(t, stage != "parent-sync" && (o.debt != nil || len(sourceEntries(t, dir)) != 0), "unpublished cleanup was not completed")
				if reopen {
					o = sourceReopen(t, s, dir, sourceLimits())
				}
				sourcePrepare(t, o, m, parts)
				sourceRead(t, o, m, parts)
				sourceFailIf(t, !bytes.Equal(original, sourceReadFile(t, path)), "source operation changed control bytes")
			})
		}
	}
}

func TestSourcePartialCleanupRetry(t *testing.T) {
	m, parts := sourceBundle(1, false)
	parts[0] = bytes.Repeat([]byte{42}, 70000)
	m.Parts[0].Length = 70000
	limits := sourceLimits()
	limits.Bytes, _ = m.SizeV1()
	limits.Files = 1
	_, o, dir := sourceScene(t, limits)
	cause := errors.New("partial write")
	cleanup := errors.New("unlink refusal")
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
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		p, err := o.PrepareSourceV1(a, m, producer)
		sourceFailIf(t, p != nil || !errors.Is(err, cause) || !errors.Is(err, cleanup) || errors.Is(err, later) || o.debt == nil || !o.debt.staging,
			"partial owner: %v/%v %+v", p, err, o.debt)
		return nil
	})
	staging := filepath.Join(dir, sourceDirectory, ".staging-"+m.name(o.id))
	info, err := os.Stat(staging)
	sourceMust(t, err)
	sourceFailIf(t, info.Size() <= 0 || info.Size() >= 70000, "partial size=%d", info.Size())
	testSourceUnfundedBacking(t, o, m, parts, staging)
	foreign := m
	foreign.Identity[0]++
	sourcePrepareRefusal(t, o, foreign, parts, ErrBusyV1)
	o.ops = realSourceFS
	prior := sourceReadFile(t, staging)
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
	sourceFailIf(t, calls != 1 || !bytes.Equal(sourceReadFile(t, staging), prior), "space refusal: checks=%d or staged bytes changed", calls)
	sourcePresence(t, root, m.name(o.id), false)
	o.ops = realSourceFS
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
	sourcePresence(t, root, stage, false)
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
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(mdbx.TreeLaneMaxBytes-o.limits.WorkingBytesV1()-sourceBackingCharge(parts)+1, func() error {
			p, err := o.PrepareSourceV1(a, m, producer)
			sourceFailIf(t, p != nil || !mdbx.IsOperationReservationCapacity(err) || entries != 1 || delivered != 0,
				"unfunded source: %v/%v producer=%d delivered=%d", p, err, entries, delivered)
			return nil
		})
	})
	after, afterErr := os.ReadFile(staging)
	sourceFailIf(t, (beforeErr == nil) != (afterErr == nil) || !bytes.Equal(before, after), "unfunded source changed staged bytes")
}

func TestSourceReleaseOnlyRetry(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "close", "rename", "rename-visible", "intent-sync", "unlink", "unlink-reopen-competing-prepare", "unlink-sync", "marker-clear", "final-sync"} {
		t.Run(stage, func(t *testing.T) { testSourceReleaseStage(t, stage) })
	}
	for _, mode := range []string{"changed-content", "changed-inode", "linked-backing"} {
		t.Run(mode, func(t *testing.T) { testSourceReleaseIncarnation(t, mode) })
	}
	t.Run("scratch-link", testSourceReleaseScratchLink)
	t.Run("backing-reappears", testSourceReleaseBackingReappears)
	for _, stage := range []string{"pending-absent", "pending-visible", "clear-present", "clear-absent"} {
		t.Run(stage, func(t *testing.T) { testSourceReleaseInconclusive(t, stage) })
	}
}

func testSourceReleaseScratchLink(t *testing.T) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
	root := filepath.Join(dir, sourceDirectory)
	path, marker, scratch := filepath.Join(root, p.name), filepath.Join(root, releaseFile), filepath.Join(root, releaseScratch)
	original := sourceReadFile(t, path)
	cause := errors.New("source unlink refusal")
	injectReleaseFault(o, "unlink", cause)
	sourceReleaseResult(t, o, p, true, cause)
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
	sourceFileCount(t, dir, 0, "qualified release left backing")
}

func testSourceReleaseBackingReappears(t *testing.T) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
	root := filepath.Join(dir, sourceDirectory)
	path, marker := filepath.Join(root, p.name), filepath.Join(root, releaseFile)
	sourceMust(t, os.Link(path, filepath.Join(t.TempDir(), "held")))
	entry := []byte("entry at the released name")
	unlinks := 0
	o.ops.remove = func(r *os.Root, name string) error {
		if name == p.name {
			unlinks++
			o.ops.dirSync = func(r *sourceRoot) error {
				o.ops.dirSync = syncSourceRoot
				err := syncSourceRoot(r)
				sourceMust(t, os.WriteFile(path, entry, 0o600))
				return err
			}
		}
		return r.Remove(name)
	}
	sourceReleaseResult(t, o, p, true, ErrIdentityV1)
	foreign := m
	foreign.Identity[0]++
	sourcePrepareRefusal(t, o, foreign, parts, ErrBusyV1)
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
	unchanged([]byte{1}, "retry with a differing marker")
	sourceMust(t, os.WriteFile(marker, record, 0o600))
	sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), ErrIdentityV1)
	unchanged(record, "fresh open")
}

func testSourceReleaseInconclusive(t *testing.T, stage string) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
	root := filepath.Join(dir, sourceDirectory)
	size := uint64(len(sourceReadFile(t, filepath.Join(root, p.name))))
	cause := errors.New("release observation unavailable")
	clearing := stage == "clear-present" || stage == "clear-absent"
	markerPresent := stage == "pending-visible" || stage == "clear-present"
	injectInconclusiveRelease(t, o, stage, cause)
	sourceReleaseResult(t, o, p, true, cause)
	sourcePresence(t, root, p.name, !clearing)
	sourcePresence(t, root, releaseFile, markerPresent)
	foreign := m
	foreign.Identity[0]++
	sourcePrepareRefusal(t, o, foreign, parts, ErrBusyV1)
	assertSourceReleaseCharge(t, o, m, size)
	o.ops = realSourceFS
	if markerPresent {
		path := filepath.Join(root, releaseFile)
		record := sourceReadFile(t, path)
		sourceMust(t, os.WriteFile(path, []byte{1}, 0o600))
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourcePresence(t, root, p.name, !clearing)
		assertSourceReleaseCharge(t, o, m, size)
		sourceMust(t, os.WriteFile(path, record, 0o600))
	}
	finishInconclusiveRelease(t, o, p, clearing, stage == "pending-absent")
	sourceFileCount(t, dir, 0, "resumed release left backing")
	sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
	sourcePrepare(t, o, foreign, parts)
	sourceRead(t, o, foreign, parts)
}

func injectInconclusiveRelease(t *testing.T, o *SourceOwnerV1, stage string, cause error) {
	t.Helper()
	switch stage {
	case "pending-absent", "pending-visible":
		o.ops.rename = func(r *os.Root, from, to string) error {
			if stage == "pending-visible" {
				sourceMust(t, r.Rename(from, to))
			}
			sourceMust(t, r.Close())
			return cause
		}
	case "clear-present", "clear-absent":
		o.ops.remove = func(r *os.Root, name string) error {
			if name != releaseFile {
				return r.Remove(name)
			}
			if stage == "clear-absent" {
				sourceMust(t, r.Remove(name))
			}
			sourceMust(t, r.Close())
			return cause
		}
	}
}

func finishInconclusiveRelease(t *testing.T, o *SourceOwnerV1, p *PreparedSourceV1, clearing, republish bool) {
	t.Helper()
	renames, unlinks, syncs := 0, 0, 0
	o.ops.rename = func(r *os.Root, from, to string) error { renames++; return r.Rename(from, to) }
	o.ops.remove = func(r *os.Root, name string) error {
		if name == p.name {
			unlinks++
		}
		return r.Remove(name)
	}
	o.ops.dirSync = func(r *sourceRoot) error { syncs++; return syncSourceRoot(r) }
	sourceReleaseResult(t, o, p, true, nil)
	wantRenames, wantUnlinks, wantSyncs := 0, 1, 3
	if republish {
		wantRenames, wantSyncs = 1, 5
	}
	if clearing {
		wantUnlinks, wantSyncs = 0, 1
	}
	sourceFailIf(t, renames != wantRenames || unlinks != wantUnlinks || syncs != wantSyncs, "release retry rename/unlink/sync=%d/%d/%d, want %d/%d/%d", renames, unlinks, syncs, wantRenames, wantUnlinks, wantSyncs)
	o.ops = realSourceFS
}

func assertSourceReleaseCharge(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, size uint64) {
	t.Helper()
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return o.withFiles(a, m, false, func(_ *sourceRoot, _ SourceManifestV1, _ uint64, used sourceUsage) error {
			sourceFailIf(t, used.files != 1 || used.bytes != size, "release charge: %d files/%d bytes, want 1/%d", used.files, used.bytes, size)
			return nil
		})
	})
}

func testSourceReleaseIncarnation(t *testing.T, mode string) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
	root := filepath.Join(dir, sourceDirectory)
	path, marker := filepath.Join(root, p.name), filepath.Join(root, releaseFile)
	original := sourceReadFile(t, path)
	changed := slices.Clone(original)
	if mode == "changed-content" {
		end := len(changed) - sha256.Size
		changed[end-1] ^= 1
		footer := sha256.Sum256(changed[:end])
		copy(changed[end:], footer[:])
		sourceMust(t, os.WriteFile(path, changed, 0o600))
		sourcePrepareRefusal(t, o, m, parts, ErrIntegrityV1)
		sourceReleaseResult(t, o, p, true, ErrIntegrityV1)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), changed), "refused release changed original backing")
		sourceFileCount(t, dir, 1, "refused release created intent")
		sourceMust(t, os.WriteFile(path, original, 0o600))
	}
	cause := errors.New("source unlink refusal")
	injectReleaseFault(o, "unlink", cause)
	sourceReleaseResult(t, o, p, true, cause)
	o = sourceReopen(t, s, dir, sourceLimits())
	record := sourceReadFile(t, marker)
	want := ErrIntegrityV1
	if mode != "changed-content" {
		moved := map[bool]string{false: filepath.Join(t.TempDir(), "original"), true: filepath.Join(root, "moved")}[mode == "linked-backing"]
		o.ops.dirSync = func(r *sourceRoot) error {
			o.ops.dirSync = syncSourceRoot
			sourceMust(t, syncSourceRoot(r))
			sourceMust(t, os.Rename(path, moved))
			if mode == "linked-backing" {
				return os.Symlink("moved", path)
			}
			return os.WriteFile(path, changed, 0o600)
		}
		want = ErrIdentityV1
	} else {
		end := len(record) - sha256.Size
		for _, offset := range []int{3, len(record) - 1, 4, 36, releasePrefix + 3, releasePrefix + 4, releasePrefix + bundleHeader - 1} {
			invalid := slices.Clone(record)
			invalid[offset] ^= 1
			if offset < end {
				digest := sha256.Sum256(invalid[:end])
				copy(invalid[end:], digest[:])
			}
			markerErr := ErrIntegrityV1
			if offset == 4 || offset == releasePrefix+4 {
				markerErr = ErrIdentityV1
			}
			if release, err := o.decodeRelease(invalid); release != nil || any(err) != any(markerErr) {
				t.Fatalf("release marker offset %d: %v/%v, want %v", offset, release, err, markerErr)
			}
		}
		sourceMust(t, os.WriteFile(path, changed, 0o600))
	}
	sourceReleaseResult(t, o, nil, true, want)
	sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), changed) || !bytes.Equal(sourceReadFile(t, marker), record),
		"refused release changed backing or intent")
	if mode == "linked-backing" {
		r, err := o.root(false)
		sourceMust(t, err)
		defer r.Close()
		sourceMust(t, os.Symlink("absent", filepath.Join(root, "dangling")))
		if os.Geteuid() != 0 {
			sourceMust(t, os.WriteFile(filepath.Join(root, "unreadable"), nil, 0))
		}
		for name, want := range map[string]error{p.name: ErrIntegrityV1, "dangling": ErrIntegrityV1, "unreadable": ErrUnavailableV1, "absent": ErrUnavailableV1} {
			_, err = openSourceFile(r, name, ErrUnavailableV1)
			sourceWantError(t, err, want, "open of "+name)
		}
	}
}

func testSourceReleaseStage(t *testing.T, stage string) {
	m, parts := sourceBundle(1, false)
	size, err := m.SizeV1()
	sourceMust(t, err)
	limits := sourceLimits()
	limits.Files, limits.Bytes = 1, size
	spare := stage == "unlink-reopen-competing-prepare"
	if spare {
		limits.Files, limits.Bytes = 2, 2*size
	}
	s, o, dir := sourceScene(t, limits)
	p := sourcePrepare(t, o, m, parts)
	root := filepath.Join(dir, sourceDirectory)
	originalSize := uint64(len(sourceReadFile(t, filepath.Join(root, p.name))))
	foreign := m
	foreign.Identity[0]++
	sourceReleaseResult(t, o, p, false, ErrIntegrityV1)
	sourceReleaseResult(t, o, nil, true, ErrIntegrityV1)
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return o.WithCapturedSourceV1(a, m, func(SourcePartV1) error {
			sourceWantError(t, o.ReleaseUnpublishedSourceV1(a, p, true), ErrBusyV1, "live export release")
			return nil
		})
	})
	cause := errors.New("release refusal")
	visible, backing := injectReleaseFault(o, stage, cause)
	sourceReleaseResult(t, o, p, true, cause)
	if visible {
		sourcePrepareRefusal(t, o, foreign, parts, ErrBusyV1)
	}
	fresh := sourceReopen(t, s, dir, limits)
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
	sourcePresence(t, root, p.name, backing)
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
		if !backing {
			assertSourceReleaseCharge(t, fresh, m, originalSize)
		}
		sourcePrepareRefusal(t, fresh, foreign, parts, ErrBusyV1)
		sourceReleaseResult(t, fresh, nil, true, nil)
	}
	sourceFileCount(t, dir, 0, "released backing or record remained")
	sourcePrepare(t, fresh, foreign, parts)
	if spare {
		sourcePrepareRefusal(t, fresh, oversized, parts, ErrCapacityV1)
		sourcePrepare(t, fresh, m, parts)
	}
}

func injectReleaseFault(o *SourceOwnerV1, stage string, cause error) (visible, backing bool) {
	switch stage {
	case "write", "file-sync", "close", "rename":
		sourceFault(o, stage, cause, nil)
		return false, true
	case "rename-visible":
		o.ops.rename = func(r *os.Root, from, to string) error {
			if err := r.Rename(from, to); err != nil {
				return err
			}
			return cause
		}
		return true, true
	case "unlink", "unlink-reopen-competing-prepare":
		sourceFault(o, "unlink", cause, nil)
		return true, true
	case "marker-clear":
		o.ops.remove = func(r *os.Root, name string) error {
			if name == releaseFile {
				return cause
			}
			return r.Remove(name)
		}
		return true, false
	}
	calls, failAt := 0, map[string]int{"intent-sync": 1, "unlink-sync": 2, "final-sync": 3}[stage]
	o.ops.dirSync = func(r *sourceRoot) error {
		calls++
		if calls == failAt {
			return cause
		}
		return r.pin.Sync()
	}
	return true, stage == "intent-sync"
}

func sourcePresence(t *testing.T, root, name string, present bool) {
	t.Helper()
	_, err := os.Lstat(filepath.Join(root, name))
	sourceFailIf(t, present && err != nil || !present && !errors.Is(err, os.ErrNotExist), "source path %q present=%t: %v", name, present, err)
}

func sourceReleaseResult(t *testing.T, o *SourceOwnerV1, p *PreparedSourceV1, proof bool, want error) {
	t.Helper()
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		sourceWantError(t, o.ReleaseUnpublishedSourceV1(a, p, proof), want, "source release")
		return nil
	})
}

func TestSourceReopenRequiresDirectorySync(t *testing.T) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	sourcePrepare(t, o, m, parts)
	opened := sourceReopenStore(t, s, dir)
	child, err := os.Stat(filepath.Join(dir, sourceDirectory))
	sourceMust(t, err)
	saved := realSourceFS
	defer func() { realSourceFS = saved }()
	calls := 0
	cause := errors.New("source directory sync")
	realSourceFS.dirSync = func(r *sourceRoot) error {
		calls++
		info, err := r.pin.Stat()
		sourceFailIf(t, err != nil || !os.SameFile(child, info), "source directory pin: %v", err)
		return cause
	}
	sourceOpen(t, opened, sourceID(), sourceLimits(), cause)
	sourceFailIf(t, calls != 1, "reopened directory sync calls=%d", calls)
	realSourceFS = saved
	fresh := sourceOpen(t, opened, sourceID(), sourceLimits(), nil)
	path := filepath.Join(dir, sourceDirectory, m.name(o.id))
	original := sourceReadFile(t, path)
	corrupt := slices.Clone(original)
	corrupt[len(corrupt)-1] ^= 1
	sourceMust(t, os.WriteFile(path, corrupt, 0o600))
	sourcePrepareRefusal(t, fresh, m, parts, ErrIntegrityV1)
	sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), corrupt), "refused reuse changed source bytes")
	sourceMust(t, os.WriteFile(path, original, 0o600))
	sourcePrepare(t, fresh, m, parts)
	sourceRead(t, fresh, m, parts)
}

func TestSourceNoOverwriteAndDistinctCopies(t *testing.T) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
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
	producer := func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		return sourceExportParts(op, m, parts, func(part SourcePartV1) error { return sourceAlteredPart("length", part, visit) })
	}
	sourcePrepareResult(t, o, m, producer, ErrIntegrityV1)
	sourceFailIf(t, !bytes.Equal(original[:1], sourceReadFile(t, staging)) || !bytes.Equal(original, sourceReadFile(t, path)), "refused reuse changed backing")
	sourcePrepare(t, o, m, parts)
	sourcePresence(t, filepath.Dir(staging), filepath.Base(staging), false)
	sourceRead(t, o, m, parts)
	t.Run("acquired-copy", testSourceAcquiredCopies)
	t.Run("name-occupied-during-export", func(t *testing.T) {
		_, owner, dir := sourceScene(t, sourceLimits())
		root := filepath.Join(dir, sourceDirectory)
		path := filepath.Join(root, p.name)
		producer := sourceAfterFirstPart(m, changed, func() error {
			sourcePresence(t, root, ".staging-"+p.name, true)
			return os.WriteFile(path, original, 0o600)
		})
		sourcePrepareResult(t, owner, m, producer, ErrIntegrityV1)
		sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), original) || len(sourceEntries(t, dir)) != 1 || owner.debt != nil,
			"name collision changed existing bytes or retained staging")
	})
	t.Run("stale-prepared", func(t *testing.T) {
		_, owner, dir := sourceScene(t, sourceLimits())
		a, b := sourcePrepare(t, owner, m, parts), sourcePrepare(t, owner, m, parts)
		copied := *b
		sourceReleaseResult(t, owner, a, true, nil)
		replacement := sourcePrepare(t, owner, m, parts)
		for _, old := range []*PreparedSourceV1{b, &copied} {
			sourceReleaseResult(t, owner, old, true, ErrIntegrityV1)
			sourceRead(t, owner, m, parts)
		}
		sourceReleaseResult(t, owner, replacement, true, nil)
		sourcePresence(t, filepath.Join(dir, sourceDirectory), replacement.name, false)
	})
}

func testSourceAcquiredCopies(t *testing.T) {
	const common = "0100000000000000000000000000000000000000000000000000000000000000" +
		"00000000dc6c2a3fd574b0f69ddd16d999b2ed94cdc20a399ef12b0d84eb8cd6" +
		"7d5a22021b04000000000000ffffffffffffffffffffffffffffffffffffffff" +
		"ffffffffffffffffffffffff0000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000010100000002010000000000" +
		"0000000000000000010000000000000000000000000000000000000000000000" +
		"00000000000000000000521ec18851e17bbba961bc46c70baf03ee67ebdea11a" +
		"8306de39c15a90e9d2e500"
	s, o, dir := sourceScene(t, sourceLimits())
	one, first := acquiredSourceFrame(t, common+"0142", 237, "115b308a43ffbe3e33feef20751954bbe327086396dfc5ffb3804674af89a30c")
	two, second := acquiredSourceFrame(t, common+"024243", 238, "5be9beac7d666b77658007d0cb47c6ed4c7adc3183ea51e563587bd85b5d662e")
	a, b := sourcePrepare(t, o, one, first), sourcePrepare(t, o, two, second)
	sourceFailIf(t, a.name == b.name || !bytes.Equal(first[0][:235], second[0][:235]),
		"acquired copies did not retain distinct suffixes and a common frame prefix")
	o = sourceReopen(t, s, dir, sourceLimits())
	sourceRead(t, o, one, first)
	sourceRead(t, o, two, second)
}

func acquiredSourceFrame(t *testing.T, encoded string, size int, want string) (SourceManifestV1, [][]byte) {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	sourceMust(t, err)
	digest := sha256.Sum256(raw)
	sourceFailIf(t, len(raw) != size || hex.EncodeToString(digest[:]) != want, "acquired frame length or digest: %d/%x", len(raw), digest)
	m, parts := sourceBundle(3, false)
	parts[0], m.Parts[0].Length, m.AcquiredDigest = raw, uint64(size), digest
	return m, parts
}

func TestSourceCapacityBeforeCopy(t *testing.T) {
	t.Run("statfs-exact-fit", testSourceSpaceExactFit)
	m, parts := sourceBundle(1, false)
	size, err := m.SizeV1()
	sourceMust(t, err)
	for _, mode := range []string{"bytes", "files", "statfs-error", "statfs-zero", "statfs-overflow", "statfs-space", "census-name", "census-link", "census-staging", "census-files", "census-bytes", "census-scans"} {
		t.Run(mode, func(t *testing.T) {
			limits := sourceLimits()
			if mode == "bytes" {
				limits.Bytes = size - 1
			}
			if mode == "files" {
				limits.Files = 1
			}
			_, o, dir := sourceScene(t, limits)
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
					if mode == "census-bytes" {
						sourceMust(t, os.Truncate(path, int64(limits.Bytes)+1))
					}
				}
			case "files":
				sourcePrepare(t, o, m, parts)
				m.Identity[1]++
			case "statfs-error", "statfs-zero", "statfs-overflow", "statfs-space":
				o.ops.statfs = func(_ int, s *syscall.Statfs_t) error {
					if mode == "statfs-error" {
						return io.ErrUnexpectedEOF
					}
					sourceStatfsFixture(s, 1, size+limits.Overhead-1)
					switch mode {
					case "statfs-zero":
						sourceStatfsFixture(s, 0, math.MaxUint64)
					case "statfs-overflow":
						sourceStatfsFixture(s, 2, math.MaxUint64)
					}
					return nil
				}
			}
			before := sourceEntries(t, dir)
			sourcePrepareRefusal(t, o, m, parts, want)
			sourceFailIf(t, !reflect.DeepEqual(sourceEntries(t, dir), before), "admission changed existing source files")
		})
	}
}

func sourceStatfsFixture(stat *syscall.Statfs_t, unit, available uint64) {
	stat.Bsize = 4096
	stat.Bavail = available
	if runtime.GOOS == "linux" {
		reflect.ValueOf(stat).Elem().FieldByName("Frsize").SetInt(int64(unit))
	} else {
		reflect.ValueOf(stat).Elem().FieldByName("Bsize").SetUint(unit)
	}
}

func testSourceSpaceExactFit(t *testing.T) {
	_, o, _, m, parts := sourceBundleScene(t, 1, false)
	size, err := m.SizeV1()
	sourceMust(t, err)
	o.ops.statfs = func(_ int, stat *syscall.Statfs_t) error {
		sourceStatfsFixture(stat, 1, size+o.limits.Overhead)
		return nil
	}
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
}

func TestSourceLimitsAndIdentity(t *testing.T) {
	t.Run("source-directory-mode", testSourceDirectoryMode)
	s, _, dir := sourceScene(t, sourceLimits())
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
		if field == "Profile" {
			v.SetUint(2)
		} else {
			v.Index(0).SetUint(99)
		}
		sourceOpen(t, s, wrong, sourceLimits(), ErrIdentityV1)
	}
	sourceFileCount(t, dir, 0, "invalid admission created backing")
}

func testSourceDirectoryMode(t *testing.T) {
	dir := t.TempDir()
	sourceMust(t, os.Chmod(dir, 0o700))
	s, err := policycontrol.Create(dir, sourceID(), policycontrol.NewInstallationProof{Identity: sourceID()})
	sourceMust(t, err)
	defer s.Close()
	root := filepath.Join(dir, sourceDirectory)
	sourceMust(t, os.Mkdir(root, 0o700))
	for _, mode := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		sourceMust(t, os.Chmod(root, mode|0o700))
		info, err := os.Lstat(root)
		sourceMust(t, err)
		sourceFailIf(t, info.Mode() != os.ModeDir|mode|0o700, "source directory mode not established: %v", info.Mode())
		sourceOpen(t, s, sourceID(), sourceLimits(), ErrIdentityV1)
	}
	sourceMust(t, os.Chmod(root, 0o700))
	o := sourceOpen(t, s, sourceID(), sourceLimits(), nil)
	m, parts := sourceBundle(1, false)
	p := sourcePrepare(t, o, m, parts)
	path := filepath.Join(root, p.name)
	before := sourceReadFile(t, path)
	for _, mode := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		sourceMust(t, os.Chmod(root, mode|0o700))
		sourcePrepareRefusal(t, o, m, parts, ErrIdentityV1)
		sourceFailIf(t, !bytes.Equal(before, sourceReadFile(t, path)), "mode refusal changed retained backing")
	}
	sourceMust(t, os.Chmod(root, 0o700))
	sourceRead(t, o, m, parts)
}

func TestSourceSharedCaptureBudget(t *testing.T) {
	t.Run("live-length", testSourceLiveLength)
	t.Run("counted-name-lost", testSourceCountedNameLost)
	for _, mode := range []string{"exact", "files", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			first, one := sourceBundle(1, false)
			second, two := sourceBundle(3, false)
			a, err := first.SizeV1()
			sourceMust(t, err)
			b, err := second.SizeV1()
			sourceMust(t, err)
			limits := sourceLimits()
			limits.Bytes, limits.Files = a+b, 2
			switch mode {
			case "files":
				limits.Bytes = a + 2*b
			case "bytes":
				limits.Bytes, limits.Files = a+b-1, 3
			}
			_, o, dir := sourceScene(t, limits)
			original := sourcePrepare(t, o, first, one)
			attempt := second
			if mode != "bytes" {
				sourcePrepare(t, o, second, two)
				attempt.Identity[0]++
			}
			before := sourceEntries(t, dir)
			sourcePrepareRefusal(t, o, attempt, two, ErrCapacityV1)
			sourceFailIf(t, !reflect.DeepEqual(before, sourceEntries(t, dir)), "shared capacity changed retained backing")
			if mode == "files" {
				path, moved := filepath.Join(dir, sourceDirectory, original.name), filepath.Join(dir, "moved")
				sourceMust(t, os.Rename(path, moved))
				sourcePrepareRefusal(t, o, attempt, two, ErrIntegrityV1)
				sourceFileCount(t, dir, 1, "refused preparation created backing")
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
}

func testSourceLiveLength(t *testing.T) {
	m, parts := sourceBundle(1, false)
	size, err := m.SizeV1()
	sourceMust(t, err)
	limits := sourceLimits()
	limits.Bytes, limits.Files = 2*size-1, 2
	_, o, dir := sourceScene(t, limits)
	p := sourcePrepare(t, o, m, parts)
	path := filepath.Join(dir, sourceDirectory, p.name)
	before, err := os.Stat(path)
	sourceMust(t, err)
	data := sourceReadFile(t, path)
	sourceMust(t, os.Truncate(path, before.Size()-1))
	after, err := os.Stat(path)
	sourceMust(t, err)
	sourceFailIf(t, !os.SameFile(before, after) || after.Size() != before.Size()-1, "did not shorten the live inode")
	other := m
	other.Identity[0]++
	sourcePrepareRefusal(t, o, other, parts, ErrIntegrityV1)
	sourceFileCount(t, dir, 1, "length refusal changed the source census")
	sourceMust(t, os.WriteFile(path, data, 0o600))
	sourceRead(t, o, m, parts)
	sourceFailIf(t, sourcePrepare(t, o, m, parts).incarnation != p.incarnation, "retained source token changed")
}

func testSourceCountedNameLost(t *testing.T) {
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
	path, moved := filepath.Join(dir, sourceDirectory, p.name), filepath.Join(dir, "counted")
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return o.withFiles(a, m, true, func(r *sourceRoot, admitted SourceManifestV1, size uint64, used sourceUsage) error {
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
		})
	})
	sourceFileCount(t, dir, 0, "replacement after counted backing disappeared")
	sourceMust(t, os.Rename(moved, path))
	sourceRead(t, o, m, parts)
	sourceFailIf(t, sourcePrepare(t, o, m, parts).incarnation != p.incarnation, "retained source token changed")
}

func TestSourcePositiveInsufficientLimits(t *testing.T) {
	s, _, _ := sourceScene(t, sourceLimits())
	ram, descriptors := sourceLimits(), sourceLimits()
	ram.RAM = ram.WorkingBytesV1() - 1
	descriptors.Descriptors = 3
	for _, limits := range []SourceLimitsV1{ram, descriptors} {
		sourceOpen(t, s, sourceID(), limits, ErrCapacityV1)
	}
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
	funded := mdbx.TreeLaneMaxBytes - (65536 + 4096 + 64*512) - sourceBackingCharge(parts)
	producer := func(op *SourceOperationV1, v func(SourcePartV1) error) error {
		return sourceExportParts(op, m, parts, func(part SourcePartV1) error {
			read := part.ReadAt
			part.ReadAt = func(dst []byte, off int64) (int, error) { maximum = max(maximum, len(dst)); return read(dst, off) }
			return v(part)
		})
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(funded, func() error {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			p, err := o.PrepareSourceV1(a, m, producer)
			runtime.ReadMemStats(&after)
			sourceFailIf(t, err != nil || p == nil, "maximum capture: %v/%v", p, err)
			sourceFailIf(t, after.TotalAlloc-before.TotalAlloc >= 2*65536, "prepare heap allocation: %d bytes", after.TotalAlloc-before.TotalAlloc)
			limitErr := a.WithReservation(mdbx.TreeLaneMaxBytes-funded+1, func() error { t.Fatal("caller funding was released"); return nil })
			sourceFailIf(t, !mdbx.IsOperationReservationCapacity(limitErr), "caller charge: %v", limitErr)
			return a.WithReservation(mdbx.TreeLaneMaxBytes-funded, func() error { return nil })
		})
	})
	sourceFailIf(t, maximum == 0 || maximum > 65536, "copy scratch=%d", maximum)
	sourceRead(t, o, m, parts)
}

func TestSourceStagingRestartAndAmbiguousRename(t *testing.T) {
	for _, mode := range []string{"staging", "renamed", "unobserved-renamed", "unobserved-staged"} {
		t.Run(mode, func(t *testing.T) {
			s, o, dir, m, parts := sourceBundleScene(t, 1, false)
			cause := errors.New("rename observation")
			if mode != "staging" {
				o.ops.rename = func(r *os.Root, from, to string) error {
					if mode != "unobserved-staged" {
						if err := r.Rename(from, to); err != nil {
							return err
						}
					}
					if mode != "renamed" {
						sourceMust(t, r.Close())
					}
					return cause
				}
				o.ops.remove = func(_ *os.Root, name string) error { return os.Remove(filepath.Join(dir, sourceDirectory, name)) }
				sourcePrepareResult(t, o, m, sourceProducer(m, parts), cause)
				sourceFailIf(t, o.debt == nil || o.debt.staging, "ambiguous publication debt: %+v", o.debt)
				sourceFileCount(t, dir, 1, "ambiguous publication lost backing")
			} else {
				sourceMust(t, os.WriteFile(filepath.Join(dir, sourceDirectory, ".staging-"+m.name(o.id)), []byte{1, 2, 3}, 0o600))
			}
			if mode == "unobserved-renamed" || mode == "unobserved-staged" {
				o.ops = realSourceFS
				sourcePrepare(t, o, m, parts)
				sourceRead(t, o, m, parts)
				sourceFileCount(t, dir, 1, "same identity retry retained staging")
			}
			fresh := sourceReopen(t, s, dir, sourceLimits())
			if mode == "staging" {
				sourceReadRefusal(t, fresh, m, ErrBusyV1, "staging owner readback")
			}
			sourcePrepare(t, fresh, m, parts)
			sourceRead(t, fresh, m, parts)
		})
	}
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
	sourceFailIf(t, o.live[name] != token || (o.debt == nil) != reuse || !reuse && (o.debt.name != name || o.debt.staging),
		"moved root changed the retained owner: token=%v debt=%+v", o.live[name], o.debt)
	sourcePresence(t, moved, name, true)
	sourceFileCount(t, dir, 0, "replacement directory acquired backing")
	sourceMust(t, os.Remove(root))
	sourceMust(t, os.Rename(moved, root))
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
}

func TestSourceOperationAuthorityAdmission(t *testing.T) {
	t.Run("second-owner-in-export", testSourceSecondOwner)
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
	before := sourceEntries(t, dir)
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
		sourceFailIf(t, prepared != nil || calls != 0 || !reflect.DeepEqual(before, sourceEntries(t, dir)), "refused authority changed source owners")
	}
	check(nil, ErrCapacityV1)
	var closed *mdbx.OperationAccount
	unexpected := func() error { t.Fatal("unfunded reservation ran"); return nil }
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		closed = a
		return a.WithReservation(mdbx.TreeLaneMaxBytes-o.limits.WorkingBytesV1()+1, func() error {
			check(a, a.WithReservation(o.limits.WorkingBytesV1(), unexpected))
			return nil
		})
	})
	for _, a := range []*mdbx.OperationAccount{{}, closed} {
		check(a, a.WithReservation(0, unexpected))
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		tx, err := s.Begin()
		sourceMust(t, err)
		check(a, policycontrol.ErrBusy)
		_, err = tx.Abort()
		sourceMust(t, err)
		sourceMust(t, s.Close())
		check(a, policycontrol.ErrClosed)
		o = nil
		check(a, ErrIdentityV1)
		return nil
	})
}

func testSourceSecondOwner(t *testing.T) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	alias := s
	producer := sourceAfterFirstPart(m, parts, func() error {
		root, stage := filepath.Join(dir, sourceDirectory), ".staging-"+m.name(o.id)
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
}

func TestSourcePreparationPanicRetainsCleanup(t *testing.T) {
	s, o, _, m, parts := sourceBundleScene(t, 1, false)
	original := slices.Clone(parts[0])
	cause := errors.New("export panic")
	cleanup := errors.New("cleanup refusal")
	o.ops.remove = func(*os.Root, string) error {
		sourceWantError(t, s.Close(), policycontrol.ErrBusy, "cleanup lost authority")
		return cleanup
	}
	producer := sourceAfterFirstPart(m, parts, func() error { panic(cause) })
	var caught any
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		func() { defer func() { caught = recover() }(); _, _ = o.PrepareSourceV1(a, m, producer) }()
		sourceFailIf(t, caught != any(cause) || o.debt == nil || !o.debt.staging || !bytes.Equal(parts[0], original), "panic owner: %v %+v", caught, o.debt)
		return a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil })
	})
	o.ops = realSourceFS
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
}

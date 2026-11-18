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
	if count := len(sourceEntries(t, dir)); count != want {
		t.Fatalf("%s: got %d files, want %d", message, count, want)
	}
}

func sourcePrepareRefusal(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, want error) {
	t.Helper()
	calls := 0
	sourcePrepareResult(t, o, m, func(op *SourceOperationV1, v func(SourcePartV1) error) error {
		calls++
		return sourceExportParts(op, m, parts, v)
	}, want)
	if calls != 0 {
		t.Fatalf("refused source preparation entered producer %d times", calls)
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
			_, o, dir, m, parts := sourceBundleScene(t, class, true)
			p := sourcePrepare(t, o, m, parts)
			path := filepath.Join(dir, sourceDirectory, p.name)
			image := sourceReadFile(t, path)
			refuse := func(b []byte) {
				sourceMust(t, os.WriteFile(path, b, 0o600))
				calls := 0
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					err := o.WithCapturedSourceV1(a, m, func(SourcePartV1) error { calls++; return nil })
					if any(err) != any(ErrIntegrityV1) || calls != 0 {
						t.Fatalf("malformed source: length=%d error=%v calls=%d", len(b), err, calls)
					}
					return nil
				})
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
							if err := v(sourceMemoryPart(ExpectedHeaderPathV1, parts[1])); any(err) != any(ErrIntegrityV1) {
								t.Fatalf("nested source delivery: %v", err)
							}
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
				if p != nil || any(err) != any(ErrIntegrityV1) {
					t.Fatalf("part refusal: %v/%v", p, err)
				}
				return nil
			})
			if mode == "nested-delivery" && !nested {
				t.Fatal("admitted read did not finish after nested refusal")
			}
			if late != nil {
				if err := late(SourcePartV1{}); any(err) != any(ErrUnavailableV1) {
					t.Fatalf("expired callback: %v", err)
				}
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
					if err := s.Close(); any(err) != any(policycontrol.ErrBusy) {
						t.Fatalf("close in source I/O: %v", err)
					}
					failed = true
				})
				want := cause
				if stage == "statfs" {
					want = ErrCapacityV1
				}
				sourcePrepareResult(t, o, m, sourceProducer(m, parts), want)
				sourceFailIf(t, !failed, "durability operation did not reach %s", stage)
				if stage == "parent-sync" && (o.debt == nil || o.debt.staging || len(sourceEntries(t, dir)) != 1) {
					t.Fatal("renamed backing lost its owner")
				}
				if stage != "parent-sync" && (o.debt != nil || len(sourceEntries(t, dir)) != 0) {
					t.Fatal("unpublished cleanup was not completed")
				}
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
	_, o, dir, m, parts := sourceBundleScene(t, 1, false)
	parts[0] = bytes.Repeat([]byte{42}, 70000)
	m.Parts[0].Length = 70000
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
		if p != nil || !errors.Is(err, cause) || !errors.Is(err, cleanup) || errors.Is(err, later) || o.debt == nil || !o.debt.staging {
			t.Fatalf("partial owner: %v/%v %+v", p, err, o.debt)
		}
		return nil
	})
	staging := filepath.Join(dir, sourceDirectory, ".staging-"+m.name(o.id))
	info, err := os.Stat(staging)
	sourceMust(t, err)
	if info.Size() <= 0 || info.Size() >= 70000 {
		t.Fatalf("partial size=%d", info.Size())
	}
	testSourceUnfundedBacking(t, o, m, parts, staging)
	foreign := m
	foreign.Identity[0]++
	sourcePrepareRefusal(t, o, foreign, parts, ErrBusyV1)
	o.ops = realSourceFS
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
	sourcePresence(t, filepath.Dir(staging), filepath.Base(staging), false)
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
	for _, stage := range []string{"write", "file-sync", "close", "rename", "intent-sync", "unlink", "unlink-reopen-competing-prepare", "unlink-sync", "marker-clear", "final-sync"} {
		t.Run(stage, func(t *testing.T) { testSourceReleaseStage(t, stage) })
	}
	t.Run("changed-content", func(t *testing.T) { testSourceReleaseIncarnation(t, false) })
	t.Run("changed-inode", func(t *testing.T) { testSourceReleaseIncarnation(t, true) })
}

func testSourceReleaseIncarnation(t *testing.T, replacement bool) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	p := sourcePrepare(t, o, m, parts)
	cause := errors.New("source unlink refusal")
	injectReleaseFault(o, "unlink", cause)
	sourceReleaseResult(t, o, p, true, cause)
	o = sourceReopen(t, s, dir, sourceLimits())
	root := filepath.Join(dir, sourceDirectory)
	path, marker := filepath.Join(root, p.name), filepath.Join(root, releaseFile)
	changed := sourceReadFile(t, path)
	record := sourceReadFile(t, marker)
	want := ErrIntegrityV1
	if replacement {
		original := filepath.Join(t.TempDir(), "original")
		o.ops.dirSync = func(r *sourceRoot) error {
			o.ops.dirSync = syncSourceRoot
			sourceMust(t, syncSourceRoot(r))
			sourceMust(t, os.Rename(path, original))
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
		changed[len(changed)-33] ^= 1
		footer := sha256.Sum256(changed[:len(changed)-32])
		copy(changed[len(changed)-32:], footer[:])
		sourceMust(t, os.WriteFile(path, changed, 0o600))
	}
	sourceReleaseResult(t, o, nil, true, want)
	sourceFailIf(t, !bytes.Equal(sourceReadFile(t, path), changed) || !bytes.Equal(sourceReadFile(t, marker), record),
		"refused release changed backing or intent")
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
	foreign := m
	foreign.Identity[0]++
	sourceReleaseResult(t, o, p, false, ErrIntegrityV1)
	sourceReleaseResult(t, o, nil, true, ErrIntegrityV1)
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return o.WithCapturedSourceV1(a, m, func(SourcePartV1) error {
			if err := o.ReleaseUnpublishedSourceV1(a, p, true); any(err) != any(ErrBusyV1) {
				t.Fatalf("live export release: %v", err)
			}
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
	if spare {
		sourcePrepareRefusal(t, fresh, foreign, parts, ErrBusyV1)
	}
	root := filepath.Join(dir, sourceDirectory)
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
		sourcePrepareRefusal(t, fresh, foreign, parts, ErrBusyV1)
		sourceReleaseResult(t, fresh, nil, true, nil)
	}
	sourceFileCount(t, dir, 0, "released backing or record remained")
	sourcePrepare(t, fresh, foreign, parts)
	if spare {
		sourcePrepare(t, fresh, m, parts)
	}
}

func injectReleaseFault(o *SourceOwnerV1, stage string, cause error) (visible, backing bool) {
	switch stage {
	case "write", "file-sync", "close", "rename":
		sourceFault(o, stage, cause, nil)
		return false, true
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
		if err := o.ReleaseUnpublishedSourceV1(a, p, proof); any(err) != any(want) {
			t.Fatalf("source release: %v, want %v", err, want)
		}
		return nil
	})
}

func TestSourceReopenRequiresDirectorySync(t *testing.T) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	sourcePrepare(t, o, m, parts)
	sourceMust(t, s.Close())
	opened, err := policycontrol.Open(dir, sourceID())
	sourceMust(t, err)
	defer opened.Close()
	child, err := os.Stat(filepath.Join(dir, sourceDirectory))
	sourceMust(t, err)
	saved := realSourceFS
	defer func() { realSourceFS = saved }()
	calls := 0
	cause := errors.New("source directory sync")
	realSourceFS.dirSync = func(r *sourceRoot) error {
		calls++
		info, err := r.pin.Stat()
		if err != nil || !os.SameFile(child, info) {
			t.Fatalf("source directory pin: %v", err)
		}
		return cause
	}
	sourceOpen(t, opened, sourceID(), sourceLimits(), cause)
	sourceFailIf(t, calls != 1, "reopened directory sync calls=%d", calls)
	realSourceFS = saved
	fresh := sourceOpen(t, opened, sourceID(), sourceLimits(), nil)
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
	sourceRead(t, o, m, parts)
	sourceRead(t, o, accepted, acceptedParts)
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
	if len(raw) != size || hex.EncodeToString(digest[:]) != want {
		t.Fatalf("acquired frame length or digest: %d/%x", len(raw), digest)
	}
	m, parts := sourceBundle(3, false)
	parts[0], m.Parts[0].Length, m.AcquiredDigest = raw, uint64(size), digest
	return m, parts
}

func TestSourceCapacityBeforeCopy(t *testing.T) {
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
				o.ops.statfs = func(fd int, s *syscall.Statfs_t) error {
					if mode == "statfs-error" {
						return io.ErrUnexpectedEOF
					}
					if err := syscall.Fstatfs(fd, s); err != nil {
						return err
					}
					switch mode {
					case "statfs-zero":
						s.Bsize = 0
					case "statfs-overflow":
						s.Bavail = math.MaxUint64
					case "statfs-space":
						s.Bavail = 0
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

func TestSourceLimitsAndIdentity(t *testing.T) {
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

func TestSourceSharedCaptureBudget(t *testing.T) {
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
				sourceMust(t, os.Rename(moved, path))
			}
			sourceRead(t, o, first, one)
			if mode != "bytes" {
				sourceRead(t, o, second, two)
			}
		})
	}
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
			p, err := o.PrepareSourceV1(a, m, producer)
			sourceFailIf(t, err != nil || p == nil, "maximum capture: %v/%v", p, err)
			if err := a.WithReservation(mdbx.TreeLaneMaxBytes-funded+1, func() error { t.Fatal("caller funding was released"); return nil }); !mdbx.IsOperationReservationCapacity(err) {
				t.Fatalf("caller charge: %v", err)
			}
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
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					p, err := o.PrepareSourceV1(a, m, sourceProducer(m, parts))
					if p != nil || !errors.Is(err, cause) || o.debt == nil || o.debt.staging {
						t.Fatalf("ambiguous publication: %v/%v %+v", p, err, o.debt)
					}
					sourceFileCount(t, dir, 1, "ambiguous publication lost backing")
					return nil
				})
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
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					err := fresh.WithCapturedSourceV1(a, m, func(SourcePartV1) error { t.Fatal("staging name was accepted as source"); return nil })
					sourceFailIf(t, any(err) != any(ErrBusyV1), "staging owner: %v", err)
					return nil
				})
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
		if err := syscall.Fstatfs(fd, stat); err != nil {
			return err
		}
		if err := os.Rename(sourcePath, retained); err != nil {
			return err
		}
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
	if reuse {
		sourcePrepare(t, o, m, parts)
	}
	root, moved := filepath.Join(dir, sourceDirectory), filepath.Join(dir, "moved")
	producer := sourceAfterFirstPart(m, parts, func() error {
		sourceMust(t, os.Rename(root, moved))
		return os.Mkdir(root, 0o700)
	})
	sourcePrepareResult(t, o, m, producer, ErrIdentityV1)
	sourcePresence(t, moved, m.name(o.id), true)
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
		if err := s.Close(); any(err) != any(policycontrol.ErrBusy) {
			t.Fatalf("cleanup lost authority: %v", err)
		}
		return cleanup
	}
	producer := sourceAfterFirstPart(m, parts, func() error { panic(cause) })
	var caught any
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		func() { defer func() { caught = recover() }(); _, _ = o.PrepareSourceV1(a, m, producer) }()
		if caught != any(cause) || o.debt == nil || !o.debt.staging || !bytes.Equal(parts[0], original) {
			t.Fatalf("panic owner: %v %+v", caught, o.debt)
		}
		return a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil })
	})
	o.ops = realSourceFS
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
}

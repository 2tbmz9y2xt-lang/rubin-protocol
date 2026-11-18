package exclusionjournal

import (
	"bytes"
	"crypto/sha256"
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

func sourcePrepareRefusal(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte, want error) {
	t.Helper()
	calls := 0
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		p, err := o.PrepareSourceV1(a, m, func(v func(SourcePartV1) error) error { calls++; return ExportSourceBytesV1(m, parts, v) })
		if p != nil || any(err) != any(want) || calls != 0 {
			t.Fatalf("preparation refusal: %v/%v want=%v calls=%d", p, err, want, calls)
		}
		return nil
	})
}

func sourceFault(o *SourceOwnerV1, stage string, cause error, failed *bool, observe func()) {
	once := func() error {
		if observe != nil {
			observe()
		}
		if !*failed {
			*failed = true
			return cause
		}
		return nil
	}
	run := func(action func() error) error {
		if err := once(); err != nil {
			return err
		}
		return action()
	}
	switch stage {
	case "write":
		o.ops.write = func(f *os.File, b []byte) (int, error) {
			if err := once(); err != nil {
				return 0, err
			}
			return realSourceFS.write(f, b)
		}
	case "file-sync":
		o.ops.fileSync = func(f *os.File) error {
			return run(f.Sync)
		}
	case "close":
		o.ops.close = func(f *os.File) error {
			return run(f.Close)
		}
	case "rename":
		o.ops.rename = func(r *os.Root, a, b string) error {
			return run(func() error { return r.Rename(a, b) })
		}
	case "parent-sync":
		o.ops.dirSync = func(r *sourceRoot) error {
			return run(r.pin.Sync)
		}
	case "unlink":
		o.ops.remove = func(r *os.Root, n string) error {
			return run(func() error { return r.Remove(n) })
		}
	case "statfs":
		o.ops.statfs = func(fd int, s *syscall.Statfs_t) error {
			return run(func() error { return syscall.Fstatfs(fd, s) })
		}
	}
}

func TestSourceCodecCorpus(t *testing.T) {
	for _, class := range []byte{1, 3} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			_, o, dir := sourceScene(t, sourceLimits())
			m, parts := sourceBundle(class, true)
			p := sourcePrepare(t, o, m, parts)
			path := filepath.Join(dir, sourceDirectory, p.name)
			image, err := os.ReadFile(path)
			sourceMust(t, err)
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
			}
			for n := range image {
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
			_, o, dir := sourceScene(t, sourceLimits())
			m, parts := sourceBundle(row.class, false)
			row.edit(&m)
			sourcePrepareRefusal(t, o, m, parts, ErrIntegrityV1)
			if len(sourceEntries(t, dir)) != 0 {
				t.Fatal("manifest refusal published bytes")
			}
		})
	}
}

func TestSourcePartAndAssuranceRefusals(t *testing.T) {
	for _, mode := range []string{"short", "extra", "reorder", "length", "unreadable", "full-extra", "conditional-short", "conditional-zero", "unknown-assurance", "digest-substitution", "nil-producer", "missing-callback", "nil-reader", "ignored-refusal"} {
		t.Run(mode, func(t *testing.T) {
			_, o, dir := sourceScene(t, sourceLimits())
			class := byte(3)
			if mode == "short" || mode == "unreadable" || mode == "length" {
				class = 1
			}
			m, parts := sourceBundle(class, false)
			switch mode {
			case "full-extra":
				parts[3] = []byte{1, 1}
			case "conditional-short":
				parts[3] = []byte{2, 1}
			case "conditional-zero":
				parts[3] = make([]byte, 33)
				parts[3][0] = 2
			case "unknown-assurance":
				parts[3] = []byte{9}
			case "digest-substitution":
				parts[0] = slices.Clone(m.AcquiredDigest[:])
			}
			for i := range parts {
				m.Parts[i].Length = uint64(len(parts[i]))
			}
			producer := sourceProducer(m, parts)
			var late func(SourcePartV1) error
			switch mode {
			case "nil-producer":
				producer = nil
			case "missing-callback":
				producer = func(func(SourcePartV1) error) error { return nil }
			case "nil-reader":
				producer = func(v func(SourcePartV1) error) error {
					return v(SourcePartV1{Kind: m.Parts[0].Kind, Length: m.Parts[0].Length})
				}
			case "ignored-refusal":
				producer = func(v func(SourcePartV1) error) error {
					late = v
					_ = v(SourcePartV1{})
					return ExportSourceBytesV1(m, parts, v)
				}
			}
			if mode == "short" || mode == "unreadable" {
				producer = func(v func(SourcePartV1) error) error {
					return ExportSourceBytesV1(m, parts, func(p SourcePartV1) error {
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
						return v(p)
					})
				}
			}
			if mode == "extra" {
				producer = func(v func(SourcePartV1) error) error {
					if err := ExportSourceBytesV1(m, parts, v); err != nil {
						return err
					}
					return ExportSourceBytesV1(m, parts, v)
				}
			}
			if mode == "reorder" || mode == "length" {
				producer = func(v func(SourcePartV1) error) error {
					return ExportSourceBytesV1(m, parts, func(p SourcePartV1) error {
						if mode == "reorder" {
							p.Kind = 1
						} else {
							p.Length++
						}
						return v(p)
					})
				}
			}
			sourceAccount(t, func(a *mdbx.OperationAccount) error {
				if mode == "length" || mode == "nil-reader" || mode == "missing-callback" {
					calls := 0
					err := o.WithSourceExportV1(a, m, producer, func(SourcePartV1) error { calls++; return nil })
					if any(err) != any(ErrIntegrityV1) || calls != 0 {
						t.Fatalf("declared length refusal: %v/%d", err, calls)
					}
				}
				p, err := o.PrepareSourceV1(a, m, producer)
				if p != nil || any(err) != any(ErrIntegrityV1) {
					t.Fatalf("part refusal: %v/%v", p, err)
				}
				return nil
			})
			if late != nil {
				if err := late(SourcePartV1{}); any(err) != any(ErrUnavailableV1) {
					t.Fatalf("expired callback: %v", err)
				}
			}
			if len(sourceEntries(t, dir)) != 0 || o.debt != nil {
				t.Fatal("part refusal lost cleanup ownership")
			}
		})
	}
}

func TestSourceDurabilityFailures(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "close", "rename", "parent-sync", "statfs"} {
		for _, reopen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reopen%v", stage, reopen), func(t *testing.T) {
				s, o, dir := sourceScene(t, sourceLimits())
				m, parts := sourceBundle(1, false)
				original, err := os.ReadFile(filepath.Join(dir, "policy-control"))
				sourceMust(t, err)
				cause := errors.New("filesystem refusal")
				failed := false
				sourceFault(o, stage, cause, &failed, func() {
					if err := s.Close(); any(err) != any(policycontrol.ErrBusy) {
						t.Fatalf("close in source I/O: %v", err)
					}
				})
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					p, err := o.PrepareSourceV1(a, m, sourceProducer(m, parts))
					matches := errors.Is(err, cause)
					if stage == "statfs" {
						matches = any(err) == any(ErrCapacityV1)
					}
					if p != nil || !matches || !failed {
						t.Fatalf("durability refusal: %v/%v stage=%s", p, err, stage)
					}
					return nil
				})
				if stage == "parent-sync" {
					if o.debt == nil || o.debt.staging || len(sourceEntries(t, dir)) != 1 {
						t.Fatal("renamed backing lost its owner")
					}
				} else if o.debt != nil || len(sourceEntries(t, dir)) != 0 {
					t.Fatal("unpublished cleanup was not completed")
				}
				o.ops = realSourceFS
				if reopen {
					o = sourceReopen(t, s, dir, sourceLimits())
				}
				sourcePrepare(t, o, m, parts)
				sourceRead(t, o, m, parts)
				after, err := os.ReadFile(filepath.Join(dir, "policy-control"))
				sourceMust(t, err)
				if !bytes.Equal(original, after) {
					t.Fatal("source operation changed control bytes")
				}
			})
		}
	}
}

func TestSourcePartialCleanupRetry(t *testing.T) {
	_, o, dir := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
	parts[0] = bytes.Repeat([]byte{42}, 70000)
	m.Parts[0].Length = 70000
	cause := errors.New("partial read")
	cleanup := errors.New("unlink refusal")
	o.ops.remove = func(*os.Root, string) error { return cleanup }
	producer := func(v func(SourcePartV1) error) error {
		return ExportSourceBytesV1(m, parts, func(p SourcePartV1) error {
			if p.Kind == 1 {
				read := p.ReadAt
				p.ReadAt = func(dst []byte, off int64) (int, error) {
					if off != 0 {
						return 0, cause
					}
					return read(dst, off)
				}
			}
			return v(p)
		})
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		p, err := o.PrepareSourceV1(a, m, producer)
		if p != nil || !errors.Is(err, cleanup) || o.debt == nil || !o.debt.staging {
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
	foreign := m
	foreign.Identity[0]++
	calls := 0
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		p, err := o.PrepareSourceV1(a, foreign, func(func(SourcePartV1) error) error { calls++; return nil })
		if p != nil || any(err) != any(ErrBusyV1) || calls != 0 {
			t.Fatal("unreconciled owner allowed another preparation")
		}
		return nil
	})
	o.ops = realSourceFS
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
	if _, err = os.Stat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial staging was resumed or retained")
	}
}

func TestSourceReleaseOnlyRetry(t *testing.T) {
	for _, stage := range []string{"unlink", "parent-sync"} {
		for _, reopen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reopen%v", stage, reopen), func(t *testing.T) {
				m, parts := sourceBundle(1, false)
				size, err := m.SizeV1()
				sourceMust(t, err)
				limits := sourceLimits()
				limits.Files = 1
				limits.Bytes = size
				s, o, dir := sourceScene(t, limits)
				p := sourcePrepare(t, o, m, parts)
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					if err := o.ReleaseUnpublishedSourceV1(a, p, false); any(err) != any(ErrIntegrityV1) {
						t.Fatalf("unreconciled release: %v", err)
					}
					return o.WithCapturedSourceV1(a, m, func(SourcePartV1) error {
						if err := o.ReleaseUnpublishedSourceV1(a, p, true); any(err) != any(ErrBusyV1) {
							t.Fatalf("live export release: %v", err)
						}
						return nil
					})
				})
				cause := errors.New("release refusal")
				failed := false
				sourceFault(o, stage, cause, &failed, nil)
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					if err := o.ReleaseUnpublishedSourceV1(a, p, true); !errors.Is(err, cause) || p.released || o.debt == nil || !o.debt.release {
						t.Fatalf("release owner: %v %+v", err, o.debt)
					}
					return nil
				})
				foreign := m
				foreign.Identity[0]++
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					prepared, err := o.PrepareSourceV1(a, foreign, sourceProducer(foreign, parts))
					if prepared != nil || any(err) != any(ErrBusyV1) {
						t.Fatal("release-only owner allowed preparation")
					}
					return nil
				})
				o.ops = realSourceFS
				if reopen {
					o = sourceReopen(t, s, dir, limits)
					if stage == "parent-sync" {
						if len(sourceEntries(t, dir)) != 0 {
							t.Fatal("unlinked source reappeared")
						}
						sourcePrepare(t, o, foreign, parts)
						return
					}
					p = sourcePrepare(t, o, m, parts)
				}
				sourceAccount(t, func(a *mdbx.OperationAccount) error { return o.ReleaseUnpublishedSourceV1(a, p, true) })
				if !p.released || o.debt != nil || len(sourceEntries(t, dir)) != 0 {
					t.Fatal("successful release retained charge")
				}
				sourcePrepare(t, o, foreign, parts)
			})
		}
	}
}

func TestSourceReopenRequiresDirectorySync(t *testing.T) {
	s, o, dir := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
	p := sourcePrepare(t, o, m, parts)
	cause := errors.New("source directory sync")
	o.ops.dirSync = func(*sourceRoot) error { return cause }
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		if err := o.ReleaseUnpublishedSourceV1(a, p, true); any(err) != any(cause) || p.released || o.debt == nil || !o.debt.removed {
			t.Fatalf("release sync refusal: %v %+v", err, o.debt)
		}
		return nil
	})
	if len(sourceEntries(t, dir)) != 0 {
		t.Fatal("source unlink did not complete")
	}
	sourceMust(t, s.Close())
	opened, err := policycontrol.Open(dir, sourceID())
	sourceMust(t, err)
	defer opened.Close()
	child, err := os.Stat(filepath.Join(dir, sourceDirectory))
	sourceMust(t, err)
	saved := realSourceFS
	defer func() { realSourceFS = saved }()
	calls := 0
	realSourceFS.dirSync = func(r *sourceRoot) error {
		calls++
		info, err := r.pin.Stat()
		if err != nil || !os.SameFile(child, info) {
			t.Fatalf("source directory pin: %v", err)
		}
		return cause
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		fresh, err := NewSourceOwnerV1(opened, sourceID(), sourceLimits(), a)
		if fresh != nil || any(err) != any(cause) || calls != 1 {
			t.Fatalf("reopened directory sync refusal: %v/%v calls=%d", fresh, err, calls)
		}
		return nil
	})
	realSourceFS = saved
	fresh := sourceReopen(t, opened, dir, sourceLimits())
	sourcePrepare(t, fresh, m, parts)
	sourceRead(t, fresh, m, parts)
}

func TestSourceNoOverwriteAndDistinctCopies(t *testing.T) {
	_, o, dir := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
	p := sourcePrepare(t, o, m, parts)
	path := filepath.Join(dir, sourceDirectory, p.name)
	original, err := os.ReadFile(path)
	sourceMust(t, err)
	for _, length := range []bool{false, true} {
		changed := append([][]byte(nil), parts...)
		changed[0] = slices.Clone(parts[0])
		changed[0][0] ^= 1
		manifest := m
		manifest.Parts = slices.Clone(m.Parts)
		if length {
			changed[0] = append(changed[0], 1)
			manifest.Parts[0].Length++
		}
		sourceAccount(t, func(a *mdbx.OperationAccount) error {
			p, err := o.PrepareSourceV1(a, manifest, sourceProducer(manifest, changed))
			if p != nil || any(err) != any(ErrIntegrityV1) {
				t.Fatalf("same identity overwrite: %v/%v", p, err)
			}
			return nil
		})
		after, err := os.ReadFile(path)
		sourceMust(t, err)
		if !bytes.Equal(after, original) || len(sourceEntries(t, dir)) != 1 {
			t.Fatal("same identity changed bytes or created another file")
		}
	}
	accepted, acceptedParts := sourceBundle(2, false)
	acceptedSource := sourcePrepare(t, o, accepted, acceptedParts)
	if p.name == acceptedSource.name {
		t.Fatal("distinct capture classes share identity")
	}
	sourceRead(t, o, m, parts)
	sourceRead(t, o, accepted, acceptedParts)
	first, one := sourceBundle(3, false)
	second, two := sourceBundle(3, false)
	two[0] = slices.Clone(two[0])
	two[0][0] ^= 1
	second.AcquiredDigest = sha256.Sum256(two[0])
	a, b := sourcePrepare(t, o, first, one), sourcePrepare(t, o, second, two)
	if a.name == b.name {
		t.Fatal("distinct acquired copies share identity")
	}
	sourceRead(t, o, first, one)
	sourceRead(t, o, second, two)
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
			}
			if mode == "files" {
				sourcePrepare(t, o, m, parts)
				m.Identity[1]++
			}
			if len(mode) > 6 && mode[:6] == "statfs" {
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
			if !reflect.DeepEqual(sourceEntries(t, dir), before) {
				t.Fatal("admission changed existing source files")
			}
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
	if len(sourceEntries(t, dir)) != 0 {
		t.Fatal("invalid admission created backing")
	}
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
			if mode == "files" {
				limits.Bytes = a + 2*b
			}
			if mode == "bytes" {
				limits.Bytes, limits.Files = a+b-1, 3
			}
			_, o, dir := sourceScene(t, limits)
			sourcePrepare(t, o, first, one)
			attempt := second
			if mode != "bytes" {
				sourcePrepare(t, o, second, two)
				attempt.Identity[0]++
			}
			before := sourceEntries(t, dir)
			sourcePrepareRefusal(t, o, attempt, two, ErrCapacityV1)
			if !reflect.DeepEqual(before, sourceEntries(t, dir)) {
				t.Fatal("shared capacity changed retained backing")
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
	for _, mode := range []string{"ram", "descriptors"} {
		limits := sourceLimits()
		if mode == "ram" {
			limits.RAM = limits.WorkingBytesV1() - 1
		} else {
			limits.Descriptors = 3
		}
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
	_, o, _ := sourceScene(t, limits)
	maximum := 0
	producer := func(v func(SourcePartV1) error) error {
		return ExportSourceBytesV1(m, parts, func(part SourcePartV1) error {
			read := part.ReadAt
			part.ReadAt = func(dst []byte, off int64) (int, error) { maximum = max(maximum, len(dst)); return read(dst, off) }
			return v(part)
		})
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(4096, func() error {
			p, err := o.PrepareSourceV1(a, m, producer)
			if err != nil || p == nil {
				t.Fatalf("maximum capture: %v/%v", p, err)
			}
			if err := a.WithReservation(mdbx.TreeLaneMaxBytes-4096+1, func() error { t.Fatal("caller funding was released"); return nil }); !mdbx.IsOperationReservationCapacity(err) {
				t.Fatalf("caller charge: %v", err)
			}
			return a.WithReservation(mdbx.TreeLaneMaxBytes-4096, func() error { return nil })
		})
	})
	if maximum == 0 || maximum > 65536 {
		t.Fatalf("copy scratch=%d", maximum)
	}
	sourceRead(t, o, m, parts)
}

func TestSourceStagingRestartAndAmbiguousRename(t *testing.T) {
	for _, mode := range []string{"staging", "renamed", "unobserved-renamed", "unobserved-staged"} {
		t.Run(mode, func(t *testing.T) {
			s, o, dir := sourceScene(t, sourceLimits())
			m, parts := sourceBundle(1, false)
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
					if len(sourceEntries(t, dir)) != 1 {
						t.Fatal("ambiguous publication lost backing")
					}
					return nil
				})
			} else {
				sourceMust(t, os.WriteFile(filepath.Join(dir, sourceDirectory, ".staging-"+m.name(o.id)), []byte{1, 2, 3}, 0o600))
			}
			if mode == "unobserved-renamed" || mode == "unobserved-staged" {
				o.ops = realSourceFS
				sourcePrepare(t, o, m, parts)
				sourceRead(t, o, m, parts)
				if len(sourceEntries(t, dir)) != 1 {
					t.Fatal("same identity retry retained staging")
				}
			}
			fresh := sourceReopen(t, s, dir, sourceLimits())
			if mode == "staging" {
				sourceAccount(t, func(a *mdbx.OperationAccount) error {
					err := fresh.WithCapturedSourceV1(a, m, func(SourcePartV1) error { t.Fatal("staging name was accepted as source"); return nil })
					if any(err) != any(ErrBusyV1) {
						t.Fatalf("staging owner: %v", err)
					}
					return nil
				})
			}
			sourcePrepare(t, fresh, m, parts)
			sourceRead(t, fresh, m, parts)
		})
	}
}

func TestSourceDirectoryChangeBeforeCopy(t *testing.T) {
	_, o, dir := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
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

func TestSourceOperationAuthorityAdmission(t *testing.T) {
	s, o, dir := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
	p := sourcePrepare(t, o, m, parts)
	before := sourceEntries(t, dir)
	check := func(want error) {
		calls := 0
		sourceAccount(t, func(a *mdbx.OperationAccount) error {
			producer := func(v func(SourcePartV1) error) error { calls++; return ExportSourceBytesV1(m, parts, v) }
			visitor := func(SourcePartV1) error { calls++; return nil }
			errorsSeen := []error{o.WithSourceExportV1(a, m, producer, visitor), o.WithCapturedSourceV1(a, m, visitor), o.ReleaseUnpublishedSourceV1(a, p, true)}
			prepared, err := o.PrepareSourceV1(a, m, producer)
			errorsSeen = append(errorsSeen, err)
			for _, err := range errorsSeen {
				if any(err) != any(want) {
					t.Fatalf("authority admission=%v, want %v", err, want)
				}
			}
			if prepared != nil || p.released || calls != 0 || !reflect.DeepEqual(before, sourceEntries(t, dir)) {
				t.Fatal("refused authority changed source owners")
			}
			return nil
		})
	}
	tx, err := s.Begin()
	sourceMust(t, err)
	check(policycontrol.ErrBusy)
	_, err = tx.Abort()
	sourceMust(t, err)
	sourceMust(t, s.Close())
	check(policycontrol.ErrClosed)
	o = nil
	check(ErrIdentityV1)
}

func TestSourcePreparationPanicRetainsCleanup(t *testing.T) {
	s, o, _ := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
	original := slices.Clone(parts[0])
	cause := errors.New("export panic")
	cleanup := errors.New("cleanup refusal")
	o.ops.remove = func(*os.Root, string) error {
		if err := s.Close(); any(err) != any(policycontrol.ErrBusy) {
			t.Fatalf("cleanup lost authority: %v", err)
		}
		return cleanup
	}
	producer := func(v func(SourcePartV1) error) error {
		return ExportSourceBytesV1(m, parts, func(part SourcePartV1) error {
			if err := v(part); err != nil {
				return err
			}
			panic(cause)
		})
	}
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

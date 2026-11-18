package exclusionjournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

func sourceID() policycontrol.Identity {
	return policycontrol.Identity{InstallationID: [32]byte{1}, ChainID: [32]byte{2}, GenesisHash: [32]byte{3}, Profile: 1}
}

func sourceLimits() SourceLimitsV1 {
	return SourceLimitsV1{Bytes: 8 << 20, Files: 8, Scans: 64, RAM: 1 << 20, Headers: 256, Descriptors: 4, Overhead: 4096}
}

func sourceMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func sourceAccount(t *testing.T, use func(*mdbx.OperationAccount) error) {
	t.Helper()
	o, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
	sourceMust(t, err)
	sourceMust(t, o.WithOperation(mdbx.TreeOperation, use))
}

func sourceOpen(t *testing.T, s *policycontrol.Store, id policycontrol.Identity, limits SourceLimitsV1, want error) *SourceOwnerV1 {
	t.Helper()
	var owner *SourceOwnerV1
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		var err error
		owner, err = NewSourceOwnerV1(s, id, limits, a)
		if any(err) != any(want) || (owner == nil) != (want != nil) {
			t.Fatalf("source owner: %v/%v want=%v limits=%+v identity=%+v", owner, err, want, limits, id)
		}
		return nil
	})
	return owner
}

func sourceScene(t *testing.T, limits SourceLimitsV1) (*policycontrol.Store, *SourceOwnerV1, string) {
	t.Helper()
	dir := t.TempDir()
	sourceMust(t, os.Chmod(dir, 0o700))
	s, err := policycontrol.Create(dir, sourceID(), policycontrol.NewInstallationProof{Identity: sourceID()})
	sourceMust(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s, sourceOpen(t, s, sourceID(), limits, nil), dir
}

func sourceReopen(t *testing.T, old *policycontrol.Store, dir string, limits SourceLimitsV1) *SourceOwnerV1 {
	t.Helper()
	sourceMust(t, old.Close())
	s, err := policycontrol.Open(dir, sourceID())
	sourceMust(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return sourceOpen(t, s, sourceID(), limits, nil)
}

func sourceBundle(class byte, conditional bool) (SourceManifestV1, [][]byte) {
	kinds := []byte{1, 2, 3, 4, 5, 6}
	parts := [][]byte{[]byte("original body bytes"), []byte("TX_ERR_EXACT"), []byte("original law/config/build"), {1}, []byte("original parent path"), {}}
	if class == 3 {
		kinds = []byte{7, 8, 3, 4, 9}
		parts = [][]byte{[]byte("acquired canonical bytes"), []byte("expected header path"), []byte("original law/config/build"), {1}, []byte("acquisition position")}
	}
	if conditional {
		parts[3] = []byte{2}
		for _, original := range []string{"b0", "H0", "E0", "COMPLETE"} {
			parts[3] = binary.LittleEndian.AppendUint64(parts[3], uint64(len(original)))
			parts[3] = append(parts[3], original...)
		}
	}
	m := SourceManifestV1{Identity: [32]byte{7}, Class: CaptureClassV1(class)}
	for i, kind := range kinds {
		m.Parts = append(m.Parts, SourcePartSpecV1{Kind: PartKindV1(kind), Length: uint64(len(parts[i]))})
	}
	if class == 3 {
		m.AcquiredDigest = sha256.Sum256(parts[0])
	}
	return m, parts
}

func sourceBundleScene(t *testing.T, class byte, conditional bool) (*policycontrol.Store, *SourceOwnerV1, string, SourceManifestV1, [][]byte) {
	t.Helper()
	s, o, dir := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(class, conditional)
	return s, o, dir, m, parts
}

func sourceProducer(m SourceManifestV1, parts [][]byte) SourceExporterV1 {
	return func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		return sourceExportParts(op, m, parts, visit)
	}
}

func sourceOrigins(parts [][]byte) ([]SourceOriginV1, []SourceViewV1) {
	var origins []SourceOriginV1
	views := make([]SourceViewV1, 0, len(parts))
	for _, part := range parts {
		if cap(part) == 0 {
			views = append(views, SourceViewV1{Origin: -1})
		} else {
			views = append(views, SourceViewV1{Origin: len(origins), Length: uint64(len(part))})
			origins = append(origins, SourceOriginV1{Bytes: part[:cap(part)]})
		}
	}
	return origins, views
}

func sourceExportParts(op *SourceOperationV1, m SourceManifestV1, parts [][]byte, visit func(SourcePartV1) error) error {
	origins, views := sourceOrigins(parts)
	return op.WithBackingV1(origins, views, func() error {
		for i, data := range parts {
			if err := visit(sourceMemoryPart(m.Parts[i].Kind, data)); err != nil {
				return err
			}
		}
		return nil
	})
}

func sourceMemoryPart(kind PartKindV1, data []byte) SourcePartV1 {
	return SourcePartV1{Kind: kind, Length: uint64(len(data)), ReadAt: func(dst []byte, off int64) (int, error) {
		return copy(dst, data[off:]), nil
	}}
}

func sourceAfterFirstPart(m SourceManifestV1, parts [][]byte, after func() error) SourceExporterV1 {
	return func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		return sourceExportParts(op, m, parts, func(part SourcePartV1) error {
			if err := visit(part); err != nil || part.Kind != m.Parts[0].Kind {
				return err
			}
			return after()
		})
	}
}

func sourceRead(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, want [][]byte, beforeFirst ...func()) {
	t.Helper()
	kinds := []byte{1, 2, 3, 4, 5, 6}
	if byte(m.Class) == 3 {
		kinds = []byte{7, 8, 3, 4, 9}
	}
	i := 0
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return o.WithCapturedSourceV1(a, m, func(part SourcePartV1) error {
			if i == 0 && len(beforeFirst) != 0 {
				beforeFirst[0]()
			}
			sourceCheckPart(t, part, i, kinds, want)
			i++
			return nil
		})
	})
	if i != len(want) {
		t.Fatalf("part count=%d, want %d", i, len(want))
	}
}

func sourceCheckPart(t *testing.T, part SourcePartV1, i int, kinds []byte, want [][]byte) []byte {
	t.Helper()
	if i >= len(want) {
		t.Fatal("extra source part")
	}
	buf := make([]byte, len(want[i]))
	n, err := part.ReadAt(buf, 0)
	if byte(part.Kind) != kinds[i] || part.Length != uint64(len(want[i])) || n != len(buf) || err != nil || !bytes.Equal(buf, want[i]) {
		t.Fatalf("part %d: kind=%d length=%d n=%d err=%v bytes=%x", i, part.Kind, part.Length, n, err, buf)
	}
	return buf
}

func sourcePrepare(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte) *PreparedSourceV1 {
	t.Helper()
	return sourcePrepareResult(t, o, m, sourceProducer(m, parts), nil)
}

func sourcePrepareResult(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, producer SourceExporterV1, want error) *PreparedSourceV1 {
	t.Helper()
	var p *PreparedSourceV1
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		var err error
		p, err = o.PrepareSourceV1(a, m, producer)
		if any(err) != any(want) || (p == nil) != (want != nil) {
			t.Fatalf("source preparation: %v/%v, want %v", p, err, want)
		}
		return nil
	})
	return p
}

func sourceChild(t *testing.T, dir, shape string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSourceChildV1$", "-test.count=1")
	cmd.Env = append(os.Environ(), "RUBIN_SOURCE_CHILD="+dir, "RUBIN_SOURCE_SHAPE="+shape)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("source child: %s: %v", output, err)
	}
}

func sourceReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	sourceMust(t, err)
	return data
}

func TestSourceDurableRoundTrip(t *testing.T) {
	for _, class := range []byte{1, 2, 3} {
		for _, conditional := range []bool{false, true} {
			t.Run(fmt.Sprintf("class%d/conditional%v", class, conditional), func(t *testing.T) {
				s, o, dir, m, parts := sourceBundleScene(t, class, conditional)
				generations := []string{t.TempDir(), t.TempDir()}
				for _, path := range generations {
					sourceMust(t, os.WriteFile(filepath.Join(path, "body"), parts[0], 0o600))
				}
				held, err := os.Open(filepath.Join(generations[0], "body"))
				sourceMust(t, err)
				defer held.Close()
				producer := func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
					return sourceExportParts(op, m, parts, func(part SourcePartV1) error {
						if part.Kind == m.Parts[0].Kind {
							part.ReadAt = held.ReadAt
						}
						return visit(part)
					})
				}
				p := sourcePrepareResult(t, o, m, producer, nil)
				file := filepath.Join(dir, sourceDirectory, p.name)
				original := sourceReadFile(t, file)
				sourcePrepareResult(t, o, m, producer, nil)
				sourceMust(t, held.Close())
				if !bytes.Equal(sourceReadFile(t, file), original) {
					t.Fatal("identical preparation changed bytes")
				}
				for _, path := range generations {
					sourceMust(t, os.RemoveAll(path))
				}
				sourceRead(t, o, m, parts)
				sourceMust(t, s.Close())
				sourceChild(t, dir, fmt.Sprintf("%d/%v", class, conditional))
			})
		}
	}
}

func TestSourceChildV1(t *testing.T) {
	dir := os.Getenv("RUBIN_SOURCE_CHILD")
	if dir == "" {
		return
	}
	s, err := policycontrol.Open(dir, sourceID())
	if os.Getenv("RUBIN_SOURCE_SHAPE") == "busy" {
		if s != nil || !errors.Is(err, policycontrol.ErrBusy) {
			t.Fatalf("writer exclusion: %v %v", s, err)
		}
		return
	}
	sourceMust(t, err)
	defer s.Close()
	var class byte
	var conditional bool
	_, err = fmt.Sscanf(os.Getenv("RUBIN_SOURCE_SHAPE"), "%d/%t", &class, &conditional)
	sourceMust(t, err)
	m, parts := sourceBundle(class, conditional)
	sourceRead(t, sourceOpen(t, s, sourceID(), sourceLimits(), nil), m, parts)
}

type sourceTypedError struct{}

func (*sourceTypedError) Error() string { return "typed visitor result" }

func TestSourceExportScope(t *testing.T) {
	direct := errors.New("visitor result")
	for _, row := range []struct {
		name  string
		cause error
	}{
		{"success", nil},
		{"error", direct},
		{"wrapped", fmt.Errorf("application: %w", direct)},
		{"typed-nil", (*sourceTypedError)(nil)},
		{"panic", direct},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, o, dir, m, parts := sourceBundleScene(t, 1, false)
			admitted := m
			admitted.Parts = slices.Clone(m.Parts)
			want := slices.Clone(parts[0])
			var escaped SourcePartV1
			var scope *SourceOperationV1
			producer := func(op *SourceOperationV1, v func(SourcePartV1) error) error {
				scope = op
				m.Parts[0].Length++
				return sourceExportParts(op, admitted, parts, v)
			}
			var copied []byte
			var got error
			var panicValue any
			calls := 0
			sourceAccount(t, func(a *mdbx.OperationAccount) error {
				func() {
					defer func() { panicValue = recover() }()
					got = o.WithSourceExportV1(a, m, producer, func(part SourcePartV1) error {
						buf := sourceCheckPart(t, part, calls, []byte{1, 2, 3, 4, 5, 6}, parts)
						calls++
						if calls != 1 {
							return nil
						}
						escaped = part
						if limits, err := scope.LimitsV1(); err != nil || limits != o.limits {
							t.Fatalf("live source limits: %+v/%v", limits, err)
						}
						copied = buf
						if n, err := part.ReadAt(make([]byte, 1), -1); n != 0 || any(err) != any(ErrIntegrityV1) {
							t.Fatal("negative range was read")
						}
						if n, err := part.ReadAt(make([]byte, part.Length+1), 0); n != 0 || any(err) != any(ErrIntegrityV1) {
							t.Fatal("oversized range was read")
						}
						if err := s.Close(); any(err) != any(policycontrol.ErrBusy) {
							t.Fatalf("close during export: %v", err)
						}
						tx, err := s.Begin()
						sourceMust(t, err)
						_, err = tx.Abort()
						sourceMust(t, err)
						sourceChild(t, dir, "busy")
						if row.name == "panic" {
							panic(row.cause)
						}
						return row.cause
					})
				}()
				if row.name == "panic" {
					if panicValue != any(row.cause) {
						t.Fatalf("panic=%v", panicValue)
					}
				} else if any(got) != any(row.cause) || row.name == "success" && calls != 6 {
					t.Fatalf("export result=%v count=%d", got, calls)
				}
				if n, err := escaped.ReadAt(make([]byte, 1), 0); n != 0 || any(err) != any(ErrUnavailableV1) {
					t.Fatalf("escaped read: %d/%v", n, err)
				}
				for _, expired := range []*SourceOperationV1{nil, {}, scope} {
					if err := expired.WithBackingV1(nil, nil, nil); any(err) != any(ErrUnavailableV1) {
						t.Fatalf("expired source operation: %v", err)
					}
				}
				parts[0][0] ^= 0x80
				if !bytes.Equal(copied, want) {
					t.Fatal("visitor copy aliases original backing")
				}
				return a.WithReservation(17, func() error { return nil })
			})
			sourceMust(t, s.Close())
		})
	}
}

func TestSourceBackingUnion(t *testing.T) {
	for _, mode := range []string{"shared", "equal-copies", "live-empty", "planned", "invalid-index", "invalid-offset", "missing-origin", "length", "overlap", "overflow"} {
		t.Run(mode, func(t *testing.T) { testSourceOriginAdmission(t, mode) })
	}
}

func testSourceOriginAdmission(t *testing.T, mode string) {
	_, o, _, m, _ := sourceBundleScene(t, 1, false)
	origins := []SourceOriginV1{{Bytes: make([]byte, 256)}}
	var views []SourceViewV1
	for i, part := range m.Parts {
		views = append(views, SourceViewV1{Origin: 0, Offset: uint64(i * 32), Length: part.Length})
	}
	charge, refusal := sourceOriginFixture(mode, &origins, views)
	for shortage := uint64(0); shortage <= 1; shortage++ {
		sourceAccount(t, func(a *mdbx.OperationAccount) error {
			return a.WithReservation(mdbx.TreeLaneMaxBytes-o.limits.WorkingBytesV1()-charge+shortage, func() error {
				entered := false
				err := o.WithSourceExportV1(a, m, func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
					return op.WithBackingV1(origins, views, func() error {
						entered = true
						if mode == "planned" {
							origins[0].Bytes = make([]byte, origins[0].PlannedBytes)
						}
						for i, part := range m.Parts {
							view := views[i]
							backing := origins[view.Origin].Bytes[view.Offset : view.Offset+view.Length]
							if err := visit(sourceMemoryPart(part.Kind, backing)); err != nil {
								return err
							}
						}
						return nil
					})
				}, func(SourcePartV1) error { return nil })
				if refusal != nil && (entered || any(err) != any(refusal)) || refusal == nil && shortage == 1 && (entered || !mdbx.IsOperationReservationCapacity(err)) ||
					refusal == nil && shortage == 0 && (!entered || err != nil) {
					t.Fatalf("origin admission, shortage=%d: entered=%t error=%v", shortage, entered, err)
				}
				if mode == "planned" {
					origins[0].Bytes = nil
				}
				return nil
			})
		})
	}
}

func sourceOriginFixture(mode string, origins *[]SourceOriginV1, views []SourceViewV1) (uint64, error) {
	switch mode {
	case "equal-copies", "live-empty":
		*origins = append(*origins, SourceOriginV1{Bytes: make([]byte, 256)})
		index := 1
		if mode == "live-empty" {
			index = len(views) - 1
		}
		views[index].Origin = 1
		return 512, nil
	case "planned":
		(*origins)[0] = SourceOriginV1{PlannedBytes: 256}
	case "invalid-index":
		views[0].Origin = -2
	case "invalid-offset":
		views[0].Offset = 256
	case "missing-origin":
		*origins = nil
	case "length":
		views[0].Length++
	case "overlap":
		*origins = append(*origins, (*origins)[0])
	case "overflow":
		(*origins)[0] = SourceOriginV1{PlannedBytes: math.MaxUint64}
	}
	if mode == "shared" || mode == "planned" {
		return 256, nil
	}
	return 256, ErrIntegrityV1
}

func TestSourcePreparedManifestOwnership(t *testing.T) {
	_, o, _, m, parts := sourceBundleScene(t, 1, false)
	admitted := slices.Clone(m.Parts)
	p := sourcePrepare(t, o, m, parts)
	m.Parts[0].Length++
	if !slices.Equal(p.manifest.Parts, admitted) {
		t.Fatal("prepared manifest aliases caller metadata")
	}
	m.Parts[0] = admitted[0]
	sourceRead(t, o, m, parts, func() { m.Parts[1].Length++ })
}

func TestSourceExpiryWaitsForAdmittedRead(t *testing.T) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	entered, allow, visitorLeft, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(allow) })
	wait := func(signal <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-signal:
		case <-time.After(5 * time.Second):
			t.Fatal(message)
		}
	}
	t.Cleanup(func() {
		release()
		wait(done, "source operation did not finish")
	})
	readDone := make(chan error, 1)
	var escaped SourcePartV1
	buf := make([]byte, len(parts[0]))
	producer := func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		return sourceExportParts(op, m, parts, func(part SourcePartV1) error {
			if byte(part.Kind) == 1 {
				read := part.ReadAt
				part.ReadAt = func(dst []byte, off int64) (int, error) { close(entered); <-allow; return read(dst, off) }
			}
			return visit(part)
		})
	}
	go func() {
		defer close(done)
		sourceAccount(t, func(a *mdbx.OperationAccount) error {
			err := o.WithSourceExportV1(a, m, producer, func(part SourcePartV1) error {
				escaped = part
				go func() { _, err := part.ReadAt(buf, 0); readDone <- err }()
				<-entered
				close(visitorLeft)
				return io.EOF
			})
			if any(err) != any(io.EOF) {
				t.Errorf("visitor result: %v", err)
			}
			return nil
		})
	}()
	wait(visitorLeft, "visitor did not enter")
	sourceChild(t, dir, "busy")
	select {
	case <-done:
		t.Fatal("export ended before an admitted read")
	default:
	}
	if err := s.Close(); any(err) != any(policycontrol.ErrBusy) {
		t.Fatalf("read lifetime lost source authority: %v", err)
	}
	release()
	wait(done, "read expiry did not finish")
	if err := <-readDone; err != nil || !bytes.Equal(buf, parts[0]) {
		t.Fatalf("admitted copy: %v/%x", err, buf)
	}
	if n, err := escaped.ReadAt(buf, 0); n != 0 || any(err) != any(ErrUnavailableV1) {
		t.Fatalf("expired read: %d/%v", n, err)
	}
	sourceMust(t, s.Close())
}

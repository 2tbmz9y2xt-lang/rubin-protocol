package exclusionjournal

import (
	"bytes"
	"cmp"
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

// TestSourceVerifiedReadWindows changes backing after qualification and before a partial read.
func TestSourceVerifiedReadWindows(t *testing.T) {
	t.Run("single-window-conditional-assurance", func(t *testing.T) {
		m, parts := sourceBundle(1, true)
		w := newSourceWindows(m)
		for _, malformed := range []bool{false, true} {
			data := bytes.Clone(parts[3])
			if malformed {
				data = data[:len(data)-1]
			}
			reader := bytes.NewReader(data)
			reads := 0
			part := SourcePartV1{Kind: OriginalAssuranceV1, Length: uint64(len(data)), ReadAt: func(dst []byte, off int64) (int, error) {
				reads++
				return reader.ReadAt(dst, off)
			}}
			var want error
			if malformed {
				want = ErrIntegrityV1
			}
			sourceWantError(t, w.checkAssurance(part), want, "conditional assurance")
			sourceFailIf(t, reads != 1, "conditional assurance made %d storage reads", reads)
		}
	})
	t.Run("visitor-lifetime-and-funding", func(t *testing.T) {
		s, o, dir, m, parts, _ := sourcePreparedBundle(t)
		exact := uint64(65536+4096) + 512*o.limits.Scans + 32*(o.limits.Bytes/65536+6)
		limits := o.limits
		limits.RAM = exact + limits.retainedRAM()
		o = sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), limits, nil)
		visitorErr := errors.New("visitor result")
		var escaped SourcePartV1
		sourceAccount(t, func(a *mdbx.OperationAccount) {
			sourceMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-exact+1, func() error {
				err := o.WithCapturedSourceV1(a, m, func(SourcePartV1) error { t.Fatal("unfunded read entered visitor"); return nil })
				sourceFailIf(t, !mdbx.IsOperationReservationCapacity(err), "unfunded read: %v", err)
				return nil
			}))
			sourceMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-exact, func() error {
				err := o.WithCapturedSourceV1(a, m, func(part SourcePartV1) error { escaped = part; return visitorErr })
				sourceWantError(t, err, visitorErr, "visitor result")
				func() {
					defer func() { sourceFailIf(t, recover() != any(visitorErr), "readback changed visitor panic") }()
					_ = o.WithCapturedSourceV1(a, m, func(part SourcePartV1) error { escaped = part; panic(visitorErr) })
				}()
				n, err := escaped.ReadAt(make([]byte, 1), 0)
				sourceFailIf(t, n != 0 || any(err) != any(ErrUnavailableV1), "expired retained reader: %d/%v", n, err)
				sourceReadOn(t, a, o, m, parts)
				return a.WithReservation(exact, func() error { return nil })
			}))
		})
		sourceRead(t, o, m, parts)
	})
	t.Run("invalid-assurance-before-visit", func(t *testing.T) {
		s, o, dir, m, parts := sourceBundleScene(t, 1, false)
		p := sourcePrepare(t, o, m, parts)
		path := filepath.Join(dir, sourceDirectory, p.name)
		image := sourceReadFile(t, path)
		offset := len(m.header(o.id)) + len(parts[0]) + len(parts[1]) + len(parts[2])
		image[offset] = 0
		end := len(image) - 32
		digest := sha256.Sum256(image[:end])
		copy(image[end:], digest[:])
		sourceMust(t, os.WriteFile(path, image, 0o600))
		fresh := sourceOpen(t, sourceReopenStore(t, s, dir), sourceID(), sourceLimits(), nil)
		sourceReadRefusal(t, fresh, m, ErrIntegrityV1, "malformed retained assurance")
	})
	for _, result := range []error{nil, errors.New("visitor result"), fmt.Errorf("wrapped: %w", io.EOF)} {
		t.Run(fmt.Sprint(result), func(t *testing.T) {
			_, o, dir, m, parts := sourceBundleScene(t, 1, false)
			parts[0] = bytes.Repeat([]byte{0x21}, 65536+37)
			m.Parts[0].Length = uint64(len(parts[0]))
			p := sourcePrepare(t, o, m, parts)
			f, err := os.OpenFile(filepath.Join(dir, sourceDirectory, p.name), os.O_RDWR, 0)
			sourceMust(t, err)
			defer f.Close()
			base := int64(len(m.header(o.id)))
			var visits int
			sourceAccount(t, func(a *mdbx.OperationAccount) {
				err := o.WithCapturedSourceV1(a, m, func(part SourcePartV1) error {
					visits++
					var intact [4]byte
					n, readErr := part.ReadAt(intact[:], 65534)
					sourceFailIf(t, readErr != nil || n != 4 || !bytes.Equal(intact[:], parts[0][65534:65538]), "intact crossing: %x/%d/%v", intact, n, readErr)
					_, err := f.WriteAt([]byte{0x20}, base+65536+36)
					sourceMust(t, err)
					buf := [4]byte{0xfe, 0xfe, 0xfe, 0xfe}
					n, readErr = part.ReadAt(buf[:], 65534)
					sourceFailIf(t, any(readErr) != any(ErrIntegrityV1) || n != 2 || buf != [4]byte{0x21, 0x21, 0xfe, 0xfe}, "changed crossing: %x/%d/%v", buf, n, readErr)
					n, readErr = part.ReadAt(buf[:1], 0)
					sourceFailIf(t, n != 0 || any(readErr) != any(ErrIntegrityV1), "read after failed window: %d/%v", n, readErr)
					return result
				})
				sourceWantError(t, err, ErrIntegrityV1, "changed retained window")
			})
			sourceFailIf(t, visits != 1, "visits after changed window: %d", visits)
			_, err = f.WriteAt([]byte{0x21}, base+65536+36)
			sourceMust(t, err)
			sourceRead(t, o, m, parts)
		})
	}
}

func testSourceProducerEndReads(t *testing.T) {
	t.Run("conditional-field", func(t *testing.T) {
		_, o, dir, m, parts := sourceBundleScene(t, 1, true)
		called := false
		producer := sourceMappedProducer(m, parts, func(p SourcePartV1, visit func(SourcePartV1) error) error {
			if p.Kind == OriginalAssuranceV1 {
				read := p.ReadAt
				p.ReadAt = func(b []byte, off int64) (int, error) {
					n, err := read(b, off)
					if off == 1 && len(b) == 8 {
						called = true
						return n, io.EOF
					}
					return n, err
				}
			}
			return visit(p)
		})
		sourcePrepareResult(t, o, m, producer, ErrIntegrityV1)
		sourceFailIf(t, !called || len(sourceEntries(t, dir)) != 0, "partial conditional read reached publication")
	})
	for _, kind := range []PartKindV1{BoundBodyV1, OriginalAssuranceV1} {
		for _, mode := range []string{"end", "early", "short", "short-nil", "wrapped", "other"} {
			t.Run(fmt.Sprintf("%d/%s", kind, mode), func(t *testing.T) {
				for _, reuse := range []bool{false, true} {
					_, o, _, m, parts := sourceBundleScene(t, 1, kind == OriginalAssuranceV1 && mode == "early")
					parts[0] = bytes.Repeat([]byte{1}, 65537)
					m.Parts[0].Length = uint64(len(parts[0]))
					if reuse {
						sourcePrepare(t, o, m, parts)
					}
					fired := false
					produce := sourceMappedProducer(m, parts, func(p SourcePartV1, v func(SourcePartV1) error) error {
						if p.Kind == kind {
							read := p.ReadAt
							p.ReadAt = func(dst []byte, off int64) (int, error) {
								n, err := read(dst, off)
								end := uint64(off)+uint64(n) == p.Length
								if end == (mode != "early") {
									fired = true
									return sourceEndResult(mode, n)
								}
								return n, err
							}
						}
						return v(p)
					})
					var want error
					if mode != "end" {
						want = ErrIntegrityV1
					}
					sourcePrepareResult(t, o, m, produce, want)
					sourceFailIf(t, !fired, "producer read case was not reached")
					if reuse || want == nil {
						sourceRead(t, o, m, parts)
					}
				}
			})
		}
	}
}

func sourceEndResult(mode string, n int) (int, error) {
	switch mode {
	case "short":
		return n - 1, io.EOF
	case "short-nil":
		return n - 1, nil
	case "wrapped":
		return n, fmt.Errorf("part: %w", io.EOF)
	case "other":
		return n, io.ErrUnexpectedEOF
	default:
		return n, io.EOF
	}
}

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

func sourceFailIf(t *testing.T, failed bool, format string, args ...any) {
	t.Helper()
	if failed {
		t.Fatalf(format, args...)
	}
}

func sourceWantError(t *testing.T, got, want error, action string) {
	t.Helper()
	sourceFailIf(t, any(got) != any(want), "%s: %v, want %v", action, got, want)
}

func sourceAccount(t *testing.T, check func(*mdbx.OperationAccount)) {
	t.Helper()
	o, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
	sourceMust(t, err)
	sourceMust(t, o.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		check(a)
		return nil
	}))
}

func sourceHandle[T any](t *testing.T, label string, want error, run func(*mdbx.OperationAccount) (*T, error)) *T {
	t.Helper()
	var handle *T
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		var err error
		handle, err = run(a)
		sourceFailIf(t, any(err) != any(want) || (handle == nil) != (want != nil), "%s: %v/%v, want %v", label, handle, err, want)
	})
	return handle
}

func sourceOpen(t *testing.T, s *policycontrol.Store, id policycontrol.Identity, limits SourceLimitsV1, want error) *SourceOwnerV1 {
	t.Helper()
	label := fmt.Sprintf("source owner limits=%+v identity=%+v", limits, id)
	return sourceHandle(t, label, want, func(a *mdbx.OperationAccount) (*SourceOwnerV1, error) {
		return NewSourceOwnerV1(s, id, limits, a)
	})
}

func sourceScene(t *testing.T, limits SourceLimitsV1) (*policycontrol.Store, *SourceOwnerV1, string) {
	t.Helper()
	s, dir := sourceStore(t)
	return s, sourceOpen(t, s, sourceID(), limits, nil), dir
}

func sourceStore(t *testing.T) (*policycontrol.Store, string) {
	t.Helper()
	dir := t.TempDir()
	sourceMust(t, os.Chmod(dir, 0o700))
	s, err := policycontrol.Create(dir, sourceID(), policycontrol.NewInstallationProof{Identity: sourceID()})
	sourceMust(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func sourceReopenStore(t *testing.T, old *policycontrol.Store, dir string) *policycontrol.Store {
	t.Helper()
	sourceMust(t, old.Close())
	s, err := policycontrol.Open(dir, sourceID())
	sourceMust(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sourceBundle(class byte, conditional bool) (SourceManifestV1, [][]byte) {
	m := SourceManifestV1{Identity: [32]byte{7}, Class: CaptureClassV1(class)}
	kinds := []byte{1, 2, 3, 4, 5, 6}
	parts := [][]byte{[]byte("original body bytes"), []byte("TX_ERR_EXACT"), []byte("original law/config/build"), {1}, []byte("original parent path"), {}}
	if class == 3 {
		kinds = []byte{7, 8, 3, 4, 9}
		parts = [][]byte{[]byte("acquired canonical bytes"), []byte("expected header path"), []byte("original law/config/build"), {1}, []byte("acquisition position")}
		m.AcquiredDigest = sha256.Sum256(parts[0])
	}
	if conditional {
		parts[3] = []byte{2}
		for _, original := range []string{"b0", "H0", "E0", "COMPLETE"} {
			parts[3] = binary.LittleEndian.AppendUint64(parts[3], uint64(len(original)))
			parts[3] = append(parts[3], original...)
		}
	}
	for i, kind := range kinds {
		m.Parts = append(m.Parts, SourcePartSpecV1{Kind: PartKindV1(kind), Length: uint64(len(parts[i]))})
	}
	return m, parts
}

func sourceBundleScene(t *testing.T, class byte, conditional bool) (*policycontrol.Store, *SourceOwnerV1, string, SourceManifestV1, [][]byte) {
	t.Helper()
	s, o, dir := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(class, conditional)
	return s, o, dir, m, parts
}

func sourcePreparedBundle(t *testing.T) (*policycontrol.Store, *SourceOwnerV1, string, SourceManifestV1, [][]byte, *PreparedSourceV1) {
	t.Helper()
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	return s, o, dir, m, parts, sourcePrepare(t, o, m, parts)
}

func sourceProducer(m SourceManifestV1, parts [][]byte) SourceExporterV1 {
	return func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		return sourceExportParts(op, m, parts, visit)
	}
}

func sourceMappedProducer(m SourceManifestV1, parts [][]byte, mapPart func(SourcePartV1, func(SourcePartV1) error) error) SourceExporterV1 {
	return func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		return sourceExportParts(op, m, parts, func(part SourcePartV1) error { return mapPart(part, visit) })
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
	return sourceMappedProducer(m, parts, func(part SourcePartV1, visit func(SourcePartV1) error) error {
		if err := visit(part); err != nil || part.Kind != m.Parts[0].Kind {
			return err
		}
		return after()
	})
}

func sourceRead(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, want [][]byte, beforeFirst ...func()) {
	t.Helper()
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceReadOn(t, a, o, m, want, beforeFirst...)
	})
}

func sourceReadOn(t *testing.T, a *mdbx.OperationAccount, o *SourceOwnerV1, m SourceManifestV1, want [][]byte, beforeFirst ...func()) {
	t.Helper()
	kinds := map[bool][]byte{false: {1, 2, 3, 4, 5, 6}, true: {7, 8, 3, 4, 9}}[m.Class == 3]
	i := 0
	sourceMust(t, o.WithCapturedSourceV1(a, m, func(part SourcePartV1) error {
		if i == 0 && len(beforeFirst) != 0 {
			beforeFirst[0]()
		}
		sourceCheckPart(t, part, i, kinds, want)
		i++
		return nil
	}))
	sourceFailIf(t, i != len(want), "part count=%d, want %d", i, len(want))
}

func sourceReadRefusal(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, want error, action string) {
	t.Helper()
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		sourceWantError(t, o.WithCapturedSourceV1(a, m, func(SourcePartV1) error { t.Fatalf("%s: refused source was visited", action); return nil }), want, action)
	})
}

func sourceCheckPart(t *testing.T, part SourcePartV1, i int, kinds []byte, want [][]byte) []byte {
	t.Helper()
	sourceFailIf(t, i >= len(want), "extra source part")
	buf := make([]byte, len(want[i]))
	n, err := part.ReadAt(buf, 0)
	sourceFailIf(t, byte(part.Kind) != kinds[i] || part.Length != uint64(len(want[i])) || n != len(buf) || err != nil || !bytes.Equal(buf, want[i]),
		"part %d: kind=%d length=%d n=%d err=%v bytes=%x", i, part.Kind, part.Length, n, err, buf)
	return buf
}

func sourcePrepare(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte) *PreparedSourceV1 {
	t.Helper()
	return sourcePrepareResult(t, o, m, sourceProducer(m, parts), nil)
}

func sourcePrepareAndRead(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte) {
	t.Helper()
	sourcePrepare(t, o, m, parts)
	sourceRead(t, o, m, parts)
}

func sourcePrepareResult(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, producer SourceExporterV1, want error) *PreparedSourceV1 {
	t.Helper()
	return sourceHandle(t, "source preparation", want, func(a *mdbx.OperationAccount) (*PreparedSourceV1, error) {
		return o.PrepareSourceV1(a, m, producer)
	})
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
				sourceReadRefusal(t, o, m, ErrUnavailableV1, "unprepared source readback")
				generations, backed := []string{t.TempDir(), t.TempDir()}, map[PartKindV1]*os.File{}
				for i, path := range generations {
					sourceMust(t, os.WriteFile(filepath.Join(path, "part"), parts[i], 0o600))
					held, err := os.Open(filepath.Join(path, "part"))
					sourceMust(t, err)
					t.Cleanup(func() { _ = held.Close() })
					backed[m.Parts[i].Kind] = held
				}
				producer := sourceMappedProducer(m, parts, func(part SourcePartV1, visit func(SourcePartV1) error) error {
					if held := backed[part.Kind]; held != nil {
						part.ReadAt = held.ReadAt
					}
					return visit(part)
				})
				p := sourcePrepareResult(t, o, m, producer, nil)
				file := filepath.Join(dir, sourceDirectory, p.name)
				original := sourceReadFile(t, file)
				sourcePrepareResult(t, o, m, producer, nil)
				sourceFailIf(t, !bytes.Equal(sourceReadFile(t, file), original), "identical preparation changed bytes")
				for i, path := range generations {
					sourceMust(t, errors.Join(backed[m.Parts[i].Kind].Close(), os.RemoveAll(path)))
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
		sourceFailIf(t, s != nil || !errors.Is(err, policycontrol.ErrBusy), "writer exclusion: %v %v", s, err)
		return
	}
	sourceMust(t, err)
	defer s.Close()
	class, conditional := byte(0), false
	_, err = fmt.Sscanf(os.Getenv("RUBIN_SOURCE_SHAPE"), "%d/%t", &class, &conditional)
	sourceMust(t, err)
	m, parts := sourceBundle(class, conditional)
	sourceRead(t, sourceOpen(t, s, sourceID(), sourceLimits(), nil), m, parts)
}

type sourceTypedError struct{}

func (*sourceTypedError) Error() string { return "typed visitor result" }

type sourceExportCase struct {
	name                              string
	result, visitorPanic, exportPanic error
	finalPart                         bool
}

func TestSourceExportScope(t *testing.T) {
	direct := errors.New("visitor result")
	visitorPanic, exporterPanic := errors.New("final visitor panic"), errors.New("exporter panic")
	for _, row := range []sourceExportCase{
		{name: "recovered-final-panic", visitorPanic: visitorPanic, finalPart: true},
		{name: "visitor-panic-repanicked", visitorPanic: visitorPanic, exportPanic: exporterPanic, finalPart: true},
		{name: "exporter-panic", exportPanic: exporterPanic, finalPart: true},
		{name: "success"},
		{name: "error", result: direct},
		{name: "wrapped", result: fmt.Errorf("application: %w", direct)},
		{name: "typed-nil", result: (*sourceTypedError)(nil)},
		{name: "panic", visitorPanic: direct},
	} {
		t.Run(row.name, func(t *testing.T) { testSourceExportScope(t, row) })
	}
}

func testSourceExportScope(t *testing.T, row sourceExportCase) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	admitted := m
	admitted.Parts = slices.Clone(m.Parts)
	var escaped SourcePartV1
	var operation *SourceOperationV1
	var caught, wantCaught any
	at := 1
	if row.finalPart {
		at, wantCaught = len(parts), row.visitorPanic
	}
	producer := func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
		operation = op
		m.Parts[0].Length++
		if row.finalPart {
			defer func() {
				caught = recover()
				if row.exportPanic != nil {
					panic(row.exportPanic)
				}
			}()
		}
		return sourceExportParts(op, admitted, parts, visit)
	}
	calls := 0
	var copied []byte
	wantBytes := slices.Clone(parts[at-1])
	visit := func(part SourcePartV1) error {
		buf := sourceCheckPart(t, part, calls, []byte{1, 2, 3, 4, 5, 6}, parts)
		calls++
		if calls != at {
			return nil
		}
		escaped, copied = part, buf
		if !row.finalPart {
			assertSourceLiveExport(t, s, dir, operation, part)
		}
		if row.visitorPanic != nil {
			panic(row.visitorPanic)
		}
		return row.result
	}
	sourceAccount(t, func(a *mdbx.OperationAccount) {
		var got error
		outer := catchSourcePanic(func() { got = o.WithSourceExportV1(a, m, producer, visit) })
		wantPanic := cmp.Or(row.visitorPanic, row.exportPanic)
		wantCalls := len(parts)
		if row.result != nil || wantPanic != nil {
			wantCalls = at
		}
		sourceFailIf(t, caught != wantCaught || outer != any(wantPanic) || any(got) != any(row.result) || calls != wantCalls,
			"export result=%v caught=%v panic=%v deliveries=%d", got, caught, outer, calls)
		n, err := escaped.ReadAt(make([]byte, len(copied)), 0)
		sourceFailIf(t, n != 0 || any(err) != any(ErrUnavailableV1), "escaped read: %d/%v", n, err)
		_, err = operation.LimitsV1()
		sourceWantError(t, err, ErrUnavailableV1, "expired source limits")
		for _, expired := range []*SourceOperationV1{nil, {}, operation} {
			sourceWantError(t, expired.WithBackingV1(nil, nil, nil), ErrUnavailableV1, "expired source operation")
		}
		sourceFailIf(t, !bytes.Equal(copied, wantBytes), "visitor copy changed after expiry: %x", copied)
		sourceMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil }))
	})
	if row.finalPart {
		sourcePrepareAndRead(t, o, admitted, parts)
	}
	sourceMust(t, s.Close())
}

func assertSourceLiveExport(t *testing.T, s *policycontrol.Store, dir string, scope *SourceOperationV1, part SourcePartV1) {
	t.Helper()
	limits, err := scope.LimitsV1()
	sourceFailIf(t, err != nil || limits != sourceLimits(), "live source limits: %+v/%v", limits, err)
	for _, row := range []struct{ size, offset int64 }{{1, -1}, {int64(part.Length) + 1, 0}} {
		n, err := part.ReadAt(make([]byte, row.size), row.offset)
		sourceFailIf(t, n != 0 || any(err) != any(ErrIntegrityV1), "out of bounds read %d/%d: %d/%v", row.offset, row.size, n, err)
	}
	sourceWantError(t, s.Close(), policycontrol.ErrBusy, "close during export")
	tx, err := s.Begin()
	sourceMust(t, err)
	_, err = tx.Abort()
	sourceMust(t, err)
	sourceChild(t, dir, "busy")
}

func catchSourcePanic(use func()) (caught any) {
	defer func() { caught = recover() }()
	use()
	return nil
}

func TestSourceBackingUnion(t *testing.T) {
	origin := SourceOriginV1{Bytes: make([]byte, 256)}
	shared := []SourceOriginV1{origin}
	separate := []SourceOriginV1{origin, {Bytes: make([]byte, 256)}}
	limits := sourceLimits()
	ram := limits.RAM - limits.WorkingBytesV1() - limits.retainedRAM()
	for _, row := range []struct {
		name    string
		origins []SourceOriginV1
		edit    func([]SourceViewV1)
		charge  uint64
		refusal error
	}{
		{"shared", shared, nil, 256, nil},
		{"equal-copies", separate, func(v []SourceViewV1) { v[1].Origin = 1 }, 512, nil},
		{"live-empty", separate, func(v []SourceViewV1) { v[len(v)-1].Origin = 1 }, 512, nil},
		{"planned", []SourceOriginV1{{PlannedBytes: 256}}, nil, 256, nil},
		{"invalid-index", shared, func(v []SourceViewV1) { v[0].Origin = -2 }, 256, ErrIntegrityV1},
		{"invalid-offset", shared, func(v []SourceViewV1) { v[0].Offset = 256 }, 256, ErrIntegrityV1},
		{"missing-origin", nil, nil, 256, ErrIntegrityV1},
		{"length", shared, func(v []SourceViewV1) { v[0].Length++ }, 256, ErrIntegrityV1},
		{"overlap", []SourceOriginV1{origin, origin}, nil, 256, ErrIntegrityV1},
		{"overflow", []SourceOriginV1{{PlannedBytes: math.MaxUint64}}, nil, 256, ErrIntegrityV1},
		{"sum-overflow", []SourceOriginV1{origin, {PlannedBytes: math.MaxInt}, {PlannedBytes: math.MaxInt - 253}}, nil, 256, ErrCapacityV1},
		{"ram-limit", []SourceOriginV1{origin, {PlannedBytes: ram - 255}}, nil, ram + 1, ErrCapacityV1},
		{"ram-exact", []SourceOriginV1{origin, {PlannedBytes: ram - 256}}, nil, ram, nil},
	} {
		t.Run(row.name, func(t *testing.T) { testSourceOriginAdmission(t, row.origins, row.edit, row.charge, row.refusal) })
	}
}

func testSourceOriginAdmission(t *testing.T, origins []SourceOriginV1, edit func([]SourceViewV1), charge uint64, refusal error) {
	_, o, _, m, _ := sourceBundleScene(t, 1, false)
	var views []SourceViewV1
	for i, part := range m.Parts {
		views = append(views, SourceViewV1{Offset: uint64(i * 32), Length: part.Length})
	}
	if edit != nil {
		edit(views)
	}
	for shortage := uint64(0); shortage <= 1; shortage++ {
		sourceAccount(t, func(a *mdbx.OperationAccount) {
			sourceMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-o.limits.WorkingBytesV1()-charge+shortage, func() error {
				entered := false
				err := o.WithSourceExportV1(a, m, func(op *SourceOperationV1, visit func(SourcePartV1) error) error {
					return op.WithBackingV1(origins, views, func() error {
						entered = true
						if refusal != nil {
							return nil
						}
						if origins[0].PlannedBytes != 0 {
							origins[0].Bytes = make([]byte, origins[0].PlannedBytes)
							defer func() { origins[0].Bytes = nil }()
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
				switch {
				case refusal != nil:
					sourceFailIf(t, entered || any(err) != any(refusal), "refused origin: entered=%t error=%v, want %v", entered, err, refusal)
				case shortage == 1:
					sourceFailIf(t, entered || !mdbx.IsOperationReservationCapacity(err), "unfunded origin: entered=%t error=%v", entered, err)
				default:
					sourceFailIf(t, !entered || err != nil, "funded origin: entered=%t error=%v", entered, err)
				}
				return nil
			}))
		})
	}
}

func TestSourcePreparedManifestOwnership(t *testing.T) {
	_, o, _, m, parts := sourceBundleScene(t, 1, false)
	admitted := slices.Clone(m.Parts)
	p := sourcePrepare(t, o, m, parts)
	m.Parts[0].Length++
	sourceFailIf(t, !slices.Equal(p.manifest.Parts, admitted), "prepared manifest aliases caller metadata")
	m.Parts[0] = admitted[0]
	sourceRead(t, o, m, parts, func() { m.Parts[1].Length++ })
}

func TestSourceExpiryWaitsForAdmittedRead(t *testing.T) {
	s, o, dir, m, parts := sourceBundleScene(t, 1, false)
	reservations, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
	sourceMust(t, err)
	entered, allow, visitorLeft, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(allow) })
	var outcome error
	wait := func(signal, stopped <-chan struct{}, message string) {
		t.Helper()
		select {
		case <-signal:
		case <-stopped:
			t.Fatalf("source operation ended before the visitor: %v", outcome)
		case <-time.After(5 * time.Second):
			t.Fatal(message)
		}
	}
	t.Cleanup(func() {
		release()
		wait(done, nil, "source operation did not finish")
	})
	readDone := make(chan error, 1)
	var escaped SourcePartV1
	buf := make([]byte, len(parts[0]))
	producer := sourceMappedProducer(m, parts, func(part SourcePartV1, visit func(SourcePartV1) error) error {
		if byte(part.Kind) == 1 {
			read := part.ReadAt
			part.ReadAt = func(dst []byte, off int64) (int, error) { close(entered); <-allow; return read(dst, off) }
		}
		return visit(part)
	})
	go func() {
		defer close(done)
		outcome = reservations.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
			return o.WithSourceExportV1(a, m, producer, func(part SourcePartV1) error {
				escaped = part
				go func() { _, err := part.ReadAt(buf, 0); readDone <- err }()
				select {
				case <-entered:
				case <-allow:
				case err := <-readDone:
					return fmt.Errorf("read ended before entering its backing: %w", err)
				}
				close(visitorLeft)
				return io.EOF
			})
		})
	}()
	wait(visitorLeft, done, "visitor did not enter")
	sourceChild(t, dir, "busy")
	select {
	case <-done:
		t.Fatal("export ended before an admitted read")
	default:
	}
	sourceWantError(t, s.Close(), policycontrol.ErrBusy, "read lifetime lost source authority")
	release()
	wait(done, nil, "read expiry did not finish")
	sourceFailIf(t, any(outcome) != any(io.EOF), "visitor result: %v", outcome)
	err = <-readDone
	sourceFailIf(t, err != nil || !bytes.Equal(buf, parts[0]), "admitted copy: %v/%x", err, buf)
	n, err := escaped.ReadAt(buf, 0)
	sourceFailIf(t, n != 0 || any(err) != any(ErrUnavailableV1), "expired read: %d/%v", n, err)
	sourceMust(t, s.Close())
}

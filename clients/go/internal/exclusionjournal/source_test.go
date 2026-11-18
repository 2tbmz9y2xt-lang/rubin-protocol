package exclusionjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	dir := filepath.Join(t.TempDir(), "policy")
	sourceMust(t, os.Mkdir(dir, 0o700))
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

func sourceProducer(m SourceManifestV1, parts [][]byte) SourceExporterV1 {
	return func(visit func(SourcePartV1) error) error { return ExportSourceBytesV1(m, parts, visit) }
}

func sourceRead(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, want [][]byte) {
	t.Helper()
	i := 0
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		return o.WithCapturedSourceV1(a, m, func(part SourcePartV1) error {
			if i >= len(want) {
				t.Fatal("extra source part")
			}
			kinds := []byte{1, 2, 3, 4, 5, 6}
			if byte(m.Class) == 3 {
				kinds = []byte{7, 8, 3, 4, 9}
			}
			buf := make([]byte, len(want[i]))
			n, err := part.ReadAt(buf, 0)
			if byte(part.Kind) != kinds[i] || part.Length != uint64(len(want[i])) || n != len(buf) || err != nil || !bytes.Equal(buf, want[i]) {
				t.Fatalf("part %d: kind=%d length=%d n=%d err=%v bytes=%x", i, part.Kind, part.Length, n, err, buf)
			}
			i++
			return nil
		})
	})
	if i != len(want) {
		t.Fatalf("part count=%d, want %d", i, len(want))
	}
}

func sourcePrepare(t *testing.T, o *SourceOwnerV1, m SourceManifestV1, parts [][]byte) *PreparedSourceV1 {
	t.Helper()
	var p *PreparedSourceV1
	sourceAccount(t, func(a *mdbx.OperationAccount) error {
		var err error
		p, err = o.PrepareSourceV1(a, m, sourceProducer(m, parts))
		return err
	})
	if p == nil {
		t.Fatal("missing prepared owner")
	}
	return p
}

func TestSourceDurableRoundTrip(t *testing.T) {
	for _, class := range []byte{1, 2, 3} {
		for _, conditional := range []bool{false, true} {
			t.Run(fmt.Sprintf("class%d/conditional%v", class, conditional), func(t *testing.T) {
				s, o, dir := sourceScene(t, sourceLimits())
				m, parts := sourceBundle(class, conditional)
				var err error
				var generations []string
				for _, generation := range []string{"old", "replacement"} {
					path := filepath.Join(t.TempDir(), generation)
					sourceMust(t, os.Mkdir(path, 0o700))
					sourceMust(t, os.WriteFile(filepath.Join(path, "body"), parts[0], 0o600))
					parts[0], err = os.ReadFile(filepath.Join(path, "body"))
					sourceMust(t, err)
					generations = append(generations, path)
				}
				p := sourcePrepare(t, o, m, parts)
				original, err := os.ReadFile(filepath.Join(dir, sourceDirectory, p.name))
				sourceMust(t, err)
				sourcePrepare(t, o, m, parts)
				after, err := os.ReadFile(filepath.Join(dir, sourceDirectory, p.name))
				sourceMust(t, err)
				if !bytes.Equal(after, original) {
					t.Fatal("identical preparation changed bytes")
				}
				for _, path := range generations {
					sourceMust(t, os.RemoveAll(path))
				}
				sourceRead(t, o, m, parts)
				sourceMust(t, s.Close())
				cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSourceChildV1$", "-test.count=1")
				cmd.Env = append(os.Environ(), "RUBIN_SOURCE_CHILD="+dir, fmt.Sprintf("RUBIN_SOURCE_SHAPE=%d/%v", class, conditional))
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("reopened child: %s: %v", output, err)
				}
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
	for _, mode := range []string{"success", "error", "wrapped", "typed-nil", "panic"} {
		t.Run(mode, func(t *testing.T) {
			s, o, dir := sourceScene(t, sourceLimits())
			m, parts := sourceBundle(1, false)
			want := slices.Clone(parts[0])
			cause := errors.New("visitor result")
			if mode == "wrapped" {
				cause = fmt.Errorf("application: %w", cause)
			}
			if mode == "typed-nil" {
				var typed *sourceTypedError
				cause = typed
			}
			var escaped SourcePartV1
			var copied []byte
			var got error
			var panicValue any
			calls := 0
			sourceAccount(t, func(a *mdbx.OperationAccount) error {
				func() {
					defer func() { panicValue = recover() }()
					got = o.WithSourceExportV1(a, m, sourceProducer(m, parts), func(part SourcePartV1) error {
						calls++
						if calls != 1 {
							return nil
						}
						escaped = part
						copied = make([]byte, part.Length)
						_, err := part.ReadAt(copied, 0)
						sourceMust(t, err)
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
						cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSourceChildV1$", "-test.count=1")
						cmd.Env = append(os.Environ(), "RUBIN_SOURCE_CHILD="+dir, "RUBIN_SOURCE_SHAPE=busy")
						if output, err := cmd.CombinedOutput(); err != nil {
							t.Fatalf("child exclusion: %s: %v", output, err)
						}
						switch mode {
						case "error", "typed-nil", "wrapped":
							return cause
						case "panic":
							panic(cause)
						}
						return nil
					})
				}()
				if mode == "panic" {
					if panicValue != any(cause) {
						t.Fatalf("panic=%v", panicValue)
					}
				} else if mode == "success" {
					if got != nil || calls != 6 {
						t.Fatalf("export result=%v count=%d", got, calls)
					}
				} else if any(got) != any(cause) {
					t.Fatalf("visitor result=%v", got)
				}
				if n, err := escaped.ReadAt(make([]byte, 1), 0); n != 0 || any(err) != any(ErrUnavailableV1) {
					t.Fatalf("escaped read: %d/%v", n, err)
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
	backing := make([]byte, 20)
	for _, row := range []struct {
		parts [][]byte
		bytes uint64
	}{{[][]byte{backing[:10], backing[5:15], backing[15:20]}, 20}, {[][]byte{backing[:10], slices.Clone(backing[:10])}, 20}, {[][]byte{nil, {}, backing[:0]}, 0}} {
		got, err := SourceBackingBytesV1(row.parts)
		if err != nil || got != row.bytes {
			t.Fatalf("backing bytes=%d/%v, want %d", got, err, row.bytes)
		}
	}
}

func TestSourcePreparedManifestOwnership(t *testing.T) {
	_, o, _ := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
	p := sourcePrepare(t, o, m, parts)
	want := slices.Clone(p.manifest.Parts)
	m.Parts[0].Length++
	if !reflect.DeepEqual(p.manifest.Parts, want) {
		t.Fatal("prepared manifest aliases caller metadata")
	}
}

func TestSourceExpiryWaitsForAdmittedRead(t *testing.T) {
	s, o, _ := sourceScene(t, sourceLimits())
	m, parts := sourceBundle(1, false)
	entered, allow, visitorLeft, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(allow) })
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("source operation did not finish")
		}
	})
	readDone := make(chan error, 1)
	var escaped SourcePartV1
	buf := make([]byte, len(parts[0]))
	producer := func(visit func(SourcePartV1) error) error {
		return ExportSourceBytesV1(m, parts, func(part SourcePartV1) error {
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
	select {
	case <-visitorLeft:
	case <-time.After(5 * time.Second):
		t.Fatal("visitor did not enter")
	}
	select {
	case <-done:
		t.Fatal("export ended before an admitted read")
	default:
	}
	if err := s.Close(); any(err) != any(policycontrol.ErrBusy) {
		t.Fatalf("read lifetime lost source authority: %v", err)
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("read expiry did not finish")
	}
	if err := <-readDone; err != nil || !bytes.Equal(buf, parts[0]) {
		t.Fatalf("admitted copy: %v/%x", err, buf)
	}
	if n, err := escaped.ReadAt(buf, 0); n != 0 || any(err) != any(ErrUnavailableV1) {
		t.Fatalf("expired read: %d/%v", n, err)
	}
	sourceMust(t, s.Close())
}

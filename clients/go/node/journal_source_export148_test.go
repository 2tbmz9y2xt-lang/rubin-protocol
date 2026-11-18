package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

func journalHeaderAccount(t *testing.T, use func(*mdbx.OperationAccount) error) {
	t.Helper()
	o, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.WithOperation(mdbx.TreeOperation, use); err != nil {
		t.Fatal(err)
	}
}

func journalExpectedPath(t *testing.T, in JournalHeaderPathInput148V1, raw [][148]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	fields := []any{in.Incarnation, in.Version, in.Height, in.Hash, in.AttachmentHeight, in.AttachmentHash, in.Provenance, in.Expected, uint64(len(raw)), uint64(len(in.DurablePrefix))}
	for _, field := range fields {
		if err := binary.Write(&out, binary.LittleEndian, field); err != nil {
			t.Fatal(err)
		}
	}
	for i, header := range raw {
		out.Write(in.Path[i][:])
		out.Write(header[:])
	}
	return out.Bytes()
}

func journalHeaderScene(t *testing.T, class byte, configure func(*exclusionjournal.SourceLimitsV1, exclusionjournal.SourceManifestV1)) (*policycontrol.Store, *exclusionjournal.SourceOwnerV1, exclusionjournal.SourceManifestV1, JournalHeaderPathInput148V1, []byte) {
	t.Helper()
	owner := hcNew(t, hcLim())
	durable := hcExt(hcMk(t, hcRoot, 1, 1, 1))
	body := hcExt(hcMk(t, durable.Hash, 2, 2, 2))
	hcEstablish(t, owner, body)
	in := JournalHeaderPathInput148V1{Owner: owner, Incarnation: 7, Version: owner.VersionV1(), Height: 2, AttachmentHeight: 0, Hash: body.Hash, AttachmentHash: hcRoot, Provenance: hcProvA, Expected: slices.Clone(body.Raw[:]), Path: [][32]byte{durable.Hash, body.Hash}, DurablePrefix: [][]byte{slices.Clone(durable.Raw[:])}}
	expected := journalExpectedPath(t, in, [][148]byte{durable.Raw, body.Raw})
	kinds := []byte{1, 2, 3, 4, 5, 6}
	in.Parts = [][]byte{[]byte("body"), []byte("original result"), []byte("historical context"), {1}, nil, {}}
	if class == 3 {
		kinds = []byte{7, 8, 3, 4, 9}
		in.Parts = [][]byte{[]byte("acquired canonical bytes"), nil, []byte("historical context"), {1}, []byte("acquisition position")}
	}
	m := exclusionjournal.SourceManifestV1{Identity: [32]byte{19}, Class: exclusionjournal.CaptureClassV1(class)}
	for i, k := range kinds {
		length := len(in.Parts[i])
		if k == 5 || k == 8 {
			length = len(expected)
		}
		m.Parts = append(m.Parts, exclusionjournal.SourcePartSpecV1{Kind: exclusionjournal.PartKindV1(k), Length: uint64(length)})
	}
	if class == 3 {
		m.AcquiredDigest = sha256.Sum256(in.Parts[0])
	}
	id := policycontrol.Identity{InstallationID: [32]byte{1}, ChainID: [32]byte{2}, GenesisHash: [32]byte{3}, Profile: 1}
	dir := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := policycontrol.Create(dir, id, policycontrol.NewInstallationProof{Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	limits := exclusionjournal.SourceLimitsV1{Bytes: 1 << 20, Files: 8, Scans: 64, RAM: 1 << 20, Headers: 16, Descriptors: 4, Overhead: 4096}
	if configure != nil {
		configure(&limits, m)
	}
	var source *exclusionjournal.SourceOwnerV1
	journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
		source, err = exclusionjournal.NewSourceOwnerV1(store, id, limits, a)
		return err
	})
	return store, source, m, in, expected
}

func TestJournalHeaderPathSource148(t *testing.T) {
	t.Run("snapshot", journalHeaderSnapshot)
	t.Run("refusals", journalHeaderRefusals)
	t.Run("prepared-retention", journalHeaderPreparedRetention)
}

func journalHeaderSnapshot(t *testing.T) {
	for _, class := range []byte{1, 3} {
		for _, mode := range []string{"publish", "close"} {
			t.Run(fmt.Sprintf("class%d/%s", class, mode), func(t *testing.T) {
				store, source, m, in, want := journalHeaderScene(t, class, nil)
				originalExpected := slices.Clone(in.Expected)
				originalPrefix := slices.Clone(in.DurablePrefix[0])
				originalPath := slices.Clone(in.Path)
				calls := 0
				var path []byte
				journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
					export, err := NewJournalHeaderPathSource148V1(source, a, m, in)
					if err != nil {
						return err
					}
					return source.WithSourceExportV1(a, m, export, func(part exclusionjournal.SourcePartV1) error {
						calls++
						if calls == 1 {
							if err := store.Close(); any(err) != any(policycontrol.ErrBusy) {
								t.Fatalf("source borrow: %v", err)
							}
							if mode == "publish" {
								tr := hcTr(in.Owner, nil)
								tr.NewSource = hcSrc2
								if _, out := hcPublish(t, in.Owner, tr); out != HeaderCandidateOK148V1 {
									t.Fatalf("publication during visitor: %d", out)
								}
							} else {
								in.Owner.CloseV1()
							}
							in.Expected[0] ^= 1
							in.DurablePrefix[0][0] ^= 1
							in.Path[0][0] ^= 1
						}
						if byte(part.Kind) == 5 || byte(part.Kind) == 8 {
							path = make([]byte, part.Length)
							n, err := part.ReadAt(path, 0)
							if err != nil || n != len(path) {
								t.Fatalf("path read: %d/%v", n, err)
							}
						}
						return nil
					})
				})
				if !bytes.Equal(path, want) || calls != len(m.Parts) {
					t.Fatalf("independent snapshot: %x count=%d", path, calls)
				}
				in.Owner.mu.Lock()
				guards, leases := in.Owner.guards, in.Owner.leases
				in.Owner.mu.Unlock()
				if guards != 0 || leases != 0 {
					t.Fatalf("provider owners retained: guards=%d leases=%d", guards, leases)
				}
				in.Expected = originalExpected
				in.DurablePrefix[0] = originalPrefix
				in.Path = originalPath
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func journalHeaderRefusals(t *testing.T) {
	for _, mode := range []string{"shape-before-closed", "length-before-capacity", "length-before-bytes", "length-before-scans", "path-length-before-bytes", "headers", "scans", "ram", "bytes", "nil-provider", "unestablished", "closed", "unknown", "version", "incarnation", "received-missing", "prefix-missing", "prefix-malformed", "attachment-missing", "expected-mismatch", "path-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			configure := func(l *exclusionjournal.SourceLimitsV1, m exclusionjournal.SourceManifestV1) {
				switch mode {
				case "headers", "length-before-capacity":
					l.Headers = 1
				case "scans":
					l.Scans = 39
				case "length-before-scans":
					l.Scans = 35
				case "ram":
					l.RAM = l.WorkingBytesV1() + uint64(292+360+1024) - 1
				case "bytes", "length-before-bytes", "path-length-before-bytes":
					n, _ := m.SizeV1()
					l.Bytes = n - 1
				}
			}
			_, source, m, in, expected := journalHeaderScene(t, 1, configure)
			want := exclusionjournal.ErrUnavailableV1
			switch mode {
			case "shape-before-closed":
				m.Parts = m.Parts[:5]
				in.Owner.CloseV1()
				want = exclusionjournal.ErrIntegrityV1
			case "length-before-capacity", "length-before-bytes", "length-before-scans":
				in.Expected = []byte{1}
				want = exclusionjournal.ErrIntegrityV1
			case "path-length-before-bytes":
				m.Parts[4].Length++
				want = exclusionjournal.ErrIntegrityV1
			case "headers", "scans", "ram", "bytes":
				want = exclusionjournal.ErrCapacityV1
			case "nil-provider":
				in.Owner = nil
			case "unestablished":
				in.Owner = hcNew(t, hcLim())
				in.Version = in.Owner.VersionV1()
			case "closed":
				in.Owner.CloseV1()
			case "unknown":
				tr := hcTr(in.Owner, nil)
				tr.NewSource = hcSrc2
				h, out := in.Owner.PrepareV1(tr)
				if out != HeaderCandidateOK148V1 {
					t.Fatalf("prepare: %d", out)
				}
				if out = h.UnknownV1(); out != HeaderCandidateOK148V1 {
					t.Fatalf("unknown: %d", out)
				}
				in.Version = in.Owner.VersionV1()
			case "version":
				in.Version--
			case "incarnation":
				in.Incarnation++
			case "received-missing":
				in.Path[1] = [32]byte{99}
				in.Hash = in.Path[1]
			case "prefix-missing":
				in.DurablePrefix[0] = nil
			case "prefix-malformed":
				in.DurablePrefix[0] = []byte{1}
				want = exclusionjournal.ErrIntegrityV1
			case "attachment-missing":
				in.AttachmentHash = [32]byte{}
			case "expected-mismatch":
				in.Expected[0] ^= 1
				want = exclusionjournal.ErrIntegrityV1
			case "path-mismatch":
				in.Parts[4] = slices.Clone(expected)
				in.Parts[4][0] ^= 1
				want = exclusionjournal.ErrIntegrityV1
			}
			calls := 0
			journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
				export, err := NewJournalHeaderPathSource148V1(source, a, m, in)
				if err == nil {
					err = source.WithSourceExportV1(a, m, export, func(exclusionjournal.SourcePartV1) error { calls++; return nil })
				}
				if any(err) != any(want) || calls != 0 {
					t.Fatalf("refusal=%v want=%v calls=%d", err, want, calls)
				}
				sibling := exclusionjournal.SourceManifestV1{Identity: [32]byte{21}, Class: 3, AcquiredDigest: sha256.Sum256([]byte{1})}
				parts := [][]byte{{1}, {2}, {3}, {1}, {5}}
				kinds := []byte{7, 8, 3, 4, 9}
				for i, part := range parts {
					sibling.Parts = append(sibling.Parts, exclusionjournal.SourcePartSpecV1{Kind: exclusionjournal.PartKindV1(kinds[i]), Length: uint64(len(part))})
				}
				if err := source.WithSourceExportV1(a, sibling, func(v func(exclusionjournal.SourcePartV1) error) error {
					return exclusionjournal.ExportSourceBytesV1(sibling, parts, v)
				}, func(exclusionjournal.SourcePartV1) error { return nil }); err != nil {
					return err
				}
				return a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil })
			})
			if in.Owner != nil {
				in.Owner.mu.Lock()
				guards := in.Owner.guards
				in.Owner.mu.Unlock()
				if guards != 0 {
					t.Fatalf("refusal retained %d guards", guards)
				}
			}
		})
	}
}

func journalHeaderPreparedRetention(t *testing.T) {
	_, source, m, in, want := journalHeaderScene(t, 3, nil)
	journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
		export, err := NewJournalHeaderPathSource148V1(source, a, m, in)
		if err != nil {
			return err
		}
		p, err := source.PrepareSourceV1(a, m, export)
		if err != nil || p == nil {
			t.Fatalf("prepare snapshot: %v/%v", p, err)
		}
		in.Owner.CloseV1()
		in.Expected[0] ^= 1
		in.DurablePrefix[0][0] ^= 1
		calls := 0
		return source.WithCapturedSourceV1(a, m, func(part exclusionjournal.SourcePartV1) error {
			calls++
			if byte(part.Kind) == 8 {
				got := make([]byte, part.Length)
				if _, err := part.ReadAt(got, 0); err != nil {
					return err
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("retained snapshot=%x", got)
				}
			}
			return nil
		})
	})
}

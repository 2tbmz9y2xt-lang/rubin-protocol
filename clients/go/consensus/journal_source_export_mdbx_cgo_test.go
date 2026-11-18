//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

func journalReplayFixture(class byte) (exclusionjournal.SourceManifestV1, journalReplaySourcePartsV1, [][]byte) {
	body := bytes.Repeat([]byte{43}, 100)
	parts := [][]byte{body, []byte("TX_ERR_LITERAL"), body[10:50], {1}, body[50:100], {}}
	m := exclusionjournal.SourceManifestV1{Identity: [32]byte{9}, Class: exclusionjournal.CaptureClassV1(class)}
	for i, p := range parts {
		m.Parts = append(m.Parts, exclusionjournal.SourcePartSpecV1{Kind: exclusionjournal.PartKindV1(i + 1), Length: uint64(len(p))})
	}
	return m, journalReplaySourcePartsV1{parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]}, parts
}

func journalReplayAccount(t *testing.T, use func(*mdbx.OperationAccount) error) {
	t.Helper()
	o, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.WithOperation(mdbx.TreeOperation, use); err != nil {
		t.Fatal(err)
	}
}

func journalReplayAssertPart(t *testing.T, part exclusionjournal.SourcePartV1, index int, want []byte) {
	t.Helper()
	buf := make([]byte, len(want))
	n, err := part.ReadAt(buf, 0)
	if byte(part.Kind) != byte(index+1) || part.Length != uint64(len(want)) || n != len(buf) || err != nil || !bytes.Equal(buf, want) {
		t.Fatalf("part %d: %d/%d/%d/%v/%x", index, part.Kind, part.Length, n, err, buf)
	}
}

func TestJournalSourceExportExactAndScoped(t *testing.T) {
	for _, class := range []byte{1, 2} {
		m, parts, want := journalReplayFixture(class)
		snapshot := slices.Clone(parts.BoundBody)
		journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
			var escaped exclusionjournal.SourcePartV1
			index := 0
			err := withJournalReplaySourceExportV1(a, m, parts, func(p exclusionjournal.SourcePartV1) error {
				journalReplayAssertPart(t, p, index, want[index])
				if index == 0 {
					escaped = p
				}
				if index == 1 {
					if n, err := escaped.ReadAt(make([]byte, 1), 0); n != 0 || any(err) != any(exclusionjournal.ErrUnavailableV1) {
						t.Fatal("part pin survived into sibling visitor")
					}
				}
				index++
				return nil
			})
			if err != nil || index != 6 {
				t.Fatalf("export=%v count=%d", err, index)
			}
			if n, err := escaped.ReadAt(make([]byte, 1), 0); n != 0 || any(err) != any(exclusionjournal.ErrUnavailableV1) {
				t.Fatalf("escaped reader=%d/%v", n, err)
			}
			if !bytes.Equal(parts.BoundBody, snapshot) {
				t.Fatal("export changed caller body")
			}
			return nil
		})
	}
}

func TestJournalSourceExportAccountCensus(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		m, parts, _ := journalReplayFixture(1)
		backing := uint64(100 + 14 + 1)
		if distinct {
			parts.HistoricalContext = slices.Clone(parts.HistoricalContext)
			backing += 40
		}
		journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
			remaining := backing + 65536 + 1024
			return a.WithReservation(mdbx.TreeLaneMaxBytes-remaining, func() error {
				calls := 0
				err := withJournalReplaySourceExportV1(a, m, parts, func(exclusionjournal.SourcePartV1) error { calls++; return nil })
				if err != nil || calls != 6 {
					t.Fatalf("exact shared census: %v calls=%d distinct=%v", err, calls, distinct)
				}
				return a.WithReservation(1, func() error {
					calls = 0
					err := withJournalReplaySourceExportV1(a, m, parts, func(exclusionjournal.SourcePartV1) error { calls++; return nil })
					if !mdbx.IsOperationReservationCapacity(err) || calls != 0 {
						t.Fatalf("one-over census: %v calls=%d", err, calls)
					}
					return nil
				})
			})
		})
	}
}

func TestJournalSourceExportRefusalAndFunding(t *testing.T) {
	m, original, _ := journalReplayFixture(1)
	originalBody := slices.Clone(original.BoundBody)
	for _, mode := range []string{"missing-result", "result-length", "reordered-result", "error", "panic"} {
		parts := original
		manifest := m
		manifest.Parts = slices.Clone(m.Parts)
		cause := errors.New("visitor refusal")
		calls := 0
		switch mode {
		case "missing-result":
			parts.ObservedResult = nil
		case "result-length":
			manifest.Parts[1].Length++
		case "reordered-result":
			manifest.Parts[1].Kind = 3
		}
		journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
			return a.WithReservation(17, func() error {
				var err error
				var caught any
				func() {
					defer func() { caught = recover() }()
					err = withJournalReplaySourceExportV1(a, manifest, parts, func(exclusionjournal.SourcePartV1) error {
						calls++
						if mode == "panic" {
							panic(cause)
						}
						return cause
					})
				}()
				if mode == "panic" {
					if caught != any(cause) || calls != 1 {
						t.Fatalf("panic=%v calls=%d", caught, calls)
					}
				} else if mode == "error" {
					if any(err) != any(cause) || calls != 1 {
						t.Fatalf("callback=%v calls=%d", err, calls)
					}
				} else if any(err) != any(exclusionjournal.ErrIntegrityV1) || calls != 0 {
					t.Fatalf("shape=%v calls=%d", err, calls)
				}
				if !bytes.Equal(parts.BoundBody, originalBody) {
					t.Fatal("refusal changed body")
				}
				if err := a.WithReservation(mdbx.TreeLaneMaxBytes-17+1, func() error { t.Fatal("caller funding was consumed"); return nil }); !mdbx.IsOperationReservationCapacity(err) {
					t.Fatalf("caller funding: %v", err)
				}
				return a.WithReservation(mdbx.TreeLaneMaxBytes-17, func() error { return nil })
			})
		})
	}
	for _, a := range []*mdbx.OperationAccount{nil, {}} {
		calls := 0
		if err := withJournalReplaySourceExportV1(a, m, original, func(exclusionjournal.SourcePartV1) error { calls++; return nil }); err == nil || calls != 0 {
			t.Fatalf("unopened account: %v/%d", err, calls)
		}
	}
}

func TestJournalSourceExportPrepare(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id := policycontrol.Identity{InstallationID: [32]byte{1}, ChainID: [32]byte{2}, GenesisHash: [32]byte{3}, Profile: 1}
	store, err := policycontrol.Create(dir, id, policycontrol.NewInstallationProof{Identity: id})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m, parts, want := journalReplayFixture(1)
	w := btNew(t)
	want[0] = initial148BlockGenesis(t)
	block := btRequest(want[0], 5).Block
	w.pair(t, btMutation(3, block[:], want[0][:148]), btMutation(4, block[:], want[0]))
	var expired *mdbx.Reader
	err = w.s.View(func(r *mdbx.Reader) error {
		var present bool
		parts.BoundBody, present, err = r.Get(mdbx.TreeSchemaV1DBIs()[4], block[:])
		logicalMDBXAssert(t, err == nil && present && bytes.Equal(parts.BoundBody, want[0]), "native source: %v/%v", present, err)
		expired = r
		return err
	})
	logicalMDBXAssert(t, err == nil, "native source View: %v", err)
	m.Parts[0].Length = uint64(len(want[0]))
	if _, _, err := expired.Get(mdbx.TreeSchemaV1DBIs()[4], block[:]); err == nil {
		t.Fatal("original Reader remained active")
	}
	journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
		o, err := exclusionjournal.NewSourceOwnerV1(store, id, exclusionjournal.SourceLimitsV1{Bytes: 1 << 20, Files: 8, Scans: 64, RAM: 1 << 20, Headers: 8, Descriptors: 4, Overhead: 4096}, a)
		if err != nil {
			return err
		}
		producer := func(v func(exclusionjournal.SourcePartV1) error) error {
			return withJournalReplaySourceExportV1(a, m, parts, v)
		}
		p, err := o.PrepareSourceV1(a, m, producer)
		if err != nil || p == nil {
			t.Fatalf("prepared source: %v/%v", p, err)
		}
		logicalMDBXAssert(t, w.s.Close() == nil, "native source close")
		logicalMDBXAssert(t, os.RemoveAll(w.path) == nil, "native source retirement")
		parts.BoundBody[0] ^= 1
		index := 0
		if err := o.WithCapturedSourceV1(a, m, func(part exclusionjournal.SourcePartV1) error {
			journalReplayAssertPart(t, part, index, want[index])
			index++
			return nil
		}); err != nil || index != 6 {
			t.Fatalf("captured source: %v/%d", err, index)
		}
		refused := m
		refused.Identity[1]++
		saved := slices.Clone(parts.ObservedResult)
		parts.ObservedResult = nil
		p, err = o.PrepareSourceV1(a, refused, func(v func(exclusionjournal.SourcePartV1) error) error {
			return withJournalReplaySourceExportV1(a, refused, parts, v)
		})
		if p != nil || any(err) != any(exclusionjournal.ErrIntegrityV1) {
			t.Fatalf("preparation refusal: %v/%v", p, err)
		}
		parts.ObservedResult = saved
		p, err = o.PrepareSourceV1(a, refused, func(v func(exclusionjournal.SourcePartV1) error) error {
			return withJournalReplaySourceExportV1(a, refused, parts, v)
		})
		if p == nil || err != nil {
			t.Fatalf("source-only retry: %v/%v", p, err)
		}
		return nil
	})
}

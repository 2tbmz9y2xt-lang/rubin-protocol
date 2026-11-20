//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

var journalReplayLimits = exclusionjournal.SourceLimitsV1{Bytes: 1 << 20, Files: 8, Scans: 64, RAM: 1 << 20, Headers: 16, Descriptors: 4, Overhead: 4096}

func journalReplayMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func journalReplayAccount(t *testing.T, run func(*mdbx.OperationAccount) error) {
	t.Helper()
	owner, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
	journalReplayMust(t, err)
	journalReplayMust(t, owner.WithOperation(mdbx.TreeOperation, run))
}

func journalReplaySource(t *testing.T, dir string, reopen bool) (*policycontrol.Store, *exclusionjournal.SourceOwnerV1) {
	t.Helper()
	id := policycontrol.Identity{InstallationID: [32]byte{1}, ChainID: [32]byte{2}, GenesisHash: [32]byte{3}, Profile: 1}
	var store *policycontrol.Store
	var err error
	if reopen {
		store, err = policycontrol.Open(dir, id)
	} else {
		journalReplayMust(t, os.Chmod(dir, 0o700))
		store, err = policycontrol.Create(dir, id, policycontrol.NewInstallationProof{Identity: id})
	}
	journalReplayMust(t, err)
	t.Cleanup(func() { _ = store.Close() })
	var source *exclusionjournal.SourceOwnerV1
	journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
		source, err = exclusionjournal.NewSourceOwnerV1(store, id, journalReplayLimits, a)
		return err
	})
	return store, source
}

type journalReplayEvidence struct {
	manifest exclusionjournal.SourceManifestV1
	origins  []exclusionjournal.SourceOriginV1
	views    []exclusionjournal.SourceViewV1
	want     [6]string
}

func newJournalReplayEvidence(class byte, prefix string) journalReplayEvidence {
	e := journalReplayEvidence{manifest: exclusionjournal.SourceManifestV1{Class: exclusionjournal.CaptureClassV1(class), Identity: [32]byte{7}}}
	e.want = [6]string{"bound-body", "TX_ERR_PARSE", "history-v2", "\x01", "path-bytes", prefix}
	if class == 2 {
		e.want[1] = "accepted-v3!"
	}
	shared := make([]byte, 96)
	for i, payload := range e.want {
		offset := i*16 + 2
		copy(shared[offset:], payload)
		e.manifest.Parts = append(e.manifest.Parts, exclusionjournal.SourcePartSpecV1{Kind: exclusionjournal.PartKindV1(i + 1), Length: uint64(len(payload))})
		e.views = append(e.views, exclusionjournal.SourceViewV1{Offset: uint64(offset), Length: uint64(len(payload))})
	}
	distinct := append(make([]byte, 0, len(shared)), shared...)
	e.origins = []exclusionjournal.SourceOriginV1{{Bytes: shared}, {Bytes: distinct}}
	e.views[2].Origin = 1
	if prefix == "" {
		e.origins = append(e.origins, exclusionjournal.SourceOriginV1{Bytes: make([]byte, 17)})
		e.views[5] = exclusionjournal.SourceViewV1{Origin: 2, Offset: 17}
	}
	return e
}

func (e journalReplayEvidence) producer(t *testing.T) exclusionjournal.SourceExporterV1 {
	t.Helper()
	export, err := withJournalReplaySourceExportV1(e.manifest, e.origins, e.views)
	journalReplayMust(t, err)
	return export
}

func (e journalReplayEvidence) assertPart(t *testing.T, p exclusionjournal.SourcePartV1, index int, scoped bool) {
	t.Helper()
	if index >= len(e.want) || byte(p.Kind) != byte(index+1) || p.Length != uint64(len(e.want[index])) {
		t.Fatalf("part %d: kind=%d length=%d", index, p.Kind, p.Length)
	}
	want := e.want[index]
	got := make([]byte, len(want))
	if len(got) != 0 || scoped {
		if n, err := p.ReadAt(got, 0); n != len(got) || err != nil || string(got) != want {
			t.Fatalf("part %d read %d/%v: got %q, want %q", index, n, err, got, want)
		}
	}
	if scoped {
		if n, err := p.ReadAt(nil, int64(len(want))); n != 0 || err != nil {
			t.Fatalf("part %d empty end read: %d/%v", index, n, err)
		}
		if len(want) > 1 {
			if n, err := p.ReadAt(got[:len(got)-1], 1); n != len(got)-1 || err != nil || string(got[:n]) != want[1:] {
				t.Fatalf("part %d suffix: %d/%v, %q", index, n, err, got)
			}
		}
	}
}

func journalReplayExpired(t *testing.T, p exclusionjournal.SourcePartV1) {
	t.Helper()
	if n, err := p.ReadAt(nil, 0); n != 0 || any(err) != any(exclusionjournal.ErrUnavailableV1) {
		t.Fatalf("escaped read: %d/%v", n, err)
	}
}

func TestJournalSourceExportExactAndScoped(t *testing.T) {
	for _, class := range []byte{1, 2} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			_, source := journalReplaySource(t, t.TempDir(), false)
			e := newJournalReplayEvidence(class, "prefix-v4!")
			export := e.producer(t)
			e.origins[0].Bytes = nil
			e.views[0].Offset++
			var operation *exclusionjournal.SourceOperationV1
			var prior exclusionjournal.SourcePartV1
			visits := 0
			journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
				return source.WithSourceExportV1(a, e.manifest, func(op *exclusionjournal.SourceOperationV1, visit func(exclusionjournal.SourcePartV1) error) error {
					operation = op
					return export(op, visit)
				}, func(part exclusionjournal.SourcePartV1) error {
					if visits != 0 {
						journalReplayExpired(t, prior)
					}
					e.assertPart(t, part, visits, true)
					prior = part
					visits++
					return nil
				})
			})
			if visits != 6 {
				t.Fatalf("visits=%d, want 6", visits)
			}
			journalReplayExpired(t, prior)
			for _, op := range []*exclusionjournal.SourceOperationV1{nil, {}, operation} {
				if err := export(op, func(exclusionjournal.SourcePartV1) error { t.Fatal("inactive operation visited"); return nil }); any(err) != any(exclusionjournal.ErrUnavailableV1) {
					t.Fatalf("inactive operation: %v", err)
				}
			}
		})
	}
}

func journalReplayBackingUnchanged(t *testing.T, e journalReplayEvidence) func() {
	t.Helper()
	var originals [][]byte
	for _, o := range e.origins {
		originals = append(originals, slices.Clone(o.Bytes))
	}
	return func() {
		for i, o := range e.origins {
			if !bytes.Equal(originals[i], o.Bytes) {
				t.Fatalf("origin %d changed", i)
			}
		}
	}
}

func TestJournalSourceExportRefusalAndFunding(t *testing.T) {
	_, source := journalReplaySource(t, t.TempDir(), false)
	journalReplayBadShapes(t, source)
	direct := errors.New("stop export")
	var typedNil *os.PathError
	for _, c := range []struct {
		name  string
		cause error
	}{{"direct", direct}, {"wrapped", fmt.Errorf("read: %w", direct)}, {"typed-nil", typedNil}, {"panic", nil}} {
		t.Run(c.name, func(t *testing.T) { journalReplayFirstResult(t, source, c.cause) })
	}
}

func journalReplayBadShapes(t *testing.T, source *exclusionjournal.SourceOwnerV1) {
	for _, c := range []struct {
		name      string
		preflight bool
		edit      func(*journalReplayEvidence)
	}{
		{"zero-class", true, func(e *journalReplayEvidence) { e.manifest.Class = 0 }},
		{"unknown-class", true, func(e *journalReplayEvidence) { e.manifest.Class = 9 }},
		{"zero-identity", true, func(e *journalReplayEvidence) { e.manifest.Identity = [32]byte{} }},
		{"ordinary-digest", true, func(e *journalReplayEvidence) { e.manifest.AcquiredDigest[0] = 1 }},
		{"missing-spec", true, func(e *journalReplayEvidence) { e.manifest.Parts = slices.Delete(e.manifest.Parts, 1, 2) }},
		{"extra-spec", true, func(e *journalReplayEvidence) { e.manifest.Parts = append(e.manifest.Parts, e.manifest.Parts[1]) }},
		{"wrong-kind", true, func(e *journalReplayEvidence) { e.manifest.Parts[1].Kind = 9 }},
		{"reordered-specs", true, func(e *journalReplayEvidence) { p := e.manifest.Parts; p[1], p[2] = p[2], p[1] }},
		{"empty-result", true, func(e *journalReplayEvidence) { e.manifest.Parts[1].Length = 0 }},
		{"wrong-result-length", true, func(e *journalReplayEvidence) { e.manifest.Parts[1].Length++ }},
		{"missing-view", true, func(e *journalReplayEvidence) { e.views = slices.Delete(e.views, 1, 2) }},
		{"extra-view", true, func(e *journalReplayEvidence) { e.views = append(e.views, e.views[1]) }},
		{"absent-result", true, func(e *journalReplayEvidence) { e.views[1] = exclusionjournal.SourceViewV1{Origin: -1} }},
		{"reordered-views", true, func(e *journalReplayEvidence) { e.views[1], e.views[2] = e.views[2], e.views[1] }},
		{"missing-origin", false, func(e *journalReplayEvidence) { e.origins = e.origins[:1] }},
		{"too-many-origins", true, func(e *journalReplayEvidence) {
			for i := len(e.origins); i < 10; i++ {
				e.origins = append(e.origins, exclusionjournal.SourceOriginV1{Bytes: []byte{byte(i)}})
			}
		}},
		{"wrong-origin-index", false, func(e *journalReplayEvidence) { e.views[1].Origin = 4 }},
		{"clipped-origin", false, func(e *journalReplayEvidence) {
			e.origins[0].Bytes = append(make([]byte, 0, 97), e.origins[0].Bytes...)
		}},
		{"empty-origin", false, func(e *journalReplayEvidence) { e.origins[2].Bytes = nil }},
		{"duplicate-origin", false, func(e *journalReplayEvidence) { e.origins[1] = e.origins[0] }},
		{"overlap-origin", false, func(e *journalReplayEvidence) { e.origins[1].Bytes = e.origins[0].Bytes[2:95:95] }},
		{"planned-origin", true, func(e *journalReplayEvidence) { e.origins[2] = exclusionjournal.SourceOriginV1{PlannedBytes: 17} }},
		{"view-overflow", false, func(e *journalReplayEvidence) { e.views[1].Offset = math.MaxUint64 }},
		{"view-end", false, func(e *journalReplayEvidence) { e.views[1].Offset = 95 }},
		{"offset-unbacked", false, func(e *journalReplayEvidence) { e.views[5] = exclusionjournal.SourceViewV1{Origin: -1, Offset: 1} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := newJournalReplayEvidence(1, "")
			c.edit(&bad)
			defer journalReplayBackingUnchanged(t, bad)()
			journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
				export, err := withJournalReplaySourceExportV1(bad.manifest, bad.origins, bad.views)
				if c.preflight != (err != nil) || (err != nil && export != nil) {
					t.Fatalf("constructor: producer=%v err=%v, want preflight refusal=%v", export != nil, err, c.preflight)
				}
				if err == nil {
					err = source.WithSourceExportV1(a, bad.manifest, export, func(exclusionjournal.SourcePartV1) error { t.Fatal("malformed input delivered"); return nil })
				}
				if any(err) != any(exclusionjournal.ErrIntegrityV1) {
					t.Fatalf("malformed input: %v", err)
				}
				return journalReplaySibling(t, source, a, newJournalReplayEvidence(1, ""))
			})
		})
	}
	recovery := exclusionjournal.SourceManifestV1{Identity: [32]byte{7}, Class: 3, AcquiredDigest: [32]byte{1}}
	for _, kind := range []exclusionjournal.PartKindV1{7, 8, 3, 4, 9} {
		recovery.Parts = append(recovery.Parts, exclusionjournal.SourcePartSpecV1{Kind: kind, Length: 1})
	}
	views := slices.Repeat([]exclusionjournal.SourceViewV1{{Length: 1}}, 5)
	if export, err := withJournalReplaySourceExportV1(recovery, []exclusionjournal.SourceOriginV1{{Bytes: []byte{1}}}, views); export != nil || any(err) != any(exclusionjournal.ErrIntegrityV1) {
		t.Fatalf("recovery replay constructor: export=%v err=%v", export != nil, err)
	}
}

func journalReplayFirstResult(t *testing.T, source *exclusionjournal.SourceOwnerV1, cause error) {
	t.Helper()
	e := newJournalReplayEvidence(1, "")
	defer journalReplayBackingUnchanged(t, e)()
	export := e.producer(t)
	panicValue := new(int)
	journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
		var operation *exclusionjournal.SourceOperationV1
		var saved exclusionjournal.SourcePartV1
		attempts, visits := 0, 0
		var result error
		var panicked any
		func() {
			defer func() { panicked = recover() }()
			result = source.WithSourceExportV1(a, e.manifest, func(op *exclusionjournal.SourceOperationV1, visit func(exclusionjournal.SourcePartV1) error) error {
				operation = op
				return export(op, func(p exclusionjournal.SourcePartV1) error { attempts++; return visit(p) })
			}, func(p exclusionjournal.SourcePartV1) error {
				e.assertPart(t, p, visits, true)
				visits++
				saved = p
				if cause == nil {
					panic(panicValue)
				}
				return cause
			})
		}()
		if attempts != 1 || visits != 1 || any(result) != any(cause) || (cause == nil && panicked != panicValue) || (cause != nil && panicked != nil) {
			t.Fatalf("first result=%v panic=%v forwarding=%d visits=%d", result, panicked, attempts, visits)
		}
		journalReplayExpired(t, saved)
		if _, err := operation.LimitsV1(); any(err) != any(exclusionjournal.ErrUnavailableV1) {
			t.Fatalf("escaped operation: %v", err)
		}
		return journalReplaySibling(t, source, a, e)
	})
}

func journalReplaySibling(t *testing.T, source *exclusionjournal.SourceOwnerV1, a *mdbx.OperationAccount, e journalReplayEvidence) error {
	t.Helper()
	calls := 0
	err := source.WithSourceExportV1(a, e.manifest, e.producer(t), func(p exclusionjournal.SourcePartV1) error {
		e.assertPart(t, p, calls, true)
		calls++
		return nil
	})
	if err != nil || calls != 6 {
		t.Fatalf("sibling: %v visits=%d", err, calls)
	}
	return a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil })
}

func TestJournalSourceExportAccountCensus(t *testing.T) {
	_, source := journalReplaySource(t, t.TempDir(), false)
	for _, backed := range []bool{true, false} {
		e := newJournalReplayEvidence(1, "")
		funding := journalReplayLimits.WorkingBytesV1() + 96 + 96 + 17
		if !backed {
			e.views[5] = exclusionjournal.SourceViewV1{Origin: -1}
			e.origins = e.origins[:2]
			funding -= 17
		}
		journalReplayFunding(t, source, e, funding, false)
	}
}

func journalReplayFunding(t *testing.T, source *exclusionjournal.SourceOwnerV1, e journalReplayEvidence, funding uint64, prepare bool) {
	t.Helper()
	defer journalReplayBackingUnchanged(t, e)()
	export := e.producer(t)
	journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
		capacity := a.WithReservation(mdbx.TreeLaneMaxBytes+1, func() error { return nil })
		for _, short := range []uint64{1, 0} {
			calls := 0
			err := a.WithReservation(mdbx.TreeLaneMaxBytes-funding+short, func() error {
				visit := func(p exclusionjournal.SourcePartV1) error {
					e.assertPart(t, p, calls, true)
					calls++
					return nil
				}
				if !prepare {
					return source.WithSourceExportV1(a, e.manifest, export, visit)
				}
				prepared, err := source.PrepareSourceV1(a, e.manifest, func(op *exclusionjournal.SourceOperationV1, merged func(exclusionjournal.SourcePartV1) error) error {
					return export(op, func(p exclusionjournal.SourcePartV1) error { calls++; return merged(p) })
				})
				if (prepared == nil) != (short != 0) {
					t.Fatalf("prepare short=%d: prepared=%v err=%v", short, prepared != nil, err)
				}
				return err
			})
			if short != 0 && (any(err) != any(capacity) || calls != 0) || short == 0 && (err != nil || calls != 6) {
				t.Fatalf("funding short=%d: %v visits=%d", short, err, calls)
			}
		}
		return journalReplaySibling(t, source, a, e)
	})
}

func TestJournalSourceExportPrepare(t *testing.T) {
	for _, class := range []byte{1, 2} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			dir := t.TempDir()
			store, source := journalReplaySource(t, dir, false)
			e := newJournalReplayEvidence(class, "")
			journalReplayFunding(t, source, e, journalReplayLimits.WorkingBytesV1()+96+96+17, true)
			journalReplayMust(t, store.Close())
			_, reopened := journalReplaySource(t, dir, true)
			clear(e.origins[0].Bytes)
			clear(e.origins[1].Bytes)
			calls := 0
			journalReplayAccount(t, func(a *mdbx.OperationAccount) error {
				return reopened.WithCapturedSourceV1(a, e.manifest, func(p exclusionjournal.SourcePartV1) error {
					e.assertPart(t, p, calls, false)
					calls++
					return nil
				})
			})
			if calls != 6 {
				t.Fatalf("reopened visits=%d, want 6", calls)
			}
		})
	}
}

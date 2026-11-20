package node

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

var journalHeaderLimits = exclusionjournal.SourceLimitsV1{Bytes: 1 << 20, Files: 8, Scans: 64, RAM: 1 << 20, Headers: 16, Descriptors: 4, Overhead: 4096}

func journalHeaderMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func journalHeaderAccount(t *testing.T, use func(*mdbx.OperationAccount) error) {
	t.Helper()
	o, err := mdbx.NewOperationReservationOwner(mdbx.MinReservationLimit)
	journalHeaderMust(t, err)
	journalHeaderMust(t, o.WithOperation(mdbx.TreeOperation, use))
}

func journalHeaderSource(t *testing.T, dir string, limits exclusionjournal.SourceLimitsV1, reopen bool) (*policycontrol.Store, *exclusionjournal.SourceOwnerV1) {
	t.Helper()
	id := policycontrol.Identity{InstallationID: [32]byte{1}, ChainID: [32]byte{2}, GenesisHash: [32]byte{3}, Profile: 1}
	var store *policycontrol.Store
	var err error
	if reopen {
		store, err = policycontrol.Open(dir, id)
	} else {
		journalHeaderMust(t, os.Chmod(dir, 0o700))
		store, err = policycontrol.Create(dir, id, policycontrol.NewInstallationProof{Identity: id})
	}
	journalHeaderMust(t, err)
	t.Cleanup(func() { _ = store.Close() })
	var source *exclusionjournal.SourceOwnerV1
	journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
		source, err = exclusionjournal.NewSourceOwnerV1(store, id, limits, a)
		return err
	})
	return store, source
}

type journalHeaderEvidence struct {
	manifest  exclusionjournal.SourceManifestV1
	input     JournalHeaderPathInput148V1
	kinds     []byte
	want      [][]byte
	pathIndex int
}

func newJournalHeaderEvidence(t *testing.T, class byte, count, extent int, supplied bool) journalHeaderEvidence {
	t.Helper()
	return newJournalHeaderEvidenceWithReceived(t, class, count, extent, supplied, 0)
}

func newJournalHeaderEvidenceWithReceived(t *testing.T, class byte, count, extent int, supplied bool, receivedStart int) journalHeaderEvidence {
	t.Helper()
	owner := hcNew(t, hcLim())
	oldest := hcMk(t, hcRoot, 10, 100, 1)
	tip := hcMk(t, oldest.Hash, 11, 110, 2)
	records := []HeaderCandidateRecord148V1{oldest, tip}
	received := records[receivedStart:]
	if len(received) != 0 {
		received[0] = hcExt(received[0])
	}
	hcEstablish(t, owner, received...)
	recs := records[2-count:]
	e := journalHeaderEvidence{manifest: exclusionjournal.SourceManifestV1{Class: exclusionjournal.CaptureClassV1(class), Identity: [32]byte{19}}}
	e.input = JournalHeaderPathInput148V1{
		Owner: owner, Incarnation: 7, Version: owner.VersionV1(), Height: 11, AttachmentHeight: 9,
		Hash: tip.Hash, AttachmentHash: hcRoot, Provenance: hcProvA, HasExpected: true, Expected: tip.Raw,
		DurableExtent: uint64(extent), OriginalProjection: exclusionjournal.SourceViewV1{Origin: -1},
	}
	var path, durable []byte
	for i, r := range recs {
		path = append(path, r.Hash[:]...)
		if i < extent {
			durable = append(durable, 1)
			durable = append(durable, r.Raw[:]...)
		}
	}
	e.input.Path, e.input.Durable = e.origin(path), e.origin(durable)
	projection := journalHeaderProjection(t, e.input, recs, uint64(extent))
	if supplied {
		e.input.OriginalProjection = e.origin(projection)
	}
	e.addParts(class, projection)
	return e
}

func journalHeaderProjection(t *testing.T, input JournalHeaderPathInput148V1, recs []HeaderCandidateRecord148V1, originalExtent uint64) []byte {
	t.Helper()
	var expected bytes.Buffer
	fields := []any{input.Incarnation, input.Version, input.Height, input.Hash, input.AttachmentHeight, input.AttachmentHash, input.Provenance, input.Expected, uint64(len(recs)), originalExtent}
	for _, field := range fields {
		journalHeaderMust(t, binary.Write(&expected, binary.LittleEndian, field))
	}
	for _, r := range recs {
		expected.Write(r.Hash[:])
		expected.Write(r.Raw[:])
	}
	return expected.Bytes()
}

func (e *journalHeaderEvidence) origin(payload []byte) exclusionjournal.SourceViewV1 {
	if len(payload) == 0 {
		return exclusionjournal.SourceViewV1{Origin: -1}
	}
	backing := make([]byte, len(payload)+13)
	copy(backing[5:], payload)
	view := exclusionjournal.SourceViewV1{Origin: len(e.input.Origins), Offset: 5, Length: uint64(len(payload))}
	e.input.Origins = append(e.input.Origins, exclusionjournal.SourceOriginV1{Bytes: backing})
	return view
}

func (e *journalHeaderEvidence) addParts(class byte, projection []byte) {
	e.kinds = []byte{1, 2, 3, 4, 5, 6}
	e.want = [][]byte{[]byte("body"), []byte("original result"), []byte("old law and build"), {1}, projection, []byte("accepted prefix")}
	e.pathIndex = 4
	if class == 3 {
		e.kinds = []byte{7, 8, 3, 4, 9}
		e.want = [][]byte{[]byte("acquired canonical bytes"), projection, []byte("old law and build"), {1}, []byte("acquisition position")}
		e.manifest.AcquiredDigest = sha256.Sum256(e.want[0])
		e.pathIndex = 1
	}
	for i, kind := range e.kinds {
		e.manifest.Parts = append(e.manifest.Parts, exclusionjournal.SourcePartSpecV1{Kind: exclusionjournal.PartKindV1(kind), Length: uint64(len(e.want[i]))})
		if i != e.pathIndex {
			e.input.Parts = append(e.input.Parts, e.origin(e.want[i]))
		}
	}
}

func (e journalHeaderEvidence) producer(t *testing.T) exclusionjournal.SourceExporterV1 {
	t.Helper()
	export, err := NewJournalHeaderPathSource148V1(e.manifest, e.input)
	journalHeaderMust(t, err)
	return export
}

func (e journalHeaderEvidence) assertPart(t *testing.T, part exclusionjournal.SourcePartV1, i int) {
	t.Helper()
	if i >= len(e.kinds) || byte(part.Kind) != e.kinds[i] || part.Length != uint64(len(e.want[i])) {
		t.Fatalf("part %d: kind=%d length=%d", i, part.Kind, part.Length)
	}
	data := make([]byte, len(e.want[i]))
	if n, err := part.ReadAt(data, 0); n != len(data) || err != nil || !bytes.Equal(data, e.want[i]) {
		t.Fatalf("part %d read %d/%v: got %x want %x", i, n, err, data, e.want[i])
	}
}

func (e journalHeaderEvidence) assertPathSuffix(t *testing.T, part exclusionjournal.SourcePartV1) {
	t.Helper()
	want := e.want[e.pathIndex][1:]
	got := make([]byte, len(want))
	if n, err := part.ReadAt(got, 1); n != len(want) || err != nil || !bytes.Equal(got, want) {
		t.Fatalf("path suffix read %d/%v: got %x want %x", n, err, got, want)
	}
}

func journalHeaderGuards(t *testing.T, owner *HeaderCandidateOwner148V1) {
	t.Helper()
	if owner == nil {
		return
	}
	if state := hcInnerOf(owner); state.guards != 0 || state.leases != 0 {
		t.Fatalf("provider held guards=%d leases=%d", state.guards, state.leases)
	}
}

func (e journalHeaderEvidence) preserve(t *testing.T) func() {
	t.Helper()
	originals := make([][]byte, len(e.input.Origins))
	for i, origin := range e.input.Origins {
		originals[i] = slices.Clone(origin.Bytes)
	}
	return func() {
		for i, origin := range e.input.Origins {
			if !bytes.Equal(originals[i], origin.Bytes) {
				t.Fatalf("origin %d changed", i)
			}
		}
	}
}

func TestJournalHeaderPathSource148(t *testing.T) {
	t.Run("snapshot", journalHeaderSnapshot)
	t.Run("refusals", journalHeaderRefusals)
	t.Run("prepared-retention", journalHeaderPreparedRetention)
}

func journalHeaderSnapshot(t *testing.T) {
	for _, c := range []struct {
		class, extent byte
		close         bool
	}{{1, 1, false}, {2, 0, true}, {3, 2, false}} {
		t.Run(fmt.Sprint(c.class), func(t *testing.T) {
			_, source := journalHeaderSource(t, t.TempDir(), journalHeaderLimits, false)
			extent := int(c.extent)
			e := newJournalHeaderEvidenceWithReceived(t, c.class, 2, extent, true, extent)
			if c.class == 2 {
				e.manifest.Parts[5].Length = 0
				e.input.Parts[4] = exclusionjournal.SourceViewV1{Origin: -1}
				e.input.Origins = e.input.Origins[:len(e.input.Origins)-1]
				e.want[5] = nil
			}
			export := e.producer(t)
			e.input.Parts[0].Offset++
			visits := 0
			journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
				return source.WithSourceExportV1(a, e.manifest, export, func(part exclusionjournal.SourcePartV1) error {
					if visits == 0 {
						journalHeaderChangeOriginal(t, e.input, c.close)
					}
					e.assertPart(t, part, visits)
					if visits == e.pathIndex {
						e.assertPathSuffix(t, part)
					}
					visits++
					return nil
				})
			})
			journalHeaderGuards(t, e.input.Owner)
			if visits != len(e.kinds) {
				t.Fatalf("snapshot visits=%d, want %d", visits, len(e.kinds))
			}
		})
	}
}

func journalHeaderChangeOriginal(t *testing.T, in JournalHeaderPathInput148V1, closeProvider bool) {
	t.Helper()
	journalHeaderGuards(t, in.Owner)
	if closeProvider {
		in.Owner.CloseV1()
	} else {
		tr := hcTr(in.Owner, nil)
		tr.NewSource = hcSrc2
		if pub, out := hcPublish(t, in.Owner, tr); out != HeaderCandidateOK148V1 || !pub.Changed {
			t.Fatalf("publish during visitor: %+v/%d", pub, out)
		}
	}
	for _, view := range []exclusionjournal.SourceViewV1{in.Path, in.Durable, in.OriginalProjection} {
		if view.Origin >= 0 {
			in.Origins[view.Origin].Bytes[view.Offset] ^= 1
		}
	}
}

func journalHeaderPreparedRetention(t *testing.T) {
	for _, class := range []byte{1, 2, 3} {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			dir := t.TempDir()
			store, source := journalHeaderSource(t, dir, journalHeaderLimits, false)
			e := newJournalHeaderEvidence(t, class, 2, 1, true)
			journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
				prepared, err := source.PrepareSourceV1(a, e.manifest, e.producer(t))
				if err != nil || prepared == nil {
					t.Fatalf("prepare: handle=%v err=%v", prepared != nil, err)
				}
				return a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil })
			})
			journalHeaderChangeOriginal(t, e.input, true)
			for _, origin := range e.input.Origins {
				clear(origin.Bytes)
			}
			journalHeaderMust(t, store.Close())
			_, reopened := journalHeaderSource(t, dir, journalHeaderLimits, true)
			calls := 0
			journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
				return reopened.WithCapturedSourceV1(a, e.manifest, func(part exclusionjournal.SourcePartV1) error {
					e.assertPart(t, part, calls)
					calls++
					return nil
				})
			})
			if calls != len(e.kinds) {
				t.Fatalf("reopened visits=%d, want %d", calls, len(e.kinds))
			}
		})
	}
}

func journalHeaderRefusals(t *testing.T) {
	journalHeaderShapeRefusals(t)
	journalHeaderPointRefusals(t)
	t.Run("precedence", journalHeaderPrecedence)
	t.Run("capacity", journalHeaderCapacityRefusals)
	t.Run("funding", journalHeaderFunding)
	t.Run("prepare-closed", journalHeaderPrepareRefusal)
	t.Run("visitor-outcome", journalHeaderVisitorOutcome)
}

func journalHeaderShapeRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*journalHeaderEvidence)
	}{
		{"zero-class", func(e *journalHeaderEvidence) { e.manifest.Class = 0 }},
		{"unknown-class", func(e *journalHeaderEvidence) { e.manifest.Class = 9 }},
		{"zero-identity", func(e *journalHeaderEvidence) { e.manifest.Identity = [32]byte{} }},
		{"missing-digest", func(e *journalHeaderEvidence) { e.manifest.AcquiredDigest = [32]byte{} }},
		{"missing-spec", func(e *journalHeaderEvidence) { e.manifest.Parts = e.manifest.Parts[:4] }},
		{"extra-spec", func(e *journalHeaderEvidence) { e.manifest.Parts = append(e.manifest.Parts, e.manifest.Parts[0]) }},
		{"wrong-kind", func(e *journalHeaderEvidence) { e.manifest.Parts[0].Kind = 1 }},
		{"reordered-spec", func(e *journalHeaderEvidence) { p := e.manifest.Parts; p[0], p[2] = p[2], p[0] }},
		{"wrong-spec-length", func(e *journalHeaderEvidence) { e.manifest.Parts[1].Length++ }},
		{"empty-context", func(e *journalHeaderEvidence) { e.input.Parts[1] = exclusionjournal.SourceViewV1{Origin: -1} }},
		{"extra-view", func(e *journalHeaderEvidence) { e.input.Parts = append(e.input.Parts, e.input.Parts[0]) }},
		{"context-origin", func(e *journalHeaderEvidence) { e.input.Parts[1].Origin = 9 }},
		{"context-length", func(e *journalHeaderEvidence) { e.input.Parts[1].Length-- }},
		{"path-width", func(e *journalHeaderEvidence) { e.input.Path.Length-- }},
		{"path-range", func(e *journalHeaderEvidence) { e.input.Path.Offset = math.MaxUint64 }},
		{"durable-width", func(e *journalHeaderEvidence) { e.input.Durable.Length-- }},
		{"durable-range", func(e *journalHeaderEvidence) { e.input.Durable.Offset = math.MaxUint64 }},
		{"extent-exceeds-path", func(e *journalHeaderEvidence) { e.input.DurableExtent = 3 }},
		{"surplus-slots", func(e *journalHeaderEvidence) { e.input.DurableExtent = 0 }},
		{"projection-range", func(e *journalHeaderEvidence) { e.input.OriginalProjection.Offset = math.MaxUint64 }},
		{"projection-length", func(e *journalHeaderEvidence) { e.input.OriginalProjection.Length-- }},
		{"excess-origins", func(e *journalHeaderEvidence) { e.origin([]byte{1}) }},
		{"planned-input", func(e *journalHeaderEvidence) { e.input.Origins[0].PlannedBytes = 1 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newJournalHeaderEvidence(t, 3, 2, 1, true)
			c.edit(&e)
			journalHeaderAssertShape(t, e, exclusionjournal.ErrIntegrityV1)
		})
	}
	t.Run("projection-overflow", func(t *testing.T) {
		e := newJournalHeaderEvidence(t, 1, 2, 1, false)
		e.input.Path.Length = uint64((math.MaxInt-292)/180+1) * 32
		journalHeaderAssertShape(t, e, exclusionjournal.ErrCapacityV1)
	})
}

func journalHeaderAssertShape(t *testing.T, e journalHeaderEvidence, want error) {
	t.Helper()
	defer e.preserve(t)()
	export, err := NewJournalHeaderPathSource148V1(e.manifest, e.input)
	if export != nil || any(err) != any(want) {
		t.Fatalf("preflight: producer=%v err=%v, want %v", export != nil, err, want)
	}
	journalHeaderGuards(t, e.input.Owner)
}

func journalHeaderPointRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		want error
		edit func(*testing.T, *journalHeaderEvidence)
	}{
		{"nil-provider", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Owner = nil }},
		{"unestablished", nil, func(t *testing.T, e *journalHeaderEvidence) {
			e.input.Owner = hcNew(t, hcLim())
			e.input.Version = e.input.Owner.VersionV1()
		}},
		{"closed", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Owner.CloseV1() }},
		{"unknown", nil, journalHeaderUnknown},
		{"stale", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Version--; e.input.Origins[1].Bytes[6] ^= 1 }},
		{"incarnation", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Incarnation++ }},
		{"zero-incarnation", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Incarnation = 0 }},
		{"zero-version", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Version = 0 }},
		{"missing-attachment", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.AttachmentHash = [32]byte{} }},
		{"missing-provenance", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Provenance = [32]byte{} }},
		{"missing-B-hash", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Hash = [32]byte{} }},
		{"missing-expected-B", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.HasExpected = false }},
		{"short-durable", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.DurableExtent = 2 }},
		{"durable-hole", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Origins[1].Bytes[5] = 0 }},
		{"absent-received", nil, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Origins[0].Bytes[37] ^= 1 }},
		{"bad-presence", exclusionjournal.ErrIntegrityV1, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Origins[1].Bytes[5] = 2 }},
		{"wrong-raw-hash", exclusionjournal.ErrIntegrityV1, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Origins[1].Bytes[6] ^= 1 }},
		{"wrong-final-B", exclusionjournal.ErrIntegrityV1, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Hash[0] ^= 1 }},
		{"wrong-expected-B", exclusionjournal.ErrIntegrityV1, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Expected[0] ^= 1 }},
		{"wrong-projection", exclusionjournal.ErrIntegrityV1, func(_ *testing.T, e *journalHeaderEvidence) { e.input.Origins[2].Bytes[5] ^= 1 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, source := journalHeaderSource(t, t.TempDir(), journalHeaderLimits, false)
			supplied := true
			switch c.name {
			case "stale", "wrong-raw-hash", "short-durable", "wrong-final-B", "wrong-expected-B":
				supplied = false
			}
			e := newJournalHeaderEvidence(t, 1, 2, 1, supplied)
			c.edit(t, &e)
			journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
				journalHeaderAssertRefusal(t, source, a, e, cmp.Or(c.want, exclusionjournal.ErrUnavailableV1), 1)
				if c.name == "closed" && e.input.Owner.VersionV1() != e.input.Version {
					t.Fatalf("closed version=%d, want %d", e.input.Owner.VersionV1(), e.input.Version)
				}
				return journalHeaderSibling(t, source, a)
			})
		})
	}
}

func journalHeaderUnknown(t *testing.T, e *journalHeaderEvidence) {
	t.Helper()
	tr := hcTr(e.input.Owner, nil)
	tr.NewSource = hcSrc2
	handle, out := e.input.Owner.PrepareV1(tr)
	if out != HeaderCandidateOK148V1 || handle.UnknownV1() != HeaderCandidateOK148V1 {
		t.Fatalf("unknown provider transition: %d", out)
	}
	e.input.Version = e.input.Owner.VersionV1()
}

func journalHeaderAssertRefusal(t *testing.T, source *exclusionjournal.SourceOwnerV1, a *mdbx.OperationAccount, e journalHeaderEvidence, want error, exporterCalls int) {
	t.Helper()
	defer e.preserve(t)()
	export := e.producer(t)
	calls, visits := 0, 0
	err := source.WithSourceExportV1(a, e.manifest, func(op *exclusionjournal.SourceOperationV1, visit func(exclusionjournal.SourcePartV1) error) error {
		calls++
		return export(op, visit)
	}, func(exclusionjournal.SourcePartV1) error { visits++; return nil })
	if any(err) != any(want) || calls != exporterCalls || visits != 0 {
		t.Fatalf("refusal=%v, want %v; exporter=%d, want %d; visits=%d", err, want, calls, exporterCalls, visits)
	}
	journalHeaderGuards(t, e.input.Owner)
}

func journalHeaderSibling(t *testing.T, source *exclusionjournal.SourceOwnerV1, a *mdbx.OperationAccount) error {
	t.Helper()
	return journalHeaderAssertOnePoint(t, source, a, newJournalHeaderEvidence(t, 1, 1, 0, false))
}

func journalHeaderAssertOnePoint(t *testing.T, source *exclusionjournal.SourceOwnerV1, a *mdbx.OperationAccount, e journalHeaderEvidence) error {
	t.Helper()
	calls := 0
	err := source.WithSourceExportV1(a, e.manifest, e.producer(t), func(part exclusionjournal.SourcePartV1) error {
		e.assertPart(t, part, calls)
		calls++
		return nil
	})
	if err != nil || calls != 6 || len(e.want[4]) != 472 {
		t.Fatalf("one-point sibling: %v visits=%d length=%d", err, calls, len(e.want[4]))
	}
	return a.WithReservation(mdbx.TreeLaneMaxBytes, func() error { return nil })
}

func journalHeaderPrecedence(t *testing.T) {
	store, source := journalHeaderSource(t, t.TempDir(), journalHeaderLimits, false)
	_, sibling := journalHeaderSource(t, t.TempDir(), journalHeaderLimits, false)
	empty := newJournalHeaderEvidence(t, 1, 0, 0, false)
	one := newJournalHeaderEvidence(t, 1, 1, 0, false)
	empty.input.Owner = one.input.Owner
	if len(empty.want[4]) != 292 {
		t.Fatalf("empty projection length=%d", len(empty.want[4]))
	}
	journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
		journalHeaderAssertRefusal(t, source, a, empty, exclusionjournal.ErrCapacityV1, 1)
		journalHeaderMust(t, journalHeaderAssertOnePoint(t, source, a, one))
		empty.input.Owner = nil
		exact := a.WithReservation(mdbx.TreeLaneMaxBytes+1, func() error { return nil })
		journalHeaderMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-journalHeaderLimits.WorkingBytesV1(), func() error {
			for _, e := range []journalHeaderEvidence{empty, newJournalHeaderEvidence(t, 1, 1, 0, false)} {
				bad := e
				bad.input.Parts = slices.Clone(e.input.Parts)
				bad.input.Parts[2].Offset = math.MaxUint64
				journalHeaderAssertShape(t, bad, exclusionjournal.ErrIntegrityV1)
				bad.input.Parts = slices.Delete(bad.input.Parts, 2, 3)
				journalHeaderAssertShape(t, bad, exclusionjournal.ErrIntegrityV1)
			}
			journalHeaderAssertRefusal(t, source, a, empty, exclusionjournal.ErrCapacityV1, 1)
			journalHeaderAssertRefusal(t, source, a, newJournalHeaderEvidence(t, 1, 1, 0, false), exact, 1)
			return nil
		}))
		journalHeaderMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes, func() error {
			journalHeaderAssertRefusal(t, source, a, empty, exact, 0)
			return nil
		}))
		missing := newJournalHeaderEvidence(t, 1, 1, 0, false)
		missing.input.HasExpected = false
		journalHeaderAssertRefusal(t, source, a, missing, exclusionjournal.ErrUnavailableV1, 1)
		journalHeaderMust(t, store.Close())
		journalHeaderAssertRefusal(t, source, a, missing, policycontrol.ErrClosed, 0)
		return journalHeaderSibling(t, sibling, a)
	})
}

func (e journalHeaderEvidence) backingBytes() uint64 {
	total := uint64(len(e.want[e.pathIndex]))
	for _, origin := range e.input.Origins {
		total += uint64(len(origin.Bytes))
	}
	return total
}

func journalHeaderCapacityRefusals(t *testing.T) {
	for _, limit := range []string{"headers", "scans", "bytes", "ram"} {
		t.Run(limit, func(t *testing.T) {
			limits := journalHeaderLimits
			e := newJournalHeaderEvidence(t, 1, 2, 1, true)
			e.input.Origins[1].Bytes[6] ^= 1
			calls := 1
			switch limit {
			case "headers":
				limits.Headers = 1
			case "scans":
				limits.Scans = 39
			case "bytes":
				size, err := e.manifest.SizeV1()
				journalHeaderMust(t, err)
				limits.Bytes, calls = size-1, 0
			case "ram":
				limits.RAM = limits.WorkingBytesV1() + 1024 + 8*168 + e.backingBytes() - 1
			}
			_, source := journalHeaderSource(t, t.TempDir(), limits, false)
			journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
				journalHeaderAssertRefusal(t, source, a, e, exclusionjournal.ErrCapacityV1, calls)
				return journalHeaderSibling(t, source, a)
			})
		})
	}
}

func journalHeaderFunding(t *testing.T) {
	_, source := journalHeaderSource(t, t.TempDir(), journalHeaderLimits, false)
	e := newJournalHeaderEvidence(t, 1, 2, 1, true)
	defer e.preserve(t)()
	j := journalHeaderLimits.WorkingBytesV1() + e.backingBytes()
	journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
		exact := a.WithReservation(mdbx.TreeLaneMaxBytes+1, func() error { return nil })
		journalHeaderMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-j+1, func() error {
			journalHeaderAssertRefusal(t, source, a, e, exact, 1)
			return nil
		}))
		visits := 0
		journalHeaderMust(t, a.WithReservation(mdbx.TreeLaneMaxBytes-j, func() error {
			return source.WithSourceExportV1(a, e.manifest, e.producer(t), func(part exclusionjournal.SourcePartV1) error {
				e.assertPart(t, part, visits)
				visits++
				return nil
			})
		}))
		if visits != 6 {
			t.Fatalf("exact funding visits=%d, want 6", visits)
		}
		return journalHeaderSibling(t, source, a)
	})
}

func journalHeaderPrepareRefusal(t *testing.T) {
	_, source := journalHeaderSource(t, t.TempDir(), journalHeaderLimits, false)
	e := newJournalHeaderEvidence(t, 3, 2, 1, false)
	e.input.Owner.CloseV1()
	journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
		prepared, err := source.PrepareSourceV1(a, e.manifest, e.producer(t))
		if prepared != nil || any(err) != any(exclusionjournal.ErrUnavailableV1) {
			t.Fatalf("closed prepare: handle=%v err=%v", prepared != nil, err)
		}
		journalHeaderGuards(t, e.input.Owner)
		err = source.WithCapturedSourceV1(a, e.manifest, func(exclusionjournal.SourcePartV1) error { t.Fatal("closed source retained"); return nil })
		if any(err) != any(exclusionjournal.ErrUnavailableV1) {
			t.Fatalf("closed source readback: %v", err)
		}
		return journalHeaderSibling(t, source, a)
	})
}

func journalHeaderVisitorOutcome(t *testing.T) {
	_, source := journalHeaderSource(t, t.TempDir(), journalHeaderLimits, false)
	e := newJournalHeaderEvidence(t, 1, 2, 1, true)
	defer e.preserve(t)()
	export := e.producer(t)
	direct := os.ErrInvalid
	var typedNil *os.PathError
	for _, cause := range []error{direct, fmt.Errorf("path: %w", direct), typedNil, nil} {
		journalHeaderAccount(t, func(a *mdbx.OperationAccount) error {
			var result error
			var panicked any
			attempts, visits := 0, 0
			func() {
				defer func() { panicked = recover() }()
				result = source.WithSourceExportV1(a, e.manifest, func(op *exclusionjournal.SourceOperationV1, visit func(exclusionjournal.SourcePartV1) error) error {
					return export(op, func(p exclusionjournal.SourcePartV1) error { attempts++; return visit(p) })
				}, func(exclusionjournal.SourcePartV1) error {
					visits++
					if cause == nil {
						panic(&e)
					}
					return cause
				})
			}()
			if any(result) != any(cause) || attempts != 1 || visits != 1 || (cause == nil && panicked != &e) || (cause != nil && panicked != nil) {
				t.Fatalf("visitor result=%v panic=%v forwarding=%d visits=%d", result, panicked, attempts, visits)
			}
			journalHeaderGuards(t, e.input.Owner)
			return journalHeaderSibling(t, source, a)
		})
	}
}

//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// rawSideWorld is a side world whose image oracle compares committed rows natively, so seeded malformed rows are
// observed exactly instead of being refused by Reader.Get's width bound.
func rawSideWorld(t *testing.T, spec sideWorldSpec) *sideWorld {
	t.Helper()
	w := newSideWorld(t, spec)
	w.rawEqual = func(rank uint8, key, want []byte) (bool, error) {
		return mdbx.FixtureRawRowEqual(w.store, rank, key, want)
	}
	return w
}

func TestSelectedSideDamageFixtureMalformedAuthority(t *testing.T) {
	for _, denied := range []bool{false, true} {
		w := rawSideWorld(t, sideFullSpec)
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, []byte{9}) == nil, "seed malformed authority")
		var out selectedSideOutcome
		if denied {
			err := w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { out = w.run(3); return nil })
			logicalMDBXAssert(t, err == nil, "outer charge: %v", err)
		} else {
			out = w.run(3)
		}
		sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "malformed authority")
		sideWantEngine(t, out.Err, mdbx.EngineIntegrity, "invalid storage authority", "malformed authority")
		w.wantConsumed("malformed authority", out.Err)
		sideWantReleased(t, w.owner, "malformed authority")
		w.reopen()
		w.wantImage("malformed authority", []byte{9}, false)
	}
}

// TestSelectedSideDamageFixtureOptionalEvidence persists optional rows the Update grammar refuses: an invalid-width
// or wrong-hash header and a below-lower-bound body are positive damage without a copy; an above-upper-bound body is
// damage whose borrowed Consulted OLD image exceeds its MaxBlockBytes lane share, so the clear refuses before mutation.
func TestSelectedSideDamageFixtureOptionalEvidence(t *testing.T) {
	for _, row := range []struct {
		name  string
		rank  uint8
		value []byte
	}{{"header invalid width", 3, make([]byte, 100)}, {"header wrong hash", 3, make([]byte, 116)}, {"body below lower bound", 4, make([]byte, 115)}} {
		t.Run(row.name, func(t *testing.T) {
			w := rawSideWorld(t, sideFullSpec)
			hash := w.sideAt[3]
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, row.rank, hash[:], row.value) == nil, "seed row")
			if row.rank == 3 {
				w.headers[hash] = row.value
			} else {
				w.bodies[hash] = row.value
			}
			sideWantCleared(t, w, w.run(3), row.name)
		})
	}
	// Selective U14 wrong-hash witness: a legal header with the original parent, target and work but another nonce
	// hashes to a different key, while the persisted key, SideLink and hash-bound body stay the original valid block;
	// only the header-hash check observes the damage.
	t.Run("header legal other nonce", func(t *testing.T) {
		w := rawSideWorld(t, sideFullSpec)
		hash := w.sideAt[3]
		header := sideWorldBlock([32]byte(w.links[3][32:64]), 3_000_003)[:BLOCK_HEADER_BYTES]
		logicalMDBXAssert(t, sha3_256(header) != hash, "witness header hashes to its key")
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, hash[:], header) == nil, "seed row")
		w.headers[hash] = header
		w.wantImage("header legal other nonce seeded", w.authority, false)
		sideWantCleared(t, w, w.run(3), "header legal other nonce")
	})
	w := rawSideWorld(t, sideFullSpec)
	hash := w.sideAt[3]
	over := make([]byte, 68_000_126)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 4, hash[:], over) == nil, "seed over-width body")
	w.bodies[hash] = over
	out := w.run(3)
	sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "over-width body")
	var failure *selectedSideFailure
	logicalMDBXAssert(t, errors.As(out.Err, &failure), "over-width body: %v", out.Err)
	w.wantImage("over-width body", w.authority, false)
	w.wantOpen("over-width body")
	sideWantReleased(t, w.owner, "over-width body")
	w.reopen()
	w.wantImage("over-width body after reopen", w.authority, false)
	// A present leaving header of 8,388,609 bytes is positive damage without a Go copy, but its borrowed OLD image
	// alone exceeds the 8 MiB transfer share: the clear refuses before any Batch.
	w = rawSideWorld(t, sideFullSpec)
	hash = w.sideAt[3]
	header := make([]byte, 8_388_609)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, hash[:], header) == nil, "seed oversized header")
	w.headers[hash] = header
	out = w.run(3)
	sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "oversized header")
	logicalMDBXAssert(t, errors.As(out.Err, &failure), "oversized header: %v", out.Err)
	w.wantImage("oversized header", w.authority, false)
	w.wantOpen("oversized header")
	sideWantReleased(t, w.owner, "oversized header")
	w.reopen()
	w.wantImage("oversized header after reopen", w.authority, false)
}

// TestSelectedSideDamageFixtureRequiredWidth persists required canonical rows outside their SchemaV2 width and an
// unpaired owner row: Reader.Get or CanonicalOwnerV1 records the integrity failure and the Store is consumed; a
// legal-width wrong-hash kept header is callback-only integrity with an open Store.
func TestSelectedSideDamageFixtureRequiredWidth(t *testing.T) {
	kept := sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, override: map[uint64]uint64{3: 0}}
	sameHeight := sideWorldSpec{f: 1, tip: 4, rows: 3, b: 1, canonicalTip: 2, override: map[uint64]uint64{2: 2}}
	for _, row := range []struct {
		name, diagnostic string
		spec             sideWorldSpec
		h                uint64
		rank             uint8
		key              func(*sideWorld) []byte
		value            []byte
		damage           bool
		expect           func(w *sideWorld, key, value []byte) // records the seeded bytes in the independent oracle
	}{
		{
			"owner index inconsistency", "canonical owner index inconsistency", sideFullSpec, 3, 7, func(w *sideWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.sideAt[3])) }, mdbx.CanonicalOwnerValue(9), false,
			func(w *sideWorld, key, value []byte) { w.extra = append(w.extra, sideRawRow{7, key, value}) },
		},
		{
			"later SideLink width", "stored value width outside SchemaV2 bound", sideFullSpec, 2, 6, func(*sideWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(2, 4)) }, make([]byte, 103), true,
			func(w *sideWorld, _, value []byte) { w.links[4] = value },
		},
		{
			"kept header width", "stored value width outside SchemaV2 bound", kept, 2, 3, func(w *sideWorld) []byte { return w.canonical[0][:] }, make([]byte, 100), true,
			func(w *sideWorld, _, value []byte) { w.headers[w.canonical[0]] = value },
		},
		{
			"anchor width", "stored value width outside SchemaV2 bound", sideFullSpec, 2, 2, func(*sideWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(1, 1)) }, make([]byte, 103), false,
			func(w *sideWorld, _, value []byte) { w.entries[1] = value },
		},
		{
			"required body width", "stored value width outside SchemaV2 bound", sameHeight, 2, 4, func(w *sideWorld) []byte { return w.canonical[2][:] }, make([]byte, 100), false,
			func(w *sideWorld, _, value []byte) { w.bodies[w.canonical[2]] = value },
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := rawSideWorld(t, row.spec)
			if row.damage {
				w.removeBody(2)
			}
			key := row.key(w)
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, row.rank, key, row.value) == nil, "seed row")
			row.expect(w, key, row.value)
			out := w.run(row.h)
			sideWantOutcome(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, row.name)
			sideWantEngine(t, out.Err, mdbx.EngineIntegrity, row.diagnostic, row.name)
			w.wantConsumed(row.name, out.Err)
			sideWantReleased(t, w.owner, row.name)
			w.reopen()
			w.wantImage(row.name, w.authority, false)
		})
	}
	w := rawSideWorld(t, kept)
	w.removeBody(2)
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, w.canonical[0][:], make([]byte, 116)) == nil, "seed kept header")
	w.headers[w.canonical[0]] = make([]byte, 116)
	sideWantDefect(t, w.run(2), "kept header wrong hash")
	w.wantImage("kept header wrong hash", w.authority, false)
	w.wantOpen("kept header wrong hash")
}

type sideBridgeCase struct {
	name     string
	spec     sideWorldSpec
	prepare  func(*sideWorld)
	scenario mdbx.SelectedDamageScenario
	rank     uint8
	key      func(*sideWorld) []byte
	h        uint64
	denied   bool
	result   string
	truth    mdbx.CommitTruth
	stage    mdbx.UpdateStage
	causes   string // op:class of each flattened raw cause, "-" for a non-engine cause
	image    string // "old", "cleared" or "third"
	check    func(mdbx.SelectedDamageEvidence) bool
}

func sideCauses(err error) string {
	parts := ""
	for i, part := range genesisMDBXCauses(err) {
		if i > 0 {
			parts += ","
		}
		engine, ok := part.(*mdbx.EngineError) //nolint:errorlint // Classify each flattened direct cause.
		if !ok || engine == nil {
			parts += "-"
			continue
		}
		parts += engine.Operation + ":" + string(engine.Class)
	}
	return parts
}

func sideNoArtifact(e mdbx.SelectedDamageEvidence) bool {
	return e.OldGets[1]+e.OldGets[2]+e.OldGets[3]+e.OldGets[4]+e.OldGets[5]+e.OldGets[6]+e.OldGets[7] == 0 && e.BeginWrite == 0
}

// TestSelectedSideDamageFixtureNativeBridge drives the actual selected operation through the fixture-only native
// boundary: each fixed native result enters the real Update/Reader/commit/readback machinery, and the probe at every
// reached post-plan site must be denied the full lane. Assertions and byte oracles run after the fixture disarmed.
func TestSelectedSideDamageFixtureNativeBridge(t *testing.T) {
	damage := func(w *sideWorld) { w.removeBody(2) }
	authority := func(*sideWorld) []byte { return []byte{2} }
	begin := func(e mdbx.SelectedDamageEvidence) bool {
		return e.BeginOld == 1 && e.OldAborts == 0 && e.Probes == 0 && e.OldGets[0] == 0 && sideNoArtifact(e)
	}
	authorityOnly := func(e mdbx.SelectedDamageEvidence) bool {
		return e.OldGets[0] == 1 && sideNoArtifact(e) && e.OldAborts == 1
	}
	written := func(e mdbx.SelectedDamageEvidence) bool {
		return e.BeginWrite == 1 && e.Commits == 1 && e.BeginRead == 1
	}
	old, prewrite, crossed := mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, mdbx.UpdateStageCommitMayHaveCrossed
	storageIO := "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
	for _, row := range []sideBridgeCase{
		{name: "old begin txn full", scenario: mdbx.SelectedDamageBeginTxnFull, result: "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", truth: old, stage: prewrite, causes: "update:Transaction", image: "old", check: begin},
		{name: "old begin io", scenario: mdbx.SelectedDamageBeginEIO, result: storageIO, truth: old, stage: prewrite, causes: "update:IO", image: "old", check: begin},
		{name: "old begin io denied", scenario: mdbx.SelectedDamageBeginEIO, denied: true, result: storageIO, truth: old, stage: prewrite, causes: "update:IO", image: "old", check: begin},
		{name: "authority io", scenario: mdbx.SelectedDamageGetEIO, key: authority, result: storageIO, truth: old, stage: prewrite, causes: "get:IO", image: "old", check: authorityOnly},
		{name: "authority io denied", scenario: mdbx.SelectedDamageGetEIO, key: authority, denied: true, result: storageIO, truth: old, stage: prewrite, causes: "get:IO", image: "old", check: authorityOnly},
		{name: "authority io plus abort io", scenario: mdbx.SelectedDamageGetAbortEIO, key: authority, result: storageIO, truth: old, stage: prewrite, causes: "get:IO,abort:IO", image: "old", check: authorityOnly},
		{
			name: "healthy plus abort io", scenario: mdbx.SelectedDamageAbortEIO, h: 3, result: storageIO, truth: old, stage: prewrite, causes: "-,abort:IO", image: "old",
			check: func(e mdbx.SelectedDamageEvidence) bool { return e.OldAborts == 1 && e.BeginWrite == 0 },
		},
		{name: "optional header io", scenario: mdbx.SelectedDamageGetEIO, rank: 3, key: func(w *sideWorld) []byte { hash := w.sideAt[3]; return hash[:] }, h: 3, result: "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", truth: old, stage: prewrite, causes: "get:IO", image: "old"},
		{name: "optional later link io after damage", scenario: mdbx.SelectedDamageGetEIO, prepare: damage, rank: 6, key: func(*sideWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(2, 4)) }, result: "LOCAL_RESOURCE_UNAVAILABLE(branch_data)", truth: old, stage: prewrite, causes: "get:IO", image: "old"},
		{name: "required owner io after damage", scenario: mdbx.SelectedDamageGetEIO, prepare: damage, rank: 7, key: func(w *sideWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(1, w.sideAt[3])) }, result: "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", truth: old, stage: prewrite, causes: "get:IO", image: "old"},
		{name: "required kept header io after damage", spec: sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, override: map[uint64]uint64{3: 0}}, scenario: mdbx.SelectedDamageGetEIO, prepare: damage, rank: 3, key: func(w *sideWorld) []byte { return w.canonical[0][:] }, result: "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", truth: old, stage: prewrite, causes: "get:IO", image: "old"},
		{
			name: "definite precommit delete io", scenario: mdbx.SelectedDamageDeleteEIO, prepare: damage, result: "LOCAL_PERSISTENCE_ERROR(precommit)", truth: old, stage: mdbx.UpdateStageWriteStartedDefinitelyPrecommit, causes: "update:IO", image: "old",
			check: func(e mdbx.SelectedDamageEvidence) bool {
				return e.BeginWrite == 1 && e.Deletes == 1 && e.Commits == 0 && e.BeginRead == 0
			},
		},
		{name: "crossed coherent OLD", scenario: mdbx.SelectedDamageCommitOld, prepare: damage, result: sideCleared, truth: old, stage: crossed, causes: "update:Capacity", image: "old", check: written},
		{name: "crossed coherent NEW", scenario: mdbx.SelectedDamageCommitNew, prepare: damage, result: sideCleared, truth: mdbx.CommitTruthNew, stage: crossed, causes: "update:Capacity", image: "cleared", check: written},
		{
			name: "crossed unreadable", scenario: mdbx.SelectedDamageCommitUnreadable, prepare: damage, key: authority, result: sideCleared, truth: mdbx.CommitTruthUnknown, stage: crossed, causes: "update:Capacity,update:IO", image: "cleared",
			check: func(e mdbx.SelectedDamageEvidence) bool { return written(e) && e.ReadGets >= 1 },
		},
		{name: "crossed readable third image", scenario: mdbx.SelectedDamageCommitThird, prepare: damage, result: sideCleared, truth: mdbx.CommitTruthUnknown, stage: crossed, causes: "update:Capacity", image: "third", check: written},
	} {
		sideRunBridge(t, row)
	}
}

func sideRunBridge(t *testing.T, row sideBridgeCase) {
	t.Run(row.name, func(t *testing.T) {
		spec := row.spec
		if spec.tip == 0 {
			spec = sideFullSpec
		}
		w := newSideWorld(t, spec)
		if row.prepare != nil {
			row.prepare(w)
		}
		h := row.h
		if h == 0 {
			h = 2
		}
		var key []byte
		if row.key != nil {
			key = row.key(w)
		}
		var out selectedSideOutcome
		evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, row.scenario, row.rank, key, func() {
			if !row.denied {
				out = w.run(h)
				return
			}
			_ = w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { out = w.run(h); return nil })
		})
		logicalMDBXAssert(t, err == nil, "%s: fixture: %v (%+v)", row.name, err, evidence)
		canonical := "OLD"
		if row.result == sideCleared {
			canonical = "NOT_APPLICABLE"
		}
		sideWantOutcome(t, out, row.result, canonical, row.truth, row.stage, row.name)
		logicalMDBXAssert(t, sideCauses(out.Err) == row.causes, "%s: raw causes %q, want %q", row.name, sideCauses(out.Err), row.causes)
		logicalMDBXAssert(t, evidence.ProbeRan == 0 && evidence.ProbeDenied == evidence.Probes, "%s: full lane granted to a probe: %+v", row.name, evidence)
		logicalMDBXAssert(t, row.check == nil || row.check(evidence), "%s: native sites %+v", row.name, evidence)
		w.wantConsumed(row.name, out.Err)
		sideWantReleased(t, w.owner, row.name)
		w.reopen()
		switch row.image {
		case "cleared":
			w.wantImage(row.name, w.clearedAuthority(), true)
		case "third":
			w.wantImage(row.name, []byte{0x7f}, true)
		default:
			w.wantImage(row.name, w.authority, false)
		}
	})
}

// TestSelectedSideDamageFixtureLaneLifetime observes the full lane synchronously at every reached native site of a
// committed clear and of a healthy no-op: post-plan write begin, commit, and immediately before and after the OLD
// abort. Every probe must be denied with its callback never run; after return the lane is granted once, a nested full
// lane inside it is denied, and a later grant shows no residual charge. The exact OLD-snapshot Get counts per DBI rank
// (meta, utxo, canonical, headers, blocks, undo, staged, owner) pin every relied-on read: callback reads, Update's
// Consulted OLD capture (links, owner rows including absences, anchor, body) and preflight target images (authority,
// three leaving headers); a plan that drops any consulted observation changes its rank's count.
func TestSelectedSideDamageFixtureLaneLifetime(t *testing.T) {
	for _, row := range []struct {
		name          string
		prepare       bool
		probes        uint64
		write, commit uint64
		gets          [8]uint64
		override      map[uint64]uint64
	}{
		{"committed clear", true, 4, 1, 1, [8]uint64{2, 0, 2, 6, 2, 0, 6, 6}, nil},
		{"healthy no-op", false, 2, 0, 0, [8]uint64{1, 0, 1, 1, 1, 0, 1, 1}, nil},
		// Heights 3 and 4 both name canonical 0: one owner resolution (owner and forward rows) and one kept-header read.
		{"duplicate kept hash", true, 4, 1, 1, [8]uint64{2, 0, 4, 4, 2, 0, 6, 4}, map[uint64]uint64{3: 0, 4: 0}},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newSideWorld(t, sideWorldSpec{f: 1, tip: 4, rows: 3, canonicalTip: 1, override: row.override})
			if row.prepare {
				w.removeBody(2)
			}
			var out selectedSideOutcome
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.run(2) })
			logicalMDBXAssert(t, err == nil, "fixture: %v", err)
			logicalMDBXAssert(t, evidence.Probes == row.probes && evidence.ProbeDenied == row.probes && evidence.ProbeRan == 0 && evidence.BeginWrite == row.write && evidence.Commits == row.commit && evidence.BeginRead == 0 && evidence.OldAborts == 1, "%s: lane evidence %+v", row.name, evidence)
			logicalMDBXAssert(t, evidence.OldGets == row.gets, "%s: OLD-snapshot Gets by rank %v, want %v", row.name, evidence.OldGets, row.gets)
			if row.prepare {
				sideWantCleared(t, w, out, row.name)
				return
			}
			sideWantOutcome(t, out, "", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, row.name)
			logicalMDBXAssert(t, out.Err == nil, "%s: %v", row.name, out.Err)
			sideWantReleased(t, w.owner, row.name)
			w.wantImage(row.name, w.authority, false)
		})
	}
	// A denied lane runs only the authority/control Update: one OLD begin, one authority Get, no artifact Get, no
	// write, one OLD abort whose probes are denied by the outer holder.
	t.Run("denied lane", func(t *testing.T) {
		w := newSideWorld(t, sideFullSpec)
		w.removeBody(2)
		var out selectedSideOutcome
		evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
			_ = w.owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { out = w.run(2); return nil })
		})
		logicalMDBXAssert(t, err == nil, "fixture: %v", err)
		sideWantOutcome(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", "OLD", mdbx.CommitTruthOld, mdbx.UpdateStagePrewrite, "denied lane")
		logicalMDBXAssert(t, evidence.BeginOld == 1 && evidence.OldGets == [8]uint64{1} && evidence.BeginWrite == 0 && evidence.OldAborts == 1 && evidence.Probes == 2 && evidence.ProbeDenied == 2 && evidence.ProbeRan == 0, "denied lane evidence %+v", evidence)
		w.wantOpen("denied lane")
		w.wantImage("denied lane", w.authority, false)
	})
	// An invalid owner refuses before any Update: no native transaction begins and no probe site is reached.
	t.Run("invalid owner", func(t *testing.T) {
		w := newSideWorld(t, sideFullSpec)
		w.removeBody(2)
		for _, owner := range []*mdbx.OperationReservationOwner{nil, {}} {
			var out selectedSideOutcome
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = selectedSideDamageMDBX(w.store, owner, 2, 4, 2) })
			logicalMDBXAssert(t, err == nil, "fixture: %v", err)
			logicalMDBXAssert(t, out.Err != nil && out.Err.Error() == "invalid storage operation reservation input" && evidence.BeginOld == 0 && evidence.Probes == 0, "invalid owner: %v %+v", out.Err, evidence)
		}
		w.wantImage("invalid owner", w.authority, false)
	})
}

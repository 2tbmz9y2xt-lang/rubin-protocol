//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func stepArmed(t *testing.T, w *stepWorld, h uint64, scenario mdbx.SelectedDamageScenario, rank uint8, key []byte) (ReplayStepOutcomeV1, mdbx.SelectedDamageEvidence) {
	t.Helper()
	var out ReplayStepOutcomeV1
	evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { out = w.call(h) })
	logicalMDBXAssert(t, err == nil, "STEP fixture %d/%d: %v", scenario, rank, err)
	return out, evidence
}

// The next public STEP invocation must classify the cached original cause, with no callback or source query.
func stepCached(t *testing.T, w *stepWorld, h uint64, previous ReplayStepOutcomeV1, result string) {
	t.Helper()
	versions, protects, calls := w.view.versions, w.view.protects, w.view.headerCalls
	again := w.call(h)
	stepTuple(t, again, result, "", "OLD", uint8(previous.Truth), 1, false)
	logicalMDBXAssert(t, stepSameError(again.Err, previous.Err) && again.Needed == nil && versions == w.view.versions && protects == w.view.protects && calls == w.view.headerCalls, "cached STEP changed error identity or reached sources: %+v", again)
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureBeginAndPrecommit(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario mdbx.SelectedDamageScenario
		rank     uint8
		class    mdbx.EngineClass
		result   string
		stage    uint8
		write    uint64
	}{
		{"begin_io", mdbx.SelectedDamageBeginEIO, 0, mdbx.EngineIO, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 1, 0},
		{"begin_full", mdbx.SelectedDamageBeginTxnFull, 0, mdbx.EngineTransaction, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", 1, 0},
		{"write_begin", mdbx.SelectedDamageWriteBeginTxnFull, 0, mdbx.EngineTransaction, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", 1, 1},
		{"put", mdbx.SelectedDamagePutEIO, 1, mdbx.EngineIO, "LOCAL_PERSISTENCE_ERROR(precommit)", 2, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			before := w.image()
			var key []byte
			if row.scenario == mdbx.SelectedDamagePutEIO {
				parsed, err := ParseBlockBytes(w.bodies[0])
				logicalMDBXAssert(t, err == nil && len(parsed.Txs) == 1 && len(parsed.Txids) == 1 && len(parsed.Txs[0].Outputs) > 0, "genesis PUT source: %v", err)
				logicalMDBXAssert(t, parsed.Txs[0].Outputs[0].CovenantType != 2 && parsed.Txs[0].Outputs[0].CovenantType != 0x103, "genesis PUT output is prunable")
				key = append(binary.BigEndian.AppendUint64(nil, 2), parsed.Txids[0][:]...)
				key = binary.BigEndian.AppendUint32(key, 0)
			}
			out, evidence := stepArmed(t, w, 0, row.scenario, row.rank, key)
			stepTuple(t, out, row.result, "", "OLD", 1, row.stage, false)
			replayEngineClass(t, out.Err, row.class, row.name)
			logicalMDBXAssert(t, evidence.BeginOld == 1 && evidence.BeginWrite == row.write && evidence.Commits == 0 && evidence.Faults == 1 && out.Needed == nil, "actual site: %+v", evidence)
			cached := row.result
			if row.stage == 2 {
				cached = "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
			}
			stepCached(t, w, 0, out, cached)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), row.name)
			stepProgress(t, w, 0, w.authority(), w.call(0))
		})
	}
}

func TestReplayStepMDBXFixtureCrossed(t *testing.T) {
	for _, row := range []struct {
		name              string
		scenario          mdbx.SelectedDamageScenario
		truth             uint8
		result, canonical string
		faults            uint64
	}{
		{"OLD", mdbx.SelectedDamageCommitOld, 1, "TERMINAL_PERSISTENCE(old)", "OLD", 1},
		{"NEW", mdbx.SelectedDamageCommitNew, 2, "TERMINAL_PERSISTENCE(new)", "NEW", 1},
		{"unreadable", mdbx.SelectedDamageCommitUnreadable, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 2},
		{"neither", mdbx.SelectedDamageCommitThird, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			before := w.image()
			out, evidence := stepArmed(t, w, 0, row.scenario, 0, []byte{2})
			stepTuple(t, out, row.result, "", row.canonical, row.truth, 3, false)
			replayCrossedErr(t, out.Err, mdbx.CommitTruth(row.truth), row.name == "unreadable")
			logicalMDBXAssert(t, evidence.Faults == row.faults && evidence.BeginWrite == 1 && evidence.Commits == 1 && evidence.BeginRead == 1 && out.Needed == nil, "crossed evidence: %+v", evidence)
			stepCached(t, w, 0, out, selectedSideCapacity)
			w.store = w.reopen()
			switch row.name {
			case "OLD":
				replaySameImage(t, before, w.image(), "crossed OLD")
				stepProgress(t, w, 0, w.authority(), w.call(0))
			case "neither":
				control := newStepWorld(t, 1, false)
				controlBefore := control.image()
				stepProgress(t, control, 0, control.authority(), control.call(0))
				stepExactImage(t, control, 0, controlBefore, false)
				replaySameImage(t, replayThirdImage(control.image()), w.image(), "neither persisted complete image")
				stepTuple(t, w.call(1), selectedSideIntegrity, "", "OLD", 1, 1, false)
			case "NEW", "unreadable":
				stepExactImage(t, w, 0, before, false)
				stepProgress(t, w, 1, w.authority(), w.call(1))
			}
			stepReleased(t, w)
		})
	}
}

// All source-site faults are reached by the actual planner; transient absence never becomes a Need.
func TestReplayStepMDBXFixtureSourceReads(t *testing.T) {
	for _, row := range []struct {
		name   string
		h      uint64
		rank   uint8
		key    string
		result string
	}{
		{"authority", 0, 0, "authority", "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"},
		{"path_header", 0, 3, "tip", replayEntryRecovery},
		{"body", 0, 4, "current", replayEntryRecovery},
		{"context", 1, 2, "context", replayEntryRecovery},
		{"context_header", 1, 3, "genesis", replayEntryRecovery},
		{"counter", 1, 0, "counter", replayEntryRecovery},
		{"target_index", 0, 2, "target", replayEntryRecovery},
		{"target_owner", 0, 7, "owner", replayEntryRecovery},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			if row.h > 0 {
				w.prefix(t, row.h)
			}
			key := stepFixtureKey(w, row.key, row.h)
			before := w.image()
			out, evidence := stepArmed(t, w, row.h, mdbx.SelectedDamageGetEIO, row.rank, key)
			stepTuple(t, out, row.result, "", "OLD", 1, 1, false)
			if row.name == "counter" {
				joined, ok := out.Err.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "C32d application/native cause order: %T %v", out.Err, out.Err)
				parts := joined.Unwrap()
				failure, ok := parts[0].(*logicalStateFailure)
				logicalMDBXAssert(t, ok && failure.kind == logicalStateFailureUnavailable && failure.cause != nil, "C32d original failure: %T %v", out.Err, out.Err)
				logicalMDBXAssert(t, stepSameError(failure.cause, parts[1]), "C32d nested cause is not the original recorded native object")
				replayEngineClass(t, parts[1], mdbx.EngineIO, row.name)
			} else {
				replayEngineClass(t, out.Err, mdbx.EngineIO, row.name)
			}
			logicalMDBXAssert(t, out.Needed == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.OldGets[row.rank] > 0 && evidence.Faults == 1, "fault site/projection: %+v %+v", out, evidence)
			cached := "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
			stepCached(t, w, row.h, out, cached)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), row.name)
			stepProgress(t, w, row.h, w.authority(), w.call(row.h))
		})
	}
}

func stepFixtureKey(w *stepWorld, name string, h uint64) []byte {
	switch name {
	case "authority":
		return []byte{2}
	case "tip":
		return w.hashes[len(w.hashes)-1][:]
	case "current":
		return w.hashes[h][:]
	case "genesis":
		return w.hashes[0][:]
	case "context":
		return stepKey(2, h-1)
	case "counter":
		return binary.BigEndian.AppendUint64([]byte{0x10}, 2)
	case "target":
		return stepKey(2, h)
	case "owner":
		return append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[h][:]...)
	}
	panic("unknown fixed test site")
}

func TestReplayStepMDBXFixtureEndpoint(t *testing.T) {
	for _, scenario := range []uint8{1, 2, 3} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			w := newStepWorld(t, 1, true)
			w.prefix(t, 1)
			before := w.image()
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, nil, nil, false, func() { out = w.call(1) })
			logicalMDBXAssert(t, err == nil, "endpoint adapter: %v", err)
			if scenario == 1 {
				stepTuple(t, out, "", "", "NEW", 2, 3, true)
				logicalMDBXAssert(t, evidence.Queries == 3 && evidence.Opens == 3 && evidence.Gets == 6 && evidence.Closes == 3 && evidence.Faults == 0, "B38 endpoint census: %+v", evidence)
				stepExactImage(t, w, 1, before, false)
			} else {
				result, class := selectedSideCanonical, mdbx.EngineIO
				if scenario == 3 {
					result, class = selectedSideInvariant, mdbx.EngineLocalInvariant
				}
				stepTuple(t, out, result, "", "OLD", 1, 1, false)
				e, ok := out.Err.(*mdbx.EngineError)
				logicalMDBXAssert(t, ok && e.Class == class && e.Operation == "prefix-page" && out.Needed == nil && evidence.Queries == 1 && evidence.Opens == 1 && evidence.Gets == 1 && evidence.Closes == 1 && evidence.Faults == 1, "C31 endpoint fault: %+v %+v", e, evidence)
				stepReleased(t, w)
				w.store = w.reopen()
				replaySameImage(t, before, w.image(), "endpoint fault")
				stepProgress(t, w, 1, w.authority(), w.call(1))
			}
		})
	}
}

func TestReplayStepMDBXFixtureEndpointAndContextDrift(t *testing.T) {
	for _, generation := range []uint64{1, 2} {
		for _, offset := range []int{32, 63, 103} {
			for _, scenario := range []uint8{4, 5, 6} {
				t.Run(fmt.Sprintf("g%d_o%d_s%d", generation, offset, scenario), func(t *testing.T) {
					w := newStepWorld(t, 1, true)
					w.prefix(t, 1)
					before := w.image()
					key := stepKey(generation, 0)
					value, present := stepRead(t, w.store, 2, key)
					logicalMDBXAssert(t, present && len(value) == 104, "drift setup")
					value[offset] ^= 1
					var out ReplayStepOutcomeV1
					evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, value, true, func() { out = w.call(1) })
					logicalMDBXAssert(t, err == nil && evidence.Drift == 1, "full 104-byte drift: %v %+v", err, evidence)
					stage, queries, commits := uint8(1), uint32(2), uint32(0)
					result, canon, truth := replayEntryStale, "OLD", uint8(1)
					if scenario == 5 {
						stage, queries, result = 2, 3, selectedSidePrecommit
					}
					if scenario == 6 {
						stage, queries, commits, result, canon, truth = 3, 4, 1, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", 3
					}
					// Context inequality stops scoped proof before its later endpoint query; crossed proof still visits it.
					if generation == 2 && scenario != 6 {
						queries--
					}
					stepTuple(t, out, result, "", canon, truth, stage, false)
					logicalMDBXAssert(t, evidence.Queries == queries && evidence.Opens == queries && evidence.Closes == queries && evidence.Gets == queries*2 && evidence.Commits == commits && out.Needed == nil, "K10/K12 exact query/commit path: %+v", evidence)
					stepReleased(t, w)
					w.store = w.reopen()
					if scenario == 5 {
						replaySameImage(t, before, w.image(), "final proof aborted drift")
					}
					if scenario == 4 {
						for i := range before {
							if bytes.Equal(before[i].Key, append([]byte{2}, key...)) {
								before[i].Value = value
							}
						}
						replaySameImage(t, before, w.image(), "prewrite only fixture drift")
					}
					if scenario == 6 {
						replayCrossedErr(t, out.Err, mdbx.CommitTruthUnknown, false)
						stepExactImageExtra(t, w, 1, before, false, nil, []mdbx.PrefixRow{{Key: append([]byte{2}, key...), Value: value}})
					}
					if scenario != 5 {
						equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, value)
						logicalMDBXAssert(t, err == nil && equal, "persisted full 104-byte selected drift: %v", err)
					}
				})
			}
		}
	}
}

func TestReplayStepMDBXFixtureJoinedOriginalOrder(t *testing.T) {
	for _, abort := range []bool{false, true} {
		t.Run(fmt.Sprint(abort), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			before := w.image()
			scenario := mdbx.SelectedDamageGetEIO
			if abort {
				scenario = mdbx.SelectedDamageGetAbortEIO
			}
			out, evidence := stepArmed(t, w, 0, scenario, 3, w.hashes[1][:])
			stepTuple(t, out, replayEntryRecovery, "", "OLD", 1, 1, false)
			if abort {
				joined, ok := out.Err.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok, "native joined cause lost: %T", out.Err)
				causes := joined.Unwrap()
				logicalMDBXAssert(t, len(causes) == 2 && causes[0] != nil && causes[1] != nil, "original cause cardinality")
				first, second := causes[0].(*mdbx.EngineError), causes[1].(*mdbx.EngineError)
				logicalMDBXAssert(t, first.Operation == "get" && first.Class == mdbx.EngineIO && second.Operation == "abort" && second.Class == mdbx.EngineIO && evidence.Faults == 2, "original cause order: %+v %+v %+v", first, second, evidence)
			} else {
				replayEngineClass(t, out.Err, mdbx.EngineIO, "direct original cause")
			}
			stepCached(t, w, 0, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)")
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "joined source/abort")
		})
	}
}

func TestReplayStepMDBXFixtureSentinelAbort(t *testing.T) {
	w := newStepWorld(t, 1, false)
	stepDrop(w, 3, w.hashes[1][:])
	before := w.image()
	out, evidence := stepArmed(t, w, 0, mdbx.SelectedDamageAbortEIO, 0, nil)
	stepTuple(t, out, replayEntryRecovery, "", "OLD", 1, 1, false)
	logicalMDBXAssert(t, evidence.Faults == 1 && evidence.Commits == 0 && out.Needed != nil && out.Needed.Kind == 1 && out.Needed.Hash == w.hashes[1], "original missing observation plus abort: %+v %+v", out, evidence)
	joined, ok := out.Err.(interface{ Unwrap() []error })
	logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "original refusal/abort cardinality: %T %v", out.Err, out.Err)
	parts := joined.Unwrap()
	failure, ok := parts[0].(*selectedSideFailure)
	logicalMDBXAssert(t, ok && failure.result == "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)" && failure.cause != nil && failure.cause.Error() == "replay path ancestry header unavailable", "original refusal wrapper/cause: %T %v", parts[0], parts[0])
	abort, ok := parts[1].(*mdbx.EngineError)
	logicalMDBXAssert(t, ok && abort.Operation == "abort" && abort.Class == mdbx.EngineIO && abort.Code == 5 && abort.Diagnostic == "error 5" && abort.Cause == nil && !abort.ReopenRequired && w.step.path.slot == nil, "original native abort order and partial hold: %+v", abort)
	stepCached(t, w, 0, out, replayEntryRecovery)
	w.store = w.reopen()
	replaySameImage(t, before, w.image(), "sentinel refusal joined abort")
}

// This read reaches the connector's original R1 carrier. It has no Unwrap method; its nested cause stays intact.
func TestReplayStepMDBXFixtureInputCarrier(t *testing.T) {
	for _, row := range []struct {
		name             string
		value            []byte
		fault            bool
		decision, result string
	}{
		{"native_io", nil, true, "", "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"},
		{"positive_decode", append(make([]byte, 19), 2), false, "target local", ""},
		{"native_width", make([]byte, 19), false, "", selectedSideIntegrity},
	} {
		t.Run(row.name, func(t *testing.T) {
			op := Outpoint{Txid: hashWithPrefix(0xac), Vout: 2}
			w := newStepWorld(t, 1, false, inputViewTx(1, op))
			w.prefix(t, 1)
			key := append(binary.BigEndian.AppendUint64(nil, 2), op.Txid[:]...)
			key = binary.BigEndian.AppendUint32(key, op.Vout)
			var before []mdbx.PrefixRow
			var restore []byte
			if row.name == "native_width" {
				restore = make([]byte, 20)
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, restore) == nil, "native width readable census control")
				before = w.image()
			}
			if !row.fault {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, row.value) == nil, "positive native row setup")
			}
			if before == nil {
				before = w.image()
			}
			var invocation *replayStepInvocation
			if row.fault {
				evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageGetEIO, 1, key, func() { invocation = replayStepRun(w.step, w.store, w.owner, w.bodies[1]) })
				logicalMDBXAssert(t, err == nil && evidence.Faults == 1 && evidence.OldGets[1] == 1 && evidence.Commits == 0, "R1 exact native site: %v %+v", err, evidence)
			} else {
				invocation = replayStepRun(w.step, w.store, w.owner, w.bodies[1])
			}
			stepTuple(t, invocation.out, row.result, row.decision, "OLD", 1, 1, row.decision != "")
			incoming := invocation.out.Err
			var recorded error
			if row.decision != "" {
				incoming = invocation.observation.incoming
			}
			if row.decision == "" {
				joined, ok := incoming.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "R1 application/native cause order: %T %v", incoming, incoming)
				parts := joined.Unwrap()
				incoming, recorded = parts[0], parts[1]
			}
			carrier, ok := incoming.(*blockInputViewReadError)
			logicalMDBXAssert(t, ok && carrier != nil && carrier.txIndex == 1 && carrier.inputIndex == 0 && carrier.outpoint == op && carrier.failure != nil && carrier.failure.cause != nil, "actual original R1 carrier: %T %+v", incoming, carrier)
			_, unwrap := any(carrier).(interface{ Unwrap() error })
			logicalMDBXAssert(t, !unwrap, "carrier acquired an Unwrap API")
			if row.decision != "" {
				logicalMDBXAssert(t, invocation.observation.failure == carrier.failure && stepSameError(invocation.observation.cause, carrier.failure.cause), "C31 outer/nested cause identity")
				replaySameImage(t, before, w.image(), "positive decode clean OLD")
			} else {
				kind, class := logicalStateFailureStoreIntegrity, mdbx.EngineIntegrity
				if row.fault {
					kind, class = logicalStateFailureUnavailable, mdbx.EngineIO
				}
				logicalMDBXAssert(t, carrier.failure.kind == kind && stepSameError(carrier.failure.cause, recorded), "C31 original nested/recorded native cause identity")
				replayEngineClass(t, recorded, class, row.name)
				cached := row.result
				stepCached(t, w, 1, invocation.out, cached)
				w.store = w.reopen()
				if restore != nil {
					equal, err := mdbx.FixtureRawRowEqual(w.store, 1, key, row.value)
					logicalMDBXAssert(t, err == nil && equal, "raw malformed width preimage changed: %v", err)
					logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, restore) == nil, "restore census control after exact raw assertion")
				}
				replaySameImage(t, before, w.image(), "R1 fault OLD")
			}
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureGrantAndCardinality(t *testing.T) {
	w := newStepWorld(t, 1, false)
	before := w.image()
	var out ReplayStepOutcomeV1
	var evidence mdbx.SelectedDamageEvidence
	err := w.owner.WithReservation(1, func() error {
		var fixtureErr error
		evidence, fixtureErr = mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.call(0) })
		return fixtureErr
	})
	logicalMDBXAssert(t, err == nil, "aggregate grant fixture: %v", err)
	stepTuple(t, out, selectedSideCapacity, "", "OLD", 1, 1, true)
	logicalMDBXAssert(t, evidence.OldGets[0] == 1 && evidence.OldGets[1] == 0 && evidence.OldGets[2] == 0 && evidence.OldGets[3] == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0 && w.view.protects == 0 && w.step.path.slot == nil, "RC3 authority-only denial: %+v", evidence)
	replaySameImage(t, before, w.image(), "aggregate grant denial")
	stepProgress(t, w, 0, w.authority(), w.call(0))
	w = newStepWorld(t, 1, false, inputViewTx(0, Outpoint{Txid: hashWithPrefix(0xbd)}))
	w.prefix(t, 1)
	before = w.image()
	out, evidence = stepArmed(t, w, 1, mdbx.SelectedDamageProbeOnly, 0, nil)
	stepTuple(t, out, "", "consensus invalid", "OLD", 1, 1, true)
	// No writer starts; the OLD abort probes the held grant once before and once after native cleanup.
	logicalMDBXAssert(t, evidence.OldGets[1] == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.OldAborts == 1 && evidence.Probes == 2 && evidence.ProbeDenied == 2 && evidence.ProbeRan == 0, "C27/C30/B37 first validation before UTXO reads, full lane: %+v", evidence)
	replaySameImage(t, before, w.image(), "first consensus observation")
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureNoArtifactRewrite(t *testing.T) {
	for _, rank := range []uint8{3, 4, 5} {
		t.Run(fmt.Sprint(rank), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			if rank == 4 {
				stepSeedArtifact(w, 4, 0, w.bodies[0])
			}
			if rank == 5 {
				stepSeedArtifact(w, 5, 0, stepManifest(0, 0, 1, 0))
			}
			before := w.image()
			var out ReplayStepOutcomeV1
			key := w.hashes[0][:]
			if rank == 5 {
				key = append(bytes.Clone(key), 0)
			}
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamagePutEIO, rank, key, func() { out = w.call(0) })
			logicalMDBXAssert(t, err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.BeginWrite == 1 && evidence.Commits == 1, "B2/B3/B4 actual unchanged-row PUT site must remain unreachable: %v %+v", err, evidence)
			stepTuple(t, out, "", "", "NEW", 2, 3, true)
			stepExactImage(t, w, 0, before, false)
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureMisnamedHeader(t *testing.T) {
	w := newStepWorld(t, 1, false)
	value := bytes.Clone(w.headers[0][:])
	value[68] ^= 1
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, w.hashes[0][:], value) == nil, "seed misnamed header")
	equal, err := mdbx.FixtureRawRowEqual(w.store, 3, w.hashes[0][:], value)
	logicalMDBXAssert(t, err == nil && equal, "misnamed header raw seed readback: %v", err)
	before := w.image()
	out, evidence := stepArmed(t, w, 0, mdbx.SelectedDamageProbeOnly, 0, nil)
	stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
	logicalMDBXAssert(t, out.Needed == nil && evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.OldGets[1] == 0 && evidence.OldGets[4] == 0 && evidence.OldGets[5] == 0, "C2 misnamed header precedes body/state/undo: %+v %+v", out, evidence)
	stepReleased(t, w)
	w.store = w.reopen()
	equal, err = mdbx.FixtureRawRowEqual(w.store, 3, w.hashes[0][:], value)
	logicalMDBXAssert(t, err == nil && equal, "misnamed header exact preimage changed: %v", err)
	replaySameImage(t, before, w.image(), "header_misnamed")
}

func TestReplayStepMDBXFixtureUndoFamily(t *testing.T) {
	for _, kind := range []string{"missing", "extra", "version", "width", "wrong_entry", "body_header"} {
		t.Run(kind, func(t *testing.T) {
			w, _, oldValue, entryKey := stepSpentWorld(t)
			manifestKey := append(bytes.Clone(w.hashes[1][:]), 0)
			stepSeedArtifact(w, 5, 1, stepManifest(1, 0, 3, 1))
			if kind != "missing" {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, entryKey, oldValue) == nil, "seed complete family")
			}
			var before []mdbx.PrefixRow
			if kind == "width" {
				before = w.image()
			}
			switch kind {
			case "extra":
				key := bytes.Clone(entryKey)
				key[76] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, key, oldValue) == nil, "seed extra member")
			case "version":
				value := stepManifest(1, 0, 3, 1)
				value[0] = 2
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, manifestKey, value) == nil, "seed malformed manifest")
			case "width":
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, manifestKey, make([]byte, 32)) == nil, "seed malformed width")
			case "wrong_entry":
				value := bytes.Clone(oldValue)
				value[0] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, entryKey, value) == nil, "seed differing complete row")
			case "body_header":
				value := bytes.Clone(w.bodies[1])
				value[108] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 4, w.hashes[1][:], value) == nil, "seed positively misbound body")
			}
			if before == nil {
				before = w.image()
			}
			out := w.call(1)
			stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			logicalMDBXAssert(t, out.Needed == nil && w.step.path.slot != nil, "K7 comparison lost completed hold or fabricated Need")
			stepReleased(t, w)
			w.store = w.reopen()
			if kind == "width" {
				equal, err := mdbx.FixtureRawRowEqual(w.store, 5, manifestKey, make([]byte, 32))
				logicalMDBXAssert(t, err == nil && equal, "malformed family width exact preimage changed")
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 5, manifestKey, stepManifest(1, 0, 3, 1)) == nil, "restore readable family census control")
			}
			replaySameImage(t, before, w.image(), "whole-family rejection "+kind)
		})
	}
}

func TestReplayStepMDBXFixtureOldActive(t *testing.T) {
	for _, kind := range []string{"absent_header", "parent", "work", "predecessor", "native_io"} {
		t.Run(kind, func(t *testing.T) {
			w := newStepWorld(t, 15120, true)
			y := stepActiveOther(t, w)
			w.prefix(t, 1)
			stepSeedArtifact(w, 4, 1, w.bodies[1])
			stepSeedArtifact(w, 5, 1, stepManifest(1, 0, 1, 0))
			switch kind {
			case "absent_header":
				stepDrop(w, 3, y[:])
			case "parent", "work":
				value, _ := stepRead(t, w.store, 2, stepKey(1, 1))
				if kind == "parent" {
					value[32] ^= 1
				} else {
					value[103] ^= 1
				}
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, stepKey(1, 1), value) == nil, "seed old health contradiction")
			case "predecessor":
				value, _ := stepRead(t, w.store, 2, stepKey(1, 0))
				value[0] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, stepKey(1, 0), value) == nil, "seed predecessor contradiction")
			}
			before := w.image()
			var out ReplayStepOutcomeV1
			if kind == "native_io" {
				var evidence mdbx.SelectedDamageEvidence
				out, evidence = stepArmed(t, w, 1, mdbx.SelectedDamageGetEIO, 3, y[:])
				logicalMDBXAssert(t, evidence.Faults == 1 && evidence.BeginWrite == 0 && evidence.Commits == 0, "canonical old health fault")
				stepTuple(t, out, selectedSideCanonical, "", "OLD", 1, 1, false)
				replayEngineClass(t, out.Err, mdbx.EngineIO, "C10 old-active")
			} else {
				out = w.call(1)
				stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			}
			logicalMDBXAssert(t, out.Needed == nil, "old-active damage became acquisition")
			stepReleased(t, w)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "C7-C10/C22 "+kind)
		})
	}
}

func TestReplayStepMDBXFixtureCardinality(t *testing.T) {
	for _, variant := range []string{"absent", "io", "nonce", "creation", "earlier_qualification"} {
		t.Run(variant, func(t *testing.T) {
			later, _, _, _, err := ParseTx(coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1))
			logicalMDBXAssert(t, err == nil, "extra exact coinbase")
			ordinary := inputViewTx(1, Outpoint{Txid: hashWithPrefix(0xb1)})
			if variant == "nonce" {
				ordinary.TxNonce = 0
			}
			w := newStepWorld(t, 1, false, ordinary, later)
			w.prefix(t, 1)
			if variant == "creation" {
				input := inputViewRewriteFirst(t, inputViewBlock(t, 1, 1, ordinary, later), func(tx *Tx) { tx.Outputs[0].CovenantType = COV_TYPE_VAULT })
				stepReplaceRaw(t, w, stepFixHeader(t, w, input.BlockBytes, w.lastTime+240))
			}
			if variant == "earlier_qualification" {
				stepReplaceRaw(t, w, stepFixHeader(t, w, bytes.Clone(w.bodies[1]), w.lastTime))
			}
			before := w.image()
			var invocation *replayStepInvocation
			scenario, rank := mdbx.SelectedDamageProbeOnly, uint8(0)
			var key []byte
			if variant == "io" {
				scenario, rank = mdbx.SelectedDamageGetEIO, 1
				op := Outpoint{Txid: hashWithPrefix(0xb1)}
				key = append(binary.BigEndian.AppendUint64(nil, 2), op.Txid[:]...)
				key = binary.BigEndian.AppendUint32(key, 0)
			}
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { invocation = replayStepRun(w.step, w.store, w.owner, w.bodies[1]) })
			unreached := variant == "io" && err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed"
			logicalMDBXAssert(t, (err == nil || unreached) && evidence.Faults == 0 && evidence.OldGets[1] == 0 && evidence.BeginWrite == 0 && evidence.Commits == 0, "C30 first cardinality/qualification before inputs: %v %+v", err, evidence)
			stepTuple(t, invocation.out, "", "consensus invalid", "OLD", 1, 1, true)
			code := ErrorCode("BLOCK_ERR_COINBASE_INVALID")
			if variant == "earlier_qualification" {
				code = "BLOCK_ERR_TIMESTAMP_OLD"
			}
			original, ok := invocation.observation.incoming.(*TxError)
			logicalMDBXAssert(t, ok && original.Code == code && invocation.observation.h == 1 && invocation.observation.x == w.hashes[1], "literal original cardinality code/h/x: %+v", invocation.observation)
			replaySameImage(t, before, w.image(), variant)
			stepReleased(t, w)
		})
	}
}

func stepFixHeader(t *testing.T, w *stepWorld, raw []byte, timestamp uint64) []byte {
	t.Helper()
	copy(raw[4:36], w.hashes[0][:])
	binary.LittleEndian.PutUint64(raw[68:76], timestamp)
	for nonce := uint64(0); ; nonce++ {
		binary.LittleEndian.PutUint64(raw[108:116], nonce)
		if PowCheck(raw[:116], filledHash(0xff)) == nil {
			return raw
		}
	}
}

func stepReplaceRaw(t *testing.T, w *stepWorld, raw []byte) {
	t.Helper()
	old := w.hashes[1]
	w.bodies[1], w.headers[1], w.hashes[1] = raw, [116]byte(raw[:116]), mustHash([116]byte(raw[:116]))
	stepDrop(w, 3, old[:])
	w.apply(mdbx.Mutation{DBI: logicalMDBXDBIs[3], Key: w.hashes[1][:], AfterKind: mdbx.AfterLiteral, Literal: w.headers[1][:]})
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Replay.Target.TipHash = w.hashes[1] })
	w.step.DiscardV1()
}

func TestReplayStepMDBXFixtureQualifierBindingPriority(t *testing.T) {
	for _, source := range []string{"supplied", "stored", "bound_control"} {
		t.Run(source, func(t *testing.T) {
			w := newStepWorld(t, 1, false, inputViewTx(1, Outpoint{Txid: hashWithPrefix(0xb2)}))
			w.prefix(t, 1)
			raw := stepFixHeader(t, w, bytes.Clone(w.bodies[1]), w.lastTime)
			stepReplaceRaw(t, w, raw)
			if source != "bound_control" {
				raw[len(raw)-1] ^= 1
			}
			if source == "stored" {
				stepSeedArtifact(w, 4, 1, raw)
			}
			before := w.image()
			var invocation *replayStepInvocation
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { invocation = replayStepRun(w.step, w.store, w.owner, raw) })
			logicalMDBXAssert(t, err == nil && evidence.OldGets[1] == 0 && evidence.Commits == 0 && evidence.BeginWrite == 0, "C34 binding-only recheck order: %v %+v", err, evidence)
			switch source {
			case "supplied":
				stepRefusal(t, invocation.out, "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)", "replay block bytes unavailable or unbound")
				logicalMDBXAssert(t, invocation.out.Needed != nil && *invocation.out.Needed == (ReplayStepNeedV1{Kind: 2, Height: 1, Hash: w.hashes[1]}) && invocation.observation.incoming == nil, "unbound supplied did not erase invalidity observation")
			case "stored":
				stepTuple(t, invocation.out, selectedSideIntegrity, "", "OLD", 1, 1, false)
				logicalMDBXAssert(t, invocation.out.Needed == nil && invocation.observation.incoming == nil, "unbound stored exposed local invalidity")
				w.store = w.reopen()
			case "bound_control":
				stepTuple(t, invocation.out, "", "consensus invalid", "OLD", 1, 1, true)
				e, ok := invocation.observation.incoming.(*TxError)
				logicalMDBXAssert(t, ok && e.Code == "BLOCK_ERR_TIMESTAMP_OLD" && invocation.observation.h == 1 && invocation.observation.x == w.hashes[1], "bound earlier qualifier literal code/h/x")
			}
			replaySameImage(t, before, w.image(), source)
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureFullContextWindow(t *testing.T) {
	for _, h := range []uint64{12, 10080} {
		first := uint64(1)
		if h == 10080 {
			first = 0
		}
		for _, changed := range []uint64{first, h - 1} {
			for _, scenario := range []uint8{4, 5, 6} {
				t.Run(fmt.Sprintf("h%d_k%d_s%d", h, changed, scenario), func(t *testing.T) {
					w := newStepWorld(t, int(h), true)
					w.prefix(t, h)
					before := w.image()
					key := stepKey(2, changed)
					value, exists := stepRead(t, w.store, 2, key)
					logicalMDBXAssert(t, exists && len(value) == 104, "actual full context row")
					value[63] ^= 1
					var out ReplayStepOutcomeV1
					evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, value, true, func() { out = w.call(h) })
					logicalMDBXAssert(t, err == nil && evidence.Drift == 1 && out.Needed == nil, "B38 complete target descriptor: %v %+v", err, evidence)
					if scenario == 4 {
						stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
						for i := range before {
							if bytes.Equal(before[i].Key, append([]byte{2}, key...)) {
								before[i].Value = value
							}
						}
					} else if scenario == 5 {
						stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
					} else {
						stepTuple(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "", "UNKNOWN", 3, 3, false)
					}
					stepReleased(t, w)
					w.store = w.reopen()
					if scenario != 6 {
						replaySameImage(t, before, w.image(), "full target window equality")
					}
					if scenario == 6 {
						replayCrossedErr(t, out.Err, mdbx.CommitTruthUnknown, false)
						logicalMDBXAssert(t, evidence.Commits == 1, "full target window STEP commit count: %+v", evidence)
						stepExactImageExtra(t, w, h, before, false, nil, []mdbx.PrefixRow{{Key: append([]byte{2}, key...), Value: value}})
					}
					if scenario != 5 {
						equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, value)
						logicalMDBXAssert(t, err == nil && equal, "persisted full context selected drift: %v", err)
					}
				})
			}
		}
	}
	w := newStepWorld(t, 12, false)
	w.prefix(t, 12)
	stepDrop(w, 3, w.hashes[1][:])
	key := stepKey(2, 11)
	value, _ := stepRead(t, w.store, 2, key)
	value[32] ^= 1
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, key, value) == nil, "later positive context contradiction")
	before := w.image()
	out := w.call(12)
	stepRefusal(t, out, "TERMINAL_STORE_INTEGRITY(canonical)", "target context named header absent or misnamed")
	logicalMDBXAssert(t, out.Needed == nil, "B30 ascending context first observation invented Need")
	w.store = w.reopen()
	replaySameImage(t, before, w.image(), "ascending complete target context")
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureOneBelowClassification(t *testing.T) {
	for _, presence := range []string{"both", "neither", "undo_only", "body_only"} {
		t.Run(presence, func(t *testing.T) {
			w := newStepWorld(t, 15120, true)
			y := stepActiveOther(t, w)
			w.prefix(t, 1)
			if presence == "both" || presence == "body_only" {
				stepSeedArtifact(w, 4, 1, w.bodies[1])
			}
			if presence == "both" || presence == "undo_only" {
				stepSeedArtifact(w, 5, 1, stepManifest(1, 0, 1, 0))
			}
			before := w.image()
			out, evidence := stepArmed(t, w, 1, mdbx.SelectedDamageProbeOnly, 0, nil)
			stepTuple(t, out, "", "", "NEW", 2, 3, true)
			// At h1, tip15120 promises body (B=1) but not undo (U=13681). Only present undo classifies Y.
			want := uint64(1)
			if presence == "neither" || presence == "body_only" {
				want = 0
			}
			// Own/context source headers plus admission/preflight/final rereads total eight OLD Gets.
			// One classification adds Y's header at source and the same three consulted-proof phases.
			logicalMDBXAssert(t, evidence.OldGets[3] == 8+4*want && evidence.Commits == 1 && evidence.ProbeRan == 0 && evidence.Probes == evidence.ProbeDenied, "B13/B14/B21 one or zero OLD health classification: %+v y=%x", evidence, y)
			stepExactImage(t, w, 1, before, presence != "neither")
			stepReleased(t, w)
		})
	}
}

func TestReplayStepMDBXFixtureDeleteAtomic(t *testing.T) {
	w := newStepWorld(t, 15120, false)
	stepSeedArtifact(w, 4, 0, w.bodies[0])
	stepSeedArtifact(w, 5, 0, stepManifest(0, 0, 1, 0))
	before := w.image()
	out, evidence := stepArmed(t, w, 0, mdbx.SelectedDamageDeleteEIO, 4, w.hashes[0][:])
	stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
	logicalMDBXAssert(t, evidence.Deletes == 1 && evidence.Faults == 1 && evidence.Commits == 0 && out.Needed == nil, "K13 delete site: %+v", evidence)
	stepCached(t, w, 0, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)")
	w.store = w.reopen()
	replaySameImage(t, before, w.image(), "atomic artifact deletion fault")
	stepProgress(t, w, 0, w.authority(), w.call(0))
	stepExactImage(t, w, 0, before, true)
}

func TestReplayStepMDBXFixtureCachedSentinel(t *testing.T) {
	w := newStepWorld(t, 1, false)
	stepProgress(t, w, 0, w.authority(), w.call(0))
	stepProgress(t, w, 1, w.authority(), w.call(1))
	before := w.image()
	out, evidence := stepArmed(t, w, 1, mdbx.SelectedDamageAbortEIO, 0, nil)
	stepTuple(t, out, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "", "OLD", 1, 1, false)
	joined, ok := out.Err.(interface{ Unwrap() []error })
	logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2 && joined.Unwrap()[0].Error() == "replay step decision" && joined.Unwrap()[1].(*mdbx.EngineError).Operation == "abort" && evidence.OldGets[0] == 1 && evidence.BeginWrite == 0 && evidence.Commits == 0, "sentinel normalization must preserve native cleanup: %+v %v", evidence, out.Err)
	stepCached(t, w, 1, out, selectedSideInvariant)
	w.store = w.reopen()
	replaySameImage(t, before, w.image(), "sentinel/cached native cleanup")
	stepReleased(t, w)
}

func TestReplayStepMDBXFixtureStateRemainder(t *testing.T) {
	w, before, key, _ := stepRemainderWorld(t, 1)
	value, present := stepRead(t, w.store, 1, key)
	logicalMDBXAssert(t, present, "B41 actual readonly row")
	var out ReplayStepOutcomeV1
	drift, err := mdbx.FixtureWriteSnapshotDrift(w.store, 1, key, func() { out = w.call(1) })
	logicalMDBXAssert(t, err == nil && drift == 1, "STATE equality proof fixture: %d %v", drift, err)
	stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
	logicalMDBXAssert(t, out.Needed == nil, "STATE drift invented Need")
	stepReleased(t, w)
	w.store = w.reopen()
	equal, err := mdbx.FixtureRawRowEqual(w.store, 1, key, []byte{0x7f})
	logicalMDBXAssert(t, err == nil && equal, "only fixture changed readonly STATE")
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 1, key, value) == nil, "restore physical fixture row")
	replaySameImage(t, before, w.image(), "complete OLD after restoring the single fixture drift")
	stepProgress(t, w, 1, w.authority(), w.call(1))
}

func TestReplayStepMDBXFixtureGrantPriority(t *testing.T) {
	for _, mode := range []string{"malformed", "none", "at_tip", "differing_header"} {
		t.Run(mode, func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			if mode == "none" {
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.Phase, a.Lifecycle, a.Replay = 1, 1, nil })
			}
			if mode == "at_tip" {
				stepProgress(t, w, 0, w.authority(), w.call(0))
				stepProgress(t, w, 1, w.authority(), w.call(1))
				w.step.DiscardV1()
			}
			before := w.image()
			authority, _ := stepRead(t, w.store, 0, []byte{2})
			if mode == "malformed" {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, []byte{0x7f}) == nil, "malformed authority")
			}
			if mode == "differing_header" {
				value := bytes.Clone(w.headers[0][:])
				value[68] ^= 1
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 3, w.hashes[0][:], value) == nil, "later differing header")
				before = w.image()
			}
			protects, calls := w.view.protects, w.view.headerCalls
			if mode != "at_tip" {
				logicalMDBXAssert(t, protects == 0 && calls == 0, "authority-only setup reached provider")
			}
			var out ReplayStepOutcomeV1
			var evidence mdbx.SelectedDamageEvidence
			err := w.owner.WithReservation(1, func() error {
				var err error
				evidence, err = mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.call(0) })
				return err
			})
			logicalMDBXAssert(t, err == nil, "authority-only fixture")
			result, decision, clean := selectedSideCapacity, "", true
			if mode == "malformed" {
				result, clean = selectedSideIntegrity, false
			}
			if mode == "none" || mode == "at_tip" {
				result, decision = "", "not applicable"
			}
			stepTuple(t, out, result, decision, "OLD", 1, 1, clean)
			logicalMDBXAssert(t, out.Needed == nil && evidence.OldGets == ([8]uint64{1}) && evidence.BeginWrite == 0 && evidence.Commits == 0 && w.view.protects == protects && w.view.headerCalls == calls && w.step.path.slot == nil, "C1/C17/C19 first authority result: %+v", evidence)
			stepReleased(t, w)
			if mode == "malformed" {
				w.store = w.reopen()
				equal, err := mdbx.FixtureRawRowEqual(w.store, 0, []byte{2}, []byte{0x7f})
				logicalMDBXAssert(t, equal && err == nil, "original invalid authority retained")
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 0, []byte{2}, authority) == nil, "restore authority census control")
			}
			replaySameImage(t, before, w.image(), "priority committed no STEP effect")
		})
	}
}

func TestReplayStepMDBXFixtureDescriptorPresence(t *testing.T) {
	for _, generation := range []uint64{1, 2} {
		for _, scenario := range []uint8{4, 5, 6} {
			t.Run(fmt.Sprintf("g%d_s%d", generation, scenario), func(t *testing.T) {
				w := newStepWorld(t, 1, true)
				w.prefix(t, 1)
				before := w.image()
				key := stepKey(generation, 0)
				value, exists := stepRead(t, w.store, 2, key)
				logicalMDBXAssert(t, exists, "actual descriptor presence source")
				var out ReplayStepOutcomeV1
				evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, nil, false, func() { out = w.call(1) })
				logicalMDBXAssert(t, err == nil && evidence.Drift == 1 && out.Needed == nil, "presence drift: %v %+v", err, evidence)
				if scenario == 4 {
					stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
				}
				if scenario == 5 {
					stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
				}
				if scenario == 6 {
					stepTuple(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "", "UNKNOWN", 3, 3, false)
				}
				stepReleased(t, w)
				w.store = w.reopen()
				if scenario != 5 {
					equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, nil)
					logicalMDBXAssert(t, err == nil && equal, "exact physical descriptor absence")
					logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, 2, key, value) == nil, "restore descriptor census control")
				}
				if scenario == 6 {
					stepExactImage(t, w, 1, before, false)
				} else {
					replaySameImage(t, before, w.image(), "complete OLD with fixture restored")
				}
			})
		}
	}
}

func TestReplayStepMDBXFixtureEndpointKey(t *testing.T) {
	for _, scenario := range []uint8{4, 5, 6} {
		t.Run(fmt.Sprint(scenario), func(t *testing.T) {
			w := newStepWorld(t, 1, true)
			w.prefix(t, 1)
			before := w.image()
			key := stepKey(1, 1)
			value := append(append(bytes.Clone(w.hashes[1][:]), w.hashes[0][:]...), make([]byte, 40)...)
			value[103] = 2
			var out ReplayStepOutcomeV1
			evidence, err := mdbx.FixtureCanonicalTipStep(w.store, scenario, key, value, true, func() { out = w.call(1) })
			logicalMDBXAssert(t, err == nil && evidence.Drift == 1 && out.Needed == nil, "actual maximal endpoint key change: %v %+v", err, evidence)
			if scenario == 4 {
				stepTuple(t, out, replayEntryStale, "", "OLD", 1, 1, false)
			}
			if scenario == 5 {
				stepTuple(t, out, selectedSidePrecommit, "", "OLD", 1, 2, false)
			}
			if scenario == 6 {
				stepTuple(t, out, "TERMINAL_PERSISTENCE(neither_or_unreadable)", "", "UNKNOWN", 3, 3, false)
			}
			stepReleased(t, w)
			w.store = w.reopen()
			if scenario != 5 {
				equal, err := mdbx.FixtureRawRowEqual(w.store, 2, key, value)
				logicalMDBXAssert(t, err == nil && equal, "fixture alone added the endpoint")
				stepDrop(w, 2, key)
			}
			if scenario == 6 {
				stepExactImage(t, w, 1, before, false)
			} else {
				replaySameImage(t, before, w.image(), "endpoint maximality proof preserved OLD")
			}
		})
	}
}

func TestReplayStepMDBXFixtureStagingMismatch(t *testing.T) {
	for _, rank := range []uint8{2, 7} {
		t.Run(fmt.Sprint(rank), func(t *testing.T) {
			w := newStepWorld(t, 1, false)
			key, value := stepKey(2, 0), append(bytes.Clone(w.hashes[0][:]), make([]byte, 72)...)
			value[0] ^= 1
			value[103] = 1
			cause := "replay target staging entry differs"
			if rank == 7 {
				key = append(binary.BigEndian.AppendUint64(nil, 2), w.hashes[0][:]...)
				value, cause = binary.BigEndian.AppendUint64(nil, 1), "replay target staging owner differs"
			}
			logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, rank, key, value) == nil, "actual differing staging row")
			before := w.image()
			out := w.call(0)
			stepTuple(t, out, selectedSideIntegrity, "", "OLD", 1, 1, false)
			failure, ok := out.Err.(*selectedSideFailure)
			logicalMDBXAssert(t, ok && failure.cause.Error() == cause && out.Needed == nil && w.step.path.slot != nil, "staging comparison guard: %+v", out)
			stepReleased(t, w)
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "no partial cursor pair")
		})
	}
}

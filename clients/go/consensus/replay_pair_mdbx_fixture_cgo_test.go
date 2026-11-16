//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// rpfCase consumes the independently signed history fixture; the actual new
// production composer, rather than the earlier test-owned composer, is tested.
func rpfCase(t *testing.T, f *icbReplayFamilyV1, body uint8, paired bool) (*rpCase, *fgWorld) {
	t.Helper()
	w := icbReplayWorldV1(t, f)
	profile := mdbx.StorageProfileArchiveV1
	if body == 3 { profile = mdbx.StorageProfilePrunedV1 }
	a := icbReplayAuthorityV1(t, w, f, profile)
	if !paired {
		a.Authority.Replay.Target.TipHeight = 15119
		w.seedAuthority(t, a)
	}
	icbReplayBodyPreconditionV1(t, w, f, body)
	c := &rpCase{w: w.btWorld, in: f.block.in, request: replayPairRequestV1{Authority: a, Database: w.database,
		Height: f.block.in.Height, Endpoint: f.block.in.Endpoint, LagParent: f.block.in.Parent, Raw: f.block.in.Raw},
		rows: replayPairRowsV1{BodyKind: body, Undo: mdbx.UndoTransientV1}, store: rpStore{store: w.s}}
	return c, w
}

// rpfKeys owns only the existing exact-capacity lexical key frame. The real
// validated spent source and protected LAG OLD qualify each independent key.
func rpfKeys(t *testing.T, c *rpCase, a *mdbx.OperationAccount, expected []mdbx.TreeOutpointV1) replayPairWithLagInputsV1 {
	t.Helper()
	return func(r *mdbx.Reader, result *initial148CompleteBlockResultV1, use func([]mdbx.TreeOutpointV1) error) error {
		c.lag++
		logicalMDBXAssert(t, r == c.store.reader && result == c.result, "F3 same Reader/live result")
		return a.WithReservation(36*uint64(len(expected)), func() error {
			keys := make([]mdbx.TreeOutpointV1, 0, len(expected))
			spent := result.transition.spentInputs
			for item, have := spent.next(); have; item, have = spent.next() {
				op := item.outpoint
				_, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[1], btUTXOKey(2, op))
				if err != nil { return err }
				logicalMDBXAssert(t, present, "F3 protected LAG key must exist: %+v", op)
				keys = append(keys, mdbx.TreeOutpointV1{Txid: op.Txid, Vout: op.Vout})
			}
			slices.SortFunc(keys, func(a, b mdbx.TreeOutpointV1) int {
				if n := bytes.Compare(a.Txid[:], b.Txid[:]); n != 0 { return n }
				return int(a.Vout) - int(b.Vout)
			})
			logicalMDBXAssert(t, len(keys) == cap(keys) && slices.Equal(keys, expected), "exact-capacity qualified LAG key census")
			if len(keys) != 0 { logicalMDBXAssert(t, &keys[0] != &expected[0], "F3 key backing cannot alias oracle") }
			return use(keys)
		})
	}
}

// rpfRun holds the complete-run W/M frame through the real native operation.
// Filler is a preexisting test charge, not composer funding or a smaller lane.
func rpfRun(t *testing.T, c *rpCase, keys []mdbx.TreeOutpointV1, alter func(replayPairPrepareCurrentV1) replayPairPrepareCurrentV1, lag func(replayPairWithLagInputsV1) replayPairWithLagInputsV1, filler uint64) replayPairOutcomeV1 {
	t.Helper()
	var got replayPairOutcomeV1
	err := c.w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(8388608, func() error {
		out, runErr := withInitial148CompleteBlockV1(a, c.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			invoke := func() error {
				prepare := rpStoredRows(t, c, false)(c.prepare(t, validate))
				if alter != nil { prepare = alter(prepare) }
				inputs := rpfKeys(t, c, a, keys)
				if lag != nil { inputs = lag(inputs) }
				got = applyReplayPairV1(&c.store, a, c.request, prepare, inputs)
				logicalMDBXAssert(t, c.store.account == a, "same account through CURRENT/F3/native")
				return got.Err
			}
			if filler != 0 { return a.WithReservation(filler, invoke) }
			return invoke()
		})
		logicalMDBXAssert(t, any(runErr) == any(got.Err), "complete/native identity: %v/%v", runErr, got.Err)
		c.validation = out
		return nil
		})
	})
	logicalMDBXAssert(t, err == nil && c.store.calls == 1, "single native call/account: %v/%d", err, c.store.calls)
	btReservationsReleased(t, c.w.owner)
	return got
}

// TestReplayPairNativeBodies protects both role images, FULL_HISTORY, cursor,
// indexes and transient undo through reopen. Earlier test-owned planning does
// not cover production composition. No production seam is added.
func TestReplayPairNativeBodies(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	for _, row := range []struct { body uint8; paired bool }{{1, true}, {2, true}, {3, true}, {2, false}} {
		t.Run(fmt.Sprintf("body%d/pair%v", row.body, row.paired), func(t *testing.T) {
			c, w := rpfCase(t, f, row.body, row.paired)
			before, raw := icbReplayLagImageV1(t, w), bytes.Clone(c.in.Raw)
			count := 1
			if row.paired { count = 2 }
			c.store.inspect = func(op mdbx.TreeOperationV1) {
				rpAssertPlan(t, c, op, count)
				logicalMDBXAssert(t, mdbx.FixtureReservationLive(w.owner) == icbMV1(uint64(len(c.in.Raw)))+8388608, "F3 key/grant retires before native; complete M/source hold remains")
			}
			got := rpfRun(t, c, f.inputs, nil, nil, 0)
			rpTuple(t, got, 2, 3, -1, nil, "")
			logicalMDBXAssert(t, c.result.transition == nil && c.result.effect.Primitive.Source == nil, "validated M/result retires after last native consumer")
			logicalMDBXAssert(t, bytes.Equal(c.in.Raw, raw) && c.current == 1 && c.lag == count-1, "immutable Raw/single stage invocation")
			w.reopen(t)
			icbReplayStateV1(t, w, 1, f.block, f.inputs)
			if row.paired { icbReplayStateV1(t, w, 2, f.block, f.inputs) } else { icbReplayWantLagImageV1(t, w, before) }
			icbReplayCursorV1(t, w, f.block.in.Endpoint)
			for _, g := range []uint64{1, 2} {
				if g == 2 && !row.paired { continue }
				r := btRequest(c.in.Raw, c.in.Height)
				r.Generation, r.Endpoint = g, c.in.Endpoint
				btIndexes(t, w.btWorld, r, true)
				err := w.s.View(func(reader *mdbx.Reader) error {
					binding, present, err := reader.ReadTreeRootBindingV1(g)
					logicalMDBXAssert(t, err == nil && present && binding.Assurance.Kind == 1 && binding.Assurance.Import == nil, "own FULL_HISTORY role%d", g)
					return err
				})
				logicalMDBXAssert(t, err == nil, "role assurance read: %v", err)
			}
			w.read(t, 5, append(bytes.Clone(c.in.Endpoint.BlockHash[:]), 0), nil)
			icbReplayFollowingV1(t, w)
		})
	}
}

// TestReplayPairHeightFive proves A1 from an independently constructed 0..5
// history, rather than treating a high-height fixture as an equivalent case.
func TestReplayPairHeightFive(t *testing.T) {
	full := icbReplayVaultBlockV1(t, 200, 1)
	f := *full
	f.prefix, f.block, f.old, f.inputs = full.prefix[:5], full.prefix[5], full.prefix[4].rows, nil
	for _, profile := range []mdbx.StorageProfileV1{1, 2} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			body := uint8(1)
			if profile == 1 { body = 3 }
			c, w := rpfCase(t, &f, body, true)
			c.request.Authority.Authority.Replay.TargetProfile = profile
			w.seedAuthority(t, c.request.Authority)
			c.store.inspect = func(op mdbx.TreeOperationV1) { rpAssertPlan(t, c, op, 2) }
			lag := func(base replayPairWithLagInputsV1) replayPairWithLagInputsV1 {
				return func(r *mdbx.Reader, result *initial148CompleteBlockResultV1, use func([]mdbx.TreeOutpointV1) error) error {
					return base(r, result, func(keys []mdbx.TreeOutpointV1) error {
						logicalMDBXAssert(t, len(keys) == 0 && result.effect.Primitive.Coverage.BlockMeta.EventCount == 0, "E0 nil/empty key domain")
						if profile == 1 { return use(nil) }
						return use(keys)
					})
				}
			}
			got := rpfRun(t, c, nil, nil, lag, 0)
			rpTuple(t, got, 2, 3, -1, nil, "")
			w.reopen(t)
			for _, g := range []uint64{1, 2} { icbReplayStateV1(t, w, g, f.block, nil) }
			icbReplayCursorV1(t, w, f.block.in.Endpoint)
			icbReplayFollowingV1(t, w)
		})
	}
}

// TestReplayPairNativeBoundaries reaches production/native at both sides of
// the H15840 boundary; earlier helper-only arithmetic tests cannot prove effects.
func TestReplayPairNativeBoundaries(t *testing.T) {
	for _, h := range []uint64{720, 721} {
		f := icbReplayVaultBlockV1(t, h, 1)
		t.Run(fmt.Sprint(h), func(t *testing.T) {
			c, w := rpfCase(t, f, 1, true)
			before := icbReplayLagImageV1(t, w)
			count := 1
			if h == 720 { count = 2 }
			c.store.inspect = func(op mdbx.TreeOperationV1) { rpAssertPlan(t, c, op, count) }
			got := rpfRun(t, c, f.inputs, nil, nil, 0)
			logicalMDBXAssert(t, got.Truth == 2 && got.Err == nil && c.lag == count-1, "real h%d pair boundary: %+v", h, got)
			w.reopen(t)
			icbReplayStateV1(t, w, 1, f.block, f.inputs)
			if count == 2 { icbReplayStateV1(t, w, 2, f.block, f.inputs) } else { icbReplayWantLagImageV1(t, w, before) }
			icbReplayCursorV1(t, w, c.in.Endpoint)
		})
	}
}

// TestReplayPairCrossing observes complete OLD-first/NEW/UNKNOWN products on
// the real composer, including both roles and the one cursor on strict reopen.
func TestReplayPairCrossing(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	for _, row := range []struct { name string; scenario mdbx.SelectedDamageScenario; truth mdbx.CommitTruth; mixed bool }{
		{"OLD", mdbx.SelectedDamageCommitOld, 1, false},
		{"NEW", mdbx.SelectedDamageCommitNew, 2, false},
		{"UNKNOWN-unreadable", mdbx.SelectedDamageCommitUnreadable, 3, false},
		{"UNKNOWN-mixed", mdbx.SelectedDamageProbeOnly, 3, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			c, w := rpfCase(t, f, 1, true)
			var got replayPairOutcomeV1
			var drift uint32
			var driftErr error
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, row.scenario, 0, btMeta(0x11, 2), func() {
				run := func() { got = rpfRun(t, c, f.inputs, nil, nil, 0) }
				if row.mixed { drift, driftErr = mdbx.FixtureCleanupReadbackDrift(w.s, 4, c.in.Endpoint.BlockHash[:], run) } else { run() }
			})
			logicalMDBXAssert(t, err == nil && driftErr == nil && evidence.BeginRead == 1 && (drift == 1) == row.mixed, "strict crossing readback: %+v/%d/%v/%v", evidence, drift, err, driftErr)
			icbReplayCrossedV1(t, w, btResult{truth: got.Truth, stage: got.Stage, index: got.Index, err: got.Err}, row.truth, row.scenario == mdbx.SelectedDamageCommitUnreadable)
			w.reopen(t)
			if row.mixed { w.seed(t, 4, c.in.Endpoint.BlockHash[:], c.in.Raw) }
			block, spent := f.block, f.inputs
			if row.truth == 1 { block, spent = f.prefix[len(f.prefix)-1], nil }
			for _, g := range []uint64{1, 2} { icbReplayStateV1(t, w, g, block, spent) }
			icbReplayCursorV1(t, w, block.in.Endpoint)
			icbReplayFollowingV1(t, w)
		})
	}
}

// TestReplayPairLagFailure covers unlatched target-local absence, positive
// native integrity and plain Get without observation. It asserts the final
// Store disposition and unchanged CURRENT/cursor after the actual refusal.
func TestReplayPairLagFailure(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	for _, name := range []string{"counter-absent", "counter-malformed", "root-absent", "root-malformed", "node-malformed", "plainGet"} {
		t.Run(name, func(t *testing.T) {
			c, w := rpfCase(t, f, 1, true)
			oldCurrent, oldAuthority := rtImageRow(t, w.btWorld, btMeta(0x11, 1)), rtImageRow(t, w.btWorld, []byte{2})
			oldLag := icbReplayLagImageV1(t, w)
			rank, key := uint8(0), btMeta(0x10, 2)
			value := []byte{0xff}
			switch name {
			case "counter-absent": value = nil
			case "root-absent": key, value = btMeta(0x11, 2), nil
			case "root-malformed": key = btMeta(0x11, 2)
			case "node-malformed":
				err := w.s.View(func(r *mdbx.Reader) error {
					root, _, err := r.ReadTreeRootBindingV1(2)
					if err != nil { return err }
					logicalMDBXAssert(t, root.Top.Node != nil, "existing LAG root node")
					key, err = mdbx.TreeNodeKey(2, *root.Top.Node)
					return err
				})
				logicalMDBXAssert(t, err == nil, "LAG node key: %v", err)
				rank = 8
			case "plainGet": rank, key = 1, btUTXOKey(2, Outpoint{Txid: f.inputs[0].Txid, Vout: f.inputs[0].Vout})
			}
			if name != "plainGet" {
				w.seed(t, rank, key, value)
				found := false
				for i := range oldLag {
					if oldLag[i].rank == rank && bytes.Equal(oldLag[i].key, key) {
						oldLag[i].value, found = bytes.Clone(value), true
					}
				}
				if !found { oldLag = append(oldLag, btfRow{rank, bytes.Clone(key), bytes.Clone(value)}) }
			}
			var got replayPairOutcomeV1
			var evidence mdbx.SelectedDamageEvidence
			var fixtureErr error
			counts, err := mdbx.FixturePairReadObservation(w.s, nil, func() {
				run := func() { got = rpfRun(t, c, f.inputs, nil, nil, 0) }
				if name == "plainGet" {
					evidence, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, rank, key, run)
				} else {
					// Arming the first CURRENT put proves no put or delete is
					// attempted even for a late native LAG refusal (H2).
					evidence, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamagePutEIO, 0, btMeta(0x10, 1), run)
				}
			})
			logicalMDBXAssert(t, err == nil && counts.Writes == 0 && evidence.Deletes == 0 && evidence.Commits == 0 && got.Truth == 1 && got.Stage == 1, "LAG raw tuple/zero effects: %+v/%+v/%+v/%v", got, counts, evidence, err)
			logicalMDBXAssert(t, c.validation.attempted && c.validation.validationErr == nil && c.current == 1, "LAG refusal preserves successful CURRENT verdict")
			wantIndex := -1
			if name == "counter-absent" || name == "counter-malformed" { wantIndex = 1 }
			logicalMDBXAssert(t, got.Index == wantIndex, "native LAG index: got%d want%d", got.Index, wantIndex)
			var engine *mdbx.EngineError
			logicalMDBXAssert(t, errors.As(got.Err, &engine) && engine.Cause == nil && !engine.ReopenRequired, "unchanged native engine cause: %T/%v", got.Err, got.Err)
			if name == "plainGet" {
				logicalMDBXAssert(t, fixtureErr == nil && evidence.Faults == 1 && engine.TreeObservation == nil && engine.Class == "IO" && engine.Code == 5 && got.Err == engine && got.Role == "LAG", "plainGet roleLAG without observation: %+v", engine)
			} else {
				logicalMDBXAssert(t, fixtureErr != nil && fixtureErr.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && engine.TreeObservation != nil && engine.TreeObservation.Generation == 2 && got.Role == "LAG", "no put attempt/LAG observation: %+v/%v", engine, fixtureErr)
				if wantIndex == -1 { logicalMDBXAssert(t, engine.TreeObservation.Primitive == 0, "F3 observation0 is not native callback index or role") }
			}
			btfCached(t, w.btWorld, btResult{truth: got.Truth, stage: got.Stage, index: got.Index, err: got.Err})
			w.reopen(t)
			w.read(t, 0, btMeta(0x11, 1), oldCurrent)
			w.read(t, 0, []byte{2}, oldAuthority)
			icbReplayStateV1(t, w, 1, f.prefix[len(f.prefix)-1], nil)
			icbReplayCursorV1(t, w, c.in.Parent)
			for _, row := range oldLag {
				equal, err := mdbx.FixtureRawRowEqual(w.s, row.rank, row.key, row.value)
				logicalMDBXAssert(t, err == nil && equal, "LAG refusal preserves original raw row rank%d key%x: %v", row.rank, row.key, err)
			}
		})
	}
}

// TestReplayPairDrift reaches ORIGINAL OLD/write-snapshot disagreement on LAG.
// Its expected stale result and zero write attempts are independent of planner.
func TestReplayPairDrift(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	c, w := rpfCase(t, f, 1, true)
	old := icbReplayLagImageV1(t, w)
	var got replayPairOutcomeV1
	var drift uint32
	var driftErr error
	counts, err := mdbx.FixturePairReadObservation(w.s, nil, func() {
		drift, driftErr = mdbx.FixtureWriteSnapshotDrift(w.s, 0, btMeta(0x10, 2), func() { got = rpfRun(t, c, f.inputs, nil, nil, 0) })
	})
	logicalMDBXAssert(t, err == nil && driftErr == nil && drift == 1 && counts.Writes == 0 && got.Truth == 1 && got.Stage == 1, "stale LAG OLD zero effect: %+v/%+v/%d/%v/%v", got, counts, drift, err, driftErr)
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(got.Err, &engine) && engine.Class == "StateMismatch", "STALE_LOCAL_PLAN native cause: %+v", got.Err)
	w.reopen(t)
	icbReplayWantLagImageV1(t, w, old)
}

// TestReplayPairSourceOrder combines earlier producer refusal with a later
// failing key/grant stage. Moving that stage earlier changes its invocation
// count and error priority, even without any TreeObservation.
func TestReplayPairSourceOrder(t *testing.T) {
	for _, name := range []string{"CURRENT-F2", "LAG-source", "F3-source"} {
		t.Run(name, func(t *testing.T) {
			body := uint8(1)
			if name == "F3-source" { body = 2 }
			c := rpNew(t, 15840, body, mdbx.UndoTransientV1)
			if name == "LAG-source" { c.request.Authority.TargetLagGenerationID = 0 }
			if name == "F3-source" { c.request.Raw = nil }
			alter := rpStoredRows(t, c, false)
			if name == "CURRENT-F2" {
				alter = func(prepare replayPairPrepareCurrentV1) replayPairPrepareCurrentV1 {
					return func(r *mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error) {
						result, rows, err := prepare(r)
						rows.BodyKind = 0
						return result, rows, err
					}
				}
			}
			later := errors.New("later LAG grant must not run")
			got := c.run(t, alter, func(*mdbx.Reader, *initial148CompleteBlockResultV1, func([]mdbx.TreeOutpointV1) error) error { c.lag++; return later })
			var local *logicalStateFailure
			role := "LAG"
			if name == "CURRENT-F2" { role = "CURRENT" }
			logicalMDBXAssert(t, c.lag == 0 && errors.As(got.Err, &local) && got.Err != later && got.Role == role && got.Index == -1 && got.Truth == 1 && got.Stage == 1, "earlier source must suppress later key/grant/Get stage: %+v calls%d", got, c.lag)
			rpFollowing(t, c.w)
		})
	}
}

// TestReplayPairRepeatUse counts the actual native F3 reads. Removing the
// one-use guard both loses sticky refusal and repeats the root derivation.
func TestReplayPairRepeatUse(t *testing.T) {
	var baseline uint64
	for _, repeated := range []bool{false, true} {
		c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
		var got replayPairOutcomeV1
		var useErr error
		counts, err := mdbx.FixturePairReadObservation(c.w.s, nil, func() {
			got = c.run(t, nil, func(_ *mdbx.Reader, _ *initial148CompleteBlockResultV1, use func([]mdbx.TreeOutpointV1) error) error {
				first := use(nil)
				logicalMDBXAssert(t, first == nil, "first LAG derive succeeds: %v", first)
				if repeated { useErr = use(nil); return nil }
				// End baseline at the same callback position, before admission.
				return errors.New("baseline callback stop")
			})
		})
		logicalMDBXAssert(t, err == nil, "repeat-use observation: %v", err)
		if !repeated {
			logicalMDBXAssert(t, counts.Writes == 0, "baseline callback refusal has zero writes")
			baseline = counts.Gets
			continue
		}
		var local *logicalStateFailure
		logicalMDBXAssert(t, errors.As(useErr, &local) && got.Err == useErr && got.Role == "LAG" && got.Index == -1 && counts.Gets == baseline, "second use must refuse sticky before second Derive: got%+v reads%d baseline%d", got, counts.Gets, baseline)
		logicalMDBXAssert(t, counts.Writes == 0, "sticky repeated-use refusal has zero writes")
		rpFollowing(t, c.w)
	}
}

// TestReplayPairExactFit measures an attained real-operation peak on the legal
// lane, then changes only a preexisting test filler by one byte. The conservative
// predecessor T is deliberately not used as an attained charge oracle.
func TestReplayPairExactFit(t *testing.T) {
	full := icbReplayVaultBlockV1(t, 200, 1)
	f := *full
	f.prefix, f.block, f.old, f.inputs = full.prefix[:5], full.prefix[5], full.prefix[4].rows, nil
	var peak uint64
	c, _ := rpfCase(t, &f, 1, true)
	c.store.inspect = func(op mdbx.TreeOperationV1) {
		rpAssertPlan(t, c, op, 2)
		logicalMDBXAssert(t, mdbx.FixtureReservationLive(c.w.owner) == icbMV1(uint64(len(c.in.Raw)))+8388608, "A13 composer has no internal margin")
	}
	var got replayPairOutcomeV1
	_, err := mdbx.FixturePairReadObservation(c.w.s, func(uint32) { peak = max(peak, mdbx.FixtureReservationLive(c.w.owner)) }, func() { got = rpfRun(t, c, nil, nil, nil, 0) })
	rpTuple(t, got, 2, 3, -1, nil, "")
	logicalMDBXAssert(t, err == nil && peak > 0 && peak < 402653184, "attained operation peak: %d/%v", peak, err)
	for _, extra := range []uint64{0, 1} {
		c, w := rpfCase(t, &f, 1, true)
		old := icbReplayLagImageV1(t, w)
		filler := uint64(402653184)-peak+extra
		c.store.inspect = func(op mdbx.TreeOperationV1) {
			rpAssertPlan(t, c, op, 2)
			logicalMDBXAssert(t, mdbx.FixtureReservationLive(c.w.owner) == icbMV1(uint64(len(c.in.Raw)))+8388608+filler, "A13 composer has no internal margin")
		}
		var maxHeld uint64
		_, err := mdbx.FixturePairReadObservation(c.w.s, func(uint32) { maxHeld = max(maxHeld, mdbx.FixtureReservationLive(c.w.owner)) }, func() { got = rpfRun(t, c, nil, nil, nil, filler) })
		logicalMDBXAssert(t, err == nil && maxHeld <= 402653184, "unchanged legal account ceiling: %d/%v", maxHeld, err)
		if extra == 0 {
			rpTuple(t, got, 2, 3, -1, nil, "")
			logicalMDBXAssert(t, maxHeld == 402653184, "exact fit must attain legal ceiling, got%d", maxHeld)
			for _, g := range []uint64{1, 2} { icbReplayStateV1(t, w, g, f.block, nil) }
		} else {
			logicalMDBXAssert(t, got.Truth == 1 && got.Stage == 1 && mdbx.IsOperationReservationCapacity(got.Err), "one-byte filler increment must refuse owning acquisition: %+v", got)
			icbReplayWantLagImageV1(t, w, old)
			icbReplayStateV1(t, w, 1, f.prefix[4], nil)
			icbReplayFollowingV1(t, w)
		}
	}
	t.Logf("attained A1 peak=%d; conservative predecessor T=400000000 is not measured peak", peak)
}

// TestReplayPairTargetCorpus sends the finite H domain through actual CURRENT
// validation/native effects. Boundary arithmetic itself has independent literals.
func TestReplayPairTargetCorpus(t *testing.T) {
	for _, target := range []uint64{15120, 15839, 15840, 0xffffffff} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			c := rpNew(t, target, 1, mdbx.UndoTransientV1)
			c.store.inspect = func(op mdbx.TreeOperationV1) { rpAssertPlan(t, c, op, 2) }
			got := c.run(t, nil, c.inputs)
			rpTuple(t, got, 2, 3, -1, nil, "")
			rpGenesisState(t, c, true)
		})
	}
	full := icbReplayVaultBlockV1(t, 200, 1)
	f := *full
	f.prefix, f.block, f.old, f.inputs = full.prefix[:1], full.prefix[1], full.prefix[0].rows, nil
	for _, target := range []uint64{15120, 15839} {
		c, w := rpfCase(t, &f, 1, true)
		c.request.Authority.Authority.Replay.Target.TipHeight = target
		w.seedAuthority(t, c.request.Authority)
		old := icbReplayLagImageV1(t, w)
		c.store.inspect = func(op mdbx.TreeOperationV1) { rpAssertPlan(t, c, op, 1) }
		got := rpfRun(t, c, nil, nil, nil, 0)
		rpTuple(t, got, 2, 3, -1, nil, "")
		logicalMDBXAssert(t, c.lag == 0, "b0 h1 must skip LAG stage")
		icbReplayWantLagImageV1(t, w, old)
	}
}

// TestReplayPairEndpointUnequal supplies a coherent alternative LAG image,
// with a real native-created extra leaf, at the same qualified parent. The
// endpoint consistency check must distinguish it from accepted CURRENT state.
func TestReplayPairEndpointUnequal(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	c, w := rpfCase(t, f, 1, true)
	extra := btTransaction(999, 0, nil, [][]byte{btFrame(1, 0, []byte{99})}, nil, []byte{0}, nil)
	req := btRequest(btBody(148, 99, c.in.Parent.BlockHash, extra), c.in.Parent.Height)
	req.Generation, req.Kind, req.Undo, req.BodyKind = 2, mdbx.TreeKindDirectApplyV1, mdbx.UndoTransientV1, 3
	req.CanonicalBeforePresent = true
	seed, _, _ := w.btWorld.run(t, []blockTreeRequestV1{req}, nil)
	seed.want(t, 2, 3, -1)
	logicalMDBXAssert(t, seed.err == nil, "native coherent alternative LAG: %v", seed.err)
	var binding mdbx.RootBindingV1
	err := w.s.View(func(r *mdbx.Reader) error { var err error; binding, _, err = r.ReadTreeRootBindingV1(2); return err })
	logicalMDBXAssert(t, err == nil, "alternative root read: %v", err)
	binding.Endpoint = c.in.Parent
	w.seedBinding(t, 2, binding)
	old := icbReplayLagImageV1(t, w)
	oldAuthority := rtImageRow(t, w.btWorld, []byte{2})
	var got replayPairOutcomeV1
	counts, err := mdbx.FixturePairReadObservation(w.s, nil, func() { got = rpfRun(t, c, f.inputs, nil, nil, 0) })
	var unequal *replayPairUnequalV1
	logicalMDBXAssert(t, err == nil && counts.Writes == 0 && errors.As(got.Err, &unequal) && got.Truth == 1 && got.Stage == 1 && got.Index == -1 && got.Role == "LAG", "coherent unequal typed local callback evidence: %+v/%+v/%v", got, counts, err)
	logicalMDBXAssert(t, unequal.Generation == 2 && unequal.Height == c.in.Height && unequal.Block == c.in.Endpoint.BlockHash && unequal.Derived != unequal.Accepted && bytes.Equal(unequal.Accepted[:], c.in.Raw[108:140]), "exact protected-LAG unequal evidence: %+v", unequal)
	icbReplayWantLagImageV1(t, w, old)
	w.read(t, 0, []byte{2}, oldAuthority)
	icbReplayFollowingV1(t, w)
}

// TestReplayPairBorrowIsolation mutates only CURRENT's retired private working
// map and independent Pair descriptors after the engine has its owned copy.
// Source/Coverage/Raw bytes remain immutable through readback and unwind.
func TestReplayPairBorrowIsolation(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	c, w := rpfCase(t, f, 1, true)
	before := bytes.Clone(c.in.Raw)
	alter := func(prepare replayPairPrepareCurrentV1) replayPairPrepareCurrentV1 {
		return func(r *mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error) {
			result, rows, err := prepare(r)
			if err == nil { clear(result.transition.createdUtxos) }
			return result, rows, err
		}
	}
	var borrowed []mdbx.Mutation
	mutated := false
	c.store.inspect = func(op mdbx.TreeOperationV1) {
		rpAssertPlan(t, c, op, 2)
		borrowed = op.Pair.Mutations
		for i := range op.Primitives {
			source := op.Primitives[i].Source.(*blockTreeSourceV1)
			observed := &btObserved{t: t, source: source}
			observed.before = func(mdbx.TreePositionV1, *mdbx.Reader, *mdbx.TreeDeltaSinkV1) error {
				if !mutated {
					// Replacing descriptors does not mutate their borrowed payloads.
					for j := range borrowed { borrowed[j] = mdbx.Mutation{} }
					mutated = true
				}
				return nil
			}
			op.Primitives[i].Source = observed
		}
	}
	var got replayPairOutcomeV1
	_, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageCommitNew, 0, btMeta(0x11, 1), func() { got = rpfRun(t, c, f.inputs, alter, nil, 0) })
	logicalMDBXAssert(t, err == nil && got.Truth == 2 && mutated && bytes.Equal(c.in.Raw, before), "borrowed immutable source survives independent Pair/current-image changes: %+v/%v", got, err)
	w.reopen(t)
	for _, g := range []uint64{1, 2} { icbReplayStateV1(t, w, g, f.block, f.inputs) }
}

// TestReplayPairCallbackUnwind checks the new stage boundary's application
// error/panic/Goexit handling. Native engine tests retain infrastructure matrices.
func TestReplayPairCallbackUnwind(t *testing.T) {
	for _, stage := range []string{"CURRENT", "LAG"} {
		for _, mode := range []string{"error", "panic", "Goexit"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
				primary := errors.New("composer application cause")
				calls := 0
				invoke := func() error {
					calls++
					if mode == "panic" { panic(primary) }
					if mode == "Goexit" { runtime.Goexit() }
					return primary
				}
				alter := func(prepare replayPairPrepareCurrentV1) replayPairPrepareCurrentV1 {
					if stage != "CURRENT" { return prepare }
					return func(*mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error) { return nil, replayPairRowsV1{}, invoke() }
				}
				inputs := replayPairWithLagInputsV1(c.inputs)
				if stage == "LAG" { inputs = func(*mdbx.Reader, *initial148CompleteBlockResultV1, func([]mdbx.TreeOutpointV1) error) error { return invoke() } }
				done := make(chan any, 1)
				go func() {
					var recovered any
					defer func() { if p := recover(); p != nil { recovered = p }; done <- recovered }()
					got := c.run(t, alter, inputs)
					rpTuple(t, got, 1, 1, -1, primary, stage)
				}()
				observed := <-done
				logicalMDBXAssert(t, calls == 1 && ((mode == "panic" && observed == primary) || (mode != "panic" && observed == nil)), "unwind preserves identity/count: %v/%d", observed, calls)
				btReservationsReleased(t, c.w.owner)
				rpFollowing(t, c.w)
			})
		}
	}
}

// TestReplayPairNativeCurrentRole reaches the native CURRENT primitive0 after
// height-zero validation (whose empty logical parent needs no persisted counter).
func TestReplayPairNativeCurrentRole(t *testing.T) {
	c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
	err := mdbx.FixtureStartupDeleteRow(c.w.s, 0, btMeta(0x10, 1))
	logicalMDBXAssert(t, err == nil, "remove CURRENT counter fixture: %v", err)
	got := c.run(t, nil, c.inputs)
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, got.Truth == 1 && got.Stage == 1 && got.Index == 0 && got.Role == "CURRENT" && errors.As(got.Err, &engine) && engine.TreeObservation != nil && engine.TreeObservation.Generation == 1, "native primitive0 exact CURRENT projection: %+v", got)
	btfCached(t, c.w, btResult{truth: got.Truth, stage: got.Stage, index: got.Index, err: got.Err})
}

// TestReplayPairNativeCapacity leaves 2.2/2.45 MB after the caller M/source
// charges. The existing native P floor is 2097152, each frozen role owns
// 74912+65560+104*E, and its walk owns 147968: CURRENT's peak fits only the
// second row, while retaining both roles exceeds it. No lane ceiling changes.
func TestReplayPairNativeCapacity(t *testing.T) {
	for _, row := range []struct { headroom uint64; index int; role string }{{2200000, 0, "CURRENT"}, {2450000, 1, "LAG"}} {
		t.Run(row.role, func(t *testing.T) {
			c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
			var got replayPairOutcomeV1
			var finish chan struct{}
			var held chan error
			err := c.w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
				defer func() {
					if finish != nil { close(finish); logicalMDBXAssert(t, <-held == nil, "native-capacity test hold retires") }
				}()
				_, runErr := withInitial148CompleteBlockV1(a, c.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
					c.store.inspect = func(op mdbx.TreeOperationV1) {
						rpAssertPlan(t, c, op, 2)
						ready := make(chan error, 1)
						finish, held = make(chan struct{}), make(chan error, 1)
						filler := uint64(402653184)-mdbx.FixtureReservationLive(c.w.owner)-row.headroom
						go func() {
							err := a.WithReservation(filler, func() error { ready <- nil; <-finish; return nil })
							if err != nil { ready <- err }
							held <- err
						}()
						logicalMDBXAssert(t, <-ready == nil, "pre-native test filler acquisition")
					}
					got = applyReplayPairV1(&c.store, a, c.request, c.prepare(t, validate), c.inputs)
					return got.Err
				})
				logicalMDBXAssert(t, any(runErr) == any(got.Err), "capacity cause identity")
				return nil
			})
			logicalMDBXAssert(t, err == nil && got.Truth == 1 && got.Stage == 1 && got.Index == row.index && got.Role == row.role && mdbx.IsOperationReservationCapacity(got.Err), "native charge refusal retains raw role/index/account: %+v/%v", got, err)
			btReservationsReleased(t, c.w.owner)
			btState(t, c.w, 1, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
			btState(t, c.w, 2, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
			rpFollowing(t, c.w)
		})
	}
}

// TestReplayPairLagGrantCapacity reaches the lexical caller grant only after
// F2/LAG/F3 source success; a plain account refusal has no tree observation.
func TestReplayPairLagGrantCapacity(t *testing.T) {
	c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
	var reached int
	got := c.run(t, nil, func(*mdbx.Reader, *initial148CompleteBlockResultV1, func([]mdbx.TreeOutpointV1) error) error {
		reached++
		live := mdbx.FixtureReservationLive(c.w.owner)
		return c.store.account.WithReservation(402653184-live+1, func() error { t.Fatal("refused LAG grant invoked use frame"); return nil })
	})
	logicalMDBXAssert(t, reached == 1 && got.Truth == 1 && got.Stage == 1 && got.Index == -1 && got.Role == "LAG" && mdbx.IsOperationReservationCapacity(got.Err), "LAG grant capacity/no-observation role: %+v reached%d", got, reached)
	btState(t, c.w, 1, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
	btState(t, c.w, 2, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
	rpFollowing(t, c.w)
}

// TestReplayPairCallbackDisposition protects raw cause ordering and the actual
// Store disposition at the two new callback boundaries. The native owner keeps
// its existing full panic/Goexit/infrastructure matrix; no second matrix is added.
func TestReplayPairCallbackDisposition(t *testing.T) {
	for _, stage := range []string{"CURRENT", "LAG"} {
		for _, mode := range []uint32{9, 10} {
			t.Run(fmt.Sprintf("%s/%d", stage, mode), func(t *testing.T) {
				c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
				primary := errors.New("composer callback application cause")
				alter := func(prepare replayPairPrepareCurrentV1) replayPairPrepareCurrentV1 {
					if stage != "CURRENT" { return prepare }
					return func(*mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error) { return nil, replayPairRowsV1{}, primary }
				}
				inputs := replayPairWithLagInputsV1(c.inputs)
				if stage == "LAG" { inputs = func(*mdbx.Reader, *initial148CompleteBlockResultV1, func([]mdbx.TreeOutpointV1) error) error { return primary } }
				var got replayPairOutcomeV1
				state, _, err := mdbx.FixtureStartupCleanup(c.w.s, mode, false, func() { got = c.run(t, alter, inputs) })
				want := "CLOSED"
				if mode == 10 { want = "POISONED_THREAD" }
				logicalMDBXAssert(t, err == nil && state == want && got.Truth == 1 && got.Stage == 1 && got.Index == -1 && got.Role == stage && errors.Is(got.Err, primary), "callback raw role/actual consumed or retained state: %+v/%s/%v", got, state, err)
				btfAbortResult(t, got.Err, mode, primary)
				btfCached(t, c.w, btResult{truth: got.Truth, stage: got.Stage, index: got.Index, err: got.Err})
				value, present, expired := c.store.reader.Get(mdbx.TreeSchemaV1DBIs()[0], []byte{2})
				logicalMDBXAssert(t, value == nil && !present, "expired callback Reader cannot return data")
				btfEngine(t, expired, "get", "InvalidInput", 22, "Reader is not active")
				if mode == 10 { logicalMDBXAssert(t, mdbx.FixtureStartupRelease(c.w.s) == nil, "release retained native fixture handle") }
			})
		}
	}
}

// TestReplayPairKeyShape reaches the existing root API's sorted/unique key
// guards after proper LAG point qualification, without a composer parser.
func TestReplayPairKeyShape(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	for _, shape := range []string{"duplicate", "descending"} {
		t.Run(shape, func(t *testing.T) {
			c, w := rpfCase(t, f, 1, true)
			old := icbReplayLagImageV1(t, w)
			lag := func(base replayPairWithLagInputsV1) replayPairWithLagInputsV1 {
				return func(r *mdbx.Reader, result *initial148CompleteBlockResultV1, use func([]mdbx.TreeOutpointV1) error) error {
					return base(r, result, func(keys []mdbx.TreeOutpointV1) error {
						logicalMDBXAssert(t, len(keys) >= 2, "distinct qualified keys for shape witness")
						if shape == "duplicate" { keys[1] = keys[0] } else { keys[0], keys[1] = keys[1], keys[0] }
						return use(keys)
					})
				}
			}
			got := rpfRun(t, c, f.inputs, nil, lag, 0)
			var engine *mdbx.EngineError
			logicalMDBXAssert(t, got.Truth == 1 && got.Stage == 1 && got.Index == -1 && got.Role == "LAG" && errors.As(got.Err, &engine) && engine.Class == "InvalidInput" && engine.Diagnostic == "invalid Update Batch" && engine.TreeObservation == nil, "root API key-shape error preserved at LAG: %+v", got)
			icbReplayWantLagImageV1(t, w, old)
			icbReplayFollowingV1(t, w)
		})
	}
}

// TestReplayPairIndexPhysicalMismatch preserves the raw physical Pair failure.
// This deliberately incoherent new-h target is not required OLD-index health
// evidence; that qualification remains with the future replay-step caller.
func TestReplayPairIndexPhysicalMismatch(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	c, w := rpfCase(t, f, 1, true)
	key := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 2), c.in.Height)
	w.seed(t, 2, key, []byte{0xff})
	old := icbReplayLagImageV1(t, w)
	oldAuthority := rtImageRow(t, w.btWorld, []byte{2})
	got := rpfRun(t, c, f.inputs, nil, nil, 0)
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, got.Truth == 1 && got.Stage == 2 && got.Index == -1 && got.Role == "" && errors.As(got.Err, &engine) && engine.Class == "StateMismatch" && engine.Operation == "update" && engine.Code == -30799 && engine.Diagnostic == "MDBX_KEYEXIST: Key/data pair already exists" && engine.Cause == nil && engine.TreeObservation == nil && !engine.ReopenRequired, "new-h Pair mismatch raw enclosing product: %+v", got)
	btfCached(t, w.btWorld, btResult{truth: got.Truth, stage: got.Stage, index: got.Index, err: got.Err})
	w.reopen(t)
	w.read(t, 0, []byte{2}, oldAuthority)
	icbReplayWantLagImageV1(t, w, old)
	icbReplayStateV1(t, w, 1, f.prefix[len(f.prefix)-1], nil)
}

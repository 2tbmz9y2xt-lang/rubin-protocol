//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestCandidateRootFixtureOrder(t *testing.T) {
	t.Run("growth_before_binding", candidateGrowthBeforeBinding)
	t.Run("coinbase_placement", candidatePlacementBeforeReads)
}

func candidateGrowthBeforeBinding(t *testing.T) {
	w, in, _, raws := candidateGrowthSetup(t, true)
	after, want := candidateGrowthCoinbase(t, in, raws)
	key := btMeta(17, 1)
	evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 0, key, func() {
		candidateView(t, w, func(r *mdbx.Reader) {
			candidateTxError(t, r, w.owner, in, "BLOCK_ERR_STATE_GROWTH_EXCEEDED", "logical state growth exceeded")
		})
	})
	candidateUnreached(t, evidence, fixtureErr)
	logicalMDBXAssert(t, evidence.OldGets[0] == 2 && evidence.NodeGets == 0, "growth reached binding or node: %+v", evidence)
	candidateView(t, w, func(r *mdbx.Reader) { candidateRootOK(t, r, w.owner, after, want) })
	candidateBindingIO(t, w, after, 5)
}

func candidatePlacementBeforeReads(t *testing.T) {
	s := newCandidateScene(t, 5)
	extra := initial148BlockCoinbase(t)
	raw, _ := candidateFrame(t, s.parent, 1, extra)
	in := candidateInput(t, raw, s.parent)
	next, want := s.body(t, 0, 1)
	evidence, err := mdbx.FixturePairReadObservation(s.world.s, nil, func() {
		candidateView(t, s.world, func(r *mdbx.Reader) {
			candidateTxError(t, r, s.world.owner, in, "BLOCK_ERR_COINBASE_INVALID", "coinbase-like tx is only allowed at index 0")
		})
	})
	logicalMDBXAssert(t, err == nil && evidence.Gets == 0 && evidence.Writes == 0, "coinbase placement reached storage: %+v/%v", evidence, err)
	candidateView(t, s.world, func(r *mdbx.Reader) { candidateRootOK(t, r, s.world.owner, next, want) })
}

func TestCandidateRootFixtureFailure(t *testing.T) {
	t.Run("get_consumed", func(t *testing.T) { candidateFailedView(t, mdbx.SelectedDamageGetEIO) })
	t.Run("get_and_abort", func(t *testing.T) { candidateFailedView(t, mdbx.SelectedDamageGetAbortEIO) })
	t.Run("abort_after_success", func(t *testing.T) { candidateFailedView(t, mdbx.SelectedDamageAbortEIO) })
	t.Run("binding_integrity", candidateBindingFailures)
	t.Run("application_integrity", candidateApplicationFailures)
}

func candidateFailedView(t *testing.T, scenario mdbx.SelectedDamageScenario) {
	t.Helper()
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 1, 1)
	w := s.world
	preview := scenario == mdbx.SelectedDamageAbortEIO
	var viewErr, selected error
	evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 1, btUTXOKey(1, s.funding), func() {
		viewErr = w.s.View(func(r *mdbx.Reader) error {
			root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
			selected = err
			if preview {
				logicalMDBXAssert(t, err == nil && root == want, "candidate preview %x/%v, want %x", root, err, want)
				candidateReadControl(t, r)
			} else {
				logicalMDBXAssert(t, root == [32]byte{}, "native refusal returned digest %x", root)
				candidateEIO(t, err, "get")
				candidateInactiveReader(t, r)
			}
			return err
		})
	})
	candidateViewFailure(t, scenario, selected, viewErr)
	candidateTerminalView(t, w, viewErr)
	wantFaults := uint64(1)
	if scenario == mdbx.SelectedDamageGetAbortEIO {
		wantFaults = 2
	}
	logicalMDBXAssert(t, fixtureErr == nil && evidence.Faults == wantFaults && evidence.BeginOld == 1 && evidence.OldAborts == 1 && evidence.OldGets[1] > 0,
		"candidate reached fault: %+v/%v", evidence, fixtureErr)
	candidateNoNativeWrite(t, evidence)
	logicalMDBXAssert(t, mdbx.FixtureReservationLive(w.owner) == 0, "native error leaked a candidate reservation")
}

func candidateViewFailure(t *testing.T, scenario mdbx.SelectedDamageScenario, selected, viewErr error) {
	t.Helper()
	switch scenario {
	case mdbx.SelectedDamageAbortEIO:
		candidateEIO(t, viewErr, "abort")
	case mdbx.SelectedDamageGetAbortEIO:
		joint, ok := viewErr.(interface{ Unwrap() []error })
		logicalMDBXAssert(t, ok, "expected ordered native errors: %v", viewErr)
		items := joint.Unwrap()
		logicalMDBXAssert(t, len(items) == 2 && any(items[0]) == any(selected), "original get does not lead View error: %v", viewErr)
		candidateEIO(t, items[1], "abort")
	default:
		logicalMDBXAssert(t, any(viewErr) == any(selected), "View replaced original get error: %v/%v", selected, viewErr)
	}
}

func candidateEngine(t *testing.T, err error, op string, class mdbx.EngineClass, code int, diagnostic string) *mdbx.EngineError {
	t.Helper()
	engine, ok := err.(*mdbx.EngineError)
	logicalMDBXAssert(t, ok && engine != nil && engine.Operation == op && engine.Class == class && engine.Code == code && engine.Diagnostic == diagnostic,
		"native result %T/%v, want %s/%s/%d/%q", err, err, op, class, code, diagnostic)
	return engine
}

func candidateEIO(t *testing.T, err error, op string) {
	t.Helper()
	candidateEngine(t, err, op, "IO", 5, "error 5")
}

func candidateInactiveReader(t *testing.T, r *mdbx.Reader) {
	t.Helper()
	raw, found, err := r.Get(mdbx.TreeSchemaV1DBIs()[0], []byte{3})
	candidateEngine(t, err, "get", "InvalidInput", 22, "Reader is not active")
	logicalMDBXAssert(t, raw == nil && !found, "inactive Reader returned data")
}

func candidateTerminalView(t *testing.T, w *btWorld, first error) {
	t.Helper()
	called := false
	next := w.s.View(func(*mdbx.Reader) error { called = true; return nil })
	logicalMDBXAssert(t, !called && any(next) == any(first), "terminal View replaced its error or entered callback: %v", next)
}

func candidateReadControl(t *testing.T, r *mdbx.Reader) {
	t.Helper()
	id := [32]byte{7}
	candidateReadExact(t, r, 0, []byte{3}, id[:])
}

func candidateNoNativeWrite(t *testing.T, evidence mdbx.SelectedDamageEvidence) {
	t.Helper()
	logicalMDBXAssert(t, evidence.BeginWrite == 0 && evidence.Commits == 0 && evidence.Deletes == 0 && evidence.OldGets[4] == 0 && evidence.OldPulls[5] == 0,
		"candidate performed write, body or undo I/O: %+v", evidence)
}

func candidateUnreached(t *testing.T, evidence mdbx.SelectedDamageEvidence, err error) {
	t.Helper()
	logicalMDBXAssert(t, err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0,
		"unexpected damage site: %+v/%v", evidence, err)
}

func candidateApplicationFailures(t *testing.T) {
	for _, row := range []struct {
		name    string
		rank    uint8
		value   []byte
		message string
	}{
		{"consumed_utxo", 1, nil, "invalid MDBX SchemaV2 bytes"},
		{"counter_absent", 0, nil, "required logical counters are absent or malformed"},
		{"counter_envelope", 0, []byte{7: 1, 15: 3}, "invalid required logical counter envelope"},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := newCandidateScene(t, 5)
			w := s.world
			key, value := btMeta(16, 1), row.value
			if row.rank == 1 {
				key = btUTXOKey(1, s.funding)
				entry := s.entries[s.funding]
				value = btValue(btFrame(entry.Value, entry.CovenantType, entry.CovenantData), entry.CreationHeight, false)
				value[len(value)-1] = 2
			}
			candidateRawRow(t, w, row.rank, key, value)
			in, _ := s.body(t, 1, 1)
			var selected error
			outer := w.s.View(func(r *mdbx.Reader) error {
				root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
				selected = err
				logicalMDBXAssert(t, root == [32]byte{}, "application integrity returned digest %x", root)
				irFailureV1(t, err, logicalStateFailureStoreIntegrity, row.message)
				candidateReadControl(t, r)
				return err
			})
			logicalMDBXAssert(t, any(outer) == any(selected), "retained View replaced selected application failure: %v/%v", outer, selected)
			candidateView(t, w, func(r *mdbx.Reader) { candidateReadControl(t, r) })
		})
	}
}

func candidateRawRow(t *testing.T, w *btWorld, rank uint8, key, value []byte) {
	t.Helper()
	var err error
	if value == nil {
		err = mdbx.FixtureStartupDeleteRow(w.s, rank, key)
	} else {
		err = mdbx.FixtureSeedRawRow(w.s, rank, key, value)
	}
	logicalMDBXAssert(t, err == nil, "candidate raw row %d/%x: %v", rank, key, err)
}

func candidateBindingFailures(t *testing.T) {
	for _, row := range []struct {
		name string
		kind mdbx.TreeObservationKindV1
	}{
		{"absent", 1}, {"malformed", 2}, {"wrong_database", 3}, {"wrong_endpoint", 3}, {"node_digest", 4},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := newCandidateScene(t, 5)
			in, _ := s.body(t, 1, 1)
			rank, key := candidateDamageBinding(t, s.world, row.name)
			candidateObserveBinding(t, s.world, in, rank, key, row.kind)
		})
	}
}

func candidateDamageBinding(t *testing.T, w *btWorld, name string) (uint8, []byte) {
	t.Helper()
	key := btMeta(17, 1)
	switch name {
	case "absent":
		candidateRawRow(t, w, 0, key, nil)
	case "malformed":
		candidateRawRow(t, w, 0, key, []byte{3})
	default:
		var binding mdbx.RootBindingV1
		candidateView(t, w, func(r *mdbx.Reader) {
			var err error
			binding, _, err = r.ReadTreeRootBindingV1(1)
			logicalMDBXAssert(t, err == nil && binding.Top.Node != nil, "candidate binding prestate: %v", err)
		})
		if name == "node_digest" {
			return 8, candidateDamageNode(t, w, *binding.Top.Node)
		}
		if name == "wrong_database" {
			binding.DatabaseID[0] = 8
		} else {
			binding.Endpoint.BlockHash[0] ^= 1
		}
		encoded, err := binding.Encode()
		logicalMDBXAssert(t, err == nil, "candidate altered binding: %v", err)
		candidateRawRow(t, w, 0, key, encoded)
	}
	return 0, key
}

func candidateDamageNode(t *testing.T, w *btWorld, node mdbx.TreeNodeIDV1) []byte {
	t.Helper()
	key, err := mdbx.TreeNodeKey(1, node)
	logicalMDBXAssert(t, err == nil, "candidate branch key: %v", err)
	var value []byte
	candidateView(t, w, func(r *mdbx.Reader) {
		value, _, err = r.Get(mdbx.TreeSchemaV1DBIs()[8], key)
		logicalMDBXAssert(t, err == nil && len(value) == 140, "candidate branch row: %d/%v", len(value), err)
	})
	value[38] ^= 1
	candidateRawRow(t, w, 8, key, value)
	return key
}

func candidateObserveBinding(t *testing.T, w *btWorld, in CandidateRootInput, rank uint8, key []byte, kind mdbx.TreeObservationKindV1) {
	t.Helper()
	var selected error
	outer := w.s.View(func(r *mdbx.Reader) error {
		root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
		selected = err
		logicalMDBXAssert(t, root == [32]byte{}, "binding integrity returned digest %x", root)
		engine := candidateEngine(t, err, "update", "Integrity", -30796, "invalid tree native representation")
		observation := engine.TreeObservation
		logicalMDBXAssert(t, observation != nil && observation.Rank == rank && observation.Kind == kind, "candidate binding observation: %+v", observation)
		logicalMDBXAssert(t, observation.DatabaseID == [32]byte{7} && observation.Generation == 1 && observation.Height == 5 && observation.Block == [32]byte{} &&
			bytes.Equal(observation.Key[:observation.KeyLength], key) && observation.OriginalImage && observation.OriginalReference,
			"candidate observation identity: %+v", observation)
		candidateInactiveReader(t, r)
		return err
	})
	logicalMDBXAssert(t, any(outer) == any(selected), "binding View replaced selected cause: %v/%v", outer, selected)
	candidateTerminalView(t, w, outer)
}

func TestCandidateRootFixtureParent(t *testing.T) {
	t.Run("spent_after_advance", candidateAfterAdvance)
	t.Run("lag_named", candidateLagNamed)
	t.Run("work_only", candidateWorkDrift)
	t.Run("stale_reader_reuse", candidateWorkDrift)
	t.Run("different_generation_missing_tip", func(t *testing.T) { candidateDifferentGeneration(t, "missing_tip", 1) })
	t.Run("different_generation_malformed_tip", func(t *testing.T) { candidateDifferentGeneration(t, "malformed_tip", 1) })
	t.Run("different_generation_cursor_eio", func(t *testing.T) { candidateDifferentGeneration(t, "cursor_eio", 2) })
	t.Run("matching_generation_cursor_eio", candidateMatchingCursor)
	t.Run("authority_get_eio", candidateAuthorityIO)
	t.Run("authority_absent_nonempty", func(t *testing.T) { candidateAuthorityIntegrity(t, nil) })
	t.Run("authority_malformed", func(t *testing.T) { candidateAuthorityIntegrity(t, []byte{3}) })
	t.Run("qualified_tip_binding_mismatch", func(t *testing.T) {
		s := newCandidateScene(t, 5)
		in, _ := s.body(t, 1, 1)
		rank, key := candidateDamageBinding(t, s.world, "wrong_endpoint")
		candidateObserveBinding(t, s.world, in, rank, key, 3)
	})
	t.Run("wrong_reader_db", candidateWrongDatabase)
	t.Run("empty_control", candidateEmptyControl)
	t.Run("current_read", candidateNoIdentityRead)
}

func candidateRootStale(t *testing.T, r *mdbx.Reader, w *btWorld, in CandidateRootInput) error {
	t.Helper()
	root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
	logicalMDBXAssert(t, root == [32]byte{} && errors.Is(err, mdbx.ErrCandidateParentNotCurrent), "stale parent returned %x/%v", root, err)
	return err
}

func candidateWorkDrift(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 1, 1)
	old := in
	old.Selection.Parent.CumulativeChainwork[39] = 98
	evidence, err := mdbx.FixtureSelectedDamage(s.world.s, s.world.owner, mdbx.SelectedDamageGetEIO, 1, btUTXOKey(1, s.other), func() {
		candidateView(t, s.world, func(r *mdbx.Reader) {
			candidateRootStale(t, r, s.world, old)
			logicalMDBXAssert(t, mdbx.FixtureReservationLive(s.world.owner) == 0, "stale result retained bytes")
			candidateRootOK(t, r, s.world.owner, in, want)
			logicalMDBXAssert(t, mdbx.FixtureReservationLive(s.world.owner) == 0, "candidate retry retained bytes")
		})
	})
	candidateUnreached(t, evidence, err)
	logicalMDBXAssert(t, evidence.OldGets[1] == 5 && mdbx.FixtureReservationLive(s.world.owner) == 0, "stale work entered parent reads: %+v", evidence)
}

func candidateAfterAdvance(t *testing.T) {
	s := newCandidateScene(t, 5)
	old, _ := s.body(t, 1, 1)
	req := btRequest(old.Raw, 5)
	req.Endpoint.CumulativeChainwork[39] = 100
	result, _, _ := s.world.run(t, []blockTreeRequestV1{req}, nil)
	logicalMDBXAssert(t, result.err == nil, "advance native CURRENT: %v", result.err)
	p, err := ParseInitial148BlockBytes(old.Raw)
	logicalMDBXAssert(t, err == nil, "advance body parse: %v", err)
	delete(s.entries, s.funding)
	s.entries[Outpoint{Txid: p.Txids[0]}] = btEntry(1, 0, validP2PKCovenantData(), 5, true)
	s.entries[Outpoint{Txid: p.Txids[1]}] = btEntry(990, 0, s.cov, 5, false)
	s.parent = req.Endpoint
	next, want := s.body(t, 0, 1)
	evidence, err := mdbx.FixtureSelectedDamage(s.world.s, s.world.owner, mdbx.SelectedDamageGetEIO, 1, btUTXOKey(1, s.funding), func() {
		candidateView(t, s.world, func(r *mdbx.Reader) {
			candidateRootStale(t, r, s.world, old)
			candidateRootOK(t, r, s.world.owner, next, want)
		})
	})
	candidateUnreached(t, evidence, err)
}

func candidateAuthority(t *testing.T, w *btWorld, active, lag uint64) {
	t.Helper()
	value, err := (mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: active, NextGenerationID: 5, Phase: 1, Lifecycle: 1}, LagGenerationID: lag}).Encode()
	logicalMDBXAssert(t, err == nil, "candidate authority encoding: %v", err)
	row := btMutation(0, []byte{2}, value)
	row.BeforePresent = true
	w.pair(t, row)
}

func candidateLagNamed(t *testing.T) {
	s := newCandidateScene(t, 5)
	candidateAuthority(t, s.world, 3, 1)
	in, _ := s.body(t, 1, 1)
	candidateView(t, s.world, func(r *mdbx.Reader) {
		candidateRootStale(t, r, s.world, in)
		candidateReadControl(t, r)
	})
}

func candidateDifferentGeneration(t *testing.T, mode string, scenario uint8) {
	t.Helper()
	s := newCandidateScene(t, 5)
	candidateAuthority(t, s.world, 3, 1)
	in, _ := s.body(t, 1, 1)
	if mode != "missing_tip" {
		candidateSeedTip(t, s.world, in.Selection.Parent, 3, mode == "malformed_tip")
	}
	evidence, err := mdbx.FixtureCanonicalTipStep(s.world.s, scenario, nil, nil, false, func() {
		viewErr := s.world.s.View(func(r *mdbx.Reader) error {
			err := candidateRootStale(t, r, s.world, in)
			candidateReadControl(t, r)
			return err
		})
		logicalMDBXAssert(t, errors.Is(viewErr, mdbx.ErrCandidateParentNotCurrent), "stale View error: %v", viewErr)
	})
	logicalMDBXAssert(t, err == nil && evidence == (mdbx.CanonicalTipStepFixtureEvidence{}), "unselected generation cursor: %+v/%v", evidence, err)
	candidateView(t, s.world, func(r *mdbx.Reader) { candidateReadControl(t, r) })
	in.Selection.Generation = 3
	candidateCheckMatchingTip(t, s.world, in, mode, scenario)
}

func candidateSeedTip(t *testing.T, w *btWorld, parent mdbx.TreeEndpointV1, generation uint64, malformed bool) {
	t.Helper()
	key, err := mdbx.HeightKey(generation, parent.Height)
	logicalMDBXAssert(t, err == nil, "candidate canonical tip key: %v", err)
	if malformed {
		candidateRawRow(t, w, 2, key, make([]byte, 103))
		return
	}
	w.pair(t, btMutation(2, key, mdbx.ChainValue(parent.BlockHash, [32]byte{}, parent.CumulativeChainwork)))
}

func candidateMatchingCursor(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, _ := s.body(t, 1, 1)
	candidateCheckMatchingTip(t, s.world, in, "cursor_eio", 2)
}

func candidateCheckMatchingTip(t *testing.T, w *btWorld, in CandidateRootInput, mode string, scenario uint8) {
	t.Helper()
	var selected, outer error
	counts, err := mdbx.FixtureCanonicalTipStep(w.s, scenario, nil, nil, false, func() {
		outer = w.s.View(func(r *mdbx.Reader) error {
			root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
			selected = err
			logicalMDBXAssert(t, root == [32]byte{}, "canonical tip error returned digest %x", root)
			switch mode {
			case "cursor_eio":
				candidateEIO(t, err, "prefix-page")
			case "missing_tip":
				candidateEngine(t, err, "prefix-page", "Integrity", -30793, "canonical tip absent")
			case "malformed_tip":
				candidateEngine(t, err, "prefix-page", "Integrity", -30793, "stored value width outside SchemaV2 bound")
			}
			candidateInactiveReader(t, r)
			return err
		})
	})
	logicalMDBXAssert(t, any(outer) == any(selected), "canonical tip View replaced selected result: %v/%v", outer, selected)
	candidateTerminalView(t, w, outer)
	logicalMDBXAssert(t, err == nil && counts.Opens == 1 && counts.Closes == 1 && counts.Gets > 0, "canonical tip cursor counters: %+v/%v", counts, err)
	if mode == "cursor_eio" {
		logicalMDBXAssert(t, counts.Queries == 1 && counts.Faults == 1 && counts.Gets == 1, "canonical tip cursor fault: %+v", counts)
	}
}

func candidateAuthorityIO(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, _ := s.body(t, 1, 1)
	w := s.world
	var reads mdbx.SelectedDamageEvidence
	var fixtureErr, outer error
	cursors, err := mdbx.FixtureCanonicalTipStep(w.s, 1, nil, nil, false, func() {
		reads, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 0, []byte{2}, func() {
			outer = w.s.View(func(r *mdbx.Reader) error {
				root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
				logicalMDBXAssert(t, root == [32]byte{}, "authority refusal returned digest %x", root)
				candidateEIO(t, err, "get")
				candidateInactiveReader(t, r)
				return err
			})
		})
	})
	candidateTerminalView(t, w, outer)
	logicalMDBXAssert(t, err == nil && fixtureErr == nil && cursors == (mdbx.CanonicalTipStepFixtureEvidence{}) && reads.Faults == 1 && reads.OldGets[0] == 1,
		"authority reached tip or wrong read: %+v/%+v/%v/%v", reads, cursors, fixtureErr, err)
}

func candidateAuthorityIntegrity(t *testing.T, value []byte) {
	t.Helper()
	s := newCandidateScene(t, 5)
	in, _ := s.body(t, 1, 1)
	w := s.world
	candidateRawRow(t, w, 0, []byte{2}, value)
	var outer error
	counts, err := mdbx.FixtureCanonicalTipStep(w.s, 1, nil, nil, false, func() {
		outer = w.s.View(func(r *mdbx.Reader) error {
			root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
			logicalMDBXAssert(t, root == [32]byte{}, "authority integrity returned digest %x", root)
			engine := candidateEngine(t, err, "get", "Integrity", -30796, "invalid tree native representation")
			logicalMDBXAssert(t, (engine.Cause != nil) == (value != nil), "authority error cause: %v", engine)
			candidateInactiveReader(t, r)
			return err
		})
	})
	logicalMDBXAssert(t, err == nil && counts == (mdbx.CanonicalTipStepFixtureEvidence{}), "damaged authority reached tip: %+v/%v", counts, err)
	candidateTerminalView(t, w, outer)
}

func candidateWrongDatabase(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, _ := s.body(t, 1, 1)
	in.Selection.DatabaseID[0] = 8
	w := s.world
	evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 0, []byte{2}, func() {
		candidateView(t, w, func(r *mdbx.Reader) {
			root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
			logicalMDBXAssert(t, root == [32]byte{}, "wrong database returned digest %x", root)
			candidateEngine(t, err, "update", "InvalidInput", 22, "invalid tree delta")
			candidateReadControl(t, r)
		})
	})
	candidateUnreached(t, evidence, err)
	logicalMDBXAssert(t, evidence.OldGets[0] == 1 && evidence.OldGets[1] == 0, "invalid database reached authority: %+v", evidence)
}

func candidateEmptyControl(t *testing.T) {
	cfg := mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}
	store, err := mdbx.CreateTreeV1(filepath.Join(t.TempDir(), "empty"), cfg, [32]byte{7})
	logicalMDBXAssert(t, err == nil, "empty tree: %v", err)
	t.Cleanup(func() { _ = store.Close() })
	owner, err := mdbx.NewOperationReservationOwner(805306368)
	logicalMDBXAssert(t, err == nil, "empty owner: %v", err)
	w := &btWorld{s: store, owner: owner}
	parent := mdbx.TreeEndpointV1{Kind: 1, BlockHash: [32]byte{9}, CumulativeChainwork: [40]byte{39: 1}}
	raw, _ := candidateFrame(t, parent, 1)
	in := candidateInput(t, raw, parent)
	candidateView(t, w, func(r *mdbx.Reader) {
		root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
		logicalMDBXAssert(t, root == [32]byte{} && errors.Is(err, mdbx.ErrCandidateSourceUnavailable), "exact empty returned %x/%v", root, err)
		candidateReadControl(t, r)
	})
	id := [32]byte{8}
	candidateRawRow(t, w, 0, []byte{3}, id[:])
	outer := w.s.View(func(r *mdbx.Reader) error {
		root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
		logicalMDBXAssert(t, root == [32]byte{}, "damaged empty control returned digest %x", root)
		candidateEngine(t, err, "get", "Integrity", -30796, "invalid tree native representation")
		candidateInactiveReader(t, r)
		return err
	})
	candidateTerminalView(t, w, outer)
}

func candidateNoIdentityRead(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 1, 1)
	evidence, err := mdbx.FixtureSelectedDamage(s.world.s, s.world.owner, mdbx.SelectedDamageGetEIO, 0, []byte{3}, func() {
		candidateView(t, s.world, func(r *mdbx.Reader) { candidateRootOK(t, r, s.world.owner, in, want) })
	})
	candidateUnreached(t, evidence, err)
	logicalMDBXAssert(t, evidence.OldGets[0] == 3 && evidence.OldGets[1] == 5, "qualified current read shape: %+v", evidence)
}

func TestCandidateRootFixtureResource(t *testing.T) {
	t.Run("w_admit", candidateWAdmission)
	t.Run("d_live", candidateDLive)
	t.Run("d_aggregate", candidateDAggregate)
	t.Run("below_floor", candidateBelowFloor)
	t.Run("next_operation", candidateNextOperation)
	t.Run("no_write", candidateNoWrite)
}

func candidateCapacity(t *testing.T, r *mdbx.Reader, owner *mdbx.OperationReservationOwner, in CandidateRootInput) {
	t.Helper()
	got, err := DeriveCandidateUTXORootV1(r, owner, in)
	logicalMDBXAssert(t, got == [32]byte{} && mdbx.IsOperationReservationCapacity(err), "capacity returned %x/%v", got, err)
}

func candidateFill(owner *mdbx.OperationReservationOwner, amount uint64, entered *uint64, use func() error) error {
	if amount == 0 {
		return use()
	}
	shard := min(amount, 154611183)
	return owner.WithReservation(shard, func() error {
		(*entered)++
		return candidateFill(owner, amount-shard, entered, use)
	})
}

func candidateWAdmission(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, _ := s.body(t, 1, 1)
	w := candidateW(uint64(len(in.Raw)), 5, 0)
	for _, limit := range []uint64{805306368, 1073741824} {
		owner, err := mdbx.NewOperationReservationOwner(limit)
		logicalMDBXAssert(t, err == nil, "candidate aggregate owner: %v", err)
		for _, short := range []uint64{0, 1} {
			evidence, err := mdbx.FixturePairReadObservation(s.world.s, nil, func() {
				candidateView(t, s.world, func(r *mdbx.Reader) {
					var shards uint64
					preheld := limit - w + short
					err := candidateFill(owner, preheld, &shards, func() error {
						candidateCapacity(t, r, owner, in)
						logicalMDBXAssert(t, mdbx.FixtureReservationLive(owner) == preheld, "W refusal changed continuing bytes")
						return nil
					})
					logicalMDBXAssert(t, err == nil && shards > 0, "candidate W competing shards: %v", err)
				})
			})
			logicalMDBXAssert(t, err == nil && evidence.Gets == 1-short && evidence.Writes == 0, "W admission at short=%d: %+v/%v", short, evidence, err)
		}
	}
}

func candidateDLive(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		spends                int
		get, events, keyBytes uint64
	}{{"present_keys", 1, 8, 3, 108}, {"no_present_keys", 0, 5, 1, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s := newCandidateScene(t, 5)
			in, want := s.body(t, tc.spends, 1)
			owner := s.world.owner
			const continuing = 127
			expected := continuing + uint64(len(in.Raw)) + 4096 + tc.keyBytes + 288440 + 104*tc.events
			gets, live := uint64(0), uint64(0)
			counts, err := mdbx.FixturePairReadObservation(s.world.s, func(site uint32) {
				if site == 1 {
					gets++
					if gets == tc.get {
						live = mdbx.FixtureReservationLive(owner)
					}
				}
			}, func() {
				err := owner.WithReservation(continuing, func() error {
					candidateView(t, s.world, func(r *mdbx.Reader) { candidateRootOK(t, r, owner, in, want) })
					logicalMDBXAssert(t, mdbx.FixtureReservationLive(owner) == continuing, "D return changed continuing bytes")
					return nil
				})
				logicalMDBXAssert(t, err == nil, "D continuing hold: %v", err)
			})
			logicalMDBXAssert(t, err == nil && live == expected && counts.Gets >= tc.get && counts.Writes == 0, "D live at get %d: %d want %d, counts %+v/%v", tc.get, live, expected, counts, err)
			fault := newCandidateScene(t, 5)
			logicalMDBXAssert(t, fault.parent == in.Selection.Parent, "binding fault parent differs from observed parent")
			candidateBindingIO(t, fault.world, in, tc.get)
		})
	}
}

func candidateBindingIO(t *testing.T, w *btWorld, in CandidateRootInput, atGet uint64) {
	t.Helper()
	var viewErr, fixtureErr error
	var selected mdbx.SelectedDamageEvidence
	counts, observationErr := mdbx.FixturePairReadObservation(w.s, nil, func() {
		selected, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 0, btMeta(17, 1), func() {
			viewErr = w.s.View(func(r *mdbx.Reader) error {
				root, err := DeriveCandidateUTXORootV1(r, w.owner, in)
				logicalMDBXAssert(t, root == [32]byte{}, "binding I/O returned digest %x", root)
				candidateEIO(t, err, "update")
				candidateInactiveReader(t, r)
				return err
			})
		})
	})
	candidateTerminalView(t, w, viewErr)
	logicalMDBXAssert(t, observationErr == nil && fixtureErr == nil && counts.Gets == atGet && selected.Faults == 1 && selected.OldGets[0] == 3 && selected.NodeGets == 0,
		"binding I/O reached get %d not %d: %+v/%v/%v", counts.Gets, atGet, selected, fixtureErr, observationErr)
}

type candidateAggregateProbe struct {
	gets, live, inside, after, entered uint64
	err                                error
}

func (p *candidateAggregateProbe) observe(owner *mdbx.OperationReservationOwner, limit, expected, excess uint64, site uint32) {
	if site != 1 {
		return
	}
	p.gets++
	if p.gets != 8 {
		return
	}
	p.live = mdbx.FixtureReservationLive(owner)
	p.err = candidateFill(owner, limit-expected+excess, &p.entered, func() error {
		p.inside = mdbx.FixtureReservationLive(owner)
		return nil
	})
	p.after = mdbx.FixtureReservationLive(owner)
}

func candidateDAggregate(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 1, 1)
	expected := uint64(len(in.Raw)) + 4096 + 108 + 288752
	for _, limit := range []uint64{805306368, 1073741824} {
		owner, err := mdbx.NewOperationReservationOwner(limit)
		logicalMDBXAssert(t, err == nil, "aggregate owner: %v", err)
		for _, excess := range []uint64{0, 1} {
			p := &candidateAggregateProbe{}
			counts, err := mdbx.FixturePairReadObservation(s.world.s, func(site uint32) {
				p.observe(owner, limit, expected, excess, site)
			}, func() {
				candidateView(t, s.world, func(r *mdbx.Reader) { candidateRootOK(t, r, owner, in, want) })
			})
			last := (limit - expected + excess + 154611182) / 154611183
			logicalMDBXAssert(t, err == nil && counts.Gets >= 8 && p.live == expected && p.after == expected && p.entered == last-excess,
				"D probe %d/%d: %+v/%+v/%v", limit, excess, p, counts, err)
			if excess == 0 {
				logicalMDBXAssert(t, p.err == nil && p.inside == limit, "D aggregate equality: %+v", p)
			} else {
				logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(p.err) && p.inside == 0, "D aggregate excess: %+v", p)
			}
			logicalMDBXAssert(t, mdbx.FixtureReservationLive(owner) == 0, "D aggregate owner leaked reservation")
		}
	}
}

func candidateBelowFloor(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 1, 1)
	owner, err := mdbx.NewOperationReservationOwner(805306367)
	logicalMDBXAssert(t, err == nil, "below-floor owner: %v", err)
	candidateView(t, s.world, func(r *mdbx.Reader) {
		candidateCapacity(t, r, owner, in)
		candidateCapacity(t, r, owner, in)
		candidateRootOK(t, r, s.world.owner, in, want)
	})
	logicalMDBXAssert(t, mdbx.FixtureReservationLive(owner) == 0, "below-floor admission leaked bytes")
}

func candidateNextOperation(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 1, 1)
	owner := s.world.owner
	candidateView(t, s.world, func(r *mdbx.Reader) {
		var entered uint64
		fill := uint64(805306368) - candidateW(uint64(len(in.Raw)), 5, 0) + 1
		err := candidateFill(owner, fill, &entered, func() error {
			for range 2 {
				candidateCapacity(t, r, owner, in)
				logicalMDBXAssert(t, mdbx.FixtureReservationLive(owner) == fill, "refusal changed competing owner")
			}
			return nil
		})
		logicalMDBXAssert(t, err == nil && mdbx.FixtureReservationLive(owner) == 0, "competing release: %v", err)
		candidateRootOK(t, r, owner, in, want)
		logicalMDBXAssert(t, mdbx.FixtureReservationLive(owner) == 0, "next root leaked bytes")
	})
}

func candidateNoWrite(t *testing.T) {
	s := newCandidateScene(t, 5)
	in, want := s.body(t, 1, 1)
	w := s.world
	evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
		const continuing = 127
		err := w.owner.WithReservation(continuing, func() error {
			candidateView(t, w, func(r *mdbx.Reader) {
				for range 2 {
					candidateRootOK(t, r, w.owner, in, want)
					logicalMDBXAssert(t, mdbx.FixtureReservationLive(w.owner) == continuing, "candidate changed continuing bytes")
				}
			})
			return nil
		})
		logicalMDBXAssert(t, err == nil && mdbx.FixtureReservationLive(w.owner) == 0, "continuing hold release: %v", err)
	})
	logicalMDBXAssert(t, err == nil && evidence.BeginOld == 1 && evidence.OldGets[0] == 6 && evidence.NodeGets > 0 && evidence.OldAborts == 1,
		"candidate native read path: %+v/%v", evidence, err)
	candidateNoNativeWrite(t, evidence)
}

//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// TestInitial148CompleteBlockFixtureAdmission runs the composer under the
// fixture build against a read-only Store.View owner inside an existing
// TreeOperation account: a steps 1-12 rejection delivers no result, keeps the
// exact error and has no D evidence. The UpdateTreeV1 no-operation/no-write
// case is TestInitial148CompleteBlockUpdateTreeFailuresH5.
func TestInitial148CompleteBlockFixtureAdmission(t *testing.T) {
	w := btNew(t)
	in := icbInputV1()
	want := icbStepsErrorV1(t, in)
	icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
		out, err := withInitial148CompleteBlockV1(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			return w.s.View(func(reader *mdbx.Reader) error {
				result, verr := validate(reader)
				logicalMDBXAssert(t, result == nil, "rejected candidate delivered a result")
				return verr
			})
		})
		logicalMDBXAssert(t, out.attempted && err != nil && err.Error() == want.Error() && !out.required.derived && !out.required.hasObservation, "fixture rejection: %+v / %v", out, err)
	})
}

// TestInitial148CompleteBlockReadFailureH5 (C04, C08) arms one native EIO on
// tx2's parent row B in the h=5 fixture. Selected, that unavailable read is a
// no-result keeping the raw engine cause, never a TxError or mismatch; an
// earlier queued invalid signature in tx1 is selected over it; a definitive
// absence at tx1 stays TX_ERR_MISSING_UTXO with no D.
func TestInitial148CompleteBlockReadFailureH5(t *testing.T) {
	for _, workers := range []int{-1, 1, 4} {
		for _, c := range []struct {
			name string
			opts icbH5OptsV1
		}{
			{"unavailable-selected", icbH5OptsV1{flip: 1}},
			{"earlier-queued-sig-over-later-sticky-read", icbH5OptsV1{badSig: true, flip: 1}},
		} {
			w := btNew(t)
			f := icbH5VariantV1(t, w, c.opts)
			var got icbObservedV1
			counts, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 1, btUTXOKey(1, f.b), func() {
				got = icbObserveV1(t, w, f.in, workers)
			})
			// Sequentially tx1's signature fails before tx2 reads B, so the armed
			// site is never reached; the queued entries read B and fault once.
			sequentialEarlier := c.opts.badSig && workers < 0
			reached := fixtureErr == nil && counts.Faults == 1
			unreached := counts.Faults == 0 && fixtureErr != nil && fixtureErr.Error() == icbSiteNotReachedV1
			logicalMDBXAssert(t, counts.Commits == 0 && (reached != sequentialEarlier) && (reached || unreached), "%s workers=%d fixture: %+v / %v", c.name, workers, counts, fixtureErr)
			// The enclosing View returns the native reader's sticky fault joined
			// to the callback error; the outer entry keeps that run error and the
			// selected validation error separately.
			verr := got.out.validationErr
			logicalMDBXAssert(t, got.out.attempted && verr != nil && errors.Is(got.err, verr) && got.summary == (BlockBasicSummary{}), "%s workers=%d result delivered: err=%v verr=%v %+v", c.name, workers, got.err, verr, got.summary)
			var txErr *TxError
			if c.opts.badSig {
				ok := errors.As(verr, &txErr) && any(txErr) == any(verr)
				logicalMDBXAssert(t, ok && txErr.Code == TX_ERR_SIG_INVALID && txErr.Msg == "CORE_P2PK signature invalid", "%s workers=%d earlier error lost: %v", c.name, workers, verr)
				logicalMDBXAssert(t, got.out.required == (initial148RootReadOutcomeV1{}), "%s workers=%d later read recorded: %+v", c.name, workers, got.out.required)
				continue
			}
			logicalMDBXAssert(t, counts.Faults == 1 && !errors.As(verr, &txErr), "%s workers=%d unavailable became %v (faults %d)", c.name, workers, verr, counts.Faults)
			_ = btfEngine(t, got.out.required.cause, "get", mdbx.EngineIO, 5, "error 5")
			logicalMDBXAssert(t, (any(verr) == any(got.out.required.cause) || icbWrapsCauseV1(verr, got.out.required.cause)) && !got.out.required.derived && got.out.required.root == ([32]byte{}), "%s workers=%d raw cause tuple: %v / %+v", c.name, workers, verr, got.out.required)
		}
		w := btNew(t)
		f := icbH5VariantV1(t, w, icbH5OptsV1{missing: true, flip: 1})
		got := icbObserveV1(t, w, f.in, workers)
		var txErr *TxError
		logicalMDBXAssert(t, errors.As(got.err, &txErr) && txErr.Code == TX_ERR_MISSING_UTXO && txErr.Msg == "utxo not found" && got.out.required == (initial148RootReadOutcomeV1{}), "workers=%d absence: %v / %+v", workers, got.err, got.out.required)
	}
}

// TestInitial148CompleteBlockRowIntegrityH5 (C08) damages persisted state the
// selected R/cap reads consume, each paired with a bad header root: a
// malformed complete parent row B, an active cap over a valid counter
// envelope inconsistent with the present rows, and both together (row
// integrity is classified before the cap's counter arithmetic). Each is a
// store-integrity no-result keeping its raw cause; no TxError, mismatch, D
// or result.
func TestInitial148CompleteBlockRowIntegrityH5(t *testing.T) {
	for _, c := range []struct {
		name          string
		row, counters bool
		text          string
	}{
		{name: "malformed-row", row: true, text: "invalid MDBX SchemaV2 bytes"},
		{name: "inconsistent-counters", counters: true, text: "required subset exceeds parent counters"},
		{name: "row-before-counters", row: true, counters: true, text: "invalid MDBX SchemaV2 bytes"},
	} {
		for _, workers := range []int{-1, 1, 4} {
			w := btNew(t)
			f := icbH5VariantV1(t, w, icbH5OptsV1{flip: 1})
			if c.row {
				// B's complete row with an invalid coinbase flag byte (2).
				value := btValue(btFrame(2000, COV_TYPE_P2PK, f.created[f.o2].CovenantData), f.h-1, false)
				value[len(value)-1] = 2
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 1, btUTXOKey(1, f.b), value) == nil, "malformed row setup")
			}
			if c.counters {
				icbCapAtV1(&f.in, icbHeightV1)
				irCounterV1(t, w, 89, 1)
			}
			got := icbObserveV1(t, w, f.in, workers)
			var failure *logicalStateFailure
			var read *blockInputViewReadError
			var txErr *TxError
			required := got.out.required
			if errors.As(got.err, &read) {
				failure = read.failure
			} else {
				_ = errors.As(got.err, &failure)
			}
			selected := failure != nil && failure.kind == logicalStateFailureStoreIntegrity && failure.cause.Error() == c.text
			logicalMDBXAssert(t, selected && icbWrapsCauseV1(got.err, required.cause) && !errors.As(got.err, &txErr), "%s workers=%d: %T %v", c.name, workers, got.err, got.err)
			logicalMDBXAssert(t, any(got.out.validationErr) == any(got.err) && got.summary == (BlockBasicSummary{}) && !required.derived && required.root == ([32]byte{}), "%s workers=%d no-result tuple: %+v", c.name, workers, required)
		}
	}
}

// icbSiteNotReachedV1 is FixtureSelectedDamage's exact error when run ran but
// the armed site was never read (internal/mdbx/mdbx_fixture_cgo.go); its two
// pre-run refusals carry different texts.
const icbSiteNotReachedV1 = "selected damage fixture site was not reached exactly as armed"

// icbParentBindingV1 reads the generation-1 parent root binding (rank 0) of
// the seeded h=5 image and the rank-8 key of the root node it names.
func icbParentBindingV1(t *testing.T, w *btWorld) (mdbx.RootBindingV1, []byte) {
	t.Helper()
	var raw []byte
	logicalMDBXAssert(t, w.s.View(func(reader *mdbx.Reader) error {
		value, _, err := reader.Get(mdbx.TreeSchemaV1DBIs()[0], btMeta(0x11, 1))
		raw = bytes.Clone(value)
		return err
	}) == nil, "binding read")
	binding, err := mdbx.DecodeRootBindingV1(raw)
	logicalMDBXAssert(t, err == nil && binding.Top.Node != nil, "parent binding top: %v", err)
	node, err := mdbx.TreeNodeKey(1, *binding.Top.Node)
	logicalMDBXAssert(t, err == nil, "node key: %v", err)
	return binding, node
}

// icbDeriveDamageV1 arms or applies one D-only native fault after the parent
// seed and observes in through one entry. R reads only UTXO rows and
// counters; D alone reads the root binding and the tree nodes.
// The second result is the rank-8 key of the node that D reads first.
func icbDeriveDamageV1(t *testing.T, w *btWorld, f icbH5V1, damage string, workers int) (icbObservedV1, []byte) {
	t.Helper()
	binding, node := icbParentBindingV1(t, w)
	var got icbObservedV1
	observe := func() { got = icbObserveV1(t, w, f.in, workers) }
	eio := func(rank uint8, key []byte) {
		counts, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, rank, key, observe)
		logicalMDBXAssert(t, err == nil && counts.Faults == 1 && counts.Commits == 0, "%s workers=%d fixture: %+v / %v", damage, workers, counts, err)
	}
	switch damage {
	case "binding-eio":
		eio(0, btMeta(0x11, 1))
		return got, node
	case "node-eio":
		eio(8, node)
		return got, node
	case "node-malformed":
		// The existing rank-8 drift helper persists 0x7f as the root node row.
		btfDamage(t, w, 8, node, "malformed")
	case "binding-top-outside-inputs":
		// A identifies only the first actual parent input; B is a distinct
		// actual premise, independently of their shared Txid/prefix.
		logicalMDBXAssert(t, f.a != f.b, "fixture parent inputs must differ")
		id := mdbx.TreeNodeIDV1{Kind: mdbx.TreeNodeLeafV1, Depth: 288, RoutingKey: [36]byte(btUTXOKey(1, f.a)[8:])}
		binding.Top = mdbx.TreeTopV1{Kind: mdbx.TreeTopLeafV1, Node: &id}
		value, err := binding.Encode()
		logicalMDBXAssert(t, err == nil && mdbx.FixtureSeedRawRow(w.s, 0, btMeta(0x11, 1), value) == nil, "rebind top: %v", err)
		counts, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, observe)
		logicalMDBXAssert(t, fixtureErr == nil && counts.NodeGets == 0 && counts.Faults == 0 && counts.BeginWrite == 0 && counts.Commits == 0 && counts.Deletes == 0 && counts.NodePulls == 0 && counts.OldPulls == ([8]uint64{}), "binding identity must refuse before rank8: %+v / %v", counts, fixtureErr)
		return got, node
	case "binding-absent":
		logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 0, btMeta(0x11, 1)) == nil, "delete binding")
	case "binding-malformed":
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 0, btMeta(0x11, 1), []byte{0xff}) == nil, "malform binding")
	case "binding-endpoint":
		// A well-formed binding whose parent block hash differs from the selected parent.
		binding.Endpoint.BlockHash[0] ^= 0x01
		value, err := binding.Encode()
		logicalMDBXAssert(t, err == nil && mdbx.FixtureSeedRawRow(w.s, 0, btMeta(0x11, 1), value) == nil, "rebind endpoint: %v", err)
	}
	observe()
	return got, node
}

// icbNodeKeyV1 is the observed key projection for a rank-8 node key.
func icbNodeKeyV1(o mdbx.TreeObservationV1, key []byte) bool {
	return int(o.KeyLength) == len(key) && bytes.Equal(o.Key[:o.KeyLength], key)
}

// TestInitial148CompleteBlockDeriveFailureH5 (C10) makes only the fresh D of
// the root-valid h=5 block fail, through the sequential entry and the queued
// entry with one and four workers: a native EIO on the root binding or root
// node (unavailable: no observation), a Top leaf excluding actual input B
// (unobserved integrity before rank8), and an absent, malformed or
// endpoint-inconsistent parent root binding (localized integrity with its
// observation). Each keeps the raw D cause as the validation error,
// derived=false, a zero root and no delivered result; none is a mismatch.
func TestInitial148CompleteBlockDeriveFailureH5(t *testing.T) {
	cases := []struct {
		damage string
		kind   mdbx.TreeObservationKindV1
		rank   uint8
	}{
		{"binding-top-outside-inputs", 0, 0},
		{"binding-eio", 0, 0},
		{"node-eio", 0, 8},
		{"binding-absent", mdbx.TreeObservationAbsentV1, 0},
		{"binding-malformed", mdbx.TreeObservationMalformedV1, 0},
		{"binding-endpoint", mdbx.TreeObservationIdentityMismatchV1, 0},
		{"node-malformed", mdbx.TreeObservationMalformedV1, 8},
	}
	for _, c := range cases {
		for _, workers := range []int{-1, 1, 4} {
			w := btNew(t)
			f := icbH5FixtureV1(t, w)
			got, node := icbDeriveDamageV1(t, w, f, c.damage, workers)
			req, verr := got.out.required, got.out.validationErr
			var txErr *TxError
			logicalMDBXAssert(t, got.out.attempted && verr != nil && !errors.As(verr, &txErr) && got.summary == (BlockBasicSummary{}), "%s workers=%d no-result: err=%v verr=%v", c.damage, workers, got.err, verr)
			logicalMDBXAssert(t, any(req.cause) == any(verr) && !req.derived && req.root == ([32]byte{}), "%s workers=%d raw D cause: %v / %+v", c.damage, workers, verr, req)
			var engine *mdbx.EngineError
			logicalMDBXAssert(t, errors.As(req.cause, &engine) && any(engine) == any(req.cause), "%s workers=%d cause is not the raw native error: %T %v", c.damage, workers, req.cause, req.cause)
			if c.kind == 0 {
				if c.damage == "binding-top-outside-inputs" {
					_ = btfEngine(t, req.cause, "update", mdbx.EngineIntegrity, -30796, "invalid tree native representation")
					logicalMDBXAssert(t, any(got.err) == any(verr) && engine.Cause == nil && !engine.ReopenRequired && engine.TreeObservation == nil && !req.hasObservation && req.observation == (mdbx.TreeObservationV1{}), "%s workers=%d semantic no-result: %+v", c.damage, workers, req)
					continue
				}
				logicalMDBXAssert(t, engine.Class == mdbx.EngineIO && !req.hasObservation && req.observation == (mdbx.TreeObservationV1{}), "%s workers=%d unavailable fabricated observation: %+v", c.damage, workers, req)
				continue
			}
			o := req.observation
			logicalMDBXAssert(t, engine.Class == mdbx.EngineIntegrity && req.hasObservation && engine.TreeObservation != nil && o == *engine.TreeObservation, "%s workers=%d observation lost: %+v", c.damage, workers, req)
			// Observation identity: database 7, generation 1, this block at h=5, writer position 1, the damaged rank.
			same := o.DatabaseID == [32]byte{7} && o.Generation == 1 && o.Block == f.in.Endpoint.BlockHash && o.Height == icbHeightV1 && o.Position == 1 && o.Rank == c.rank && o.Kind == c.kind
			logicalMDBXAssert(t, same, "%s workers=%d observation %+v", c.damage, workers, o)
			if c.rank == 8 {
				// The drifted root node keeps the schema cause for a short record.
				logicalMDBXAssert(t, icbNodeKeyV1(o, node), "%s workers=%d node key %x want %x", c.damage, workers, o.Key, node)
				wantCause := engine.Cause == nil
				if c.kind == mdbx.TreeObservationMalformedV1 {
					wantCause = engine.Cause != nil && engine.Cause.Error() == "invalid MDBX SchemaV2 bytes"
				}
				logicalMDBXAssert(t, wantCause && engine.Operation == "update" && engine.Code == -30796 && engine.Diagnostic == "invalid tree native representation" && !engine.ReopenRequired, "%s workers=%d node cause %+v", c.damage, workers, engine)
			}
		}
	}
}

// TestInitial148CompleteBlockGenesisPersistedStateH0 (C07, C08) admits the
// published genesis over a store that already holds generation-1 parent
// state: an applied h=4 block's UTXO rows, root binding, tree nodes and
// counters. One native EIO is armed in turn on a persisted UTXO row, the
// counters, the root binding and its top node: none is reached (no parent
// read). Then the counters, the binding, the top node and the row are all
// made malformed. With the cap active from height 0 every run accepts with
// the literal genesis root and GeneratedN1 zero.
func TestInitial148CompleteBlockGenesisPersistedStateH0(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		_, _, tx1 := icbSeedV1(t, w, validP2PKCovenantData(), icbHeightV1)
		row := btUTXOKey(1, Outpoint{Txid: tx1.id})
		_, node := icbParentBindingV1(t, w)
		in, _ := icbGenesisInputV1(t, -1)
		icbCapAtV1(&in, 0)
		literal := icbGenesisRootV1(t, in.Raw)
		accept := func(label string) {
			t.Helper()
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				out, delivered, got, err := icbValidateOnceV1(t, w, account, in, parallel)
				logicalMDBXAssert(t, err == nil && out.validationErr == nil && delivered != nil, "%s parallel=%v genesis over persisted state: %v / %+v", label, parallel, err, out)
				logicalMDBXAssert(t, out.required.derived && out.required.cause == nil && out.required.root == literal && got.transition.alreadyGeneratedN1 == (Uint128{}), "%s parallel=%v h0 tuple: %+v", label, parallel, out.required)
			})
		}
		for _, site := range []struct {
			name string
			rank uint8
			key  []byte
		}{
			{"utxo-row", 1, row},
			{"counters", 0, btMeta(0x10, 1)},
			{"root-binding", 0, btMeta(0x11, 1)},
			{"top-node", 8, node},
		} {
			ran := 0
			counts, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, site.rank, site.key, func() { ran++; accept(site.name) })
			unreached := fixtureErr != nil && fixtureErr.Error() == icbSiteNotReachedV1
			logicalMDBXAssert(t, ran == 1 && unreached && counts.Faults == 0 && counts.Commits == 0, "%s parallel=%v persisted parent site was read (ran %d): %+v / %v", site.name, parallel, ran, counts, fixtureErr)
		}
		btfDamage(t, w, 8, node, "malformed")
		irCounterV1(t, w, 1, 1)
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 0, btMeta(0x11, 1), []byte{0xff}) == nil, "malform binding")
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 1, row, []byte{0xff}) == nil, "malform row")
		accept("malformed-parent-state")
	}
}

// TestInitial148CompleteBlockUpdateTreeReadbackH5 (C13 readback) is
// TestInitial148CompleteBlockUpdateTreeH5 with the commit armed to report a
// failure after it crossed (SelectedDamageCommitNew): the native truth
// evaluator replays the source at TreeReadbackV1, so the writer and the
// readback each consume it exactly once through a fresh Reader after the
// builder's Reader expired, with retained M held; the outer error is the native
// *CommitError (truth New) returned by run, never a validation projection;
// the Store is consumed with that terminal error and, reopened, holds the
// final rows.
func TestInitial148CompleteBlockUpdateTreeReadbackH5(t *testing.T) {
	for name, parallel := range map[string]bool{"sequential": false, "parallel": true} {
		w := btNew(t)
		f := icbH5FixtureV1(t, w)
		var got icbUpdateTreeV1
		counts, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageCommitNew, 0, nil, func() {
			got = icbUpdateTreeH5V1(t, w, f, parallel)
		})
		logicalMDBXAssert(t, fixtureErr == nil && counts.Commits == 1, "%s fixture: %+v / %v", name, counts, fixtureErr)
		var commitErr *mdbx.CommitError
		logicalMDBXAssert(t, errors.As(got.native.err, &commitErr) && any(commitErr) == any(got.native.err) && commitErr.Truth == mdbx.CommitTruthNew, "%s native commit error: %v", name, got.native.err)
		got.check(t, f, name, got.native.err, [3]int{0, 1, 1})
		// The crossed commit consumes the Store with that same terminal error.
		terminal := w.s.View(func(*mdbx.Reader) error { return nil })
		logicalMDBXAssert(t, any(terminal) == any(got.native.err), "%s Store terminal %v", name, terminal)
		w.reopen(t)
		icbFinalRowsH5V1(t, w, f)
	}
}

// icbHistoryBlockV1 binds actual transaction outpoints, independent root and
// subsidy state for one validated source-history block.
type icbHistoryBlockV1 struct {
	in   initial148CompleteBlockInputV1
	root [32]byte
	rows map[Outpoint]UtxoEntry
}

func icbHistorySignV1(t *testing.T, kp *MLDSA87Keypair, chain [32]byte, tx *Tx, value uint64) []byte {
	t.Helper()
	for i := range tx.Inputs {
		digest, err := SighashV1DigestWithType(tx, uint32(i), value, chain, SIGHASH_ALL)
		logicalMDBXAssert(t, err == nil, "history sighash: %v", err)
		sig, err := kp.SignDigest32(digest)
		logicalMDBXAssert(t, err == nil, "history signature: %v", err)
		tx.Witness[i] = WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Signature: append(sig, SIGHASH_ALL)}
	}
	return icbSignedRawV1(t, tx)
}

// icbHistoryTransactionsV1 spends only TxCore identifiers from the validated
// history; h101 fans eight matured h1 payouts into 8192 actual outputs.
func icbHistoryTransactionsV1(t *testing.T, h uint64, kp *MLDSA87Keypair, chain [32]byte, rows map[Outpoint]UtxoEntry) [][]byte {
	t.Helper()
	if h != 101 && h != 102 {
		return nil
	}
	var keys []Outpoint
	for key, row := range rows {
		if h == 101 && row.CreationHeight == 1 || h == 102 && row.CreationHeight == 101 {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a, b Outpoint) int {
		if c := bytes.Compare(a.Txid[:], b.Txid[:]); c != 0 {
			return c
		}
		return int(a.Vout) - int(b.Vout)
	})
	width := 1
	if h == 102 {
		width = 13
	}
	var txs [][]byte
	for i := 0; i < len(keys); i += width {
		ops := keys[i:min(i+width, len(keys))]
		tx := inputViewTx(uint64(i+1), ops...)
		if h == 101 {
			tx.Outputs = slices.Repeat([]TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}}, 1024)
		} else {
			tx.Outputs[0].Value = uint64(len(ops))
		}
		txs = append(txs, icbHistorySignV1(t, kp, chain, tx, rows[ops[0]].Value))
	}
	logicalMDBXAssert(t, h == 101 && len(txs) == 8 || h == 102 && len(txs) == 631, "history h%d transaction count%d", h, len(txs))
	return txs
}

func icbHistoryRowsV1(t *testing.T, previous map[Outpoint]UtxoEntry, h uint64, txs [][]byte) map[Outpoint]UtxoEntry {
	t.Helper()
	rows := maps.Clone(previous)
	for ordinal, raw := range txs {
		tx, id, _, _, err := ParseTx(raw)
		logicalMDBXAssert(t, err == nil, "history TxCore identifiers: %v", err)
		if ordinal != 0 {
			for _, in := range tx.Inputs {
				key := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
				_, present := rows[key]
				logicalMDBXAssert(t, present, "history spends nonexistent outpoint: %+v", key)
				delete(rows, key)
			}
		}
		for i, out := range tx.Outputs {
			if out.CovenantType == COV_TYPE_ANCHOR {
				continue
			}
			rows[Outpoint{Txid: id, Vout: uint32(i)}] = UtxoEntry{Value: out.Value, CovenantType: out.CovenantType, CovenantData: bytes.Clone(out.CovenantData), CreationHeight: h, CreatedByCoinbase: ordinal == 0}
		}
	}
	return rows
}

func icbHistoryRootV1(rows map[Outpoint]UtxoEntry) [32]byte {
	leaves := map[[36]byte][]byte{}
	for key, row := range rows {
		icbLeafKindV1(leaves, key, row.Value, row.CovenantType, row.CovenantData, row.CreationHeight, row.CreatedByCoinbase)
	}
	return icbRootV1(leaves)
}

func icbHistoryV1(t *testing.T, genesis PublishedGenesisContextV1) []icbHistoryBlockV1 {
	t.Helper()
	kp := icbKeyV1(t)
	rows := icbHistoryRowsV1(t, map[Outpoint]UtxoEntry{}, 0, [][]byte{genesis.Published[149:]})
	parent := mdbx.TreeEndpointV1{Kind: 1, BlockHash: genesis.GenesisHash, CumulativeChainwork: [40]byte{39: 1}}
	generated := Uint128{}
	times := []uint64{initial148GenesisTimestamp}
	var history []icbHistoryBlockV1
	for height := uint64(1); height <= 102; height++ {
		txs := icbHistoryTransactionsV1(t, height, kp, genesis.ChainID, rows)
		commit := initial148BlockWitnessCommit(t, txs...)
		outs := []testOutput{{covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]}}
		if height == 1 {
			outs = append(slices.Repeat([]testOutput{{value: 1024, covenantType: COV_TYPE_P2PK, covenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}}, 8), outs...)
		}
		if height == 102 {
			outs = append([]testOutput{{value: 1, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}}, outs...)
		}
		txs = append([][]byte{coinbaseTxWithOutputs(uint32(height), outs)}, txs...)
		rows = icbHistoryRowsV1(t, rows, height, txs)
		root := icbHistoryRootV1(rows)
		raw := initial148BlockFrame(t, txs, func(h *initial148BlockHead) {
			h.parent, h.root, h.timestamp = parent.BlockHash, root, initial148GenesisTimestamp+height
		})
		hash, err := Initial148BlockHash(raw[:148])
		logicalMDBXAssert(t, err == nil, "history hash: %v", err)
		endpoint := mdbx.TreeEndpointV1{Kind: 1, Height: height, BlockHash: hash}
		binary.BigEndian.PutUint64(endpoint.CumulativeChainwork[32:], height+1)
		in := initial148CompleteBlockInputV1{
			Raw: raw, Height: height, ParentHash: parent.BlockHash, ExpectedTarget: POW_LIMIT, ChainID: genesis.ChainID,
			DatabaseID: [32]byte{7}, Generation: 1, ParentTimestamps: slices.Clone(times[max(0, len(times)-11):]), AlreadyGenerated: generated,
			Parent: parent, Endpoint: endpoint, CapRegistry: &validatedLogicalStateCapRegistry{}, Registry: DefaultSuiteRegistry(), Rotation: icbFrozenV1(height),
		}
		history = append(history, icbHistoryBlockV1{in: in, root: root, rows: rows})
		generated, err = checkedAdvanceAlreadyGenerated(height, generated, generated.Big())
		logicalMDBXAssert(t, err == nil, "history generated scalar: %v", err)
		parent, times = endpoint, append(times, initial148GenesisTimestamp+height)
	}
	return history
}

// icbHistoryApplyV1 validates inside the actual public builder. Filler starts
// only after validation/M reduction and its holder is released and joined
// before the account closes; the observer records Source once per position.
func icbHistoryApplyV1(t *testing.T, w *fgWorld, block icbHistoryBlockV1, workers int, filler uint64) (btResult, initial148CompleteBlockOutcomeV1, [3]int) {
	t.Helper()
	var got btResult
	var out initial148CompleteBlockOutcomeV1
	var calls [3]int
	var events uint32
	validM := false
	var finish chan struct{}
	var held <-chan error
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		defer func() {
			if finish != nil {
				close(finish)
				logicalMDBXAssert(t, <-held == nil, "history filler cleanup")
			}
		}()
		observed := &icbNativeSourceV1{before: func(pos mdbx.TreePositionV1, _ *mdbx.Reader, _ *mdbx.TreeDeltaSinkV1) error { calls[pos]++; return nil }}
		var runErr error
		out, runErr = icbEntryWorkersV1(workers)(a, block.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			got.truth, got.stage, got.index, got.err = w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
				result, err := validate(r)
				if err != nil {
					return mdbx.TreeOperationV1{}, err
				}
				validM = result != nil && icbHoldsExactlyV1(a, icbMV1(uint64(len(block.in.Raw))))
				if !validM {
					return mdbx.TreeOperationV1{}, errors.New("history M after root differs")
				}
				events = result.effect.Primitive.Coverage.BlockMeta.EventCount
				if filler != 0 {
					ready, done := make(chan error, 1), make(chan error, 1)
					finish, held = make(chan struct{}), done
					go func() {
						err := a.WithReservation(filler, func() error { ready <- nil; <-finish; return nil })
						if err != nil {
							ready <- err
						}
						done <- err
					}()
					if err := <-ready; err != nil {
						return mdbx.TreeOperationV1{}, err
					}
				}
				observed.source = result.effect.Primitive.Source.(*blockTreeSourceV1)
				return icbComposeV1(result, observed, block.in.Raw[:148], false), nil
			})
			return got.err
		})
		logicalMDBXAssert(t, any(runErr) == any(got.err), "history native error identity: %v/%v", runErr, got.err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "history operation: %v", err)
	logicalMDBXAssert(t, validM, "history retained-phase observation")
	logicalMDBXAssert(t, block.in.Height != 102 || events == 8824, "actual history h102 E=%d", events)
	btReservationsReleased(t, w.owner)
	return got, out, calls
}

func icbHistoryReadV1(t *testing.T, w *fgWorld, block icbHistoryBlockV1) {
	t.Helper()
	w.reopen(t)
	logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error {
		binding, present, err := r.ReadTreeRootBindingV1(1)
		logicalMDBXAssert(t, err == nil && present && binding.RootDigest == block.root && binding.Endpoint == block.in.Endpoint, "history reopened root/endpoint: %v", err)
		for key, row := range block.rows {
			value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[1], btUTXOKey(1, key))
			logicalMDBXAssert(t, err == nil && present && bytes.Equal(value, btValue(btFrame(row.Value, row.CovenantType, row.CovenantData), row.CreationHeight, row.CreatedByCoinbase)), "history reopened outpoint %+v", key)
		}
		return nil
	}) == nil, "history reopened rows")
}

// TestInitial148WriterHistoryV1 is A1/R1: actual validated history, both entries,
// definite NEW, forced strict NEW and exact/minus-one writer acquisition.
func TestInitial148WriterHistoryV1(t *testing.T) {
	genesis := fgContext(t, initial148BlockGenesis(t))
	history := icbHistoryV1(t, genesis)
	last := history[101]
	summary, err := ValidateInitial148BlockSteps1To12(last.in.Raw, last.in.ParentHash, last.in.ExpectedTarget, 102, last.in.ParentTimestamps)
	logicalMDBXAssert(t, err == nil && len(last.in.Raw) == 59580771 && summary.SumWeight == 60773472 && summary.TxCount == 632, "actual h102 shape: n=%d %+v/%v", len(last.in.Raw), summary, err)
	for _, workers := range []int{-1, 4} {
		for _, mode := range []string{"NEW", "strict-NEW", "exact", "one-short"} {
			t.Run(fmt.Sprintf("workers%d/%s", workers, mode), func(t *testing.T) {
				w := fgNew(t, [32]byte{7}, 1, 2)
				fgTuple(t, w.call(), "ACCEPTED", 2, 3)
				for _, block := range history[:101] {
					got, out, calls := icbHistoryApplyV1(t, w, block, -1, 0)
					got.want(t, 2, 3, -1)
					logicalMDBXAssert(t, got.err == nil && out.required.root == block.root && calls == [3]int{0, 1, 0}, "validated history h%d: %v/%+v/%v", block.in.Height, got.err, out, calls)
				}
				filler := uint64(0)
				if mode == "exact" || mode == "one-short" {
					n := uint64(len(last.in.Raw))
					// E=8192 spends+631 outputs+one spendable coinbase.
					peak := icbMV1(n) + (n + 892) + n + 2*(288440+104*8824)
					filler = 402653184 - peak
					if mode == "one-short" {
						filler++
					}
				}
				var got btResult
				var out initial148CompleteBlockOutcomeV1
				var calls [3]int
				scenario := mdbx.SelectedDamageProbeOnly
				if mode == "strict-NEW" {
					scenario = mdbx.SelectedDamageCommitNew
				}
				evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, scenario, 0, btMeta(0x11, 1), func() { got, out, calls = icbHistoryApplyV1(t, w, last, workers, filler) })
				logicalMDBXAssert(t, fixtureErr == nil && out.required.derived && out.required.root == last.root, "history selected fixture: %v/%+v", fixtureErr, evidence)
				if mode == "one-short" {
					got.want(t, 1, 2, -1)
					logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(got.err) && evidence.Commits == 0 && evidence.Deletes == 8193 && calls == [3]int{0, 1, 0}, "writer node-work refusal: %v/%+v/%v", got.err, evidence, calls)
					icbHistoryTerminalV1(t, w, got, 1)
					icbHistoryReadV1(t, w, history[100])
					fresh, _, _ := icbHistoryApplyV1(t, w, last, workers, 0)
					fresh.want(t, 2, 3, -1)
					logicalMDBXAssert(t, fresh.err == nil, "reopened fresh operation: %v", fresh.err)
				} else {
					got.want(t, 2, 3, -1)
					wantCalls := [3]int{0, 1, 0}
					if mode == "strict-NEW" {
						wantCalls[2] = 1
						ce, ok := got.err.(*mdbx.CommitError)
						logicalMDBXAssert(t, ok && ce.Truth == 2 && ce.ReadbackCause == nil && evidence.BeginRead == 1, "history strict NEW: %v", got.err)
						icbHistoryTerminalV1(t, w, got, 2)
					} else {
						logicalMDBXAssert(t, got.err == nil, "history definite NEW: %v", got.err)
					}
					logicalMDBXAssert(t, calls == wantCalls && evidence.Commits == 1, "history Source counts %v/%v", calls, wantCalls)
				}
				icbHistoryReadV1(t, w, last)
			})
		}
	}
}

func icbHistoryTerminalV1(t *testing.T, w *fgWorld, got btResult, truth mdbx.CommitTruth) {
	t.Helper()
	calls := 0
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		tr, stage, index, err := w.s.UpdateTreeV1(a, func(*mdbx.Reader) (mdbx.TreeOperationV1, error) { calls++; return mdbx.TreeOperationV1{}, nil })
		logicalMDBXAssert(t, tr == truth && stage == 1 && index == -1 && any(err) == any(got.err) && calls == 0, "history consumed UpdateTree terminal: %v", err)
		return nil
	}) == nil, "history terminal operation")
	err := w.s.View(func(*mdbx.Reader) error { calls++; return nil })
	logicalMDBXAssert(t, any(err) == any(got.err) && calls == 0, "history consumed View terminal")
}

type icbReplayFamilyV1 struct {
	genesis PublishedGenesisContextV1
	prefix  []icbHistoryBlockV1
	block   icbHistoryBlockV1
	old     map[Outpoint]UtxoEntry
	inputs  []mdbx.TreeOutpointV1
	target  mdbx.RecoveryTargetV1
}

// icbReplaySignV1 uses actual ML-DSA signatures with each input's own value.
func icbReplaySignV1(t *testing.T, kp *MLDSA87Keypair, chain [32]byte, tx *Tx, values ...uint64) []byte {
	t.Helper()
	logicalMDBXAssert(t, len(values) == len(tx.Inputs), "replay signature value cardinality")
	for i, value := range values {
		digest, err := SighashV1DigestWithType(tx, uint32(i), value, chain, SIGHASH_ALL)
		logicalMDBXAssert(t, err == nil, "replay sighash: %v", err)
		sig, err := kp.SignDigest32(digest)
		logicalMDBXAssert(t, err == nil, "replay real signature: %v", err)
		tx.Witness[i] = WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Signature: append(sig, SIGHASH_ALL)}
	}
	return icbSignedRawV1(t, tx)
}

// icbReplayVaultCovenantV1 has a different owner and payout descriptor. All
// 1024 whitelist entries are real, distinct, sorted and exclude the owner.
func icbReplayVaultCovenantV1(t *testing.T, kp *MLDSA87Keypair, owner, payout []byte) []byte {
	t.Helper()
	x := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, owner))
	y := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, payout))
	white := [][32]byte{y}
	for i := uint64(0); i < 1023; i++ {
		white = append(white, sha3_256(binary.BigEndian.AppendUint64([]byte("replay-vault-destination"), i)))
	}
	slices.SortFunc(white, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	for i, hash := range white {
		logicalMDBXAssert(t, hash != x && (i == 0 || hash != white[i-1]), "whitelist owner/duplicate at%d", i)
	}
	return encodeVaultCovenantData(x, 1, [][32]byte{sha3_256(kp.PubkeyBytes())}, white)
}

// icbReplayHistoryBlockV1 builds an independent post-state and mined header.
// Anchor-only extensions reuse the immutable prior map and root.
func icbReplayHistoryBlockV1(t *testing.T, g PublishedGenesisContextV1, previous icbHistoryBlockV1, txs [][]byte, payouts []testOutput) icbHistoryBlockV1 {
	t.Helper()
	h := previous.in.Height + 1
	commit := initial148BlockWitnessCommit(t, txs...)
	cb := coinbaseTxWithOutputs(uint32(h), append(payouts, testOutput{covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]}))
	all := append([][]byte{cb}, txs...)
	rows, root := previous.rows, previous.root
	if len(txs) != 0 || len(payouts) != 0 {
		rows = icbHistoryRowsV1(t, previous.rows, h, all)
		root = icbHistoryRootV1(rows)
	}
	raw := initial148BlockFrame(t, all, func(head *initial148BlockHead) {
		head.parent, head.root, head.timestamp = previous.in.Endpoint.BlockHash, root, initial148GenesisTimestamp+121*h
	})
	hash, err := Initial148BlockHash(raw[:148])
	logicalMDBXAssert(t, err == nil, "replay history header: %v", err)
	endpoint := mdbx.TreeEndpointV1{Kind: 1, Height: h, BlockHash: hash}
	binary.BigEndian.PutUint64(endpoint.CumulativeChainwork[32:], h+1)
	generated, err := checkedAdvanceAlreadyGenerated(previous.in.Height, previous.in.AlreadyGenerated, previous.in.AlreadyGenerated.Big())
	logicalMDBXAssert(t, err == nil, "replay generated h%d: %v", h, err)
	times := make([]uint64, min(h, 11))
	for i := range times {
		times[i] = initial148GenesisTimestamp + 121*(h-uint64(len(times))+uint64(i))
	}
	in := initial148CompleteBlockInputV1{Raw: raw, Height: h, ParentHash: previous.in.Endpoint.BlockHash, ExpectedTarget: POW_LIMIT, ChainID: g.ChainID, DatabaseID: [32]byte{7}, Generation: 1, ParentTimestamps: times, AlreadyGenerated: generated, Parent: previous.in.Endpoint, Endpoint: endpoint, CapRegistry: &validatedLogicalStateCapRegistry{}, Registry: DefaultSuiteRegistry(), Rotation: icbFrozenV1(h)}
	return icbHistoryBlockV1{in: in, rows: rows, root: root}
}

// icbReplayVaultBlockV1 constructs a reachable funding prefix: mature h1
// funding, h101 split, at most 23 Vault creations per block, then the spend.
// No codec-only or stored invalid transaction supplies the validated body.
func icbReplayVaultBlockV1(t *testing.T, height uint64, pairs int) *icbReplayFamilyV1 {
	t.Helper()
	g := fgContext(t, initial148BlockGenesis(t))
	kp := icbKeyV1(t)
	owner, payout := p2pkCovenantDataForPubkey(kp.PubkeyBytes()), validP2PKCovenantData()
	vault := icbReplayVaultCovenantV1(t, kp, owner, payout)
	in, _ := icbGenesisInputV1(t, -1)
	in.Raw, in.PublishedGenesis, in.ChainID, in.Registry = g.Published, g.Published, g.ChainID, DefaultSuiteRegistry()
	rows := icbHistoryRowsV1(t, map[Outpoint]UtxoEntry{}, 0, [][]byte{g.Published[149:]})
	previous := icbHistoryBlockV1{in: in, rows: rows, root: icbHistoryRootV1(rows)}
	f := &icbReplayFamilyV1{genesis: g, prefix: []icbHistoryBlockV1{previous}}
	var funding, split Outpoint
	var spends [][]byte
	for h := uint64(1); h < height; h++ {
		var txs [][]byte
		var payouts []testOutput
		switch {
		case h == 1:
			payouts = []testOutput{{value: uint64(376 * pairs), covenantType: COV_TYPE_P2PK, covenantData: owner}}
		case h == 101:
			tx := inputViewTx(1, funding)
			tx.Outputs = slices.Repeat([]TxOutput{{Value: 376, CovenantType: COV_TYPE_P2PK, CovenantData: owner}}, pairs)
			txs = [][]byte{icbReplaySignV1(t, kp, g.ChainID, tx, uint64(376*pairs))}
			split = Outpoint{Txid: testTxID(t, txs[0])}
		case h >= 102 && h < 102+uint64((pairs+22)/23):
			txs = icbReplayCreationsV1(t, kp, g.ChainID, split.Txid, int(h-102)*23, min(int(h-101)*23, pairs), owner, vault)
			for _, raw := range txs {
				id := testTxID(t, raw)
				tx := inputViewTx(uint64(len(spends)+1), Outpoint{Txid: id}, Outpoint{Txid: id, Vout: 1})
				outputCount := 375
				tx.Outputs = slices.Repeat([]TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: payout}}, outputCount)
				spends = append(spends, icbReplaySignV1(t, kp, g.ChainID, tx, 375, 1))
			}
		}
		previous = icbReplayHistoryBlockV1(t, g, previous, txs, payouts)
		if h == 1 {
			parsed, err := ParseInitial148BlockBytes(previous.in.Raw)
			logicalMDBXAssert(t, err == nil, "funding coinbase: %v", err)
			funding = Outpoint{Txid: parsed.Txids[0]}
		}
		f.prefix = append(f.prefix, previous)
	}
	f.old = previous.rows
	f.block = icbReplayHistoryBlockV1(t, g, previous, spends, nil)
	f.inputs = icbReplayInputsV1(t, f.block.in.Raw, f.old)
	previous = f.block
	for previous.in.Height < 15840 {
		previous = icbReplayHistoryBlockV1(t, g, previous, nil, nil)
	}
	f.target = mdbx.RecoveryTargetV1{ChainID: g.ChainID, GenesisHash: g.GenesisHash, TipHash: previous.in.Endpoint.BlockHash, TipHeight: 15840, CumulativeChainwork: previous.in.Endpoint.CumulativeChainwork}
	return f
}

func icbReplayCreationsV1(t *testing.T, kp *MLDSA87Keypair, chain [32]byte, split [32]byte, first, last int, owner, vault []byte) [][]byte {
	t.Helper()
	var txs [][]byte
	for i := first; i < last; i++ {
		tx := inputViewTx(uint64(i+2), Outpoint{Txid: split, Vout: uint32(i)})
		tx.Outputs = []TxOutput{{Value: 375, CovenantType: COV_TYPE_VAULT, CovenantData: vault}, {Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: owner}}
		txs = append(txs, icbReplaySignV1(t, kp, chain, tx, 376))
	}
	return txs
}

// icbReplayInputsV1 independently selects only ORIGINAL OLD spent keys, never
// values or a caller-provided digest, for the protected LAG derivation.
func icbReplayInputsV1(t *testing.T, raw []byte, old map[Outpoint]UtxoEntry) []mdbx.TreeOutpointV1 {
	t.Helper()
	p, err := ParseInitial148BlockBytes(raw)
	logicalMDBXAssert(t, err == nil, "F3 key framing: %v", err)
	var keys []mdbx.TreeOutpointV1
	for _, tx := range p.Txs[1:] {
		for _, input := range tx.Inputs {
			key := Outpoint{Txid: input.PrevTxid, Vout: input.PrevVout}
			if _, present := old[key]; present {
				keys = append(keys, mdbx.TreeOutpointV1{Txid: key.Txid, Vout: key.Vout})
			}
		}
	}
	slices.SortFunc(keys, func(a, b mdbx.TreeOutpointV1) int {
		if c := bytes.Compare(a.Txid[:], b.Txid[:]); c != 0 {
			return c
		}
		return int(a.Vout) - int(b.Vout)
	})
	exact := make([]mdbx.TreeOutpointV1, len(keys))
	copy(exact, keys)
	return exact
}

type icbReplayJoinV1 struct {
	body       uint8
	paired     bool
	currentCap int // 1=exact 4824-byte producer acquisition, 2=one byte short.
	envelope   *mdbx.TreeAuthorityV1
	inputs     []mdbx.TreeOutpointV1 // Independent expected keys, never the operation-owned F3 backing.
	observed   [2]*btObserved
	trace      []uint64
	owner      *mdbx.OperationReservationOwner
	sealed     uint64
	readback   bool
	lateGrow   bool
	ownerLost  bool
}

// icbReplayF3V1 derives LAG from its own protected OLD and own original keys.
// Its transient source/Inputs/root workspace ends before native writing.
func icbReplayF3V1(t *testing.T, r *mdbx.Reader, a *mdbx.OperationAccount, req blockTreeRequestV1, raw []byte, parent mdbx.TreeEndpointV1, spent *blockSpentInputSource, expected []mdbx.TreeOutpointV1, want [32]byte) error {
	t.Helper()
	req.Generation, req.Kind, req.Undo = 2, mdbx.TreeKindDirectApplyV1, mdbx.UndoTransientV1
	req.BodyKind, req.Raw = 1, raw
	var source blockTreeSourceV1
	effect, err := prepareBlockTreeEffectV1(&source, r, a, req)
	if err != nil {
		return err
	}
	var root [32]byte
	err = a.WithReservation(36*uint64(len(spent.spent)), func() error {
		// Acquire the exact operation-owned backing only here. The earlier
		// expected fixture keys are an independent oracle, not this owner.
		inputs := make([]mdbx.TreeOutpointV1, 0, len(spent.spent))
		for item, have := spent.next(); have; item, have = spent.next() {
			key := item.outpoint
			_, present, readErr := r.Get(mdbx.TreeSchemaV1DBIs()[1], btUTXOKey(2, key))
			if readErr != nil {
				return readErr
			}
			logicalMDBXAssert(t, present, "F3 key must belong to protected LAG OLD: %+v", key)
			inputs = append(inputs, mdbx.TreeOutpointV1{Txid: key.Txid, Vout: key.Vout})
		}
		slices.SortFunc(inputs, func(a, b mdbx.TreeOutpointV1) int {
			if c := bytes.Compare(a.Txid[:], b.Txid[:]); c != 0 {
				return c
			}
			return int(a.Vout) - int(b.Vout)
		})
		logicalMDBXAssert(t, len(inputs) == cap(inputs) && slices.Equal(inputs, expected), "protected LAG exact-capacity original key census")
		if len(inputs) != 0 {
			logicalMDBXAssert(t, &inputs[0] != &expected[0], "F3 operation-owned keys must be distinct from fixture oracle backing")
		}
		var deriveErr error
		root, deriveErr = r.DeriveTreeRootV1(a, mdbx.TreeRootReadV1{Primitive: effect.Primitive, Parent: parent, Inputs: inputs})
		return deriveErr
	})
	if err == nil {
		logicalMDBXAssert(t, root == want && &source.Raw[0] == &raw[0], "protected LAG F3 root/backing got%x want%x", root, want)
	}
	return err
}

// icbReplayOperationV1 is a test-owned F2/F3 consumer. The validator's
// DirectApply effect is never committed; CURRENT gets a separate producer.
func icbReplayOperationV1(t *testing.T, r *mdbx.Reader, a *mdbx.OperationAccount, result *initial148CompleteBlockResultV1, block icbHistoryBlockV1, join *icbReplayJoinV1) (mdbx.TreeOperationV1, error) {
	t.Helper()
	generated := initial148PendingGeneratedV1(block.in)
	req := blockTreeRequestV1{DatabaseID: [32]byte{7}, Generation: 1, Block: block.in.Endpoint.BlockHash, Height: block.in.Height, HeaderBytes: 148, BodyKind: join.body, Raw: block.in.Raw, Generated: &generated, Direction: mdbx.TreeForwardV1, Undo: mdbx.UndoTransientV1, Endpoint: block.in.Endpoint}
	req.Kind = mdbx.TreeKindReplayNextV1
	if req.BodyKind == 2 {
		req.Raw = nil
	}
	var source blockTreeSourceV1
	var current blockTreeEffectV1
	prepare := func() error {
		var err error
		current, err = prepareBlockTreeEffectV1(&source, r, a, req)
		return err
	}
	var err error
	if join.currentCap != 0 {
		filler := uint64(402653184) - mdbx.FixtureReservationLive(join.owner) - 4824 + uint64(join.currentCap-1)
		err = a.WithReservation(filler, prepare)
	} else {
		err = prepare()
	}
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	logicalMDBXAssert(t, current.Primitive.Kind == mdbx.TreeKindReplayNextV1, "committing CURRENT kind must be ReplayNext")
	logicalMDBXAssert(t, result.effect.Primitive.Kind == mdbx.TreeKindDirectApplyV1 && current.Primitive.Source != result.effect.Primitive.Source, "F2 must be a separate producer")
	logicalMDBXAssert(t, source.coverage.BlockMeta == result.effect.Primitive.Coverage.BlockMeta, "separate CURRENT full metadata")
	if join.body == 2 {
		logicalMDBXAssert(t, source.Raw == nil && source.coverage.CurrentBody == nil, "stored body source must not invent Raw backing")
	} else {
		logicalMDBXAssert(t, &source.Raw[0] == &block.in.Raw[0], "CURRENT borrowed immutable Raw/backing")
		if join.body == 1 {
			logicalMDBXAssert(t, &current.CurrentBody.Literal[0] == &block.in.Raw[0], "body1 Pair must borrow the original Raw before native ownership")
		} else {
			logicalMDBXAssert(t, current.CurrentBody.AfterKind == 0 && current.CurrentBody.Literal == nil, "held body3 must not emit a stored body")
		}
	}
	op := mdbx.TreeOperationV1{Primitives: []mdbx.TreePrimitiveV1{current.Primitive}}
	op.Pair.Mutations = append(op.Pair.Mutations, current.Index[:]...)
	if current.CurrentBody.AfterKind != 0 {
		op.Pair.Mutations = append(op.Pair.Mutations, current.CurrentBody)
	}
	join.observed[0].source = &source
	op.Primitives[0].Source = join.observed[0]
	if join.paired {
		req.Generation, req.Kind = 2, mdbx.TreeKindLagForwardV1
		lagSource := new(blockTreeSourceV1)
		lag, lagErr := prepareBlockTreeEffectV1(lagSource, r, a, req)
		if lagErr != nil {
			return mdbx.TreeOperationV1{}, lagErr
		}
		join.observed[1].source = lagSource
		lag.Primitive.Source = join.observed[1]
		op.Primitives = append(op.Primitives, lag.Primitive)
		op.Pair.Mutations = append(op.Pair.Mutations, lag.Index[:]...)
		logicalMDBXAssert(t, lagSource.coverage.BlockMeta == source.coverage.BlockMeta && lag.Primitive.Generation != current.Primitive.Generation, "independent role metadata/identity")
		if join.body != 2 {
			logicalMDBXAssert(t, &lagSource.Raw[0] == &source.Raw[0] && &source.Raw[0] == &block.in.Raw[0], "both roles must borrow identical immutable Raw backing")
		}
		if err := icbReplayF3V1(t, r, a, req, block.in.Raw, block.in.Parent, result.transition.spentInputs, join.inputs, block.root); err != nil {
			return mdbx.TreeOperationV1{}, err
		}
		join.inputs = nil
	}
	return icbReplayFinishPlanV1(t, r, op, block, join)
}

func icbReplayFinishPlanV1(t *testing.T, r *mdbx.Reader, op mdbx.TreeOperationV1, block icbHistoryBlockV1, join *icbReplayJoinV1) (mdbx.TreeOperationV1, error) {
	t.Helper()
	if join.paired {
		logicalMDBXAssert(t, len(op.Primitives) == 2, "pair primitive count: got %d want 2", len(op.Primitives))
	}
	_, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[3], block.in.Endpoint.BlockHash[:])
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	if !present {
		op.Pair.Mutations = append(op.Pair.Mutations, btMutation(3, block.in.Endpoint.BlockHash[:], block.in.Raw[:148]))
	}
	if join.envelope != nil {
		planned := *join.envelope
		replay := *planned.Authority.Replay
		replay.Cursor = mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: block.in.Height, BlockHash: block.in.Endpoint.BlockHash}
		planned.Authority.Replay = &replay
		encoded, encodeErr := planned.Encode()
		logicalMDBXAssert(t, encodeErr == nil, "planned replay cursor: %v", encodeErr)
		mutation := btMutation(0, []byte{2}, encoded)
		mutation.BeforePresent = true
		op.Pair.Mutations = append(op.Pair.Mutations, mutation)
		genesisHash := replay.Target.GenesisHash
		header, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[3], genesisHash[:])
		if err != nil {
			return mdbx.TreeOperationV1{}, err
		}
		logicalMDBXAssert(t, present && len(header) == 148, "consulted genesis header: present=%v bytes=%d", present, len(header))
		op.Pair.Consulted = []mdbx.ConsultedRow{{DBI: mdbx.TreeSchemaV1DBIs()[3], Key: genesisHash[:]}}
		op.Pair.ContextConsulted = &mdbx.CanonicalContextWindowV1{Generation: 1, FirstHeight: block.in.Height - 11, Count: 11}
	}
	btSort(op.Pair.Mutations)
	return op, nil
}

// icbReplayApplyV1 retains actual W then M on one account. The fixed 8 MiB
// hold is an explicitly labelled future caller-budget control, not a precheck
// or a grant-consumption implementation. Native/source charges remain real.
func icbReplayApplyV1(t *testing.T, w *fgWorld, block icbHistoryBlockV1, workers int, join *icbReplayJoinV1) (btResult, initial148CompleteBlockOutcomeV1) {
	t.Helper()
	// These independent fixture observations are outside the operation's
	// consumers; only the scalar census and digest survive into this frame.
	expectedEvents := icbReplayEventsV1(t, block.in.Raw)
	beforeHash := sha3_256(block.in.Raw)
	var got btResult
	var outcome initial148CompleteBlockOutcomeV1
	join.owner = w.owner
	if !join.paired {
		join.inputs = nil
	}
	for i := range join.observed {
		join.observed[i] = &btObserved{t: t}
		join.observed[i].before = func(position mdbx.TreePositionV1, _ *mdbx.Reader, _ *mdbx.TreeDeltaSinkV1) error {
			held := mdbx.FixtureReservationLive(w.owner)
			join.trace = append(join.trace, held-2653184)
			join.ownerLost = join.ownerLost || held < icbMV1(uint64(len(block.in.Raw)))+8388608+2653184
			join.ownerLost = join.ownerLost || join.paired && join.inputs != nil
			if position == mdbx.TreeReadbackV1 {
				if !join.readback {
					join.sealed, join.readback = held, true
				}
				join.lateGrow = join.lateGrow || held != join.sealed
			}
			return nil
		}
	}
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		// Artificial headroom leaves exactly T for every actual acquisition,
		// including acquisitions between observer samples. It is neither
		// operation data nor the future single-precheck consumption mechanism.
		return a.WithReservation(2653184, func() error {
			return a.WithReservation(8388608, func() error {
				var outer error
				outcome, outer = icbEntryWorkersV1(workers)(a, block.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
					got.truth, got.stage, got.index, got.err = w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
						result, validationErr := validate(r)
						if validationErr != nil {
							return mdbx.TreeOperationV1{}, validationErr
						}
						logicalMDBXAssert(t, result != nil && mdbx.FixtureReservationLive(w.owner) == icbMV1(uint64(len(block.in.Raw)))+8388608+2653184, "successful validation must retain M plus caller-budget control and artificial headroom")
						join.trace = append(join.trace, mdbx.FixtureReservationLive(w.owner)-2653184)
						return icbReplayOperationV1(t, r, a, result, block, join)
					})
					return got.err
				})
				logicalMDBXAssert(t, any(outer) == any(got.err), "native/outer cause identity: %v/%v", outer, got.err)
				return nil
			})
		})
	})
	logicalMDBXAssert(t, err == nil && mdbx.FixtureReservationLive(w.owner) == 0, "one-account final cleanup: %v", err)
	for _, held := range join.trace {
		logicalMDBXAssert(t, held <= 400000000, "actual source/retained observation %d exceeds T", held)
	}
	btReservationsReleased(t, w.owner)
	logicalMDBXAssert(t, sha3_256(block.in.Raw) == beforeHash, "immutable Raw changed through final native consumer")
	for _, observed := range join.observed {
		if observed.source != nil {
			logicalMDBXAssert(t, uint64(observed.source.coverage.BlockMeta.EventCount) == expectedEvents, "full real source EventCount: got%d want%d", observed.source.coverage.BlockMeta.EventCount, expectedEvents)
		}
	}
	return got, outcome
}

// icbReplayWorldV1 installs the real signed prefix in both generations. Setup
// is not a surrogate validator: each complete block passes the real entry and
// LAG's separate protected derivation before its native operation.
func icbReplayWorldV1(t *testing.T, f *icbReplayFamilyV1) *fgWorld {
	t.Helper()
	// Persist the larger test database geometry at creation; OpenTreeV1
	// correctly requires the exact persisted ConfigV1 on every reopen.
	base := &btWorld{path: filepath.Join(t.TempDir(), "replay"), cfg: mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 1 << 30, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}}
	var err error
	base.s, err = mdbx.CreateTreeV1(base.path, base.cfg, [32]byte{7})
	logicalMDBXAssert(t, err == nil, "create replay fixture: %v", err)
	base.owner, err = mdbx.NewOperationReservationOwner(805306368)
	logicalMDBXAssert(t, err == nil, "replay reservation owner: %v", err)
	t.Cleanup(func() { _ = base.s.Close() })
	w := &fgWorld{btWorld: base, database: [32]byte{7}, current: 1, lag: 2, raw: f.genesis.Published, genesis: f.genesis}
	w.seedAuthority(t, mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: 1, Lifecycle: 1}, LagGenerationID: 2})
	for _, generation := range []uint64{1, 2} {
		w.seed(t, 0, btMeta(0x10, generation), mdbx.LogicalCounterValue(0, 0))
		w.seedBinding(t, generation, w.emptyBinding())
	}
	old := map[Outpoint]UtxoEntry{}
	for _, block := range f.prefix {
		join := &icbReplayJoinV1{body: 1, paired: true, inputs: icbReplayInputsV1(t, block.in.Raw, old)}
		got, outcome := icbReplayApplyV1(t, w, block, -1, join)
		got.want(t, 2, 3, -1)
		logicalMDBXAssert(t, got.err == nil && outcome.required.derived && outcome.required.root == block.root, "signed setup h%d: %v", block.in.Height, got.err)
		old = block.rows
	}
	icbReplayStateV1(t, w, 1, f.prefix[len(f.prefix)-1], nil)
	icbReplayStateV1(t, w, 2, f.prefix[len(f.prefix)-1], nil)
	return w
}

func icbReplayAuthorityV1(t *testing.T, w *fgWorld, f *icbReplayFamilyV1, profile mdbx.StorageProfileV1) mdbx.TreeAuthorityV1 {
	t.Helper()
	parent := f.block.in.Parent
	a := mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: mdbx.StorageProfilePrunedV1, ActiveGenerationID: 3, NextGenerationID: 5, Phase: mdbx.StoragePhaseReplayV1, Lifecycle: mdbx.StorageLifecycleRecoveryRequiredV1, Replay: &mdbx.ReplayV1{TargetProfile: profile, TargetGenerationID: 1, Target: f.target, Cursor: mdbx.ReplayCursorV1{Kind: mdbx.ReplayCursorAppliedV1, Height: parent.Height, BlockHash: parent.BlockHash}}}, LagGenerationID: 4, TargetLagGenerationID: 2, SourceKind: mdbx.TreeSourceGenesisReplayV1}
	w.seedAuthority(t, a)
	return a
}

// icbReplayStateV1 compares every expected UTXO, every original spend's
// absence, exact counters and the independently built canonical root/endpoint.
func icbReplayStateV1(t *testing.T, w *fgWorld, generation uint64, block icbHistoryBlockV1, spent []mdbx.TreeOutpointV1) {
	t.Helper()
	err := w.s.View(func(r *mdbx.Reader) error {
		var total uint64
		for key, row := range block.rows {
			want := btValue(btFrame(row.Value, row.CovenantType, row.CovenantData), row.CreationHeight, row.CreatedByCoinbase)
			total += 36 + uint64(len(want))
			value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[1], btUTXOKey(generation, key))
			logicalMDBXAssert(t, err == nil && present && bytes.Equal(value, want), "generation%d full UTXO %+v: %v", generation, key, err)
		}
		for _, key := range spent {
			_, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[1], btUTXOKey(generation, Outpoint{Txid: key.Txid, Vout: key.Vout}))
			logicalMDBXAssert(t, err == nil && !present, "generation%d spent row retained %+v: %v", generation, key, err)
		}
		value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[0], btMeta(0x10, generation))
		logicalMDBXAssert(t, err == nil && present && bytes.Equal(value, mdbx.LogicalCounterValue(total, uint64(len(block.rows)))), "generation%d exact counters: %v", generation, err)
		root, present, err := r.ReadTreeRootBindingV1(generation)
		logicalMDBXAssert(t, err == nil && present && root.RootDigest == block.root && root.Endpoint == block.in.Endpoint && root.ChainID == w.genesis.ChainID && root.GenesisHash == w.genesis.GenesisHash, "generation%d independent root/endpoint/identity: %+v/%v", generation, root, err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "complete replay state: %v", err)
}

// icbReplayLagImageV1 takes independent byte snapshots of every LAG-owned
// UTXO/index/owner/node and both metadata rows, with real paged reads.
func icbReplayLagImageV1(t *testing.T, w *fgWorld) []btfRow {
	t.Helper()
	var rows []btfRow
	err := w.s.View(func(r *mdbx.Reader) error {
		for _, tag := range []byte{0x10, 0x11} {
			key := btMeta(tag, 2)
			value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[0], key)
			logicalMDBXAssert(t, err == nil && present, "LAG metadata snapshot: %v", err)
			rows = append(rows, btfRow{0, key, value})
		}
		for _, rank := range []uint8{1, 2, 7, 8} {
			var after []byte
			for {
				page, err := r.PrefixPage(mdbx.TreeSchemaV1DBIs()[rank], binary.BigEndian.AppendUint64(nil, 2), after, 1440, 1<<20)
				if err != nil {
					return err
				}
				for _, row := range page.Rows {
					rows = append(rows, btfRow{rank, row.Key, row.Value})
				}
				if page.Stop == mdbx.PrefixPageExhausted {
					break
				}
				logicalMDBXAssert(t, len(page.Rows) != 0, "LAG snapshot page made no progress")
				after = page.Rows[len(page.Rows)-1].Key
			}
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "complete LAG snapshot: %v", err)
	return rows
}

func icbReplayWantLagImageV1(t *testing.T, w *fgWorld, before []btfRow) {
	t.Helper()
	after := icbReplayLagImageV1(t, w)
	logicalMDBXAssert(t, len(before) == len(after), "CURRENT-alone LAG row cardinality %d/%d", len(before), len(after))
	for i := range before {
		logicalMDBXAssert(t, before[i].rank == after[i].rank && bytes.Equal(before[i].key, after[i].key) && bytes.Equal(before[i].value, after[i].value), "CURRENT-alone changed LAG bytes row%d", i)
	}
}

// icbReplayFollowingV1 distinguishes a released account and usable reopened
// owner from a final-image-only assertion.
func icbReplayFollowingV1(t *testing.T, w *fgWorld) {
	t.Helper()
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		truth, stage, index, err := w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
			value, present, readErr := r.Get(mdbx.TreeSchemaV1DBIs()[0], []byte{2})
			if readErr != nil {
				return mdbx.TreeOperationV1{}, readErr
			}
			logicalMDBXAssert(t, present, "next operation requires the actual authority owner")
			mutation := btMutation(0, []byte{2}, value)
			mutation.BeforePresent = true
			return mdbx.TreeOperationV1{Pair: mdbx.TreePairV1{Mutations: []mdbx.Mutation{mutation}}}, nil
		})
		logicalMDBXAssert(t, err == nil && truth == 2 && stage == 3 && index == -1, "next legal native operation: %d/%d/%d/%v", truth, stage, index, err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "next legal account: %v", err)
	btReservationsReleased(t, w.owner)
}

func icbReplayMetadataV1(t *testing.T, f *icbReplayFamilyV1) {
	t.Helper()
	logicalMDBXAssert(t, len(f.block.in.Raw) == 24847456, "vault800 Raw: got %d want 24847456", len(f.block.in.Raw))
	summary, err := ValidateInitial148BlockSteps1To12(f.block.in.Raw, f.block.in.ParentHash, POW_LIMIT, f.block.in.Height, f.block.in.ParentTimestamps)
	logicalMDBXAssert(t, err == nil && summary.TxCount == 801 && summary.SumWeight == 64707614, "vault800 TxCount/weight: %+v/%v", summary, err)
	logicalMDBXAssert(t, len(f.inputs) == 1600 && len(f.block.rows) == 300001 && len(f.old) == 1601, "vault800 full event cardinality: %d/%d/%d", len(f.inputs), len(f.block.rows), len(f.old))
	logicalMDBXAssert(t, icbReplayEventsV1(t, f.block.in.Raw) == 301600, "vault800 EventCount must be 301600")
	logicalMDBXAssert(t, icbReplayLogicalBytesV1(f.block.rows)-icbReplayLogicalBytesV1(f.old) == 313600, "vault800 growth must be 313600")
	logicalMDBXAssert(t, icbHistoryRootV1(f.block.rows) == f.block.root && bytes.Equal(f.block.in.Raw[108:140], f.block.root[:]), "vault800 independent canonical post-root")
}

func icbReplayEventsV1(t *testing.T, raw []byte) uint64 {
	t.Helper()
	parsed, err := ParseInitial148BlockBytes(raw)
	logicalMDBXAssert(t, err == nil, "independent event census: %v", err)
	var events uint64
	for i, tx := range parsed.Txs {
		if i != 0 {
			events += uint64(len(tx.Inputs))
		}
		for _, out := range tx.Outputs {
			if out.CovenantType != COV_TYPE_ANCHOR && out.CovenantType != COV_TYPE_DA_COMMIT {
				events++
			}
		}
	}
	return events
}

func icbReplayLogicalBytesV1(rows map[Outpoint]UtxoEntry) uint64 {
	var total uint64
	for _, row := range rows {
		total += 36 + uint64(len(btValue(btFrame(row.Value, row.CovenantType, row.CovenantData), row.CreationHeight, row.CreatedByCoinbase)))
	}
	return total
}

// TestInitial148ReplayLargeV1 joins the actual large family through both
// validators, separate F2 and protected F3, selected native writer/readback.
func TestInitial148ReplayLargeV1(t *testing.T) {
	families := map[uint64]*icbReplayFamilyV1{}
	load := func(t *testing.T, height uint64) *icbReplayFamilyV1 {
		if families[height] == nil {
			families[height] = icbReplayVaultBlockV1(t, height, 800)
		}
		return families[height]
	}
	t.Run("metadata", func(t *testing.T) { icbReplayMetadataV1(t, load(t, 200)) })
	for _, tc := range []struct {
		name    string
		height  uint64
		workers int
		paired  bool
	}{
		{"pair-sequential", 200, -1, true},
		{"pair-queued", 200, 4, true},
		{"current-sequential", 721, -1, false},
		{"current-queued", 721, 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := load(t, tc.height)
			icbReplayMetadataV1(t, f)
			w := icbReplayWorldV1(t, f)
			authority := icbReplayAuthorityV1(t, w, f, mdbx.StorageProfileArchiveV1)
			var lagBefore []btfRow
			if !tc.paired {
				lagBefore = icbReplayLagImageV1(t, w)
			}
			join := &icbReplayJoinV1{body: 1, paired: tc.paired, envelope: &authority, inputs: f.inputs}
			var got btResult
			var outcome initial148CompleteBlockOutcomeV1
			var evidence mdbx.SelectedDamageEvidence
			var fixtureErr error
			counts, observeErr := mdbx.FixturePairReadObservation(w.s, func(site uint32) {
				if join.readback && (site == 1 || site == 2) && mdbx.FixtureReservationLive(w.owner) != join.sealed {
					join.lateGrow = true
				}
			}, func() {
				evidence, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageCommitNew, 0, btMeta(0x11, 1), func() { got, outcome = icbReplayApplyV1(t, w, f.block, tc.workers, join) })
			})
			logicalMDBXAssert(t, observeErr == nil && fixtureErr == nil && evidence.Commits == 1 && evidence.BeginRead == 1 && counts.Comparisons != 0, "large complete crossing: %+v/%+v/%v/%v", counts, evidence, observeErr, fixtureErr)
			icbReplayCrossedV1(t, w, got, 2, false)
			logicalMDBXAssert(t, outcome.required.derived && outcome.required.root == f.block.root && outcome.validationErr == nil, "large validation root: %+v", outcome)
			icbReplaySourceCallsV1(t, join, [3]int{0, 1, 1})
			w.reopen(t)
			icbReplayStateV1(t, w, 1, f.block, f.inputs)
			if tc.paired {
				icbReplayStateV1(t, w, 2, f.block, f.inputs)
			} else {
				icbReplayWantLagImageV1(t, w, lagBefore)
			}
			icbReplayCursorV1(t, w, f.block.in.Endpoint)
			icbReplayFollowingV1(t, w)
			t.Logf("real Vault800 h%d Raw24847456 E301600 weight64707614 growth313600 observed grants=%v; conservative T400000000", tc.height, join.trace)
		})
	}
}

func icbReplaySourceCallsV1(t *testing.T, join *icbReplayJoinV1, want [3]int) {
	t.Helper()
	roles := 1
	if join.paired {
		roles = 2
		logicalMDBXAssert(t, join.inputs == nil, "F3 Inputs must retire before writing")
	}
	for i, source := range join.observed[:roles] {
		logicalMDBXAssert(t, source.calls == want, "role%d exact writer/readback positions: got%v want%v", i, source.calls, want)
	}
	logicalMDBXAssert(t, !join.lateGrow, "strict readback must not grow the carried account")
	logicalMDBXAssert(t, !join.ownerLost, "CURRENT/M/Raw or F3 retirement owner lost before last consumer")
}

func icbReplayCursorV1(t *testing.T, w *fgWorld, endpoint mdbx.TreeEndpointV1) {
	t.Helper()
	a := rtEnvelope(t, w.btWorld)
	logicalMDBXAssert(t, a.Authority.Replay != nil && a.Authority.Replay.Cursor == (mdbx.ReplayCursorV1{Kind: 2, Height: endpoint.Height, BlockHash: endpoint.BlockHash}), "cursor must advance once with complete NEW: %+v", a.Authority.Replay)
}

// icbReplayCrossedV1 preserves native cause/truth and consumed disposition;
// complete durable observations and a legal next operation follow reopening.
func icbReplayCrossedV1(t *testing.T, w *fgWorld, got btResult, truth mdbx.CommitTruth, unreadable bool) {
	t.Helper()
	got.want(t, uint8(truth), 3, -1)
	ce, ok := got.err.(*mdbx.CommitError)
	logicalMDBXAssert(t, ok && ce.Truth == truth && (ce.ReadbackCause != nil) == unreadable, "exact crossed cause/truth: %v", got.err)
	engine, ok := ce.Cause.(*mdbx.EngineError)
	logicalMDBXAssert(t, ok && engine.Class == mdbx.EngineCapacity && engine.Operation == "update" && engine.Code == 28 && engine.Diagnostic == "error 28" && engine.Cause == nil, "original native commit cause: %v", ce.Cause)
	if unreadable {
		var read *mdbx.EngineError
		logicalMDBXAssert(t, errors.As(ce.ReadbackCause, &read) && read.Class == mdbx.EngineIO && read.Code == 5 && read.Diagnostic == "error 5", "readback original unavailable cause: %v", ce.ReadbackCause)
	}
	icbHistoryTerminalV1(t, w, got, truth)
}

// TestInitial148ReplayPairV1 retains the exact M1/M2 local mutation owners and
// exercises stored/held body representatives at the real replay boundary.
func TestInitial148ReplayPairV1(t *testing.T) {
	families := map[uint64]*icbReplayFamilyV1{}
	load := func(t *testing.T, h uint64) *icbReplayFamilyV1 {
		if families[h] == nil {
			families[h] = icbReplayVaultBlockV1(t, h, 1)
		}
		return families[h]
	}
	for _, name := range []string{"f2-current-kind", "pair-shape"} {
		t.Run(name, func(t *testing.T) {
			f := load(t, 200)
			icbReplaySmallSuccessV1(t, f, -1, 1, true)
		})
	}
	for _, workers := range []int{-1, 4} {
		for _, tc := range []struct {
			name   string
			h      uint64
			body   uint8
			paired bool
		}{
			{"pair-body2", 200, 2, true},
			{"pair-body3", 200, 3, true},
			{"pair-at-boundary-body1", 720, 1, true},
			{"current-body2", 721, 2, false},
		} {
			t.Run(fmt.Sprintf("%s/workers%d", tc.name, workers), func(t *testing.T) {
				icbReplaySmallSuccessV1(t, load(t, tc.h), workers, tc.body, tc.paired)
			})
		}
	}
	// For H15840 PRUNED, L_body=b_target+1=721. A replay CURRENT
	// alone has h>=721, so body3 is unreachable; its numeric cell is retained.
	t.Log("CURRENT-alone BodyKind3: codec-only/unreachable replay cell; numeric full-domain evidence is TestInitial148ReplayFitV1")
}

func icbReplaySmallSuccessV1(t *testing.T, f *icbReplayFamilyV1, workers int, body uint8, paired bool) {
	t.Helper()
	w := icbReplayWorldV1(t, f)
	profile := mdbx.StorageProfileArchiveV1
	if body == 3 {
		profile = mdbx.StorageProfilePrunedV1
	}
	a := icbReplayAuthorityV1(t, w, f, profile)
	icbReplayBodyPreconditionV1(t, w, f, body)
	before := icbReplayLagImageV1(t, w)
	join := &icbReplayJoinV1{body: body, paired: paired, envelope: &a, inputs: f.inputs}
	got, outcome := icbReplayApplyV1(t, w, f.block, workers, join)
	got.want(t, 2, 3, -1)
	logicalMDBXAssert(t, got.err == nil && outcome.required.derived && outcome.required.root == f.block.root, "real replay body%d: %v", body, got.err)
	icbReplaySourceCallsV1(t, join, [3]int{0, 1, 0})
	w.reopen(t)
	icbReplayStateV1(t, w, 1, f.block, f.inputs)
	if paired {
		icbReplayStateV1(t, w, 2, f.block, f.inputs)
	} else {
		icbReplayWantLagImageV1(t, w, before)
	}
	var wantBody []byte
	if body != 3 {
		wantBody = f.block.in.Raw
	}
	w.read(t, 4, f.block.in.Endpoint.BlockHash[:], wantBody)
	icbReplayCursorV1(t, w, f.block.in.Endpoint)
	icbReplayFollowingV1(t, w)
}

func icbReplayBodyPreconditionV1(t *testing.T, w *fgWorld, f *icbReplayFamilyV1, body uint8) {
	t.Helper()
	logicalMDBXAssert(t, f.target.TipHeight == 15840 && f.target.TipHeight-15120 == 720 && f.target.TipHeight-1439 == 14401, "actual replay target promises")
	if body == 2 {
		w.pair(t, btMutation(3, f.block.in.Endpoint.BlockHash[:], f.block.in.Raw[:148]), btMutation(4, f.block.in.Endpoint.BlockHash[:], f.block.in.Raw))
	}
	if body == 3 {
		logicalMDBXAssert(t, f.block.in.Height <= 720, "held body is reachable only in paired below-promise replay")
	}
}

// TestInitial148ReplayCapacityV1 preloads the actual CURRENT producer's 4824
// acquisition. T-1 is deliberately not treated as an attained fixture peak.
func TestInitial148ReplayCapacityV1(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	for _, workers := range []int{-1, 4} {
		for _, capacity := range []int{1, 2} {
			t.Run(fmt.Sprintf("workers%d/cap%d", workers, capacity), func(t *testing.T) {
				w := icbReplayWorldV1(t, f)
				a := icbReplayAuthorityV1(t, w, f, mdbx.StorageProfileArchiveV1)
				before := icbReplayLagImageV1(t, w)
				oldAuthority := rtImageRow(t, w.btWorld, []byte{2})
				join := &icbReplayJoinV1{body: 1, paired: true, currentCap: capacity, envelope: &a, inputs: f.inputs}
				var got btResult
				evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { got, _ = icbReplayApplyV1(t, w, f.block, workers, join) })
				logicalMDBXAssert(t, fixtureErr == nil, "actual capacity fixture: %v", fixtureErr)
				if capacity == 1 {
					got.want(t, 2, 3, -1)
					logicalMDBXAssert(t, got.err == nil && evidence.Commits == 1, "exact acquisition must continue to complete NEW: %v", got.err)
					icbReplayStateV1(t, w, 1, f.block, f.inputs)
					icbReplayStateV1(t, w, 2, f.block, f.inputs)
				} else {
					got.want(t, 1, 1, -1)
					logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(got.err) && evidence.Commits == 0 && evidence.BeginWrite == 0, "one byte short CURRENT acquisition: %v/%+v", got.err, evidence)
					logicalMDBXAssert(t, join.observed[0].source == nil && join.observed[0].calls == [3]int{}, "source published/used after refused acquisition")
					w.read(t, 0, []byte{2}, oldAuthority)
					icbReplayWantLagImageV1(t, w, before)
					icbReplayStateV1(t, w, 1, f.prefix[len(f.prefix)-1], nil)
					icbReplayFollowingV1(t, w)
					fresh := &icbReplayJoinV1{body: 1, paired: true, envelope: &a, inputs: f.inputs}
					next, _ := icbReplayApplyV1(t, w, f.block, workers, fresh)
					logicalMDBXAssert(t, next.err == nil && next.truth == 2 && next.stage == 3, "next legal replay after local refusal: %v", next.err)
				}
				icbReplayFollowingV1(t, w)
			})
		}
	}
}

// TestInitial148ReplayReadbackV1 joins the complete native truth domain to
// real validation/F2/F3. Mixed-image damage affects only the body row;
// reopening observes that damage before restoring the fixture's body bytes.
func TestInitial148ReplayReadbackV1(t *testing.T) {
	f := icbReplayVaultBlockV1(t, 200, 1)
	for _, workers := range []int{-1, 4} {
		for _, tc := range []struct {
			name       string
			scenario   mdbx.SelectedDamageScenario
			truth      mdbx.CommitTruth
			unreadable bool
			commits    uint64
			drift      uint32
		}{
			{"OLD", mdbx.SelectedDamageCommitOld, 1, false, 1, 0},
			{"NEW", mdbx.SelectedDamageCommitNew, 2, false, 1, 0},
			{"mixed", mdbx.SelectedDamageProbeOnly, 3, false, 0, 1},
			{"unreadable", mdbx.SelectedDamageCommitUnreadable, 3, true, 1, 0},
		} {
			t.Run(fmt.Sprintf("%s/workers%d", tc.name, workers), func(t *testing.T) {
				w := icbReplayWorldV1(t, f)
				a := icbReplayAuthorityV1(t, w, f, mdbx.StorageProfileArchiveV1)
				join := &icbReplayJoinV1{body: 1, paired: true, envelope: &a, inputs: f.inputs}
				var got btResult
				var evidence mdbx.SelectedDamageEvidence
				var fixtureErr, driftErr error
				var drift uint32
				hash := f.block.in.Endpoint.BlockHash
				counts, observeErr := mdbx.FixturePairReadObservation(w.s, func(site uint32) {
					if join.readback && (site == 1 || site == 2) && mdbx.FixtureReservationLive(w.owner) != join.sealed {
						join.lateGrow = true
					}
				}, func() {
					evidence, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, tc.scenario, 0, btMeta(0x11, 2), func() {
						apply := func() { got, _ = icbReplayApplyV1(t, w, f.block, workers, join) }
						if tc.drift == 1 {
							drift, driftErr = mdbx.FixtureCleanupReadbackDrift(w.s, 4, hash[:], apply)
							return
						}
						apply()
					})
				})
				logicalMDBXAssert(t, observeErr == nil && fixtureErr == nil && evidence.Commits == tc.commits && counts.Comparisons != 0, "complete crossing observations: %+v/%+v/%v/%v", counts, evidence, observeErr, fixtureErr)
				logicalMDBXAssert(t, driftErr == nil && drift == tc.drift, "complete crossing body drift: got%d want%d: %v", drift, tc.drift, driftErr)
				icbReplayCrossedV1(t, w, got, tc.truth, tc.unreadable)
				icbReplaySourceCallsV1(t, join, [3]int{0, 1, 1})
				w.reopen(t)
				if tc.name == "mixed" {
					equal, rawErr := mdbx.FixtureRawRowEqual(w.s, 4, hash[:], []byte{0x7f})
					logicalMDBXAssert(t, rawErr == nil && equal, "reopened mixed body must retain exact malformed byte 7f: equal=%t err=%v", equal, rawErr)
					w.seed(t, 4, hash[:], f.block.in.Raw)
				}
				block, spent := f.block, f.inputs
				if tc.truth == 1 {
					block, spent = f.prefix[len(f.prefix)-1], nil
				}
				icbReplayStateV1(t, w, 1, block, spent)
				icbReplayStateV1(t, w, 2, block, spent)
				icbReplayCursorV1(t, w, block.in.Endpoint)
				icbReplayFollowingV1(t, w)
			})
		}
	}
}

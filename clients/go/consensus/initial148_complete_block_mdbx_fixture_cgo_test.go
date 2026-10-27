//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// TestInitial148CompleteBlockFixtureAdmission runs the composer against the
// native tree store inside an existing TreeOperation account: a rejection
// inside UpdateTreeV1's builder must return no operation, so no write occurs.
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
			logicalMDBXAssert(t, counts.Commits == 0 && (reached != sequentialEarlier) && (reached || counts.Faults == 0 && fixtureErr != nil), "%s workers=%d fixture: %+v / %v", c.name, workers, counts, fixtureErr)
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
func icbDeriveDamageV1(t *testing.T, w *btWorld, in initial148CompleteBlockInputV1, damage string, workers int) (icbObservedV1, []byte) {
	t.Helper()
	binding, node := icbParentBindingV1(t, w)
	var got icbObservedV1
	observe := func() { got = icbObserveV1(t, w, in, workers) }
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
	case "node-absent":
		// A well-formed binding naming a valid node identity with no stored row.
		binding = icbAbsentNodeBindingV1(t, binding)
		value, err := binding.Encode()
		logicalMDBXAssert(t, err == nil && mdbx.FixtureSeedRawRow(w.s, 0, btMeta(0x11, 1), value) == nil, "rebind node: %v", err)
		node, err = mdbx.TreeNodeKey(1, *binding.Top.Node)
		logicalMDBXAssert(t, err == nil, "absent node key: %v", err)
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

// icbAbsentNodeBindingV1 moves the binding's top to a different valid node
// identity of the same kind; no rank-8 row exists under its key.
func icbAbsentNodeBindingV1(t *testing.T, binding mdbx.RootBindingV1) mdbx.RootBindingV1 {
	t.Helper()
	id := *binding.Top.Node
	switch {
	case id.Kind == mdbx.TreeNodeLeafV1:
		id.RoutingKey[35] ^= 0x01
	case id.Depth > 0:
		id.Prefix[0] ^= 0x80
	default:
		id.Depth = 1
	}
	binding.Top.Node = &id
	return binding
}

// icbNodeKeyV1 is the observed key projection for a rank-8 node key.
func icbNodeKeyV1(o mdbx.TreeObservationV1, key []byte) bool {
	return int(o.KeyLength) == len(key) && bytes.Equal(o.Key[:o.KeyLength], key)
}

// TestInitial148CompleteBlockDeriveFailureH5 (C10) makes only the fresh D of
// the root-valid h=5 block fail, through the sequential entry and the queued
// entry with one and four workers: a native EIO on the root binding or root
// node (unavailable: no observation), and an absent, malformed or
// endpoint-inconsistent parent root binding (localized integrity with its
// observation). Each keeps the raw D cause as the validation error,
// derived=false, a zero root and no delivered result; none is a mismatch.
func TestInitial148CompleteBlockDeriveFailureH5(t *testing.T) {
	cases := []struct {
		damage string
		kind   mdbx.TreeObservationKindV1
		rank   uint8
	}{
		{"binding-eio", 0, 0},
		{"node-eio", 0, 8},
		{"binding-absent", mdbx.TreeObservationAbsentV1, 0},
		{"binding-malformed", mdbx.TreeObservationMalformedV1, 0},
		{"binding-endpoint", mdbx.TreeObservationIdentityMismatchV1, 0},
		{"node-malformed", mdbx.TreeObservationMalformedV1, 8},
		{"node-absent", mdbx.TreeObservationAbsentV1, 8},
	}
	for _, c := range cases {
		for _, workers := range []int{-1, 1, 4} {
			w := btNew(t)
			f := icbH5FixtureV1(t, w)
			got, node := icbDeriveDamageV1(t, w, f.in, c.damage, workers)
			req, verr := got.out.required, got.out.validationErr
			var txErr *TxError
			logicalMDBXAssert(t, got.out.attempted && verr != nil && !errors.As(verr, &txErr) && got.summary == (BlockBasicSummary{}), "%s workers=%d no-result: err=%v verr=%v", c.damage, workers, got.err, verr)
			logicalMDBXAssert(t, any(req.cause) == any(verr) && !req.derived && req.root == ([32]byte{}), "%s workers=%d raw D cause: %v / %+v", c.damage, workers, verr, req)
			var engine *mdbx.EngineError
			logicalMDBXAssert(t, errors.As(req.cause, &engine), "%s workers=%d cause is not native: %T %v", c.damage, workers, req.cause, req.cause)
			if c.kind == 0 {
				logicalMDBXAssert(t, engine.Class == mdbx.EngineIO && !req.hasObservation && req.observation == (mdbx.TreeObservationV1{}), "%s workers=%d unavailable fabricated observation: %+v", c.damage, workers, req)
				continue
			}
			o := req.observation
			logicalMDBXAssert(t, engine.Class == mdbx.EngineIntegrity && req.hasObservation && engine.TreeObservation != nil && o == *engine.TreeObservation, "%s workers=%d observation lost: %+v", c.damage, workers, req)
			// Observation identity: database 7, generation 1, this block at h=5, writer position 1, the damaged rank.
			same := o.DatabaseID == [32]byte{7} && o.Generation == 1 && o.Block == f.in.Endpoint.BlockHash && o.Height == icbHeightV1 && o.Position == 1 && o.Rank == c.rank && o.Kind == c.kind
			logicalMDBXAssert(t, same, "%s workers=%d observation %+v", c.damage, workers, o)
			if c.rank == 8 {
				// The drifted root node, or the rebound absent identity; absence has no cause, a short record the schema cause.
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

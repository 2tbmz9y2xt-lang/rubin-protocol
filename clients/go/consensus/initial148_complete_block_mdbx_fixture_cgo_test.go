//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
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
				logicalMDBXAssert(t, errors.As(verr, &txErr) && txErr.Code == TX_ERR_SIG_INVALID && txErr.Msg == "CORE_P2PK signature invalid", "%s workers=%d earlier error lost: %v", c.name, workers, verr)
				logicalMDBXAssert(t, got.out.required == (initial148RootReadOutcomeV1{}), "%s workers=%d later read recorded: %+v", c.name, workers, got.out.required)
				continue
			}
			logicalMDBXAssert(t, counts.Faults == 1 && !errors.As(verr, &txErr), "%s workers=%d unavailable became %v (faults %d)", c.name, workers, verr, counts.Faults)
			btfEngine(t, got.out.required.cause, "get", mdbx.EngineIO, 5, "error 5")
			logicalMDBXAssert(t, (any(verr) == any(got.out.required.cause) || icbWrapsCauseV1(verr, got.out.required.cause)) && !got.out.required.derived && got.out.required.root == ([32]byte{}), "%s workers=%d raw cause tuple: %v / %+v", c.name, workers, verr, got.out.required)
		}
		w := btNew(t)
		f := icbH5VariantV1(t, w, icbH5OptsV1{missing: true, flip: 1})
		got := icbObserveV1(t, w, f.in, workers)
		var txErr *TxError
		logicalMDBXAssert(t, errors.As(got.err, &txErr) && txErr.Code == TX_ERR_MISSING_UTXO && txErr.Msg == "utxo not found" && got.out.required == (initial148RootReadOutcomeV1{}), "workers=%d absence: %v / %+v", workers, got.err, got.out.required)
	}
}

//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// icbRegistryV1 is an explicit two-suite registry: r=2, a=len("ML-DSA-87")+len("X")=10.
func icbRegistryV1() *SuiteRegistry {
	return NewSuiteRegistryFromParams([]SuiteParams{
		{SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627, VerifyCost: 8, AlgName: "ML-DSA-87"},
		{SuiteID: 0x02, PubkeyLen: 11, SigLen: 21, VerifyCost: 9, AlgName: "X"},
	})
}

// icbInputV1 is a well-formed h=1 local context over a 200-byte body that
// fails steps 1-12; it reaches validate but never a usable candidate.
func icbInputV1() initial148CompleteBlockInputV1 {
	parent := [32]byte{0x51}
	return initial148CompleteBlockInputV1{
		Raw: make([]byte, 200), Height: 1, ParentHash: parent, ExpectedTarget: [32]byte{0x7f},
		DatabaseID: [32]byte{7}, Generation: 1, ParentTimestamps: []uint64{1},
		Parent:      mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: 0, BlockHash: parent},
		Endpoint:    mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: 1, BlockHash: [32]byte{0x52}},
		CapRegistry: &validatedLogicalStateCapRegistry{}, Registry: icbRegistryV1(),
		Rotation: icbFrozenV1(1),
	}
}

// icbFrozenV1 is the caller-frozen default suite surface at height.
func icbFrozenV1(height uint64) *boundSpendSurface {
	inner := DefaultRotationProvider{}
	return &boundSpendSurface{inner: inner, height: height, haveCreate: true, haveSpend: true, create: inner.NativeCreateSuites(height), spend: inner.NativeSpendSuites(height)}
}

func icbWithAccountV1(t *testing.T, w *btWorld, use func(*mdbx.OperationAccount)) {
	t.Helper()
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		use(account)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "complete block operation: %v", err)
	btReservationsReleased(t, w.owner)
}

func TestInitial148CompleteBlockTariffLiteral(t *testing.T) {
	in := icbInputV1()
	// 16,777,216 + 8,192*200 + 16,384*0 + 128*0 + 1,024*2 + 2*10 + 8*1 + 0.
	w, ok := initial148CompleteTariffV1(in)
	logicalMDBXAssert(t, ok && w == 18_417_692, "W literal: %d/%v", w, ok)
	in.CapRegistry = &validatedLogicalStateCapRegistry{rows: make([]validatedLogicalStateCapRegistryRow, 3)}
	in.Height, in.ParentTimestamps, in.PublishedGenesis = 0, nil, make([]byte, 200)
	w, ok = initial148CompleteTariffV1(in)
	// Distinct published backing adds g=200; c=3 adds 384; p=0.
	logicalMDBXAssert(t, ok && w == 18_417_692-8+384+200, "W distinct genesis literal: %d/%v", w, ok)
	in.PublishedGenesis = in.Raw
	w, ok = initial148CompleteTariffV1(in)
	logicalMDBXAssert(t, ok && w == 18_417_692-8+384, "W same backing literal: %d/%v", w, ok)
	in.Rotation = &boundSpendSurfaceWithDeployment{boundSpendSurface: icbFrozenV1(0), descriptors: make([]SimplicityDeploymentDescriptor, 2), have: true}
	w, ok = initial148CompleteTariffV1(in)
	// d=2 concrete descriptors add 2*16,384.
	logicalMDBXAssert(t, ok && w == 18_417_692-8+384+32_768, "W descriptor literal: %d/%v", w, ok)
}

func TestInitial148CompleteBlockLocalRefusalOrder(t *testing.T) {
	w := btNew(t)
	local := func(err error) bool {
		var failure *logicalStateFailure
		return errors.As(err, &failure) && failure.kind == logicalStateFailureLocalInvariant
	}
	cases := []struct {
		name string
		edit func(*initial148CompleteBlockInputV1)
		want func(error) bool
	}{
		{"nil-cap-registry", func(in *initial148CompleteBlockInputV1) { in.CapRegistry = nil }, local},
		{"nil-suite-registry", func(in *initial148CompleteBlockInputV1) { in.Registry = nil }, local},
		{"unbound-rotation", func(in *initial148CompleteBlockInputV1) { in.Rotation = DefaultRotationProvider{} }, local},
		{"rotation-other-height", func(in *initial148CompleteBlockInputV1) {
			in.Rotation = &boundSpendSurface{height: 2, haveCreate: true, haveSpend: true}
		}, local},
		{"rotation-before-capacity", func(in *initial148CompleteBlockInputV1) {
			in.Rotation, in.Raw = nil, make([]byte, initial148BlockMaxBytes+1)
		}, local},
		{"capacity-before-identity", func(in *initial148CompleteBlockInputV1) {
			in.Raw, in.Generation = make([]byte, initial148BlockMaxBytes+1), 0
		}, func(err error) bool { return errors.Is(err, ErrInitial148BlockCapacity) }},
		{"zero-generation", func(in *initial148CompleteBlockInputV1) { in.Generation = 0 }, local},
		{"zero-database", func(in *initial148CompleteBlockInputV1) { in.DatabaseID = [32]byte{} }, local},
		{"height-above-u32", func(in *initial148CompleteBlockInputV1) { in.Height = 1 << 32 }, local},
		{"parent-hash-differs", func(in *initial148CompleteBlockInputV1) { in.ParentHash[0] ^= 1 }, local},
		{"endpoint-height", func(in *initial148CompleteBlockInputV1) { in.Endpoint.Height = 2 }, local},
		{"positive-published-genesis", func(in *initial148CompleteBlockInputV1) { in.PublishedGenesis = in.Raw }, local},
		{"identity-before-target", func(in *initial148CompleteBlockInputV1) { in.Generation, in.ExpectedTarget = 0, [32]byte{} }, local},
		{"target-context", func(in *initial148CompleteBlockInputV1) { in.ExpectedTarget = [32]byte{} }, func(err error) bool { return errors.Is(err, ErrBlockSteps1To12Context) }},
		{"timestamp-context", func(in *initial148CompleteBlockInputV1) { in.ParentTimestamps = nil }, func(err error) bool { return errors.Is(err, ErrBlockSteps1To12Context) }},
		{"genesis-generated", func(in *initial148CompleteBlockInputV1) {
			*in = icbGenesisContextV1(*in)
			in.AlreadyGenerated = Uint128{Lo: 1}
		}, local},
		{"genesis-published-differs", func(in *initial148CompleteBlockInputV1) {
			*in = icbGenesisContextV1(*in)
			in.PublishedGenesis = make([]byte, len(in.Raw)+1)
		}, local},
		{"genesis-zero-target", func(in *initial148CompleteBlockInputV1) {
			*in = icbGenesisContextV1(*in)
			in.ExpectedTarget = [32]byte{}
		}, func(err error) bool { return errors.Is(err, ErrBlockSteps1To12Context) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := icbInputV1()
			tc.edit(&in)
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				called := false
				out, err := withInitial148CompleteBlockV1(account, in, func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
					called = true
					return nil
				})
				logicalMDBXAssert(t, tc.want(err) && !called && out == (initial148CompleteBlockOutcomeV1{}), "%s: err=%v called=%v out=%+v", tc.name, err, called, out)
			})
		})
	}
	icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
		out, err := withInitial148CompleteBlockV1(nil, icbInputV1(), func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error { return nil })
		logicalMDBXAssert(t, local(err) && out == (initial148CompleteBlockOutcomeV1{}), "nil account: %v", err)
		out, err = withInitial148CompleteBlockV1(account, icbInputV1(), nil)
		logicalMDBXAssert(t, local(err) && out == (initial148CompleteBlockOutcomeV1{}), "nil run: %v", err)
	})
}

func icbGenesisContextV1(in initial148CompleteBlockInputV1) initial148CompleteBlockInputV1 {
	in.Height, in.ParentHash, in.ParentTimestamps, in.PublishedGenesis = 0, [32]byte{}, nil, in.Raw
	in.Parent = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointPreGenesisV1}
	in.Endpoint.Height = 0
	in.Rotation = icbFrozenV1(0)
	return in
}

// TestInitial148CompleteBlockReservationBoundary holds bytes on the same account
// so that exactly W remains, then W-1: the latter refuses before run.
func TestInitial148CompleteBlockReservationBoundary(t *testing.T) {
	w := btNew(t)
	in := icbInputV1()
	tariff, ok := initial148CompleteTariffV1(in)
	logicalMDBXAssert(t, ok, "tariff")
	for _, spare := range []uint64{0, 1} {
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			// TREE_LANE_MAX=402,653,184 is the TreeOperation account ceiling.
			err := account.WithReservation(402_653_184-tariff+spare, func() error {
				called := false
				out, err := withInitial148CompleteBlockV1(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
					called = true
					return errors.New("stop after admission")
				})
				if spare == 0 {
					logicalMDBXAssert(t, called && err != nil && err.Error() == "stop after admission" && !out.attempted, "exact W residual: called=%v err=%v", called, err)
					return nil
				}
				logicalMDBXAssert(t, !called && mdbx.IsOperationReservationCapacity(err) && out == (initial148CompleteBlockOutcomeV1{}), "W-1 residual: called=%v err=%v", called, err)
				return nil
			})
			logicalMDBXAssert(t, err == nil, "pre-hold: %v", err)
		})
	}
}

// icbStepsErrorV1 is the exact steps 1-12 refusal of the fixed failing body.
func icbStepsErrorV1(t *testing.T, in initial148CompleteBlockInputV1) error {
	t.Helper()
	_, err := ValidateInitial148BlockSteps1To12(in.Raw, in.ParentHash, in.ExpectedTarget, in.Height, in.ParentTimestamps)
	var txErr *TxError
	logicalMDBXAssert(t, errors.As(err, &txErr), "fixture body must fail steps 1-12 with a TxError: %v", err)
	return err
}

func icbEntryV1(parallel bool) func(*mdbx.OperationAccount, initial148CompleteBlockInputV1, initial148CompleteRunV1) (initial148CompleteBlockOutcomeV1, error) {
	if parallel {
		return func(a *mdbx.OperationAccount, in initial148CompleteBlockInputV1, run initial148CompleteRunV1) (initial148CompleteBlockOutcomeV1, error) {
			return withInitial148CompleteBlockParallelV1(a, in, 2, run)
		}
	}
	return withInitial148CompleteBlockV1
}

func TestInitial148CompleteBlockRunProtocol(t *testing.T) {
	w := btNew(t)
	in := icbInputV1()
	want := icbStepsErrorV1(t, in)
	same := func(err error) bool { return icbSameTxErrorV1(err, want) }
	for _, parallel := range []bool{false, true} {
		entry := icbEntryV1(parallel)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			var retained func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)
			out, err := entry(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				retained = validate
				return w.s.View(func(reader *mdbx.Reader) error {
					result, verr := validate(reader)
					logicalMDBXAssert(t, result == nil && same(verr), "validation rejection must deliver no result: %v", verr)
					again, aerr := validate(reader)
					logicalMDBXAssert(t, again == nil && aerr != nil && !same(aerr), "repeated validate must refuse locally: %v", aerr)
					return verr
				})
			})
			logicalMDBXAssert(t, out.attempted && same(out.validationErr) && same(err) && !out.required.derived && out.required.cause == nil, "propagated rejection: %+v / %v", out, err)
			late, lerr := retained(nil)
			logicalMDBXAssert(t, late == nil && lerr != nil, "expired validate must refuse: %v", lerr)

			out, err = entry(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				return w.s.View(func(reader *mdbx.Reader) error {
					_, _ = validate(reader)
					return nil // incorrectly suppressed rejection
				})
			})
			logicalMDBXAssert(t, out.attempted && same(err), "suppressed rejection is never success: %+v / %v", out, err)

			out, err = entry(account, in, func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error { return nil })
			var failure *logicalStateFailure
			logicalMDBXAssert(t, !out.attempted && errors.As(err, &failure) && failure.kind == logicalStateFailureLocalInvariant, "nil run without validate: %v", err)

			native := errors.New("native admission before validate")
			out, err = entry(account, in, func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error { return native })
			logicalMDBXAssert(t, !out.attempted && errors.Is(err, native) && out.validationErr == nil, "run error before validate: %v", err)
		})
	}
}

func TestInitial148CompleteBlockRunUnwind(t *testing.T) {
	w := btNew(t)
	in := icbInputV1()
	icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
		recovered := func() (r any) {
			defer func() { r = recover() }()
			_, _ = withInitial148CompleteBlockV1(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				_ = w.s.View(func(reader *mdbx.Reader) error {
					_, _ = validate(reader)
					return nil
				})
				panic("enclosing run panic")
			})
			return nil
		}()
		logicalMDBXAssert(t, recovered == "enclosing run panic", "run panic must propagate: %v", recovered)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = withInitial148CompleteBlockParallelV1(account, in, 0, func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				runtime.Goexit()
				return nil
			})
		}()
		<-done
		// A fresh invocation after unwinding admits again with the same W.
		_, err := withInitial148CompleteBlockV1(account, in, func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error { return errors.New("fresh") })
		logicalMDBXAssert(t, err != nil && err.Error() == "fresh", "fresh invocation after unwind: %v", err)
	})
}

// icbGenesisInputV1 binds the published initial148 genesis literal as the
// admitted h0 body; flip (when >= 0) toggles one utxo_root header byte.
func icbGenesisInputV1(t *testing.T, flip int) (initial148CompleteBlockInputV1, Initial148Header) {
	t.Helper()
	raw := initial148BlockGenesis(t)
	if flip >= 0 {
		raw[108+flip] ^= 0x01
	}
	header, err := ParseInitial148HeaderBytes(raw[:Initial148HeaderBytes])
	logicalMDBXAssert(t, err == nil, "genesis header: %v", err)
	hash, err := Initial148BlockHash(raw[:Initial148HeaderBytes])
	logicalMDBXAssert(t, err == nil, "genesis hash: %v", err)
	in := icbGenesisContextV1(icbInputV1())
	in.Raw, in.PublishedGenesis, in.ExpectedTarget = raw, raw, header.Target
	// The enclosing owner supplies the qualified cumulative work; any nonzero
	// value is an admissible immutable operation input here.
	in.Endpoint.BlockHash, in.Endpoint.CumulativeChainwork = hash, [40]byte{39: 1}
	return in, header
}

func icbValidateOnceV1(t *testing.T, w *btWorld, account *mdbx.OperationAccount, in initial148CompleteBlockInputV1, parallel bool) (initial148CompleteBlockOutcomeV1, *initial148CompleteBlockResultV1, initial148CompleteBlockResultV1, error) {
	t.Helper()
	var delivered *initial148CompleteBlockResultV1
	var copied initial148CompleteBlockResultV1
	out, err := icbEntryV1(parallel)(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			result, verr := validate(reader)
			if result != nil {
				delivered, copied = result, *result
				copied.transition = &connectBlockInputViewResult{}
				*copied.transition = *result.transition
			}
			return verr
		})
	})
	return out, delivered, copied, err
}

func TestInitial148CompleteBlockGenesisAccept(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		in, header := icbGenesisInputV1(t, -1)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, delivered, got, err := icbValidateOnceV1(t, w, account, in, parallel)
			logicalMDBXAssert(t, err == nil && out.validationErr == nil && out.attempted && delivered != nil, "parallel=%v genesis acceptance: %v / %+v", parallel, err, out)
			logicalMDBXAssert(t, out.required.derived && out.required.cause == nil && out.required.root == header.UtxoRoot, "parallel=%v fresh D root %x want header %x", parallel, out.required.root, header.UtxoRoot)
			logicalMDBXAssert(t, got.summary.TxCount == 1 && got.summary.BlockHash == in.Endpoint.BlockHash, "genesis summary: %+v", got.summary)
			logicalMDBXAssert(t, got.transition.alreadyGeneratedN1 == (Uint128{}) && got.transition.sumFees == (Uint128{}) && len(got.transition.createdUtxos) != 0, "genesis transition: %+v", got.transition)
			logicalMDBXAssert(t, got.effect.Primitive.Height == 0 && got.effect.Primitive.Block == in.Endpoint.BlockHash, "genesis effect identity: %+v", got.effect.Primitive)
			// After run the frame released the delivered result.
			logicalMDBXAssert(t, delivered.transition == nil && delivered.effect.Primitive.Source == nil, "result escaped run: %+v", *delivered)
		})
	}
}

func TestInitial148CompleteBlockRootMismatch(t *testing.T) {
	for _, flip := range []int{0, 31} {
		for _, parallel := range []bool{false, true} {
			w := btNew(t)
			in, header := icbGenesisInputV1(t, flip)
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				out, delivered, _, err := icbValidateOnceV1(t, w, account, in, parallel)
				var txErr *TxError
				logicalMDBXAssert(t, errors.As(err, &txErr) && txErr.Code == BLOCK_ERR_UTXO_ROOT_MISMATCH && txErr.Msg == "utxo_root mismatch" && any(out.validationErr) == any(err), "flip=%d parallel=%v mismatch: %v", flip, parallel, err)
				logicalMDBXAssert(t, delivered == nil && out.attempted && out.required.derived && out.required.cause == nil && out.required.root != header.UtxoRoot, "flip=%d mismatch outcome: %+v", flip, out)
			})
		}
	}
}

// TestInitial148CompleteBlockEarlierErrorBeforeD (C06) flips the coinbase
// da_payload_len byte (the last body byte) and the header root together: the prefix merkle refusal wins and D
// never runs, so no derived root or observation is reported.
func TestInitial148CompleteBlockEarlierErrorBeforeD(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		in, _ := icbGenesisInputV1(t, 0)
		raw := append([]byte(nil), in.Raw...)
		raw[len(raw)-1] ^= 0x01
		in.Raw, in.PublishedGenesis = raw, raw
		hash, err := Initial148BlockHash(raw[:Initial148HeaderBytes])
		logicalMDBXAssert(t, err == nil, "hash: %v", err)
		in.Endpoint.BlockHash = hash
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, delivered, _, err := icbValidateOnceV1(t, w, account, in, parallel)
			var txErr *TxError
			logicalMDBXAssert(t, errors.As(err, &txErr) && txErr.Code == TX_ERR_PARSE && txErr.Msg == "da_payload_len must be 0 for tx_kind=0x00" && any(out.validationErr) == any(err), "parallel=%v earlier error must win: %v", parallel, err)
			logicalMDBXAssert(t, delivered == nil && out.attempted && out.required == (initial148RootReadOutcomeV1{}), "parallel=%v no D after earlier error: %+v", parallel, out)
		})
	}
}

// TestInitial148CompleteBlockRunErrorAfterSuccess (C13) keeps the enclosing
// run error after a root-valid validation; the captured success is not a
// commit and the run error is never replaced by a validation projection.
func TestInitial148CompleteBlockRunErrorAfterSuccess(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		in, header := icbGenesisInputV1(t, -1)
		native := errors.New("native writer failure after builder return")
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, err := icbEntryV1(parallel)(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				verr := w.s.View(func(reader *mdbx.Reader) error {
					result, verr := validate(reader)
					logicalMDBXAssert(t, result != nil && verr == nil, "parallel=%v success: %v", parallel, verr)
					return verr
				})
				if verr != nil {
					return verr
				}
				return native
			})
			logicalMDBXAssert(t, errors.Is(err, native) && out.attempted && out.validationErr == nil, "parallel=%v run error kept: %v / %+v", parallel, err, out)
			logicalMDBXAssert(t, out.required.derived && out.required.root == header.UtxoRoot, "parallel=%v D evidence kept: %+v", parallel, out.required)
			// A fresh next invocation succeeds on the same account.
			out2, delivered, _, err2 := icbValidateOnceV1(t, w, account, in, parallel)
			logicalMDBXAssert(t, err2 == nil && delivered != nil && out2.required.derived, "parallel=%v fresh retry: %v", parallel, err2)
		})
	}
}

// TestInitial148CompleteBlockRunErrorAfterRejection (C13) returns a distinct
// enclosing error after a validation rejection: the outer entry returns that
// run error exactly and keeps the rejection only as validationErr.
func TestInitial148CompleteBlockRunErrorAfterRejection(t *testing.T) {
	w := btNew(t)
	in := icbInputV1()
	want := icbStepsErrorV1(t, in)
	native := errors.New("enclosing cleanup failure after rejection")
	for _, parallel := range []bool{false, true} {
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, err := icbEntryV1(parallel)(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				_ = w.s.View(func(reader *mdbx.Reader) error {
					_, verr := validate(reader)
					return verr
				})
				return native
			})
			logicalMDBXAssert(t, errors.Is(err, native) && out.attempted && icbSameTxErrorV1(out.validationErr, want), "parallel=%v run error not overwritten: %v / %+v", parallel, err, out)
		})
	}
}

// icbSameTxErrorV1 compares two independently produced TxErrors by code and message.
func icbSameTxErrorV1(got, want error) bool {
	var g, w *TxError
	return errors.As(got, &g) && errors.As(want, &w) && g.Code == w.Code && g.Msg == w.Msg
}

// TestInitial148CompleteBlockEarlierConnectErrorBeforeD (C06) keeps the genesis
// body intact but freezes an empty create-suite set, so the refusal happens
// inside the candidate after source preparation; D still never runs.
func TestInitial148CompleteBlockEarlierConnectErrorBeforeD(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		in, _ := icbGenesisInputV1(t, 0)
		frozen := icbFrozenV1(0)
		frozen.create = NewNativeSuiteSet()
		in.Rotation = frozen
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, delivered, _, err := icbValidateOnceV1(t, w, account, in, parallel)
			var txErr *TxError
			logicalMDBXAssert(t, errors.As(err, &txErr) && txErr.Code == TX_ERR_SIG_ALG_INVALID && txErr.Msg == "CORE_P2PK suite not in native create set" && any(out.validationErr) == any(err), "parallel=%v earlier connect error must win: %v", parallel, err)
			logicalMDBXAssert(t, delivered == nil && out.attempted && out.required == (initial148RootReadOutcomeV1{}), "parallel=%v no D after earlier error: %+v", parallel, out)
		})
	}
}

// TestInitial148CompleteBlockDeriveCapacityNoResult (C10) leaves room on the
// same account for W, the source scratch and R, but not D: derived=false keeps
// the raw capacity cause as the validation error, never a root mismatch, and
// no result is delivered. R=69,656+196,824E and D=288,408+104E use the
// genesis source EventCount E.
func TestInitial148CompleteBlockDeriveCapacityNoResult(t *testing.T) {
	// The published genesis source records one event (E=1).
	const genesisEvents = 1
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		in, _ := icbGenesisInputV1(t, -1)
		tariff, ok := initial148CompleteTariffV1(in)
		logicalMDBXAssert(t, ok, "tariff")
		hold := uint64(402_653_184) - tariff - (69_656 + 196_824*genesisEvents) - (288_408 + 104*genesisEvents)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			// Control: with exactly D remaining the same input derives and is delivered.
			logicalMDBXAssert(t, account.WithReservation(hold, func() error {
				out, delivered, _, err := icbValidateOnceV1(t, w, account, in, parallel)
				logicalMDBXAssert(t, err == nil && delivered != nil && out.required.derived, "parallel=%v exact D residual: %v / %+v", parallel, err, out)
				return nil
			}) == nil, "pre-hold control")
			logicalMDBXAssert(t, account.WithReservation(hold+1, func() error {
				out, delivered, _, err := icbValidateOnceV1(t, w, account, in, parallel)
				var txErr *TxError
				logicalMDBXAssert(t, !errors.As(err, &txErr), "parallel=%v derive capacity became a TxError: %v", parallel, err)
				logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(err) && any(out.validationErr) == any(err) && any(out.required.cause) == any(err), "parallel=%v raw D cause lost: %v / %+v", parallel, err, out)
				logicalMDBXAssert(t, delivered == nil && out.attempted && !out.required.derived && out.required.root == ([32]byte{}) && !out.required.hasObservation, "parallel=%v D capacity outcome: %+v", parallel, out)
				return nil
			}) == nil, "pre-hold")
		})
	}
}

// icbKeyDERV1 is a 54-byte seed-only ML-DSA-87 PKCS#8 key (seed = repeat(a5, 32)),
// so every fixture txid and wtxid below is deterministic.
const icbKeyDERV1 = "3034020100300b060960864801650304031304228020" +
	"a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"

// icbFinalRootHexV1 is CSM 2.6 Root of the final map {C, cb:0, tx2:0}, computed
// independently from the section 2.6 text over the literal leaf bytes.
// icbHeightV1 block at height 5 spends rows of an Applied parent at height 4.
// already_generated(5) = sum of block_subsidy(1..4) and already_generated(6)
// under L1 section 19.1 (MINEABLE_CAP 4.9e15, shift 20, tail 19,025,875).
const (
	icbHeightV1       = 5
	icbGenerated5V1   = 18_691_989_860
	icbGenerated6V1   = 23_364_976_184
	icbFinalRootHexV1 = "2a7a92ce203c7af8d45e4deb964bd2d15ea7f22c02405f2ee7ad738ac51153de"
)

// icbH5V1 is the h>0 fixture: seeded parent rows C (coinbase, immature),
// A and B (P2PK to the fixture key); block txs cb, tx1 (A -> O1) and
// tx2 (O1 + B -> O2). Final map: C, cb:0, tx2:0. Absent: A, B, the in-block
// created-then-spent O1 and the nonspendable cb:1 anchor.
type icbH5V1 struct {
	h                         uint64
	in                        initial148CompleteBlockInputV1
	header                    Initial148Header
	c, a, b, o1, cb0, o2      Outpoint
	v, o3, s, o4              Outpoint
	parentLeaves, finalLeaves map[[36]byte][]byte
	preSpendLeaves            map[[36]byte][]byte
	created                   map[Outpoint]UtxoEntry
}

func icbKeyV1(t *testing.T) *MLDSA87Keypair {
	t.Helper()
	der, err := hex.DecodeString(icbKeyDERV1)
	logicalMDBXAssert(t, err == nil, "key literal: %v", err)
	kp, err := NewMLDSA87KeypairFromDER(der)
	if err != nil && strings.Contains(err.Error(), "unsupported") {
		t.Skipf("ML-DSA backend unavailable: %v", err)
	}
	logicalMDBXAssert(t, err == nil, "fixture key: %v", err)
	t.Cleanup(kp.Close)
	return kp
}

// icbSignV1 signs every input with deterministic FIPS 204 ML-DSA.
func icbSignV1(t *testing.T, kp *MLDSA87Keypair, tx *Tx, values ...uint64) []byte {
	t.Helper()
	for i, value := range values {
		digest, err := SighashV1DigestWithType(tx, uint32(i), value, [32]byte{}, SIGHASH_ALL)
		logicalMDBXAssert(t, err == nil, "sighash: %v", err)
		sig, err := kp.SignDigest32ForConformanceFixture(digest)
		logicalMDBXAssert(t, err == nil, "deterministic sign: %v", err)
		tx.Witness[i] = WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Signature: append(sig, SIGHASH_ALL)}
	}
	raw, err := MarshalTx(tx)
	logicalMDBXAssert(t, err == nil, "marshal: %v", err)
	return raw
}

func icbSignedRawV1(t *testing.T, tx *Tx) []byte {
	t.Helper()
	raw, err := MarshalTx(tx)
	logicalMDBXAssert(t, err == nil, "marshal: %v", err)
	return raw
}

// icbLeafV1 is CSM 2.6 K(op) and S(op,e) built from literal fields.
func icbLeafV1(leaves map[[36]byte][]byte, op Outpoint, value uint64, data []byte, height uint64, coinbase bool) {
	var key [36]byte
	copy(key[:], op.Txid[:])
	binary.BigEndian.PutUint32(key[32:], op.Vout)
	s := binary.LittleEndian.AppendUint32(bytes.Clone(op.Txid[:]), op.Vout)
	leaves[key] = append(s, btValue(btFrame(value, COV_TYPE_P2PK, data), height, coinbase)...)
}

// icbRootV1 is the written CSM 2.6 recursion with literal 19-byte domains.
func icbRootV1(leaves map[[36]byte][]byte) [32]byte {
	keys := make([][36]byte, 0, len(leaves))
	for k := range leaves {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y [36]byte) int { return bytes.Compare(x[:], y[:]) })
	return icbNodeV1(keys, leaves)
}

func icbNodeV1(keys [][36]byte, leaves map[[36]byte][]byte) [32]byte {
	domain, _ := hex.DecodeString("525542494e5f5554584f5f545245455f5631")
	switch len(keys) {
	case 0:
		return sha3.Sum256(append(domain, 0x00))
	case 1:
		return sha3.Sum256(append(append(domain, 0x01), leaves[keys[0]]...))
	}
	d := 0
	for icbBitV1(keys[0], d) == icbBitV1(keys[len(keys)-1], d) {
		d++
	}
	var prefix [36]byte
	copy(prefix[:d/8], keys[0][:d/8])
	if d%8 != 0 {
		prefix[d/8] = keys[0][d/8] & byte(0xff<<(8-d%8))
	}
	split := slices.IndexFunc(keys, func(k [36]byte) bool { return icbBitV1(k, d) == 1 })
	left, right := icbNodeV1(keys[:split], leaves), icbNodeV1(keys[split:], leaves)
	pre := binary.BigEndian.AppendUint16(append(domain, 0x02), uint16(d))
	pre = append(append(append(pre, prefix[:]...), left[:]...), right[:]...)
	return sha3.Sum256(pre)
}

func icbBitV1(k [36]byte, i int) byte { return (k[i/8] >> (7 - i%8)) & 1 }

// icbSeedV1 applies the parent block at height 4 through the real native
// operation and returns its endpoint.
func icbSeedV1(t *testing.T, w *btWorld, cov []byte, height uint64, extra ...[]byte) (blockTreeRequestV1, btTx, btTx) {
	t.Helper()
	tx0 := btTransaction(41, 0, nil, [][]byte{btFrame(7, COV_TYPE_P2PK, validP2PKCovenantData())}, nil, []byte{0}, nil)
	frames := append([][]byte{btFrame(1000, COV_TYPE_P2PK, cov), btFrame(2000, COV_TYPE_P2PK, cov)}, extra...)
	tx1 := btTransaction(42, 0, nil, frames, nil, []byte{0}, nil)
	seed := btRequest(btBody(148, 41, [32]byte{}, tx0, tx1), height-1)
	result, _, _ := w.run(t, []blockTreeRequestV1{seed}, nil)
	logicalMDBXAssert(t, result.err == nil, "parent seed: %v", result.err)
	return seed, tx0, tx1
}

func icbH5FixtureV1(t *testing.T, w *btWorld) icbH5V1 {
	t.Helper()
	return icbH5VariantV1(t, w, icbH5OptsV1{})
}

// icbH5OptsV1 perturbs one dimension of the h=5 fixture: tx1 spends an
// unseeded outpoint (missing), tx1's signature is corrupted (badSig), tx2
// creates one unit more than it spends (overspend), the coinbase pays
// cbExtra above the fee-only output, or header root byte flip-1 is inverted.
// height (0: icbHeightV1) moves the whole fixture; split pays the coinbase
// as two P2PK outputs of 10 (net +1 row, +89 logical bytes); dup makes tx2
// spend A again after tx1's in-block spend (tombstone) instead of B.
// tx2 edits tx2 before it is signed; post2 edits the signed tx2. vault seeds
// a parent Vault row V and appends tx3 (V + O2 -> O3); tx3 edits it before
// signing. simplicity (with vault) also seeds a CORE_SIMPLICITY row S, freezes
// an active deployment at the fixture height and appends tx4 (S -> O4).
type icbH5OptsV1 struct {
	missing, badSig, overspend, split, dup bool
	cbExtra, height                        uint64
	flip                                   int
	tx2, post2, tx3                        func(*Tx)
	vault, simplicity                      bool
}

func icbH5VariantV1(t *testing.T, w *btWorld, opts icbH5OptsV1) icbH5V1 {
	t.Helper()
	kp := icbKeyV1(t)
	cov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	h := max(opts.height, icbHeightV1)
	seed, tx0, seedTx := icbSeedV1(t, w, cov, h, icbVaultFramesV1(opts, kp, cov)...)
	f := icbH5V1{h: h, c: Outpoint{Txid: tx0.id}, a: Outpoint{Txid: seedTx.id}, b: Outpoint{Txid: seedTx.id, Vout: 1}, v: Outpoint{Txid: seedTx.id, Vout: 2}, s: Outpoint{Txid: seedTx.id, Vout: 3}}
	spend1 := f.a
	if opts.missing {
		spend1 = Outpoint{Txid: [32]byte{0x99}}
	}
	tx1 := inputViewTx(1, spend1)
	tx1.Outputs[0] = TxOutput{Value: 990, CovenantType: COV_TYPE_P2PK, CovenantData: cov}
	raw1 := icbSignV1(t, kp, tx1, 1000)
	if opts.badSig {
		tx1.Witness[0].Signature[0] ^= 0x01
		raw1 = icbSignedRawV1(t, tx1)
	}
	f.o1 = Outpoint{Txid: testTxID(t, raw1)}
	raw2 := icbTx2V1(t, kp, cov, &f, opts)
	f.o2 = Outpoint{Txid: testTxID(t, raw2)}
	txs := [][]byte{raw1, raw2}
	if opts.vault {
		txs = append(txs, f.icbVaultTx3V1(t, kp, cov, opts))
	}
	if opts.simplicity {
		txs = append(txs, f.icbSimplicityTx4V1(t, cov))
	}
	commit := initial148BlockWitnessCommit(t, txs...)
	cbOuts := []testOutput{{value: 20 + opts.cbExtra, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}}
	if opts.split {
		cbOuts = []testOutput{{value: 10, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}, {value: 10, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}}
	}
	cb := coinbaseTxWithOutputs(uint32(h), append(cbOuts, testOutput{covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]}))
	f.cb0 = Outpoint{Txid: testTxID(t, cb)}
	f.icbLeavesV1(cov, cbOuts[0].value)
	f.icbVaultLeavesV1(cov)
	if opts.split {
		icbLeafV1(f.finalLeaves, Outpoint{Txid: f.cb0.Txid, Vout: 1}, 10, validP2PKCovenantData(), h, true)
	}
	root := icbRootV1(f.finalLeaves)
	if opts.flip > 0 {
		root[opts.flip-1] ^= 0x80
	}
	raw := initial148BlockFrame(t, append([][]byte{cb}, txs...), func(h *initial148BlockHead) { h.parent, h.root = seed.Block, root })
	hash, err := Initial148BlockHash(raw[:Initial148HeaderBytes])
	logicalMDBXAssert(t, err == nil, "block hash: %v", err)
	f.header, err = ParseInitial148HeaderBytes(raw[:Initial148HeaderBytes])
	logicalMDBXAssert(t, err == nil, "header: %v", err)
	f.in = icbInputV1()
	f.in.Raw, f.in.Height, f.in.ParentHash, f.in.ExpectedTarget = raw, h, seed.Block, POW_LIMIT
	f.in.ParentTimestamps = slices.Repeat([]uint64{blockStepsMedian}, int(min(h, 11)))
	f.in.AlreadyGenerated, f.in.Parent, f.in.Rotation = Uint128{Lo: icbGenerated5V1}, seed.Endpoint, icbFrozenV1(h)
	f.in.Registry = DefaultSuiteRegistry()
	if opts.simplicity {
		f.in.Rotation = icbSimplicityFrozenV1(h, f.in.ChainID)
	}
	f.in.Endpoint = mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointAppliedV1, Height: h, BlockHash: hash, CumulativeChainwork: [40]byte{39: 100}}
	f.created = map[Outpoint]UtxoEntry{
		f.cb0: {Value: 20 + opts.cbExtra, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData(), CreationHeight: h, CreatedByCoinbase: true},
		f.o2:  {Value: 2980, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: h},
	}
	return f
}

// icbTx2V1 signs tx2 (O1 + B -> O2) with the opts perturbations.
func icbTx2V1(t *testing.T, kp *MLDSA87Keypair, cov []byte, f *icbH5V1, opts icbH5OptsV1) []byte {
	t.Helper()
	spend2 := f.b
	if opts.dup {
		spend2 = f.a
	}
	tx2 := inputViewTx(2, f.o1, spend2)
	tx2.Outputs[0] = TxOutput{Value: 2980, CovenantType: COV_TYPE_P2PK, CovenantData: cov}
	if opts.overspend {
		tx2.Outputs[0].Value = 2991
	}
	if opts.tx2 != nil {
		opts.tx2(tx2)
	}
	raw2 := icbSignV1(t, kp, tx2, 990, 2000)
	if opts.post2 == nil {
		return raw2
	}
	opts.post2(tx2)
	return icbSignedRawV1(t, tx2)
}

// icbVaultCovV1 is a 1-of-1 CORE_VAULT to the fixture key whose owner lock
// and only whitelisted destination are both the fixture P2PK descriptor.
func icbVaultCovV1(kp *MLDSA87Keypair, cov []byte) []byte {
	lock := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, cov))
	return encodeVaultCovenantData(lock, 1, [][32]byte{sha3_256(kp.PubkeyBytes())}, [][32]byte{lock})
}

// icbVaultFramesV1 adds the parent Vault row V (500) for opts.vault.
func icbVaultFramesV1(opts icbH5OptsV1, kp *MLDSA87Keypair, cov []byte) [][]byte {
	if !opts.vault {
		return nil
	}
	frames := [][]byte{btFrame(500, COV_TYPE_VAULT, icbVaultCovV1(kp, cov))}
	if opts.simplicity {
		frames = append(frames, btFrame(300, COV_TYPE_CORE_SIMPLICITY, encodeSimplicityCovenantData(coreSimplicityAcceptCMR, nil)))
	}
	return frames
}

// icbSimplicityTx4V1 spends S with the accept program (fee 10).
func (f *icbH5V1) icbSimplicityTx4V1(t *testing.T, cov []byte) []byte {
	t.Helper()
	tx4 := inputViewTx(4, f.s)
	tx4.Outputs[0] = TxOutput{Value: 290, CovenantType: COV_TYPE_P2PK, CovenantData: cov}
	tx4.Witness = []WitnessItem{coreSimplicityAcceptWitness()}
	raw4 := icbSignedRawV1(t, tx4)
	f.o4 = Outpoint{Txid: testTxID(t, raw4)}
	return raw4
}

// icbSimplicityFrozenV1 is the caller-frozen surface with the active test
// deployment already read, as the composer admits it.
func icbSimplicityFrozenV1(height uint64, chainID [32]byte) *boundSpendSurfaceWithDeployment {
	rp := activeSimplicityRotation(chainID, 1).(testRotationProvider)
	base := &boundSpendSurface{inner: rp, height: height, haveCreate: true, haveSpend: true, create: rp.NativeCreateSuites(height), spend: rp.NativeSpendSuites(height)}
	d, anchor, ok, err := rp.PublishedSimplicityDeployments()
	return &boundSpendSurfaceWithDeployment{boundSpendSurface: base, provider: rp, descriptors: d, setAnchor: anchor, ok: ok, err: err, have: true}
}

// icbVaultTx3V1 signs tx3 (V + O2 -> O3, fee 10): a Vault spend whose
// owner-authorized input O2 was created by tx2 in this block.
func (f *icbH5V1) icbVaultTx3V1(t *testing.T, kp *MLDSA87Keypair, cov []byte, opts icbH5OptsV1) []byte {
	t.Helper()
	tx3 := inputViewTx(3, f.v, f.o2)
	tx3.Outputs[0] = TxOutput{Value: 3470, CovenantType: COV_TYPE_P2PK, CovenantData: cov}
	if opts.tx3 != nil {
		opts.tx3(tx3)
	}
	raw3 := icbSignV1(t, kp, tx3, 500, 2980)
	f.o3 = Outpoint{Txid: testTxID(t, raw3)}
	return raw3
}

// icbVaultLeavesV1 replaces the spent O2 with O3 in the final map.
func (f *icbH5V1) icbVaultLeavesV1(cov []byte) {
	if f.o3 == (Outpoint{}) {
		return
	}
	var key [36]byte
	copy(key[:], f.o2.Txid[:])
	binary.BigEndian.PutUint32(key[32:], f.o2.Vout)
	delete(f.finalLeaves, key)
	icbLeafV1(f.finalLeaves, f.o3, 3470, cov, f.h, false)
	if f.o4 != (Outpoint{}) {
		icbLeafV1(f.finalLeaves, f.o4, 290, cov, f.h, false)
	}
}

// icbLeavesV1 builds the parent, pre-spend (after tx1, before tx2) and final
// leaf maps from literal fields.
func (f *icbH5V1) icbLeavesV1(cov []byte, cbValue uint64) {
	f.parentLeaves, f.preSpendLeaves, f.finalLeaves = map[[36]byte][]byte{}, map[[36]byte][]byte{}, map[[36]byte][]byte{}
	for _, m := range []map[[36]byte][]byte{f.parentLeaves, f.preSpendLeaves, f.finalLeaves} {
		icbLeafV1(m, f.c, 7, validP2PKCovenantData(), f.h-1, true)
	}
	icbLeafV1(f.parentLeaves, f.a, 1000, cov, f.h-1, false)
	icbLeafV1(f.parentLeaves, f.b, 2000, cov, f.h-1, false)
	for _, m := range []map[[36]byte][]byte{f.preSpendLeaves, f.finalLeaves} {
		icbLeafV1(m, f.cb0, cbValue, validP2PKCovenantData(), f.h, true)
	}
	icbLeafV1(f.preSpendLeaves, f.b, 2000, cov, f.h-1, false)
	icbLeafV1(f.preSpendLeaves, f.o1, 990, cov, f.h, false)
	icbLeafV1(f.finalLeaves, f.o2, 2980, cov, f.h, false)
}

// icbSpentV1 drains the single-pass preblock spent stream: tx2's in-block O1
// spend is not a parent row and is skipped.
func icbSpentV1(source *blockSpentInputSource) []blockSpentInput {
	var got []blockSpentInput
	for item, ok := source.next(); ok; item, ok = source.next() {
		got = append(got, item)
	}
	return got
}

type icbObservedV1 struct {
	out     initial148CompleteBlockOutcomeV1
	err     error
	summary BlockBasicSummary
	result  connectBlockInputViewResult
	spent   []blockSpentInput
	block   [32]byte
	height  uint64
}

func icbObserveV1(t *testing.T, w *btWorld, in initial148CompleteBlockInputV1, workers int) icbObservedV1 {
	t.Helper()
	var got icbObservedV1
	icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
		run := func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			return w.s.View(func(reader *mdbx.Reader) error {
				result, err := validate(reader)
				if result != nil {
					got.summary, got.result = result.summary, *result.transition
					got.block, got.height = result.effect.Primitive.Block, result.effect.Primitive.Height
					got.spent = icbSpentV1(result.transition.spentInputs)
				}
				return err
			})
		}
		if workers < 0 {
			got.out, got.err = withInitial148CompleteBlockV1(account, in, run)
			return
		}
		got.out, got.err = withInitial148CompleteBlockParallelV1(account, in, workers, run)
	})
	got.result.spentInputs = nil
	return got
}

// TestInitial148CompleteBlockAcceptH5 (C01, C03) accepts a signed h=5 block
// through both entries; the expected header root is the literal CSM 2.6
// encoding of the finite final map, pinned as icbFinalRootHexV1.
func TestInitial148CompleteBlockAcceptH5(t *testing.T) {
	var first *icbObservedV1
	for _, workers := range []int{-1, 1, 4} {
		w := btNew(t)
		f := icbH5FixtureV1(t, w)
		want, err := hex.DecodeString(icbFinalRootHexV1)
		logicalMDBXAssert(t, err == nil && bytes.Equal(f.header.UtxoRoot[:], want), "header root %x is not the pinned literal %s", f.header.UtxoRoot, icbFinalRootHexV1)
		parent, preSpend := icbRootV1(f.parentLeaves), icbRootV1(f.preSpendLeaves)
		logicalMDBXAssert(t, parent != f.header.UtxoRoot && preSpend != f.header.UtxoRoot && parent != preSpend, "parent/pre-spend/final roots must differ")
		got := icbObserveV1(t, w, f.in, workers)
		logicalMDBXAssert(t, got.err == nil && got.out.attempted && got.out.validationErr == nil, "workers=%d acceptance: %v / %+v", workers, got.err, got.out)
		logicalMDBXAssert(t, got.out.required.derived && got.out.required.cause == nil && !got.out.required.hasObservation && got.out.required.root == f.header.UtxoRoot, "workers=%d fresh D root %x", workers, got.out.required.root)
		logicalMDBXAssert(t, got.summary.TxCount == 3 && got.summary.BlockHash == f.in.Endpoint.BlockHash && got.block == f.in.Endpoint.BlockHash && got.height == icbHeightV1, "workers=%d identity: %+v", workers, got.summary)
		logicalMDBXAssert(t, got.result.sumFees == (Uint128{Lo: 20}) && got.result.alreadyGenerated == (Uint128{Lo: icbGenerated5V1}) && got.result.alreadyGeneratedN1 == (Uint128{Lo: icbGenerated6V1}), "workers=%d scalars: %+v", workers, got.result)
		logicalMDBXAssert(t, reflect.DeepEqual(got.result.createdUtxos, f.created), "workers=%d created: %+v", workers, got.result.createdUtxos)
		// Each spent parent row is StateEntryBytes of a 33-byte P2PK covenant: 45+44 = 89.
		wantSpent := []blockSpentInput{{outpoint: f.a, txIndex: 1, inputIndex: 0, logicalEntryLength: 89}, {outpoint: f.b, txIndex: 2, inputIndex: 1, logicalEntryLength: 89}}
		logicalMDBXAssert(t, reflect.DeepEqual(got.spent, wantSpent), "workers=%d spent stream: %+v", workers, got.spent)
		if first == nil {
			first = &got
			continue
		}
		same := got.summary == first.summary && got.out.required == first.out.required && got.block == first.block
		logicalMDBXAssert(t, same && reflect.DeepEqual(got.result, first.result) && reflect.DeepEqual(got.spent, first.spent), "workers=%d differs from sequential: %+v", workers, got)
	}
}

// icbComposeV1 is the enclosing builder: the root-valid result is composed
// into one TreeOperationV1 (header row, Primitive, both Index rows and
// CurrentBody), exactly as the existing bt operation composes a source.
func icbComposeV1(result *initial148CompleteBlockResultV1, observed *btObserved, header []byte, present bool) mdbx.TreeOperationV1 {
	var op mdbx.TreeOperationV1
	if !present {
		op.Pair.Mutations = append(op.Pair.Mutations, btMutation(3, bytes.Clone(result.effect.Primitive.Block[:]), bytes.Clone(header)))
	}
	op.Primitives = []mdbx.TreePrimitiveV1{result.effect.Primitive}
	op.Primitives[0].Source = observed
	op.Pair.Mutations = append(op.Pair.Mutations, result.effect.Index[:]...)
	if result.effect.CurrentBody.AfterKind != 0 {
		op.Pair.Mutations = append(op.Pair.Mutations, result.effect.CurrentBody)
	}
	btSort(op.Pair.Mutations)
	return op
}

// TestInitial148CompleteBlockUpdateTreeH5 (C13) composes the root-valid h=5
// result into a real Store.UpdateTreeV1 inside run: the native writer and
// readback consume the immutable source after the builder (and its Reader)
// returned, while W is still held on the same account; the native
// truth/stage/index are the owner's own values and the final rows are written.
func TestInitial148CompleteBlockUpdateTreeH5(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		f := icbH5FixtureV1(t, w)
		tariff, ok := initial148CompleteTariffV1(f.in)
		logicalMDBXAssert(t, ok, "tariff")
		var native btResult
		builderReturned, consumed := false, 0
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			observed := &btObserved{t: t}
			observed.before = func(mdbx.TreePositionV1, *mdbx.Reader, *mdbx.TreeDeltaSinkV1) error {
				logicalMDBXAssert(t, builderReturned, "parallel=%v source consumed before the builder returned", parallel)
				// W stays held: the remaining lane cannot fit another W.
				held := account.WithReservation(402_653_184-tariff+1, func() error { return nil })
				logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(held), "parallel=%v W released before native last use: %v", parallel, held)
				consumed++
				return nil
			}
			out, err := icbEntryV1(parallel)(account, f.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				native.truth, native.stage, native.index, native.err = w.s.UpdateTreeV1(account, func(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
					result, verr := validate(reader)
					if verr != nil {
						return mdbx.TreeOperationV1{}, verr
					}
					observed.source = result.effect.Primitive.Source.(*blockTreeSourceV1)
					_, present, gerr := reader.Get(mdbx.TreeSchemaV1DBIs()[3], result.effect.Primitive.Block[:])
					if gerr != nil {
						return mdbx.TreeOperationV1{}, gerr
					}
					op := icbComposeV1(result, observed, f.in.Raw[:Initial148HeaderBytes], present)
					builderReturned = true
					return op, nil
				})
				return native.err
			})
			logicalMDBXAssert(t, err == nil && out.attempted && out.validationErr == nil && out.required.root == f.header.UtxoRoot, "parallel=%v composed acceptance: %v / %+v", parallel, err, out)
		})
		native.want(t, 2, 3, -1)
		logicalMDBXAssert(t, consumed > 0, "parallel=%v native writer never consumed the source", parallel)
		cov := f.created[f.o2].CovenantData
		w.read(t, 1, btUTXOKey(1, f.o2), btValue(btFrame(2980, COV_TYPE_P2PK, cov), icbHeightV1, false))
		w.read(t, 1, btUTXOKey(1, f.cb0), btValue(btFrame(20, COV_TYPE_P2PK, validP2PKCovenantData()), icbHeightV1, true))
		w.read(t, 1, btUTXOKey(1, f.c), btValue(btFrame(7, COV_TYPE_P2PK, validP2PKCovenantData()), icbHeightV1-1, true))
		for _, gone := range []Outpoint{f.a, f.b, f.o1, {Txid: f.cb0.Txid, Vout: 1}} {
			w.read(t, 1, btUTXOKey(1, gone), nil)
		}
	}
}

// icbSubsidy5V1 is block_subsidy(5) = already_generated(6) - already_generated(5).
const icbSubsidy5V1 = icbGenerated6V1 - icbGenerated5V1

// icbCapAtV1 activates the cap for the fixture chain id from height.
func icbCapAtV1(in *initial148CompleteBlockInputV1, height uint64) {
	in.CapRegistry = &validatedLogicalStateCapRegistry{rows: []validatedLogicalStateCapRegistryRow{{chainID: in.ChainID, activationHeight: height}}}
}

type icbH5CaseV1 struct {
	name     string
	opts     icbH5OptsV1
	capFrom  uint64 // 0: inactive registry
	counters [2]uint64
	code     ErrorCode
	msg      string
	derived  bool
}

// icbH5RunCaseV1 observes one variant through every entry. A nil code means
// root-valid acceptance with fresh D; otherwise no result is delivered and D
// evidence is present only for the root mismatch.
func icbH5RunCaseV1(t *testing.T, c icbH5CaseV1) {
	t.Helper()
	for _, workers := range []int{-1, 1, 4} {
		w := btNew(t)
		f := icbH5VariantV1(t, w, c.opts)
		if c.capFrom != 0 {
			icbCapAtV1(&f.in, c.capFrom)
		}
		if c.counters != ([2]uint64{}) {
			irCounterV1(t, w, c.counters[0], c.counters[1])
		}
		got := icbObserveV1(t, w, f.in, workers)
		if c.code == "" {
			logicalMDBXAssert(t, got.err == nil && got.out.validationErr == nil && got.summary.TxCount == 3, "%s workers=%d acceptance: %v", c.name, workers, got.err)
			logicalMDBXAssert(t, got.out.required.derived && got.out.required.root == f.header.UtxoRoot, "%s workers=%d fresh D: %+v", c.name, workers, got.out.required)
			continue
		}
		// The selected error is the bare TxError itself, not a join carrying it.
		var txErr *TxError
		ok := errors.As(got.err, &txErr) && any(txErr) == any(got.err)
		logicalMDBXAssert(t, ok && txErr.Code == c.code && txErr.Msg == c.msg && any(got.out.validationErr) == any(got.err), "%s workers=%d error %v, want %s/%s", c.name, workers, got.err, c.code, c.msg)
		logicalMDBXAssert(t, got.out.attempted && got.summary == (BlockBasicSummary{}), "%s workers=%d result delivered: %+v", c.name, workers, got.summary)
		if !c.derived {
			logicalMDBXAssert(t, got.out.required == (initial148RootReadOutcomeV1{}), "%s workers=%d D ran after earlier error: %+v", c.name, workers, got.out.required)
			continue
		}
		final := icbRootV1(f.finalLeaves)
		logicalMDBXAssert(t, got.out.required.derived && got.out.required.cause == nil && got.out.required.root == final && final != f.header.UtxoRoot, "%s workers=%d D evidence: %+v", c.name, workers, got.out.required)
	}
}

// TestInitial148CompleteBlockCapH5 (C02, C08) keeps the h=5 final map. The
// active cap reads the native parent counters (and a nondefault valid
// below-bound state) and still requires fresh D; an inactive registry with
// malformed counters proves zero cap-only reads while D still runs; active
// malformed counters are a store-integrity no-result before D.
func TestInitial148CompleteBlockCapH5(t *testing.T) {
	malformed := [2]uint64{1, 1}
	for _, c := range []icbH5CaseV1{
		{name: "active-native-counters", capFrom: icbHeightV1},
		{name: "active-below-bound-nondefault", capFrom: icbHeightV1, counters: [2]uint64{89 * 10, 10}},
		{name: "inactive-malformed-counters", capFrom: icbHeightV1 + 1, counters: malformed},
		{name: "inactive-empty-registry-malformed-counters", counters: malformed},
	} {
		icbH5RunCaseV1(t, c)
	}
	for _, workers := range []int{-1, 4} {
		w := btNew(t)
		f := icbH5VariantV1(t, w, icbH5OptsV1{flip: 1})
		icbCapAtV1(&f.in, icbHeightV1)
		irCounterV1(t, w, malformed[0], malformed[1])
		got := icbObserveV1(t, w, f.in, workers)
		// The required producer validates the counter envelope on the cap's first Counters read.
		irFailureV1(t, got.err, logicalStateFailureStoreIntegrity, "invalid required logical counter envelope")
		logicalMDBXAssert(t, any(got.out.validationErr) == any(got.err) && got.summary == (BlockBasicSummary{}), "workers=%d cap no-result delivered: %+v", workers, got.summary)
		// The selected R failure keeps its exact raw cause; D never ran.
		required := got.out.required
		logicalMDBXAssert(t, icbWrapsCauseV1(got.err, required.cause) && !required.derived && !required.hasObservation && required.root == ([32]byte{}), "workers=%d cap no-result tuple: %+v", workers, required)
	}
}

// TestInitial148CompleteBlockErrorPairsH5 (C03, C04, C05, C06) pins the
// first error of each ordered pair through the sequential entry and the
// queued entry with one and four workers: tx1's queued invalid signature
// wins over tx2's later synchronous conservation error; the valid-signature
// control selects tx2's error; subsidy precedes active-cap reads; every
// earlier error precedes D; a completed D with a differing first or last
// header root byte is the canonical mismatch.
func TestInitial148CompleteBlockErrorPairsH5(t *testing.T) {
	// sig_verify_queued.go and spend_verify.go: context "CORE_P2PK" + " signature invalid".
	sig := icbH5CaseV1{code: TX_ERR_SIG_INVALID, msg: "CORE_P2PK signature invalid"}
	conservation := icbH5CaseV1{code: TX_ERR_VALUE_CONSERVATION, msg: "sum_out exceeds sum_in"}
	subsidy := icbH5CaseV1{code: BLOCK_ERR_SUBSIDY_EXCEEDED, msg: "coinbase outputs exceed subsidy+fees bound"}
	mismatch := icbH5CaseV1{code: BLOCK_ERR_UTXO_ROOT_MISMATCH, msg: "utxo_root mismatch", derived: true}
	cases := []icbH5CaseV1{
		{name: "mismatch-first-byte", opts: icbH5OptsV1{flip: 1}},
		{name: "mismatch-last-byte", opts: icbH5OptsV1{flip: 32}},
		{name: "queued-sig-before-later-sync", opts: icbH5OptsV1{badSig: true, overspend: true, flip: 1}},
		{name: "sig-before-root", opts: icbH5OptsV1{badSig: true, flip: 1}},
		{name: "valid-prior-control", opts: icbH5OptsV1{overspend: true, flip: 1}},
		{name: "subsidy-before-cap-and-root", opts: icbH5OptsV1{cbExtra: icbSubsidy5V1 + 1, flip: 1}, capFrom: icbHeightV1, counters: [2]uint64{1, 1}},
		{name: "subsidy-boundary-accepts", opts: icbH5OptsV1{cbExtra: icbSubsidy5V1}},
	}
	for i, base := range []icbH5CaseV1{mismatch, mismatch, sig, sig, conservation, subsidy, {}} {
		c := cases[i]
		c.code, c.msg, c.derived = base.code, base.msg, base.derived
		icbH5RunCaseV1(t, c)
	}
}

// icbWrapsCauseV1 holds when err is an application wrapper (input-view read
// error and/or logicalStateFailure) whose cause is exactly the raw cause.
func icbWrapsCauseV1(err, cause error) bool {
	var read *blockInputViewReadError
	if errors.As(err, &read) {
		err = read.failure
	}
	var failure *logicalStateFailure
	return cause != nil && errors.As(err, &failure) && any(failure.cause) == any(cause)
}

// icbCapHeightV1 = 4800 >= ceil(maxLogicalStateBytes / maxCreatedLogicalStateBytes)
// = 4765, the least height whose counter envelope admits S0 >= max.
// icbCapMaxEntriesV1 keeps max/65,596 <= entries <= max/56.
const (
	icbCapHeightV1     = 4800
	icbCapMaxEntriesV1 = 6_300_000
	icbCapRootHexV1    = "0c8f866a6478b8365f1c7bf1de0d92977e830762d85ff230207d26adf2209f0e"
)

// TestInitial148CompleteBlockCapBoundaryV1 (C02, C06) runs every cap variant
// on ONE h=4800 final map whose header root is the literal CSM 2.6 recursion
// over its leaf bytes: stable S1==max, draining S1==S0>max, below-bound and
// inactive accept with fresh D; a split coinbase (+89 bytes) over S0==max is
// BLOCK_ERR_STATE_CAP_EXCEEDED before D despite a wrong header root.
func TestInitial148CompleteBlockCapBoundaryV1(t *testing.T) {
	w := btNew(t)
	f := icbH5VariantV1(t, w, icbH5OptsV1{height: icbCapHeightV1})
	logicalMDBXAssert(t, hex.EncodeToString(f.header.UtxoRoot[:]) == icbCapRootHexV1, "C02 header root %x is not the pinned literal", f.header.UtxoRoot)
	at := icbH5OptsV1{height: icbCapHeightV1}
	stable := [2]uint64{maxLogicalStateBytes, icbCapMaxEntriesV1}
	for _, c := range []icbH5CaseV1{
		{name: "stable-S1-equals-max", opts: at, capFrom: icbCapHeightV1, counters: stable},
		{name: "draining-S1-equals-S0", opts: at, capFrom: icbCapHeightV1, counters: [2]uint64{maxLogicalStateBytes + 89*1000, icbCapMaxEntriesV1}},
		{name: "below-bound-native", opts: at, capFrom: icbCapHeightV1},
		{name: "inactive-malformed", opts: at, capFrom: icbCapHeightV1 + 1, counters: [2]uint64{1, 1}},
		{
			name: "cap-exceeded-before-root", opts: icbH5OptsV1{height: icbCapHeightV1, split: true, flip: 1}, capFrom: icbCapHeightV1, counters: stable,
			code: BLOCK_ERR_STATE_CAP_EXCEEDED, msg: "logical state cap exceeded",
		},
	} {
		icbH5RunCaseV1(t, c)
	}
}

// TestInitial148CompleteBlockTombstoneH5 (C09 subset) spends A twice in one
// block on the shared input-view path: the in-block tombstone yields R1
// TX_ERR_MISSING_UTXO through every entry, and a pending invalid signature
// in tx1 is selected over tx2's later tombstone refusal; no result, no D.
func TestInitial148CompleteBlockTombstoneH5(t *testing.T) {
	missing := icbH5CaseV1{code: TX_ERR_MISSING_UTXO, msg: "utxo not found"}
	pending := icbH5CaseV1{code: TX_ERR_SIG_INVALID, msg: "CORE_P2PK signature invalid"}
	missing.name, missing.opts = "duplicate-spend-tombstone", icbH5OptsV1{dup: true, flip: 1}
	pending.name, pending.opts = "pending-signature-over-tombstone", icbH5OptsV1{dup: true, badSig: true, flip: 1}
	icbH5RunCaseV1(t, missing)
	icbH5RunCaseV1(t, pending)
}

// icbDiscardRunV1 validates in through one entry on account and returns the
// outcome, the error and whether a result was delivered.
func icbDiscardRunV1(w *btWorld, account *mdbx.OperationAccount, in initial148CompleteBlockInputV1, workers int) (initial148CompleteBlockOutcomeV1, bool, error) {
	delivered := false
	run := func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			result, err := validate(reader)
			delivered = result != nil
			return err
		})
	}
	if workers < 0 {
		out, err := withInitial148CompleteBlockV1(account, in, run)
		return out, delivered, err
	}
	out, err := withInitial148CompleteBlockParallelV1(account, in, workers, run)
	return out, delivered, err
}

// icbPendingDiscardV1 (C09 discard) rejects opts plus tx1's pending invalid
// signature through every entry, then on the same account: the whole lane is
// free again (W, R and source released), and a fresh invocation of the valid
// block over the same parent succeeds with fresh D.
func icbPendingDiscardV1(t *testing.T, name string, opts icbH5OptsV1) {
	t.Helper()
	opts.badSig = true
	for _, workers := range []int{-1, 1, 4} {
		w := btNew(t)
		bad := icbH5VariantV1(t, w, opts)
		good := icbH5VariantV1(t, btNew(t), icbH5OptsV1{vault: opts.vault, simplicity: opts.simplicity, cbExtra: opts.cbExtra})
		logicalMDBXAssert(t, good.in.Parent == bad.in.Parent, "%s workers=%d fixtures do not share the parent", name, workers)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, delivered, err := icbDiscardRunV1(w, account, bad.in, workers)
			var txErr *TxError
			exact := errors.As(err, &txErr) && any(txErr) == any(err) && txErr.Code == TX_ERR_SIG_INVALID && txErr.Msg == "CORE_P2PK signature invalid"
			logicalMDBXAssert(t, exact && !delivered && out.attempted && any(out.validationErr) == any(err) && out.required == (initial148RootReadOutcomeV1{}), "%s workers=%d rejected tuple: %v / %+v", name, workers, err, out)
			free := account.WithReservation(402_653_184, func() error { return nil })
			logicalMDBXAssert(t, free == nil, "%s workers=%d residual hold after rejection: %v", name, workers, free)
			out, delivered, err = icbDiscardRunV1(w, account, good.in, workers)
			logicalMDBXAssert(t, err == nil && delivered && out.required.derived && out.required.root == good.header.UtxoRoot, "%s workers=%d fresh second invocation: %v / %+v", name, workers, err, out)
		})
	}
}

// TestInitial148CompleteBlockDiscardH5 (C09 discard) is the duplicate-spend
// tombstone behind tx1's pending invalid signature.
func TestInitial148CompleteBlockDiscardH5(t *testing.T) {
	icbPendingDiscardV1(t, "pending-signature-over-tombstone", icbH5OptsV1{dup: true, flip: 1})
}

// TestInitial148CompleteBlockPendingStagesH5 (C09) gives tx2 one later error
// at each reachable stage while tx1's queued signature task is pending: the
// earlier invalid signature is selected through every entry with the discard
// tuple of icbPendingDiscardV1; the valid-signature control selects tx2's own
// exact stage error, so the two outcomes are distinguishable. Header root
// byte 1 is wrong throughout, so any D or mismatch would also be visible.
func TestInitial148CompleteBlockPendingStagesH5(t *testing.T) {
	cases := []struct {
		stage, msg string
		code       ErrorCode
		tx2, post2 func(*Tx)
	}{
		// S1B is block work (connect_block_inmem.go validateNonCoinbaseBlockTx).
		{"S1B", "duplicate tx_nonce in block", TX_ERR_NONCE_REPLAY, func(tx *Tx) { tx.TxNonce = 1 }, nil},
		// covenant_genesis.go validateP2PKGenesisOutput.
		{"S2", "invalid CORE_P2PK covenant_data length", TX_ERR_COVENANT_TYPE_INVALID, func(tx *Tx) { tx.Outputs[0].CovenantData = tx.Outputs[0].CovenantData[:32] }, nil},
		// utxo_basic_stages.go assignInputWitness: two P2PK inputs, one witness.
		{"R3", "witness underflow", TX_ERR_PARSE, nil, func(tx *Tx) { tx.Witness = tx.Witness[:1] }},
		// utxo_basic_vault.go validateVaultCreations: owner lock 0x77.. is no input lock.
		{"S3b", "missing owner-authorized input for CORE_VAULT creation", TX_ERR_VAULT_OWNER_AUTH_REQUIRED, func(tx *Tx) {
			tx.Outputs[0] = TxOutput{Value: 2980, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData([32]byte{0x77}, 1, [][32]byte{{0x01}}, [][32]byte{{0x02}})}
		}, nil},
		// sig_verify_queued.go verifyMLDSAKeyAndSigQ: synchronous before any Push.
		{"S4", "CORE_P2PK key binding mismatch", TX_ERR_SIG_INVALID, nil, func(tx *Tx) {
			tx.Witness[1].Pubkey = bytes.Clone(tx.Witness[1].Pubkey)
			tx.Witness[1].Pubkey[0] ^= 0x01
		}},
		// S5: CheckValueConservationTxWide.
		{"S5", "sum_out exceeds sum_in", TX_ERR_VALUE_CONSERVATION, func(tx *Tx) { tx.Outputs[0].Value = 2991 }, nil},
	}
	for _, c := range cases {
		opts := icbH5OptsV1{flip: 1, tx2: c.tx2, post2: c.post2}
		icbH5RunCaseV1(t, icbH5CaseV1{name: c.stage + "-control", opts: opts, code: c.code, msg: c.msg})
		icbPendingDiscardV1(t, c.stage+"-pending", opts)
	}
}

// TestInitial148CompleteBlockMixedStagesH5 (C09 mixed stages) accepts one
// h=5 block whose native P2PK spends (tx1, tx2) are followed by a CORE_VAULT
// spend (tx3: V + the in-block O2 -> whitelisted O3) and a CORE_SIMPLICITY
// spend under the frozen active deployment (tx4: S -> O4) on the shared
// input-view path, through the sequential entry and the queued entry with
// one and four workers. tx3's synchronous whitelist refusal is selected on
// its own and loses to tx1's pending invalid signature with the full discard
// tuple.
func TestInitial148CompleteBlockMixedStagesH5(t *testing.T) {
	mixed := icbH5OptsV1{vault: true, simplicity: true, cbExtra: 20}
	for _, workers := range []int{-1, 1, 4} {
		w := btNew(t)
		f := icbH5VariantV1(t, w, mixed)
		logicalMDBXAssert(t, f.header.UtxoRoot == icbRootV1(f.finalLeaves) && f.o3 != (Outpoint{}) && f.o4 != (Outpoint{}), "workers=%d literal final root", workers)
		got := icbObserveV1(t, w, f.in, workers)
		logicalMDBXAssert(t, got.err == nil && got.out.validationErr == nil && got.out.required.derived && got.out.required.root == f.header.UtxoRoot, "workers=%d mixed acceptance: %v / %+v", workers, got.err, got.out)
		cov := f.created[f.o2].CovenantData
		created := map[Outpoint]UtxoEntry{
			f.cb0: {Value: 40, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData(), CreationHeight: icbHeightV1, CreatedByCoinbase: true},
			f.o3:  {Value: 3470, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: icbHeightV1},
			f.o4:  {Value: 290, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: icbHeightV1},
		}
		logicalMDBXAssert(t, got.summary.TxCount == 5 && got.result.sumFees == (Uint128{Lo: 40}) && reflect.DeepEqual(got.result.createdUtxos, created), "workers=%d mixed candidate: %+v", workers, got.result)
		ok := len(got.spent) == 4 && got.spent[2].outpoint == f.v && got.spent[2].txIndex == 3 && got.spent[3].outpoint == f.s && got.spent[3].txIndex == 4
		logicalMDBXAssert(t, ok && got.spent[2].inputIndex == 0 && got.spent[3].inputIndex == 0, "workers=%d vault/simplicity spent rows: %+v", workers, got.spent)
	}
	whitelist := mixed
	whitelist.flip, whitelist.tx3 = 1, func(tx *Tx) { tx.Outputs[0].CovenantData = validP2PKCovenantData() }
	icbH5RunCaseV1(t, icbH5CaseV1{name: "vault-whitelist-control", opts: whitelist, code: TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, msg: "output not whitelisted for CORE_VAULT"})
	icbPendingDiscardV1(t, "vault-whitelist-pending", whitelist)
}

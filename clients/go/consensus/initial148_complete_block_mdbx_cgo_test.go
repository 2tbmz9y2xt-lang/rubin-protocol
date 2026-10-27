//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"errors"
	"reflect"
	"runtime"
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
	same := func(err error) bool { return reflect.DeepEqual(err, want) }
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

func icbValidateOnceV1(t *testing.T, w *btWorld, account *mdbx.OperationAccount, in initial148CompleteBlockInputV1, parallel bool) (initial148CompleteBlockOutcomeV1, error, *initial148CompleteBlockResultV1, initial148CompleteBlockResultV1) {
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
	return out, err, delivered, copied
}

func TestInitial148CompleteBlockGenesisAccept(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		in, header := icbGenesisInputV1(t, -1)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, err, delivered, got := icbValidateOnceV1(t, w, account, in, parallel)
			logicalMDBXAssert(t, err == nil && out.validationErr == nil && out.attempted && delivered != nil, "parallel=%v genesis acceptance: %v / %+v", parallel, err, out)
			logicalMDBXAssert(t, out.required.derived && out.required.cause == nil && out.required.root == header.UtxoRoot, "parallel=%v fresh D root %x want header %x", parallel, out.required.root, header.UtxoRoot)
			logicalMDBXAssert(t, got.summary.TxCount == 1 && got.summary.BlockHash == in.Endpoint.BlockHash, "genesis summary: %+v", got.summary)
			logicalMDBXAssert(t, got.transition.alreadyGeneratedN1 == (Uint128{}) && got.transition.sumFees == (Uint128{}) && len(got.transition.createdUtxos) != 0, "genesis transition: %+v", got.transition)
			logicalMDBXAssert(t, got.effect.Primitive.Height == 0 && got.effect.Primitive.Block == in.Endpoint.BlockHash && &got.effect.CurrentBody != nil, "genesis effect identity: %+v", got.effect.Primitive)
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
				out, err, delivered, _ := icbValidateOnceV1(t, w, account, in, parallel)
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
			out, err, delivered, _ := icbValidateOnceV1(t, w, account, in, parallel)
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
			logicalMDBXAssert(t, err == native && out.attempted && out.validationErr == nil, "parallel=%v run error kept: %v / %+v", parallel, err, out)
			logicalMDBXAssert(t, out.required.derived && out.required.root == header.UtxoRoot, "parallel=%v D evidence kept: %+v", parallel, out.required)
			// A fresh next invocation succeeds on the same account.
			out2, err2, delivered, _ := icbValidateOnceV1(t, w, account, in, parallel)
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
			logicalMDBXAssert(t, err == native && out.attempted && reflect.DeepEqual(out.validationErr, want), "parallel=%v run error not overwritten: %v / %+v", parallel, err, out)
		})
	}
}

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
		Rotation: &boundSpendSurface{inner: DefaultRotationProvider{}, height: 1, haveCreate: true, haveSpend: true},
	}
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
		}, func(err error) bool { return err == ErrInitial148BlockCapacity }},
		{"zero-generation", func(in *initial148CompleteBlockInputV1) { in.Generation = 0 }, local},
		{"zero-database", func(in *initial148CompleteBlockInputV1) { in.DatabaseID = [32]byte{} }, local},
		{"height-above-u32", func(in *initial148CompleteBlockInputV1) { in.Height = 1 << 32 }, local},
		{"parent-hash-differs", func(in *initial148CompleteBlockInputV1) { in.ParentHash[0] ^= 1 }, local},
		{"endpoint-height", func(in *initial148CompleteBlockInputV1) { in.Endpoint.Height = 2 }, local},
		{"positive-published-genesis", func(in *initial148CompleteBlockInputV1) { in.PublishedGenesis = in.Raw }, local},
		{"identity-before-target", func(in *initial148CompleteBlockInputV1) { in.Generation, in.ExpectedTarget = 0, [32]byte{} }, local},
		{"target-context", func(in *initial148CompleteBlockInputV1) { in.ExpectedTarget = [32]byte{} }, func(err error) bool { return err == ErrBlockSteps1To12Context }},
		{"timestamp-context", func(in *initial148CompleteBlockInputV1) { in.ParentTimestamps = nil }, func(err error) bool { return err == ErrBlockSteps1To12Context }},
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
		}, func(err error) bool { return err == ErrBlockSteps1To12Context }},
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
	in.Rotation = &boundSpendSurface{inner: DefaultRotationProvider{}, height: 0, haveCreate: true, haveSpend: true}
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
			logicalMDBXAssert(t, !out.attempted && err == native && out.validationErr == nil, "run error before validate: %v", err)
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

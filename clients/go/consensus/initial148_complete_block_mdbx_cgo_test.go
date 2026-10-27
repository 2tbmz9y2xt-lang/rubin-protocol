//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

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

// TestInitial148CompleteBlockTariffCensus (C12) checks the census arithmetic
// and typed-size inequalities that close the W formula, independently of
// initial148CompleteTariffV1.
func TestInitial148CompleteBlockTariffCensus(t *testing.T) {
	// The linear rows sum to the 8,192*n coefficient.
	rows := []uint64{1, 127, 512, 4096, 512, 512, 2432}
	var sum uint64
	for _, r := range rows {
		sum += r
	}
	logicalMDBXAssert(t, sum == 8192, "linear census rows sum %d", sum)
	// tx_parse.go: input = prev_txid 32 + prev_vout 4 + script_sig CompactSize 1 + sequence 4;
	// output = value 8 + covenant_type 2 + covenant_data CompactSize 1.
	const minInput, minOutput = 32 + 4 + 1 + 4, 8 + 2 + 1
	logicalMDBXAssert(t, minInput == 41 && minOutput == 11, "minimum wire sizes %d/%d", minInput, minOutput)
	// Two 65,536-byte covenant copies per minimum input fit the 4,096 row with
	// the 256-byte per-input metadata allowance.
	logicalMDBXAssert(t, 2*65_536/minInput < 3197 && 3197+256 <= 4096, "covenant row")
	// At most n/41 inputs + n/11 outputs; two candidate maps at 256 bytes per
	// entry fit the 512 row: 2*256*(n/41 + n/11) < 512*n, i.e.
	// 2*256*(11+41) < 512*41*11.
	logicalMDBXAssert(t, 2*256*(minOutput+minInput) < 512*minInput*minOutput, "candidate map row")
	// The typed map entry and queued task fit their 256-byte logical charges.
	entry := unsafe.Sizeof(Outpoint{}) + unsafe.Sizeof(UtxoEntry{})
	task := unsafe.Sizeof(sigCheckTask{})
	logicalMDBXAssert(t, entry <= 256 && task <= 256, "typed sizes entry=%d task=%d", entry, task)
	// block_steps_1_12.go: blockStepsDA allocates one step12DARecord per
	// non-zero TxKind transaction (blockStepsPass.account), so at most n
	// records, each within the census's 64-byte typed size.
	logicalMDBXAssert(t, unsafe.Sizeof(step12DARecord{}) <= 64, "DA record size %d", unsafe.Sizeof(step12DARecord{}))
	// The fixed allowance covers the pinned Simplicity live memory and frame.
	logicalMDBXAssert(t, 1_048_576+65_536 < 16_777_216, "fixed allowance")
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
	// Contract W for icbInputV1 (n=200, d=0, c=0, r=2, a=10, p=1, g=0):
	// 16,777,216 + 8,192*200 + 1,024*2 + 2*10 + 8*1 = 18,417,692.
	const tariff = uint64(18_417_692)
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
		in, _ := icbGenesisInputV1(t, -1)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, delivered, got, err := icbValidateOnceV1(t, w, account, in, parallel)
			logicalMDBXAssert(t, err == nil && out.validationErr == nil && out.attempted && delivered != nil, "parallel=%v genesis acceptance: %v / %+v", parallel, err, out)
			literal := icbGenesisRootV1(t, in.Raw)
			logicalMDBXAssert(t, hex.EncodeToString(literal[:]) == icbGenesisRootHexV1, "genesis literal recursion %x", literal)
			logicalMDBXAssert(t, out.required.derived && out.required.cause == nil && out.required.root == literal, "parallel=%v fresh D root %x want literal %x", parallel, out.required.root, literal)
			logicalMDBXAssert(t, got.summary.TxCount == 1 && got.summary.BlockHash == in.Endpoint.BlockHash, "genesis summary: %+v", got.summary)
			logicalMDBXAssert(t, got.transition.alreadyGeneratedN1 == (Uint128{}) && got.transition.sumFees == (Uint128{}) && len(got.transition.createdUtxos) != 0, "genesis transition: %+v", got.transition)
			logicalMDBXAssert(t, got.effect.Primitive.Height == 0 && got.effect.Primitive.Block == in.Endpoint.BlockHash, "genesis effect identity: %+v", got.effect.Primitive)
			// After run the frame released the delivered result.
			logicalMDBXAssert(t, delivered.transition == nil && delivered.effect.Primitive.Source == nil, "result escaped run: %+v", *delivered)
		})
	}
}

// icbGenesisRootHexV1 is the CSM 2.6 recursion (icbRootV1) over the final
// spendable genesis map built by icbGenesisRootV1 from the literal body; it
// is pinned independently of the header under test.
const icbGenesisRootHexV1 = "c53b167dd819e13c2442bde23729bfe6c09d899624ebaf7e98e0bb44466c694b"

// icbGenesisRootV1 builds the final genesis map from the literal outputs of
// the single genesis transaction (U_pre_genesis is empty) at height 0 as
// coinbase rows and returns its literal CSM 2.6 root.
func icbGenesisRootV1(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	tx, txid, _, n, err := ParseTx(raw[149:])
	logicalMDBXAssert(t, err == nil && 149+n == len(raw), "genesis tx parse: %v", err)
	leaves := map[[36]byte][]byte{}
	for i, out := range tx.Outputs {
		// ANCHOR (0x0002) and DA_COMMIT outputs are not spendable members.
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			continue
		}
		icbLeafKindV1(leaves, Outpoint{Txid: txid, Vout: uint32(i)}, out.Value, out.CovenantType, out.CovenantData, 0, true)
	}
	return icbRootV1(leaves)
}

// TestInitial148CompleteBlockGenesisFrozenParentH0 (C07, C08) runs the
// admitted genesis on a store whose persisted logical counters are malformed
// while the cap is active from height 0: h0 reads no persisted parent
// counter (S0=0), accepts with the literal root and keeps GeneratedN1 zero.
func TestInitial148CompleteBlockGenesisFrozenParentH0(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		irCounterV1(t, w, 1, 1)
		in, _ := icbGenesisInputV1(t, -1)
		icbCapAtV1(&in, 0)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, delivered, got, err := icbValidateOnceV1(t, w, account, in, parallel)
			logicalMDBXAssert(t, err == nil && out.validationErr == nil && delivered != nil, "parallel=%v active h0 cap with malformed persisted counters: %v / %+v", parallel, err, out)
			literal := icbGenesisRootV1(t, in.Raw)
			logicalMDBXAssert(t, out.required.derived && out.required.root == literal && got.transition.alreadyGeneratedN1 == (Uint128{}), "parallel=%v h0 tuple: %+v", parallel, out.required)
		})
	}
}

// TestInitial148CompleteBlockEndpointHashGuard (C11) supplies an Endpoint
// whose block hash differs from the computed full148 hash of a valid
// genesis: the composer's own guard refuses before source preparation and no
// required-read tuple exists. The account leaves exactly W + 4823 bytes free,
// one short of the 4824-byte source scratch charge, so the endpoint error
// (not that capacity refusal) shows the guard ran first; the control with
// the correct endpoint over the same hold hits the capacity refusal.
func TestInitial148CompleteBlockEndpointHashGuard(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		w := btNew(t)
		in, _ := icbGenesisInputV1(t, -1)
		tariff, ok := initial148CompleteTariffV1(in)
		logicalMDBXAssert(t, ok, "tariff")
		for _, bad := range []bool{true, false} {
			probe := in
			if bad {
				probe.Endpoint.BlockHash[31] ^= 1
			}
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				hold := account.WithReservation(icbLaneV1-tariff-4823, func() error {
					out, delivered, _, err := icbValidateOnceV1(t, w, account, probe, parallel)
					logicalMDBXAssert(t, delivered == nil && out.attempted && any(out.validationErr) == any(err) && out.required == (initial148RootReadOutcomeV1{}), "bad=%v parallel=%v guard tuple: %+v", bad, parallel, out)
					if bad {
						irFailureV1(t, err, logicalStateFailureLocalInvariant, "complete initial148 endpoint hash differs")
						return nil
					}
					logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(err), "parallel=%v source scratch charge did not refuse at W+4823: %v", parallel, err)
					return nil
				})
				logicalMDBXAssert(t, hold == nil, "pre-hold: %v", hold)
			})
		}
	}
}

// TestInitial148CompleteBlockGenesisTargetMismatch (C06, ORDER steps 2-5)
// runs the composer's h0 header step on the published genesis, whose header
// target is POW_LIMIT (all 0xff), against an admissible in-range expected
// target that differs in the last byte. The mismatch is a TxError before D
// with no result; header PoW refusal precedes it and the merkle commitment
// follows it, each pinned by a dual-violation row plus a merkle-only control.
func TestInitial148CompleteBlockGenesisTargetMismatch(t *testing.T) {
	lower := [32]byte{}
	for i := range lower {
		lower[i] = 0xff
	}
	lower[31] = 0xfe
	tiny := [32]byte{31: 0x01}
	cases := []struct {
		name     string
		header   func(raw []byte)
		expected [32]byte
		code     ErrorCode
		msg      string
	}{
		{"mismatch", func([]byte) {}, lower, BLOCK_ERR_TARGET_INVALID, "target mismatch"},
		{"pow-before-mismatch", func(raw []byte) { copy(raw[76:108], tiny[:]) }, lower, BLOCK_ERR_POW_INVALID, "pow invalid"},
		{"mismatch-before-merkle", func(raw []byte) { raw[36] ^= 0x01 }, lower, BLOCK_ERR_TARGET_INVALID, "target mismatch"},
		{"merkle-control", func(raw []byte) { raw[36] ^= 0x01 }, POW_LIMIT, BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch"},
	}
	for _, tc := range cases {
		for _, parallel := range []bool{false, true} {
			w := btNew(t)
			in, _ := icbGenesisInputV1(t, -1)
			raw := append([]byte(nil), in.Raw...)
			tc.header(raw)
			in.Raw, in.PublishedGenesis, in.ExpectedTarget = raw, raw, tc.expected
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				out, delivered, _, err := icbValidateOnceV1(t, w, account, in, parallel)
				var txErr *TxError
				logicalMDBXAssert(t, errors.As(err, &txErr) && txErr.Code == tc.code && txErr.Msg == tc.msg && any(out.validationErr) == any(err), "%s parallel=%v genesis header error: %v", tc.name, parallel, err)
				logicalMDBXAssert(t, delivered == nil && out.attempted && out.required == (initial148RootReadOutcomeV1{}), "%s parallel=%v no result and no D: %+v", tc.name, parallel, out)
			})
		}
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
				logicalMDBXAssert(t, delivered == nil && out.attempted && out.required.derived && out.required.cause == nil && out.required.root == icbGenesisRootV1(t, in.Raw) && out.required.root != header.UtxoRoot, "flip=%d mismatch outcome: %+v", flip, out)
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
		in, _ := icbGenesisInputV1(t, -1)
		native := errors.New("native writer failure after builder return")
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			var spent *blockSpentInputSource
			out, err := icbEntryV1(parallel)(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				verr := w.s.View(func(reader *mdbx.Reader) error {
					result, verr := validate(reader)
					logicalMDBXAssert(t, result != nil && verr == nil, "parallel=%v success: %v", parallel, verr)
					spent = result.transition.spentInputs
					logicalMDBXAssert(t, spent != nil && spent.raw != nil, "parallel=%v spent source live within run", parallel)
					return verr
				})
				if verr != nil {
					return verr
				}
				return native
			})
			logicalMDBXAssert(t, errors.Is(err, native) && out.attempted && out.validationErr == nil, "parallel=%v run error kept: %v / %+v", parallel, err, out)
			logicalMDBXAssert(t, reflect.DeepEqual(*spent, blockSpentInputSource{}), "parallel=%v unexhausted spent source discarded after run: %+v", parallel, *spent)
			logicalMDBXAssert(t, out.required.derived && out.required.root == icbGenesisRootV1(t, in.Raw), "parallel=%v D evidence kept: %+v", parallel, out.required)
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
// body intact but freezes an empty create-suite set, so the refusal is the
// connect stage's TxError (steps 1-12 pass), and D never runs.
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
// so the fixture public key and P2PK covenant are fixed. Signatures are hedged.
const icbKeyDERV1 = "3034020100300b060960864801650304031304228020" +
	"a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"

// icbFixedSigsV1 maps the three base-fixture sighash digests (tx1 input 0,
// tx2 inputs 0 and 1; identical at heights 5 and 4800) to signatures produced
// once by hedged SignDigest32 under icbKeyDERV1. They fix the wtxids, hence the
// coinbase witness commitment, cb:0 txid and the pinned literal roots.
var icbFixedSigsV1 = map[string]string{
	"24c78e3a754e0525645a3d9e4b694d53e3b7fda319c52b96c8033948c06cd8e1": "a266d2e2592d5af92780e2b1b4d23d2d34a20574a9a8f0f80fabc36c57730d3b60ecd971e0d9b0df17c13e02568ee589f42bb9bb7496b28b6f840cb09d7a230b161bb87e6607b413e5d144be37f61123145e5afe15070ecad34d7a959b57d690858d7f31b5d77eba21cd4bc50afbf744a61a9c241780c1a835f1480076a3556fd66b5d01ad355e14b14c64cc9096262768f08318e2914615073c0e6513536c72e9efcafdadb6d90d8c1a1043f0db0f15f8fedba5186555ff0f46394fede7fbd216d1c8e99358835e945bc59594f2bed158e15eb9b6aca6693c60fbbee84ae29d51ea78cc4b4e59eee887cf554e445fc8f784b19a0206a6b5b43a343536276e69eba3db403b79564194fae49a8c342dfe08e855297d3e8f75f23be661e4b33fd42fdb78bd435eb15f49849507347a0cbe453b3a22a82745e441c0a58c23db43aea8e3a565b2cb720411d7edd6003cca0a5365e0b51c567b457382bd792ca12afcb4f8e9267178fe8429eb7990c19b104bef27897a467749cd4c1f2a2b44d424bdd6a10230d39867afe4ceef76d37d8a70e29d0311738e11ac4368d56532f7fc66e30672fb17c0a07db662999163d9b8b91b5a55fa777d906d64656f579013311c94e10003df9d042098a705c6b0f589811112453cb856612234367f800f2d32d8fd373cd46a9039f099330b36e9223cdb61af549d4885ffe509b448987717b6c7506dc0b193a49146a177bf1a4d3843b02366be9771f4ff724f8b929f3cd13c259efa681690e58975200c1853433f900fe1f502b3c965e331e39c4d7996b175d9f14e2d374734944595bad341026776a4fc252eee5e2a6fa61a7b96aac7eff907e4b50e6f178f231effaa401db994dba511e3f1d7dec63b87ae2b6312854b5c37df82f0c3144fa63139fff3a2453d018bc8ce953b9f3e809d771565d939a31836333d73f3a4102a6e4bc55dec75b871f72862078ebe40598440d98d62865a897d1d3d317226796d1b227c5be2c775c0bc31332cd19f81bbc45ea41b56e219756884cd4f3be763926651606ca64ced39b3b9b0df3305fbce64a23a0fd634b04913b83cac6d2a78d31127b36267c85229b9e85e054e94b45d88fcfb02752277a806cc103c7c3d04302e55266134566738411a41ac1b35b0e28c2525b50a0ade54392f1c25ad1f54154ab22c61f51ba8026a3d5cf67ae6a77435256acb785066600632517f3b8674ce3b040b018112d6e0a8598af5973f1a9508e3b352bf4a905dacf74b9e549adcee0a681b5a641bb18253008aa14a3cdba59dd8944776162cc3e8b3707c9eed7be53e00d3c7a2c0d86cd687be8066a19361eb1395663eaa613b77e0bab41aadf14a2ea36a8833e925e1c786dee934d485ae5e6361e8fc6716da7cf3b0366085210ac182ee631603617fbb6612fde86bb362d60408080829c29ce8de1f4b62a26eb84ab7a5e5edc2621c3d85b1e3f408f0ad139056a52244bbc181b8a7f9185445c20e40da44645dea640b9296fd2feef76f1070e291453ec8033a150662dc4d68f907a49e40888373601a8bc705333c09e5595f3fb3068c1bc0a422d52cb056256ef75d9828f01cb9b4cbf547af4675ca2a5fd53cfc8ded22f50c75c1454ce16f9ab0056feed05bbb823ca7fac5ba8426bff2b75e2b1b599b2292dbc262afbb2ce6391044d84b9493a9f1c7261aefa479cb909e3c22b679c3bb88e232377e19d262c548b2332552325d3c5bb3462c7506ffcdf5a28b1c56e4a28c06e99e2ee682f2b372458a4606b4389a0f344043f1a346b526df91d12e0bb4d59577cfc1f6a02d4105af52f31519becec57d265edf9eeafd474222cdbe84030293f69dbd599d07d4ba1eb600ddb817b58575c9031f9687607804a8436ebf6a2448d9504fc367f1b72d52792bc74d9352e911126b303e299d39a0b45a3f3abc545052d2a1349980862adc238df4821383669ba7a49f0a433327e569c08f42e3fd91ec21b9bbafc0ae053f60d6c49f6d08bc5d7e2e434f8568f5e8f5a65972585878acf716bed633e8c24e8050d8a2fbdee63cac0c41b24d72159c7c06f04ad716eb7863a670774bce357c420abd6cb57abcd1504e7893963644de8546799d94a291f1336f26a1ded47502c98a6131527d4ad2b98525636bf93c15d6e4f163afac3b85e220da5b9f46b3e73bfe7e8545e7c1f8e3918af6a810428d4ee255d1ba7362f68688c7bd878e090d69e7ce80267e866f367eda58dd1970da301a0acef35b283318d0c58f500d7b5e7b445fe67a02e4346a17917751f3b84c5e46593f2127efb100457c4e5649ebd8bb2203beb7ec2b54fc0114272a93a91689d8a718f96cbc65fd7405466e111b7298eb550222e09b4bd733d1e3b8e9bf620434265a822db6f5ec207bca30197761711677fa17e32896d5e0e5edaa375d8664669c8a0551bdafbb489554d7490421122b37ffcfa24f73a10dcebd4d5032496af004fdc15901c6256132303aa3bcd7741c00158e2b75aed30b47b5c124bfb1d27cd90d28a487d7ca414f0466b60a7de32ef766c8671891b55170c9ddea6967b2175e25eb777b728355b04a551f134079b55a36ab69b51baf93d96ef6681905847bc0690a02a217d6c8e7b59a1aff5594b8b25a3324c59b3cc8b45cd969cbd150b4a7c316a26779fb6ceba0b8285b9fe30539c99bf096945de302d8f0d26c8f49c6080f0b88b2e7301ac54f8e22f96bf7bff82e18852af48d0cd2999a4c9ac3def9e16547b549bea9a584506b57f9deb89ac1db9c10db3d4bfce1809b139c836d79d03ce4463a43c720ca356fc1251051cb1163042cb869b3566065d9996fa463dc7d744559d52f4e0bef283ccebeb6b6dbcfa748a132dd982a04a50360bf384d1fd76d2257a4c75df113996b9a4dbe3da4514d69f0014225dc8a4f92d31d516aa3cf1d1e802aed1b724b755f2f124473dcc2e13d807e8286d0cf895d81b3bbe0fe6e8692d785d67aae64960ceefcc9953299c3894c8923d38d47ebfdf9cc7fe21d2591af95e3128ee9bf42f946a086ffd6e4c410db868beaf2bf9f010b04e9646b68116356aa30d79df40132fddc490db82e401ce188495ec0497018d1bccf4b63a78b0c25c65a91e8cd5ffcfcc25b097ec3df77d517b9cbb143f0e5833963968fcb8725f62a82fe7cd8cc841e3000215ac57f411cc3671ce1bb7bb5f24e81e5720b3a6bb14838b1b17196cc8f20157fd58d43bac8335bb6b9f3b87f691d6a058e2afaa277bf90818555aec087708e888cf7c998f3edb4e60e6b2d0f0920fb66037c72007f7558d3533f43872b0ae4eb2442b17fba6365023bc3bb805c1a39d3d2bd813890ca7e7f080e17b93de8b0e30fe376eab48c55330eaf3fcb8d8d3d12ef476011b0093ac6b1b70f045df746bf39763b3477e4adfe577437c31bed9fd10f9c3bbc8f96883a1fa65a0e4d1c5bc467b86fa2b53a70c92891c7d641e9c175081636901a7fd3c6dd2f09c17141e25a7d31342703469b35bb3cedfafb091a550bdf0e25973401d56cd3a50a39fbcf758d1c312df3ca3f444ad5e6d52f772151d5ae1d2ae0681dab1e4ad4d3048f17b7204e581449534503b2c8711dea663bd3fcf8f51f4dd01741d222db263fbfafede0065221d4b12523259a629ad67e413af176855412471c9bd7f8d056b6ef0dbf228f23406faf81d6ce9511e9e7d8fc7292afe79224115f69883cc833ff6e64cecb67d4e04874970b91e69ba38f2ee466db65d313b73234e3c3f7180b00aa52694a43507e464f88eba9e94875f626b0f6a2c93d62166c30ce5246d91c8a2f2b67a77c3b22f104341e564e45e4f915925c3e0d45f0dc146eec08d8acbef9555529e76b8797994ed17c50ae4024fe22f5c9f3ae0b68518d6a75eb9b1809b3ddef4679367d68df8627122668c0b42327a562f401d625eb4c1ba749561680a5aa69e8d8ad18350b9a62f30180bba7f76d59de1f72f713028ed5dbec09b65d9bfa18d5e5a7a6aa2502f1f34d80ad713bcb39340e2881fa944ddc795b66c3664701f22ec7ffe246454fa186d4382293f4be446e7c057d8bfae8b5e7912d30382ae731ba09887ef1b9e988837d4902318489908d283d1e36fcfd1a2c6ccf211bfab314f7b64c470d073ecb4a5c8b3fa7aec3486e55668bc7575e39a0ca5c1f400f20bf4e31841d8513e5454c3dd980f2b7e6000897ab4264a8a56d5c239f445007fe43cbd21b85d648e0c9edc95771ca478953a41f14fe130b68aaab0b52588b0ac053b74e32315a5b9f2a96dedb567ae86469a8989ad7c1a3a27a98d3e4ec732914bc6e3c89f5057ef1198db5f551e09f181ccaf6fc6322dc7d17ea6abf0b169444ed22988120b3735b66395a47a34fa8a3b55523690532ff875b5523839e1b3788fab34301b9fff0503dd375ad63657c799e9e1855be11e175602560ccf322499b90579fb4220aa735b651d59d2e7ae12ae09f9c603c470eb2de7920b031d4cb0098fccf6c8ae2ea6f3e10d52e269182c2b9e47ff7494ad4a1f84a6c28649bf71cf46fb8db148e4fe29276546b540aa057c28642b0f8b1666eb51c91b056ab4fd30ba8b1fee81d282a9555e2acd0fa5f9837e40dee3a402e01c2c67da8dbd04f15584ba0225583ee1fa272d1a6da3cba6232dfcb6644e0e6d714d92a439bdbe49eefd564664b9753b1686f08252401e3cf905f235bda9d77ebf912c8f29272d52c7497dabedf48eb22f432271811553d04f30330eb2fd084d4e36a21f439b6c494c4d1da90a090a5a91142223dcccd33e72207f2d3f0d3664939ea7763082e0ee81a86bd630a23dcfb0e6e47066745b81323a5121fa2bbb43c53586ab0a32644267b75170b8c260a744c38eebc8a7445017dbdccb27144a44749f6d4f4b5021250f9e525a0c82222237923166d335bfa9c8699813505398c40bc58538fb1e8bde5aecc26ab37ee622b58bfa05511a23271b67c3106aae84ee32ec4cb4dfcfbc355f5a42bd7aaf554baab467bd87be48848bb7592131d606eafa87ba91503a68075abf9db59f0ffc8c5a2e2f2197a0409b371652c4e91db3876d9200e5a3513b9b5121341007fb7466ff3813ca8cffef2ca73dba2f9702bf938b2228d6242a03f1e67398f8730d288a64010e9aad92d8d2c5b65c62d6e4752b8b65aab215856d16205effc4586e7988ac2e6c534f342a83c2551c2c6028b05096f25b6cabca4cdeb15f4ad6ccfa59a7656936199544f11c57df6a610b1fa18968a29f9e72c5c9c5029450acad5b58e1ed00d2465fce1666d490e5814bfa59cb8023664646bf0dc66259e53693982249f304b89120b5c5060979656bd1d1daa0639acb3065e55a7f2cb1c8ca54e26455e34f52505d8655cd472fe29a997538d2f7e44d50e3488a33a017cca28da7ec3291bf7ab2f60ece21cde119d25bbef6abc52138c830f91fe73559750e7eed66cf7c7fcf6a4e7f91ad2f628972ff22005debeef19319832d64e7c47542b47892ccea626baf746979dbb52d3ec516b0c4d11b56d80437e44d45670633cf18506c64532c60295f4281e556bf80e76c3564f5384cdaace6e4ef3d8f18efe534175ad51be55b9c539b6e88f79d42a2176ff62b6f65eb0b529da45cd7576f8bd60e9f4a5e230a0126f69c0e1920cc5ebccd7408bc80f1d2337a701c0ae9b9b7151d9a0012dacdef3d8c07942de0a159d2bc825cc32e7feb23ecd6189316c3cfca29abf3f8d6cc0009499715f001dbbcd37403f03e3f2d24a13b491a7139ff9ae649d65adb7c83ed2318f50ff6da9bfd5df084fb10d3f32d41315884a33b13b5293e4826c0ed8f6e3ce8d6fcb17003dbc2f00eec0f7aa92962dbbf8a0ff4b43b9f7140c68922888c53d01fe0d66c6008a370dffcd3398d846080fcb687d9ac81ed116491a15192042c934247bcfbed945035fa04dfc147f80f4a81bd321ada129265897c01df47b420292083bf9cde11b1de60f664318b086aa5298b8c77a320b7440285b60bcd1dfda75d11d6f0e4adae25ef824b86f1127528c4f7e6fe5039c6b641bbcaa70c9d34c5f4a26faf703a825613e87fae198ce6cb3a6db052e3fa2f84c27207fee59b01fdb5137300ebb891b43f888c27ffd7fe9a50c0328262eb5ef0469cd219b53d493d25abf1543cf995415348854e5652c65e77484a6355b272b24d2c35df6da4f09ab885f95be52cdf11983962c83650d68aaba44a39e38b3003404cfe25606c308afd7d33bb836edd1470c5216cfcc680787fa818a1335c5dee889ade0650ea61b83b174f1ce95cc8881de7882e0b6b29a942a0dc56aa0b3e309e778a516626e9e29704f163b80bbcbaafdc7001af53e341c7ba3de3781b07b9d5a49d87ad55f4458f46492d70e1eb238909389b60551bb57e769f1527e997a850a7eda2ec05fdc05b0a471b4dd60b4ca77172732448fc1181f363798181a1b4a9ca9b0253c588cbdd3e8ebf1afb4bbd0d7e1eff72a59c929384785ef4478bef300000000000000000000000000000000000000000000000000000000060b121b23262b2f",
	"749c7998327a32c1be4ce9d160200b56caa176880aaee7e194472eccab8e729a": "182e16e83ce303ae54c6393dc486535b3de789e95464d4645c72572a4763bbefaadf64e6fbe09ea4c1b78950aa4f5ff5b975bf983e696265495e0d929aa0b287646a69d45b26baa50c01cb75e5451dba12d2a82f9011adae5ea5d9498fcecad17639c036d0bc41667d762a2d8d1425f0c1f59ee2953cf4ced68883f91ccab16b0cbc407b41ed3e3cf3dd5265bce0ec2ff1ee644128c8f2b7a0baf41b7ddaa4602a9bed0e21147754ea4e4a00e7429cfab37334540e3ebc05b8a8cc05c967d78f47b00d90dd2bb2a17274362d5377bca9bd5130117422f7e788b7674d1198b774bfa2f79c52eb1b9a06cbdb50dcd0a3961ffe8f9e6ae84e6b86af53baa288cddd4c8e5b687f1f0e957818afc05012196ece025046ce65f52016f97136630d57006c14dd0981ced624beb3991412cba260f3e337ca61429e942c811556a51a10a1e043ebc10ac58c8c5fc43d94790db9f3647f11c604708272eca8f4641353dd79e6bf6a03e1412317393c3d0d45b3291abad4aea7b6abec243176b0c5fa4e1a58a64e8d376fff5133f992b7cc1f09f3e292734f3d45412069b4b41bf43c198cd6f6ba76917c912dad0e5dbdc03465c672b477eaef54a2a1b2a4c113216b07a396c260bd0e8fd8302f8842d53936b7cf9f884785c56b6fcd95b202fd2c6982b628427245252767b94bcbf811803335fe6b2d513ada4dd1425c160ceebec8577dd74d9324f7f5b2aca5a75163636ea3257e74f3f032d4f1b602adccbcccf17b715f32653f7d32aea311a3bd3924047a1a168a0d30d89351b72b354586ef60a0949a1cd61298cb8ebc57f7484f6daca1f1e1fd8df6536ea3a1a6259e4636064243ef7769dd0dfab5680b30ed61c8cb9f232a6d2cd4636f8b4452a7fdb027a1e5da25e2d83d703124cee9bd312a205eae29028d46d34d722727560a871fb290ca28c2d646f7d47ced10f8cc4f622be9be6fc14b16cb41d9dd47d3bb313705a8d7d509bb86a028047d34d842cc3165ff79502a7512b34d4465d7c7bcb06a5ed3e86a7cb4ac1baf75b32ea3a3dce94cebade3027d8fe1ddb801386bbbfeb98e806ef4bc3d3861fb7e4f41f47aadbaec4a33e7ac62ba74b2a81a14c04b3e7e80c4a022d1587f50a49793521e7b61455d215a2c52f792cef656ea71646c206eb6b7de4fd168b3d26879c2fb28a1686ade80dd87c4522615d9f38a1ae55bf54ed8e3905e87809d5afeba8a8ca08dd29ef4ce2720b649fdbba9478a8fbe9f7e5c2f80092f3be4d9d1864745e4a92209564b7fc51f9bd98f946bb45154521412d595c01ab1ecf7f4b58a2b0f3458464a41ec06687895e21f4a802b4bfc090b035c5be187cfdfeca0032d45c08a485db43dc91311d0e9155653f3ba7d5fb466cb86f4b918ffc64b9abefd374ce972a848868aa3a93e3c8ab0e3f27519d90eaca467b6a84b1ec42d57bb903f5c2f4c9dca6f551dc6613602b18314be44ce69145861ca9483c58e9926cc9b2b8ecfff0680ce6b89b03a417d8ab2d470a9a6c3c2cc130aabdfdd260cc7895cb18946bf4b682b0f7fb965987861475b17fb988c32987fec68deeead94a3ef26cb8006ee5c667056e0082ff0d2367172096bae89505946d6ba4a25047d86f8087604592650c35f047fd66f06dd381bf470fd81def2dbd3c7cb101ac4d018d86247c2eea81715b613d5ae54de67fad546e9ee55e425654bc8cf14a15746086339ae4289cdf69c030f4392644b7b5625906ec8e20d47a08659b4cacc7aa4ee4c66a0de1c8a784eb4e591cb5ebbfcab73af2915c5e55651ac3d610dd65d56c4ac14e640735c30969963da150483705db42f96edca28b62a98b835afa69bf143e8f9914394e078f797dc8c58f686b036bfc35605638d1967eb8937b92ed900ed9bd45a4a739cbe79022dfb6c0f780b5b4ea1948530764ccfbc1c31af8e6694aa6b113f4c979902f8addab7abbf7ddf1218c474a038d9ce3d76046e030fc4c196d0d7e14e38e2648558ff9bc727ca574de371f0b42e80eb795706dd3d710df7412ff43c591eb45baab38df6964524a1c1f68c10199dfdbf342b638da2aebbfd08b241b5a80b9f75fdd23326bdeeb078ea87464032f61736c6f481f9eda620c1b522e4f9496365d1400e179602a6b10df5540c1c054f33b1e7a32a990530f332ac34d5e0505679777fe36a13cf057b49c3f0c46fdcf6403beb4b842eb212053d4f1ca0b668d5248905d8d1b5d021429e9173d48250070483119fffdd302d696d379870b90efb60b19077a2203f913d6824ff0c1ef56a57b9f9218b33581a1505bcb1e11e448f19d9c7f3bd464fe87e9a3ab00cddb1357bd1f631b4b18118e3096cf2d54beeb957621544a20b63b6966fbdbf9dfcfccc02f60a9aa880b51b892812511d29ddeb9130b8ecdd28c7650195f701977f77106d05ad471d7c5001962aecb3046b7756988f568972e7cfac3249c08926cc63f3e977b1e0505daac929dfcc5a1e72a8aaa5a05f35df7c939429bd1641fdc8cd99346c0be699cf1f951a6fe97a4c335d1537d8a4d51c07173ba67cb365bf606ec5c522c144e6d07e2a845199e25834b8e076c1908f8adb3c1cea3ab69ad36c5c2180b6f9c885f2214068d81229e9fd81381b0eadabdc9482efad8b44a024f8722c87e9eb613aa2e94d80f36dd5f20a10d851d687736895986a84705f57f24018747caa4eacc4de42ca270b3f5aafd301d8c991e1810d668e79dae84fcc40d0453f2f96385ec4d74432efcfe47c7c66aac7ea788d303d56557a206dfb09c0fde7605f2f17c2128e0c42d746dddb2da229c8e82afc7311526254c2c015b9db5153f0f703ab938bd7d852112731bef32c15fcc00b186fba4e6dbf1f950293b4935cd375178300861f12673df5b2911b4c22f94909db7d7aa34520d008b550313c2037046be98ab18e42a3c638be38fc97af4d619ba22c3c0eab7b8000b07d4ab5f25552af8be21ab26c4b64326e55577236804b3de2babd4398a3b4ccefb08b582cb132c05527b01eb4d4e2a3cf1b45cff1d32100f38b4442ea237ac0f8cc0a73949b9dbb8f767b0a68b5cf733ca109668b30187df7176a28e8a3a6fbae47c3077ca32ac97bfa840048160d32f1491060f8a312207c1f9d214f81f693809e89bedbf2438a21ebaf4c2e4f7cdc9df27a9df2153d42dc5fb7892ec241fe65b2b8a07858bcd6c6b9f5e737ee4ba2ccf780261a7caa47ad7431585f2a34485d51d3fc90b833ad0ebe62c092730c8cbc1cad79625986b2aaff24d357b2fe947969ac1b7cc4f47d2f20706f9075e743aed3d56d8f781bd56f0318e93866cf79d4ac0dbf3075397604a62e7063f92a9cf06cff581b5220b3be7d0f04963a01b95e93a6a0e7a0bf915b1bb1e0ba09098b0759bbff49fb6e9ff57f0d6dd20c3ddbc2e31c8191c36ab56c38616eaa709dfbeae3ae0f5050d1797c5d5fcb580997aa71a33ce6b218d8ba5315a43923fd8e7b6b9c9bbdb71c7120e1f3301b84c939babeb9706a8f69a22683b8403811a5799dcee01d667c1fd7ae32e463090743566d7001106beaf9f1f4059cc35ac554c6946456e0a4aafa54bf44fcb100ee4c427b6e6adb151832a6f572b6b44cebb1079b655b02a79fbe6fffaacf4e417c458f02a22b0b2344e6895f36f254b15bf3241adaee6c2349a437710be14022ec66ffc825cfdfd35f62925916b6fd620de2c0087592ee8d2e287b79e84acb95e7a6057d34cf22ebdd78774dc663772eaf9cd01979ecab4020e9423ab7dc7fdbb18269cded19767f5263c1b357102147a769b5e409e66ac2a4f0aae8a35730b338aea01a86633d7ab11a0888ae2775f4a89114c6ea3f85bb2a1f6d612e6b0158a6d5d0f2908117cfd4a0d3b4e5238aa3d69cbff64f673d7afd79857f286540e78c043090dc2d1e46dee7780a949ec764913f2f63a60a0cec38789a8ed9ef6d041976b96ce34041be87d6f0f781a31221f101925f43995bc763e17f8bde8617927159223f2f0b1d4182397c8982b38922800462569163714f660e9ac3571863c3f53515a057b3b5668811c670dd6d5b1f4b22826ba69af0183b92143c7d75f5f937807a3fa8ae9294d83ea8c00aaa05b1efc7ecb5a7b5b6685f118cb32a48cba6eadcdaa462f4c1fdb4906f8162a93ece1db80f21d98d323a453a14ca7ab1c818c84bf7f6078889993a8a0b72c2a06acc858d7a36c40396a6f9a03de97b10b793e10e6f6fedd39074bc6a0c33c82a7856aa7e52b2fc688d1a7b6e1b2295e748bf05e47d93c7dfab5c444a0dd0470e28343cbda5292b69c7a4667285426b39cd5ee9aa5089e124dffa7023cb8106a9fde4ed4a0c2671973d14819e1b347f1e0bac97d0029b6de534b4f7f032773ccf24d263f885362b10ba5ba3884ab846e1ae9a56aac24a122f2764bb92c459d754d10d7e1a07a41e9a66ae4e9b64c21062c1fc1e5606cde14995e173776260f9339d93c9d0f0435db3a22c2bbcef83713f4c0d3accf6384ad5e6945c3907f72f8e8c961371c9863c820161c221ad0573d3183dfb8350e3a5cd3375956d896d0a4b137342d11028bf003145371d3cdea322df7160383774b8e0d39b4cfab5c8ea584e3de94031b46d2eccbb3947e13ca98743b58256daa8b1b20b022dc86930d04a032d12740aa4f84afde292287f710cb349136b701eee709650bb151817d876c1a39cba9aea9f605ca1e0aabf51af93dab39b00ec7c614afcd5a520118cab78cdf03f7c22ece1d17849f1bd45350acce2c2e0d6e77252f01f87b6cf16a0ef333ad7519358f84749070a857145e35778add499ec750b375cc5edfbf2a80f515b5aedeeb837df28113e8d68b7b3ed2069ad3750e1e544a8c59616dd73d45669febc25096274bd64666cb7ac463aeb5f16650d954807269d2ab98e1671183f8b91fb9ff34a3937d062a1e7a77c377634fd2f00ea0b93f3fbd7363395848a72b4776b21bced23018c9b91b7ba42d45050a4439f02951f9a9fa380187bab0ed3348783d0a5ce5f78889fcb61652663955a49c9db573f2f6351e7d2d3e8f18a86dc35c65cd5b4716a80962ab1ca55ea96c009e39c75a5729fa54b1434f1a9f8e474ad0b8cceb8b9869054c9407ed4204af0dac1f83a3307e38b1d87fdd35e349128a0b58cd58bf2f93563d104694f3fc3486b0c35f96f7ff708e6901b060860a2daa172c01837a254e55856c626fbd7799ffc5a798dd61460466db790b541d02510a79e100c5e83275dd4b75645ebff5e0b15ec430112e00622c5fce942d2fae3d7e950ccc15ec10eb86af9150cf5ef7e7f362004fca843e39d59b19035e61030f3ce71dda525e34a7782f73e0c9aeac5e9052595b4adcd653bf312124f831a37da0b7ab1f7ae20da89328ce68285f3cb0b42b88b82be1d6894ea686e666c4248d35f3835e757996c96332922783012968bd92f58e60170908b91b8f70d50e6a481d3fff160ee53b018f2c80211a28efc102c4047d8955b8220a6885c693aef548d17e8ec072f7afc4b349aa684c7d2ff183c446c14f5412a2f5a46ae3d3f8769a346115c4d7d132d6ebc5fb953c1759165af47374a1eb9bb462d952120a31df3fc0b3c2b2c8e195dc38157bb96c3997390fa8f4fc1dfe70aea526df952d7cf4c641e26ff61fe48c8e4bf312bc6450eee7d85a63217ad24d45b037ed9d5f64d4c50a25fcc6db36634e6c0d40f453216e239d127e3a379d14b7036bb10df01cd84f71989e1f24977fca6e1a394c406472fac51d6eef5dfdc4c15324548af0aecb13bcdde9238f5dbbb7112bc80fa7d25a4b8228fbccd086e470fce8c73854c8c18beacc3b624eeb1f251f4f72e569f4a998764ccd21626dd16a566f78bf5364d5eac97ca2fc83143ec5bfbcddfa599f5bd66824a13e853d08cd96b333761a7ec63dc05a63eda75e1a2f6c45fb570c2d94e16ef6598828a79218f07506de0281a149499bfaefe9c7ea52d0c4caffe53e576d986be90f03ad7dade0c27e492c1706fded65ab1f29b70517b6ae8089082fc53743ba2300c981f997f03992ff62bb590eea0c51d12f79597dc448c0099953c9fc70bb1d953749e4189798e27e1914435332f5fc5881bfaedf5defbbed10f0f5d827af40f432864e9a2d02c36377e902fb8f19fc8e37b1284116723ad7bdd3b8c7118cefb920a3d9cc4deb7473fc2b4f9ffe80e4909822edc5273e5fc8b8ac60da4882178931afe05f8877dc38d9e579107e6e7c51a8c0fc738bda335fd867e153e3ede5c0cfb378b075660f37f885704471318f9bbb485ecc052e369afc05ff59606b7d5106c04360d4d189f6f31d31d610e9963dccce933413e9673e3f607d9f5fef412c09096c3366c7b32ad96f8f2f63e19e58233006ae7013a7f986c6107ee75065fac14dade9a5f44141876276ef22b9dd99c2b59cc1a2573979fb906152b434f63ff488d97aac5e001029abf1222686d7f89cafc012e5ff10ca5fd065c7781c1d1e2000000000000000000000000000000000000000000000000000000000000060d13171f23262d",
	"c1e5b39bf7bb031979772d6e3dade529ca68d92efe34bfe96b39eb2de80eaf15": "6c42a20d639158b1e1b5654f8d0587b2921a7c43c0cf58fc488e0f19df3e1dea679a15681ef8b5018425606112060c384cb0d6536175a8ccd2e2818b6461afbb6ca35f0a892b7aea0d163df218f660247d2d98b4e1e3c437f5dc6fcdccbea76004dd7c78b54f4b85957358bc10b0c17223e4062afe057a360305fe09b45acdc7fe3d6235cb7086c891acae9436b0d1d4be67f0ca27ea795fef0dc148d2bbaf9e9254f617049bab7ec22d4555d6fe5476127ecb991b109521b49850dd892340a120db49ff7bd9ce363774cd30fae8dead1c3bec79f1a4c7718fe54e8a1454c058e45ee246ef6b5bc7c6cbe676e25843c440ac90826279d8285758a3af2f4b38dfa5c2825e0a0323a5c2673dd75d04ad4a88839062965ed2177992412a815e541a2e73fa6c8a16410b9df8347db0b03561ad659ee29a4b2ae1e2f2e8fe05db16d0163ee419ddba3410eb30d5445a6eb98b5a228569a4edd948dbc8e65fd38c19e6b198e9205cd3b2245cc035d1315a79077a397f73f2fd8bc66de99431e33f7ae929befe3411be2b112c7948ea0f4a137edfc9d958fcf662524ebd77523a8b755a2a6ccdae069b5bcf0d1869e46aa46b4514083805d7bdf9f1f7a9b1053b87844894ffdfd3929a55c1e9b709fff41e8779a49d0ca0431a6e8e2e5b60989d3a3c766c11dc0f636617ccdea7ba528330c844e897c7686a4f0b8e7f6a4bc8358bc50f9c315f968ad95235e97f550a0e1c681828666185daa2753cacef1ea7d327070c0d3e04202e975508fd6f257bb996cc5f2998621ce6c208a1cfecea43588d4966405ec65f8a69ac6354e09764c93711a5d36c769f8d004afd9b5c88f6e24b32f4c03bc8d2da3ecd83eda2c9958444691c126f26ffd3c32291c9e3a3bc5af52426000585f29437d1a7c9e1154869b77205f10c78c2a69eeeef08a98fb4eaee1016fca1ad889a23e8748e517d69d28438b63337fa343163b5bc85a0fb43553d242909dee99332f53bba2c5fce06f7f9f8cb60cf19a454bc075370fe4b5f1bdff3bb834e696cba9c4f48da0febb7292f9543c061a49305f59a6ab7b8f680f6f8da79913b494624e8d5782981c8bb5649e01b36d6393896d5f0f4147cef91200b9abafb57ba5dbf3dc4a0b6327dc6901ee96873181b08173f6915ec06ae1f88bafdc044b74660f73075a2fe65ca3147fdc30f536ade38a6ded565550b88bb225f77150311bfbb9a90bdea86a4b1e1c63e4c7487b7affda26e5e31b6e0d54c0b382fca4a7ea15385194d0bffccf8689b79df14a0e300e57bbda9c044594e9987c1d35bcfe790e30a8e1e1b1d4bcd946875dea7dd79c68d5024cd47898298b727f54112f6d40d055efe6ce61a29ba3414c10e416412310e506e572114a1e51f6ffa5c30d5424c00e65fc0db0f1f1f6d68f4138cd0dfab87cec203f1c0977999015ae9250e4e67150b6a79ba487fcf2e90c1ef12ea9b0cd78baac1af3ab8300237bd34a1a62ebbce54002408500cc53e2d0307db2bcb3a87589fbe1b8a2acb258abbf46618ed25835161f257c70326e53f00d2613bdb39367c1435b43d3cac597d26711cedcafefa257d7f81c0df3411ecdd3429d1a08a9f0a4422f82803e79f377a05bc31495e20b2d2a9b9a13a2b118b6b764621ea09bdf3e39fdd60dedbd7d704ec90ff2de3de77210ba3b2e5825d07aff7826ea18a862303916e8ad3ffac0b7668d47388a0ebb8ab61efade23fb3853242e0c2197e4d17f1de612d920b429ef1ad511a1ab31a0b3c574c28894b276cfc8bd2a49ba3eb570c63d46ba7936b9f25be4030473392cd37837c941eb4ce5c0f38608ef06697808d6e7cfe63586110d10259360a7ab379d8a73e10c04a42532538e36a41982f8286cfd6defca743c8db85aa14210250536c58e607d7f07692c0da9d620d6dc35a4b4fb8ba0bd03a8135ee2995847135aac458fa23ebe16cd137b573d1b8d34e452ad8171a92ac2480784df053baa5cee40b670af66b217cccb8659be0fa540095e6500f6263e905554366959ba3818f259a71a063268b53a36028bc963b83cc0f0f75aeb449f1905726390817e1737ed910bcaced67b04133234e1094560c9a02c9236ad67dc4478035ef0410d30e5d1607af2266bf1084989a63c7862394b1b2f95a4f817987221be6527b0b87139641f07a2cfa7a8bf3728693c166bb526c5b1517436af785b36e7838338a945ea3e84b7c66d5ec51f7da34039929eadb542d56d86fb8ae2212e57668b9c1567f69aeb75e6830262dba86076d5207505fdb088dd36fb1c1d3ef4336b45341278200b98a701357a6af9275f165df0528b1056292fd2ea8b1b62f9da5af1a70e512eb5f710145fd80c7262dd4540649d0ef7a01050a78f1607473c9bbc9c2f7bd987a858cf00368b4dc9d243579eee98b60fdda4cfbe1dcbbd7988a4b14f670e710ca02e88d4495c4240e32affb4d38d5a368333548bf0e69ddda6b052d144c9c05f52e283cfba65122d4ec3799da4522abbb0fb2bcb8327b8b9d802b7d551d1fbf3f52a4940e33c026a82d9ad6eea6e08cf508bf35ad23a77205a8f429853b14788d44793a9bf7742fa8de90bf0de3c10594b909adfa13c0597017f03f78f4fa0b31a8df8e7e029318a1abe9b3b93498c62bce8b51cf192899bd63ba7d1b12b585985d2bcef46ec9299c7b97d73916791d147ab09d3e3ce81bb551a3f3dba45d5e9fdc711616327c5c540d3478165480185bac8bd2776d1c34ab2888b6836214c7c58669ebeb7c7d312a796a26a54eee2da92e2b45b1de6a7d898fa9385927f6516ab036671b8a4232078117fa50c1a3fc249608b545baeda51b8400acdfa8a53ab9e54148c791b52ff799775b19d6e0f7f475e179dcafdcac75032e02c26fed3260960ec969ccfaec6232162cacff39b2631e5369bffdd1017c6ae72e8031884813105eb3893ac4d12280c494f0be1085709303eb2828bdbb2900996cd0e0bb32c002e5f75476f0015a8dc771ea1ef2f8136ad5d38036923bc9fd3de81094c7786d0b825797f1031bbd19df511b33d41bf470f8ed7b9e7deaa8b4ea967567f2a02529c71f939acf1f5ab6986eb14248bfc1d1a9fa01d49d240e6c3122d6ef855d08b76c6df755e0a9e0727ea0496040afc74d8bd0633746cbf68425f8e67f44e68979448f5e5aeba3d45d6420cf8dd29b623a42c07b72b7fd02bbb0b7a42d16d50995b29bbc4a24781b5db2e5ca502a6424a06df12e3d8557158d2088a1ad54db2e8036bfd0e19de71f846365fd0cc2c47d10783e5b49f69befd4e8c2e116c71694a81f47e35b6ccba47d81bf2d74586bb5636022042244ab593dfe08a0c700051652133d50106cee98194133d99691772dddf2e0569d280e5efca3a81998277e4bb9d2e8ea6329e9d36479a85d6021dcae89b1466df389d4e9a94f8ba450173d5f3097f4a7f7e773c20872c7d415b6eb781658b8ba64ef36a48bdaefca64cc9c481a614ed5b7c6d9c08d08ed02a1e133a79380cc71cfa9acfa722d8d2604777da19565e1dae6681410f2cdc5476022d3bba56dee90386e69185bcc04c0b3dde43514fa74c7c1928b22bd208b93c2e5b4e9ac8fa47d5b193a42b0df2abcacbe48690bd7443d1dcf54ff90d15a59ae6dde5a16ef8d52fd14118e92791a757ffbce837567dafbbfabb3628930c6c9e55b8b12872e6e3ce6ff186b535dd70786db10d11d5fee4ce84074161aa94cbac103b97dd59ef6411c63e8140952dbae19e30a496454a412c26fbff76c3f03f7b2ec424474b03ce188014f6e59064535dfa7865aacecf5613a57c59b858fc3e6cba3350823d7a097778d488367f6e4b82702b5059a3071929f82ecec44945ffcec41aa3acff098111cb2dbe62ca1dbc771141e35a803c096b9822c0e1c7e0294ca18f2955f75ad91eb0563b31607698c3ba8752ac1508e60bf5a171ec85d2f5912a002081ccead7c970186b11fe95fb041f317cd58a7b15299556d8f8ae810017d09e63454c3915245d07720f1aceb81bfc98b4e849ba76a1a8ac8aada282a1cefa6124c6785b869ef1c1b09e5c5dbeb6e9cceb571c9a3dc9f930467c9c8a5c6d556fcf218cae2ca95725294794d6d8d91c8be0c683e66cfca31d751a0efa78b059bbb275f4272a03fe7803615e1fbc481733218845e6400aa79f1a9cec8ee816e38e5c73435779a27140f6cd0e31ac0060f994e0b0661c20a9e4db7e55275371c6ec18341e2066968f48b3c5d4b2860ab6b2868eb4309efa353ac51cd055810dda24796979ee39d3adbc0d92399b2f611006d593401833857d019ba049753893744d7eb75366e66e5bb61a0ecd76017b3a4320fbe0fe4c74010194868a8c62c59557a0c1c06a49b589f366daef764faccdde2322f4e7d627e1e60935e0414dc03fd8dee166442d0d09d8b5f636b04e5589bb48dca19de2d79649f1639b81d919aea59f379f2e2d4b705a9289db2a57b049499db0064dea0fc82831fb1ff2570ed1f18d77a005f10d19624d74f46b0f0d9a668157f3cc3f63f7318a4c263d5475bc3fa624245d50f7a8b2b5c0ca166c0f48b55783fcc5075e95ad53713103ea3710c5199062199dc60c4ab9cb727f51eb4b6a39237de88be9ddf0b67a169c79e272c5b45e3dc76938d3bf350ce5cfc4db02d13e96be9ec39e7c6813edc185b215953a86e906282231f7b263be3b326402d710951ec014f13579e00a5e91f05aca78630b23a2a6db673664968f3bbb926f485675e191930a7f8d02ae1006cb64dce4da31751c6e5fd1c487014f488bb974041cce995ba33e28397e5becae3f7fb2ff8751ad7b5583bcb57972c1ba33b0dd4adeeadfae40d8e7562ba21157ab977d0e10d739540f8e842b106faea5fdf09b52aad7093f1e501d85e23963f112576ff17e243da6a749bbacae99afb651556545029440d2f73e2350b9ddb8c045a03155809f713a85c18713167c4d38c0713973a4243c98c628b705d36bb702bd2981626b8f7e31ef974c18c17f75f8a02dda348deee3775b67c5577bc8a91a14570325f867e5feb86d3ca20f558c4c0050b4dd48d4e1c9f9d00cc98f48ebece17dfa98be90e3eba37a3726d15ff4be3cea8dff5507398f806493482b1a463803fe5736a8e5b6874719165c3ca63f923789242f0c419370c2c9e2a17adc6d7e7855e10c6684677bc9eec163f80ebb8c5b6285b1d1c608935480e20f3f53bfaa4597505beee1a522e69f293426d45d49eaedb60e122be1de0960d8a3acee3dc5524d8d098276b7d2fbf4a42ce0ac9e2dfcc491fdc6a322cd8b356570846dde15f8418622bcc0e60bc73eba7b98e2e2cc1e51d86cc24719a983ae554b62e20b3d5b0d34cb22a7b62af4de0d7c6c28eaff820ee26d3342f7f3a8c0d05cb4ff0a74b77f3f3f186b713adf932dc76f6d31427cc57bad147aacb1f78a799c24be48e3eb45a53c8e5c8e759a854b01e27f1311f07d6bb95ff98b81343ec22b925adaf565098be57ea6959950bd03b3960b807e76484ecc364e2146555c5924f63225ab969be05062ba386f0fe70360d5693cf0307875ae76dd26fc9a341b286d17b6afefa81f7a473398d41a543cf2eb78804a3799c70f5d8de28d5cb8c294e1a1b33e6bfce9f91bb7458746f244590b08c8bb77778cb77fe66c42e9ac3c06c03beadedf9706485ad87f44a5b9a7220275209e390837e52c84c736681ac57ed47fe150641b3904a902fc04152f791185f41f912e4ce1dcd294fc4973d308f879ce5baca6c1389ba7d42a6053c7b810a6851e5c440273d6c5454ad78c372095de9fcb928dae7d7f257bb75f61a6e506522d5c8c6279806506e9684eb33a15b715e4cbdd06979b9f4099a43e723010c45815f24bb41a8f3c17ee1a6bc5bb42b3ea3747224eb4f0f369a686fd14ed9f6087ef8f26812d7b83731d5c8eccfb832c25519b28604b299a7b75303979b622156dee45cbd19e2b4d37688197a297a72a5374a72b6181d43442b2457e69535a0ab2044683ce4685cb7efaad0104428215997b5caa6c02f22fa20c25044250f5846bb93fd4a2c4aef724c1949d2d01297b81a330744f2f99df302cb2bbaada90579600f2dde9f9e7dd977f041971c57b23a7ec35600e0a03e44ee5a1898e25a336223a0e149832ab1fc72f1bdae7a20ac1fb1f5f990575af2c6b7e8400f17eefef685f6d80dfb4b4f13a442f422a5152ced7d09dc0db5f23a13332e76a0221634b33c98b320607d1ecb7eecc84bf7c12c1fd4170462f893888cd705516b6be4b793c8e4b5b44b6607d61412b623634e8bcafae2a0aa8ecbd068f39f4833df9f1bafd7d36ae2e83fe00d2a38fa3457506e7a21d1bb0c14e850f468fbc728d27087ec86af5751d9ebd644abf63655214003eb9810c226f04317d6add9a8cdbf7557ee061ca27a69ba17272b3b5293a2d0072359788490a8aaafc3121d252e7fabde184650858b9d203a5eb3bec808204244475e62d2da000d11152f889fecf70a2c6d85a8f7ff000000000000000000000000000812191f252e373e",
}

// icbFinalRootHexV1 is CSM 2.6 Root of the final map {C, cb:0, tx2:0}, computed
// independently from the section 2.6 text over the literal leaf bytes.
// icbHeightV1 block at height 5 spends rows of an Applied parent at height 4.
// already_generated(5) = sum of block_subsidy(1..4) and already_generated(6)
// under L1 section 19.1 (MINEABLE_CAP 4.9e15, shift 20, tail 19,025,875).
const (
	icbHeightV1       = 5
	icbGenerated5V1   = 18_691_989_860
	icbGenerated6V1   = 23_364_976_184
	icbFinalRootHexV1 = "dd7b4b9043ddf7556b26a225d3c0bd33c2fbd7404eeb376736c040ebb02ad711"
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
	sRows, sSpent             int
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

// icbSignV1 signs every input with hedged SignDigest32, except that a digest
// listed in icbFixedSigsV1 takes its literal signature.
func icbSignV1(t *testing.T, kp *MLDSA87Keypair, tx *Tx, values ...uint64) []byte {
	t.Helper()
	for i, value := range values {
		digest, err := SighashV1DigestWithType(tx, uint32(i), value, [32]byte{}, SIGHASH_ALL)
		logicalMDBXAssert(t, err == nil, "sighash: %v", err)
		sig, err := hex.DecodeString(icbFixedSigsV1[hex.EncodeToString(digest[:])])
		if err == nil && len(sig) == 0 {
			sig, err = kp.SignDigest32(digest)
		}
		logicalMDBXAssert(t, err == nil, "sign: %v", err)
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
	icbLeafKindV1(leaves, op, value, COV_TYPE_P2PK, data, height, coinbase)
}

func icbLeafKindV1(leaves map[[36]byte][]byte, op Outpoint, value uint64, kind uint16, data []byte, height uint64, coinbase bool) {
	var key [36]byte
	copy(key[:], op.Txid[:])
	binary.BigEndian.PutUint32(key[32:], op.Vout)
	s := binary.LittleEndian.AppendUint32(bytes.Clone(op.Txid[:]), op.Vout)
	leaves[key] = append(s, btValue(btFrame(value, kind, data), height, coinbase)...)
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
// signing. simplicity n (with vault) also seeds n accept-CMR CORE_SIMPLICITY
// rows from S, freezes an active deployment at the fixture height and appends
// tx4 spending the first spend4 of them (0: all n; -> O4, fee 10).
type icbH5OptsV1 struct {
	missing, badSig, overspend, split, dup bool
	cbExtra, height                        uint64
	flip                                   int
	tx2, post2, tx3                        func(*Tx)
	vault                                  bool
	simplicity, spend4                     int
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
	if opts.simplicity > 0 {
		f.sRows, f.sSpent = opts.simplicity, cmp.Or(opts.spend4, opts.simplicity)
		txs = append(txs, f.icbSimplicityTx4V1(t, cov, f.sSpent))
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
	if opts.simplicity > 0 {
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
	for range opts.simplicity {
		frames = append(frames, btFrame(300, COV_TYPE_CORE_SIMPLICITY, encodeSimplicityCovenantData(coreSimplicityAcceptCMR, nil)))
	}
	return frames
}

// icbSimplicityTx4V1 spends the n rows from S with the accept program (fee 10).
func (f *icbH5V1) icbSimplicityTx4V1(t *testing.T, cov []byte, n int) []byte {
	t.Helper()
	tx4 := inputViewTx(4)
	for i := range n {
		tx4.Inputs = append(tx4.Inputs, TxInput{PrevTxid: f.s.Txid, PrevVout: f.s.Vout + uint32(i)})
		tx4.Witness = append(tx4.Witness, coreSimplicityAcceptWitness())
	}
	tx4.Outputs[0] = TxOutput{Value: 300*uint64(n) - 10, CovenantType: COV_TYPE_P2PK, CovenantData: cov}
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
		icbLeafV1(f.finalLeaves, f.o4, 300*uint64(f.sSpent)-10, cov, f.h, false)
	}
	for i := f.sSpent; i < f.sRows; i++ {
		op := Outpoint{Txid: f.s.Txid, Vout: f.s.Vout + uint32(i)}
		icbLeafKindV1(f.finalLeaves, op, 300, COV_TYPE_CORE_SIMPLICITY, encodeSimplicityCovenantData(coreSimplicityAcceptCMR, nil), f.h-1, false)
	}
}

// icbCandidateV1 is the valid variant's expected candidate from its literal
// inputs: tx1 and tx2 pay fee 10 each and create O2 (f.created); with tx3,
// O2 is spent into O3 (3470) for fee 10; with tx4, sSpent Simplicity rows
// of 300 become O4 (300*sSpent-10) for fee 10.
func (f *icbH5V1) icbCandidateV1() (Uint128, map[Outpoint]UtxoEntry) {
	fees, created := uint64(20), maps.Clone(f.created)
	cov := created[f.o2].CovenantData
	if f.o3 != (Outpoint{}) {
		delete(created, f.o2)
		created[f.o3] = UtxoEntry{Value: 3470, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: f.h}
		fees += 10
	}
	if f.o4 != (Outpoint{}) {
		created[f.o4] = UtxoEntry{Value: 300*uint64(f.sSpent) - 10, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: f.h}
		fees += 10
	}
	return Uint128{Lo: fees}, created
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

// icbNativeSourceV1 is the Source composed into the native operation. The
// native writer calls it on its own goroutine (internal/mdbx/tree_call_cgo.go
// runTreeLockedV1), so it only records; tests assert after UpdateTreeV1.
type icbNativeSourceV1 struct {
	source    *blockTreeSourceV1
	before    func(mdbx.TreePositionV1, *mdbx.Reader, *mdbx.TreeDeltaSinkV1) error
	badWindow int
}

func (s *icbNativeSourceV1) TreeDeltaV1(p mdbx.TreePositionV1, r *mdbx.Reader, sink *mdbx.TreeDeltaSinkV1) error {
	if len(sink.WindowV1()) != 65536 {
		s.badWindow++
	}
	if err := s.before(p, r, sink); err != nil {
		return err
	}
	return s.source.TreeDeltaV1(p, r, sink)
}

// icbComposeV1 is the enclosing builder: the root-valid result is composed
// into one TreeOperationV1 (header row, Primitive, both Index rows and
// CurrentBody), exactly as the existing bt operation composes a source.
func icbComposeV1(result *initial148CompleteBlockResultV1, observed *icbNativeSourceV1, header []byte, present bool) mdbx.TreeOperationV1 {
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

// icbSourceCallsV1 records each native source call per TreePositionV1:
// the call count, calls made while W was not held, and calls whose Reader is
// the builder's own Reader or while the builder's Reader still answers a Get
// (internal/mdbx expires it when the builder returns, tree_stream_cgo.go
// callbackV1, so a later Get refuses with "Reader is not active").
type icbSourceCallsV1 struct {
	calls, unheld, builderLive [3]int
	builder                    *mdbx.Reader
	key                        []byte
}

func (c *icbSourceCallsV1) record(account *mdbx.OperationAccount, tariff uint64, p mdbx.TreePositionV1, r *mdbx.Reader) {
	// W stays held: the remaining lane cannot fit another W.
	held := account.WithReservation(402_653_184-tariff+1, func() error { return nil })
	if !mdbx.IsOperationReservationCapacity(held) {
		c.unheld[p]++
	}
	if _, _, err := c.builder.Get(mdbx.TreeSchemaV1DBIs()[3], c.key); r == c.builder || err == nil {
		c.builderLive[p]++
	}
	c.calls[p]++
}

// icbUpdateTreeV1 is one composed attempt of TestInitial148CompleteBlockUpdateTreeH5.
type icbUpdateTreeV1 struct {
	native    btResult
	out       initial148CompleteBlockOutcomeV1
	err       error
	calls     icbSourceCallsV1
	badWindow int
}

// icbUpdateTreeH5V1 composes the root-valid h=5 result of f into a real
// Store.UpdateTreeV1 inside run on a fresh TreeOperation account and records
// every native source call per position.
func icbUpdateTreeH5V1(t *testing.T, w *btWorld, f icbH5V1, parallel bool) icbUpdateTreeV1 {
	t.Helper()
	tariff, ok := initial148CompleteTariffV1(f.in)
	logicalMDBXAssert(t, ok, "tariff")
	var got icbUpdateTreeV1
	icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
		observed := &icbNativeSourceV1{}
		// The native writer may run this on its own goroutine: record only;
		// the assertions run on the test goroutine after UpdateTreeV1.
		observed.before = func(p mdbx.TreePositionV1, r *mdbx.Reader, _ *mdbx.TreeDeltaSinkV1) error {
			got.calls.record(account, tariff, p, r)
			return nil
		}
		got.out, got.err = icbEntryV1(parallel)(account, f.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			got.native.truth, got.native.stage, got.native.index, got.native.err = w.s.UpdateTreeV1(account, func(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
				result, verr := validate(reader)
				if verr != nil {
					return mdbx.TreeOperationV1{}, verr
				}
				observed.source = result.effect.Primitive.Source.(*blockTreeSourceV1)
				got.calls.builder, got.calls.key = reader, bytes.Clone(result.effect.Primitive.Block[:])
				_, present, gerr := reader.Get(mdbx.TreeSchemaV1DBIs()[3], got.calls.key)
				if gerr != nil {
					return mdbx.TreeOperationV1{}, gerr
				}
				return icbComposeV1(result, observed, f.in.Raw[:Initial148HeaderBytes], present), nil
			})
			return got.native.err
		})
		got.badWindow = observed.badWindow
	})
	return got
}

// check asserts the accepted outcome under run error runErr, the exact
// per-position call counts want, and W held and the builder's Reader expired
// at every call.
func (got icbUpdateTreeV1) check(t *testing.T, f icbH5V1, name string, runErr error, want [3]int) {
	t.Helper()
	logicalMDBXAssert(t, got.err == runErr && got.out.attempted && got.out.validationErr == nil && got.out.required.root == f.header.UtxoRoot, "%s composed acceptance: %v / %+v", name, got.err, got.out)
	logicalMDBXAssert(t, got.badWindow == 0, "%s native source window length differs from 65536 (%d)", name, got.badWindow)
	got.native.want(t, 2, 3, -1)
	logicalMDBXAssert(t, got.calls.calls == want, "%s source calls per position %v, want %v", name, got.calls.calls, want)
	for _, p := range []mdbx.TreePositionV1{mdbx.TreeWriterV1, mdbx.TreeReadbackV1} {
		logicalMDBXAssert(t, got.calls.unheld[p] == 0, "%s position %d: W released before native last use (%d)", name, p, got.calls.unheld[p])
		logicalMDBXAssert(t, got.calls.builderLive[p] == 0, "%s position %d consumed the source under the builder Reader (%d)", name, p, got.calls.builderLive[p])
	}
}

// icbFinalRowsH5V1 reads the h=5 final rows written by the composed operation.
func icbFinalRowsH5V1(t *testing.T, w *btWorld, f icbH5V1) {
	t.Helper()
	cov := f.created[f.o2].CovenantData
	w.read(t, 1, btUTXOKey(1, f.o2), btValue(btFrame(2980, COV_TYPE_P2PK, cov), icbHeightV1, false))
	w.read(t, 1, btUTXOKey(1, f.cb0), btValue(btFrame(20, COV_TYPE_P2PK, validP2PKCovenantData()), icbHeightV1, true))
	w.read(t, 1, btUTXOKey(1, f.c), btValue(btFrame(7, COV_TYPE_P2PK, validP2PKCovenantData()), icbHeightV1-1, true))
	for _, gone := range []Outpoint{f.a, f.b, f.o1, {Txid: f.cb0.Txid, Vout: 1}} {
		w.read(t, 1, btUTXOKey(1, gone), nil)
	}
}

// TestInitial148CompleteBlockUpdateTreeH5 (C13) composes the root-valid h=5
// result into a real Store.UpdateTreeV1 inside run: the native writer
// consumes the immutable source exactly once through a fresh Reader after
// the builder's Reader expired, while W is still held on the same account;
// the native truth/stage/index are the owner's own values and the final rows
// are written. A commit that reports success runs no readback (internal/mdbx
// updateNativeReadback runs the truth evaluator only after a possibly
// crossed commit), so the readback position is observed by
// TestInitial148CompleteBlockUpdateTreeReadbackH5 under the fixture tag.
func TestInitial148CompleteBlockUpdateTreeH5(t *testing.T) {
	for name, parallel := range map[string]bool{"sequential": false, "parallel": true} {
		w := btNew(t)
		f := icbH5FixtureV1(t, w)
		icbUpdateTreeH5V1(t, w, f, parallel).check(t, f, name, nil, [3]int{0, 1, 0})
		icbFinalRowsH5V1(t, w, f)
	}
}

// TestInitial148CompleteBlockUpdateTreeFailuresH5 (C13) runs the h=5
// fixture inside a real Store.UpdateTreeV1. A root mismatch makes the builder
// return the validation error with no operation: nothing is written and the
// parent rows stay. A root-valid result composed into the operation whose
// native source consumption then fails returns that native error unchanged
// (validationErr stays nil, the result is not replaced by a validation
// projection), W is still held at the native failure and released after run,
// and nothing is written.
func TestInitial148CompleteBlockUpdateTreeFailuresH5(t *testing.T) {
	nativeErr := errors.New("native source consumption failure")
	for _, mode := range []string{"validation", "native"} {
		for _, parallel := range []bool{false, true} {
			w := btNew(t)
			opts := icbH5OptsV1{}
			if mode == "validation" {
				opts.flip = 1
			}
			f := icbH5VariantV1(t, w, opts)
			tariff, ok := initial148CompleteTariffV1(f.in)
			logicalMDBXAssert(t, ok, "tariff")
			composed, consumed, released := false, 0, 0
			var nativeOut error
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				observed := &icbNativeSourceV1{}
				// Possibly on the native writer goroutine: record only; asserted below.
				observed.before = func(mdbx.TreePositionV1, *mdbx.Reader, *mdbx.TreeDeltaSinkV1) error {
					consumed++
					held := account.WithReservation(402_653_184-tariff+1, func() error { return nil })
					if !mdbx.IsOperationReservationCapacity(held) {
						released++
					}
					return nativeErr
				}
				out, err := icbEntryV1(parallel)(account, f.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
					_, _, _, nativeOut = w.s.UpdateTreeV1(account, func(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
						result, verr := validate(reader)
						if verr != nil {
							return mdbx.TreeOperationV1{}, verr
						}
						observed.source = result.effect.Primitive.Source.(*blockTreeSourceV1)
						_, present, gerr := reader.Get(mdbx.TreeSchemaV1DBIs()[3], result.effect.Primitive.Block[:])
						if gerr != nil {
							return mdbx.TreeOperationV1{}, gerr
						}
						composed = true
						return icbComposeV1(result, observed, f.in.Raw[:Initial148HeaderBytes], present), nil
					})
					return nativeOut
				})
				if mode == "validation" {
					var txErr *TxError
					logicalMDBXAssert(t, errors.As(err, &txErr) && txErr.Code == BLOCK_ERR_UTXO_ROOT_MISMATCH && any(out.validationErr) == any(err) && !composed && consumed == 0, "%s parallel=%v: %v composed=%v consumed=%d", mode, parallel, err, composed, consumed)
					return
				}
				logicalMDBXAssert(t, errors.Is(err, nativeErr) && any(err) == any(nativeOut) && out.attempted && out.validationErr == nil && out.required.derived, "%s parallel=%v run error replaced: %v / %+v", mode, parallel, err, out)
				logicalMDBXAssert(t, released == 0, "%s parallel=%v W released before native failure (%d)", mode, parallel, released)
				logicalMDBXAssert(t, observed.badWindow == 0, "%s parallel=%v native source window length differs from 65536 (%d)", mode, parallel, observed.badWindow)
				logicalMDBXAssert(t, composed && consumed > 0 && icbHoldsExactlyV1(account, 0), "%s parallel=%v composed=%v consumed=%d or residual hold", mode, parallel, composed, consumed)
			})
			if mode == "native" {
				// The failed native writer closes this store handle; read the
				// durable state through a fresh handle.
				w.reopen(t)
			}
			cov := f.created[f.o2].CovenantData
			w.read(t, 1, btUTXOKey(1, f.o2), nil)
			w.read(t, 1, btUTXOKey(1, f.cb0), nil)
			w.read(t, 1, btUTXOKey(1, f.a), btValue(btFrame(1000, COV_TYPE_P2PK, cov), f.h-1, false))
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
		{name: "tx-before-subsidy", opts: icbH5OptsV1{overspend: true, cbExtra: icbSubsidy5V1 + 1, flip: 1}, capFrom: icbHeightV1, counters: [2]uint64{1, 1}},
	}
	for i, base := range []icbH5CaseV1{mismatch, mismatch, sig, sig, conservation, subsidy, {}, conservation} {
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
	icbCapRootHexV1    = "e0fd3b958eeb0f0f5bb8f375b55c5d0274b2ae6bec37d5f906b0d144be4dd2d0"
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
// signature through every entry, with the tuple of icbRefusedDiscardV1.
func icbPendingDiscardV1(t *testing.T, name string, opts icbH5OptsV1) {
	t.Helper()
	opts.badSig = true
	icbRefusedDiscardV1(t, name, opts, TX_ERR_SIG_INVALID, "CORE_P2PK signature invalid")
}

// icbRefusedDiscardV1 rejects opts through every entry with the exact bare
// TxError code/msg, no delivered result and no D; then on the same account
// the whole lane is free again (W, R and source released), and a fresh
// invocation of the valid block over the same parent succeeds with fresh D,
// exactly its own fees and created set (icbCandidateV1): no nonce, fee or
// candidate effect of the refused invocation survives.
func icbRefusedDiscardV1(t *testing.T, name string, opts icbH5OptsV1, code ErrorCode, msg string) {
	t.Helper()
	for _, workers := range []int{-1, 1, 4} {
		w := btNew(t)
		bad := icbH5VariantV1(t, w, opts)
		good := icbH5VariantV1(t, btNew(t), icbH5OptsV1{vault: opts.vault, simplicity: opts.simplicity, spend4: 1, cbExtra: opts.cbExtra})
		logicalMDBXAssert(t, good.in.Parent == bad.in.Parent, "%s workers=%d fixtures do not share the parent", name, workers)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			out, delivered, err := icbDiscardRunV1(w, account, bad.in, workers)
			var txErr *TxError
			exact := errors.As(err, &txErr) && any(txErr) == any(err) && txErr.Code == code && txErr.Msg == msg
			logicalMDBXAssert(t, exact && !delivered && out.attempted && any(out.validationErr) == any(err) && out.required == (initial148RootReadOutcomeV1{}), "%s workers=%d rejected tuple: %v / %+v", name, workers, err, out)
			free := account.WithReservation(402_653_184, func() error { return nil })
			logicalMDBXAssert(t, free == nil, "%s workers=%d residual hold after rejection: %v", name, workers, free)
			var fees Uint128
			var created map[Outpoint]UtxoEntry
			delivered = false
			run := func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				return w.s.View(func(reader *mdbx.Reader) error {
					result, verr := validate(reader)
					if result != nil {
						delivered = true
						fees, created = result.transition.sumFees, maps.Clone(result.transition.createdUtxos)
					}
					return verr
				})
			}
			out, err = icbEntryWorkersV1(workers)(account, good.in, run)
			logicalMDBXAssert(t, err == nil && delivered && out.required.derived && out.required.root == good.header.UtxoRoot, "%s workers=%d fresh second invocation: %v / %+v", name, workers, err, out)
			wantFees, wantCreated := good.icbCandidateV1()
			logicalMDBXAssert(t, fees == wantFees && reflect.DeepEqual(created, wantCreated), "%s workers=%d refused effects leaked: fees=%+v created=%+v", name, workers, fees, created)
		})
	}
}

// TestInitial148CompleteBlockAcceptedRollbackH5 (C06 candidate rollback)
// refuses tx2 (sum_out exceeds sum_in) after tx1 was accepted into the
// candidate: the exact conservation error, no result and no D, and the
// fresh valid invocation on the same account and parent is unaffected.
func TestInitial148CompleteBlockAcceptedRollbackH5(t *testing.T) {
	icbRefusedDiscardV1(t, "tx2-refused-after-tx1-accepted", icbH5OptsV1{overspend: true, flip: 1}, TX_ERR_VALUE_CONSERVATION, "sum_out exceeds sum_in")
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
	mixed := icbH5OptsV1{vault: true, simplicity: 1, cbExtra: 20}
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
	// S3d: nine same-CMR inputs exceed SIMPLICITY_MAX_GROUP_INPUTS (8) after
	// complete R1, R3 and S3b (simplicity_txcontext.go populate input views).
	group := mixed
	group.flip, group.simplicity = 1, 9
	icbH5RunCaseV1(t, icbH5CaseV1{name: "S3d-control", opts: group, code: TX_ERR_COVENANT_TYPE_INVALID, msg: "CORE_SIMPLICITY same-cmr input group exceeds limit"})
	icbPendingDiscardV1(t, "S3d-pending", group)
}

// TestInitial148CompleteBlockDeriveCapacityH5 (C10 capacity, h>0) is the h=5
// form of TestInitial148CompleteBlockDeriveCapacityNoResult: the same account
// keeps exactly W, R=69,656+196,824E and D=288,408+104E free (the control is
// delivered), then one byte less; the refused D keeps its raw capacity cause,
// derived=false, no observation and no result through every entry. E is the
// EventCount the control's delivered source coverage records.
func TestInitial148CompleteBlockDeriveCapacityH5(t *testing.T) {
	for _, workers := range []int{-1, 1, 4} {
		w := btNew(t)
		f := icbH5FixtureV1(t, w)
		tariff, ok := initial148CompleteTariffV1(f.in)
		logicalMDBXAssert(t, ok, "tariff")
		var events uint64
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			_, err := withInitial148CompleteBlockV1(account, f.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				return w.s.View(func(reader *mdbx.Reader) error {
					result, verr := validate(reader)
					if result != nil {
						events = uint64(result.effect.Primitive.Coverage.BlockMeta.EventCount)
					}
					return verr
				})
			})
			logicalMDBXAssert(t, err == nil && events != 0, "event count control: %v", err)
		})
		hold := uint64(402_653_184) - tariff - (69_656 + 196_824*events) - (288_408 + 104*events)
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			logicalMDBXAssert(t, account.WithReservation(hold, func() error {
				out, delivered, err := icbDiscardRunV1(w, account, f.in, workers)
				logicalMDBXAssert(t, err == nil && delivered && out.required.derived, "workers=%d exact D residual: %v / %+v", workers, err, out)
				return nil
			}) == nil, "pre-hold control")
			logicalMDBXAssert(t, account.WithReservation(hold+1, func() error {
				out, delivered, err := icbDiscardRunV1(w, account, f.in, workers)
				var txErr *TxError
				logicalMDBXAssert(t, !errors.As(err, &txErr) && mdbx.IsOperationReservationCapacity(err), "workers=%d D capacity: %v", workers, err)
				logicalMDBXAssert(t, any(out.validationErr) == any(err) && any(out.required.cause) == any(err), "workers=%d raw D cause lost: %+v", workers, out)
				logicalMDBXAssert(t, !delivered && out.attempted && !out.required.derived && out.required.root == ([32]byte{}) && !out.required.hasObservation, "workers=%d D capacity outcome: %+v", workers, out)
				return nil
			}) == nil, "pre-hold")
		})
	}
}

// icbLaneV1 is TREE_LANE_MAX=402,653,184, the TreeOperation account ceiling.
const icbLaneV1 = 402_653_184

// icbW5V1 is the RUB-1654 W of an h=5 fixture input from literal counts:
// n=len(Raw); d=0, c=0 (inactive empty cap registry); DefaultSuiteRegistry
// has r=1 suite named "ML-DSA-87" (a=9); p=min(5,11)=5 parent timestamps; g=0.
func icbW5V1(n int) uint64 {
	return 16_777_216 + 8_192*uint64(n) + 16_384*0 + 128*0 + 1_024*1 + 2*9 + 8*5 + 0
}

// icbHoldsExactlyV1 reports whether the account holds exactly held bytes:
// the remaining lane fits icbLaneV1-held and not one byte more.
func icbHoldsExactlyV1(account *mdbx.OperationAccount, held uint64) bool {
	fits := account.WithReservation(icbLaneV1-held, func() error { return nil }) == nil
	over := account.WithReservation(icbLaneV1-held+1, func() error { return nil })
	return fits && mdbx.IsOperationReservationCapacity(over)
}

// icbHugeLenV1 returns a slice header of length n over one element. Only
// len() is read by the tariff; no element beyond the first is ever indexed.
func icbHugeLenV1(n int) []SimplicityDeploymentDescriptor {
	s := make([]SimplicityDeploymentDescriptor, 1)
	header := (*struct {
		data     unsafe.Pointer
		len, cap int
	})(unsafe.Pointer(&s))
	header.len, header.cap = n, n
	return s
}

// TestInitial148CompleteBlockTariffOverflow (C12 overflow) drives the checked
// uint64 recipe on icbInputV1 (fixed part 18,417,692, d the only varied
// count) across multiplication overflow (16,384*2^50 = 2^64), addition carry
// (16,384*(2^50-2^10) = 2^64-2^24, plus 2^24), the int64 domain bound and its
// largest admitted value. The refusals return the local invariant failure
// before W and never invoke run.
func TestInitial148CompleteBlockTariffOverflow(t *testing.T) {
	const fixed = 18_417_692
	const largest = (1<<63 - 1 - fixed) / 16_384
	cases := []struct {
		name string
		d    int
		ok   bool
		w    uint64
	}{
		{"multiplication-overflow", 1 << 50, false, 0},
		{"addition-carry", 1<<50 - 1<<10, false, 0},
		{"above-int64", 1 << 49, false, 0},
		{"largest-admitted", largest, true, fixed + 16_384*largest},
		{"one-above-largest", largest + 1, false, 0},
	}
	w := btNew(t)
	for _, c := range cases {
		in := icbInputV1()
		in.Rotation = &boundSpendSurfaceWithDeployment{boundSpendSurface: icbFrozenV1(1), descriptors: icbHugeLenV1(c.d), have: true}
		got, ok := initial148CompleteTariffV1(in)
		logicalMDBXAssert(t, ok == c.ok && (!c.ok || got == c.w), "%s: W=%d ok=%v want %d/%v", c.name, got, ok, c.w, c.ok)
		if c.ok {
			continue
		}
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			called := false
			out, err := withInitial148CompleteBlockParallelV1(account, in, 4, func(func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				called = true
				return nil
			})
			var failure *logicalStateFailure
			local := errors.As(err, &failure) && failure.kind == logicalStateFailureLocalInvariant
			logicalMDBXAssert(t, local && !called && out == (initial148CompleteBlockOutcomeV1{}) && icbHoldsExactlyV1(account, 0), "%s entry: err=%v called=%v out=%+v", c.name, err, called, out)
		})
	}
}

// TestInitial148CompleteBlockTariffH5 (C12 exact residual) pins the h=5 W
// from literal counts and, on the same account pre-holding everything but W
// plus the nested source scratch 4,824, R=69,656+196,824E and D=288,408+104E,
// walks every reserve boundary through each entry: one byte below the source
// scratch, R and D each refuses with the raw capacity cause at its own charge
// (only D's refusal is the D cause), the exact sum accepts, and W-1 refuses
// before run. E is the control's delivered source EventCount.
func TestInitial148CompleteBlockTariffH5(t *testing.T) {
	for _, workers := range []int{-1, 1, 4} {
		w := btNew(t)
		f := icbH5FixtureV1(t, w)
		tariff := icbW5V1(len(f.in.Raw))
		got, ok := initial148CompleteTariffV1(f.in)
		logicalMDBXAssert(t, ok && got == tariff, "h5 W %d/%v want literal %d", got, ok, tariff)
		events := icbEventsV1(t, w, f.in)
		r, d := uint64(69_656+196_824*events), uint64(288_408+104*events)
		cases := []struct {
			name             string
			free             uint64
			called, accepted bool
			dCause           bool
		}{
			{"W-1", tariff - 1, false, false, false},
			{"source-scratch-1", tariff + 4_824 - 1, true, false, false},
			{"R-1", tariff + r - 1, true, false, false},
			{"D-1", tariff + r + d - 1, true, false, true},
			{"exact", tariff + r + d, true, true, false},
		}
		for _, c := range cases {
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				logicalMDBXAssert(t, account.WithReservation(icbLaneV1-c.free, func() error {
					called := false
					var out initial148CompleteBlockOutcomeV1
					var delivered bool
					var err error
					run := func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
						called = true
						return w.s.View(func(reader *mdbx.Reader) error {
							result, verr := validate(reader)
							delivered = result != nil
							return verr
						})
					}
					if workers < 0 {
						out, err = withInitial148CompleteBlockV1(account, f.in, run)
					} else {
						out, err = withInitial148CompleteBlockParallelV1(account, f.in, workers, run)
					}
					logicalMDBXAssert(t, called == c.called && delivered == c.accepted, "%s workers=%d called=%v delivered=%v err=%v", c.name, workers, called, delivered, err)
					if c.accepted {
						logicalMDBXAssert(t, err == nil && out.required.derived && out.required.root == f.header.UtxoRoot, "%s workers=%d: %v / %+v", c.name, workers, err, out)
						return nil
					}
					var txErr *TxError
					logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(err) && !errors.As(err, &txErr) && out.attempted == c.called, "%s workers=%d capacity: %v / %+v", c.name, workers, err, out)
					logicalMDBXAssert(t, (any(out.required.cause) == any(err)) == c.dCause && !out.required.derived && !out.required.hasObservation, "%s workers=%d required: %+v", c.name, workers, out.required)
					return nil
				}) == nil, "%s pre-hold", c.name)
			})
		}
	}
}

// icbEventsV1 returns the source EventCount of a delivered control validation.
func icbEventsV1(t *testing.T, w *btWorld, in initial148CompleteBlockInputV1) uint64 {
	t.Helper()
	var events uint64
	icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
		_, err := withInitial148CompleteBlockV1(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			return w.s.View(func(reader *mdbx.Reader) error {
				result, verr := validate(reader)
				if result != nil {
					events = uint64(result.effect.Primitive.Coverage.BlockMeta.EventCount)
				}
				return verr
			})
		})
		logicalMDBXAssert(t, err == nil && events != 0, "event count control: %v", err)
	})
	return events
}

// TestInitial148CompleteBlockStageHoldsH5 (C12 last-use holds) probes the
// same account at every run-visible stage of the h=5 block through each
// entry: before validate, inside the Reader after validate returned (source
// scratch, R and D already released), after the builder's Reader expired, and
// for a rejected variant after validate returned; each holds exactly W. After
// the entry returns, nothing is held.
func TestInitial148CompleteBlockStageHoldsH5(t *testing.T) {
	for _, flip := range []int{0, 1} {
		for _, workers := range []int{-1, 1, 4} {
			w := btNew(t)
			f := icbH5VariantV1(t, w, icbH5OptsV1{flip: flip})
			tariff := icbW5V1(len(f.in.Raw))
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				var stages []string
				probe := func(stage string) {
					if !icbHoldsExactlyV1(account, tariff) {
						stages = append(stages, stage)
					}
				}
				run := func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
					probe("before-validate")
					err := w.s.View(func(reader *mdbx.Reader) error {
						_, verr := validate(reader)
						probe("after-validate")
						return verr
					})
					probe("after-builder")
					return err
				}
				var err error
				if workers < 0 {
					_, err = withInitial148CompleteBlockV1(account, f.in, run)
				} else {
					_, err = withInitial148CompleteBlockParallelV1(account, f.in, workers, run)
				}
				logicalMDBXAssert(t, (err == nil) == (flip == 0) && len(stages) == 0, "flip=%d workers=%d W not exactly held at %v (err %v)", flip, workers, stages, err)
				logicalMDBXAssert(t, icbHoldsExactlyV1(account, 0), "flip=%d workers=%d residual hold after return", flip, workers)
			})
		}
	}
}

// TestInitial148CompleteBlockUnwindReleaseH5 (C12 release, C13) delivers the
// root-valid h=5 result and then ends run by error, panic or Goexit through
// each entry: the error or panic is propagated exactly, the account holds
// nothing afterwards and a fresh invocation on the same account accepts with
// a fresh D.
func TestInitial148CompleteBlockUnwindReleaseH5(t *testing.T) {
	for _, delivery := range []string{"error", "panic", "goexit"} {
		for _, workers := range []int{-1, 1, 4} {
			w := btNew(t)
			f := icbH5FixtureV1(t, w)
			icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
				failure, panicValue := errors.New("enclosing failure after success"), new(int)
				var err, validated error
				var recovered any
				delivered := false
				done := make(chan struct{})
				go func() {
					defer close(done)
					defer func() { recovered = recover() }()
					_, err = icbEntryWorkersV1(workers)(account, f.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
						verr := w.s.View(func(reader *mdbx.Reader) error {
							result, verr := validate(reader)
							delivered, validated = result != nil, verr
							return verr
						})
						switch delivery {
						case "panic":
							panic(panicValue)
						case "goexit":
							runtime.Goexit()
						}
						return errors.Join(verr, failure)
					})
				}()
				<-done
				// FailNow must run on the test goroutine: the condition was recorded above.
				logicalMDBXAssert(t, delivered && validated == nil, "%s workers=%d success: %v", delivery, workers, validated)
				switch delivery {
				case "error":
					logicalMDBXAssert(t, errors.Is(err, failure) && recovered == nil, "%s workers=%d: %v", delivery, workers, err)
				case "panic":
					logicalMDBXAssert(t, recovered == panicValue, "%s workers=%d panic changed: %v", delivery, workers, recovered)
				default:
					logicalMDBXAssert(t, recovered == nil && err == nil, "%s workers=%d Goexit continued: %v / %v", delivery, workers, recovered, err)
				}
				logicalMDBXAssert(t, icbHoldsExactlyV1(account, 0), "%s workers=%d residual hold after unwind", delivery, workers)
				out, delivered, err := icbDiscardRunV1(w, account, f.in, workers)
				logicalMDBXAssert(t, err == nil && delivered && out.required.derived && out.required.root == f.header.UtxoRoot, "%s workers=%d fresh retry: %v / %+v", delivery, workers, err, out)
			})
		}
	}
}

func icbEntryWorkersV1(workers int) func(*mdbx.OperationAccount, initial148CompleteBlockInputV1, initial148CompleteRunV1) (initial148CompleteBlockOutcomeV1, error) {
	if workers < 0 {
		return withInitial148CompleteBlockV1
	}
	return func(a *mdbx.OperationAccount, in initial148CompleteBlockInputV1, run initial148CompleteRunV1) (initial148CompleteBlockOutcomeV1, error) {
		return withInitial148CompleteBlockParallelV1(a, in, workers, run)
	}
}

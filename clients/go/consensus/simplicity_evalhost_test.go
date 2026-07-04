package consensus

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
)

// in builds a minimal context-ABI probe row: the RUB-614 adapter dispatches only on
// ID/Index (Either is a totality hint the adapter never reads), so these two fields
// fully determine resolve()'s branch.
func in(id, index uint16) simplicity.ContextIntrinsic {
	return simplicity.ContextIntrinsic{ID: id, Index: index}
}

// evalHostFixture builds one rich context: two same-CMR CORE_SIMPLICITY inputs (a live
// group), a foreign-CMR CORE_SIMPLICITY input, a P2PK input, one CORE_SIMPLICITY output
// sharing the self CMR plus a P2PK output — so global scalars, self, indexed IO, group,
// and descriptor-hash intrinsics all have real answers. The self input is index 0.
func evalHostFixture(t *testing.T) (*SimplicityTxContext, [32]byte, uint8, [32]byte, uint64) {
	t.Helper()
	chainID := [32]byte{0: 0xc1, 31: 0xc2}
	selfCMR := [32]byte{0: 0x5e, 31: 0x1f}
	foreignCMR := [32]byte{0: 0xf0}
	digest32 := [32]byte{0: 0xd1, 1: 0xd2}
	selfState := []byte{0xaa, 0xbb, 0xcc}
	tx := &Tx{
		Version:  TX_WIRE_VERSION,
		TxKind:   0x00,
		TxNonce:  0x1122334455667788,
		Locktime: 0xdeadbeef,
		Inputs:   []TxInput{{PrevVout: 0}, {PrevVout: 1}, {PrevVout: 2}, {PrevVout: 3}},
		Outputs: []TxOutput{
			{Value: 900, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(selfCMR, []byte{0x09})},
			{Value: 800, CovenantType: COV_TYPE_P2PK, CovenantData: []byte{0x02, 0xab, 0xcd}},
		},
	}
	resolved := []UtxoEntry{
		{Value: 100, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(selfCMR, selfState)},
		{Value: 200, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(selfCMR, []byte{0x77})},
		{Value: 300, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(foreignCMR, nil)},
		{Value: 400, CovenantType: COV_TYPE_P2PK, CovenantData: []byte{0x03, 0x01, 0x02, 0x03}},
	}
	ctx, err := BuildSimplicityTxContext(tx, resolved, 0x4242, chainID)
	if err != nil {
		t.Fatalf("BuildSimplicityTxContext: %v", err)
	}
	return ctx, chainID, SIGHASH_ALL, digest32, 100
}

func newEvalHostForTest(t *testing.T, ctx *SimplicityTxContext, sighashType uint8, digest32 [32]byte) *simplicityEvalHost {
	t.Helper()
	host, err := newSimplicityEvalHost(ctx, 0, sighashType, digest32)
	if err != nil {
		t.Fatalf("newSimplicityEvalHost: %v", err)
	}
	return host
}

func mustRead(t *testing.T, host *simplicityEvalHost, row simplicity.ContextIntrinsic) simplicity.IntrinsicResult {
	t.Helper()
	res, err := host.ReadIntrinsic(row)
	if err != nil {
		t.Fatalf("ReadIntrinsic(%#x): %v", row.ID, err)
	}
	return res
}

func mustCost(t *testing.T, host *simplicityEvalHost, row simplicity.ContextIntrinsic) uint64 {
	t.Helper()
	cost, err := host.IntrinsicCost(row)
	if err != nil {
		t.Fatalf("IntrinsicCost(%#x): %v", row.ID, err)
	}
	return cost
}

func TestSimplicityEvalHostGlobalAndSelf(t *testing.T) {
	ctx, chainID, sighashType, digest32, selfValue := evalHostFixture(t)
	host := newEvalHostForTest(t, ctx, sighashType, digest32)

	// digest32 (a fabricated fixture value) is surfaced verbatim and stable after other reads; the
	// REAL eager SighashV1DigestWithType binding is discharged by TestSimplicityEvalHostEagerRealDigest.
	digestRow := in(0x0115, 0)
	if got := mustRead(t, host, digestRow).Value.Bytes32; got != digest32 {
		t.Fatalf("ctx_self_digest32=%x want %x", got, digest32)
	}

	b := ctx.Base
	for _, tc := range []struct {
		name string
		row  simplicity.ContextIntrinsic
		kind simplicity.ContextValueKind
		uint uint64
		b32  [32]byte
		u128 simplicity.Uint128
		byts []byte
	}{
		{"chain_id", in(0x0100, 0), simplicity.ContextValueBytes32, 0, chainID, simplicity.Uint128{}, nil},
		{"height", in(0x0101, 0), simplicity.ContextValueU64, b.Height, [32]byte{}, simplicity.Uint128{}, nil},
		{"tx_kind", in(0x0102, 0), simplicity.ContextValueU8, uint64(b.TxKind), [32]byte{}, simplicity.Uint128{}, nil},
		{"tx_nonce", in(0x0103, 0), simplicity.ContextValueU64, b.TxNonce, [32]byte{}, simplicity.Uint128{}, nil},
		{"locktime", in(0x0104, 0), simplicity.ContextValueU32, uint64(b.Locktime), [32]byte{}, simplicity.Uint128{}, nil},
		{"input_count", in(0x0105, 0), simplicity.ContextValueU16, uint64(b.InputCount), [32]byte{}, simplicity.Uint128{}, nil},
		{"output_count", in(0x0106, 0), simplicity.ContextValueU16, uint64(b.OutputCount), [32]byte{}, simplicity.Uint128{}, nil},
		{"total_in", in(0x0107, 0), simplicity.ContextValueU128, 0, [32]byte{}, simplicity.Uint128{Lo: b.TotalIn.Lo, Hi: b.TotalIn.Hi}, nil},
		{"total_out", in(0x0108, 0), simplicity.ContextValueU128, 0, [32]byte{}, simplicity.Uint128{Lo: b.TotalOut.Lo, Hi: b.TotalOut.Hi}, nil},
		{"self_input_index", in(0x0110, 0), simplicity.ContextValueU16, 0, [32]byte{}, simplicity.Uint128{}, nil},
		{"self_value", in(0x0111, 0), simplicity.ContextValueU64, selfValue, [32]byte{}, simplicity.Uint128{}, nil},
		{"self_state", in(0x0112, 0), simplicity.ContextValueBytes, 0, [32]byte{}, simplicity.Uint128{}, []byte{0xaa, 0xbb, 0xcc}},
		{"self_program_cmr", in(0x0113, 0), simplicity.ContextValueBytes32, 0, [32]byte{0: 0x5e, 31: 0x1f}, simplicity.Uint128{}, nil},
		{"self_sighash_type", in(0x0114, 0), simplicity.ContextValueU8, uint64(sighashType), [32]byte{}, simplicity.Uint128{}, nil},
		{"self_digest32", digestRow, simplicity.ContextValueBytes32, 0, digest32, simplicity.Uint128{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := mustRead(t, host, tc.row)
			if res.Failure {
				t.Fatalf("%s unexpected Failure", tc.name)
			}
			v := res.Value
			if v.Kind != tc.kind {
				t.Fatalf("%s kind=%d want %d", tc.name, v.Kind, tc.kind)
			}
			if v.Uint != tc.uint || v.Bytes32 != tc.b32 || v.Uint128 != tc.u128 || string(v.Bytes) != string(tc.byts) {
				t.Fatalf("%s value mismatch: %+v", tc.name, v)
			}
			if c := mustCost(t, host, tc.row); c != simplicity.IntrinsicReadCost {
				t.Fatalf("%s cost=%d want %d", tc.name, c, simplicity.IntrinsicReadCost)
			}
		})
	}

	if got := mustRead(t, host, digestRow).Value.Bytes32; got != digest32 {
		t.Fatalf("ctx_self_digest32 drifted after reads: %x want %x", got, digest32)
	}
}

// TestSimplicityEvalHostEagerRealDigest discharges the E1 eager-binding mandate: the host must
// hold the REAL sighash digest — SighashV1DigestWithType(tx, i, value, chainID, sighash_type),
// computed eagerly by the caller — asserted on an input whose program never reads
// ctx_self_digest32. A fabricated digest (as evalHostFixture uses for the surface-verbatim path)
// would pass the round-trip check but not prove the real sighash digest is wired; a zero digest
// would pass just as trivially — hence the explicit non-zero + real-derivation assertions here.
func TestSimplicityEvalHostEagerRealDigest(t *testing.T) {
	chainID := [32]byte{0: 0xab, 31: 0xcd}
	selfCMR := [32]byte{0: 0x5e, 31: 0x1f}
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: []byte{0x01, 0x02}}},
	}
	resolved := []UtxoEntry{{Value: 500, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(selfCMR, nil)}}
	ctx, err := BuildSimplicityTxContext(tx, resolved, 7, chainID)
	if err != nil {
		t.Fatalf("BuildSimplicityTxContext: %v", err)
	}
	want, err := SighashV1DigestWithType(tx, 0, 500, chainID, SIGHASH_ALL)
	if err != nil {
		t.Fatalf("SighashV1DigestWithType: %v", err)
	}
	if want == ([32]byte{}) {
		t.Fatal("real sighash digest must be non-zero (else the binding assertion is vacuous)")
	}
	// The self input's program does NOT read ctx_self_digest32 here: the host must already bind the
	// eager real digest at construction (via SelfView), independent of any intrinsic read.
	host := newEvalHostForTest(t, ctx, SIGHASH_ALL, want)
	if host.self.Digest32 != want {
		t.Fatalf("eager digest not bound: got %x want SighashV1DigestWithType %x", host.self.Digest32, want)
	}
}

func TestSimplicityEvalHostIndexedInputsOutputs(t *testing.T) {
	ctx, _, sighashType, digest32, _ := evalHostFixture(t)
	host := newEvalHostForTest(t, ctx, sighashType, digest32)

	for _, tc := range []struct {
		name string
		row  simplicity.ContextIntrinsic
		kind simplicity.ContextValueKind
		want uint64
	}{
		{"inputs_value_0", in(0x0120, 0), simplicity.ContextValueU64, 100},
		{"inputs_value_3", in(0x0120, 3), simplicity.ContextValueU64, 400},
		{"inputs_covenant_0", in(0x0121, 0), simplicity.ContextValueU16, uint64(COV_TYPE_CORE_SIMPLICITY)},
		{"inputs_covenant_3", in(0x0121, 3), simplicity.ContextValueU16, uint64(COV_TYPE_P2PK)},
		{"outputs_value_0", in(0x0128, 0), simplicity.ContextValueU64, 900},
		{"outputs_value_1", in(0x0128, 1), simplicity.ContextValueU64, 800},
		{"outputs_covenant_1", in(0x0129, 1), simplicity.ContextValueU16, uint64(COV_TYPE_P2PK)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := mustRead(t, host, tc.row)
			if res.Failure || res.Value.Kind != tc.kind || res.Value.Uint != tc.want {
				t.Fatalf("%s=%+v want kind %d value %d", tc.name, res, tc.kind, tc.want)
			}
			if c := mustCost(t, host, tc.row); c != simplicity.IntrinsicReadCost {
				t.Fatalf("%s cost=%d want read", tc.name, c)
			}
		})
	}

	// E7 totality: an out-of-range Either read is Failure (never an error) at miss cost.
	for _, row := range []simplicity.ContextIntrinsic{in(0x0120, 4), in(0x0121, 4), in(0x0128, 2), in(0x0129, 9)} {
		res := mustRead(t, host, row)
		if !res.Failure {
			t.Fatalf("out-of-range %#x must be Failure, got %+v", row.ID, res)
		}
		if c := mustCost(t, host, row); c != simplicity.IntrinsicMissCost {
			t.Fatalf("out-of-range %#x cost=%d want miss", row.ID, c)
		}
	}
}

func TestSimplicityEvalHostGroup(t *testing.T) {
	ctx, _, sighashType, digest32, _ := evalHostFixture(t)
	host := newEvalHostForTest(t, ctx, sighashType, digest32)

	// The self CMR group has 2 inputs (values 100,200) and 1 output (value 900).
	for _, tc := range []struct {
		name  string
		row   simplicity.ContextIntrinsic
		value uint64
		state []byte
	}{
		{"group_inputs_value_0", in(0x0130, 0), 100, nil},
		{"group_inputs_value_1", in(0x0130, 1), 200, nil},
		{"group_inputs_state_0", in(0x0131, 0), 0, []byte{0xaa, 0xbb, 0xcc}},
		{"group_inputs_state_1", in(0x0131, 1), 0, []byte{0x77}},
		{"group_outputs_value_0", in(0x0138, 0), 900, nil},
		{"group_outputs_state_0", in(0x0139, 0), 0, []byte{0x09}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := mustRead(t, host, tc.row)
			if res.Failure {
				t.Fatalf("%s unexpected Failure", tc.name)
			}
			if tc.state != nil {
				if res.Value.Kind != simplicity.ContextValueBytes || string(res.Value.Bytes) != string(tc.state) {
					t.Fatalf("%s state=%x want %x", tc.name, res.Value.Bytes, tc.state)
				}
			} else if res.Value.Kind != simplicity.ContextValueU64 || res.Value.Uint != tc.value {
				t.Fatalf("%s value=%d want %d", tc.name, res.Value.Uint, tc.value)
			}
		})
	}

	for _, row := range []simplicity.ContextIntrinsic{in(0x0130, 2), in(0x0131, 2), in(0x0138, 1), in(0x0139, 5)} {
		res := mustRead(t, host, row)
		if !res.Failure {
			t.Fatalf("out-of-range group %#x must be Failure, got %+v", row.ID, res)
		}
		if c := mustCost(t, host, row); c != simplicity.IntrinsicMissCost {
			t.Fatalf("out-of-range group %#x cost=%d want miss", row.ID, c)
		}
	}
}

func TestSimplicityEvalHostDescriptorHash(t *testing.T) {
	ctx, _, sighashType, digest32, _ := evalHostFixture(t)
	host := newEvalHostForTest(t, ctx, sighashType, digest32)

	// E15: in-range descriptor hash returns Bytes32 and charges base+per-byte, matching
	// the txcontext's own metered access exactly (no memoization discount).
	for _, tc := range []struct {
		name string
		row  simplicity.ContextIntrinsic
		want func(uint16, *SimplicityTxContextMeter) (SimplicityTxContextDescriptorHashResult, error)
	}{
		{"input_descriptor_0", in(0x0122, 0), ctx.InputDescriptorHash},
		{"input_descriptor_3", in(0x0122, 3), ctx.InputDescriptorHash},
		{"output_descriptor_1", in(0x012a, 1), ctx.OutputDescriptorHash},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var meter SimplicityTxContextMeter
			want, err := tc.want(tc.row.Index, &meter)
			if err != nil || !want.Present {
				t.Fatalf("%s reference access err=%v present=%v", tc.name, err, want.Present)
			}
			res := mustRead(t, host, tc.row)
			if res.Failure || res.Value.Kind != simplicity.ContextValueBytes32 || res.Value.Bytes32 != want.Hash {
				t.Fatalf("%s=%+v want hash %x", tc.name, res, want.Hash)
			}
			if c := mustCost(t, host, tc.row); c != meter.Cost() {
				t.Fatalf("%s cost=%d want %d (base+perByte)", tc.name, c, meter.Cost())
			}
			if meter.Cost() <= simplicity.DescriptorHashBaseCost {
				t.Fatalf("%s per-byte cost not applied: %d", tc.name, meter.Cost())
			}
		})
	}

	// E15: reading the SAME descriptor hash twice re-charges the full base+per-byte cost
	// (no memoization discount) and re-materializes the identical hash — a future result
	// cache that discounted the second read would break this.
	twice := in(0x0122, 0)
	c1, c2 := mustCost(t, host, twice), mustCost(t, host, twice)
	if c1 != c2 || c1 <= simplicity.DescriptorHashBaseCost {
		t.Fatalf("descriptor-hash repeat cost c1=%d c2=%d want equal base+perByte", c1, c2)
	}
	if r1, r2 := mustRead(t, host, twice), mustRead(t, host, twice); r1.Value.Bytes32 != r2.Value.Bytes32 {
		t.Fatalf("descriptor-hash repeat read not pure: %x vs %x", r1.Value.Bytes32, r2.Value.Bytes32)
	}

	// Out-of-range descriptor hash -> Failure at miss cost.
	for _, row := range []simplicity.ContextIntrinsic{in(0x0122, 9), in(0x012a, 9)} {
		res := mustRead(t, host, row)
		if !res.Failure {
			t.Fatalf("out-of-range descriptor %#x must be Failure, got %+v", row.ID, res)
		}
		if c := mustCost(t, host, row); c != simplicity.IntrinsicMissCost {
			t.Fatalf("out-of-range descriptor %#x cost=%d want miss", row.ID, c)
		}
	}
}

func TestSimplicityEvalHostDAViews(t *testing.T) {
	selfCMR := [32]byte{0: 0x7a}
	daID := [32]byte{0: 0x0d}
	build := func(t *testing.T, tx *Tx) *simplicityEvalHost {
		t.Helper()
		tx.Version = TX_WIRE_VERSION
		tx.Inputs = []TxInput{{PrevVout: 0}}
		resolved := []UtxoEntry{{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(selfCMR, nil)}}
		ctx, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{})
		if err != nil {
			t.Fatalf("BuildSimplicityTxContext: %v", err)
		}
		return newEvalHostForTest(t, ctx, SIGHASH_ALL, [32]byte{})
	}

	// Commit ctx: every commit intrinsic returns its value; a chunk intrinsic is Failure.
	retl := [32]byte{0: 0xe1}
	commit := &DaCommitCore{
		DaID: daID, ChunkCount: 3, BatchNumber: 9, RetlDomainID: retl,
		TxDataRoot: [32]byte{0: 0x74}, StateRoot: [32]byte{0: 0x57}, WithdrawalsRoot: [32]byte{0: 0x9d},
	}
	commitHost := build(t, &Tx{TxKind: 0x01, DaCommitCore: commit})
	for _, tc := range []struct {
		row  simplicity.ContextIntrinsic
		u    uint64
		b32  [32]byte
		want simplicity.ContextValueKind
	}{
		{in(0x0140, 0), 0, daID, simplicity.ContextValueBytes32},
		{in(0x0141, 0), 3, [32]byte{}, simplicity.ContextValueU16},
		{in(0x0142, 0), 0, retl, simplicity.ContextValueBytes32},
		{in(0x0143, 0), 9, [32]byte{}, simplicity.ContextValueU64},
		{in(0x0144, 0), 0, commit.TxDataRoot, simplicity.ContextValueBytes32},
		{in(0x0145, 0), 0, commit.StateRoot, simplicity.ContextValueBytes32},
		{in(0x0146, 0), 0, commit.WithdrawalsRoot, simplicity.ContextValueBytes32},
	} {
		res := mustRead(t, commitHost, tc.row)
		if res.Failure || res.Value.Kind != tc.want || res.Value.Uint != tc.u || res.Value.Bytes32 != tc.b32 {
			t.Fatalf("commit %#x=%+v", tc.row.ID, res)
		}
	}
	if res := mustRead(t, commitHost, in(0x0150, 0)); !res.Failure {
		t.Fatalf("chunk intrinsic on commit ctx must Failure, got %+v", res)
	}

	// Chunk ctx: every chunk intrinsic returns its value; a commit intrinsic is a Failure.
	chunkHash := [32]byte{0: 0xcc}
	chunkHost := build(t, &Tx{TxKind: 0x02, DaChunkCore: &DaChunkCore{DaID: daID, ChunkIndex: 5, ChunkHash: chunkHash}})
	if res := mustRead(t, chunkHost, in(0x0150, 0)); res.Failure || res.Value.Bytes32 != daID {
		t.Fatalf("da_chunk_da_id=%+v want %x", res, daID)
	}
	if res := mustRead(t, chunkHost, in(0x0151, 0)); res.Failure || res.Value.Uint != 5 {
		t.Fatalf("da_chunk_chunk_index=%+v want 5", res)
	}
	if res := mustRead(t, chunkHost, in(0x0152, 0)); res.Failure || res.Value.Bytes32 != chunkHash {
		t.Fatalf("da_chunk_chunk_hash=%+v want %x", res, chunkHash)
	}
	if res := mustRead(t, chunkHost, in(0x0140, 0)); !res.Failure {
		t.Fatalf("commit intrinsic on chunk ctx must Failure, got %+v", res)
	}

	// E9: DA-absent ctx -> every DA intrinsic is Failure at miss cost.
	absentHost := build(t, &Tx{TxKind: 0x00})
	for _, row := range []simplicity.ContextIntrinsic{in(0x0140, 0), in(0x0151, 0), in(0x0152, 0)} {
		res := mustRead(t, absentHost, row)
		if !res.Failure {
			t.Fatalf("DA-absent %#x must Failure, got %+v", row.ID, res)
		}
		if c := mustCost(t, absentHost, row); c != simplicity.IntrinsicMissCost {
			t.Fatalf("DA-absent %#x cost=%d want miss", row.ID, c)
		}
	}
}

func TestSimplicityEvalHostMeterAndUnknown(t *testing.T) {
	ctx, _, sighashType, digest32, _ := evalHostFixture(t)
	host := newEvalHostForTest(t, ctx, sighashType, digest32)

	// E5: Charge fills to exactly MaxExecCost; one more unit rejects with the shared
	// ErrBudgetExceeded and leaves Cost unchanged (Charge never saturates on error).
	if err := host.Charge(simplicity.MaxExecCost); err != nil {
		t.Fatalf("Charge(MaxExecCost): %v", err)
	}
	if host.Cost() != simplicity.MaxExecCost {
		t.Fatalf("Cost after Charge(MaxExecCost)=%d want %d", host.Cost(), simplicity.MaxExecCost)
	}
	if err := host.Charge(1); err == nil || err.Error() != string(simplicity.ErrBudgetExceeded) {
		t.Fatalf("Charge(1) over budget = %v, want ErrBudgetExceeded", err)
	}
	if host.Cost() != simplicity.MaxExecCost {
		t.Fatalf("Cost after over-budget Charge=%d want %d", host.Cost(), simplicity.MaxExecCost)
	}

	// E8: a fresh host does not inherit the exhausted meter.
	fresh := newEvalHostForTest(t, ctx, sighashType, digest32)
	if fresh.Cost() != 0 {
		t.Fatalf("fresh host Cost=%d want 0", fresh.Cost())
	}
	if err := fresh.Charge(1); err != nil {
		t.Fatalf("fresh host Charge(1): %v", err)
	}
	if fresh.Cost() != 1 || host.Cost() != simplicity.MaxExecCost {
		t.Fatalf("meters shared: fresh=%d host=%d", fresh.Cost(), host.Cost())
	}

	// An unknown intrinsic id is a Failure/miss.
	res := mustRead(t, host, in(0x0200, 0))
	if !res.Failure {
		t.Fatalf("unknown intrinsic must Failure, got %+v", res)
	}
	if c := mustCost(t, host, in(0x0200, 0)); c != simplicity.IntrinsicMissCost {
		t.Fatalf("unknown intrinsic cost=%d want miss", c)
	}
}

func TestSimplicityEvalHostConstructionFailsClosed(t *testing.T) {
	ctx, _, _, _, _ := evalHostFixture(t)
	// Self input index out of range and a non-CORE_SIMPLICITY self input (index 3 is P2PK)
	// both fail construction with the EXACT SelfView code, not a half-built host.
	_, err := newSimplicityEvalHost(ctx, 9, SIGHASH_ALL, [32]byte{})
	assertTxErrCode(t, err, TX_ERR_PARSE)
	_, err = newSimplicityEvalHost(ctx, 3, SIGHASH_ALL, [32]byte{})
	assertTxErrCode(t, err, TX_ERR_COVENANT_TYPE_INVALID)
}

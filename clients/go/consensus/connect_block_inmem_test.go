package consensus

import (
	"math/big"
	"testing"
)

func txBytesFromTx(t *testing.T, tx *Tx) []byte {
	t.Helper()
	if tx == nil {
		t.Fatalf("tx must not be nil")
	}

	b := make([]byte, 0, 256)
	b = AppendU32le(b, tx.Version)
	b = append(b, tx.TxKind)
	b = AppendU64le(b, tx.TxNonce)

	b = AppendCompactSize(b, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		b = append(b, in.PrevTxid[:]...)
		b = AppendU32le(b, in.PrevVout)
		b = AppendCompactSize(b, uint64(len(in.ScriptSig)))
		b = append(b, in.ScriptSig...)
		b = AppendU32le(b, in.Sequence)
	}

	b = AppendCompactSize(b, uint64(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		b = AppendU64le(b, out.Value)
		b = AppendU16le(b, out.CovenantType)
		b = AppendCompactSize(b, uint64(len(out.CovenantData)))
		b = append(b, out.CovenantData...)
	}

	b = AppendU32le(b, tx.Locktime)

	b = AppendCompactSize(b, uint64(len(tx.Witness)))
	for _, w := range tx.Witness {
		b = append(b, w.SuiteID)
		b = AppendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = AppendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}

	b = AppendCompactSize(b, uint64(len(tx.DaPayload)))
	b = append(b, tx.DaPayload...)

	return b
}

func TestConnectBlockBasicInMemoryAtHeight_OK_ComputesFeesAndUpdatesState(t *testing.T) {
	height := uint64(1)

	prev := hashWithPrefix(0x77)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	// Spend a single P2PK UTXO: 100 -> 90 (fee=10).
	prevOut := Outpoint{Txid: prev, Vout: 0}
	spendTx := &Tx{
		Version:   1,
		TxKind:    0x00,
		TxNonce:   1,
		Inputs:    []TxInput{{PrevTxid: prev, PrevVout: 0, ScriptSig: nil, Sequence: 0}},
		Outputs:   []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime:  0,
		Witness:   nil,
		DaPayload: nil,
	}
	spendTx.Witness = []WitnessItem{signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	state := &InMemoryChainState{
		Utxos: map[Outpoint]UtxoEntry{
			prevOut: {
				Value:             100,
				CovenantType:      COV_TYPE_P2PK,
				CovenantData:      covData,
				CreationHeight:    0,
				CreatedByCoinbase: false,
			},
		},
		AlreadyGenerated: new(big.Int),
	}

	sumFees := uint64(10)
	subsidy := BlockSubsidyBig(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	// Provide minimal prev_timestamps to exercise MTP branch (k=min(11,height)=1).
	s, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, state, [32]byte{})
	if err != nil {
		t.Fatalf("ConnectBlockBasicInMemoryAtHeight: %v", err)
	}

	if s.SumFees.Cmp(Uint128FromU64(sumFees)) != 0 {
		t.Fatalf("sum_fees=%d, want %d", s.SumFees, sumFees)
	}
	if s.AlreadyGenerated != (Uint128{}) {
		t.Fatalf("already_generated=%s, want 0", s.AlreadyGenerated.String())
	}
	if s.AlreadyGeneratedN1 != Uint128FromU64(subsidy) {
		t.Fatalf("already_generated_n1=%s, want %d", s.AlreadyGeneratedN1.String(), subsidy)
	}
	// UTXO set should contain spend output + coinbase p2pk output (anchor output is not added).
	if s.UtxoCount != 2 {
		t.Fatalf("utxo_count=%d, want 2", s.UtxoCount)
	}
	if got := state.AlreadyGenerated.Uint64(); got != subsidy {
		t.Fatalf("state.already_generated=%d, want %d", got, subsidy)
	}

	// Per-element UTXO verification: CovenantType, Value, CreatedByCoinbase for each entry.
	spendOut := Outpoint{Txid: spendTxid, Vout: 0}
	spendEntry, ok := state.Utxos[spendOut]
	if !ok {
		t.Fatalf("spend output missing from UTXO set")
	}
	if spendEntry.CovenantType != COV_TYPE_P2PK {
		t.Fatalf("spend output CovenantType=%d, want %d", spendEntry.CovenantType, COV_TYPE_P2PK)
	}
	if spendEntry.Value != 90 {
		t.Fatalf("spend output Value=%d, want 90", spendEntry.Value)
	}
	if spendEntry.CreatedByCoinbase {
		t.Fatalf("spend output CreatedByCoinbase should be false")
	}

	cbOut := Outpoint{Txid: cbTxid, Vout: 0}
	cbEntry, ok := state.Utxos[cbOut]
	if !ok {
		t.Fatalf("coinbase output missing from UTXO set")
	}
	if cbEntry.CovenantType != COV_TYPE_P2PK {
		t.Fatalf("coinbase output CovenantType=%d, want %d", cbEntry.CovenantType, COV_TYPE_P2PK)
	}
	if cbEntry.Value != subsidy+sumFees {
		t.Fatalf("coinbase output Value=%d, want %d", cbEntry.Value, subsidy+sumFees)
	}
	if !cbEntry.CreatedByCoinbase {
		t.Fatalf("coinbase output CreatedByCoinbase should be true")
	}
}

func TestConnectBlockBasicInMemoryAtHeight_NilState(t *testing.T) {
	height := uint64(0)
	prev := hashWithPrefix(0x11)
	target := filledHash(0xff)

	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, height)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 3, [][]byte{coinbase})

	_, err = ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, nil, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}

func TestParseAndValidateBlockBasicWithContextAtHeight_ReturnsParsedBlock(t *testing.T) {
	height := uint64(0)
	prev := hashWithPrefix(0x41)
	target := filledHash(0xff)

	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, height)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 5, [][]byte{coinbase})

	pb, summary, err := parseAndValidateBlockBasicWithContextAtHeight(block, &prev, &target, height, nil, [32]byte{}, nil)
	if err != nil {
		t.Fatalf("parseAndValidateBlockBasicWithContextAtHeight: %v", err)
	}
	if pb == nil || len(pb.Txs) != 1 || len(pb.Txids) != 1 {
		t.Fatalf("unexpected parsed block shape: %#v", pb)
	}
	if pb.Txids[0] != cbTxid {
		t.Fatalf("parsed txid mismatch")
	}

	want, err := ValidateBlockBasicWithContextAtHeight(block, &prev, &target, height, nil)
	if err != nil {
		t.Fatalf("ValidateBlockBasicWithContextAtHeight: %v", err)
	}
	if *summary != *want {
		t.Fatalf("summary mismatch: got %#v want %#v", *summary, *want)
	}
}

func TestConnectBlockBasicInMemoryAtHeight_Height0_DoesNotAdvanceAlreadyGenerated(t *testing.T) {
	height := uint64(0)
	prev := hashWithPrefix(0x12)
	target := filledHash(0xff)

	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, 1)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 4, [][]byte{coinbase})

	state := &InMemoryChainState{Utxos: nil, AlreadyGenerated: new(big.Int).SetUint64(123)}
	s, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, state, [32]byte{})
	if err != nil {
		t.Fatalf("ConnectBlockBasicInMemoryAtHeight: %v", err)
	}
	if s.SumFees.Cmp(Uint128FromU64(0)) != 0 {
		t.Fatalf("sum_fees=%d, want 0", s.SumFees)
	}
	if s.AlreadyGenerated != Uint128FromU64(123) || s.AlreadyGeneratedN1 != Uint128FromU64(123) || state.AlreadyGenerated.Uint64() != 123 {
		t.Fatalf("already_generated advanced at height=0: %#v / state=%d", s, state.AlreadyGenerated.Uint64())
	}
	if s.UtxoCount != 1 {
		t.Fatalf("utxo_count=%d, want 1", s.UtxoCount)
	}
}

func TestConnectBlockBasicInMemoryAtHeight_RejectsSubsidyExceeded(t *testing.T) {
	height := uint64(1)

	prev := hashWithPrefix(0x78)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	prevOut := Outpoint{Txid: prev, Vout: 0}
	spendTx := &Tx{
		Version:   1,
		TxKind:    0x00,
		TxNonce:   1,
		Inputs:    []TxInput{{PrevTxid: prev, PrevVout: 0, ScriptSig: nil, Sequence: 0}},
		Outputs:   []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime:  0,
		Witness:   nil,
		DaPayload: nil,
	}
	spendTx.Witness = []WitnessItem{signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	state := &InMemoryChainState{
		Utxos: map[Outpoint]UtxoEntry{
			prevOut: {
				Value:             100,
				CovenantType:      COV_TYPE_P2PK,
				CovenantData:      covData,
				CreationHeight:    0,
				CreatedByCoinbase: false,
			},
		},
		AlreadyGenerated: new(big.Int),
	}

	sumFees := uint64(10)
	subsidy := BlockSubsidyBig(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees+1, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 2, [][]byte{coinbase, spendBytes})

	_, err = ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, state, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_SUBSIDY_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_SUBSIDY_EXCEEDED)
	}
}

// TestConnectBlockInMemory_SumFeesBindsAnIndividualFeeAboveU64 pins an
// INDIVIDUAL transaction fee whose high u128 limb is non-zero flowing into
// sum_fees, on BOTH accumulation sites: the sequential one in
// connect_block_inmem.go and the queued-parallel one in
// connect_block_parallel.go, which is fed by the separate
// applyNonCoinbaseTxBasicWorkQ apply implementation. CV-SUB-U128-01 and every
// other shared vector cross u64 only in the ACCUMULATOR (two txs of fee 2^63,
// each Hi=0), so narrowing the addend at either accumulation site stays
// invisible to all of them and to every other unit test. The coinbase claims
// only the subsidy, so the >u64 value is bound purely by the fee path.
// Mirrors Rust `connect_block_sum_fees_binds_an_individual_fee_above_u64`.
func TestConnectBlockInMemory_SumFeesBindsAnIndividualFeeAboveU64(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0x91)
	target := filledHash(0xff)
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	// sum_in = 2^63 + (2^63+1) = 2^64+1, sum_out = 1, so fee is exactly 2^64.
	const half = uint64(1) << 63
	spendTx := &Tx{
		Version: 1, TxKind: 0x00, TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prev, PrevVout: 0},
			{PrevTxid: prev, PrevVout: 1},
		},
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	spendTx.Witness = []WitnessItem{
		signP2PKInputWitness(t, spendTx, 0, half, [32]byte{}, kp),
		signP2PKInputWitness(t, spendTx, 1, half+1, [32]byte{}, kp),
	}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	utxo := func(v uint64) UtxoEntry {
		return UtxoEntry{Value: v, CovenantType: COV_TYPE_P2PK, CovenantData: covData}
	}
	// Each connect path mutates the state it is handed, so build a fresh one
	// per path.
	newState := func() *InMemoryChainState {
		return &InMemoryChainState{
			Utxos: map[Outpoint]UtxoEntry{
				{Txid: prev, Vout: 0}: utxo(half),
				{Txid: prev, Vout: 1}: utxo(half + 1),
			},
			AlreadyGenerated: new(big.Int),
		}
	}

	subsidy := BlockSubsidyBig(height, new(big.Int))
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy, spendBytes)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	want := Uint128{Hi: 1, Lo: 0} // exactly 2^64

	// Site 1: sequential accumulation.
	seq, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, newState(), [32]byte{})
	if err != nil {
		t.Fatalf("ConnectBlockBasicInMemoryAtHeight: %v", err)
	}
	if seq.SumFees.Cmp(want) != 0 {
		t.Fatalf("sequential sum_fees=%s, want %s", seq.SumFees.String(), want.String())
	}
	if seq.SumFees.Hi == 0 {
		t.Fatalf("sum_fees=%s must carry a non-zero high limb", seq.SumFees.String())
	}

	// Site 2: queued-parallel accumulation.
	par, err := ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, newState(), [32]byte{}, 4)
	if err != nil {
		t.Fatalf("ConnectBlockParallelSigVerify: %v", err)
	}
	if par.SumFees.Cmp(want) != 0 {
		t.Fatalf("queued-parallel sum_fees=%s, want %s", par.SumFees.String(), want.String())
	}
	if seq.SumFees.Cmp(par.SumFees) != 0 {
		t.Fatalf("sequential/parallel divergence: %s vs %s", seq.SumFees.String(), par.SumFees.String())
	}
}

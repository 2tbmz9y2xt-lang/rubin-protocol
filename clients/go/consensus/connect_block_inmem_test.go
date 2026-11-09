package consensus

import (
	"maps"
	"math/big"
	"reflect"
	"slices"
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

// logicalGrowthCensus is the valid funded nine-signature block census. Outputs
// are value 1; the first eight transactions create 1024 P2PK each and the ninth
// the remainder plus every HTLC.
type logicalGrowthCensus struct {
	p2pk, htlc           int
	spendCreated, badSig bool
}

var (
	logicalGrowthEqual = logicalGrowthCensus{p2pk: 8626, htlc: 38}
	logicalGrowthBelow = logicalGrowthCensus{p2pk: 8588, htlc: 59}
	logicalGrowthOver  = logicalGrowthCensus{p2pk: 8664, htlc: 17}
)

func logicalGrowthParents(cov []byte) map[Outpoint]UtxoEntry {
	parents := make(map[Outpoint]UtxoEntry, 9)
	for i := byte(0); i < 9; i++ {
		parents[Outpoint{Txid: hashWithPrefix(0xb0 + i)}] = UtxoEntry{Value: 2000, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreatedByCoinbase: true}
	}
	return parents
}

func logicalGrowthOutputs(cov []byte, p2pk, htlc int) []TxOutput {
	outs := make([]TxOutput, 0, p2pk+htlc)
	for range p2pk {
		outs = append(outs, TxOutput{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: cov})
	}
	data := encodeHTLCCovenantData(filledHash(0x41), LOCK_MODE_HEIGHT, 1, filledHash(0x42), filledHash(0x43))
	for range htlc {
		outs = append(outs, TxOutput{Value: 1, CovenantType: COV_TYPE_HTLC, CovenantData: data})
	}
	return outs
}

func logicalGrowthSignedTx(t *testing.T, kp *MLDSA87Keypair, chainID [32]byte, nonce uint64, outs []TxOutput, created *Outpoint) *Tx {
	t.Helper()
	tx := &Tx{Version: 1, TxNonce: nonce, Inputs: []TxInput{{PrevTxid: hashWithPrefix(0xb0 + byte(nonce-1))}}, Outputs: outs}
	values := []uint64{2000}
	if created != nil {
		tx.Inputs, values = append(tx.Inputs, TxInput{PrevTxid: created.Txid, PrevVout: created.Vout}), append(values, 1)
	}
	for i, value := range values {
		tx.Witness = append(tx.Witness[:i:i], signP2PKInputWitness(t, tx, uint32(i), value, chainID, kp))
	}
	return tx
}

func logicalGrowthMarshal(t *testing.T, txs []*Tx) [][]byte {
	t.Helper()
	raws := make([][]byte, len(txs))
	for i, tx := range txs {
		raw, err := MarshalTx(tx)
		if err != nil {
			t.Fatal(err)
		}
		raws[i] = raw
	}
	return raws
}

func logicalGrowthTxs(t *testing.T, kp *MLDSA87Keypair, chainID [32]byte, census logicalGrowthCensus) []*Tx {
	t.Helper()
	cov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	txs := make([]*Tx, 0, 9)
	for nonce := uint64(1); nonce <= 8; nonce++ {
		txs = append(txs, logicalGrowthSignedTx(t, kp, chainID, nonce, logicalGrowthOutputs(cov, 1024, 0), nil))
	}
	var created *Outpoint
	if census.spendCreated {
		created = &Outpoint{Txid: testTxID(t, logicalGrowthMarshal(t, txs[7:])[0])}
	}
	last := logicalGrowthSignedTx(t, kp, chainID, 9, logicalGrowthOutputs(cov, census.p2pk-8192, census.htlc), created)
	if census.badSig {
		last.Witness[0].Signature[0] ^= 1
	}
	return append(txs, last)
}

type logicalGrowthBlock struct {
	raw          []byte
	prev, target [32]byte
}

func logicalGrowthBlock116(t *testing.T, raws [][]byte, coinbaseValue uint64) logicalGrowthBlock {
	t.Helper()
	prev, target := hashWithPrefix(0xd2), filledHash(0xff)
	encoded := append([][]byte{coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 200, coinbaseValue, raws...)}, raws...)
	txids := make([][32]byte, len(encoded))
	for i, tx := range encoded {
		txids[i] = testTxID(t, tx)
	}
	root, err := MerkleRootTxids(txids)
	if err != nil {
		t.Fatal(err)
	}
	return logicalGrowthBlock{raw: buildBlockBytes(t, prev, root, target, 1, encoded), prev: prev, target: target}
}

type logicalGrowthDispatch struct {
	name string
	run  func(logicalGrowthBlock, *InMemoryChainState) (*ConnectBlockBasicSummary, error)
}

func logicalGrowthDispatches() []logicalGrowthDispatch {
	ts := slices.Repeat([]uint64{0}, 11)
	queued := func(workers int) func(logicalGrowthBlock, *InMemoryChainState) (*ConnectBlockBasicSummary, error) {
		return func(b logicalGrowthBlock, s *InMemoryChainState) (*ConnectBlockBasicSummary, error) {
			return ConnectBlockParallelSigVerify(b.raw, &b.prev, &b.target, 200, ts, s, [32]byte{}, workers)
		}
	}
	return []logicalGrowthDispatch{
		{"sequential", func(b logicalGrowthBlock, s *InMemoryChainState) (*ConnectBlockBasicSummary, error) {
			return ConnectBlockBasicInMemoryAtHeight(b.raw, &b.prev, &b.target, 200, ts, s, [32]byte{})
		}},
		{"queued1", queued(1)},
		{"queued4", queued(4)},
	}
}

// logicalGrowthCensusBytes sums CSM entry lengths with the written formula,
// independently of the production helper.
func logicalGrowthCensusBytes(rows map[Outpoint]UtxoEntry) uint64 {
	var total uint64
	for _, e := range rows {
		n := uint64(len(e.CovenantData))
		switch {
		case n < 253:
			total += 45 + 1 + n + 10
		case n < 1<<16:
			total += 45 + 3 + n + 10
		default:
			total += 45 + 5 + n + 10
		}
	}
	return total
}

func logicalGrowthState(cov []byte) *InMemoryChainState {
	return &InMemoryChainState{Utxos: logicalGrowthParents(cov), AlreadyGenerated: new(big.Int)}
}

func assertLogicalGrowthRefused(t *testing.T, name string, s *ConnectBlockBasicSummary, err error, state *InMemoryChainState, before map[Outpoint]UtxoEntry, code ErrorCode) {
	t.Helper()
	txErr, ok := any(err).(*TxError)
	if !ok || txErr.Code != code || s != nil {
		t.Fatalf("%s: summary=%v err=%T %v, want %s", name, s, err, err, code)
	}
	if !reflect.DeepEqual(state.Utxos, before) || state.AlreadyGenerated.Sign() != 0 {
		t.Fatalf("%s: refused connect mutated state", name)
	}
}

func TestConnectBlockLogicalStateGrowthBoundary(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	cov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	build := func(c logicalGrowthCensus, coinbase uint64) logicalGrowthBlock {
		return logicalGrowthBlock116(t, logicalGrowthMarshal(t, logicalGrowthTxs(t, kp, [32]byte{}, c)), coinbase)
	}
	equal, below, over := build(logicalGrowthEqual, 1), build(logicalGrowthBelow, 1), build(logicalGrowthOver, 1)
	if len(equal.raw) >= 1<<20 || len(over.raw) >= 1<<20 {
		t.Fatalf("fixture wire sizes %d/%d", len(equal.raw), len(over.raw))
	}
	var first map[Outpoint]UtxoEntry
	for _, d := range logicalGrowthDispatches() {
		for _, tc := range []struct {
			name  string
			block logicalGrowthBlock
			rows  int
			total uint64
		}{{"equal", equal, 8626 + 38 + 1, 773921}, {"below", below, 8588 + 59 + 1, 773920}} {
			state := logicalGrowthState(cov)
			if census := logicalGrowthCensusBytes(state.Utxos); census != 801 {
				t.Fatalf("parent census %d", census)
			}
			summary, err := d.run(tc.block, state)
			if err != nil || summary == nil || len(state.Utxos) != tc.rows || logicalGrowthCensusBytes(state.Utxos) != tc.total {
				t.Fatalf("%s/%s: %v rows=%d total=%d", d.name, tc.name, err, len(state.Utxos), logicalGrowthCensusBytes(state.Utxos))
			}
			if tc.name != "equal" {
				continue
			}
			if first == nil {
				first = maps.Clone(state.Utxos)
			} else if !reflect.DeepEqual(first, state.Utxos) {
				t.Fatalf("%s accepted state differs from sequential", d.name)
			}
		}
		state := logicalGrowthState(cov)
		before := logicalGrowthParents(cov)
		summary, err := d.run(over, state)
		assertLogicalGrowthRefused(t, d.name+"/over", summary, err, state, before, BLOCK_ERR_STATE_GROWTH_EXCEEDED)
		if err.Error() != testLogicalGrowthMsg {
			t.Fatalf("%s growth text: %v", d.name, err)
		}
		// The next corrected operation is legal and publishes only its own state.
		if summary, err = d.run(equal, state); err != nil || summary == nil || !reflect.DeepEqual(first, state.Utxos) {
			t.Fatalf("%s next call: %v", d.name, err)
		}
	}
}

func TestConnectBlockLogicalStatePrecedenceAndAccounting(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	cov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	build := func(c logicalGrowthCensus, coinbase uint64) logicalGrowthBlock {
		return logicalGrowthBlock116(t, logicalGrowthMarshal(t, logicalGrowthTxs(t, kp, [32]byte{}, c)), coinbase)
	}
	badSig := logicalGrowthOver
	badSig.badSig = true
	sigBlock := build(badSig, 1)
	subsidyBlock := build(logicalGrowthOver, BlockSubsidyBig(200, new(big.Int))+9319+1)
	created := logicalGrowthOver
	created.spendCreated = true
	createdBlock := build(created, 1)
	over := build(logicalGrowthOver, 1)
	for _, d := range logicalGrowthDispatches() {
		before := logicalGrowthParents(cov)
		state := logicalGrowthState(cov)
		summary, err := d.run(sigBlock, state)
		assertLogicalGrowthRefused(t, d.name+"/sig", summary, err, state, before, TX_ERR_SIG_INVALID)
		state = logicalGrowthState(cov)
		summary, err = d.run(subsidyBlock, state)
		assertLogicalGrowthRefused(t, d.name+"/subsidy", summary, err, state, before, BLOCK_ERR_SUBSIDY_EXCEEDED)

		// An output created and spent in the block contributes zero, so the
		// over census minus that one 89-byte row is accepted.
		state = logicalGrowthState(cov)
		if summary, err = d.run(createdBlock, state); err != nil || summary == nil || logicalGrowthCensusBytes(state.Utxos) != 773922-89 {
			t.Fatalf("%s created-and-spent: %v total=%d", d.name, err, logicalGrowthCensusBytes(state.Utxos))
		}

		// An untouched parent row counts on both sides and stays byte-exact.
		state = logicalGrowthState(cov)
		kept := Outpoint{Txid: hashWithPrefix(0xc9), Vout: 4}
		keptEntry := UtxoEntry{Value: 5, CovenantType: COV_TYPE_P2PK, CovenantData: cov, CreationHeight: 3}
		state.Utxos[kept] = keptEntry
		wantBefore := maps.Clone(state.Utxos)
		summary, err = d.run(over, state)
		assertLogicalGrowthRefused(t, d.name+"/untouched", summary, err, state, wantBefore, BLOCK_ERR_STATE_GROWTH_EXCEEDED)

		// A malformed untouched parent row is the store-integrity no-result,
		// not a growth refusal, and nothing is published.
		state = logicalGrowthState(cov)
		state.Utxos[kept] = UtxoEntry{Value: 5, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, 65537)}
		wantBefore = maps.Clone(state.Utxos)
		summary, err = d.run(over, state)
		failure, ok := any(err).(*logicalStateFailure)
		if !ok || failure.kind != logicalStateFailureStoreIntegrity || failure.Error() != "invalid present logical state row" || summary != nil || !reflect.DeepEqual(wantBefore, state.Utxos) {
			t.Fatalf("%s malformed parent row: %T %v", d.name, err, err)
		}
	}
}

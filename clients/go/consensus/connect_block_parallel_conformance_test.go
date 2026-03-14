package consensus

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConnectBlockParallelSigVerify_ConformanceParity loads all connect_block_basic
// conformance vectors with expect_ok=true and runs each through both the sequential
// and parallel paths, asserting identical results.
//
// This test exercises the full parallel pipeline including setup guards, tx loop,
// coinbase validation, and signature flush across real-world block data.
func TestConnectBlockParallelSigVerify_ConformanceParity(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "..", "conformance", "fixtures")
	if _, err := os.Stat(fixturesDir); os.IsNotExist(err) {
		t.Skip("conformance/fixtures not found (run from repo root)")
	}

	files, err := filepath.Glob(filepath.Join(fixturesDir, "CV-*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	var tested int
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		var doc struct {
			Gate    string            `json:"gate"`
			Vectors []json.RawMessage `json:"vectors"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		for _, rawVec := range doc.Vectors {
			var probe struct {
				ID       string `json:"id"`
				Op       string `json:"op"`
				ExpectOK bool   `json:"expect_ok"`
			}
			if err := json.Unmarshal(rawVec, &probe); err != nil {
				continue
			}
			if probe.Op != "connect_block_basic" || !probe.ExpectOK {
				continue
			}

			var v connectBlockTestVector
			if err := json.Unmarshal(rawVec, &v); err != nil {
				t.Fatalf("parse vector %s: %v", probe.ID, err)
			}

			t.Run(probe.ID, func(t *testing.T) {
				testParallelParityFromVector(t, v)
			})
			tested++
		}
	}

	if tested == 0 {
		t.Fatal("no connect_block_basic expect_ok vectors found")
	}
	t.Logf("tested %d conformance vectors for parallel/sequential parity", tested)
}

// connectBlockTestVector is the subset of ConnectBlockVector fields we need.
type connectBlockTestVector struct {
	ID               string   `json:"id"`
	BlockHex         string   `json:"block_hex"`
	ChainID          string   `json:"chain_id"`
	Height           uint64   `json:"height"`
	AlreadyGenerated uint64   `json:"already_generated"`
	Utxos            []utxoJ  `json:"utxos"`
	PrevTimestamps   []uint64 `json:"prev_timestamps"`
	ExpectedPrevHash string   `json:"expected_prev_hash"`
	ExpectedTarget   string   `json:"expected_target"`
}

type utxoJ struct {
	Txid              string `json:"txid"`
	CovenantData      string `json:"covenant_data"`
	Value             uint64 `json:"value"`
	CreationHeight    uint64 `json:"creation_height"`
	Vout              uint32 `json:"vout"`
	CovenantType      uint16 `json:"covenant_type"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

func testParallelParityFromVector(t *testing.T, v connectBlockTestVector) {
	t.Helper()

	blockBytes, err := hex.DecodeString(v.BlockHex)
	if err != nil {
		t.Fatalf("decode block_hex: %v", err)
	}

	var chainID [32]byte
	if v.ChainID != "" {
		chainID, err = decodeHex32Field("chain_id", v.ChainID)
		if err != nil {
			t.Fatalf("decode chain_id: %v", err)
		}
	}

	var prevHash *[32]byte
	if v.ExpectedPrevHash != "" {
		h, err := decodeHex32Field("expected_prev_hash", v.ExpectedPrevHash)
		if err != nil {
			t.Fatalf("decode expected_prev_hash: %v", err)
		}
		prevHash = &h
	}

	var target *[32]byte
	if v.ExpectedTarget != "" {
		tgt, err := decodeHex32Field("expected_target", v.ExpectedTarget)
		if err != nil {
			t.Fatalf("decode expected_target: %v", err)
		}
		target = &tgt
	}

	utxos := buildUtxoMapFromVectorJSON(t, v.Utxos)

	// Run sequential path.
	seqState := &InMemoryChainState{
		Utxos:            copyUtxoMap(utxos),
		AlreadyGenerated: new(big.Int).SetUint64(v.AlreadyGenerated),
	}
	seqResult, seqErr := ConnectBlockBasicInMemoryAtHeight(
		blockBytes, prevHash, target, v.Height, v.PrevTimestamps, seqState, chainID,
	)
	if seqErr != nil {
		t.Fatalf("sequential ConnectBlock failed: %v", seqErr)
	}

	// Run parallel path.
	parState := &InMemoryChainState{
		Utxos:            copyUtxoMap(utxos),
		AlreadyGenerated: new(big.Int).SetUint64(v.AlreadyGenerated),
	}
	parResult, parErr := ConnectBlockParallelSigVerify(
		blockBytes, prevHash, target, v.Height, v.PrevTimestamps, parState, chainID, 0,
	)
	if parErr != nil {
		t.Fatalf("parallel ConnectBlock failed: %v", parErr)
	}

	// Compare results.
	if seqResult.SumFees != parResult.SumFees {
		t.Errorf("SumFees mismatch: seq=%d par=%d", seqResult.SumFees, parResult.SumFees)
	}
	if seqResult.AlreadyGenerated != parResult.AlreadyGenerated {
		t.Errorf("AlreadyGenerated mismatch: seq=%d par=%d", seqResult.AlreadyGenerated, parResult.AlreadyGenerated)
	}
	if seqResult.AlreadyGeneratedN1 != parResult.AlreadyGeneratedN1 {
		t.Errorf("AlreadyGeneratedN1 mismatch: seq=%d par=%d", seqResult.AlreadyGeneratedN1, parResult.AlreadyGeneratedN1)
	}
	if seqResult.UtxoCount != parResult.UtxoCount {
		t.Errorf("UtxoCount mismatch: seq=%d par=%d", seqResult.UtxoCount, parResult.UtxoCount)
	}

	// Compare UTXO sets.
	if len(seqState.Utxos) != len(parState.Utxos) {
		t.Fatalf("UTXO set size mismatch: seq=%d par=%d", len(seqState.Utxos), len(parState.Utxos))
	}
	for op, seqEntry := range seqState.Utxos {
		parEntry, ok := parState.Utxos[op]
		if !ok {
			t.Errorf("UTXO %s:%d missing from parallel result", hex.EncodeToString(op.Txid[:]), op.Vout)
			continue
		}
		if seqEntry.Value != parEntry.Value {
			t.Errorf("UTXO %s:%d value mismatch: seq=%d par=%d", hex.EncodeToString(op.Txid[:]), op.Vout, seqEntry.Value, parEntry.Value)
		}
		if seqEntry.CovenantType != parEntry.CovenantType {
			t.Errorf("UTXO %s:%d covenant_type mismatch", hex.EncodeToString(op.Txid[:]), op.Vout)
		}
	}
}

func decodeHex32Field(name, value string) ([32]byte, error) {
	var out [32]byte
	value = strings.TrimSpace(value)
	raw, err := hex.DecodeString(value)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, &TxError{Code: BLOCK_ERR_PARSE, Msg: name + ": expected 32 bytes"}
	}
	copy(out[:], raw)
	return out, nil
}

func buildUtxoMapFromVectorJSON(t *testing.T, utxos []utxoJ) map[Outpoint]UtxoEntry {
	t.Helper()
	m := make(map[Outpoint]UtxoEntry, len(utxos))
	for _, u := range utxos {
		txid, err := decodeHex32Field("utxo.txid", u.Txid)
		if err != nil {
			t.Fatalf("decode utxo txid %q: %v", u.Txid, err)
		}
		covData, err := hex.DecodeString(u.CovenantData)
		if err != nil {
			t.Fatalf("decode utxo covenant_data: %v", err)
		}
		m[Outpoint{Txid: txid, Vout: u.Vout}] = UtxoEntry{
			Value:             u.Value,
			CovenantType:      u.CovenantType,
			CovenantData:      covData,
			CreationHeight:    u.CreationHeight,
			CreatedByCoinbase: u.CreatedByCoinbase,
		}
	}
	return m
}

func copyUtxoMap(src map[Outpoint]UtxoEntry) map[Outpoint]UtxoEntry {
	out := make(map[Outpoint]UtxoEntry, len(src))
	for k, v := range src {
		out[k] = UtxoEntry{
			Value:             v.Value,
			CovenantType:      v.CovenantType,
			CovenantData:      append([]byte(nil), v.CovenantData...),
			CreationHeight:    v.CreationHeight,
			CreatedByCoinbase: v.CreatedByCoinbase,
		}
	}
	return out
}

// TestConnectBlockParallelSigVerify_GuardPaths exercises early-return guard
// paths in ConnectBlockParallelSigVerifyWithCoreExtProfiles.
func TestConnectBlockParallelSigVerify_GuardPaths(t *testing.T) {
	t.Run("nil_state", func(t *testing.T) {
		_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
			[]byte{}, nil, nil, 0, nil, nil, [32]byte{}, nil, 0,
		)
		if err == nil {
			t.Fatal("expected error for nil state")
		}
	})

	t.Run("nil_AlreadyGenerated", func(t *testing.T) {
		state := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: nil,
		}
		// Should normalize nil to zero, then fail at block validation.
		_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
			[]byte{0x00}, nil, nil, 0, nil, state, [32]byte{}, nil, 0,
		)
		if err == nil {
			t.Fatal("expected error for invalid block bytes")
		}
	})

	t.Run("negative_AlreadyGenerated", func(t *testing.T) {
		state := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: big.NewInt(-1),
		}
		_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
			[]byte{0x00}, nil, nil, 0, nil, state, [32]byte{}, nil, 0,
		)
		if err == nil {
			t.Fatal("expected error for negative AlreadyGenerated")
		}
	})

	t.Run("nil_Utxos_normalized", func(t *testing.T) {
		state := &InMemoryChainState{
			Utxos:            nil, // should be normalized to empty map
			AlreadyGenerated: new(big.Int),
		}
		_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
			[]byte{0x00}, nil, nil, 0, nil, state, [32]byte{}, nil, 0,
		)
		// Will fail at block validation but nil Utxos normalization is covered.
		if err == nil {
			t.Fatal("expected error for invalid block bytes")
		}
		if state.Utxos == nil {
			t.Fatal("expected Utxos to be normalized to non-nil")
		}
	})

	t.Run("nil_Utxos_and_nil_AlreadyGenerated", func(t *testing.T) {
		state := &InMemoryChainState{
			Utxos:            nil,
			AlreadyGenerated: nil,
		}
		_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
			[]byte{0x00}, nil, nil, 0, nil, state, [32]byte{}, nil, 0,
		)
		if err == nil {
			t.Fatal("expected error for invalid block bytes")
		}
	})

	t.Run("wrapper_convenience_function", func(t *testing.T) {
		state := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: new(big.Int),
		}
		_, err := ConnectBlockParallelSigVerify(
			[]byte{0x00}, nil, nil, 0, nil, state, [32]byte{}, 0,
		)
		if err == nil {
			t.Fatal("expected error for invalid block bytes")
		}
	})
}

// buildTestBlock builds a structurally valid block containing one P2PK spend transaction.
// Returns blockBytes, prevHash, target, and the utxoSet that makes the spend valid.
// The non-coinbase tx spends 100 from a UTXO and outputs 90 (fee = 10).
func buildTestBlock(t *testing.T, coinbaseP2PKValue uint64) (blockBytes []byte, prev [32]byte, target [32]byte, utxos map[Outpoint]UtxoEntry) {
	t.Helper()
	height := uint64(1)
	prev = hashWithPrefix(0x99)
	target = filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	prevOut := Outpoint{Txid: prev, Vout: 0}
	spendTx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	spendTx.Witness = []WitnessItem{signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, coinbaseP2PKValue, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	blockBytes = buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	utxos = map[Outpoint]UtxoEntry{
		prevOut: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		},
	}
	return
}

// TestConnectBlockParallelSigVerify_TxValidationError_MissingUTXO covers lines 118-119:
// a valid block with a non-coinbase tx referencing a UTXO not in the state.
func TestConnectBlockParallelSigVerify_TxValidationError_MissingUTXO(t *testing.T) {
	height := uint64(1)
	block, prev, target, _ := buildTestBlock(t, 100)

	// Empty UTXO set → non-coinbase tx fails at input lookup.
	state := &InMemoryChainState{
		Utxos:            make(map[Outpoint]UtxoEntry),
		AlreadyGenerated: new(big.Int),
	}
	_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
		block, &prev, &target, height, []uint64{0}, state, [32]byte{}, nil, 4,
	)
	if err == nil {
		t.Fatal("expected error for missing UTXO")
	}
}

// TestConnectBlockParallelSigVerify_CoinbaseValueBound covers lines 136-137:
// a block where coinbase value exceeds subsidy + fees.
func TestConnectBlockParallelSigVerify_CoinbaseValueBound(t *testing.T) {
	height := uint64(1)

	// Set AlreadyGenerated = MINEABLE_CAP → subsidy = TAIL_EMISSION_PER_BLOCK.
	// Fee from the tx = 100 - 90 = 10. Bound = TAIL + 10.
	// Build coinbase with value = TAIL + 11 → exceeds bound.
	coinbaseVal := uint64(TAIL_EMISSION_PER_BLOCK) + 11
	block, prev, target, utxos := buildTestBlock(t, coinbaseVal)

	state := &InMemoryChainState{
		Utxos:            utxos,
		AlreadyGenerated: new(big.Int).SetUint64(MINEABLE_CAP),
	}
	_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
		block, &prev, &target, height, []uint64{0}, state, [32]byte{}, nil, 4,
	)
	if err == nil {
		t.Fatal("expected coinbase value bound error")
	}
}

// TestConnectBlockParallelSigVerify_AlreadyGeneratedOverflow covers lines 167-168:
// already_generated > MaxUint64 causes bigIntToUint64 to fail.
func TestConnectBlockParallelSigVerify_AlreadyGeneratedOverflow(t *testing.T) {
	height := uint64(1)

	// With huge AlreadyGenerated, subsidy = TAIL_EMISSION_PER_BLOCK.
	// Fee = 10. Coinbase value must be <= TAIL + 10 to pass value bound check.
	coinbaseVal := uint64(TAIL_EMISSION_PER_BLOCK) + 10
	block, prev, target, utxos := buildTestBlock(t, coinbaseVal)

	// AlreadyGenerated = 2^64 → overflows uint64 conversion at line 167.
	hugeAG := new(big.Int).SetBit(new(big.Int), 64, 1)

	state := &InMemoryChainState{
		Utxos:            utxos,
		AlreadyGenerated: hugeAG,
	}
	_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
		block, &prev, &target, height, []uint64{0}, state, [32]byte{}, nil, 4,
	)
	if err == nil {
		t.Fatal("expected already_generated overflow error")
	}
}

// TestConnectBlockParallelSigVerify_AlreadyGeneratedN1Overflow covers lines 171-172:
// already_generated fits uint64 but already_generated + subsidy overflows.
func TestConnectBlockParallelSigVerify_AlreadyGeneratedN1Overflow(t *testing.T) {
	height := uint64(1)

	// AlreadyGenerated = MaxUint64 - 1000 → fits uint64, passes line 167.
	// Subsidy = TAIL_EMISSION_PER_BLOCK = 19_025_875 (since AG >= MINEABLE_CAP).
	// N1 = (MaxUint64-1000) + 19_025_875 overflows uint64 → line 171-172.
	// Coinbase value must be <= TAIL + 10 to pass value bound check.
	coinbaseVal := uint64(TAIL_EMISSION_PER_BLOCK) + 10
	block, prev, target, utxos := buildTestBlock(t, coinbaseVal)

	ag := new(big.Int).SetUint64(^uint64(0) - 1000)

	state := &InMemoryChainState{
		Utxos:            utxos,
		AlreadyGenerated: ag,
	}
	_, err := ConnectBlockParallelSigVerifyWithCoreExtProfiles(
		block, &prev, &target, height, []uint64{0}, state, [32]byte{}, nil, 4,
	)
	if err == nil {
		t.Fatal("expected already_generated_n1 overflow error")
	}
}

// TestConnectBlockParallelSigVerify_CoinbaseVaultForbidden covers lines 139-140:
// a block with a valid VAULT output in the coinbase.
func TestConnectBlockParallelSigVerify_CoinbaseVaultForbidden(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0xBB)
	target := filledHash(0xff)

	// Build a coinbase-only block where the coinbase contains a VAULT output.
	// VAULT in coinbase passes basic validation (ValidateTxCovenantsGenesis checks
	// the vault structure, not its placement in coinbase) but fails at
	// validateCoinbaseApplyOutputs.
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())

	// Build a minimal valid vault covenant: owner_lock_id[32] || threshold=1 || key_count=1 || key[32] || whitelist_count=0
	vaultCov := make([]byte, 0, 68)
	vaultCov = append(vaultCov, keyID[:]...) // owner_lock_id
	vaultCov = append(vaultCov, 1)           // threshold
	vaultCov = append(vaultCov, 1)           // key_count
	vaultCov = append(vaultCov, keyID[:]...) // key
	vaultCov = AppendU16le(vaultCov, 0)      // whitelist_count

	// Coinbase with VAULT output + anchor for witness commitment.
	wtxids := [][32]byte{{}} // single coinbase → wtxid[0] = zero
	wroot, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	coinbase := coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: 100, covenantType: COV_TYPE_VAULT, covenantData: vaultCov},
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase})

	state := &InMemoryChainState{
		Utxos:            make(map[Outpoint]UtxoEntry),
		AlreadyGenerated: new(big.Int),
	}
	_, err = ConnectBlockParallelSigVerifyWithCoreExtProfiles(
		block, &prev, &target, height, []uint64{0}, state, [32]byte{}, nil, 4,
	)
	if err == nil {
		t.Fatal("expected coinbase vault forbidden error")
	}
}

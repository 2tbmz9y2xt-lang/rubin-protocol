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
}

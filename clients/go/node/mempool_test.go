package node

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestMempoolAdd(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
}

func TestMempoolRelayMetadata(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 3, 5, fromKey, fromAddress, toAddress)
	meta, err := mp.RelayMetadata(txBytes)
	if err != nil {
		t.Fatalf("RelayMetadata: %v", err)
	}
	if meta.Fee != 3 {
		t.Fatalf("fee=%d, want 3", meta.Fee)
	}
	if meta.Size != len(txBytes) {
		t.Fatalf("size=%d, want %d", meta.Size, len(txBytes))
	}
}

func TestMempoolRelayMetadataNil(t *testing.T) {
	var mp *Mempool
	if _, err := mp.RelayMetadata([]byte{0x01}); err == nil {
		t.Fatal("nil mempool should reject RelayMetadata")
	}
}

func TestMempoolPolicyRejectsNonCoinbaseAnchorOutputs(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectNonCoinbaseAnchorOutputs: true,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedAnchorOutputTx(t, st.Utxos, outpoints[0], 0, 1, 1, fromKey, toAddress)
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
		t.Fatalf("expected non-coinbase anchor policy rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
		t.Fatalf("expected relay metadata anchor policy rejection, got %v", err)
	}
}

func TestMempoolPolicyRejectsLowFeeDaCommit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 99, 1, 1, fromKey, toAddress, []byte("0123456789"))
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "DA fee below policy minimum") {
		t.Fatalf("expected DA surcharge rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "DA fee below policy minimum") {
		t.Fatalf("expected relay metadata DA surcharge rejection, got %v", err)
	}
}

func TestMempoolPolicyAllowsSufficientFeeDaCommit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 80, 10, 1, fromKey, toAddress, []byte("0123456789"))
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("expected DA tx admission, got %v", err)
	}
}

func TestMempoolPolicyRejectsNilCheckedTransaction(t *testing.T) {
	mp := &Mempool{}
	if err := mp.applyPolicyLocked(nil); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
		t.Fatalf("expected nil checked transaction rejection, got %v", err)
	}
	if err := mp.applyPolicyLocked(&consensus.CheckedTransaction{}); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
		t.Fatalf("expected nil checked tx rejection, got %v", err)
	}
}

func TestMempoolPolicyPropagatesDaFeeComputationErrors(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 80, 10, 1, fromKey, toAddress, []byte("0123456789"))
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx(da): %v", err)
	}

	mp := &Mempool{
		chainState: &ChainState{},
		policy: MempoolConfig{
			PolicyDaSurchargePerByte: 1,
		},
	}
	if err := mp.applyPolicyLocked(&consensus.CheckedTransaction{Tx: tx}); err == nil || !strings.Contains(err.Error(), "nil utxo set") {
		t.Fatalf("expected DA fee computation error, got %v", err)
	}
}

func TestMempoolDoubleSpend(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 89, 2, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if err := mp.AddTx(tx2); err == nil {
		t.Fatalf("expected double-spend rejection")
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
}

func TestMempoolEviction(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	block := buildSingleTxBlock(t, [32]byte{}, consensus.POW_LIMIT, 1, txBytes)
	if err := mp.EvictConfirmed(block); err != nil {
		t.Fatalf("EvictConfirmed: %v", err)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func TestMempoolSelectByFee(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 100, 100})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 90, 3, 2, fromKey, fromAddress, toAddress)
	txMid := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 90, 2, 3, fromKey, fromAddress, toAddress)
	for _, txBytes := range [][]byte{txLow, txHigh, txMid} {
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("AddTx: %v", err)
		}
	}

	selected := mp.SelectTransactions(2, 1<<20)
	if len(selected) != 2 {
		t.Fatalf("selected=%d, want 2", len(selected))
	}
	if got, want := txIDHex(t, selected[0]), txIDHex(t, txHigh); got != want {
		t.Fatalf("selected[0]=%s, want %s", got, want)
	}
	if got, want := txIDHex(t, selected[1]), txIDHex(t, txMid); got != want {
		t.Fatalf("selected[1]=%s, want %s", got, want)
	}
}

func TestMinerMineOneSelectsFromMempool(t *testing.T) {
	dir := t.TempDir()
	store := mustOpenBlockStore(t, BlockStorePath(dir))

	var tipHash [32]byte
	for height := uint64(0); height <= 100; height++ {
		hash, _ := mustPutBlock(t, store, height, byte(height), height+1, []byte{byte(height)})
		if height == 100 {
			tipHash = hash
		}
	}

	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
	st.HasTip = true
	st.Height = 100
	st.TipHash = tipHash

	syncEngine, err := NewSyncEngine(st, store, DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	mp, err := NewMempool(st, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	syncEngine.SetMempool(mp)

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 90, 1, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 124 }
	miner, err := NewMiner(st, store, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}
	mined, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("MineOne: %v", err)
	}
	if mined.TxCount != 2 {
		t.Fatalf("tx_count=%d, want 2", mined.TxCount)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func mustNodeMLDSA87Keypair(t *testing.T) *consensus.MLDSA87Keypair {
	t.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			t.Skipf("ML-DSA backend unavailable: %v", err)
		}
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func testSpendableChainState(fromAddress []byte, values []uint64) (*ChainState, []consensus.Outpoint) {
	st := NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x11
	outpoints := make([]consensus.Outpoint, 0, len(values))
	for i, value := range values {
		var txid [32]byte
		txid[0] = byte(i + 1)
		txid[31] = byte(i + 9)
		op := consensus.Outpoint{Txid: txid, Vout: uint32(i)}
		st.Utxos[op] = consensus.UtxoEntry{
			Value:             value,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), fromAddress...),
			CreationHeight:    1,
			CreatedByCoinbase: true,
		}
		outpoints = append(outpoints, op)
	}
	return st, outpoints
}

func mustBuildSignedTransferTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	inputs []consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	toAddress []byte,
) []byte {
	t.Helper()
	txInputs := make([]consensus.TxInput, 0, len(inputs))
	var totalIn uint64
	for _, op := range inputs {
		entry, ok := utxos[op]
		if !ok {
			t.Fatalf("missing utxo for %x:%d", op.Txid, op.Vout)
		}
		totalIn += entry.Value
		txInputs = append(txInputs, consensus.TxInput{
			PrevTxid: op.Txid,
			PrevVout: op.Vout,
			Sequence: 0,
		})
	}
	change := totalIn - amount - fee
	outputs := []consensus.TxOutput{{
		Value:        amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), toAddress...),
	}}
	if change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), changeAddress...),
		})
	}

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  nonce,
		Inputs:   txInputs,
		Outputs:  outputs,
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return txBytes
}

func mustBuildSignedAnchorOutputTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	anchorValue uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
) []byte {
	t.Helper()
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	var anchorData [32]byte
	anchorData[0] = 0x42
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: anchorValue, CovenantType: consensus.COV_TYPE_ANCHOR, CovenantData: anchorData[:]},
			{Value: entry.Value - anchorValue - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), changeAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(anchor): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(anchor): %v", err)
	}
	return txBytes
}

func mustBuildSignedDaCommitTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	toAddress []byte,
	manifest []byte,
) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        amount,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), toAddress...),
		}},
		Locktime:  0,
		DaPayload: append([]byte(nil), manifest...),
		DaCommitCore: &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		},
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(da): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(da): %v", err)
	}
	return txBytes
}

func txIDHex(t *testing.T, txBytes []byte) string {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return fmt.Sprintf("%x", txid[:])
}

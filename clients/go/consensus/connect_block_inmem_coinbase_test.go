package consensus

import (
	"math/big"
	"testing"
)

func coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t *testing.T, height uint64, value uint64, vaultData []byte, nonCoinbaseTxs ...[]byte) []byte {
	t.Helper()

	wtxids := make([][32]byte, 1, 1+len(nonCoinbaseTxs))
	for _, txb := range nonCoinbaseTxs {
		_, _, wtxid, _, err := ParseTx(txb)
		if err != nil {
			t.Fatalf("ParseTx(non-coinbase): %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}

	wroot, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: COV_TYPE_VAULT, covenantData: vaultData},
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
}

func TestConnectBlockBasicInMemoryAtHeight_RejectsCoinbaseVaultOutput(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0xb1)
	target := filledHash(0xff)

	coinbase := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 1, validVaultCovenantDataForP2PKOutput())
	cbid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 51, [][]byte{coinbase})

	state := &InMemoryChainState{Utxos: map[Outpoint]UtxoEntry{}, AlreadyGenerated: new(big.Int)}
	_, err = ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, state, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_COINBASE_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_COINBASE_INVALID)
	}
	if len(state.Utxos) != 0 {
		t.Fatalf("state mutated on coinbase vault reject: utxos=%d", len(state.Utxos))
	}
	if state.AlreadyGenerated.Sign() != 0 {
		t.Fatalf("already_generated mutated on coinbase vault reject")
	}
}

func TestConnectBlockBasicInMemoryAtHeight_CoinbaseVaultRejectDoesNotMutateAppliedSpends(t *testing.T) {
	height := uint64(1)
	prev := hashWithPrefix(0xb2)
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

	coinbase := coinbaseWithWitnessCommitmentAndVaultOutputAtHeight(t, height, 1, validVaultCovenantDataForP2PKOutput(), spendBytes)
	cbid := testTxID(t, coinbase)
	spendTxid := testTxID(t, spendBytes)
	root, err := MerkleRootTxids([][32]byte{cbid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 52, [][]byte{coinbase, spendBytes})

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

	_, err = ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, state, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_COINBASE_INVALID {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_COINBASE_INVALID)
	}
	if len(state.Utxos) != 1 {
		t.Fatalf("state.utxos len=%d, want 1", len(state.Utxos))
	}
	entry, ok := state.Utxos[prevOut]
	if !ok {
		t.Fatalf("original utxo removed on rejected block")
	}
	if entry.Value != 100 || entry.CovenantType != COV_TYPE_P2PK || entry.CreatedByCoinbase {
		t.Fatalf("original utxo mutated: %#v", entry)
	}
	if state.AlreadyGenerated.Sign() != 0 {
		t.Fatalf("already_generated mutated on rejected block")
	}
}

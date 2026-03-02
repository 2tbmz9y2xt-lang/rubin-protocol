package node

import "testing"

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"

func TestRejectDaAnchorTxPolicy_DaSurchargeRejectsLowFee(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x11
	op := consensus.Outpoint{Txid: prev, Vout: 0}

	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		op: {Value: 100},
	}

	tx := &consensus.Tx{
		Version:   1,
		TxKind:    0x01,
		TxNonce:   1,
		Inputs:    []consensus.TxInput{{PrevTxid: prev, PrevVout: 0}},
		Outputs:   []consensus.TxOutput{{Value: 100, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: make([]byte, consensus.MAX_P2PK_COVENANT_DATA)}},
		DaPayload: []byte("0123456789"), // 10 bytes
		DaCommitCore: &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		},
	}
	tx.Outputs[0].CovenantData[0] = consensus.SUITE_ID_ML_DSA_87

	reject, daBytes, _, err := RejectDaAnchorTxPolicy(tx, utxos, 1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if daBytes != 10 {
		t.Fatalf("daBytes=%d, want 10", daBytes)
	}
	if !reject {
		t.Fatalf("expected reject (fee=0 < min_fee=10)")
	}
}

func TestRejectDaAnchorTxPolicy_DaSurchargeAllowsSufficientFee(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x22
	op := consensus.Outpoint{Txid: prev, Vout: 0}

	utxos := map[consensus.Outpoint]consensus.UtxoEntry{
		op: {Value: 100},
	}

	tx := &consensus.Tx{
		Version:   1,
		TxKind:    0x01,
		TxNonce:   1,
		Inputs:    []consensus.TxInput{{PrevTxid: prev, PrevVout: 0}},
		Outputs:   []consensus.TxOutput{{Value: 90, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: make([]byte, consensus.MAX_P2PK_COVENANT_DATA)}},
		DaPayload: []byte("0123456789"), // 10 bytes
		DaCommitCore: &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		},
	}
	tx.Outputs[0].CovenantData[0] = consensus.SUITE_ID_ML_DSA_87

	reject, daBytes, _, err := RejectDaAnchorTxPolicy(tx, utxos, 1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if daBytes != 10 {
		t.Fatalf("daBytes=%d, want 10", daBytes)
	}
	if reject {
		t.Fatalf("expected allow (fee=10 >= min_fee=10)")
	}
}

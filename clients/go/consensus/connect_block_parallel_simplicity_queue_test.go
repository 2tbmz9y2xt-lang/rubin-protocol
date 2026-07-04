package consensus

import "testing"

func TestApplyNonCoinbaseTxBasicWorkQ_CoreSimplicityPreservesEarlierPrevalidationPriority(t *testing.T) {
	makeTx := func(firstPrev, simpPrev [32]byte, witness []WitnessItem) *Tx {
		return &Tx{
			Version: TX_WIRE_VERSION,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: firstPrev, PrevVout: 0},
				{PrevTxid: simpPrev, PrevVout: 0},
			},
			Outputs: []TxOutput{{Value: 190, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
			Witness: witness,
		}
	}
	makeOutpoint := func(prev [32]byte) Outpoint {
		return Outpoint{Txid: prev, Vout: 0}
	}

	p2pkPrev := hashWithPrefix(0xD3)
	p2pkSimpPrev := hashWithPrefix(0xD4)
	htlcPrev := hashWithPrefix(0xD5)
	htlcSimpPrev := hashWithPrefix(0xD6)
	for _, tc := range []struct {
		name    string
		tx      *Tx
		utxos   map[Outpoint]UtxoEntry
		code    ErrorCode
		message string
	}{
		{
			name: "p2pk_missing_witness",
			tx:   makeTx(p2pkPrev, p2pkSimpPrev, nil),
			utxos: map[Outpoint]UtxoEntry{
				makeOutpoint(p2pkPrev):     {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
				makeOutpoint(p2pkSimpPrev): coreSimplicityAcceptEntry(100),
			},
			code:    TX_ERR_PARSE,
			message: "witness underflow",
		},
		{
			name: "htlc_malformed_data",
			tx:   makeTx(htlcPrev, htlcSimpPrev, dummyWitnesses(2)),
			utxos: map[Outpoint]UtxoEntry{
				makeOutpoint(htlcPrev):     {Value: 100, CovenantType: COV_TYPE_HTLC, CovenantData: []byte{0x01}},
				makeOutpoint(htlcSimpPrev): coreSimplicityAcceptEntry(100),
			},
			code:    TX_ERR_COVENANT_TYPE_INVALID,
			message: "CORE_HTLC covenant_data length mismatch",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := NewSigCheckQueue(1)
			work, fee, err := applyNonCoinbaseTxBasicWorkQ(tc.tx, hashWithPrefix(0xD7), tc.utxos, 1, 0, [32]byte{}, q, nil, nil)
			if work != nil || fee != 0 || q.Len() != 0 {
				t.Fatalf("expected no queued mutation/sigs on reject, got work=%v fee=%d sigs=%d", work, fee, q.Len())
			}
			assertTxErrCodeMsg(t, err, tc.code, tc.message)
		})
	}
}

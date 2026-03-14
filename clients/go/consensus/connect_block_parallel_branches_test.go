package consensus

import (
	"testing"
)

// These tests exercise the covenant-type branches in applyNonCoinbaseTxBasicWorkQ
// that are not reached by the conformance parity test (which only has P2PK blocks).

func TestApplyNonCoinbaseTxBasicWorkQ_MultisigBranch(t *testing.T) {
	kp1 := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t)
	keyID1 := sha3_256(kp1.PubkeyBytes())
	keyID2 := sha3_256(kp2.PubkeyBytes())

	// Keys must be strictly sorted for multisig covenant validation.
	keys := [][32]byte{keyID1, keyID2}
	if keyID1[0] > keyID2[0] || (keyID1[0] == keyID2[0] && string(keyID1[:]) > string(keyID2[:])) {
		keys[0], keys[1] = keyID2, keyID1
		kp1, kp2 = kp2, kp1
	}
	covData := encodeMultisigCovenantData(1, keys)
	prevTxid := hashWithPrefix(0xAA)

	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        1000,
			CovenantType: COV_TYPE_MULTISIG,
			CovenantData: covData,
		},
	}

	// Build P2PK output for the spend.
	outCovData := p2pkCovenantDataForPubkey(kp1.PubkeyBytes())
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 900, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
	}

	// Sign with kp1 only (threshold=1), kp2 as sentinel.
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 1000, [32]byte{}, kp1),
		{SuiteID: SUITE_ID_SENTINEL},
	}

	q := NewSigCheckQueue(1)
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xBB), utxoSet, 1, 0, [32]byte{}, nil, q)
	if err != nil {
		t.Fatalf("multisig branch: %v", err)
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if fee != 100 {
		t.Errorf("expected fee=100, got %d", fee)
	}
	if len(nextUtxos) != 1 {
		t.Errorf("expected 1 UTXO, got %d", len(nextUtxos))
	}
}

func TestApplyNonCoinbaseTxBasicWorkQ_HTLCClaimBranch(t *testing.T) {
	claimKP := mustMLDSA87Keypair(t)
	refundKP := mustMLDSA87Keypair(t)
	claimKeyID := sha3_256(claimKP.PubkeyBytes())
	refundKeyID := sha3_256(refundKP.PubkeyBytes())

	preimage := []byte("htlc-branch-preimage")
	entry := makeHTLCEntry(sha3_256(preimage), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)
	prevTxid := hashWithPrefix(0xCC)

	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: entry,
	}

	outCovData := p2pkCovenantDataForPubkey(claimKP.PubkeyBytes())
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
	}

	// HTLC needs 2 witness items: path selector + signature.
	pathItem := WitnessItem{
		SuiteID:   SUITE_ID_SENTINEL,
		Pubkey:    claimKeyID[:],
		Signature: encodeHTLCClaimPayload(preimage),
	}
	sigItem := signP2PKInputWitness(t, tx, 0, entry.Value, [32]byte{}, claimKP)

	tx.Witness = []WitnessItem{pathItem, sigItem}

	q := NewSigCheckQueue(1)
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xDD), utxoSet, 1, 0, [32]byte{}, nil, q)
	if err != nil {
		t.Fatalf("HTLC claim branch: %v", err)
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if fee != entry.Value-90 {
		t.Errorf("expected fee=%d, got %d", entry.Value-90, fee)
	}
	_ = nextUtxos
}

func TestApplyNonCoinbaseTxBasicWorkQ_StealthBranch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	keyID := sha3_256(kp.PubkeyBytes())

	covData := makeStealthCovenantData(keyID)
	prevTxid := hashWithPrefix(0xEE)

	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        500,
			CovenantType: COV_TYPE_CORE_STEALTH,
			CovenantData: covData,
		},
	}

	outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 400, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
	}

	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 500, [32]byte{}, kp)}

	q := NewSigCheckQueue(1)
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xFF), utxoSet, 1, 0, [32]byte{}, nil, q)
	if err != nil {
		t.Fatalf("stealth branch: %v", err)
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if fee != 100 {
		t.Errorf("expected fee=100, got %d", fee)
	}
	if len(nextUtxos) != 1 {
		t.Errorf("expected 1 UTXO, got %d", len(nextUtxos))
	}
}

func TestApplyNonCoinbaseTxBasicWorkQ_ErrorPaths(t *testing.T) {
	t.Run("nil_tx", func(t *testing.T) {
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(nil, [32]byte{}, nil, 0, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected error for nil tx")
		}
	})

	t.Run("no_inputs", func(t *testing.T) {
		tx := &Tx{Version: 1, TxNonce: 1}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, nil, 0, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected error for no inputs")
		}
	})

	t.Run("zero_nonce", func(t *testing.T) {
		tx := &Tx{
			Version: 1,
			TxNonce: 0,
			Inputs:  []TxInput{{PrevTxid: hashWithPrefix(1), PrevVout: 0}},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, nil, 0, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected error for zero nonce")
		}
		if !isTxErrCode(err, TX_ERR_TX_NONCE_INVALID) {
			t.Fatalf("expected TX_ERR_TX_NONCE_INVALID, got: %v", err)
		}
	})

	t.Run("missing_utxo", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: hashWithPrefix(0x42), PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

		q := NewSigCheckQueue(1)
		utxos := make(map[Outpoint]UtxoEntry) // empty
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected missing UTXO error")
		}
		if !isTxErrCode(err, TX_ERR_MISSING_UTXO) {
			t.Fatalf("expected TX_ERR_MISSING_UTXO, got: %v", err)
		}
	})

	t.Run("duplicate_input", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		prevTxid := hashWithPrefix(0x42)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0},
				{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}, // duplicate
			},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{
			signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp),
			signP2PKInputWitness(t, tx, 1, 100, [32]byte{}, kp),
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected duplicate input error")
		}
	})

	t.Run("coinbase_immature", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		prevTxid := hashWithPrefix(0x42)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {
				Value:             100,
				CovenantType:      COV_TYPE_P2PK,
				CovenantData:      covData,
				CreationHeight:    0,
				CreatedByCoinbase: true, // coinbase output, not yet mature
			},
		}
		q := NewSigCheckQueue(1)
		// height=50, but coinbase at height=0 needs COINBASE_MATURITY blocks
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 50, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected coinbase immature error")
		}
		if !isTxErrCode(err, TX_ERR_COINBASE_IMMATURE) {
			t.Fatalf("expected TX_ERR_COINBASE_IMMATURE, got: %v", err)
		}
	})

	t.Run("anchor_unspendable", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		prevTxid := hashWithPrefix(0x42)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		// No witness needed — error fires before witness check.
		tx.Witness = nil

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {
				Value:        100,
				CovenantType: COV_TYPE_ANCHOR,
			},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected unspendable anchor error")
		}
		if !isTxErrCode(err, TX_ERR_MISSING_UTXO) {
			t.Fatalf("expected TX_ERR_MISSING_UTXO, got: %v", err)
		}
	})

	t.Run("sequence_invalid", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		prevTxid := hashWithPrefix(0x42)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0x80000000}}, // exceeds 0x7fffffff
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q)
		if err == nil {
			t.Fatal("expected sequence invalid error")
		}
		if !isTxErrCode(err, TX_ERR_SEQUENCE_INVALID) {
			t.Fatalf("expected TX_ERR_SEQUENCE_INVALID, got: %v", err)
		}
	})
}

package consensus

import (
	"bytes"
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
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xBB), utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
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
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xDD), utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
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
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xFF), utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
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
		_, _, err := applyNonCoinbaseTxBasicWorkQ(nil, [32]byte{}, nil, 0, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil tx")
		}
	})

	t.Run("no_inputs", func(t *testing.T) {
		tx := &Tx{Version: 1, TxNonce: 1}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, nil, 0, 0, [32]byte{}, nil, q, nil, nil)
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
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, nil, 0, 0, [32]byte{}, nil, q, nil, nil)
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
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected missing UTXO error")
		}
		if !isTxErrCode(err, TX_ERR_MISSING_UTXO) {
			t.Fatalf("expected TX_ERR_MISSING_UTXO, got: %v", err)
		}
	})

	t.Run("core_ext_0x0102_unassigned_rejected", func(t *testing.T) {
		// 0x0102 (CORE_EXT) is unassigned per CANONICAL §14 — the parallel work-queue apply
		// path must reject it as TX_ERR_COVENANT_TYPE_INVALID (RUB-585), even with well-formed
		// covenant_data (ext_id=7 || compactSize(0) = 070000) that the retired parser accepted.
		prevTxid := hashWithPrefix(0x67)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
			Witness: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87}},
		}
		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: []byte{0x07, 0x00, 0x00}},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected CORE_EXT 0x0102 to be rejected")
		}
		if !isTxErrCode(err, TX_ERR_COVENANT_TYPE_INVALID) {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got: %v", err)
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
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
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
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 50, 0, [32]byte{}, nil, q, nil, nil)
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
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
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
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected sequence invalid error")
		}
		if !isTxErrCode(err, TX_ERR_SEQUENCE_INVALID) {
			t.Fatalf("expected TX_ERR_SEQUENCE_INVALID, got: %v", err)
		}
	})

	t.Run("witness_count_mismatch", func(t *testing.T) {
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
		tx.Witness = []WitnessItem{
			signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp),
			{SuiteID: SUITE_ID_SENTINEL}, // extra witness item
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected witness count mismatch error")
		}
	})

	t.Run("value_conservation_violation", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		prevTxid := hashWithPrefix(0x42)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 200, CovenantType: COV_TYPE_P2PK, CovenantData: covData}}, // more than input
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected value conservation error")
		}
		if !isTxErrCode(err, TX_ERR_VALUE_CONSERVATION) {
			t.Fatalf("expected TX_ERR_VALUE_CONSERVATION, got: %v", err)
		}
	})

	t.Run("coinbase_prevout_encoding", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: [32]byte{}, PrevVout: 0xffffffff, Sequence: 0}},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

		utxos := make(map[Outpoint]UtxoEntry)
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected coinbase prevout encoding error")
		}
	})

	t.Run("da_commit_unspendable", func(t *testing.T) {
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
		tx.Witness = nil

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {
				Value:        100,
				CovenantType: COV_TYPE_DA_COMMIT,
				CovenantData: make([]byte, 32),
			},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected DA_COMMIT unspendable error")
		}
		if !isTxErrCode(err, TX_ERR_MISSING_UTXO) {
			t.Fatalf("expected TX_ERR_MISSING_UTXO, got: %v", err)
		}
	})

	t.Run("script_sig_not_empty", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		prevTxid := hashWithPrefix(0x42)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0, ScriptSig: []byte{0x01}}},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected script_sig error")
		}
	})

	t.Run("witness_underflow", func(t *testing.T) {
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
		tx.Witness = nil // no witness at all

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected witness underflow error")
		}
	})

	t.Run("multiple_vault_inputs", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		ownerCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

		destCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

		var vaultKeyID [32]byte
		vaultKeyID[0] = 0x11
		vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

		prevVault1 := hashWithPrefix(0x51)
		prevVault2 := hashWithPrefix(0x52)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: prevVault1, PrevVout: 0, Sequence: 0},
				{PrevTxid: prevVault2, PrevVout: 0, Sequence: 0},
			},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData}},
		}
		tx.Witness = []WitnessItem{
			{SuiteID: SUITE_ID_SENTINEL},
			{SuiteID: SUITE_ID_SENTINEL},
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevVault1, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
			{Txid: prevVault2, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected multiple vault inputs error")
		}
		if !isTxErrCode(err, TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN) {
			t.Fatalf("expected TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN, got: %v", err)
		}
	})
}

// TestApplyNonCoinbaseTxBasicWorkQ_VaultSpendOK exercises the complete CORE_VAULT
// spend path: vault input + owner-authorized fee input → whitelisted P2PK output.
func TestApplyNonCoinbaseTxBasicWorkQ_VaultSpendOK(t *testing.T) {
	ownerKP := mustMLDSA87Keypair(t)
	vaultKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destKP := mustMLDSA87Keypair(t)
	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	prevVault := hashWithPrefix(0xD1)
	prevOwner := hashWithPrefix(0xD2)
	txid := hashWithPrefix(0xD3)

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0, Sequence: 0},
			{PrevTxid: prevOwner, PrevVout: 0, Sequence: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}

	// Vault input: 1 witness slot (key_count=1).
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, [32]byte{}, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
		{Txid: prevOwner, Vout: 0}: {Value: 10, CovenantType: COV_TYPE_P2PK, CovenantData: ownerCovData},
	}

	q := NewSigCheckQueue(1)
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, 200, 0, [32]byte{}, nil, q, nil, nil)
	if err != nil {
		t.Fatalf("vault spend: %v", err)
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Fee = (100 + 10) - 100 = 10
	if fee != 10 {
		t.Errorf("expected fee=10, got %d", fee)
	}
	if len(nextUtxos) != 1 {
		t.Errorf("expected 1 UTXO, got %d", len(nextUtxos))
	}
}

// TestApplyNonCoinbaseTxBasicWorkQ_VaultCreationOK exercises the CORE_VAULT creation
// path: P2PK input → vault output with matching owner_lock_id.
func TestApplyNonCoinbaseTxBasicWorkQ_VaultCreationOK(t *testing.T) {
	ownerKP := mustMLDSA87Keypair(t)
	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destKP := mustMLDSA87Keypair(t)
	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	var vaultKeyID [32]byte
	vaultKeyID[0] = 0x11
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	prevOwner := hashWithPrefix(0xC1)
	txid := hashWithPrefix(0xC2)

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevOwner, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{
			{Value: 90, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
		},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, ownerKP)}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevOwner, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: ownerCovData},
	}

	q := NewSigCheckQueue(1)
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, 200, 0, [32]byte{}, nil, q, nil, nil)
	if err != nil {
		t.Fatalf("vault creation: %v", err)
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if fee != 10 {
		t.Errorf("expected fee=10, got %d", fee)
	}
	if len(nextUtxos) != 1 {
		t.Errorf("expected 1 UTXO, got %d", len(nextUtxos))
	}
}

// TestApplyNonCoinbaseTxBasicWorkQ_VaultErrorPaths exercises CORE_VAULT error branches.
func TestApplyNonCoinbaseTxBasicWorkQ_VaultErrorPaths(t *testing.T) {
	// Helper: build a standard vault spend setup and return all components.
	buildVaultSpendSetup := func(t *testing.T) (ownerKP, vaultKP, destKP *MLDSA87Keypair, ownerCovData, vaultCovData, destCovData []byte, ownerLockID, whitelistH [32]byte) {
		t.Helper()
		ownerKP = mustMLDSA87Keypair(t)
		vaultKP = mustMLDSA87Keypair(t)
		destKP = mustMLDSA87Keypair(t)
		ownerCovData = p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
		ownerLockID = sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))
		destCovData = p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
		whitelistH = sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))
		vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
		vaultCovData = encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})
		return
	}

	t.Run("vault_output_in_spend", func(t *testing.T) {
		ownerKP, vaultKP, _, ownerCovData, vaultCovData, _, ownerLockID, whitelistH := buildVaultSpendSetup(t)
		_ = ownerLockID

		// Vault spend that tries to create a vault output — forbidden.
		var vaultKeyID2 [32]byte
		vaultKeyID2[0] = 0x22
		outputVaultData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID2}, [][32]byte{whitelistH})

		prevVault := hashWithPrefix(0xE1)
		prevOwner := hashWithPrefix(0xE2)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: prevVault, PrevVout: 0, Sequence: 0},
				{PrevTxid: prevOwner, PrevVout: 0, Sequence: 0},
			},
			Outputs: []TxOutput{
				{Value: 50, CovenantType: COV_TYPE_VAULT, CovenantData: outputVaultData},
			},
		}
		tx.Witness = []WitnessItem{
			signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, vaultKP),
			signP2PKInputWitness(t, tx, 1, 10, [32]byte{}, ownerKP),
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevVault, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
			{Txid: prevOwner, Vout: 0}: {Value: 10, CovenantType: COV_TYPE_P2PK, CovenantData: ownerCovData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 200, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected vault output in spend error")
		}
		if !isTxErrCode(err, TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED) {
			t.Fatalf("expected TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, got: %v", err)
		}
	})

	t.Run("vault_fee_sponsor_forbidden", func(t *testing.T) {
		ownerKP, vaultKP, destKP, ownerCovData, vaultCovData, destCovData, _, _ := buildVaultSpendSetup(t)
		_ = destKP

		sponsorKP := mustMLDSA87Keypair(t)
		sponsorCovData := p2pkCovenantDataForPubkey(sponsorKP.PubkeyBytes())

		prevVault := hashWithPrefix(0xF1)
		prevOwner := hashWithPrefix(0xF2)
		prevSponsor := hashWithPrefix(0xF3)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: prevVault, PrevVout: 0, Sequence: 0},
				{PrevTxid: prevOwner, PrevVout: 0, Sequence: 0},
				{PrevTxid: prevSponsor, PrevVout: 0, Sequence: 0},
			},
			Outputs: []TxOutput{
				{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
			},
		}
		tx.Witness = []WitnessItem{
			signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, vaultKP),
			signP2PKInputWitness(t, tx, 1, 10, [32]byte{}, ownerKP),
			signP2PKInputWitness(t, tx, 2, 5, [32]byte{}, sponsorKP),
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevVault, Vout: 0}:   {Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
			{Txid: prevOwner, Vout: 0}:   {Value: 10, CovenantType: COV_TYPE_P2PK, CovenantData: ownerCovData},
			{Txid: prevSponsor, Vout: 0}: {Value: 5, CovenantType: COV_TYPE_P2PK, CovenantData: sponsorCovData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 200, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected fee sponsor forbidden error")
		}
		if !isTxErrCode(err, TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN) {
			t.Fatalf("expected TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN, got: %v", err)
		}
	})

	t.Run("vault_output_not_whitelisted", func(t *testing.T) {
		ownerKP, vaultKP, _, ownerCovData, vaultCovData, _, _, _ := buildVaultSpendSetup(t)

		// Create a P2PK output that is NOT in the whitelist.
		nonWhitelistedKP := mustMLDSA87Keypair(t)
		nonWhitelistedCovData := p2pkCovenantDataForPubkey(nonWhitelistedKP.PubkeyBytes())

		prevVault := hashWithPrefix(0xA1)
		prevOwner := hashWithPrefix(0xA2)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: prevVault, PrevVout: 0, Sequence: 0},
				{PrevTxid: prevOwner, PrevVout: 0, Sequence: 0},
			},
			Outputs: []TxOutput{
				{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: nonWhitelistedCovData},
			},
		}
		tx.Witness = []WitnessItem{
			signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, vaultKP),
			signP2PKInputWitness(t, tx, 1, 10, [32]byte{}, ownerKP),
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevVault, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
			{Txid: prevOwner, Vout: 0}: {Value: 10, CovenantType: COV_TYPE_P2PK, CovenantData: ownerCovData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 200, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected whitelist error")
		}
		if !isTxErrCode(err, TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED) {
			t.Fatalf("expected TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, got: %v", err)
		}
	})

	t.Run("vault_creation_missing_owner", func(t *testing.T) {
		// Input's lock_id does NOT match vault's owner_lock_id.
		inputKP := mustMLDSA87Keypair(t)
		inputCovData := p2pkCovenantDataForPubkey(inputKP.PubkeyBytes())

		// Different owner_lock_id from what inputKP produces.
		var fakeOwnerLockID [32]byte
		fakeOwnerLockID[0] = 0xFF

		destKP := mustMLDSA87Keypair(t)
		destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
		whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

		var vaultKeyID [32]byte
		vaultKeyID[0] = 0x11
		vaultCovData := encodeVaultCovenantData(fakeOwnerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

		prevInput := hashWithPrefix(0xB1)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevInput, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{
				{Value: 90, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
			},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, inputKP)}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevInput, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: inputCovData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 200, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected vault owner auth error")
		}
		if !isTxErrCode(err, TX_ERR_VAULT_OWNER_AUTH_REQUIRED) {
			t.Fatalf("expected TX_ERR_VAULT_OWNER_AUTH_REQUIRED, got: %v", err)
		}
	})

	t.Run("vault_disallowed_destination_type", func(t *testing.T) {
		ownerKP, vaultKP, _, ownerCovData, vaultCovData, _, _, _ := buildVaultSpendSetup(t)

		stealthOutData := stealthCovenantDataForKeyID([32]byte{0x01})

		prevVault := hashWithPrefix(0xB2)
		prevOwner := hashWithPrefix(0xB3)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: prevVault, PrevVout: 0, Sequence: 0},
				{PrevTxid: prevOwner, PrevVout: 0, Sequence: 0},
			},
			Outputs: []TxOutput{
				{Value: 50, CovenantType: COV_TYPE_CORE_STEALTH, CovenantData: stealthOutData},
			},
		}
		tx.Witness = []WitnessItem{
			signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, vaultKP),
			signP2PKInputWitness(t, tx, 1, 10, [32]byte{}, ownerKP),
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevVault, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
			{Txid: prevOwner, Vout: 0}: {Value: 10, CovenantType: COV_TYPE_P2PK, CovenantData: ownerCovData},
		}
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 200, 0, [32]byte{}, nil, q, nil, nil)
		if err == nil {
			t.Fatal("expected disallowed destination type error")
		}
		if !isTxErrCode(err, TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED) {
			t.Fatalf("expected TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, got: %v", err)
		}
	})
}

// TestApplyNonCoinbaseTxBasicWorkQ_AnchorOutputSkip verifies that ANCHOR outputs
// are skipped in the output processing loop (not added to UTXO set).
func TestApplyNonCoinbaseTxBasicWorkQ_AnchorOutputSkip(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevTxid := hashWithPrefix(0x60)
	txid := hashWithPrefix(0x61)

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{
			{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
			{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: make([]byte, 32)},
		},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	q := NewSigCheckQueue(1)
	nextUtxos, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
	if err != nil {
		t.Fatalf("anchor output skip: %v", err)
	}
	if err := q.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Only P2PK output should be in spendable UTXO set (ANCHOR skipped).
	if len(nextUtxos) != 1 {
		t.Errorf("expected 1 UTXO (anchor skipped), got %d", len(nextUtxos))
	}
	if fee != 10 {
		t.Errorf("expected fee=10, got %d", fee)
	}
}

// TestApplyWrapper exercises the wrapper function
// applyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesQ through both success
// and error paths.
func TestApplyWrapper(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
		prevTxid := hashWithPrefix(0x70)
		txid := hashWithPrefix(0x71)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
		}

		q := NewSigCheckQueue(1)
		nextUtxos, summary, err := applyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesQ(
			tx, txid, utxos, 1, 12345, 0, [32]byte{}, nil, q, nil, nil,
		)
		if err != nil {
			t.Fatalf("wrapper success: %v", err)
		}
		if err := q.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if summary.Fee != 10 {
			t.Errorf("expected fee=10, got %d", summary.Fee)
		}
		if len(nextUtxos) != 1 {
			t.Errorf("expected 1 UTXO, got %d", len(nextUtxos))
		}
	})

	t.Run("error_propagated", func(t *testing.T) {
		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesQ(
			nil, [32]byte{}, nil, 0, 0, 0, [32]byte{}, nil, q, nil, nil,
		)
		if err == nil {
			t.Fatal("expected error from nil tx")
		}
	})
}

// TestApplyNonCoinbaseTxBasicWorkQ_CovenantGenesisError exercises the
// ValidateTxCovenantsGenesis error path (connect_block_parallel.go lines 241-242).
func TestApplyNonCoinbaseTxBasicWorkQ_CovenantGenesisError(t *testing.T) {
	// P2PK output with value=0 fails covenant genesis validation.
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevTxid := hashWithPrefix(0xCC)
	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		},
	}

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_P2PK, CovenantData: covData}}, // value=0 is invalid for P2PK
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	q := NewSigCheckQueue(1)
	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
	if err == nil {
		t.Fatal("expected covenant genesis error for P2PK value=0")
	}
	if !isTxErrCode(err, TX_ERR_COVENANT_TYPE_INVALID) {
		t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got: %v", err)
	}
}

// TestApplyNonCoinbaseTxBasicWorkQ_SighashPrehashError exercises the
// NewSighashV1PrehashCache error path (connect_block_parallel.go line 245).
func TestApplyNonCoinbaseTxBasicWorkQ_SighashPrehashError(t *testing.T) {
	// TxKind=0x01 without DaCommitCore fails sighash prehash cache creation.
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevTxid := hashWithPrefix(0xDD)
	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		},
	}

	tx := &Tx{
		Version:      1,
		TxKind:       0x01, // DA commit
		TxNonce:      1,
		DaCommitCore: nil, // missing → sighash fails
		Inputs:       []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs:      []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: kp.PubkeyBytes(), Signature: make([]byte, ML_DSA_87_SIG_BYTES)}}

	q := NewSigCheckQueue(1)
	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
	if err == nil {
		t.Fatal("expected sighash prehash error for tx_kind=0x01 without da_commit_core")
	}
	if !isTxErrCode(err, TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE, got: %v", err)
	}
}

// TestApplyNonCoinbaseTxBasicWorkQ_CheckSpendCovenantError exercises line 305-306:
// UTXO with corrupt vault covenant data triggers checkSpendCovenant error.
func TestApplyNonCoinbaseTxBasicWorkQ_CheckSpendCovenantError(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevTxid := hashWithPrefix(0xEE)

	// UTXO with COV_TYPE_VAULT but truncated covenant data → ParseVaultCovenantDataForSpend fails.
	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: []byte{0xFF}, // too short for vault
		},
	}

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}

	q := NewSigCheckQueue(1)
	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
	if err == nil {
		t.Fatal("expected checkSpendCovenant error for corrupt vault data")
	}
}

func TestApplyNonCoinbaseTxBasicWorkQ_CoreSimplicitySpendRejected(t *testing.T) {
	prevTxid := hashWithPrefix(0xEF)
	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_SIMPLICITY,
			CovenantData: encodeSimplicityCovenantData([32]byte{0xef}, nil),
		},
	}
	txBytes := txWithOneInputOneOutputWithWitness(prevTxid, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData(), dummyWitnesses(SIMPLICITY_WITNESS_SLOTS))
	tx, txid := mustParseTxForUtxo(t, txBytes)
	q := NewSigCheckQueue(1)

	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
	assertTxErrCodeMsg(t, err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
}

func TestApplyNonCoinbaseTxBasicWorkQ_CoreSimplicityRejectsBeforeWitnessChecks(t *testing.T) {
	prevTxid := hashWithPrefix(0xEE)
	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_SIMPLICITY,
			CovenantData: encodeSimplicityCovenantData([32]byte{0xee}, nil),
		},
	}
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}
	q := NewSigCheckQueue(1)

	work, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xed), utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
	if work != nil || fee != 0 || q.Len() != 0 {
		t.Fatalf("expected no queued mutation/sigs on reject, got work=%v fee=%d sigs=%d", work, fee, q.Len())
	}
	assertTxErrCodeMsg(t, err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
}

func TestApplyNonCoinbaseTxBasicUpdate_CoreSimplicityOutputGroupingShadowOnly(t *testing.T) {
	prevTxid := hashWithPrefix(0xF0)
	kp := mustMLDSA87Keypair(t)
	prevCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: prevCovData},
	}
	makeTx := func(outputCount int) *Tx {
		outputs := make([]TxOutput, outputCount)
		for i := range outputs {
			outputs[i] = TxOutput{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData([32]byte{0xf0}, nil)}
		}
		tx := &Tx{Version: 1, TxKind: 0x00, TxNonce: 1, Inputs: []TxInput{{PrevTxid: prevTxid, PrevVout: 0}}, Outputs: outputs}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
		return tx
	}
	rotation := testRotationProvider{createSuiteID: SUITE_ID_ML_DSA_87, simplicityActiveHeight: 1}
	outputCount := 9

	work, summary, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(makeTx(outputCount), hashWithPrefix(0xF1), utxoSet, 1, 0, [32]byte{}, rotation, nil)
	if err != nil {
		t.Fatalf("sequential same-CMR output grouping is shadow-only in this slice: %v", err)
	}
	if work == nil || summary == nil {
		t.Fatalf("expected work and summary, got work=%v summary=%v", work, summary)
	}

	work, fee, err := applyNonCoinbaseTxBasicWorkQ(makeTx(outputCount), hashWithPrefix(0xF2), utxoSet, 1, 0, [32]byte{}, nil, NewSigCheckQueue(1), rotation, nil)
	if err != nil {
		t.Fatalf("queued same-CMR output grouping is shadow-only in this slice: %v", err)
	}
	if work == nil || fee == 0 {
		t.Fatalf("expected work and fee, got work=%v fee=%d", work, fee)
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_CoreSimplicityInputGroupCapDeferredBehindDisabledSpend(t *testing.T) {
	makeCase := func(inputCount int, splitLast bool) (*Tx, [32]byte, map[Outpoint]UtxoEntry) {
		tx := &Tx{Version: 1, TxKind: 0x00, TxNonce: 1, Inputs: make([]TxInput, inputCount), Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}, Witness: dummyWitnesses(inputCount * SIMPLICITY_WITNESS_SLOTS)}
		utxos := make(map[Outpoint]UtxoEntry, inputCount)
		for i := range tx.Inputs {
			cmr := [32]byte{0xf6}
			if splitLast && i == len(tx.Inputs)-1 {
				cmr = [32]byte{0xf7}
			}
			prev := hashWithPrefix(byte(0x80 + i))
			tx.Inputs[i] = TxInput{PrevTxid: prev, PrevVout: 0}
			utxos[Outpoint{Txid: prev, Vout: 0}] = UtxoEntry{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData(cmr, nil)}
		}
		return tx, hashWithPrefix(0xf8), utxos
	}
	runSeq := func(inputCount int, splitLast bool) error {
		tx, txid, utxos := makeCase(inputCount, splitLast)
		work, summary, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(tx, txid, utxos, 1, 0, [32]byte{}, nil, nil)
		if work != nil || summary != nil {
			t.Fatalf("expected no sequential mutation on reject, got work=%v summary=%v", work, summary)
		}
		return err
	}
	runQ := func(inputCount int, splitLast bool) error {
		tx, txid, utxos := makeCase(inputCount, splitLast)
		q := NewSigCheckQueue(1)
		work, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, 1, 0, [32]byte{}, nil, q, nil, nil)
		if work != nil || fee != 0 || q.Len() != 0 {
			t.Fatalf("expected no queued mutation/sigs on reject, got work=%v fee=%d sigs=%d", work, fee, q.Len())
		}
		return err
	}
	assertTxErrCodeMsg(t, runSeq(SIMPLICITY_MAX_GROUP_INPUTS, false), TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
	assertTxErrCodeMsg(t, runSeq(SIMPLICITY_MAX_GROUP_INPUTS+1, true), TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
	assertTxErrCodeMsg(t, runSeq(SIMPLICITY_MAX_GROUP_INPUTS+1, false), TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
	assertTxErrCodeMsg(t, runQ(SIMPLICITY_MAX_GROUP_INPUTS, false), TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
	assertTxErrCodeMsg(t, runQ(SIMPLICITY_MAX_GROUP_INPUTS+1, true), TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
	assertTxErrCodeMsg(t, runQ(SIMPLICITY_MAX_GROUP_INPUTS+1, false), TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY spend evaluation not enabled")
}

// TestApplyNonCoinbaseTxBasicWorkQ_P2PKSpendQError exercises line 326:
// P2PK input with an invalid suite ID triggers validateP2PKSpendQ error.
func TestApplyNonCoinbaseTxBasicWorkQ_P2PKSpendQError(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevTxid := hashWithPrefix(0xFF)

	utxoSet := map[Outpoint]UtxoEntry{
		{Txid: prevTxid, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), covData...),
		},
	}

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	// Witness with invalid suite ID (0xFF instead of ML_DSA_87).
	tx.Witness = []WitnessItem{{SuiteID: 0xFF, Pubkey: kp.PubkeyBytes(), Signature: make([]byte, ML_DSA_87_SIG_BYTES)}}

	q := NewSigCheckQueue(1)
	_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxoSet, 1, 0, [32]byte{}, nil, q, nil, nil)
	if err == nil {
		t.Fatal("expected P2PK spend error for invalid suite ID")
	}
	if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
		t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
	}
}

// sortKeys32 sorts two 32-byte arrays lexicographically and returns them in order.
func sortKeys32(a, b [32]byte) ([32]byte, [32]byte) {
	if bytes.Compare(a[:], b[:]) > 0 {
		return b, a
	}
	return a, b
}

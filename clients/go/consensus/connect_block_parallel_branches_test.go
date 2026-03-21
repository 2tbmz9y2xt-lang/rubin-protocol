package consensus

import (
	"bytes"
	"encoding/binary"
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

		// CORE_EXT output — disallowed covenant type for vault spend.
		coreExtOutData := []byte{0x01, 0x00, 0x00} // ext_id=1, payload_len=0
		coreExtH := sha3_256(OutputDescriptorBytes(COV_TYPE_CORE_EXT, coreExtOutData))
		_ = coreExtH

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
				{Value: 50, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtOutData},
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

// makeCoreExtCovenantData builds minimal valid CORE_EXT covenant_data: ext_id(2 LE) + compact_size(0).
func makeCoreExtCovenantData(extID uint16) []byte {
	b := make([]byte, 3)
	binary.LittleEndian.PutUint16(b[0:2], extID)
	b[2] = 0x00 // compact_size(0) for empty payload
	return b
}

// testCoreExtProfileProvider implements CoreExtProfileProvider for tests.
type testCoreExtProfileProvider struct {
	profile CoreExtProfile
	found   bool
	err     error
}

func (p *testCoreExtProfileProvider) LookupCoreExtProfile(extID uint16, height uint64) (CoreExtProfile, bool, error) {
	return p.profile, p.found, p.err
}

func TestApplyNonCoinbaseTxBasicWorkQ_CoreExtBranches(t *testing.T) {
	t.Run("inactive_profile_break", func(t *testing.T) {
		// CORE_EXT input with no active profile → break (no-op on sig check).
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xA0)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		// CORE_EXT takes 1 witness slot.
		tx.Witness = []WitnessItem{{
			SuiteID:   SUITE_ID_ML_DSA_87,
			Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
			Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
		}}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}
		// Explicit empty provider models the pre-ACTIVE no-deployment case.
		q := NewSigCheckQueue(1)
		_, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xA1), utxos, 1, 0, [32]byte{}, EmptyCoreExtProfileProvider(), q, nil, nil)
		if err != nil {
			t.Fatalf("inactive CORE_EXT: %v", err)
		}
		if err := q.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if fee != 10 {
			t.Errorf("expected fee=10, got %d", fee)
		}
	})

	t.Run("active_profile_mldsa87_queued", func(t *testing.T) {
		// CORE_EXT with active profile that allows ML-DSA-87 → queued verification.
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xB0)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}

		sigItem := signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)
		tx.Witness = []WitnessItem{sigItem}

		profiles := &testCoreExtProfileProvider{
			profile: CoreExtProfile{
				Active:        true,
				AllowedSuites: map[uint8]struct{}{SUITE_ID_ML_DSA_87: {}},
			},
			found: true,
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xB1), utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err != nil {
			t.Fatalf("active CORE_EXT ML-DSA-87: %v", err)
		}
		// Signature was queued — flush to verify.
		if q.Len() != 1 {
			t.Errorf("expected 1 queued sig, got %d", q.Len())
		}
		if err := q.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if fee != 10 {
			t.Errorf("expected fee=10, got %d", fee)
		}
	})

	t.Run("txcontext_enabled_dispatches_nine_param", func(t *testing.T) {
		prevTxid := hashWithPrefix(0xB2)
		txBytes := txWithOneInputOneOutputWithWitness(prevTxid, 0, 90, COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), []WitnessItem{{
			SuiteID:   0x42,
			Pubkey:    []byte{0x01, 0x02, 0x03},
			Signature: []byte{0x04, 0x01},
		}})
		tx, txid := mustParseTxForUtxo(t, txBytes)

		called := false
		profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
			ExtID:            7,
			ActivationHeight: 0,
			TxContextEnabled: true,
			AllowedSuites:    map[uint8]struct{}{0x42: {}},
			VerifySigExtTxContextFn: func(
				extID uint16,
				suiteID uint8,
				pubkey []byte,
				signature []byte,
				digest32 [32]byte,
				extPayload []byte,
				ctxBase *TxContextBase,
				ctxContinuing *TxContextContinuing,
				selfInputValue uint64,
			) (bool, error) {
				called = true
				if extID != 7 || suiteID != 0x42 {
					t.Fatalf("extID/suiteID=%d/%d", extID, suiteID)
				}
				if string(extPayload) != string([]byte{0x99}) {
					t.Fatalf("extPayload=%x", extPayload)
				}
				if ctxBase == nil || ctxBase.TotalIn != (Uint128{Lo: 100, Hi: 0}) || ctxBase.TotalOut != (Uint128{Lo: 90, Hi: 0}) || ctxBase.Height != 1 {
					t.Fatalf("ctxBase=%+v", ctxBase)
				}
				if ctxContinuing == nil || ctxContinuing.ContinuingOutputCount != 1 || ctxContinuing.ContinuingOutputs[0].Value != 90 {
					t.Fatalf("ctxContinuing=%+v", ctxContinuing)
				}
				if ctxContinuing.ContinuingOutputs[0].ExtPayload == nil || len(ctxContinuing.ContinuingOutputs[0].ExtPayload) != 0 {
					t.Fatalf("continuing payload must be non-nil empty slice, got %#v", ctxContinuing.ContinuingOutputs[0].ExtPayload)
				}
				if selfInputValue != 100 {
					t.Fatalf("selfInputValue=%d", selfInputValue)
				}
				_ = pubkey
				_ = signature
				_ = digest32
				return true, nil
			},
			BindingDescriptor: []byte{0xa1},
			ExtPayloadSchema:  []byte{0xb2},
		}})
		if err != nil {
			t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {
				Value:        100,
				CovenantType: COV_TYPE_CORE_EXT,
				CovenantData: coreExtCovenantData(7, []byte{0x99}),
			},
		}

		q := NewSigCheckQueue(1)
		_, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err != nil {
			t.Fatalf("txcontext-enabled CORE_EXT: %v", err)
		}
		if err := q.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if !called {
			t.Fatalf("expected txcontext-enabled verifier to run")
		}
		if fee != 10 {
			t.Errorf("expected fee=10, got %d", fee)
		}
	})

	t.Run("txcontext_malformed_output_fails_before_verifier", func(t *testing.T) {
		prevTxid := hashWithPrefix(0xB3)
		txBytes := txWithOneInputOneOutputWithWitness(prevTxid, 0, 90, COV_TYPE_CORE_EXT, []byte{0x01}, []WitnessItem{{
			SuiteID:   0x42,
			Pubkey:    []byte{0x01, 0x02, 0x03},
			Signature: []byte{0x04, 0x01},
		}})
		tx, _ := mustParseTxForUtxo(t, txBytes)

		called := false
		profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
			ExtID:            7,
			ActivationHeight: 0,
			TxContextEnabled: true,
			AllowedSuites:    map[uint8]struct{}{0x42: {}},
			VerifySigExtTxContextFn: func(uint16, uint8, []byte, []byte, [32]byte, []byte, *TxContextBase, *TxContextContinuing, uint64) (bool, error) {
				called = true
				return true, nil
			},
			BindingDescriptor: []byte{0xa1},
			ExtPayloadSchema:  []byte{0xb2},
		}})
		if err != nil {
			t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {
				Value:        100,
				CovenantType: COV_TYPE_CORE_EXT,
				CovenantData: coreExtCovenantData(7, []byte{0x99}),
			},
		}

		q := NewSigCheckQueue(1)
		_, _, err = applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected malformed output error")
		}
		if !isTxErrCode(err, TX_ERR_COVENANT_TYPE_INVALID) {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got: %v", err)
		}
		if called {
			t.Fatalf("verifier must not run when txcontext output cache build fails")
		}
	})

	t.Run("txcontext_too_many_continuing_outputs_fails_before_verifier", func(t *testing.T) {
		prevTxid := hashWithPrefix(0xB4)
		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{
				{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, nil)},
				{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, []byte{0x01})},
				{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, []byte{0x02})},
			},
			Witness: []WitnessItem{{
				SuiteID:   0x42,
				Pubkey:    []byte{0x01, 0x02, 0x03},
				Signature: []byte{0x04, 0x01},
			}},
		}

		called := false
		profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
			ExtID:            7,
			ActivationHeight: 0,
			TxContextEnabled: true,
			AllowedSuites:    map[uint8]struct{}{0x42: {}},
			VerifySigExtTxContextFn: func(uint16, uint8, []byte, []byte, [32]byte, []byte, *TxContextBase, *TxContextContinuing, uint64) (bool, error) {
				called = true
				return true, nil
			},
			BindingDescriptor: []byte{0xa1},
			ExtPayloadSchema:  []byte{0xb2},
		}})
		if err != nil {
			t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {
				Value:        100,
				CovenantType: COV_TYPE_CORE_EXT,
				CovenantData: coreExtCovenantData(7, []byte{0x99}),
			},
		}

		q := NewSigCheckQueue(1)
		_, _, err = applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected excessive continuing outputs error")
		}
		if !isTxErrCode(err, TX_ERR_COVENANT_TYPE_INVALID) {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got: %v", err)
		}
		if called {
			t.Fatalf("verifier must not run when txcontext build rejects excessive continuing outputs")
		}
	})

	t.Run("active_profile_suite_disallowed", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xC0)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		tx.Witness = []WitnessItem{{
			SuiteID:   SUITE_ID_ML_DSA_87,
			Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
			Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
		}}

		// Active profile but ML-DSA-87 not in allowed suites.
		profiles := &testCoreExtProfileProvider{
			profile: CoreExtProfile{
				Active:        true,
				AllowedSuites: map[uint8]struct{}{0x99: {}}, // some other suite
			},
			found: true,
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected suite disallowed error")
		}
		if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
			t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
		}
	})

	t.Run("active_profile_sentinel_forbidden", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xC1)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}

		profiles := &testCoreExtProfileProvider{
			profile: CoreExtProfile{
				Active:        true,
				AllowedSuites: map[uint8]struct{}{SUITE_ID_SENTINEL: {}},
			},
			found: true,
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected sentinel forbidden error")
		}
		if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
			t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
		}
	})

	t.Run("active_profile_ext_verifier_ok", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xD0)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		// Use custom suite 0x42 with external verifier.
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
		// Override suite ID to 0x42 for the external verifier path.
		tx.Witness[0].SuiteID = 0x42

		profiles := &testCoreExtProfileProvider{
			profile: CoreExtProfile{
				Active:        true,
				AllowedSuites: map[uint8]struct{}{0x42: {}},
				VerifySigExtFn: func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error) {
					return true, nil // always approve
				},
			},
			found: true,
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xD1), utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err != nil {
			t.Fatalf("ext verifier OK: %v", err)
		}
		if err := q.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if fee != 10 {
			t.Errorf("expected fee=10, got %d", fee)
		}
	})

	t.Run("active_profile_ext_verifier_rejects", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xD2)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
		tx.Witness[0].SuiteID = 0x42

		profiles := &testCoreExtProfileProvider{
			profile: CoreExtProfile{
				Active:        true,
				AllowedSuites: map[uint8]struct{}{0x42: {}},
				VerifySigExtFn: func(extID uint16, suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, extPayload []byte) (bool, error) {
					return false, nil // reject
				},
			},
			found: true,
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected ext verifier rejection error")
		}
		if !isTxErrCode(err, TX_ERR_SIG_INVALID) {
			t.Fatalf("expected TX_ERR_SIG_INVALID, got: %v", err)
		}
	})

	t.Run("active_profile_nil_ext_verifier", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xD3)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
		tx.Witness[0].SuiteID = 0x42

		// Active profile with allowed suite 0x42 but nil VerifySigExtFn.
		profiles := &testCoreExtProfileProvider{
			profile: CoreExtProfile{
				Active:         true,
				AllowedSuites:  map[uint8]struct{}{0x42: {}},
				VerifySigExtFn: nil,
			},
			found: true,
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected nil ext verifier error")
		}
		if !isTxErrCode(err, TX_ERR_SIG_ALG_INVALID) {
			t.Fatalf("expected TX_ERR_SIG_ALG_INVALID, got: %v", err)
		}
	})

	t.Run("profile_lookup_error", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xD4)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: make([]byte, ML_DSA_87_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_87_SIG_BYTES+1)}}

		profiles := &testCoreExtProfileProvider{
			err: txerr(TX_ERR_COVENANT_TYPE_INVALID, "test lookup error"),
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected profile lookup error")
		}
		if !isTxErrCode(err, TX_ERR_COVENANT_TYPE_INVALID) {
			t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID, got: %v", err)
		}
	})

	t.Run("mldsa87_noncanonical_lengths", func(t *testing.T) {
		kp := mustMLDSA87Keypair(t)
		outCovData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

		coreExtCovData := makeCoreExtCovenantData(42)
		prevTxid := hashWithPrefix(0xD5)

		tx := &Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs:  []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0}},
			Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: outCovData}},
		}
		// Wrong pubkey length for ML-DSA-87.
		tx.Witness = []WitnessItem{{
			SuiteID:   SUITE_ID_ML_DSA_87,
			Pubkey:    make([]byte, 10), // too short
			Signature: make([]byte, ML_DSA_87_SIG_BYTES+1),
		}}

		profiles := &testCoreExtProfileProvider{
			profile: CoreExtProfile{
				Active:        true,
				AllowedSuites: map[uint8]struct{}{SUITE_ID_ML_DSA_87: {}},
			},
			found: true,
		}

		utxos := map[Outpoint]UtxoEntry{
			{Txid: prevTxid, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovData},
		}

		q := NewSigCheckQueue(1)
		_, _, err := applyNonCoinbaseTxBasicWorkQ(tx, [32]byte{}, utxos, 1, 0, [32]byte{}, profiles, q, nil, nil)
		if err == nil {
			t.Fatal("expected non-canonical lengths error")
		}
		if !isTxErrCode(err, TX_ERR_SIG_NONCANONICAL) {
			t.Fatalf("expected TX_ERR_SIG_NONCANONICAL, got: %v", err)
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

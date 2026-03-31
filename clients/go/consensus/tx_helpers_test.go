package consensus

import (
	"reflect"
	"testing"
)

type stubDigestSigner struct {
	pub []byte
	sig []byte
	err error
}

func copyTestUtxoSet(src map[Outpoint]UtxoEntry) map[Outpoint]UtxoEntry {
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

func (s stubDigestSigner) PubkeyBytes() []byte {
	return append([]byte(nil), s.pub...)
}

func (s stubDigestSigner) SignDigest32([32]byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.sig...), nil
}

func TestP2PKCovenantDataForPubkey(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pub := kp.PubkeyBytes()

	data := P2PKCovenantDataForPubkey(pub)
	if len(data) != MAX_P2PK_COVENANT_DATA {
		t.Fatalf("expected %d bytes, got %d", MAX_P2PK_COVENANT_DATA, len(data))
	}
	if data[0] != SUITE_ID_ML_DSA_87 {
		t.Fatalf("expected suite_id 0x%02x, got 0x%02x", SUITE_ID_ML_DSA_87, data[0])
	}
	// key_id should be SHA3-256(pub)
	keyID := sha3_256(pub)
	for i := 0; i < 32; i++ {
		if data[1+i] != keyID[i] {
			t.Fatalf("key_id byte %d mismatch", i)
		}
	}
}

func TestCheckTransaction_TrailingBytes(t *testing.T) {
	// Build a minimal valid non-coinbase tx scenario with trailing bytes
	kp := mustMLDSA87Keypair(t)
	covData := P2PKCovenantDataForPubkey(kp.PubkeyBytes())

	// Create a synthetic UTXO
	var prevTxid [32]byte
	prevTxid[0] = 0x99
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxoSet := map[Outpoint]UtxoEntry{
		op: {Value: 100_000_000, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	// Build minimal tx
	tx := &Tx{
		Version:  1,
		TxNonce:  1,
		Locktime: 0,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
		Outputs: []TxOutput{{
			Value:        90_000_000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
	}
	var chainID [32]byte
	chainID[0] = 0x88

	// Sign the tx
	err := SignTransaction(tx, utxoSet, chainID, kp)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	// Serialize
	txBytes, merr := MarshalTx(tx)
	if merr != nil {
		t.Fatalf("MarshalTx: %v", merr)
	}

	// Append trailing byte
	txBytesTrailing := append(txBytes, 0x00)
	_, err = CheckTransaction(txBytesTrailing, utxoSet, 10, 0, chainID)
	if err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestCheckTransaction_ValidTx(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := P2PKCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0xAA
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxoSet := map[Outpoint]UtxoEntry{
		op: {
			Value:             100_000_000,
			CovenantType:      COV_TYPE_P2PK,
			CovenantData:      covData,
			CreationHeight:    1,
			CreatedByCoinbase: true,
		},
	}

	tx := &Tx{
		Version:  1,
		TxNonce:  1,
		Locktime: 0,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
		Outputs: []TxOutput{{
			Value:        90_000_000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
	}
	var chainID [32]byte
	chainID[0] = 0x88

	err := SignTransaction(tx, utxoSet, chainID, kp)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	txBytes, merr := MarshalTx(tx)
	if merr != nil {
		t.Fatalf("MarshalTx: %v", merr)
	}
	// Use height well past maturity
	checked, err := CheckTransaction(txBytes, utxoSet, 200, 0, chainID)
	if err != nil {
		t.Fatalf("CheckTransaction: %v", err)
	}
	if checked.Fee != 10_000_000 {
		t.Fatalf("expected fee 10_000_000, got %d", checked.Fee)
	}
	if checked.SerializedSize != len(txBytes) {
		t.Fatalf("serialized size mismatch: %d vs %d", checked.SerializedSize, len(txBytes))
	}
	if _, ok := utxoSet[op]; !ok {
		t.Fatalf("CheckTransaction mutated caller utxo set")
	}
	if len(utxoSet) != 1 {
		t.Fatalf("utxo set size changed: %d", len(utxoSet))
	}
}

func TestCheckTransactionWithCoreExtProfilesAndSuiteContext_DoesNotMutateCallerUtxoSet(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := P2PKCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0xAB
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxoSet := map[Outpoint]UtxoEntry{
		op: {
			Value:             100_000_000,
			CovenantType:      COV_TYPE_P2PK,
			CovenantData:      covData,
			CreationHeight:    1,
			CreatedByCoinbase: true,
		},
	}

	tx := &Tx{
		Version:  1,
		TxNonce:  2,
		Locktime: 0,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
		Outputs: []TxOutput{{
			Value:        90_000_000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
	}
	var chainID [32]byte
	chainID[0] = 0x77

	if err := SignTransaction(tx, utxoSet, chainID, kp); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	txBytes, err := MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}

	original := copyTestUtxoSet(utxoSet)
	checked, err := CheckTransactionWithCoreExtProfilesAndSuiteContext(
		txBytes,
		utxoSet,
		200,
		0,
		chainID,
		nil,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CheckTransactionWithCoreExtProfilesAndSuiteContext: %v", err)
	}
	if checked.Fee != 10_000_000 {
		t.Fatalf("expected fee 10_000_000, got %d", checked.Fee)
	}
	if !reflect.DeepEqual(utxoSet, original) {
		t.Fatalf("CheckTransactionWithCoreExtProfilesAndSuiteContext mutated caller utxo set")
	}
}

func TestCheckParsedTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext_NilTx(t *testing.T) {
	_, err := CheckParsedTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		nil,
		nil,
		[32]byte{},
		[32]byte{},
		map[Outpoint]UtxoEntry{},
		1,
		0,
		[32]byte{},
		nil,
		nil,
		nil,
	)
	if err == nil {
		t.Fatal("expected nil tx error")
	}
}

func TestCheckParsedTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext_ValidTx(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := P2PKCovenantDataForPubkey(kp.PubkeyBytes())

	var prevTxid [32]byte
	prevTxid[0] = 0xAC
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxoSet := map[Outpoint]UtxoEntry{
		op: {
			Value:             100_000_000,
			CovenantType:      COV_TYPE_P2PK,
			CovenantData:      covData,
			CreationHeight:    1,
			CreatedByCoinbase: true,
		},
	}

	tx := &Tx{
		Version:  1,
		TxNonce:  3,
		Locktime: 0,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
		Outputs: []TxOutput{{
			Value:        90_000_000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
	}
	var chainID [32]byte
	chainID[0] = 0x66

	if err := SignTransaction(tx, utxoSet, chainID, kp); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	parsed, txid, wtxid, consumed, err := ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(txBytes) {
		t.Fatalf("consumed=%d len=%d", consumed, len(txBytes))
	}

	checked, err := CheckParsedTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		parsed,
		txid,
		wtxid,
		copyTestUtxoSet(utxoSet),
		200,
		0,
		chainID,
		nil,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("CheckParsedTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext: %v", err)
	}
	if checked.Fee != 10_000_000 {
		t.Fatalf("expected fee 10_000_000, got %d", checked.Fee)
	}
	if checked.SerializedSize != len(txBytes) {
		t.Fatalf("serialized size mismatch: %d vs %d", checked.SerializedSize, len(txBytes))
	}
}

func TestSignTransaction_NilTx(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var chainID [32]byte
	err := SignTransaction(nil, nil, chainID, kp)
	if err == nil {
		t.Fatal("expected error for nil tx")
	}
}

func TestSignTransaction_NoInputs(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	tx := &Tx{Version: 1}
	var chainID [32]byte
	err := SignTransaction(tx, nil, chainID, kp)
	if err == nil {
		t.Fatal("expected error for no inputs")
	}
}

func TestSignTransaction_NilSigner(t *testing.T) {
	tx := &Tx{
		Version: 1,
		Inputs:  []TxInput{{Sequence: 0xFFFFFFFF}},
	}
	var chainID [32]byte
	err := SignTransaction(tx, nil, chainID, nil)
	if err == nil {
		t.Fatal("expected error for nil signer")
	}
}

func TestSignTransaction_MissingUTXO(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var prevTxid [32]byte
	prevTxid[0] = 0xBB
	tx := &Tx{
		Version: 1,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
	}
	var chainID [32]byte
	utxoSet := map[Outpoint]UtxoEntry{} // empty
	err := SignTransaction(tx, utxoSet, chainID, kp)
	if err == nil {
		t.Fatal("expected error for missing UTXO")
	}
}

func TestSignTransaction_KeyBindingMismatch(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	kp2 := mustMLDSA87Keypair(t) // different keypair

	// UTXO locked to kp2, but signing with kp
	covData := P2PKCovenantDataForPubkey(kp2.PubkeyBytes())
	var prevTxid [32]byte
	prevTxid[0] = 0xCC
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxoSet := map[Outpoint]UtxoEntry{
		op: {Value: 50_000_000, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}

	tx := &Tx{
		Version: 1,
		TxNonce: 1,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
		Outputs: []TxOutput{{
			Value:        40_000_000,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: covData,
		}},
	}
	var chainID [32]byte
	err := SignTransaction(tx, utxoSet, chainID, kp) // signing with wrong key
	if err == nil {
		t.Fatal("expected error for key binding mismatch")
	}
}

func TestSignTransaction_RejectsUnsupportedTxKindForPrehashCache(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	covData := P2PKCovenantDataForPubkey(kp.PubkeyBytes())
	var prevTxid [32]byte
	prevTxid[0] = 0xdd
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxoSet := map[Outpoint]UtxoEntry{
		op: {Value: 50_000_000, CovenantType: COV_TYPE_P2PK, CovenantData: covData},
	}
	tx := &Tx{
		Version: 1,
		TxKind:  0xff,
		TxNonce: 1,
		Inputs: []TxInput{{
			PrevTxid: prevTxid,
			PrevVout: 0,
			Sequence: 0x7FFFFFFF,
		}},
	}
	if err := SignTransaction(tx, utxoSet, [32]byte{}, kp); err == nil {
		t.Fatal("expected unsupported tx_kind error")
	}
}

func TestSignerBinding_RejectsNonCanonicalPubkeyLength(t *testing.T) {
	if _, _, err := signerBinding(stubDigestSigner{pub: []byte{0x01}}); err == nil {
		t.Fatal("expected non-canonical public key length error")
	}
}

func TestSignWitnessItem_NilCacheUsesDirectSighash(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	pub := kp.PubkeyBytes()

	got, err := signWitnessItem(tx, inputIndex, inputValue, chainID, nil, kp, pub)
	if err != nil {
		t.Fatalf("signWitnessItem(nil cache): %v", err)
	}
	if got.SuiteID != SUITE_ID_ML_DSA_87 {
		t.Fatalf("suite = 0x%02x, want 0x%02x", got.SuiteID, SUITE_ID_ML_DSA_87)
	}
	if len(got.Pubkey) != len(pub) {
		t.Fatalf("pubkey length = %d, want %d", len(got.Pubkey), len(pub))
	}
	if len(got.Signature) != ML_DSA_87_SIG_BYTES+1 {
		t.Fatalf("signature length = %d, want %d", len(got.Signature), ML_DSA_87_SIG_BYTES+1)
	}
	if got.Signature[len(got.Signature)-1] != SIGHASH_ALL {
		t.Fatalf("missing sighash type trailer")
	}
}

func TestSignWitnessItem_RejectsNonCanonicalSignatureLength(t *testing.T) {
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	// Signer returns a signature that is one byte too short.
	shortSig := make([]byte, ML_DSA_87_SIG_BYTES-1)
	signer := stubDigestSigner{pub: pub, sig: shortSig}

	_, err := signWitnessItem(tx, inputIndex, inputValue, chainID, nil, signer, pub)
	if err == nil {
		t.Fatal("expected non-canonical signature length error")
	}
	txErr, ok := err.(*TxError)
	if !ok {
		t.Fatalf("expected *TxError, got %T", err)
	}
	if txErr.Code != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("error code = %s, want %s", txErr.Code, TX_ERR_SIG_NONCANONICAL)
	}
}

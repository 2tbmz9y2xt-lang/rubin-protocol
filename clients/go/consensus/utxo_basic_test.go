package consensus

import (
	"testing"
)

func txWithOneInputOneOutput(prevTxid [32]byte, prevVout uint32, outValue uint64, outCovType uint16, outCovData []byte) []byte {
	b := make([]byte, 0, 256+len(outCovData))
	b = appendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = appendU64le(b, 1)
	b = appendCompactSize(b, 1) // input_count
	b = append(b, prevTxid[:]...)
	b = appendU32le(b, prevVout)
	b = appendCompactSize(b, 0) // script_sig_len
	b = appendU32le(b, 0)       // sequence

	b = appendCompactSize(b, 1) // output_count
	b = appendU64le(b, outValue)
	b = appendU16le(b, outCovType)
	b = appendCompactSize(b, uint64(len(outCovData)))
	b = append(b, outCovData...)

	b = appendU32le(b, 0) // locktime
	b = appendCompactSize(b, 0)
	b = appendCompactSize(b, 0)
	return b
}

func validP2PKCovenantData() []byte {
	b := make([]byte, MAX_P2PK_COVENANT_DATA)
	b[0] = SUITE_ID_ML_DSA_87
	return b
}

func mustParseTxForUtxo(t *testing.T, txBytes []byte) (*Tx, [32]byte) {
	t.Helper()
	tx, txid, _, _, err := ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return tx, txid
}

func TestApplyNonCoinbaseTxBasic_MissingUTXO(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xaa
	txBytes := txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, map[Outpoint]UtxoEntry{}, 100, 1000)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_MISSING_UTXO {
		t.Fatalf("code=%s, want %s", got, TX_ERR_MISSING_UTXO)
	}
}

func TestApplyNonCoinbaseTxBasic_SpendAnchorRejected(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xab
	txBytes := txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        1,
			CovenantType: COV_TYPE_ANCHOR,
			CovenantData: []byte{0x01},
		},
	}
	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 100, 1000)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_MISSING_UTXO {
		t.Fatalf("code=%s, want %s", got, TX_ERR_MISSING_UTXO)
	}
}

func TestApplyNonCoinbaseTxBasic_ValueConservation(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xae
	txBytes := txWithOneInputOneOutput(prev, 0, 101, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		},
	}
	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VALUE_CONSERVATION {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VALUE_CONSERVATION)
	}
}

func TestApplyNonCoinbaseTxBasic_OK(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xaf
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		},
	}
	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee != 10 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}
	if s.UtxoCount != 1 {
		t.Fatalf("utxo_count=%d, want 1", s.UtxoCount)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultCannotFundFee(t *testing.T) {
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xc0
	prevFee[0] = 0xc1
	txid[0] = 0xc2

	tx := &Tx{
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
		},
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: validVaultCovenantDataForP2PKOutput(),
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VALUE_CONSERVATION {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VALUE_CONSERVATION)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultPreservedWithExternalFeeSponsor(t *testing.T) {
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xd0
	prevFee[0] = 0xd1
	txid[0] = 0xd2

	tx := &Tx{
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
		},
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: validVaultCovenantDataForP2PKOutput(),
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		},
	}

	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee != 10 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultWhitelistRejectsOutput(t *testing.T) {
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xe0
	prevFee[0] = 0xe1
	txid[0] = 0xe2

	nonWhitelistedOutData := make([]byte, MAX_P2PK_COVENANT_DATA)
	nonWhitelistedOutData[0] = SUITE_ID_ML_DSA_87
	nonWhitelistedOutData[1] = 0xff

	tx := &Tx{
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: nonWhitelistedOutData},
		},
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: validVaultCovenantDataForP2PKOutput(),
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_MultisigInputAccepted(t *testing.T) {
	var prevMS, txid [32]byte
	prevMS[0] = 0xf0
	txid[0] = 0xf1
	txBytes := txWithOneInputOneOutput(prevMS, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, parsedTxid := mustParseTxForUtxo(t, txBytes)
	txid = parsedTxid

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevMS, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_MULTISIG,
			CovenantData: encodeMultisigCovenantData(1, makeKeys(1, 0x31)),
		},
	}
	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee != 10 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}
}

package consensus

import (
	"testing"
)

func txWithOneInputOneOutput(prevTxid [32]byte, prevVout uint32, outValue uint64, outCovType uint16, outCovData []byte) []byte {
	return txWithOneInputOneOutputWithWitness(prevTxid, prevVout, outValue, outCovType, outCovData, nil)
}

func txWithOneInputOneOutputWithWitness(
	prevTxid [32]byte,
	prevVout uint32,
	outValue uint64,
	outCovType uint16,
	outCovData []byte,
	witnesses []WitnessItem,
) []byte {
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
	b = appendCompactSize(b, uint64(len(witnesses)))
	for _, w := range witnesses {
		b = append(b, w.SuiteID)
		b = appendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = appendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}
	b = appendCompactSize(b, 0)
	return b
}

func dummyWitnesses(n int) []WitnessItem {
	witnesses := make([]WitnessItem, 0, n)
	for i := 0; i < n; i++ {
		witnesses = append(witnesses, WitnessItem{
			SuiteID: SUITE_ID_SENTINEL,
		})
	}
	return witnesses
}

func validP2PKCovenantData() []byte {
	b := make([]byte, MAX_P2PK_COVENANT_DATA)
	b[0] = SUITE_ID_ML_DSA_87
	return b
}

func ownerP2PKCovenantDataForVault() []byte {
	b := validP2PKCovenantData()
	b[1] = 0x01
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

func TestApplyNonCoinbaseTxBasic_InputValidationErrors(t *testing.T) {
	cases := []struct {
		name      string
		prevByte  byte
		outValue  uint64
		utxosFn   func(prev [32]byte) map[Outpoint]UtxoEntry
		wantError ErrorCode
	}{
		{
			name:     "missing_utxo",
			prevByte: 0xaa,
			outValue: 1,
			utxosFn: func(prev [32]byte) map[Outpoint]UtxoEntry {
				return map[Outpoint]UtxoEntry{}
			},
			wantError: TX_ERR_MISSING_UTXO,
		},
		{
			name:     "spend_anchor_rejected",
			prevByte: 0xab,
			outValue: 1,
			utxosFn: func(prev [32]byte) map[Outpoint]UtxoEntry {
				return map[Outpoint]UtxoEntry{
					{Txid: prev, Vout: 0}: {
						Value:        1,
						CovenantType: COV_TYPE_ANCHOR,
						CovenantData: []byte{0x01},
					},
				}
			},
			wantError: TX_ERR_MISSING_UTXO,
		},
		{
			name:     "witness_count_zero_rejected",
			prevByte: 0xb0,
			outValue: 90,
			utxosFn: func(prev [32]byte) map[Outpoint]UtxoEntry {
				return map[Outpoint]UtxoEntry{
					{Txid: prev, Vout: 0}: {
						Value:        100,
						CovenantType: COV_TYPE_P2PK,
						CovenantData: validP2PKCovenantData(),
					},
				}
			},
			wantError: TX_ERR_PARSE,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prev [32]byte
			prev[0] = tc.prevByte
			txBytes := txWithOneInputOneOutput(prev, 0, tc.outValue, COV_TYPE_P2PK, validP2PKCovenantData())
			tx, txid := mustParseTxForUtxo(t, txBytes)

			_, err := ApplyNonCoinbaseTxBasic(tx, txid, tc.utxosFn(prev), 200, 1000, [32]byte{})
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != tc.wantError {
				t.Fatalf("code=%s, want %s", got, tc.wantError)
			}
		})
	}
}

func TestApplyNonCoinbaseTxBasic_P2PKValueConservationCases(t *testing.T) {
	var chainID [32]byte
	cases := []struct {
		name      string
		prevByte  byte
		txidByte  byte
		outValue  uint64
		wantErr   ErrorCode
		wantFee   uint64
		wantUTXOs uint64
	}{
		{
			name:     "value_conservation_error",
			prevByte: 0xae,
			txidByte: 0x01,
			outValue: 101,
			wantErr:  TX_ERR_VALUE_CONSERVATION,
		},
		{
			name:      "ok_fee_10",
			prevByte:  0xaf,
			txidByte:  0x02,
			outValue:  90,
			wantFee:   10,
			wantUTXOs: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prev [32]byte
			prev[0] = tc.prevByte
			var txid [32]byte
			txid[0] = tc.txidByte

			kp := mustMLDSA87Keypair(t)
			covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
			tx := &Tx{
				Version:  1,
				TxKind:   0x00,
				TxNonce:  1,
				Inputs:   []TxInput{{PrevTxid: prev, PrevVout: 0}},
				Outputs:  []TxOutput{{Value: tc.outValue, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
				Locktime: 0,
			}
			tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp)}

			utxos := map[Outpoint]UtxoEntry{
				{Txid: prev, Vout: 0}: {
					Value:        100,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: covData,
				},
			}
			s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error")
				}
				if got := mustTxErrCode(t, err); got != tc.wantErr {
					t.Fatalf("code=%s, want %s", got, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s.Fee != tc.wantFee {
				t.Fatalf("fee=%d, want %d", s.Fee, tc.wantFee)
			}
			if s.UtxoCount != tc.wantUTXOs {
				t.Fatalf("utxo_count=%d, want %d", s.UtxoCount, tc.wantUTXOs)
			}
		})
	}
}

func TestApplyNonCoinbaseTxBasic_VaultCannotFundFee(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xc0
	prevFee[0] = 0xc1
	txid[0] = 0xc2

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VALUE_CONSERVATION {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VALUE_CONSERVATION)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultPreservedWithOwnerFeeInput(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xd0
	prevFee[0] = 0xd1
	txid[0] = 0xd2

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee != 10 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultAllowsOwnerTopUp(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xd3
	prevFee[0] = 0xd4
	txid[0] = 0xd5

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 105, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee != 5 {
		t.Fatalf("fee=%d, want 5", s.Fee)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultWhitelistRejectsOutput(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xe0
	prevFee[0] = 0xe1
	txid[0] = 0xe2

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	whitelistedDestKP := mustMLDSA87Keypair(t)
	nonWhitelistedDestKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	whitelistedOutData := p2pkCovenantDataForPubkey(whitelistedDestKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, whitelistedOutData))

	nonWhitelistedOutData := p2pkCovenantDataForPubkey(nonWhitelistedDestKP.PubkeyBytes())

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: nonWhitelistedOutData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultRejectsFeeSponsor(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevOwner, prevSponsor, txid [32]byte
	prevVault[0] = 0xf2
	prevOwner[0] = 0xf3
	prevSponsor[0] = 0xf4
	txid[0] = 0xf5

	ownerKP := mustMLDSA87Keypair(t)
	sponsorKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	sponsorCovData := p2pkCovenantDataForPubkey(sponsorKP.PubkeyBytes())

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	var dummyVaultKeyID [32]byte
	dummyVaultKeyID[0] = 0x11
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{dummyVaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevOwner, PrevVout: 0},
			{PrevTxid: prevSponsor, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL}, // vault slot (not reached; sponsor check fails earlier)
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
		signP2PKInputWitness(t, tx, 2, 10, chainID, sponsorKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevOwner, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
		{Txid: prevSponsor, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: sponsorCovData,
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN)
	}
}

func TestApplyNonCoinbaseTxBasic_MultisigInputAccepted(t *testing.T) {
	var chainID [32]byte
	var prevMS, txid [32]byte
	prevMS[0] = 0xf0
	txid[0] = 0xf1

	msKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	msKeyID := sha3_256(msKP.PubkeyBytes())
	msCovData := encodeMultisigCovenantData(1, [][32]byte{msKeyID})

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())

	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prevMS, PrevVout: 0}},
		Outputs:  []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData}},
		Locktime: 0,
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, msKP)}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevMS, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_MULTISIG,
			CovenantData: msCovData,
		},
	}
	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee != 10 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}
}

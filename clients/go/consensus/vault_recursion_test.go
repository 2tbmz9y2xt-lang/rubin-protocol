package consensus

import "testing"

func TestApplyNonCoinbaseTxBasic_VaultSpendForbidsVaultOutputs(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevOwner, txid [32]byte
	prevVault[0] = 0xd0
	prevOwner[0] = 0xd1
	txid[0] = 0xd2

	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	var dummyVaultKeyID [32]byte
	dummyVaultKeyID[0] = 0x42
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{dummyVaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevOwner, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_VAULT, CovenantData: vaultCovData},
		},
	}
	tx.Witness = []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL}, // vault slot (threshold check is after recursion check)
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
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
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED)
	}
}

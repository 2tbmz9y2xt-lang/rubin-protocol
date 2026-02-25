package consensus

import (
	"testing"
)

func makeKeys(count int, base byte) [][32]byte {
	keys := make([][32]byte, 0, count)
	for i := 0; i < count; i++ {
		var k [32]byte
		k[0] = base + byte(i)
		keys = append(keys, k)
	}
	return keys
}

func encodeVaultCovenantData(ownerLockID [32]byte, threshold uint8, keys [][32]byte, whitelist [][32]byte) []byte {
	b := make([]byte, 0, 32+1+1+len(keys)*32+2+len(whitelist)*32)
	b = append(b, ownerLockID[:]...)
	b = append(b, threshold)
	b = append(b, uint8(len(keys)))
	for _, k := range keys {
		b = append(b, k[:]...)
	}
	b = appendU16le(b, uint16(len(whitelist)))
	for _, h := range whitelist {
		b = append(b, h[:]...)
	}
	return b
}

func encodeMultisigCovenantData(threshold uint8, keys [][32]byte) []byte {
	b := make([]byte, 0, 2+len(keys)*32)
	b = append(b, threshold)
	b = append(b, uint8(len(keys)))
	for _, k := range keys {
		b = append(b, k[:]...)
	}
	return b
}

func validVaultCovenantDataForP2PKOutput() []byte {
	// Destination (whitelisted) output descriptor.
	destData := make([]byte, MAX_P2PK_COVENANT_DATA)
	destData[0] = SUITE_ID_ML_DSA_87
	h := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destData))

	// Owner lock id is the hash of a (possibly different) owner output descriptor.
	ownerData := make([]byte, MAX_P2PK_COVENANT_DATA)
	ownerData[0] = SUITE_ID_ML_DSA_87
	ownerData[1] = 0x01 // make owner descriptor distinct from the whitelisted destination
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerData))

	return encodeVaultCovenantData(ownerLockID, 1, makeKeys(1, 0x11), [][32]byte{h})
}

func TestValidateTxCovenantsGenesis_P2PK_OK(t *testing.T) {
	data := make([]byte, MAX_P2PK_COVENANT_DATA)
	data[0] = SUITE_ID_ML_DSA_87
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: data},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_P2PK_BadSuite(t *testing.T) {
	data := make([]byte, MAX_P2PK_COVENANT_DATA)
	data[0] = SUITE_ID_SLH_DSA_SHAKE_256F
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: data},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}

	if err := ValidateTxCovenantsGenesis(tx, SLH_DSA_ACTIVATION_HEIGHT); err != nil {
		t.Fatalf("unexpected error at activation height: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_Unassigned0001Rejected(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: 0x0001, CovenantData: []byte{0x00}},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateTxCovenantsGenesis_ANCHOR_OK(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: []byte{0x01}},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_ANCHOR_NonZeroValue(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_ANCHOR, CovenantData: []byte{0x01}},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_OK(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: validVaultCovenantDataForP2PKOutput()},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_BadThreshold(t *testing.T) {
	keys := makeKeys(2, 0x11)
	whitelist := makeKeys(1, 0x51)
	var ownerLockID [32]byte
	ownerLockID[0] = 0x99
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 3, keys, whitelist)},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_PARAMS_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_PARAMS_INVALID)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_UnsortedKeys(t *testing.T) {
	keys := makeKeys(2, 0x11)
	keys[0], keys[1] = keys[1], keys[0]
	whitelist := makeKeys(1, 0x51)
	var ownerLockID [32]byte
	ownerLockID[0] = 0x99
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 1, keys, whitelist)},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_KEYS_NOT_CANONICAL {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_KEYS_NOT_CANONICAL)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_UnsortedWhitelist(t *testing.T) {
	keys := makeKeys(1, 0x11)
	whitelist := makeKeys(2, 0x51)
	whitelist[0], whitelist[1] = whitelist[1], whitelist[0]
	var ownerLockID [32]byte
	ownerLockID[0] = 0x99
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 1, keys, whitelist)},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_WHITELIST_NOT_CANONICAL {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_WHITELIST_NOT_CANONICAL)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_EmptyWhitelist(t *testing.T) {
	keys := makeKeys(1, 0x11)
	var ownerLockID [32]byte
	ownerLockID[0] = 0x99
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 1, keys, nil)},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_PARAMS_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_PARAMS_INVALID)
	}
}

func TestValidateTxCovenantsGenesis_MULTISIG_OK(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_MULTISIG, CovenantData: encodeMultisigCovenantData(2, makeKeys(2, 0x31))},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_MULTISIG_BadThreshold(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_MULTISIG, CovenantData: encodeMultisigCovenantData(3, makeKeys(2, 0x31))},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateTxCovenantsGenesis_MULTISIG_UnsortedKeys(t *testing.T) {
	keys := makeKeys(2, 0x31)
	keys[0], keys[1] = keys[1], keys[0]
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_MULTISIG, CovenantData: encodeMultisigCovenantData(1, keys)},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

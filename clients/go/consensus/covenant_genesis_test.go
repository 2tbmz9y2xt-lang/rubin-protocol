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

func TestValidateTxCovenantsGenesis_Table(t *testing.T) {
	validP2PK := make([]byte, MAX_P2PK_COVENANT_DATA)
	validP2PK[0] = SUITE_ID_ML_DSA_87
	keys := makeKeys(2, 0x11)
	oneWhitelist := makeKeys(1, 0x51)
	var ownerLockID [32]byte
	ownerLockID[0] = 0x99
	unsortedKeys := makeKeys(2, 0x11)
	unsortedKeys[0], unsortedKeys[1] = unsortedKeys[1], unsortedKeys[0]
	unsortedWhitelist := makeKeys(2, 0x51)
	unsortedWhitelist[0], unsortedWhitelist[1] = unsortedWhitelist[1], unsortedWhitelist[0]
	unsortedMultisigKeys := makeKeys(2, 0x31)
	unsortedMultisigKeys[0], unsortedMultisigKeys[1] = unsortedMultisigKeys[1], unsortedMultisigKeys[0]

	cases := []struct {
		name    string
		output  TxOutput
		wantErr ErrorCode
	}{
		{
			name:    "p2pk_ok",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PK},
			wantErr: "",
		},
		{
			name:    "unassigned_0001_rejected",
			output:  TxOutput{Value: 1, CovenantType: 0x0001, CovenantData: []byte{0x00}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "anchor_ok",
			output:  TxOutput{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: []byte{0x01}},
			wantErr: "",
		},
		{
			name:    "anchor_nonzero_value",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_ANCHOR, CovenantData: []byte{0x01}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "vault_ok",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: validVaultCovenantDataForP2PKOutput()},
			wantErr: "",
		},
		{
			name:    "vault_bad_threshold",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 3, keys, oneWhitelist)},
			wantErr: TX_ERR_VAULT_PARAMS_INVALID,
		},
		{
			name:    "vault_unsorted_keys",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 1, unsortedKeys, oneWhitelist)},
			wantErr: TX_ERR_VAULT_KEYS_NOT_CANONICAL,
		},
		{
			name:    "vault_unsorted_whitelist",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 1, makeKeys(1, 0x11), unsortedWhitelist)},
			wantErr: TX_ERR_VAULT_WHITELIST_NOT_CANONICAL,
		},
		{
			name:    "vault_empty_whitelist",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_VAULT, CovenantData: encodeVaultCovenantData(ownerLockID, 1, makeKeys(1, 0x11), nil)},
			wantErr: TX_ERR_VAULT_PARAMS_INVALID,
		},
		{
			name:    "multisig_ok",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_MULTISIG, CovenantData: encodeMultisigCovenantData(2, makeKeys(2, 0x31))},
			wantErr: "",
		},
		{
			name:    "multisig_bad_threshold",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_MULTISIG, CovenantData: encodeMultisigCovenantData(3, makeKeys(2, 0x31))},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "multisig_unsorted_keys",
			output:  TxOutput{Value: 1, CovenantType: COV_TYPE_MULTISIG, CovenantData: encodeMultisigCovenantData(1, unsortedMultisigKeys)},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &Tx{Outputs: []TxOutput{tc.output}}
			err := ValidateTxCovenantsGenesis(tx, 0)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != tc.wantErr {
				t.Fatalf("code=%s, want %s", got, tc.wantErr)
			}
		})
	}
}

func TestValidateTxCovenantsGenesis_NilTx(t *testing.T) {
	err := ValidateTxCovenantsGenesis(nil, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestValidateTxCovenantsGenesis_MoreBranches(t *testing.T) {
	validP2PK := make([]byte, MAX_P2PK_COVENANT_DATA)
	validP2PK[0] = SUITE_ID_ML_DSA_87

	invalidP2PKLen := make([]byte, MAX_P2PK_COVENANT_DATA-1)
	invalidP2PKSuite := make([]byte, MAX_P2PK_COVENANT_DATA)
	invalidP2PKSuite[0] = 0xff

	_, _, claimKeyID, refundKeyID := makeSLHKeyMaterial(0x20)
	htlcData := encodeHTLCCovenantData(sha3_256([]byte("x")), LOCK_MODE_HEIGHT, 1, claimKeyID, refundKeyID)

	cases := []struct {
		name    string
		tx      *Tx
		wantErr ErrorCode
	}{
		{
			name:    "p2pk_value_zero",
			tx:      &Tx{Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PK}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "p2pk_len_mismatch",
			tx:      &Tx{Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: invalidP2PKLen}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "p2pk_suite_invalid",
			tx:      &Tx{Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: invalidP2PKSuite}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "anchor_len_zero",
			tx:      &Tx{Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: nil}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "anchor_len_too_large",
			tx:      &Tx{Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: make([]byte, MAX_ANCHOR_PAYLOAD_SIZE+1)}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "vault_value_zero",
			tx:      &Tx{Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_VAULT, CovenantData: validVaultCovenantDataForP2PKOutput()}}},
			wantErr: TX_ERR_VAULT_PARAMS_INVALID,
		},
		{
			name:    "multisig_value_zero",
			tx:      &Tx{Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_MULTISIG, CovenantData: encodeMultisigCovenantData(1, makeKeys(1, 0x31))}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "htlc_value_zero",
			tx:      &Tx{Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_HTLC, CovenantData: htlcData}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "reserved_future_rejected",
			tx:      &Tx{Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_RESERVED_FUTURE, CovenantData: []byte{0x00}}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
		{
			name:    "unknown_covenant_type_rejected",
			tx:      &Tx{Outputs: []TxOutput{{Value: 1, CovenantType: 0xffff, CovenantData: []byte{0x00}}}},
			wantErr: TX_ERR_COVENANT_TYPE_INVALID,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTxCovenantsGenesis(tc.tx, 0)
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != tc.wantErr {
				t.Fatalf("code=%s, want %s", got, tc.wantErr)
			}
		})
	}
}

func TestValidateTxCovenantsGenesis_DACommitRules(t *testing.T) {
	var cov32 [32]byte
	valid := TxOutput{Value: 0, CovenantType: COV_TYPE_DA_COMMIT, CovenantData: cov32[:]}

	// tx_kind must be 0x01
	{
		tx := &Tx{TxKind: 0x00, Outputs: []TxOutput{valid}}
		err := ValidateTxCovenantsGenesis(tx, 0)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
		}
	}

	// value must be 0
	{
		out := valid
		out.Value = 1
		tx := &Tx{TxKind: 0x01, Outputs: []TxOutput{out}}
		err := ValidateTxCovenantsGenesis(tx, 0)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
		}
	}

	// covenant_data length must be 32
	{
		out := valid
		out.CovenantData = make([]byte, 31)
		tx := &Tx{TxKind: 0x01, Outputs: []TxOutput{out}}
		err := ValidateTxCovenantsGenesis(tx, 0)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
		}
	}

	// ok
	{
		tx := &Tx{TxKind: 0x01, Outputs: []TxOutput{valid}}
		if err := ValidateTxCovenantsGenesis(tx, 0); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

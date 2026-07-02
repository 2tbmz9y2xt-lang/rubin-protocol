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
	b = AppendU16le(b, uint16(len(whitelist)))
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

func encodeSimplicityCovenantData(programCMR [32]byte, state []byte) []byte {
	b := make([]byte, 0, 32+len(EncodeCompactSize(uint64(len(state))))+len(state))
	b = append(b, programCMR[:]...)
	b = AppendCompactSize(b, uint64(len(state)))
	b = append(b, state...)
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
	data[0] = 0x02 // non-native/unknown suite
	tx := &Tx{
		Outputs: []TxOutput{
			{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: data},
		},
	}
	err := ValidateTxCovenantsGenesis(tx, 0, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
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
		wantErr ErrorCode
		output  TxOutput
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
			err := ValidateTxCovenantsGenesis(tx, 0, nil)
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

func TestValidateTxCovenantsGenesis_CoreSimplicityActive(t *testing.T) {
	provider := testRotationProvider{createSuiteID: SUITE_ID_ML_DSA_87, simplicityActiveHeight: 10}
	var cmr [32]byte
	cmr[0] = 0xa5
	valid := encodeSimplicityCovenantData(cmr, []byte{0x01, 0x02})
	trailing := append(append([]byte(nil), valid...), 0xff)
	nonMinimal := append(append([]byte(nil), cmr[:]...), 0xfd, 0xfc, 0x00)
	nonMinimal = append(nonMinimal, make([]byte, 0xfc)...)
	out := func(value uint64, data []byte) TxOutput {
		return TxOutput{Value: value, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: data}
	}

	check := func(height uint64, rotation RotationProvider, output TxOutput, want ErrorCode) {
		t.Helper()
		err := ValidateTxCovenantsGenesis(&Tx{Outputs: []TxOutput{output}}, height, rotation)
		if want == "" {
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		assertTxErrCode(t, err, want)
	}

	check(10, provider, out(1, encodeSimplicityCovenantData(cmr, nil)), "")
	check(10, provider, out(1, encodeSimplicityCovenantData(cmr, make([]byte, MAX_SIMPLICITY_STATE_BYTES))), "")
	check(9, provider, out(1, valid), TX_ERR_COVENANT_TYPE_INVALID)
	check(10, nil, out(1, valid), TX_ERR_COVENANT_TYPE_INVALID)
	check(10, DescriptorRotationProvider{Descriptor: CryptoRotationDescriptor{
		Name:         "crypto-only",
		OldSuiteID:   SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x02,
		CreateHeight: 10,
		SpendHeight:  20,
	}}, out(1, valid), TX_ERR_COVENANT_TYPE_INVALID)
	check(10, provider, out(0, valid), TX_ERR_COVENANT_TYPE_INVALID)
	check(10, provider, out(1, encodeSimplicityCovenantData(cmr, make([]byte, MAX_SIMPLICITY_STATE_BYTES+1))), TX_ERR_COVENANT_TYPE_INVALID)
	check(10, provider, out(1, trailing), TX_ERR_COVENANT_TYPE_INVALID)
	check(10, provider, out(1, valid[:len(valid)-1]), TX_ERR_COVENANT_TYPE_INVALID)
	check(10, provider, out(1, nonMinimal), TX_ERR_COVENANT_TYPE_INVALID)

	// Same-program_cmr CORE_SIMPLICITY outputs are capped at
	// SIMPLICITY_MAX_GROUP_OUTPUTS on the live creation/apply path (RUB-594):
	// exactly the cap passes, one more is rejected atomically, and distinct
	// program_cmr groups are counted independently.
	var cmr2 [32]byte
	cmr2[0] = 0x5a
	sameCMR := func(n int, c [32]byte) []TxOutput {
		outs := make([]TxOutput, n)
		for i := range outs {
			outs[i] = out(1, encodeSimplicityCovenantData(c, nil))
		}
		return outs
	}
	if err := ValidateTxCovenantsGenesis(&Tx{Outputs: sameCMR(SIMPLICITY_MAX_GROUP_OUTPUTS, cmr)}, 10, provider); err != nil {
		t.Fatalf("exactly SIMPLICITY_MAX_GROUP_OUTPUTS same-cmr outputs must pass: %v", err)
	}
	assertTxErrCode(t, ValidateTxCovenantsGenesis(&Tx{Outputs: sameCMR(SIMPLICITY_MAX_GROUP_OUTPUTS+1, cmr)}, 10, provider), TX_ERR_COVENANT_TYPE_INVALID)
	mixed := append(sameCMR(SIMPLICITY_MAX_GROUP_OUTPUTS, cmr), sameCMR(SIMPLICITY_MAX_GROUP_OUTPUTS, cmr2)...)
	if err := ValidateTxCovenantsGenesis(&Tx{Outputs: mixed}, 10, provider); err != nil {
		t.Fatalf("distinct program_cmr groups must not aggregate: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_NilTx(t *testing.T) {
	err := ValidateTxCovenantsGenesis(nil, 0, nil)
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

	_, _, claimKeyID, refundKeyID := makeMLKeyMaterial(0x20)
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
			wantErr: TX_ERR_SIG_ALG_INVALID,
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
			err := ValidateTxCovenantsGenesis(tc.tx, 0, nil)
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
		err := ValidateTxCovenantsGenesis(tx, 0, nil)
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
		err := ValidateTxCovenantsGenesis(tx, 0, nil)
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
		err := ValidateTxCovenantsGenesis(tx, 0, nil)
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
		if err := ValidateTxCovenantsGenesis(tx, 0, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

// testRotationProvider is a RotationProvider that allows only the specified
// suite ID for creation. Used to test that ValidateTxCovenantsGenesis
// respects the rotation provider rather than hardcoding ML-DSA-87.
type testRotationProvider struct {
	createSuiteID          uint8
	simplicityActiveHeight uint64
}

func (p testRotationProvider) NativeCreateSuites(height uint64) *NativeSuiteSet {
	return mustNewNativeSuiteSet(p.createSuiteID)
}

func (p testRotationProvider) NativeSpendSuites(height uint64) *NativeSuiteSet {
	return mustNewNativeSuiteSet(p.createSuiteID)
}

func (p testRotationProvider) SimplicityActiveAtHeight(height uint64) (bool, error) {
	return height >= p.simplicityActiveHeight, nil
}

func TestValidateTxCovenantsGenesis_RotationAware(t *testing.T) {
	// A rotation provider that accepts only suite 0x42, NOT ML-DSA-87 (0x01).
	rot := testRotationProvider{createSuiteID: 0x42}

	// P2PK with ML-DSA-87 should be REJECTED under this rotation.
	mlDSA := make([]byte, MAX_P2PK_COVENANT_DATA)
	mlDSA[0] = SUITE_ID_ML_DSA_87
	tx := &Tx{Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: mlDSA}}}
	err := ValidateTxCovenantsGenesis(tx, 0, rot)
	if err == nil {
		t.Fatalf("expected ML-DSA-87 to be rejected by custom rotation")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}

	// P2PK with suite 0x42 should be ACCEPTED under this rotation.
	custom := make([]byte, MAX_P2PK_COVENANT_DATA)
	custom[0] = 0x42
	tx2 := &Tx{Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: custom}}}
	if err := ValidateTxCovenantsGenesis(tx2, 0, rot); err != nil {
		t.Fatalf("expected suite 0x42 to be accepted: %v", err)
	}
}

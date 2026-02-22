package consensus

import "testing"

func TestValidateTxCovenantsGenesis_P2PK_OK(t *testing.T) {
	data := make([]byte, MAX_P2PK_COVENANT_DATA)
	data[0] = SUITE_ID_ML_DSA_87
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: data,
			},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_P2PK_BadSuite(t *testing.T) {
	data := make([]byte, MAX_P2PK_COVENANT_DATA)
	data[0] = SUITE_ID_SLH_DSA_SHAKE_256F
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: data,
			},
		},
	}
	err := ValidateTxCovenantsGenesis(tx)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateTxCovenantsGenesis_TIMELOCK_OK(t *testing.T) {
	data := make([]byte, MAX_TIMELOCK_COVENANT_DATA)
	data[0] = 0x00
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_TIMELOCK,
				CovenantData: data,
			},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_TIMELOCK_BadMode(t *testing.T) {
	data := make([]byte, MAX_TIMELOCK_COVENANT_DATA)
	data[0] = 0x02
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_TIMELOCK,
				CovenantData: data,
			},
		},
	}
	err := ValidateTxCovenantsGenesis(tx)
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
			{
				Value:        0,
				CovenantType: COV_TYPE_ANCHOR,
				CovenantData: []byte{0x01},
			},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_ANCHOR_NonZeroValue(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_ANCHOR,
				CovenantData: []byte{0x01},
			},
		},
	}
	err := ValidateTxCovenantsGenesis(tx)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_ReservedUntilQV01(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_VAULT,
				CovenantData: []byte{0x00},
			},
		},
	}
	err := ValidateTxCovenantsGenesis(tx)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func vaultCovenantData(extended bool, spendDelay uint64, lockMode byte, lockValue uint64, sameKeys bool) []byte {
	owner := bytes.Repeat([]byte{0x11}, 32)
	recovery := bytes.Repeat([]byte{0x22}, 32)
	if sameKeys {
		recovery = owner
	}
	if !extended {
		b := make([]byte, 0, MAX_VAULT_COVENANT_LEGACY)
		b = append(b, owner...)
		b = append(b, lockMode)
		var lock [8]byte
		binary.LittleEndian.PutUint64(lock[:], lockValue)
		b = append(b, lock[:]...)
		b = append(b, recovery...)
		return b
	}

	b := make([]byte, 0, MAX_VAULT_COVENANT_DATA)
	b = append(b, owner...)
	var delay [8]byte
	binary.LittleEndian.PutUint64(delay[:], spendDelay)
	b = append(b, delay[:]...)
	b = append(b, lockMode)
	var lock [8]byte
	binary.LittleEndian.PutUint64(lock[:], lockValue)
	b = append(b, lock[:]...)
	b = append(b, recovery...)
	return b
}

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

func TestValidateTxCovenantsGenesis_VAULT_LegacyOK(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_VAULT,
				CovenantData: vaultCovenantData(false, 0, 0x00, 100, false),
			},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_ExtendedOK(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_VAULT,
				CovenantData: vaultCovenantData(true, MIN_VAULT_SPEND_DELAY, 0x01, 1_700_000_000, false),
			},
		},
	}
	if err := ValidateTxCovenantsGenesis(tx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTxCovenantsGenesis_VAULT_BadDelay(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_VAULT,
				CovenantData: vaultCovenantData(true, MIN_VAULT_SPEND_DELAY-1, 0x00, 100, false),
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

func TestValidateTxCovenantsGenesis_VAULT_OwnerRecoveryEqual(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_VAULT,
				CovenantData: vaultCovenantData(true, MIN_VAULT_SPEND_DELAY, 0x00, 100, true),
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

func TestValidateTxCovenantsGenesis_VAULT_BadLockMode(t *testing.T) {
	tx := &Tx{
		Outputs: []TxOutput{
			{
				Value:        1,
				CovenantType: COV_TYPE_VAULT,
				CovenantData: vaultCovenantData(false, 0, 0x02, 100, false),
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

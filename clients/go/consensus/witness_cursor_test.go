package consensus

import (
	"encoding/binary"
	"errors"
	"testing"
)

// --------------- covenant data builders (test-only) ---------------

func wcP2PKEntry(value uint64) UtxoEntry {
	b := make([]byte, MAX_P2PK_COVENANT_DATA)
	b[0] = SUITE_ID_ML_DSA_87
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_P2PK, CovenantData: b}
}

func wcHTLCEntry(value uint64) UtxoEntry {
	// HTLC covenant data: hash[32] || lock_mode[1] || lock_value[8] || claim_key[32] || refund_key[32]
	data := make([]byte, 105)
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_HTLC, CovenantData: data}
}

func wcMultisigEntry(value uint64, threshold, keyCount uint8) UtxoEntry {
	// multisig: threshold[1] || key_count[1] || key_ids[key_count*32]
	data := make([]byte, 2+int(keyCount)*32)
	data[0] = threshold
	data[1] = keyCount
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_MULTISIG, CovenantData: data}
}

func wcVaultEntry(value uint64, threshold, keyCount uint8) UtxoEntry {
	// vault: owner_lock_id[32] || threshold[1] || key_count[1] || keys...
	data := make([]byte, 34+int(keyCount)*32)
	data[32] = threshold
	data[33] = keyCount
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_VAULT, CovenantData: data}
}

func wcCoreExtEntry(value uint64, extID uint16) UtxoEntry {
	b := make([]byte, 3)
	binary.LittleEndian.PutUint16(b[0:2], extID)
	b[2] = 0x00
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_CORE_EXT, CovenantData: b}
}

func wcCoreStealthEntry(value uint64) UtxoEntry {
	data := make([]byte, MAX_STEALTH_COVENANT_DATA)
	return UtxoEntry{Value: value, CovenantType: COV_TYPE_CORE_STEALTH, CovenantData: data}
}

func dummyWitnessItems(n int) []WitnessItem {
	items := make([]WitnessItem, n)
	for i := range items {
		items[i] = WitnessItem{SuiteID: SUITE_ID_ML_DSA_87}
	}
	return items
}

func makeCursorTx(inputs []TxInput, witnessCount int) *Tx {
	return &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  inputs,
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: make([]byte, MAX_P2PK_COVENANT_DATA)}},
		Witness: dummyWitnessItems(witnessCount),
	}
}

func oneInput() []TxInput {
	var prev [32]byte
	prev[0] = 0xAA
	return []TxInput{{PrevTxid: prev, PrevVout: 0}}
}

func nInputs(n int) []TxInput {
	inputs := make([]TxInput, n)
	for i := range inputs {
		var prev [32]byte
		prev[0] = byte(i + 1)
		inputs[i] = TxInput{PrevTxid: prev, PrevVout: uint32(i)}
	}
	return inputs
}

// --------------- tests ---------------

func TestComputeWitnessAssignments_SingleP2PK(t *testing.T) {
	tx := makeCursorTx(oneInput(), 1)
	entries := []UtxoEntry{wcP2PKEntry(100)}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d, want 1", total)
	}
	if len(assigns) != 1 {
		t.Fatalf("len=%d, want 1", len(assigns))
	}
	a := assigns[0]
	if a.Start != 0 || a.End != 1 || a.Slots != 1 {
		t.Fatalf("P2PK: got Start=%d End=%d Slots=%d, want 0,1,1", a.Start, a.End, a.Slots)
	}
}

func TestComputeWitnessAssignments_SingleHTLC(t *testing.T) {
	tx := makeCursorTx(oneInput(), 2)
	entries := []UtxoEntry{wcHTLCEntry(100)}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Fatalf("total=%d, want 2", total)
	}
	a := assigns[0]
	if a.Start != 0 || a.End != 2 || a.Slots != 2 {
		t.Fatalf("HTLC: got Start=%d End=%d Slots=%d, want 0,2,2", a.Start, a.End, a.Slots)
	}
}

func TestComputeWitnessAssignments_SingleMultisig(t *testing.T) {
	tx := makeCursorTx(oneInput(), 3)
	entries := []UtxoEntry{wcMultisigEntry(100, 2, 3)}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 3 {
		t.Fatalf("total=%d, want 3", total)
	}
	a := assigns[0]
	if a.Start != 0 || a.End != 3 || a.Slots != 3 {
		t.Fatalf("MULTISIG(3): got Start=%d End=%d Slots=%d, want 0,3,3", a.Start, a.End, a.Slots)
	}
}

func TestComputeWitnessAssignments_SingleVault(t *testing.T) {
	tx := makeCursorTx(oneInput(), 2)
	entries := []UtxoEntry{wcVaultEntry(100, 1, 2)}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Fatalf("total=%d, want 2", total)
	}
	a := assigns[0]
	if a.Start != 0 || a.End != 2 || a.Slots != 2 {
		t.Fatalf("VAULT(2): got Start=%d End=%d Slots=%d, want 0,2,2", a.Start, a.End, a.Slots)
	}
}

func TestComputeWitnessAssignments_SingleCoreExt(t *testing.T) {
	tx := makeCursorTx(oneInput(), 1)
	entries := []UtxoEntry{wcCoreExtEntry(100, 0x0001)}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d, want 1", total)
	}
	a := assigns[0]
	if a.Start != 0 || a.End != 1 || a.Slots != 1 {
		t.Fatalf("CORE_EXT: got Start=%d End=%d Slots=%d, want 0,1,1", a.Start, a.End, a.Slots)
	}
}

func TestComputeWitnessAssignments_SingleCoreStealth(t *testing.T) {
	tx := makeCursorTx(oneInput(), 1)
	entries := []UtxoEntry{wcCoreStealthEntry(100)}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d, want 1", total)
	}
	a := assigns[0]
	if a.Start != 0 || a.End != 1 || a.Slots != 1 {
		t.Fatalf("CORE_STEALTH: got Start=%d End=%d Slots=%d, want 0,1,1", a.Start, a.End, a.Slots)
	}
}

// Mixed covenant families — verifies cursor advances correctly across types.
func TestComputeWitnessAssignments_MixedCovenants(t *testing.T) {
	// 4 inputs: P2PK(1) + HTLC(2) + MULTISIG(3) + CORE_EXT(1) = 7 total
	inputs := nInputs(4)
	tx := makeCursorTx(inputs, 7)
	entries := []UtxoEntry{
		wcP2PKEntry(100),
		wcHTLCEntry(50),
		wcMultisigEntry(200, 2, 3),
		wcCoreExtEntry(10, 0x0001),
	}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 7 {
		t.Fatalf("total=%d, want 7", total)
	}
	if len(assigns) != 4 {
		t.Fatalf("len=%d, want 4", len(assigns))
	}

	// P2PK: [0,1)
	if assigns[0].Start != 0 || assigns[0].End != 1 {
		t.Fatalf("P2PK: [%d,%d), want [0,1)", assigns[0].Start, assigns[0].End)
	}
	// HTLC: [1,3)
	if assigns[1].Start != 1 || assigns[1].End != 3 {
		t.Fatalf("HTLC: [%d,%d), want [1,3)", assigns[1].Start, assigns[1].End)
	}
	// MULTISIG: [3,6)
	if assigns[2].Start != 3 || assigns[2].End != 6 {
		t.Fatalf("MULTISIG: [%d,%d), want [3,6)", assigns[2].Start, assigns[2].End)
	}
	// CORE_EXT: [6,7)
	if assigns[3].Start != 6 || assigns[3].End != 7 {
		t.Fatalf("CORE_EXT: [%d,%d), want [6,7)", assigns[3].Start, assigns[3].End)
	}
}

// All 6 covenant families in one tx.
func TestComputeWitnessAssignments_AllCovenantFamilies(t *testing.T) {
	// P2PK(1) + HTLC(2) + MULTISIG(2) + VAULT(3) + CORE_EXT(1) + STEALTH(1) = 10
	inputs := nInputs(6)
	tx := makeCursorTx(inputs, 10)
	entries := []UtxoEntry{
		wcP2PKEntry(100),
		wcHTLCEntry(50),
		wcMultisigEntry(200, 1, 2),
		wcVaultEntry(300, 2, 3),
		wcCoreExtEntry(10, 0x0001),
		wcCoreStealthEntry(25),
	}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 10 {
		t.Fatalf("total=%d, want 10", total)
	}
	if len(assigns) != 6 {
		t.Fatalf("len=%d, want 6", len(assigns))
	}

	expected := [][2]int{{0, 1}, {1, 3}, {3, 5}, {5, 8}, {8, 9}, {9, 10}}
	for i, exp := range expected {
		if assigns[i].Start != exp[0] || assigns[i].End != exp[1] {
			t.Fatalf("input[%d]: [%d,%d), want [%d,%d)", i, assigns[i].Start, assigns[i].End, exp[0], exp[1])
		}
	}
}

// Error: witness underflow (not enough witness items).
func TestComputeWitnessAssignments_WitnessUnderflow(t *testing.T) {
	tx := makeCursorTx(oneInput(), 0) // 0 witness items but P2PK needs 1
	entries := []UtxoEntry{wcP2PKEntry(100)}

	_, _, err := ComputeWitnessAssignments(tx, entries)
	if err == nil {
		t.Fatal("expected error for witness underflow")
	}
	assertTxErrCode(t, err, TX_ERR_PARSE)
}

// Error: resolvedInputs length mismatch.
func TestComputeWitnessAssignments_LengthMismatch(t *testing.T) {
	tx := makeCursorTx(nInputs(2), 2)
	entries := []UtxoEntry{wcP2PKEntry(100)} // only 1 entry for 2 inputs

	_, _, err := ComputeWitnessAssignments(tx, entries)
	if err == nil {
		t.Fatal("expected error for length mismatch")
	}
	assertTxErrCode(t, err, TX_ERR_PARSE)
}

// Error: unsupported covenant type.
func TestComputeWitnessAssignments_UnsupportedCovenant(t *testing.T) {
	tx := makeCursorTx(oneInput(), 1)
	entries := []UtxoEntry{{Value: 100, CovenantType: 0xFFFF, CovenantData: nil}}

	_, _, err := ComputeWitnessAssignments(tx, entries)
	if err == nil {
		t.Fatal("expected error for unsupported covenant")
	}
	assertTxErrCode(t, err, TX_ERR_COVENANT_TYPE_INVALID)
}

// Parity: ComputeWitnessAssignments matches sequential cursor for mixed tx.
func TestComputeWitnessAssignments_ParityWithSequentialCursor(t *testing.T) {
	// Simulate the sequential cursor model manually for:
	// P2PK(1) + HTLC(2) + VAULT(2) = 5 witness items
	inputs := nInputs(3)
	tx := makeCursorTx(inputs, 5)
	entries := []UtxoEntry{
		wcP2PKEntry(100),
		wcHTLCEntry(50),
		wcVaultEntry(300, 1, 2),
	}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manual sequential cursor simulation.
	cursor := 0
	for i, entry := range entries {
		slots, _ := WitnessSlots(entry.CovenantType, entry.CovenantData)
		if assigns[i].Start != cursor {
			t.Fatalf("input[%d]: Start=%d, sequential cursor=%d", i, assigns[i].Start, cursor)
		}
		if assigns[i].Slots != slots {
			t.Fatalf("input[%d]: Slots=%d, WitnessSlots=%d", i, assigns[i].Slots, slots)
		}
		cursor += slots
	}
	if total != cursor {
		t.Fatalf("total=%d, cursor=%d", total, cursor)
	}
}

// Partial consumption: total < len(tx.Witness) is allowed; caller checks.
func TestComputeWitnessAssignments_PartialConsumption(t *testing.T) {
	tx := makeCursorTx(oneInput(), 5) // 5 items but P2PK only needs 1
	entries := []UtxoEntry{wcP2PKEntry(100)}

	assigns, total, err := ComputeWitnessAssignments(tx, entries)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 1 {
		t.Fatalf("total=%d, want 1", total)
	}
	if assigns[0].End != 1 {
		t.Fatalf("End=%d, want 1", assigns[0].End)
	}
}

// Dynamic MULTISIG key_count variations.
func TestComputeWitnessAssignments_MultisigKeyCountVariants(t *testing.T) {
	tests := []struct {
		name      string
		threshold uint8
		keyCount  uint8
	}{
		{"1-of-1", 1, 1},
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"5-of-7", 5, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeCursorTx(oneInput(), int(tt.keyCount))
			entries := []UtxoEntry{wcMultisigEntry(100, tt.threshold, tt.keyCount)}

			assigns, total, err := ComputeWitnessAssignments(tx, entries)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if total != int(tt.keyCount) {
				t.Fatalf("total=%d, want %d", total, tt.keyCount)
			}
			if assigns[0].Slots != int(tt.keyCount) {
				t.Fatalf("Slots=%d, want %d", assigns[0].Slots, tt.keyCount)
			}
		})
	}
}

// Dynamic VAULT key_count variations.
func TestComputeWitnessAssignments_VaultKeyCountVariants(t *testing.T) {
	tests := []struct {
		name      string
		threshold uint8
		keyCount  uint8
	}{
		{"1-of-1", 1, 1},
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := makeCursorTx(oneInput(), int(tt.keyCount))
			entries := []UtxoEntry{wcVaultEntry(100, tt.threshold, tt.keyCount)}

			assigns, total, err := ComputeWitnessAssignments(tx, entries)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if total != int(tt.keyCount) {
				t.Fatalf("total=%d, want %d", total, tt.keyCount)
			}
			if assigns[0].Slots != int(tt.keyCount) {
				t.Fatalf("Slots=%d, want %d", assigns[0].Slots, tt.keyCount)
			}
		})
	}
}

func assertTxErrCode(t *testing.T, err error, expected ErrorCode) {
	t.Helper()
	var te *TxError
	if !errors.As(err, &te) {
		t.Fatalf("expected TxError, got %T: %v", err, err)
	}
	if te.Code != expected {
		t.Fatalf("error code=%q, want %q", te.Code, expected)
	}
}

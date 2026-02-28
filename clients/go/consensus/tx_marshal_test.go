package consensus

import (
	"bytes"
	"testing"
)

func TestMarshalTx_NilReturnsError(t *testing.T) {
	_, err := MarshalTx(nil)
	if err == nil {
		t.Fatalf("expected error for nil tx")
	}
}

func TestMarshalTx_MinimalRoundtrip(t *testing.T) {
	tx := &Tx{Version: 1, TxKind: 0x00, TxNonce: 0}
	b, err := MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}

	parsed, _, _, n, err := ParseTx(b)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if n != len(b) {
		t.Fatalf("consumed %d, want %d", n, len(b))
	}
	if parsed.Version != tx.Version || parsed.TxKind != tx.TxKind || parsed.TxNonce != tx.TxNonce {
		t.Fatalf("header mismatch")
	}
}

func TestMarshalTx_WithInputsOutputs(t *testing.T) {
	prevTxid := [32]byte{0x01, 0x02, 0x03}
	tx := &Tx{
		Version: 1,
		TxKind:  0x00, // standard tx (kind=0x01/0x02 have DA core fields not handled by MarshalTx)
		TxNonce: 42,
		Inputs: []TxInput{
			{PrevTxid: prevTxid, PrevVout: 7, ScriptSig: []byte{0xaa, 0xbb}, Sequence: 0xffffffff},
		},
		Outputs: []TxOutput{
			{Value: 50_000, CovenantType: 0, CovenantData: nil},
			{Value: 10_000, CovenantType: 1, CovenantData: []byte{0xcc}},
		},
		Locktime: 100,
	}

	b, err := MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}

	parsed, _, _, n, err := ParseTx(b)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if n != len(b) {
		t.Fatalf("consumed %d, want %d", n, len(b))
	}
	if len(parsed.Inputs) != 1 {
		t.Fatalf("inputs: got %d, want 1", len(parsed.Inputs))
	}
	if parsed.Inputs[0].PrevTxid != prevTxid {
		t.Fatalf("prevTxid mismatch")
	}
	if len(parsed.Outputs) != 2 {
		t.Fatalf("outputs: got %d, want 2", len(parsed.Outputs))
	}
	if parsed.Outputs[0].Value != 50_000 {
		t.Fatalf("output[0] value: got %d", parsed.Outputs[0].Value)
	}
	if parsed.Locktime != 100 {
		t.Fatalf("locktime: got %d", parsed.Locktime)
	}
}

func TestMarshalTx_EmptyDaPayload(t *testing.T) {
	// tx_kind=0x00 requires da_payload_len=0.
	tx := &Tx{
		Version:   1,
		TxKind:    0x00,
		DaPayload: nil,
	}

	b, err := MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}

	parsed, _, _, n, err := ParseTx(b)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if n != len(b) {
		t.Fatalf("consumed %d, want %d", n, len(b))
	}
	if len(parsed.DaPayload) != 0 {
		t.Fatalf("DaPayload should be empty, got %x", parsed.DaPayload)
	}
}

func TestMarshalTx_ParseRoundtripEquality(t *testing.T) {
	// Parse reference minimal bytes, then marshal back and compare.
	ref := minimalTxBytes()
	parsed, _, _, n, err := ParseTx(ref)
	if err != nil {
		t.Fatalf("ParseTx(ref): %v", err)
	}
	if n != len(ref) {
		t.Fatalf("consumed %d, want %d", n, len(ref))
	}

	b, err := MarshalTx(parsed)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	if !bytes.Equal(b, ref) {
		t.Fatalf("roundtrip mismatch:\n  got  %x\n  want %x", b, ref)
	}
}

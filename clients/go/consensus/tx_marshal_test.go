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

func TestMarshalTx_DACommitRoundtrip(t *testing.T) {
	tx := &Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: 7,
		DaCommitCore: &DaCommitCore{
			DaID:            [32]byte{0x10},
			ChunkCount:      1,
			RetlDomainID:    [32]byte{0x20},
			BatchNumber:     9,
			TxDataRoot:      [32]byte{0x30},
			StateRoot:       [32]byte{0x40},
			WithdrawalsRoot: [32]byte{0x50},
			BatchSigSuite:   0x00,
			BatchSig:        []byte{0xaa, 0xbb},
		},
		DaPayload: []byte{0xde, 0xad, 0xbe, 0xef},
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
	if parsed.DaCommitCore == nil {
		t.Fatalf("DaCommitCore is nil after roundtrip")
	}
	if parsed.DaCommitCore.ChunkCount != 1 {
		t.Fatalf("chunk_count: got %d, want 1", parsed.DaCommitCore.ChunkCount)
	}
	if !bytes.Equal(parsed.DaPayload, tx.DaPayload) {
		t.Fatalf("da payload mismatch: got %x, want %x", parsed.DaPayload, tx.DaPayload)
	}
}

func TestMarshalTx_DAChunkRoundtrip(t *testing.T) {
	tx := &Tx{
		Version: 1,
		TxKind:  0x02,
		TxNonce: 9,
		DaChunkCore: &DaChunkCore{
			DaID:       [32]byte{0x11},
			ChunkIndex: 0,
			ChunkHash:  [32]byte{0x22},
		},
		DaPayload: []byte{0x01},
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
	if parsed.DaChunkCore == nil {
		t.Fatalf("DaChunkCore is nil after roundtrip")
	}
	if parsed.DaChunkCore.ChunkIndex != 0 {
		t.Fatalf("chunk_index: got %d, want 0", parsed.DaChunkCore.ChunkIndex)
	}
	if !bytes.Equal(parsed.DaPayload, tx.DaPayload) {
		t.Fatalf("da payload mismatch: got %x, want %x", parsed.DaPayload, tx.DaPayload)
	}
}

func TestMarshalTx_DAKindMissingCoreError(t *testing.T) {
	txCommit := &Tx{Version: 1, TxKind: 0x01, DaPayload: []byte{0x01}}
	if _, err := MarshalTx(txCommit); err == nil {
		t.Fatalf("expected error when tx_kind=0x01 has no DaCommitCore")
	}

	txChunk := &Tx{Version: 1, TxKind: 0x02, DaPayload: []byte{0x01}}
	if _, err := MarshalTx(txChunk); err == nil {
		t.Fatalf("expected error when tx_kind=0x02 has no DaChunkCore")
	}
}

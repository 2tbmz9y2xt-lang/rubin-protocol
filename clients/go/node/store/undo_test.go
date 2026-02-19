package store

import (
	"bytes"
	"testing"

	"rubin.dev/node/consensus"
)

func TestUndoRecord_RoundTrip(t *testing.T) {
	var txid [32]byte
	txid[0] = 9
	p := consensus.TxOutPoint{TxID: txid, Vout: 1}

	u := UndoRecord{
		Spent: []UndoSpent{
			{
				OutPoint: p,
				RestoredEntry: consensus.UtxoEntry{
					Output: consensus.TxOutput{
						Value:        1,
						CovenantType: 0,
						CovenantData: []byte{},
					},
					CreationHeight:    0,
					CreatedByCoinbase: false,
				},
			},
		},
		Created: []consensus.TxOutPoint{p},
	}

	b, err := encodeUndoRecord(u)
	if err != nil {
		t.Fatalf("encodeUndoRecord: %v", err)
	}
	got, err := decodeUndoRecord(b)
	if err != nil {
		t.Fatalf("decodeUndoRecord: %v", err)
	}
	if got == nil || len(got.Spent) != 1 || len(got.Created) != 1 {
		t.Fatalf("unexpected decoded undo: %+v", got)
	}
	if got.Spent[0].OutPoint != p || got.Created[0] != p {
		t.Fatalf("outpoint mismatch")
	}
	if got.Spent[0].RestoredEntry.Output.Value != 1 {
		t.Fatalf("restored entry mismatch")
	}

	// Trailing bytes should be rejected.
	bad := append(append([]byte(nil), b...), 0x00)
	if _, err := decodeUndoRecord(bad); err == nil {
		t.Fatalf("expected trailing bytes error")
	}
	// Truncated should be rejected.
	if _, err := decodeUndoRecord(b[:len(b)-1]); err == nil {
		t.Fatalf("expected truncated error")
	}
	// Ensure stable encoding for the same input.
	b2, err := encodeUndoRecord(u)
	if err != nil {
		t.Fatalf("encodeUndoRecord 2: %v", err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("encoding not deterministic")
	}
}

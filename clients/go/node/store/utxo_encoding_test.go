package store

import (
	"bytes"
	"testing"

	"rubin.dev/node/consensus"
)

func TestOutpointKey_RoundTrip(t *testing.T) {
	var txid [32]byte
	txid[0] = 1
	txid[31] = 2
	p := consensus.TxOutPoint{TxID: txid, Vout: 7}
	k := encodeOutpointKey(p)
	got, err := decodeOutpointKey(k)
	if err != nil {
		t.Fatalf("decodeOutpointKey: %v", err)
	}
	if got != p {
		t.Fatalf("roundtrip mismatch")
	}
	if _, err := decodeOutpointKey(k[:10]); err == nil {
		t.Fatalf("expected length error")
	}
}

func TestUtxoEntry_RoundTripAndBounds(t *testing.T) {
	e := consensus.UtxoEntry{
		Output: consensus.TxOutput{
			Value:        42,
			CovenantType: 0x0101,
			CovenantData: []byte{0xaa, 0xbb, 0xcc},
		},
		CreationHeight:    9,
		CreatedByCoinbase: true,
	}
	b, err := encodeUtxoEntry(e)
	if err != nil {
		t.Fatalf("encodeUtxoEntry: %v", err)
	}
	got, err := decodeUtxoEntry(b)
	if err != nil {
		t.Fatalf("decodeUtxoEntry: %v", err)
	}
	if got.Output.Value != e.Output.Value ||
		got.Output.CovenantType != e.Output.CovenantType ||
		!bytes.Equal(got.Output.CovenantData, e.Output.CovenantData) ||
		got.CreationHeight != e.CreationHeight ||
		got.CreatedByCoinbase != e.CreatedByCoinbase {
		t.Fatalf("decoded entry mismatch: got=%+v want=%+v", got, e)
	}

	if _, err := decodeUtxoEntry([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected truncated error")
	}
	// Corrupt covenant_data_len so it points past end.
	bad := append([]byte(nil), b...)
	// covenant_data_len starts at offset 10; set it to an invalid large CompactSize (u8=0xff => needs more bytes, will error).
	bad[10] = 0xff
	if _, err := decodeUtxoEntry(bad); err == nil {
		t.Fatalf("expected covenant_data_len error")
	}
}


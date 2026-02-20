package p2p

import (
	"bytes"
	"testing"

	"rubin.dev/node/consensus"
)

func TestBuildBlockLocatorHeights(t *testing.T) {
	// Small chain includes down to genesis without duplicates.
	h := BuildBlockLocatorHeights(5)
	want := []uint64{5, 4, 3, 2, 1, 0}
	if !bytes.Equal(u64sToBytes(h), u64sToBytes(want)) {
		t.Fatalf("got %v want %v", h, want)
	}

	// Large tip: should cap and must end in genesis.
	h = BuildBlockLocatorHeights(10_000)
	if len(h) > MaxLocatorHashes {
		t.Fatalf("expected <=%d, got %d", MaxLocatorHashes, len(h))
	}
	if h[len(h)-1] != 0 {
		t.Fatalf("expected genesis at end, got %d", h[len(h)-1])
	}
	// No height should exceed tip.
	for _, x := range h {
		if x > 10_000 {
			t.Fatalf("height exceeds tip: %d", x)
		}
	}
}

func u64sToBytes(v []uint64) []byte {
	// Helper for deterministic equality without reflect.
	out := make([]byte, 0, len(v)*8)
	for _, x := range v {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(x >> (8 * i))
		}
		out = append(out, b[:]...)
	}
	return out
}

func TestGetHeadersEncodeDecodeRoundtrip(t *testing.T) {
	var loc [][32]byte
	loc = append(loc, [32]byte{1})
	loc = append(loc, [32]byte{2})
	p := GetHeadersPayload{Version: 1, BlockLocator: loc}
	b, err := EncodeGetHeadersPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeGetHeadersPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || len(got.BlockLocator) != 2 || got.BlockLocator[0][0] != 1 || got.BlockLocator[1][0] != 2 {
		t.Fatalf("unexpected decode: %+v", got)
	}
}

func TestHeadersEncodeDecodeRoundtrip(t *testing.T) {
	h1 := consensus.BlockHeader{Version: 1, Timestamp: 2}
	h2 := consensus.BlockHeader{Version: 3, Timestamp: 4, Nonce: 5}
	payload, err := EncodeHeadersPayload([]consensus.BlockHeader{h1, h2})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeHeadersPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2, got %d", len(decoded))
	}
	if decoded[0].Version != 1 || decoded[0].Timestamp != 2 {
		t.Fatalf("decoded[0] mismatch: %+v", decoded[0])
	}
	if decoded[1].Version != 3 || decoded[1].Timestamp != 4 || decoded[1].Nonce != 5 {
		t.Fatalf("decoded[1] mismatch: %+v", decoded[1])
	}
}

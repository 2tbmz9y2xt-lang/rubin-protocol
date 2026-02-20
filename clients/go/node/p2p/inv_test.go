package p2p

import "testing"

func TestInvEncodeDecodeRoundtrip(t *testing.T) {
	vecs := []InvVector{
		{Type: InvTypeBlock, Hash: [32]byte{1}},
		{Type: InvTypeWitnessTx, Hash: [32]byte{2}},
	}
	b, err := EncodeInvPayload(vecs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeInvPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Type != InvTypeBlock || got[0].Hash[0] != 1 || got[1].Type != InvTypeWitnessTx || got[1].Hash[0] != 2 {
		t.Fatalf("unexpected decode: %+v", got)
	}
}

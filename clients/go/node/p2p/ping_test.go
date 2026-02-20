package p2p

import "testing"

func TestPingPongEncodeDecode(t *testing.T) {
	pb, err := EncodePingPayload(PingPayload{Nonce: 42})
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePingPayload(pb)
	if err != nil {
		t.Fatal(err)
	}
	if p.Nonce != 42 {
		t.Fatalf("expected 42, got %d", p.Nonce)
	}

	b, err := EncodePongPayload(PongPayload{Nonce: 99})
	if err != nil {
		t.Fatal(err)
	}
	pp, err := DecodePongPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	if pp.Nonce != 99 {
		t.Fatalf("expected 99, got %d", pp.Nonce)
	}
}

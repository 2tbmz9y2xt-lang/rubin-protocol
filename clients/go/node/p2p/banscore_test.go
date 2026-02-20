package p2p

import (
	"testing"
	"time"
)

func TestBanScoreDecay(t *testing.T) {
	var b BanScore
	t0 := time.Unix(1_700_000_000, 0)
	b.Add(t0, 60)
	if s := b.Score(t0); s != 60 {
		t.Fatalf("expected 60, got %d", s)
	}
	// 10 minutes => -10.
	t1 := t0.Add(10 * time.Minute)
	if s := b.Score(t1); s != 50 {
		t.Fatalf("expected 50, got %d", s)
	}
	// Another 100 minutes should floor at 0.
	t2 := t1.Add(100 * time.Minute)
	if s := b.Score(t2); s != 0 {
		t.Fatalf("expected 0, got %d", s)
	}
}

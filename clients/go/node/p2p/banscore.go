package p2p

import (
	"time"
)

const (
	BanThreshold       = 100
	ThrottleThreshold  = 50
	ThrottleDelay      = 500 * time.Millisecond
	BanDurationDefault = 24 * time.Hour

	// BanScoreDecaysPerMinute is the normative decay rate from the P2P spec.
	BanScoreDecaysPerMinute = 1
)

// BanScore is a small deterministic policy primitive. It is not consensus.
type BanScore struct {
	score       int
	lastUpdated time.Time
}

func (b *BanScore) Score(now time.Time) int {
	b.decayTo(now)
	return b.score
}

func (b *BanScore) Add(now time.Time, delta int) int {
	b.decayTo(now)
	b.score += delta
	if b.score < 0 {
		b.score = 0
	}
	return b.score
}

func (b *BanScore) ShouldBan(now time.Time) bool {
	return b.Score(now) >= BanThreshold
}

func (b *BanScore) ShouldThrottle(now time.Time) bool {
	return b.Score(now) >= ThrottleThreshold
}

func (b *BanScore) decayTo(now time.Time) {
	if b.lastUpdated.IsZero() {
		b.lastUpdated = now
		return
	}
	if now.Before(b.lastUpdated) {
		// Clock went backwards; don't increase score.
		b.lastUpdated = now
		return
	}
	minutes := int(now.Sub(b.lastUpdated) / time.Minute)
	if minutes <= 0 {
		return
	}
	dec := minutes * BanScoreDecaysPerMinute
	b.score -= dec
	if b.score < 0 {
		b.score = 0
	}
	b.lastUpdated = now
}

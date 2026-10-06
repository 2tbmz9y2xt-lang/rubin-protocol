//go:build cgo && (darwin || linux) && (amd64 || arm64)

package node

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// TestReplayExpectedTargetMatchesNodeSchedule pins consensus.ReplayExpectedTargetV1 to the mirrored node schedule
// expectedTargetForCandidateWithReader (RUBIN_L1_CANONICAL.md Section 15) at and around retarget boundaries.
func TestReplayExpectedTargetMatchesNodeSchedule(t *testing.T) {
	w := uint64(consensus.WINDOW_SIZE)
	targetOld := consensus.POW_LIMIT
	targetOld[0] = 0x0f
	for _, height := range []uint64{1, w - 1, w, w + 1, 2 * w} {
		chain := newScheduleChain(t, int(height), targetOld)
		parent := chain.hashes[height-1]
		want, err := expectedTargetForCandidateWithReader(chain.read, parent, height)
		if err != nil {
			t.Fatalf("height %d: node schedule: %v", height, err)
		}
		window := chain.times[height-min(height, w):]
		got, err := consensus.ReplayExpectedTargetV1(height, targetOld, window)
		if err != nil || got != want {
			t.Fatalf("height %d: ReplayExpectedTargetV1=%x err=%v, node=%x", height, got, err, want)
		}
	}
	clampedScheduleCase(t, targetOld)
	if _, err := consensus.ReplayExpectedTargetV1(0, targetOld, nil); err == nil {
		t.Fatal("height 0 accepted")
	}
}

// clampedScheduleCase is a retarget window with one step above MAX_TIMESTAMP_STEP_PER_BLOCK and one step backwards
// at its end, so the per-step clamp changes the result: the unclamped RetargetV1 over the first and last timestamps differs.
func clampedScheduleCase(t *testing.T, targetOld [32]byte) {
	t.Helper()
	w := int(consensus.WINDOW_SIZE)
	c := scheduleChain{make(map[[32]byte][]byte, w), make([][32]byte, 0, w), make([]uint64, w)}
	var prev [32]byte
	for i := 0; i < w; i++ {
		c.times[i] = 1_000_000 + uint64(i)*consensus.TARGET_BLOCK_INTERVAL
		if i >= 100 {
			c.times[i] += 100_000 // a jump above MAX_TIMESTAMP_STEP_PER_BLOCK at height 100
		}
		if i == w-1 {
			c.times[i] -= 150_000 // a step backwards at the last window height
		}
		target := consensus.POW_LIMIT
		if i == w-1 {
			target = targetOld
		}
		raw, hash := scheduleHeader(t, prev, target, c.times[i], uint64(i+1))
		c.headers[hash] = raw
		c.hashes = append(c.hashes, hash)
		prev = hash
	}
	want, err := expectedTargetForCandidateWithReader(c.read, c.hashes[w-1], uint64(w))
	if err != nil {
		t.Fatalf("clamped window: node schedule: %v", err)
	}
	unclamped, err := consensus.RetargetV1(targetOld, c.times[0], c.times[w-1])
	if err != nil || unclamped == want {
		t.Fatalf("clamped window does not exercise the clamp: unclamped=%x err=%v node=%x", unclamped, err, want)
	}
	got, err := consensus.ReplayExpectedTargetV1(uint64(w), targetOld, c.times)
	if err != nil || got != want {
		t.Fatalf("clamped window: ReplayExpectedTargetV1=%x err=%v, node=%x", got, err, want)
	}
}

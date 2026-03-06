package consensus

import "testing"

func TestBlockSubsidy_Height0IsZero(t *testing.T) {
	if got := BlockSubsidy(0, 0); got != 0 {
		t.Fatalf("got=%d, want 0", got)
	}
}

func TestBlockSubsidy_Height1AlreadyGeneratedZeroMatchesSpecFormula(t *testing.T) {
	const want = uint64(4_673_004_150)
	if got := BlockSubsidy(1, 0); got != want {
		t.Fatalf("got=%d, want %d", got, want)
	}
}

func TestBlockSubsidy_TailEmissionAfterCap(t *testing.T) {
	if got := BlockSubsidy(1, MINEABLE_CAP); got != TAIL_EMISSION_PER_BLOCK {
		t.Fatalf("got=%d, want %d", got, TAIL_EMISSION_PER_BLOCK)
	}
	if got := BlockSubsidy(1, MINEABLE_CAP+1); got != TAIL_EMISSION_PER_BLOCK {
		t.Fatalf("got=%d, want %d", got, TAIL_EMISSION_PER_BLOCK)
	}
}

func TestBlockSubsidy_ClampsToTailEmissionWhenBaseWouldUndercut(t *testing.T) {
	// Choose alreadyGenerated such that remaining >> EMISSION_SPEED_FACTOR would be
	// smaller than TAIL_EMISSION_PER_BLOCK, forcing the clamp.
	alreadyGenerated := MINEABLE_CAP - (uint64(TAIL_EMISSION_PER_BLOCK-1) << EMISSION_SPEED_FACTOR)
	got := BlockSubsidy(1, alreadyGenerated)
	if got != TAIL_EMISSION_PER_BLOCK {
		t.Fatalf("got=%d, want clamp %d", got, TAIL_EMISSION_PER_BLOCK)
	}
}

func TestBlockSubsidy_BaseRewardFormula(t *testing.T) {
	alreadyGenerated := uint64(123)
	remaining := MINEABLE_CAP - alreadyGenerated
	want := remaining >> EMISSION_SPEED_FACTOR
	got := BlockSubsidy(1, alreadyGenerated)
	if got != want {
		t.Fatalf("got=%d, want %d", got, want)
	}
}

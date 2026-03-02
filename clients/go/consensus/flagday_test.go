package consensus

import "testing"

func TestFlagDayActiveAtHeight(t *testing.T) {
	bit := uint8(5)
	d := FlagDayDeployment{
		Name:             "X",
		ActivationHeight: 100,
		Bit:              &bit,
	}

	active, err := FlagDayActiveAtHeight(d, 99)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Fatalf("expected inactive at h=99")
	}

	active, err = FlagDayActiveAtHeight(d, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !active {
		t.Fatalf("expected active at h=100")
	}
}

func TestFlagDayActiveAtHeight_BitRange(t *testing.T) {
	bit := uint8(32)
	d := FlagDayDeployment{
		Name:             "X",
		ActivationHeight: 0,
		Bit:              &bit,
	}
	_, err := FlagDayActiveAtHeight(d, 0)
	if err == nil || err.Error() != "flagday: bit out of range: 32" {
		t.Fatalf("unexpected err: %v", err)
	}
}

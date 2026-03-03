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

func bitPtr(b uint8) *uint8 { return &b }

func TestValidateDeploymentBitUniqueness_NoConflict(t *testing.T) {
	ds := []FlagDayDeployment{
		{Name: "A", ActivationHeight: 1000, Bit: bitPtr(3)},
		{Name: "B", ActivationHeight: 5000, Bit: bitPtr(5)},
	}
	warnings := ValidateDeploymentBitUniqueness(ds)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
}

func TestValidateDeploymentBitUniqueness_SameBitOverlap(t *testing.T) {
	// Both use bit 3. A is reserved until 1000+2016=3016, B starts at 2000 < 3016 → overlap.
	ds := []FlagDayDeployment{
		{Name: "A", ActivationHeight: 1000, Bit: bitPtr(3)},
		{Name: "B", ActivationHeight: 2000, Bit: bitPtr(3)},
	}
	warnings := ValidateDeploymentBitUniqueness(ds)
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
}

func TestValidateDeploymentBitUniqueness_SameBitNoOverlap(t *testing.T) {
	// Both use bit 3. A is reserved until 1000+2016=3016, B starts at 4000 >= 3016 → ok.
	ds := []FlagDayDeployment{
		{Name: "A", ActivationHeight: 1000, Bit: bitPtr(3)},
		{Name: "B", ActivationHeight: 4000, Bit: bitPtr(3)},
	}
	warnings := ValidateDeploymentBitUniqueness(ds)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
}

func TestValidateDeploymentBitUniqueness_NoBitSkipped(t *testing.T) {
	// Deployments without bit should not trigger warnings.
	ds := []FlagDayDeployment{
		{Name: "A", ActivationHeight: 1000, Bit: nil},
		{Name: "B", ActivationHeight: 1000, Bit: nil},
	}
	warnings := ValidateDeploymentBitUniqueness(ds)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
}

func TestValidateDeploymentBitUniqueness_ThreeWayOverlap(t *testing.T) {
	// Three deployments on same bit → 3 pairwise warnings.
	ds := []FlagDayDeployment{
		{Name: "A", ActivationHeight: 1000, Bit: bitPtr(7)},
		{Name: "B", ActivationHeight: 1500, Bit: bitPtr(7)},
		{Name: "C", ActivationHeight: 2000, Bit: bitPtr(7)},
	}
	warnings := ValidateDeploymentBitUniqueness(ds)
	if len(warnings) != 3 {
		t.Fatalf("expected 3 warnings (A-B, A-C, B-C), got %d: %v", len(warnings), warnings)
	}
}

func TestValidateDeploymentBitUniqueness_Empty(t *testing.T) {
	warnings := ValidateDeploymentBitUniqueness(nil)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
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

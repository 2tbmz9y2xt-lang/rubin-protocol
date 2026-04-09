package consensus

import (
	"strings"
	"testing"
)

func TestIsV1ProductionRotationNetwork(t *testing.T) {
	if !IsV1ProductionRotationNetwork("mainnet") || !IsV1ProductionRotationNetwork("MAINNET") {
		t.Fatal("expected mainnet")
	}
	if !IsV1ProductionRotationNetwork("testnet") {
		t.Fatal("expected testnet")
	}
	if IsV1ProductionRotationNetwork("devnet") || IsV1ProductionRotationNetwork("") {
		t.Fatal("devnet/empty are not production rotation networks")
	}
}

func TestValidateV1ProductionRotationDescriptor_PropagateValidateError(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
		},
	}
	d := CryptoRotationDescriptor{
		Name:         "",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 10,
		SpendHeight:  20,
		SunsetHeight: 100,
	}
	err := ValidateV1ProductionRotationDescriptor(d, reg)
	if err == nil || !strings.Contains(err.Error(), "name required") {
		t.Fatalf("expected validate error before H4, got %v", err)
	}
}

func TestValidateV1ProductionRotationDescriptor_RequiresH4(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
		},
	}
	d := CryptoRotationDescriptor{
		Name:         "r1",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 10,
		SpendHeight:  20,
		SunsetHeight: 0,
	}
	err := ValidateV1ProductionRotationDescriptor(d, reg)
	if err == nil || !strings.Contains(err.Error(), "sunset_height") {
		t.Fatalf("expected H4 error, got %v", err)
	}
	d.SunsetHeight = 100
	if err := ValidateV1ProductionRotationDescriptor(d, reg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateV1ProductionRotationSet_ChainedH1AfterPriorH4(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
			0x03: {SuiteID: 0x03, PubkeyLen: 1024, SigLen: 512},
		},
	}
	d1 := CryptoRotationDescriptor{
		Name:         "first",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 10,
		SpendHeight:  20,
		SunsetHeight: 100,
	}
	d2 := CryptoRotationDescriptor{
		Name:         "second",
		OldSuiteID:   0x02,
		NewSuiteID:   0x03,
		CreateHeight: 50,
		SpendHeight:  60,
		SunsetHeight: 200,
	}
	err := ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2}, reg)
	if err == nil || !strings.Contains(err.Error(), "successor") {
		t.Fatalf("expected chained ordering error, got %v", err)
	}
	d2ok := CryptoRotationDescriptor{
		Name:         "second",
		OldSuiteID:   0x02,
		NewSuiteID:   0x03,
		CreateHeight: 100,
		SpendHeight:  110,
		SunsetHeight: 200,
	}
	if err := ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2ok}, reg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateV1ProductionRotationSet_RejectsThreeDescriptorChain(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
			0x03: {SuiteID: 0x03, PubkeyLen: 1024, SigLen: 512},
			0x04: {SuiteID: 0x04, PubkeyLen: 1024, SigLen: 512},
		},
	}
	d1 := CryptoRotationDescriptor{
		Name: "r1", OldSuiteID: 0x01, NewSuiteID: 0x02,
		CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100,
	}
	d2 := CryptoRotationDescriptor{
		Name: "r2", OldSuiteID: 0x02, NewSuiteID: 0x03,
		CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200,
	}
	d3 := CryptoRotationDescriptor{
		Name: "r3", OldSuiteID: 0x03, NewSuiteID: 0x04,
		CreateHeight: 200, SpendHeight: 210, SunsetHeight: 300,
	}
	err := ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2, d3}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most two descriptors") {
		t.Fatalf("expected max-2 error, got %v", err)
	}
	// Out-of-order slice must still fail through the same structural cap.
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d3, d1, d2}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most two descriptors") {
		t.Fatalf("expected max-2 error for shuffled order, got %v", err)
	}
	d2bad := d2
	d2bad.SunsetHeight = 0
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2bad, d3}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most two descriptors") {
		t.Fatalf("expected max-2 error to win over finite-H4 check, got %v", err)
	}
}

func TestValidateRotationSetForNetwork_DevnetStillAllowsThreeDescriptorChain(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
			0x03: {SuiteID: 0x03, PubkeyLen: 1024, SigLen: 512},
			0x04: {SuiteID: 0x04, PubkeyLen: 1024, SigLen: 512},
		},
	}
	d1 := CryptoRotationDescriptor{
		Name: "r1", OldSuiteID: 0x01, NewSuiteID: 0x02,
		CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100,
	}
	d2 := CryptoRotationDescriptor{
		Name: "r2", OldSuiteID: 0x02, NewSuiteID: 0x03,
		CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200,
	}
	d3 := CryptoRotationDescriptor{
		Name: "r3", OldSuiteID: 0x03, NewSuiteID: 0x04,
		CreateHeight: 200, SpendHeight: 210, SunsetHeight: 300,
	}
	if err := ValidateRotationSetForNetwork("devnet", []CryptoRotationDescriptor{d1, d2, d3}, reg); err != nil {
		t.Fatalf("devnet should preserve non-production experimentation, got %v", err)
	}
}

func TestValidateRotationDescriptorForNetwork(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
		},
	}
	ok := CryptoRotationDescriptor{
		Name:         "r1",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 10,
		SpendHeight:  20,
		SunsetHeight: 0,
	}
	if err := ValidateRotationDescriptorForNetwork("devnet", ok, reg); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRotationDescriptorForNetwork("  MAINNET  ", ok, reg); err == nil || !strings.Contains(err.Error(), "sunset_height") {
		t.Fatalf("mainnet must require H4, got %v", err)
	}
	ok.SunsetHeight = 100
	if err := ValidateRotationDescriptorForNetwork("testnet", ok, reg); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.Name = ""
	if err := ValidateRotationDescriptorForNetwork("devnet", bad, reg); err == nil || !strings.Contains(err.Error(), "name required") {
		t.Fatalf("expected validate error, got %v", err)
	}
}

func TestValidateRotationSetForNetwork(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
		},
	}
	a := CryptoRotationDescriptor{Name: "a", OldSuiteID: 0x01, NewSuiteID: 0x02, CreateHeight: 10, SpendHeight: 20, SunsetHeight: 0}
	b := CryptoRotationDescriptor{Name: "b", OldSuiteID: 0x01, NewSuiteID: 0x02, CreateHeight: 15, SpendHeight: 25, SunsetHeight: 0}
	if err := ValidateRotationSetForNetwork("devnet", []CryptoRotationDescriptor{a, b}, reg); err == nil {
		t.Fatal("expected overlap error on devnet")
	}
	if err := ValidateRotationSetForNetwork("mainnet", []CryptoRotationDescriptor{a, b}, reg); err == nil {
		t.Fatal("expected error on mainnet (overlap and H4)")
	}
	if err := ValidateRotationSetForNetwork("mainnet", []CryptoRotationDescriptor{}, reg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateV1ProductionRotationSet_EmptySingleAndH4Gap(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
			0x03: {SuiteID: 0x03, PubkeyLen: 1024, SigLen: 512},
		},
	}
	if err := ValidateV1ProductionRotationSet(nil, reg); err != nil {
		t.Fatal(err)
	}
	one := CryptoRotationDescriptor{
		Name: "only", OldSuiteID: 0x01, NewSuiteID: 0x02,
		CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100,
	}
	if err := ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{one}, reg); err != nil {
		t.Fatal(err)
	}
	d1 := CryptoRotationDescriptor{
		Name: "first", OldSuiteID: 0x01, NewSuiteID: 0x02,
		CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100,
	}
	d2bad := CryptoRotationDescriptor{
		Name: "second", OldSuiteID: 0x02, NewSuiteID: 0x03,
		CreateHeight: 100, SpendHeight: 110, SunsetHeight: 0,
	}
	err := ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2bad}, reg)
	if err == nil || !strings.Contains(err.Error(), "rotation[1]") || !strings.Contains(err.Error(), "sunset_height") {
		t.Fatalf("expected H4 error on second descriptor, got %v", err)
	}
	baseFail := CryptoRotationDescriptor{
		Name: "", OldSuiteID: 0x01, NewSuiteID: 0x02,
		CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100,
	}
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{baseFail}, reg)
	if err == nil || !strings.Contains(err.Error(), "rotation[0]") {
		t.Fatalf("expected wrapped validate error, got %v", err)
	}
}

func TestValidateV1ProductionRotationSet_SortTieBreakStableChain(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
			0x03: {SuiteID: 0x03, PubkeyLen: 1024, SigLen: 512},
		},
	}
	// Same H1 is impossible under ValidateRotationSet; exercise tie-break via equal H1 only on
	// the chained-order check by passing a set that is invalid for another reason first, then
	// use descriptors with distinct H1 values where the sort still compares names only if H1 equal.
	// Direct coverage of name branch: two entries with same CreateHeight would overlap — instead
	// call sort helper logic by duplicating the production validation ordering invariant:
	dEarly := CryptoRotationDescriptor{
		Name: "z", OldSuiteID: 0x01, NewSuiteID: 0x02,
		CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100,
	}
	dLate := CryptoRotationDescriptor{
		Name: "a", OldSuiteID: 0x02, NewSuiteID: 0x03,
		CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200,
	}
	// Reversed slice order should still validate (sort by H1 then name).
	if err := ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{dLate, dEarly}, reg); err != nil {
		t.Fatal(err)
	}
}

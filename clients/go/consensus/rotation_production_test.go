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

func TestValidateV1ProductionRotationSet_RejectsMultiDescriptorBatch(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
			0x03: {SuiteID: 0x03, PubkeyLen: 1024, SigLen: 512},
			0x04: {SuiteID: 0x04, PubkeyLen: 1024, SigLen: 512},
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
		CreateHeight: 100,
		SpendHeight:  110,
		SunsetHeight: 200,
	}
	err := ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most one descriptor") {
		t.Fatalf("expected max-1 error, got %v", err)
	}
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d2, d1}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most one descriptor") {
		t.Fatalf("expected max-1 error for reversed batch, got %v", err)
	}
	d2bad := d2
	d2bad.SunsetHeight = 0
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2bad}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most one descriptor") {
		t.Fatalf("expected max-1 error to win over finite-H4 check, got %v", err)
	}
	d2overlap := d2
	d2overlap.CreateHeight = 15
	d2overlap.SpendHeight = 25
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2overlap}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most one descriptor") {
		t.Fatalf("expected max-1 error to win over overlap validation, got %v", err)
	}
	d3 := CryptoRotationDescriptor{
		Name: "third", OldSuiteID: 0x03, NewSuiteID: 0x04,
		CreateHeight: 200, SpendHeight: 210, SunsetHeight: 300,
	}
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{d1, d2, d3}, reg)
	if err == nil || !strings.Contains(err.Error(), "at most one descriptor") {
		t.Fatalf("expected max-1 error for 3-descriptor batch, got %v", err)
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
		t.Fatal("expected production reject on mainnet")
	}
	if err := ValidateRotationSetForNetwork("mainnet", []CryptoRotationDescriptor{}, reg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateV1ProductionRotationSet_EmptySingleAndValidationPaths(t *testing.T) {
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
	if err == nil || !strings.Contains(err.Error(), "at most one descriptor") {
		t.Fatalf("expected max-1 error on multi-descriptor batch, got %v", err)
	}
	baseFail := CryptoRotationDescriptor{
		Name: "", OldSuiteID: 0x01, NewSuiteID: 0x02,
		CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100,
	}
	err = ValidateV1ProductionRotationSet([]CryptoRotationDescriptor{baseFail}, reg)
	if err == nil || !strings.Contains(err.Error(), "name required") {
		t.Fatalf("expected wrapped validate error, got %v", err)
	}
}

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

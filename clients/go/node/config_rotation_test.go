package node

import (
	"encoding/json"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestBuildRotationProvider_NilDescriptor(t *testing.T) {
	cfg := DefaultConfig()
	rot, reg, err := cfg.BuildRotationProvider()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rot != nil {
		t.Fatal("expected nil rotation for default config")
	}
	if reg != nil {
		t.Fatal("expected nil registry for default config")
	}
}

func TestBuildRotationProvider_ValidDescriptor(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RotationDescriptor = &RotationConfigJSON{
		Name:         "test-rotation",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x02,
		CreateHeight: 1,
		SpendHeight:  5,
		SunsetHeight: 10,
	}
	// Need suite 0x02 in registry — but default registry only has ML-DSA-87.
	// Validation will fail because new suite is not registered.
	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected error: new suite 0x02 not registered")
	}
}

func TestBuildRotationProvider_InvalidDescriptor_SameOldNew(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RotationDescriptor = &RotationConfigJSON{
		Name:         "bad",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		CreateHeight: 1,
		SpendHeight:  5,
	}
	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected error: old == new")
	}
}

func TestValidateConfig_RejectsInvalidRotation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RotationDescriptor = &RotationConfigJSON{
		Name:         "bad",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		CreateHeight: 1,
		SpendHeight:  5,
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected validation error for bad rotation")
	}
}

func TestValidateConfig_AcceptsNoRotation(t *testing.T) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRotationConfigJSON_Roundtrip(t *testing.T) {
	cfg := Config{
		Network:  "devnet",
		DataDir:  "/tmp/test",
		BindAddr: "0.0.0.0:19111",
		LogLevel: "info",
		MaxPeers: 64,
		RotationDescriptor: &RotationConfigJSON{
			Name:         "test",
			OldSuiteID:   1,
			NewSuiteID:   2,
			CreateHeight: 100,
			SpendHeight:  200,
			SunsetHeight: 300,
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored Config
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.RotationDescriptor == nil {
		t.Fatal("rotation descriptor lost in roundtrip")
	}
	if restored.RotationDescriptor.Name != "test" {
		t.Fatalf("name=%q, want 'test'", restored.RotationDescriptor.Name)
	}
	if restored.RotationDescriptor.SunsetHeight != 300 {
		t.Fatalf("sunset=%d, want 300", restored.RotationDescriptor.SunsetHeight)
	}
}

func TestRotationConfigJSON_OmittedInDefault(t *testing.T) {
	cfg := DefaultConfig()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["rotation_descriptor"]; ok {
		t.Fatal("rotation_descriptor should be omitted when nil")
	}
}

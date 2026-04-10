package node

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func stringPtr(s string) *string {
	return &s
}

var productionRotationNetworks = []string{"mainnet", "testnet", " MAINNET ", "\tTestNet\t"}

func quotedSubtestName(raw string) string {
	return fmt.Sprintf("%q", raw)
}

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

func TestBuildRotationProvider_ValidDescriptorOnNonProductionNetwork(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuiteRegistry = []SuiteParamsJSON{
		{
			SuiteID:    0x02,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    stringPtr("ML-DSA-87"),
		},
	}
	cfg.RotationDescriptor = &RotationConfigJSON{
		Name:         "test-rotation",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x02,
		CreateHeight: 1,
		SpendHeight:  5,
		SunsetHeight: 10,
	}
	rot, reg, err := cfg.BuildRotationProvider()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rot == nil {
		t.Fatal("expected descriptor-backed rotation")
	}
	if reg == nil {
		t.Fatal("expected explicit suite registry")
	}
	if _, ok := reg.Lookup(consensus.SUITE_ID_ML_DSA_87); !ok {
		t.Fatal("expected overlay registry to preserve ML-DSA-87")
	}
	if _, ok := reg.Lookup(0x02); !ok {
		t.Fatal("expected explicit suite registry to include suite 0x02")
	}
}

func TestBuildRotationProvider_RejectsProductionLocalRotationDescriptor(t *testing.T) {
	for _, network := range productionRotationNetworks {
		t.Run(quotedSubtestName(network), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Network = network
			cfg.SuiteRegistry = []SuiteParamsJSON{
				{
					SuiteID:    0x02,
					PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
					SigLen:     consensus.ML_DSA_87_SIG_BYTES,
					VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
					AlgName:    stringPtr("ML-DSA-87"),
				},
			}
			cfg.RotationDescriptor = &RotationConfigJSON{
				Name:         "prod-rotation",
				OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
				NewSuiteID:   0x02,
				CreateHeight: 1,
				SpendHeight:  5,
				SunsetHeight: 10,
			}
			_, _, err := cfg.BuildRotationProvider()
			if err == nil {
				t.Fatal("expected production local rotation_descriptor rejection")
			}
			if got, want := err.Error(), productionLocalRotationDescriptorErr; got != want {
				t.Fatalf("error=%q, want %q", got, want)
			}
		})
	}
}

func TestBuildRotationProvider_RejectsSuiteRegistryEmptyAlgName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuiteRegistry = []SuiteParamsJSON{{
		SuiteID:    0x42,
		PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
		SigLen:     consensus.ML_DSA_87_SIG_BYTES,
		VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
		AlgName:    stringPtr(""),
	}}
	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected suite_registry rejection for empty alg_name")
	}
	if got, want := err.Error(), "suite_registry: bad suite_registry"; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestBuildRotationProvider_AcceptsCaseInsensitiveSuiteRegistryAlgName(t *testing.T) {
	for _, alg := range []string{"ml-dsa-87", "ML-dSa-87"} {
		t.Run(alg, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.SuiteRegistry = []SuiteParamsJSON{{
				SuiteID:    0x42,
				PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
				SigLen:     consensus.ML_DSA_87_SIG_BYTES,
				VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
				AlgName:    stringPtr(alg),
			}}
			_, reg, err := cfg.BuildRotationProvider()
			if err != nil {
				t.Fatalf("unexpected error for alg_name=%q: %v", alg, err)
			}
			params, ok := reg.Lookup(0x42)
			if !ok {
				t.Fatalf("missing suite 0x42 for alg_name=%q", alg)
			}
			if got, want := params.AlgName, "ML-DSA-87"; got != want {
				t.Fatalf("alg_name=%q normalized to %q, want %q", alg, got, want)
			}
		})
	}
}

func TestBuildRotationProvider_RejectsMalformedSuiteRegistryAlgName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuiteRegistry = []SuiteParamsJSON{{
		SuiteID:    0x42,
		PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
		SigLen:     consensus.ML_DSA_87_SIG_BYTES,
		VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
		AlgName:    stringPtr("MLDSA87"),
	}}
	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected suite_registry rejection for malformed alg_name")
	}
	if got, want := err.Error(), "suite_registry: bad suite_registry"; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestBuildRotationProvider_RejectsSuiteRegistryNoncanonicalVerifyCost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuiteRegistry = []SuiteParamsJSON{{
		SuiteID:    0x42,
		PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
		SigLen:     consensus.ML_DSA_87_SIG_BYTES,
		VerifyCost: consensus.VERIFY_COST_ML_DSA_87 + 1,
		AlgName:    stringPtr("ML-DSA-87"),
	}}
	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected suite_registry rejection for noncanonical verify_cost")
	}
	if got, want := err.Error(), "suite_registry: bad suite_registry"; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestBuildRotationProvider_RejectsSuiteRegistrySyntheticHarnessParams(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuiteRegistry = []SuiteParamsJSON{{
		SuiteID:    0x42,
		PubkeyLen:  64,
		SigLen:     0,
		VerifyCost: 9,
		AlgName:    stringPtr("ML-DSA-87"),
	}}
	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected live node suite_registry to reject synthetic harness params")
	}
	if got, want := err.Error(), "suite_registry: bad suite_registry"; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestBuildRotationProvider_DescriptorRejectsUnregisteredNewSuiteWithoutExplicitRegistry(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RotationDescriptor = &RotationConfigJSON{
		Name:         "needs-registry",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x02,
		CreateHeight: 1,
		SpendHeight:  5,
	}
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

func TestBuildRotationProvider_ExplicitSuiteRegistryWithoutDescriptor(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuiteRegistry = []SuiteParamsJSON{
		{
			SuiteID:    0x42,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    stringPtr("ML-DSA-87"),
		},
	}
	rot, reg, err := cfg.BuildRotationProvider()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rot == nil {
		t.Fatal("expected default rotation with explicit suite registry")
	}
	if reg == nil {
		t.Fatal("expected explicit suite registry")
	}
	if _, ok := reg.Lookup(consensus.SUITE_ID_ML_DSA_87); !ok {
		t.Fatal("expected overlay registry to preserve ML-DSA-87")
	}
	params, ok := reg.Lookup(0x42)
	if !ok {
		t.Fatal("expected suite 0x42 in registry")
	}
	if params.VerifyCost != consensus.VERIFY_COST_ML_DSA_87 {
		t.Fatalf("verify_cost=%d, want %d", params.VerifyCost, consensus.VERIFY_COST_ML_DSA_87)
	}
	if !rot.NativeSpendSuites(0).Contains(consensus.SUITE_ID_ML_DSA_87) {
		t.Fatal("default rotation must continue to expose ML-DSA-87")
	}
}

func TestBuildRotationProvider_ProductionExplicitSuiteRegistryWithoutDescriptor(t *testing.T) {
	for _, network := range productionRotationNetworks {
		t.Run(quotedSubtestName(network), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Network = network
			cfg.SuiteRegistry = []SuiteParamsJSON{
				{
					SuiteID:    0x42,
					PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
					SigLen:     consensus.ML_DSA_87_SIG_BYTES,
					VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
					AlgName:    stringPtr("ML-DSA-87"),
				},
			}
			rot, reg, err := cfg.BuildRotationProvider()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rot == nil || reg == nil {
				t.Fatal("expected production suite_registry-only bootstrap to remain available")
			}
			if _, ok := reg.Lookup(0x42); !ok {
				t.Fatal("expected suite 0x42 in production registry")
			}
		})
	}
}

func TestBuildRotationProvider_RejectsUnknownNetworkWithoutSeparateValidateConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network = " not-a-network "
	cfg.RotationDescriptor = &RotationConfigJSON{
		Name:         "dev-rotation",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x42,
		CreateHeight: 1,
		SpendHeight:  5,
		SunsetHeight: 10,
	}
	cfg.SuiteRegistry = []SuiteParamsJSON{
		{
			SuiteID:    0x42,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    stringPtr("ML-DSA-87"),
		},
	}

	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected unknown network error")
	}
	if !strings.Contains(err.Error(), "unknown network") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildRotationProvider_RejectsWhitespaceOnlyNetworkWithoutSeparateValidateConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Network = "   "
	cfg.RotationDescriptor = &RotationConfigJSON{
		Name:         "dev-rotation",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x42,
		CreateHeight: 1,
		SpendHeight:  5,
		SunsetHeight: 10,
	}
	cfg.SuiteRegistry = []SuiteParamsJSON{
		{
			SuiteID:    0x42,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    stringPtr("ML-DSA-87"),
		},
	}

	_, _, err := cfg.BuildRotationProvider()
	if err == nil {
		t.Fatal("expected whitespace-only network error")
	}
	if got, want := err.Error(), "network is required"; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestValidateConfig_RejectsProductionLocalRotationDescriptor(t *testing.T) {
	for _, network := range productionRotationNetworks {
		t.Run(quotedSubtestName(network), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Network = network
			cfg.SuiteRegistry = []SuiteParamsJSON{
				{
					SuiteID:    0x02,
					PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
					SigLen:     consensus.ML_DSA_87_SIG_BYTES,
					VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
					AlgName:    stringPtr("ML-DSA-87"),
				},
			}
			cfg.RotationDescriptor = &RotationConfigJSON{
				Name:         "prod-rotation",
				OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
				NewSuiteID:   0x02,
				CreateHeight: 1,
				SpendHeight:  5,
				SunsetHeight: 10,
			}
			err := ValidateConfig(cfg)
			if err == nil {
				t.Fatal("expected validation error for production local rotation_descriptor")
			}
			if got, want := err.Error(), productionLocalRotationDescriptorErr; got != want {
				t.Fatalf("error=%q, want %q", got, want)
			}
		})
	}
}

func TestValidateConfig_RejectsBadSuiteRegistry(t *testing.T) {
	cases := []SuiteParamsJSON{
		{
			SuiteID:    0x01,
			PubkeyLen:  10,
			SigLen:     20,
			VerifyCost: 30,
			AlgName:    stringPtr("NO_SUCH_ALG"),
		},
		{
			SuiteID:    0x42,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    stringPtr(""),
		},
		{
			SuiteID:    0x42,
			PubkeyLen:  64,
			SigLen:     96,
			VerifyCost: 30,
			AlgName:    stringPtr("ML-DSA-87"),
		},
		{
			SuiteID:    consensus.SUITE_ID_SENTINEL,
			PubkeyLen:  64,
			SigLen:     96,
			VerifyCost: 30,
			AlgName:    stringPtr("ML-DSA-87"),
		},
		{
			SuiteID:    0x42,
			PubkeyLen:  64,
			SigLen:     96,
			VerifyCost: 0,
			AlgName:    stringPtr("ML-DSA-87"),
		},
		{
			SuiteID:    consensus.SUITE_ID_ML_DSA_87,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES - 1,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    stringPtr("ML-DSA-87"),
		},
		{
			SuiteID:    0x42,
			PubkeyLen:  maxSuiteRegistryParamLen + 1,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: 30,
			AlgName:    stringPtr("ML-DSA-87"),
		},
		{
			SuiteID:    0x42,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: 30,
			AlgName:    stringPtr("ML-DSA-87"),
		},
	}
	for _, tc := range cases {
		cfg := DefaultConfig()
		cfg.SuiteRegistry = []SuiteParamsJSON{tc}
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("expected validation error for bad suite_registry case %+v", tc)
		}
	}
}

func TestValidateConfig_RejectsUnknownNetwork(t *testing.T) {
	for _, network := range []string{
		"foobar",
		"  not-a-network  ",
		strings.Repeat("M", 1024),
	} {
		t.Run(network, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Network = network
			err := ValidateConfig(cfg)
			if err == nil {
				t.Fatalf("expected validation error for network=%q", network)
			}
			if !strings.Contains(err.Error(), "unknown network") {
				t.Fatalf("unexpected error for network=%q: %v", network, err)
			}
		})
	}
}

func TestValidateConfig_RejectsTooManySuiteRegistryEntries(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SuiteRegistry = make([]SuiteParamsJSON, 0, maxExplicitSuiteRegistryEntries+1)
	for i := 0; i < maxExplicitSuiteRegistryEntries+1; i++ {
		suiteID := uint8(i + 2)
		cfg.SuiteRegistry = append(cfg.SuiteRegistry, SuiteParamsJSON{
			SuiteID:    suiteID,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    stringPtr("ML-DSA-87"),
		})
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected validation error for oversized suite_registry")
	}
}

func TestValidateConfig_RejectsNegativeSuiteRegistryLengthsJSON(t *testing.T) {
	var cfg Config
	err := json.Unmarshal([]byte(`{
		"network":"devnet",
		"data_dir":"/tmp/test",
		"bind_addr":"0.0.0.0:19111",
		"log_level":"info",
		"max_peers":64,
		"mine_address":"",
		"suite_registry":[{"suite_id":66,"pubkey_len":-1,"sig_len":4627,"verify_cost":19,"alg_name":"ML-DSA-87"}]
	}`), &cfg)
	if err == nil {
		t.Fatal("expected unmarshal error for negative suite_registry.pubkey_len")
	}
}

func TestValidateConfig_RejectsMissingSuiteRegistryAlgName(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{
		"network":"devnet",
		"data_dir":"/tmp/test",
		"bind_addr":"0.0.0.0:19111",
		"log_level":"info",
		"max_peers":64,
		"mine_address":"",
		"suite_registry":[{"suite_id":66,"pubkey_len":2592,"sig_len":4627,"verify_cost":19}]
	}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected validation error for missing suite_registry.alg_name")
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
		SuiteRegistry: []SuiteParamsJSON{
			{
				SuiteID:    0x02,
				PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
				SigLen:     consensus.ML_DSA_87_SIG_BYTES,
				VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
				AlgName:    stringPtr("ML-DSA-87"),
			},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	suiteRegistry, ok := raw["suite_registry"].([]any)
	if !ok || len(suiteRegistry) != 1 {
		t.Fatalf("suite_registry raw=%#v, want singleton array", raw["suite_registry"])
	}
	entry, ok := suiteRegistry[0].(map[string]any)
	if !ok {
		t.Fatalf("suite_registry entry raw=%#v, want object", suiteRegistry[0])
	}
	if got := entry["alg_name"]; got != "ML-DSA-87" {
		t.Fatalf("alg_name raw=%#v, want %q", got, "ML-DSA-87")
	}
	if _, ok := entry["openssl_alg"]; ok {
		t.Fatal("marshal should not emit legacy openssl_alg key")
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
	if len(restored.SuiteRegistry) != 1 {
		t.Fatalf("suite_registry len=%d, want 1", len(restored.SuiteRegistry))
	}
	if restored.SuiteRegistry[0].SuiteID != 0x02 {
		t.Fatalf("suite_id=0x%02x, want 0x02", restored.SuiteRegistry[0].SuiteID)
	}
	if restored.SuiteRegistry[0].AlgName == nil || *restored.SuiteRegistry[0].AlgName != "ML-DSA-87" {
		t.Fatal("alg_name lost in roundtrip")
	}
}

func TestValidateConfig_AcceptsLegacySuiteRegistryOpenSSLAlgAlias(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{
		"network":"devnet",
		"data_dir":"/tmp/test",
		"bind_addr":"0.0.0.0:19111",
		"log_level":"info",
		"max_peers":64,
		"mine_address":"",
		"suite_registry":[{"suite_id":66,"pubkey_len":2592,"sig_len":4627,"verify_cost":8,"openssl_alg":"ML-DSA-87"}]
	}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("expected legacy openssl_alg alias to remain accepted, got %v", err)
	}
	if cfg.SuiteRegistry[0].AlgName == nil || *cfg.SuiteRegistry[0].AlgName != "ML-DSA-87" {
		t.Fatal("legacy openssl_alg alias did not normalize into alg_name")
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
	if _, ok := m["suite_registry"]; ok {
		t.Fatal("suite_registry should be omitted when empty")
	}
}

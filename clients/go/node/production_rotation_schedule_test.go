package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func productionRotationScheduleRepoPath(parts ...string) string {
	segments := append([]string{"..", "..", ".."}, parts...)
	return filepath.Join(segments...)
}

func canonicalProductionScheduleRegistry() *consensus.SuiteRegistry {
	return consensus.NewSuiteRegistryFromParams([]consensus.SuiteParams{
		{
			SuiteID:    consensus.SUITE_ID_ML_DSA_87,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    "ML-DSA-87",
		},
		{
			SuiteID:    0x42,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    "ML-DSA-87",
		},
	})
}

func compactJSONBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		t.Fatalf("json.Compact: %v", err)
	}
	return out.Bytes()
}

func TestEmbeddedProductionRotationScheduleMatchesCanonicalFixture(t *testing.T) {
	raw, err := os.ReadFile(productionRotationScheduleRepoPath(
		"conformance",
		"fixtures",
		"protocol",
		"production_rotation_schedule_v1.json",
	))
	if err != nil {
		t.Fatalf("ReadFile(canonical fixture): %v", err)
	}
	if !bytes.Equal(
		compactJSONBytes(t, raw),
		compactJSONBytes(t, embeddedProductionRotationScheduleV1),
	) {
		t.Fatal("embedded production schedule drifted from canonical fixture")
	}
}

func TestLoadCompiledProductionRotationScheduleAcceptsExplicitEmptySchedule(t *testing.T) {
	schedule, registry, err := loadCompiledProductionRotationSchedule()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schedule.Version != productionRotationScheduleVersion {
		t.Fatalf("version=%d, want %d", schedule.Version, productionRotationScheduleVersion)
	}
	if schedule.Networks["mainnet"] != nil {
		t.Fatal("expected mainnet schedule to be explicitly empty")
	}
	if schedule.Networks["testnet"] != nil {
		t.Fatal("expected testnet schedule to be explicitly empty")
	}
	if !registry.IsCanonicalDefaultLiveManifest() {
		t.Fatal("expected canonical default live manifest registry")
	}
}

func TestLoadCompiledProductionRotationScheduleRejectsUnsupportedVersion(t *testing.T) {
	_, _, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 2,
		"networks": {"mainnet": null, "testnet": null}
	}`), consensus.DefaultSuiteRegistry())
	if err == nil {
		t.Fatal("expected unsupported version rejection")
	}
	if got, want := err.Error(), `production_rotation_schedule: unsupported version 2 (want 1)`; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestLoadCompiledProductionRotationScheduleRejectsMissingNetworkKey(t *testing.T) {
	_, _, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 1,
		"networks": {"mainnet": null}
	}`), consensus.DefaultSuiteRegistry())
	if err == nil {
		t.Fatal("expected missing network key rejection")
	}
	if got, want := err.Error(), `production_rotation_schedule: networks.testnet missing`; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestLoadCompiledProductionRotationScheduleRejectsUnknownNetworkKey(t *testing.T) {
	_, _, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 1,
		"networks": {"mainnet": null, "devnet": null}
	}`), consensus.DefaultSuiteRegistry())
	if err == nil {
		t.Fatal("expected unknown network key rejection")
	}
	if got, want := err.Error(), `production_rotation_schedule: unknown networks.devnet entry`; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestLoadCompiledProductionRotationScheduleRejectsMalformedDescriptorShape(t *testing.T) {
	_, _, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 1,
		"networks": {"mainnet": [], "testnet": null}
	}`), consensus.DefaultSuiteRegistry())
	if err == nil {
		t.Fatal("expected malformed descriptor rejection")
	}
	if !strings.Contains(err.Error(), `production_rotation_schedule: networks.mainnet:`) {
		t.Fatalf("error=%q, want production schedule stem + mainnet path", err)
	}
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("error=%q, want wrapped *json.UnmarshalTypeError", err)
	}
	if got, want := typeErr.Value, "array"; got != want {
		t.Fatalf("unmarshal value=%q, want %q", got, want)
	}
}

func TestLoadCompiledProductionRotationScheduleRejectsMissingRequiredDescriptorField(t *testing.T) {
	_, _, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 1,
		"networks": {
			"mainnet": {
				"name": "rotation-v1",
				"old_suite_id": 1,
				"new_suite_id": 66,
				"spend_height": 20
			},
			"testnet": null
		}
	}`), canonicalProductionScheduleRegistry())
	if err == nil {
		t.Fatal("expected missing required descriptor field rejection")
	}
	if got, want := err.Error(), `production_rotation_schedule: networks.mainnet: missing required field "create_height"`; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestLoadCompiledProductionRotationScheduleParsesSingleDescriptorWithCanonicalRegistry(t *testing.T) {
	schedule, registry, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 1,
		"networks": {
			"mainnet": {
				"name": "rotation-v1",
				"old_suite_id": 1,
				"new_suite_id": 66,
				"create_height": 10,
				"spend_height": 20,
				"sunset_height": 30
			},
			"testnet": null
		}
	}`), canonicalProductionScheduleRegistry())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	desc := schedule.Networks["mainnet"]
	if desc == nil {
		t.Fatal("expected mainnet descriptor")
	}
	if desc.NewSuiteID != 0x42 {
		t.Fatalf("new_suite_id=0x%02x, want 0x42", desc.NewSuiteID)
	}
	if schedule.Networks["testnet"] != nil {
		t.Fatal("expected testnet schedule to remain empty")
	}
	if _, ok := registry.Lookup(0x42); !ok {
		t.Fatal("expected custom canonical registry to retain suite 0x42")
	}
}

func TestLoadCompiledProductionRotationScheduleRejectsTrailingJSONTokens(t *testing.T) {
	_, _, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 1,
		"networks": {"mainnet": null, "testnet": null}
	} true`), consensus.DefaultSuiteRegistry())
	if err == nil {
		t.Fatal("expected trailing token rejection")
	}
	if got, want := err.Error(), `production_rotation_schedule: parse embedded artifact: trailing JSON tokens`; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

func TestLoadCompiledProductionRotationScheduleNilRegistryFallsBackToCanonicalDefault(t *testing.T) {
	schedule, registry, err := loadCompiledProductionRotationScheduleFromJSONWithRegistry([]byte(`{
		"version": 1,
		"networks": {"mainnet": null, "testnet": null}
	}`), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schedule.Networks["mainnet"] != nil || schedule.Networks["testnet"] != nil {
		t.Fatal("expected explicit empty schedule")
	}
	if !registry.IsCanonicalDefaultLiveManifest() {
		t.Fatal("expected nil registry to fall back to canonical default live manifest")
	}
}

func TestProductionRotationDescriptorForNetworkRejectsNonProductionCaller(t *testing.T) {
	_, _, err := productionRotationDescriptorForNetwork("devnet")
	if err == nil {
		t.Fatal("expected non-production caller rejection")
	}
	if got, want := err.Error(), `production_rotation_schedule: network "devnet" is not a production schedule caller`; got != want {
		t.Fatalf("error=%q, want %q", got, want)
	}
}

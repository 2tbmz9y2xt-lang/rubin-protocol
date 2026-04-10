package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func cliTestRotationSuites() []SuiteParamsJSON {
	return []SuiteParamsJSON{
		{
			SuiteID:    1,
			PubkeyLen:  consensus.ML_DSA_87_PUBKEY_BYTES,
			SigLen:     consensus.ML_DSA_87_SIG_BYTES,
			VerifyCost: consensus.VERIFY_COST_ML_DSA_87,
			AlgName:    "ML-DSA-87",
		},
		{
			SuiteID:    2,
			PubkeyLen:  1024,
			SigLen:     512,
			VerifyCost: 9,
			AlgName:    "ML-DSA-87",
		},
	}
}

func TestRubinConsensusCLI_RotationProduction_MainnetRequiresH4(t *testing.T) {
	reg := cliTestRotationSuites()
	rd := &RotationDescriptorJSON{
		Name:         "r1",
		OldSuiteID:   1,
		NewSuiteID:   2,
		CreateHeight: 10,
		SpendHeight:  20,
		SunsetHeight: 0,
	}
	sid1 := uint8(1)
	mustRunErr(t, Request{
		Op:                 "rotation_create_suite_check",
		Network:            "mainnet",
		Height:             15,
		SuiteID:            &sid1,
		RotationDescriptor: rd,
		SuiteRegistry:      reg,
	}, "descriptor-not-activated")
}

func TestRubinConsensusCLI_RotationProduction_MainnetSingleDescriptorAndDevnetBatchOK(t *testing.T) {
	reg := cliTestRotationSuites()
	rd := &RotationDescriptorJSON{
		Name:         "r1",
		OldSuiteID:   1,
		NewSuiteID:   2,
		CreateHeight: 10,
		SpendHeight:  20,
		SunsetHeight: 100,
	}
	sid1 := uint8(1)
	sid2 := uint8(2)
	mustRunOk(t, Request{
		Op:                 "rotation_create_suite_check",
		Network:            "testnet",
		Height:             15,
		SuiteID:            &sid1,
		RotationDescriptor: rd,
		SuiteRegistry:      reg,
	})
	mustRunOk(t, Request{
		Op:                 "rotation_spend_suite_check",
		Network:            "mainnet",
		Height:             15,
		SuiteID:            &sid2,
		RotationDescriptor: rd,
		SuiteRegistry:      reg,
	})
	resp := mustRunOk(t, Request{
		Op:                 "rotation_native_create_suites",
		Network:            "mainnet",
		Height:             15,
		RotationDescriptor: rd,
		SuiteRegistry:      reg,
	})
	if len(resp.SuiteIDs) != 2 {
		t.Fatalf("expected two create suites at H15, got %+v", resp.SuiteIDs)
	}
	mustRunOk(t, Request{
		Op:                 "rotation_descriptor_check",
		Network:            "devnet",
		RotationDescriptor: rd,
		SuiteRegistry:      reg,
	})
}

func TestRubinConsensusCLI_RotationProduction_MainnetRejectsMultiDescriptorBatch(t *testing.T) {
	reg := append(
		cliTestRotationSuites(),
		SuiteParamsJSON{SuiteID: 3, PubkeyLen: 1024, SigLen: 512, VerifyCost: 9, AlgName: "ML-DSA-87"},
		SuiteParamsJSON{SuiteID: 4, PubkeyLen: 1024, SigLen: 512, VerifyCost: 9, AlgName: "ML-DSA-87"},
	)
	mustRunErr(t, Request{
		Op:            "rotation_descriptor_check",
		Network:       "mainnet",
		SuiteRegistry: reg,
		RotationDescriptors: []RotationDescriptorJSON{
			{Name: "a", OldSuiteID: 1, NewSuiteID: 2, CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100},
			{Name: "b", OldSuiteID: 2, NewSuiteID: 3, CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200},
		},
	}, rotationDescriptorNotActivatedErr)
	mustRunErr(t, Request{
		Op:            "rotation_descriptor_check",
		Network:       "testnet",
		SuiteRegistry: reg,
		RotationDescriptors: []RotationDescriptorJSON{
			{Name: "a", OldSuiteID: 1, NewSuiteID: 2, CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100},
			{Name: "b", OldSuiteID: 2, NewSuiteID: 3, CreateHeight: 100, SpendHeight: 110, SunsetHeight: 0},
		},
	}, rotationDescriptorNotActivatedErr)
	mustRunOk(t, Request{
		Op:            "rotation_descriptor_check",
		Network:       "devnet",
		SuiteRegistry: reg,
		RotationDescriptors: []RotationDescriptorJSON{
			{Name: "a", OldSuiteID: 1, NewSuiteID: 2, CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100},
			{Name: "b", OldSuiteID: 2, NewSuiteID: 3, CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200},
			{Name: "c", OldSuiteID: 3, NewSuiteID: 4, CreateHeight: 200, SpendHeight: 210, SunsetHeight: 300},
		},
	})
}

func TestRubinConsensusCLI_RotationDescriptorCheck_PreservesStableErrAndDiagnostics(t *testing.T) {
	reg := append(
		cliTestRotationSuites(),
		SuiteParamsJSON{SuiteID: 3, PubkeyLen: 1024, SigLen: 512, VerifyCost: 9, AlgName: "ML-DSA-87"},
	)
	resp := mustRunErr(t, Request{
		Op:            "rotation_descriptor_check",
		Network:       "mainnet",
		SuiteRegistry: reg,
		RotationDescriptors: []RotationDescriptorJSON{
			{Name: "a", OldSuiteID: 1, NewSuiteID: 2, CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100},
			{Name: "b", OldSuiteID: 2, NewSuiteID: 3, CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200},
		},
	}, rotationDescriptorNotActivatedErr)
	if got, _ := resp.Diagnostics["rotation_validation_err"].(string); got != "rotation-too-many-descriptors" {
		t.Fatalf("expected concrete validation diagnostics, got %+v", resp.Diagnostics)
	}
}

func TestSanitizeRotationValidationErr_UsesSharedStems(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "exact production cap stem",
			err:  errors.New(consensus.RotationV1ProductionAtMostOneDescriptorErrStem + ", got 2"),
			want: rotationTooManyDescriptorsErr,
		},
		{
			name: "wrapped generic validation stem",
			err:  errors.New(`rotation[0] "bad": rotation: new suite 0x03 not registered`),
			want: rotationUnregisteredSuiteErr,
		},
		{
			name: "name required stays invalid descriptor",
			err:  errors.New(`rotation[0] "bad": rotation: name required`),
			want: rotationInvalidDescriptorErr,
		},
		{
			name: "equal suite must not be mislabeled as unregistered",
			err:  errors.New(`rotation[0] "bad": rotation: old suite (0x01) must differ from new suite`),
			want: rotationEqualSuiteIDsErr,
		},
		{
			name: "exact finite H4 stem",
			err:  errors.New(consensus.RotationV1ProductionFiniteH4RequiredErrStem),
			want: rotationFiniteH4RequiredErr,
		},
		{
			name: "create height ordering keeps concrete code",
			err:  errors.New(`rotation[0] "bad": rotation: create_height (20) must be < spend_height (10)`),
			want: rotationInvalidHeightOrderErr,
		},
		{
			name: "sunset height ordering keeps concrete code",
			err:  errors.New(`rotation[0] "bad": rotation: sunset_height (20) must be > spend_height (20)`),
			want: rotationInvalidHeightOrderErr,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeRotationValidationErr(tc.err); got != tc.want {
				t.Fatalf("sanitizeRotationValidationErr() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRubinConsensusCLI_RotationDescriptorCheck_AcceptsLegacyOpenSSLAlgAlias(t *testing.T) {
	var req Request
	if err := json.Unmarshal([]byte(`{
		"op":"rotation_descriptor_check",
		"network":"devnet",
		"suite_registry":[
			{"suite_id":1,"pubkey_len":2592,"sig_len":4627,"verify_cost":8,"openssl_alg":"ML-DSA-87"},
			{"suite_id":2,"pubkey_len":1024,"sig_len":512,"verify_cost":9,"openssl_alg":"ML-DSA-87"}
		],
		"rotation_descriptor":{"name":"r1","old_suite_id":1,"new_suite_id":2,"create_height":10,"spend_height":20,"sunset_height":100}
	}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.SuiteRegistry[0].AlgName != "ML-DSA-87" || req.SuiteRegistry[1].AlgName != "ML-DSA-87" {
		t.Fatalf("legacy alias failed to populate alg_name: %+v", req.SuiteRegistry)
	}
	mustRunOk(t, req)
}

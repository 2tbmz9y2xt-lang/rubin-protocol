package main

import (
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
			OpenSSLAlg: "ML-DSA-87",
		},
		{
			SuiteID:    2,
			PubkeyLen:  1024,
			SigLen:     512,
			VerifyCost: 9,
			OpenSSLAlg: "ML-DSA-87",
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

func TestRubinConsensusCLI_RotationProduction_MainnetAndBatchOK(t *testing.T) {
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
		Op:            "rotation_descriptor_check",
		Network:       "mainnet",
		SuiteRegistry: reg,
		RotationDescriptors: []RotationDescriptorJSON{
			{Name: "a", OldSuiteID: 1, NewSuiteID: 2, CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100},
			{Name: "b", OldSuiteID: 2, NewSuiteID: 1, CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200},
		},
	})
	mustRunOk(t, Request{
		Op:                 "rotation_descriptor_check",
		Network:            "devnet",
		RotationDescriptor: rd,
		SuiteRegistry:      reg,
	})
}

func TestRubinConsensusCLI_RotationProduction_MainnetRejectsThreeDescriptorBatch(t *testing.T) {
	reg := append(cliTestRotationSuites(),
		SuiteParamsJSON{SuiteID: 3, PubkeyLen: 1024, SigLen: 512, VerifyCost: 9, OpenSSLAlg: "ML-DSA-87"},
		SuiteParamsJSON{SuiteID: 4, PubkeyLen: 1024, SigLen: 512, VerifyCost: 9, OpenSSLAlg: "ML-DSA-87"},
	)
	mustRunErr(t, Request{
		Op:            "rotation_descriptor_check",
		Network:       "mainnet",
		SuiteRegistry: reg,
		RotationDescriptors: []RotationDescriptorJSON{
			{Name: "a", OldSuiteID: 1, NewSuiteID: 2, CreateHeight: 10, SpendHeight: 20, SunsetHeight: 100},
			{Name: "b", OldSuiteID: 2, NewSuiteID: 3, CreateHeight: 100, SpendHeight: 110, SunsetHeight: 200},
			{Name: "c", OldSuiteID: 3, NewSuiteID: 4, CreateHeight: 200, SpendHeight: 210, SunsetHeight: 300},
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

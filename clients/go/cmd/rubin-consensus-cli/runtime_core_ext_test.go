package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func mustRuntimeOpenSSLDigest32Descriptor(t *testing.T) []byte {
	t.Helper()
	descriptor, err := consensus.CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", consensus.ML_DSA_87_PUBKEY_BYTES, consensus.ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("CoreExtOpenSSLDigest32BindingDescriptorBytes: %v", err)
	}
	return descriptor
}

func TestBuildCoreExtProfilesEmpty(t *testing.T) {
	provider, err := buildCoreExtProfiles(nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Fatalf("expected explicit empty provider for empty profiles")
	}
	if _, ok, err := provider.LookupCoreExtProfile(7, 0); err != nil {
		t.Fatalf("LookupCoreExtProfile: %v", err)
	} else if ok {
		t.Fatalf("expected no active profile from empty provider")
	}
}

func TestBuildCoreExtProfilesNativeBinding(t *testing.T) {
	provider, err := buildCoreExtProfiles([]CoreExtProfileJSON{
		{
			ExtID:               7,
			ActivationHeight:    5,
			AllowedSuiteIDs:     []uint8{1, 3},
			Binding:             " native_verify_sig \n",
			ExtPayloadSchemaHex: "b2",
		},
	}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Fatalf("expected non-nil provider")
	}

	if _, ok, err := provider.LookupCoreExtProfile(7, 4); err != nil {
		t.Fatalf("lookup failed: %v", err)
	} else if ok {
		t.Fatalf("profile must be inactive before activation height")
	}

	profile, ok, err := provider.LookupCoreExtProfile(7, 5)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected active profile for ext_id=7")
	}
	if !profile.Active {
		t.Fatalf("expected profile active")
	}
	if profile.VerifySigExtFn != nil {
		t.Fatalf("expected nil VerifySigExtFn for native binding")
	}
	if _, has := profile.AllowedSuites[1]; !has {
		t.Fatalf("expected allowed suite 1")
	}
	if _, has := profile.AllowedSuites[3]; !has {
		t.Fatalf("expected allowed suite 3")
	}
}

func TestBuildCoreExtProfilesVerifySigExtBindings(t *testing.T) {
	opensslDescriptor, err := consensus.CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", consensus.ML_DSA_87_PUBKEY_BYTES, consensus.ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("CoreExtOpenSSLDigest32BindingDescriptorBytes: %v", err)
	}
	tests := []struct {
		name              string
		binding           string
		bindingDescriptor string
		extPayloadSchema  string
		skipCall          bool
	}{
		{
			name:              "openssl-digest32-whitespace",
			binding:           "  " + consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 + "\n",
			bindingDescriptor: hex.EncodeToString(opensslDescriptor),
			extPayloadSchema:  "b2",
			skipCall:          true,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := buildCoreExtProfiles([]CoreExtProfileJSON{
				{
					ExtID:                uint16(100 + i),
					ActivationHeight:     0,
					AllowedSuiteIDs:      []uint8{3},
					Binding:              tc.binding,
					BindingDescriptorHex: tc.bindingDescriptor,
					ExtPayloadSchemaHex:  tc.extPayloadSchema,
				},
			}, "", "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			profile, ok, err := provider.LookupCoreExtProfile(uint16(100+i), 0)
			if err != nil {
				t.Fatalf("lookup failed: %v", err)
			}
			if !ok {
				t.Fatalf("missing profile")
			}
			if profile.VerifySigExtFn == nil {
				t.Fatalf("expected VerifySigExtFn for binding=%s", tc.binding)
			}
			if tc.skipCall {
				return
			}
			if gotOK, gotErr := profile.VerifySigExtFn(0, 3, nil, nil, [32]byte{}, nil); gotOK || gotErr != nil {
				t.Fatalf("unexpected verifier result for %s: ok=%v err=%v", tc.binding, gotOK, gotErr)
			}
		})
	}
}

func TestBuildCoreExtProfilesRejectsOpenSSLBindingWithoutPayloadSchema(t *testing.T) {
	descriptor, err := consensus.CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", consensus.ML_DSA_87_PUBKEY_BYTES, consensus.ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("CoreExtOpenSSLDigest32BindingDescriptorBytes: %v", err)
	}
	_, err = buildCoreExtProfiles([]CoreExtProfileJSON{
		{
			ExtID:                77,
			ActivationHeight:     0,
			AllowedSuiteIDs:      []uint8{3},
			Binding:              consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1,
			BindingDescriptorHex: hex.EncodeToString(descriptor),
		},
	}, "", "")
	if err == nil {
		t.Fatalf("expected missing ext_payload_schema rejection")
	}
}

func TestBuildCoreExtProfilesHeightGate(t *testing.T) {
	provider, err := buildCoreExtProfiles([]CoreExtProfileJSON{
		{
			ExtID:                77,
			ActivationHeight:     42,
			AllowedSuiteIDs:      []uint8{3},
			Binding:              consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1,
			BindingDescriptorHex: hex.EncodeToString(mustRuntimeOpenSSLDigest32Descriptor(t)),
			ExtPayloadSchemaHex:  "b2",
		},
	}, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Fatalf("expected provider")
	}
	if _, ok, err := provider.LookupCoreExtProfile(77, 41); err != nil {
		t.Fatalf("lookup failed: %v", err)
	} else if ok {
		t.Fatalf("profile must be inactive before activation height")
	}
	if _, ok, err := provider.LookupCoreExtProfile(77, 42); err != nil {
		t.Fatalf("lookup failed: %v", err)
	} else if !ok {
		t.Fatalf("profile must activate at activation height")
	}
}

func TestBuildCoreExtProfilesDuplicateRejected(t *testing.T) {
	descriptorHex := hex.EncodeToString(mustRuntimeOpenSSLDigest32Descriptor(t))
	_, err := buildCoreExtProfiles([]CoreExtProfileJSON{
		{ExtID: 9, ActivationHeight: 0, AllowedSuiteIDs: []uint8{3}, Binding: consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1, BindingDescriptorHex: descriptorHex, ExtPayloadSchemaHex: "b2"},
		{ExtID: 9, ActivationHeight: 10, AllowedSuiteIDs: []uint8{3}, Binding: consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1, BindingDescriptorHex: descriptorHex, ExtPayloadSchemaHex: "b2"},
	}, "", "")
	if err == nil {
		t.Fatalf("expected duplicate deployment error")
	}
}

func TestBuildCoreExtProfilesUnsupportedBindingRejected(t *testing.T) {
	_, err := buildCoreExtProfiles([]CoreExtProfileJSON{
		{ExtID: 10, ActivationHeight: 0, AllowedSuiteIDs: []uint8{3}, Binding: "unknown-binding"},
	}, "", "")
	if err == nil {
		t.Fatalf("expected unsupported binding error")
	}
}

func TestBuildCoreExtProfilesRejectsEmptyAllowedSuites(t *testing.T) {
	_, err := buildCoreExtProfiles([]CoreExtProfileJSON{
		{ExtID: 10, ActivationHeight: 0, AllowedSuiteIDs: nil, Binding: "native_verify_sig"},
	}, "", "")
	if err == nil {
		t.Fatalf("expected empty allowed suites error")
	}
}

func TestBuildCoreExtProfilesEmptySetAnchorEnforced(t *testing.T) {
	chainID := [32]byte{0: 0x42}
	anchor, err := consensus.CoreExtProfileSetAnchorV1(chainID, nil)
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(empty): %v", err)
	}
	provider, err := buildCoreExtProfiles(nil, hex.EncodeToString(chainID[:]), hex.EncodeToString(anchor[:]))
	if err != nil {
		t.Fatalf("buildCoreExtProfiles(empty anchor): %v", err)
	}
	if provider == nil {
		t.Fatalf("expected explicit empty provider for empty anchored profile set")
	}
	if _, ok, err := provider.LookupCoreExtProfile(7, 0); err != nil {
		t.Fatalf("LookupCoreExtProfile: %v", err)
	} else if ok {
		t.Fatalf("expected no active profile from empty anchored provider")
	}
	anchor[0] ^= 0xff
	if _, err := buildCoreExtProfiles(nil, hex.EncodeToString(chainID[:]), hex.EncodeToString(anchor[:])); err == nil {
		t.Fatalf("expected empty profile set anchor mismatch")
	}
}

func TestBuildCoreExtProfilesRejectsSetAnchorMismatch(t *testing.T) {
	descriptorHex := hex.EncodeToString(mustRuntimeOpenSSLDigest32Descriptor(t))
	items := []CoreExtProfileJSON{{
		ExtID:                7,
		ActivationHeight:     12,
		AllowedSuiteIDs:      []uint8{3},
		Binding:              consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1,
		BindingDescriptorHex: descriptorHex,
		ExtPayloadSchemaHex:  "b2",
	}}
	deployments, err := buildCoreExtDeployments(items)
	if err != nil {
		t.Fatalf("buildCoreExtDeployments: %v", err)
	}
	chainID := [32]byte{0: 0x42}
	anchor, err := consensus.CoreExtProfileSetAnchorV1(chainID, deployments)
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1: %v", err)
	}
	anchor[0] ^= 0xff
	if _, err := buildCoreExtProfiles(items, hex.EncodeToString(chainID[:]), hex.EncodeToString(anchor[:])); err == nil {
		t.Fatalf("expected set anchor mismatch error")
	}
}

func TestBuildCoreExtProfilesRejectsOversizedHexFields(t *testing.T) {
	_, err := buildCoreExtProfiles([]CoreExtProfileJSON{{
		ExtID:                7,
		ActivationHeight:     12,
		AllowedSuiteIDs:      []uint8{3},
		Binding:              consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1,
		BindingDescriptorHex: strings.Repeat("aa", maxCoreExtHexFieldBytes+1),
		ExtPayloadSchemaHex:  "b2",
	}}, "", "")
	if err == nil {
		t.Fatalf("expected oversized binding descriptor rejection")
	}
}

func TestBuildCoreExtProfilesRejectsUnsupportedBindingBeforeHexDecode(t *testing.T) {
	_, err := buildCoreExtProfiles([]CoreExtProfileJSON{{
		ExtID:                7,
		ActivationHeight:     12,
		AllowedSuiteIDs:      []uint8{3},
		Binding:              "unknown-binding",
		BindingDescriptorHex: "zz",
		ExtPayloadSchemaHex:  "zz",
	}}, "", "")
	if err == nil || !strings.Contains(err.Error(), "unsupported core_ext binding") {
		t.Fatalf("expected unsupported binding error, got %v", err)
	}
}

func TestBuildCoreExtProfilesRejectsTxContextEnabledWithoutRuntimeVerifier(t *testing.T) {
	_, err := buildCoreExtProfiles([]CoreExtProfileJSON{{
		ExtID:               7,
		ActivationHeight:    12,
		TxContextEnabled:    1,
		AllowedSuiteIDs:     []uint8{3},
		Binding:             "native_verify_sig",
		ExtPayloadSchemaHex: "b2",
	}}, "", "")
	if err == nil || !strings.Contains(err.Error(), "tx_context_enabled core_ext profile requires runtime txcontext verifier wiring") {
		t.Fatalf("expected tx_context_enabled runtime verifier rejection, got %v", err)
	}
}

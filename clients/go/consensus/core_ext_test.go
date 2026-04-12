package consensus

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type staticCoreExtProfiles map[uint16]CoreExtProfile

func (m staticCoreExtProfiles) LookupCoreExtProfile(extID uint16, _ uint64) (CoreExtProfile, bool, error) {
	p, ok := m[extID]
	return p, ok, nil
}

type nativeRotationProvider struct{}

func (nativeRotationProvider) NativeCreateSuites(uint64) *NativeSuiteSet {
	return mustNewNativeSuiteSet(0x02)
}

func (nativeRotationProvider) NativeSpendSuites(uint64) *NativeSuiteSet {
	return mustNewNativeSuiteSet(0x02)
}

type sunsetNativeRotationProvider struct{}

func (sunsetNativeRotationProvider) NativeCreateSuites(uint64) *NativeSuiteSet {
	return mustNewNativeSuiteSet(0x02)
}

func (sunsetNativeRotationProvider) NativeSpendSuites(uint64) *NativeSuiteSet {
	return mustNewNativeSuiteSet()
}

func coreExtCovenantData(extID uint16, payload []byte) []byte {
	out := AppendU16le(nil, extID)
	out = AppendCompactSize(out, uint64(len(payload)))
	out = append(out, payload...)
	return out
}

func TestParseCoreExtCovenantData_RejectsHugePayloadLenWithoutPanic(t *testing.T) {
	covData := []byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00}

	_, err := ParseCoreExtCovenantData(covData)
	if err == nil {
		t.Fatalf("expected error for oversized payload length")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if !strings.Contains(err.Error(), "ext_payload parse failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCoreExtCovenantData_RejectsUint64MaxPayloadLenWithoutPanic(t *testing.T) {
	covData := []byte{0x34, 0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}

	_, err := ParseCoreExtCovenantData(covData)
	if err == nil {
		t.Fatalf("expected error for uint64-max payload length")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if !strings.Contains(err.Error(), "ext_payload parse failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStaticCoreExtProfileProviderEmptyReturnsInactiveProvider(t *testing.T) {
	provider, err := NewStaticCoreExtProfileProvider(nil)
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider(nil): %v", err)
	}
	if provider == nil {
		t.Fatalf("expected non-nil provider for empty deployments")
	}
	if _, ok, err := provider.LookupCoreExtProfile(7, 0); err != nil {
		t.Fatalf("LookupCoreExtProfile: %v", err)
	} else if ok {
		t.Fatalf("expected no active profile from empty provider")
	}
}

func TestStaticCoreExtProfileProviderRejectsDuplicateExtID(t *testing.T) {
	_, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{
		{ExtID: 7, ActivationHeight: 1, AllowedSuites: map[uint8]struct{}{3: {}}, ExtPayloadSchema: []byte{0xb2}},
		{ExtID: 7, ActivationHeight: 2, AllowedSuites: map[uint8]struct{}{3: {}}, ExtPayloadSchema: []byte{0xb2}},
	})
	if err == nil {
		t.Fatalf("expected duplicate deployment error")
	}
}

func TestStaticCoreExtProfileProviderRejectsEmptyAllowedSuites(t *testing.T) {
	_, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{
		{ExtID: 7, ActivationHeight: 1, AllowedSuites: nil},
	})
	if err == nil {
		t.Fatalf("expected empty allowed suites error")
	}
}

func TestStaticCoreExtProfileProviderLookupRespectsActivationHeight(t *testing.T) {
	verifyFn := func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) {
		return true, nil
	}
	allowed := map[uint8]struct{}{1: {}, 3: {}}
	provider, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{
		{
			ExtID:            7,
			ActivationHeight: 12,
			AllowedSuites:    allowed,
			VerifySigExtFn:   verifyFn,
			BindingDescriptor: []byte{
				0xa1,
			},
			ExtPayloadSchema: []byte{
				0xb2,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	if profile, ok, err := provider.LookupCoreExtProfile(7, 11); err != nil {
		t.Fatalf("LookupCoreExtProfile pre-activation: %v", err)
	} else if ok || profile.Active {
		t.Fatalf("profile must be inactive before activation height")
	}

	profile, ok, err := provider.LookupCoreExtProfile(7, 12)
	if err != nil {
		t.Fatalf("LookupCoreExtProfile active: %v", err)
	}
	if !ok || !profile.Active {
		t.Fatalf("expected active profile at activation height")
	}
	if profile.VerifySigExtFn == nil {
		t.Fatalf("missing verify_sig_ext binding")
	}
	if _, has := profile.AllowedSuites[1]; !has {
		t.Fatalf("missing allowed suite 1")
	}
	if _, has := profile.AllowedSuites[3]; !has {
		t.Fatalf("missing allowed suite 3")
	}
	if len(profile.BindingDescriptor) != 1 || profile.BindingDescriptor[0] != 0xa1 {
		t.Fatalf("missing binding descriptor")
	}
	if len(profile.ExtPayloadSchema) != 1 || profile.ExtPayloadSchema[0] != 0xb2 {
		t.Fatalf("missing ext payload schema")
	}

	delete(profile.AllowedSuites, 1)
	profile.BindingDescriptor[0] = 0xff
	profile.ExtPayloadSchema[0] = 0xee
	profile2, ok, err := provider.LookupCoreExtProfile(7, 12)
	if err != nil {
		t.Fatalf("LookupCoreExtProfile second active lookup: %v", err)
	}
	if !ok {
		t.Fatalf("expected active profile on second lookup")
	}
	if _, has := profile2.AllowedSuites[1]; !has {
		t.Fatalf("provider must clone allowed suites per lookup")
	}
	if len(profile2.BindingDescriptor) != 1 || profile2.BindingDescriptor[0] != 0xa1 {
		t.Fatalf("provider must clone binding descriptor per lookup")
	}
	if len(profile2.ExtPayloadSchema) != 1 || profile2.ExtPayloadSchema[0] != 0xb2 {
		t.Fatalf("provider must clone ext payload schema per lookup")
	}
}

func TestStaticCoreExtProfileProviderNilReceiverAndUnknownExtID(t *testing.T) {
	var provider *StaticCoreExtProfileProvider
	if profile, ok, err := provider.LookupCoreExtProfile(7, 12); err != nil {
		t.Fatalf("LookupCoreExtProfile nil receiver: %v", err)
	} else if ok || profile.Active {
		t.Fatalf("nil provider must behave as inactive")
	}

	provider, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		AllowedSuites:    map[uint8]struct{}{1: {}},
		ExtPayloadSchema: []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}
	if profile, ok, err := provider.LookupCoreExtProfile(8, 12); err != nil {
		t.Fatalf("LookupCoreExtProfile unknown ext id: %v", err)
	} else if ok || profile.Active {
		t.Fatalf("unknown ext id must behave as inactive")
	}
}

func TestWrapCoreExtVerifySigExtWithTxContextNilAndForwarding(t *testing.T) {
	if wrapCoreExtVerifySigExtWithTxContext(nil) != nil {
		t.Fatalf("nil verify_sig_ext function must stay nil after wrapping")
	}

	digest := [32]byte{0: 0xaa, 31: 0x55}
	pubkey := []byte{0x01, 0x02}
	signature := []byte{0x03, 0x04}
	extPayload := []byte{0x05, 0x06}

	called := false
	wrapped := wrapCoreExtVerifySigExtWithTxContext(func(
		extID uint16,
		suiteID uint8,
		gotPubkey []byte,
		gotSignature []byte,
		gotDigest [32]byte,
		gotPayload []byte,
	) (bool, error) {
		called = true
		if extID != 7 || suiteID != 3 {
			t.Fatalf("unexpected ext dispatch: ext_id=%d suite_id=%d", extID, suiteID)
		}
		if string(gotPubkey) != string(pubkey) {
			t.Fatalf("unexpected pubkey: %x", gotPubkey)
		}
		if string(gotSignature) != string(signature) {
			t.Fatalf("unexpected signature: %x", gotSignature)
		}
		if gotDigest != digest {
			t.Fatalf("unexpected digest: %x", gotDigest)
		}
		if string(gotPayload) != string(extPayload) {
			t.Fatalf("unexpected payload: %x", gotPayload)
		}
		return true, nil
	})
	if wrapped == nil {
		t.Fatalf("expected wrapped verifier")
	}
	ok, err := wrapped(
		7,
		3,
		pubkey,
		signature,
		digest,
		extPayload,
		&TxContextBase{},
		&TxContextContinuing{},
		42,
	)
	if err != nil {
		t.Fatalf("wrapped verifier error: %v", err)
	}
	if !ok {
		t.Fatalf("wrapped verifier must preserve legacy success result")
	}
	if !called {
		t.Fatalf("wrapped verifier did not call legacy verifier")
	}
}

func TestCoreExtVerifySigExtTxContextFnPrefersExplicitBinding(t *testing.T) {
	explicitCalled := false
	legacyCalled := false
	explicitFn := func(
		uint16,
		uint8,
		[]byte,
		[]byte,
		[32]byte,
		[]byte,
		*TxContextBase,
		*TxContextContinuing,
		uint64,
	) (bool, error) {
		explicitCalled = true
		return true, nil
	}
	legacyFn := func(uint16, uint8, []byte, []byte, [32]byte, []byte) (bool, error) {
		legacyCalled = true
		return true, nil
	}

	preferred := coreExtVerifySigExtTxContextFn(CoreExtProfile{
		VerifySigExtFn:          legacyFn,
		VerifySigExtTxContextFn: explicitFn,
	})
	if preferred == nil {
		t.Fatalf("expected explicit txcontext verifier")
	}
	ok, err := preferred(7, 3, nil, nil, [32]byte{}, nil, &TxContextBase{}, &TxContextContinuing{}, 1)
	if err != nil {
		t.Fatalf("preferred verifier error: %v", err)
	}
	if !ok {
		t.Fatalf("preferred verifier must return explicit success result")
	}
	if !explicitCalled {
		t.Fatalf("explicit txcontext verifier not called")
	}
	if legacyCalled {
		t.Fatalf("legacy verifier must not be used when explicit txcontext binding exists")
	}

	explicitCalled = false
	legacyCalled = false
	fallback := coreExtVerifySigExtTxContextFn(CoreExtProfile{VerifySigExtFn: legacyFn})
	if fallback == nil {
		t.Fatalf("expected wrapped legacy verifier fallback")
	}
	ok, err = fallback(7, 3, nil, nil, [32]byte{}, nil, &TxContextBase{}, &TxContextContinuing{}, 2)
	if err != nil {
		t.Fatalf("fallback verifier error: %v", err)
	}
	if !ok {
		t.Fatalf("fallback verifier must preserve legacy success result")
	}
	if !legacyCalled {
		t.Fatalf("legacy verifier fallback not called")
	}
	if explicitCalled {
		t.Fatalf("explicit verifier state leaked into fallback path")
	}
	if coreExtVerifySigExtTxContextFn(CoreExtProfile{}) != nil {
		t.Fatalf("empty profile must not synthesize verify_sig_ext binding")
	}
}

func TestCoreExtProfileSetAnchorChangesWithPayloadSchema(t *testing.T) {
	chainID := [32]byte{0: 0x42}
	base := CoreExtDeploymentProfile{
		ExtID:             7,
		ActivationHeight:  1,
		AllowedSuites:     map[uint8]struct{}{3: {}},
		VerifySigExtFn:    func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) { return true, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}
	changed := base
	changed.ExtPayloadSchema = []byte{0xb3}

	baseAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{base})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(base): %v", err)
	}
	changedAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{changed})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(changed): %v", err)
	}
	if baseAnchor == changedAnchor {
		t.Fatalf("expected profile set anchor to change when ext_payload_schema changes")
	}
}

func TestCoreExtProfileSetAnchorChangesWithActivationHeight(t *testing.T) {
	chainID := [32]byte{0: 0x42}
	base := CoreExtDeploymentProfile{
		ExtID:             7,
		ActivationHeight:  1,
		AllowedSuites:     map[uint8]struct{}{3: {}},
		VerifySigExtFn:    func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) { return true, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}
	changed := base
	changed.ActivationHeight = 2

	baseAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{base})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(base): %v", err)
	}
	changedAnchor, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{changed})
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1(changed): %v", err)
	}
	if baseAnchor == changedAnchor {
		t.Fatalf("expected profile set anchor to change when activation_height changes")
	}
}

func TestCoreExtProfileSetAnchorV1RejectsTxContextEnabledProfiles(t *testing.T) {
	chainID := [32]byte{0: 0x42}
	_, err := CoreExtProfileSetAnchorV1(chainID, []CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 1,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{3: {}},
		ExtPayloadSchema: []byte{0xb2},
	}})
	if err == nil || err.Error() != "core_ext profile ext_id=7 txcontext-enabled profile requires v2 anchor pipeline" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCoreExtProfileBytesV1RejectsInvalidProfiles(t *testing.T) {
	t.Run("empty allowed suites", func(t *testing.T) {
		_, err := CoreExtProfileBytesV1(CoreExtDeploymentProfile{
			ExtID:            7,
			ActivationHeight: 1,
			ExtPayloadSchema: []byte{0xb2},
		})
		if err == nil || err.Error() != "core_ext profile ext_id=7 must have non-empty allowed suites" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("native binding rejects descriptor", func(t *testing.T) {
		_, err := CoreExtProfileBytesV1(CoreExtDeploymentProfile{
			ExtID:             7,
			ActivationHeight:  1,
			AllowedSuites:     map[uint8]struct{}{3: {}},
			BindingDescriptor: []byte{0xa1},
			ExtPayloadSchema:  []byte{0xb2},
		})
		if err == nil || err.Error() != "core_ext profile ext_id=7 native-only profile must not carry binding_descriptor" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("verify_sig_ext binding requires descriptor", func(t *testing.T) {
		_, err := CoreExtProfileBytesV1(CoreExtDeploymentProfile{
			ExtID:            7,
			ActivationHeight: 1,
			AllowedSuites:    map[uint8]struct{}{3: {}},
			VerifySigExtFn: func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) {
				return true, nil
			},
			ExtPayloadSchema: []byte{0xb2},
		})
		if err == nil || err.Error() != "core_ext profile ext_id=7 verify_sig_ext profile must carry binding_descriptor" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("txcontext enabled requires v2 pipeline", func(t *testing.T) {
		_, err := CoreExtProfileBytesV1(CoreExtDeploymentProfile{
			ExtID:            7,
			ActivationHeight: 1,
			TxContextEnabled: true,
			AllowedSuites:    map[uint8]struct{}{3: {}},
			ExtPayloadSchema: []byte{0xb2},
		})
		if err == nil || err.Error() != "core_ext profile ext_id=7 txcontext-enabled profile requires v2 anchor pipeline" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestValidateCoreExtWitnessAtHeightMixedProfileNativeSuiteUsesNativePath(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xad
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, _ := mustParseTxForUtxo(t, txBytes)
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}
	called := false
	profile := CoreExtProfile{
		Active:            true,
		AllowedSuites:     map[uint8]struct{}{0x02: {}, 0x03: {}},
		VerifySigExtFn:    func(uint16, uint8, []byte, []byte, [32]byte, []byte) (bool, error) { called = true; return false, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}
	w := WitnessItem{
		SuiteID:   0x02,
		Pubkey:    []byte{0x01, 0x02, 0x03, 0x04},
		Signature: []byte{0x05, 0x06, 0x07, 0x01},
	}
	registry := NewSuiteRegistryFromParams([]SuiteParams{{
		SuiteID:    0x02,
		PubkeyLen:  len(w.Pubkey),
		SigLen:     len(w.Signature) - 1,
		VerifyCost: 1,
		AlgName:    "ML-DSA-87",
	}})
	queue := NewSigCheckQueue(0).WithRegistry(registry)
	if err := validateCoreExtWitnessAtHeight(
		&CoreExtCovenantData{ExtID: 7, ExtPayload: []byte{0x99}},
		profile,
		w,
		tx,
		0,
		100,
		[32]byte{0: 0x42},
		0,
		cache,
		nativeRotationProvider{},
		registry,
		nil,
		queue,
	); err != nil {
		t.Fatalf("validateCoreExtWitnessAtHeight: %v", err)
	}
	if called {
		t.Fatalf("native suite path must not invoke verify_sig_ext")
	}
	if got := queue.Len(); got != 1 {
		t.Fatalf("sigQueue len=%d, want 1", got)
	}
}

func TestValidateCoreExtWitnessAtHeightNativeSuiteMissingRegistryFailsClosed(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xae
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, _ := mustParseTxForUtxo(t, txBytes)
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}
	called := false
	profile := CoreExtProfile{
		Active:            true,
		AllowedSuites:     map[uint8]struct{}{0x02: {}, 0x03: {}},
		VerifySigExtFn:    func(uint16, uint8, []byte, []byte, [32]byte, []byte) (bool, error) { called = true; return true, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}
	w := WitnessItem{
		SuiteID:   0x02,
		Pubkey:    []byte{0x01, 0x02, 0x03, 0x04},
		Signature: []byte{0x05, 0x06, 0x07, 0x01},
	}
	err = validateCoreExtWitnessAtHeight(
		&CoreExtCovenantData{ExtID: 7, ExtPayload: []byte{0x99}},
		profile,
		w,
		tx,
		0,
		100,
		[32]byte{0: 0x43},
		0,
		cache,
		nativeRotationProvider{},
		NewSuiteRegistryFromParams(nil),
		nil,
		nil,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	if err.Error() != "TX_ERR_SIG_ALG_INVALID: CORE_EXT registered native suite missing from registry" {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatalf("native suite path must fail closed before verify_sig_ext")
	}
}

func TestValidateCoreExtWitnessAtHeightRegisteredNativeSuiteOutsideSpendSetRejected(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xaf
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, _ := mustParseTxForUtxo(t, txBytes)
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}
	called := false
	profile := CoreExtProfile{
		Active:            true,
		AllowedSuites:     map[uint8]struct{}{0x02: {}, 0x03: {}},
		VerifySigExtFn:    func(uint16, uint8, []byte, []byte, [32]byte, []byte) (bool, error) { called = true; return true, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}
	w := WitnessItem{
		SuiteID:   0x02,
		Pubkey:    []byte{0x01, 0x02, 0x03, 0x04},
		Signature: []byte{0x05, 0x06, 0x07, 0x01},
	}
	err = validateCoreExtWitnessAtHeight(
		&CoreExtCovenantData{ExtID: 7, ExtPayload: []byte{0x99}},
		profile,
		w,
		tx,
		0,
		100,
		[32]byte{0: 0x44},
		0,
		cache,
		sunsetNativeRotationProvider{},
		NewSuiteRegistryFromParams([]SuiteParams{{
			SuiteID:    0x02,
			PubkeyLen:  len(w.Pubkey),
			SigLen:     len(w.Signature) - 1,
			VerifyCost: 1,
			AlgName:    "ML-DSA-87",
		}}),
		nil,
		nil,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	if err.Error() != "TX_ERR_SIG_ALG_INVALID: CORE_EXT registered native suite not spend-permitted at this height" {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatalf("registered native suite outside spend set must reject before verify_sig_ext")
	}
}

func TestValidateCoreExtWitnessAtHeight_TxContextEnabledDispatchesNineParam(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xb0

	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), []WitnessItem{{
		SuiteID:   0x42,
		Pubkey:    []byte{0x01, 0x02, 0x03},
		Signature: []byte{0x04, 0x01},
	}})
	tx, _ := mustParseTxForUtxo(t, txBytes)
	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	resolved := []UtxoEntry{{
		Value:        100,
		CovenantType: COV_TYPE_CORE_EXT,
		CovenantData: coreExtCovenantData(7, []byte{0xaa}),
	}}
	txContext, err := BuildTxContext(tx, resolved, mustBuildTxContextOutputExtIDCache(t, tx), 55, staticCoreExtProfiles{
		7: {Active: true, TxContextEnabled: true},
	})
	if err != nil {
		t.Fatalf("BuildTxContext: %v", err)
	}

	called := false
	profile := CoreExtProfile{
		Active:           true,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(
			extID uint16,
			suiteID uint8,
			pubkey []byte,
			signature []byte,
			digest32 [32]byte,
			extPayload []byte,
			ctxBase *TxContextBase,
			ctxContinuing *TxContextContinuing,
			selfInputValue uint64,
		) (bool, error) {
			called = true
			if extID != 7 || suiteID != 0x42 {
				t.Fatalf("extID/suiteID=%d/%d", extID, suiteID)
			}
			if string(extPayload) != string([]byte{0xaa}) {
				t.Fatalf("extPayload=%x", extPayload)
			}
			if ctxBase == nil || ctxBase.TotalIn != (Uint128{Lo: 100, Hi: 0}) || ctxBase.TotalOut != (Uint128{Lo: 90, Hi: 0}) || ctxBase.Height != 55 {
				t.Fatalf("ctxBase=%+v", ctxBase)
			}
			if ctxContinuing == nil || ctxContinuing.ContinuingOutputCount != 1 || ctxContinuing.ContinuingOutputs[0].Value != 90 {
				t.Fatalf("ctxContinuing=%+v", ctxContinuing)
			}
			if ctxContinuing.ContinuingOutputs[0].ExtPayload == nil || len(ctxContinuing.ContinuingOutputs[0].ExtPayload) != 0 {
				t.Fatalf("continuing payload must be non-nil empty slice, got %#v", ctxContinuing.ContinuingOutputs[0].ExtPayload)
			}
			if selfInputValue != 100 {
				t.Fatalf("selfInputValue=%d", selfInputValue)
			}
			_ = pubkey
			_ = signature
			_ = digest32
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}

	if err := validateCoreExtWitnessAtHeight(
		&CoreExtCovenantData{ExtID: 7, ExtPayload: []byte{0xaa}},
		profile,
		tx.Witness[0],
		tx,
		0,
		100,
		[32]byte{0: 0x55},
		55,
		sighashCache,
		nativeRotationProvider{},
		nil,
		txContext,
		nil,
	); err != nil {
		t.Fatalf("validateCoreExtWitnessAtHeight: %v", err)
	}
	if !called {
		t.Fatalf("expected 9-parameter verifier to run")
	}
}

func TestValidateCoreExtWitnessAtHeight_TxContextEnabledNilBundleFailsClosed(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xb1

	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), []WitnessItem{{
		SuiteID:   0x42,
		Pubkey:    []byte{0x01, 0x02, 0x03},
		Signature: []byte{0x04, 0x01},
	}})
	tx, _ := mustParseTxForUtxo(t, txBytes)
	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	called := false
	profile := CoreExtProfile{
		Active:           true,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(uint16, uint8, []byte, []byte, [32]byte, []byte, *TxContextBase, *TxContextContinuing, uint64) (bool, error) {
			called = true
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}

	err = validateCoreExtWitnessAtHeight(
		&CoreExtCovenantData{ExtID: 7, ExtPayload: []byte{0xaa}},
		profile,
		tx.Witness[0],
		tx,
		0,
		100,
		[32]byte{0: 0x56},
		55,
		sighashCache,
		nativeRotationProvider{},
		nil,
		nil,
		nil,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s want %s", got, TX_ERR_SIG_INVALID)
	}
	if err.Error() != "TX_ERR_SIG_INVALID: CORE_EXT txcontext bundle missing" {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Fatalf("verifier must not run when txcontext bundle is missing")
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_CORE_EXT_TxContextStep3cAndDispatch(t *testing.T) {
	var chainID [32]byte
	chainID[0] = 0x61
	var prev [32]byte
	prev[0] = 0xb2

	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), []WitnessItem{{
		SuiteID:   0x42,
		Pubkey:    []byte{0x01, 0x02, 0x03},
		Signature: []byte{0x04, 0x01},
	}})
	tx, txid := mustParseTxForUtxo(t, txBytes)

	called := false
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(
			extID uint16,
			suiteID uint8,
			_ []byte,
			_ []byte,
			_ [32]byte,
			extPayload []byte,
			ctxBase *TxContextBase,
			ctxContinuing *TxContextContinuing,
			selfInputValue uint64,
		) (bool, error) {
			called = true
			if extID != 7 || suiteID != 0x42 {
				t.Fatalf("extID/suiteID=%d/%d", extID, suiteID)
			}
			if string(extPayload) != string([]byte{0x99}) {
				t.Fatalf("extPayload=%x", extPayload)
			}
			if ctxBase == nil || ctxBase.TotalIn != (Uint128{Lo: 100, Hi: 0}) || ctxBase.TotalOut != (Uint128{Lo: 90, Hi: 0}) || ctxBase.Height != 1 {
				t.Fatalf("ctxBase=%+v", ctxBase)
			}
			if ctxContinuing == nil || ctxContinuing.ContinuingOutputCount != 1 || ctxContinuing.ContinuingOutputs[0].Value != 90 {
				t.Fatalf("ctxContinuing=%+v", ctxContinuing)
			}
			if ctxContinuing.ContinuingOutputs[0].ExtPayload == nil || len(ctxContinuing.ContinuingOutputs[0].ExtPayload) != 0 {
				t.Fatalf("continuing payload must be non-nil empty slice, got %#v", ctxContinuing.ContinuingOutputs[0].ExtPayload)
			}
			if selfInputValue != 100 {
				t.Fatalf("selfInputValue=%d", selfInputValue)
			}
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x99}),
		},
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
		tx,
		txid,
		utxos,
		1,
		0,
		0,
		chainID,
		profiles,
		nativeRotationProvider{},
		nil,
	); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext: %v", err)
	}
	if !called {
		t.Fatalf("expected txcontext-enabled verifier to run")
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_CORE_EXT_TxContextMalformedOutputFailsBeforeVerifier(t *testing.T) {
	var chainID [32]byte
	chainID[0] = 0x62
	var prev [32]byte
	prev[0] = 0xb3

	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_CORE_EXT, []byte{0x01}, []WitnessItem{{
		SuiteID:   0x42,
		Pubkey:    []byte{0x01, 0x02, 0x03},
		Signature: []byte{0x04, 0x01},
	}})
	tx, txid := mustParseTxForUtxo(t, txBytes)

	called := false
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(uint16, uint8, []byte, []byte, [32]byte, []byte, *TxContextBase, *TxContextContinuing, uint64) (bool, error) {
			called = true
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x99}),
		},
	}
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
		tx,
		txid,
		utxos,
		1,
		0,
		0,
		chainID,
		profiles,
		nativeRotationProvider{},
		nil,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if called {
		t.Fatalf("verifier must not run when step-2 cache construction fails")
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_CORE_EXT_TxContextTooManyContinuingOutputsFailsBeforeVerifier(t *testing.T) {
	var chainID [32]byte
	chainID[0] = 0x63
	var prev [32]byte
	prev[0] = 0xb4

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs: []TxOutput{
			{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, nil)},
			{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, []byte{0x01})},
			{Value: 30, CovenantType: COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantData(7, []byte{0x02})},
		},
		Witness: []WitnessItem{{
			SuiteID:   0x42,
			Pubkey:    []byte{0x01, 0x02, 0x03},
			Signature: []byte{0x04, 0x01},
		}},
	}
	txid := hashWithPrefix(0xb5)

	called := false
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		TxContextEnabled: true,
		AllowedSuites:    map[uint8]struct{}{0x42: {}},
		VerifySigExtTxContextFn: func(uint16, uint8, []byte, []byte, [32]byte, []byte, *TxContextBase, *TxContextContinuing, uint64) (bool, error) {
			called = true
			return true, nil
		},
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x99}),
		},
	}
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
		tx,
		txid,
		utxos,
		1,
		0,
		0,
		chainID,
		profiles,
		nativeRotationProvider{},
		nil,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
	if called {
		t.Fatalf("verifier must not run when txcontext build rejects excessive continuing outputs")
	}
}

func TestParseTx_UnknownSuiteAcceptedAndCharged(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xaa

	sentinelTxBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{
		// Use canonical HTLC-refund sentinel form to keep witness byte size identical
		// to the "unknown suite" item below (so weight delta is cost-only).
		{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}},
	})
	sentinelTx, _, _, _, err := ParseTx(sentinelTxBytes)
	if err != nil {
		t.Fatalf("ParseTx(sentinel): %v", err)
	}
	wSentinel, _, _, err := TxWeightAndStats(sentinelTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(sentinel): %v", err)
	}

	unknownTxBytes := txWithOneInputOneOutputWithWitness(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData(), []WitnessItem{
		{SuiteID: 0x09, Pubkey: make([]byte, 32), Signature: []byte{0x01}},
	})
	unknownTx, _, _, _, err := ParseTx(unknownTxBytes)
	if err != nil {
		t.Fatalf("ParseTx(unknown): %v", err)
	}
	if got := len(unknownTx.Witness); got != 1 || unknownTx.Witness[0].SuiteID != 0x09 {
		t.Fatalf("witness=%v, want suite_id=0x09", unknownTx.Witness)
	}
	wUnknown, _, _, err := TxWeightAndStats(unknownTx)
	if err != nil {
		t.Fatalf("TxWeightAndStats(unknown): %v", err)
	}
	if wUnknown != wSentinel+VERIFY_COST_UNKNOWN_SUITE {
		t.Fatalf("weight_unknown=%d, want %d", wUnknown, wSentinel+VERIFY_COST_UNKNOWN_SUITE)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_PreActiveAnyoneCanSpend_KeylessSentinelOK(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa1

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(1, nil),
		},
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdate: %v", err)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_PreActiveAnyoneCanSpend_NonKeylessSentinelOK(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa2

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(1, nil),
		},
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdate: %v", err)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_DeterministicCovenantDataParseFirst(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa3

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL, Pubkey: make([]byte, 32), Signature: []byte{0x01}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: []byte{0x01}, // malformed, must map to TX_ERR_COVENANT_TYPE_INVALID before witness checks
		},
	}
	_, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_RotatedNativeSuiteUsesRegistryPath(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa4

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	sig := make([]byte, ML_DSA_87_SIG_BYTES+1)
	sig[ML_DSA_87_SIG_BYTES] = 0x01
	tx.Witness = []WitnessItem{{
		SuiteID:   0x02,
		Pubkey:    make([]byte, ML_DSA_87_PUBKEY_BYTES),
		Signature: sig,
	}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, nil),
		},
	}
	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:            7,
		ActivationHeight: 0,
		AllowedSuites:    map[uint8]struct{}{0x02: {}},
		ExtPayloadSchema: []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}
	registry := NewSuiteRegistryFromParams([]SuiteParams{{
		SuiteID:    0x02,
		PubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
		SigLen:     ML_DSA_87_SIG_BYTES,
		VerifyCost: VERIFY_COST_ML_DSA_87,
		AlgName:    "ML-DSA-87",
	}})
	err = nil
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfilesAndSuiteContext(
		tx,
		txid,
		utxos,
		0,
		0,
		0,
		chainID,
		profiles,
		&mockRotationProvider{h2: 0},
		registry,
	)
	if err == nil {
		t.Fatalf("expected invalid signature error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_ActiveSuiteRulesAndVerifySig(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa4

	kp := mustMLDSA87Keypair(t)

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: SUITE_ID_SENTINEL}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x01}),
		},
	}

	profiles := staticCoreExtProfiles{
		7: {
			Active: true,
			AllowedSuites: map[uint8]struct{}{
				SUITE_ID_SENTINEL:  {},
				SUITE_ID_ML_DSA_87: {},
			},
		},
	}

	// Sentinel is explicitly forbidden under ACTIVE.
	_, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}

	// Valid ML-DSA signature succeeds under ACTIVE.
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp)}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(valid sig): %v", err)
	}

	// Same-length mutated signature must deterministically reject as TX_ERR_SIG_INVALID.
	bad := tx.Witness[0]
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[0] ^= 0x01
	tx.Witness = []WitnessItem{bad}
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_VerifySigExtErrorMapsToAlgInvalid(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa5

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{{SuiteID: 0x09, Pubkey: []byte{0x01}, Signature: []byte{0x02}}}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x01}),
		},
	}

	profiles := staticCoreExtProfiles{
		7: {
			Active: true,
			AllowedSuites: map[uint8]struct{}{
				0x09: {},
			},
			VerifySigExtFn: func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) {
				return false, errors.New("unsupported")
			},
		},
	}

	_, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestCoreExtOpenSSLDigest32BindingDescriptorRoundTrip(t *testing.T) {
	raw, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("CoreExtOpenSSLDigest32BindingDescriptorBytes: %v", err)
	}
	desc, err := ParseCoreExtOpenSSLDigest32BindingDescriptor(raw)
	if err != nil {
		t.Fatalf("ParseCoreExtOpenSSLDigest32BindingDescriptor: %v", err)
	}
	if desc.OpenSSLAlg != "ML-DSA-87" {
		t.Fatalf("alg=%q, want ML-DSA-87", desc.OpenSSLAlg)
	}
	if desc.PubkeyLen != ML_DSA_87_PUBKEY_BYTES {
		t.Fatalf("pubkey_len=%d, want %d", desc.PubkeyLen, ML_DSA_87_PUBKEY_BYTES)
	}
	if desc.SigLen != ML_DSA_87_SIG_BYTES {
		t.Fatalf("sig_len=%d, want %d", desc.SigLen, ML_DSA_87_SIG_BYTES)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_OpenSSLDigest32BindingVerifiesNonNativeSuite(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var chainID [32]byte
	chainID[0] = 0x33
	var prev [32]byte
	prev[0] = 0xa6

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	witness := signP2PKInputWitness(t, tx, 0, 100, chainID, kp)
	witness.SuiteID = 0x09
	tx.Witness = []WitnessItem{witness}

	descriptor, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("CoreExtOpenSSLDigest32BindingDescriptorBytes: %v", err)
	}
	verifyFn, err := ParseCoreExtVerifySigExtBinding(CoreExtBindingNameVerifySigExtOpenSSLDigest32V1, descriptor, []byte{0xb2})
	if err != nil {
		t.Fatalf("ParseCoreExtVerifySigExtBinding: %v", err)
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x01}),
		},
	}

	profiles := staticCoreExtProfiles{
		7: {
			Active: true,
			AllowedSuites: map[uint8]struct{}{
				0x09: {},
			},
			VerifySigExtFn:    verifyFn,
			BindingDescriptor: descriptor,
			ExtPayloadSchema:  []byte{0xb2},
		},
	}

	if _, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 0, 0, 0, chainID, profiles); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles: %v", err)
	}
}

func TestApplyNonCoinbaseTxBasic_CORE_EXT_TxContextEnabledOpenSSLDigest32BindingVerifiesMLDSA87Parity(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var chainID [32]byte
	chainID[0] = 0x74
	var prev [32]byte
	prev[0] = 0xa7

	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_CORE_EXT, coreExtCovenantData(7, nil), nil)
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp)}

	descriptor, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("CoreExtOpenSSLDigest32BindingDescriptorBytes: %v", err)
	}
	verifyFn, err := ParseCoreExtVerifySigExtBinding(CoreExtBindingNameVerifySigExtOpenSSLDigest32V1, descriptor, []byte{0xb2})
	if err != nil {
		t.Fatalf("ParseCoreExtVerifySigExtBinding: %v", err)
	}

	profiles, err := NewStaticCoreExtProfileProvider([]CoreExtDeploymentProfile{{
		ExtID:             7,
		ActivationHeight:  0,
		TxContextEnabled:  true,
		AllowedSuites:     map[uint8]struct{}{SUITE_ID_ML_DSA_87: {}},
		VerifySigExtFn:    verifyFn,
		BindingDescriptor: descriptor,
		ExtPayloadSchema:  []byte{0xb2},
	}})
	if err != nil {
		t.Fatalf("NewStaticCoreExtProfileProvider: %v", err)
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_EXT,
			CovenantData: coreExtCovenantData(7, []byte{0x99}),
		},
	}

	if _, _, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 55, 0, 0, chainID, profiles); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(valid sig): %v", err)
	}

	bad := tx.Witness[0]
	bad.Signature = append([]byte(nil), bad.Signature...)
	bad.Signature[0] ^= 0x01
	tx.Witness = []WitnessItem{bad}
	_, _, err = ApplyNonCoinbaseTxBasicUpdateWithMTPAndCoreExtProfiles(tx, txid, utxos, 55, 0, 0, chainID, profiles)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestVerifyCoreExtOpenSSLDigest32_LengthMismatchSkipsConsensusInit(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)
	opensslConsensusInitFn = func() error {
		return errors.New("boom")
	}
	desc := CoreExtOpenSSLDigest32BindingDescriptor{
		OpenSSLAlg: "ML-DSA-87",
		PubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
		SigLen:     ML_DSA_87_SIG_BYTES,
	}
	var digest32 [32]byte
	ok, err := verifyCoreExtOpenSSLDigest32(desc, []byte{0x01}, []byte{0x02}, digest32)
	if err != nil {
		t.Fatalf("verifyCoreExtOpenSSLDigest32: %v", err)
	}
	if ok {
		t.Fatalf("length mismatch should reject before OpenSSL init")
	}
}

func TestParseCoreExtVerifySigExtBinding_NativeAndUnsupported(t *testing.T) {
	verifyFn, err := ParseCoreExtVerifySigExtBinding("", nil, nil)
	if err != nil {
		t.Fatalf("native empty binding: %v", err)
	}
	if verifyFn != nil {
		t.Fatalf("native empty binding must not create verify function")
	}
	verifyFn, err = ParseCoreExtVerifySigExtBinding("native_verify_sig", nil, nil)
	if err != nil {
		t.Fatalf("native binding: %v", err)
	}
	if verifyFn != nil {
		t.Fatalf("native binding must not create verify function")
	}
	if _, err := ParseCoreExtVerifySigExtBinding("unsupported", nil, nil); err == nil {
		t.Fatalf("unsupported binding must fail")
	}
	if _, err := ParseCoreExtVerifySigExtBinding(CoreExtBindingNameVerifySigExtOpenSSLDigest32V1, []byte{0x01}, nil); err == nil {
		t.Fatalf("openssl binding without ext_payload_schema must fail")
	} else if got, want := err.Error(), fmt.Sprintf("core_ext binding %s requires ext_payload_schema_hex", CoreExtBindingNameVerifySigExtOpenSSLDigest32V1); got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}

func TestNormalizeLiveCoreExtBindingName(t *testing.T) {
	got, err := NormalizeLiveCoreExtBindingName(" " + CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 + " ")
	if err != nil {
		t.Fatalf("NormalizeLiveCoreExtBindingName(valid): %v", err)
	}
	if got != CoreExtBindingNameVerifySigExtOpenSSLDigest32V1 {
		t.Fatalf("got %q, want %q", got, CoreExtBindingNameVerifySigExtOpenSSLDigest32V1)
	}

	for _, binding := range []string{"", "native_verify_sig", "unsupported"} {
		if _, err := NormalizeLiveCoreExtBindingName(binding); err == nil {
			t.Fatalf("binding %q must fail live normalization", binding)
		}
	}
}

func TestParseLiveCoreExtVerifySigExtBinding(t *testing.T) {
	descriptor, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("descriptor bytes: %v", err)
	}

	if _, err := ParseLiveCoreExtVerifySigExtBinding("native_verify_sig", descriptor, []byte{0xb2}); err == nil {
		t.Fatalf("native binding must fail on live path")
	}
	if _, err := ParseLiveCoreExtVerifySigExtBinding(CoreExtBindingNameVerifySigExtOpenSSLDigest32V1, descriptor, nil); err == nil {
		t.Fatalf("missing ext_payload_schema must fail on live path")
	}

	verifyFn, err := ParseLiveCoreExtVerifySigExtBinding(" "+CoreExtBindingNameVerifySigExtOpenSSLDigest32V1+" ", descriptor, []byte{0xb2})
	if err != nil {
		t.Fatalf("ParseLiveCoreExtVerifySigExtBinding(valid): %v", err)
	}
	if verifyFn == nil {
		t.Fatalf("valid live binding must create verify function")
	}

	verifyFn, err = ParseNormalizedLiveCoreExtVerifySigExtBinding(CoreExtBindingNameVerifySigExtOpenSSLDigest32V1, descriptor, []byte{0xb2})
	if err != nil {
		t.Fatalf("ParseNormalizedLiveCoreExtVerifySigExtBinding(valid): %v", err)
	}
	if verifyFn == nil {
		t.Fatalf("normalized live binding must create verify function")
	}
	if _, err := ParseNormalizedLiveCoreExtVerifySigExtBinding("", descriptor, []byte{0xb2}); err == nil {
		t.Fatalf("empty normalized live binding must fail")
	} else if got, want := err.Error(), unsupportedCoreExtBindingError("").Error(); got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
	if _, err := ParseNormalizedLiveCoreExtVerifySigExtBinding("native_verify_sig", descriptor, []byte{0xb2}); err == nil {
		t.Fatalf("native normalized live binding must fail")
	} else if got, want := err.Error(), unsupportedCoreExtBindingError("native_verify_sig").Error(); got != want {
		t.Fatalf("err=%q, want %q", got, want)
	}
}

func TestLiveCoreExtNormalizationAndParserShareAcceptanceSet(t *testing.T) {
	descriptor, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("descriptor bytes: %v", err)
	}

	for _, binding := range []string{
		CoreExtBindingNameVerifySigExtOpenSSLDigest32V1,
		"",
		"native_verify_sig",
		"unsupported",
	} {
		normalized, normErr := NormalizeLiveCoreExtBindingName(binding)
		_, parseErr := ParseLiveCoreExtVerifySigExtBinding(binding, descriptor, []byte{0xb2})

		if normErr == nil && parseErr != nil {
			t.Fatalf("binding %q normalized to %q but parser rejected it: %v", binding, normalized, parseErr)
		}
		if normErr != nil && parseErr == nil {
			t.Fatalf("binding %q failed normalization but parser accepted it", binding)
		}
	}
}

func TestCoreExtOpenSSLDigest32BindingDescriptorErrors(t *testing.T) {
	if _, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("bad", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES); err == nil {
		t.Fatalf("unsupported alg must fail")
	}
	if _, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES-1, ML_DSA_87_SIG_BYTES); err == nil {
		t.Fatalf("pubkey len mismatch must fail")
	}
	if _, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES-1); err == nil {
		t.Fatalf("sig len mismatch must fail")
	}
}

func TestParseCoreExtOpenSSLDigest32BindingDescriptorRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"bad-prefix":      []byte("bad"),
		"missing-alg-len": append([]byte(nil), coreExtOpenSSLDigest32BindingDescriptorPrefix...),
		"alg-len-overflow": append(
			append([]byte(nil), coreExtOpenSSLDigest32BindingDescriptorPrefix...),
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		),
		"truncated-alg": append(
			AppendCompactSize(append([]byte(nil), coreExtOpenSSLDigest32BindingDescriptorPrefix...), 5),
			'M',
		),
		"missing-pubkey-len": append(
			AppendCompactSize(append([]byte(nil), coreExtOpenSSLDigest32BindingDescriptorPrefix...), 8),
			[]byte("ML-DSA-87")...,
		),
	}
	for name, raw := range cases {
		if _, err := ParseCoreExtOpenSSLDigest32BindingDescriptor(raw); err == nil {
			t.Fatalf("%s: expected malformed descriptor error", name)
		}
	}

	raw, err := CoreExtOpenSSLDigest32BindingDescriptorBytes("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("descriptor bytes: %v", err)
	}
	if _, err := ParseCoreExtOpenSSLDigest32BindingDescriptor(raw[:len(raw)-1]); err == nil {
		t.Fatalf("truncated descriptor must fail")
	}
	withExtra := append(append([]byte(nil), raw...), 0x00)
	if _, err := ParseCoreExtOpenSSLDigest32BindingDescriptor(withExtra); err == nil {
		t.Fatalf("trailing bytes must fail")
	}

	unsupportedAlg := append([]byte(nil), coreExtOpenSSLDigest32BindingDescriptorPrefix...)
	unsupportedAlg = AppendCompactSize(unsupportedAlg, 3)
	unsupportedAlg = append(unsupportedAlg, []byte("bad")...)
	unsupportedAlg = AppendCompactSize(unsupportedAlg, uint64(ML_DSA_87_PUBKEY_BYTES))
	unsupportedAlg = AppendCompactSize(unsupportedAlg, uint64(ML_DSA_87_SIG_BYTES))
	if _, err := ParseCoreExtOpenSSLDigest32BindingDescriptor(unsupportedAlg); err == nil {
		t.Fatalf("unsupported parsed alg must fail validation")
	}
}

func TestHasSuiteExported(t *testing.T) {
	allowed := map[uint8]struct{}{1: {}, 3: {}}
	if !HasSuiteExported(allowed, 1) {
		t.Fatal("expected suite 1 to be allowed")
	}
	if HasSuiteExported(allowed, 2) {
		t.Fatal("expected suite 2 to not be allowed")
	}
	if HasSuiteExported(nil, 1) {
		t.Fatal("expected nil map to return false")
	}
}

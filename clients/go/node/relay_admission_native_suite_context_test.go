package node

import (
	"fmt"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type nativeSuiteRelayContextMutableRotation struct {
	consensus.DefaultRotationProvider
	calls     int
	nilResult bool
}

func (p *nativeSuiteRelayContextMutableRotation) NativeSpendSuites(uint64) *consensus.NativeSuiteSet {
	p.calls++
	if p.nilResult {
		return nil
	}
	if p.calls%2 == 1 {
		return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87)
	}
	return consensus.NewNativeSuiteSet(0x03)
}

func TestNativeSuiteRelayContextTrust(t *testing.T) {
	registry := reorgTestSuiteRegistry(0x02)
	descriptor := consensus.CryptoRotationDescriptor{Name: "test", OldSuiteID: consensus.SUITE_ID_ML_DSA_87, NewSuiteID: 0x02, CreateHeight: 200, SpendHeight: 300}
	valid := consensus.DescriptorRotationProvider{Descriptor: descriptor}
	invalid := valid
	invalid.Descriptor.Name = ""
	validPointer := &consensus.DescriptorRotationProvider{Descriptor: descriptor}
	if err := validPointer.Descriptor.Validate(registry); err != nil || nativeSuiteRelayContextTrusted(MempoolConfig{RotationProvider: validPointer, SuiteRegistry: registry}) {
		t.Fatalf("pointer descriptor trust=%v validation=%v", nativeSuiteRelayContextTrusted(MempoolConfig{RotationProvider: validPointer, SuiteRegistry: registry}), err)
	}
	mutatedPointer := &consensus.DescriptorRotationProvider{Descriptor: descriptor}
	mutatedPointer.Descriptor.Name = ""
	var nilDefault *consensus.DefaultRotationProvider
	var nilDescriptor *consensus.DescriptorRotationProvider
	uncausedSuiteError := &consensus.TxError{Code: consensus.TX_ERR_SIG_ALG_INVALID}
	for _, rotation := range []consensus.RotationProvider{nilDefault, nilDescriptor} {
		policy := MempoolConfig{RotationProvider: rotation}
		if nativeSuiteRelayContextTrusted(policy) || relayDispositionForConsensusError(uncausedSuiteError, policy) != RelayAdmissionUnavailable {
			t.Fatal("typed-nil provider trusted or cache-authorizing")
		}
	}
	uncausedSimplicitySuiteError := &consensus.TxError{Code: consensus.TX_ERR_SIG_ALG_INVALID, Msg: "CORE_SIMPLICITY witness suite must be 0xF0"}
	if relayDispositionForConsensusError(uncausedSimplicitySuiteError, MempoolConfig{RotationProvider: &deploymentCauseRotation{}}) != RelayAdmissionUnavailable {
		t.Fatal("uncaused CORE_SIMPLICITY suite error cache-authorizing under untrusted policy")
	}
	suiteMessage := "TX_ERR_SIG_ALG_INVALID: CORE_P2PK suite not in native spend set"
	cases := []struct {
		name    string
		policy  MempoolConfig
		trusted bool
	}{
		{"nil", MempoolConfig{}, true},
		{"nil canonical registry", MempoolConfig{SuiteRegistry: consensus.DefaultSuiteRegistry()}, false},
		{"default value nil registry", MempoolConfig{RotationProvider: consensus.DefaultRotationProvider{}}, true},
		{"default value canonical registry", MempoolConfig{RotationProvider: consensus.DefaultRotationProvider{}, SuiteRegistry: consensus.DefaultSuiteRegistry()}, true},
		{"default pointer nil registry", MempoolConfig{RotationProvider: &consensus.DefaultRotationProvider{}}, true},
		{"default pointer canonical registry", MempoolConfig{RotationProvider: &consensus.DefaultRotationProvider{}, SuiteRegistry: consensus.DefaultSuiteRegistry()}, true},
		{"default pointer noncanonical registry", MempoolConfig{RotationProvider: &consensus.DefaultRotationProvider{}, SuiteRegistry: unboundAlgSuiteRegistry()}, false},
		{"default noncanonical registry", MempoolConfig{RotationProvider: consensus.DefaultRotationProvider{}, SuiteRegistry: unboundAlgSuiteRegistry()}, false},
		{"validated descriptor", MempoolConfig{RotationProvider: valid, SuiteRegistry: registry}, true},
		{"invalid descriptor", MempoolConfig{RotationProvider: invalid, SuiteRegistry: registry}, false},
		{"descriptor missing registry membership", MempoolConfig{RotationProvider: valid, SuiteRegistry: consensus.DefaultSuiteRegistry()}, false},
		{"validated descriptor pointer", MempoolConfig{RotationProvider: validPointer, SuiteRegistry: registry}, false},
		{"mutated descriptor pointer", MempoolConfig{RotationProvider: mutatedPointer, SuiteRegistry: registry}, false},
		{"custom default behavior", MempoolConfig{RotationProvider: &deploymentCauseRotation{}}, false},
		{"custom nil suites", MempoolConfig{RotationProvider: &nativeSuiteRelayContextMutableRotation{nilResult: true}}, false},
		{"custom empty suites", MempoolConfig{RotationProvider: emptySpendRotationProvider{}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nativeSuiteRelayContextTrusted(tc.policy); got != tc.trusted {
				t.Fatalf("trusted=%v, want %v", got, tc.trusted)
			}
			h := newRelayHarness(t, &tc.policy, 1_000_000)
			got := h.mp.AddRemoteTxForRelay(retargetFirstWitnessSuite(t, h.tx(0, 100_000, 100_000, 1), 0x02), h.context())
			want := RelayAdmissionUnavailable
			if tc.trusted {
				want = RelayAdmissionStableTerminalReject
			}
			if got.Disposition != want || got.HasAdmissionContext != tc.trusted || admitKind(t, got.Err) != TxAdmitRejected || got.Err.Error() != suiteMessage || h.mp.Len() != 0 || (!tc.trusted && got.AdmissionContext != (PendingOutpointAdmissionContext{})) {
				t.Fatalf("result=%+v, want disposition=%v context=%v message=%q", got, want, tc.trusted, suiteMessage)
			}
		})
	}
	h := newRelayHarness(t, nil, 1_000_000)
	h.mp.mu.Lock()
	h.mp.policy.RotationProvider = &deploymentCauseRotation{}
	h.mp.mu.Unlock()
	got := h.mp.AddRemoteTxForRelay(retargetFirstWitnessSuite(t, h.tx(0, 100_000, 100_000, 1), 0x02), h.context())
	if got.Disposition != RelayAdmissionUnavailable || got.HasAdmissionContext || got.AdmissionContext != (PendingOutpointAdmissionContext{}) || h.mp.Len() != 0 || admitKind(t, got.Err) != TxAdmitRejected || got.Err.Error() != suiteMessage {
		t.Fatalf("replacement result=%+v", got)
	}
	shape := &nativeSuiteRelayContextMutableRotation{}
	first, second := shape.NativeSpendSuites(0), shape.NativeSpendSuites(0)
	if first.Len() != 1 || !first.Contains(consensus.SUITE_ID_ML_DSA_87) || first.Contains(0x02) || first.Contains(0x03) || second.Len() != 1 || !second.Contains(0x03) || second.Contains(0x02) || second.Contains(consensus.SUITE_ID_ML_DSA_87) || first.Contains(0x03) == second.Contains(0x03) {
		t.Fatal("mutable provider suite shapes collapsed")
	}
	mutable := &nativeSuiteRelayContextMutableRotation{}
	if nativeSuiteRelayContextTrusted(MempoolConfig{RotationProvider: mutable}) || mutable.calls != 0 {
		t.Fatal("trust predicate called custom provider")
	}
	h = newRelayHarness(t, &MempoolConfig{RotationProvider: mutable}, 1_000_000)
	context, raw := h.context(), retargetFirstWitnessSuite(t, h.tx(0, 100_000, 100_000, 1), 0x02)
	for i := range 2 {
		got = h.mp.AddRemoteTxForRelay(raw, context)
		if got.Disposition != RelayAdmissionUnavailable || got.HasAdmissionContext || got.AdmissionContext != (PendingOutpointAdmissionContext{}) || admitKind(t, got.Err) != TxAdmitRejected || got.Err.Error() != suiteMessage || h.mp.Len() != 0 || mutable.calls != 2*(i+1) {
			t.Fatalf("mutable provider result=%+v", got)
		}
	}
	if after := h.context(); *after != *context {
		t.Fatalf("admission context moved: after=%+v before=%+v", *after, *context)
	}
	rotation := testSimplicityRotation{activeAt: 0, chainID: devnetGenesisChainID}
	if nativeSuiteRelayContextTrusted(MempoolConfig{RotationProvider: rotation}) {
		t.Fatal("custom CORE_SIMPLICITY provider trusted")
	}
	h = consensusSeamHarness(t, rotation)
	entry := h.st.Utxos[h.outpoints[0]]
	entry.CovenantType, entry.CovenantData = consensus.COV_TYPE_CORE_SIMPLICITY, simplicityCovenantDataForNodeTest([32]byte{0x54}, nil)
	h.st.Utxos[h.outpoints[0]] = entry
	expected := h.context()
	simplicityRaw := txWithOneInputOneOutput(h.outpoints[0].Txid, h.outpoints[0].Vout, 1, consensus.COV_TYPE_P2PK, h.toAddr, []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}})
	got = h.mp.AddRemoteTxForRelay(simplicityRaw, expected)
	if got.Disposition != RelayAdmissionStableTerminalReject || !got.HasAdmissionContext || got.AdmissionContext != *expected || admitKind(t, got.Err) != TxAdmitRejected || got.Err.Error() != "TX_ERR_SIG_ALG_INVALID: CORE_SIMPLICITY witness suite must be 0xF0" || h.mp.Len() != 0 {
		t.Fatalf("CORE_SIMPLICITY witness suite result=%+v", got)
	}
	h = newRelayHarness(t, &MempoolConfig{SuiteRegistry: unboundAlgSuiteRegistry()}, 1_000_000)
	got = h.mp.AddRemoteTxForRelay(h.tx(0, 100_000, 100_000, 1), h.context())
	localMessage := fmt.Sprintf("%s: suite_id=0x%02x resolveSuiteVerifierBinding: unsupported alg=%q pubkey_len=%d sig_len=%d", consensus.TX_ERR_SIG_ALG_INVALID, consensus.SUITE_ID_ML_DSA_87, "ML-DSA-87-NOT-LIVE-BOUND", consensus.ML_DSA_87_PUBKEY_BYTES, consensus.ML_DSA_87_SIG_BYTES)
	if got.Disposition != RelayAdmissionInternal || got.HasAdmissionContext || got.AdmissionContext != (PendingOutpointAdmissionContext{}) || admitKind(t, got.Err) != TxAdmitRejected || got.Err.Error() != localMessage || h.mp.Len() != 0 {
		t.Fatalf("local backend result=%+v", got)
	}
	h = newRelayHarness(t, &MempoolConfig{RotationProvider: &deploymentCauseRotation{}}, 1_000_000)
	got = h.mp.AddRemoteTxForRelay(corruptFirstWitnessSignature(t, h.tx(0, 100_000, 100_000, 1)), h.context())
	if got.Disposition != RelayAdmissionStableTerminalReject || !got.HasAdmissionContext || admitKind(t, got.Err) != TxAdmitRejected || got.Err.Error() != "TX_ERR_SIG_INVALID: CORE_P2PK signature invalid" || h.mp.Len() != 0 {
		t.Fatalf("unrelated result=%+v", got)
	}
}

package node

import (
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// This file is the RELAY CLASSIFICATION CORPUS for the CORE_SIMPLICITY
// deployment seam reached through CONSENSUS validation — the path taken when
// PolicyRejectSimplicityPreActivation is DISABLED, so the deployment gate fires
// inside CheckTransactionWithOwnedUtxoSetAndValidationContext and the error
// arrives at relayDispositionForInputError.
//
// OBSERVABILITY: the typed consensus cause is NOT published through this
// surface. AddRemoteTxForRelay exposes the disposition, the identity fields, the
// context authority and the rendered "CODE: message" text — never a
// *consensus.TxError. These rows therefore prove the cause only INDIRECTLY,
// through the disposition it selects. THREE of the four causes share the
// UNAVAILABLE disposition and are NOT separable from each other here; that
// distinction is proven in the consensus corpus
// (consensus/simplicity_deployment_cause_test.go) and a row claiming to
// separate them at this surface would be a false claim.

// deploymentCauseRotation publishes one CORE_SIMPLICITY deployment state
// through a live RotationProvider. It is a POINTER receiver so a single mempool
// can observe a different published set at the SAME tip and generation.
type deploymentCauseRotation struct {
	consensus.DefaultRotationProvider
	descriptors []consensus.SimplicityDeploymentDescriptor
	anchor      [32]byte
	ok          bool
	err         error
}

func (p *deploymentCauseRotation) PublishedSimplicityDeployments() ([]consensus.SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	return p.descriptors, p.anchor, p.ok, p.err
}

// deploymentSetAt builds a complete, anchor-valid published set whose single
// descriptor activates at activationHeight.
func deploymentSetAt(t *testing.T, activationHeight uint64) ([]consensus.SimplicityDeploymentDescriptor, [32]byte) {
	t.Helper()
	descriptor := consensus.LiveSimplicityDeploymentDescriptor(devnetGenesisChainID)
	descriptor.ActivationHeight = activationHeight
	set := []consensus.SimplicityDeploymentDescriptor{descriptor}
	anchor, err := consensus.SimplicityDeploymentSetAnchor(devnetGenesisChainID, set)
	if err != nil {
		t.Fatalf("SimplicityDeploymentSetAnchor: %v", err)
	}
	return set, anchor
}

// consensusSeamHarness builds a mempool whose CORE_SIMPLICITY pre-activation
// POLICY lane is disabled, so the candidate reaches consensus validation and the
// deployment gate decides there.
func consensusSeamHarness(t *testing.T, rotation consensus.RotationProvider) *relayHarness {
	t.Helper()
	return newRelayHarness(t, &MempoolConfig{
		MaxTransactions:                     10,
		MaxBytes:                            1 << 20,
		PolicyRejectSimplicityPreActivation: false,
		RotationProvider:                    rotation,
	}, 1_000_000)
}

// candidateIdentity is the canonical identity the producer must publish for the
// candidate bytes, parsed independently of the mempool.
func candidateIdentity(t *testing.T, raw []byte) ([32]byte, [32]byte) {
	t.Helper()
	_, txid, wtxid, _, err := consensus.ParseTx(raw)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return txid, wtxid
}

// TestRelayAdmissionSimplicityDeploymentCauseDispositions is the FAULT-INJECTION
// MATRIX over the consensus seam: provider I/O error, ok=false, anchor mismatch,
// duplicate anchor, a complete verified inactive set, a governing active set, and
// no provider configured — all through the same real public entry point.
//
// Only the no-provider state rests on constructor-frozen configuration and stays
// a stable terminal rejection carrying context authority. Every provider-decided
// state is UNAVAILABLE and publishes no context, so none of them can authorize a
// relay representation cache.
func TestRelayAdmissionSimplicityDeploymentCauseDispositions(t *testing.T) {
	governingSet, governingAnchor := deploymentSetAt(t, 0)
	futureSet, futureAnchor := deploymentSetAt(t, 1<<40)
	mismatchedAnchor := governingAnchor
	mismatchedAnchor[0] ^= 0xFF

	const notActive = "TX_ERR_COVENANT_TYPE_INVALID: CORE_SIMPLICITY deployment not active"
	const lookupFailure = "TX_ERR_COVENANT_TYPE_INVALID: CORE_SIMPLICITY deployment lookup failure"

	duplicateSet := []consensus.SimplicityDeploymentDescriptor{governingSet[0], governingSet[0]}

	cases := []struct {
		name        string
		rotation    consensus.RotationProvider
		want        RelayAdmissionDisposition
		wantMessage string
	}{
		{name: "no provider configured is constructor-frozen and terminal", rotation: nil,
			want: RelayAdmissionStableTerminalReject, wantMessage: notActive},
		{name: "provider I/O error cannot determine the state", rotation: &deploymentCauseRotation{err: errors.New("deployment store offline")},
			want: RelayAdmissionUnavailable, wantMessage: lookupFailure},
		{name: "ok=false publishes an unobtainable or partial set", rotation: &deploymentCauseRotation{descriptors: governingSet, anchor: governingAnchor, ok: false},
			want: RelayAdmissionUnavailable, wantMessage: notActive},
		{name: "a set failing its own anchor is invalid evidence", rotation: &deploymentCauseRotation{descriptors: governingSet, anchor: mismatchedAnchor, ok: true},
			want: RelayAdmissionUnavailable, wantMessage: notActive},
		{name: "a duplicate descriptor anchor is invalid evidence", rotation: &deploymentCauseRotation{descriptors: duplicateSet, anchor: governingAnchor, ok: true},
			want: RelayAdmissionUnavailable, wantMessage: notActive},
		{name: "a complete verified set with no governing descriptor is still provider-dependent", rotation: &deploymentCauseRotation{descriptors: futureSet, anchor: futureAnchor, ok: true},
			want: RelayAdmissionUnavailable, wantMessage: notActive},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := consensusSeamHarness(t, tc.rotation)
			raw := simplicityPolicyCandidate(h)
			wantTxID, wantWTxID := candidateIdentity(t, raw)
			expected := h.context()
			entryTime := *expected

			got := h.mp.AddRemoteTxForRelay(raw, expected)

			if got.Disposition != tc.want {
				t.Fatalf("disposition=%v, want %v (err=%v)", got.Disposition, tc.want, got.Err)
			}
			if kind := admitKind(t, got.Err); kind != TxAdmitRejected {
				t.Fatalf("kind=%v, want the unchanged TxAdmitRejected", kind)
			}
			if got.Err.Error() != tc.wantMessage {
				t.Fatalf("message=%q, want the unchanged %q", got.Err.Error(), tc.wantMessage)
			}
			if got.TxID != wantTxID || got.WTxID != wantWTxID {
				t.Fatalf("identity=(%x,%x), want (%x,%x)", got.TxID, got.WTxID, wantTxID, wantWTxID)
			}
			wantContext := tc.want == RelayAdmissionStableTerminalReject
			if got.HasAdmissionContext != wantContext {
				t.Fatalf("HasAdmissionContext=%v, want %v", got.HasAdmissionContext, wantContext)
			}
			if wantContext && got.AdmissionContext != entryTime {
				t.Fatalf("published context=%+v, want the entry-time %+v", got.AdmissionContext, entryTime)
			}
			if !wantContext && got.AdmissionContext != (PendingOutpointAdmissionContext{}) {
				t.Fatalf("a provider-decided outcome published cache authority: %+v", got.AdmissionContext)
			}
			if h.mp.Len() != 0 {
				t.Fatalf("a rejected candidate became resident: len=%d", h.mp.Len())
			}
			// The legacy wrapper observes the byte-identical failure: the
			// classification is published beside the error, never inside it.
			legacy := h.mp.AddRemoteTx(raw)
			if legacy == nil || legacy.Error() != tc.wantMessage || admitKind(t, legacy) != TxAdmitRejected {
				t.Fatalf("legacy AddRemoteTx err=%v, want the identical %q", legacy, tc.wantMessage)
			}
		})
	}
}

// TestRelayAdmissionSimplicityDeploymentActiveContinues is the matrix's
// affirmative row at this surface: with a governing descriptor the deployment
// gate produces no error at all, so validation CONTINUES and the candidate is
// judged on its own bytes. The published outcome must therefore be neither
// deployment message.
func TestRelayAdmissionSimplicityDeploymentActiveContinues(t *testing.T) {
	governingSet, governingAnchor := deploymentSetAt(t, 0)
	h := consensusSeamHarness(t, &deploymentCauseRotation{descriptors: governingSet, anchor: governingAnchor, ok: true})
	raw := simplicityPolicyCandidate(h)

	got := h.mp.AddRemoteTxForRelay(raw, h.context())
	if got.Err == nil {
		t.Fatal("the unsigned candidate was admitted")
	}
	// The candidate is unsigned, so validation runs PAST the deployment gate and
	// stops at the witness it does not carry.
	if got.Err.Error() != witnessUnderflow {
		t.Fatalf("message=%q, want validation to continue to %q", got.Err.Error(), witnessUnderflow)
	}
	// Its own bytes are stably invalid against this exact context.
	if got.Disposition != RelayAdmissionStableTerminalReject {
		t.Fatalf("disposition=%v, want STABLE_TERMINAL_REJECT for candidate invalidity (err=%v)", got.Disposition, got.Err)
	}
}

// witnessUnderflow is the first error the unsigned corpus candidate meets ONCE
// the CORE_SIMPLICITY deployment gate stops deciding: proof that the gate is out
// of the way, not that the candidate is well formed.
const witnessUnderflow = "TX_ERR_PARSE: witness underflow"

// TestRelayAdmissionSimplicityDeploymentSetIsNotPinnedByContext is the hostile
// row that motivates the whole classification: at the SAME stable tip and the
// SAME generation, a non-nil provider publishing a DIFFERENT complete set flips
// the outcome for byte-identical candidate bytes. The admission context compares
// equal across both calls, which is exactly why a provider-decided outcome may
// never publish that context as cache authority.
func TestRelayAdmissionSimplicityDeploymentSetIsNotPinnedByContext(t *testing.T) {
	futureSet, futureAnchor := deploymentSetAt(t, 1<<40)
	rotation := &deploymentCauseRotation{descriptors: futureSet, anchor: futureAnchor, ok: true}
	h := consensusSeamHarness(t, rotation)
	raw := simplicityPolicyCandidate(h)

	before := *h.context()
	first := h.mp.AddRemoteTxForRelay(raw, &before)
	if first.Disposition != RelayAdmissionUnavailable {
		t.Fatalf("first disposition=%v, want UNAVAILABLE (err=%v)", first.Disposition, first.Err)
	}

	// Same mempool, same tip, same generation — only the published set moves.
	governingSet, governingAnchor := deploymentSetAt(t, 0)
	rotation.descriptors = governingSet
	rotation.anchor = governingAnchor

	after := *h.context()
	if after != before {
		t.Fatalf("admission context moved between calls: %+v vs %+v", after, before)
	}
	second := h.mp.AddRemoteTxForRelay(raw, &after)
	if second.Err == nil || second.Err.Error() != witnessUnderflow {
		t.Fatalf("second outcome=%v, want the gate to stop deciding and validation to reach %q", second.Err, witnessUnderflow)
	}
	if first.HasAdmissionContext {
		t.Fatal("a provider-decided outcome published cache authority")
	}
}

// TestRelayDispositionForInputErrorCauseArms pins the consumer arm itself,
// including the property the end-to-end rows cannot reach: an UNSPECIFIED cause
// preserves every existing ErrorCode-based mapping, in both the dependency and
// the non-dependency direction.
//
// An UNKNOWN non-zero cause is deliberately NOT a row: the cause field is
// unexported and only a consensus producer can set one, so package node cannot
// construct that value and no test here may claim to have exercised it. Its
// behavior is structural instead — the cause switch's default arm returns
// INTERNAL, so a cause added upstream without an arm here fails closed rather
// than reaching the caller's nonDependency verdict. An UNSPECIFIED cause is a
// separate explicit arm and does keep the ErrorCode fallback; that half IS
// pinned by the uncaused rows below.
//
// It does NOT claim to prove the cause-before-code ORDER: no error can carry a
// deployment cause AND one of the switch-set codes, so the two orders are
// observationally identical here (see the ordering note on
// relayDispositionForInputError).
func TestRelayDispositionForInputErrorCauseArms(t *testing.T) {
	chainID := devnetGenesisChainID
	// Real producer errors, not literals: the cause field is unexported, so
	// package node can only obtain a caused error from the consensus producer.
	futureDescriptor := consensus.LiveSimplicityDeploymentDescriptor(chainID)
	futureDescriptor.ActivationHeight = 1 << 40
	futureSet := []consensus.SimplicityDeploymentDescriptor{futureDescriptor}
	futureAnchor, err := consensus.SimplicityDeploymentSetAnchor(chainID, futureSet)
	if err != nil {
		t.Fatalf("SimplicityDeploymentSetAnchor: %v", err)
	}

	simplicityOutputTx := func() *consensus.Tx {
		return &consensus.Tx{Outputs: []consensus.TxOutput{{
			Value:        1,
			CovenantType: consensus.COV_TYPE_CORE_SIMPLICITY,
			CovenantData: simplicityCovenantDataForNodeTest([32]byte{0x53}, nil),
		}}}
	}
	causedBy := func(rotation consensus.RotationProvider) error {
		e := consensus.ValidateTxCovenantsGenesis(simplicityOutputTx(), chainID, 10, rotation)
		if e == nil {
			t.Fatal("expected a deployment rejection")
		}
		return e
	}

	cases := []struct {
		name string
		err  error
		want RelayAdmissionDisposition
	}{
		{"frozen no-provider stays terminal", causedBy(nil), RelayAdmissionStableTerminalReject},
		{"provider I/O error is unavailable",
			causedBy(&deploymentCauseRotation{err: errors.New("offline")}), RelayAdmissionUnavailable},
		{"ok=false is unavailable",
			causedBy(&deploymentCauseRotation{descriptors: futureSet, anchor: futureAnchor, ok: false}), RelayAdmissionUnavailable},
		{"provider-dependent inactivity is unavailable",
			causedBy(&deploymentCauseRotation{descriptors: futureSet, anchor: futureAnchor, ok: true}), RelayAdmissionUnavailable},
		// UNSPECIFIED preserves the baseline mappings in both directions.
		{"uncaused missing utxo keeps the dependency mapping",
			&consensus.TxError{Code: consensus.TX_ERR_MISSING_UTXO, Msg: "missing utxo"}, RelayAdmissionMissingDependency},
		{"uncaused covenant rejection keeps the caller's non-dependency verdict",
			&consensus.TxError{Code: consensus.TX_ERR_COVENANT_TYPE_INVALID, Msg: "CORE_SIMPLICITY deployment not active"},
			RelayAdmissionStableTerminalReject},
		{"a non-TxError keeps the caller's non-dependency verdict",
			errors.New("plain"), RelayAdmissionStableTerminalReject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := relayDispositionForInputError(tc.err, RelayAdmissionStableTerminalReject); got != tc.want {
				t.Fatalf("disposition=%v, want %v", got, tc.want)
			}
		})
	}

	// The OTHER caller — the policy input-snapshot seam — passes
	// RelayAdmissionInternal as its non-dependency verdict, and an uncaused error
	// must still receive exactly that.
	if got := relayDispositionForInputError(errors.New("nil utxo set"), RelayAdmissionInternal); got != RelayAdmissionInternal {
		t.Fatalf("snapshot-seam non-dependency=%v, want INTERNAL", got)
	}
	// The frozen arm selects its disposition rather than deferring to the
	// caller's. That difference is NOT production-reachable — policyInputSnapshot
	// produces only errors.New and a cause-free TX_ERR_MISSING_UTXO, so no
	// deployment cause reaches the snapshot seam — but it is the code's behavior
	// and is pinned here rather than left for a reader to infer.
	if got := relayDispositionForInputError(causedBy(nil), RelayAdmissionInternal); got != RelayAdmissionStableTerminalReject {
		t.Fatalf("frozen cause under an INTERNAL caller=%v, want STABLE_TERMINAL_REJECT", got)
	}
}

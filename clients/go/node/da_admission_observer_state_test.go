//go:build rubin_da_observer

package node

import (
	"bytes"
	"cmp"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var daNodeObserverStateIDs = []string{
	"CAP_ALL_MEMBERS_REMOVED",
	"CAP_PLAN_ABORT_PRESERVES_IMAGE",
	"CAP_STALE_PLAN_REJECT",
	"CAP_COMMIT_EXACT_IMAGE",
	"CAP_COUNTER_COHERENCE",
	"CAP_OWNER_ROLLBACK",
	"CAP_INVALID_RESIDENT_REJECT",
	"CAP_MISSING_MEMBER_REJECT",
	"CAP_OWNER_ORPHAN_REJECT",
	"CAP_SEQUENCE_LAST",
	"CAP_SEQUENCE_BOUNDARY_CROSS",
	"STATE_B_PEER_CHUNK_CLEANUP_PRESERVES_NONPEER",
	"STATE_B_PEER_COMMIT_CLEANUP_PROTECTED",
}

type daNodeObserverStateInput struct {
	ExecutionBoundary string          `json:"execution_boundary"`
	ConstructionRef   string          `json:"construction_ref"`
	CaseOrdinal       *uint64         `json:"case_ordinal"`
	AcceptedSequence  json.RawMessage `json:"accepted_sequence"`
	Control           json.RawMessage `json:"control"`
	FollowUp          string          `json:"follow_up"`
	MemberProvenance  json.RawMessage `json:"member_provenance"`
	CleanupSelector   json.RawMessage `json:"cleanup_selector"`
	acceptedSequence  uint64
	control           daNodeObserverStateControl
	quotaIdentity     string
	provenance        []DAProvenance
}

type daNodeObserverStateControl struct {
	Phase                    json.RawMessage `json:"phase"`
	Action                   json.RawMessage `json:"action"`
	Member                   json.RawMessage `json:"member"`
	PreserveOtherFields      json.RawMessage `json:"preserve_other_fields"`
	LocatorDAID              json.RawMessage `json:"locator_da_id"`
	TargetRevision           json.RawMessage `json:"target_revision"`
	GlobalRecordRevision     json.RawMessage `json:"global_record_revision"`
	IntrinsicTotalBytesDelta json.RawMessage `json:"intrinsic_total_bytes_delta"`
	phase                    string
	action                   string
	selected                 *daNodeObserverStateMemberKey
	locator                  [32]byte
	delta                    uint64
}

type daNodeObserverStateMemberSelector struct {
	ClassOrdinal    *uint64 `json:"class_ordinal"`
	ResidentOrdinal *uint64 `json:"resident_ordinal"`
	MemberOrdinal   *uint64 `json:"member_ordinal"`
}

type daNodeObserverProvenance struct {
	Source        json.RawMessage `json:"source"`
	PeerIdentity  json.RawMessage `json:"peer_identity"`
	QuotaIdentity json.RawMessage `json:"quota_identity"`
}

type daNodeObserverCleanupSelector struct {
	QuotaIdentity json.RawMessage `json:"quota_identity"`
}

type daNodeObserverStateCase struct {
	Case  daNodeObserverCase
	Input daNodeObserverStateInput
}

type daNodeObserverStateFixtures struct {
	ChainContexts      map[string]json.RawMessage `json:"chain_contexts"`
	ConstructionInputs map[string]json.RawMessage `json:"construction_inputs"`
}

type daNodeObserverStateCanonicalProfile struct {
	ChainContextRef string `json:"chain_context_ref"`
	ChainHeight     string `json:"chain_height"`
	Version         uint32 `json:"version"`
	Locktime        uint32 `json:"locktime"`
	Input           struct {
		Count             uint64 `json:"count"`
		Value             string `json:"value"`
		CreationHeight    string `json:"creation_height"`
		CreatedByCoinbase bool   `json:"created_by_coinbase"`
		ScriptSigHex      string `json:"script_sig_hex"`
		Sequence          uint32 `json:"sequence"`
		PrevTxID          string `json:"prev_txid"`
		PrevVout          string `json:"prev_vout"`
	} `json:"input"`
	Nonce   string `json:"nonce"`
	Signing struct {
		SuiteID                         uint8  `json:"suite_id"`
		PubkeyBytes                     uint64 `json:"pubkey_bytes"`
		SignatureBytesIncludingSelector uint64 `json:"signature_bytes_including_selector"`
		SighashSelector                 uint8  `json:"sighash_selector"`
		KeyBinding                      string `json:"key_binding"`
	} `json:"signing"`
	Outputs struct {
		Change     string `json:"change"`
		CommitOnly string `json:"commit_only"`
	} `json:"outputs"`
	Commit struct {
		ManifestHex     string `json:"manifest_hex"`
		BatchNumber     string `json:"batch_number"`
		RetlDomainID    string `json:"retl_domain_id"`
		TxDataRoot      string `json:"tx_data_root"`
		StateRoot       string `json:"state_root"`
		WithdrawalsRoot string `json:"withdrawals_root"`
		BatchSigSuite   uint8  `json:"batch_sig_suite"`
		BatchSigHex     string `json:"batch_sig_hex"`
		ChunkCount      string `json:"chunk_count"`
	} `json:"commit"`
	Chunk struct {
		ChunkIndex string `json:"chunk_index"`
		ChunkHash  string `json:"chunk_hash"`
		Payload    string `json:"payload"`
	} `json:"chunk"`
	Policy struct {
		MinDAFeeRate             string `json:"min_da_fee_rate"`
		DASurchargePerByte       string `json:"da_surcharge_per_byte"`
		PolicyMaxDABytesPerBlock string `json:"policy_max_da_bytes_per_block"`
		RollingFeeFloor          string `json:"rolling_fee_floor"`
	} `json:"policy"`
	WireSize struct {
		Commit string `json:"commit"`
		Chunk  string `json:"chunk"`
	} `json:"wire_size"`
	ConstructionBoundary string `json:"construction_boundary"`
	IdentityProjection   string `json:"identity_projection"`
}

type daNodeObserverStateResidentClass struct {
	ClassOrdinal  uint64   `json:"class_ordinal"`
	ResidentCount uint64   `json:"resident_count"`
	ChunkCount    uint64   `json:"chunk_count"`
	ChunkLengths  []uint64 `json:"chunk_lengths"`
	PayloadByte   string   `json:"payload_byte"`
	CommitFee     string   `json:"commit_fee"`
	ChunkFee      string   `json:"chunk_fee"`
}

type daNodeObserverStateCompleteProfile struct {
	MemberTemplateRef string                             `json:"member_template_ref"`
	InitialSource     string                             `json:"initial_source"`
	DAID              string                             `json:"da_id"`
	AdmissionOrder    string                             `json:"admission_order"`
	ResidentClasses   []daNodeObserverStateResidentClass `json:"resident_classes"`
	Target            struct {
		ClassOrdinal           uint64   `json:"class_ordinal"`
		ResidentOrdinal        uint64   `json:"resident_ordinal"`
		ChunkCount             uint64   `json:"chunk_count"`
		ChunkLengths           []uint64 `json:"chunk_lengths"`
		PayloadByte            string   `json:"payload_byte"`
		CommitFee              string   `json:"commit_fee"`
		ChunkFee               string   `json:"chunk_fee"`
		RetainedMemberOrdinals []uint64 `json:"retained_member_ordinals"`
		TriggerMemberOrdinal   uint64   `json:"trigger_member_ordinal"`
	} `json:"target"`
	EffectiveDAMempoolSize string `json:"effective_da_mempool_size"`
	CompleteSetMaxCount    uint64 `json:"complete_set_max_count"`
	PinnedPayloadMax       string `json:"pinned_payload_max"`
	AcceptedSequence       string `json:"accepted_sequence"`
	EqualityFeeOverride    struct {
		Scope        string `json:"scope"`
		MemberFee    string `json:"member_fee"`
		OtherClasses string `json:"other_classes"`
	} `json:"equality_fee_override"`
	FaultBaseline string `json:"fault_baseline"`
}

type daNodeObserverStateMixedProfile struct {
	MemberTemplateRef      string   `json:"member_template_ref"`
	ClassOrdinal           uint64   `json:"class_ordinal"`
	ResidentOrdinal        uint64   `json:"resident_ordinal"`
	DAID                   string   `json:"da_id"`
	ChunkCount             uint64   `json:"chunk_count"`
	ChunkLengths           []uint64 `json:"chunk_lengths"`
	PayloadByte            string   `json:"payload_byte"`
	CommitFee              string   `json:"commit_fee"`
	ChunkFee               string   `json:"chunk_fee"`
	AdmissionOrder         []uint64 `json:"admission_order"`
	RetainedMemberOrdinals []uint64 `json:"retained_member_ordinals"`
	AbsentMemberOrdinals   []uint64 `json:"absent_member_ordinals"`
	MemberOrdinals         string   `json:"member_ordinals"`
	AdmissionOrdinals      []uint64 `json:"admission_ordinals"`
	AcceptedSequence       string   `json:"accepted_sequence"`
	FirstReceivedSequence  string   `json:"first_received_sequence"`
	PeerQuotaAccounting    []any    `json:"peer_quota_accounting"`
}

type daNodeObserverStateChain struct {
	ChainID [32]byte
	TipHash [32]byte
	Height  uint64
}

type daNodeObserverStateProfile struct {
	Canonical daNodeObserverStateCanonicalProfile
	Complete  daNodeObserverStateCompleteProfile
	Mixed     daNodeObserverStateMixedProfile
	Chain     daNodeObserverStateChain
}

type daNodeObserverStateMemberKey struct {
	ClassOrdinal, ResidentOrdinal, MemberOrdinal uint64
}

type daNodeObserverStateMember struct {
	Key         daNodeObserverStateMemberKey
	DAID        [32]byte
	TxID, WTxID [32]byte
	Fee         consensus.Uint128
	Inputs      []consensus.Outpoint
	Raw         []byte
	Provenance  DAProvenance
	ChunkIndex  uint16
}

type daNodeObserverStateFixture struct {
	Relay        *DARelayState
	Mempool      *Mempool
	Signer       *consensus.MLDSA87Keypair
	Members      map[daNodeObserverStateMemberKey]daNodeObserverStateMember
	TargetCommit daNodeObserverStateMember
	Candidate    daNodeObserverStateMember
}

func loadDANodeObserverStateProfile(raw json.RawMessage) (daNodeObserverStateProfile, error) {
	var profile daNodeObserverStateProfile
	var fixtures daNodeObserverStateFixtures
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		return profile, fmt.Errorf("observer input fixtures: %w", err)
	}
	for name, target := range map[string]any{
		"CANONICAL_MEMBER":       &profile.Canonical,
		"COMPLETE_COMMIT_7_SETS": &profile.Complete,
		"STATE_B_MIXED":          &profile.Mixed,
	} {
		fixture, ok := fixtures.ConstructionInputs[name]
		if !ok {
			return profile, fmt.Errorf("observer input fixtures: missing %s", name)
		}
		if err := decodeDANodeObserverInput(fixture, target); err != nil {
			return profile, fmt.Errorf("observer input fixture %s: %w", name, err)
		}
	}
	chainRaw, ok := fixtures.ChainContexts["CHAIN_100"]
	if !ok {
		return profile, fmt.Errorf("observer input fixtures: missing CHAIN_100")
	}
	var chain struct {
		ChainID string `json:"chain_id"`
		Height  uint64 `json:"height"`
		TipHash string `json:"tip_hash"`
	}
	if err := json.Unmarshal(chainRaw, &chain); err != nil {
		return profile, fmt.Errorf("observer input CHAIN_100: %w", err)
	}
	var err, tipErr error
	profile.Chain.ChainID, err = daNodeObserverStateHex32("CHAIN_100.chain_id", chain.ChainID)
	profile.Chain.TipHash, tipErr = daNodeObserverStateHex32("CHAIN_100.tip_hash", chain.TipHash)
	if err = cmp.Or(err, tipErr); err != nil {
		return profile, err
	}
	profile.Chain.Height = chain.Height
	return profile, validateDANodeObserverStateProfile(profile)
}

func daNodeObserverStateHex32(label, value string) ([32]byte, error) {
	var out [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		return out, fmt.Errorf("observer input %s: expected 32-byte hex", label)
	}
	copy(out[:], decoded)
	return out, nil
}

func validateDANodeObserverStateProfile(profile daNodeObserverStateProfile) error {
	if profile.Chain.Height != 100 {
		return fmt.Errorf("observer input CHAIN_100: height must be 100")
	}
	return cmp.Or(
		validateDANodeObserverStateCanonicalProfile(profile.Canonical),
		validateDANodeObserverStateCompleteProfile(profile.Complete),
		validateDANodeObserverStateMixedProfile(profile.Mixed),
	)
}

func validateDANodeObserverStateCanonicalProfile(p daNodeObserverStateCanonicalProfile) error {
	if p.ChainContextRef != "CHAIN_100" || p.ChainHeight != "100" || p.Version != 1 || p.Locktime != 0 ||
		p.Input.Count != 1 || p.Input.Value != "10000000" || p.Input.CreationHeight != "1" || p.Input.CreatedByCoinbase ||
		p.Input.ScriptSigHex != "" || p.Input.Sequence != 0 || p.Input.PrevTxID != "0x53 || seven 0x00 bytes || u64be(case_ordinal) || u64be(class_ordinal) || u64be(resident_ordinal)" ||
		p.Input.PrevVout != "member_ordinal" || p.Nonce != "100 + admission_ordinal" {
		return fmt.Errorf("observer input CANONICAL_MEMBER: unsupported signed-member profile")
	}
	if p.Signing.SuiteID != 1 || p.Signing.PubkeyBytes != 2592 || p.Signing.SignatureBytesIncludingSelector != 4628 || p.Signing.SighashSelector != 1 ||
		p.Signing.KeyBinding != "Generate a valid ML-DSA-87 key and bind every constructed input UTXO and P2PK change output to that key. Sign the exact canonical transaction using CHAIN_100.chain_id; verify before retention." {
		return fmt.Errorf("observer input CANONICAL_MEMBER.signing: unsupported profile")
	}
	if p.Outputs.Change != "one P2PK output with value 10000000 - member_fee" || p.Outputs.CommitOnly != "prepend one zero-value DA_COMMIT output containing SHA3-256(concatenated ordered chunk payloads)" ||
		p.Commit.ManifestHex != "5255422d31323837206d616e6966657374" || p.Commit.BatchNumber != "9" || p.Commit.RetlDomainID != daNodeObserverZero32 ||
		p.Commit.TxDataRoot != daNodeObserverZero32 || p.Commit.StateRoot != daNodeObserverZero32 || p.Commit.WithdrawalsRoot != daNodeObserverZero32 || p.Commit.BatchSigSuite != 0 || p.Commit.BatchSigHex != "" || p.Commit.ChunkCount != "profile chunk_count" {
		return fmt.Errorf("observer input CANONICAL_MEMBER.commit: unsupported profile")
	}
	if p.Chunk.ChunkIndex != "member_ordinal - 1" || p.Chunk.ChunkHash != "SHA3-256(exact payload)" || p.Chunk.Payload != "repeat profile.payload_byte for profile chunk length" ||
		p.Policy.MinDAFeeRate != "1" || p.Policy.DASurchargePerByte != "0" || p.Policy.PolicyMaxDABytesPerBlock != "32000000" ||
		p.WireSize.Commit != "7565" || p.WireSize.Chunk != "7399 + payload_length + CompactSizeWidth(payload_length) - 1" {
		return fmt.Errorf("observer input CANONICAL_MEMBER: unsupported wire or policy profile")
	}
	if p.ConstructionBoundary != "All bytes, IDs, fees, immutable intrinsic metadata and finalized claims must agree with these inputs before the observed operation. No value is read from expect. Validated construction may establish the prestate without replaying an entire public history." ||
		p.IdentityProjection != "Map actual constructed txid/wtxid/outpoint/token identities to their input case/class/resident/member keys. Preserve membership, multiplicity, order and field values; no expected-dependent substitution or grouping of unequal members. Random signature bytes and signer keys are not equality observations; byte preservation is checked against independent copies of the actual input." {
		return fmt.Errorf("observer input CANONICAL_MEMBER: unsupported construction boundary")
	}
	return nil
}

const daNodeObserverZero32 = "0000000000000000000000000000000000000000000000000000000000000000"

func validateDANodeObserverStateClass(class daNodeObserverStateResidentClass, ordinal, residents, chunks, length uint64, payload, commitFee, chunkFee string) bool {
	return class.ClassOrdinal == ordinal && class.ResidentCount == residents && class.ChunkCount == chunks && class.PayloadByte == payload && class.CommitFee == commitFee && class.ChunkFee == chunkFee &&
		slices.Equal(class.ChunkLengths, slices.Repeat([]uint64{length}, int(chunks)))
}

func validateDANodeObserverStateCompleteProfile(p daNodeObserverStateCompleteProfile) error {
	if p.MemberTemplateRef != "CANONICAL_MEMBER" || p.InitialSource != "LOCAL" ||
		p.DAID != "0x52 || seven 0x00 bytes || u64be(case_ordinal) || u64be(class_ordinal) || u64be(resident_ordinal)" ||
		p.AdmissionOrder != "class, resident, then commit followed by ascending chunk index; global admission ordinals start at 1" || len(p.ResidentClasses) != 3 {
		return fmt.Errorf("observer input COMPLETE_COMMIT_7_SETS: unsupported resident profile")
	}
	classes := p.ResidentClasses
	if !validateDANodeObserverStateClass(classes[0], 0, 3, 42, 1, "01", "32000", "10000") ||
		!validateDANodeObserverStateClass(classes[1], 1, 3, 61, 524288, "02", "3000000", "3000000") ||
		!validateDANodeObserverStateClass(classes[2], 2, 1, 1, 55170, "03", "3000000", "3000000") {
		return fmt.Errorf("observer input COMPLETE_COMMIT_7_SETS: invalid resident classes")
	}
	if p.Target.ClassOrdinal != 65535 || p.Target.ResidentOrdinal != 0 || p.Target.ChunkCount != 1 || !slices.Equal(p.Target.ChunkLengths, []uint64{126}) ||
		p.Target.PayloadByte != "04" || p.Target.CommitFee != "600000" || p.Target.ChunkFee != "600000" || !slices.Equal(p.Target.RetainedMemberOrdinals, []uint64{0}) || p.Target.TriggerMemberOrdinal != 1 {
		return fmt.Errorf("observer input COMPLETE_COMMIT_7_SETS: invalid target")
	}
	// Bind the profile bounds to the knobs the relay enforces (sync.go EffectiveDAMempoolSize reads caps.stagedBytes).
	caps := defaultDARelayCaps()
	byteCap, err := stateDANodeObserverUint("effective_da_mempool_size", p.EffectiveDAMempoolSize)
	payloadCap, payloadErr := stateDANodeObserverUint("pinned_payload_max", p.PinnedPayloadMax)
	if err != nil || payloadErr != nil || byteCap != caps.stagedBytes || payloadCap != caps.pinnedPayloadBytes ||
		p.CompleteSetMaxCount != daCompleteSetMaxCount || p.AcceptedSequence != "318" ||
		p.EqualityFeeOverride.Scope != "all members of class 0 and target" || p.EqualityFeeOverride.MemberFee != "2 * exact canonical member wire length" || p.EqualityFeeOverride.OtherClasses != "unchanged" ||
		p.FaultBaseline != "Capture the independent DA image and old claims after the named injected control and before the operation can publish. Fault changes are not attributed to admission. Restore only the named corruption before a fresh retry; never rewind owner high-water." {
		return fmt.Errorf("observer input COMPLETE_COMMIT_7_SETS: unsupported bounds or control profile")
	}
	return nil
}

func validateDANodeObserverStateMixedProfile(p daNodeObserverStateMixedProfile) error {
	if p.MemberTemplateRef != "CANONICAL_MEMBER" || p.ClassOrdinal != 0 || p.ResidentOrdinal != 0 ||
		p.DAID != "0x52 || seven 0x00 bytes || u64be(case_ordinal) || u64be(0) || u64be(0)" ||
		p.ChunkCount != 3 || !slices.Equal(p.ChunkLengths, []uint64{10, 20, 1}) ||
		p.PayloadByte != "05" || p.CommitFee != "600000" || p.ChunkFee != "600000" || p.MemberOrdinals != "0 is commit; 1 and 2 are chunks 0 and 1. Chunk 2 is absent but its one-byte payload participates in the commit commitment." ||
		p.AcceptedSequence != "3" || p.FirstReceivedSequence != "1" || len(p.PeerQuotaAccounting) != 0 ||
		!slices.Equal(p.AdmissionOrder, []uint64{0, 1, 2}) || !slices.Equal(p.RetainedMemberOrdinals, []uint64{0, 1, 2}) ||
		!slices.Equal(p.AbsentMemberOrdinals, []uint64{3}) || !slices.Equal(p.AdmissionOrdinals, []uint64{1, 2, 3}) {
		return fmt.Errorf("observer input STATE_B_MIXED: unsupported cleanup profile")
	}
	return nil
}

func stateDANodeObserverUint(label, value string) (uint64, error) {
	parsed, err := parseDANodeObserverUint(label, value)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("observer input %s: invalid decimal", label)
	}
	return parsed, nil
}

func newDANodeObserverStateFixture(row daNodeObserverStateCase, profile daNodeObserverStateProfile) (fixture *daNodeObserverStateFixture, err error) {
	signer, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		return nil, fmt.Errorf("observer state signer: %w", err)
	}
	defer func() {
		if err != nil {
			signer.Close()
		}
	}()
	st := NewChainState()
	st.HasTip, st.Height, st.TipHash = true, profile.Chain.Height, profile.Chain.TipHash
	address := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	// The closed profile was validated before construction; these conversions cannot fail.
	minFee, _ := stateDANodeObserverUint("min_da_fee_rate", profile.Canonical.Policy.MinDAFeeRate)
	surcharge, _ := stateDANodeObserverUint("da_surcharge_per_byte", profile.Canonical.Policy.DASurchargePerByte)
	maxDABytes, _ := stateDANodeObserverUint("policy_max_da_bytes_per_block", profile.Canonical.Policy.PolicyMaxDABytesPerBlock)
	cfg := DefaultMempoolConfig()
	cfg.MinDaFeeRate, cfg.PolicyDaSurchargePerByte, cfg.PolicyMaxDaBytesPerBlock = minFee, surcharge, maxDABytes
	mp, err := NewMempoolWithConfig(st, nil, profile.Chain.ChainID, cfg)
	if err != nil {
		return nil, fmt.Errorf("observer state mempool: %w", err)
	}
	if floor, err := stateDANodeObserverUint("rolling_fee_floor", profile.Canonical.Policy.RollingFeeFloor); err != nil || floor != mp.CurrentMinFeeRateSnapshot() {
		return nil, fmt.Errorf("observer input CANONICAL_MEMBER.policy.rolling_fee_floor: not the mempool floor %d", mp.CurrentMinFeeRateSnapshot())
	}
	relay, err := newDARelayState(mp, defaultDARelayCaps())
	if err != nil {
		return nil, fmt.Errorf("observer state relay: %w", err)
	}
	fixture = &daNodeObserverStateFixture{Relay: relay, Mempool: mp, Signer: signer, Members: make(map[daNodeObserverStateMemberKey]daNodeObserverStateMember, 320)}
	if row.Input.ExecutionBoundary == "COMPLETE_COMMIT_PRECONDITION" {
		err = setupDANodeObserverStateComplete(fixture, row, profile, address)
	} else {
		mixed := profile.Mixed
		class := daNodeObserverStateResidentClass{ClassOrdinal: mixed.ClassOrdinal, ChunkCount: mixed.ChunkCount, ChunkLengths: mixed.ChunkLengths, PayloadByte: mixed.PayloadByte, CommitFee: mixed.CommitFee, ChunkFee: mixed.ChunkFee}
		var members []daNodeObserverStateMember
		members, err = setupDANodeObserverStateSet(fixture, row, profile, address, class, mixed.ResidentOrdinal, mixed.AdmissionOrdinals[0], 3, 3, row.Input.provenance, false)
		if err == nil {
			err = stateSequencesChecked(fixture, members[0].DAID, mixed.FirstReceivedSequence, mixed.AcceptedSequence)
		}
	}
	if err != nil {
		return nil, err
	}
	if err = stateSetupBaseline(fixture); err != nil {
		return nil, err
	}
	if row.Input.control.selected != nil {
		if err = stateControlDeltaChecked(fixture, row.Input.control); err != nil {
			return nil, err
		}
	}
	return fixture, nil
}

// stateControlDeltaChecked validates the selected member and its intrinsic delta before any measured call.
func stateControlDeltaChecked(f *daNodeObserverStateFixture, control daNodeObserverStateControl) error {
	member, err := stateSelectedMember(f, control)
	if err != nil {
		return err
	}
	f.Relay.mu.Lock()
	defer f.Relay.mu.Unlock()
	if control.action == "INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES" && ^uint64(0)-f.Relay.sets[member.DAID].completeIntrinsic.totalBytes < control.delta {
		return fmt.Errorf("observer input control.intrinsic_total_bytes_delta: overflow")
	}
	return nil
}

func stateSequencesChecked(f *daNodeObserverStateFixture, daID [32]byte, first, next string) error {
	// The closed profile was validated before construction; these conversions cannot fail.
	wantFirst, _ := stateDANodeObserverUint("first_received_sequence", first)
	wantNext, _ := stateDANodeObserverUint("accepted_sequence", next)
	f.Relay.mu.Lock()
	defer f.Relay.mu.Unlock()
	if f.Relay.nextReceivedTime != wantNext || f.Relay.sets[daID].receivedTime != wantFirst {
		return fmt.Errorf("observer state setup: first received sequence %d next %d, want %d/%d", f.Relay.sets[daID].receivedTime, f.Relay.nextReceivedTime, wantFirst, wantNext)
	}
	return nil
}

func buildDANodeObserverStateMemberOnce(f *daNodeObserverStateFixture, row daNodeObserverStateCase, p daNodeObserverStateProfile, address []byte, key daNodeObserverStateMemberKey, admissionOrdinal, fee uint64, kind uint8, chunkCount, chunkIndex uint64, payload []byte, commitment [32]byte) (daNodeObserverStateMember, error) {
	var out daNodeObserverStateMember
	if admissionOrdinal > ^uint64(0)-100 || fee >= 10000000 || chunkCount > uint64(^uint16(0)) || chunkIndex > uint64(^uint16(0)) {
		return out, fmt.Errorf("observer input %s: signed member scalar overflow", row.Case.ID)
	}
	caseOrdinal := *row.Input.CaseOrdinal
	out.Key, out.DAID = key, daNodeObserverIdentity(caseOrdinal, key.ClassOrdinal, key.ResidentOrdinal)
	input := consensus.Outpoint{Txid: daNodeObserverIdentity(caseOrdinal, key.ClassOrdinal, key.ResidentOrdinal), Vout: uint32(key.MemberOrdinal)}
	input.Txid[0] = 0x53
	entry := consensus.UtxoEntry{Value: 10000000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), address...), CreationHeight: 1, CreatedByCoinbase: false}
	f.Mempool.chainState.Utxos[input] = entry
	tx := &consensus.Tx{
		Version: p.Canonical.Version, TxKind: kind, TxNonce: 100 + admissionOrdinal,
		Inputs:   []consensus.TxInput{{PrevTxid: input.Txid, PrevVout: input.Vout, Sequence: p.Canonical.Input.Sequence}},
		Outputs:  []consensus.TxOutput{{Value: 10000000 - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), address...)}},
		Locktime: p.Canonical.Locktime,
	}
	if kind == 0x01 {
		manifest, _ := hex.DecodeString(p.Canonical.Commit.ManifestHex)
		// The closed profile pins the remaining roots and batch-signature fields to zero/empty.
		tx.DaPayload = manifest
		tx.DaCommitCore = &consensus.DaCommitCore{BatchNumber: 9, ChunkCount: uint16(chunkCount), DaID: out.DAID}
		tx.Outputs = append([]consensus.TxOutput{{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: append([]byte(nil), commitment[:]...)}}, tx.Outputs...)
	} else {
		if key.MemberOrdinal == 0 {
			return out, fmt.Errorf("observer input %s: chunk member ordinal zero", row.Case.ID)
		}
		chunkHash := sha3.Sum256(payload)
		tx.DaPayload = append([]byte(nil), payload...)
		tx.DaChunkCore = &consensus.DaChunkCore{DaID: out.DAID, ChunkIndex: uint16(chunkIndex), ChunkHash: chunkHash}
		out.ChunkIndex = uint16(chunkIndex)
	}
	if err := consensus.SignTransaction(tx, f.Mempool.chainState.Utxos, p.Chain.ChainID, f.Signer); err != nil {
		return out, fmt.Errorf("observer state SignTransaction: %w", err)
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		return out, fmt.Errorf("observer state MarshalTx: %w", err)
	}
	wantBytes := 7565
	if kind == 2 {
		wantBytes = 7399 + len(payload) + int(compactSizeLenForMiner(uint64(len(payload)))) - 1
	}
	if len(raw) != wantBytes {
		return out, fmt.Errorf("observer input canonical wire size: got %d want %d", len(raw), wantBytes)
	}
	parsed, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) || parsed.TxKind != kind || parsed.TxNonce != tx.TxNonce || len(parsed.Inputs) != 1 || parsed.Inputs[0].Sequence != 0 {
		return out, fmt.Errorf("observer state canonical parse: consumed=%d size=%d err=%v", consumed, len(raw), err)
	}
	out.Raw, out.TxID, out.WTxID = append([]byte(nil), raw...), txid, wtxid
	out.Fee, out.Inputs = consensus.Uint128{Lo: fee}, []consensus.Outpoint{input}
	out.Provenance = LocalDAProvenance()
	return out, nil
}

func buildDANodeObserverStateMember(f *daNodeObserverStateFixture, row daNodeObserverStateCase, p daNodeObserverStateProfile, address []byte, key daNodeObserverStateMemberKey, admissionOrdinal, baseFee uint64, kind uint8, chunkCount, chunkIndex uint64, payload []byte, commitment [32]byte, overrideFee bool) (daNodeObserverStateMember, error) {
	member, err := buildDANodeObserverStateMemberOnce(f, row, p, address, key, admissionOrdinal, baseFee, kind, chunkCount, chunkIndex, payload, commitment)
	if err != nil || !overrideFee {
		return member, err
	}
	if uint64(len(member.Raw)) > ^uint64(0)/2 {
		return member, fmt.Errorf("observer input %s: equality fee overflow", row.Case.ID)
	}
	fee := uint64(len(member.Raw)) * 2
	firstLength := len(member.Raw)
	member, err = buildDANodeObserverStateMemberOnce(f, row, p, address, key, admissionOrdinal, fee, kind, chunkCount, chunkIndex, payload, commitment)
	if err != nil {
		return member, err
	}
	if len(member.Raw) != firstLength {
		return member, fmt.Errorf("observer input %s: equality fee changed canonical wire length", row.Case.ID)
	}
	return member, nil
}

func stateDANodeObserverCommitment(lengths []uint64, payloadByte byte) ([32]byte, error) {
	h := sha3.New256()
	for _, length := range lengths {
		if length > uint64(^uint(0)>>1) {
			return [32]byte{}, fmt.Errorf("observer input: payload length exceeds int range")
		}
		h.Write(bytes.Repeat([]byte{payloadByte}, int(length))) // hash.Hash.Write never returns an error
	}
	return [32]byte(h.Sum(nil)), nil
}

func setupDANodeObserverStateSet(f *daNodeObserverStateFixture, row daNodeObserverStateCase, p daNodeObserverStateProfile, address []byte, class daNodeObserverStateResidentClass, resident, ordinal, count, retained uint64, provenance []DAProvenance, equality bool) ([]daNodeObserverStateMember, error) {
	payloadHex, err := hex.DecodeString(class.PayloadByte)
	if err != nil || len(payloadHex) != 1 {
		return nil, fmt.Errorf("observer input payload_byte: expected one byte")
	}
	payloadByte := payloadHex[0]
	commitment, err := stateDANodeObserverCommitment(class.ChunkLengths, payloadByte)
	if err != nil {
		return nil, err
	}
	commitFee, err := stateDANodeObserverUint("commit_fee", class.CommitFee)
	if err != nil {
		return nil, err
	}
	chunkFee, err := stateDANodeObserverUint("chunk_fee", class.ChunkFee)
	if err != nil || retained > count || count > uint64(len(class.ChunkLengths))+1 || len(provenance) != 0 && uint64(len(provenance)) != count {
		return nil, fmt.Errorf("observer input: invalid member sequence")
	}
	members := make([]daNodeObserverStateMember, 0, count)
	for i := uint64(0); i < count; i++ {
		kind, fee, index := uint8(1), commitFee, uint64(0)
		var payload []byte
		if i != 0 {
			kind, fee, index = 2, chunkFee, i-1
			payload = bytes.Repeat([]byte{payloadByte}, int(class.ChunkLengths[index]))
		}
		key := daNodeObserverStateMemberKey{ClassOrdinal: class.ClassOrdinal, ResidentOrdinal: resident, MemberOrdinal: i}
		member, err := buildDANodeObserverStateMember(f, row, p, address, key, ordinal+i, fee, kind, class.ChunkCount, index, payload, commitment, equality)
		if err != nil {
			return nil, err
		}
		if len(provenance) != 0 {
			member.Provenance = provenance[i]
		}
		if i < retained {
			got, err := f.Relay.AdmitDA(member.Raw, member.Provenance)
			if err != nil || got.DAID != member.DAID || got.Disposition != DAAdmissionRetained || got.SameDAIDCommitConflict {
				return nil, fmt.Errorf("observer state setup AdmitDA=(%+v,%v), want retained %x", got, err, member.DAID)
			}
			f.Members[key] = member
		}
		members = append(members, member)
	}
	return members, nil
}

func setupDANodeObserverStateComplete(f *daNodeObserverStateFixture, row daNodeObserverStateCase, p daNodeObserverStateProfile, address []byte) error {
	ordinal := uint64(1)
	equality := row.Input.control.action == "EQUALITY_FEE_OVERRIDE"
	for _, class := range p.Complete.ResidentClasses {
		for resident := uint64(0); resident < class.ResidentCount; resident++ {
			if _, err := setupDANodeObserverStateSet(f, row, p, address, class, resident, ordinal, class.ChunkCount+1, class.ChunkCount+1, nil, equality && class.ClassOrdinal == 0); err != nil {
				return err
			}
			ordinal += class.ChunkCount + 1
		}
	}
	target := p.Complete.Target
	class := daNodeObserverStateResidentClass{ClassOrdinal: target.ClassOrdinal, ChunkCount: target.ChunkCount, ChunkLengths: target.ChunkLengths, PayloadByte: target.PayloadByte, CommitFee: target.CommitFee, ChunkFee: target.ChunkFee}
	members, err := setupDANodeObserverStateSet(f, row, p, address, class, target.ResidentOrdinal, ordinal, 2, 1, nil, equality)
	if err != nil {
		return err
	}
	f.TargetCommit, f.Candidate = members[0], members[1]
	if err := stateSequencesChecked(f, f.TargetCommit.DAID, p.Complete.AcceptedSequence, p.Complete.AcceptedSequence); err != nil {
		return err
	}
	f.Relay.mu.Lock()
	defer f.Relay.mu.Unlock()
	f.Relay.nextReceivedTime = row.Input.acceptedSequence
	return nil
}

func parseDANodeObserverStateProvenance(raw json.RawMessage) ([]DAProvenance, error) {
	var members []daNodeObserverProvenance
	if err := decodeDANodeObserverInput(raw, &members); err != nil {
		return nil, err
	}
	if len(members) != 3 {
		return nil, fmt.Errorf("observer input member_provenance: expected three members")
	}
	out := make([]DAProvenance, len(members))
	for i, member := range members {
		source, err := decodeDANodeObserverStateString(member.Source, "member_provenance.source")
		if err != nil {
			return nil, err
		}
		switch source {
		case "LOCAL", "DETACHED_REORG":
			if len(member.PeerIdentity) != 0 || len(member.QuotaIdentity) != 0 {
				return nil, fmt.Errorf("observer input member_provenance[%d]: forbidden peer identities", i)
			}
			out[i] = map[string]DAProvenance{"LOCAL": LocalDAProvenance(), "DETACHED_REORG": DetachedReorgDAProvenance()}[source]
		case "PEER":
			peer, err := decodeDANodeObserverStateString(member.PeerIdentity, "member_provenance.peer_identity")
			quota, quotaErr := decodeDANodeObserverStateString(member.QuotaIdentity, "member_provenance.quota_identity")
			if err = cmp.Or(err, quotaErr); err != nil {
				return nil, err
			}
			out[i], err = NewPeerDAProvenance(peer, quota)
			if err != nil {
				return nil, fmt.Errorf("observer input member_provenance[%d]: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("observer input member_provenance: unknown source %q", source)
		}
	}
	return out, nil
}

type daNodeObserverStateOwnerImage struct {
	Identity       *PendingOutpointOwner
	Counts         DAObserverOwnerCounts
	TokenHighWater uint64
	Generation     uint64
}

type daNodeObserverStateObservation struct {
	Image DAObserverStateImage
	Owner daNodeObserverStateOwnerImage
}

type daNodeObserverStateAdmission struct {
	Call         DAObserverAdmitCall
	Before       daNodeObserverStateObservation
	After        daNodeObserverStateObservation
	PlanOrder    [][32]byte
	Restore      func()
	ControlReach bool
	Invocations  uint64
}

func ownerImageLocked(owner *PendingOutpointOwner) daNodeObserverStateOwnerImage {
	return daNodeObserverStateOwnerImage{
		Identity:       owner,
		Counts:         DAObserverOwnerCounts{owner.reserveCalls, owner.reservationsAcquired, owner.finalizations, owner.candidateReleases},
		TokenHighWater: owner.tokenHighWater,
		Generation:     owner.generation,
	}
}

func observerImageLocked(relay *DARelayState, owner *PendingOutpointOwner) daNodeObserverStateObservation {
	image := relay.daObserverRelayImageLocked()
	image.Claims, image.OutpointRows = owner.daObserverClaimsLocked()
	return daNodeObserverStateObservation{Image: image, Owner: ownerImageLocked(owner)}
}

func observerImageInHook(f *daNodeObserverStateFixture, stage daCompleteStage) (daNodeObserverStateObservation, error) {
	relay, owner := f.Relay, f.Mempool.pendingOutpoints
	if stage == daCompletePlanned {
		relay.mu.Lock()
		defer relay.mu.Unlock()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return observerImageLocked(relay, owner), nil
}

func observerImageOutsideHook(f *daNodeObserverStateFixture, closed bool) (daNodeObserverStateObservation, error) {
	release, err := f.Relay.lockAdmissionFence()
	if err != nil {
		return daNodeObserverStateObservation{}, err
	}
	defer release()
	f.Relay.mu.Lock()
	defer f.Relay.mu.Unlock()
	if closed {
		if err := canonicalDARetainedImageClosed(f.Relay, f.Relay.sortedRetainedDAIDsLocked()); err != nil {
			return daNodeObserverStateObservation{}, fmt.Errorf("observer state accounting closure: %w", err)
		}
	}
	return observerImageInHook(f, daCompleteEffects)
}

func stateSetupBaseline(f *daNodeObserverStateFixture) error {
	observed, err := observerImageOutsideHook(f, true)
	if err != nil {
		return err
	}
	image, records, members := observed.Image, make(map[[32]byte]bool), 0
	for key, member := range f.Members {
		records[member.DAID] = true
		if !daNodeObserverStateCandidateMatches(image, member, observed.Owner.Generation) {
			return fmt.Errorf("observer state setup baseline: retained member %+v does not match its construction", key)
		}
	}
	for _, record := range image.Records {
		if record.Commit.Member != nil {
			members++
		}
		members += len(record.Chunks)
	}
	// Every constructed member owns exactly one input, so each row family must count the members exactly.
	if len(image.Records) != len(records) || members != len(f.Members) ||
		len(image.Locators) != len(f.Members) || len(image.Claims) != len(f.Members) || len(image.OutpointRows) != len(f.Members) {
		return fmt.Errorf("observer state setup baseline: retained image holds rows outside the constructed members")
	}
	return nil
}

func stateSelectedMember(f *daNodeObserverStateFixture, control daNodeObserverStateControl) (daNodeObserverStateMember, error) {
	member, ok := f.Members[*control.selected]
	if !ok {
		return member, fmt.Errorf("observer input control.member: constructed member is absent")
	}
	return member, nil
}

func lockedRestore(mu sync.Locker, restore func()) func() {
	return func() {
		mu.Lock()
		restore()
		mu.Unlock()
	}
}

func applyDANodeObserverStatePlannedControl(f *daNodeObserverStateFixture, control daNodeObserverStateControl) (func(), error) {
	relay := f.Relay
	if control.action == "ADVANCE_TARGET_AND_GLOBAL_REVISION" {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		id := f.Candidate.DAID
		record, ok := relay.sets[id]
		if !ok || relay.records == ^uint64(0) {
			return nil, fmt.Errorf("observer state control: target revision is unavailable")
		}
		revision := relay.records + 1
		record.revision, relay.records = revision, revision
		relay.sets[id] = record
		return nil, nil
	}
	member, err := stateSelectedMember(f, control)
	if err != nil {
		return nil, err
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	record, ok := relay.sets[member.DAID]
	if !ok {
		return nil, fmt.Errorf("observer state control: selected record is absent")
	}
	switch control.action {
	case "CORRUPT_RESIDENT_LOCATOR_DA_ID":
		locator, ok := relay.locators[member.TxID]
		if !ok || locator.daID != member.DAID {
			return nil, fmt.Errorf("observer state control: selected locator is absent")
		}
		relay.locators[member.TxID] = daRelayLocator{daID: control.locator, kind: locator.kind, chunkIndex: locator.chunkIndex}
		return lockedRestore(&relay.mu, func() { relay.locators[member.TxID] = locator }), nil
	case "INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES":
		old := record.completeIntrinsic.totalBytes
		record.completeIntrinsic.totalBytes += control.delta
		relay.sets[member.DAID] = record
		return lockedRestore(&relay.mu, func() {
			current := relay.sets[member.DAID]
			current.completeIntrinsic.totalBytes = old
			relay.sets[member.DAID] = current
		}), nil
	case "REMOVE_RESIDENT_CHUNK":
		if member.Key.MemberOrdinal == 0 || member.Key.MemberOrdinal > uint64(^uint16(0)) {
			return nil, fmt.Errorf("observer state control: invalid chunk selector")
		}
		index := uint16(member.Key.MemberOrdinal - 1)
		chunk, ok := record.chunks[index]
		if !ok {
			return nil, fmt.Errorf("observer state control: selected chunk is absent")
		}
		delete(record.chunks, index)
		relay.sets[member.DAID] = record
		return lockedRestore(&relay.mu, func() {
			current := relay.sets[member.DAID]
			current.chunks[index] = chunk
			relay.sets[member.DAID] = current
		}), nil
	default:
		return nil, fmt.Errorf("observer input control: invalid PLANNED action %q", control.action)
	}
}

func ownerClaimForMemberLocked(owner *PendingOutpointOwner, member daNodeObserverStateMember) (PendingOutpointToken, *pendingOutpointClaim, error) {
	var found PendingOutpointToken
	var claim *pendingOutpointClaim
	for token, current := range owner.byToken {
		if current.txid != member.TxID {
			continue
		}
		if claim != nil {
			return PendingOutpointToken{}, nil, fmt.Errorf("observer state control: duplicate owner claim")
		}
		found, claim = token, current
	}
	if claim == nil || claim.token.owner != owner || claim.domain != PendingOutpointDA {
		return PendingOutpointToken{}, nil, fmt.Errorf("observer state control: DA owner claim is absent")
	}
	return found, claim, nil
}

func applyDANodeObserverStateEffectsControl(f *daNodeObserverStateFixture, control daNodeObserverStateControl) (func(), error) {
	member, err := stateSelectedMember(f, control)
	if err != nil {
		return nil, err
	}
	owner := f.Mempool.pendingOutpoints
	owner.mu.Lock()
	defer owner.mu.Unlock()
	token, claim, err := ownerClaimForMemberLocked(owner, member)
	if err != nil {
		return nil, err
	}
	switch control.action {
	case "CLEAR_PRIOR_CLAIM_FINALIZED":
		old := claim.finalized
		claim.finalized = false
		return lockedRestore(&owner.mu, func() { claim.finalized = old }), nil
	case "REMOVE_PRIOR_CLAIM":
		delete(owner.byToken, token)
		return lockedRestore(&owner.mu, func() { owner.byToken[token] = claim }), nil
	default:
		return nil, fmt.Errorf("observer input control: invalid EFFECTS action %q", control.action)
	}
}

func admitDANodeObserverStateCandidate(f *daNodeObserverStateFixture, control daNodeObserverStateControl) (daNodeObserverStateAdmission, error) {
	var observed []DAObserverAdmitCall
	DAObserverSetAdmitObserver(f.Relay, func(call DAObserverAdmitCall) { observed = append(observed, call) })
	defer DAObserverSetAdmitObserver(f.Relay, nil)
	result := daNodeObserverStateAdmission{}
	if control.phase == "NONE" {
		var err error
		result.Before, err = observerImageOutsideHook(f, false)
		if err != nil {
			return result, err
		}
	}
	var hookErr error
	prior := f.Relay.completeHook
	f.Relay.completeHook = func(stage daCompleteStage, plan *daCompleteCommitPlan) {
		if prior != nil {
			prior(stage, plan)
		}
		if stage == daCompleteEffects && plan != nil {
			result.PlanOrder = append([][32]byte(nil), plan.capacity.victims...)
		}
		phase := map[daCompleteStage]string{daCompletePlanned: "PLANNED", daCompleteEffects: "EFFECTS"}[stage]
		if control.phase != phase || result.ControlReach {
			return
		}
		result.ControlReach = true
		apply := applyDANodeObserverStatePlannedControl
		if phase == "EFFECTS" {
			apply = applyDANodeObserverStateEffectsControl
		}
		result.Restore, hookErr = apply(f, control)
		if hookErr != nil {
			return
		}
		result.Before, hookErr = observerImageInHook(f, stage)
	}
	_, callErr := f.Relay.AdmitDA(f.Candidate.Raw, f.Candidate.Provenance)
	f.Relay.completeHook = nil
	if hookErr != nil {
		return result, hookErr
	}
	if control.phase != "NONE" && !result.ControlReach {
		return result, fmt.Errorf("observer input %s: named %s hook was not reached", control.phase, control.action)
	}
	if len(observed) != 1 || observed[0].Err != callErr {
		return result, fmt.Errorf("observer state AdmitDA callback count or error mismatch")
	}
	result.Call = observed[0]
	result.Invocations = uint64(len(observed))
	result.After, callErr = observerImageOutsideHook(f, callErr == nil && result.Call.Result.Disposition == DAAdmissionRetained)
	return result, callErr
}

func daNodeObserverStateCounters(image DAObserverStateImage) map[string]any {
	return map[string]any{
		"staged_retained_bytes":   daNodeObserverStateDecimal(image.StagedBytes),
		"complete_retained_bytes": daNodeObserverStateDecimal(image.CompleteBytes),
		"complete_set_count":      image.CompleteCount,
		"complete_payload_bytes":  daNodeObserverStateDecimal(image.PinnedPayloadBytes),
		"accepted_sequence":       daNodeObserverStateDecimal(image.NextReceivedTime),
	}
}

func daNodeObserverStateOwnerDeltas(before, after daNodeObserverStateOwnerImage) (DAObserverOwnerCounts, uint64, error) {
	if before.Identity == nil || before.Identity != after.Identity ||
		after.Counts.ReserveCalls < before.Counts.ReserveCalls || after.Counts.ReservationsAcquired < before.Counts.ReservationsAcquired ||
		after.Counts.Finalizations < before.Counts.Finalizations || after.Counts.CandidateReleases < before.Counts.CandidateReleases || after.TokenHighWater < before.TokenHighWater {
		return DAObserverOwnerCounts{}, 0, fmt.Errorf("observer state owner image: identity or counter regression")
	}
	return DAObserverOwnerCounts{
		after.Counts.ReserveCalls - before.Counts.ReserveCalls,
		after.Counts.ReservationsAcquired - before.Counts.ReservationsAcquired,
		after.Counts.Finalizations - before.Counts.Finalizations,
		after.Counts.CandidateReleases - before.Counts.CandidateReleases,
	}, after.TokenHighWater - before.TokenHighWater, nil
}

func stateRemoved[T any, K comparable](before, after []T, key func(T) K) []T {
	removed := make([]T, 0)
	for _, row := range before {
		if !slices.ContainsFunc(after, func(other T) bool { return key(other) == key(row) }) {
			removed = append(removed, row)
		}
	}
	return removed
}

func daNodeObserverStateOrderedVictims(plan [][32]byte, removed [][32]byte) ([]string, error) {
	ordered := make([]string, 0, len(removed))
	for _, id := range plan {
		text := daNodeObserverHexID(id)
		if slices.Contains(removed, id) && !slices.Contains(ordered, text) {
			ordered = append(ordered, text)
		}
	}
	if len(ordered) != len(removed) {
		return nil, fmt.Errorf("observer state victims: committed removal missing from capacity plan order")
	}
	return ordered, nil
}

func daNodeObserverStateResult(call DAObserverAdmitCall, acceptedSequence uint64, candidatePublished bool) (map[string]any, error) {
	var admissionErr *TxAdmitError
	errors.As(call.Err, &admissionErr)
	var reason string
	switch {
	case call.Err == nil && call.Result.Disposition == DAAdmissionRetained && !candidatePublished:
		return nil, fmt.Errorf("observer state result: retained outcome without candidate publication")
	case call.Err == nil && call.Result.Disposition == DAAdmissionRetained:
		return map[string]any{"disposition": "COMMIT_WITH_VICTIMS", "semantic_reason_id": "NONE"}, nil
	case call.Err == nil && call.Result.Disposition == DAAdmissionDuplicate:
		reason = "DUPLICATE_CONFLICT"
	case call.Err == nil:
		return nil, fmt.Errorf("observer state result: unknown success disposition %d", call.Result.Disposition)
	case call.Result != (DAAdmissionResult{}):
		return nil, fmt.Errorf("observer state result: nonzero result on error")
	case errors.Is(call.Err, errDARelayArithmeticOverflow) && acceptedSequence == ^uint64(0):
		reason = "SEQUENCE_EXHAUSTED"
	case errors.Is(call.Err, errDARelayImageIncompatible):
		reason = "INTERNAL"
	case admissionErr != nil && admissionErr.Kind == TxAdmitUnavailable && admissionErr.Message == "retained DA record moved while this admission was planned" && DAObserverRelayDisposition(call.Err) == RelayAdmissionUnavailable:
		reason = "STALE_PLAN"
	case admissionErr != nil && admissionErr.disposition == RelayAdmissionCapacity:
		reason = "CANDIDATE_NOT_BETTER"
	case admissionErr != nil && admissionErr.disposition == RelayAdmissionInternal:
		reason = "INTERNAL"
	default:
		return nil, fmt.Errorf("observer state result: unrecognized outcome %T %v", call.Err, call.Err)
	}
	return map[string]any{"disposition": "REJECT_UNCHANGED", "semantic_reason_id": reason}, nil
}

func daNodeObserverStateFindRecord(image DAObserverStateImage, daID [32]byte) (DAObserverRecord, bool) {
	i := slices.IndexFunc(image.Records, func(record DAObserverRecord) bool { return record.DAID == daID })
	if i < 0 {
		return DAObserverRecord{}, false
	}
	return image.Records[i], true
}

func daNodeObserverStateFindMember(record DAObserverRecord, candidate daNodeObserverStateMember) (*DAObserverMember, []byte, bool) {
	if candidate.Key.MemberOrdinal == 0 && record.Commit.Member != nil && record.Commit.Member.TxID == candidate.TxID {
		return record.Commit.Member, record.Commit.TxBytes, true
	}
	for _, chunk := range record.Chunks {
		if chunk.Member != nil && chunk.Member.TxID == candidate.TxID {
			return chunk.Member, chunk.TxBytes, true
		}
	}
	return nil, nil, false
}

func daNodeObserverStateCandidateMatches(image DAObserverStateImage, candidate daNodeObserverStateMember, generation uint64) bool {
	record, ok := daNodeObserverStateFindRecord(image, candidate.DAID)
	if !ok {
		return false
	}
	member, raw, ok := daNodeObserverStateFindMember(record, candidate)
	if !ok || member.WTxID != candidate.WTxID || member.Fee != candidate.Fee || member.Provenance != daObserverProvenance(candidate.Provenance) || !reflect.DeepEqual(member.Inputs, candidate.Inputs) || !bytes.Equal(raw, candidate.Raw) {
		return false
	}
	claims := slices.DeleteFunc(slices.Clone(image.Claims), func(row DAObserverClaim) bool {
		return row.TxID != candidate.TxID && row.TokenSeq != member.TokenSeq
	})
	if len(claims) != 1 {
		return false
	}
	claim := claims[0]
	if claim.TxID != candidate.TxID || claim.Domain != "DA" || !claim.Finalized || claim.TokenSeq != member.TokenSeq || claim.Generation != generation || !reflect.DeepEqual(claim.Inputs, candidate.Inputs) {
		return false
	}
	kind := "CHUNK"
	if candidate.Key.MemberOrdinal == 0 {
		kind = "COMMIT"
	}
	locators := slices.DeleteFunc(slices.Clone(image.Locators), func(row DAObserverLocator) bool {
		return row.TxID != candidate.TxID
	})
	outpoints := slices.DeleteFunc(slices.Clone(image.OutpointRows), func(row DAObserverOutpointRow) bool {
		return row.TxID != candidate.TxID && row.TokenSeq != member.TokenSeq
	})
	want := make([]DAObserverOutpointRow, len(candidate.Inputs))
	for i, input := range candidate.Inputs {
		want[i] = DAObserverOutpointRow{Outpoint: input, TokenSeq: member.TokenSeq, TxID: candidate.TxID}
	}
	return slices.Equal(locators, []DAObserverLocator{{TxID: candidate.TxID, DAID: candidate.DAID, Kind: kind, ChunkIndex: candidate.ChunkIndex}}) && slices.Equal(outpoints, want)
}

// daNodeObserverStateSurvivorsEqual compares both images without the candidate and without removed
// members; any after-image row that still names a removed member makes the comparison false.
func daNodeObserverStateSurvivorsEqual(before, after DAObserverStateImage, removedRecords, removedMembers [][32]byte, candidate [32]byte) bool {
	removed := make(map[[32]byte]bool, len(removedMembers))
	for _, id := range removedMembers {
		removed[id] = true
	}
	for _, record := range before.Records {
		if slices.Contains(removedRecords, record.DAID) {
			if record.Commit.Member != nil {
				removed[record.Commit.Member.TxID] = true
			}
			for _, chunk := range record.Chunks {
				if chunk.Member != nil {
					removed[chunk.Member.TxID] = true
				}
			}
		}
	}
	stale := false
	// Images already own independent buffers and deterministic row ordering.
	filter := func(image DAObserverStateImage, live bool) []any {
		keep := func(txid [32]byte) bool {
			stale = stale || live && removed[txid]
			return !removed[txid] && txid != candidate
		}
		rows := make([]any, 0)
		for _, record := range image.Records {
			if slices.Contains(removedRecords, record.DAID) {
				continue
			}
			if record.Commit.Member != nil && keep(record.Commit.Member.TxID) {
				rows = append(rows, record.Commit)
			}
			for _, chunk := range record.Chunks {
				if chunk.Member == nil || keep(chunk.Member.TxID) {
					rows = append(rows, chunk)
				}
			}
		}
		for _, row := range image.Locators {
			if keep(row.TxID) && !slices.Contains(removedRecords, row.DAID) {
				rows = append(rows, row)
			}
		}
		for _, row := range image.Claims {
			if keep(row.TxID) {
				rows = append(rows, row)
			}
		}
		for _, row := range image.OutpointRows {
			if keep(row.TxID) {
				rows = append(rows, row)
			}
		}
		return rows
	}
	return reflect.DeepEqual(filter(before, false), filter(after, true)) && !stale
}

func daNodeObserverStateDecimal(value uint64) string { return strconv.FormatUint(value, 10) }

func daNodeObserverStateOwnerOutput(invocations uint64, counts DAObserverOwnerCounts, highWater uint64, releaseScope string) map[string]any {
	return map[string]any{
		"admission_entrypoint": map[string]any{"domain": "DA", "invocations": invocations},
		"pending_outpoint": map[string]any{
			"reserve_calls":         counts.ReserveCalls,
			"reservations_acquired": counts.ReservationsAcquired,
			"finalizations":         counts.Finalizations,
			"exact_releases":        counts.CandidateReleases,
		},
		"token_high_water_delta": daNodeObserverStateDecimal(highWater),
		"exact_release_scope":    releaseScope,
	}
}

func daNodeObserverStateAdmissionImageOutput(f *daNodeObserverStateFixture, run daNodeObserverStateAdmission) (map[string]any, []string, error) {
	before, after := run.Before.Image, run.After.Image
	removedRecords := make([][32]byte, 0)
	for _, row := range stateRemoved(before.Records, after.Records, func(r DAObserverRecord) [32]byte { return r.DAID }) {
		removedRecords = append(removedRecords, row.DAID)
	}
	removedLocators := stateRemoved(before.Locators, after.Locators, func(l DAObserverLocator) [32]byte { return l.TxID })
	removedClaims := stateRemoved(before.Claims, after.Claims, func(c DAObserverClaim) uint64 { return c.TokenSeq })
	victims, err := daNodeObserverStateOrderedVictims(run.PlanOrder, removedRecords)
	if err != nil {
		return nil, nil, err
	}
	targetRecord, _ := daNodeObserverStateFindRecord(after, f.Candidate.DAID)
	_, _, candidatePublished := daNodeObserverStateFindMember(targetRecord, f.Candidate)
	candidateMatches := daNodeObserverStateCandidateMatches(after, f.Candidate, run.After.Owner.Generation)
	result, err := daNodeObserverStateResult(run.Call, run.Before.Image.NextReceivedTime, candidatePublished)
	if err != nil {
		return nil, nil, err
	}
	counts, highWater, err := daNodeObserverStateOwnerDeltas(run.Before.Owner, run.After.Owner)
	if err != nil {
		return nil, nil, err
	}
	releaseScope := "NONE"
	if counts.CandidateReleases > 0 {
		releaseScope = "CANDIDATE_ONLY"
		for _, claim := range removedClaims {
			if claim.TxID != f.Candidate.TxID {
				return nil, nil, fmt.Errorf("observer state candidate release scope includes prior claim")
			}
		}
	}
	imageUnchanged := reflect.DeepEqual(before, after)
	targetCommitMatches := daNodeObserverStateCandidateMatches(after, f.TargetCommit, run.After.Owner.Generation)
	survivors := daNodeObserverStateSurvivorsEqual(before, after, removedRecords, nil, f.Candidate.TxID) && targetCommitMatches
	firstSequence := targetRecord.ReceivedTime
	if firstSequence == 0 {
		return nil, nil, fmt.Errorf("observer state image: target record is absent")
	}
	stateImage := map[string]any{
		"candidate_published":                    candidatePublished,
		"retained_counters":                      daNodeObserverStateCounters(after),
		"target_first_received_sequence":         daNodeObserverStateDecimal(firstSequence),
		"removed":                                map[string]any{"record_count": len(removedRecords), "member_locator_count": len(removedLocators), "claim_count": len(removedClaims)},
		"surviving_members_and_claims_unchanged": survivors,
	}
	if candidatePublished {
		stateImage["candidate_members_match_construction"] = candidateMatches
	} else {
		stateImage["image_and_prior_claims_unchanged_from_control_baseline"] = imageUnchanged
	}
	owner := daNodeObserverStateOwnerOutput(run.Invocations, counts, highWater, releaseScope)
	return map[string]any{"result": result, "victims": victims, "owner": owner, "state_image": stateImage}, victims, nil
}

func collectDANodeObserverStateCase(row daNodeObserverStateCase, profile daNodeObserverStateProfile) (daNodeObserverOutCase, error) {
	fixture, err := newDANodeObserverStateFixture(row, profile)
	if err != nil {
		return daNodeObserverOutCase{}, err
	}
	defer fixture.Signer.Close()
	if row.Input.ExecutionBoundary == "COMPLETE_COMMIT_PRECONDITION" {
		return collectDANodeObserverStateAdmission(row, fixture)
	}
	return collectDANodeObserverStateCleanup(row, fixture)
}

func collectDANodeObserverStateAdmission(row daNodeObserverStateCase, fixture *daNodeObserverStateFixture) (daNodeObserverOutCase, error) {
	primary, err := admitDANodeObserverStateCandidate(fixture, row.Input.control)
	if err != nil {
		return daNodeObserverOutCase{}, err
	}
	actual, _, err := daNodeObserverStateAdmissionImageOutput(fixture, primary)
	if err != nil {
		return daNodeObserverOutCase{}, err
	}
	followUp, err := daNodeObserverStateAdmissionFollowUp(row, fixture, primary)
	if err != nil {
		return daNodeObserverOutCase{}, err
	}
	actual["follow_up"] = followUp
	return daNodeObserverOutCase{ID: row.Case.ID, Actual: actual}, nil
}

func daNodeObserverStateCandidateToken(image DAObserverStateImage, candidate daNodeObserverStateMember) uint64 {
	record, _ := daNodeObserverStateFindRecord(image, candidate.DAID)
	if member, _, ok := daNodeObserverStateFindMember(record, candidate); ok {
		return member.TokenSeq
	}
	return 0
}

func daNodeObserverStateAdmissionFollowUp(row daNodeObserverStateCase, fixture *daNodeObserverStateFixture, primary daNodeObserverStateAdmission) (map[string]any, error) {
	if row.Input.FollowUp == "RESTORE_NAMED_CORRUPTION_THEN_FRESH_ADMISSION" {
		if primary.Restore == nil {
			return nil, fmt.Errorf("observer input %s: named control has no restorable field", row.Case.ID)
		}
		primary.Restore()
	}
	prior, err := observerImageOutsideHook(fixture, false)
	if err != nil {
		return nil, err
	}
	if row.Input.FollowUp != "REPEAT_IDENTICAL_ADMISSION" && primary.After.Owner != prior.Owner {
		return nil, fmt.Errorf("observer state follow-up high-water continuity: owner identity or counters changed before retry")
	}
	run, err := admitDANodeObserverStateCandidate(fixture, daNodeObserverStateControl{phase: "NONE", action: "NONE"})
	if err != nil {
		return nil, err
	}
	projected, victims, err := daNodeObserverStateAdmissionImageOutput(fixture, run)
	if err != nil {
		return nil, err
	}
	stateImage := projected["state_image"].(map[string]any)
	if err := stateRetryImageChecked(run.Call, stateImage); err != nil {
		return nil, err
	}
	result, owner := projected["result"], projected["owner"]
	if row.Input.FollowUp == "REPEAT_IDENTICAL_ADMISSION" {
		return map[string]any{
			"result": result, "owner": owner,
			"image_and_prior_claims_unchanged": reflect.DeepEqual(run.Before.Image, run.After.Image),
			"accepted_sequence":                daNodeObserverStateDecimal(run.After.Image.NextReceivedTime),
		}, nil
	}
	if run.After.Owner.Counts.ReservationsAcquired < run.Before.Owner.Counts.ReservationsAcquired ||
		^uint64(0)-run.Before.Owner.TokenHighWater < run.After.Owner.Counts.ReservationsAcquired-run.Before.Owner.Counts.ReservationsAcquired ||
		run.After.Owner.TokenHighWater != run.Before.Owner.TokenHighWater+run.After.Owner.Counts.ReservationsAcquired-run.Before.Owner.Counts.ReservationsAcquired ||
		(run.Call.Err == nil && run.Call.Result.Disposition == DAAdmissionRetained && daNodeObserverStateCandidateToken(run.After.Image, fixture.Candidate) <= prior.Owner.TokenHighWater) {
		return nil, fmt.Errorf("observer state follow-up high-water continuity: retry reservation did not advance the saved owner")
	}
	return map[string]any{
		"result": result, "owner": owner,
		"retained_counters": stateImage["retained_counters"], "victims": victims,
		"target_first_received_sequence": stateImage["target_first_received_sequence"],
	}, nil
}

func stateRetryImageChecked(call DAObserverAdmitCall, stateImage map[string]any) error {
	if call.Err == nil && call.Result.Disposition == DAAdmissionRetained && (stateImage["surviving_members_and_claims_unchanged"] != true || stateImage["candidate_members_match_construction"] != true) {
		return fmt.Errorf("observer state follow-up: retained retry changed survivors or published a candidate that does not match its construction")
	}
	return nil
}

func stateCleanupMembers(f *daNodeObserverStateFixture, image DAObserverStateImage) ([]any, map[[32]byte]uint64, DAObserverRecord, bool, error) {
	constructed := slices.SortedFunc(maps.Values(f.Members), func(a, b daNodeObserverStateMember) int { return cmp.Compare(a.Key.MemberOrdinal, b.Key.MemberOrdinal) })
	members, charges := make([]any, 0), make(map[[32]byte]uint64)
	record, exists := daNodeObserverStateFindRecord(image, constructed[0].DAID)
	for _, expected := range constructed {
		member, raw, present := daNodeObserverStateFindMember(record, expected)
		if !present {
			continue
		}
		role, charge := "COMMIT", uint64(len(raw))
		provenance := map[string]any{"source": member.Provenance.Kind}
		if member.Provenance.Kind == "PEER" {
			provenance["peer_identity"], provenance["quota_identity"] = member.Provenance.PeerIdentity, member.Provenance.QuotaIdentity
		}
		output := map[string]any{"member_ordinal": expected.Key.MemberOrdinal, "role": role, "provenance": provenance, "retained_tx_bytes": daNodeObserverStateDecimal(uint64(len(raw)))}
		if expected.Key.MemberOrdinal != 0 {
			for _, chunk := range record.Chunks {
				if chunk.Member != nil && chunk.Member.TxID == member.TxID {
					payload := uint64(len(chunk.Payload))
					if charge > ^uint64(0)-payload {
						return nil, nil, record, false, fmt.Errorf("observer state cleanup charge overflow")
					}
					charge += payload
					output["role"], output["chunk_index"], output["payload_bytes"] = "CHUNK", chunk.ChunkIndex, daNodeObserverStateDecimal(payload)
				}
			}
		}
		output["incomplete_member_charge"] = daNodeObserverStateDecimal(charge)
		charges[member.TxID] = charge
		members = append(members, output)
	}
	return members, charges, record, exists, nil
}

func projectDANodeObserverStateCleanup(f *daNodeObserverStateFixture, row daNodeObserverStateCase, before, after daNodeObserverStateObservation) (map[string]any, error) {
	_, oldCharges, _, _, err := stateCleanupMembers(f, before.Image)
	if err != nil {
		return nil, err
	}
	members, charges, record, exists, err := stateCleanupMembers(f, after.Image)
	if err != nil {
		return nil, err
	}
	if !exists {
		// The frozen after_image needs the real record fields; an absent record is an unrecognized outcome.
		return nil, fmt.Errorf("observer state cleanup: retained record is absent after cleanup")
	}
	selected, removedIDs := make([]uint64, 0), make([][32]byte, 0)
	var released uint64
	for _, member := range f.Members {
		charge, retained := oldCharges[member.TxID]
		if _, present := charges[member.TxID]; retained && !present {
			selected = append(selected, member.Key.MemberOrdinal)
			removedIDs = append(removedIDs, member.TxID)
			if released > ^uint64(0)-charge {
				return nil, fmt.Errorf("observer state cleanup charge overflow")
			}
			released += charge
		}
	}
	slices.Sort(selected)
	quota := make([]any, 0, len(after.Image.OrphanBytesByPeerQuotaKey))
	for _, account := range after.Image.OrphanBytesByPeerQuotaKey {
		quota = append(quota, map[string]any{"quota_identity": account.Key, "bytes": daNodeObserverStateDecimal(account.Bytes)})
	}
	_, highWater, err := daNodeObserverStateOwnerDeltas(before.Owner, after.Owner)
	if err != nil {
		return nil, err
	}
	result := "NO_SELECTION"
	if len(selected) != 0 {
		result = "REMOVED_PEER_CHUNKS"
	}
	out := map[string]any{
		"cleanup_result": result, "selected_member_ordinals": selected,
		"released_charge":                        daNodeObserverStateDecimal(released),
		"removed_locator_count":                  len(stateRemoved(before.Image.Locators, after.Image.Locators, func(l DAObserverLocator) [32]byte { return l.TxID })),
		"removed_claim_count":                    len(stateRemoved(before.Image.Claims, after.Image.Claims, func(c DAObserverClaim) uint64 { return c.TokenSeq })),
		"owner_high_water_delta":                 daNodeObserverStateDecimal(highWater),
		"after_image":                            map[string]any{"state": record.State, "da_id": daNodeObserverHexID(record.DAID), "received_sequence": daNodeObserverStateDecimal(record.ReceivedTime), "commit_chunk_count": record.Commit.ChunkCount, "members": members, "retained_counters": daNodeObserverStateCounters(after.Image), "peer_quota_accounting": quota},
		"surviving_members_and_claims_unchanged": daNodeObserverStateSurvivorsEqual(before.Image, after.Image, nil, removedIDs, [32]byte{}),
		"whole_record_removed":                   !exists,
	}
	if row.Case.ID == "STATE_B_PEER_COMMIT_CLEANUP_PROTECTED" {
		out["image_byte_identical"] = reflect.DeepEqual(before.Image, after.Image)
	}
	return out, nil
}

func collectDANodeObserverStateCleanup(row daNodeObserverStateCase, f *daNodeObserverStateFixture) (daNodeObserverOutCase, error) {
	key := row.Input.quotaIdentity
	images := make([]daNodeObserverStateObservation, 1, 3)
	var err error
	if images[0], err = observerImageOutsideHook(f, false); err != nil {
		return daNodeObserverOutCase{}, err
	}
	for len(images) < 3 {
		if err := f.Relay.ReleasePeerQuotaKey(key); err != nil {
			return daNodeObserverOutCase{}, err
		}
		image, err := observerImageOutsideHook(f, true)
		if err != nil {
			return daNodeObserverOutCase{}, err
		}
		images = append(images, image)
	}
	actual, err := projectDANodeObserverStateCleanup(f, row, images[0], images[1])
	if err != nil {
		return daNodeObserverOutCase{}, err
	}
	repeat, err := projectDANodeObserverStateCleanup(f, row, images[1], images[2])
	if err != nil {
		return daNodeObserverOutCase{}, err
	}
	actual["follow_up"] = map[string]any{"cleanup_result": repeat["cleanup_result"], "image_and_claims_unchanged": reflect.DeepEqual(images[1].Image, images[2].Image), "owner_high_water_delta": repeat["owner_high_water_delta"]}
	return daNodeObserverOutCase{ID: row.Case.ID, Actual: actual}, nil
}

func decodeDANodeObserverStateString(raw json.RawMessage, label string) (string, error) {
	value, present, err := optionalDANodeObserverDecimal(raw, label)
	if err == nil && !present {
		err = fmt.Errorf("observer input %s: missing string", label)
	}
	return value, err
}

func validateDANodeObserverStateControl(raw json.RawMessage) (daNodeObserverStateControl, error) {
	var c daNodeObserverStateControl
	if err := decodeDANodeObserverInput(raw, &c); err != nil {
		return c, err
	}
	var err, actionErr error
	c.phase, err = decodeDANodeObserverStateString(c.Phase, "control.phase")
	c.action, actionErr = decodeDANodeObserverStateString(c.Action, "control.action")
	if err = cmp.Or(err, actionErr); err != nil {
		return c, err
	}
	member, preserve, locator, revision, delta := false, false, false, false, false
	switch c.phase + "/" + c.action {
	case "NONE/NONE", "NONE/EQUALITY_FEE_OVERRIDE", "NONE/ACCEPTED_SEQUENCE_MAX_MINUS_ONE", "NONE/ACCEPTED_SEQUENCE_MAX":
	case "PLANNED/CORRUPT_RESIDENT_LOCATOR_DA_ID":
		member, preserve, locator = true, true, true
	case "PLANNED/ADVANCE_TARGET_AND_GLOBAL_REVISION":
		preserve, revision = true, true
	case "PLANNED/INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES":
		member, preserve, delta = true, true, true
	case "PLANNED/REMOVE_RESIDENT_CHUNK", "EFFECTS/CLEAR_PRIOR_CLAIM_FINALIZED", "EFFECTS/REMOVE_PRIOR_CLAIM":
		member, preserve = true, true
	default:
		return c, fmt.Errorf("observer input control: unknown phase/action")
	}
	for _, field := range []struct {
		name     string
		raw      json.RawMessage
		required bool
	}{
		{"member", c.Member, member},
		{"preserve_other_fields", c.PreserveOtherFields, preserve},
		{"locator_da_id", c.LocatorDAID, locator},
		{"target_revision", c.TargetRevision, revision},
		{"global_record_revision", c.GlobalRecordRevision, revision},
		{"intrinsic_total_bytes_delta", c.IntrinsicTotalBytesDelta, delta},
	} {
		if (len(field.raw) != 0) != field.required {
			return c, fmt.Errorf("observer input control.%s: missing or forbidden payload", field.name)
		}
	}
	if member {
		var m daNodeObserverStateMemberSelector
		if err := decodeDANodeObserverInput(c.Member, &m); err != nil {
			return c, err
		}
		if m.ClassOrdinal == nil || m.ResidentOrdinal == nil || m.MemberOrdinal == nil || *m.ClassOrdinal > 2 || *m.ResidentOrdinal > 2 || *m.MemberOrdinal > 61 {
			return c, fmt.Errorf("observer input control.member: invalid selector")
		}
		if *m.ResidentOrdinal >= [3]uint64{3, 3, 1}[*m.ClassOrdinal] || *m.MemberOrdinal > [3]uint64{42, 61, 1}[*m.ClassOrdinal] || c.action == "REMOVE_RESIDENT_CHUNK" && *m.MemberOrdinal == 0 {
			return c, fmt.Errorf("observer input control.member: absent member or incompatible role")
		}
		c.selected = &daNodeObserverStateMemberKey{*m.ClassOrdinal, *m.ResidentOrdinal, *m.MemberOrdinal}
	}
	if preserve && !bytes.Equal(bytes.TrimSpace(c.PreserveOtherFields), []byte("true")) {
		return c, fmt.Errorf("observer input control.preserve_other_fields: must be true")
	}
	for _, field := range []struct {
		raw  json.RawMessage
		kind string
	}{{c.LocatorDAID, "locator"}, {c.IntrinsicTotalBytesDelta, "delta"}, {c.TargetRevision, "revision"}, {c.GlobalRecordRevision, "revision"}} {
		if len(field.raw) == 0 {
			continue
		}
		text, e := decodeDANodeObserverStateString(field.raw, field.kind)
		if e != nil {
			return c, e
		}
		switch field.kind {
		case "locator":
			c.locator, err = daNodeObserverStateHex32("locator_da_id", text)
		case "delta":
			c.delta, err = stateDANodeObserverUint("intrinsic_total_bytes_delta", text)
			if c.delta == 0 {
				err = fmt.Errorf("observer input control delta: must be positive")
			}
		case "revision":
			if text != "global_record_revision + 1" {
				err = fmt.Errorf("observer input control revision: unsupported expression")
			}
		}
		if err != nil {
			return c, err
		}
	}
	return c, nil
}

func validateDANodeObserverStateInput(id string, raw json.RawMessage) (daNodeObserverStateInput, error) {
	var input daNodeObserverStateInput
	if err := decodeDANodeObserverInput(raw, &input); err != nil {
		return input, err
	}
	if input.CaseOrdinal == nil {
		return input, fmt.Errorf("observer input %s: missing case_ordinal", id)
	}
	switch input.ExecutionBoundary {
	case "COMPLETE_COMMIT_PRECONDITION":
		if input.ConstructionRef != "COMPLETE_COMMIT_7_SETS" || len(input.MemberProvenance) != 0 || len(input.CleanupSelector) != 0 {
			return input, fmt.Errorf("observer input %s: invalid complete-commit shape", id)
		}
		sequenceText, err := decodeDANodeObserverStateString(input.AcceptedSequence, "accepted_sequence")
		sequence, parseErr := stateDANodeObserverUint("accepted_sequence", sequenceText)
		// The target is the 318th admission, so a lower value would rewind its first received sequence.
		if err != nil || parseErr != nil || sequence < 318 {
			return input, fmt.Errorf("observer input %s: invalid accepted_sequence", id)
		}
		control, err := validateDANodeObserverStateControl(input.Control)
		if err != nil {
			return input, err
		}
		labeled, ok := map[string]uint64{"ACCEPTED_SEQUENCE_MAX": ^uint64(0), "ACCEPTED_SEQUENCE_MAX_MINUS_ONE": ^uint64(0) - 1}[control.action]
		if ok != (sequence >= ^uint64(0)-1) || ok && labeled != sequence {
			return input, fmt.Errorf("observer input %s: accepted_sequence conflicts with control", id)
		}
		input.acceptedSequence, input.control = sequence, control
		wantFollowUp := "RESTORE_NAMED_CORRUPTION_THEN_FRESH_ADMISSION"
		switch control.phase + "/" + control.action {
		case "NONE/NONE", "NONE/EQUALITY_FEE_OVERRIDE", "NONE/ACCEPTED_SEQUENCE_MAX_MINUS_ONE", "NONE/ACCEPTED_SEQUENCE_MAX":
			wantFollowUp = "REPEAT_IDENTICAL_ADMISSION"
		case "PLANNED/ADVANCE_TARGET_AND_GLOBAL_REVISION":
			wantFollowUp = "FRESH_ADMISSION_WITH_CURRENT_TARGET"
		}
		if input.FollowUp != wantFollowUp {
			return input, fmt.Errorf("observer input %s: follow_up does not match control", id)
		}
	case "PEER_CLEANUP_STEP_PRECONDITION":
		if input.ConstructionRef != "STATE_B_MIXED" || len(input.AcceptedSequence) != 0 || len(input.Control) != 0 || len(input.MemberProvenance) == 0 || len(input.CleanupSelector) == 0 || input.FollowUp != "REPEAT_IDENTICAL_CLEANUP" {
			return input, fmt.Errorf("observer input %s: invalid cleanup shape", id)
		}
		var selector daNodeObserverCleanupSelector
		if err := decodeDANodeObserverInput(input.CleanupSelector, &selector); err != nil {
			return input, err
		}
		quota, err := decodeDANodeObserverStateString(selector.QuotaIdentity, "cleanup_selector.quota_identity")
		if err != nil {
			return input, fmt.Errorf("observer input %s: invalid cleanup selector", id)
		}
		input.quotaIdentity = quota
		if input.provenance, err = parseDANodeObserverStateProvenance(input.MemberProvenance); err != nil {
			return input, err
		}
	default:
		return input, fmt.Errorf("observer input %s: unknown execution_boundary", id)
	}
	return input, nil
}

func selectDANodeObserverStateCases(corpus daNodeObserverCorpus) ([]daNodeObserverStateCase, error) {
	selected := make([]daNodeObserverStateCase, 0, len(daNodeObserverStateIDs))
	for _, raw := range corpus.Cases {
		var row daNodeObserverCase
		if err := json.Unmarshal(raw, &row); err != nil {
			return nil, fmt.Errorf("observer census: invalid case: %w", err)
		}
		index := slices.Index(daNodeObserverStateIDs, row.ID)
		if index < 0 {
			var input struct {
				Boundary string `json:"execution_boundary"`
			}
			if len(row.Input) != 0 {
				if err := json.Unmarshal(row.Input, &input); err != nil {
					return nil, fmt.Errorf("observer census: invalid unassigned case input: %w", err)
				}
			}
			if input.Boundary == "COMPLETE_COMMIT_PRECONDITION" || input.Boundary == "PEER_CLEANUP_STEP_PRECONDITION" {
				return nil, fmt.Errorf("observer census: unknown owned case %q", row.ID)
			}
			continue
		}
		if index != len(selected) {
			return nil, fmt.Errorf("observer census: duplicate or out-of-order case %q", row.ID)
		}
		if len(row.Input) == 0 || bytes.Equal(bytes.TrimSpace(row.Input), []byte("null")) {
			return nil, fmt.Errorf("observer input %s: missing input", row.ID)
		}
		input, err := validateDANodeObserverStateInput(row.ID, row.Input)
		if err != nil {
			return nil, err
		}
		selected = append(selected, daNodeObserverStateCase{Case: row, Input: input})
	}
	if len(selected) != len(daNodeObserverStateIDs) {
		return nil, fmt.Errorf("observer census: got %d owned cases, want %d", len(selected), len(daNodeObserverStateIDs))
	}
	return selected, nil
}

func collectDANodeObserverState(raw []byte) ([]byte, error) {
	var corpus daNodeObserverCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		return nil, fmt.Errorf("observer input corpus: %w", err)
	}
	if corpus.FormatVersion != 1 || len(corpus.InputFixtures) == 0 {
		return nil, fmt.Errorf("observer input corpus: missing versioned inputs")
	}
	cases, err := selectDANodeObserverStateCases(corpus)
	if err != nil {
		return nil, err
	}
	profile, err := loadDANodeObserverStateProfile(corpus.InputFixtures)
	if err != nil {
		return nil, err
	}
	out := daNodeObserverOutput{FormatVersion: 1, Cases: make([]daNodeObserverOutCase, 0, len(cases))}
	for _, row := range cases {
		observed, err := collectDANodeObserverStateCase(row, profile)
		if err != nil {
			return nil, err
		}
		out.Cases = append(out.Cases, observed)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("observer output: %w", err)
	}
	return append(encoded, '\n'), nil
}

func TestDAAdmissionObserverNodeState(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	require(t, err == nil, "observer input corpus: %v", err)
	actual, err := collectDANodeObserverState(raw)
	require(t, err == nil, "observer state: %v", err)
	var output daNodeObserverOutput
	err = json.Unmarshal(actual, &output)
	require(t, err == nil, "observer output: %v", err)
	require(t, output.FormatVersion == 1 && len(output.Cases) == len(daNodeObserverStateIDs), "observer census: output version=%d cases=%d", output.FormatVersion, len(output.Cases))
	if path := os.Getenv("RUBIN_DA_NODE_STATE_ACTUAL_OUT"); path != "" {
		err := os.WriteFile(path, actual, 0o600)
		require(t, err == nil, "observer output write: %v", err)
	}
}

func stateTestData(t *testing.T) ([]byte, daNodeObserverCorpus, []daNodeObserverStateCase, daNodeObserverStateProfile) {
	t.Helper()
	corpus, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	require(t, err == nil, "observer state: %v", err)
	cases, err := selectDANodeObserverStateCases(corpus)
	require(t, err == nil, "observer state: %v", err)
	profile, err := loadDANodeObserverStateProfile(corpus.InputFixtures)
	require(t, err == nil, "observer state: %v", err)
	return raw, corpus, cases, profile
}

func stateAssertJSON(t *testing.T, got any, want string) {
	t.Helper()
	var expected any
	err := json.Unmarshal([]byte(want), &expected)
	require(t, err == nil, "observer expected JSON: %v", err)
	actual, err := json.Marshal(got)
	target, _ := json.Marshal(expected)
	require(t, err == nil && bytes.Equal(actual, target), "observer state projection: got %s, want %s (%v)", actual, target, err)
}

func TestDAAdmissionObserverNodeStateIsolation(t *testing.T) {
	raw, _, _, _ := stateTestData(t)
	baseline, err := collectDANodeObserverState(raw)
	require(t, err == nil, "observer state: %v", err)
	poisoned, err := poisonDANodeObserverExpectations(raw)
	require(t, err == nil, "observer state: %v", err)
	actual, err := collectDANodeObserverState(poisoned)
	require(t, err == nil && bytes.Equal(actual, baseline), "observer state expected isolation: %v", err)
}

func TestDAAdmissionObserverNodeStateReachability(t *testing.T) {
	_, _, cases, profile := stateTestData(t)
	for i, row := range cases {
		t.Run(row.Case.ID, func(t *testing.T) {
			baseline, err := collectDANodeObserverStateCase(row, profile)
			require(t, err == nil, "observer state: %v", err)
			var input map[string]json.RawMessage
			require(t, json.Unmarshal(row.Case.Input, &input) == nil, "observer state: invalid case input")
			switch {
			case i == 11:
				input["cleanup_selector"] = json.RawMessage(`{"quota_identity":"absent-quota"}`)
			case i == 12:
				input["member_provenance"] = json.RawMessage(`[{"source":"PEER","peer_identity":"peer-cleanup","quota_identity":"quota-cleanup"},{"source":"PEER","peer_identity":"peer-cleanup","quota_identity":"quota-cleanup"},{"source":"DETACHED_REORG"}]`)
			case row.Input.control.action == "NONE":
				input["accepted_sequence"] = json.RawMessage(`"319"`)
			default:
				input["control"] = json.RawMessage(`{"phase":"NONE","action":"NONE"}`)
				input["follow_up"], input["accepted_sequence"] = json.RawMessage(`"REPEAT_IDENTICAL_ADMISSION"`), json.RawMessage(`"318"`)
			}
			row.Case.Input, err = json.Marshal(input)
			require(t, err == nil, "observer state: %v", err)
			row.Input, err = validateDANodeObserverStateInput(row.Case.ID, row.Case.Input)
			require(t, err == nil, "observer state: %v", err)
			actual, err := collectDANodeObserverStateCase(row, profile)
			require(t, err == nil, "observer state: %v", err)
			if i == 12 {
				require(t, actual.Actual["cleanup_result"] == "REMOVED_PEER_CHUNKS", "observer state cleanup: changed PEER chunk was not removed")
				require(t, reflect.DeepEqual(actual.Actual["selected_member_ordinals"], []uint64{1}), "observer state cleanup: selected %v, want only member 1", actual.Actual["selected_member_ordinals"])
			}
			delete(baseline.Actual, "follow_up")
			delete(actual.Actual, "follow_up")
			left, _ := json.Marshal(baseline)
			right, _ := json.Marshal(actual)
			require(t, !bytes.Equal(left, right), "observer state input reachability: %s", row.Case.ID)
		})
	}
}

func TestDAAdmissionObserverNodeStateIntegrity(t *testing.T) {
	_, corpus, cases, profile := stateTestData(t)
	owned := make([]json.RawMessage, len(cases))
	for i, row := range cases {
		owned[i], _ = json.Marshal(row.Case)
	}
	unknownCommit, unknownCleanup := cases[0].Case, cases[12].Case
	unknownCommit.ID, unknownCleanup.ID = "UNKNOWN_STATE_CASE", "UNKNOWN_STATE_CASE"
	for mode, probe := range []struct {
		mutate func([]json.RawMessage) []json.RawMessage
		want   string
	}{
		{func(c []json.RawMessage) []json.RawMessage { return c[:len(c)-1] }, "observer census: got 12 owned cases"},
		{func(c []json.RawMessage) []json.RawMessage { return append(c, owned[0]) }, "observer census: duplicate or out-of-order"},
		{func(c []json.RawMessage) []json.RawMessage { c[0], c[1] = c[1], c[0]; return c }, "observer census: duplicate or out-of-order"},
		{func(c []json.RawMessage) []json.RawMessage { c[0], _ = json.Marshal(unknownCommit); return c }, "observer census: unknown owned case"},
		{func(c []json.RawMessage) []json.RawMessage { c[12], _ = json.Marshal(unknownCleanup); return c }, "observer census: unknown owned case"},
	} {
		bad := corpus
		bad.Cases = probe.mutate(slices.Clone(owned))
		_, err := selectDANodeObserverStateCases(bad)
		require(t, err != nil && strings.Contains(err.Error(), probe.want), "observer state integrity census %d: %v", mode, err)
	}
	// The extra value conflicts with the row's own sequence label: MAX on a NONE row, 318 on the MAX_MINUS_ONE row.
	for _, probe := range []struct {
		row   daNodeObserverStateCase
		extra string
	}{{cases[0], `"18446744073709551615"`}, {cases[9], `"318"`}} {
		for _, field := range []string{"execution_boundary", "construction_ref", "case_ordinal", "accepted_sequence", "follow_up"} {
			for _, value := range []string{"null", `"UNKNOWN"`, `"-1"`, `"317"`, `"18446744073709551616"`, probe.extra} {
				var input map[string]json.RawMessage
				_ = json.Unmarshal(probe.row.Case.Input, &input)
				input[field] = json.RawMessage(value)
				raw, _ := json.Marshal(input)
				_, err := validateDANodeObserverStateInput(probe.row.Case.ID, raw)
				require(t, err != nil && strings.Contains(err.Error(), "observer input"), "observer state integrity %s %s=%s: %v", probe.row.Case.ID, field, value, err)
			}
		}
	}
	for _, row := range cases[:11] {
		var control map[string]json.RawMessage
		_ = json.Unmarshal(row.Input.Control, &control)
		for field := range control {
			bad := maps.Clone(control)
			delete(bad, field)
			raw, _ := json.Marshal(bad)
			_, err := validateDANodeObserverStateControl(raw)
			require(t, err != nil && strings.Contains(err.Error(), "observer input"), "observer state integrity missing control.%s in %s: %v", field, row.Case.ID, err)
		}
	}
	for _, raw := range []string{
		`{"phase":"UNKNOWN","action":"NONE"}`, `{"phase":"NONE","action":"UNKNOWN"}`,
		`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":0,"resident_ordinal":0,"member_ordinal":1},"preserve_other_fields":false}`,
		`{"phase":"NONE","action":"NONE","member":null}`, `{"phase":"NONE","action":"NONE","extra":1}`,
		`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":2,"resident_ordinal":2,"member_ordinal":1},"preserve_other_fields":true}`,
		`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"resident_ordinal":0,"member_ordinal":1},"preserve_other_fields":true}`,
		`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":0,"member_ordinal":1},"preserve_other_fields":true}`,
		`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":0,"resident_ordinal":0},"preserve_other_fields":true}`,
		`{"phase":"PLANNED","action":"CORRUPT_RESIDENT_LOCATOR_DA_ID","member":{"class_ordinal":0,"resident_ordinal":0,"member_ordinal":1},"preserve_other_fields":true,"locator_da_id":"zz"}`,
		`{"phase":"PLANNED","action":"INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES","member":{"class_ordinal":0,"resident_ordinal":0,"member_ordinal":0},"preserve_other_fields":true,"intrinsic_total_bytes_delta":"18446744073709551616"}`,
	} {
		_, err := validateDANodeObserverStateControl([]byte(raw))
		require(t, err != nil && strings.Contains(err.Error(), "observer input"), "observer state integrity accepted control %s: %v", raw, err)
	}
	for _, raw := range []string{`[{"source":"UNKNOWN"},{"source":"LOCAL"},{"source":"DETACHED_REORG"}]`, `[{"source":"PEER"},{"source":"LOCAL"},{"source":"DETACHED_REORG"}]`, `[{"source":"LOCAL","peer_identity":"x"},{"source":"LOCAL"},{"source":"DETACHED_REORG"}]`} {
		_, err := parseDANodeObserverStateProvenance([]byte(raw))
		require(t, err != nil && strings.Contains(err.Error(), "observer input"), "observer state integrity accepted provenance %s: %v", raw, err)
	}
	for mode, mutate := range []func(*daNodeObserverStateProfile){
		func(p *daNodeObserverStateProfile) { p.Mixed.MemberTemplateRef = "UNKNOWN" },
		func(p *daNodeObserverStateProfile) { p.Mixed.ChunkCount = 65536 },
		func(p *daNodeObserverStateProfile) { p.Complete.Target.ChunkLengths = []uint64{^uint64(0)} },
		func(p *daNodeObserverStateProfile) { p.Canonical.Input.Value = "18446744073709551616" },
		func(p *daNodeObserverStateProfile) { p.Complete.EffectiveDAMempoolSize = "536870913" },
		func(p *daNodeObserverStateProfile) { p.Complete.PinnedPayloadMax = "96000001" },
		func(p *daNodeObserverStateProfile) { p.Complete.CompleteSetMaxCount = 65537 },
	} {
		bad := profile
		mutate(&bad)
		err := validateDANodeObserverStateProfile(bad)
		require(t, err != nil && strings.Contains(err.Error(), "observer input"), "observer state integrity accepted construction %d: %v", mode, err)
	}
	f, err := newDANodeObserverStateFixture(cases[0], profile)
	require(t, err == nil, "observer state: %v", err)
	defer f.Signer.Close()
	initial, err := observerImageOutsideHook(f, false)
	require(t, err == nil, "observer state: %v", err)
	tx, _, _, _, err := consensus.ParseTx(f.Candidate.Raw)
	require(t, err == nil, "observer state: %v", err)
	tx.Witness[0].Signature[0] ^= 1
	invalid, err := consensus.MarshalTx(tx)
	require(t, err == nil, "observer state: %v", err)
	_, err = f.Relay.AdmitDA(invalid, f.Candidate.Provenance)
	require(t, err != nil, "observer state integrity: invalid signature retained")
	unchanged, err := observerImageOutsideHook(f, false)
	require(t, err == nil && reflect.DeepEqual(initial, unchanged), "observer state integrity: invalid signature changed retained state: %v", err)
	tampered := f.TargetCommit
	tampered.Fee.Lo++
	f.Members[tampered.Key] = tampered
	require(t, stateSetupBaseline(f) != nil, "observer state setup baseline: tampered member accepted")
	delete(f.Members, tampered.Key)
	require(t, stateSetupBaseline(f) != nil, "observer state setup baseline: retained rows outside the constructed members accepted")
	f.Members[tampered.Key] = f.TargetCommit
	overflow := daNodeObserverStateControl{action: "INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES", selected: &daNodeObserverStateMemberKey{}, delta: ^uint64(0)}
	require(t, stateControlDeltaChecked(f, overflow) != nil, "observer state integrity: intrinsic delta overflow accepted before the measured call")
	seq := profile
	seq.Mixed.FirstReceivedSequence, seq.Complete.AcceptedSequence = "2", "317"
	for _, row := range []daNodeObserverStateCase{cases[11], cases[0]} {
		_, err = newDANodeObserverStateFixture(row, seq)
		require(t, err != nil && strings.Contains(err.Error(), "first received sequence"), "observer state setup: %s sequence mismatch accepted: %v", row.Case.ID, err)
	}
	floor := profile
	floor.Canonical.Policy.RollingFeeFloor = "2"
	_, err = newDANodeObserverStateFixture(cases[11], floor)
	require(t, err != nil && strings.Contains(err.Error(), "rolling_fee_floor"), "observer state integrity: unbound rolling fee floor accepted: %v", err)
	// The rejected invalid txid is cached, so the closure probe takes a fresh fixture; a per-peer
	// entry added at EFFECTS survives Go's pre-mutation owner-ready check and publication.
	m, err := newDANodeObserverStateFixture(cases[0], profile)
	require(t, err == nil, "observer state: %v", err)
	defer m.Signer.Close()
	m.Relay.completeHook = func(stage daCompleteStage, _ *daCompleteCommitPlan) {
		if stage == daCompleteEffects {
			m.Relay.orphanBytesByPeerQuotaKey["stale"] = 1
		}
	}
	_, err = admitDANodeObserverStateCandidate(m, cases[0].Input.control)
	require(t, err != nil && strings.Contains(err.Error(), "accounting closure"), "observer state accounting closure: retained admission accepted stale accounting: %v", err)
	_, open := observerImageOutsideHook(m, false)
	_, closed := observerImageOutsideHook(m, true)
	require(t, open == nil && closed != nil && strings.Contains(closed.Error(), "accounting closure"), "observer state accounting closure: closed=%v open=%v", closed, open)
}

func TestDAAdmissionObserverNodeStateProjection(t *testing.T) {
	stateAssertJSON(t, daNodeObserverStateCounters(DAObserverStateImage{StagedBytes: 1, CompleteBytes: 2, CompleteCount: 3, PinnedPayloadBytes: 4, NextReceivedTime: 5}), `{"staged_retained_bytes":"1","complete_retained_bytes":"2","complete_set_count":3,"complete_payload_bytes":"4","accepted_sequence":"5"}`)
	owner := &PendingOutpointOwner{}
	before := daNodeObserverStateOwnerImage{Identity: owner, Counts: DAObserverOwnerCounts{1, 2, 3, 4}, TokenHighWater: 5, Generation: 6}
	after := daNodeObserverStateOwnerImage{Identity: owner, Counts: DAObserverOwnerCounts{11, 22, 33, 44}, TokenHighWater: 55}
	counts, highWater, err := daNodeObserverStateOwnerDeltas(before, after)
	require(t, err == nil, "observer state: %v", err)
	stateAssertJSON(t, daNodeObserverStateOwnerOutput(7, counts, highWater, "CANDIDATE_ONLY"), `{"admission_entrypoint":{"domain":"DA","invocations":7},"pending_outpoint":{"reserve_calls":10,"reservations_acquired":20,"finalizations":30,"exact_releases":40},"token_high_water_delta":"50","exact_release_scope":"CANDIDATE_ONLY"}`)
	victims, err := daNodeObserverStateOrderedVictims([][32]byte{{1}, {2}}, [][32]byte{{1}})
	require(t, err == nil, "observer state: %v", err)
	stateAssertJSON(t, victims, `["0100000000000000000000000000000000000000000000000000000000000000"]`)
	for _, row := range []struct {
		call   DAObserverAdmitCall
		reason string
	}{
		{DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionRetained}}, "NONE"},
		{DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionDuplicate}}, "DUPLICATE_CONFLICT"},
		{DAObserverAdmitCall{Err: errDARelayArithmeticOverflow}, "SEQUENCE_EXHAUSTED"},
		{DAObserverAdmitCall{Err: daCompleteStaleError()}, "STALE_PLAN"},
		{DAObserverAdmitCall{Err: &TxAdmitError{disposition: RelayAdmissionCapacity}}, "CANDIDATE_NOT_BETTER"},
		{DAObserverAdmitCall{Err: errDARelayImageIncompatible}, "INTERNAL"},
	} {
		actual, err := daNodeObserverStateResult(row.call, ^uint64(0), true)
		disposition := "REJECT_UNCHANGED"
		if row.reason == "NONE" {
			disposition = "COMMIT_WITH_VICTIMS"
		}
		require(t, err == nil && reflect.DeepEqual(actual, map[string]any{"disposition": disposition, "semantic_reason_id": row.reason}), "observer state projection result %s: %v %v", row.reason, actual, err)
	}
	_, err = daNodeObserverStateResult(DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionRetained}}, 0, false)
	require(t, err != nil, "observer state projection: retained result without publication accepted")
	_, err = daNodeObserverStateResult(DAObserverAdmitCall{Err: errors.New("unknown")}, 0, false)
	require(t, err != nil, "observer state projection: unknown error accepted")
	commit := daNodeObserverStateMember{Key: daNodeObserverStateMemberKey{MemberOrdinal: 0}, DAID: [32]byte{9}, TxID: [32]byte{1}, Provenance: LocalDAProvenance()}
	chunk := daNodeObserverStateMember{Key: daNodeObserverStateMemberKey{MemberOrdinal: 1}, DAID: [32]byte{9}, TxID: [32]byte{2}, Provenance: DAProvenance{kind: daProvenancePeer, peerIdentity: "p", quotaIdentity: "q"}}
	small := &daNodeObserverStateFixture{Members: map[daNodeObserverStateMemberKey]daNodeObserverStateMember{commit.Key: commit, chunk.Key: chunk}}
	cm := &DAObserverMember{TxID: commit.TxID, Provenance: DAObserverProvenance{Kind: "LOCAL"}}
	ch := &DAObserverMember{TxID: chunk.TxID, Provenance: DAObserverProvenance{Kind: "PEER", PeerIdentity: "p", QuotaIdentity: "q"}}
	record := DAObserverRecord{DAID: commit.DAID, State: "STAGED_COMMIT", ReceivedTime: 2, Commit: DAObserverCommit{Member: cm, ChunkCount: 1, TxBytes: []byte{1}}, Chunks: []DAObserverChunk{{Member: ch, TxBytes: []byte{2, 3}, Payload: []byte{4, 5}}}}
	prior := daNodeObserverStateObservation{Owner: before, Image: DAObserverStateImage{Records: []DAObserverRecord{record}, StagedBytes: 5, NextReceivedTime: 4, Locators: []DAObserverLocator{{TxID: chunk.TxID, DAID: chunk.DAID}}, Claims: []DAObserverClaim{{TxID: chunk.TxID, TokenSeq: 3}}}}
	record.Chunks = nil
	next := daNodeObserverStateObservation{Owner: before, Image: DAObserverStateImage{Records: []DAObserverRecord{record}, StagedBytes: 1, NextReceivedTime: 4}}
	cleanup, err := projectDANodeObserverStateCleanup(small, daNodeObserverStateCase{}, prior, next)
	require(t, err == nil, "observer state: %v", err)
	next.Image.OutpointRows = []DAObserverOutpointRow{{TxID: chunk.TxID}}
	stale, err := projectDANodeObserverStateCleanup(small, daNodeObserverStateCase{}, prior, next)
	require(t, err == nil && stale["surviving_members_and_claims_unchanged"] == false, "observer state cleanup: removed member outpoint row survived: %v", err)
	_, err = projectDANodeObserverStateCleanup(small, daNodeObserverStateCase{}, prior, daNodeObserverStateObservation{Owner: before})
	require(t, err != nil, "observer state cleanup: absent record projected as zero values")
	stateAssertJSON(t, cleanup, `{"cleanup_result":"REMOVED_PEER_CHUNKS","selected_member_ordinals":[1],"released_charge":"4","removed_locator_count":1,"removed_claim_count":1,"owner_high_water_delta":"0","after_image":{"state":"STAGED_COMMIT","da_id":"0900000000000000000000000000000000000000000000000000000000000000","received_sequence":"2","commit_chunk_count":1,"members":[{"member_ordinal":0,"role":"COMMIT","provenance":{"source":"LOCAL"},"retained_tx_bytes":"1","incomplete_member_charge":"1"}],"retained_counters":{"staged_retained_bytes":"1","complete_retained_bytes":"0","complete_set_count":0,"complete_payload_bytes":"0","accepted_sequence":"4"},"peer_quota_accounting":[]},"surviving_members_and_claims_unchanged":true,"whole_record_removed":false}`)
	// Independent completion values exercise the final consumer, including false observations.
	commit.Raw, chunk.Raw = []byte{1}, []byte{2, 3}
	small.TargetCommit, small.Candidate = commit, chunk
	cm.TokenSeq, ch.TokenSeq = 1, 2
	chunk.Inputs = []consensus.Outpoint{{Txid: [32]byte{42}, Vout: 7}}
	ch.Inputs, small.Candidate = slices.Clone(chunk.Inputs), chunk
	commitLocator := DAObserverLocator{TxID: commit.TxID, DAID: commit.DAID, Kind: "COMMIT"}
	commitClaim := DAObserverClaim{TxID: commit.TxID, TokenSeq: 1, Domain: "DA", Finalized: true, Generation: 6}
	base := DAObserverStateImage{Records: []DAObserverRecord{record}, Locators: []DAObserverLocator{commitLocator}, Claims: []DAObserverClaim{commitClaim}}
	published := base
	published.Records = []DAObserverRecord{record}
	published.Records[0].Chunks = []DAObserverChunk{{Member: ch, TxBytes: []byte{2, 3}}}
	published.Locators = append(slices.Clone(base.Locators), DAObserverLocator{TxID: chunk.TxID, DAID: chunk.DAID, Kind: "CHUNK"})
	published.Claims = append(slices.Clone(base.Claims), DAObserverClaim{TxID: chunk.TxID, TokenSeq: 2, Domain: "DA", Inputs: slices.Clone(chunk.Inputs), Finalized: true, Generation: 6})
	owned := DAObserverOutpointRow{Outpoint: chunk.Inputs[0], TxID: chunk.TxID, TokenSeq: 2}
	published.OutpointRows = []DAObserverOutpointRow{owned}
	for mode := 0; mode < 4; mode++ {
		run := daNodeObserverStateAdmission{Invocations: 7, Before: daNodeObserverStateObservation{Image: base, Owner: before}, After: daNodeObserverStateObservation{Image: published, Owner: before}, Call: DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionRetained}}}
		run.After.Image.Records = slices.Clone(published.Records)
		run.After.Image.Records[0].Chunks = slices.Clone(published.Records[0].Chunks)
		if mode == 1 {
			run.After.Image.Records[0].Chunks[0].TxBytes = []byte{99}
		} else if mode == 2 {
			run.After.Image.Records[0].Commit.TxBytes = []byte{99}
		} else if mode == 3 {
			run.Call = DAObserverAdmitCall{Err: errDARelayImageIncompatible}
			run.After.Image, run.PlanOrder = base, [][32]byte{{8}}
		}
		actual, _, err := daNodeObserverStateAdmissionImageOutput(small, run)
		require(t, err == nil, "observer state projection consumer: %v", err)
		stateAssertJSON(t, actual["owner"], `{"admission_entrypoint":{"domain":"DA","invocations":7},"pending_outpoint":{"reserve_calls":0,"reservations_acquired":0,"finalizations":0,"exact_releases":0},"token_high_water_delta":"0","exact_release_scope":"NONE"}`)
		stateAssertJSON(t, actual["victims"], `[]`)
		image := actual["state_image"].(map[string]any)
		key, flag := "candidate_members_match_construction", mode != 1
		if mode == 3 {
			key, flag = "image_and_prior_claims_unchanged_from_control_baseline", true
		}
		want := map[string]any{"candidate_published": mode != 3, "retained_counters": map[string]any{"staged_retained_bytes": "0", "complete_retained_bytes": "0", "complete_set_count": uint64(0), "complete_payload_bytes": "0", "accepted_sequence": "0"}, "target_first_received_sequence": "2", "removed": map[string]any{"record_count": 0, "member_locator_count": 0, "claim_count": 0}, "surviving_members_and_claims_unchanged": mode != 2, key: flag}
		require(t, reflect.DeepEqual(image, want), "observer state projection consumer mode %d: got %v want %v", mode, image, want)
	}
	for _, rows := range [][]DAObserverOutpointRow{
		nil,
		{{Outpoint: owned.Outpoint, TxID: owned.TxID, TokenSeq: 3}},
		{{Outpoint: owned.Outpoint, TxID: [32]byte{99}, TokenSeq: 2}},
		{{Outpoint: consensus.Outpoint{Vout: 99}, TxID: owned.TxID, TokenSeq: 2}},
		{owned, owned},
		{owned, {Outpoint: consensus.Outpoint{Vout: 99}, TxID: [32]byte{99}, TokenSeq: 2}},
	} {
		broken := published
		broken.OutpointRows = rows
		actual, _, err := daNodeObserverStateAdmissionImageOutput(small, daNodeObserverStateAdmission{Before: daNodeObserverStateObservation{Image: base, Owner: before}, After: daNodeObserverStateObservation{Image: broken, Owner: before}, Call: DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionRetained}}})
		require(t, err == nil && actual["state_image"].(map[string]any)["candidate_members_match_construction"] == false, "observer state candidate outpoint bindings: rows=%v error=%v", rows, err)
	}
	duplicated := published
	duplicated.Claims = append(slices.Clone(published.Claims), published.Claims[len(published.Claims)-1])
	require(t, daNodeObserverStateCandidateMatches(published, chunk, 6), "observer state candidate: constructed claim rejected")
	require(t, !daNodeObserverStateCandidateMatches(duplicated, chunk, 6), "observer state candidate claim multiplicity")
	require(t, !daNodeObserverStateCandidateMatches(published, chunk, 7), "observer state candidate claim generation")
	require(t, !daNodeObserverStateSurvivorsEqual(published, DAObserverStateImage{OutpointRows: published.OutpointRows}, [][32]byte{commit.DAID}, nil, [32]byte{}), "observer state completion: removed member outpoint row survived")
	retained := DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionRetained}}
	require(t, stateRetryImageChecked(retained, map[string]any{"surviving_members_and_claims_unchanged": true, "candidate_members_match_construction": true}) == nil, "observer state follow-up: retained retry rejected")
	require(t, stateRetryImageChecked(retained, map[string]any{"surviving_members_and_claims_unchanged": true, "candidate_members_match_construction": false}) != nil, "observer state follow-up: retained retry candidate mismatch accepted")
	require(t, stateRetryImageChecked(retained, map[string]any{"surviving_members_and_claims_unchanged": false, "candidate_members_match_construction": true}) != nil, "observer state follow-up: retained retry survivor change accepted")
	_, _, cases, profile := stateTestData(t)
	f, err := newDANodeObserverStateFixture(cases[5], profile)
	require(t, err == nil, "observer state: %v", err)
	defer f.Signer.Close()
	primary, err := admitDANodeObserverStateCandidate(f, cases[5].Input.control)
	require(t, err == nil && primary.Call.Err != nil && primary.After.Owner.Counts.ReservationsAcquired-primary.Before.Owner.Counts.ReservationsAcquired == 1, "observer state follow-up high-water continuity: primary refusal not observed: %v", err)
	saved := primary.After.Owner
	original := f.Relay.sets[f.Candidate.DAID].commit.txBytes
	independent := bytes.Clone(original)
	original[0] ^= 1
	require(t, bytes.Equal(primary.Before.Image.Records[len(primary.Before.Image.Records)-1].Commit.TxBytes, independent) && bytes.Equal(primary.After.Image.Records[len(primary.After.Image.Records)-1].Commit.TxBytes, independent), "observer state alias: primary baseline changed")
	original[0] ^= 1
	follow, err := daNodeObserverStateAdmissionFollowUp(cases[5], f, primary)
	require(t, err == nil, "observer state: %v", err)
	stateAssertJSON(t, follow["result"], `{"disposition":"COMMIT_WITH_VICTIMS","semantic_reason_id":"NONE"}`)
	final, err := observerImageOutsideHook(f, false)
	require(t, err == nil && final.Owner.Identity == saved.Identity && final.Owner.TokenHighWater == saved.TokenHighWater+1 && final.Owner.Counts.ReservationsAcquired == saved.Counts.ReservationsAcquired+1 && daNodeObserverStateCandidateToken(final.Image, f.Candidate) > saved.TokenHighWater, "observer state follow-up high-water continuity: %v", err)
	require(t, daNodeObserverStateCandidateMatches(final.Image, f.Candidate, final.Owner.Generation), "observer state projection: retried candidate does not match its construction")
	require(t, daNodeObserverStateSurvivorsEqual(final.Image, final.Image, nil, nil, [32]byte{}), "observer state projection: identical images reported unequal")
	f.Relay.sets[f.Candidate.DAID].commit.txBytes[0] ^= 1
	changed, err := observerImageOutsideHook(f, false)
	require(t, err == nil && bytes.Equal(final.Image.Records[len(final.Image.Records)-1].Commit.TxBytes, independent), "observer state alias: final baseline changed: %v", err)
	f.Relay.sets[f.Candidate.DAID].commit.txBytes[0] ^= 1
	require(t, !daNodeObserverStateSurvivorsEqual(final.Image, changed.Image, nil, nil, [32]byte{}), "observer state projection: changed member reported as a surviving equal")
	require(t, !daNodeObserverStateCandidateMatches(changed.Image, f.TargetCommit, changed.Owner.Generation), "observer state projection: changed member reported as matching its construction")
}

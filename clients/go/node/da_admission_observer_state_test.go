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
	"path/filepath"
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
	Restore      func() error
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

func observerImageInHook(f *daNodeObserverStateFixture, stage daCompleteStage) daNodeObserverStateObservation {
	relay, owner := f.Relay, f.Mempool.pendingOutpoints
	if stage == daCompletePlanned {
		relay.mu.Lock()
		defer relay.mu.Unlock()
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return observerImageLocked(relay, owner)
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
	return observerImageInHook(f, daCompleteEffects), nil
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

// lockedRestore undoes one named corruption only while its target still carries it.
func lockedRestore(mu sync.Locker, corrupted func() bool, restore func()) func() error {
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		if !corrupted() {
			return fmt.Errorf("observer state restore: named corruption target is absent or no longer corrupted")
		}
		restore()
		return nil
	}
}

func applyDANodeObserverStatePlannedControl(f *daNodeObserverStateFixture, control daNodeObserverStateControl) (func() error, error) {
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
		corrupt := daRelayLocator{daID: control.locator, kind: locator.kind, chunkIndex: locator.chunkIndex}
		relay.locators[member.TxID] = corrupt
		return lockedRestore(&relay.mu, func() bool { current, ok := relay.locators[member.TxID]; return ok && current == corrupt },
			func() { relay.locators[member.TxID] = locator }), nil
	case "INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES":
		old := record.completeIntrinsic.totalBytes
		record.completeIntrinsic.totalBytes += control.delta
		relay.sets[member.DAID] = record
		return lockedRestore(&relay.mu, func() bool {
			current, ok := relay.sets[member.DAID]
			return ok && current.completeIntrinsic.totalBytes == record.completeIntrinsic.totalBytes
		}, func() {
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
		return lockedRestore(&relay.mu, func() bool {
			current, ok := relay.sets[member.DAID]
			_, present := current.chunks[index]
			return ok && current.chunks != nil && !present
		}, func() { relay.sets[member.DAID].chunks[index] = chunk }), nil
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

func applyDANodeObserverStateEffectsControl(f *daNodeObserverStateFixture, control daNodeObserverStateControl) (func() error, error) {
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
		return lockedRestore(&owner.mu, func() bool { return owner.byToken[token] == claim && !claim.finalized }, func() { claim.finalized = old }), nil
	case "REMOVE_PRIOR_CLAIM":
		delete(owner.byToken, token)
		restore := lockedRestore(&owner.mu, func() bool {
			locator, retained := f.Relay.locators[member.TxID]
			_, present := owner.byToken[token]
			return retained && locator.daID == member.DAID && !present
		}, func() { owner.byToken[token] = claim })
		// DA->owner lock order: the claim returns only while its member is still retained.
		return func() error { f.Relay.mu.Lock(); defer f.Relay.mu.Unlock(); return restore() }, nil
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
		if result.Restore, hookErr = apply(f, control); hookErr == nil {
			result.Before = observerImageInHook(f, stage)
		}
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
	// The completion value also requires the retained target commit to still match its construction.
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
			return nil, fmt.Errorf("observer state restore %s: named control has no restorable field", row.Case.ID)
		}
		if err := primary.Restore(); err != nil {
			return nil, err
		}
	}
	prior, err := observerImageOutsideHook(fixture, false)
	if err != nil {
		return nil, err
	}
	if primary.After.Owner != prior.Owner {
		return nil, fmt.Errorf("observer state follow-up high-water continuity: owner identity or counters changed before retry")
	}
	run, err := admitDANodeObserverStateCandidate(fixture, daNodeObserverStateControl{phase: "NONE", action: "NONE"})
	if err != nil {
		return nil, err
	}
	return stateAdmissionFollowUpOutput(fixture, row.Input.FollowUp, run, prior.Owner.TokenHighWater)
}

// stateAdmissionFollowUpOutput projects one follow-up call; savedHighWater is the owner high-water saved after the primary call.
func stateAdmissionFollowUpOutput(fixture *daNodeObserverStateFixture, followUp string, run daNodeObserverStateAdmission, savedHighWater uint64) (map[string]any, error) {
	projected, victims, err := daNodeObserverStateAdmissionImageOutput(fixture, run)
	if err != nil {
		return nil, err
	}
	stateImage := projected["state_image"].(map[string]any)
	if err := stateRetryImageChecked(run.Call, stateImage); err != nil {
		return nil, err
	}
	result, owner := projected["result"], projected["owner"]
	if followUp == "REPEAT_IDENTICAL_ADMISSION" {
		return map[string]any{
			"result": result, "owner": owner,
			"image_and_prior_claims_unchanged": reflect.DeepEqual(run.Before.Image, run.After.Image),
			"accepted_sequence":                daNodeObserverStateDecimal(run.After.Image.NextReceivedTime),
		}, nil
	}
	if run.After.Owner.Counts.ReservationsAcquired < run.Before.Owner.Counts.ReservationsAcquired ||
		^uint64(0)-run.Before.Owner.TokenHighWater < run.After.Owner.Counts.ReservationsAcquired-run.Before.Owner.Counts.ReservationsAcquired ||
		run.After.Owner.TokenHighWater != run.Before.Owner.TokenHighWater+run.After.Owner.Counts.ReservationsAcquired-run.Before.Owner.Counts.ReservationsAcquired ||
		(run.Call.Err == nil && run.Call.Result.Disposition == DAAdmissionRetained && daNodeObserverStateCandidateToken(run.After.Image, fixture.Candidate) <= savedHighWater) {
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
	constructed := stateConstructedMembers(f)
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
	actual := len(record.Chunks)
	if record.Commit.Member != nil {
		actual++
	}
	if len(members) != actual {
		return nil, nil, record, false, fmt.Errorf("observer state cleanup: retained record member has no constructed input")
	}
	return members, charges, record, exists, nil
}

// stateConstructedMembers lists the constructed members in input (member ordinal) order.
func stateConstructedMembers(f *daNodeObserverStateFixture) []daNodeObserverStateMember {
	return slices.SortedFunc(maps.Values(f.Members), func(a, b daNodeObserverStateMember) int {
		return cmp.Compare(a.Key.MemberOrdinal, b.Key.MemberOrdinal)
	})
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
	for _, member := range stateConstructedMembers(f) {
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
	if before.Image.StagedBytes < after.Image.StagedBytes || released != before.Image.StagedBytes-after.Image.StagedBytes {
		return nil, fmt.Errorf("observer state cleanup: released charge %d is not Go's staged-bytes delta", released)
	}
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
	if actual["follow_up"], err = stateCleanupFollowUp(f, row, images[1], images[2]); err != nil {
		return daNodeObserverOutCase{}, err
	}
	return daNodeObserverOutCase{ID: row.Case.ID, Actual: actual}, nil
}

func stateCleanupFollowUp(f *daNodeObserverStateFixture, row daNodeObserverStateCase, before, after daNodeObserverStateObservation) (map[string]any, error) {
	repeat, err := projectDANodeObserverStateCleanup(f, row, before, after)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"cleanup_result":             repeat["cleanup_result"],
		"image_and_claims_unchanged": reflect.DeepEqual(before.Image, after.Image),
		"owner_high_water_delta":     repeat["owner_high_water_delta"],
	}, nil
}

func decodeDANodeObserverStateString(raw json.RawMessage, label string) (string, error) {
	value, present, err := optionalDANodeObserverDecimal(raw, label)
	if err == nil && !present {
		err = fmt.Errorf("observer input %s: missing string", label)
	}
	return value, err
}

type stateRawField struct {
	name     string
	raw      json.RawMessage
	required bool
}

// stateRawFieldsChecked names the first payload field whose presence differs from its requirement.
func stateRawFieldsChecked(label string, fields []stateRawField) error {
	for _, field := range fields {
		if (len(field.raw) != 0) != field.required {
			return fmt.Errorf("observer input %s%s: missing or forbidden payload", label, field.name)
		}
	}
	return nil
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
	fields := []stateRawField{
		{"member", c.Member, member},
		{"preserve_other_fields", c.PreserveOtherFields, preserve},
		{"locator_da_id", c.LocatorDAID, locator},
		{"target_revision", c.TargetRevision, revision},
		{"global_record_revision", c.GlobalRecordRevision, revision},
		{"intrinsic_total_bytes_delta", c.IntrinsicTotalBytesDelta, delta},
	}
	if err := stateRawFieldsChecked("control.", fields); err != nil {
		return c, err
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
	for _, field := range fields[2:] {
		if len(field.raw) == 0 {
			continue
		}
		label := "control." + field.name
		text, e := decodeDANodeObserverStateString(field.raw, label)
		if e != nil {
			return c, e
		}
		switch field.name {
		case "locator_da_id":
			c.locator, err = daNodeObserverStateHex32(label, text)
		case "intrinsic_total_bytes_delta":
			c.delta, err = stateDANodeObserverUint(label, text)
			if err == nil && c.delta == 0 {
				err = fmt.Errorf("observer input %s: must be positive", label)
			}
		default:
			if text != "global_record_revision + 1" {
				err = fmt.Errorf("observer input %s: unsupported expression", label)
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
	ref, known := map[string]string{"COMPLETE_COMMIT_PRECONDITION": "COMPLETE_COMMIT_7_SETS", "PEER_CLEANUP_STEP_PRECONDITION": "STATE_B_MIXED"}[input.ExecutionBoundary]
	if !known {
		return input, fmt.Errorf("observer input %s: unknown execution_boundary", id)
	}
	if input.ConstructionRef != ref {
		return input, fmt.Errorf("observer input %s: construction_ref does not match its boundary", id)
	}
	complete := ref == "COMPLETE_COMMIT_7_SETS"
	wantFollowUp := "REPEAT_IDENTICAL_CLEANUP"
	fields := []stateRawField{
		{"accepted_sequence", input.AcceptedSequence, complete},
		{"control", input.Control, complete},
		{"member_provenance", input.MemberProvenance, !complete},
		{"cleanup_selector", input.CleanupSelector, !complete},
	}
	if err := stateRawFieldsChecked(id+" ", fields); err != nil {
		return input, err
	}
	if complete {
		sequenceText, err := decodeDANodeObserverStateString(input.AcceptedSequence, "accepted_sequence")
		sequence, parseErr := stateDANodeObserverUint("accepted_sequence", sequenceText)
		// The target is the 318th admission, so a lower value would rewind its first received sequence.
		if err != nil || parseErr != nil || sequence < 318 {
			return input, fmt.Errorf("observer input %s: invalid accepted_sequence", id)
		}
		control, err := validateDANodeObserverStateControl(input.Control)
		if err != nil {
			return input, fmt.Errorf("observer input %s: control: %w", id, err)
		}
		labeled, ok := map[string]uint64{"ACCEPTED_SEQUENCE_MAX": ^uint64(0), "ACCEPTED_SEQUENCE_MAX_MINUS_ONE": ^uint64(0) - 1}[control.action]
		if ok != (sequence >= ^uint64(0)-1) || ok && labeled != sequence {
			return input, fmt.Errorf("observer input %s: accepted_sequence conflicts with control", id)
		}
		input.acceptedSequence, input.control = sequence, control
		wantFollowUp = "RESTORE_NAMED_CORRUPTION_THEN_FRESH_ADMISSION"
		switch control.phase + "/" + control.action {
		case "NONE/NONE", "NONE/EQUALITY_FEE_OVERRIDE", "NONE/ACCEPTED_SEQUENCE_MAX_MINUS_ONE", "NONE/ACCEPTED_SEQUENCE_MAX":
			wantFollowUp = "REPEAT_IDENTICAL_ADMISSION"
		case "PLANNED/ADVANCE_TARGET_AND_GLOBAL_REVISION":
			wantFollowUp = "FRESH_ADMISSION_WITH_CURRENT_TARGET"
		}
	} else {
		var selector daNodeObserverCleanupSelector
		err := decodeDANodeObserverInput(input.CleanupSelector, &selector)
		if err == nil {
			input.quotaIdentity, err = decodeDANodeObserverStateString(selector.QuotaIdentity, "cleanup_selector.quota_identity")
		}
		if err != nil {
			return input, fmt.Errorf("observer input %s: cleanup_selector: %w", id, err)
		}
		if input.provenance, err = parseDANodeObserverStateProvenance(input.MemberProvenance); err != nil {
			return input, fmt.Errorf("observer input %s: member_provenance: %w", id, err)
		}
	}
	if input.FollowUp != wantFollowUp {
		return input, fmt.Errorf("observer input %s: follow_up does not match execution_boundary and control", id)
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
		if strings.HasPrefix(row.ID, "CAP_") != (input.ExecutionBoundary == "COMPLETE_COMMIT_PRECONDITION") {
			return nil, fmt.Errorf("observer census: case %q in the wrong execution_boundary", row.ID)
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
	return emitDANodeObserverState(cases, profile, "")
}

// emitDANodeObserverState writes path, when set, only after every row was collected.
func emitDANodeObserverState(cases []daNodeObserverStateCase, profile daNodeObserverStateProfile, path string) ([]byte, error) {
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
	encoded = append(encoded, '\n')
	if path != "" {
		// A temporary sibling renamed over path never leaves a truncated or partial destination.
		tmp, err := os.CreateTemp(filepath.Dir(path), ".rubin-da-node-state-*")
		if err != nil {
			return nil, fmt.Errorf("observer output write: %w", err)
		}
		_, err = tmp.Write(encoded)
		if err = cmp.Or(err, tmp.Close()); err == nil {
			err = os.Rename(tmp.Name(), path)
		}
		if err != nil {
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("observer output write: %w", err)
		}
	}
	return encoded, nil
}

func TestDAAdmissionObserverNodeState(t *testing.T) {
	_, _, cases, profile := stateTestData(t)
	actual, err := emitDANodeObserverState(cases, profile, os.Getenv("RUBIN_DA_NODE_STATE_ACTUAL_OUT"))
	require(t, err == nil, "observer state: %v", err)
	var output daNodeObserverOutput
	err = json.Unmarshal(actual, &output)
	require(t, err == nil, "observer output: %v", err)
	require(t, output.FormatVersion == 1 && len(output.Cases) == len(daNodeObserverStateIDs), "observer census: output version=%d cases=%d", output.FormatVersion, len(output.Cases))
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
	cleanupAsCommit, commitAsCleanup := cases[0].Case, cases[12].Case
	cleanupAsCommit.Input, commitAsCleanup.Input = cases[12].Case.Input, cases[0].Case.Input
	for mode, probe := range []struct {
		mutate func([]json.RawMessage) []json.RawMessage
		want   string
	}{
		{func(c []json.RawMessage) []json.RawMessage { return c[:len(c)-1] }, "observer census: got 12 owned cases"},
		{func(c []json.RawMessage) []json.RawMessage { return append(c, owned[0]) }, "observer census: duplicate or out-of-order"},
		{func(c []json.RawMessage) []json.RawMessage { c[0], c[1] = c[1], c[0]; return c }, "observer census: duplicate or out-of-order"},
		{func(c []json.RawMessage) []json.RawMessage { c[0], _ = json.Marshal(unknownCommit); return c }, "observer census: unknown owned case"},
		{func(c []json.RawMessage) []json.RawMessage { c[12], _ = json.Marshal(unknownCleanup); return c }, "observer census: unknown owned case"},
		{func(c []json.RawMessage) []json.RawMessage { c[0], _ = json.Marshal(cleanupAsCommit); return c }, `case "CAP_ALL_MEMBERS_REMOVED" in the wrong execution_boundary`},
		{func(c []json.RawMessage) []json.RawMessage { c[12], _ = json.Marshal(commitAsCleanup); return c }, `case "STATE_B_PEER_COMMIT_CLEANUP_PROTECTED" in the wrong execution_boundary`},
	} {
		bad := corpus
		bad.Cases = probe.mutate(slices.Clone(owned))
		_, err := selectDANodeObserverStateCases(bad)
		require(t, err != nil && strings.Contains(err.Error(), probe.want), "observer state integrity census %d: %v", mode, err)
	}
	// The extra value conflicts with the row's own label: MAX on a NONE row, 318 on the MAX_MINUS_ONE row, an admission follow-up on a cleanup row.
	// An empty value deletes a field the row carries; every other value replaces or adds the field.
	for _, probe := range []struct {
		row   daNodeObserverStateCase
		extra string
	}{{cases[0], `"18446744073709551615"`}, {cases[9], `"318"`}, {cases[11], `"REPEAT_IDENTICAL_ADMISSION"`}} {
		for _, field := range []string{"execution_boundary", "construction_ref", "case_ordinal", "accepted_sequence", "control", "follow_up", "member_provenance", "cleanup_selector"} {
			for _, value := range []string{"", "null", `"UNKNOWN"`, `"-1"`, `"317"`, `"18446744073709551616"`, `{}`, `[{"source":"LOCAL"}]`, probe.extra} {
				var input map[string]json.RawMessage
				_ = json.Unmarshal(probe.row.Case.Input, &input)
				if _, carried := input[field]; value == "" && !carried {
					continue
				}
				input[field] = json.RawMessage(value)
				if value == "" {
					delete(input, field)
				}
				raw, _ := json.Marshal(input)
				_, err := validateDANodeObserverStateInput(probe.row.Case.ID, raw)
				require(t, err != nil && strings.Contains(err.Error(), "observer input") && strings.Contains(err.Error(), field), "observer state integrity %s %s=%s: %v", probe.row.Case.ID, field, value, err)
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
			require(t, err != nil && strings.Contains(err.Error(), "observer input control."+field+":"), "observer state integrity missing control.%s in %s: %v", field, row.Case.ID, err)
		}
	}
	for _, probe := range [][2]string{
		{`{"phase":"UNKNOWN","action":"NONE"}`, "control: unknown phase/action"},
		{`{"phase":"NONE","action":"UNKNOWN"}`, "control: unknown phase/action"},
		{`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":0,"resident_ordinal":0,"member_ordinal":1},"preserve_other_fields":false}`, "control.preserve_other_fields: must be true"},
		{`{"phase":"NONE","action":"NONE","member":null}`, "control.member: missing or forbidden"},
		{`{"phase":"NONE","action":"NONE","extra":1}`, `unknown field "extra"`},
		{`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":2,"resident_ordinal":2,"member_ordinal":1},"preserve_other_fields":true}`, "control.member: absent member"},
		{`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"resident_ordinal":0,"member_ordinal":1},"preserve_other_fields":true}`, "control.member: invalid selector"},
		{`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":0,"member_ordinal":1},"preserve_other_fields":true}`, "control.member: invalid selector"},
		{`{"phase":"PLANNED","action":"REMOVE_RESIDENT_CHUNK","member":{"class_ordinal":0,"resident_ordinal":0},"preserve_other_fields":true}`, "control.member: invalid selector"},
		{`{"phase":"PLANNED","action":"CORRUPT_RESIDENT_LOCATOR_DA_ID","member":{"class_ordinal":0,"resident_ordinal":0,"member_ordinal":1},"preserve_other_fields":true,"locator_da_id":"zz"}`, "locator_da_id: expected 32-byte hex"},
		{`{"phase":"PLANNED","action":"INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES","member":{"class_ordinal":0,"resident_ordinal":0,"member_ordinal":0},"preserve_other_fields":true,"intrinsic_total_bytes_delta":"18446744073709551616"}`, "intrinsic_total_bytes_delta: invalid decimal"},
		{`{"phase":"PLANNED","action":"INCREMENT_RESIDENT_INTRINSIC_TOTAL_BYTES","member":{"class_ordinal":0,"resident_ordinal":0,"member_ordinal":0},"preserve_other_fields":true,"intrinsic_total_bytes_delta":"0"}`, "control.intrinsic_total_bytes_delta: must be positive"},
		{`{"phase":"PLANNED","action":"ADVANCE_TARGET_AND_GLOBAL_REVISION","preserve_other_fields":true,"target_revision":"global_record_revision","global_record_revision":"global_record_revision + 1"}`, "control.target_revision: unsupported expression"},
		{`{"phase":"PLANNED","action":"ADVANCE_TARGET_AND_GLOBAL_REVISION","preserve_other_fields":true,"target_revision":"global_record_revision + 1","global_record_revision":"global_record_revision + 2"}`, "control.global_record_revision: unsupported expression"},
	} {
		_, err := validateDANodeObserverStateControl([]byte(probe[0]))
		require(t, err != nil && strings.Contains(err.Error(), "observer input") && strings.Contains(err.Error(), probe[1]), "observer state integrity accepted control %s: %v", probe[0], err)
	}
	for _, probe := range [][2]string{
		{`[{"source":"UNKNOWN"},{"source":"LOCAL"},{"source":"DETACHED_REORG"}]`, "member_provenance: unknown source"},
		{`[{"source":"PEER"},{"source":"LOCAL"},{"source":"DETACHED_REORG"}]`, "member_provenance.peer_identity: missing string"},
		{`[{"source":"LOCAL","peer_identity":"x"},{"source":"LOCAL"},{"source":"DETACHED_REORG"}]`, "member_provenance[0]: forbidden peer identities"},
	} {
		_, err := parseDANodeObserverStateProvenance([]byte(probe[0]))
		require(t, err != nil && strings.Contains(err.Error(), "observer input "+probe[1]), "observer state integrity accepted provenance %s: %v", probe[0], err)
	}
	for _, probe := range []struct {
		mutate func(*daNodeObserverStateProfile)
		want   string
	}{
		{func(p *daNodeObserverStateProfile) { p.Mixed.MemberTemplateRef = "UNKNOWN" }, "STATE_B_MIXED: unsupported cleanup profile"},
		{func(p *daNodeObserverStateProfile) { p.Mixed.ChunkCount = 65536 }, "STATE_B_MIXED: unsupported cleanup profile"},
		{func(p *daNodeObserverStateProfile) { p.Complete.Target.ChunkLengths = []uint64{^uint64(0)} }, "COMPLETE_COMMIT_7_SETS: invalid target"},
		{func(p *daNodeObserverStateProfile) { p.Canonical.Input.Value = "18446744073709551616" }, "CANONICAL_MEMBER: unsupported signed-member profile"},
		{func(p *daNodeObserverStateProfile) { p.Complete.EffectiveDAMempoolSize = "536870913" }, "COMPLETE_COMMIT_7_SETS: unsupported bounds"},
		{func(p *daNodeObserverStateProfile) { p.Complete.PinnedPayloadMax = "96000001" }, "COMPLETE_COMMIT_7_SETS: unsupported bounds"},
		{func(p *daNodeObserverStateProfile) { p.Complete.CompleteSetMaxCount = 65537 }, "COMPLETE_COMMIT_7_SETS: unsupported bounds"},
	} {
		bad := profile
		probe.mutate(&bad)
		err := validateDANodeObserverStateProfile(bad)
		require(t, err != nil && strings.Contains(err.Error(), "observer input "+probe.want), "observer state integrity accepted construction %s: %v", probe.want, err)
	}
	f, err := newDANodeObserverStateFixture(cases[0], profile)
	require(t, err == nil, "observer state: %v", err)
	defer f.Signer.Close()
	initial, err := observerImageOutsideHook(f, false)
	require(t, err == nil, "observer state: %v", err)
	tx, _, _, _, err := consensus.ParseTx(bytes.Clone(f.Candidate.Raw))
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
	// Each named restore returns the exact pre-control image once and then refuses: its target no longer carries the corruption.
	for _, row := range cases[1:9] {
		control, apply := row.Input.control, applyDANodeObserverStatePlannedControl
		if control.phase == "EFFECTS" {
			apply = applyDANodeObserverStateEffectsControl
		}
		if control.selected == nil {
			continue
		}
		restore, err := apply(f, control)
		require(t, err == nil && restore != nil, "observer state restore %s: no named restore: %v", row.Case.ID, err)
		err = restore()
		require(t, err == nil, "observer state restore %s: restore failed: %v", row.Case.ID, err)
		restored, err := observerImageOutsideHook(f, false)
		require(t, err == nil && reflect.DeepEqual(initial, restored), "observer state restore %s: restored image differs from the pre-control image: %v", row.Case.ID, err)
		err = restore()
		require(t, err != nil && strings.Contains(err.Error(), "no longer corrupted"), "observer state restore %s: repeated restore accepted: %v", row.Case.ID, err)
	}
	// A repeat that actually retains the candidate reports a changed image.
	follow, err := daNodeObserverStateAdmissionFollowUp(cases[0], f, daNodeObserverStateAdmission{After: initial})
	require(t, err == nil && follow["image_and_prior_claims_unchanged"] == false, "observer state follow-up: changed repeat image reported unchanged: %v %v", follow, err)
	// A per-peer entry added at EFFECTS survives Go's pre-mutation owner-ready check and publication.
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
	// A collection failure on the thirteenth row, after the census passed, leaves the destination directory untouched.
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.json")
	require(t, os.WriteFile(existing, []byte("prior\n"), 0o600) == nil, "observer output: seed write failed")
	broken := slices.Clone(cases)
	broken[12].Input.provenance = broken[12].Input.provenance[:2]
	_, err = emitDANodeObserverState(broken, profile, existing)
	require(t, err != nil && strings.Contains(err.Error(), "invalid member sequence"), "observer state last row: collection failure not observed: %v", err)
	kept, err := os.ReadFile(existing)
	entries, dirErr := os.ReadDir(dir)
	require(t, err == nil && dirErr == nil && string(kept) == "prior\n" && len(entries) == 1, "observer state output: failed last-row collection wrote output: %q %d %v", kept, len(entries), dirErr)
}

func TestDAAdmissionObserverNodeStateProjection(t *testing.T) {
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
	_, err := daNodeObserverStateResult(DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionRetained}}, 0, false)
	require(t, err != nil, "observer state projection: retained result without publication accepted")
	_, err = daNodeObserverStateResult(DAObserverAdmitCall{Err: errors.New("unknown")}, 0, false)
	require(t, err != nil, "observer state projection: unknown error accepted")
	// Synthetic admission rows: within each row every projected source value is nonzero and distinct from
	// the other values of its JSON type, except where the projector couples them (see closure-table).
	owner := &PendingOutpointOwner{}
	ownerAt := func(reserve, acquired, finalized, released, highWater uint64) daNodeObserverStateOwnerImage {
		return daNodeObserverStateOwnerImage{
			Identity:       owner,
			Counts:         DAObserverOwnerCounts{reserve, acquired, finalized, released},
			TokenHighWater: highWater,
			Generation:     6,
		}
	}
	zero := ownerAt(100, 100, 100, 100, 1000)
	commit := daNodeObserverStateMember{
		DAID:       [32]byte{9},
		TxID:       [32]byte{1},
		Raw:        []byte{1},
		Provenance: LocalDAProvenance(),
	}
	chunk := daNodeObserverStateMember{
		Key:        daNodeObserverStateMemberKey{MemberOrdinal: 1},
		DAID:       [32]byte{9},
		TxID:       [32]byte{2},
		Raw:        []byte{2, 3},
		Inputs:     []consensus.Outpoint{{Txid: [32]byte{42}, Vout: 7}},
		Provenance: DAProvenance{kind: daProvenancePeer, peerIdentity: "p", quotaIdentity: "q"},
	}
	small := &daNodeObserverStateFixture{TargetCommit: commit, Candidate: chunk}
	cm := &DAObserverMember{
		TxID:       commit.TxID,
		TokenSeq:   1,
		Provenance: DAObserverProvenance{Kind: "LOCAL"},
	}
	ch := &DAObserverMember{
		TxID:       chunk.TxID,
		TokenSeq:   3000,
		Inputs:     slices.Clone(chunk.Inputs),
		Provenance: DAObserverProvenance{Kind: "PEER", PeerIdentity: "p", QuotaIdentity: "q"},
	}
	survivor := DAObserverClaim{
		TxID:       [32]byte{5},
		TokenSeq:   5,
		Domain:     "DA",
		Finalized:  true,
		Generation: 6,
	}
	// build derives every counter from received; each victim leaves one record, two claims and one
	// locator, and the first victim one extra locator.
	build := func(received uint64, candidate []byte, victims ...byte) DAObserverStateImage {
		image := DAObserverStateImage{
			StagedBytes:        received - 4,
			CompleteBytes:      received - 3,
			PinnedPayloadBytes: received - 2,
			NextReceivedTime:   received - 1,
			CompleteCount:      received - 12,
			Locators:           []DAObserverLocator{{TxID: commit.TxID, DAID: commit.DAID, Kind: "COMMIT"}},
			Claims: []DAObserverClaim{
				{TxID: commit.TxID, TokenSeq: 1, Domain: "DA", Finalized: true, Generation: 6},
				survivor,
			},
		}
		for _, id := range victims {
			member := [32]byte{id, 1}
			image.Records = append(image.Records, DAObserverRecord{
				DAID:   [32]byte{id},
				Commit: DAObserverCommit{Member: &DAObserverMember{TxID: member}},
			})
			image.Locators = append(image.Locators, DAObserverLocator{TxID: member, DAID: [32]byte{id}})
			image.Claims = append(image.Claims, DAObserverClaim{TxID: member, TokenSeq: uint64(id)})
			image.Claims = append(image.Claims, DAObserverClaim{TxID: member, TokenSeq: uint64(id) + 100})
		}
		if len(victims) != 0 {
			image.Locators = append(image.Locators, DAObserverLocator{TxID: [32]byte{victims[0], 1}, DAID: [32]byte{victims[0]}})
		}
		target := DAObserverRecord{
			DAID:         commit.DAID,
			ReceivedTime: received,
			Commit:       DAObserverCommit{Member: cm, TxBytes: []byte{1}},
		}
		if candidate != nil {
			target.Chunks = []DAObserverChunk{{Member: ch, TxBytes: candidate}}
			image.Locators = append(image.Locators, DAObserverLocator{TxID: chunk.TxID, DAID: chunk.DAID, Kind: "CHUNK"})
			image.Claims = append(image.Claims, DAObserverClaim{
				TxID:       chunk.TxID,
				TokenSeq:   3000,
				Domain:     "DA",
				Inputs:     slices.Clone(chunk.Inputs),
				Finalized:  true,
				Generation: 6,
			})
			image.OutpointRows = []DAObserverOutpointRow{{Outpoint: chunk.Inputs[0], TokenSeq: 3000, TxID: chunk.TxID}}
		}
		image.Records = append(image.Records, target)
		return image
	}
	// survivorChanged flips the survivor claim; mismatched changes the retained target commit bytes.
	survivorChanged := func(image DAObserverStateImage) DAObserverStateImage {
		image.Claims[1].Finalized = false
		return image
	}
	mismatched := func(image DAObserverStateImage) DAObserverStateImage {
		image.Records[len(image.Records)-1].Commit.TxBytes = []byte{7}
		return image
	}
	admission := func(invocations uint64, err error, before, after DAObserverStateImage, owned daNodeObserverStateOwnerImage, plan ...byte) daNodeObserverStateAdmission {
		run := daNodeObserverStateAdmission{
			Invocations: invocations,
			Call:        DAObserverAdmitCall{Err: err},
			Before:      daNodeObserverStateObservation{Image: before, Owner: zero},
			After:       daNodeObserverStateObservation{Image: after, Owner: owned},
		}
		if err == nil {
			run.Call.Result.Disposition = DAAdmissionRetained
		}
		for _, id := range plan {
			run.PlanOrder = append(run.PlanOrder, [32]byte{id})
		}
		return run
	}
	internal := errDARelayImageIncompatible
	published := ownerAt(105, 106, 107, 100, 1016)
	refused := ownerAt(105, 106, 107, 110, 1016)
	fresh := admission(15, nil, build(26, nil, 0x41, 0x42), build(26, []byte{2, 3}), ownerAt(110, 111, 112, 100, 1011), 0x42, 0x41)
	repeated := ownerAt(111, 112, 113, 114, 1028)
	same := admission(15, internal, build(28, []byte{2, 3}), build(28, []byte{2, 3}), repeated)
	differs := admission(15, internal, build(28, []byte{2, 3}), survivorChanged(build(28, []byte{2, 3})), repeated)
	const (
		commitResult = `{
			"disposition": "COMMIT_WITH_VICTIMS",
			"semantic_reason_id": "NONE"
		}`
		internalResult = `{
			"disposition": "REJECT_UNCHANGED",
			"semantic_reason_id": "INTERNAL"
		}`
		counters21 = `{
			"staged_retained_bytes": "17",
			"complete_retained_bytes": "18",
			"complete_set_count": 9,
			"complete_payload_bytes": "19",
			"accepted_sequence": "20"
		}`
		repeatOwner = `{
			"admission_entrypoint": {
				"domain": "DA",
				"invocations": 15
			},
			"pending_outpoint": {
				"reserve_calls": 11,
				"reservations_acquired": 12,
				"finalizations": 13,
				"exact_releases": 14
			},
			"token_high_water_delta": "28",
			"exact_release_scope": "CANDIDATE_ONLY"
		}`
	)
	primaryOwner := func(releases int, scope string) string {
		return fmt.Sprintf(`{
			"admission_entrypoint": {
				"domain": "DA",
				"invocations": 8
			},
			"pending_outpoint": {
				"reserve_calls": 5,
				"reservations_acquired": 6,
				"finalizations": 7,
				"exact_releases": %d
			},
			"token_high_water_delta": "16",
			"exact_release_scope": %q
		}`, releases, scope)
	}
	repeatFollowUp := func(unchanged bool) string {
		return fmt.Sprintf(`{
			"result": %s,
			"owner": %s,
			"image_and_prior_claims_unchanged": %t,
			"accepted_sequence": "27"
		}`, internalResult, repeatOwner, unchanged)
	}
	noRemoval := `{
		"record_count": 0,
		"member_locator_count": 0,
		"claim_count": 0
	}`
	for _, input := range []struct {
		name           string
		primary, retry daNodeObserverStateAdmission
		followUp, want string
	}{{
		// Publish with two committed victims out of plan order and one merely planned victim; fresh retry.
		"publish, candidate mismatch", admission(8, nil, build(21, nil, 0x31, 0x32), build(21, []byte{2, 4}), published, 0x32, 0x31, 0x33),
		fresh, "RESTORE_NAMED_CORRUPTION_THEN_FRESH_ADMISSION", `{
		"result": ` + commitResult + `,
		"victims": [
			"3200000000000000000000000000000000000000000000000000000000000000",
			"3100000000000000000000000000000000000000000000000000000000000000"
		],
		"owner": ` + primaryOwner(0, "NONE") + `,
		"state_image": {
			"candidate_published": true,
			"retained_counters": ` + counters21 + `,
			"target_first_received_sequence": "21",
			"removed": {
				"record_count": 2,
				"member_locator_count": 3,
				"claim_count": 4
			},
			"surviving_members_and_claims_unchanged": true,
			"candidate_members_match_construction": false
		},
		"follow_up": {
			"result": ` + commitResult + `,
			"owner": {
				"admission_entrypoint": {
					"domain": "DA",
					"invocations": 15
				},
				"pending_outpoint": {
					"reserve_calls": 10,
					"reservations_acquired": 11,
					"finalizations": 12,
					"exact_releases": 0
				},
				"token_high_water_delta": "11",
				"exact_release_scope": "NONE"
			},
			"retained_counters": {
				"staged_retained_bytes": "22",
				"complete_retained_bytes": "23",
				"complete_set_count": 14,
				"complete_payload_bytes": "24",
				"accepted_sequence": "25"
			},
			"victims": [
				"4200000000000000000000000000000000000000000000000000000000000000",
				"4100000000000000000000000000000000000000000000000000000000000000"
			],
			"target_first_received_sequence": "26"
		}
	}`}, {
		"publish, survivor changed", admission(8, nil, build(21, nil, 0x31, 0x32), survivorChanged(build(21, []byte{2, 3})), published, 0x32, 0x31, 0x33),
		same, "REPEAT_IDENTICAL_ADMISSION", `{
		"result": ` + commitResult + `,
		"victims": [
			"3200000000000000000000000000000000000000000000000000000000000000",
			"3100000000000000000000000000000000000000000000000000000000000000"
		],
		"owner": ` + primaryOwner(0, "NONE") + `,
		"state_image": {
			"candidate_published": true,
			"retained_counters": ` + counters21 + `,
			"target_first_received_sequence": "21",
			"removed": {
				"record_count": 2,
				"member_locator_count": 3,
				"claim_count": 4
			},
			"surviving_members_and_claims_unchanged": false,
			"candidate_members_match_construction": true
		},
		"follow_up": ` + repeatFollowUp(true) + `
	}`}, {
		// A refusal with an actual candidate release; the image is unchanged but the target commit mismatches.
		"refusal, image unchanged", admission(8, internal, mismatched(build(21, nil)), mismatched(build(21, nil)), refused),
		differs, "REPEAT_IDENTICAL_ADMISSION", `{
		"result": ` + internalResult + `,
		"victims": [],
		"owner": ` + primaryOwner(10, "CANDIDATE_ONLY") + `,
		"state_image": {
			"candidate_published": false,
			"retained_counters": ` + counters21 + `,
			"target_first_received_sequence": "21",
			"removed": ` + noRemoval + `,
			"surviving_members_and_claims_unchanged": false,
			"image_and_prior_claims_unchanged_from_control_baseline": true
		},
		"follow_up": ` + repeatFollowUp(false) + `
	}`}, {
		"refusal, candidate present", admission(8, internal, mismatched(build(21, nil)), mismatched(build(21, []byte{2, 4})), refused),
		differs, "REPEAT_IDENTICAL_ADMISSION", `{
		"result": ` + internalResult + `,
		"victims": [],
		"owner": ` + primaryOwner(10, "CANDIDATE_ONLY") + `,
		"state_image": {
			"candidate_published": true,
			"retained_counters": ` + counters21 + `,
			"target_first_received_sequence": "21",
			"removed": ` + noRemoval + `,
			"surviving_members_and_claims_unchanged": false,
			"candidate_members_match_construction": false
		},
		"follow_up": ` + repeatFollowUp(false) + `
	}`}, {
		"refusal, image changed", admission(8, internal, mismatched(build(21, nil)), survivorChanged(mismatched(build(21, nil))), refused),
		same, "REPEAT_IDENTICAL_ADMISSION", `{
		"result": ` + internalResult + `,
		"victims": [],
		"owner": ` + primaryOwner(10, "CANDIDATE_ONLY") + `,
		"state_image": {
			"candidate_published": false,
			"retained_counters": ` + counters21 + `,
			"target_first_received_sequence": "21",
			"removed": ` + noRemoval + `,
			"surviving_members_and_claims_unchanged": false,
			"image_and_prior_claims_unchanged_from_control_baseline": false
		},
		"follow_up": ` + repeatFollowUp(true) + `
	}`}} {
		t.Run(input.name, func(t *testing.T) {
			row, _, err := daNodeObserverStateAdmissionImageOutput(small, input.primary)
			require(t, err == nil, "observer state projection: %v", err)
			row["follow_up"], err = stateAdmissionFollowUpOutput(small, input.followUp, input.retry, input.primary.After.Owner.TokenHighWater)
			require(t, err == nil, "observer state projection: %v", err)
			stateAssertJSON(t, row, input.want)
		})
	}
	// Synthetic cleanup rows: LOCAL commit, PEER and DETACHED_REORG chunk survivors; members 7 and 5 are removed.
	peer := DAObserverProvenance{Kind: "PEER", PeerIdentity: "peer-1", QuotaIdentity: "quota-1"}
	chunkRow := func(txid byte, provenance DAObserverProvenance, index uint16, tx, payload int) DAObserverChunk {
		return DAObserverChunk{
			Member:     &DAObserverMember{TxID: [32]byte{txid}, Provenance: provenance},
			ChunkIndex: index,
			TxBytes:    make([]byte, tx),
			Payload:    make([]byte, payload),
		}
	}
	cleanupImage := func(removed, final bool) DAObserverStateImage {
		image := DAObserverStateImage{
			StagedBytes:               100,
			CompleteBytes:             101,
			CompleteCount:             12,
			PinnedPayloadBytes:        102,
			NextReceivedTime:          103,
			Claims:                    []DAObserverClaim{{TxID: [32]byte{0x61}, TokenSeq: 61, Finalized: final}},
			OrphanBytesByPeerQuotaKey: []DAObserverKeyBytes{{Key: "quota-z", Bytes: 108}, {Key: "quota-a", Bytes: 109}},
		}
		record := DAObserverRecord{
			DAID:         [32]byte{0x70},
			State:        "STAGED_COMMIT",
			ReceivedTime: 104,
			Commit: DAObserverCommit{
				Member:     &DAObserverMember{TxID: [32]byte{0x60}, Provenance: DAObserverProvenance{Kind: "LOCAL"}},
				ChunkCount: 11,
				TxBytes:    make([]byte, 13),
			},
			Chunks: []DAObserverChunk{chunkRow(0x61, peer, 9, 14, 15)},
		}
		if removed {
			record.Chunks = append(record.Chunks, chunkRow(0x67, peer, 1, 18, 19))
		}
		record.Chunks = append(record.Chunks, chunkRow(0x66, DAObserverProvenance{Kind: "DETACHED_REORG"}, 10, 16, 17))
		if removed {
			record.Chunks = append(record.Chunks, chunkRow(0x65, peer, 2, 20, 21))
			image.StagedBytes += 78
			image.Locators = []DAObserverLocator{{TxID: [32]byte{0x65}}, {TxID: [32]byte{0x67}}}
			image.Claims = append(image.Claims, DAObserverClaim{TxID: [32]byte{0x65}, TokenSeq: 65})
			image.Claims = append(image.Claims, DAObserverClaim{TxID: [32]byte{0x67}, TokenSeq: 67})
			image.Claims = append(image.Claims, DAObserverClaim{TxID: [32]byte{0x67}, TokenSeq: 68})
		}
		image.Records = []DAObserverRecord{record}
		return image
	}
	cleanupFixture := &daNodeObserverStateFixture{Members: map[daNodeObserverStateMemberKey]daNodeObserverStateMember{}}
	for ordinal, txid := range map[uint64]byte{0: 0x60, 1: 0x61, 5: 0x65, 6: 0x66, 7: 0x67} {
		key := daNodeObserverStateMemberKey{MemberOrdinal: ordinal}
		cleanupFixture.Members[key] = daNodeObserverStateMember{Key: key, DAID: [32]byte{0x70}, TxID: [32]byte{txid}}
	}
	observe := func(image DAObserverStateImage, highWater uint64) daNodeObserverStateObservation {
		return daNodeObserverStateObservation{Image: image, Owner: daNodeObserverStateOwnerImage{Identity: owner, TokenHighWater: highWater}}
	}
	protected := daNodeObserverStateCase{Case: daNodeObserverCase{ID: "STATE_B_PEER_COMMIT_CLEANUP_PROTECTED"}}
	cleanupRow := func(result, selected, released string, locators, claims int, survivors, identical, repeat bool) string {
		return fmt.Sprintf(`{
			"cleanup_result": %q,
			"selected_member_ordinals": %s,
			"released_charge": %q,
			"removed_locator_count": %d,
			"removed_claim_count": %d,
			"owner_high_water_delta": "105",
			"after_image": {
				"state": "STAGED_COMMIT",
				"da_id": "7000000000000000000000000000000000000000000000000000000000000000",
				"received_sequence": "104",
				"commit_chunk_count": 11,
				"members": [
					{
						"member_ordinal": 0,
						"role": "COMMIT",
						"provenance": {
							"source": "LOCAL"
						},
						"retained_tx_bytes": "13",
						"incomplete_member_charge": "13"
					},
					{
						"member_ordinal": 1,
						"role": "CHUNK",
						"provenance": {
							"source": "PEER",
							"peer_identity": "peer-1",
							"quota_identity": "quota-1"
						},
						"retained_tx_bytes": "14",
						"chunk_index": 9,
						"payload_bytes": "15",
						"incomplete_member_charge": "29"
					},
					{
						"member_ordinal": 6,
						"role": "CHUNK",
						"provenance": {
							"source": "DETACHED_REORG"
						},
						"retained_tx_bytes": "16",
						"chunk_index": 10,
						"payload_bytes": "17",
						"incomplete_member_charge": "33"
					}
				],
				"retained_counters": {
					"staged_retained_bytes": "100",
					"complete_retained_bytes": "101",
					"complete_set_count": 12,
					"complete_payload_bytes": "102",
					"accepted_sequence": "103"
				},
				"peer_quota_accounting": [
					{
						"quota_identity": "quota-z",
						"bytes": "108"
					},
					{
						"quota_identity": "quota-a",
						"bytes": "109"
					}
				]
			},
			"surviving_members_and_claims_unchanged": %t,
			"whole_record_removed": false,
			"image_byte_identical": %t,
			"follow_up": {
				"cleanup_result": "NO_SELECTION",
				"image_and_claims_unchanged": %t,
				"owner_high_water_delta": "107"
			}
		}`, result, selected, released, locators, claims, survivors, identical, repeat)
	}
	for _, input := range []struct {
		name  string
		steps [3]DAObserverStateImage
		want  string
	}{
		{"removed", [3]DAObserverStateImage{cleanupImage(true, true), cleanupImage(false, true), cleanupImage(false, false)},
			cleanupRow("REMOVED_PEER_CHUNKS", "[\n5,\n7\n]", "78", 2, 3, true, false, false)},
		{"survivor changed", [3]DAObserverStateImage{cleanupImage(false, false), cleanupImage(false, true), cleanupImage(false, true)},
			cleanupRow("NO_SELECTION", "[]", "0", 0, 0, false, false, true)},
		{"unchanged", [3]DAObserverStateImage{cleanupImage(false, true), cleanupImage(false, true), cleanupImage(false, true)},
			cleanupRow("NO_SELECTION", "[]", "0", 0, 0, true, true, true)},
	} {
		t.Run(input.name, func(t *testing.T) {
			second := observe(input.steps[1], 106)
			row, err := projectDANodeObserverStateCleanup(cleanupFixture, protected, observe(input.steps[0], 1), second)
			require(t, err == nil, "observer state cleanup: %v", err)
			row["follow_up"], err = stateCleanupFollowUp(cleanupFixture, protected, second, observe(input.steps[2], 213))
			require(t, err == nil, "observer state cleanup: %v", err)
			stateAssertJSON(t, row, input.want)
		})
	}
	// Refusals and removed-member rows that the synthetic rows above do not reach.
	removedBefore, kept := observe(cleanupImage(true, true), 1), observe(cleanupImage(false, true), 106)
	stale := kept
	stale.Image.OutpointRows = []DAObserverOutpointRow{{TxID: [32]byte{0x65}}}
	staleRow, err := projectDANodeObserverStateCleanup(cleanupFixture, protected, removedBefore, stale)
	require(t, err == nil && staleRow["surviving_members_and_claims_unchanged"] == false, "observer state cleanup: removed member outpoint row survived: %v", err)
	_, err = projectDANodeObserverStateCleanup(cleanupFixture, protected, removedBefore, observe(DAObserverStateImage{}, 106))
	require(t, err != nil, "observer state cleanup: absent record projected as zero values")
	extra := observe(cleanupImage(false, true), 106)
	extra.Image.Records[0].Chunks = append(extra.Image.Records[0].Chunks, DAObserverChunk{Member: &DAObserverMember{TxID: [32]byte{0x77}}})
	_, err = projectDANodeObserverStateCleanup(cleanupFixture, protected, removedBefore, extra)
	require(t, err != nil && strings.Contains(err.Error(), "no constructed input"), "observer state cleanup: unconstructed surviving member dropped: %v", err)
	skewed := kept
	skewed.Image.StagedBytes++
	_, err = projectDANodeObserverStateCleanup(cleanupFixture, protected, removedBefore, skewed)
	require(t, err != nil && strings.Contains(err.Error(), "staged-bytes delta"), "observer state cleanup: released charge not bound to Go accounting: %v", err)
	base, publishedImage := build(21, nil), build(21, []byte{2, 3})
	owned := publishedImage.OutpointRows[0]
	for _, rows := range [][]DAObserverOutpointRow{
		nil,
		{{Outpoint: owned.Outpoint, TxID: owned.TxID, TokenSeq: 3}},
		{{Outpoint: owned.Outpoint, TxID: [32]byte{99}, TokenSeq: 3000}},
		{{Outpoint: consensus.Outpoint{Vout: 99}, TxID: owned.TxID, TokenSeq: 3000}},
		{owned, owned},
		{owned, {Outpoint: consensus.Outpoint{Vout: 99}, TxID: [32]byte{99}, TokenSeq: 3000}},
	} {
		broken := build(21, []byte{2, 3})
		broken.OutpointRows = rows
		actual, _, err := daNodeObserverStateAdmissionImageOutput(small, admission(8, nil, base, broken, zero))
		require(t, err == nil && actual["state_image"].(map[string]any)["candidate_members_match_construction"] == false, "observer state candidate outpoint bindings: rows=%v error=%v", rows, err)
	}
	duplicated := build(21, []byte{2, 3})
	duplicated.Claims = append(duplicated.Claims, duplicated.Claims[len(duplicated.Claims)-1])
	require(t, daNodeObserverStateCandidateMatches(publishedImage, chunk, 6), "observer state candidate: constructed claim rejected")
	require(t, !daNodeObserverStateCandidateMatches(duplicated, chunk, 6), "observer state candidate claim multiplicity")
	require(t, !daNodeObserverStateCandidateMatches(publishedImage, chunk, 7), "observer state candidate claim generation")
	require(t, !daNodeObserverStateSurvivorsEqual(publishedImage, DAObserverStateImage{OutpointRows: publishedImage.OutpointRows}, [][32]byte{commit.DAID}, nil, [32]byte{}), "observer state completion: removed member outpoint row survived")
	retained := DAObserverAdmitCall{Result: DAAdmissionResult{Disposition: DAAdmissionRetained}}
	retryImage := func(survivors, candidate bool) map[string]any {
		return map[string]any{
			"surviving_members_and_claims_unchanged": survivors,
			"candidate_members_match_construction":   candidate,
		}
	}
	require(t, stateRetryImageChecked(retained, retryImage(true, true)) == nil, "observer state follow-up: retained retry rejected")
	require(t, stateRetryImageChecked(retained, retryImage(true, false)) != nil, "observer state follow-up: retained retry candidate mismatch accepted")
	require(t, stateRetryImageChecked(retained, retryImage(false, true)) != nil, "observer state follow-up: retained retry survivor change accepted")
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
	repeat := cases[5]
	repeat.Input.FollowUp = "REPEAT_IDENTICAL_ADMISSION"
	lagging := final
	lagging.Owner.TokenHighWater--
	_, err = daNodeObserverStateAdmissionFollowUp(repeat, f, daNodeObserverStateAdmission{After: lagging})
	require(t, err != nil && strings.Contains(err.Error(), "high-water continuity"), "observer state follow-up high-water continuity: repeat row skipped the owner check: %v", err)
}

//go:build rubin_da_observer

package node

import (
	"bytes"
	"cmp"
	"errors"
	"maps"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// This file is the conformance-collector read surface. It is compiled only
// under the rubin_da_observer build tag and never into a default build.

// DAObserverOwnerCounts is one read of the pending-outpoint owner operation counts.
type DAObserverOwnerCounts struct {
	ReserveCalls, ReservationsAcquired, Finalizations, CandidateReleases uint64
}

// DAObserverReadOwnerCounts reads the counts under one owner-mutex hold. A nil
// owner returns zero counts.
func DAObserverReadOwnerCounts(o *PendingOutpointOwner) DAObserverOwnerCounts {
	if o == nil {
		return DAObserverOwnerCounts{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return DAObserverOwnerCounts{o.reserveCalls, o.reservationsAcquired, o.finalizations, o.candidateReleases}
}

// DAObserverProvenance is a DAProvenance copy: Kind is PEER, LOCAL,
// DETACHED_REORG or INVALID, and the identities are copied verbatim.
type DAObserverProvenance struct {
	Kind, PeerIdentity, QuotaIdentity string
}

var daObserverProvenanceKinds = map[daProvenanceKind]string{daProvenancePeer: "PEER", daProvenanceLocal: "LOCAL", daProvenanceDetachedReorg: "DETACHED_REORG"}

func daObserverProvenance(p DAProvenance) DAObserverProvenance {
	return DAObserverProvenance{Kind: cmp.Or(daObserverProvenanceKinds[p.kind], "INVALID"), PeerIdentity: p.peerIdentity, QuotaIdentity: p.quotaIdentity}
}

// DAObserverAdmitCall is one AdmitDA invocation exactly as it returned.
type DAObserverAdmitCall struct {
	Provenance DAObserverProvenance
	Result     DAAdmissionResult
	Err        error
}

// DAObserverSetAdmitObserver installs fn as the AdmitDA observer of s; a nil fn
// uninstalls it and a nil s is a no-op. fn runs once per AdmitDA call after the
// outcome is final, with no DA relay or owner mutex held, and must not call
// AdmitDA. A panicking AdmitDA call is not observed.
func DAObserverSetAdmitObserver(s *DARelayState, fn func(DAObserverAdmitCall)) {
	if s == nil {
		return
	}
	if fn == nil {
		s.admitObserver.Store(nil)
		return
	}
	observe := func(call daAdmitCall) {
		fn(DAObserverAdmitCall{Provenance: daObserverProvenance(call.provenance), Result: call.result, Err: call.err})
	}
	s.admitObserver.Store(&observe)
}

// DAObserverRelayDisposition returns the relay disposition err carries.
func DAObserverRelayDisposition(err error) RelayAdmissionDisposition {
	return relayDispositionOf(err)
}

// DAObserverCompleteSetMaxCount returns the COMPLETE_SET count bound.
func DAObserverCompleteSetMaxCount() uint64 { return daCompleteSetMaxCount }

// DAObserverStateImage copies the D01-relevant DA relay and owner claim fields.
type DAObserverStateImage struct {
	Records      []DAObserverRecord
	Locators     []DAObserverLocator
	Claims       []DAObserverClaim
	OutpointRows []DAObserverOutpointRow

	NextReceivedTime, StagedBytes, CompleteBytes, CompleteCount, OrphanBytes uint64
	OrphanCommitOverheadBytes, PinnedPayloadBytes, RecordRevisionHighWater   uint64

	OrphanBytesByPeerQuotaKey []DAObserverKeyBytes
	OrphanBytesByDAID         []DAObserverIDBytes
}

// DAObserverRecord copies one retained DA set record.
type DAObserverRecord struct {
	DAID                                                                [32]byte
	State                                                               string
	Revision, ReceivedTime, PayloadBytes, WireBytes, TTLBlocksRemaining uint64
	CompleteIntrinsic                                                   DAObserverCapacitySet
	Commit                                                              DAObserverCommit
	Chunks                                                              []DAObserverChunk
	ReplaceableChunks                                                   []DAObserverReplaceable
}

// DAObserverCapacitySet copies a record's COMPLETE_SET capacity descriptor.
type DAObserverCapacitySet struct {
	ID                                         [32]byte
	Fee                                        consensus.Uint128
	TotalBytes, PayloadBytes, ReceivedSequence uint64
}

// DAObserverCommit copies a record's commit slot.
type DAObserverCommit struct {
	DAID, PayloadCommitment [32]byte
	PeerQuotaKey            string
	Member                  *DAObserverMember
	ChunkCount              uint16
	WireBytes               uint64
	TxBytes                 []byte
}

// DAObserverChunk copies one retained chunk.
type DAObserverChunk struct {
	DAID, ChunkHash [32]byte
	PeerQuotaKey    string
	Member          *DAObserverMember
	ChunkIndex      uint16
	Payload         []byte
	WireBytes       uint64
	TxBytes         []byte
	HashChecked     bool
}

// DAObserverMember copies one retained member identity.
type DAObserverMember struct {
	TxID, WTxID [32]byte
	Fee         consensus.Uint128
	Inputs      []consensus.Outpoint
	TokenSeq    uint64
	Provenance  DAObserverProvenance
}

// DAObserverLocator copies one txid locator row.
type DAObserverLocator struct {
	TxID, DAID [32]byte
	Kind       string
	ChunkIndex uint16
}

// DAObserverClaim copies one live pending-outpoint claim.
type DAObserverClaim struct {
	TokenSeq   uint64
	Domain     string
	TxID       [32]byte
	Inputs     []consensus.Outpoint
	Finalized  bool
	Generation uint64
}

// DAObserverOutpointRow copies one by-outpoint owner row.
type DAObserverOutpointRow struct {
	Outpoint consensus.Outpoint
	TokenSeq uint64
	TxID     [32]byte
}

// DAObserverKeyBytes is one per-peer-quota-key orphan charge.
type DAObserverKeyBytes struct {
	Key   string
	Bytes uint64
}

// DAObserverIDBytes is one per-da_id orphan charge.
type DAObserverIDBytes struct {
	DAID  [32]byte
	Bytes uint64
}

// DAObserverReplaceable is one replaceable-chunk flag.
type DAObserverReplaceable struct {
	Index uint16
	Value bool
}

// DAObserverReadStateImage holds the admission fence across one s.mu hold and
// one owner-mutex hold nested inside it. A nil relay,
// mempool or owner, or nil sets or locators, returns an error and a zero image.
func DAObserverReadStateImage(s *DARelayState) (DAObserverStateImage, error) {
	if s == nil {
		return DAObserverStateImage{}, errors.New("nil DA relay")
	}
	release, err := s.lockAdmissionFence()
	if err != nil {
		return DAObserverStateImage{}, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mempool == nil || s.mempool.pendingOutpoints == nil || s.sets == nil || s.locators == nil {
		return DAObserverStateImage{}, errors.New("DA relay state unavailable")
	}
	o := s.mempool.pendingOutpoints
	o.mu.Lock()
	defer o.mu.Unlock()
	image := s.daObserverRelayImageLocked()
	image.Claims, image.OutpointRows = o.daObserverClaimsLocked()
	return image, nil
}

// daObserverRelayImageLocked copies the DA relay half; the caller holds s.mu.
// Map keys fix a deterministic pre-order and the stable sort then orders by
// the copied field.
func (s *DARelayState) daObserverRelayImageLocked() DAObserverStateImage {
	image := DAObserverStateImage{
		NextReceivedTime: s.nextReceivedTime, StagedBytes: s.stagedBytes, CompleteBytes: s.completeBytes,
		CompleteCount: s.completeCount, OrphanBytes: s.orphanBytes, OrphanCommitOverheadBytes: s.orphanCommitOverheadBytes,
		PinnedPayloadBytes: s.pinnedPayloadBytes, RecordRevisionHighWater: s.records,
	}
	for _, id := range slices.SortedFunc(maps.Keys(s.sets), compareDAObserverID) {
		image.Records = append(image.Records, daObserverRecord(s.sets[id]))
	}
	slices.SortStableFunc(image.Records, func(a, b DAObserverRecord) int { return compareDAObserverID(a.DAID, b.DAID) })
	for _, txid := range slices.SortedFunc(maps.Keys(s.locators), compareDAObserverID) {
		l := s.locators[txid]
		image.Locators = append(image.Locators, DAObserverLocator{TxID: txid, DAID: l.daID, Kind: cmp.Or(daObserverLocatorKinds[l.kind], "INVALID"), ChunkIndex: l.chunkIndex})
	}
	for _, key := range slices.Sorted(maps.Keys(s.orphanBytesByPeerQuotaKey)) {
		image.OrphanBytesByPeerQuotaKey = append(image.OrphanBytesByPeerQuotaKey, DAObserverKeyBytes{Key: key, Bytes: s.orphanBytesByPeerQuotaKey[key]})
	}
	for _, id := range slices.SortedFunc(maps.Keys(s.orphanBytesByDAID), compareDAObserverID) {
		image.OrphanBytesByDAID = append(image.OrphanBytesByDAID, DAObserverIDBytes{DAID: id, Bytes: s.orphanBytesByDAID[id]})
	}
	return image
}

// daObserverClaimsLocked copies the owner half; the caller holds o.mu.
func (o *PendingOutpointOwner) daObserverClaimsLocked() ([]DAObserverClaim, []DAObserverOutpointRow) {
	var claims []DAObserverClaim
	for _, token := range slices.SortedFunc(maps.Keys(o.byToken), func(a, b PendingOutpointToken) int { return cmp.Compare(a.seq, b.seq) }) {
		c := o.byToken[token]
		claims = append(claims, DAObserverClaim{TokenSeq: c.token.seq, Domain: cmp.Or(daObserverDomains[c.domain], "INVALID"), TxID: c.txid, Inputs: slices.Clone(c.inputs), Finalized: c.finalized, Generation: c.generation})
	}
	slices.SortStableFunc(claims, func(a, b DAObserverClaim) int { return cmp.Compare(a.TokenSeq, b.TokenSeq) })
	var rows []DAObserverOutpointRow
	for _, op := range slices.SortedFunc(maps.Keys(o.byOutpoint), compareDAObserverOutpoint) {
		row := o.byOutpoint[op]
		rows = append(rows, DAObserverOutpointRow{Outpoint: op, TokenSeq: row.token.seq, TxID: row.txid})
	}
	return claims, rows
}

var (
	daObserverLocatorKinds = map[daRelayLocatorKind]string{daRelayLocatorCommit: "COMMIT", daRelayLocatorChunk: "CHUNK"}
	daObserverDomains      = map[PendingOutpointDomain]string{PendingOutpointStandardMempool: "STANDARD", PendingOutpointDA: "DA"}
	daObserverStates       = map[daRelaySetState]string{daRelayStateOrphanChunks: "ORPHAN_CHUNKS", daRelayStateStagedCommit: "STAGED_COMMIT", daRelayStateCompleteSet: "COMPLETE_SET"}
)

func compareDAObserverID(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) }

func compareDAObserverOutpoint(a, b consensus.Outpoint) int {
	return cmp.Or(compareDAObserverID(a.Txid, b.Txid), cmp.Compare(a.Vout, b.Vout))
}

func daObserverRecord(r daRelaySetRecord) DAObserverRecord {
	c := r.completeIntrinsic
	out := DAObserverRecord{
		DAID: r.daID, State: cmp.Or(daObserverStates[r.state], "INVALID"),
		Revision: r.revision, ReceivedTime: r.receivedTime, PayloadBytes: r.payloadBytes, WireBytes: r.wireBytes, TTLBlocksRemaining: r.ttlBlocksRemaining,
		CompleteIntrinsic: DAObserverCapacitySet{ID: c.id, Fee: c.fee, TotalBytes: c.totalBytes, PayloadBytes: c.payloadBytes, ReceivedSequence: c.receivedSequence},
		Commit: DAObserverCommit{
			DAID: r.commit.daID, PayloadCommitment: r.commit.payloadCommitment, PeerQuotaKey: r.commit.peerQuotaKey, Member: daObserverMember(r.commit.member),
			ChunkCount: r.commit.chunkCount, WireBytes: r.commit.wireBytes, TxBytes: bytes.Clone(r.commit.txBytes),
		},
	}
	for _, index := range slices.Sorted(maps.Keys(r.chunks)) {
		ch := r.chunks[index]
		out.Chunks = append(out.Chunks, DAObserverChunk{
			DAID: ch.daID, ChunkHash: ch.chunkHash, PeerQuotaKey: ch.peerQuotaKey, Member: daObserverMember(ch.member), ChunkIndex: ch.chunkIndex,
			Payload: bytes.Clone(ch.payload), WireBytes: ch.wireBytes, TxBytes: bytes.Clone(ch.txBytes), HashChecked: ch.hashChecked,
		})
	}
	slices.SortStableFunc(out.Chunks, func(a, b DAObserverChunk) int { return cmp.Compare(a.ChunkIndex, b.ChunkIndex) })
	for _, index := range slices.Sorted(maps.Keys(r.replaceableChunks)) {
		out.ReplaceableChunks = append(out.ReplaceableChunks, DAObserverReplaceable{Index: index, Value: r.replaceableChunks[index]})
	}
	return out
}

func daObserverMember(m *daRelayMemberIdentity) *DAObserverMember {
	if m == nil {
		return nil
	}
	return &DAObserverMember{TxID: m.txid, WTxID: m.wtxid, Fee: m.fee, Inputs: slices.Clone(m.inputs), TokenSeq: m.token.seq, Provenance: daObserverProvenance(m.provenance)}
}

// DAObserverRetainedFault names one structural-only retained-state fault.
type DAObserverRetainedFault uint8

const (
	// DAObserverFaultOwnerUnavailable sets the sets and locators maps to nil.
	DAObserverFaultOwnerUnavailable DAObserverRetainedFault = iota + 1
	// DAObserverFaultLocatorDangling deletes the located record and keeps its locator.
	DAObserverFaultLocatorDangling
	// DAObserverFaultRetainedRawMalformed appends one byte to the member's retained raw bytes.
	DAObserverFaultRetainedRawMalformed
	// DAObserverFaultAdmissionWTxIDMismatch flips the low bit of byte 0 of the member's stored wtxid.
	DAObserverFaultAdmissionWTxIDMismatch
)

// DAObserverInjectRetainedFault installs fault for the retained member txid
// under one s.mu hold. A nil relay, an unlocated txid or an unknown fault
// returns an error and changes nothing; so does LocatorDangling when the located
// record is absent, and either member fault when the located member is absent.
func DAObserverInjectRetainedFault(s *DARelayState, txid [32]byte, fault DAObserverRetainedFault) error {
	if s == nil {
		return errors.New("nil DA relay")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	locator, located := s.locators[txid]
	if !located {
		return errors.New("txid is not located")
	}
	switch fault {
	case DAObserverFaultOwnerUnavailable:
		s.sets, s.locators = nil, nil
		return nil
	case DAObserverFaultLocatorDangling:
		if _, present := s.sets[locator.daID]; !present {
			return errors.New("located record is absent")
		}
		delete(s.sets, locator.daID)
		return nil
	case DAObserverFaultRetainedRawMalformed, DAObserverFaultAdmissionWTxIDMismatch:
		return s.injectDAObserverMemberFaultLocked(locator, fault == DAObserverFaultAdmissionWTxIDMismatch)
	}
	return errors.New("unknown retained fault")
}

// injectDAObserverMemberFaultLocked flips the located member's wtxid, or
// appends one byte to its retained raw bytes; the caller holds s.mu.
func (s *DARelayState) injectDAObserverMemberFaultLocked(locator daRelayLocator, wtxid bool) error {
	record, present := s.sets[locator.daID]
	member, raw := record.commit.member, &record.commit.txBytes
	chunk := record.chunks[locator.chunkIndex]
	if locator.kind == daRelayLocatorChunk {
		member, raw = chunk.member, &chunk.txBytes
	}
	if !present || member == nil {
		return errors.New("located member is absent")
	}
	if wtxid {
		member.wtxid[0] ^= 1
		return nil
	}
	*raw = append(slices.Clip(*raw), 0)
	if locator.kind == daRelayLocatorChunk {
		record.chunks[locator.chunkIndex] = chunk
	}
	s.sets[locator.daID] = record
	return nil
}

// DAObserverBeginOwnerTransition begins a pending-outpoint owner transition so
// the DA admission hold cannot be acquired; end aborts that transition. A nil
// owner, or a transition that cannot begin, returns an error and no end.
func DAObserverBeginOwnerTransition(o *PendingOutpointOwner) (end func(), err error) {
	if o == nil {
		return nil, errors.New("nil pending-outpoint owner")
	}
	if _, err = o.beginTransition(); err != nil {
		return nil, err
	}
	return o.endTransitionAborted, nil
}

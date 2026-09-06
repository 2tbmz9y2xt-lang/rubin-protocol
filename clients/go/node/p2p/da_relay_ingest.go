package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// IDENTITY_BOUNDS_V1: the process-local byte limits a remote DA candidate's
// captured peer identity and its derived quota identity satisfy before any
// provenance is built. They bound local memory per retained member only; they
// are not wire, DNS or retained-byte constants.
const (
	maxDAPeerIdentityBytes  = 263
	maxDAQuotaIdentityBytes = 255
)

// COMPETING_SCORE_V1: the connection-local peer-quality policy the remote DA
// path applies (the RUBIN_COMPACT_BLOCKS.md Section 14 score shape with local
// magnitudes). A connection starts at qualityScoreInitial; a fully validated
// distinct commit competing with the retained commit of the same da_id subtracts
// qualityCompetingCommitDelta, or qualityCompetingCommitGrace while the captured
// local tip height is below qualityGraceHeight, saturating at 0; the score drifts
// one point toward qualityScoreInitial per qualityNormalizeBlocks of local
// height, evaluated lazily; and the DA prefetch scheduler keeps the trigger
// peer's front-of-list preference only while the score is at least
// qualityPreferenceMinimum. This task reaches only [0, qualityScoreInitial].
const (
	qualityScoreInitial         uint8  = 50
	qualityPreferenceMinimum    uint8  = 40
	qualityCompetingCommitDelta uint8  = 2
	qualityCompetingCommitGrace uint8  = 1
	qualityNormalizeBlocks      uint64 = 144
	qualityGraceHeight          uint64 = 1440
)

// handleRelayDATx is the ONE production remote DA admission path: every remote
// tx_kind 0x01/0x02 transaction that passed the message bound and the full
// canonical parse arrives here before any standard-pool, seen-set, metadata or
// inventory effect, and invokes AdmitDA exactly once. Postconditions, in order:
//   - the peer identity is captured once from the peer state, which handleConn
//     already normalized, and the quota identity derived from that string; an
//     identity outside IDENTITY_BOUNDS_V1 returns nil with no effect at all;
//   - an engine already latched by a terminal transition returns nil before the
//     quota key is taken and before AdmitDA; a latch landing after that check
//     keeps the existing same-key teardown/Close limitation until restart, which
//     this path does not repair;
//   - the per-quota lock is held only around the one AdmitDA call and released
//     before any result effect, so the order stays quota key, then the admission
//     fence, DARelayState.mu and PendingOutpointOwner.mu inside AdmitDA, with
//     peer-state and peer-map locks never held across that chain;
//   - no candidate hash, signature, fee or chain check runs here before AdmitDA's
//     owner observation; errors.Is(err, node.ErrDARelayChunkHashMismatch) alone is
//     a peer fault, every other AdmitDA error is peer-neutral with no relay effect;
//   - RETAINED without a conflict flag schedules the bounded prefetch once with
//     the captured identity; DUPLICATE with SameDAIDCommitConflict applies
//     COMPETING_SCORE_V1 once to this peer; every other success shape, which
//     publicDAAdmissionResult cannot emit, returns nil with zero effect.
func (p *peer) handleRelayDATx(txBytes []byte) error {
	s := p.service
	peerIdentity, quotaIdentity, provenance, ok := p.remoteDAProvenance()
	if !ok {
		return nil
	}
	if s.cfg.SyncEngine.TerminalFaulted() {
		return nil
	}
	unlock := s.lockPeerQuotaKey(quotaIdentity)
	result, err := s.daRelay.AdmitDA(txBytes, provenance)
	unlock()
	if err != nil {
		return p.penalizeDAAdmissionError(err)
	}
	switch {
	case result.Disposition == node.DAAdmissionRetained && !result.SameDAIDCommitConflict:
		s.scheduleDAPrefetch(peerIdentity, result.DAID)
	case result.Disposition == node.DAAdmissionDuplicate && result.SameDAIDCommitConflict:
		p.applyCompetingCommitScore(s.cfg.SyncEngine.LocalTipHeight())
	}
	return nil
}

// remoteDAProvenance captures the peer identity once, derives the quota identity
// from that captured string without normalizing it again, and applies
// IDENTITY_BOUNDS_V1 before any provenance exists. ok is false for an empty or
// over-bound identity, which the caller answers with nil and no effect; the
// nonempty check also makes NewPeerDAProvenance's only refusal unreachable.
func (p *peer) remoteDAProvenance() (peerIdentity, quotaIdentity string, provenance node.DAProvenance, ok bool) {
	peerIdentity = p.addr()
	quotaIdentity = peerQuotaKey(peerIdentity)
	if peerIdentity == "" || len(peerIdentity) > maxDAPeerIdentityBytes || quotaIdentity == "" || len(quotaIdentity) > maxDAQuotaIdentityBytes {
		return "", "", node.DAProvenance{}, false
	}
	provenance, err := node.NewPeerDAProvenance(peerIdentity, quotaIdentity)
	return peerIdentity, quotaIdentity, provenance, err == nil
}

// penalizeDAAdmissionError maps the one peer-attributable AdmitDA error — a
// candidate chunk whose payload contradicts its own declared hash, selected by
// sentinel identity alone and never by error kind or text — to the existing +10
// ban step with the sentinel's text as LastError, returning the sentinel itself
// only when the ban threshold is reached. Every other error is peer-neutral.
func (p *peer) penalizeDAAdmissionError(err error) error {
	if errors.Is(err, node.ErrDARelayChunkHashMismatch) && p.bumpBan(10, node.ErrDARelayChunkHashMismatch.Error()) {
		return node.ErrDARelayChunkHashMismatch
	}
	return nil
}

// applyCompetingCommitScore is COMPETING_SCORE_V1's one event. The caller
// captured height after AdmitDA released its admission and owner locks and after
// the quota key was released; under stateMu the score first drifts for every
// interval that height completed and then loses the grace-adjusted delta with
// lower saturation. BanScore, LastError and the peer manager are untouched.
func (p *peer) applyCompetingCommitScore(height uint64) {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	p.normalizeQualityLocked(height)
	delta := qualityCompetingCommitDelta
	if height < qualityGraceHeight {
		delta = qualityCompetingCommitGrace
	}
	if p.qualityScore < delta {
		delta = p.qualityScore
	}
	p.qualityScore -= delta
}

// qualityPreferred drifts the score for height and reports whether this peer
// keeps its DA prefetch front-of-list preference; it never removes the peer
// from the eligible set or moves score to another session.
func (p *peer) qualityPreferred(height uint64) bool {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	p.normalizeQualityLocked(height)
	return p.qualityScore >= qualityPreferenceMinimum
}

// normalizeQualityLocked consumes every whole qualityNormalizeBlocks interval
// between the anchor and height: a height at or below the anchor changes
// nothing, the anchor advances by exactly the completed intervals so a partial
// interval is kept for a later read, and the score moves toward
// qualityScoreInitial by at most one point per interval, bounded in uint64
// before any narrowing. Caller holds stateMu.
func (p *peer) normalizeQualityLocked(height uint64) {
	if height <= p.qualityHeight {
		return
	}
	intervals := (height - p.qualityHeight) / qualityNormalizeBlocks
	if intervals == 0 {
		return
	}
	p.qualityHeight += intervals * qualityNormalizeBlocks
	if p.qualityScore < qualityScoreInitial {
		p.qualityScore += boundedQualityStep(intervals, qualityScoreInitial-p.qualityScore)
	} else {
		p.qualityScore -= boundedQualityStep(intervals, p.qualityScore-qualityScoreInitial)
	}
}

func boundedQualityStep(intervals uint64, distance uint8) uint8 {
	if intervals < uint64(distance) {
		return uint8(intervals)
	}
	return distance
}

// validateRelayDATxForAdmission is the LOCAL standard-domain check kept for
// Service.AnnounceTx and relayTxFromPool: a locally submitted or pool-resident
// DA chunk must carry the payload its declared hash names. The remote DA path
// never calls it; AdmitDA owns that check after its owner observation.
func validateRelayDATxForAdmission(txBytes []byte, tx *consensus.Tx) error {
	if tx == nil || tx.TxKind != 0x02 || tx.DaChunkCore == nil {
		return nil
	}
	return node.ValidateDARelayChunk(node.DARelayChunk{
		DAID:       tx.DaChunkCore.DaID,
		ChunkHash:  tx.DaChunkCore.ChunkHash,
		ChunkIndex: tx.DaChunkCore.ChunkIndex,
		Payload:    tx.DaPayload,
		WireBytes:  uint64(len(txBytes)),
	})
}

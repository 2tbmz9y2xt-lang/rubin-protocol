package p2p

import (
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// IDENTITY_BOUNDS_V1: process-local byte limits on a remote DA candidate's captured peer
// identity and derived quota identity, checked before any provenance is built; they bound
// local memory per retained member and are not wire, DNS or retained-byte constants.
const (
	maxDAPeerIdentityBytes  = 263
	maxDAQuotaIdentityBytes = 255
)

// COMPETING_SCORE_V1: the connection-local peer-quality policy (RUBIN_COMPACT_BLOCKS.md Section 14
// score shape, local magnitudes). A connection starts at 50; a validated distinct commit competing
// for a retained da_id subtracts 2 (1 below height 1440), saturating at 0; the score drifts one point
// toward 50 per 144 blocks of local height, lazily; the prefetch trigger keeps its preference at >= 40.
const (
	qualityScoreInitial         uint8  = 50
	qualityPreferenceMinimum    uint8  = 40
	qualityCompetingCommitDelta uint8  = 2
	qualityCompetingCommitGrace uint8  = 1
	qualityNormalizeBlocks      uint64 = 144
	qualityGraceHeight          uint64 = 1440
)

// AdmitLocalDA registers one local admission as Service work and delegates the
// unchanged bytes to the shared DA owner with LOCAL provenance.
func (s *Service) AdmitLocalDA(txBytes []byte) (node.DAAdmissionResult, error) {
	var zero node.DAAdmissionResult
	if s == nil {
		return zero, &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "nil service"}
	}
	if !s.acquireWork() {
		return zero, &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: errServiceClosed.Error()}
	}
	defer s.releaseWork()
	return s.daRelay.AdmitDA(txBytes, node.LocalDAProvenance())
}

// admitDetachedReorgDA transfers a retained result's work lease to its
// once-only post-lock completion.
func (s *Service) admitDetachedReorgDA(txBytes []byte) (completion func(bool), err error) {
	if s == nil {
		return nil, &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "nil service"}
	}
	if !s.acquireWork() {
		return nil, &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: errServiceClosed.Error()}
	}
	defer func() {
		if completion == nil {
			s.releaseWork()
		}
	}()
	result, err := s.daRelay.AdmitDA(txBytes, node.DetachedReorgDAProvenance())
	if err != nil {
		return nil, err
	}
	if result.Disposition != node.DAAdmissionRetained || result.SameDAIDCommitConflict {
		return nil, nil
	}
	daID := result.DAID
	consumed := false
	return func(run bool) {
		if consumed {
			return
		}
		consumed = true
		defer s.releaseWork()
		if run {
			s.scheduleDAPrefetch("", daID)
		}
	}, nil
}

// handleRelayDATx is the ONE production remote DA admission path: a remote tx_kind 0x01/0x02
// transaction past the message bound and full canonical parse invokes AdmitDA exactly once before any
// standard-pool, seen-set, metadata or inventory effect. The identity is captured once from the peer
// state handleConn normalized; one outside IDENTITY_BOUNDS_V1 (a defense-in-depth ceiling no normalized
// address reaches) exits nil with zero effect. The terminal latch is checked before the quota key (a
// latch landing later keeps the same-key teardown/Close limitation until restart); the key is held only
// around AdmitDA and released before any effect; no candidate validation precedes AdmitDA's owner
// observation; errors.Is on the hash sentinel is the only peer fault. RETAINED without conflict
// schedules the prefetch once; DUPLICATE with conflict applies COMPETING_SCORE_V1 once; DUPLICATE without
// conflict is the reachable neutral exit (exact/nonexact replay, occupied index); a zero/unknown
// discriminator or RETAINED with the conflict flag — shapes publicDAAdmissionResult cannot emit — also exit
// nil. AdmitDA refuses a set-completing member until RUB-1118 activates the COMPLETE_SET owner.
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

// remoteDAProvenance: the identity is captured once, the quota key derived from it and IDENTITY_BOUNDS_V1
// applied before any provenance; ok=false exits nil with zero effect; the nonempty check keeps NewPeerDAProvenance's refusal unreachable.
func (p *peer) remoteDAProvenance() (peerIdentity, quotaIdentity string, provenance node.DAProvenance, ok bool) {
	peerIdentity = p.addr()
	quotaIdentity = peerQuotaKey(peerIdentity)
	if peerIdentity == "" || len(peerIdentity) > maxDAPeerIdentityBytes || quotaIdentity == "" || len(quotaIdentity) > maxDAQuotaIdentityBytes {
		return "", "", node.DAProvenance{}, false
	}
	provenance, err := node.NewPeerDAProvenance(peerIdentity, quotaIdentity)
	return peerIdentity, quotaIdentity, provenance, err == nil
}

// penalizeDAAdmissionError: only the hash-mismatch sentinel (errors.Is identity alone) takes the +10 ban
// step with its text as LastError and is returned at the ban threshold; every other error is peer-neutral.
func (p *peer) penalizeDAAdmissionError(err error) error {
	if errors.Is(err, node.ErrDARelayChunkHashMismatch) && p.bumpBan(10, node.ErrDARelayChunkHashMismatch.Error()) {
		return node.ErrDARelayChunkHashMismatch
	}
	return nil
}

// applyCompetingCommitScore is COMPETING_SCORE_V1's one event, height captured after every lock was
// released: under stateMu the score drifts, then loses the grace-adjusted delta saturating at 0; BanScore/LastError untouched.
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

// qualityPreferred drifts the score for height and reports whether this peer keeps its DA
// prefetch front-of-list preference; it never removes the peer from the eligible set.
func (p *peer) qualityPreferred(height uint64) bool {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	p.normalizeQualityLocked(height)
	return p.qualityScore >= qualityPreferenceMinimum
}

// normalizeQualityLocked consumes every whole qualityNormalizeBlocks interval between the
// anchor and height: at or below the anchor nothing changes; the anchor advances by exactly
// the completed intervals (a partial one is kept); the score moves up toward
// qualityScoreInitial by at most one point per interval, bounded in uint64 before narrowing.
// Only the negative event and this drift exist, so the score never exceeds
// qualityScoreInitial and no downward arm is needed. Caller holds stateMu.
func (p *peer) normalizeQualityLocked(height uint64) {
	if height <= p.qualityHeight {
		return
	}
	intervals := (height - p.qualityHeight) / qualityNormalizeBlocks
	if intervals == 0 {
		return
	}
	p.qualityHeight += intervals * qualityNormalizeBlocks
	p.qualityScore += uint8(min(intervals, uint64(qualityScoreInitial-p.qualityScore))) //nolint:gosec // bounded above by the distance to qualityScoreInitial (<= 50)
}

// validateRelayDATxForAdmission is the LOCAL standard-domain check for Service.AnnounceTx and
// relayTxFromPool; the remote arm never calls it (AdmitDA owns it after the owner observation).
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

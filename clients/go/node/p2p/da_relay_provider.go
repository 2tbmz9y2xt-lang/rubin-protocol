package p2p

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"

// CompleteDASetCandidates returns caller-owned COMPLETE_SET snapshots up to maxPayloadBytes.
func (s *Service) CompleteDASetCandidates(maxPayloadBytes uint64) []node.CompleteDASetCandidate {
	if s == nil || s.daRelay == nil {
		return nil
	}
	return s.daRelay.CompleteSetCandidates(maxPayloadBytes)
}

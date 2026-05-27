package p2p

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"

// CompleteDASetCandidates returns immutable snapshots of relay-complete DA sets.
func (s *Service) CompleteDASetCandidates(maxPayloadBytes uint64) []node.CompleteDASetCandidate {
	return s.completeDASetCandidates(maxPayloadBytes)
}

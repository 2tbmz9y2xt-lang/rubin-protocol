package p2p

import (
	"bytes"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// CompleteDASetCandidates returns immutable snapshots of relay-complete DA sets.
func (s *Service) CompleteDASetCandidates(maxPayloadBytes uint64) []node.CompleteDASetCandidate {
	if s == nil || s.daRelay == nil {
		return nil
	}
	return s.daRelay.completeSetCandidates(maxPayloadBytes)
}

func (s *daRelayState) completeSetCandidates(maxPayloadBytes uint64) []node.CompleteDASetCandidate {
	if s == nil || maxPayloadBytes == 0 {
		return nil
	}
	var candidates []node.CompleteDASetCandidate
	for _, record := range s.completeSetCandidateRecords(maxPayloadBytes) {
		candidate, ok := record.completeSetCandidate()
		if ok {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func (s *daRelayState) completeSetCandidateRecords(maxPayloadBytes uint64) []daRelaySetRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	daIDs := make([][32]byte, 0, len(s.sets))
	for daID, record := range s.sets {
		if record.state == daRelayStateCompleteSet {
			daIDs = append(daIDs, daID)
		}
	}
	sort.Slice(daIDs, func(i, j int) bool {
		return bytes.Compare(daIDs[i][:], daIDs[j][:]) < 0
	})

	records := make([]daRelaySetRecord, 0, len(daIDs))
	var payloadBytes uint64
	for _, daID := range daIDs {
		record := s.sets[daID]
		if record.payloadBytes > maxPayloadBytes-payloadBytes {
			break
		}
		records = append(records, record.cloneForStateMutation())
		payloadBytes += record.payloadBytes
	}
	return records
}

func (r daRelaySetRecord) completeSetCandidate() (node.CompleteDASetCandidate, bool) {
	if len(r.commit.txBytes) == 0 {
		return node.CompleteDASetCandidate{}, false
	}
	chunks := make([]node.CompleteDASetChunkCandidate, 0, r.commit.chunkCount)
	for i := uint16(0); i < r.commit.chunkCount; i++ {
		chunk, ok := r.chunks[i]
		if !ok || len(chunk.txBytes) == 0 {
			return node.CompleteDASetCandidate{}, false
		}
		chunks = append(chunks, node.CompleteDASetChunkCandidate{
			Index: i,
			Tx:    cloneBytes(chunk.txBytes),
		})
	}
	return node.CompleteDASetCandidate{
		DAID:         r.daID,
		PayloadBytes: r.payloadBytes,
		CommitTx:     cloneBytes(r.commit.txBytes),
		Chunks:       chunks,
	}, true
}

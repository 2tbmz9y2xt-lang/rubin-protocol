package p2p

import (
	"bytes"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// CompleteDASetCandidates returns caller-owned COMPLETE_SET snapshots up to maxPayloadBytes.
func (s *Service) CompleteDASetCandidates(maxPayloadBytes uint64) []node.CompleteDASetCandidate {
	if s == nil {
		return nil
	}
	return s.daRelay.completeSetCandidates(maxPayloadBytes)
}

func (s *daRelayState) completeSetCandidates(maxPayloadBytes uint64) []node.CompleteDASetCandidate {
	if s == nil || maxPayloadBytes == 0 {
		return nil
	}
	var candidates []node.CompleteDASetCandidate
	var payloadBytes uint64
	for _, record := range s.completeSetCandidateRecordsSnapshot() {
		if record.payloadBytes > maxPayloadBytes-payloadBytes {
			continue
		}
		candidate, ok := record.completeSetCandidate()
		if !ok {
			continue
		}
		candidates = append(candidates, candidate)
		payloadBytes += record.payloadBytes
	}
	return candidates
}

func (s *daRelayState) completeSetCandidateRecordsSnapshot() []daRelaySetRecord {
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
	for _, daID := range daIDs {
		records = append(records, s.sets[daID].cloneForStateMutation())
	}
	return records
}

func (r daRelaySetRecord) completeSetCandidate() (node.CompleteDASetCandidate, bool) {
	if r.commit.chunkCount == 0 || len(r.commit.txBytes) == 0 {
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

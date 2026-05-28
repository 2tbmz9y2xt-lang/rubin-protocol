package node

import (
	"bytes"
	"crypto/sha3"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestMinerFlatDAFilterPreservesExplicitNonDACandidates(t *testing.T) {
	daCommit := daCommitTxBytesForMinerPolicyTest(1, []byte("manifest"))
	daChunk := minerFlatDATestChunk(t, [32]byte{0x71}, 0, []byte("chunk"))
	nonDA := minerFlatTestNonDA(0x11)

	miner := &Miner{cfg: MinerConfig{MaxTxPerBlock: 2}}
	candidates := miner.candidateTransactions([][]byte{daCommit, daChunk, nonDA})
	selected, err := miner.selectCandidateTransactions(candidates, nil, 1, ^uint64(0))
	if err != nil {
		t.Fatalf("selectCandidateTransactions: %v", err)
	}
	if len(selected) != 1 || !bytes.Equal(selected[0].raw, nonDA) {
		t.Fatalf("selected=%d, want only trailing non-DA candidate", len(selected))
	}
}

func TestMinerMempoolCandidateEntriesSkipFlatDABeforeWindowCap(t *testing.T) {
	daCommit := daCommitTxBytesForMinerPolicyTest(1, []byte("manifest"))
	nonDA := minerFlatTestNonDA(0x12)
	entries := []*mempoolEntry{
		{raw: daCommit, size: len(daCommit)},
		{raw: nonDA, size: len(nonDA)},
		{raw: minerFlatDATestChunk(t, [32]byte{0x72}, 0, []byte("chunk")), size: 1},
	}

	selected := pickMinerCandidateEntries(entries, 1, 1<<20)
	if len(selected) != 1 || !bytes.Equal(selected[0], nonDA) {
		t.Fatalf("selected=%d, want non-DA candidate past skipped flat DA entries", len(selected))
	}
}

func TestMinerFlatDAFilterKeepsCapacityBoundedByCandidates(t *testing.T) {
	nonDA := minerFlatTestNonDA(0x13)

	selected := pickFlatCandidateRaw([][]byte{nonDA}, 1_000_000)
	if len(selected) != 1 || cap(selected) != 1 {
		t.Fatalf("explicit selected len/cap=%d/%d, want 1/1", len(selected), cap(selected))
	}

	entries := []*mempoolEntry{{raw: nonDA, size: len(nonDA)}}
	selected = pickMinerCandidateEntries(entries, 1_000_000, 1<<20)
	if len(selected) != 1 || cap(selected) != 1 {
		t.Fatalf("mempool selected len/cap=%d/%d, want 1/1", len(selected), cap(selected))
	}
}

func TestMinerFlatDAFilterSkipsDAInSelectionPath(t *testing.T) {
	miner := &Miner{cfg: DefaultMinerConfig()}
	if _, _, ok, err := miner.trySelectFlatCandidate(daCommitTxBytesForMinerPolicyTest(2, []byte("manifest")), nil, 1, 0, ^uint64(0), 0); err != nil || ok {
		t.Fatalf("DA candidate ok=%v err=%v, want skipped without error", ok, err)
	}
}

func TestMinerFlatDAFilterSkipsWeightBudgetRejects(t *testing.T) {
	nonDA := minerFlatTestNonDA(0x15)
	miner := &Miner{cfg: DefaultMinerConfig()}
	if _, _, ok, err := miner.trySelectFlatCandidate(nonDA, nil, 1, 0, 0, 0); err != nil || ok {
		t.Fatalf("zero remaining weight ok=%v err=%v, want skipped without error", ok, err)
	}
	if _, _, ok, err := miner.trySelectFlatCandidate(nonDA, nil, 1, 0, 1, 0); err != nil || ok {
		t.Fatalf("overweight candidate ok=%v err=%v, want skipped without error", ok, err)
	}
}

func TestMinerFlatDAFilterPreservesNonCanonicalInputError(t *testing.T) {
	badDACommit := append(daCommitTxBytesForMinerPolicyTest(1, []byte("manifest")), 0x00)
	miner := &Miner{cfg: MinerConfig{MaxTxPerBlock: 2}}

	candidates := miner.candidateTransactions([][]byte{badDACommit})
	if len(candidates) != 1 {
		t.Fatalf("candidate count=%d, want malformed DA-shaped input preserved", len(candidates))
	}
	if _, err := miner.selectCandidateTransactions(candidates, nil, 1, ^uint64(0)); err == nil {
		t.Fatalf("expected non-canonical miner input error")
	}
}

func minerFlatDATestChunk(t *testing.T, daID [32]byte, index uint16, payload []byte) []byte {
	t.Helper()
	chunkHash := sha3.Sum256(payload)
	return mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:     1,
		TxKind:      0x02,
		TxNonce:     uint64(index) + 1,
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: chunkHash},
		DaPayload:   append([]byte(nil), payload...),
	})
}

func minerFlatTestNonDA(marker byte) []byte {
	return txWithOneInputOneOutput([32]byte{marker}, 0, 1, consensus.COV_TYPE_P2PK, testP2PKCovenantData(marker), nil)
}

package node

import (
	"crypto/sha3"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type staticCompleteDASetProvider []CompleteDASetCandidate

func (p staticCompleteDASetProvider) CompleteDASetCandidates(uint64) []CompleteDASetCandidate {
	return p
}

type budgetProbeProvider struct{ got uint64 }

func (p *budgetProbeProvider) CompleteDASetCandidates(max uint64) []CompleteDASetCandidate {
	p.got = max
	return nil
}

type countingCompleteDASetProvider struct {
	calls int
	sets  []CompleteDASetCandidate
}

func (p *countingCompleteDASetProvider) CompleteDASetCandidates(uint64) []CompleteDASetCandidate {
	p.calls++
	return p.sets
}

func TestMinerSelectsCompleteDASetAndDropsFlatDA(t *testing.T) {
	daID := [32]byte{0x71}
	candidate, commit, chunk0, chunk1 := minerTestDASet(t, daID)
	flatNonDA := txWithOneInputOneOutput([32]byte{0x11}, 0, 1, consensus.COV_TYPE_P2PK, testP2PKCovenantData(0x11), nil)
	candidate.Chunks[0], candidate.Chunks[1] = candidate.Chunks[1], candidate.Chunks[0]
	miner := minerTestWithDAProvider(staticCompleteDASetProvider{candidate})

	selected, err := miner.selectCandidateTransactions([][]byte{commit, chunk0, flatNonDA}, nil, 1, ^uint64(0))
	if err != nil {
		t.Fatalf("selectCandidateTransactions: %v", err)
	}
	if len(selected) != 4 || string(selected[0].raw) != string(flatNonDA) || string(selected[1].raw) != string(commit) ||
		string(selected[2].raw) != string(chunk0) || string(selected[3].raw) != string(chunk1) {
		t.Fatalf("selected sequence mismatch")
	}
}

func TestMinerCompleteDASetSelectionCapsRuntimeWork(t *testing.T) {
	if got := mempoolCandidateFetchLimit(4, 1000); got != 8 {
		t.Fatalf("fetch limit=%d, want bounded overfetch 8", got)
	}
	if got := mempoolCandidateFetchLimit(200, 1000); got != 200+int(consensus.MAX_DA_BATCHES_PER_BLOCK) {
		t.Fatalf("fetch limit=%d, want max plus DA batch cap", got)
	}
	if got := mempoolCandidateFetchLimit(200, 250); got != 250 {
		t.Fatalf("fetch limit=%d, want available cap", got)
	}

	provider := &countingCompleteDASetProvider{}
	miner := minerTestWithDAProvider(provider)
	miner.cfg.MaxTxPerBlock = 2
	flatNonDA := txWithOneInputOneOutput([32]byte{0x15}, 0, 1, consensus.COV_TYPE_P2PK, testP2PKCovenantData(0x15), nil)
	selected, err := miner.selectCandidateTransactions([][]byte{flatNonDA}, nil, 1, ^uint64(0))
	if err != nil {
		t.Fatalf("selectCandidateTransactions: %v", err)
	}
	if len(selected) != 1 || provider.calls != 0 {
		t.Fatalf("selected=%d provider_calls=%d, want full template without provider call", len(selected), provider.calls)
	}
}

func TestMinerCompleteDASetSelectionCapsDABatches(t *testing.T) {
	const groupSize = 3
	sets := make([]CompleteDASetCandidate, 0, consensus.MAX_DA_BATCHES_PER_BLOCK+1)
	for i := 0; i < consensus.MAX_DA_BATCHES_PER_BLOCK+1; i++ {
		daID := [32]byte{0x75, byte(i), byte(i >> 8)}
		candidate, _, _, _ := minerTestDASet(t, daID)
		sets = append(sets, candidate)
	}
	miner := minerTestWithDAProvider(staticCompleteDASetProvider(sets))
	miner.cfg.MaxTxPerBlock = 1 + len(sets)*groupSize
	selected, err := miner.selectCandidateTransactions(nil, nil, 1, ^uint64(0))
	if err != nil {
		t.Fatalf("selectCandidateTransactions: %v", err)
	}
	want := int(consensus.MAX_DA_BATCHES_PER_BLOCK) * groupSize
	if len(selected) != want {
		t.Fatalf("selected=%d, want %d capped DA batch transactions", len(selected), want)
	}
}

func TestMinerCompleteDASetSelectionRejectsCoverageEdges(t *testing.T) {
	daID := [32]byte{0x73}
	candidate, _, _, chunk1 := minerTestDASet(t, daID)
	flatNonDA := txWithOneInputOneOutput([32]byte{0x12}, 0, 1, consensus.COV_TYPE_P2PK, testP2PKCovenantData(0x12), nil)
	miner := minerTestWithDAProvider(staticCompleteDASetProvider{candidate})
	if got := (&Miner{cfg: MinerConfig{MaxTxPerBlock: 0}}).maxSelectedTransactions(); got != 0 {
		t.Fatalf("max selected=%d, want 0", got)
	}
	if selected, err := miner.selectCandidateTransactions([][]byte{flatNonDA}, nil, 1, 0); err != nil || len(selected) != 0 {
		t.Fatalf("overweight flat selected=%d err=%v, want none", len(selected), err)
	}
	if selected, err := miner.selectCandidateTransactions(nil, nil, 1, 0); err != nil || len(selected) != 0 {
		t.Fatalf("overweight group selected=%d err=%v, want none", len(selected), err)
	}
	miner.cfg.PolicyDaAnchorAntiAbuse = true
	if selected, err := miner.selectCandidateTransactions(nil, nil, 1, ^uint64(0)); err != nil || len(selected) != 0 {
		t.Fatalf("policy-error group selected=%d err=%v, want none", len(selected), err)
	}
	badIndex := candidate
	badIndex.Chunks = []CompleteDASetChunkCandidate{candidate.Chunks[0], {Index: 2, Tx: chunk1}}
	assertNoCompleteDASelection(t, badIndex, 16)
}

func TestCompleteDASetChunkCountRejectsConsensusCap(t *testing.T) {
	daID := [32]byte{0x76}
	tx := &consensus.Tx{DaCommitCore: &consensus.DaCommitCore{
		DaID:       daID,
		ChunkCount: uint16(consensus.MAX_DA_CHUNK_COUNT + 1),
	}}
	set := CompleteDASetCandidate{
		DAID:   daID,
		Chunks: make([]CompleteDASetChunkCandidate, int(consensus.MAX_DA_CHUNK_COUNT)+1),
	}
	if chunkCount, ok := completeDASetChunkCount(tx, set); ok || chunkCount != 0 {
		t.Fatalf("completeDASetChunkCount=%d,%v, want cap rejection", chunkCount, ok)
	}
}

func TestMinerCompleteDASetRejectsMalformedProviderRawAndBudgetFallback(t *testing.T) {
	daID := [32]byte{0x74}
	candidate, _, _, _ := minerTestDASet(t, daID)
	miner := minerTestWithDAProvider(staticCompleteDASetProvider{{DAID: daID, CommitTx: []byte{0xff}}})
	if _, err := miner.selectCandidateTransactions(nil, nil, 1, ^uint64(0)); err == nil {
		t.Fatalf("malformed commit raw must error")
	}
	candidate.Chunks[0].Tx = []byte{0xff}
	miner = minerTestWithDAProvider(staticCompleteDASetProvider{candidate})
	if _, err := miner.selectCandidateTransactions(nil, nil, 1, ^uint64(0)); err == nil {
		t.Fatalf("malformed chunk raw must error")
	}
	probe := &budgetProbeProvider{}
	miner = minerTestWithDAProvider(probe)
	miner.cfg.PolicyMaxDaBytesPerBlock = 0
	_ = miner.completeDASetCandidatesForMining()
	if probe.got != consensus.MAX_DA_BYTES_PER_BLOCK {
		t.Fatalf("budget=%d, want consensus max", probe.got)
	}
}

func TestMinerSkipsCompleteDASetWithoutAtomicFit(t *testing.T) {
	daID := [32]byte{0x72}
	candidate, _, _, _ := minerTestDASet(t, daID)
	badCommit := mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:      1,
		TxKind:       0x01,
		TxNonce:      9,
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: 1, BatchNumber: 1},
		DaPayload:    []byte{0xa1},
	})
	assertNoCompleteDASelection(t, CompleteDASetCandidate{DAID: daID, CommitTx: candidate.CommitTx, Chunks: candidate.Chunks[:1]}, 16)
	assertNoCompleteDASelection(t, candidate, 3)
	assertNoCompleteDASelection(t, CompleteDASetCandidate{DAID: daID, CommitTx: badCommit, Chunks: candidate.Chunks[:1]}, 16)
}

func assertNoCompleteDASelection(t *testing.T, candidate CompleteDASetCandidate, maxTxPerBlock int) {
	miner := minerTestWithDAProvider(staticCompleteDASetProvider{candidate})
	miner.cfg.MaxTxPerBlock = maxTxPerBlock
	if selected, err := miner.selectCandidateTransactions(nil, nil, 1, ^uint64(0)); err != nil || len(selected) != 0 {
		t.Fatalf("selectCandidateTransactions selected=%d err=%v, want none", len(selected), err)
	}
}

func minerTestDASet(t *testing.T, daID [32]byte) (CompleteDASetCandidate, []byte, []byte, []byte) {
	payload0, payload1 := []byte("chunk-0"), []byte("chunk-1")
	commit := minerTestDACommitTx(t, daID, payload0, payload1)
	chunk0 := minerTestDAChunkTx(t, daID, 0, payload0, 2)
	chunk1 := minerTestDAChunkTx(t, daID, 1, payload1, 3)
	return CompleteDASetCandidate{
		DAID:     daID,
		CommitTx: commit,
		Chunks: []CompleteDASetChunkCandidate{
			{Index: 0, Tx: chunk0},
			{Index: 1, Tx: chunk1},
		},
	}, commit, chunk0, chunk1
}

func minerTestWithDAProvider(provider CompleteDASetProvider) *Miner {
	cfg := DefaultMinerConfig()
	cfg.CompleteDASetProvider = provider
	cfg.MaxTxPerBlock = 16
	cfg.PolicyDaAnchorAntiAbuse = false
	return &Miner{cfg: cfg}
}

func minerTestDACommitTx(t *testing.T, daID [32]byte, payloads ...[]byte) []byte {
	var concat []byte
	for _, payload := range payloads {
		concat = append(concat, payload...)
	}
	commitment := sha3.Sum256(concat)
	return mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:      1,
		TxKind:       0x01,
		TxNonce:      1,
		Inputs:       []consensus.TxInput{{PrevTxid: [32]byte{0xc1}}},
		Outputs:      []consensus.TxOutput{{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: commitment[:]}},
		DaCommitCore: &consensus.DaCommitCore{DaID: daID, ChunkCount: uint16(len(payloads)), BatchNumber: 1},
		DaPayload:    []byte{0xa1},
	})
}

func minerTestDAChunkTx(t *testing.T, daID [32]byte, index uint16, payload []byte, nonce uint64) []byte {
	chunkHash := sha3.Sum256(payload)
	return mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:     1,
		TxKind:      0x02,
		TxNonce:     nonce,
		Inputs:      []consensus.TxInput{{PrevTxid: [32]byte{0xc2}, PrevVout: uint32(index)}},
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: chunkHash},
		DaPayload:   append([]byte(nil), payload...),
	})
}

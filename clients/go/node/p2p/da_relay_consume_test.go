package p2p

import (
	"crypto/sha3"
	"reflect"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestConsumeAcceptedBlockDASetsConsumesMatchingCompleteSet(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	consumeID, absentID, keepID, incompleteID := daRelayTestID(0x81), daRelayTestID(0x82), daRelayTestID(0x83), daRelayTestID(0x84)
	payload := []byte("accepted-payload")
	stageCompleteDASetForService(t, h.service, consumeID, payload)
	stageCompleteDASetForService(t, h.service, keepID, []byte("keep"))
	stageIncompleteDASetForService(t, h.service, incompleteID, []byte("incomplete"))
	if got := h.service.CompleteDASetCandidates(^uint64(0)); len(got) != 2 {
		t.Fatalf("candidates=%+v, want two retained complete sets", got)
	}
	block := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, consumeID, 1, payload),
		daChunkRelayTxBytes(t, consumeID, 0, 2, payload),
		daCommitRelayTxBytes(t, absentID, 3, payload),
		daChunkRelayTxBytes(t, absentID, 0, 4, payload),
	})
	parsed, err := consensus.ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	if ids, err := node.CompleteDASetIDsFromParsedBlock(parsed); err != nil || !reflect.DeepEqual(ids, [][32]byte{consumeID, absentID}) {
		t.Fatalf("CompleteDASetIDsFromParsedBlock ids=%x err=%v", ids, err)
	}
	if err := h.service.ConsumeAcceptedBlockDASets(block); err != nil {
		t.Fatalf("ConsumeAcceptedBlockDASets: %v", err)
	}
	if got := h.service.CompleteDASetCandidates(^uint64(0)); len(got) != 1 || got[0].DAID != keepID {
		t.Fatalf("candidates after consume=%+v, want unrelated set", got)
	}
	requireIncompleteDASet(t, h.service, incompleteID)
}

func TestConsumeAcceptedBlockDASetsRejectsMalformedBytesWithoutMutation(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	daID := daRelayTestID(0x82)
	stageCompleteDASetForService(t, h.service, daID, []byte("malformed-payload"))
	if err := h.service.ConsumeAcceptedBlockDASets([]byte{0x01, 0x02}); err == nil {
		t.Fatal("malformed bytes returned nil")
	}
	if got := h.service.CompleteDASetCandidates(^uint64(0)); len(got) != 1 || got[0].DAID != daID {
		t.Fatalf("candidates after malformed bytes=%+v, want %x", got, daID)
	}
}

func TestConsumeCanonicalAppliedDASetsDirectApplyConsumes(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	daID := daRelayTestID(0x61)
	stageCompleteDASetForService(t, h.service, daID, []byte("direct-payload"))
	hash := daRelayTestID(0xa0)
	if err := h.service.noteAcceptedBlock(nil, hash, hash, &node.ChainStateConnectSummary{CanonicalAppliedBlocks: []node.CanonicalAppliedBlock{{Hash: hash, CompleteDAIDs: [][32]byte{daID}}}}); err != nil {
		t.Fatalf("noteAcceptedBlock: %v", err)
	}
	if got := h.service.CompleteDASetCandidates(^uint64(0)); len(got) != 0 {
		t.Fatalf("candidates after direct apply=%+v", got)
	}
}

func TestConsumeCanonicalAppliedDASetsSideAndReorg(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	first, second := daRelayTestID(0x62), daRelayTestID(0x63)
	stageCompleteDASetForService(t, h.service, first, []byte("side"))
	if err := h.service.consumeCanonicalAppliedDASets(nil); err != nil || len(h.service.CompleteDASetCandidates(^uint64(0))) != 1 {
		t.Fatalf("side report err=%v candidates=%+v", err, h.service.CompleteDASetCandidates(^uint64(0)))
	}
	stageCompleteDASetForService(t, h.service, second, []byte("reorg"))
	blocks := []node.CanonicalAppliedBlock{
		{Hash: daRelayTestID(0xa1), CompleteDAIDs: [][32]byte{first}},
		{Hash: daRelayTestID(0xa2), CompleteDAIDs: [][32]byte{second}},
	}
	if err := h.service.consumeCanonicalAppliedDASets(blocks); err != nil || len(h.service.CompleteDASetCandidates(^uint64(0))) != 0 {
		t.Fatalf("reorg report err=%v candidates=%+v", err, h.service.CompleteDASetCandidates(^uint64(0)))
	}
}

func TestConsumeCanonicalAppliedDASetsNoOpRowsContinue(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	first, last, incomplete, unknown := daRelayTestID(0x65), daRelayTestID(0x66), daRelayTestID(0x67), daRelayTestID(0x68)
	stageCompleteDASetForService(t, h.service, first, []byte("first"))
	stageCompleteDASetForService(t, h.service, last, []byte("last"))
	stageIncompleteDASetForService(t, h.service, incomplete, []byte("incomplete"))
	blocks := []node.CanonicalAppliedBlock{{
		Hash: daRelayTestID(0xa3), CompleteDAIDs: [][32]byte{unknown, incomplete, first, first, last},
	}}
	if err := h.service.consumeCanonicalAppliedDASets(blocks); err != nil {
		t.Fatalf("consume no-op rows: %v", err)
	}
	if got := h.service.CompleteDASetCandidates(^uint64(0)); len(got) != 0 {
		t.Fatalf("complete candidates after no-op rows=%+v", got)
	}
	requireIncompleteDASet(t, h.service, incomplete)
}

func TestConsumeCanonicalAppliedDASetsNoOpRowsAcrossBlocks(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	first, last, incomplete, unknown := daRelayTestID(0x69), daRelayTestID(0x6a), daRelayTestID(0x6b), daRelayTestID(0x6c)
	stageCompleteDASetForService(t, h.service, first, []byte("first"))
	stageCompleteDASetForService(t, h.service, last, []byte("last"))
	stageIncompleteDASetForService(t, h.service, incomplete, []byte("incomplete"))
	blocks := []node.CanonicalAppliedBlock{
		{Hash: daRelayTestID(0xa4), CompleteDAIDs: [][32]byte{unknown, first}},
		{Hash: daRelayTestID(0xa5), CompleteDAIDs: [][32]byte{incomplete, first, last}},
	}
	if err := h.service.consumeCanonicalAppliedDASets(blocks); err != nil {
		t.Fatalf("consume across blocks: %v", err)
	}
	if got := h.service.CompleteDASetCandidates(^uint64(0)); len(got) != 0 {
		t.Fatalf("complete candidates after blocks=%+v", got)
	}
	requireIncompleteDASet(t, h.service, incomplete)
}

func TestConsumeAcceptedBlockDASetsRetainsIncompleteGroup(t *testing.T) {
	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	daID := daRelayTestID(0x64)
	payload := []byte("incomplete")
	if err := h.service.daRelay.StageCommit("peer", node.DARelayCommit{DAID: daID, ChunkCount: 1, WireBytes: 1}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	block := compactTestBlockBytesWithTxs(t, [][]byte{minimalValidTxBytes(t), daCommitRelayTxBytes(t, daID, 1, payload)})
	if err := h.service.ConsumeAcceptedBlockDASets(block); err != nil {
		t.Fatalf("ConsumeAcceptedBlockDASets: %v", err)
	}
	if plans, diagnostic := h.service.daRelay.PlanPrefetch(daID, []string{"peer"}, time.Unix(1, 0)); len(plans) != 1 || diagnostic != "" {
		t.Fatalf("incomplete plans=%d diagnostic=%q", len(plans), diagnostic)
	}
}

func TestConsumeAcceptedBlockDASetsNilService(t *testing.T) {
	var svc *Service
	if err := svc.ConsumeAcceptedBlockDASets([]byte{0x00}); err == nil {
		t.Fatal("nil service returned nil")
	}
	if err := (&Service{}).ConsumeAcceptedBlockDASets([]byte{0x00}); err == nil {
		t.Fatal("service without relay returned nil")
	}
}

func stageCompleteDASetForService(t *testing.T, svc *Service, daID [32]byte, payload []byte) {
	t.Helper()
	commitment := sha3.Sum256(payload)
	if err := svc.daRelay.StageCommit("peer-a", node.DARelayCommit{
		DAID:              daID,
		PayloadCommitment: commitment,
		ChunkCount:        1,
		WireBytes:         1,
		TxBytes:           []byte("commit"),
	}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
	if err := svc.daRelay.StageChunk("peer-b", node.DARelayChunk{
		DAID:       daID,
		ChunkHash:  sha3.Sum256(payload),
		ChunkIndex: 0,
		Payload:    payload,
		WireBytes:  uint64(len(payload)),
		TxBytes:    []byte("chunk"),
	}); err != nil {
		t.Fatalf("StageChunk: %v", err)
	}
}

func stageIncompleteDASetForService(t *testing.T, svc *Service, daID [32]byte, payload []byte) {
	if err := svc.daRelay.StageCommit("peer", node.DARelayCommit{DAID: daID, PayloadCommitment: sha3.Sum256(payload), ChunkCount: 1, WireBytes: 1}); err != nil {
		t.Fatalf("StageCommit: %v", err)
	}
}

func requireIncompleteDASet(t *testing.T, svc *Service, daID [32]byte) {
	t.Helper()
	plans, diagnostic := svc.daRelay.PlanPrefetch(daID, []string{"probe"}, time.Unix(1, 0))
	if len(plans) != 1 || diagnostic != "" {
		t.Fatalf("incomplete plans=%d diagnostic=%q", len(plans), diagnostic)
	}
	for _, plan := range plans {
		svc.daRelay.ReleasePrefetchPlan(plan)
	}
}

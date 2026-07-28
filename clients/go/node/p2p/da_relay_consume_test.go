package p2p

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// mustParseCompleteDASetIDs runs the shared extraction core over real block
// bytes: parse first, exactly as ConsumeAcceptedBlockDASets does, so these rows
// pin the behavior of the encoded-block entry and not only of the core.
func mustParseCompleteDASetIDs(t *testing.T, blockBytes []byte) [][32]byte {
	t.Helper()
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	ids, err := node.CompleteDASetIDsFromParsedBlock(parsed)
	if err != nil {
		t.Fatalf("CompleteDASetIDsFromParsedBlock: %v", err)
	}
	return ids
}

// TestConsumeAcceptedBlockDASetsMatchesParsedCore is the equivalence row: the
// bytes entry (RPC hook) and the parsed core (canonical-apply attach point) must
// select the SAME complete DA sets for the same block, or the two entries would
// consume different relay records.
func TestConsumeAcceptedBlockDASetsMatchesParsedCore(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	consumeID := daRelayTestID(0x81)
	keepID := daRelayTestID(0x82)
	consumePayload := []byte("equiv-consume")
	incompletePayload := []byte("equiv-incomplete")

	// Staged for its relay-accounting side effect only; the block this row needs
	// is the richer one built below, which also carries keepID's commit.
	_ = stageCompleteDASet(t, state, consumeID, "equiv", consumePayload)
	// keepID is complete in relay accounting but INCOMPLETE in the block (commit
	// only), so a divergence between the two entries would show up here.
	mustAddDACommit(t, state, "equiv-keep-commit", daRelayTestCommitForPayloads(keepID, 1, incompletePayload))
	mustAddDAChunk(t, state, "equiv-keep-chunk", daRelayTestChunkPayload(keepID, 0, uint64(len(incompletePayload)), incompletePayload))
	block := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, consumeID, 1, consumePayload),
		daChunkRelayTxBytes(t, consumeID, 0, 2, consumePayload),
		daCommitRelayTxBytes(t, keepID, 3, incompletePayload),
	})

	coreIDs := mustParseCompleteDASetIDs(t, block)
	if !reflect.DeepEqual(coreIDs, [][32]byte{consumeID}) {
		t.Fatalf("parsed core ids=%x, want %x", coreIDs, [][32]byte{consumeID})
	}
	before := len(state.sets)
	if err := (&Service{daRelay: state}).ConsumeAcceptedBlockDASets(block); err != nil {
		t.Fatalf("ConsumeAcceptedBlockDASets: %v", err)
	}
	if _, ok := state.sets[consumeID]; ok {
		t.Fatal("bytes entry did not consume the id the parsed core selected")
	}
	if got := state.sets[keepID]; got.state != daRelayStateCompleteSet {
		t.Fatalf("bytes entry consumed %x which the parsed core did not select", keepID)
	}
	if len(state.sets) != before-len(coreIDs) {
		t.Fatalf("consumed %d records, want exactly the %d ids the core selected", before-len(state.sets), len(coreIDs))
	}
}

func TestServiceConsumeAcceptedBlockDASetsRemovesCompleteSetAccounting(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	consumeID := daRelayTestID(0x51)
	keepID := daRelayTestID(0x52)
	consumePayload := []byte("consume-payload")
	keepPayload := []byte("keep-payload")

	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(consumeID, 1, consumePayload))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(consumeID, 0, uint64(len(consumePayload)), consumePayload))
	mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(keepID, 1, keepPayload))
	keepRecord := mustAddDAChunk(t, state, "peer-d", daRelayTestChunkPayload(keepID, 0, uint64(len(keepPayload)), keepPayload))
	keepPinned := mustPinnedPayloadAccounting(t, keepRecord)

	block := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, consumeID, 1, consumePayload),
		daChunkRelayTxBytes(t, consumeID, 0, 2, consumePayload),
	})
	if err := (&Service{daRelay: state}).ConsumeAcceptedBlockDASets(block); err != nil {
		t.Fatalf("ConsumeAcceptedBlockDASets: %v", err)
	}
	if _, ok := state.sets[consumeID]; ok {
		t.Fatal("consumed complete set retained record")
	}
	if got := state.sets[keepID]; got.state != daRelayStateCompleteSet {
		t.Fatalf("unrelated set state=%v, want complete", got.state)
	}
	if state.pinnedPayloadBytes != keepPinned {
		t.Fatalf("pinned after consume=%d, want %d", state.pinnedPayloadBytes, keepPinned)
	}
}

func TestServiceConsumeAcceptedBlockDASetsRequiresCompleteAcceptedGroup(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(0x53)
	payload := []byte("partial-accepted-payload")
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload)), payload))

	block := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, daID, 1, payload),
	})
	if err := (&Service{daRelay: state}).ConsumeAcceptedBlockDASets(block); err != nil {
		t.Fatalf("ConsumeAcceptedBlockDASets: %v", err)
	}
	if got := state.sets[daID]; got.state != daRelayStateCompleteSet {
		t.Fatalf("partial accepted group consumed state=%v, want complete", got.state)
	}
}

func TestConsumeAcceptedBlockDASetsNilService(t *testing.T) {
	var svc *Service
	if err := svc.ConsumeAcceptedBlockDASets([]byte{0x00}); err == nil {
		t.Fatal("nil service returned nil error")
	}
}

func TestConsumeAcceptedBlockDASetsNilDARelay(t *testing.T) {
	svc := &Service{daRelay: nil}
	if err := svc.ConsumeAcceptedBlockDASets([]byte{0x00}); err == nil {
		t.Fatal("nil daRelay returned nil error")
	}
}

func TestConsumeAcceptedBlockDASetsMalformedBlock(t *testing.T) {
	svc := &Service{daRelay: newDARelayStateForTest(t, defaultDARelayCaps())}
	if err := svc.ConsumeAcceptedBlockDASets([]byte{0x01, 0x02}); err == nil {
		t.Fatal("malformed block via Service returned nil error")
	}
}

// stageCompleteDASet stages a relay-complete (single commit + full chunk set)
// DA record and returns block bytes carrying the same complete DA group.
func stageCompleteDASet(t *testing.T, state *daRelayState, daID [32]byte, peer string, payload []byte) []byte {
	t.Helper()
	mustAddDACommit(t, state, peer+"-commit", daRelayTestCommitForPayloads(daID, 1, payload))
	mustAddDAChunk(t, state, peer+"-chunk", daRelayTestChunkPayload(daID, 0, uint64(len(payload)), payload))
	return compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, daID, 1, payload),
		daChunkRelayTxBytes(t, daID, 0, 2, payload),
	})
}

func TestConsumeCanonicalAppliedDASetsDirectApplyConsumes(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(0x61)
	block := stageCompleteDASet(t, state, daID, "direct", []byte("direct-payload"))

	svc := &Service{daRelay: state}
	blocks := []node.CanonicalAppliedBlock{{
		Hash:          daRelayTestID(0xa0),
		CompleteDAIDs: mustParseCompleteDASetIDs(t, block),
	}}
	if err := svc.consumeCanonicalAppliedDASets(blocks); err != nil {
		t.Fatalf("consumeCanonicalAppliedDASets: %v", err)
	}
	if _, ok := state.sets[daID]; ok {
		t.Fatal("direct canonical apply did not consume the complete DA set")
	}
}

func TestConsumeCanonicalAppliedDASetsSideBranchDoesNotConsume(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(0x62)
	_ = stageCompleteDASet(t, state, daID, "side", []byte("side-payload"))

	svc := &Service{daRelay: state}
	// Non-switching side branch: SyncEngine reports nil CanonicalAppliedBlocks.
	if err := svc.consumeCanonicalAppliedDASets(nil); err != nil {
		t.Fatalf("consumeCanonicalAppliedDASets(nil): %v", err)
	}
	if got := state.sets[daID]; got.state != daRelayStateCompleteSet {
		t.Fatalf("side branch consumed DA set state=%v, want complete (untouched)", got.state)
	}
}

func TestConsumeCanonicalAppliedDASetsReorgConsumesAllBlocks(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	idA := daRelayTestID(0x63)
	idB := daRelayTestID(0x64)
	blockA := stageCompleteDASet(t, state, idA, "reorg-a", []byte("reorg-a-payload"))
	blockB := stageCompleteDASet(t, state, idB, "reorg-b", []byte("reorg-b-payload"))

	svc := &Service{daRelay: state}
	blocks := []node.CanonicalAppliedBlock{
		{Hash: daRelayTestID(0xa1), CompleteDAIDs: mustParseCompleteDASetIDs(t, blockA)},
		{Hash: daRelayTestID(0xb1), CompleteDAIDs: mustParseCompleteDASetIDs(t, blockB)},
	}
	if err := svc.consumeCanonicalAppliedDASets(blocks); err != nil {
		t.Fatalf("consumeCanonicalAppliedDASets: %v", err)
	}
	if _, ok := state.sets[idA]; ok {
		t.Fatal("reorg did not consume first canonical block's DA set")
	}
	if _, ok := state.sets[idB]; ok {
		t.Fatal("reorg did not consume second canonical block's DA set")
	}
}

// TestConsumeCanonicalAppliedDASetsSurfacesErrorAndContinues pins the failure
// contract of the hook that runs AFTER a canonical application has already
// committed (handlers_block.go noteAcceptedBlock): the first relay-accounting
// failure is reported and attributed to its block, later canonical blocks are
// still consumed, and the canonical-applied report itself is left untouched —
// nothing here can undo or rewrite what the apply committed.
func TestConsumeCanonicalAppliedDASetsSurfacesErrorAndContinues(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	goodID := daRelayTestID(0x65)
	badID := daRelayTestID(0x67)
	_ = stageCompleteDASet(t, state, goodID, "after-bad", []byte("after-bad"))
	pinnedGood := state.pinnedPayloadBytes
	_ = stageCompleteDASet(t, state, badID, "bad", []byte("a-strictly-longer-payload-than-the-good-one"))
	// Corrupt relay accounting so releasing badID underflows the pinned-payload
	// counter while releasing goodID still balances exactly.
	state.pinnedPayloadBytes = pinnedGood

	badHash := daRelayTestID(0xee)
	goodHash := daRelayTestID(0xcc)
	svc := &Service{daRelay: state}
	blocks := []node.CanonicalAppliedBlock{
		{Hash: badHash, CompleteDAIDs: [][32]byte{badID}},
		{Hash: goodHash, CompleteDAIDs: [][32]byte{goodID}},
	}
	err := svc.consumeCanonicalAppliedDASets(blocks)
	if err == nil {
		t.Fatal("relay accounting failure was swallowed (want visible error)")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%x", badHash)) {
		t.Fatalf("error %q does not identify failing block %x", err, badHash)
	}
	// Best-effort: the later canonical block is still consumed despite the
	// earlier error.
	if _, ok := state.sets[goodID]; ok {
		t.Fatal("best-effort consume skipped a valid canonical block after an earlier error")
	}
	want := []node.CanonicalAppliedBlock{
		{Hash: badHash, CompleteDAIDs: [][32]byte{badID}},
		{Hash: goodHash, CompleteDAIDs: [][32]byte{goodID}},
	}
	if !reflect.DeepEqual(blocks, want) {
		t.Fatal("consume mutated the canonical-applied report")
	}
}

func TestConsumeCanonicalAppliedDASetsNilRelayNoOp(t *testing.T) {
	// DA relay disabled: the hook must no-op (not error on every accepted block).
	svc := &Service{daRelay: nil}
	blocks := []node.CanonicalAppliedBlock{{Hash: daRelayTestID(0x66), CompleteDAIDs: [][32]byte{daRelayTestID(0x68)}}}
	if err := svc.consumeCanonicalAppliedDASets(blocks); err != nil {
		t.Fatalf("nil daRelay should no-op, got: %v", err)
	}
}

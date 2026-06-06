package p2p

import (
	"reflect"
	"testing"
)

func TestExtractAcceptedBlockDAIDsNoDA(t *testing.T) {
	block := compactTestBlockBytesWithTxs(t, [][]byte{minimalValidTxBytes(t)})

	got, err := extractAcceptedBlockDAIDs(block)
	if err != nil {
		t.Fatalf("extractAcceptedBlockDAIDs: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d DA ids, want none", len(got))
	}
}

func TestExtractAcceptedBlockDAIDsSingle(t *testing.T) {
	daID := daRelayTestID(0x41)
	payload := []byte("payload")
	block := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, daID, 1, payload),
		daChunkRelayTxBytes(t, daID, 0, 2, payload),
	})

	got, err := extractAcceptedBlockDAIDs(block)
	if err != nil {
		t.Fatalf("extractAcceptedBlockDAIDs: %v", err)
	}
	if !reflect.DeepEqual(got, [][32]byte{daID}) {
		t.Fatalf("got %x, want %x", got, [][32]byte{daID})
	}
}

func TestExtractAcceptedBlockDAIDsSorted(t *testing.T) {
	low := daRelayTestID(0x01)
	mid := daRelayTestID(0x7f)
	high := daRelayTestID(0xf0)
	lowPayload, midPayload, highPayload := []byte("low"), []byte("mid"), []byte("high")
	block := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, high, 1, highPayload),
		daChunkRelayTxBytes(t, high, 0, 2, highPayload),
		daCommitRelayTxBytes(t, low, 3, lowPayload),
		daChunkRelayTxBytes(t, low, 0, 4, lowPayload),
		daCommitRelayTxBytes(t, mid, 7, midPayload),
		daChunkRelayTxBytes(t, mid, 0, 8, midPayload),
	})

	got, err := extractAcceptedBlockDAIDs(block)
	if err != nil {
		t.Fatalf("extractAcceptedBlockDAIDs: %v", err)
	}
	want := [][32]byte{low, mid, high}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestExtractAcceptedBlockDAIDsMalformedBlock(t *testing.T) {
	_, err := extractAcceptedBlockDAIDs([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("malformed block returned nil error")
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

func TestAcceptedBlockDASetCompleteRejectsNonSingleCommit(t *testing.T) {
	s := acceptedBlockDASet{commitCount: 2, chunkCount: 1, chunks: map[uint16]struct{}{0: {}}}
	if s.complete() {
		t.Fatal("commitCount=2 accepted as complete")
	}
}

func TestAcceptedBlockDASetCompleteRejectsZeroChunks(t *testing.T) {
	s := acceptedBlockDASet{commitCount: 1, chunkCount: 0}
	if s.complete() {
		t.Fatal("chunkCount=0 accepted as complete")
	}
}

func TestAcceptedBlockDASetCompleteRejectsChunkCountMismatch(t *testing.T) {
	s := acceptedBlockDASet{commitCount: 1, chunkCount: 2, chunks: map[uint16]struct{}{0: {}}}
	if s.complete() {
		t.Fatal("chunk count mismatch accepted as complete")
	}
}

func TestConsumeAcceptedBlockDASetsMalformedBlock(t *testing.T) {
	svc := &Service{daRelay: newDARelayStateForTest(t, defaultDARelayCaps())}
	if err := svc.ConsumeAcceptedBlockDASets([]byte{0x01, 0x02}); err == nil {
		t.Fatal("malformed block via Service returned nil error")
	}
}

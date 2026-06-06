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

func TestExtractAcceptedBlockDAIDsSortedUnique(t *testing.T) {
	low := daRelayTestID(0x01)
	mid := daRelayTestID(0x7f)
	high := daRelayTestID(0xf0)
	lowPayload := []byte("low")
	midPayload := []byte("mid")
	highPayloadA := []byte("high-a")
	highPayloadB := []byte("high-b")
	block := compactTestBlockBytesWithTxs(t, [][]byte{
		minimalValidTxBytes(t),
		daCommitRelayTxBytes(t, high, 1, highPayloadA),
		daChunkRelayTxBytes(t, high, 0, 2, highPayloadA),
		daCommitRelayTxBytes(t, low, 3, lowPayload),
		daChunkRelayTxBytes(t, low, 0, 4, lowPayload),
		daCommitRelayTxBytes(t, high, 5, highPayloadB),
		daChunkRelayTxBytes(t, high, 0, 6, highPayloadB),
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

package node

import (
	"strings"
	"testing"
)

func TestGetParentTimestampAtHeightZero(t *testing.T) {
	s := &SyncEngine{blockStore: nil}
	ts, err := s.getParentTimestamp(0, [32]byte{})
	if err != nil || ts != 0 {
		t.Fatalf("expected (0, nil) at height=0, got (%d, %v)", ts, err)
	}
}

func TestParseAndValidateDisconnectBlockRejectsBadBlockBytes(t *testing.T) {
	_, _, err := parseAndValidateDisconnectBlock([]byte("not-a-block"), &BlockUndo{}, [32]byte{}, 0)
	if err == nil {
		t.Fatal("expected error for bad block bytes")
	}
}

func TestValidateMempoolEntryParsedRejectsBadRaw(t *testing.T) {
	entry := mempoolEntry{
		txid:  [32]byte{0x01},
		wtxid: [32]byte{0x01},
		raw:   []byte{},
		size:  1,
	}
	err := validateMempoolEntryParsed(entry)
	if err == nil || !strings.Contains(err.Error(), "invalid mempool snapshot entry raw") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestNoteBlockApplyNilReceiver(t *testing.T) {
	(*SyncEngine)(nil).noteBlockApplyAccepted()
	(*SyncEngine)(nil).noteBlockApplyAcceptedN(5)
	s := &SyncEngine{}
	s.noteBlockApplyAcceptedN(0)
	(*SyncEngine)(nil).noteBlockApplyRejected()
}

func TestNoteBlockApplyOutcome(t *testing.T) {
	s := &SyncEngine{}
	s.noteBlockApplyOutcome(blockApplyMetricNone)
	s.noteBlockApplyOutcome(blockApplyMetricAccepted)
	if s.blockApply.Accepted != 1 {
		t.Fatalf("expected Accepted=1, got %d", s.blockApply.Accepted)
	}
	s.noteBlockApplyOutcome(blockApplyMetricRejected)
	if s.blockApply.Rejected != 1 {
		t.Fatalf("expected Rejected=1, got %d", s.blockApply.Rejected)
	}
}

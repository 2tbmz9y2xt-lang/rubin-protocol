package node

import (
	"errors"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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

func TestNoteReorgNilReceiver(t *testing.T) {
	(*SyncEngine)(nil).noteReorg(3)
}

func TestFetchDisconnectBlockAndUndoWithMissingBlock(t *testing.T) {
	_, _, _, err := (&SyncEngine{blockStore: &BlockStore{}}).fetchDisconnectBlockAndUndo([32]byte{0xff})
	if err == nil {
		t.Fatal("expected error for missing block")
	}
}

func TestCurrentCanonicalTipNoTip(t *testing.T) {
	_, _, err := (&SyncEngine{blockStore: &BlockStore{}}).currentCanonicalTip()
	if err == nil || !strings.Contains(err.Error(), "no canonical tip") {
		t.Fatalf("expected no canonical tip error, got %v", err)
	}
}

func TestRecordAppliedBlock(t *testing.T) {
	s := &SyncEngine{}
	s.recordAppliedBlock(5, 1000)
	s.mu.RLock()
	if s.tipTimestamp != 1000 || s.bestKnownHeight != 5 || s.lastReorgDepth != 0 {
		t.Fatalf("recordAppliedBlock: ts=%d height=%d reorg=%d", s.tipTimestamp, s.bestKnownHeight, s.lastReorgDepth)
	}
	s.mu.RUnlock()
}

func TestStoreSideBlockAndSummaryRejectsEmptyBranch(t *testing.T) {
	bs := &BlockStore{}
	s := &SyncEngine{blockStore: bs, cfg: SyncConfig{}}
	_, err := s.storeSideBlockAndSummary(nil, 0, 1)
	if err == nil {
		t.Fatal("expected validation error for empty branch")
	}
}

func TestSideBranchPrevTimestampsRejectsNilStore(t *testing.T) {
	_, err := sideBranchPrevTimestamps(nil, []reorgBranchBlock{{}}, 0)
	if err == nil {
		t.Fatal("expected timestamp context error for nil blockstore")
	}
}

func TestValidateGenesisIdentityRejectsBadChainID(t *testing.T) {
	s := &SyncEngine{cfg: SyncConfig{ChainID: [32]byte{0x01}}}
	outcome, err := s.validateGenesisIdentity(0, devnetGenesisBlockHash)
	if err == nil || outcome != blockApplyMetricRejected {
		t.Fatalf("expected reject for non-devnet chain_id at height 0, got outcome=%v err=%v", outcome, err)
	}
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) || !strings.Contains(txErr.Msg, "chain_id") {
		t.Fatalf("expected chain_id TxError, got %v", err)
	}
}

func TestValidateGenesisIdentityRejectsBadGenesisHash(t *testing.T) {
	s := &SyncEngine{cfg: SyncConfig{ChainID: devnetGenesisChainID}}
	var badHash [32]byte
	badHash[0] = 0xff
	outcome, err := s.validateGenesisIdentity(0, badHash)
	if err == nil || outcome != blockApplyMetricRejected {
		t.Fatalf("expected reject for wrong genesis hash, got outcome=%v err=%v", outcome, err)
	}
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) || !strings.Contains(txErr.Msg, "genesis_hash") {
		t.Fatalf("expected genesis_hash TxError, got %v", err)
	}
}

func TestValidateGenesisIdentityPassesAtNonZeroHeight(t *testing.T) {
	s := &SyncEngine{cfg: SyncConfig{ChainID: [32]byte{0x01}}}
	outcome, err := s.validateGenesisIdentity(1, [32]byte{})
	if err != nil || outcome != blockApplyMetricNone {
		t.Fatalf("expected pass at height>0, got outcome=%v err=%v", outcome, err)
	}
}

func TestRestoreRollbackChainStateRejectsNil(t *testing.T) {
	s := &SyncEngine{}
	err := s.restoreRollbackChainState(syncRollbackState{})
	if err == nil || !strings.Contains(err.Error(), "nil chainstate destination") {
		t.Fatalf("expected nil chainstate error, got %v", err)
	}
}

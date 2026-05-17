package node

import (
	"errors"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

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

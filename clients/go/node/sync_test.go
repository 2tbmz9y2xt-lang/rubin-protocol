package node

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestSyncEngineIBDLogic(t *testing.T) {
	st := NewChainState()
	cfg := DefaultSyncConfig(nil, [32]byte{}, "")
	engine, err := NewSyncEngine(st, nil, cfg)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	if !engine.IsInIBD(1_000) {
		t.Fatalf("expected IBD when no tip")
	}

	st.HasTip = true
	st.Height = 10
	engine.tipTimestamp = 1_000
	engine.cfg.IBDLagSeconds = 100
	if !engine.IsInIBD(1_200) {
		t.Fatalf("expected IBD when lag exceeds threshold")
	}
	if engine.IsInIBD(1_050) {
		t.Fatalf("did not expect IBD when lag below threshold")
	}
}

func TestSyncEngineApplyBlockPersistsChainstateAndStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)
	store, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	st := NewChainState()
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(st, store, DefaultSyncConfig(&target, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	prev := mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111")
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, 1)
	block := buildSingleTxBlock(t, prev, target, 12345, coinbase)

	summary, err := engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("apply block: %v", err)
	}
	if summary.BlockHeight != 0 {
		t.Fatalf("block height=%d, want 0", summary.BlockHeight)
	}
	if _, err := os.Stat(chainStatePath); err != nil {
		t.Fatalf("chainstate file not persisted: %v", err)
	}

	loaded, err := LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("reload chainstate: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 0 {
		t.Fatalf("unexpected persisted chainstate: has_tip=%v height=%d", loaded.HasTip, loaded.Height)
	}

	height, _, ok, err := store.Tip()
	if err != nil {
		t.Fatalf("blockstore tip: %v", err)
	}
	if !ok || height != 0 {
		t.Fatalf("unexpected blockstore tip: ok=%v height=%d", ok, height)
	}
}

func TestSyncEngineApplyBlockNoMutationOnFailure(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := filepath.Join(dir, "chainstate.json")
	st := NewChainState()
	st.HasTip = true
	st.Height = 5
	st.TipHash = mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	st.AlreadyGenerated = 10
	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		Vout: 0,
	}] = consensus.UtxoEntry{
		Value:             1,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x22),
		CreationHeight:    1,
		CreatedByCoinbase: false,
	}

	engine, err := NewSyncEngine(st, nil, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}

	if _, err := engine.ApplyBlock([]byte{0x01, 0x02}, nil); err == nil {
		t.Fatalf("expected apply error")
	}
	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mutated on failed apply")
	}
}

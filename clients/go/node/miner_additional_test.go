package node

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestNewMinerSetsDefaultMaxTxPerBlockWhenNonPositive(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	cfg := DefaultMinerConfig()
	cfg.MaxTxPerBlock = 0
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}
	if miner.cfg.MaxTxPerBlock != 1024 {
		t.Fatalf("MaxTxPerBlock=%d, want 1024", miner.cfg.MaxTxPerBlock)
	}
}

func TestNewMinerRejectsNilChainState(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(NewChainState(), blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	if _, err := NewMiner(nil, blockStore, syncEngine, DefaultMinerConfig()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewMinerRejectsNilBlockStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	if _, err := NewMiner(chainState, nil, syncEngine, DefaultMinerConfig()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMinerMineNRejectsNegativeBlocks(t *testing.T) {
	var m Miner
	if _, err := m.MineN(context.Background(), -1, nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMinerMineOneRejectsUninitializedMiner(t *testing.T) {
	var m *Miner
	if _, err := m.MineOne(context.Background(), nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMinerMineOneReturnsContextError(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	miner, err := NewMiner(chainState, blockStore, syncEngine, DefaultMinerConfig())
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := miner.MineOne(ctx, nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMinerMineOneRejectsNonCanonicalTxBytesInInput(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	coinbaseLike, err := buildCoinbaseTx(0, [32]byte{})
	if err != nil {
		t.Fatalf("build coinbase tx: %v", err)
	}
	raw := append(append([]byte(nil), coinbaseLike...), 0x00)
	if _, err := miner.MineOne(context.Background(), [][]byte{raw}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMinerPolicyDropsCoreExtCreatePreActivation(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x21
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(1, nil), nil)

	mb, err := miner.MineOne(context.Background(), [][]byte{raw})
	if err != nil {
		t.Fatalf("mine one: %v", err)
	}
	if mb.TxCount != 1 {
		t.Fatalf("tx_count=%d, want 1 (policy should drop pre-activation CORE_EXT)", mb.TxCount)
	}
}

func TestMinerPolicyDisabledAllowsCoreExtTxAndBlockConnectFails(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	cfg := DefaultMinerConfig()
	cfg.PolicyRejectCoreExtPreActivation = false
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	var prev [32]byte
	prev[0] = 0x22
	raw := txWithOneInputOneOutput(prev, 0, 1, consensus.COV_TYPE_CORE_EXT, coreExtCovenantData(1, nil), nil)

	if _, err := miner.MineOne(context.Background(), [][]byte{raw}); err == nil {
		t.Fatalf("expected error (block should fail to connect without policy filter)")
	}
}

func TestChooseValidTimestampGenesisNowZeroReturnsOne(t *testing.T) {
	if got := chooseValidTimestamp(0, nil, 0); got != 1 {
		t.Fatalf("timestamp=%d, want 1", got)
	}
}

func TestChooseValidTimestampGenesisReturnsNow(t *testing.T) {
	if got := chooseValidTimestamp(0, nil, 123); got != 123 {
		t.Fatalf("timestamp=%d, want 123", got)
	}
}

func TestChooseValidTimestampUsesNowWhenWithinDrift(t *testing.T) {
	median := uint64(1_000)
	now := median + 1
	prev := []uint64{median}
	if got := chooseValidTimestamp(1, prev, now); got != now {
		t.Fatalf("timestamp=%d, want now=%d", got, now)
	}
}

func TestChooseValidTimestampReturnsMedianPlusOneWhenTooEarlyOrTooLate(t *testing.T) {
	median := uint64(1_000)
	prev := []uint64{median}
	if got := chooseValidTimestamp(1, prev, 0); got != median+1 {
		t.Fatalf("timestamp=%d, want %d", got, median+1)
	}
	if got := chooseValidTimestamp(1, prev, median+consensus.MAX_FUTURE_DRIFT+1); got != median+1 {
		t.Fatalf("timestamp=%d, want %d", got, median+1)
	}
}

func TestMtpMedianHandlesEmptyAndSorting(t *testing.T) {
	if got := mtpMedian(1, nil); got != 0 {
		t.Fatalf("median=%d, want 0", got)
	}
	if got := mtpMedian(5, []uint64{5, 1, 4, 2, 3}); got != 3 {
		t.Fatalf("median=%d, want 3", got)
	}
}

func TestMtpMedianUsesAvailableWindowWhenPrevShorterThanK(t *testing.T) {
	if got := mtpMedian(10, []uint64{3, 1, 2}); got != 2 {
		t.Fatalf("median=%d, want 2", got)
	}
}

func TestAppendCompactSizeMinerEncodesAllWidthBranches(t *testing.T) {
	cases := []struct {
		want     []byte
		value    uint64
		wantLen  int
		frontPad byte
	}{
		{value: 0xFC, want: []byte{0xFC}, wantLen: 1, frontPad: 0xAA},
		{value: 0xFD, want: []byte{0xFD, 0xFD, 0x00}, wantLen: 3, frontPad: 0xAB},
		{value: 0xFFFF, want: []byte{0xFD, 0xFF, 0xFF}, wantLen: 3, frontPad: 0xAC},
		{value: 0x1_0000, want: []byte{0xFE, 0x00, 0x00, 0x01, 0x00}, wantLen: 5, frontPad: 0xAD},
		{value: 0xFFFF_FFFF, want: []byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF}, wantLen: 5, frontPad: 0xAE},
		{value: 0x1_0000_0000, want: []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, wantLen: 9, frontPad: 0xAF},
	}
	for _, tc := range cases {
		dst := []byte{tc.frontPad}
		out := consensus.AppendCompactSize(dst, tc.value)
		if len(out) != 1+tc.wantLen {
			t.Fatalf("value=%d len=%d, want %d", tc.value, len(out), 1+tc.wantLen)
		}
		if out[0] != tc.frontPad {
			t.Fatalf("value=%d first_byte=%x, want %x", tc.value, out[0], tc.frontPad)
		}
		got := out[1:]
		if string(got) != string(tc.want) {
			t.Fatalf("value=%d got=%x want=%x", tc.value, got, tc.want)
		}
	}

	out32 := consensus.AppendCompactSize(nil, 0xA1B2C3D4)
	if len(out32) != 5 || out32[0] != 0xFE {
		t.Fatalf("unexpected 32-bit encoding: %x", out32)
	}
	if binary.LittleEndian.Uint32(out32[1:]) != 0xA1B2C3D4 {
		t.Fatalf("unexpected 32-bit le: %x", out32)
	}

	out64 := consensus.AppendCompactSize(nil, 0x0102030405060708)
	if len(out64) != 9 || out64[0] != 0xFF {
		t.Fatalf("unexpected 64-bit encoding: %x", out64)
	}
	if binary.LittleEndian.Uint64(out64[1:]) != 0x0102030405060708 {
		t.Fatalf("unexpected 64-bit le: %x", out64)
	}
}

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

	coinbaseLike, err := buildCoinbaseTx(0, 0, nil, [32]byte{})
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

func TestUpdatedPolicyDaBytes(t *testing.T) {
	cases := []struct {
		current uint64
		daBytes uint64
		max     uint64
		want    uint64
		ok      bool
	}{
		{current: 0, daBytes: 0, max: 10, want: 0, ok: true},
		{current: 4, daBytes: 3, max: 10, want: 7, ok: true},
		{current: 4, daBytes: 7, max: 10, want: 4, ok: false},
		{current: ^uint64(0), daBytes: 1, max: ^uint64(0), want: ^uint64(0), ok: false},
	}
	for _, tc := range cases {
		got, ok := updatedPolicyDaBytes(tc.current, tc.daBytes, tc.max)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("updatedPolicyDaBytes(%d,%d,%d)=(%d,%v), want (%d,%v)", tc.current, tc.daBytes, tc.max, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMinerBuildContextAndAssembleBlockBytes(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	chainState.HasTip = true
	chainState.Height = 7
	chainState.TipHash = [32]byte{0x44}
	blockStore, err := OpenBlockStore(BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := NewSyncEngine(chainState, blockStore, DefaultSyncConfig(nil, [32]byte{}, chainStatePath))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	cfg := DefaultMinerConfig()
	cfg.MaxTxPerBlock = 2
	miner, err := NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	txA, err := buildCoinbaseTx(0, 0, nil, [32]byte{})
	if err != nil {
		t.Fatalf("build txA: %v", err)
	}
	txB := append([]byte(nil), txA...)
	txC := append([]byte(nil), txA...)
	buildCtx, err := miner.buildContext([][]byte{txA, txB, txC})
	if err != nil {
		t.Fatalf("buildContext: %v", err)
	}
	if buildCtx.nextHeight != 8 {
		t.Fatalf("nextHeight=%d, want 8", buildCtx.nextHeight)
	}
	if buildCtx.prevHash != chainState.TipHash {
		t.Fatalf("prevHash mismatch")
	}
	if len(buildCtx.candidateTxs) != 1 {
		t.Fatalf("candidate count=%d, want 1", len(buildCtx.candidateTxs))
	}
	if buildCtx.remainingWeight == 0 {
		t.Fatalf("expected non-zero remaining weight")
	}

	header := make([]byte, consensus.BLOCK_HEADER_BYTES)
	coinbase := []byte{0xaa}
	parsed := []minedCandidate{{raw: []byte{0xbb}}, {raw: []byte{0xcc}}}
	block := assembleBlockBytes(header, coinbase, parsed)
	want := append(append(append(append([]byte{}, header...), 0x03), coinbase...), 0xbb, 0xcc)
	if string(block) != string(want) {
		t.Fatalf("assembled block mismatch: got=%x want=%x", block, want)
	}
}

func TestCanonicalCoinbaseWeightMatchesLegacyWeight(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		height           uint64
		alreadyGenerated uint64
		mineAddress      []byte
	}{
		{name: "genesis_anchor_only", height: 0, alreadyGenerated: 0, mineAddress: nil},
		{name: "subsidy_height", height: 1, alreadyGenerated: 0, mineAddress: testMineAddress(0x41)},
		{name: "later_height", height: 101, alreadyGenerated: 50 * consensus.BASE_UNITS_PER_RBN, mineAddress: testMineAddress(0x52)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := canonicalCoinbaseWeight(tc.height, tc.alreadyGenerated, tc.mineAddress)
			if err != nil {
				t.Fatalf("canonicalCoinbaseWeight: %v", err)
			}
			raw, err := buildCoinbaseTx(tc.height, tc.alreadyGenerated, tc.mineAddress, [32]byte{})
			if err != nil {
				t.Fatalf("buildCoinbaseTx: %v", err)
			}
			want, err := canonicalTxWeight(raw, "coinbase")
			if err != nil {
				t.Fatalf("canonicalTxWeight: %v", err)
			}
			if got != want {
				t.Fatalf("coinbase weight=%d, want %d", got, want)
			}
		})
	}
}

func TestCanonicalCoinbaseWeightRejectsOverflowAndInvalidAddress(t *testing.T) {
	t.Parallel()

	if _, err := canonicalCoinbaseWeight(^uint64(0), 0, nil); err == nil {
		t.Fatal("expected height overflow error")
	}
	if _, err := canonicalCoinbaseWeight(1, 0, nil); err == nil {
		t.Fatal("expected invalid mine address error")
	}
	tooLong := make([]byte, consensus.MAX_P2PK_COVENANT_DATA+1)
	tooLong[0] = consensus.SUITE_ID_ML_DSA_87
	if _, err := canonicalCoinbaseWeight(1, 0, tooLong); err == nil {
		t.Fatal("expected oversized mine address error")
	}
}

func TestCompactSizeLenForMinerCoversAllBranches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		value uint64
		want  uint64
	}{
		{value: 0, want: 1},
		{value: 0xfc, want: 1},
		{value: 0xfd, want: 3},
		{value: 0xffff, want: 3},
		{value: 0x1_0000, want: 5},
		{value: 0xffff_ffff, want: 5},
		{value: 0x1_0000_0000, want: 9},
	}
	for _, tc := range cases {
		if got := compactSizeLenForMiner(tc.value); got != tc.want {
			t.Fatalf("compactSizeLenForMiner(%d)=%d, want %d", tc.value, got, tc.want)
		}
	}
}

func TestPolicyNeedsReadonlyUtxoSnapshotMatrix(t *testing.T) {
	t.Parallel()

	var nilMiner *Miner
	if nilMiner.policyNeedsReadonlyUtxoSnapshot() {
		t.Fatal("nil miner should not require snapshot")
	}

	base := &Miner{cfg: DefaultMinerConfig()}
	if !base.policyNeedsReadonlyUtxoSnapshot() {
		t.Fatal("default miner should require snapshot")
	}

	disabled := &Miner{cfg: DefaultMinerConfig()}
	disabled.cfg.PolicyRejectCoreExtPreActivation = false
	disabled.cfg.PolicyDaAnchorAntiAbuse = false
	if disabled.policyNeedsReadonlyUtxoSnapshot() {
		t.Fatal("fully disabled policy matrix should not require snapshot")
	}

	coreExt := &Miner{cfg: DefaultMinerConfig()}
	coreExt.cfg.PolicyRejectCoreExtPreActivation = true
	if !coreExt.policyNeedsReadonlyUtxoSnapshot() {
		t.Fatal("core-ext policy should require snapshot")
	}

	da := &Miner{cfg: DefaultMinerConfig()}
	da.cfg.PolicyRejectCoreExtPreActivation = false
	da.cfg.PolicyDaAnchorAntiAbuse = true
	if !da.policyNeedsReadonlyUtxoSnapshot() {
		t.Fatal("da anchor policy should require snapshot")
	}

	da.cfg.PolicyDaSurchargePerByte = 1
	if !da.policyNeedsReadonlyUtxoSnapshot() {
		t.Fatal("da anchor surcharge path should require snapshot")
	}
}

func TestSnapshotBuildContextStateHandlesNilAndNoPolicyPaths(t *testing.T) {
	t.Parallel()

	var nilMiner *Miner
	if _, err := nilMiner.snapshotBuildContextState(); err == nil {
		t.Fatal("expected nil miner error")
	}

	minerWithNilState := &Miner{cfg: DefaultMinerConfig()}
	if _, err := minerWithNilState.snapshotBuildContextState(); err == nil {
		t.Fatal("expected nil chainstate error")
	}

	state := NewChainState()
	state.HasTip = true
	state.Height = 9
	state.TipHash = [32]byte{0x99}
	op := consensus.Outpoint{Txid: [32]byte{0x42}, Vout: 0}
	state.Utxos[op] = consensus.UtxoEntry{
		Value:             12,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x11),
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}

	miner := &Miner{chainState: state, cfg: DefaultMinerConfig()}
	snapshot, err := miner.snapshotBuildContextState()
	if err != nil {
		t.Fatalf("snapshotBuildContextState: %v", err)
	}
	if !snapshot.hasTip || snapshot.height != 9 || snapshot.tipHash != state.TipHash {
		t.Fatal("snapshot lost chainstate fields")
	}
	if snapshot.utxos == nil {
		t.Fatal("default policy path should copy utxo map")
	}
	miner.cfg.PolicyRejectCoreExtPreActivation = false
	miner.cfg.PolicyDaAnchorAntiAbuse = true
	snapshot, err = miner.snapshotBuildContextState()
	if err != nil {
		t.Fatalf("snapshotBuildContextState without surcharge: %v", err)
	}
	if snapshot.utxos == nil {
		t.Fatal("da anti-abuse path should still copy utxo map when surcharge is disabled")
	}
	miner.cfg.PolicyDaAnchorAntiAbuse = false
	snapshot, err = miner.snapshotBuildContextState()
	if err != nil {
		t.Fatalf("snapshotBuildContextState without policy snapshot: %v", err)
	}
	if snapshot.utxos != nil {
		t.Fatal("disabled policy path should not copy utxo map")
	}
}

func TestMinerBuildContextUtxoMapDoesNotAliasChainStateMap(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := ChainStatePath(dir)

	chainState := NewChainState()
	chainState.HasTip = true
	chainState.Height = 2
	var txid [32]byte
	txid[0] = 0x7a
	outpoint := consensus.Outpoint{Txid: txid, Vout: 1}
	chainState.Utxos[outpoint] = consensus.UtxoEntry{
		Value:             33,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x31),
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}

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

	buildCtx, err := miner.buildContext(nil)
	if err != nil {
		t.Fatalf("buildContext: %v", err)
	}
	delete(buildCtx.utxos, outpoint)
	if _, ok := chainState.Utxos[outpoint]; !ok {
		t.Fatal("buildContext utxo map aliases chainstate map")
	}
}

func TestParseCanonicalTx(t *testing.T) {
	raw, err := buildCoinbaseTx(0, 0, nil, [32]byte{})
	if err != nil {
		t.Fatalf("buildCoinbaseTx: %v", err)
	}
	tx, _, _, err := parseCanonicalTx(raw, "bad")
	if err != nil {
		t.Fatalf("parseCanonicalTx(valid): %v", err)
	}
	if tx == nil {
		t.Fatalf("expected parsed tx")
	}

	raw = append(raw, 0x00)
	if _, _, _, err := parseCanonicalTx(raw, "bad"); err == nil || err.Error() != "bad" {
		t.Fatalf("expected non-canonical parse error, got %v", err)
	}
}

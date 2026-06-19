package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestChainStateSaveLoadRoundTripDeterministic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chainstate.json")

	st := NewChainState()
	st.HasTip = true
	st.Height = 42
	st.AlreadyGenerated = 123_456
	st.TipHash = mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		Vout: 2,
	}] = consensus.UtxoEntry{
		Value:             100,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x55),
		CreationHeight:    8,
		CreatedByCoinbase: true,
	}
	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "0101010101010101010101010101010101010101010101010101010101010101"),
		Vout: 0,
	}] = consensus.UtxoEntry{
		Value:             7,
		CovenantType:      consensus.COV_TYPE_MULTISIG,
		CovenantData:      []byte{0x01, 0x01, 0x01, 0x01},
		CreationHeight:    3,
		CreatedByCoinbase: false,
	}

	if err := st.Save(path); err != nil {
		t.Fatalf("save chainstate: %v", err)
	}
	firstBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chainstate file: %v", err)
	}

	if err := st.Save(path); err != nil {
		t.Fatalf("save chainstate second time: %v", err)
	}
	secondBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chainstate file second time: %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("chainstate encoding is not deterministic")
	}

	var disk chainStateDisk
	if err := json.Unmarshal(firstBytes, &disk); err != nil {
		t.Fatalf("decode disk chainstate: %v", err)
	}
	if len(disk.Utxos) != 2 {
		t.Fatalf("disk utxos=%d, want 2", len(disk.Utxos))
	}
	if !slices.IsSortedFunc(disk.Utxos, func(a, b utxoDiskEntry) int {
		if a.Txid < b.Txid {
			return -1
		}
		if a.Txid > b.Txid {
			return 1
		}
		if a.Vout < b.Vout {
			return -1
		}
		if a.Vout > b.Vout {
			return 1
		}
		return 0
	}) {
		t.Fatalf("disk utxo order is not sorted")
	}

	loaded, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("load chainstate: %v", err)
	}
	if !equalChainState(st, loaded) {
		t.Fatalf("loaded chainstate mismatch")
	}
}

func TestChainStateSaveCreatesPrivateParentAndFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-parent", "chainstate.json")
	st := NewChainState()

	if err := st.Save(path); err != nil {
		t.Fatalf("save chainstate: %v", err)
	}

	assertNodePathMode(t, filepath.Dir(path), 0o700)
	assertNodePathMode(t, path, 0o600)

	loaded, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("load saved chainstate: %v", err)
	}
	if loaded.HasTip || loaded.Height != 0 || len(loaded.Utxos) != 0 {
		t.Fatalf("unexpected loaded empty chainstate: has_tip=%v height=%d utxos=%d", loaded.HasTip, loaded.Height, len(loaded.Utxos))
	}
}

func TestChainStateConnectBlockDeterministicUpdate(t *testing.T) {
	target := consensus.POW_LIMIT

	st := NewChainState()
	summary, err := st.ConnectBlock(devnetGenesisBlockBytes, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("connect genesis block: %v", err)
	}
	if summary.BlockHeight != 0 {
		t.Fatalf("genesis block height=%d, want 0", summary.BlockHeight)
	}
	if !st.HasTip || st.Height != 0 {
		t.Fatalf("unexpected tip after genesis: has_tip=%v height=%d", st.HasTip, st.Height)
	}
	if st.AlreadyGenerated != 0 {
		t.Fatalf("already_generated after height 0=%d, want 0", st.AlreadyGenerated)
	}
	if len(st.Utxos) == 0 {
		t.Fatalf("expected at least one utxo after genesis")
	}

	subsidy1 := consensus.BlockSubsidy(1, 0)
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1)
	block1 := buildSingleTxBlock(t, st.TipHash, target, 2, block1Coinbase)
	second, err := st.ConnectBlock(block1, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("connect height-1 block: %v", err)
	}
	if second.BlockHeight != 1 {
		t.Fatalf("second block height=%d, want 1", second.BlockHeight)
	}
	if st.Height != 1 {
		t.Fatalf("state height=%d, want 1", st.Height)
	}
	if st.AlreadyGenerated != subsidy1 {
		t.Fatalf("already_generated=%d, want %d", st.AlreadyGenerated, subsidy1)
	}
	if len(st.Utxos) != 2 {
		t.Fatalf("utxo_count=%d, want 2", len(st.Utxos))
	}
	_, coinbaseTxid, _, _, err := consensus.ParseTx(block1Coinbase)
	if err != nil {
		t.Fatalf("parse coinbase tx: %v", err)
	}
	entry, ok := st.Utxos[consensus.Outpoint{Txid: coinbaseTxid, Vout: 0}]
	if !ok {
		t.Fatalf("missing height-1 coinbase subsidy utxo")
	}
	if entry.CreationHeight != 1 {
		t.Fatalf("creation_height=%d, want 1", entry.CreationHeight)
	}
	if !entry.CreatedByCoinbase {
		t.Fatalf("expected coinbase flag on subsidy utxo")
	}
}

// E.8 surface-parity: pinned cross-client digest vectors. The genesis-only
// digest is also pinned in conformance/fixtures/CV-PV-*.json (expect_digest)
// and in the Rust ChainState test (GENESIS_ONLY_STATE_DIGEST_HEX), so a single
// hex string here keeps Go bit-identical with Rust. The empty-set digest is
// the bare SHA3-256 of DST || 0_u64_le and is exercised here to lock in the
// nil-receiver / fresh-state contract; any encoding drift would change it.
const (
	chainStateEmptyDigestHex       = "e0a6004258a669e1c7f1e12c1b249964e31ad956661237162a6d4daa22d39a6f"
	chainStateGenesisOnlyDigestHex = "8b172fb3a5e70b56de9ae78ce750c04eccbc4dd8b3be55751252e5a1b4f2e752"
)

func TestChainStateUtxoSetHashEmptyAndNilReceiver(t *testing.T) {
	emptyDigest := NewChainState().UtxoSetHash()
	if got := hex.EncodeToString(emptyDigest[:]); got != chainStateEmptyDigestHex {
		t.Fatalf("empty UTXO digest=%s, want %s", got, chainStateEmptyDigestHex)
	}

	var nilState *ChainState
	if nilState.UtxoSetHash() != emptyDigest {
		t.Fatalf("nil receiver must return empty-set digest")
	}
	if nilState.StateDigest() != emptyDigest {
		t.Fatalf("nil receiver StateDigest must return empty-set digest")
	}

	st := NewChainState()
	if st.StateDigest() != st.UtxoSetHash() {
		t.Fatalf("StateDigest must alias UtxoSetHash")
	}
}

func TestChainStateUtxoSetHashMatchesRustGenesisOnlyVector(t *testing.T) {
	target := consensus.POW_LIMIT
	st := NewChainState()
	if _, err := st.ConnectBlock(devnetGenesisBlockBytes, &target, nil, devnetGenesisChainID); err != nil {
		t.Fatalf("connect genesis block: %v", err)
	}
	digest := st.StateDigest()
	if got := hex.EncodeToString(digest[:]); got != chainStateGenesisOnlyDigestHex {
		t.Fatalf("genesis-only state_digest=%s, want %s (Rust parity)", got, chainStateGenesisOnlyDigestHex)
	}
	if st.UtxoSetHash() != digest {
		t.Fatalf("UtxoSetHash and StateDigest must agree")
	}
}

func TestChainStateUtxoSetHashIsDeterministicAndSensitiveToChange(t *testing.T) {
	st := NewChainState()
	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111"),
		Vout: 0,
	}] = consensus.UtxoEntry{
		Value:             42,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x11),
		CreationHeight:    5,
		CreatedByCoinbase: false,
	}

	first := st.UtxoSetHash()
	if first != st.UtxoSetHash() {
		t.Fatalf("UtxoSetHash must be idempotent on the same state")
	}

	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "2222222222222222222222222222222222222222222222222222222222222222"),
		Vout: 1,
	}] = consensus.UtxoEntry{
		Value:             7,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x22),
		CreationHeight:    6,
		CreatedByCoinbase: false,
	}
	second := st.UtxoSetHash()
	if first == second {
		t.Fatalf("adding a UTXO must change the digest")
	}
}

func TestChainStateConnectBlockAcceptsLocalGenesisWithConfiguredChainID(t *testing.T) {
	target := consensus.POW_LIMIT
	st := NewChainState()
	wroot, err := consensus.WitnessMerkleRootWtxids([][32]byte{{}})
	if err != nil {
		t.Fatalf("witness merkle root: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	block := buildSingleTxBlock(
		t,
		[32]byte{},
		target,
		2,
		coinbaseTxWithOutputs(0, []testOutput{
			{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
		}),
	)

	summary, err := st.ConnectBlock(block, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("connect local genesis block: %v", err)
	}
	if summary.BlockHeight != 0 {
		t.Fatalf("block height=%d, want 0", summary.BlockHeight)
	}
	if !st.HasTip || st.Height != 0 {
		t.Fatalf("unexpected tip after local genesis: has_tip=%v height=%d", st.HasTip, st.Height)
	}
	if st.TipHash == devnetGenesisBlockHash {
		t.Fatalf("local genesis unexpectedly matched embedded devnet genesis hash")
	}
}

func TestChainStateConnectBlockHeightZeroEnforcesExpectedTarget(t *testing.T) {
	target := consensus.POW_LIMIT
	wrongTarget := target
	wrongTarget[0] = 0x7f
	st := NewChainState()
	wroot, err := consensus.WitnessMerkleRootWtxids([][32]byte{{}})
	if err != nil {
		t.Fatalf("witness merkle root: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	block := buildSingleTxBlock(
		t,
		[32]byte{},
		target,
		2,
		coinbaseTxWithOutputs(0, []testOutput{
			{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
		}),
	)

	_, err = st.ConnectBlock(block, &wrongTarget, nil, devnetGenesisChainID)
	if err == nil {
		t.Fatalf("expected target mismatch")
	}
	var txErr *consensus.TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected consensus.TxError, got %T", err)
	}
	if txErr.Code != consensus.BLOCK_ERR_TARGET_INVALID {
		t.Fatalf("error code=%s, want %s", txErr.Code, consensus.BLOCK_ERR_TARGET_INVALID)
	}
}

func TestChainStateConnectBlockNoMutationOnFailure(t *testing.T) {
	st := NewChainState()
	st.HasTip = true
	st.Height = 3
	st.TipHash = mustHash32Hex(t, "2222222222222222222222222222222222222222222222222222222222222222")
	st.AlreadyGenerated = 77
	st.Utxos[consensus.Outpoint{
		Txid: mustHash32Hex(t, "3333333333333333333333333333333333333333333333333333333333333333"),
		Vout: 1,
	}] = consensus.UtxoEntry{
		Value:             9,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x21),
		CreationHeight:    2,
		CreatedByCoinbase: false,
	}

	before, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk before: %v", err)
	}

	var target [32]byte
	_, err = st.ConnectBlock([]byte{0x00, 0x01, 0x02}, &target, nil, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}

	after, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk after: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("chainstate mutated on failed connect")
	}
}

func TestLoadChainStateNotFoundReturnsEmpty(t *testing.T) {
	st, err := LoadChainState(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("load missing chainstate: %v", err)
	}
	if st == nil || st.Utxos == nil || len(st.Utxos) != 0 {
		t.Fatalf("unexpected missing-load state: %+v", st)
	}
}

func TestChainStateSuiteExposureQueriesByExplicitSuiteID(t *testing.T) {
	st := NewChainState()
	first := consensus.Outpoint{
		Txid: mustHash32Hex(t, "0303030303030303030303030303030303030303030303030303030303030303"),
		Vout: 2,
	}
	second := consensus.Outpoint{
		Txid: mustHash32Hex(t, "0101010101010101010101010101010101010101010101010101010101010101"),
		Vout: 0,
	}
	third := consensus.Outpoint{
		Txid: mustHash32Hex(t, "0202020202020202020202020202020202020202020202020202020202020202"),
		Vout: 1,
	}
	ignored := consensus.Outpoint{
		Txid: mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Vout: 9,
	}

	st.Utxos[first] = consensus.UtxoEntry{
		Value:             10,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x10),
		CreationHeight:    3,
		CreatedByCoinbase: false,
	}
	entry := consensus.UtxoEntry{
		Value:             11,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testP2PKCovenantData(0x11),
		CreationHeight:    4,
		CreatedByCoinbase: false,
	}
	entry.CovenantData[0] = 0x42
	st.Utxos[second] = entry
	st.Utxos[third] = entry
	st.Utxos[ignored] = consensus.UtxoEntry{
		Value:             7,
		CovenantType:      consensus.COV_TYPE_HTLC,
		CovenantData:      make([]byte, consensus.MAX_HTLC_COVENANT_DATA),
		CreationHeight:    5,
		CreatedByCoinbase: false,
	}

	if got := st.IndexedSuiteIDs(); !reflect.DeepEqual(got, []uint8{consensus.SUITE_ID_ML_DSA_87, 0x42}) {
		t.Fatalf("indexed suite ids=%v", got)
	}
	if got := st.UtxoExposureCountBySuiteID(0x42); got != 2 {
		t.Fatalf("suite 0x42 exposure=%d, want 2", got)
	}
	gotOutpoints := st.UtxoOutpointsBySuiteID(0x42)
	wantOutpoints := []consensus.Outpoint{second, third}
	if !reflect.DeepEqual(gotOutpoints, wantOutpoints) {
		t.Fatalf("suite 0x42 outpoints=%v, want %v", gotOutpoints, wantOutpoints)
	}
	if got := st.UtxoExposureCountBySuiteID(0x99); got != 0 {
		t.Fatalf("suite 0x99 exposure=%d, want 0", got)
	}
}

func equalChainState(a, b *ChainState) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.HasTip != b.HasTip ||
		a.Height != b.Height ||
		a.TipHash != b.TipHash ||
		a.AlreadyGenerated != b.AlreadyGenerated ||
		len(a.Utxos) != len(b.Utxos) {
		return false
	}
	for op, ae := range a.Utxos {
		be, ok := b.Utxos[op]
		if !ok {
			return false
		}
		if ae.Value != be.Value ||
			ae.CovenantType != be.CovenantType ||
			ae.CreationHeight != be.CreationHeight ||
			ae.CreatedByCoinbase != be.CreatedByCoinbase ||
			!bytes.Equal(ae.CovenantData, be.CovenantData) {
			return false
		}
	}
	return true
}

type testOutput struct {
	covenantData []byte
	value        uint64
	covenantType uint16
}

func buildSingleTxBlock(t *testing.T, prevHash [32]byte, target [32]byte, timestamp uint64, tx []byte) []byte {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(tx)
	if err != nil {
		t.Fatalf("parse tx: %v", err)
	}
	root, err := consensus.MerkleRootTxids([][32]byte{txid})
	if err != nil {
		t.Fatalf("merkle root: %v", err)
	}
	header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
	header = consensus.AppendU32le(header, 1)
	header = append(header, prevHash[:]...)
	header = append(header, root[:]...)
	header = consensus.AppendU64le(header, timestamp)
	header = append(header, target[:]...)
	header = consensus.AppendU64le(header, 7)

	block := make([]byte, 0, len(header)+len(tx)+4)
	block = append(block, header...)
	block = consensus.AppendCompactSize(block, 1)
	block = append(block, tx...)
	return block
}

func coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t *testing.T, height uint64, value uint64) []byte {
	t.Helper()
	wtxids := [][32]byte{{}}
	wroot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		t.Fatalf("witness merkle root: %v", err)
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: consensus.COV_TYPE_P2PK, covenantData: testP2PKCovenantData(0x11)},
		{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
	})
}

func coinbaseTxWithOutputs(locktime uint32, outputs []testOutput) []byte {
	sizeHint := 128
	for _, out := range outputs {
		sizeHint += 16 + len(out.covenantData)
	}
	b := make([]byte, 0, sizeHint)
	b = consensus.AppendU32le(b, 1)
	b = append(b, 0x00)
	b = consensus.AppendU64le(b, 0)
	b = consensus.AppendCompactSize(b, 1)
	b = append(b, make([]byte, 32)...)
	b = consensus.AppendU32le(b, ^uint32(0))
	b = consensus.AppendCompactSize(b, 0)
	b = consensus.AppendU32le(b, ^uint32(0))
	b = consensus.AppendCompactSize(b, uint64(len(outputs)))
	for _, out := range outputs {
		b = consensus.AppendU64le(b, out.value)
		b = consensus.AppendU16le(b, out.covenantType)
		b = consensus.AppendCompactSize(b, uint64(len(out.covenantData)))
		b = append(b, out.covenantData...)
	}
	b = consensus.AppendU32le(b, locktime)
	b = consensus.AppendCompactSize(b, 0)
	b = consensus.AppendCompactSize(b, 0)
	return b
}

func testP2PKCovenantData(seed byte) []byte {
	data := make([]byte, consensus.MAX_P2PK_COVENANT_DATA)
	data[0] = consensus.SUITE_ID_ML_DSA_87
	for i := 1; i < len(data); i++ {
		data[i] = seed + byte(i)
	}
	return data
}

func mustHash32Hex(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hash hex: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("hash length=%d, want 32", len(b))
	}
	copy(out[:], b)
	return out
}

// TestChainStateConnectBlockParallelSigs exercises the ConnectBlockParallelSigs
// method on ChainState, ensuring it produces identical results to ConnectBlock
// for the genesis block and a coinbase-only follow-up block.
func TestChainStateConnectBlockParallelSigs(t *testing.T) {
	target := consensus.POW_LIMIT

	// Sequential path: connect genesis + one block.
	seqSt := NewChainState()
	seqGenesis, err := seqSt.ConnectBlock(devnetGenesisBlockBytes, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("seq connect genesis: %v", err)
	}

	subsidy1 := consensus.BlockSubsidy(1, 0)
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1)
	block1 := buildSingleTxBlock(t, seqSt.TipHash, target, 2, block1Coinbase)
	seqBlock1, err := seqSt.ConnectBlock(block1, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("seq connect block 1: %v", err)
	}

	// Parallel path: connect genesis + same block.
	parSt := NewChainState()
	parGenesis, err := parSt.ConnectBlockParallelSigs(devnetGenesisBlockBytes, &target, nil, devnetGenesisChainID, nil, 4)
	if err != nil {
		t.Fatalf("par connect genesis: %v", err)
	}
	if seqGenesis.BlockHeight != parGenesis.BlockHeight {
		t.Fatalf("genesis height mismatch: seq=%d par=%d", seqGenesis.BlockHeight, parGenesis.BlockHeight)
	}

	parBlock1, err := parSt.ConnectBlockParallelSigs(block1, &target, nil, devnetGenesisChainID, nil, 4)
	if err != nil {
		t.Fatalf("par connect block 1: %v", err)
	}

	// Compare results.
	if seqBlock1.SumFees != parBlock1.SumFees {
		t.Fatalf("SumFees mismatch: seq=%d par=%d", seqBlock1.SumFees, parBlock1.SumFees)
	}
	if seqBlock1.AlreadyGenerated != parBlock1.AlreadyGenerated {
		t.Fatalf("AlreadyGenerated mismatch: seq=%d par=%d", seqBlock1.AlreadyGenerated, parBlock1.AlreadyGenerated)
	}
	if seqBlock1.AlreadyGeneratedN1 != parBlock1.AlreadyGeneratedN1 {
		t.Fatalf("AlreadyGeneratedN1 mismatch: seq=%d par=%d", seqBlock1.AlreadyGeneratedN1, parBlock1.AlreadyGeneratedN1)
	}
	if seqBlock1.UtxoCount != parBlock1.UtxoCount {
		t.Fatalf("UtxoCount mismatch: seq=%d par=%d", seqBlock1.UtxoCount, parBlock1.UtxoCount)
	}

	// State must match.
	if seqSt.Height != parSt.Height {
		t.Fatalf("height mismatch: seq=%d par=%d", seqSt.Height, parSt.Height)
	}
	if seqSt.AlreadyGenerated != parSt.AlreadyGenerated {
		t.Fatalf("already_generated mismatch: seq=%d par=%d", seqSt.AlreadyGenerated, parSt.AlreadyGenerated)
	}
	if len(seqSt.Utxos) != len(parSt.Utxos) {
		t.Fatalf("utxo count mismatch: seq=%d par=%d", len(seqSt.Utxos), len(parSt.Utxos))
	}
}

// TestChainStateConnectBlockParallelSigs_NilState checks that nil receiver is rejected.
func TestChainStateConnectBlockParallelSigs_NilState(t *testing.T) {
	var st *ChainState
	_, err := st.ConnectBlockParallelSigs(nil, nil, nil, [32]byte{}, nil, 0)
	if err == nil {
		t.Fatal("expected error for nil chainstate")
	}
}

// TestChainStateConnectBlockParallelSigs_InvalidBlock checks error propagation.
func TestChainStateConnectBlockParallelSigs_InvalidBlock(t *testing.T) {
	target := consensus.POW_LIMIT
	st := NewChainState()
	_, err := st.ConnectBlockParallelSigs([]byte{0x00}, &target, nil, [32]byte{}, nil, 1)
	if err == nil {
		t.Fatal("expected error for invalid block")
	}
}

// TestChainState_RotationOrNil_ReturnsNilWhenNotSet verifies that nil Rotation
// is passed through as nil (consensus internally fallbacks to DefaultRotationProvider).
func TestChainState_RotationOrNil_ReturnsNilWhenNotSet(t *testing.T) {
	st := NewChainState()
	rot := st.rotationOrNil()
	if rot != nil {
		t.Fatal("rotationOrNil must return nil when Rotation not set")
	}
}

// TestChainState_RotationOrDefault_UsesStored verifies that a non-nil
// Rotation field is used instead of the default.
func TestChainState_RotationOrDefault_UsesStored(t *testing.T) {
	st := NewChainState()
	// Create a rotation provider that sunsets ML-DSA-87 at height 10
	registry := consensus.NewSuiteRegistryFromParams([]consensus.SuiteParams{
		{SuiteID: consensus.SUITE_ID_ML_DSA_87, PubkeyLen: consensus.ML_DSA_87_PUBKEY_BYTES, SigLen: consensus.ML_DSA_87_SIG_BYTES, VerifyCost: consensus.VERIFY_COST_ML_DSA_87},
		{SuiteID: 0x02, PubkeyLen: 32, SigLen: 64, VerifyCost: 100},
	})
	desc := consensus.CryptoRotationDescriptor{
		Name:         "test-sunset",
		OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x02,
		CreateHeight: 1,
		SpendHeight:  5,
		SunsetHeight: 10,
	}
	if err := desc.Validate(registry); err != nil {
		t.Fatalf("descriptor validation: %v", err)
	}
	st.Rotation = consensus.DescriptorRotationProvider{Descriptor: desc}

	rot := st.rotationOrNil()
	// At height 15 (after sunset), ML-DSA-87 should NOT be in spend set
	suites := rot.NativeSpendSuites(15)
	if suites.Contains(consensus.SUITE_ID_ML_DSA_87) {
		t.Fatal("ML-DSA-87 should be sunset at height 15")
	}
}

// TestChainState_RegistryOrNil_ReturnsNilWhenNotSet verifies nil Registry
// is passed through as nil (consensus internally fallbacks to DefaultSuiteRegistry).
func TestChainState_RegistryOrNil_ReturnsNilWhenNotSet(t *testing.T) {
	st := NewChainState()
	reg := st.registryOrNil()
	if reg != nil {
		t.Fatal("registryOrNil must return nil when Registry not set")
	}
}

// TestChainState_RegistryOrDefault_UsesStored verifies that a non-nil
// Registry field is used instead of the default.
func TestChainState_RegistryOrDefault_UsesStored(t *testing.T) {
	st := NewChainState()
	customRegistry := consensus.NewSuiteRegistryFromParams([]consensus.SuiteParams{
		{SuiteID: 0x42, PubkeyLen: 32, SigLen: 64, VerifyCost: 100},
	})
	st.Registry = customRegistry
	reg := st.registryOrNil()
	if _, ok := reg.Lookup(0x42); !ok {
		t.Fatal("stored registry must be used")
	}
	if _, ok := reg.Lookup(consensus.SUITE_ID_ML_DSA_87); ok {
		t.Fatal("default ML-DSA-87 must NOT be in custom registry")
	}
}

// TestChainState_ConnectBlock_DefaultRotation_StillWorks is a regression test
// confirming that ChainState without explicit rotation connects blocks normally.
func TestChainState_ConnectBlock_DefaultRotation_StillWorks(t *testing.T) {
	target := consensus.POW_LIMIT
	st := NewChainState()
	// No Rotation or Registry set — defaults should be used
	_, err := st.ConnectBlock(devnetGenesisBlockBytes, &target, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("connect genesis with default rotation: %v", err)
	}
	if !st.HasTip || st.Height != 0 {
		t.Fatalf("unexpected state after genesis: has_tip=%v height=%d", st.HasTip, st.Height)
	}
}

// TestWriteFileAtomicDurablyPersistsFreshFile is the Go-side smoke test for
// the E.1 durability contract: a fresh write goes through OpenFile + Sync +
// Rename + parent dir Sync without surfacing an error on a real filesystem,
// and the resulting bytes are exactly what we wrote. We cannot directly
// observe the fsync syscall from a unit test, but this DOES regression-guard
// the OpenFile/Sync/Rename chain returning an error on the platforms that
// run CI (Linux/macOS).
func TestWriteFileAtomicDurablyPersistsFreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	data := []byte("E.1 fsync contract: bytes + dir entry must both be durable")

	if err := writeFileAtomic(path, data, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("payload mismatch: got %q want %q", got, data)
	}
}

// TestWriteFileAtomicReplacesExistingFileWithNewDurableBytes verifies the
// dominant chainstate/blockstore path: rewriting the index file on every
// commit must atomically replace it AND leave no stale .tmp.* sibling
// behind once the rename succeeds.
func TestWriteFileAtomicReplacesExistingFileWithNewDurableBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.json")

	if err := writeFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, []byte("second")) {
		t.Fatalf("payload mismatch: got %q want %q", got, "second")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.Contains(name, ".tmp.") {
			t.Fatalf("stale tmp file remained after rename: %s", name)
		}
	}
}

// TestSyncDirSucceedsOnExistingDirectory pins the standalone helper:
// storage callers may want to fsync ad-hoc directory mutations (for example
// after deleting a stale undo file) without going through writeFileAtomic.
func TestSyncDirSucceedsOnExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := syncDir(dir); err != nil {
		t.Fatalf("syncDir on existing directory: %v", err)
	}
}

// TestSyncDirFailsOnMissingDirectory exercises the error path of syncDir
// (os.Open returns an error). Without this the durability helper's failure
// mode is silent under coverage.
func TestSyncDirFailsOnMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-subdir")
	if err := syncDir(missing); err == nil {
		t.Fatalf("syncDir on missing dir: expected error, got nil")
	}
}

// Permission-based tests that rely on os.Geteuid() (Unix-only) live in
// chainstate_fsync_unix_test.go behind a `//go:build unix` tag so this
// file still compiles under GOOS=windows (Copilot review feedback on
// PR #1218).

// TestAllocateAndWriteTemp_RetriesOnStaleTemp exercises the stale-temp
// collision retry path added for Copilot P1 on PR #1220. Pre-create a
// stale `.tmp.<pid>.<seq>` at the next-expected seq, verify the
// allocator returns a DIFFERENT path on success, and verify the stale
// file was NOT truncated.
func TestAllocateAndWriteTemp_RetriesOnStaleTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.bin")

	staleSeq := nextTempSeq() + 1
	staleTmp := tempPathFor(path, os.Getpid(), staleSeq)
	staleBytes := []byte("stale - must survive")
	if err := os.WriteFile(staleTmp, staleBytes, 0o600); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	// Counter is already at staleSeq-1 after the `nextTempSeq()+1`
	// probe above; the next nextTempSeq() call (first allocator attempt)
	// returns staleSeq and triggers the O_EXCL AlreadyExists branch.
	// Do NOT spin a `for nextTempSeq() < staleSeq-1 {}` loop — the
	// condition itself calls nextTempSeq() and advances the counter,
	// which can overshoot staleSeq-1 and skip the collision path.

	payload := []byte("new payload")
	got, err := allocateAndWriteTemp(path, payload, 0o600)
	if err != nil {
		t.Fatalf("allocateAndWriteTemp: %v", err)
	}
	if got == staleTmp {
		t.Fatalf("allocator returned stale path %q — O_EXCL retry bypassed", got)
	}
	gotBytes, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("read allocated temp: %v", err)
	}
	if !bytes.Equal(gotBytes, payload) {
		t.Fatalf("allocated temp content mismatch")
	}
	gotStale, err := os.ReadFile(staleTmp)
	if err != nil {
		t.Fatalf("read stale after: %v", err)
	}
	if !bytes.Equal(gotStale, staleBytes) {
		t.Fatalf("stale temp was mutated — O_EXCL retry path broken")
	}
	_ = os.Remove(got)
}

// TestAllocateAndWriteTemp_ExhaustsRetries pre-creates stale files at
// every seq the allocator would hit within maxTempAllocRetries, so
// every attempt collides and the function must surface the
// collision error rather than silently succeed.
func TestAllocateAndWriteTemp_ExhaustsRetries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exhausted.bin")

	baseSeq := nextTempSeq() + 1
	var created []string
	for i := 0; i < maxTempAllocRetries; i++ {
		stale := tempPathFor(path, os.Getpid(), baseSeq+uint64(i))
		if err := os.WriteFile(stale, []byte("blocker"), 0o600); err != nil {
			t.Fatalf("seed stale #%d: %v", i, err)
		}
		created = append(created, stale)
	}
	// Counter is already at baseSeq-1 after the `nextTempSeq()+1`
	// probe above; the next nextTempSeq() call (first allocator attempt)
	// returns baseSeq, which is the first seeded stale path.

	_, err := allocateAndWriteTemp(path, []byte("data"), 0o600)
	if err == nil {
		t.Fatalf("expected exhaustion error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") &&
		!strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, stale := range created {
		_ = os.Remove(stale)
	}
}

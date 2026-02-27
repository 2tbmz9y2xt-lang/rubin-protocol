package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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

func TestChainStateConnectBlockDeterministicUpdate(t *testing.T) {
	target := consensus.POW_LIMIT
	var chainID [32]byte

	st := NewChainState()
	genesisPrev := mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111")
	genesisCoinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, 1)
	genesisBlock := buildSingleTxBlock(t, genesisPrev, target, 1, genesisCoinbase)

	first, err := st.ConnectBlock(genesisBlock, &target, nil, chainID)
	if err != nil {
		t.Fatalf("connect genesis-like block: %v", err)
	}
	if first.BlockHeight != 0 {
		t.Fatalf("first block height=%d, want 0", first.BlockHeight)
	}
	if !st.HasTip || st.Height != 0 {
		t.Fatalf("unexpected tip after first block: has_tip=%v height=%d", st.HasTip, st.Height)
	}
	if st.AlreadyGenerated != 0 {
		t.Fatalf("already_generated after height 0=%d, want 0", st.AlreadyGenerated)
	}
	if len(st.Utxos) != 1 {
		t.Fatalf("utxo_count after first block=%d, want 1", len(st.Utxos))
	}

	subsidy1 := consensus.BlockSubsidy(1, 0)
	block1Coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, subsidy1)
	block1 := buildSingleTxBlock(t, st.TipHash, target, 2, block1Coinbase)
	second, err := st.ConnectBlock(block1, &target, nil, chainID)
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

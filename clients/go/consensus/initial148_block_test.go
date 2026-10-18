package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"testing"
)

// The complete genesis block literal is copied unchanged from
// rubin-spec@2a30f15bbc4868f46fb7ccba9c776c80624159ad
// spec/DEVNET_GENESIS_BYTES.json (genesis_block_bytes_hex). It is an independent
// source fixture, not an encoder output.
const (
	initial148GenesisBlockHex =
		"0100000000000000000000000000000000000000000000000000000000000000" +
		"000000006f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd40" +
		"6f2df91340e49e6900000000ffffffffffffffffffffffffffffffffffffffff" +
		"ffffffffffffffffffffffffc53b167dd819e13c2442bde23729bfe6c09d8996" +
		"24ebaf7e98e0bb44466c694b0000000000000000010100000000000000000000" +
		"0000010000000000000000000000000000000000000000000000000000000000" +
		"000000ffffffff00ffffffff0200407a10f35a0000000021018448b91b88d1a6" +
		"fbb65e872b72c381b2a9f3ce286a232f56309667f639dd727900000000000000" +
		"00020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34c" +
		"f37071a8000000000000"
	initial148GenesisHashHex  = "f063746adc88e7f7b63edc754fc76ccc9db96f9e08f3a09697e125b453421f30"
	initial148GenesisTxidHex  = "f726016007c9e0c47c2ed35f66dcace4e5a2b6fd39a97bec14e8e1967850854f"
	initial148GenesisWtxidHex = "87ff6b7be293dd45447f082405fb2a1f23c4262a03362e7ac46a0982e5c09aac"
	initial148GenesisMerkleHex = "6f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd406f2df913"
	initial148GenesisRootHex   = "c53b167dd819e13c2442bde23729bfe6c09d899624ebaf7e98e0bb44466c694b"
	initial148DAHashHex        = "521ec18851e17bbba961bc46c70baf03ee67ebdea11a8306de39c15a90e9d2e5"
)

const initial148GenesisTimestamp = 1_772_020_800

// initial148BlockHead is a fixture header assembled byte-for-byte, never through
// the production initial148 encoder.
type initial148BlockHead struct {
	version       uint32
	parent        [32]byte
	merkle        [32]byte
	target        [32]byte
	root          [32]byte
	timestamp     uint64
	nonce         uint64
}

func initial148BlockHeaderBytes(h initial148BlockHead) []byte {
	b := make([]byte, 0, Initial148HeaderBytes)
	var word [8]byte
	binary.LittleEndian.PutUint32(word[:4], h.version)
	b = append(b, word[:4]...)
	b = append(b, h.parent[:]...)
	b = append(b, h.merkle[:]...)
	binary.LittleEndian.PutUint64(word[:], h.timestamp)
	b = append(b, word[:]...)
	b = append(b, h.target[:]...)
	b = append(b, h.root[:]...)
	binary.LittleEndian.PutUint64(word[:], h.nonce)
	return append(b, word[:]...)
}

// initial148BlockTaggedRoot is the written pairwise tagged Merkle rule: an odd
// node is promoted unchanged.
func initial148BlockTaggedRoot(ids [][32]byte, leafTag, nodeTag byte) [32]byte {
	level := make([][32]byte, len(ids))
	for i, id := range ids {
		leaf := make([]byte, 33)
		leaf[0] = leafTag
		copy(leaf[1:], id[:])
		level[i] = sha3.Sum256(leaf)
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			node := make([]byte, 65)
			node[0] = nodeTag
			copy(node[1:], level[i][:])
			copy(node[33:], level[i+1][:])
			next = append(next, sha3.Sum256(node))
		}
		level = next
	}
	return level[0]
}

func initial148BlockTxIDs(t *testing.T, txs [][]byte) [][32]byte {
	t.Helper()
	txids := make([][32]byte, 0, len(txs))
	for _, tx := range txs {
		_, txid, _, _, err := ParseTx(tx)
		if err != nil {
			t.Fatalf("initial148 fixture ParseTx: %v", err)
		}
		txids = append(txids, txid)
	}
	return txids
}

// initial148BlockWitnessCommit is the written tagged witness root over a zero
// first wtxid, then the production-independent commitment prefix.
func initial148BlockWitnessCommit(t *testing.T, nonCoinbase ...[]byte) [32]byte {
	t.Helper()
	wtxids := [][32]byte{{}}
	for _, txb := range nonCoinbase {
		_, _, wtxid, _, err := ParseTx(txb)
		if err != nil {
			t.Fatalf("initial148 fixture ParseTx: %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}
	wroot := initial148BlockTaggedRoot(wtxids, 0x02, 0x03)
	return sha3.Sum256(append([]byte("RUBIN-WITNESS/"), wroot[:]...))
}

func initial148BlockCoinbase(t *testing.T, nonCoinbase ...[]byte) []byte {
	t.Helper()
	commit := initial148BlockWitnessCommit(t, nonCoinbase...)
	return coinbaseTxWithOutputs(0, []testOutput{{covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]}})
}

// initial148BlockMine creates header bytes satisfying the fixture target with a
// direct SHA3 comparison; the production PoW primitive is not the fixture oracle.
func initial148BlockMine(t *testing.T, h initial148BlockHead) []byte {
	t.Helper()
	target := new(big.Int).SetBytes(h.target[:])
	for nonce := uint64(0); nonce < 1<<20; nonce++ {
		h.nonce = nonce
		raw := initial148BlockHeaderBytes(h)
		digest := sha3.Sum256(raw)
		if new(big.Int).SetBytes(digest[:]).Cmp(target) < 0 {
			return raw
		}
	}
	t.Fatal("initial148 fixture: no nonce satisfies the target")
	return nil
}

// initial148BlockFrame assembles a complete fixed148 frame over txs. The header
// Merkle root comes from the written tagged rule over ParseTx ids.
func initial148BlockFrame(t *testing.T, txs [][]byte, edit func(*initial148BlockHead)) []byte {
	t.Helper()
	txids := initial148BlockTxIDs(t, txs)
	h := initial148BlockHead{version: 1, parent: blockStepsParent, merkle: initial148BlockTaggedRoot(txids, 0x00, 0x01), target: POW_LIMIT, timestamp: blockStepsMedian + 1}
	if edit != nil {
		edit(&h)
	}
	raw := append([]byte(nil), initial148BlockMine(t, h)...)
	raw = AppendCompactSize(raw, uint64(len(txs)))
	for _, tx := range txs {
		raw = append(raw, tx...)
	}
	return raw
}

func initial148BlockGenesis(t *testing.T) []byte {
	t.Helper()
	raw := initial148Hex(t, initial148GenesisBlockHex)
	if len(raw) != 298 {
		t.Fatalf("initial148 genesis literal length=%d want=298", len(raw))
	}
	return raw
}

func initial148BlockGenesisTx(t *testing.T) []byte {
	t.Helper()
	raw := initial148BlockGenesis(t)
	if raw[148] != 0x01 {
		t.Fatalf("initial148 genesis count=%x want=01", raw[148])
	}
	tx := raw[149:]
	if len(tx) != 149 {
		t.Fatalf("initial148 genesis tx length=%d want=149", len(tx))
	}
	return bytes.Clone(tx)
}

func initial148BlockWantError(t *testing.T, label string, err error, code ErrorCode, msg string) {
	t.Helper()
	te, direct := err.(*TxError)
	if !direct || te == nil || te.Code != code || te.Msg != msg || te.Cause() != TxErrorCause(0) || te.Error() != string(code)+": "+msg {
		t.Fatalf("%s: got %T %v, want direct (%s,%q,0)", label, err, err, code, msg)
	}
}

func initial148BlockParserRefusal(t *testing.T, label string, raw []byte, code ErrorCode, msg string) {
	t.Helper()
	before := bytes.Clone(raw)
	parsed, err := ParseInitial148BlockBytes(raw)
	if parsed != nil {
		t.Fatalf("%s: parsed=%+v want nil", label, parsed)
	}
	initial148BlockWantError(t, label, err, code, msg)
	initial148Unchanged(t, raw, before)
}

func initial148BlockBodyRefusal(t *testing.T, label string, raw []byte, code ErrorCode, msg string) {
	t.Helper()
	before := bytes.Clone(raw)
	initial148BlockWantError(t, label, ValidateInitial148BlockBodyCommitments(raw), code, msg)
	initial148Unchanged(t, raw, before)
}

func initial148BlockQRefusal(t *testing.T, label string, raw []byte, parent, expected [32]byte, height uint64, times []uint64, code ErrorCode, msg string) {
	t.Helper()
	before := bytes.Clone(raw)
	summary, err := ValidateInitial148BlockSteps1To12(raw, parent, expected, height, times)
	initial148BlockWantError(t, label, err, code, msg)
	if summary != (BlockBasicSummary{}) {
		t.Fatalf("%s: summary=%+v want zero", label, summary)
	}
	initial148Unchanged(t, raw, before)
}

func initial148BlockGenesisHeader(t *testing.T) Initial148Header {
	t.Helper()
	return Initial148Header{
		Version:       1,
		PrevBlockHash: [32]byte{},
		MerkleRoot:    initial148Array(t, initial148GenesisMerkleHex),
		Timestamp:     initial148GenesisTimestamp,
		Target:        POW_LIMIT,
		UtxoRoot:      initial148Array(t, initial148GenesisRootHex),
		Nonce:         0,
	}
}

func TestInitial148BlockGenesisFrame(t *testing.T) {
	raw := initial148BlockGenesis(t)
	before := bytes.Clone(raw)
	wantHeader := initial148BlockGenesisHeader(t)
	tx := initial148BlockGenesisTx(t)
	parsed, err := ParseInitial148BlockBytes(raw)
	if err != nil {
		t.Fatalf("initial148 complete frame: %v", err)
	}
	initial148Fields(t, parsed.Header, wantHeader, "initial148 complete frame")
	if len(parsed.HeaderBytes) != Initial148HeaderBytes || !bytes.Equal(parsed.HeaderBytes, before[:Initial148HeaderBytes]) {
		t.Fatalf("initial148 complete frame: HeaderBytes=%d", len(parsed.HeaderBytes))
	}
	if parsed.TxCount != 1 || len(parsed.Txs) != 1 || len(parsed.Txids) != 1 || len(parsed.Wtxids) != 1 {
		t.Fatalf("initial148 complete frame: count=%d txs=%d txids=%d wtxids=%d", parsed.TxCount, len(parsed.Txs), len(parsed.Txids), len(parsed.Wtxids))
	}
	if got, want := parsed.Txids[0], initial148Array(t, initial148GenesisTxidHex); got != want {
		t.Fatalf("initial148 complete frame: txid=%x want=%x", got, want)
	}
	if got, want := parsed.Wtxids[0], initial148Array(t, initial148GenesisWtxidHex); got != want {
		t.Fatalf("initial148 complete frame: wtxid=%x want=%x", got, want)
	}
	if parsed.Txs[0].TxKind != 0 || len(parsed.Txs[0].Inputs) != 1 || len(parsed.Txs[0].Outputs) != 2 || len(parsed.Txs[0].Witness) != 0 || len(parsed.Txs[0].DaPayload) != 0 {
		t.Fatalf("initial148 complete frame: body shape %+v", parsed.Txs[0])
	}
	if !bytes.Equal(parsed.Txs[0].Outputs[0].CovenantData, tx[67:100]) {
		t.Fatal("initial148 complete frame: first output bytes changed")
	}
	initial148Unchanged(t, raw, before)
	hash, err := Initial148BlockHash(raw[:Initial148HeaderBytes])
	if err != nil || hash != initial148Array(t, initial148GenesisHashHex) || hash != sha3.Sum256(before[:Initial148HeaderBytes]) {
		t.Fatalf("initial148 pinned block hash: got=%x err=%v", hash, err)
	}
	if err := ValidateInitial148BlockBodyCommitments(raw); err != nil {
		t.Fatalf("initial148 pinned body commitments: %v", err)
	}
	summary, err := ValidateInitial148BlockSteps1To12(raw, [32]byte{}, POW_LIMIT, 1, []uint64{1_772_020_799})
	want := BlockBasicSummary{TxCount: 1, SumWeight: 590, SumDa: 0, BlockHash: initial148Array(t, initial148GenesisHashHex)}
	if err != nil || summary != want {
		t.Fatalf("initial148 pinned summary: got=%+v/%v want=%+v", summary, err, want)
	}
	initial148Unchanged(t, raw, before)
	initial148Next(t)
}

func TestInitial148BlockCounts(t *testing.T) {
	header := initial148BlockGenesis(t)[:Initial148HeaderBytes]
	tx := initial148BlockGenesisTx(t)
	txid, wtxid := initial148Array(t, initial148GenesisTxidHex), initial148Array(t, initial148GenesisWtxidHex)
	cases := []struct {
		name   string
		prefix []byte
		count  uint64
	}{
		{"one", []byte{0x01}, 1},
		{"252", []byte{0xfc}, 252},
		{"253", []byte{0xfd, 0xfd, 0x00}, 253},
		{"65535", []byte{0xfd, 0xff, 0xff}, 65_535},
		{"65536", []byte{0xfe, 0x00, 0x00, 0x01, 0x00}, 65_536},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := append(slices.Clone(header), tc.prefix...)
			raw = append(raw, bytes.Repeat(tx, int(tc.count))...)
			parsed, err := ParseInitial148BlockBytes(raw)
			if err != nil {
				t.Fatalf("initial148 count offset: %v", err)
			}
			if parsed.TxCount != tc.count || uint64(len(parsed.Txs)) != tc.count || uint64(len(parsed.Txids)) != tc.count || uint64(len(parsed.Wtxids)) != tc.count {
				t.Fatalf("initial148 count offset: count=%d txs=%d txids=%d wtxids=%d", parsed.TxCount, len(parsed.Txs), len(parsed.Txids), len(parsed.Wtxids))
			}
			for i := range parsed.Txs {
				body, err := MarshalTx(parsed.Txs[i])
				if err != nil || !bytes.Equal(body, tx) {
					t.Fatalf("initial148 count offset: tx %d bytes=%x err=%v", i, body, err)
				}
				if parsed.Txids[i] != txid || parsed.Wtxids[i] != wtxid {
					t.Fatalf("initial148 count offset: tx %d ids txid=%x wtxid=%x", i, parsed.Txids[i], parsed.Wtxids[i])
				}
			}
		})
	}
	for _, c := range []struct {
		name   string
		prefix []byte
	}{
		{"count 0xffffffff body absent", []byte{0xfe, 0xff, 0xff, 0xff, 0xff}},
		{"u64max body absent", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := append(slices.Clone(header), c.prefix...)
			initial148BlockParserRefusal(t, "initial148 frame error tuple", raw, BLOCK_ERR_PARSE, "unexpected EOF in tx list")
			initial148BlockQRefusal(t, "initial148 frame error tuple", raw, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_PARSE, "unexpected EOF in tx list")
		})
	}
}

func TestInitial148BlockShortPrefixes(t *testing.T) {
	raw := initial148BlockGenesis(t)
	for n := 0; n < Initial148HeaderBytes+1; n++ {
		t.Run(fmt.Sprintf("prefix_%d", n), func(t *testing.T) {
			prefix := bytes.Clone(raw[:n])
			initial148BlockParserRefusal(t, "initial148 frame error tuple", prefix, BLOCK_ERR_PARSE, "block too short")
			initial148BlockQRefusal(t, "initial148 frame error tuple", prefix, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_PARSE, "block too short")
		})
	}
}

func TestInitial148BlockFrameErrors(t *testing.T) {
	raw := initial148BlockGenesis(t)
	header, tx := raw[:Initial148HeaderBytes], initial148BlockGenesisTx(t)
	for _, c := range []struct {
		name string
		raw  []byte
		code ErrorCode
		msg  string
	}{
		{"nonminimal count", append(slices.Clone(header), 0xfd, 0x01, 0x00), BLOCK_ERR_PARSE, "invalid tx_count"},
		{"truncated count", append(slices.Clone(header), 0xfd), BLOCK_ERR_PARSE, "invalid tx_count"},
		{"truncated wide count", append(slices.Clone(header), 0xfe, 0x00, 0x00), BLOCK_ERR_PARSE, "invalid tx_count"},
		{"zero count", append(slices.Clone(header), 0x00), BLOCK_ERR_COINBASE_INVALID, "empty block tx list"},
		{"zero count with trailing", append(slices.Clone(header), 0x00, 0x01), BLOCK_ERR_COINBASE_INVALID, "empty block tx list"},
		{"count two one tx", append(append(slices.Clone(header), 0x02), tx...), BLOCK_ERR_PARSE, "unexpected EOF in tx list"},
		{"truncated tx", raw[:len(raw)-1], TX_ERR_PARSE, "unexpected EOF (u8)"},
		{"trailing bytes", append(slices.Clone(raw), 0x00), BLOCK_ERR_PARSE, "trailing bytes after tx list"},
	} {
		initial148BlockParserRefusal(t, "initial148 frame error tuple", c.raw, c.code, c.msg)
		initial148BlockQRefusal(t, "initial148 frame error tuple", c.raw, blockStepsOther, [32]byte{0x7f}, blockStepsHeight, blockStepsTimes, c.code, c.msg)
	}
	// The complete parse always owns the first error, even with a bad header target and parent.
	counter := append(slices.Clone(header), 0xfd, 0x01, 0x00)
	summary, err := ValidateInitial148BlockSteps1To12(counter, blockStepsOther, POW_LIMIT, blockStepsHeight, blockStepsTimes)
	blockStepsWantCode(t, "initial148 trailing before validity", summary, err, BLOCK_ERR_PARSE, "invalid tx_count")
}

func TestInitial148BlockHeaderDomains(t *testing.T) {
	tx := initial148BlockGenesisTx(t)
	literal, fields := initial148Literal(t)
	type fixture struct {
		name string
		raw  []byte
		want Initial148Header
	}
	fixtures := []fixture{{"L", literal, fields}}
	for _, f := range initial148Fixtures(t) {
		if f.name != "L" {
			fixtures = append(fixtures, fixture{f.name, f.raw, f.want})
		}
	}
	versions := []struct {
		name  string
		value uint32
		wire  [4]byte
	}{
		{"version0", 0, [4]byte{}},
		{"version1", 1, [4]byte{1, 0, 0, 0}},
		{"version_high_bit", 0x80000000, [4]byte{0, 0, 0, 0x80}},
		{"version_max", 0xffffffff, [4]byte{0xff, 0xff, 0xff, 0xff}},
	}
	for _, v := range versions {
		raw, want := slices.Clone(literal), fields
		copy(raw[0:4], v.wire[:])
		want.Version = v.value
		fixtures = append(fixtures, fixture{v.name, raw, want})
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			raw := append(slices.Clone(f.raw), 0x01)
			raw = append(raw, tx...)
			parsed, err := ParseInitial148BlockBytes(raw)
			if err != nil {
				t.Fatalf("initial148 structural domain: %v", err)
			}
			initial148Fields(t, parsed.Header, f.want, "initial148 structural domain")
			if !bytes.Equal(parsed.HeaderBytes, f.raw) {
				t.Fatalf("initial148 structural domain: frame bytes differ")
			}
			hash, err := Initial148BlockHash(parsed.HeaderBytes)
			if err != nil || hash != sha3.Sum256(f.raw) {
				t.Fatalf("initial148 structural domain: hash=%x err=%v", hash, err)
			}
		})
	}
}

func initial148BlockSetTarget(t *testing.T, raw []byte, target [32]byte) []byte {
	t.Helper()
	out := slices.Clone(raw)
	copy(out[76:108], target[:])
	return out
}

func TestInitial148BlockParseBeforePow(t *testing.T) {
	txs := initial148BlockFillerTxs(t)
	// A complete parsing frame with target zero is a target-range refusal, not a
	// parse or PoW-arithmetic refusal.
	targetZero := initial148BlockSetTarget(t, initial148BlockFrame(t, txs, nil), [32]byte{})
	parsed, err := ParseInitial148BlockBytes(targetZero)
	if err != nil || parsed.TxCount != 2 {
		t.Fatalf("initial148 framing before pow: parse=%+v/%v", parsed, err)
	}
	initial148BlockQRefusal(t, "initial148 framing before pow", targetZero, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_TARGET_INVALID, "target out of range")
	trailing := append(slices.Clone(targetZero), 0x00)
	initial148BlockQRefusal(t, "initial148 framing before pow", trailing, blockStepsOther, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_PARSE, "trailing bytes after tx list")
	// A frame refusal wins even with an invalid expected target and parent once
	// the supplied context itself is valid.
	frame := append(slices.Clone(targetZero[:Initial148HeaderBytes]), 0x00)
	initial148BlockQRefusal(t, "initial148 framing before pow", frame, blockStepsOther, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
}

func initial148BlockFillerTxs(t *testing.T) [][]byte {
	t.Helper()
	others := blockStepsPlain(1)
	return append([][]byte{initial148BlockCoinbase(t, others...)}, others...)
}

func TestInitial148BlockHeaderOrder(t *testing.T) {
	txs := initial148BlockFillerTxs(t)
	old := func(h *initial148BlockHead) { h.timestamp = blockStepsMedian }
	small := [32]byte{31: 1}
	noWitness := append([][]byte{coinbaseTxWithOutputs(0, []testOutput{{covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData()}})}, blockStepsPlain(1)...)
	badChunk := blockStepsChunk(blockStepsIDs[0], 0, []byte{0x42}, [32]byte{})
	for _, c := range []struct {
		name             string
		raw              []byte
		parent, expected [32]byte
		code             ErrorCode
		msg              string
	}{
		{"target before pow", initial148BlockSetTarget(t, initial148BlockFrame(t, txs, nil), [32]byte{}), blockStepsParent, POW_LIMIT, BLOCK_ERR_TARGET_INVALID, "target out of range"},
		{"pow before retarget", initial148BlockSetTarget(t, initial148BlockFrame(t, txs, nil), [32]byte{31: 1}), blockStepsOther, POW_LIMIT, BLOCK_ERR_POW_INVALID, "pow invalid"},
		{"expected target before parent", initial148BlockFrame(t, txs, nil), blockStepsOther, small, BLOCK_ERR_TARGET_INVALID, "target mismatch"},
		{"parent before merkle", initial148BlockFrame(t, txs, func(h *initial148BlockHead) { h.merkle = [32]byte{1} }), blockStepsOther, POW_LIMIT, BLOCK_ERR_LINKAGE_INVALID, "prev_block_hash mismatch"},
		{"merkle before witness", initial148BlockFrame(t, noWitness, func(h *initial148BlockHead) { h.merkle = [32]byte{1} }), blockStepsParent, POW_LIMIT, BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch"},
		{"witness before timestamp", initial148BlockFrame(t, noWitness, old), blockStepsParent, POW_LIMIT, BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated"},
		{"timestamp before resource", initial148BlockFrame(t, append([][]byte{initial148BlockCoinbase(t, blockStepsAnchors(MAX_ANCHOR_BYTES_PER_BLOCK-31))}, blockStepsAnchors(MAX_ANCHOR_BYTES_PER_BLOCK-31)), old), blockStepsParent, POW_LIMIT, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median"},
		{"timestamp before DA", initial148BlockFrame(t, append([][]byte{initial148BlockCoinbase(t, badChunk)}, badChunk), old), blockStepsParent, POW_LIMIT, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median"},
		{"resource before DA", initial148BlockFrame(t, append([][]byte{initial148BlockCoinbase(t, blockStepsAnchors(MAX_ANCHOR_BYTES_PER_BLOCK-31), badChunk)}, blockStepsAnchors(MAX_ANCHOR_BYTES_PER_BLOCK-31), badChunk), nil), blockStepsParent, POW_LIMIT, BLOCK_ERR_ANCHOR_BYTES_EXCEEDED, "anchor bytes exceeded"},
		{"chunk hash", initial148BlockFrame(t, append([][]byte{initial148BlockCoinbase(t, badChunk)}, badChunk), nil), blockStepsParent, POW_LIMIT, BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch"},
	} {
		initial148BlockQRefusal(t, "initial148 Q first error", c.raw, c.parent, c.expected, blockStepsHeight, blockStepsTimes, c.code, c.msg)
	}
}

func initial148BlockContextRefusal(t *testing.T, label string, raw []byte, parent, expected [32]byte, height uint64, times []uint64) {
	t.Helper()
	before := bytes.Clone(raw)
	summary, err := ValidateInitial148BlockSteps1To12(raw, parent, expected, height, times)
	if err != ErrBlockSteps1To12Context || summary != (BlockBasicSummary{}) || err.Error() != "block steps 1-12: invalid supplied context" {
		t.Fatalf("%s: got=%+v/%v want existing context sentinel", label, summary, err)
	}
	initial148Unchanged(t, raw, before)
}

func TestInitial148BlockContext(t *testing.T) {
	txs := initial148BlockFillerTxs(t)
	valid := initial148BlockFrame(t, txs, nil)
	atMedian := initial148BlockFrame(t, txs, func(h *initial148BlockHead) { h.timestamp = blockStepsMedian })
	future := initial148BlockFrame(t, txs, func(h *initial148BlockHead) { h.timestamp = blockStepsMedian + MAX_FUTURE_DRIFT })
	drift := initial148BlockFrame(t, txs, func(h *initial148BlockHead) { h.timestamp = blockStepsMedian + MAX_FUTURE_DRIFT + 1 })
	lowerMedian := initial148BlockFrame(t, txs, func(h *initial148BlockHead) { h.timestamp = 501 })
	wantWeight := blockStepsWeight(t, txs[0]) + blockStepsWeight(t, txs[1])
	admitted := []struct {
		name   string
		raw    []byte
		height uint64
		target [32]byte
		times  []uint64
	}{
		{"height1 admitted", valid, 1, POW_LIMIT, []uint64{1_000}},
		{"height11 admitted", valid, 11, POW_LIMIT, blockStepsTimes},
		{"height12 admitted", valid, blockStepsHeight, POW_LIMIT, blockStepsTimes},
		{"lower median admitted", lowerMedian, 2, POW_LIMIT, []uint64{900, 500}},
		{"exact drift bound", future, blockStepsHeight, POW_LIMIT, blockStepsTimes},
	}
	for _, c := range admitted {
		before := bytes.Clone(c.raw)
		summary, err := ValidateInitial148BlockSteps1To12(c.raw, blockStepsParent, c.target, c.height, c.times)
		want := BlockBasicSummary{TxCount: 2, SumWeight: wantWeight, SumDa: 0, BlockHash: sha3.Sum256(c.raw[:Initial148HeaderBytes])}
		if err != nil || summary != want {
			t.Fatalf("%s: got=%+v/%v want=%+v", c.name, summary, err, want)
		}
		initial148Unchanged(t, c.raw, before)
	}
	for _, c := range []struct {
		name   string
		raw    []byte
		height uint64
		target [32]byte
		times  []uint64
	}{
		{"height0", valid, 0, POW_LIMIT, blockStepsTimes},
		{"zero target", valid, blockStepsHeight, [32]byte{}, blockStepsTimes},
		{"zero timestamps", valid, 1, POW_LIMIT, nil},
		{"ten timestamps", valid, 11, POW_LIMIT, blockStepsTimes[:10]},
		{"twelve timestamps", valid, blockStepsHeight, POW_LIMIT, append(slices.Clone(blockStepsTimes), 1)},
	} {
		initial148BlockContextRefusal(t, "initial148 context projection", c.raw, blockStepsParent, c.target, c.height, c.times)
	}
	// Context precedes the complete parse.
	initial148BlockContextRefusal(t, "initial148 context before parse", []byte{1}, blockStepsParent, POW_LIMIT, 0, nil)
	initial148BlockQRefusal(t, "initial148 context projection", atMedian, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median")
	initial148BlockQRefusal(t, "initial148 context projection", drift, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_TIMESTAMP_FUTURE, "timestamp exceeds future drift")
}

func TestInitial148BlockFullFramePreimage(t *testing.T) {
	raw := initial148BlockGenesis(t)
	before := bytes.Clone(raw)
	hash, err := Initial148BlockHash(raw[:Initial148HeaderBytes])
	if err != nil || hash != sha3.Sum256(raw[:Initial148HeaderBytes]) {
		t.Fatalf("initial148 full frame preimage: %x/%v", hash, err)
	}
	rootOnly := slices.Clone(raw)
	rootOnly[108] ^= 0x01
	parsed, err := ParseInitial148BlockBytes(rootOnly)
	if err != nil {
		t.Fatalf("initial148 full frame preimage: parse root-only=%v", err)
	}
	rootHash, err := Initial148BlockHash(rootOnly[:Initial148HeaderBytes])
	if err != nil || rootHash == hash || rootHash != sha3.Sum256(rootOnly[:Initial148HeaderBytes]) || parsed.Header.UtxoRoot == initial148BlockGenesisHeader(t).UtxoRoot {
		t.Fatalf("initial148 full frame preimage: root-only hash=%x err=%v", rootHash, err)
	}
	summary, err := ValidateInitial148BlockSteps1To12(rootOnly, [32]byte{}, POW_LIMIT, 1, []uint64{1_772_020_799})
	if err != nil || summary.TxCount != 1 || summary.BlockHash != rootHash {
		t.Fatalf("initial148 full frame preimage: root-only summary=%+v/%v", summary, err)
	}
	initial148Unchanged(t, raw, before)
	initial148Next(t)
}

func TestInitial148BlockStep13Exclusion(t *testing.T) {
	root := initial148Array(t, "deadbeef00000000000000000000000000000000000000000000000000000000")
	// A canonical coinbase with a step13-invalid non-coinbase transaction and an
	// arbitrary header UtxoRoot passes both Q and the commitment-only entry.
	canonical := initial148BlockFrame(t, initial148BlockFillerTxs(t), func(h *initial148BlockHead) { h.root = root })
	if err := ValidateInitial148BlockBodyCommitments(canonical); err != nil {
		t.Fatalf("initial148 Q excludes step13: body=%v", err)
	}
	summary, err := ValidateInitial148BlockSteps1To12(canonical, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes)
	if err != nil || summary.TxCount != 2 || summary.BlockHash != sha3.Sum256(canonical[:Initial148HeaderBytes]) {
		t.Fatalf("initial148 Q excludes step13: summary=%+v/%v", summary, err)
	}
	// A non-canonical first transaction is still steps1-12-valid; only the
	// commitment-only entry owns the first-coinbase structure check.
	others := blockStepsPlain(1)
	commitment := initial148BlockWitnessCommit(t, others...)
	first := txWithOutputs([]testOutput{{covenantType: COV_TYPE_ANCHOR, covenantData: commitment[:]}})
	txs := append([][]byte{first}, others...)
	raw := initial148BlockFrame(t, txs, func(h *initial148BlockHead) { h.root = root })
	parsed, err := ParseInitial148BlockBytes(raw)
	if err != nil || parsed.Header.UtxoRoot != root {
		t.Fatalf("initial148 Q excludes step13: parse=%v", err)
	}
	summary, err = ValidateInitial148BlockSteps1To12(raw, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes)
	if err != nil || summary.TxCount != 2 || summary.BlockHash != sha3.Sum256(raw[:Initial148HeaderBytes]) {
		t.Fatalf("initial148 Q excludes step13: summary=%+v/%v", summary, err)
	}
	initial148BlockBodyRefusal(t, "initial148 Q excludes step13", raw, BLOCK_ERR_COINBASE_INVALID, "first tx must be canonical coinbase")
}

func TestInitial148BlockCapacity(t *testing.T) {
	exact := make([]byte, 68_000_157)
	copy(exact, initial148BlockGenesis(t)[:Initial148HeaderBytes])
	exact[Initial148HeaderBytes] = 0x00
	over := make([]byte, 68_000_158)
	copy(over, exact)
	// Exactly M is capacity-admitted: the parser, the body validator and Q all
	// reach the count-zero decision. A production M reduced to 68000125 must
	// therefore make this literal fixture refuse and fail the expected result.
	initial148BlockParserRefusal(t, "initial148 local M boundary", exact, BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
	initial148BlockQRefusal(t, "initial148 local M boundary", exact, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
	initial148BlockBodyRefusal(t, "initial148 local M boundary", exact, BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
	// At M+1 the local capacity sentinel wins before context and parse, for both
	// bounded entries; the pure parser still owns its count-zero result.
	overBefore := bytes.Clone(over)
	summary, err := ValidateInitial148BlockSteps1To12(over, [32]byte{}, [32]byte{}, 0, nil)
	if err != ErrInitial148BlockCapacity || summary != (BlockBasicSummary{}) || err.Error() != "initial148 block: raw block exceeds 68000157 bytes" {
		t.Fatalf("initial148 local M boundary: capacity=%+v/%v", summary, err)
	}
	initial148Unchanged(t, over, overBefore)
	if err := ValidateInitial148BlockBodyCommitments(over); err != ErrInitial148BlockCapacity || err.Error() != "initial148 block: raw block exceeds 68000157 bytes" {
		t.Fatalf("initial148 local M boundary: body capacity=%v", err)
	}
	initial148Unchanged(t, over, overBefore)
	initial148BlockParserRefusal(t, "initial148 local M boundary", over, BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
}

func TestInitial148BlockOwnership(t *testing.T) {
	raw := initial148BlockGenesis(t)
	before := bytes.Clone(raw)
	parsed, err := ParseInitial148BlockBytes(raw)
	if err != nil {
		t.Fatalf("initial148 framing ownership: %v", err)
	}
	initial148Unchanged(t, raw, before)
	for i := range raw {
		raw[i] ^= 0xff
	}
	initial148Fields(t, parsed.Header, initial148BlockGenesisHeader(t), "initial148 framing ownership")
	if !bytes.Equal(parsed.HeaderBytes, before[:Initial148HeaderBytes]) {
		t.Fatal("initial148 framing ownership: HeaderBytes aliases raw")
	}
	parsed.HeaderBytes[0] = 0xaa
	if raw[0] != before[0]^0xff {
		t.Fatal("initial148 framing ownership: HeaderBytes write reached raw")
	}
	// Transaction variable-byte fields keep the declared immutable read-only
	// borrow; only the header and its bytes are independent copies, so raw must
	// not be mutated while a parsed transaction is still used.
	if err := ValidateInitial148BlockBodyCommitments(before); err != nil {
		t.Fatalf("initial148 framing next operation: body=%v", err)
	}
	summary, err := ValidateInitial148BlockSteps1To12(before, [32]byte{}, POW_LIMIT, 1, []uint64{1_772_020_799})
	if err != nil || summary.TxCount != 1 {
		t.Fatalf("initial148 framing next operation: summary=%+v/%v", summary, err)
	}
	initial148BlockParserRefusal(t, "initial148 framing next operation", append(slices.Clone(before), 0), BLOCK_ERR_PARSE, "trailing bytes after tx list")
	again, err := ParseInitial148BlockBytes(before)
	if err != nil || again.TxCount != 1 {
		t.Fatalf("initial148 framing next operation: %v", err)
	}
}

func TestInitial148BlockDAFrame(t *testing.T) {
	hash := initial148Array(t, initial148DAHashHex)
	id := blockStepsIDs[0]
	payload := []byte{0x42}
	if sha3.Sum256(payload) != hash {
		t.Fatal("initial148 DA frame: payload42 literal mismatch")
	}
	commit := blockStepsCommit(id, 1, blockStepsDAOut(hash))
	chunk := blockStepsChunk(id, 0, payload, hash)
	txs := append([][]byte{initial148BlockCoinbase(t, commit, chunk)}, commit, chunk)
	raw := initial148BlockFrame(t, txs, nil)
	parsed, err := ParseInitial148BlockBytes(raw)
	if err != nil {
		t.Fatalf("initial148 context projection: %v", err)
	}
	summary, err := ValidateInitial148BlockSteps1To12(raw, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes)
	wantWeight := blockStepsWeight(t, txs[0]) + blockStepsWeight(t, txs[1]) + blockStepsWeight(t, txs[2])
	want := BlockBasicSummary{TxCount: 3, SumWeight: wantWeight, SumDa: 1, BlockHash: sha3.Sum256(raw[:Initial148HeaderBytes])}
	if err != nil || summary != want {
		t.Fatalf("initial148 context projection: got=%+v/%v want=%+v", summary, err, want)
	}
	if parsed.TxCount != 3 || len(parsed.Txids) != 3 {
		t.Fatalf("initial148 context projection: count=%d ids=%d", parsed.TxCount, len(parsed.Txids))
	}
	// A lost 32-byte offset in the one-byte payload record fails the payload
	// commitment instead of satisfying this exact accepted summary.
	mutated := blockStepsChunk(id, 0, []byte{0x43}, hash)
	bad := append([][]byte{initial148BlockCoinbase(t, commit, mutated)}, commit, mutated)
	badRaw := initial148BlockFrame(t, bad, nil)
	initial148BlockQRefusal(t, "initial148 context projection", badRaw, blockStepsParent, POW_LIMIT, blockStepsHeight, blockStepsTimes, BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch")
}

func TestInitial148BlockHostileFirstError(t *testing.T) {
	raw := initial148BlockGenesis(t)
	header, tx := raw[:Initial148HeaderBytes], initial148BlockGenesisTx(t)
	for _, c := range []struct {
		name string
		raw  []byte
		code ErrorCode
		msg  string
	}{
		{"bad count dominates target", append(append(slices.Clone(header), 0xfd, 0x01, 0x00), tx...), BLOCK_ERR_PARSE, "invalid tx_count"},
		{"zero count dominates pow", append(slices.Clone(header), 0x00, 0x01, 0x02), BLOCK_ERR_COINBASE_INVALID, "empty block tx list"},
		{"u64max dominates target", append(slices.Clone(header), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), BLOCK_ERR_PARSE, "unexpected EOF in tx list"},
		{"boundary eof dominates parent", append(append(slices.Clone(header), 0x02), tx...), BLOCK_ERR_PARSE, "unexpected EOF in tx list"},
		{"truncated tx dominates target", raw[:len(raw)-1], TX_ERR_PARSE, "unexpected EOF (u8)"},
		{"trailing dominates merkle", append(slices.Clone(raw), 0x00), BLOCK_ERR_PARSE, "trailing bytes after tx list"},
	} {
		initial148BlockParserRefusal(t, "initial148 hostile first error", c.raw, c.code, c.msg)
		initial148BlockQRefusal(t, "initial148 hostile first error", c.raw, blockStepsOther, POW_LIMIT, 7, []uint64{1, 2, 3, 4, 5, 6, 7}, c.code, c.msg)
		initial148BlockBodyRefusal(t, "initial148 hostile first error", c.raw, c.code, c.msg)
	}
}
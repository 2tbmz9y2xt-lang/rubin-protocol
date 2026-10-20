package mdbx

import (
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Spec literals: RUBIN_CONSENSUS_STATE_MACHINE.md section 2.6 (rubin-spec 2a30f15b).
func testTreeHex(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad literal %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// testTreeValue is the stored utxo-v1 value of entry E with the named overrides.
func testTreeValue(value uint64, data []byte, height uint64, coinbase byte) []byte {
	b := binary.LittleEndian.AppendUint64(nil, value)
	b = append(b, 0, 0)
	b = appendCompactSize(b, uint64(len(data)))
	b = append(b, data...)
	b = binary.LittleEndian.AppendUint64(b, height)
	return append(b, coinbase)
}

func testTreeE() []byte { return testTreeValue(1, testTreeData(0x11), 0, 0) }

func testTreeData(fill byte) []byte {
	d := []byte{1}
	for i := 0; i < 32; i++ {
		d = append(d, fill)
	}
	return d
}

func testTreeKey(first byte, rest byte, vout uint32) [36]byte {
	var k [36]byte
	k[0] = first
	for i := 1; i < 32; i++ {
		k[i] = rest
	}
	binary.BigEndian.PutUint32(k[32:], vout)
	return k
}

// testTreeLeafPreimage builds D_LEAF || S(op, e) byte by byte, independent of tree_digest.go.
func testTreeLeafPreimage(k [36]byte, value []byte) [32]byte {
	p := append([]byte("RUBIN_UTXO_TREE_V1\x01"), k[:32]...)
	p = binary.LittleEndian.AppendUint32(p, binary.BigEndian.Uint32(k[32:]))
	return sha3.Sum256(append(p, value...))
}

func testTreeBranchPreimage(d uint16, prefix [36]byte, zero, one [32]byte) [32]byte {
	p := binary.BigEndian.AppendUint16([]byte("RUBIN_UTXO_TREE_V1\x02"), d)
	p = append(p, prefix[:]...)
	p = append(p, zero[:]...)
	return sha3.Sum256(append(p, one[:]...))
}

var (
	testKA = testTreeKey(0, 0, 0)
	testKB = testTreeKey(0, 0, 1)
	testKC = testTreeKey(0x80, 0, 0)
	testKX = testTreeKey(0xa7, 0x55, 0)
	testKY = testTreeKey(0xb9, 0xff, 0)
)

func TestTreeDigestV1Literals(t *testing.T) {
	e := testTreeE()
	leaf := func(name string, k [36]byte, v []byte, want string) [32]byte {
		got := treeLeafDigestV1(k, v)
		if got != testTreeHex(t, want) {
			t.Fatalf("%s: got %x", name, got)
		}
		return got
	}
	if got := treeEmptyDigestV1(); got != testTreeHex(t, "0a978e2cf0e03934b2ec7c369b301f8f3a687aed501227a7af76730a8e64f8bb") {
		t.Fatalf("C01: %x", got)
	}
	a := leaf("C02", testKA, e, "14bd6311f35ed9534d8cd8a101bc09c5d289978e393e775271fd9e446c8cde8d")
	b := leaf("C03", testKB, e, "480f5e45ffbf5dbc0ec499ef7574c3379e26ab4ffb25220df9eb023b057526cc")
	c := treeLeafDigestV1(testKC, e)
	c8 := leaf("C08", testTreeKey(0, 0, 255), e, "0b1d7e322458a7b09a40321abd7c70ab71b3f1d436bd4b2dc1e20be014e967f3")
	c9 := leaf("C09", testTreeKey(0, 0, 256), e, "e394106e180d6e4d4ff403a0f506fef3ec83f07000a493c0e1b15648bc2ffd7f")
	leaf("C11", testTreeKey(0, 0, 0xffffffff), e, "9f2a1e2045e9fbb21e11904fa3bf180c5b303e08b2736798bc6e16a810377109")
	leaf("C12", testKA, testTreeValue(1, testTreeData(0x11), 0, 1), "aee487de02b1d0365069254d3bd46173099f21f15992b066640f4de27a9d910b")
	leaf("C13", testKA, testTreeValue(1, testTreeData(0x11), 1, 0), "7f33e7092506562aa419b6429fe944e1e0d1cc0c6e59ba7df0ad686b47cbda39")
	leaf("C14", testKA, testTreeValue(2, testTreeData(0x11), 0, 0), "d8ca4a9d2c487486e0dd12ea08862b0c8c0f87c292b2dab4010b85bce5c30fc9")
	leaf("C15", testKA, testTreeValue(1, testTreeData(0x22), 0, 0), "bb62b3599ef92d59b61fef4ed4a1deb0f6ce41c56921ee9f83faee050217fea2")
	hx := leaf("HX", testKX, e, "cc9911b53cb802ce58012714419aef9ad9c195bd8edf0617381efbd00d27a84c")
	hy := leaf("HY", testKY, e, "a92ec5b09f47d0d0b02daac535a9b2633d7268fad9262957a81f31b1fd1abd11")
	branch := func(name string, d uint16, p [36]byte, z, o [32]byte, want string) [32]byte {
		got := treeBranchDigestV1(TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: d, Prefix: p}, z, o)
		if got != testTreeHex(t, want) {
			t.Fatalf("%s: got %x", name, got)
		}
		return got
	}
	branch("C04", 0, [36]byte{}, a, c, "1f3304724f76317f55c881875e5bcb741c00b090e1e1c2204d3b276aff069ac2")
	c5 := branch("C05", 287, [36]byte{}, a, b, "fc8c011e40853708f49a90759af0c9e5b738e3116dca9ed641539af0827cf9ac")
	branch("C06", 0, [36]byte{}, c5, c, "0dbb5487445845169a856b31fe2877c6cb84df41cc170f6ae9c41d062164fd7d")
	branch("C07", 3, [36]byte{0xa0}, hx, hy, "10a4199bd27aa176b2e1c052bd2a18cd961f1a861793796e4e6a594ae9073e01")
	branch("C10", 279, [36]byte{}, c8, c9, "b9965ddde341cf712ffa9655cc85caf2da2608461248c8f0f2217d5e00c2b44e")
}

func TestTreeDigestV1Envelopes(t *testing.T) {
	for _, n := range []int{0, 252, 253, 65535, 65536} {
		data := make([]byte, n)
		for i := range data {
			data[i] = 0x33
		}
		type1, typeMax := testTreeValue(1, data, 0, 0), testTreeValue(1, data, 0, 0)
		binary.LittleEndian.PutUint16(type1[8:], 1)
		binary.LittleEndian.PutUint16(typeMax[8:], 0xffff)
		// TYPE1, VALUE_ZERO, VALUE_MAX, TYPE_MAX, HEIGHT_MAX.
		for _, v := range [][]byte{
			type1, testTreeValue(0, data, 0, 0), testTreeValue(^uint64(0), data, 0, 0), typeMax, testTreeValue(1, data, ^uint64(0), 1),
		} {
			if got, want := treeLeafDigestV1(testKX, v), testTreeLeafPreimage(testKX, v); got != want {
				t.Fatalf("n=%d: got %x want %x", n, got, want)
			}
		}
	}
}

func TestTreeDigestV1DepthAndMasks(t *testing.T) {
	e := testTreeE()
	x, y := testTreeLeafPreimage(testKX, e), testTreeLeafPreimage(testKY, e)
	x1k := testKX
	x1k[35] = 1
	x1 := testTreeLeafPreimage(x1k, e)
	p04 := testKX
	p04[35] = 0
	child := testTreeBranchPreimage(287, p04, x, x1)
	if got := treeBranchDigestV1(TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: 287, Prefix: p04}, x, x1); got != child {
		t.Fatalf("ABS_PARENT3 child: %x", got)
	}
	top := testTreeBranchPreimage(3, [36]byte{0xa0}, child, y)
	if got := treeBranchDigestV1(TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: 3, Prefix: [36]byte{0xa0}}, child, y); got != top {
		t.Fatalf("ABS_PARENT3 top: %x", got)
	}
	mask8 := testTreeBranchPreimage(8, [36]byte{0xa7}, x, y)
	if got := treeBranchDigestV1(TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: 8, Prefix: [36]byte{0xa7}}, x, y); got != mask8 {
		t.Fatalf("MASK8: %x", got)
	}
}

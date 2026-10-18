package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// CSM section 2.6 at rubin-spec 2a30f15b: independent whole-root literals.
const (
	canonicalRootC01 = "0a978e2cf0e03934b2ec7c369b301f8f3a687aed501227a7af76730a8e64f8bb"
	canonicalRootC02 = "14bd6311f35ed9534d8cd8a101bc09c5d289978e393e775271fd9e446c8cde8d"
	canonicalRootC03 = "480f5e45ffbf5dbc0ec499ef7574c3379e26ab4ffb25220df9eb023b057526cc"
	canonicalRootC04 = "1f3304724f76317f55c881875e5bcb741c00b090e1e1c2204d3b276aff069ac2"
	canonicalRootC05 = "fc8c011e40853708f49a90759af0c9e5b738e3116dca9ed641539af0827cf9ac"
	canonicalRootC06 = "0dbb5487445845169a856b31fe2877c6cb84df41cc170f6ae9c41d062164fd7d"
	canonicalRootC07 = "10a4199bd27aa176b2e1c052bd2a18cd961f1a861793796e4e6a594ae9073e01"
	canonicalRootC08 = "0b1d7e322458a7b09a40321abd7c70ab71b3f1d436bd4b2dc1e20be014e967f3"
	canonicalRootC09 = "e394106e180d6e4d4ff403a0f506fef3ec83f07000a493c0e1b15648bc2ffd7f"
	canonicalRootC10 = "b9965ddde341cf712ffa9655cc85caf2da2608461248c8f0f2217d5e00c2b44e"
	canonicalRootC11 = "9f2a1e2045e9fbb21e11904fa3bf180c5b303e08b2736798bc6e16a810377109"
	canonicalRootC12 = "aee487de02b1d0365069254d3bd46173099f21f15992b066640f4de27a9d910b"
	canonicalRootC13 = "7f33e7092506562aa419b6429fe944e1e0d1cc0c6e59ba7df0ad686b47cbda39"
	canonicalRootC14 = "d8ca4a9d2c487486e0dd12ea08862b0c8c0f87c292b2dab4010b85bce5c30fc9"
	canonicalRootC15 = "bb62b3599ef92d59b61fef4ed4a1deb0f6ce41c56921ee9f83faee050217fea2"
	canonicalRootHX  = "cc9911b53cb802ce58012714419aef9ad9c195bd8edf0617381efbd00d27a84c"
	canonicalRootHY  = "a92ec5b09f47d0d0b02daac535a9b2633d7268fad9262957a81f31b1fd1abd11"
)

func canonicalRootTestData() ([5]Outpoint, UtxoEntry) {
	var ops [5]Outpoint
	ops[1].Vout = 1
	ops[2].Txid[0] = 0x80
	for i := range ops[3].Txid {
		ops[3].Txid[i] = 0x55
		ops[4].Txid[i] = 0xff
	}
	ops[3].Txid[0], ops[4].Txid[0] = 0xa7, 0xb9
	entry := UtxoEntry{Value: 1, CovenantData: append([]byte{1}, bytes.Repeat([]byte{0x11}, 32)...)}
	return ops, entry
}

func canonicalRootTestHex(t *testing.T, raw string) []byte {
	t.Helper()
	b, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func canonicalRootTestAssert(t *testing.T, name string, state map[Outpoint]UtxoEntry, want []byte) {
	t.Helper()
	if got := canonicalUTXORoot(state); !bytes.Equal(got[:], want) {
		t.Fatalf("root %s: got=%x want=%x", name, got, want)
	}
}

func TestCanonicalUTXORootLiterals(t *testing.T) {
	ops, e := canonicalRootTestData()
	a, b, c, x, y := ops[0], ops[1], ops[2], ops[3], ops[4]
	coinbase, height, value, data := e, e, e, e
	coinbase.CreatedByCoinbase, height.CreationHeight, value.Value = true, 1, 2
	data.CovenantData = append([]byte{1}, bytes.Repeat([]byte{0x22}, 32)...)
	v255, v256, vmax := a, a, a
	v255.Vout, v256.Vout, vmax.Vout = 255, 256, 0xffffffff
	for _, tc := range []struct {
		name  string
		state map[Outpoint]UtxoEntry
		want  string
	}{
		{"C01_NIL", nil, canonicalRootC01},
		{"C01_EMPTY", map[Outpoint]UtxoEntry{}, canonicalRootC01},
		{"C02", map[Outpoint]UtxoEntry{a: e}, canonicalRootC02},
		{"C03", map[Outpoint]UtxoEntry{b: e}, canonicalRootC03},
		{"C04", map[Outpoint]UtxoEntry{a: e, c: e}, canonicalRootC04},
		{"C05", map[Outpoint]UtxoEntry{a: e, b: e}, canonicalRootC05},
		{"C06", map[Outpoint]UtxoEntry{a: e, b: e, c: e}, canonicalRootC06},
		{"C07", map[Outpoint]UtxoEntry{x: e, y: e}, canonicalRootC07},
		{"C08", map[Outpoint]UtxoEntry{v255: e}, canonicalRootC08},
		{"C09", map[Outpoint]UtxoEntry{v256: e}, canonicalRootC09},
		{"C10", map[Outpoint]UtxoEntry{v255: e, v256: e}, canonicalRootC10},
		{"C11", map[Outpoint]UtxoEntry{vmax: e}, canonicalRootC11},
		{"C12", map[Outpoint]UtxoEntry{a: coinbase}, canonicalRootC12},
		{"C13", map[Outpoint]UtxoEntry{a: height}, canonicalRootC13},
		{"C14", map[Outpoint]UtxoEntry{a: value}, canonicalRootC14},
		{"C15", map[Outpoint]UtxoEntry{a: data}, canonicalRootC15},
		{"HX", map[Outpoint]UtxoEntry{x: e}, canonicalRootHX},
		{"HY", map[Outpoint]UtxoEntry{y: e}, canonicalRootHY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonicalRootTestAssert(t, tc.name, tc.state, canonicalRootTestHex(t, tc.want))
		})
	}
}

func TestCanonicalUTXORootHistory(t *testing.T) {
	ops, e := canonicalRootTestData()
	a, b, c := ops[0], ops[1], ops[2]
	for _, tc := range []struct {
		name  string
		order [3]Outpoint
	}{{"H01_ABC", [3]Outpoint{a, b, c}}, {"H01_ACB", [3]Outpoint{a, c, b}}, {"H01_BAC", [3]Outpoint{b, a, c}}, {"H01_BCA", [3]Outpoint{b, c, a}}, {"H01_CAB", [3]Outpoint{c, a, b}}, {"H01_CBA", [3]Outpoint{c, b, a}}} {
		state := make(map[Outpoint]UtxoEntry)
		for _, op := range tc.order {
			state[op] = e
		}
		canonicalRootTestAssert(t, tc.name, state, canonicalRootTestHex(t, canonicalRootC06))
	}
	state := map[Outpoint]UtxoEntry{a: e, b: e}
	state[c] = e
	canonicalRootTestAssert(t, "H02_INSERT", state, canonicalRootTestHex(t, canonicalRootC06))
	delete(state, c)
	canonicalRootTestAssert(t, "H02", state, canonicalRootTestHex(t, canonicalRootC05))
	state[c] = e
	delete(state, b)
	canonicalRootTestAssert(t, "H03", state, canonicalRootTestHex(t, canonicalRootC04))
	state[b] = e
	canonicalRootTestAssert(t, "H04_INSERT", state, canonicalRootTestHex(t, canonicalRootC06))
	delete(state, b)
	canonicalRootTestAssert(t, "H04", state, canonicalRootTestHex(t, canonicalRootC04))
	state = map[Outpoint]UtxoEntry{a: e, b: e}
	delete(state, b)
	canonicalRootTestAssert(t, "H05_ONE", state, canonicalRootTestHex(t, canonicalRootC02))
	delete(state, a)
	canonicalRootTestAssert(t, "H05_EMPTY", state, canonicalRootTestHex(t, canonicalRootC01))
	state[a] = e
	canonicalRootTestAssert(t, "H06_BEFORE", state, canonicalRootTestHex(t, canonicalRootC02))
	changed := e
	changed.Value = 2
	state[a] = changed
	canonicalRootTestAssert(t, "H06_REPLACE", state, canonicalRootTestHex(t, canonicalRootC14))
	state[a] = e
	canonicalRootTestAssert(t, "H06_RESTORE", state, canonicalRootTestHex(t, canonicalRootC02))
	// H07 and every H08 membership variant supply this same final {A:E} map.
	canonicalRootTestAssert(t, "H07_H08", state, canonicalRootTestHex(t, canonicalRootC02))
	changed = e
	changed.CreatedByCoinbase = true
	state[a] = changed
	canonicalRootTestAssert(t, "H09", state, canonicalRootTestHex(t, canonicalRootC12))
	state[b] = e
	delete(state, a)
	delete(state, b)
	canonicalRootTestAssert(t, "H10_EMPTY", state, canonicalRootTestHex(t, canonicalRootC01))
	rebuilt := map[Outpoint]UtxoEntry{b: e, a: e}
	canonicalRootTestAssert(t, "H10_REBUILD", rebuilt, canonicalRootTestHex(t, canonicalRootC05))
}

func TestCanonicalUTXORootEncodingBoundaries(t *testing.T) {
	ops, e := canonicalRootTestData()
	// All expected bytes below are finite CSM2.6/contract literals, independent
	// of the production encoder, routing helpers and domain constants.
	const leaf = "525542494e5f5554584f5f545245455f563101"
	for _, tc := range []struct {
		name    string
		n       int
		compact string
	}{{"S01", 0, "00"}, {"S02", 252, "fc"}, {"S03", 253, "fdfd00"}, {"S04", 65535, "fdffff"}, {"S05", 65536, "fe00000100"}} {
		entry := e
		entry.CovenantData = bytes.Repeat([]byte{0x33}, tc.n)
		preimage := canonicalRootTestHex(t, leaf+strings.Repeat("00", 36)+"0100000000000000"+"0000"+tc.compact)
		preimage = append(preimage, bytes.Repeat([]byte{0x33}, tc.n)...)
		preimage = append(preimage, make([]byte, 9)...)
		want := sha3.Sum256(preimage)
		canonicalRootTestAssert(t, tc.name, map[Outpoint]UtxoEntry{ops[0]: entry}, want[:])
	}
	for _, tc := range []struct {
		name              string
		value, height     uint64
		kind              uint16
		valueHex, typeHex string
		heightHex         string
	}{
		{"TYPE1", 1, 0, 1, "0100000000000000", "0100", "0000000000000000"},
		{"VALUE_ZERO", 0, 0, 0, "0000000000000000", "0000", "0000000000000000"},
		{"VALUE_MAX", 0xffffffffffffffff, 0, 0, "ffffffffffffffff", "0000", "0000000000000000"},
		{"TYPE_MAX", 1, 0, 0xffff, "0100000000000000", "ffff", "0000000000000000"},
		{"HEIGHT_MAX", 1, 0xffffffffffffffff, 0, "0100000000000000", "0000", "ffffffffffffffff"},
	} {
		entry := e
		entry.Value, entry.CreationHeight, entry.CovenantType = tc.value, tc.height, tc.kind
		preimage := canonicalRootTestHex(t, leaf+strings.Repeat("00", 36)+tc.valueHex+tc.typeHex+"2101"+strings.Repeat("11", 32)+tc.heightHex+"00")
		want := sha3.Sum256(preimage)
		canonicalRootTestAssert(t, tc.name, map[Outpoint]UtxoEntry{ops[0]: entry}, want[:])
	}
}

func TestCanonicalUTXORootAbsoluteDepthAndMasks(t *testing.T) {
	ops, e := canonicalRootTestData()
	x, y := ops[3], ops[4]
	x2 := x
	x2.Vout = 1
	const leaf = "525542494e5f5554584f5f545245455f563101"
	const branch = "525542494e5f5554584f5f545245455f563102"
	const entryTail = "0100000000000000" + "0000" + "2101"
	dataAndMetadata := strings.Repeat("11", 32) + strings.Repeat("00", 9)
	hx := canonicalRootTestHex(t, canonicalRootHX)
	hy := canonicalRootTestHex(t, canonicalRootHY)
	x2Preimage := canonicalRootTestHex(t, leaf+"a7"+strings.Repeat("55", 31)+"01000000"+entryTail+dataAndMetadata)
	x2Hash := sha3.Sum256(x2Preimage)
	childPreimage := canonicalRootTestHex(t, branch+"011f"+"a7"+strings.Repeat("55", 31)+"00000000")
	childPreimage = append(childPreimage, hx...)
	childPreimage = append(childPreimage, x2Hash[:]...)
	child := sha3.Sum256(childPreimage)
	topPreimage := canonicalRootTestHex(t, branch+"0003"+"a0"+strings.Repeat("00", 35))
	topPreimage = append(topPreimage, child[:]...)
	topPreimage = append(topPreimage, hy...)
	want := sha3.Sum256(topPreimage)
	canonicalRootTestAssert(t, "ABS_PARENT3", map[Outpoint]UtxoEntry{x: e, x2: e, y: e}, want[:])
	z := x
	z.Txid[1] = 0xd5
	zPreimage := canonicalRootTestHex(t, leaf+"a7d5"+strings.Repeat("55", 30)+"00000000"+entryTail+dataAndMetadata)
	zHash := sha3.Sum256(zPreimage)
	mask8Preimage := canonicalRootTestHex(t, branch+"0008"+"a7"+strings.Repeat("00", 35))
	mask8Preimage = append(mask8Preimage, hx...)
	mask8Preimage = append(mask8Preimage, zHash[:]...)
	want = sha3.Sum256(mask8Preimage)
	canonicalRootTestAssert(t, "MASK8", map[Outpoint]UtxoEntry{x: e, z: e}, want[:])
}

func TestCanonicalUTXORootInputPreservation(t *testing.T) {
	ops, e := canonicalRootTestData()
	other := UtxoEntry{Value: 0xffffffffffffffff, CovenantType: 1, CreationHeight: 0xffffffffffffffff, CreatedByCoinbase: true, CovenantData: bytes.Repeat([]byte{0x33}, 253)}
	state := map[Outpoint]UtxoEntry{ops[0]: e, ops[1]: other, ops[2]: e, ops[3]: other, ops[4]: e}
	before := make(map[Outpoint]UtxoEntry, len(state))
	for op, entry := range state {
		entry.CovenantData = bytes.Clone(entry.CovenantData)
		before[op] = entry
	}
	canonicalUTXORoot(state)
	if !reflect.DeepEqual(state, before) {
		t.Fatal("input changed after canonicalUTXORoot")
	}
}

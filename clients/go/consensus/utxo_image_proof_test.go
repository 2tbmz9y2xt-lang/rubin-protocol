package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// Independent whole-root literals and literal preimages from CSM2.6 at
// rubin-spec2a30f15b. These expectations never call production S/K/hash/Root.
const (
	imageTestC03 = "480f5e45ffbf5dbc0ec499ef7574c3379e26ab4ffb25220df9eb023b057526cc"
	imageTestC04 = "1f3304724f76317f55c881875e5bcb741c00b090e1e1c2204d3b276aff069ac2"
	imageTestC05 = "fc8c011e40853708f49a90759af0c9e5b738e3116dca9ed641539af0827cf9ac"
	imageTestC06 = "0dbb5487445845169a856b31fe2877c6cb84df41cc170f6ae9c41d062164fd7d"
	imageTestC07 = "10a4199bd27aa176b2e1c052bd2a18cd961f1a861793796e4e6a594ae9073e01"
	imageTestC08 = "0b1d7e322458a7b09a40321abd7c70ab71b3f1d436bd4b2dc1e20be014e967f3"
	imageTestC09 = "e394106e180d6e4d4ff403a0f506fef3ec83f07000a493c0e1b15648bc2ffd7f"
	imageTestC10 = "b9965ddde341cf712ffa9655cc85caf2da2608461248c8f0f2217d5e00c2b44e"
	imageTestC12 = "aee487de02b1d0365069254d3bd46173099f21f15992b066640f4de27a9d910b"
	imageTestC13 = "7f33e7092506562aa419b6429fe944e1e0d1cc0c6e59ba7df0ad686b47cbda39"
	imageTestC14 = "d8ca4a9d2c487486e0dd12ea08862b0c8c0f87c292b2dab4010b85bce5c30fc9"
	imageTestC15 = "bb62b3599ef92d59b61fef4ed4a1deb0f6ce41c56921ee9f83faee050217fea2"
	imageTestHX  = "cc9911b53cb802ce58012714419aef9ad9c195bd8edf0617381efbd00d27a84c"
	imageTestHY  = "a92ec5b09f47d0d0b02daac535a9b2633d7268fad9262957a81f31b1fd1abd11"
)

const (
	imageTestLeafPreimage   = "525542494e5f5554584f5f545245455f563101"
	imageTestBranchPreimage = "525542494e5f5554584f5f545245455f563102"
)

type imageProofLeaf struct {
	entry UTXOImageEntry
	s, k  string
}

func imageProofLeaves(t *testing.T) [8]imageProofLeaf {
	t.Helper()
	// A,B,C,X,Y,X2,vout255,vout256: the LE leaf and BE key literals are
	// independently written; no routing/entry encoder derives either side.
	txids := [8]string{
		strings.Repeat("00", 32), strings.Repeat("00", 32),
		"80" + strings.Repeat("00", 31), "a7" + strings.Repeat("55", 31),
		"b9" + strings.Repeat("ff", 31), "a7" + strings.Repeat("55", 31),
		strings.Repeat("00", 32), strings.Repeat("00", 32),
	}
	vouts := [8]uint32{0, 1, 0, 0, 0, 1, 255, 256}
	leafVout := [8]string{"00000000", "01000000", "00000000", "00000000", "00000000", "01000000", "ff000000", "00010000"}
	keyVout := [8]string{"00000000", "00000001", "00000000", "00000000", "00000000", "00000001", "000000ff", "00000100"}
	var leaves [8]imageProofLeaf
	for i := range leaves {
		leaves[i].entry = imageTestEntry()
		leaves[i].entry.Outpoint.Vout = vouts[i]
		copy(leaves[i].entry.Outpoint.Txid[:], imageTestHex(t, txids[i]))
		leaves[i].s = txids[i] + leafVout[i] + imageTestS[72:]
		leaves[i].k = txids[i] + keyVout[i]
	}
	return leaves
}

func imageProofHash(t *testing.T, literalPreimage string) string {
	t.Helper()
	hash := sha3.Sum256(imageTestHex(t, literalPreimage))
	return hex.EncodeToString(hash[:])
}

func imageProofParent3(t *testing.T) string {
	t.Helper()
	x2 := imageProofHash(t, imageTestLeafPreimage+"a7"+strings.Repeat("55", 31)+"01000000"+
		"0100000000000000"+"0000"+"21"+"01"+strings.Repeat("11", 32)+"0000000000000000"+"00")
	b287 := imageProofHash(t, imageTestBranchPreimage+"011f"+"a7"+strings.Repeat("55", 31)+"00000000"+imageTestHX+x2)
	return imageProofHash(t, imageTestBranchPreimage+"0003"+"a0"+strings.Repeat("00", 35)+b287+imageTestHY)
}

func imageProofEdge(t *testing.T, depth uint16, hash string) UTXOImageEdge {
	t.Helper()
	return UTXOImageEdge{Depth: depth, Hash: [32]byte(imageTestHex(t, hash))}
}

func imageProofPayload(t *testing.T, root, start, body string) []byte {
	t.Helper()
	return imageTestHex(t, "0100000000000000"+"0000000000000000"+strings.Repeat("11", 32)+root+start+"794d0200"+body)
}

func imageProofReply(t *testing.T, id string, payload []byte) UTXOImageReply {
	t.Helper()
	reply, ok, reason := DecodeUTXOImageReply(imageTestCommand(t, "7574786f696d670000000000"), payload)
	if !ok || reason != "" {
		t.Fatalf("%s_SCALAR: ok=%v reason=%q want=true/empty", id, ok, reason)
	}
	return reply
}

func imageProofAccept(t *testing.T, id string, payload []byte, want UTXOImageRange) {
	t.Helper()
	before := bytes.Clone(payload)
	reply := imageProofReply(t, id, payload)
	for range 2 {
		got, ok, reason := VerifyUTXOImageChunk(reply)
		if !ok || reason != "" || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got=(ok=%v reason=%q range=%#v) want=(ok=true reason=empty range=%#v)", id, ok, reason, got, want)
		}
	}
	if !bytes.Equal(payload, before) {
		t.Fatalf("%s_INPUT: original payload changed", id)
	}
}

func imageProofReject(t *testing.T, id string, payload []byte) {
	t.Helper()
	before := bytes.Clone(payload)
	reply := imageProofReply(t, id, payload)
	for range 2 {
		got, ok, reason := VerifyUTXOImageChunk(reply)
		if ok || reason != "image_range" || !reflect.DeepEqual(got, UTXOImageRange{}) {
			t.Fatalf("%s_C6_ZERO_RANGE: got=(%#v,%v,%q) want=(zero,false,image_range)", id, got, ok, reason)
		}
	}
	if !bytes.Equal(payload, before) {
		t.Fatalf("%s_INPUT: rejected payload changed", id)
	}
}

func TestUTXOImageRanges(t *testing.T) {
	f := imageProofLeaves(t)
	a, x, y := f[0], f[3], f[4]
	for _, tc := range []struct {
		id, root, start, body string
		want                  UTXOImageRange
	}{
		{"C3_EMPTY", imageTestC01, a.k, "00000000" + "00" + "0000" + "0000", UTXOImageRange{Terminal: true}},
		{"C3_SINGLETON_PRESENT", imageTestC02, a.k, "01000000" + a.s + "00" + "0000" + "0000", UTXOImageRange{Entries: []UTXOImageEntry{a.entry}, Terminal: true}},
		{"C3_BEFORE_FIRST", imageTestC07, a.k, "01000000" + x.s + "00" + "0000" + "0100" + "0003" + imageTestHY, UTXOImageRange{Entries: []UTXOImageEntry{x.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 3, imageTestHY)}}},
		{"C3_ABSENT_INTERNAL", imageTestC07, "b0" + strings.Repeat("00", 35), "01000000" + y.s + "01" + x.s + "0000" + "0000", UTXOImageRange{Entries: []UTXOImageEntry{y.entry}, Predecessor: &x.entry, Terminal: true}},
		{"C3_AFTER_LAST", imageTestC07, strings.Repeat("ff", 36), "00000000" + "01" + y.s + "0100" + "0003" + imageTestHX + "0000", UTXOImageRange{Predecessor: &y.entry, Terminal: true}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			imageProofAccept(t, tc.id, imageProofPayload(t, tc.root, tc.start, tc.body), tc.want)
		})
	}
}

func TestUTXOImageProofSkeleton(t *testing.T) {
	f := imageProofLeaves(t)
	a, b, c, x, y, x2, v255, v256 := f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]
	hc := imageProofHash(t, imageTestLeafPreimage+c.s)
	opaqueEmpty := imageProofHash(t, imageTestBranchPreimage+"011f"+strings.Repeat("00", 36)+imageTestC02+imageTestC01)
	for _, tc := range []struct {
		id, root, start, body string
		want                  UTXOImageRange
	}{
		{"C4_DEPTH0", imageTestC04, a.k, "02000000" + a.s + c.s + "00" + "0000" + "0000", UTXOImageRange{Entries: []UTXOImageEntry{a.entry, c.entry}, Terminal: true}},
		{"C4_DEPTH3", imageTestC07, x.k, "02000000" + x.s + y.s + "00" + "0000" + "0000", UTXOImageRange{Entries: []UTXOImageEntry{x.entry, y.entry}, Terminal: true}},
		{"C4_MASK_TAIL3", imageTestC07, x.k, "01000000" + x.s + "00" + "0000" + "0100" + "0003" + imageTestHY, UTXOImageRange{Entries: []UTXOImageEntry{x.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 3, imageTestHY)}}},
		{"C4_C05_A_RIGHT287", imageTestC05, a.k, "01000000" + a.s + "00" + "0000" + "0100" + "011f" + imageTestC03, UTXOImageRange{Entries: []UTXOImageEntry{a.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 287, imageTestC03)}}},
		{"C4_C05_B_LEFT287", imageTestC05, b.k, "01000000" + b.s + "00" + "0100" + "011f" + imageTestC02 + "0000", UTXOImageRange{Entries: []UTXOImageEntry{b.entry}, Terminal: true}},
		{"C4_NESTED_ABS287", imageTestC06, b.k, "01000000" + b.s + "00" + "0100" + "011f" + imageTestC02 + "0100" + "0000" + hc, UTXOImageRange{Entries: []UTXOImageEntry{b.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 0, hc)}}},
		{"C4_ABS_PARENT3", imageProofParent3(t), x2.k, "01000000" + x2.s + "00" + "0100" + "011f" + imageTestHX + "0100" + "0003" + imageTestHY, UTXOImageRange{Entries: []UTXOImageEntry{x2.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 3, imageTestHY)}}},
		{"C4_C10_DEPTH279", imageTestC10, v255.k, "02000000" + v255.s + v256.s + "00" + "0000" + "0000", UTXOImageRange{Entries: []UTXOImageEntry{v255.entry, v256.entry}, Terminal: true}},
		{"C4_C10_LEFT279", imageTestC10, v256.k, "01000000" + v256.s + "00" + "0100" + "0117" + imageTestC08 + "0000", UTXOImageRange{Entries: []UTXOImageEntry{v256.entry}, Terminal: true}},
		{"C4_C10_RIGHT279", imageTestC10, v255.k, "01000000" + v255.s + "00" + "0000" + "0100" + "0117" + imageTestC09, UTXOImageRange{Entries: []UTXOImageEntry{v255.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 279, imageTestC09)}}},
		{"C4_OPAQUE_EMPTY", opaqueEmpty, a.k, "01000000" + a.s + "00" + "0000" + "0100" + "011f" + imageTestC01, UTXOImageRange{Entries: []UTXOImageEntry{a.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 287, imageTestC01)}}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			payload := imageProofPayload(t, tc.root, tc.start, tc.body)
			if tc.id == "C4_ABS_PARENT3" && len(payload) != 286 {
				t.Fatalf("C4_ABS_PARENT3_LENGTH: got=%d want=286", len(payload))
			}
			imageProofAccept(t, tc.id, payload, tc.want)
		})
	}
}

func TestUTXOImageProofFields(t *testing.T) {
	a := imageTestEntry()
	coinbase, height, value, data := a, a, a, imageTestEntry()
	coinbase.Entry.CreatedByCoinbase, height.Entry.CreationHeight, value.Entry.Value = true, 1, 2
	data.Entry.CovenantData = append([]byte{1}, bytes.Repeat([]byte{0x22}, 32)...)
	for _, tc := range []struct {
		id, root, s string
		entry       UTXOImageEntry
	}{
		{"C4_C02", imageTestC02, imageTestS, a},
		{"C4_C12_COINBASE", imageTestC12, imageTestS[:176] + "01", coinbase},
		{"C4_C13_HEIGHT", imageTestC13, imageTestS[:160] + "0100000000000000" + "00", height},
		{"C4_C14_VALUE", imageTestC14, imageTestS[:72] + "0200000000000000" + imageTestS[88:], value},
		{"C4_C15_DATA", imageTestC15, imageTestS[:96] + strings.Repeat("22", 32) + "0000000000000000" + "00", data},
	} {
		imageProofAccept(t, tc.id, imageProofPayload(t, tc.root, strings.Repeat("00", 36), "01000000"+tc.s+"00"+"0000"+"0000"), UTXOImageRange{Entries: []UTXOImageEntry{tc.entry}, Terminal: true})
	}
	for _, tc := range []struct {
		id, compact string
		n           int
	}{
		{"C2_DECODE_DATA0", "00", 0},
		{"C2_DECODE_DATA252", "fc", 252},
		{"C2_DECODE_DATA253", "fdfd00", 253},
		{"C2_DECODE_DATA65535", "fdffff", 65535},
		{"C2_DECODE_DATA65536", "fe00000100", 65536},
	} {
		s := strings.Repeat("00", 36) + "0100000000000000" + "0000" + tc.compact + strings.Repeat("22", tc.n) + strings.Repeat("00", 9)
		entry := UTXOImageEntry{Entry: UtxoEntry{Value: 1}}
		if tc.n != 0 {
			entry.Entry.CovenantData = bytes.Repeat([]byte{0x22}, tc.n)
		}
		imageProofAccept(t, tc.id, imageProofPayload(t, imageProofHash(t, imageTestLeafPreimage+s), strings.Repeat("00", 36), "01000000"+s+"00"+"0000"+"0000"), UTXOImageRange{Entries: []UTXOImageEntry{entry}, Terminal: true})
	}
	for _, tc := range []struct {
		id, value, covenant, height, txid string
		entry                             UTXOImageEntry
	}{
		{"C2_DECODE_VALUE0", "0000000000000000", "0000", "0000000000000000", strings.Repeat("00", 32), UTXOImageEntry{}},
		{"C2_DECODE_VALUE_MAX", "ffffffffffffffff", "0000", "0000000000000000", strings.Repeat("00", 32), UTXOImageEntry{Entry: UtxoEntry{Value: ^uint64(0)}}},
		{"C2_DECODE_TYPE1", "0100000000000000", "0100", "0000000000000000", strings.Repeat("00", 32), UTXOImageEntry{Entry: UtxoEntry{Value: 1, CovenantType: 1}}},
		{"C2_DECODE_HEIGHT_MAX", "0100000000000000", "0000", "ffffffffffffffff", strings.Repeat("00", 32), UTXOImageEntry{Entry: UtxoEntry{Value: 1, CreationHeight: ^uint64(0)}}},
	} {
		s := tc.txid + "00000000" + tc.value + tc.covenant + "00" + tc.height + "00"
		imageProofAccept(t, tc.id, imageProofPayload(t, imageProofHash(t, imageTestLeafPreimage+s), strings.Repeat("00", 36), "01000000"+s+"00"+"0000"+"0000"), UTXOImageRange{Entries: []UTXOImageEntry{tc.entry}, Terminal: true})
	}
	rawTxid := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	rawEntry := imageTestEntry()
	copy(rawEntry.Outpoint.Txid[:], imageTestHex(t, rawTxid))
	s := rawTxid + imageTestS[64:]
	imageProofAccept(t, "C2_DECODE_RAW_TXID", imageProofPayload(t, imageProofHash(t, imageTestLeafPreimage+s), rawTxid+"00000000", "01000000"+s+"00"+"0000"+"0000"), UTXOImageRange{Entries: []UTXOImageEntry{rawEntry}, Terminal: true})
}

func TestUTXOImageProofRejections(t *testing.T) {
	f := imageProofLeaves(t)
	a, b, c, x, y := f[0], f[1], f[2], f[3], f[4]
	hc := imageProofHash(t, imageTestLeafPreimage+c.s)
	outer := imageProofHash(t, imageTestBranchPreimage+"0000"+strings.Repeat("00", 36)+imageTestC02+imageTestC07)
	tied := imageProofHash(t, imageTestBranchPreimage+"011f"+strings.Repeat("00", 36)+imageTestC02+imageTestC05)
	wrongPrefix := imageProofHash(t, imageTestBranchPreimage+"0003"+"b0"+strings.Repeat("00", 35)+imageTestHX+imageTestHY)
	value2 := a.s[:72] + "0200000000000000" + a.s[88:]
	for _, tc := range []struct{ id, root, start, body string }{
		{"C6_DUPLICATE_IDENTICAL", imageTestC02, a.k, "02000000" + a.s + a.s + "00" + "0000" + "0000"},
		{"C6_DUPLICATE_CONFLICTING", imageTestC02, a.k, "02000000" + a.s + value2 + "00" + "0000" + "0000"},
		{"C6_DESCENDING_K", imageTestC05, a.k, "02000000" + b.s + a.s + "00" + "0000" + "0000"},
		{"C6_FIRST_BELOW_START", imageTestC05, b.k, "02000000" + a.s + b.s + "00" + "0000" + "0000"},
		{"C6_PRESENT_START_PREDECESSOR", imageTestC05, b.k, "01000000" + b.s + "01" + a.s + "0000" + "0000"},
		{"C6_PREDECESSOR_CONTRADICTS_START", imageTestC07, a.k, "01000000" + y.s + "01" + x.s + "0000" + "0000"},
		{"C6_PREDECESSOR_DUPLICATES_RETURN", imageTestC02, b.k, "01000000" + a.s + "01" + a.s + "0000" + "0000"},
		{"C6_PREDECESSOR_DESCENDS", imageTestC05, "00000000" + strings.Repeat("00", 31) + "02", "01000000" + a.s + "01" + b.s + "0000" + "0000"},
		{"C6_MISSING_PREDECESSOR", imageTestC07, "b0" + strings.Repeat("00", 35), "01000000" + y.s + "00" + "0100" + "0003" + imageTestHX + "0000"},
		{"C6_FALSE_START_TERMINAL", imageTestC07, a.k, "01000000" + y.s + "00" + "0100" + "0003" + imageTestHX + "0000"},
		{"C6_NONNEAREST_PREDECESSOR", imageTestC06, b.k, "01000000" + c.s + "01" + a.s + "0000" + "0000"},
		{"C6_ZERO_NONEMPTY", imageTestC02, a.k, "00000000" + "00" + "0000" + "0000"},
		{"C6_ZERO_NONTERMINAL", imageTestC06, strings.Repeat("ff", 36), "00000000" + "01" + b.s + "0100" + "011f" + imageTestC02 + "0100" + "0000" + hc},
		{"C6_HIDDEN_INTERIOR", imageTestC06, a.k, "02000000" + a.s + c.s + "00" + "0000" + "0100" + "011f" + imageTestC03},
		{"C6_HIDDEN_GAP", imageTestC06, a.k, "02000000" + a.s + c.s + "00" + "0000" + "0000"},
		{"C6_MISSING_EDGE", imageTestC05, a.k, "01000000" + a.s + "00" + "0000" + "0000"},
		{"C6_EXTRA_DERIVED_EDGE", imageTestC05, a.k, "01000000" + a.s + "00" + "0100" + "011f" + imageTestC02 + "0100" + "011f" + imageTestC03},
		{"C6_UNUSED_RIGHT", imageTestC05, a.k, "01000000" + a.s + "00" + "0000" + "0200" + "0000" + hc + "011f" + imageTestC03},
		{"C6_REPEATED_LEFT", outer, y.k, "01000000" + y.s + "00" + "0300" + "0000" + imageTestC02 + "0000" + imageTestC02 + "0003" + imageTestHX + "0000"},
		{"C6_DESCENDING_DEPTH", outer, y.k, "01000000" + y.s + "00" + "0200" + "0003" + imageTestHX + "0000" + imageTestC02 + "0000"},
		{"C6_TIED_INTERNAL_LEFT", tied, a.k, "02000000" + a.s + b.s + "00" + "0100" + "011f" + imageTestC02 + "0000"},
		{"C6_TIED_LEFT_RIGHT", imageTestC05, a.k, "02000000" + a.s + b.s + "00" + "0100" + "011f" + imageTestC02 + "0100" + "011f" + imageTestC03},
		{"C6_WRONG_LEFT_SIDE", imageTestC05, a.k, "01000000" + a.s + "00" + "0100" + "011f" + imageTestC03 + "0000"},
		{"C6_WRONG_RIGHT_SIDE", imageTestC05, b.k, "01000000" + b.s + "00" + "0000" + "0100" + "011f" + imageTestC02},
		{"C6_WRONG_PREFIX", wrongPrefix, x.k, "02000000" + x.s + y.s + "00" + "0000" + "0000"},
		{"C6_FALSE_TERMINAL", imageTestC07, x.k, "01000000" + x.s + "00" + "0000" + "0000"},
		{"C6_WRONG_ROOT", imageTestC03, a.k, "01000000" + a.s + "00" + "0000" + "0000"},
		{"C6_OPAQUE_DERIVED_BRANCH", imageTestC06, a.k, "03000000" + a.s + b.s + c.s + "00" + "0100" + "0000" + imageTestC05 + "0000"},
		{"C6_PARENT_DEPTH_IN_CHILD", imageTestC06, b.k, "01000000" + b.s + "00" + "0100" + "011f" + imageTestC02 + "0200" + "0000" + hc + "0000" + hc},
		{"C6_INTERNAL_LEFT_FAILURE", imageTestC06, a.k, "03000000" + a.s + b.s + c.s + "00" + "0100" + "011f" + imageTestC02 + "0000"},
		{"C6_INTERNAL_RIGHT_FAILURE", outer, a.k, "03000000" + a.s + x.s + y.s + "00" + "0000" + "0100" + "0003" + imageTestHY},
		{"C6_EMPTY_WITH_EDGE", imageTestC01, a.k, "00000000" + "00" + "0100" + "0000" + imageTestC02 + "0000"},
	} {
		t.Run(tc.id, func(t *testing.T) { imageProofReject(t, tc.id, imageProofPayload(t, tc.root, tc.start, tc.body)) })
	}
	_, raw := imageTestQuery(t)
	negative, ok, reason := DecodeUTXOImageReply(imageTestCommand(t, "7574786f6e6f74617661696c"), raw)
	if !ok || reason != "" {
		t.Fatalf("C6_NEGATIVE_SETUP: ok=%v reason=%q", ok, reason)
	}
	for _, reply := range []UTXOImageReply{{}, negative} {
		got, ok, reason := VerifyUTXOImageChunk(reply)
		if ok || reason != "" || !reflect.DeepEqual(got, UTXOImageRange{}) {
			t.Fatalf("C6_NO_CHUNK: got=%#v/%v/%q want=zero/false/empty", got, ok, reason)
		}
	}
}

func TestUTXOImageProofReplyDomains(t *testing.T) {
	for _, tc := range []struct {
		id     string
		offset int
		value  string
	}{
		{"C2_VERIFY_ID0", 0, "0000000000000000"},
		{"C2_VERIFY_HEIGHT_WIDE", 8, "0000000001000000"},
		{"C2_VERIFY_LIMIT_LOW", 116, "784d0200"},
	} {
		payload := imageProofPayload(t, imageTestC02, strings.Repeat("00", 36), "01000000"+imageTestS+"00"+"0000"+"0000")
		copy(payload[tc.offset:], imageTestHex(t, tc.value))
		imageProofAccept(t, tc.id, payload, UTXOImageRange{Entries: []UTXOImageEntry{imageTestEntry()}, Terminal: true})
	}
}

func TestUTXOImageSuccessor(t *testing.T) {
	for _, tc := range []struct {
		id, input, want string
		ok              bool
	}{
		{"C3_SUCCESSOR_ZERO", strings.Repeat("00", 36), strings.Repeat("00", 35) + "01", true},
		{"C3_SUCCESSOR_255", strings.Repeat("00", 32) + "000000ff", strings.Repeat("00", 32) + "00000100", true},
		{"C3_SUCCESSOR_VOUT_CARRY", strings.Repeat("00", 31) + "01" + "ffffffff", strings.Repeat("00", 31) + "02" + "00000000", true},
		{"C3_SUCCESSOR_TXID_CARRY", strings.Repeat("00", 30) + "01ff" + "ffffffff", strings.Repeat("00", 30) + "0200" + "00000000", true},
		{"C3_SUCCESSOR_ALLFF", strings.Repeat("ff", 36), strings.Repeat("00", 36), false},
	} {
		key := [36]byte(imageTestHex(t, tc.input))
		before := key
		got, ok := UTXOImageSuccessor(key)
		want := [36]byte(imageTestHex(t, tc.want))
		if got != want || ok != tc.ok || key != before {
			t.Fatalf("%s: got=%x ok=%v want=%x/%v", tc.id, got, ok, want, tc.ok)
		}
	}
}

func TestUTXOImageOwnership(t *testing.T) {
	f := imageProofLeaves(t)
	b, c, x, y := f[1], f[2], f[3], f[4]
	hc := imageProofHash(t, imageTestLeafPreimage+c.s)
	for _, tc := range []struct {
		id, root, start, body string
		want                  UTXOImageRange
	}{
		{"C4_OWNED_ENTRY_FRONTIER", imageTestC06, b.k, "01000000" + b.s + "00" + "0100" + "011f" + imageTestC02 + "0100" + "0000" + hc, UTXOImageRange{Entries: []UTXOImageEntry{b.entry}, RightEdge: []UTXOImageEdge{imageProofEdge(t, 0, hc)}}},
		{"C4_OWNED_PREDECESSOR", imageTestC07, "b0" + strings.Repeat("00", 35), "01000000" + y.s + "01" + x.s + "0000" + "0000", UTXOImageRange{Entries: []UTXOImageEntry{y.entry}, Predecessor: &x.entry, Terminal: true}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			payload := imageProofPayload(t, tc.root, tc.start, tc.body)
			before := bytes.Clone(payload)
			reply := imageProofReply(t, tc.id, payload)
			if !bytes.Equal(payload, before) {
				t.Fatalf("%s_DECODE_INPUT: payload changed", tc.id)
			}
			// Reuse the whole transport backing for another scalar-canonical
			// message. An alias must fail this result assertion, not panic on
			// an unrelated corrupted count/span before the owner is observed.
			replacement := bytes.Clone(payload)
			copy(replacement[160:168], imageTestHex(t, "0200000000000000"))
			copy(payload, replacement)
			got, ok, reason := VerifyUTXOImageChunk(reply)
			if !ok || reason != "" || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s_FRAME_REUSE: got=%#v/%v/%q want=%#v/true/empty", tc.id, got, ok, reason, tc.want)
			}
			if got.Predecessor != nil {
				got.Predecessor.Entry.CovenantData[0] ^= 0xff
				if !reflect.DeepEqual(got.Entries, tc.want.Entries) {
					t.Fatalf("%s_OUTPUT_ROWS_ALIAS: entry changed with predecessor", tc.id)
				}
			}
			got.Entries[0].Entry.CovenantData[0] ^= 0xff
			if len(got.RightEdge) != 0 {
				got.RightEdge[0].Depth ^= 1
				got.RightEdge[0].Hash[0] ^= 0xff
			}
			again, ok, reason := VerifyUTXOImageChunk(reply)
			if !ok || reason != "" || !reflect.DeepEqual(again, tc.want) {
				t.Fatalf("%s_REPEAT: got=%#v/%v/%q want=%#v/true/empty", tc.id, again, ok, reason, tc.want)
			}
			if !bytes.Equal(payload, replacement) {
				t.Fatalf("%s_VERIFY_INPUT: reused frame changed", tc.id)
			}
		})
	}
}

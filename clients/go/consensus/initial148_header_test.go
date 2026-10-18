package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

const (
	initial148PrevHex   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	initial148MerkleHex = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	initial148TargetHex = "8000000000000000000000000000000000000000000000000000000000000001"
	initial148RootHex   = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	initial148MaxHex    = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

type initial148Fixture struct {
	name string
	raw  []byte
	want Initial148Header
}

func initial148Hex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("initial148 oracle domain: hex: %v", err)
	}
	return b
}

func initial148Array(t *testing.T, s string) [32]byte {
	t.Helper()
	b := initial148Hex(t, s)
	if len(b) != 32 {
		t.Fatalf("initial148 oracle domain: raw32 length=%d", len(b))
	}
	return [32]byte(b)
}

func initial148Literal(t *testing.T) ([]byte, Initial148Header) {
	t.Helper()
	raw := initial148Hex(t, "78563412"+initial148PrevHex+initial148MerkleHex+
		"0102030405060708"+initial148TargetHex+initial148RootHex+"1112131415161718")
	want := Initial148Header{
		Version:       0x12345678,
		PrevBlockHash: initial148Array(t, initial148PrevHex),
		MerkleRoot:    initial148Array(t, initial148MerkleHex),
		Timestamp:     0x0807060504030201,
		Target:        initial148Array(t, initial148TargetHex),
		UtxoRoot:      initial148Array(t, initial148RootHex),
		Nonce:         0x1817161514131211,
	}
	return raw, want
}

func initial148Fixtures(t *testing.T) []initial148Fixture {
	t.Helper()
	literal, fields := initial148Literal(t)
	max32 := initial148Array(t, initial148MaxHex)
	return []initial148Fixture{
		{"L", literal, fields},
		{"Z148", make([]byte, 148), Initial148Header{}},
		{"F148", bytes.Repeat([]byte{0xff}, 148), Initial148Header{
			Version: 0xffffffff, PrevBlockHash: max32, MerkleRoot: max32,
			Timestamp: 0xffffffffffffffff, Target: max32, UtxoRoot: max32,
			Nonce: 0xffffffffffffffff,
		}},
	}
}

func initial148Fields(t *testing.T, got, want Initial148Header, diagnostic string) {
	t.Helper()
	if got.Version != want.Version {
		t.Fatalf("%s: initial148 literal fields: Version=%x want=%x", diagnostic, got.Version, want.Version)
	}
	if got.PrevBlockHash != want.PrevBlockHash {
		t.Fatalf("%s: initial148 literal fields: PrevBlockHash=%x want=%x", diagnostic, got.PrevBlockHash, want.PrevBlockHash)
	}
	if got.MerkleRoot != want.MerkleRoot {
		t.Fatalf("%s: initial148 literal fields: MerkleRoot=%x want=%x", diagnostic, got.MerkleRoot, want.MerkleRoot)
	}
	if got.Timestamp != want.Timestamp {
		t.Fatalf("%s: initial148 literal fields: Timestamp=%x want=%x", diagnostic, got.Timestamp, want.Timestamp)
	}
	if got.Target != want.Target {
		t.Fatalf("%s: initial148 literal fields: Target=%x want=%x", diagnostic, got.Target, want.Target)
	}
	if got.UtxoRoot != want.UtxoRoot {
		t.Fatalf("%s: initial148 literal fields: UtxoRoot=%x want=%x", diagnostic, got.UtxoRoot, want.UtxoRoot)
	}
	if got.Nonce != want.Nonce {
		t.Fatalf("%s: initial148 literal fields: Nonce=%x want=%x", diagnostic, got.Nonce, want.Nonce)
	}
}

func initial148Unchanged(t *testing.T, raw, before []byte) {
	t.Helper()
	if !bytes.Equal(raw, before) {
		t.Fatal("initial148 input mutation")
	}
}

func initial148Codec(t *testing.T, raw []byte, want Initial148Header, diagnostic string) {
	t.Helper()
	before := bytes.Clone(raw)
	got, err := ParseInitial148HeaderBytes(raw)
	if err != nil {
		t.Fatalf("%s: parse error=%v", diagnostic, err)
	}
	initial148Fields(t, got, want, diagnostic)
	initial148Unchanged(t, raw, before)
	initial148Next(t)
	valueBefore := want
	encoded := EncodeInitial148Header(want)
	if !bytes.Equal(encoded[:], before) {
		t.Fatalf("%s: initial148 literal encoding: got=%x want=%x", diagnostic, encoded, before)
	}
	if want != valueBefore {
		t.Fatal("initial148 owned value: encoder changed input value")
	}
	initial148Unchanged(t, raw, before)
	initial148Next(t)
}

func TestInitial148Header_Codec(t *testing.T) {
	if Initial148HeaderBytes != 148 {
		t.Fatalf("initial148 exact length: constant=%d want=148", Initial148HeaderBytes)
	}
	for _, tc := range initial148Fixtures(t) {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.raw) != 148 {
				t.Fatalf("initial148 oracle domain: literal length=%d", len(tc.raw))
			}
			initial148Codec(t, tc.raw, tc.want, "initial148 literal fields")
		})
	}
}

func TestInitial148Header_Domains(t *testing.T) {
	base, want := initial148Literal(t)
	versions := []struct {
		value uint32
		wire  [4]byte
	}{
		{0, [4]byte{}},
		{1, [4]byte{1, 0, 0, 0}},
		{0x80000000, [4]byte{0, 0, 0, 0x80}},
		{0xffffffff, [4]byte{0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range versions {
		t.Run(fmt.Sprintf("Version_%08x", tc.value), func(t *testing.T) {
			raw, fields := bytes.Clone(base), want
			copy(raw[0:4], tc.wire[:])
			fields.Version = tc.value
			initial148Codec(t, raw, fields, "initial148 structural domain")
		})
	}
	initial148Uint64Domains(t, base, want)
	initial148RawDomains(t, base, want)
}

func initial148Uint64Domains(t *testing.T, base []byte, want Initial148Header) {
	t.Helper()
	cases := []struct {
		value uint64
		wire  [8]byte
	}{
		{0, [8]byte{}},
		{1, [8]byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{0xffffffffffffffff, [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, field := range []string{"Timestamp", "Nonce"} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s_%016x", field, tc.value), func(t *testing.T) {
				raw, fields := bytes.Clone(base), want
				if field == "Timestamp" {
					copy(raw[68:76], tc.wire[:])
					fields.Timestamp = tc.value
				} else {
					copy(raw[140:148], tc.wire[:])
					fields.Nonce = tc.value
				}
				initial148Codec(t, raw, fields, "initial148 structural domain")
			})
		}
	}
}

func initial148RawDomains(t *testing.T, base []byte, want Initial148Header) {
	t.Helper()
	values := []struct {
		name  string
		value [32]byte
	}{
		{"zero", [32]byte{}},
		{"ff", initial148Array(t, initial148MaxHex)},
		{"literal", initial148Array(t, initial148RootHex)},
		{"high_bit", initial148Array(t, initial148TargetHex)},
	}
	for _, field := range []string{"UtxoRoot", "Target"} {
		for _, tc := range values {
			t.Run(field+"_"+tc.name, func(t *testing.T) {
				raw, fields := bytes.Clone(base), want
				if field == "UtxoRoot" {
					copy(raw[108:140], tc.value[:])
					fields.UtxoRoot = tc.value
				} else {
					copy(raw[76:108], tc.value[:])
					fields.Target = tc.value
				}
				initial148Codec(t, raw, fields, "initial148 structural domain")
			})
		}
	}
}

func initial148Error(t *testing.T, err error, code, msg, diagnostic string) {
	t.Helper()
	te, ok := err.(*TxError)
	if !ok || te == nil {
		t.Fatalf("%s: concrete error=%T %v want=*TxError", diagnostic, err, err)
	}
	if string(te.Code) != code || te.Msg != msg || te.Cause() != TxErrorCause(0) {
		t.Fatalf("%s: tuple=(%s,%q,%d) want=(%s,%q,0)", diagnostic, te.Code, te.Msg, te.Cause(), code, msg)
	}
	if te.Error() != code+": "+msg {
		t.Fatalf("%s: Error()=%q want=%q", diagnostic, te.Error(), code+": "+msg)
	}
}

func initial148WrongLength(t *testing.T, raw []byte) {
	t.Helper()
	before := bytes.Clone(raw)
	header, err := ParseInitial148HeaderBytes(raw)
	initial148Error(t, err, "TX_ERR_PARSE", "block header length mismatch", "initial148 exact length: parse: initial148 length error tuple")
	if header != (Initial148Header{}) {
		t.Fatalf("initial148 zero result: parse len=%d got=%#v", len(raw), header)
	}
	initial148Unchanged(t, raw, before)
	initial148Next(t)
	before = bytes.Clone(raw)
	digest, err := Initial148BlockHash(raw)
	initial148Error(t, err, "TX_ERR_PARSE", "block hash: invalid header length", "initial148 exact length: hash: initial148 length error tuple")
	if digest != ([32]byte{}) {
		t.Fatalf("initial148 zero result: hash len=%d got=%x", len(raw), digest)
	}
	initial148Unchanged(t, raw, before)
	initial148Next(t)
	for _, target := range [][32]byte{{}, initial148Array(t, initial148MaxHex)} {
		before = bytes.Clone(raw)
		err := Initial148PowCheck(raw, target)
		initial148Error(t, err, "TX_ERR_PARSE", "pow: invalid header length", "initial148 exact length: pow: initial148 length error tuple")
		initial148Unchanged(t, raw, before)
		initial148Next(t)
	}
}

func TestInitial148Header_Length(t *testing.T) {
	literal, _ := initial148Literal(t)
	t.Run("nil", func(t *testing.T) { initial148WrongLength(t, nil) })
	t.Run("nonnil_empty", func(t *testing.T) { initial148WrongLength(t, make([]byte, 0)) })
	for n := range 148 {
		t.Run(fmt.Sprintf("prefix_%d", n), func(t *testing.T) {
			initial148WrongLength(t, bytes.Clone(literal[:n]))
		})
	}
	for _, suffix := range [][]byte{{0x00}, {0xff}, bytes.Repeat([]byte{0xff}, 148)} {
		t.Run(fmt.Sprintf("suffix_%d_%02x", len(suffix), suffix[0]), func(t *testing.T) {
			raw := append(bytes.Clone(literal), suffix...)
			initial148WrongLength(t, raw)
		})
	}
}

func initial148Hash(t *testing.T, raw []byte) {
	t.Helper()
	before := bytes.Clone(raw)
	want := sha3.Sum256(before)
	got, err := Initial148BlockHash(raw)
	if err != nil || got != want {
		t.Fatalf("initial148 full preimage: got=%x err=%v want=%x", got, err, want)
	}
	initial148Unchanged(t, raw, before)
	initial148Next(t)
}

func TestInitial148Header_Hash(t *testing.T) {
	for _, tc := range initial148Fixtures(t) {
		t.Run(tc.name, func(t *testing.T) { initial148Hash(t, tc.raw) })
	}
	literal, _ := initial148Literal(t)
	for _, offset := range []int{108, 139, 147, 76} {
		t.Run(fmt.Sprintf("literal_byte_%d", offset), func(t *testing.T) {
			raw := bytes.Clone(literal)
			raw[offset] ^= 1
			initial148Hash(t, raw)
		})
	}
}

func initial148PowOracle(t *testing.T) ([]byte, [32]byte, [32]byte) {
	t.Helper()
	raw := make([]byte, 148)
	digest := sha3.Sum256(raw)
	limit := initial148Array(t, initial148MaxHex)
	d := new(big.Int).SetBytes(digest[:])
	if d.Cmp(big.NewInt(1)) <= 0 || d.Cmp(new(big.Int).SetBytes(limit[:])) >= 0 {
		t.Fatalf("initial148 oracle domain: require 1<D<allff; D=%x", digest)
	}
	if POW_LIMIT != limit {
		t.Fatalf("initial148 oracle domain: actual POW_LIMIT=%x want=allff; rebind required", POW_LIMIT)
	}
	return raw, digest, limit
}

func initial148Target(digest [32]byte, delta int64) [32]byte {
	n := new(big.Int).SetBytes(digest[:])
	n.Add(n, big.NewInt(delta))
	var out [32]byte
	n.FillBytes(out[:])
	return out
}

func initial148Pow(t *testing.T, raw []byte, target [32]byte, code, msg, diagnostic string) {
	t.Helper()
	before, targetBefore, limitBefore := bytes.Clone(raw), target, POW_LIMIT
	err := Initial148PowCheck(raw, target)
	if code != "" {
		initial148Error(t, err, code, msg, diagnostic)
	} else if err != nil {
		t.Fatalf("%s: success error=%T %v want=nil", diagnostic, err, err)
	}
	initial148Unchanged(t, raw, before)
	if target != targetBefore || POW_LIMIT != limitBefore {
		t.Fatalf("initial148 input mutation: target or POW_LIMIT changed")
	}
	initial148Next(t)
}

func TestInitial148Header_PoW(t *testing.T) {
	raw, digest, limit := initial148PowOracle(t)
	cases := []struct {
		name       string
		target     [32]byte
		code       string
		diagnostic string
	}{
		{"above_hash", initial148Target(digest, 1), "", "initial148 strict above"},
		{"equal_hash", digest, "BLOCK_ERR_POW_INVALID", "initial148 strict equality"},
		{"below_hash", initial148Target(digest, -1), "BLOCK_ERR_POW_INVALID", "initial148 strict below"},
		{"minimum", initial148Target([32]byte{}, 1), "BLOCK_ERR_POW_INVALID", "initial148 minimum target"},
		{"limit", POW_LIMIT, "", "initial148 limit target"},
		{"literal_allff", limit, "", "initial148 limit target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			initial148Pow(t, raw, tc.target, tc.code, "pow invalid", tc.diagnostic)
		})
	}
	literal, _ := initial148Literal(t)
	for _, input := range []initial148Fixture{{name: "Z148", raw: raw}, {name: "L", raw: literal}} {
		t.Run("zero_target/"+input.name, func(t *testing.T) {
			initial148Pow(t, input.raw, [32]byte{}, "BLOCK_ERR_TARGET_INVALID", "target out of range", "initial148 target before pow")
		})
	}
	t.Run("endian", func(t *testing.T) { initial148Endian(t, raw, digest) })
}

func initial148Endian(t *testing.T, raw []byte, digest [32]byte) {
	t.Helper()
	var reversed [32]byte
	for i := range digest {
		reversed[i] = digest[31-i]
	}
	if reversed == digest {
		t.Fatal("initial148 oracle domain: D must differ from reverse(D)")
	}
	code := ""
	if new(big.Int).SetBytes(digest[:]).Cmp(new(big.Int).SetBytes(reversed[:])) > 0 {
		code = "BLOCK_ERR_POW_INVALID"
	}
	initial148Pow(t, raw, reversed, code, "pow invalid", "initial148 unsigned big endian")
}

func initial148Next(t *testing.T) {
	t.Helper()
	raw, want := initial148Literal(t)
	before := bytes.Clone(raw)
	header, err := ParseInitial148HeaderBytes(raw)
	if err != nil || header != want {
		t.Fatalf("initial148 next operation: parse got=%#v err=%v", header, err)
	}
	initial148Unchanged(t, raw, before)
	digest, err := Initial148BlockHash(raw)
	if err != nil || digest != sha3.Sum256(before) {
		t.Fatalf("initial148 next operation: hash got=%x err=%v", digest, err)
	}
	initial148Unchanged(t, raw, before)
	zero, _, limit := initial148PowOracle(t)
	zeroBefore := bytes.Clone(zero)
	if err := Initial148PowCheck(zero, limit); err != nil {
		t.Fatalf("initial148 next operation: pow=%v", err)
	}
	initial148Unchanged(t, zero, zeroBefore)
}

func TestInitial148Header_Ownership(t *testing.T) {
	raw, want := initial148Literal(t)
	before := bytes.Clone(raw)
	parsed, err := ParseInitial148HeaderBytes(raw)
	if err != nil {
		t.Fatalf("initial148 owned value: parse=%v", err)
	}
	initial148Unchanged(t, raw, before)
	for i := range raw {
		raw[i] ^= 0xff
	}
	initial148Fields(t, parsed, want, "initial148 owned value")
	initial148Next(t)
	copyOfParsed := parsed
	copyOfParsed.Version ^= 1
	copyOfParsed.PrevBlockHash[0] ^= 1
	copyOfParsed.MerkleRoot[0] ^= 1
	copyOfParsed.Timestamp ^= 1
	copyOfParsed.Target[0] ^= 1
	copyOfParsed.UtxoRoot[0] ^= 1
	copyOfParsed.Nonce ^= 1
	initial148Fields(t, parsed, want, "initial148 owned value")
	encoded := EncodeInitial148Header(parsed)
	encoded[108] ^= 1
	again := EncodeInitial148Header(parsed)
	if !bytes.Equal(again[:], before) || bytes.Equal(encoded[:], again[:]) {
		t.Fatal("initial148 owned value: encoded arrays alias")
	}
	initial148Next(t)
	initial148HashOwnership(t)
}

func initial148HashOwnership(t *testing.T) {
	t.Helper()
	raw, _ := initial148Literal(t)
	before := bytes.Clone(raw)
	want := sha3.Sum256(before)
	digest, err := Initial148BlockHash(raw)
	if err != nil {
		t.Fatalf("initial148 owned value: hash=%v", err)
	}
	initial148Unchanged(t, raw, before)
	initial148Next(t)
	for i := range raw {
		raw[i] ^= 0xff
	}
	if digest != want {
		t.Fatal("initial148 owned value: digest changed with caller buffer")
	}
	digest[0] ^= 1
	fresh := bytes.Clone(before)
	againHash, err := Initial148BlockHash(fresh)
	if err != nil || againHash != want || digest == againHash {
		t.Fatalf("initial148 owned value: digest arrays alias: err=%v", err)
	}
	initial148Unchanged(t, fresh, before)
	initial148Next(t)
}

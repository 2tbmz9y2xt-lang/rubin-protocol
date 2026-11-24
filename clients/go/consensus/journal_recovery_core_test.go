package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

const (
	recoveryCoreBelowGenesisTargetHexV1 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
	recoveryCoreEmptyRootHexV1          = "cc91bf5776e6097dd079c8bc871c8af0b291bb436cb222b4df5b67dca7ebf15e"
	recoveryCoreEmptyHashHexV1          = "036d289de6ce45bf4bf92155361314bceda9559874f16fd885ae1da5149f5e58"
)

func TestJournalRecoveryCoreShapeV1(t *testing.T) {
	genesis := initial148Hex(t, initial148GenesisBlockHex)
	limit := initial148Array(t, initial148MaxHex)
	zero := [32]byte{}
	full := RecoveryCoreFullHeaderV1{PowLimit: limit, ExpectedTarget: limit}
	explicitZero := full
	explicitZero.Parent = &zero
	explicitNonzero := full
	explicitNonzero.Parent = &[32]byte{1}
	image := [148]byte(genesis)

	for _, tc := range []struct {
		name   string
		height uint64
		input  RecoveryCoreHeaderInputV1
	}{
		{"absent mode and payload", 0, RecoveryCoreHeaderInputV1{}},
		{"absent mode with payload", 0, RecoveryCoreHeaderInputV1{Full: &full}},
		{"unknown mode", 0, RecoveryCoreHeaderInputV1{Mode: 255, Full: &full}},
		{"full missing payload", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1}},
		{"full with image only", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Image: &image}},
		{"full with mixed payload", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &full, Image: &image}},
		{"image missing payload", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreQualifiedImageV1}},
		{"image with full only", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreQualifiedImageV1, Full: &full}},
		{"image with mixed payload", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreQualifiedImageV1, Full: &full, Image: &image}},
		{"genesis with explicit zero parent", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &explicitZero}},
		{"genesis with explicit nonzero parent", 0, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &explicitNonzero}},
		{"positive height missing parent", 1, RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &full}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireRecoveryCoreResultV1(t, []byte{1}, zero, tc.height, tc.input, RecoveryCoreResultV1{Gate: "INVALID_INPUT"})
		})
	}

	empty, sentinel := recoveryCoreTxV1(0, false), recoveryCoreTxV1(0, true)
	if sha3.Sum256(empty) == sha3.Sum256(sentinel) {
		t.Fatal("witness variants have the same wire hash")
	}
	hash := initial148Array(t, recoveryCoreEmptyHashHexV1)
	input := RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &full}
	want := RecoveryCoreResultV1{Fact: RecoveryCoreFactV1{Kind: 0, AnchorCount: 0, Reason: "ANCHOR_COUNT"}}
	t.Run("empty witness", func(t *testing.T) {
		raw := recoveryCoreBlockV1(t, genesis, recoveryCoreEmptyRootHexV1, empty)
		requireRecoveryCoreResultV1(t, raw, hash, 0, input, want)
	})
	t.Run("sentinel witness", func(t *testing.T) {
		raw := recoveryCoreBlockV1(t, genesis, recoveryCoreEmptyRootHexV1, sentinel)
		requireRecoveryCoreResultV1(t, raw, hash, 0, input, want)
	})
}

func TestJournalRecoveryCoreGatesV1(t *testing.T) {
	t.Run("parser refusals", testRecoveryCoreParserV1)
	t.Run("work comparator", testRecoveryCoreStep2V1)

	genesis := initial148Hex(t, initial148GenesisBlockHex)
	gHash := initial148Array(t, initial148GenesisHashHex)
	limit := initial148Array(t, initial148MaxHex)
	below := initial148Array(t, recoveryCoreBelowGenesisTargetHexV1)
	zero, one, two := [32]byte{}, [32]byte{31: 1}, [32]byte{31: 2}
	pParent := [32]byte{1}

	p, r, u := bytes.Clone(genesis), bytes.Clone(genesis), bytes.Clone(genesis)
	p[4] = 1
	r[36] ^= 1
	u[139] ^= 1
	pHash := initial148Array(t, "dc4836cbaaf9660d09e8d597d22af6947b816ad6b25ba5d2173eceb773bf0989")
	rHash := initial148Array(t, "2b2aaecd61709389e07f5994a4ce894ffd0e77c3284db39b32d09a9eb1ab1b34")
	uHash := initial148Array(t, "73a15c4b1917110a18db15334bd269a5ef9f80dcc1d8d530afc4f4f9ff1a75e2")
	n := bytes.Clone(genesis)
	n[147] = 0x01
	nHash := initial148Array(t, "45b92fcc2e13afcfd96c5ad8debdc694cd96df81429a289065840b1a02730cc4")

	g0, g1 := bytes.Clone(genesis), bytes.Clone(genesis)
	clear(g0[76:108])
	copy(g1[76:108], one[:])
	g0Hash := initial148Array(t, "76a54c9f50936d2ef1a713fff271ae656dcf80d710700e99488620a343a0bbef")
	g1Hash := initial148Array(t, "824cafb93c1d82ab572d0c8928747445812542abf9cd8b2c233b998f1c802aaa")

	full := func(powLimit, target [32]byte, parent *[32]byte) RecoveryCoreHeaderInputV1 {
		return RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &RecoveryCoreFullHeaderV1{
			PowLimit: powLimit, ExpectedTarget: target, Parent: parent,
		}}
	}
	image := func(raw []byte) RecoveryCoreHeaderInputV1 {
		header := [148]byte(raw)
		return RecoveryCoreHeaderInputV1{Mode: RecoveryCoreQualifiedImageV1, Image: &header}
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		hash   [32]byte
		height uint64
		input  RecoveryCoreHeaderInputV1
		gate   RecoveryCoreGateV1
	}{
		{"hash before target range", g0, gHash, 0, full(limit, limit, nil), "EXPECTED_HASH"},
		{"hash before image", r, gHash, 0, image(genesis), "EXPECTED_HASH"},
		{"zero encoded target before work", g0, g0Hash, 0, full(limit, limit, nil), "TARGET_RANGE"},
		{"work before expected target", g1, g1Hash, 0, full(limit, two, nil), "POW_HASH"},
		{"expected target before parent and root", r, rHash, 1, full(limit, one, &pParent), "EXPECTED_TARGET"},
		{"parent before root", r, rHash, 1, full(limit, limit, &pParent), "EXPECTED_PARENT"},
		{"root after exact zero parent", r, rHash, 1, full(limit, limit, &zero), "TXID_MERKLE"},
		{"image before root", r, rHash, 0, image(genesis), "IMAGE_HEADER"},
		{"root after exact image", r, rHash, 0, image(r), "TXID_MERKLE"},
		{"genesis full inclusive limit", genesis, gHash, 0, full(limit, limit, nil), "PREDICATE_FALSE"},
		{"genesis full above limit", genesis, gHash, 0, full(below, limit, nil), "TARGET_RANGE"},
		{"genesis full zero limit", genesis, gHash, 0, full(zero, limit, nil), "TARGET_RANGE"},
		{"genesis full differing target tail", genesis, gHash, 0, full(limit, below, nil), "EXPECTED_TARGET"},
		{"genesis full zero expected target", genesis, gHash, 0, full(limit, zero, nil), "EXPECTED_TARGET"},
		{"genesis image", genesis, gHash, 0, image(genesis), "PREDICATE_FALSE"},
		{"image skips full target range", g0, g0Hash, 0, image(g0), "PREDICATE_FALSE"},
		{"image skips full work", g1, g1Hash, 0, image(g1), "PREDICATE_FALSE"},
		{"genesis hashes nonzero parent bytes", p, pHash, 0, full(limit, limit, nil), "PREDICATE_FALSE"},
		{"positive height exact nonzero parent", p, pHash, 1, full(limit, limit, &pParent), "PREDICATE_FALSE"},
		{"positive height wrong zero parent", p, pHash, 1, full(limit, limit, &zero), "EXPECTED_PARENT"},
		{"positive height image skips full parent", p, pHash, 1, image(p), "PREDICATE_FALSE"},
		{"hash includes state root tail", u, gHash, 0, full(limit, limit, nil), "EXPECTED_HASH"},
		{"hash with exact state root tail", u, uHash, 0, full(limit, limit, nil), "PREDICATE_FALSE"},
		{"image compares state root tail", u, uHash, 0, image(genesis), "IMAGE_HEADER"},
		{"hash includes final nonce byte", n, gHash, 0, full(limit, limit, nil), "EXPECTED_HASH"},
		{"hash with exact final nonce byte", n, nHash, 0, full(limit, limit, nil), "PREDICATE_FALSE"},
		{"image compares final nonce byte", genesis, gHash, 0, image(n), "IMAGE_HEADER"},
		{"image with exact final nonce byte", n, nHash, 0, image(n), "PREDICATE_FALSE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireRecoveryCoreResultV1(t, tc.raw, tc.hash, tc.height, tc.input, RecoveryCoreResultV1{Gate: tc.gate})
		})
	}
}

func testRecoveryCoreParserV1(t *testing.T) {
	genesis := initial148Hex(t, initial148GenesisBlockHex)
	limit := initial148Array(t, initial148MaxHex)
	input := RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &RecoveryCoreFullHeaderV1{PowLimit: limit, ExpectedTarget: limit}}
	t.Run("image with truncated copy", func(t *testing.T) {
		image := [148]byte(genesis)
		context := RecoveryCoreHeaderInputV1{Mode: RecoveryCoreQualifiedImageV1, Image: &image}
		want := RecoveryCoreResultV1{Gate: "PARSE", ParserCause: &TxError{Code: "BLOCK_ERR_PARSE", Msg: "block too short"}}
		requireRecoveryCoreResultV1(t, genesis[:147], [32]byte{}, 1, context, want)
	})
	header := func(tail ...byte) []byte { return append(bytes.Clone(genesis[:148]), tail...) }
	kind, payload := bytes.Clone(genesis), bytes.Clone(genesis)
	kind[153] = 3
	payload[len(payload)-1] = 1
	empty := recoveryCoreTxV1(0, false)
	witnessOverflow := append(bytes.Clone(empty[:len(empty)-2]), 0xfd, 0x01, 0x04)
	for _, tc := range []struct {
		name string
		raw  []byte
		gate RecoveryCoreGateV1
		code ErrorCode
		msg  string
	}{
		{"short header", genesis[:147], "PARSE", "BLOCK_ERR_PARSE", "block too short"},
		{"missing count", genesis[:148], "PARSE", "BLOCK_ERR_PARSE", "block too short"},
		{"truncated count", header(0xfd, 0x01), "PARSE", "BLOCK_ERR_PARSE", "invalid tx_count"},
		{"nonminimal positive count", header(0xfd, 0x01, 0x00), "PARSE", "BLOCK_ERR_PARSE", "invalid tx_count"},
		{"nonminimal zero count", header(0xfd, 0x00, 0x00), "PARSE", "BLOCK_ERR_PARSE", "invalid tx_count"},
		{"canonical zero count", header(0x00), "EMPTY_TX_COUNT", "BLOCK_ERR_COINBASE_INVALID", "empty block tx list"},
		{"canonical zero before trailing bytes", header(0x00, 0x01), "EMPTY_TX_COUNT", "BLOCK_ERR_COINBASE_INVALID", "empty block tx list"},
		{"transaction absent", header(0x01), "PARSE", "BLOCK_ERR_PARSE", "unexpected EOF in tx list"},
		{"truncated transaction payload framing", genesis[:len(genesis)-1], "PARSE", "TX_ERR_PARSE", "unexpected EOF (u8)"},
		{"illegal kind", kind, "PARSE", "TX_ERR_PARSE", "unsupported tx_kind"},
		{"illegal standard payload", payload, "PARSE", "TX_ERR_PARSE", "da_payload_len must be 0 for tx_kind=0x00"},
		{"witness count overflow before missing items", header(append([]byte{1}, witnessOverflow...)...), "PARSE", "TX_ERR_WITNESS_OVERFLOW", "witness_count overflow"},
		{"trailing bytes before hash", append(bytes.Clone(genesis), 0), "PARSE", "BLOCK_ERR_PARSE", "trailing bytes after tx list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := RecoveryCoreResultV1{Gate: tc.gate, ParserCause: &TxError{Code: tc.code, Msg: tc.msg}}
			requireRecoveryCoreResultV1(t, tc.raw, [32]byte{}, 0, input, want)
		})
	}
}

func testRecoveryCoreStep2V1(t *testing.T) {
	limit := initial148Array(t, initial148MaxHex)
	zero, one, two, three := [32]byte{}, [32]byte{31: 1}, [32]byte{31: 2}, [32]byte{31: 3}
	highOne := initial148Array(t, "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	highTwo := [32]byte{2}
	for _, tc := range []struct {
		name                  string
		digest, target, limit [32]byte
		gate                  RecoveryCoreGateV1
	}{
		{"minimum nonzero target", zero, one, limit, ""},
		{"below target", one, two, limit, ""},
		{"equal to target", two, two, limit, "POW_HASH"},
		{"above target", three, two, limit, "POW_HASH"},
		{"big endian digest", highOne, highTwo, limit, ""},
		{"big endian target range", zero, highTwo, highOne, "TARGET_RANGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if gate := recoveryCorePowGateV1(tc.digest, tc.target, tc.limit); gate != tc.gate {
				t.Fatalf("work gate=%q, want %q", gate, tc.gate)
			}
		})
	}
}

func TestJournalRecoveryCoreDerivationV1(t *testing.T) {
	genesis := initial148Hex(t, initial148GenesisBlockHex)
	limit := initial148Array(t, initial148MaxHex)
	input := RecoveryCoreHeaderInputV1{Mode: RecoveryCoreFullV1, Full: &RecoveryCoreFullHeaderV1{PowLimit: limit, ExpectedTarget: limit}}

	anchor := recoveryCoreOutputV1(0, 2, 32, 0x19)
	distinct := recoveryCoreOutputV1(0, 2, 32, 0x33)
	short := recoveryCoreOutputV1(0, 2, 31, 0x19)
	long := recoveryCoreOutputV1(0, 2, 33, 0x19)
	other := recoveryCoreOutputV1(0, 0, 32, 0x19)
	empty := recoveryCoreTxV1(0, false)
	standard := recoveryCoreTxV1(0, false, anchor)
	chunk := recoveryCoreTxV1(2, false, recoveryCoreOutputV1(7, 2, 32, 0x19))
	chunkWithDifferentPayload := bytes.Clone(chunk)
	chunkWithDifferentPayload[len(chunkWithDifferentPayload)-1] = 0x5b
	const chunkRoot = "0fe742a7ab6d52da927acaf534cfd1c6124c075a668f536339297e1737a14a63"
	const chunkHash = "09839b76498bce79ee1557618cc4f1413cd56c2e94cecd291d82773827d62ff1"
	holds := func(kind uint8, count int, reason RecoveryCoreReasonV1) RecoveryCoreResultV1 {
		return RecoveryCoreResultV1{Fact: RecoveryCoreFactV1{Kind: kind, AnchorCount: count, Reason: reason}}
	}
	falseResult := RecoveryCoreResultV1{Gate: "PREDICATE_FALSE"}
	for _, tc := range []struct {
		name       string
		txs        [][]byte
		root, hash string
		want       RecoveryCoreResultV1
	}{
		{"wrong widths and type", [][]byte{recoveryCoreTxV1(0, false, short, long, other)}, "71e064695021d189c30eed72b3c8de0713088eebba94ae847af48c4dffafbc22", "b5e8ae846001d3631890b6bae0a41a5b59c29dc59ca1d80b4d5727019c303eeb", holds(0, 0, "ANCHOR_COUNT")},
		{"wrong commitment", [][]byte{standard}, "0217ab40a21df7b8da51c252654f1b5aa2522748082c909f7ce0376e4ca7c2b1", "a8a0230fc736de28266ec052750f793e8c471c953859523dec9c0238ac7efbbf", falseResult},
		{"anchor with zero data", [][]byte{recoveryCoreTxV1(0, false, recoveryCoreOutputV1(0, 2, 32, 0))}, "db0e5fa39adfabe55b4bfc4e0b947c143cc19b6ff5a8e3f5bc7a262fc729b2af", "080a7e825f5a4f3b1e654f89e0eb3105df7d0b68cc242c411f87127b9430d1f4", falseResult},
		{"wrong commitment with witness", [][]byte{recoveryCoreTxV1(0, true, anchor)}, "0217ab40a21df7b8da51c252654f1b5aa2522748082c909f7ce0376e4ca7c2b1", "a8a0230fc736de28266ec052750f793e8c471c953859523dec9c0238ac7efbbf", falseResult},
		{"distinct anchors", [][]byte{recoveryCoreTxV1(0, false, anchor, distinct)}, "a1be69d52049f51f7e2a3c56c95fc6c21537da8afd80342744604ef92f51dec8", "d31832c96c19ec5107f0306a21b7c2eecf39836bd19601486047d1a97c54f16e", holds(0, 2, "ANCHOR_COUNT")},
		{"identical anchors", [][]byte{recoveryCoreTxV1(0, false, anchor, anchor)}, "9dbd8edc2dd8291c94790c44be3fbd5d270fadce19778ded889e5d54154faa39", "26317a6e997aea0c73c9e6eee0bf347f9ee372f6f9363cdcd28f18b404a59a48", holds(0, 2, "ANCHOR_COUNT")},
		{"chunk with valued anchor", [][]byte{chunk}, chunkRoot, chunkHash, holds(2, 1, "POSITION_ZERO_CHUNK")},
		{"chunk with different payload bytes", [][]byte{chunkWithDifferentPayload}, chunkRoot, chunkHash, holds(2, 1, "POSITION_ZERO_CHUNK")},
		{"anchor count before chunk", [][]byte{recoveryCoreTxV1(2, false, anchor, distinct)}, "41ec08ab7c9bb4afdcd9fdc117cf40402fc58fbd3406901b5050b543ffdd255c", "d541c5479fee42da76f3d5c194ebf8fca8b40ea8d4e334871ba0fa816a5d7c26", holds(2, 2, "ANCHOR_COUNT")},
		{"manifest with anchor", [][]byte{recoveryCoreTxV1(1, false, anchor)}, "c02073ca1e57945d70fca046ac20cbf1cd8d02e6e0f1215d653de9a9a2a3a68e", "ac2434a719d12c9257582afada67ad37cc8f544a648e9066e4d999c42b7685fa", falseResult},
		{"manifest without anchors", [][]byte{recoveryCoreTxV1(1, false)}, "6c315d0c8e4af51c2d4438edde473d5ac3b60339437c6e2cbfaae43f56e2844c", "0c98d7f5330c17d22ae5f19464744cd12a18cce8661512db72c94cfc30aad2ea", holds(1, 0, "ANCHOR_COUNT")},
		{"two transactions in committed order", [][]byte{chunk, empty}, "96f2973895931debc8782be29284f5ec73b940b71e1e0062900344af124ac7f6", "03ca24fb8186744a581eb03b073b3808a27ee48f07366155714156626e9d0e01", holds(2, 1, "POSITION_ZERO_CHUNK")},
		{"two transactions in reverse order", [][]byte{empty, chunk}, "96f2973895931debc8782be29284f5ec73b940b71e1e0062900344af124ac7f6", "03ca24fb8186744a581eb03b073b3808a27ee48f07366155714156626e9d0e01", RecoveryCoreResultV1{Gate: "TXID_MERKLE"}},
		{"second transaction anchor outside position zero", [][]byte{chunk, standard}, "a8ab7e2bc73e9e647e5f8d183a0f0fb5c4cedcbd9c2325025d79a6357672f1c4", "3603787f3222e8bc19f20b9730fee5e333e5efb2dbf7f31753323d3caca71fd9", holds(2, 1, "POSITION_ZERO_CHUNK")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := recoveryCoreBlockV1(t, genesis, tc.root, tc.txs...)
			requireRecoveryCoreResultV1(t, raw, initial148Array(t, tc.hash), 0, input, tc.want)
		})
	}
}

func recoveryCoreOutputV1(value uint64, tag uint16, width int, data byte) []byte {
	raw := binary.LittleEndian.AppendUint64(nil, value)
	raw = binary.LittleEndian.AppendUint16(raw, tag)
	raw = append(raw, byte(width))
	return append(raw, bytes.Repeat([]byte{data}, width)...)
}

func recoveryCoreTxV1(kind byte, witness bool, outputs ...[]byte) []byte {
	raw := []byte{1, 0, 0, 0, kind, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(len(outputs))}
	for _, output := range outputs {
		raw = append(raw, output...)
	}
	raw = append(raw, 0, 0, 0, 0)
	switch kind {
	case 1:
		core := [172]byte{32: 1}
		raw = append(raw, core[:]...)
	case 2:
		core := [66]byte{}
		raw = append(raw, core[:]...)
	}
	if witness {
		raw = append(raw, 1, 0, 0, 0)
	} else {
		raw = append(raw, 0)
	}
	if kind == 0 {
		return append(raw, 0)
	}
	return append(raw, 1, 0x5a)
}

func recoveryCoreBlockV1(t *testing.T, genesis []byte, root string, txs ...[]byte) []byte {
	t.Helper()
	raw := append(bytes.Clone(genesis[:148]), byte(len(txs)))
	copy(raw[36:68], initial148Hex(t, root))
	for _, tx := range txs {
		raw = append(raw, tx...)
	}
	return raw
}

func requireRecoveryCoreResultV1(t *testing.T, raw []byte, hash [32]byte, height uint64, input RecoveryCoreHeaderInputV1, want RecoveryCoreResultV1) {
	t.Helper()
	before := bytes.Clone(raw)
	var full RecoveryCoreFullHeaderV1
	var parent [32]byte
	if input.Full != nil {
		full = *input.Full
		if full.Parent != nil {
			parent = *full.Parent
		}
	}
	var image [148]byte
	if input.Image != nil {
		image = *input.Image
	}

	got := DeriveRecoveryCoreFactV1(raw, hash, height, input)
	if got.Gate != want.Gate {
		t.Fatalf("first gate=%q, want %q", got.Gate, want.Gate)
	}
	if got.Fact != want.Fact {
		t.Fatalf("fact=%+v, want %+v", got.Fact, want.Fact)
	}
	if wantCause, ok := errors.AsType[*TxError](want.ParserCause); ok {
		gotCause, ok := errors.AsType[*TxError](got.ParserCause)
		if !ok || gotCause == nil || reflect.TypeOf(got.ParserCause) != reflect.TypeFor[*TxError]() {
			t.Fatalf("parser cause type=%T, want nonnil *TxError", got.ParserCause)
		}
		if gotCause.Code != wantCause.Code || gotCause.Msg != wantCause.Msg || gotCause.Cause() != 0 {
			t.Fatalf("parser cause=(%s, %q, %d), want (%s, %q, 0)", gotCause.Code, gotCause.Msg, gotCause.Cause(), wantCause.Code, wantCause.Msg)
		}
	} else if got.ParserCause != nil {
		t.Fatalf("parser cause=%#v, want nil", got.ParserCause)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("block bytes changed")
	}
	if input.Full != nil && (*input.Full != full || full.Parent != nil && *full.Parent != parent) {
		t.Fatal("full header inputs changed")
	}
	if input.Image != nil && *input.Image != image {
		t.Fatal("image header input changed")
	}
}

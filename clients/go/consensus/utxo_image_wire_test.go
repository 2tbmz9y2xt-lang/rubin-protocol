package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// Independent literals: rubin-spec 2a30f15b, CSM 2.5/2.6 C01/C02 and
// P2P_AUX 7.1/7.2. No production S, K, Root or domain defines expectations.
const (
	imageTestC01 = "0a978e2cf0e03934b2ec7c369b301f8f3a687aed501227a7af76730a8e64f8bb"
	imageTestC02 = "14bd6311f35ed9534d8cd8a101bc09c5d289978e393e775271fd9e446c8cde8d"
	imageTestS   = "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000001000000000000000000210111111111111111111111111111111111" +
		"11111111111111111111111111111111000000000000000000"
)

func imageTestHex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func imageTestCommand(t *testing.T, text string) [12]byte {
	t.Helper()
	return [12]byte(imageTestHex(t, text))
}

func imageTestQuery(t *testing.T) (UTXOImageQuery, []byte) {
	t.Helper()
	q := UTXOImageQuery{RequestID: 1, ByteLimit: 150905}
	copy(q.BlockHash[:], bytes.Repeat([]byte{0x11}, 32))
	copy(q.Root[:], imageTestHex(t, imageTestC02))
	raw := imageTestHex(t, "0100000000000000"+"0000000000000000"+
		strings.Repeat("11", 32)+imageTestC02+strings.Repeat("00", 36)+"794d0200")
	return q, raw
}

func imageTestEntry() UTXOImageEntry {
	return UTXOImageEntry{Entry: UtxoEntry{
		Value: 1, CovenantData: append([]byte{1}, bytes.Repeat([]byte{0x11}, 32)...),
	}}
}

func imageTestChunk(rawQ []byte, body []byte) []byte {
	return append(bytes.Clone(rawQ), body...)
}

func imageTestEncoded(t *testing.T, id string, q UTXOImageQuery, entries []UTXOImageEntry, predecessor *UTXOImageEntry, left, right []UTXOImageEdge, want []byte) {
	t.Helper()
	got, ok, reason := EncodeUTXOImageChunk(q, entries, predecessor, left, right)
	if !ok || reason != "" || !bytes.Equal(got, want) {
		t.Fatalf("%s: got=(%x,%v,%q) want=(%x,true,empty)", id, got, ok, reason, want)
	}
}

func imageTestDecoded(t *testing.T, id string, command [12]byte, payload []byte, q UTXOImageQuery) UTXOImageReply {
	t.Helper()
	before := bytes.Clone(payload)
	reply, ok, reason := DecodeUTXOImageReply(command, payload)
	if !ok || reason != "" || reply.Query() != q || reply.Command() != command || reply.PayloadLength() != uint32(len(payload)) {
		t.Fatalf("%s: got=(%#v,%x,%d,%v,%q) want=(%#v,%x,%d,true,empty)", id,
			reply.Query(), reply.Command(), reply.PayloadLength(), ok, reason, q, command, len(payload))
	}
	if !bytes.Equal(payload, before) {
		t.Fatalf("%s: caller payload changed", id)
	}
	return reply
}

func imageTestRejected(t *testing.T, id string, command [12]byte, payload []byte, want string) {
	t.Helper()
	before := bytes.Clone(payload)
	for range 2 {
		reply, ok, reason := DecodeUTXOImageReply(command, payload)
		if ok || reason != want || !reflect.DeepEqual(reply, UTXOImageReply{}) {
			t.Fatalf("%s: got=(%#v,%v,%q) want=(zero,false,%q)", id, reply, ok, reason, want)
		}
		if !bytes.Equal(payload, before) {
			t.Fatalf("%s: caller payload changed", id)
		}
	}
}

func TestUTXOImageWireLiterals(t *testing.T) {
	q, raw := imageTestQuery(t)
	encoded, ok := EncodeUTXOImageRequest(q)
	if !ok || !bytes.Equal(encoded[:], raw) || len(raw) != 120 {
		t.Fatalf("C1_REQUEST_BYTES: got=%x want=%x ok=%v", encoded, raw, ok)
	}
	beforeRaw := bytes.Clone(raw)
	decoded, ok := DecodeUTXOImageRequest(raw)
	if !ok || decoded != q || !bytes.Equal(raw, beforeRaw) {
		t.Fatalf("C1_REQUEST_FIELDS: got=%#v/%v want=%#v/true", decoded, ok, q)
	}
	negative := EncodeUTXOImageNotAvailable(q)
	if !bytes.Equal(negative[:], raw) {
		t.Fatalf("C1_NEGATIVE_BYTES: got=%x want=%x", negative, raw)
	}
	chunkCommand := imageTestCommand(t, "7574786f696d670000000000")
	negativeCommand := imageTestCommand(t, "7574786f6e6f74617661696c")
	imageTestDecoded(t, "C1_NEGATIVE", negativeCommand, raw, q)
	imageTestRejected(t, "C1_REQUEST_COMMAND", imageTestCommand(t, "6765747574786f696d670000"), raw, "")
	singleton := imageTestChunk(raw, imageTestHex(t, "01000000"+imageTestS+"00"+"0000"+"0000"))
	if len(singleton) != 218 {
		t.Fatalf("C1_SINGLETON_LENGTH: got=%d want=218", len(singleton))
	}
	entry := imageTestEntry()
	imageTestEncoded(t, "C1_SINGLETON_BYTES", q, []UTXOImageEntry{entry}, nil, nil, nil, singleton)
	imageTestDecoded(t, "C1_SINGLETON_FIELDS", chunkCommand, singleton, q)
	copy(q.Root[:], imageTestHex(t, imageTestC01))
	emptyQ := bytes.Clone(raw)
	copy(emptyQ[48:80], imageTestHex(t, imageTestC01))
	empty := imageTestChunk(emptyQ, imageTestHex(t, "00000000"+"00"+"0000"+"0000"))
	if len(empty) != 129 {
		t.Fatalf("C1_EMPTY_LENGTH: got=%d want=129", len(empty))
	}
	imageTestEncoded(t, "C1_EMPTY_BYTES", q, nil, nil, nil, nil, empty)
	imageTestDecoded(t, "C1_EMPTY", chunkCommand, empty, q)
	q, raw = imageTestQuery(t)
	rawHash := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	copy(q.BlockHash[:], imageTestHex(t, rawHash))
	copy(raw[16:48], imageTestHex(t, rawHash))
	gotRawHash, validRawHash := EncodeUTXOImageRequest(q)
	if !validRawHash || !bytes.Equal(gotRawHash[:], raw) {
		t.Fatalf("C1_RAW_HASH: got=%x/%v want=%x/true", gotRawHash, validRawHash, raw)
	}
	imageTestDecoded(t, "C1_RAW_HASH", negativeCommand, raw, q)
	copy(entry.Outpoint.Txid[:], imageTestHex(t, rawHash))
	s := imageTestHex(t, imageTestS)
	copy(s[:32], imageTestHex(t, rawHash))
	wantRawEntry := imageTestChunk(raw, append(append(imageTestHex(t, "01000000"), s...), make([]byte, 5)...))
	imageTestEncoded(t, "C1_RAW_ENTRY_HASH", q, []UTXOImageEntry{entry}, nil, nil, nil, wantRawEntry)
	var zero UTXOImageReply
	if zero.Query() != (UTXOImageQuery{}) || zero.Command() != ([12]byte{}) || zero.PayloadLength() != 0 {
		t.Fatalf("C1_ZERO_REPLY: got=%#v", zero)
	}
}

func TestUTXOImageWireDomains(t *testing.T) {
	q, raw := imageTestQuery(t)
	for _, tc := range []struct {
		id     string
		q      UTXOImageQuery
		offset int
		hex    string
	}{
		{"C2_ID_MAX", UTXOImageQuery{RequestID: ^uint64(0), ByteLimit: 150905}, 0, "ffffffffffffffff"},
		{"C2_HEIGHT_MAX", UTXOImageQuery{RequestID: 1, Height: 0xffffffff, ByteLimit: 150905}, 8, "ffffffff00000000"},
		{"C2_LIMIT_MID", UTXOImageQuery{RequestID: 1, ByteLimit: 200000}, 116, "400d0300"},
		{"C2_LIMIT_MAX", UTXOImageQuery{RequestID: 1, ByteLimit: 2097152}, 116, "00002000"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			candidate := tc.q
			candidate.BlockHash, candidate.Root = q.BlockHash, q.Root
			want := bytes.Clone(raw)
			copy(want[tc.offset:], imageTestHex(t, tc.hex))
			got, ok := EncodeUTXOImageRequest(candidate)
			before := bytes.Clone(want)
			decoded, valid := DecodeUTXOImageRequest(want)
			if !ok || !valid || decoded != candidate || !bytes.Equal(got[:], want) || !bytes.Equal(want, before) {
				t.Fatalf("%s: got=(%x,%v,%#v,%v) want=(%x,true,%#v,true)", tc.id, got, ok, decoded, valid, want, candidate)
			}
		})
	}
	q.StartKey = [36]byte(bytes.Repeat([]byte{0xff}, 36))
	allFF := bytes.Clone(raw)
	copy(allFF[80:116], bytes.Repeat([]byte{0xff}, 36))
	got, ok := EncodeUTXOImageRequest(q)
	beforeAllFF := bytes.Clone(allFF)
	decoded, valid := DecodeUTXOImageRequest(allFF)
	if !ok || !valid || decoded != q || !bytes.Equal(got[:], allFF) || !bytes.Equal(allFF, beforeAllFF) {
		t.Fatalf("C2_K_ALLFF: got=%x/%v/%#v/%v want=%x/true/%#v/true", got, ok, decoded, valid, allFF, q)
	}
	q, raw = imageTestQuery(t)
	for _, tc := range []struct {
		id     string
		offset int
		hex    string
	}{
		{"C2_REPLY_ID0", 0, "0000000000000000"},
		{"C2_REPLY_HEIGHT_WIDE", 8, "0000000001000000"},
		{"C2_REPLY_LIMIT_LOW", 116, "784d0200"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			want := bytes.Clone(raw)
			copy(want[tc.offset:], imageTestHex(t, tc.hex))
			candidate := q
			candidate.RequestID = binary.LittleEndian.Uint64(want[:8])
			candidate.Height = binary.LittleEndian.Uint64(want[8:16])
			candidate.ByteLimit = binary.LittleEndian.Uint32(want[116:])
			negative := EncodeUTXOImageNotAvailable(candidate)
			if !bytes.Equal(negative[:], want) {
				t.Fatalf("C2_REPLY_Q: got=%x want=%x", negative, want)
			}
			imageTestDecoded(t, tc.id+"_NEGATIVE", imageTestCommand(t, "7574786f6e6f74617661696c"), want, candidate)
			chunk := imageTestChunk(want, make([]byte, 9))
			imageTestDecoded(t, tc.id+"_CHUNK", imageTestCommand(t, "7574786f696d670000000000"), chunk, candidate)
			imageTestEncoded(t, tc.id+"_ENCODE", candidate, nil, nil, nil, nil, chunk)
		})
	}
}

func TestUTXOImageWireEntryDomains(t *testing.T) {
	q, raw := imageTestQuery(t)
	for _, tc := range []struct {
		id      string
		n       int
		compact string
	}{
		{"C2_DATA0", 0, "00"}, {"C2_DATA252", 252, "fc"},
		{"C2_DATA253", 253, "fdfd00"}, {"C2_DATA65535", 65535, "fdffff"},
		{"C2_DATA65536", 65536, "fe00000100"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			entry := UTXOImageEntry{Entry: UtxoEntry{Value: 1, CovenantData: bytes.Repeat([]byte{0x22}, tc.n)}}
			s := strings.Repeat("00", 36) + "0100000000000000" + "0000" + tc.compact +
				strings.Repeat("22", tc.n) + "0000000000000000" + "00"
			want := imageTestChunk(raw, imageTestHex(t, "01000000"+s+"00"+"0000"+"0000"))
			imageTestEncoded(t, tc.id, q, []UTXOImageEntry{entry}, nil, nil, nil, want)
			imageTestDecoded(t, tc.id, imageTestCommand(t, "7574786f696d670000000000"), want, q)
		})
	}
	for _, tc := range []struct {
		id     string
		entry  UTXOImageEntry
		offset int
		hex    string
	}{
		{"C2_TYPE1", UTXOImageEntry{Entry: UtxoEntry{Value: 1, CovenantType: 1}}, 44, "0100"},
		{"C2_TYPEFFFF", UTXOImageEntry{Entry: UtxoEntry{Value: 1, CovenantType: 0xffff}}, 44, "ffff"},
		{"C2_VALUE0", UTXOImageEntry{}, 36, "0000000000000000"},
		{"C2_VALUE_MAX", UTXOImageEntry{Entry: UtxoEntry{Value: ^uint64(0)}}, 36, "ffffffffffffffff"},
		{"C2_HEIGHT1", UTXOImageEntry{Entry: UtxoEntry{Value: 1, CreationHeight: 1}}, 47, "0100000000000000"},
		{"C2_HEIGHT_MAX", UTXOImageEntry{Entry: UtxoEntry{Value: 1, CreationHeight: ^uint64(0)}}, 47, "ffffffffffffffff"},
		{"C2_COINBASE_TRUE", UTXOImageEntry{Entry: UtxoEntry{Value: 1, CreatedByCoinbase: true}}, 55, "01"},
		{"C2_VOUT255", UTXOImageEntry{Outpoint: Outpoint{Vout: 255}, Entry: UtxoEntry{Value: 1}}, 32, "ff000000"},
		{"C2_VOUT256", UTXOImageEntry{Outpoint: Outpoint{Vout: 256}, Entry: UtxoEntry{Value: 1}}, 32, "00010000"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			s := imageTestHex(t, strings.Repeat("00", 36)+"0100000000000000"+"0000"+"00"+"0000000000000000"+"00")
			copy(s[tc.offset:], imageTestHex(t, tc.hex))
			want := imageTestChunk(raw, append(append(imageTestHex(t, "01000000"), s...), make([]byte, 5)...))
			imageTestEncoded(t, tc.id, q, []UTXOImageEntry{tc.entry}, nil, nil, nil, want)
			imageTestDecoded(t, tc.id, imageTestCommand(t, "7574786f696d670000000000"), want, q)
		})
	}
}

func TestUTXOImageWireShapeDomains(t *testing.T) {
	q, raw := imageTestQuery(t)
	entry := imageTestEntry()
	pred := imageTestChunk(raw, imageTestHex(t, "00000000"+"01"+imageTestS+"0000"+"0000"))
	imageTestEncoded(t, "C2_PREDECESSOR", q, nil, &entry, nil, nil, pred)
	imageTestDecoded(t, "C2_PREDECESSOR", imageTestCommand(t, "7574786f696d670000000000"), pred, q)
	b := entry
	b.Outpoint.Vout = 1
	sb := imageTestHex(t, imageTestS)
	copy(sb[32:36], imageTestHex(t, "01000000"))
	for _, tc := range []struct {
		id      string
		entries []UTXOImageEntry
		second  []byte
	}{
		{"C2_NO_SORT", []UTXOImageEntry{b, entry}, imageTestHex(t, imageTestS)},
		{"C2_NO_COALESCE", []UTXOImageEntry{b, b}, sb},
	} {
		body := append(imageTestHex(t, "02000000"), sb...)
		body = append(body, tc.second...)
		want := imageTestChunk(raw, append(body, make([]byte, 5)...))
		imageTestEncoded(t, tc.id, q, tc.entries, nil, nil, nil, want)
		imageTestDecoded(t, tc.id, imageTestCommand(t, "7574786f696d670000000000"), want, q)
	}
	for _, side := range []string{"LEFT", "RIGHT"} {
		edges := make([]UTXOImageEdge, 288)
		span := make([]byte, 0, 9792)
		for i := range edges {
			edges[i] = UTXOImageEdge{Depth: uint16(i), Hash: [32]byte(bytes.Repeat([]byte{0x11}, 32))}
			span = binary.BigEndian.AppendUint16(span, uint16(i))
			span = append(span, bytes.Repeat([]byte{0x11}, 32)...)
		}
		left, right := edges, []UTXOImageEdge(nil)
		body := append(imageTestHex(t, "00000000"+"00"+"2001"), span...)
		body = append(body, 0, 0)
		if side == "RIGHT" {
			left, right = nil, edges
			body = append(imageTestHex(t, "00000000"+"00"+"0000"+"2001"), span...)
		}
		want := imageTestChunk(raw, body)
		imageTestEncoded(t, "C2_"+side+"288", q, nil, nil, left, right, want)
		imageTestDecoded(t, "C2_"+side+"288", imageTestCommand(t, "7574786f696d670000000000"), want, q)
	}
	for _, side := range []string{"LEFT", "RIGHT"} {
		edges := []UTXOImageEdge{{Depth: 3}, {Depth: 0}}
		span := imageTestHex(t, "0003"+strings.Repeat("00", 32)+"0000"+strings.Repeat("00", 32))
		left, right := edges, []UTXOImageEdge(nil)
		body := append(imageTestHex(t, "00000000"+"00"+"0200"), span...)
		body = append(body, 0, 0)
		if side == "RIGHT" {
			left, right = nil, edges
			body = append(imageTestHex(t, "00000000"+"00"+"0000"+"0200"), span...)
		}
		want := imageTestChunk(raw, body)
		imageTestEncoded(t, "C2_"+side+"_NO_PROOF_REPAIR", q, nil, nil, left, right, want)
		imageTestDecoded(t, "C2_"+side+"_SCALAR_DEPTH_ORDER", imageTestCommand(t, "7574786f696d670000000000"), want, q)
	}
	entries := make([]UTXOImageEntry, 37446)
	minimum := imageTestChunk(raw, append(append(imageTestHex(t, "46920000"), make([]byte, 56*37446)...), make([]byte, 5)...))
	if len(minimum) != 2097105 {
		t.Fatalf("C2_COUNT37446_LENGTH: got=%d want=2097105", len(minimum))
	}
	imageTestEncoded(t, "C2_COUNT37446", q, entries, nil, nil, nil, minimum)
	imageTestDecoded(t, "C2_COUNT37446", imageTestCommand(t, "7574786f696d670000000000"), minimum, q)
	entries[0].Entry.CovenantData = make([]byte, 47)
	first := imageTestHex(t, strings.Repeat("00", 46)+"2f"+strings.Repeat("00", 47+9))
	body := append(imageTestHex(t, "46920000"), first...)
	body = append(body, make([]byte, 56*37445+5)...)
	atCap := imageTestChunk(raw, body)
	if len(atCap) != 2097152 {
		t.Fatalf("C2_PAYLOAD_CAP: got=%d want=2097152", len(atCap))
	}
	imageTestEncoded(t, "C2_PAYLOAD_CAP", q, entries, nil, nil, nil, atCap)
	imageTestDecoded(t, "C2_PAYLOAD_CAP", imageTestCommand(t, "7574786f696d670000000000"), atCap, q)
}

func TestUTXOImageWireRejections(t *testing.T) {
	q, raw := imageTestQuery(t)
	for _, tc := range []struct {
		id     string
		q      UTXOImageQuery
		offset int
		hex    string
	}{
		{"C5_ID0", UTXOImageQuery{ByteLimit: 150905}, 0, "0000000000000000"},
		{"C5_HEIGHT_WIDE", UTXOImageQuery{RequestID: 1, Height: 0x100000000, ByteLimit: 150905}, 8, "0000000001000000"},
		{"C5_LIMIT_LOW", UTXOImageQuery{RequestID: 1, ByteLimit: 150904}, 116, "784d0200"},
		{"C5_LIMIT_HIGH", UTXOImageQuery{RequestID: 1, ByteLimit: 2097153}, 116, "01002000"},
	} {
		candidate := tc.q
		candidate.BlockHash, candidate.Root = q.BlockHash, q.Root
		payload := bytes.Clone(raw)
		copy(payload[tc.offset:], imageTestHex(t, tc.hex))
		got, ok := EncodeUTXOImageRequest(candidate)
		before := bytes.Clone(payload)
		decoded, valid := DecodeUTXOImageRequest(payload)
		if ok || valid || got != ([120]byte{}) || decoded != (UTXOImageQuery{}) || !bytes.Equal(payload, before) {
			t.Fatalf("%s: got=(%x,%v,%#v,%v) want=(zero,false,zero,false)", tc.id, got, ok, decoded, valid)
		}
	}
	for _, payload := range [][]byte{raw[:119], append(bytes.Clone(raw), 0)} {
		before := bytes.Clone(payload)
		if got, ok := DecodeUTXOImageRequest(payload); ok || got != (UTXOImageQuery{}) || !bytes.Equal(payload, before) {
			t.Fatalf("C5_REQUEST_WIDTH%d: got=%#v/%v want=zero/false", len(payload), got, ok)
		}
	}
	command := imageTestCommand(t, "7574786f696d670000000000")
	for _, tc := range []struct {
		id   string
		body string
	}{
		{"C5_FLAG02", "00000000" + "02" + "0000" + "0000"},
		{"C5_MISSING_PREDECESSOR", "00000000" + "01" + "0000" + "0000"},
		{"C5_EXTRA_PREDECESSOR", "00000000" + "00" + imageTestS + "0000" + "0000"},
		{"C5_TRAILING", "00000000" + "00" + "0000" + "0000" + "00"},
		{"C5_COINBASE02", "01000000" + imageTestS[:len(imageTestS)-2] + "02" + "00" + "0000" + "0000"},
		{"C5_LEFT_DEPTH288", "00000000" + "00" + "0100" + "0120" + strings.Repeat("11", 32) + "0000"},
		{"C5_RIGHT_DEPTH288", "00000000" + "00" + "0000" + "0100" + "0120" + strings.Repeat("11", 32)},
		{"C5_LEFT_COUNT_TRUNC", "01000000" + imageTestS + "00" + "00"},
		{"C5_RIGHT_COUNT_TRUNC", "01000000" + imageTestS + "00" + "0000" + "00"},
	} {
		imageTestRejected(t, tc.id, command, imageTestChunk(raw, imageTestHex(t, tc.body)), "image_encoding")
	}
	for _, tc := range []struct {
		id      string
		compact string
		n       int
	}{
		{"C5_NONMIN_FD", "fd0000", 0},
		{"C5_NONMIN_FE", "feffff0000", 65535},
		{"C5_NONMIN_FF", "ff0000010000000000", 65536},
		{"C5_DATA65537", "fe01000100", 65537},
	} {
		s := strings.Repeat("00", 46) + tc.compact + strings.Repeat("22", tc.n) + strings.Repeat("00", 9)
		imageTestRejected(t, tc.id, command, imageTestChunk(raw, imageTestHex(t, "01000000"+s+"00"+"0000"+"0000")), "image_encoding")
	}
	singleton := imageTestChunk(raw, imageTestHex(t, "01000000"+imageTestS+"00"+"0000"+"0000"))
	for length := 185; length < 218; length++ {
		imageTestRejected(t, "C5_STARTED_FIELD", command, singleton[:length], "image_encoding")
	}
	for length := 0; length < 124; length++ {
		imageTestRejected(t, "C5_Q_COUNT_TRUNC", command, singleton[:length], "image_encoding")
	}
	negative := imageTestCommand(t, "7574786f6e6f74617661696c")
	imageTestRejected(t, "C5_NEGATIVE119", negative, raw[:119], "image_encoding")
	imageTestRejected(t, "C7_NEGATIVE_ABOVE_CAP", negative, append(bytes.Clone(raw), 0), "")
	imageTestRejected(t, "C7_CHUNK_ABOVE_CAP", command, make([]byte, 2097153), "")
	for _, text := range []string{"000000000000000000000000", "5574786f696d670000000000", "7574786f696d670000000001"} {
		imageTestRejected(t, "C7_UNKNOWN_COMMAND", imageTestCommand(t, text), nil, "")
	}
}

func TestUTXOImageCountSpans(t *testing.T) {
	_, raw := imageTestQuery(t)
	command := imageTestCommand(t, "7574786f696d670000000000")
	for _, tc := range []struct {
		id   string
		body []byte
	}{
		{"C6_COUNT37447", imageTestHex(t, "47920000" + "00" + "0000" + "0000")},
		{"C6_COUNT_U32MAX", imageTestHex(t, "ffffffff" + "00" + "0000" + "0000")},
		{"C6_COUNT_MIN", append(imageTestHex(t, "01000000"), make([]byte, 60)...)},
		{"C6_COUNT37446_SUFFIX", append(imageTestHex(t, "46920000"), make([]byte, 56*37446+4)...)},
		{"C6_LEFT289", append(append(imageTestHex(t, "00000000" + "00" + "2101"), make([]byte, 34*289)...), 0, 0)},
		{"C6_RIGHT289", append(imageTestHex(t, "00000000" + "00" + "0000" + "2101"), make([]byte, 34*289)...)},
		{"C6_LEFT_SPAN33", append(imageTestHex(t, "00000000" + "00" + "0100"), make([]byte, 33)...)},
		{"C6_RIGHT_SPAN33", append(imageTestHex(t, "00000000" + "00" + "0000" + "0100"), make([]byte, 33)...)},
	} {
		t.Run(tc.id, func(t *testing.T) {
			payload := imageTestChunk(raw, tc.body)
			imageTestRejected(t, tc.id, command, payload, "image_count")
			var reply UTXOImageReply
			var ok bool
			var reason string
			allocations := testing.AllocsPerRun(20, func() { reply, ok, reason = DecodeUTXOImageReply(command, payload) })
			if allocations != 0 || ok || reason != "image_count" || !reflect.DeepEqual(reply, UTXOImageReply{}) {
				t.Fatalf("%s: allocs=%v ok=%v reason=%q reply=%#v want=0/false/image_count/zero", tc.id, allocations, ok, reason, reply)
			}
		})
	}
}

func TestUTXOImagePhaseOrder(t *testing.T) {
	q, raw := imageTestQuery(t)
	command := imageTestCommand(t, "7574786f696d670000000000")
	badEntry := append(imageTestHex(t, "01000000"), bytes.Repeat([]byte{0xff}, 60)...)
	imageTestRejected(t, "C7_COUNT_BEFORE_ENTRY184", command, imageTestChunk(raw, badEntry), "image_count")
	minimum := imageTestChunk(raw, append(imageTestHex(t, "01000000"), make([]byte, 61)...))
	if len(minimum) != 185 {
		t.Fatalf("C7_MINIMUM185: got=%d want=185", len(minimum))
	}
	imageTestDecoded(t, "C7_MINIMUM185", command, minimum, q)
	started := append(imageTestHex(t, "01000000"+strings.Repeat("00", 46)+"0f"), make([]byte, 14)...)
	imageTestRejected(t, "C7_STARTED_DATA15_REMAIN14", command, imageTestChunk(raw, started), "image_encoding")
}

func TestUTXOImageWireEncoderRejections(t *testing.T) {
	q, _ := imageTestQuery(t)
	oversized := UTXOImageEntry{Entry: UtxoEntry{CovenantData: make([]byte, 65537)}}
	large := make([]UTXOImageEntry, 32)
	for i := range large {
		large[i].Entry.CovenantData = make([]byte, 65536)
	}
	for _, tc := range []struct {
		id          string
		entries     []UTXOImageEntry
		predecessor *UTXOImageEntry
		left, right []UTXOImageEdge
		reason      string
	}{
		{id: "C6_ENCODE_ENTRY_COUNT", entries: make([]UTXOImageEntry, 37447), reason: "image_count"},
		{id: "C5_ENCODE_ENTRY_DATA", entries: []UTXOImageEntry{oversized}, reason: "image_encoding"},
		{id: "C5_ENCODE_PREDECESSOR_DATA", predecessor: &oversized, reason: "image_encoding"},
		{id: "C6_ENCODE_LEFT289", left: make([]UTXOImageEdge, 289), reason: "image_count"},
		{id: "C6_ENCODE_RIGHT289", right: make([]UTXOImageEdge, 289), reason: "image_count"},
		{id: "C5_ENCODE_LEFT_DEPTH288", left: []UTXOImageEdge{{Depth: 288}}, reason: "image_encoding"},
		{id: "C5_ENCODE_RIGHT_DEPTH288", right: []UTXOImageEdge{{Depth: 288}}, reason: "image_encoding"},
		{id: "C6_ENCODE_TOTAL", entries: large, reason: "image_count"},
	} {
		beforeEntries := make([]UTXOImageEntry, len(tc.entries))
		if tc.entries == nil {
			beforeEntries = nil
		}
		for i, entry := range tc.entries {
			beforeEntries[i] = entry
			beforeEntries[i].Entry.CovenantData = bytes.Clone(entry.Entry.CovenantData)
		}
		var beforePredecessor *UTXOImageEntry
		if tc.predecessor != nil {
			copyEntry := *tc.predecessor
			copyEntry.Entry.CovenantData = bytes.Clone(copyEntry.Entry.CovenantData)
			beforePredecessor = &copyEntry
		}
		beforeLeft, beforeRight := append([]UTXOImageEdge(nil), tc.left...), append([]UTXOImageEdge(nil), tc.right...)
		got, ok, reason := EncodeUTXOImageChunk(q, tc.entries, tc.predecessor, tc.left, tc.right)
		if got != nil || ok || reason != tc.reason {
			t.Fatalf("%s: got=(%x,%v,%q) want=(nil,false,%q)", tc.id, got, ok, reason, tc.reason)
		}
		if !reflect.DeepEqual(tc.entries, beforeEntries) || !reflect.DeepEqual(tc.predecessor, beforePredecessor) ||
			!reflect.DeepEqual(tc.left, beforeLeft) || !reflect.DeepEqual(tc.right, beforeRight) {
			t.Fatalf("%s: rejected typed input changed", tc.id)
		}
	}
}

func TestUTXOImageWireEncoderOwnership(t *testing.T) {
	q, raw := imageTestQuery(t)
	entries := []UTXOImageEntry{imageTestEntry()}
	predecessor := imageTestEntry()
	predecessor.Outpoint.Vout = 1
	left := []UTXOImageEdge{{Depth: 3, Hash: [32]byte(bytes.Repeat([]byte{0x11}, 32))}}
	right := []UTXOImageEdge{{Depth: 287, Hash: [32]byte(bytes.Repeat([]byte{0x55}, 32))}}
	beforeEntries := []UTXOImageEntry{imageTestEntry()}
	beforePredecessor := imageTestEntry()
	beforePredecessor.Outpoint.Vout = 1
	beforeLeft, beforeRight := append([]UTXOImageEdge(nil), left...), append([]UTXOImageEdge(nil), right...)
	predS := imageTestHex(t, imageTestS)
	copy(predS[32:36], imageTestHex(t, "01000000"))
	body := append(imageTestHex(t, "01000000"+imageTestS+"01"), predS...)
	body = append(body, imageTestHex(t, "0100"+"0003"+strings.Repeat("11", 32)+"0100"+"011f"+strings.Repeat("55", 32))...)
	want := imageTestChunk(raw, body)
	got, ok, reason := EncodeUTXOImageChunk(q, entries, &predecessor, left, right)
	if !ok || reason != "" || !bytes.Equal(got, want) {
		t.Fatalf("C4_ENCODER_OWNED_BYTES: got=%x/%v/%q want=%x/true/empty", got, ok, reason, want)
	}
	if !reflect.DeepEqual(entries, beforeEntries) || !reflect.DeepEqual(predecessor, beforePredecessor) ||
		!reflect.DeepEqual(left, beforeLeft) || !reflect.DeepEqual(right, beforeRight) {
		t.Fatal("C4_ENCODER_INPUTS: typed input changed")
	}
	entries[0].Entry.CovenantData[0] ^= 0xff
	predecessor.Entry.CovenantData[0] ^= 0xff
	left[0].Hash[0] ^= 0xff
	right[0].Depth = 0
	if !bytes.Equal(got, want) {
		t.Fatalf("C4_ENCODER_REUSE: got=%x want=%x", got, want)
	}
}

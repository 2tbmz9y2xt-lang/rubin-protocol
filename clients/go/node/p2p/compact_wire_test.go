package p2p

import (
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestCompactWireCommandConstantsAndPayloadCaps(t *testing.T) {
	liveCaps := postHandshakePayloadCap(defaultLocatorLimit, 512)
	commands := []string{messageSendCmpct, messageGetBlockTxn, messageCmpctBlock, messageBlockTxn}
	caps := []uint32{
		sendCmpctPayloadBytes,
		uint32(32 + maxCompactSizeBytes + maxCompactRelayEntries*compactRelayIndexBytes),
		uint32(consensus.MAX_RELAY_MSG_BYTES),
		uint32(consensus.MAX_BLOCK_BYTES + 32 + maxCompactSizeBytes + maxCompactRelayEntries*maxCompactSizeBytes),
	}
	for i, command := range commands {
		if _, err := encodeWireCommand(command); err != nil {
			t.Fatalf("compact command %q should be wire-encodable: %v", command, err)
		}
		if got := compactRelayPayloadCap(command); got != caps[i] {
			t.Fatalf("%s explicit cap=%d, want %d", command, got, caps[i])
		}
		if (command == messageCmpctBlock || command == messageBlockTxn) && caps[i] <= uint32(consensus.MAX_BLOCK_BYTES) {
			t.Fatalf("%s explicit cap=%d, want above MAX_BLOCK_BYTES", command, caps[i])
		}
		if got := liveCaps(command); got != caps[i] {
			t.Fatalf("%s live cap=%d, want %d", command, got, caps[i])
		}
	}
}

func TestGetBlockTxnPayloadCodec(t *testing.T) {
	want := getBlockTxnPayload{
		BlockHash: [32]byte{0x01, 0x02, 0x03},
		Indexes:   []uint64{0, 2, 5},
	}
	raw, err := encodeGetBlockTxnPayload(want)
	if err != nil {
		t.Fatalf("encodeGetBlockTxnPayload: %v", err)
	}
	wantWire := []byte{3, 0, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0}
	if gotWire := raw[32:]; !reflect.DeepEqual(gotWire, wantWire) {
		t.Fatalf("getblocktxn absolute index wire=%x, want %x", gotWire, wantWire)
	}
	got, err := decodeGetBlockTxnPayload(raw)
	if err != nil {
		t.Fatalf("decodeGetBlockTxnPayload: %v", err)
	}
	if got.BlockHash != want.BlockHash || !reflect.DeepEqual(got.Indexes, want.Indexes) {
		t.Fatalf("getblocktxn roundtrip got=%+v want=%+v", got, want)
	}
}

func TestBlockTxnPayloadCodec(t *testing.T) {
	tx1 := minimalBlockTxnTestTxBytes(1)
	tx2 := minimalBlockTxnTestTxBytes(2)
	want := blockTxnPayload{
		BlockHash:    [32]byte{0x04, 0x05, 0x06},
		Transactions: [][]byte{tx1, tx2},
	}
	raw, err := encodeBlockTxnPayload(want)
	if err != nil {
		t.Fatalf("encodeBlockTxnPayload: %v", err)
	}
	wantEntries := append(consensus.AppendCompactSize(nil, 2), cmpctBlockTxEnvelope(tx1)...)
	wantEntries = append(wantEntries, cmpctBlockTxEnvelope(tx2)...)
	if gotEntries := raw[32:]; !reflect.DeepEqual(gotEntries, wantEntries) {
		t.Fatalf("blocktxn entries=%x, want %x", gotEntries, wantEntries)
	}
	got, err := decodeBlockTxnPayload(raw)
	if err != nil {
		t.Fatalf("decodeBlockTxnPayload: %v", err)
	}
	if got.BlockHash != want.BlockHash || !reflect.DeepEqual(got.Transactions, want.Transactions) {
		t.Fatalf("blocktxn roundtrip got=%+v want=%+v", got, want)
	}
}

func TestCmpctBlockPayloadCodec(t *testing.T) {
	tx := minimalBlockTxnTestTxBytes(10)
	want := cmpctBlockPayload{
		Header:    [consensus.BLOCK_HEADER_BYTES]byte{0x01, 0x02, 0x03},
		Nonce1:    0x1122334455667788,
		Nonce2:    0x8877665544332211,
		ShortIDs:  []compactShortID{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}},
		Prefilled: []prefilledTxn{{Index: 1, Tx: tx}},
	}
	raw, err := encodeCmpctBlockPayload(want)
	if err != nil {
		t.Fatalf("encodeCmpctBlockPayload: %v", err)
	}
	wantRaw := append([]byte(nil), want.Header[:]...)
	wantRaw = consensus.AppendU64le(wantRaw, want.Nonce1)
	wantRaw = consensus.AppendU64le(wantRaw, want.Nonce2)
	wantRaw = consensus.AppendCompactSize(wantRaw, uint64(len(want.ShortIDs)))
	wantRaw = append(wantRaw, want.ShortIDs[0][:]...)
	wantRaw = consensus.AppendCompactSize(wantRaw, uint64(len(want.Prefilled)))
	wantRaw = consensus.AppendU32le(wantRaw, uint32(want.Prefilled[0].Index))
	wantRaw = consensus.AppendCompactSize(wantRaw, uint64(len(tx)))
	wantRaw = append(wantRaw, tx...)
	if !reflect.DeepEqual(raw, wantRaw) {
		t.Fatalf("cmpctblock wire layout=%x, want %x", raw, wantRaw)
	}
	got, err := decodeCmpctBlockPayload(raw)
	if err != nil {
		t.Fatalf("decodeCmpctBlockPayload: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cmpctblock roundtrip got=%+v want=%+v", got, want)
	}
	shortIDs := make([]compactShortID, maxCompactRelayEntries+1)
	raw, err = encodeCmpctBlockPayload(cmpctBlockPayload{ShortIDs: shortIDs})
	if err != nil {
		t.Fatalf("encodeCmpctBlockPayload above inventory vector limit: %v", err)
	}
	if got, err := decodeCmpctBlockPayload(raw); err != nil || len(got.ShortIDs) != len(shortIDs) {
		t.Fatalf("decode above inventory vector limit got=%d err=%v", len(got.ShortIDs), err)
	}
}

func TestCmpctBlockPayloadRejectsMalformed(t *testing.T) {
	validTx := minimalBlockTxnTestTxBytes(12)
	assertCmpctBlockEncodeFails(t, "empty", cmpctBlockPayload{}, "invalid compact relay entry count")
	assertCmpctBlockEncodeFails(t, "duplicate_prefilled", cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 1, Tx: validTx}, {Index: 1, Tx: validTx}}}, "compact relay index")
	assertCmpctBlockEncodeFails(t, "prefilled_index_outside_vector", cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 1, Tx: validTx}}}, "compact relay index out of range")
	assertCmpctBlockEncodeFails(t, "prefilled_index_range", cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: maxCompactRelayIndexValue + 1, Tx: validTx}}}, "compact relay index out of range")
	assertCmpctBlockEncodeFails(t, "empty_prefilled_tx", cmpctBlockPayload{Prefilled: []prefilledTxn{{Tx: nil}}}, "blocktxn transaction is empty")
	assertCmpctBlockEncodeFails(t, "trailing_prefilled_tx", cmpctBlockPayload{Prefilled: []prefilledTxn{{Tx: append(validTx, 0x00)}}}, "cmpctblock prefilled transaction is non-canonical")
	assertCmpctBlockEncodeFails(t, "trailing_prefilled_tx_before_next_delta", cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: append(validTx, 0x00)}, {Index: 1, Tx: validTx}}}, "cmpctblock prefilled transaction is non-canonical")

	assertCmpctBlockDecodeFails(t, "short_header", make([]byte, consensus.BLOCK_HEADER_BYTES+15), "cmpctblock payload missing header or nonce")
	assertCmpctBlockDecodeFails(t, "empty", cmpctBlockTestPayload([]byte{0, 0}), "invalid compact relay entry count")
	assertCmpctBlockDecodeFails(t, "payload_above_wire_cap", make([]byte, consensus.MAX_RELAY_MSG_BYTES+1), "cmpctblock payload too large")
	assertCmpctBlockDecodeFails(t, "nonminimal_short_count", cmpctBlockTestPayload([]byte{0xfd, 0x00, 0x00}), "non-minimal")
	assertCmpctBlockDecodeFails(t, "truncated_short_ids", cmpctBlockTestPayload([]byte{1, 0x01, 0x02}), "cmpctblock payload truncated short IDs")
	assertCmpctBlockDecodeFails(t, "nonminimal_prefilled_count", cmpctBlockTestPayload([]byte{0, 0xfd, 0x00, 0x00}), "non-minimal")
	assertCmpctBlockDecodeFails(t, "huge_prefilled_count_without_entries", cmpctBlockTestPayload(consensus.AppendCompactSize([]byte{0}, consensus.MAX_BLOCK_BYTES)), "cmpctblock payload truncated prefilled index")
	assertCmpctBlockDecodeFails(t, "truncated_prefilled_index", cmpctBlockTestPayload([]byte{0, 1, 0x01, 0x02}), "cmpctblock payload truncated prefilled index")
	assertCmpctBlockDecodeFails(t, "truncated_prefilled_tx", cmpctBlockTestPayload(cmpctBlockPrefilledPayload(0, append(consensus.AppendCompactSize(nil, uint64(len(validTx)+1)), validTx...))), "compact relay transaction truncated")
	duplicatePrefilled := consensus.AppendCompactSize(nil, 0)
	duplicatePrefilled = consensus.AppendCompactSize(duplicatePrefilled, 2)
	duplicatePrefilled = consensus.AppendU32le(duplicatePrefilled, 0)
	duplicatePrefilled = append(duplicatePrefilled, cmpctBlockTxEnvelope(validTx)...)
	duplicatePrefilled = consensus.AppendU32le(duplicatePrefilled, 0)
	duplicatePrefilled = append(duplicatePrefilled, cmpctBlockTxEnvelope(validTx)...)
	assertCmpctBlockDecodeFails(t, "duplicate_prefilled_index", cmpctBlockTestPayload(duplicatePrefilled), "compact relay index out of range")

	rangeBeforeTx := consensus.AppendU32le(consensus.AppendCompactSize(consensus.AppendCompactSize(nil, 0), 1), 1)
	assertCmpctBlockDecodeFails(t, "prefilled_index_range_before_tx", cmpctBlockTestPayload(rangeBeforeTx), "compact relay index out of range")
	assertCmpctBlockDecodeFails(t, "trailing", append(cmpctBlockTestPayload([]byte{1, 0, 0, 0, 0, 0, 0, 0}), 0x00), "cmpctblock payload has trailing bytes")
}

func TestBlockTxnPayloadRejectsMalformed(t *testing.T) {
	tooMany := make([][]byte, maxCompactRelayEntries+1)
	tooLarge := make([]byte, consensus.MAX_BLOCK_BYTES+1)
	validWithTrailing := append(minimalBlockTxnTestTxBytes(3), 0x00)
	for _, tc := range []struct {
		name    string
		in      blockTxnPayload
		wantErr string
	}{
		{name: "too_many", in: blockTxnPayload{Transactions: tooMany}, wantErr: "too many compact relay transactions"},
		{name: "empty", in: blockTxnPayload{Transactions: [][]byte{{}}}, wantErr: "blocktxn transaction is empty"},
		{name: "too_large", in: blockTxnPayload{Transactions: [][]byte{tooLarge}}, wantErr: "blocktxn transaction too large"},
		{name: "malformed_nonempty", in: blockTxnPayload{Transactions: [][]byte{{0x01}}}, wantErr: "blocktxn transaction is non-canonical"},
		{name: "valid_with_trailing", in: blockTxnPayload{Transactions: [][]byte{validWithTrailing}}, wantErr: "blocktxn transaction is non-canonical"},
	} {
		_, err := encodeBlockTxnPayload(tc.in)
		if err == nil {
			t.Fatalf("%s: expected encode failure", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: encode error=%q, want %q", tc.name, err, tc.wantErr)
		}
	}

	for _, tc := range []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{name: "short_hash", raw: make([]byte, 31), wantErr: "blocktxn payload missing block hash"},
		{name: "nonminimal_count", raw: blockTxnTestPayload([]byte{0xfd, 0x00, 0x00}), wantErr: "non-minimal"},
		{name: "count_too_large", raw: blockTxnTestPayload(consensus.AppendCompactSize(nil, maxCompactRelayEntries+1)), wantErr: "too many compact relay transactions"},
		{name: "missing_tx_len", raw: blockTxnTestPayload([]byte{1}), wantErr: "EOF"},
		{name: "empty_tx", raw: blockTxnTestPayload([]byte{1, 0}), wantErr: "blocktxn transaction is empty"},
		{name: "truncated_tx", raw: blockTxnTestPayload(append(consensus.AppendCompactSize([]byte{1}, uint64(len(minimalBlockTxnTestTxBytes(5)))), minimalBlockTxnTestTxBytes(5)[:3]...)), wantErr: "compact relay transaction truncated"},
		{name: "raw_concatenated_txbytes", raw: blockTxnTestPayload(append(consensus.AppendCompactSize(nil, 2), minimalBlockTxnTestTxBytes(5)...)), wantErr: "blocktxn transaction is non-canonical"},
		{name: "trailing", raw: append(mustEncodeBlockTxnPayload(t, [][]byte{minimalBlockTxnTestTxBytes(4)}), 0x00), wantErr: "blocktxn payload has trailing bytes"},
	} {
		_, err := decodeBlockTxnPayload(tc.raw)
		if err == nil {
			t.Fatalf("%s: expected decode failure", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: decode error=%q, want %q", tc.name, err, tc.wantErr)
		}
	}
}

func minimalBlockTxnTestTxBytes(nonce uint64) []byte {
	out := consensus.AppendU32le(nil, consensus.TX_WIRE_VERSION)
	out = append(out, 0x00) // tx_kind
	out = consensus.AppendU64le(out, nonce)
	out = consensus.AppendCompactSize(out, 0) // input_count
	out = consensus.AppendCompactSize(out, 0) // output_count
	out = consensus.AppendU32le(out, 0)       // locktime
	out = consensus.AppendCompactSize(out, 0) // witness_count
	out = consensus.AppendCompactSize(out, 0) // da_payload_len
	return out
}

func blockTxnTestPayload(tail []byte) []byte {
	return append(make([]byte, 32), tail...)
}

func mustEncodeBlockTxnPayload(t *testing.T, txs [][]byte) []byte {
	t.Helper()
	raw, err := encodeBlockTxnPayload(blockTxnPayload{Transactions: txs})
	if err != nil {
		t.Fatalf("encodeBlockTxnPayload: %v", err)
	}
	return raw
}

func assertCmpctBlockEncodeFails(t *testing.T, name string, in cmpctBlockPayload, wantErr string) {
	t.Helper()
	_, err := encodeCmpctBlockPayload(in)
	if err == nil {
		t.Fatalf("%s: expected encode failure", name)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("%s: encode error=%q, want %q", name, err, wantErr)
	}
}

func assertCmpctBlockDecodeFails(t *testing.T, name string, raw []byte, wantErr string) {
	t.Helper()
	_, err := decodeCmpctBlockPayload(raw)
	if err == nil {
		t.Fatalf("%s: expected decode failure", name)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("%s: decode error=%q, want %q", name, err, wantErr)
	}
}

func cmpctBlockTestPayload(tail []byte) []byte {
	return append(make([]byte, consensus.BLOCK_HEADER_BYTES+16), tail...)
}

func cmpctBlockPrefilledPayload(index uint32, entry []byte) []byte {
	tail := consensus.AppendCompactSize(nil, 0)
	tail = consensus.AppendCompactSize(tail, 1)
	tail = consensus.AppendU32le(tail, index)
	return append(tail, entry...)
}

func cmpctBlockTxEnvelope(tx []byte) []byte {
	out := consensus.AppendCompactSize(nil, uint64(len(tx)))
	return append(out, tx...)
}

func TestGetBlockTxnPayloadAllowsIndexesAboveRequestCountCap(t *testing.T) {
	want := getBlockTxnPayload{Indexes: []uint64{maxCompactRelayEntries + 2, 0, 0, maxCompactRelayEntries}}
	raw, err := encodeGetBlockTxnPayload(want)
	if err != nil {
		t.Fatalf("encodeGetBlockTxnPayload: %v", err)
	}
	got, err := decodeGetBlockTxnPayload(raw)
	if err != nil {
		t.Fatalf("decodeGetBlockTxnPayload: %v", err)
	}
	if !reflect.DeepEqual(got.Indexes, want.Indexes) {
		t.Fatalf("indexes=%v, want %v", got.Indexes, want.Indexes)
	}
}

func TestGetBlockTxnPayloadRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   getBlockTxnPayload
	}{
		{name: "range", in: getBlockTxnPayload{Indexes: []uint64{maxCompactRelayIndexValue + 1}}},
		{name: "max", in: getBlockTxnPayload{Indexes: []uint64{^uint64(0)}}},
	} {
		if _, err := encodeGetBlockTxnPayload(tc.in); err == nil {
			t.Fatalf("%s: expected encode failure", tc.name)
		}
	}

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{name: "short_hash", raw: make([]byte, 31)},
		{name: "nonminimal", raw: getBlockTxnTestPayload([]byte{0xfd, 0x00, 0x00})},
		{name: "count_too_large", raw: getBlockTxnTestPayload(consensus.AppendCompactSize(nil, maxCompactRelayEntries+1))},
		{name: "truncated_index", raw: getBlockTxnTestPayload([]byte{1, 0x01, 0x00, 0x00})},
		{name: "range", raw: getBlockTxnIndexedPayload(maxCompactRelayIndexValue + 1)},
		{name: "trailing", raw: append(mustEncodeGetBlockTxnPayload(t, []uint64{0}), 0x00)},
	} {
		if _, err := decodeGetBlockTxnPayload(tc.raw); err == nil {
			t.Fatalf("%s: expected decode failure", tc.name)
		}
	}
}

func getBlockTxnTestPayload(tail []byte) []byte {
	return append(make([]byte, 32), tail...)
}

func getBlockTxnIndexedPayload(indexes ...uint64) []byte {
	tail := consensus.AppendCompactSize(nil, uint64(len(indexes)))
	for _, idx := range indexes {
		tail = consensus.AppendU32le(tail, uint32(idx))
	}
	return getBlockTxnTestPayload(tail)
}

func mustEncodeGetBlockTxnPayload(t *testing.T, indexes []uint64) []byte {
	t.Helper()
	raw, err := encodeGetBlockTxnPayload(getBlockTxnPayload{Indexes: indexes})
	if err != nil {
		t.Fatalf("encodeGetBlockTxnPayload: %v", err)
	}
	return raw
}

func TestSendCmpctPayloadCodec(t *testing.T) {
	want := sendCmpctPayload{Mode: 2, Version: compactRelayVersion}
	raw, err := encodeSendCmpctPayload(want)
	if err != nil {
		t.Fatalf("encodeSendCmpctPayload: %v", err)
	}
	if got, err := decodeSendCmpctPayload(raw); err != nil || got != want {
		t.Fatalf("sendcmpct roundtrip got=%+v err=%v", got, err)
	}
	for _, raw := range [][]byte{
		{2},
		append([]byte{0x03}, make([]byte, 8)...),
		consensus.AppendU64le([]byte{2}, compactRelayVersion+1),
	} {
		if _, err := decodeSendCmpctPayload(raw); err == nil {
			t.Fatalf("expected malformed sendcmpct payload to fail: %x", raw)
		}
	}
}

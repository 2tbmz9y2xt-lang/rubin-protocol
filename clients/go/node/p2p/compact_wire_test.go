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
		uint32(32 + maxCompactSizeBytes + maxCompactRelayEntries*maxCompactSizeBytes),
		uint32(consensus.MAX_BLOCK_BYTES + consensus.BLOCK_HEADER_BYTES + 8 + 2*maxCompactSizeBytes + maxCompactRelayEntries*(compactShortIDBytes+maxCompactSizeBytes)),
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
		if got := liveCaps(command); got != 0 {
			t.Fatalf("%s live cap=%d, want 0 until runtime handler slice", command, got)
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
	if gotDeltas := raw[32:]; !reflect.DeepEqual(gotDeltas, []byte{3, 0, 1, 2}) {
		t.Fatalf("getblocktxn differential indexes=%x, want 03000102", gotDeltas)
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
	wantEntries := append(consensus.AppendCompactSize(nil, 2), tx1...)
	wantEntries = append(wantEntries, tx2...)
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
	tx1 := minimalBlockTxnTestTxBytes(10)
	tx2 := minimalBlockTxnTestTxBytes(11)
	want := cmpctBlockPayload{
		Header: [consensus.BLOCK_HEADER_BYTES]byte{0x01, 0x02, 0x03},
		Nonce:  0x1122334455667788,
		ShortIDs: []compactShortID{
			{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
		},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: tx1},
			{Index: 3, Tx: tx2},
		},
	}
	raw, err := encodeCmpctBlockPayload(want)
	if err != nil {
		t.Fatalf("encodeCmpctBlockPayload: %v", err)
	}
	got, err := decodeCmpctBlockPayload(raw)
	if err != nil {
		t.Fatalf("decodeCmpctBlockPayload: %v", err)
	}
	if got.Header != want.Header || got.Nonce != want.Nonce || !reflect.DeepEqual(got.ShortIDs, want.ShortIDs) || !reflect.DeepEqual(got.Prefilled, want.Prefilled) {
		t.Fatalf("cmpctblock roundtrip got=%+v want=%+v", got, want)
	}
}

func TestCmpctBlockPayloadRejectsMalformed(t *testing.T) {
	validTx := minimalBlockTxnTestTxBytes(12)
	tooManyShortIDs := make([]compactShortID, maxCompactRelayEntries+1)
	tooManyPrefilled := make([]prefilledTxn, maxCompactRelayEntries+1)
	for i := range tooManyPrefilled {
		tooManyPrefilled[i] = prefilledTxn{Index: uint64(i), Tx: validTx}
	}
	assertCmpctBlockEncodeFails(t, "too_many_short_ids", cmpctBlockPayload{ShortIDs: tooManyShortIDs}, "too many compact relay entries")
	assertCmpctBlockEncodeFails(t, "too_many_prefilled", cmpctBlockPayload{Prefilled: tooManyPrefilled}, "too many compact relay entries")
	assertCmpctBlockEncodeFails(t, "duplicate_prefilled", cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 1, Tx: validTx}, {Index: 1, Tx: validTx}}}, "compact relay indexes not strictly increasing")
	assertCmpctBlockEncodeFails(t, "prefilled_index_outside_vector", cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 1, Tx: validTx}}}, "compact relay index out of range")
	assertCmpctBlockEncodeFails(t, "prefilled_index_range", cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: maxCompactRelayIndexValue + 1, Tx: validTx}}}, "compact relay index out of range")
	assertCmpctBlockEncodeFails(t, "empty_prefilled_tx", cmpctBlockPayload{Prefilled: []prefilledTxn{{Tx: nil}}}, "blocktxn transaction is empty")
	assertCmpctBlockEncodeFails(t, "trailing_prefilled_tx", cmpctBlockPayload{Prefilled: []prefilledTxn{{Tx: append(validTx, 0x00)}}}, "cmpctblock prefilled transaction is non-canonical")

	assertCmpctBlockDecodeFails(t, "short_header", make([]byte, consensus.BLOCK_HEADER_BYTES+7), "cmpctblock payload missing header or nonce")
	assertCmpctBlockDecodeFails(t, "nonminimal_short_count", cmpctBlockTestPayload([]byte{0xfd, 0x00, 0x00}), "non-minimal")
	assertCmpctBlockDecodeFails(t, "too_many_short_ids", cmpctBlockTestPayload(consensus.AppendCompactSize(nil, maxCompactRelayEntries+1)), "too many compact relay short IDs")
	assertCmpctBlockDecodeFails(t, "truncated_short_ids", cmpctBlockTestPayload([]byte{1, 0x01, 0x02}), "cmpctblock payload truncated short IDs")
	assertCmpctBlockDecodeFails(t, "nonminimal_prefilled_count", cmpctBlockTestPayload([]byte{0, 0xfd, 0x00, 0x00}), "non-minimal")
	aggregate := consensus.AppendCompactSize(append(consensus.AppendCompactSize(nil, maxCompactRelayEntries), make([]byte, maxCompactRelayEntries*compactShortIDBytes)...), 1)
	assertCmpctBlockDecodeFails(t, "aggregate_count", cmpctBlockTestPayload(aggregate), "too many compact relay entries")

	rangeBeforeTx := consensus.AppendCompactSize(consensus.AppendCompactSize(consensus.AppendCompactSize(nil, 0), 1), 1)
	rangeBeforeTx = append(rangeBeforeTx, make([]byte, consensus.MAX_BLOCK_BYTES)...)
	assertCmpctBlockDecodeFails(t, "prefilled_index_range_before_tx", cmpctBlockTestPayload(rangeBeforeTx), "compact relay index out of range")
	assertCmpctBlockDecodeFails(t, "trailing", append(cmpctBlockTestPayload([]byte{0, 0}), 0x00), "cmpctblock payload has trailing bytes")
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
		{name: "empty_tx", raw: blockTxnTestPayload([]byte{1}), wantErr: "unexpected EOF"},
		{name: "truncated_tx", raw: blockTxnTestPayload([]byte{1, 1}), wantErr: "unexpected EOF"},
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
	head := make([]byte, consensus.BLOCK_HEADER_BYTES+8)
	return append(head, tail...)
}

func TestGetBlockTxnPayloadAllowsIndexesAboveRequestCountCap(t *testing.T) {
	want := getBlockTxnPayload{Indexes: []uint64{0, maxCompactRelayEntries, maxCompactRelayEntries + 2}}
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
		{name: "duplicate", in: getBlockTxnPayload{Indexes: []uint64{1, 1}}},
		{name: "descending", in: getBlockTxnPayload{Indexes: []uint64{2, 1}}},
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
		{name: "truncated_index", raw: getBlockTxnTestPayload([]byte{1, 0xfd})},
		{name: "range", raw: getBlockTxnIndexedPayload(maxCompactRelayIndexValue + 1)},
		{name: "max", raw: getBlockTxnIndexedPayload(^uint64(0))},
		{name: "range_after_first", raw: getBlockTxnIndexedPayload(0, maxCompactRelayIndexValue)},
		{name: "overflow_after_first", raw: getBlockTxnIndexedPayload(0, ^uint64(0))},
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

func getBlockTxnIndexedPayload(deltas ...uint64) []byte {
	tail := consensus.AppendCompactSize(nil, uint64(len(deltas)))
	for _, delta := range deltas {
		tail = consensus.AppendCompactSize(tail, delta)
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

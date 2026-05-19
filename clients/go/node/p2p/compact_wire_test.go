package p2p

import (
	"reflect"
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

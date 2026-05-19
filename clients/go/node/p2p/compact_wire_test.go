package p2p

import (
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestCompactWireCommandConstantsAndPayloadCaps(t *testing.T) {
	liveCaps := postHandshakePayloadCap(defaultLocatorLimit, 512)
	commands := []string{messageSendCmpct, messageGetBlockTxn, messageCmpctBlock, messageBlockTxn}
	caps := []uint32{sendCmpctPayloadBytes, uint32(32 + maxCompactSizeBytes + maxCompactRelayEntries*maxCompactSizeBytes), uint32(consensus.MAX_BLOCK_BYTES), uint32(consensus.MAX_BLOCK_BYTES)}
	for i, command := range commands {
		if _, err := encodeWireCommand(command); err != nil {
			t.Fatalf("compact command %q should be wire-encodable: %v", command, err)
		}
		if got := compactRelayPayloadCap(command); got != caps[i] {
			t.Fatalf("%s explicit cap=%d, want %d", command, got, caps[i])
		}
		if got := liveCaps(command); got != 0 {
			t.Fatalf("%s live cap=%d, want 0 until runtime handler slice", command, got)
		}
	}
}
func TestCompactWirePayloadCodecsRoundtrip(t *testing.T) {
	send := sendCmpctPayload{Mode: 2, Version: compactRelayVersion}
	sendBytes, _ := encodeSendCmpctPayload(send)
	if got, err := decodeSendCmpctPayload(sendBytes); err != nil || got != send {
		t.Fatalf("sendcmpct roundtrip got=%+v err=%v", got, err)
	}
	getReq := getBlockTxnPayload{Indexes: []uint64{0, 2, 5}}
	getBytes, _ := encodeGetBlockTxnPayload(getReq)
	if got, err := decodeGetBlockTxnPayload(getBytes); err != nil || got.BlockHash != getReq.BlockHash || !reflect.DeepEqual(got.Indexes, getReq.Indexes) {
		t.Fatalf("getblocktxn roundtrip got=%+v err=%v", got, err)
	}
	compact := compactBlockPayload{
		Nonce:     0x0102030405060708,
		ShortIDs:  [][compactShortIDBytes]byte{{1, 2, 3, 4, 5, 6}, {7, 8, 9, 10, 11, 12}},
		Prefilled: []compactPrefilledTx{{Index: 0, Tx: []byte{0x00, 0x01, 0x02}}},
	}
	compactBytes, _ := encodeCompactBlockPayload(compact)
	if got, err := decodeCompactBlockPayload(compactBytes); err != nil || got.Header != compact.Header || got.Nonce != compact.Nonce || !reflect.DeepEqual(got.ShortIDs, compact.ShortIDs) || !reflect.DeepEqual(got.Prefilled, compact.Prefilled) {
		t.Fatalf("cmpctblock roundtrip got=%+v err=%v", got, err)
	}
	resp := blockTxnPayload{Txs: [][]byte{{0x01, 0x02}, {0x03}}}
	respBytes, _ := encodeBlockTxnPayload(resp)
	if got, err := decodeBlockTxnPayload(respBytes); err != nil || got.BlockHash != resp.BlockHash || !reflect.DeepEqual(got.Txs, resp.Txs) {
		t.Fatalf("blocktxn roundtrip got=%+v err=%v", got, err)
	}
}
func TestCompactWirePayloadCodecsRejectMalformed(t *testing.T) {
	for _, raw := range [][]byte{
		{2},
		append([]byte{0x03}, make([]byte, 8)...),
		consensus.AppendU64le([]byte{2}, compactRelayVersion+1),
	} {
		_, err := decodeSendCmpctPayload(raw)
		requireErr(t, err, "")
	}
	for _, raw := range [][]byte{
		append(make([]byte, 32), 0xfd, 0x00, 0x00),
		append(make([]byte, 32), consensus.EncodeCompactSize(uint64(maxCompactRelayEntries+1))...),
	} {
		_, err := decodeGetBlockTxnPayload(raw)
		requireErr(t, err, "")
	}
	_, err := encodeGetBlockTxnPayload(getBlockTxnPayload{Indexes: []uint64{1, 1}})
	requireErr(t, err, "")
	_, err = encodeGetBlockTxnPayload(getBlockTxnPayload{Indexes: []uint64{maxCompactRelayEntries}})
	requireErr(t, err, "compact index out of range")
	rawGet := append(make([]byte, 32), consensus.EncodeCompactSize(1)...)
	rawGet = append(rawGet, consensus.EncodeCompactSize(^uint64(0))...)
	_, err = decodeGetBlockTxnPayload(rawGet)
	requireErr(t, err, "compact index out of range")
	var header [consensus.BLOCK_HEADER_BYTES]byte
	outRange := consensus.AppendU64le(append([]byte{}, header[:]...), 1)
	outRange = consensus.AppendCompactSize(outRange, 0)
	outRange = consensus.AppendCompactSize(outRange, 1)
	outRange = consensus.AppendCompactSize(consensus.AppendCompactSize(outRange, 1), uint64(consensus.MAX_BLOCK_BYTES))
	_, err = decodeCompactBlockPayload(outRange)
	requireErr(t, err, "compact prefilled index out of range")
	_, err = decodeCompactBlockPayload(duplicatePrefilledCompactBlockPayload())
	requireErr(t, err, "")
	overCap := consensus.AppendU64le(append([]byte{}, header[:]...), 1)
	overCap = consensus.AppendCompactSize(overCap, uint64(maxCompactRelayEntries))
	overCap = append(overCap, make([]byte, maxCompactRelayEntries*compactShortIDBytes)...)
	overCap = consensus.AppendCompactSize(overCap, 1)
	_, err = decodeCompactBlockPayload(overCap)
	requireErr(t, err, "")
	respBytes, _ := encodeBlockTxnPayload(blockTxnPayload{Txs: [][]byte{{0x01, 0x02}}})
	_, err = decodeBlockTxnPayload(respBytes[:len(respBytes)-1])
	requireErr(t, err, "")
}

func duplicatePrefilledCompactBlockPayload() []byte {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	out := consensus.AppendU64le(append([]byte{}, header[:]...), 1)
	out = consensus.AppendCompactSize(out, 1)
	out = append(out, []byte{1, 2, 3, 4, 5, 6}...)
	out = consensus.AppendCompactSize(out, 2)
	for i := 0; i < 2; i++ {
		out = consensus.AppendCompactSize(out, 0)
		out = consensus.AppendCompactSize(out, 1)
		out = append(out, byte(i))
	}
	return out
}
func requireErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || (want != "" && err.Error() != want) {
		t.Fatalf("err=%v, want %q", err, want)
	}
}

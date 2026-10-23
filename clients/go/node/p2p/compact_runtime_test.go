package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestSendCmpctPostHandshakeCommandPathRecordsPeerMode(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	payload := sendCmpctRuntimePayload(t, 2, compactRelayVersion)
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: payload}); err != nil {
		t.Fatalf("handleMessage(sendcmpct): %v", err)
	}
	if got := p.remoteCompactMode(); got.Mode != 2 || got.Version != compactRelayVersion {
		t.Fatalf("remote compact mode=%+v, want mode=2 version=%d", got, compactRelayVersion)
	}

	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: []byte{1, 2}}); err == nil {
		t.Fatal("short sendcmpct payload must fail")
	}
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 3, compactRelayVersion)}); err == nil {
		t.Fatal("unknown sendcmpct mode must fail")
	}
}

const maxU64 = ^uint64(0)

func requireSendCmpctState(t *testing.T, p *peer, want compactModeSnapshot, label string) {
	t.Helper()
	if got := p.remoteCompactMode(); got != want {
		t.Fatalf("%s: remote compact mode=%+v, want %+v", label, got, want)
	}
	if st := p.snapshotState(); st.BanScore != 0 || st.LastError != "" {
		t.Fatalf("%s: state=%+v, want no score and no error", label, st)
	}
	if n := p.conn.(*scriptedConn).Len(); n != 0 {
		t.Fatalf("%s: wrote %d bytes, want none", label, n)
	}
}

func applySendCmpct(t *testing.T, p *peer, mode uint8, version uint64) {
	t.Helper()
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, mode, version)}); err != nil {
		t.Fatalf("sendcmpct(%d, %d): %v", mode, version, err)
	}
}

func TestSendCmpctAppliesSupportedVersion(t *testing.T) {
	for _, mode := range []uint8{0, 1, 2} {
		p := newCompactScriptedPeer(t)
		applySendCmpct(t, p, mode, 1)
		requireSendCmpctState(t, p, compactModeSnapshot{Mode: mode, Version: 1}, "apply")
	}
	p := newCompactScriptedPeer(t)
	applySendCmpct(t, p, 0, 2)
	applySendCmpct(t, p, 1, 1)
	requireSendCmpctState(t, p, compactModeSnapshot{Mode: 1, Version: 1}, "ignored then applied")
}

func TestSendCmpctUnsupportedVersionIsIgnored(t *testing.T) {
	for _, prior := range []bool{false, true} {
		for _, mode := range []uint8{0, 1, 2} {
			for _, version := range []uint64{0, 2, 3, maxU64} {
				p := newCompactScriptedPeer(t)
				want := compactModeSnapshot{}
				if prior {
					want = compactModeSnapshot{Mode: 2, Version: 1}
					applySendCmpct(t, p, 2, 1)
				}
				applySendCmpct(t, p, mode, version)
				requireSendCmpctState(t, p, want, "ignored offer")
			}
		}
	}
}

func TestSendCmpctMalformedOrder(t *testing.T) {
	long := append(sendCmpctRuntimePayload(t, 3, 2), 0)
	cases := []struct {
		payload []byte
		want    string
	}{
		{sendCmpctRuntimePayload(t, 3, 2), "unsupported compact relay mode"},
		{sendCmpctRuntimePayload(t, 255, maxU64), "unsupported compact relay mode"},
		{sendCmpctRuntimePayload(t, 3, 1), "unsupported compact relay mode"},
		{[]byte{3, 2}, "sendcmpct payload width mismatch"},
		{sendCmpctRuntimePayload(t, 3, 2)[:8], "sendcmpct payload width mismatch"},
		{long, "sendcmpct payload width mismatch"},
	}
	for _, tc := range cases {
		p := newCompactScriptedPeer(t)
		prior := compactModeSnapshot{Mode: 2, Version: 1}
		applySendCmpct(t, p, 2, 1)
		err := p.handleMessage(message{Command: messageSendCmpct, Payload: tc.payload})
		if err == nil || err.Error() != tc.want {
			t.Fatalf("payload %x: err=%v, want %q", tc.payload, err, tc.want)
		}
		if got := p.remoteCompactMode(); got != prior {
			t.Fatalf("payload %x: remote compact mode=%+v, want %+v", tc.payload, got, prior)
		}
	}
}

func TestSendCmpctRunContinuesAfterIgnoredVersion(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	conn := &scriptedConn{}
	for _, frame := range []message{
		{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 2, 1)},
		{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 1, 2)},
		{Command: messageVersion},
	} {
		conn.reads = append(conn.reads, scriptedRead{data: mustPeerRuntimeFrameBytes(t, p, frame)})
	}
	p.conn = conn
	err := p.run(context.Background())
	if err == nil || err.Error() != "invalid version message after handshake" {
		t.Fatalf("run err=%v, want next frame processed", err)
	}
	requireSendCmpctState(t, p, compactModeSnapshot{Mode: 2, Version: 1}, "run")
	if conn.writeCount != 0 {
		t.Fatalf("run wrote %d frames, want none", conn.writeCount)
	}
}

func TestSendCmpctRunEndsOnMalformedMode(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 3, 2)})}}}
	if err := p.run(context.Background()); err == nil || err.Error() != "unsupported compact relay mode" {
		t.Fatalf("run err=%v, want mode error", err)
	}
}

func TestAdvertiseLocalCompactModeSendsDisabledSendCmpct(t *testing.T) {
	p := newCompactScriptedPeer(t)
	if err := p.advertiseLocalCompactMode(); err != nil {
		t.Fatalf("advertiseLocalCompactMode: %v", err)
	}
	frame, err := readFrame(bytes.NewReader(p.conn.(*scriptedConn).Buffer.Bytes()), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	requireNoCompactErr(t, err, "read advertised sendcmpct")
	if frame.Command != messageSendCmpct {
		t.Fatalf("command=%q, want %q", frame.Command, messageSendCmpct)
	}
	got, err := decodeSendCmpctPayload(frame.Payload)
	requireNoCompactErr(t, err, "decode advertised sendcmpct")
	if got.Mode != 0 || got.Version != compactRelayVersion {
		t.Fatalf("sendcmpct=%+v, want mode=0 version=%d", got, compactRelayVersion)
	}
}

func TestSentCmpctBlockRecordsOneShotAnnouncement(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{
		Header: header,
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: txs[0]},
		},
	})
	p := newCompactScriptedPeer(t)

	if err := p.send(messageCmpctBlock, payload); err != nil {
		t.Fatalf("send cmpctblock: %v", err)
	}
	if !p.consumeCompactBlockAnnouncement(blockHash) {
		t.Fatal("sent cmpctblock did not record getblocktxn announcement")
	}
	if p.consumeCompactBlockAnnouncement(blockHash) {
		t.Fatal("compact block announcement was not one-shot")
	}

	p = newCompactScriptedPeer(t)
	p.service.cfg.PeerRuntimeConfig.MaxMessageSize = 1
	if err := p.send(messageCmpctBlock, payload); err == nil {
		t.Fatal("oversized cmpctblock send should fail")
	}
	if p.consumeCompactBlockAnnouncement(blockHash) {
		t.Fatal("failed cmpctblock send recorded an announcement")
	}

	p = newCompactScriptedPeer(t)
	p.markCompactBlockAnnounced(blockHash)
	p.service.cfg.PeerRuntimeConfig.MaxMessageSize = 1
	if err := p.send(messageCmpctBlock, payload); err == nil {
		t.Fatal("oversized duplicate cmpctblock send should fail")
	}
	if !p.consumeCompactBlockAnnouncement(blockHash) {
		t.Fatal("failed duplicate cmpctblock send removed an existing announcement")
	}
}

func TestGetBlockTxnCanRaceWithInFlightCmpctBlockSend(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	cmpctPayload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{
		Header: header,
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: txs[0]},
		},
	})
	getBlockTxnPayload := mustEncodeGetBlockTxnRequest(t, blockHash, []uint64{0})
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")

	done := make(chan error, 1)
	p.conn = &scriptedConn{writeHook: func(writeCount int) {
		if writeCount != 2 {
			return
		}
		go func() {
			done <- p.handleGetBlockTxn(getBlockTxnPayload)
		}()
	}}

	requireNoCompactErr(t, p.send(messageCmpctBlock, cmpctPayload), "send cmpctblock")
	select {
	case err := <-done:
		requireNoCompactErr(t, err, "racing getblocktxn")
	case <-time.After(time.Second):
		t.Fatal("racing getblocktxn did not complete")
	}

	reader := bytes.NewReader(p.conn.(*scriptedConn).Buffer.Bytes())
	sentCmpctBlock, err := readFrame(reader, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	requireNoCompactErr(t, err, "read sent cmpctblock")
	if sentCmpctBlock.Command != messageCmpctBlock {
		t.Fatalf("first frame command=%q, want %q", sentCmpctBlock.Command, messageCmpctBlock)
	}
	sentBlockTxn, err := readFrame(reader, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	requireNoCompactErr(t, err, "read racing blocktxn response")
	if sentBlockTxn.Command != messageBlockTxn {
		t.Fatalf("second frame command=%q, want %q", sentBlockTxn.Command, messageBlockTxn)
	}
	response, err := decodeBlockTxnPayload(sentBlockTxn.Payload)
	requireNoCompactErr(t, err, "decode racing blocktxn response")
	if response.BlockHash != blockHash || len(response.Transactions) != 1 || !bytes.Equal(response.Transactions[0], txs[0]) {
		t.Fatalf("racing blocktxn=%+v, want hash %x and requested tx", response, blockHash)
	}
}

func TestFailedCmpctBlockSendDoesNotAuthorizeRacingGetBlockTxn(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	cmpctPayload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{
		Header: header,
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: txs[0]},
		},
	})
	getBlockTxnPayload := mustEncodeGetBlockTxnRequest(t, blockHash, []uint64{0})
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")

	done := make(chan error, 1)
	writeErr := errors.New("write failed")
	p.conn = &scriptedConn{
		writeErr:   writeErr,
		writeErrAt: 2,
		writeHook: func(writeCount int) {
			if writeCount != 2 {
				return
			}
			go func() {
				done <- p.handleGetBlockTxn(getBlockTxnPayload)
			}()
		},
	}

	if err := p.send(messageCmpctBlock, cmpctPayload); !errors.Is(err, writeErr) {
		t.Fatalf("send cmpctblock err=%v, want %v", err, writeErr)
	}
	select {
	case err := <-done:
		requireNoCompactErr(t, err, "racing getblocktxn")
	case <-time.After(time.Second):
		t.Fatal("racing getblocktxn did not complete")
	}
	if p.consumeCompactBlockAnnouncement(blockHash) {
		t.Fatal("failed cmpctblock send left consumable announcement")
	}
	if p.conn.(*scriptedConn).writeCount != 2 {
		t.Fatalf("failed in-flight cmpctblock send reached %d writes, want only cmpctblock header and payload", p.conn.(*scriptedConn).writeCount)
	}
}

func TestPopExpiredCompactOutstandingBlockHashAndPayloadCapClearsOnlyExpired(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	now := time.Unix(1000, 0)
	p.service.cfg.Now = func() time.Time { return now }
	blockHash := [32]byte{0x41}
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(blockHash))

	if gotHash, gotCap, ok := p.popExpiredCompactOutstandingBlockHashAndPayloadCap(); ok {
		t.Fatalf("pre-expiry pop hash=%x cap=%d ok=%v, want no pop", gotHash, gotCap, ok)
	}
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockHash != blockHash {
		t.Fatalf("pre-expiry pop corrupted outstanding=%+v ok=%v", snap, ok)
	}

	now = now.Add(compactOutstandingRequestTTL)
	gotHash, gotCap, ok := p.popExpiredCompactOutstandingBlockHashAndPayloadCap()
	if !ok || gotHash != blockHash || gotCap != 64 {
		t.Fatalf("expired pop hash=%x cap=%d ok=%v, want hash %x cap 64", gotHash, gotCap, ok, blockHash)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("expired pop left outstanding request active")
	}
}

func TestCompactAnnouncementSendFinishRollbackAndTrim(t *testing.T) {
	p := newCompactScriptedPeer(t)
	firstHash := [32]byte{0x01}
	for i := 0; i < compactAnnouncedBlockLimit; i++ {
		p.markCompactBlockAnnounced([32]byte{byte(i + 1)})
	}
	newHash := [32]byte{0xfe}
	p.beginCompactBlockAnnouncementSend(newHash)
	p.finishCompactBlockAnnouncementSend(newHash, errors.New("boom"))
	if !p.consumeCompactBlockAnnouncement(firstHash) {
		t.Fatal("failed in-flight send evicted existing compact announcement")
	}
	if p.consumeCompactBlockAnnouncement(newHash) {
		t.Fatal("failed in-flight send left new compact announcement")
	}

	p = newCompactScriptedPeer(t)
	for i := 0; i < compactAnnouncedBlockLimit; i++ {
		p.markCompactBlockAnnounced([32]byte{byte(i + 1)})
	}
	p.beginCompactBlockAnnouncementSend(newHash)
	p.finishCompactBlockAnnouncementSend(newHash, nil)
	if p.consumeCompactBlockAnnouncement(firstHash) {
		t.Fatal("successful over-limit compact announcement did not trim the oldest hash")
	}
	if !p.consumeCompactBlockAnnouncement(newHash) {
		t.Fatal("successful over-limit compact announcement dropped the new hash")
	}
}

func sendCmpctRuntimePayload(t *testing.T, mode uint8, version uint64) []byte {
	t.Helper()
	payload := make([]byte, sendCmpctPayloadBytes)
	payload[0] = mode
	binary.LittleEndian.PutUint64(payload[1:], version)
	return payload
}

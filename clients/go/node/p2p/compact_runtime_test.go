package p2p

import (
	"bytes"
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

	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 1, compactRelayVersion+1)}); err == nil || err.Error() != "unsupported compact relay version" {
		t.Fatalf("unsupported version err=%v, want version rejection", err)
	}
	if got := p.remoteCompactMode(); got.Mode != 2 || got.Version != compactRelayVersion {
		t.Fatalf("unsupported version changed remote compact mode: %+v", got)
	}
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 3, compactRelayVersion+1)}); err == nil || err.Error() != "unsupported compact relay version" {
		t.Fatalf("future version/future mode err=%v, want version rejection", err)
	}
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: []byte{1, 2}}); err == nil {
		t.Fatal("short sendcmpct payload must fail")
	}
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 3, compactRelayVersion)}); err == nil {
		t.Fatal("unknown sendcmpct mode must fail")
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

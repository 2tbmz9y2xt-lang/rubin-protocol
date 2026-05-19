package p2p

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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

	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 1, compactRelayVersion+1)}); err != nil {
		t.Fatalf("unsupported version should downgrade without disconnect: %v", err)
	}
	if got := p.remoteCompactMode(); got.Mode != 0 || got.Version != compactRelayVersion+1 {
		t.Fatalf("unsupported version mode=%+v, want downgraded", got)
	}
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: []byte{1, 2}}); err == nil {
		t.Fatal("short sendcmpct payload must fail")
	}
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 3, compactRelayVersion)}); err == nil {
		t.Fatal("unknown sendcmpct mode must fail")
	}
}

func TestPostHandshakeAdvertisesSendCmpctWhenEnabled(t *testing.T) {
	h := newTestHarness(t, 2, "127.0.0.1:0", nil)
	h.service.ctx = context.Background()
	h.service.cfg.CompactRelayMode = 1
	markCompactRelayReadyNow(t, h)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.service.handleConn(local, "")
	}()
	remoteVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0)
	if err := completeRemoteHandshake(remote, h.service.cfg.PeerRuntimeConfig, remoteVersion); err != nil {
		t.Fatalf("remote handshake: %v", err)
	}
	assertSendCmpctFrame(t, remote, h.service.cfg.PeerRuntimeConfig, 1)
	_ = remote.Close()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not exit after remote close")
	}
}

func TestCompactModeHighBandwidthCap(t *testing.T) {
	h := newTestHarness(t, 2, "127.0.0.1:0", nil)
	h.service.cfg.CompactRelayMode = 2
	markCompactRelayReadyNow(t, h)

	sinks := make([]compactFrameSink, 0, 4)
	for i, score := range []int{90, 89, 88, 87} {
		sink := registerCompactFrameSink(t, h.service, fmt.Sprintf("compact-peer-%d", i), score)
		sinks = append(sinks, sink)
		if err := h.service.advertiseCompactRelayMode(sink.peer); err != nil {
			t.Fatalf("advertiseCompactRelayMode: %v", err)
		}
	}
	modeTwo := 0
	for _, sink := range sinks {
		frame := sink.read(t)
		if frame.Mode == 2 {
			modeTwo++
		}
		if frame.Mode != sink.peer.localCompactMode().Mode {
			t.Fatalf("%s wire mode=%d local mode=%d", sink.peer.addr(), frame.Mode, sink.peer.localCompactMode().Mode)
		}
	}
	if modeTwo != maxHighBandwidthCompactPeers {
		t.Fatalf("mode=2 peers=%d, want %d", modeTwo, maxHighBandwidthCompactPeers)
	}
}

func TestCompactRelayReadyBlocksIBD(t *testing.T) {
	h := newTestHarness(t, 0, "127.0.0.1:0", nil)
	h.service.cfg.CompactRelayMode = 2
	if h.service.compactRelayReady() {
		t.Fatal("compact relay must not advertise while service is still in IBD")
	}
}

type compactFrameSink struct {
	peer   *peer
	frames chan sendCmpctPayload
	errs   chan error
}

func registerCompactFrameSink(t *testing.T, svc *Service, addr string, score int) compactFrameSink {
	t.Helper()
	local, remote := net.Pipe()
	p := testPeerForService(svc, addr, 0)
	p.state.Addr = addr
	p.conn = local
	p.setCompactQualityScore(score)
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
	})
	svc.peersMu.Lock()
	svc.peers[p.addr()] = p
	svc.peersMu.Unlock()

	sink := compactFrameSink{peer: p, frames: make(chan sendCmpctPayload, 1), errs: make(chan error, 1)}
	go func() {
		frame, err := readFrame(remote, networkMagic(svc.cfg.PeerRuntimeConfig.Network), svc.cfg.PeerRuntimeConfig.MaxMessageSize)
		if err != nil {
			sink.errs <- err
			return
		}
		if frame.Command != messageSendCmpct {
			sink.errs <- fmt.Errorf("command=%q, want %q", frame.Command, messageSendCmpct)
			return
		}
		payload, err := decodeSendCmpctPayload(frame.Payload)
		if err != nil {
			sink.errs <- err
			return
		}
		sink.frames <- payload
	}()
	return sink
}

func (s compactFrameSink) read(t *testing.T) sendCmpctPayload {
	t.Helper()
	select {
	case frame := <-s.frames:
		return frame
	case err := <-s.errs:
		t.Fatalf("read compact frame: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out reading compact frame")
	}
	return sendCmpctPayload{}
}

func assertSendCmpctFrame(t *testing.T, conn net.Conn, cfg node.PeerRuntimeConfig, wantMode uint8) {
	t.Helper()
	frame, err := readFrame(conn, networkMagic(cfg.Network), cfg.MaxMessageSize)
	if err != nil {
		t.Fatalf("read sendcmpct: %v", err)
	}
	if frame.Command != messageSendCmpct {
		t.Fatalf("command=%q, want %q", frame.Command, messageSendCmpct)
	}
	got, err := decodeSendCmpctPayload(frame.Payload)
	if err != nil {
		t.Fatalf("decode sendcmpct: %v", err)
	}
	if got.Mode != wantMode || got.Version != compactRelayVersion {
		t.Fatalf("sendcmpct=%+v, want mode=%d version=%d", got, wantMode, compactRelayVersion)
	}
}

func markCompactRelayReadyNow(t *testing.T, h *testHarness) {
	t.Helper()
	_, hash, ok, err := h.blockStore.Tip()
	if err != nil || !ok {
		t.Fatalf("tip: ok=%v err=%v", ok, err)
	}
	block, err := h.blockStore.GetBlockByHash(hash)
	if err != nil {
		t.Fatalf("GetBlockByHash(tip): %v", err)
	}
	parsed, err := consensus.ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes(tip): %v", err)
	}
	h.service.cfg.Now = func() time.Time { return time.Unix(int64(parsed.Header.Timestamp+1), 0) }
}

func sendCmpctRuntimePayload(t *testing.T, mode uint8, version uint64) []byte {
	t.Helper()
	payload := make([]byte, sendCmpctPayloadBytes)
	payload[0] = mode
	binary.LittleEndian.PutUint64(payload[1:], version)
	return payload
}

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

func TestPostHandshakeSendCmpctPhaseGate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		blocks   int
		mode     uint8
		ready    bool
		peerOK   bool
		missRate float64
		want     string
		wantMode uint8
	}{
		{"ready eligible mode1 advertises", 2, 1, true, true, 0.2, messageSendCmpct, 1},
		{"unknown capability keeps full block", 2, 1, true, false, 0.2, messageGetAddr, 0},
		{"warmup keeps full block", 2, 2, false, true, 0.0, messageGetAddr, 0},
		{"ibd keeps full block", 0, 2, true, true, 0.2, messageGetBlk, 0},
		{"high miss rate keeps full block", 2, 2, true, true, 12.0, messageGetAddr, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t, tc.blocks, "127.0.0.1:0", nil)
			h.service.ctx = context.Background()
			h.service.cfg.CompactRelayMode = tc.mode
			h.service.cfg.CompactRelayReady = tc.ready
			h.service.cfg.CompactMissRatePct = tc.missRate
			h.service.cfg.CompactMissBlocks = 5
			if tc.peerOK {
				h.service.cfg.CompactRelayPeerOK = func(node.PeerState) bool { return true }
			}
			if tc.blocks > 0 {
				markCompactRelayReadyNow(t, h)
			}
			local, remote := net.Pipe()
			defer local.Close()
			defer remote.Close()
			errCh := make(chan error, 1)
			go func() { errCh <- h.service.handleConn(local, "") }()
			remoteVersion := testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0)
			if err := completeRemoteHandshake(remote, h.service.cfg.PeerRuntimeConfig, remoteVersion); err != nil {
				t.Fatalf("remote handshake: %v", err)
			}
			frame, err := readFrame(remote, networkMagic(h.service.cfg.PeerRuntimeConfig.Network), h.service.cfg.PeerRuntimeConfig.MaxMessageSize)
			if err != nil {
				t.Fatalf("read post-handshake frame: %v", err)
			}
			if frame.Command != tc.want {
				t.Fatalf("first post-handshake command=%q, want %q", frame.Command, tc.want)
			}
			if tc.want == messageSendCmpct {
				assertSendCmpctPayload(t, frame.Payload, tc.wantMode)
			}
			_ = remote.Close()
			select {
			case <-errCh:
			case <-time.After(2 * time.Second):
				t.Fatal("handleConn did not exit after remote close")
			}
		})
	}
}

func TestCompactModeHighBandwidthCap(t *testing.T) {
	h := newTestHarness(t, 2, "127.0.0.1:0", nil)
	h.service.cfg.CompactRelayMode = 2
	h.service.cfg.CompactRelayReady = true
	h.service.cfg.CompactMissRatePct = 0.2
	h.service.cfg.CompactRelayPeerOK = func(node.PeerState) bool { return true }
	h.service.cfg.CompactPeerScore = func(node.PeerState) int { return 90 }
	markCompactRelayReadyNow(t, h)

	sinks := make([]compactFrameSink, 0, 4)
	for i := 0; i < 4; i++ {
		sink := registerCompactFrameSink(t, h.service, fmt.Sprintf("compact-peer-%d", i))
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

type compactFrameSink struct {
	peer   *peer
	frames chan sendCmpctPayload
	errs   chan error
}

func registerCompactFrameSink(t *testing.T, svc *Service, addr string) compactFrameSink {
	t.Helper()
	local, remote := net.Pipe()
	p := testPeerForService(svc, addr, 0)
	p.state.Addr = addr
	p.conn = local
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

func assertSendCmpctPayload(t *testing.T, payload []byte, wantMode uint8) {
	t.Helper()
	got, err := decodeSendCmpctPayload(payload)
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

package p2p

import (
	"context"
	"encoding/binary"
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
	if err := p.handleMessage(message{Command: messageSendCmpct, Payload: sendCmpctRuntimePayload(t, 3, compactRelayVersion+1)}); err != nil {
		t.Fatalf("future version with future mode should downgrade without disconnect: %v", err)
	}
	if got := p.remoteCompactMode(); got.Mode != 0 || got.Version != compactRelayVersion+1 {
		t.Fatalf("future version/future mode=%+v, want downgraded", got)
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
		peerOK   bool
		want     string
		wantMode uint8
	}{
		{"eligible peer advertises full-block mode", 2, 1, true, messageSendCmpct, 0},
		{"unknown capability keeps full block", 2, 1, false, messageGetAddr, 0},
		{"ibd keeps full block", 0, 2, true, messageGetBlk, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHarness(t, tc.blocks, "127.0.0.1:0", nil)
			h.service.ctx = context.Background()
			h.service.cfg.CompactRelayMode = tc.mode
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

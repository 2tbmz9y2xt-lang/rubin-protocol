package p2p

import (
	"encoding/binary"
	"testing"
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

func sendCmpctRuntimePayload(t *testing.T, mode uint8, version uint64) []byte {
	t.Helper()
	payload := make([]byte, sendCmpctPayloadBytes)
	payload[0] = mode
	binary.LittleEndian.PutUint64(payload[1:], version)
	return payload
}

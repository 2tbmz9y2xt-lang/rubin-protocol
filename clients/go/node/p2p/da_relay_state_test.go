package p2p

import "testing"

func TestDefaultDARelayCapsMatchSpec(t *testing.T) {
	caps := defaultDARelayCaps()

	tests := []struct {
		name string
		got  uint64
		want uint64
	}{
		{name: "orphan pool", got: caps.orphanPoolBytes, want: 64 << 20},
		{name: "per peer orphan pool", got: caps.orphanPoolPerPeerBytes, want: 4 << 20},
		{name: "per da id orphan pool", got: caps.orphanPoolPerDAIDBytes, want: 8 << 20},
		{name: "commit overhead", got: caps.orphanCommitOverheadBytes, want: 8 << 20},
		{name: "ttl blocks", got: caps.orphanTTLBlocks, want: 3},
		{name: "pinned payload", got: caps.pinnedPayloadBytes, want: 96_000_000},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Fatalf("%s cap = %d, want %d", tt.name, tt.got, tt.want)
		}
	}

	if err := caps.validate(); err != nil {
		t.Fatalf("default caps should validate: %v", err)
	}
}

func TestDARelayStatesAreDistinct(t *testing.T) {
	states := map[daRelaySetState]bool{
		daRelayStateOrphanChunks: true,
		daRelayStateStagedCommit: true,
		daRelayStateCompleteSet:  true,
	}

	if len(states) != 3 {
		t.Fatalf("DA relay states are not distinct: got %d unique states", len(states))
	}
}

func TestNewDARelayStateInitializesContainerOnly(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}
	if state == nil {
		t.Fatal("new DA relay state returned nil")
	}
	if len(state.sets) != 0 {
		t.Fatalf("new DA relay state should not contain live entries, got %d", len(state.sets))
	}
	if state.nextReceivedTime != 0 {
		t.Fatalf("new DA relay state sequence = %d, want 0", state.nextReceivedTime)
	}
	if state.caps != defaultDARelayCaps() {
		t.Fatalf("new DA relay state caps = %+v, want %+v", state.caps, defaultDARelayCaps())
	}
}

func TestNewDARelayStateInitializesEmptyAccounting(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	if state.orphanBytes != 0 {
		t.Fatalf("orphan bytes = %d, want 0", state.orphanBytes)
	}
	if len(state.orphanBytesByPeerQuotaKey) != 0 {
		t.Fatalf("orphan bytes by peer quota key = %d entries, want 0", len(state.orphanBytesByPeerQuotaKey))
	}
	if len(state.orphanBytesByDAID) != 0 {
		t.Fatalf("orphan bytes by da_id = %d entries, want 0", len(state.orphanBytesByDAID))
	}
	if state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("orphan commit overhead bytes = %d, want 0", state.orphanCommitOverheadBytes)
	}
	if state.pinnedPayloadBytes != 0 {
		t.Fatalf("pinned payload bytes = %d, want 0", state.pinnedPayloadBytes)
	}
}

func TestNewDARelayStateInitializesWritableAccountingMaps(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	var daID [32]byte
	daID[0] = 1
	state.setOrphanBytesForPeer("peer", 1)
	state.orphanBytesByDAID[daID] = 2

	if state.orphanBytesForPeer("peer") != 1 {
		t.Fatalf("orphan peer accounting map is not writable")
	}
	if state.orphanBytesByDAID[daID] != 2 {
		t.Fatalf("orphan da_id accounting map is not writable")
	}
}

func TestDARelayPeerAccountingUsesQuotaKey(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	state.setOrphanBytesForPeer("127.0.0.1:1000", 1)
	state.setOrphanBytesForPeer("127.0.0.1:2000", 2)

	if len(state.orphanBytesByPeerQuotaKey) != 1 {
		t.Fatalf("peer accounting entries = %d, want 1", len(state.orphanBytesByPeerQuotaKey))
	}
	if got := state.orphanBytesForPeer("127.0.0.1:3000"); got != 2 {
		t.Fatalf("peer accounting bytes = %d, want 2", got)
	}
}

func TestDARelayReceivedTimeIsMonotonicLocalSequence(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	first := state.nextMonotonicReceivedTime()
	second := state.nextMonotonicReceivedTime()
	third := state.nextMonotonicReceivedTime()

	if first != 1 || second != 2 || third != 3 {
		t.Fatalf("received_time sequence = %d, %d, %d; want 1, 2, 3", first, second, third)
	}
}

func TestDARelayCapsRejectInvalidLimits(t *testing.T) {
	tests := []struct {
		name string
		caps daRelayCaps
	}{
		{
			name: "zero orphan pool",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanPoolBytes = 0
				return caps
			}(),
		},
		{
			name: "zero per peer orphan pool",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanPoolPerPeerBytes = 0
				return caps
			}(),
		},
		{
			name: "per peer exceeds global",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanPoolPerPeerBytes = caps.orphanPoolBytes + 1
				return caps
			}(),
		},
		{
			name: "per da id exceeds global",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanPoolPerDAIDBytes = caps.orphanPoolBytes + 1
				return caps
			}(),
		},
		{
			name: "commit overhead exceeds global",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanCommitOverheadBytes = caps.orphanPoolBytes + 1
				return caps
			}(),
		},
		{
			name: "zero ttl",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanTTLBlocks = 0
				return caps
			}(),
		},
		{
			name: "zero pinned payload",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.pinnedPayloadBytes = 0
				return caps
			}(),
		},
	}

	for _, tt := range tests {
		if err := tt.caps.validate(); err == nil {
			t.Fatalf("%s caps should fail validation", tt.name)
		}
	}
}

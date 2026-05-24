package p2p

import (
	"crypto/sha3"
	"errors"
	"testing"
)

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
	state.setOrphanBytesForDAID(daID, 2)

	if state.orphanBytesForPeer("peer") != 1 {
		t.Fatalf("orphan peer accounting map is not writable")
	}
	if state.orphanBytesForDAID(daID) != 2 {
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
	state.setOrphanBytesForPeer("127.0.0.1:4000", 0)
	if len(state.orphanBytesByPeerQuotaKey) != 0 {
		t.Fatalf("peer accounting entries after zero update = %d, want 0", len(state.orphanBytesByPeerQuotaKey))
	}
}

func TestDARelayDAIDAccountingDeletesZeroBytes(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	var daID [32]byte
	daID[0] = 1
	state.setOrphanBytesForDAID(daID, 2)
	state.setOrphanBytesForDAID(daID, 0)

	if len(state.orphanBytesByDAID) != 0 {
		t.Fatalf("da_id accounting entries after zero update = %d, want 0", len(state.orphanBytesByDAID))
	}
	if got := state.orphanBytesForDAID(daID); got != 0 {
		t.Fatalf("da_id accounting bytes = %d, want 0", got)
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

func TestDARelayTransitionsRetainOrphansAndComplete(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	daID := daRelayTestID(1)
	chunk0 := daRelayTestChunk(daID, 0, []byte("chunk-0"), 7)
	chunk1 := daRelayTestChunk(daID, 1, []byte("chunk-1"), 13)
	staleChunk := daRelayTestChunk(daID, 2, []byte("stale"), 29)
	commit := daRelayTestCommit(daID, 2, daRelayPayloadCommitment(chunk0.payload, chunk1.payload), 19)

	record, err := state.addDAChunk("127.0.0.1:1000", chunk0)
	if err != nil {
		t.Fatalf("add orphan chunk: %v", err)
	}
	if record.state != daRelayStateOrphanChunks || record.payloadBytes != uint64(len(chunk0.payload)) {
		t.Fatalf("orphan record=%+v, want ORPHAN_CHUNKS with first payload", record)
	}
	if state.pinnedPayloadBytes != 0 {
		t.Fatalf("orphan chunk pinned bytes = %d, want 0", state.pinnedPayloadBytes)
	}
	if _, err := state.addDAChunk("127.0.0.1:1000", staleChunk); err != nil {
		t.Fatalf("add stale orphan chunk: %v", err)
	}

	record, err = state.addDACommit("127.0.0.1:2000", commit)
	if err != nil {
		t.Fatalf("add commit: %v", err)
	}
	if record.state != daRelayStateStagedCommit {
		t.Fatalf("state=%v, want STAGED_COMMIT", record.state)
	}
	if record.ttlBlocksRemaining != daOrphanTTLBlocks {
		t.Fatalf("ttl=%d, want %d", record.ttlBlocksRemaining, daOrphanTTLBlocks)
	}
	if missing := record.missingChunkIndexes(); len(missing) != 1 || missing[0] != 1 {
		t.Fatalf("missing=%v, want [1]", missing)
	}
	if _, ok := record.chunks[2]; ok || record.payloadBytes != uint64(len(chunk0.payload)) {
		t.Fatalf("stale orphan retained in staged record=%+v", record)
	}
	if _, err := state.addDACommit("127.0.0.1:2000", commit); !errors.Is(err, errDARelayDuplicateCommit) {
		t.Fatalf("duplicate commit err=%v, want %v", err, errDARelayDuplicateCommit)
	}
	if state.pinnedPayloadBytes != 0 {
		t.Fatalf("staged commit pinned bytes = %d, want 0", state.pinnedPayloadBytes)
	}

	record, err = state.addDAChunk("127.0.0.1:3000", chunk1)
	if err != nil {
		t.Fatalf("add completing chunk: %v", err)
	}
	if record.state != daRelayStateCompleteSet {
		t.Fatalf("record=%+v, want COMPLETE_SET mineable", record)
	}
	wantPayloadBytes := uint64(len(chunk0.payload) + len(chunk1.payload))
	if record.payloadBytes != wantPayloadBytes || state.pinnedPayloadBytes != wantPayloadBytes {
		t.Fatalf("payload accounting record=%d pinned=%d, want %d", record.payloadBytes, state.pinnedPayloadBytes, wantPayloadBytes)
	}
	if state.orphanBytes != 0 || len(state.orphanBytesByDAID) != 0 || len(state.orphanBytesByPeerQuotaKey) != 0 {
		t.Fatalf("orphan accounting after complete: global=%d da=%d peer=%d, want all zero", state.orphanBytes, len(state.orphanBytesByDAID), len(state.orphanBytesByPeerQuotaKey))
	}
	beforePinned := state.pinnedPayloadBytes
	if _, err := state.addDAChunk("127.0.0.1:3000", chunk1); !errors.Is(err, errDARelayDuplicateChunk) || state.pinnedPayloadBytes != beforePinned {
		t.Fatalf("duplicate chunk err=%v pinned=%d before=%d", err, state.pinnedPayloadBytes, beforePinned)
	}
}

func TestDARelayRejectsIntegrityFailuresBeforeComplete(t *testing.T) {
	state, err := newDARelayState(defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	daID := daRelayTestID(3)
	badHash := daRelayTestChunk(daID, 0, []byte("bad-hash"), 5)
	badHash.chunkHash[0] ^= 0x01
	if _, err := state.addDAChunk("peer-a", badHash); !errors.Is(err, errDARelayChunkHashMismatch) {
		t.Fatalf("bad chunk hash err=%v, want %v", err, errDARelayChunkHashMismatch)
	}
	if _, ok := state.sets[daID]; ok {
		t.Fatalf("bad chunk hash created da set")
	}

	chunk := daRelayTestChunk(daID, 0, []byte("payload"), 5)
	commit := daRelayTestCommit(daID, 1, daRelayPayloadCommitment([]byte("different")), 11)
	if _, err := state.addDACommit("peer-a", commit); err != nil {
		t.Fatalf("add commit: %v", err)
	}
	if _, err := state.addDAChunk("peer-a", chunk); !errors.Is(err, errDARelayPayloadCommitmentMismatch) {
		t.Fatalf("payload commitment err=%v, want %v", err, errDARelayPayloadCommitmentMismatch)
	}
	record, ok := state.sets[daID]
	if !ok || record.state != daRelayStateStagedCommit || state.pinnedPayloadBytes != 0 {
		t.Fatalf("after bad commitment record=%+v ok=%v pinned=%d, want staged and unpinned", record, ok, state.pinnedPayloadBytes)
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
			name: "zero per da id orphan pool",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanPoolPerDAIDBytes = 0
				return caps
			}(),
		},
		{
			name: "zero commit overhead",
			caps: func() daRelayCaps {
				caps := defaultDARelayCaps()
				caps.orphanCommitOverheadBytes = 0
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

func daRelayTestID(seed byte) (out [32]byte) {
	for i := range out {
		out[i] = seed
	}
	return out
}

func daRelayTestChunk(daID [32]byte, index uint16, payload []byte, wireBytes uint64) daRelayChunk {
	return daRelayChunk{
		daID:       daID,
		chunkIndex: index,
		chunkHash:  sha3.Sum256(payload),
		payload:    append([]byte(nil), payload...),
		wireBytes:  wireBytes,
	}
}

func daRelayTestCommit(daID [32]byte, chunkCount uint16, payloadCommitment [32]byte, wireBytes uint64) daRelayCommit {
	return daRelayCommit{
		daID:              daID,
		chunkCount:        chunkCount,
		payloadCommitment: payloadCommitment,
		wireBytes:         wireBytes,
	}
}

func daRelayPayloadCommitment(payloads ...[]byte) [32]byte {
	hasher := sha3.New256()
	for _, payload := range payloads {
		_, _ = hasher.Write(payload)
	}
	var out [32]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

package p2p

import (
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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
	}

	if len(states) != 2 {
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

func TestDARelayPeerQuotaKeyPreventsPortHopping(t *testing.T) {
	t.Run("chunk only", func(t *testing.T) {
		caps := defaultDARelayCaps()
		caps.orphanPoolPerPeerBytes = 10
		state := newDARelayStateForTest(t, caps)
		firstID := daRelayTestID(41)
		secondID := daRelayTestID(42)

		record := mustAddDAChunk(t, state, "127.0.0.1:1000", daRelayTestChunk(firstID, 0, 6))
		_, err := state.addDAChunk("127.0.0.1:2000", daRelayTestChunk(secondID, 0, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		requirePortHopRejectedWithoutMutation(t, state, secondID, record.wireBytes)
	})

	t.Run("staged commit", func(t *testing.T) {
		caps := defaultDARelayCaps()
		caps.orphanPoolPerPeerBytes = 10
		state := newDARelayStateForTest(t, caps)
		firstID := daRelayTestID(43)
		secondID := daRelayTestID(44)

		record := mustAddDACommit(t, state, "127.0.0.1:1000", daRelayTestCommit(firstID, 2, 6))
		_, err := state.addDACommit("127.0.0.1:2000", daRelayTestCommit(secondID, 2, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		requirePortHopRejectedWithoutMutation(t, state, secondID, record.wireBytes)
		if state.orphanCommitOverheadBytes != record.commit.wireBytes {
			t.Fatalf("commit overhead = %d, want %d", state.orphanCommitOverheadBytes, record.commit.wireBytes)
		}
	})
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

func TestDARelayStagesCommitAndRetainsBoundedOrphans(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(1)

	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 7))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunk(daID, 2, 11))

	record := mustAddDACommit(t, state, "peer-c", daRelayTestCommit(daID, 2, 13))
	if record.state != daRelayStateStagedCommit {
		t.Fatalf("state=%v, want STAGED_COMMIT", record.state)
	}
	if record.ttlBlocksRemaining != daOrphanTTLBlocks {
		t.Fatalf("ttl=%d, want %d", record.ttlBlocksRemaining, daOrphanTTLBlocks)
	}
	if missing := record.missingChunkIndexes(); len(missing) != 1 || missing[0] != 1 {
		t.Fatalf("missing=%v, want [1]", missing)
	}
	if _, ok := record.chunks[2]; ok {
		t.Fatalf("orphan chunk outside commit count was retained")
	}
	if state.orphanBytes != record.wireBytes || state.orphanBytesByDAID[daID] != record.wireBytes {
		t.Fatalf("orphan accounting global=%d da=%d record=%d", state.orphanBytes, state.orphanBytesByDAID[daID], record.wireBytes)
	}
	record.chunks[7] = daRelayTestChunk(daID, 7, 1)
	if _, ok := state.sets[daID].chunks[7]; ok {
		t.Fatalf("returned record aliases stored chunks")
	}
}

func TestDARelayRejectsStagedIndexAndCapFailuresBeforeMutation(t *testing.T) {
	daID := daRelayTestID(2)
	for _, tt := range []struct {
		patch func(*daRelayCaps)
		want  error
	}{
		{
			patch: func(caps *daRelayCaps) {
				caps.orphanPoolBytes, caps.orphanPoolPerPeerBytes = 4, 4
				caps.orphanPoolPerDAIDBytes, caps.orphanCommitOverheadBytes = 4, 4
			},
			want: errDARelayOrphanPoolCapExceeded,
		},
		{
			patch: func(caps *daRelayCaps) { caps.orphanPoolPerPeerBytes = 4 },
			want:  errDARelayOrphanPeerCapExceeded,
		},
		{
			patch: func(caps *daRelayCaps) { caps.orphanPoolPerDAIDBytes = 4 },
			want:  errDARelayOrphanDAIDCapExceeded,
		},
	} {
		caps := defaultDARelayCaps()
		tt.patch(&caps)
		state := newDARelayStateForTest(t, caps)
		_, err := state.addDAChunk("peer-a", daRelayTestChunk(daID, 0, 5))
		requireDAErr(t, err, tt.want)
		if len(state.sets) != 0 || state.orphanBytes != 0 {
			t.Fatalf("rejection mutated state: sets=%d orphan=%d", len(state.sets), state.orphanBytes)
		}
	}

	state := newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDACommit(t, state, "peer-a", daRelayTestCommit(daID, 1, 1))
	_, err := state.addDAChunk("peer-a", daRelayTestChunk(daID, 1, 1))
	requireDAErr(t, err, errDARelayChunkIndexOutsideCommit)
	_, err = state.addDACommit("peer-a", daRelayTestCommit(daID, 0, 1))
	requireDAErr(t, err, errDARelayChunkCountInvalid)
	_, err = state.addDAChunk("peer-a", daRelayTestChunk(daID, uint16(consensus.MAX_DA_CHUNK_COUNT), 1))
	requireDAErr(t, err, errDARelayChunkIndexOutOfRange)

	caps := defaultDARelayCaps()
	caps.orphanPoolBytes, caps.orphanPoolPerPeerBytes = ^uint64(0), ^uint64(0)
	caps.orphanPoolPerDAIDBytes = ^uint64(0)
	overflowState := newDARelayStateForTest(t, caps)
	mustAddDAChunk(t, overflowState, "peer-a", daRelayTestChunk(daID, 0, ^uint64(0)))
	_, err = overflowState.addDACommit("peer-a", daRelayTestCommit(daID, 2, 1))
	requireDAErr(t, err, errDARelayArithmeticOverflow)
}

func TestDARelayRejectsZeroWireBytesBeforeMutation(t *testing.T) {
	daID := daRelayTestID(3)
	state := newDARelayStateForTest(t, defaultDARelayCaps())

	_, err := state.addDACommit("peer-a", daRelayTestCommit(daID, 1, 0))
	requireDAErr(t, err, errDARelayWireBytesInvalid)
	_, err = state.addDAChunk("peer-a", daRelayTestChunk(daID, 0, 0))
	requireDAErr(t, err, errDARelayWireBytesInvalid)

	if len(state.sets) != 0 || state.orphanBytes != 0 || state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("zero wire rejection mutated state: sets=%d orphan=%d commit=%d", len(state.sets), state.orphanBytes, state.orphanCommitOverheadBytes)
	}
}

func TestDARelayRejectsDuplicatesBeforeMutation(t *testing.T) {
	daID := daRelayTestID(4)
	state := newDARelayStateForTest(t, defaultDARelayCaps())

	record := mustAddDACommit(t, state, "peer-a", daRelayTestCommit(daID, 2, 3))
	_, err := state.addDACommit("peer-b", daRelayTestCommit(daID, 2, 5))
	requireDAErr(t, err, errDARelayDuplicateCommit)
	if state.sets[daID].commit.wireBytes != record.commit.wireBytes || state.orphanBytes != record.wireBytes {
		t.Fatalf("duplicate commit mutated state: commit=%d orphan=%d want commit=%d orphan=%d", state.sets[daID].commit.wireBytes, state.orphanBytes, record.commit.wireBytes, record.wireBytes)
	}

	chunk := daRelayTestChunk(daID, 0, 7)
	record = mustAddDAChunk(t, state, "peer-c", chunk)
	_, err = state.addDAChunk("peer-d", chunk)
	requireDAErr(t, err, errDARelayDuplicateChunk)
	if len(state.sets[daID].chunks) != 1 || state.orphanBytes != record.wireBytes {
		t.Fatalf("duplicate chunk mutated state: chunks=%d orphan=%d want orphan=%d", len(state.sets[daID].chunks), state.orphanBytes, record.wireBytes)
	}
}

func TestDARelayRejectedCandidatesDoNotMutateStoredChunks(t *testing.T) {
	daID := daRelayTestID(5)
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 1))
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 2, 1))
	state.caps.orphanCommitOverheadBytes = 1
	_, err := state.addDACommit("peer-b", daRelayTestCommit(daID, 1, 2))
	requireDAErr(t, err, errDARelayOrphanCommitCapExceeded)
	if _, ok := state.sets[daID].chunks[2]; !ok {
		t.Fatalf("failed commit pruned stored orphan chunk")
	}
	if state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("commit overhead after rejected commit = %d, want 0", state.orphanCommitOverheadBytes)
	}

	state = newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDACommit(t, state, "peer-a", daRelayTestCommit(daID, 2, 1))
	state.caps.orphanPoolPerDAIDBytes = state.orphanBytes
	_, err = state.addDAChunk("peer-b", daRelayTestChunk(daID, 1, 1))
	requireDAErr(t, err, errDARelayOrphanDAIDCapExceeded)
	if _, ok := state.sets[daID].chunks[1]; ok {
		t.Fatalf("failed chunk insert mutated stored staged record")
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
	out[0] = seed
	return out
}

func daRelayTestChunk(daID [32]byte, index uint16, wireBytes uint64) daRelayChunk {
	return daRelayChunk{daID: daID, chunkIndex: index, wireBytes: wireBytes}
}

func daRelayTestCommit(daID [32]byte, chunkCount uint16, wireBytes uint64) daRelayCommit {
	return daRelayCommit{daID: daID, chunkCount: chunkCount, wireBytes: wireBytes}
}

func newDARelayStateForTest(t *testing.T, caps daRelayCaps) *daRelayState {
	t.Helper()
	state, err := newDARelayState(caps)
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}
	return state
}

func mustAddDAChunk(t *testing.T, state *daRelayState, peer string, chunk daRelayChunk) daRelaySetRecord {
	t.Helper()
	record, err := state.addDAChunk(peer, chunk)
	if err != nil {
		t.Fatalf("add DA chunk: %v", err)
	}
	return record
}

func mustAddDACommit(t *testing.T, state *daRelayState, peer string, commit daRelayCommit) daRelaySetRecord {
	t.Helper()
	record, err := state.addDACommit(peer, commit)
	if err != nil {
		t.Fatalf("add DA commit: %v", err)
	}
	return record
}

func requireDAErr(t *testing.T, got error, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("err=%v, want %v", got, want)
	}
}

func requirePortHopRejectedWithoutMutation(t *testing.T, state *daRelayState, rejectedID [32]byte, wantPeerBytes uint64) {
	t.Helper()
	if got := state.orphanBytesForPeer("127.0.0.1:3000"); got != wantPeerBytes {
		t.Fatalf("peer quota bytes = %d, want %d", got, wantPeerBytes)
	}
	if got := state.orphanBytes; got != wantPeerBytes {
		t.Fatalf("global orphan bytes = %d, want %d", got, wantPeerBytes)
	}
	if _, ok := state.sets[rejectedID]; ok {
		t.Fatalf("rejected port-hop candidate mutated state")
	}
	if got := state.orphanBytesForDAID(rejectedID); got != 0 {
		t.Fatalf("rejected da_id accounting = %d, want 0", got)
	}
}

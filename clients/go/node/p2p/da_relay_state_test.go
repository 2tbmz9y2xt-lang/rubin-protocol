package p2p

import (
	"crypto/sha3"
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
	chunk.chunkHash[0] ^= 0xff
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
	chunk := daRelayTestChunk(daID, 1, 1)
	_, err = state.addDAChunk("peer-b", chunk)
	requireDAErr(t, err, errDARelayOrphanDAIDCapExceeded)
	if _, ok := state.sets[daID].chunks[1]; ok {
		t.Fatalf("failed chunk insert mutated stored staged record")
	}
	chunk.chunkIndex = 2
	chunk.chunkHash[0] ^= 0xff
	_, err = state.addDAChunk("peer-b", chunk)
	requireDAErr(t, err, errDARelayChunkIndexOutsideCommit)
}

func TestDARelayCompletesSetAndPinsPayload(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(5)
	payload0 := []byte("chunk-zero")
	payload1 := []byte("chunk-one")

	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 3, payload0, payload1))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	record := mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))

	if record.state != daRelayStateCompleteSet {
		t.Fatalf("state=%v, want COMPLETE_SET", record.state)
	}
	if record.payloadBytes != uint64(len(payload0)+len(payload1)) || state.pinnedPayloadBytes != record.payloadBytes {
		t.Fatalf("payload bytes record=%d pinned=%d", record.payloadBytes, state.pinnedPayloadBytes)
	}
	if state.orphanBytes != 0 || len(state.orphanBytesByDAID) != 0 {
		t.Fatalf("complete set left orphan accounting: global=%d da=%d", state.orphanBytes, len(state.orphanBytesByDAID))
	}
	record.chunks[0].payload[0] ^= 0xff
	if state.sets[daID].chunks[0].payload[0] == record.chunks[0].payload[0] {
		t.Fatalf("returned complete record aliases stored payload")
	}
}

func TestDARelayCloneModesKeepStateCopiesShallowAndCallerCopiesDeep(t *testing.T) {
	daID := daRelayTestID(6)
	record := daRelaySetRecord{
		daID: daID,
		chunks: map[uint16]daRelayChunk{
			0: daRelayTestChunkPayload(daID, 0, 17, []byte("immutable-payload")),
		},
	}

	stateClone := record.cloneForStateMutation()
	originalChunk := record.chunks[0]
	stateChunk := stateClone.chunks[0]
	if &stateChunk.payload[0] != &originalChunk.payload[0] {
		t.Fatalf("state mutation clone deep-copied payload")
	}
	stateClone.chunks[1] = daRelayTestChunkPayload(daID, 1, 1, []byte("second"))
	if _, ok := record.chunks[1]; ok {
		t.Fatalf("state mutation clone aliases chunk map")
	}

	callerClone := record.clone()
	callerChunk := callerClone.chunks[0]
	if &callerChunk.payload[0] == &originalChunk.payload[0] {
		t.Fatalf("caller clone reused payload")
	}
	callerChunk.payload[0] ^= 0xff
	callerClone.chunks[0] = callerChunk
	if record.chunks[0].payload[0] == callerClone.chunks[0].payload[0] {
		t.Fatalf("caller clone aliases stored payload")
	}
}

func TestDARelayRejectsIntegrityAndPinnedCapBeforeMutation(t *testing.T) {
	daID := daRelayTestID(6)
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	badChunk := daRelayTestChunkPayload(daID, 0, 3, []byte("bad"))
	badChunk.chunkHash[0] ^= 0xff
	_, err := state.addDAChunk("peer-a", badChunk)
	requireDAErr(t, err, errDARelayChunkHashMismatch)
	if len(state.sets) != 0 {
		t.Fatalf("hash mismatch mutated state")
	}
	_, err = state.addDAChunk("peer-a", daRelayTestChunkPayload(daID, 0, 1, nil))
	requireDAErr(t, err, errDARelayChunkPayloadSizeInvalid)
	_, err = state.addDAChunk("peer-a", daRelayTestChunkPayload(daID, 0, 1, make([]byte, consensus.CHUNK_BYTES+1)))
	requireDAErr(t, err, errDARelayChunkPayloadSizeInvalid)
	_, err = state.addDAChunk("peer-a", daRelayTestChunkPayload(daID, 0, 1, []byte("underreported")))
	requireDAErr(t, err, errDARelayWireBytesInvalid)
	_, err = state.addDACommit("peer-a", daRelayTestCommit(daID, 1, 0))
	requireDAErr(t, err, errDARelayWireBytesInvalid)
	if len(state.sets) != 0 {
		t.Fatalf("shape rejection mutated state")
	}

	payload0 := []byte("payload-a")
	payload1 := []byte("payload-b")
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
	record := mustAddDACommit(t, state, "peer-b", daRelayTestCommitForPayloads(daID, 1, payload1, payload0))
	if record.state != daRelayStateStagedCommit || len(record.chunks) != 0 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("commitment mismatch state=%v chunks=%d pinned=%d", record.state, len(record.chunks), state.pinnedPayloadBytes)
	}

	state = newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	_, err = state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), []byte("payload-x")))
	requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
	if len(state.sets[daID].chunks) != 1 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("chunk mismatch mutated state: chunks=%d pinned=%d", len(state.sets[daID].chunks), state.pinnedPayloadBytes)
	}

	caps := defaultDARelayCaps()
	caps.pinnedPayloadBytes = 1
	state = newDARelayStateForTest(t, caps)
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0))
	_, err = state.addDAChunk("peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
	if state.sets[daID].state != daRelayStateStagedCommit || len(state.sets[daID].chunks) != 0 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("pinned cap rejection mutated state: state=%v chunks=%d pinned=%d", state.sets[daID].state, len(state.sets[daID].chunks), state.pinnedPayloadBytes)
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
	return daRelayTestChunkPayload(daID, index, wireBytes, []byte{byte(index + 1)})
}

func daRelayTestCommit(daID [32]byte, chunkCount uint16, wireBytes uint64) daRelayCommit {
	return daRelayCommit{daID: daID, chunkCount: chunkCount, wireBytes: wireBytes}
}

func daRelayTestChunkPayload(daID [32]byte, index uint16, wireBytes uint64, payload []byte) daRelayChunk {
	return daRelayChunk{daID: daID, chunkHash: sha3.Sum256(payload), chunkIndex: index, payload: cloneBytes(payload), wireBytes: wireBytes}
}

func daRelayTestCommitForPayloads(daID [32]byte, wireBytes uint64, payloads ...[]byte) daRelayCommit {
	return daRelayCommit{daID: daID, payloadCommitment: daRelayPayloadCommitment(payloads...), chunkCount: uint16(len(payloads)), wireBytes: wireBytes}
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

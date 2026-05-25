package p2p

import (
	"crypto/sha3"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestDARelayEmptyPeerQuotaKeyIsCapped(t *testing.T) {
	t.Run("chunk only", func(t *testing.T) {
		caps := defaultDARelayCaps()
		caps.orphanPoolPerPeerBytes = 10
		state := newDARelayStateForTest(t, caps)
		firstID := daRelayTestID(45)
		secondID := daRelayTestID(46)

		record := mustAddDAChunk(t, state, "", daRelayTestChunk(firstID, 0, 6))
		_, err := state.addDAChunk("", daRelayTestChunk(secondID, 0, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		if got := state.orphanBytesForPeer(""); got != record.wireBytes {
			t.Fatalf("empty peer quota bytes = %d, want %d", got, record.wireBytes)
		}
		if _, ok := state.sets[secondID]; ok {
			t.Fatalf("empty-peer cap rejection mutated state")
		}
	})

	t.Run("staged commit", func(t *testing.T) {
		caps := defaultDARelayCaps()
		caps.orphanPoolPerPeerBytes = 10
		state := newDARelayStateForTest(t, caps)
		firstID := daRelayTestID(47)
		secondID := daRelayTestID(48)

		record := mustAddDACommit(t, state, "", daRelayTestCommit(firstID, 2, 6))
		_, err := state.addDACommit("", daRelayTestCommit(secondID, 2, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		if got := state.orphanBytesForPeer(""); got != record.wireBytes {
			t.Fatalf("empty peer quota bytes = %d, want %d", got, record.wireBytes)
		}
		if _, ok := state.sets[secondID]; ok {
			t.Fatalf("empty-peer commit cap rejection mutated state")
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

	first, err := state.nextMonotonicReceivedTime()
	if err != nil {
		t.Fatalf("next received time: %v", err)
	}
	second, err := state.nextMonotonicReceivedTime()
	if err != nil {
		t.Fatalf("next received time: %v", err)
	}
	third, err := state.nextMonotonicReceivedTime()
	if err != nil {
		t.Fatalf("next received time: %v", err)
	}

	if first != 1 || second != 2 || third != 3 {
		t.Fatalf("received_time sequence = %d, %d, %d; want 1, 2, 3", first, second, third)
	}
}

func TestDARelayReceivedTimeMonotonicAcrossMutationPaths(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())

	first, err := state.nextMonotonicReceivedTime()
	if err != nil {
		t.Fatalf("next received time: %v", err)
	}
	chunkRecord := mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daRelayTestID(51), 0, 1))
	second, err := state.nextMonotonicReceivedTime()
	if err != nil {
		t.Fatalf("next received time: %v", err)
	}
	commitRecord := mustAddDACommit(t, state, "peer-b", daRelayTestCommit(daRelayTestID(52), 2, 1))

	if !(first < chunkRecord.receivedTime && chunkRecord.receivedTime < second && second < commitRecord.receivedTime) {
		t.Fatalf("received_time order first=%d chunk=%d second=%d commit=%d", first, chunkRecord.receivedTime, second, commitRecord.receivedTime)
	}
	if state.nextReceivedTime != commitRecord.receivedTime {
		t.Fatalf("state received_time=%d, want %d", state.nextReceivedTime, commitRecord.receivedTime)
	}
}

func TestDARelayReceivedTimeStaysFirstSeenForExistingRecord(t *testing.T) {
	t.Run("chunk then commit", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(84)

		firstRecord := mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 1))
		otherRecord := mustAddDAChunk(t, state, "peer-b", daRelayTestChunk(daRelayTestID(85), 0, 1))
		updatedRecord := mustAddDACommit(t, state, "peer-c", daRelayTestCommit(daID, 2, 1))

		if updatedRecord.receivedTime != firstRecord.receivedTime {
			t.Fatalf("updated received_time=%d, want first-seen %d", updatedRecord.receivedTime, firstRecord.receivedTime)
		}
		if state.nextReceivedTime != otherRecord.receivedTime {
			t.Fatalf("state received_time=%d, want latest new-record time %d", state.nextReceivedTime, otherRecord.receivedTime)
		}
		nextRecord := mustAddDAChunk(t, state, "peer-d", daRelayTestChunk(daRelayTestID(86), 0, 1))
		if nextRecord.receivedTime != otherRecord.receivedTime+1 {
			t.Fatalf("next received_time=%d, want %d", nextRecord.receivedTime, otherRecord.receivedTime+1)
		}
	})

	t.Run("commit then chunk", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(87)

		firstRecord := mustAddDACommit(t, state, "peer-a", daRelayTestCommit(daID, 2, 1))
		otherRecord := mustAddDAChunk(t, state, "peer-b", daRelayTestChunk(daRelayTestID(88), 0, 1))
		updatedRecord := mustAddDAChunk(t, state, "peer-c", daRelayTestChunk(daID, 0, 1))

		if updatedRecord.receivedTime != firstRecord.receivedTime {
			t.Fatalf("updated received_time=%d, want first-seen %d", updatedRecord.receivedTime, firstRecord.receivedTime)
		}
		if state.nextReceivedTime != otherRecord.receivedTime {
			t.Fatalf("state received_time=%d, want latest new-record time %d", state.nextReceivedTime, otherRecord.receivedTime)
		}
		nextRecord := mustAddDACommit(t, state, "peer-d", daRelayTestCommit(daRelayTestID(89), 2, 1))
		if nextRecord.receivedTime != otherRecord.receivedTime+1 {
			t.Fatalf("next received_time=%d, want %d", nextRecord.receivedTime, otherRecord.receivedTime+1)
		}
	})
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

func TestDARelayMissingChunkIndexesReturnsNilWhenComplete(t *testing.T) {
	daID := daRelayTestID(53)
	record := daRelaySetRecord{
		commit: daRelayTestCommit(daID, 2, 1),
		chunks: map[uint16]daRelayChunk{
			0: daRelayTestChunk(daID, 0, 1),
			1: daRelayTestChunk(daID, 1, 1),
		},
	}

	if missing := record.missingChunkIndexes(); missing != nil {
		t.Fatalf("missing chunk indexes = %v, want nil", missing)
	}
	record.state = daRelayStateCompleteSet
	record.chunks = map[uint16]daRelayChunk{}
	if missing := record.missingChunkIndexes(); missing != nil {
		t.Fatalf("complete-set missing chunk indexes = %v, want nil", missing)
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
	_, err = state.addDACommit("peer-a", daRelayTestCommit(daID, uint16(consensus.MAX_DA_CHUNK_COUNT+1), 1))
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

	chunkOnlyOverflowState := newDARelayStateForTest(t, caps)
	mustAddDAChunk(t, chunkOnlyOverflowState, "peer-a", daRelayTestChunk(daID, 0, ^uint64(0)))
	_, err = chunkOnlyOverflowState.addDAChunk("peer-a", daRelayTestChunk(daID, 1, 1))
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if len(chunkOnlyOverflowState.sets[daID].chunks) != 1 {
		t.Fatalf("chunk overflow mutated chunk set: got %d chunks", len(chunkOnlyOverflowState.sets[daID].chunks))
	}
}

func TestDARelayZeroRecordAccountingDoesNotAllocatePeerBytes(t *testing.T) {
	accounting, err := (daRelaySetRecord{}).orphanAccounting()
	if err != nil {
		t.Fatalf("zero record accounting: %v", err)
	}
	if accounting.orphanBytes != 0 || accounting.commitBytes != 0 {
		t.Fatalf("zero accounting totals orphan=%d commit=%d, want 0", accounting.orphanBytes, accounting.commitBytes)
	}
	if accounting.peerBytes != nil {
		t.Fatalf("zero accounting peer map = %#v, want nil", accounting.peerBytes)
	}
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

func TestDARelayRejectsReceivedTimeOverflowBeforeMutation(t *testing.T) {
	chunkState := newDARelayStateForTest(t, defaultDARelayCaps())
	chunkState.nextReceivedTime = ^uint64(0)
	chunkID := daRelayTestID(49)
	_, err := chunkState.addDAChunk("peer-a", daRelayTestChunk(chunkID, 0, 1))
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if len(chunkState.sets) != 0 || chunkState.nextReceivedTime != ^uint64(0) {
		t.Fatalf("chunk time overflow mutated state: sets=%d time=%d", len(chunkState.sets), chunkState.nextReceivedTime)
	}

	commitState := newDARelayStateForTest(t, defaultDARelayCaps())
	commitState.nextReceivedTime = ^uint64(0)
	commitID := daRelayTestID(50)
	_, err = commitState.addDACommit("peer-a", daRelayTestCommit(commitID, 2, 1))
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if len(commitState.sets) != 0 || commitState.nextReceivedTime != ^uint64(0) {
		t.Fatalf("commit time overflow mutated state: sets=%d time=%d", len(commitState.sets), commitState.nextReceivedTime)
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
	if got := state.sets[daID].commit.peerQuotaKey; got != peerQuotaKey("peer-a") {
		t.Fatalf("duplicate commit peer=%q, want first peer", got)
	}
	if got := state.orphanBytesForPeer("peer-b"); got != 0 {
		t.Fatalf("duplicate commit credited duplicate peer bytes=%d", got)
	}
	if got := state.sets[daID].receivedTime; got != record.receivedTime {
		t.Fatalf("duplicate commit received_time=%d, want first-seen %d", got, record.receivedTime)
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

func TestDARelayDuplicateCommitAfterOrphanChunksKeepsFirstSeenState(t *testing.T) {
	daID := daRelayTestID(92)
	state := newDARelayStateForTest(t, defaultDARelayCaps())

	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 7))
	record := mustAddDACommit(t, state, "peer-b", daRelayTestCommit(daID, 2, 3))

	_, err := state.addDACommit("peer-c", daRelayTestCommit(daID, 2, 11))
	requireDAErr(t, err, errDARelayDuplicateCommit)
	stored := state.sets[daID]
	if stored.commit.wireBytes != record.commit.wireBytes || stored.commit.peerQuotaKey != peerQuotaKey("peer-b") {
		t.Fatalf("duplicate commit replaced first commit: wire=%d peer=%q", stored.commit.wireBytes, stored.commit.peerQuotaKey)
	}
	if stored.receivedTime != record.receivedTime || state.nextReceivedTime != record.receivedTime {
		t.Fatalf("duplicate commit time record=%d state=%d want %d", stored.receivedTime, state.nextReceivedTime, record.receivedTime)
	}
	if _, ok := stored.chunks[0]; !ok {
		t.Fatal("duplicate commit dropped first-seen orphan chunk")
	}
	if got := state.orphanBytesForPeer("peer-c"); got != 0 {
		t.Fatalf("duplicate commit credited duplicate peer bytes=%d", got)
	}
}

func TestDARelayAdvanceOrphanTTLExpiresOrphanChunksAtomically(t *testing.T) {
	caps := defaultDARelayCaps()
	caps.orphanTTLBlocks = 1
	state := newDARelayStateForTest(t, caps)
	daID := daRelayTestID(93)

	first := mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 7))
	second := mustAddDAChunk(t, state, "peer-b", daRelayTestChunk(daID, 1, 11))
	wantBytes := first.wireBytes + second.chunks[1].wireBytes
	if state.orphanBytes != wantBytes || state.orphanBytesForDAID(daID) != wantBytes {
		t.Fatalf("setup accounting global=%d da=%d want %d", state.orphanBytes, state.orphanBytesForDAID(daID), wantBytes)
	}

	expired, err := state.advanceOrphanTTL()
	if err != nil {
		t.Fatalf("advance ttl: %v", err)
	}
	if len(expired) != 1 || expired[0].daID != daID || expired[0].state != daRelayStateOrphanChunks || expired[0].commitPeerQuotaKey != "" {
		t.Fatalf("expired=%+v, want orphan da_id without commit attribution", expired)
	}
	if _, ok := state.sets[daID]; ok {
		t.Fatalf("expired orphan da_id record was retained")
	}
	if state.orphanBytes != 0 || state.orphanBytesForDAID(daID) != 0 || state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("expiry left accounting global=%d da=%d commit=%d", state.orphanBytes, state.orphanBytesForDAID(daID), state.orphanCommitOverheadBytes)
	}
	if got := state.orphanBytesForPeer("peer-a"); got != 0 {
		t.Fatalf("expiry left peer-a bytes=%d", got)
	}
	if got := state.orphanBytesForPeer("peer-b"); got != 0 {
		t.Fatalf("expiry left peer-b bytes=%d", got)
	}
	if expired, err = state.advanceOrphanTTL(); err != nil || len(expired) != 0 {
		t.Fatalf("second ttl advance expired=%+v err=%v, want no-op", expired, err)
	}
}

func TestDARelayAdvanceOrphanTTLExpiresStagedCommitAccounting(t *testing.T) {
	caps := defaultDARelayCaps()
	caps.orphanTTLBlocks = 1
	state := newDARelayStateForTest(t, caps)
	daID := daRelayTestID(94)

	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 7))
	record := mustAddDACommit(t, state, "peer-b", daRelayTestCommit(daID, 3, 13))
	if record.state != daRelayStateStagedCommit {
		t.Fatalf("setup state=%v, want staged commit", record.state)
	}
	record.ttlBlocksRemaining = 0
	state.sets[daID] = record
	if state.orphanCommitOverheadBytes != record.commit.wireBytes {
		t.Fatalf("setup commit overhead=%d, want %d", state.orphanCommitOverheadBytes, record.commit.wireBytes)
	}

	expired, err := state.advanceOrphanTTL()
	if err != nil {
		t.Fatalf("advance ttl: %v", err)
	}
	if len(expired) != 1 || expired[0].daID != daID || expired[0].state != daRelayStateStagedCommit || expired[0].commitPeerQuotaKey != peerQuotaKey("peer-b") {
		t.Fatalf("expired=%+v, want staged commit attribution to peer-b", expired)
	}
	if _, ok := state.sets[daID]; ok {
		t.Fatalf("expired staged commit da_id record was retained")
	}
	if state.orphanBytes != 0 || state.orphanBytesForDAID(daID) != 0 || state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("expiry left accounting global=%d da=%d commit=%d", state.orphanBytes, state.orphanBytesForDAID(daID), state.orphanCommitOverheadBytes)
	}
	if got := state.orphanBytesForPeer("peer-a"); got != 0 {
		t.Fatalf("expiry left chunk peer bytes=%d", got)
	}
	if got := state.orphanBytesForPeer("peer-b"); got != 0 {
		t.Fatalf("expiry left commit peer bytes=%d", got)
	}
}

func TestDARelayAdvanceOrphanTTLDecrementsAndPreservesCompleteSets(t *testing.T) {
	caps := defaultDARelayCaps()
	caps.orphanTTLBlocks = 2
	state := newDARelayStateForTest(t, caps)
	stagedID := daRelayTestID(95)
	completeID := daRelayTestID(96)
	payload := []byte("complete-payload")

	staged := mustAddDACommit(t, state, "peer-a", daRelayTestCommit(stagedID, 2, 5))
	mustAddDACommit(t, state, "peer-b", daRelayTestCommitForPayloads(completeID, 3, payload))
	complete := mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(completeID, 0, uint64(len(payload)), payload))
	wantPinned := state.pinnedPayloadBytes
	if complete.state != daRelayStateCompleteSet || wantPinned == 0 {
		t.Fatalf("setup complete state=%v pinned=%d", complete.state, wantPinned)
	}

	expired, err := state.advanceOrphanTTL()
	if err != nil {
		t.Fatalf("first advance ttl: %v", err)
	}
	if len(expired) != 0 {
		t.Fatalf("first ttl advance expired=%+v, want none", expired)
	}
	if got := state.sets[stagedID].ttlBlocksRemaining; got != staged.ttlBlocksRemaining-1 {
		t.Fatalf("staged ttl after first tick=%d, want %d", got, staged.ttlBlocksRemaining-1)
	}
	if _, ok := state.sets[completeID]; !ok || state.pinnedPayloadBytes != wantPinned {
		t.Fatalf("first tick mutated complete set ok=%v pinned=%d want %d", ok, state.pinnedPayloadBytes, wantPinned)
	}

	expired, err = state.advanceOrphanTTL()
	if err != nil {
		t.Fatalf("second advance ttl: %v", err)
	}
	if len(expired) != 1 || expired[0].daID != stagedID {
		t.Fatalf("second ttl advance expired=%+v, want staged da_id", expired)
	}
	if _, ok := state.sets[stagedID]; ok {
		t.Fatalf("expired staged record was retained")
	}
	if got := state.sets[completeID]; got.state != daRelayStateCompleteSet || state.pinnedPayloadBytes != wantPinned {
		t.Fatalf("second tick mutated complete set state=%v pinned=%d want %d", got.state, state.pinnedPayloadBytes, wantPinned)
	}
}

func TestDARelayAdvanceOrphanTTLReturnsProjectionErrorsWithoutMutation(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	decrementID := daRelayTestID(97)
	expireID := daRelayTestID(98)

	decrementRecord := daRelayOverflowOrphanAccountingRecord(decrementID)
	decrementRecord.ttlBlocksRemaining = 2
	state.sets[decrementID] = decrementRecord
	_, err := state.advanceOrphanTTL()
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if got := state.sets[decrementID].ttlBlocksRemaining; got != 2 {
		t.Fatalf("failed ttl decrement mutated ttl=%d, want 2", got)
	}

	delete(state.sets, decrementID)
	expireRecord := daRelayOverflowOrphanAccountingRecord(expireID)
	expireRecord.ttlBlocksRemaining = 1
	state.sets[expireID] = expireRecord
	_, err = state.advanceOrphanTTL()
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if _, ok := state.sets[expireID]; !ok {
		t.Fatal("failed ttl expiry deleted corrupt record")
	}
}

func TestDARelayRemoveSetRecordReturnsPinnedProjectionErrorWithoutMutation(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(99)
	record := daRelaySetRecord{
		daID:         daID,
		state:        daRelayStateCompleteSet,
		payloadBytes: 1,
		wireBytes:    ^uint64(0),
	}
	state.sets[daID] = record

	state.mu.Lock()
	err := state.removeDASetRecordLocked(record)
	state.mu.Unlock()
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if _, ok := state.sets[daID]; !ok {
		t.Fatal("failed remove deleted corrupt complete record")
	}
}

func TestDARelayRejectedCandidatesDoNotMutateStoredChunks(t *testing.T) {
	daID := daRelayTestID(5)
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 1))
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 2, 1))
	state.caps.orphanCommitOverheadBytes = 1
	_, err := state.addDACommit("peer-b", daRelayTestCommit(daID, 2, 2))
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
	wantPinned := mustPinnedPayloadAccounting(t, record)
	if record.payloadBytes != uint64(len(payload0)+len(payload1)) || state.pinnedPayloadBytes != wantPinned {
		t.Fatalf("payload bytes record=%d pinned=%d want pinned=%d", record.payloadBytes, state.pinnedPayloadBytes, wantPinned)
	}
	if state.orphanBytes != 0 || len(state.orphanBytesByDAID) != 0 {
		t.Fatalf("complete set left orphan accounting: global=%d da=%d", state.orphanBytes, len(state.orphanBytesByDAID))
	}
	record.chunks[0].payload[0] ^= 0xff
	if state.sets[daID].chunks[0].payload[0] == record.chunks[0].payload[0] {
		t.Fatalf("returned complete record aliases stored payload")
	}
}

func TestDARelayCommitCompletesOrphanChunks(t *testing.T) {
	daID := daRelayTestID(6)
	payload0 := []byte("orphan-zero")
	payload1 := []byte("orphan-one")

	state := newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
	record := mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))

	if record.state != daRelayStateCompleteSet {
		t.Fatalf("state=%v, want COMPLETE_SET", record.state)
	}
	if record.payloadBytes != uint64(len(payload0)+len(payload1)) {
		t.Fatalf("payload bytes=%d, want %d", record.payloadBytes, len(payload0)+len(payload1))
	}
	wantPinned := mustPinnedPayloadAccounting(t, record)
	if state.pinnedPayloadBytes != wantPinned || state.orphanBytes != 0 || state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("accounting pinned=%d orphan=%d commit=%d want pinned=%d", state.pinnedPayloadBytes, state.orphanBytes, state.orphanCommitOverheadBytes, wantPinned)
	}

	caps := defaultDARelayCaps()
	caps.pinnedPayloadBytes = 1
	cappedState := newDARelayStateForTest(t, caps)
	mustAddDAChunk(t, cappedState, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	_, err := cappedState.addDACommit("peer-c", daRelayTestCommitForPayloads(daID, 1, payload0))
	requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
	if cappedState.sets[daID].commit.chunkCount != 0 || cappedState.pinnedPayloadBytes != 0 {
		t.Fatalf("pinned cap rejection mutated commit=%d pinned=%d", cappedState.sets[daID].commit.chunkCount, cappedState.pinnedPayloadBytes)
	}
}

func TestDARelayCloneModesKeepStateCopiesShallowAndCallerCopiesDeep(t *testing.T) {
	daID := daRelayTestID(7)
	record := daRelaySetRecord{
		daID: daID,
		chunks: map[uint16]daRelayChunk{
			0: daRelayTestChunkPayload(daID, 0, 17, []byte("immutable-payload")),
		},
		replaceableChunks: map[uint16]bool{0: true},
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
	stateClone.replaceableChunks[1] = true
	if record.replaceableChunks[1] {
		t.Fatalf("state mutation clone aliases replaceable chunk map")
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
	callerClone.replaceableChunks[1] = true
	if record.replaceableChunks[1] {
		t.Fatalf("caller clone aliases replaceable chunk map")
	}
}

func TestDARelayEvictionAccountingHidesUnavailableFee(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(90)
	payload0 := []byte("chunk-zero")
	payload1 := []byte("chunk-one")

	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 3, payload0, payload1))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	record := mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))

	accounting, ok := record.evictionAccounting()
	if !ok {
		t.Fatal("complete DA set did not expose eviction accounting")
	}
	if accounting.daID != daID {
		t.Fatalf("eviction da_id=%x, want %x", accounting.daID, daID)
	}
	if accounting.payloadBytes != record.payloadBytes || accounting.wireBytes != record.wireBytes || accounting.receivedTime != record.receivedTime {
		t.Fatalf("eviction accounting = %+v, want payload=%d wire=%d received=%d", accounting, record.payloadBytes, record.wireBytes, record.receivedTime)
	}

	accountingType := reflect.TypeOf(accounting)
	for i := 0; i < accountingType.NumField(); i++ {
		if strings.Contains(strings.ToLower(accountingType.Field(i).Name), "fee") {
			t.Fatalf("eviction accounting exposes unavailable fee field %q", accountingType.Field(i).Name)
		}
	}
}

func TestDARelayEvictionAccountingRejectsIncompleteSet(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(91)
	payload := []byte("chunk-zero")

	record := mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 3, payload))
	if _, ok := record.evictionAccounting(); ok {
		t.Fatal("incomplete DA set exposed eviction accounting")
	}
}

func TestDARelayRejectsIntegrityAndPinnedCapSafely(t *testing.T) {
	daID := daRelayTestID(8)
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
	_, err = state.addDACommit("peer-b", daRelayTestCommitForPayloads(daID, 1, payload1, payload0))
	requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
	record := state.sets[daID]
	if record.state != daRelayStateStagedCommit || record.commit.chunkCount != 2 || len(record.chunks) != 0 || state.orphanBytes != record.wireBytes || state.pinnedPayloadBytes != 0 {
		t.Fatalf("commitment mismatch failed to preserve first commit cleanly: state=%v commit=%d chunks=%d orphan=%d record=%d pinned=%d", record.state, record.commit.chunkCount, len(record.chunks), state.orphanBytes, record.wireBytes, state.pinnedPayloadBytes)
	}
	_, err = state.addDACommit("peer-d", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
	requireDAErr(t, err, errDARelayDuplicateCommit)
	record = mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(payload1)), payload1))
	record = mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 1, uint64(len(payload0)), payload0))
	if record.state != daRelayStateCompleteSet {
		t.Fatalf("state after orphan recovery=%v, want COMPLETE_SET", record.state)
	}
	if record.commit.payloadCommitment != daRelayPayloadCommitment(payload1, payload0) {
		t.Fatalf("complete set did not retain first commit")
	}

	state = newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), []byte("payload-x")))
	mustAddDACommit(t, state, "peer-b", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
	beforeMismatchTime := state.nextReceivedTime
	_, err = state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
	requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
	record = state.sets[daID]
	if record.replaceableChunks[0] || len(record.chunks) != 1 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("partial chunk mismatch mutated stale chunk: replaceable=%v chunks=%d pinned=%d", record.replaceableChunks, len(record.chunks), state.pinnedPayloadBytes)
	}
	if missing := record.missingChunkIndexes(); len(missing) != 1 || missing[0] != 1 {
		t.Fatalf("partial chunk mismatch missing indexes=%v, want [1]", missing)
	}
	if state.nextReceivedTime != beforeMismatchTime || record.receivedTime != beforeMismatchTime {
		t.Fatalf("partial chunk mismatch time record=%d state=%d want first-seen %d", record.receivedTime, state.nextReceivedTime, beforeMismatchTime)
	}

	state = newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	_, err = state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), []byte("payload-x")))
	requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
	if state.sets[daID].state != daRelayStateStagedCommit || len(state.sets[daID].chunks) != 1 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("chunk mismatch mutated staged chunks: state=%v chunks=%d pinned=%d", state.sets[daID].state, len(state.sets[daID].chunks), state.pinnedPayloadBytes)
	}
	record = mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
	if record.state != daRelayStateCompleteSet {
		t.Fatalf("state after partial mismatch recovery=%v, want COMPLETE_SET", record.state)
	}
	if record.replaceableChunks[0] {
		t.Fatalf("partial mismatch marked valid chunk replaceable: replaceable=%v", record.replaceableChunks)
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

	caps = defaultDARelayCaps()
	caps.pinnedPayloadBytes = uint64(len(payload0))
	state = newDARelayStateForTest(t, caps)
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0))
	_, err = state.addDAChunk("peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
	if state.sets[daID].state != daRelayStateStagedCommit || state.pinnedPayloadBytes != 0 {
		t.Fatalf("footprint cap rejection mutated state: state=%v pinned=%d", state.sets[daID].state, state.pinnedPayloadBytes)
	}
}

func TestDARelayRejectsSingleCandidateMismatchWithoutRetry(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(63)
	payload := []byte("payload")
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, []byte("different")))

	requireAddDAChunkErrWithin(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload)), payload), errDARelayPayloadCommitmentMismatch)

	record := state.sets[daID]
	if record.state != daRelayStateStagedCommit || len(record.chunks) != 0 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("single-candidate mismatch mutated state: state=%v chunks=%d pinned=%d", record.state, len(record.chunks), state.pinnedPayloadBytes)
	}
}

func TestDARelayRejectsBadReplaceableReplacementWithoutRetry(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(64)
	payload0 := []byte("payload-a")
	payload1 := []byte("payload-b")
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))

	record := state.sets[daID]
	record.chunks = map[uint16]daRelayChunk{
		0: daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), []byte("stale")),
		1: daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1),
	}
	record.replaceableChunks = map[uint16]bool{0: true}
	if err := record.recomputeOrphanTotals(); err != nil {
		t.Fatalf("recompute replaceable setup: %v", err)
	}
	state.sets[daID] = record

	if record.state != daRelayStateStagedCommit || !record.replaceableChunks[0] || len(record.chunks) != 2 {
		t.Fatalf("setup did not retain replaceable stale chunk with other chunk present: state=%v replaceable=%v chunks=%d", record.state, record.replaceableChunks, len(record.chunks))
	}

	requireAddDAChunkErrWithin(t, state, "peer-d", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), []byte("also-bad")), errDARelayPayloadCommitmentMismatch)

	record = state.sets[daID]
	if !record.replaceableChunks[0] || len(record.chunks) != 2 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("bad replacement mismatch mutated state: replaceable=%v chunks=%d pinned=%d", record.replaceableChunks, len(record.chunks), state.pinnedPayloadBytes)
	}
}

func TestDARelayRejectsCompletionOverflowBeforeMutation(t *testing.T) {
	caps := defaultDARelayCaps()
	caps.orphanPoolBytes = ^uint64(0)
	caps.orphanPoolPerPeerBytes = ^uint64(0)
	caps.orphanPoolPerDAIDBytes = ^uint64(0)
	caps.orphanCommitOverheadBytes = ^uint64(0)
	caps.pinnedPayloadBytes = ^uint64(0)

	t.Run("commit completes orphan chunk", func(t *testing.T) {
		state := newDARelayStateForTest(t, caps)
		daID := daRelayTestID(55)
		payload := []byte{1}
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, ^uint64(0), payload))

		_, err := state.addDACommit("peer-b", daRelayTestCommitForPayloads(daID, 1, payload))
		requireDAErr(t, err, errDARelayArithmeticOverflow)

		record := state.sets[daID]
		if record.commit.chunkCount != 0 || record.state != daRelayStateOrphanChunks || len(record.chunks) != 1 {
			t.Fatalf("commit completion overflow mutated record: state=%v commit=%d chunks=%d", record.state, record.commit.chunkCount, len(record.chunks))
		}
	})

	t.Run("chunk completes staged commit", func(t *testing.T) {
		state := newDARelayStateForTest(t, caps)
		daID := daRelayTestID(56)
		payload := []byte{1}
		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, ^uint64(0), payload))

		_, err := state.addDAChunk("peer-b", daRelayTestChunkPayload(daID, 0, 1, payload))
		requireDAErr(t, err, errDARelayArithmeticOverflow)

		record := state.sets[daID]
		if record.state != daRelayStateStagedCommit || len(record.chunks) != 0 || state.pinnedPayloadBytes != 0 {
			t.Fatalf("chunk completion overflow mutated record: state=%v chunks=%d pinned=%d", record.state, len(record.chunks), state.pinnedPayloadBytes)
		}
	})
}

func TestDARelayRejectsMismatchApplyFailureBeforeMutation(t *testing.T) {
	t.Run("commit mismatch drop path", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(57)
		payload0 := []byte("payload-a")
		payload1 := []byte("payload-b")
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
		state.orphanBytesByPeerQuotaKey[peerQuotaKey("peer-a")] = 0

		_, err := state.addDACommit("peer-b", daRelayTestCommitForPayloads(daID, 1, payload1, payload0))
		requireDAErr(t, err, errDARelayArithmeticOverflow)

		record := state.sets[daID]
		if record.commit.chunkCount != 0 || len(record.chunks) != 2 {
			t.Fatalf("commit mismatch apply failure mutated record: commit=%d chunks=%d", record.commit.chunkCount, len(record.chunks))
		}
	})

	t.Run("chunk mismatch replaceable path", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(58)
		payload0 := []byte("payload-a")
		payload1 := []byte("payload-b")
		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
		mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
		state.orphanBytesByPeerQuotaKey[peerQuotaKey("peer-b")] = 0

		_, err := state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), []byte("wrong")))
		requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)

		record := state.sets[daID]
		if record.replaceableChunks[0] || len(record.chunks) != 1 || record.state != daRelayStateStagedCommit {
			t.Fatalf("chunk mismatch apply failure mutated record: replaceable=%v chunks=%d state=%v", record.replaceableChunks, len(record.chunks), record.state)
		}
	})
}

func TestDARelayStageChunkRejectsDuplicateWithoutMutation(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(59)
	chunk := daRelayTestChunk(daID, 0, 1)
	record := mustAddDAChunk(t, state, "peer-a", chunk)

	state.mu.Lock()
	staged, err := state.stageDAChunkRecordLocked("peer-b", chunk, chunk.payload)
	state.mu.Unlock()
	requireDAErr(t, err, errDARelayDuplicateChunk)

	if len(staged.chunks) != 0 || len(state.sets[daID].chunks) != len(record.chunks) || state.orphanBytes != record.wireBytes {
		t.Fatalf("duplicate stage mutated state: staged=%d stored=%d orphan=%d", len(staged.chunks), len(state.sets[daID].chunks), state.orphanBytes)
	}
}

func TestDARelayCompletionSnapshotRejectsMismatches(t *testing.T) {
	daID := daRelayTestID(60)
	payload0 := []byte("payload-a")
	payload1 := []byte("payload-b")
	record := daRelaySetRecord{
		daID:   daID,
		state:  daRelayStateStagedCommit,
		commit: daRelayTestCommitForPayloads(daID, 1, payload0, payload1),
		chunks: map[uint16]daRelayChunk{
			0: daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0),
			1: daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1),
		},
	}
	snapshot, complete := record.completionSnapshot()
	if !complete {
		t.Fatalf("snapshot setup did not complete")
	}
	if !snapshot.matchesRecord(record) {
		t.Fatalf("snapshot should match original record")
	}

	if snapshot.matchesRecord(daRelaySetRecord{}) {
		t.Fatalf("snapshot matched incomplete record")
	}
	mismatched := snapshot
	mismatched.daID = daRelayTestID(61)
	if mismatched.matchesRecord(record) {
		t.Fatalf("snapshot matched wrong da_id")
	}
	mismatched = snapshot
	mismatched.chunks = mismatched.chunks[:1]
	if mismatched.matchesRecord(record) {
		t.Fatalf("snapshot matched wrong chunk length")
	}
	mismatched = snapshot
	mismatched.chunks = append([]daRelayCompletionChunkSnapshot(nil), snapshot.chunks...)
	mismatched.chunks[0].chunkIndex = 1
	if mismatched.matchesRecord(record) {
		t.Fatalf("snapshot matched wrong chunk index")
	}
	mismatched = snapshot
	mismatched.chunks = append([]daRelayCompletionChunkSnapshot(nil), snapshot.chunks...)
	mismatched.chunks[0].chunkHash[0] ^= 0xff
	if mismatched.matchesRecord(record) {
		t.Fatalf("snapshot matched wrong chunk hash")
	}
	mismatched = snapshot
	mismatched.chunks = append([]daRelayCompletionChunkSnapshot(nil), snapshot.chunks...)
	mismatched.chunks[0].payload = append(cloneBytes(mismatched.chunks[0].payload), 0)
	if mismatched.matchesRecord(record) {
		t.Fatalf("snapshot matched wrong payload length")
	}
}

func TestDARelayMarkMatchingChunksRejectsNoopSnapshots(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(62)
	payload := []byte("payload")
	sourceRecord := daRelaySetRecord{
		daID:   daID,
		state:  daRelayStateStagedCommit,
		commit: daRelayTestCommitForPayloads(daID, 1, payload),
		chunks: map[uint16]daRelayChunk{
			0: daRelayTestChunkPayload(daID, 0, uint64(len(payload)), payload),
		},
	}
	snapshot, complete := sourceRecord.completionSnapshot()
	if !complete {
		t.Fatalf("snapshot setup did not complete")
	}
	completeRecord := sourceRecord
	completeRecord.state = daRelayStateCompleteSet
	state.sets[daID] = completeRecord
	retry, err := state.markMatchingCompletionChunksReplaceable(snapshot)
	if err != nil || !retry {
		t.Fatalf("complete record mark retry=%v err=%v, want true nil", retry, err)
	}

	stagedRecord := completeRecord
	stagedRecord.state = daRelayStateStagedCommit
	stagedRecord.chunks = map[uint16]daRelayChunk{}
	state.sets[daID] = stagedRecord
	retry, err = state.markMatchingCompletionChunksReplaceable(snapshot)
	if err != nil || retry {
		t.Fatalf("empty matching mark retry=%v err=%v, want false nil", retry, err)
	}

	stagedRecord.chunks[0] = daRelayTestChunkPayload(daID, 0, uint64(len(payload)), []byte("wrong"))
	state.sets[daID] = stagedRecord
	retry, err = state.markMatchingCompletionChunksReplaceable(snapshot)
	if err != nil || retry {
		t.Fatalf("mismatched matching mark retry=%v err=%v, want false nil", retry, err)
	}
}

func TestDARelayPinnedPayloadDeltaKeepsOverflowAndCapErrorsDistinct(t *testing.T) {
	caps := defaultDARelayCaps()
	caps.pinnedPayloadBytes = 1
	state := newDARelayStateForTest(t, caps)

	state.pinnedPayloadBytes = 1
	state.mu.Lock()
	_, err := state.projectPinnedPayloadDeltaLocked(
		daRelaySetRecord{state: daRelayStateCompleteSet, payloadBytes: 2},
		daRelaySetRecord{},
	)
	state.mu.Unlock()
	requireDAErr(t, err, errDARelayArithmeticOverflow)

	state.mu.Lock()
	_, err = state.projectPinnedPayloadDeltaLocked(
		daRelaySetRecord{},
		daRelaySetRecord{state: daRelayStateCompleteSet, payloadBytes: 2},
	)
	state.mu.Unlock()
	requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)

	_, err = (daRelaySetRecord{state: daRelayStateCompleteSet, payloadBytes: 1, wireBytes: ^uint64(0)}).pinnedPayloadAccountingBytes()
	requireDAErr(t, err, errDARelayArithmeticOverflow)

	_, err = (daRelaySetRecord{
		state:        daRelayStateCompleteSet,
		payloadBytes: 1,
		wireBytes:    ^uint64(0) - daCompleteSetRecordFootprint,
		commit:       daRelayCommit{chunkCount: 1},
	}).pinnedPayloadAccountingBytes()
	requireDAErr(t, err, errDARelayArithmeticOverflow)

	_, err = (daRelaySetRecord{
		state:     daRelayStateStagedCommit,
		wireBytes: ^uint64(0),
		commit: daRelayCommit{
			peerQuotaKey: "peer-a",
			wireBytes:    ^uint64(0),
		},
		chunks: map[uint16]daRelayChunk{
			0: {peerQuotaKey: "peer-a", wireBytes: 1},
		},
	}).orphanAccounting()
	requireDAErr(t, err, errDARelayArithmeticOverflow)
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

func daRelayOverflowOrphanAccountingRecord(daID [32]byte) daRelaySetRecord {
	return daRelaySetRecord{
		daID:               daID,
		state:              daRelayStateStagedCommit,
		wireBytes:          ^uint64(0),
		ttlBlocksRemaining: 1,
		commit: daRelayCommit{
			daID:         daID,
			peerQuotaKey: "peer-overflow",
			chunkCount:   2,
			wireBytes:    ^uint64(0),
		},
		chunks: map[uint16]daRelayChunk{
			0: {
				daID:         daID,
				peerQuotaKey: "peer-overflow",
				chunkIndex:   0,
				payload:      []byte{1},
				wireBytes:    1,
			},
		},
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

func requireAddDAChunkErrWithin(t *testing.T, state *daRelayState, peer string, chunk daRelayChunk, want error) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		_, err := state.addDAChunk(peer, chunk)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		requireDAErr(t, err, want)
	case <-time.After(2 * time.Second):
		t.Fatal("add DA chunk did not return")
	}
}

func mustPinnedPayloadAccounting(t *testing.T, record daRelaySetRecord) uint64 {
	t.Helper()
	bytes, err := record.pinnedPayloadAccountingBytes()
	if err != nil {
		t.Fatalf("pinned payload accounting: %v", err)
	}
	return bytes
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

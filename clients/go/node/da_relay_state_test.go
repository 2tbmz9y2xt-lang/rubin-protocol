package node

import (
	"crypto/sha3"
	"errors"
	"maps"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

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
	state, err := newDARelayState(nil, defaultDARelayCaps())
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
	state, err := newDARelayState(nil, defaultDARelayCaps())
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
	state, err := newDARelayState(nil, defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	var daID [32]byte
	daID[0] = 1
	state.setOrphanBytesForPeerQuotaKey("peer", 1)
	state.setOrphanBytesForDAID(daID, 2)

	if state.orphanBytesForPeerQuotaKey("peer") != 1 {
		t.Fatalf("orphan peer accounting map is not writable")
	}
	if state.orphanBytesForDAID(daID) != 2 {
		t.Fatalf("orphan da_id accounting map is not writable")
	}
}

func TestDARelayPeerAccountingUsesQuotaKey(t *testing.T) {
	state, err := newDARelayState(nil, defaultDARelayCaps())
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}

	state.setOrphanBytesForPeerQuotaKey("127.0.0.1", 1)
	state.setOrphanBytesForPeerQuotaKey("127.0.0.1", 2)

	if len(state.orphanBytesByPeerQuotaKey) != 1 {
		t.Fatalf("peer accounting entries = %d, want 1", len(state.orphanBytesByPeerQuotaKey))
	}
	if got := state.orphanBytesForPeerQuotaKey("127.0.0.1"); got != 2 {
		t.Fatalf("peer accounting bytes = %d, want 2", got)
	}
	state.setOrphanBytesForPeerQuotaKey("127.0.0.1", 0)
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

		record := mustAddDAChunk(t, state, "127.0.0.1", daRelayTestChunk(firstID, 0, 6))
		err := state.addDAChunk("127.0.0.1", daRelayTestChunk(secondID, 0, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		requirePortHopRejectedWithoutMutation(t, state, secondID, record.wireBytes)
	})

	t.Run("staged commit", func(t *testing.T) {
		caps := defaultDARelayCaps()
		caps.orphanPoolPerPeerBytes = 10
		state := newDARelayStateForTest(t, caps)
		firstID := daRelayTestID(43)
		secondID := daRelayTestID(44)

		record := mustAddDACommit(t, state, "127.0.0.1", daRelayTestCommit(firstID, 2, 6))
		err := state.addDACommit("127.0.0.1", daRelayTestCommit(secondID, 2, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		requirePortHopRejectedWithoutMutation(t, state, secondID, record.wireBytes)
		if state.orphanCommitOverheadBytes != record.commit.wireBytes {
			t.Fatalf("commit overhead = %d, want %d", state.orphanCommitOverheadBytes, record.commit.wireBytes)
		}
	})
}

func TestDARelayReleasePeerQuotaKeySkipsUnchargedPeer(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	record := mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daRelayTestID(112), 0, 7))
	if err := state.ReleasePeerQuotaKey("peer-b"); err != nil {
		t.Fatalf("release uncharged peer: %v", err)
	}
	if got := state.orphanBytesForPeerQuotaKey("peer-a"); got != record.wireBytes {
		t.Fatalf("charged peer bytes after unrelated release = %d, want %d", got, record.wireBytes)
	}
}

func TestDARelayEmptyPeerQuotaKeyIsCapped(t *testing.T) {
	t.Run("chunk only", func(t *testing.T) {
		caps := defaultDARelayCaps()
		caps.orphanPoolPerPeerBytes = 10
		state := newDARelayStateForTest(t, caps)
		firstID := daRelayTestID(45)
		secondID := daRelayTestID(46)

		record := mustAddDAChunk(t, state, "", daRelayTestChunk(firstID, 0, 6))
		err := state.addDAChunk("", daRelayTestChunk(secondID, 0, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		if got := state.orphanBytesForPeerQuotaKey(""); got != record.wireBytes {
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
		err := state.addDACommit("", daRelayTestCommit(secondID, 2, 5))
		requireDAErr(t, err, errDARelayOrphanPeerCapExceeded)

		if got := state.orphanBytesForPeerQuotaKey(""); got != record.wireBytes {
			t.Fatalf("empty peer quota bytes = %d, want %d", got, record.wireBytes)
		}
		if _, ok := state.sets[secondID]; ok {
			t.Fatalf("empty-peer commit cap rejection mutated state")
		}
	})
}

func TestDARelayDAIDAccountingDeletesZeroBytes(t *testing.T) {
	state, err := newDARelayState(nil, defaultDARelayCaps())
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
	state, err := newDARelayState(nil, defaultDARelayCaps())
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
		err := state.addDAChunk("peer-a", daRelayTestChunk(daID, 0, 5))
		requireDAErr(t, err, tt.want)
		if len(state.sets) != 0 || state.orphanBytes != 0 {
			t.Fatalf("rejection mutated state: sets=%d orphan=%d", len(state.sets), state.orphanBytes)
		}
	}

	state := newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDACommit(t, state, "peer-a", daRelayTestCommit(daID, 1, 1))
	err := state.addDAChunk("peer-a", daRelayTestChunk(daID, 1, 1))
	requireDAErr(t, err, errDARelayChunkIndexOutsideCommit)
	err = state.addDACommit("peer-a", daRelayTestCommit(daID, 0, 1))
	requireDAErr(t, err, errDARelayChunkCountInvalid)
	err = state.addDACommit("peer-a", daRelayTestCommit(daID, uint16(consensus.MAX_DA_CHUNK_COUNT+1), 1))
	requireDAErr(t, err, errDARelayChunkCountInvalid)
	err = state.addDAChunk("peer-a", daRelayTestChunk(daID, uint16(consensus.MAX_DA_CHUNK_COUNT), 1))
	requireDAErr(t, err, errDARelayChunkIndexOutOfRange)

	caps := defaultDARelayCaps()
	caps.orphanPoolBytes, caps.orphanPoolPerPeerBytes = ^uint64(0), ^uint64(0)
	caps.orphanPoolPerDAIDBytes = ^uint64(0)
	overflowState := newDARelayStateForTest(t, caps)
	mustAddDAChunk(t, overflowState, "peer-a", daRelayTestChunk(daID, 0, ^uint64(0)))
	err = overflowState.addDACommit("peer-a", daRelayTestCommit(daID, 2, 1))
	requireDAErr(t, err, errDARelayArithmeticOverflow)

	chunkOnlyOverflowState := newDARelayStateForTest(t, caps)
	mustAddDAChunk(t, chunkOnlyOverflowState, "peer-a", daRelayTestChunk(daID, 0, ^uint64(0)))
	err = chunkOnlyOverflowState.addDAChunk("peer-a", daRelayTestChunk(daID, 1, 1))
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

func TestDARelayAccountingUsesRetainedTxByteLengths(t *testing.T) {
	daID := daRelayTestID(93)
	payload := []byte("retained-payload")
	commitTx := []byte("canonical-commit-tx")
	chunkTx := []byte("canonical-chunk-tx")
	record := daRelaySetRecord{
		daID:  daID,
		state: daRelayStateStagedCommit,
		commit: daRelayCommit{
			daID:         daID,
			chunkCount:   1,
			wireBytes:    1,
			txBytes:      cloneBytes(commitTx),
			peerQuotaKey: "commit-peer",
		},
		chunks: map[uint16]daRelayChunk{
			0: {
				daID:         daID,
				chunkIndex:   0,
				chunkHash:    sha3.Sum256(payload),
				payload:      cloneBytes(payload),
				wireBytes:    1,
				txBytes:      cloneBytes(chunkTx),
				peerQuotaKey: "chunk-peer",
			},
		},
	}

	if err := record.recomputeOrphanTotals(); err != nil {
		t.Fatalf("recompute retained accounting: %v", err)
	}
	wantWire := uint64(len(commitTx) + len(chunkTx))
	if record.wireBytes != wantWire {
		t.Fatalf("record wire bytes=%d, want retained tx bytes %d", record.wireBytes, wantWire)
	}

	accounting, err := record.orphanAccounting()
	if err != nil {
		t.Fatalf("orphan retained accounting: %v", err)
	}
	wantOrphan := wantWire + uint64(len(payload))
	if accounting.orphanBytes != wantOrphan || accounting.commitBytes != uint64(len(commitTx)) {
		t.Fatalf("accounting orphan=%d commit=%d, want orphan=%d commit=%d", accounting.orphanBytes, accounting.commitBytes, wantOrphan, len(commitTx))
	}
	if accounting.peerBytes["commit-peer"] != uint64(len(commitTx)) {
		t.Fatalf("commit peer bytes=%d, want %d", accounting.peerBytes["commit-peer"], len(commitTx))
	}
	wantChunkBytes := uint64(len(chunkTx) + len(payload))
	if accounting.peerBytes["chunk-peer"] != wantChunkBytes {
		t.Fatalf("chunk peer bytes=%d, want %d", accounting.peerBytes["chunk-peer"], wantChunkBytes)
	}
}

func TestDARelayCompletionIgnoresTransientOrphanCapsForRetainedTxBytes(t *testing.T) {
	caps := defaultDARelayCaps()
	caps.orphanPoolBytes = 4
	caps.orphanPoolPerPeerBytes = 4
	caps.orphanPoolPerDAIDBytes = 4
	caps.orphanCommitOverheadBytes = 4
	caps.pinnedPayloadBytes = 1 << 20

	t.Run("commit completes orphan chunk", func(t *testing.T) {
		state := newDARelayStateForTest(t, caps)
		daID := daRelayTestID(94)
		payload := []byte{1}
		commitTx := []byte("retained-commit-tx")
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, 1, payload))

		record := mustAddDACommit(t, state, "peer-b", daRelayTestCommitWithTxBytes(daID, 1, commitTx, payload))
		if record.state != daRelayStateCompleteSet || state.orphanBytes != 0 || state.orphanCommitOverheadBytes != 0 {
			t.Fatalf("commit completion state=%v orphan=%d commit=%d", record.state, state.orphanBytes, state.orphanCommitOverheadBytes)
		}
		commitTx[0] = 'X'
		if !reflect.DeepEqual(state.sets[daID].commit.txBytes, []byte("retained-commit-tx")) {
			t.Fatalf("complete commit retained caller txBytes alias: %q", state.sets[daID].commit.txBytes)
		}
	})

	t.Run("chunk completes staged commit", func(t *testing.T) {
		state := newDARelayStateForTest(t, caps)
		daID := daRelayTestID(95)
		payload := []byte{1}
		chunkTx := []byte("retained-chunk-tx")
		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload))

		record := mustAddDAChunk(t, state, "peer-b", daRelayTestChunkWithTxBytes(daID, 0, 1, chunkTx, payload))
		if record.state != daRelayStateCompleteSet || state.orphanBytes != 0 || state.orphanCommitOverheadBytes != 0 {
			t.Fatalf("chunk completion state=%v orphan=%d commit=%d", record.state, state.orphanBytes, state.orphanCommitOverheadBytes)
		}
		chunkTx[0] = 'X'
		if !reflect.DeepEqual(state.sets[daID].chunks[0].txBytes, []byte("retained-chunk-tx")) {
			t.Fatalf("complete chunk retained caller txBytes alias: %q", state.sets[daID].chunks[0].txBytes)
		}
	})

	t.Run("commit completion checks pinned cap before retaining tx bytes", func(t *testing.T) {
		rejectCaps := defaultDARelayCaps()
		rejectCaps.pinnedPayloadBytes = 1
		state := newDARelayStateForTest(t, rejectCaps)
		daID := daRelayTestID(96)
		// Two payload bytes against a one-byte cap: the pinned contribution is
		// payload-only, so the payload alone must overshoot the cap.
		payload := []byte{1, 2}
		commitTx := []byte("retained-commit-tx")
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, 2, payload))

		err := state.addDACommit("peer-b", daRelayTestCommitWithTxBytes(daID, 1, commitTx, payload))
		requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
		commitTx[0] = 'X'
		stored := state.sets[daID]
		if stored.commit.chunkCount != 0 || len(stored.commit.txBytes) != 0 || state.pinnedPayloadBytes != 0 {
			t.Fatalf("rejected complete commit retained state: commit=%d tx=%q pinned=%d", stored.commit.chunkCount, stored.commit.txBytes, state.pinnedPayloadBytes)
		}
	})

	t.Run("chunk completion checks pinned cap before retaining tx bytes", func(t *testing.T) {
		rejectCaps := defaultDARelayCaps()
		rejectCaps.pinnedPayloadBytes = 1
		state := newDARelayStateForTest(t, rejectCaps)
		daID := daRelayTestID(97)
		payload := []byte{1, 2}
		chunkTx := []byte("retained-chunk-tx")
		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload))

		err := state.addDAChunk("peer-b", daRelayTestChunkWithTxBytes(daID, 0, 2, chunkTx, payload))
		requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
		chunkTx[0] = 'X'
		stored := state.sets[daID]
		if len(stored.chunks) != 0 || state.pinnedPayloadBytes != 0 {
			t.Fatalf("rejected complete chunk retained state: chunks=%d pinned=%d", len(stored.chunks), state.pinnedPayloadBytes)
		}
	})
}

func TestDARelayRejectsZeroWireBytesBeforeMutation(t *testing.T) {
	daID := daRelayTestID(3)
	state := newDARelayStateForTest(t, defaultDARelayCaps())

	err := state.addDACommit("peer-a", daRelayTestCommit(daID, 1, 0))
	requireDAErr(t, err, errDARelayWireBytesInvalid)
	err = state.addDAChunk("peer-a", daRelayTestChunk(daID, 0, 0))
	requireDAErr(t, err, errDARelayWireBytesInvalid)

	if len(state.sets) != 0 || state.orphanBytes != 0 || state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("zero wire rejection mutated state: sets=%d orphan=%d commit=%d", len(state.sets), state.orphanBytes, state.orphanCommitOverheadBytes)
	}
}

func TestDARelayRejectsReceivedTimeOverflowBeforeMutation(t *testing.T) {
	chunkState := newDARelayStateForTest(t, defaultDARelayCaps())
	chunkState.nextReceivedTime = ^uint64(0)
	chunkID := daRelayTestID(49)
	err := chunkState.addDAChunk("peer-a", daRelayTestChunk(chunkID, 0, 1))
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if len(chunkState.sets) != 0 || chunkState.nextReceivedTime != ^uint64(0) {
		t.Fatalf("chunk time overflow mutated state: sets=%d time=%d", len(chunkState.sets), chunkState.nextReceivedTime)
	}

	commitState := newDARelayStateForTest(t, defaultDARelayCaps())
	commitState.nextReceivedTime = ^uint64(0)
	commitID := daRelayTestID(50)
	err = commitState.addDACommit("peer-a", daRelayTestCommit(commitID, 2, 1))
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if len(commitState.sets) != 0 || commitState.nextReceivedTime != ^uint64(0) {
		t.Fatalf("commit time overflow mutated state: sets=%d time=%d", len(commitState.sets), commitState.nextReceivedTime)
	}
}

func TestDARelayRejectsDuplicatesBeforeMutation(t *testing.T) {
	daID := daRelayTestID(4)
	state := newDARelayStateForTest(t, defaultDARelayCaps())

	record := mustAddDACommit(t, state, "peer-a", daRelayTestCommit(daID, 2, 3))
	err := state.addDACommit("peer-b", daRelayTestCommit(daID, 2, 5))
	requireDAErr(t, err, errDARelayDuplicateCommit)
	if state.sets[daID].commit.wireBytes != record.commit.wireBytes || state.orphanBytes != record.wireBytes {
		t.Fatalf("duplicate commit mutated state: commit=%d orphan=%d want commit=%d orphan=%d", state.sets[daID].commit.wireBytes, state.orphanBytes, record.commit.wireBytes, record.wireBytes)
	}
	if got := state.sets[daID].commit.peerQuotaKey; got != "peer-a" {
		t.Fatalf("duplicate commit peer=%q, want first peer", got)
	}
	if got := state.orphanBytesForPeerQuotaKey("peer-b"); got != 0 {
		t.Fatalf("duplicate commit credited duplicate peer bytes=%d", got)
	}
	if got := state.sets[daID].receivedTime; got != record.receivedTime {
		t.Fatalf("duplicate commit received_time=%d, want first-seen %d", got, record.receivedTime)
	}

	chunk := daRelayTestChunkWithTxBytes(daID, 0, 7, []byte{'a', 1, 'b'}, []byte{1})
	record = mustAddDAChunk(t, state, "peer-c", chunk)
	duplicateChunk := daRelayTestChunkWithTxBytes(daID, 0, 11, []byte{'d', 1, 'e'}, []byte{1})
	duplicateChunk.chunkHash[0] ^= 0xff
	err = state.addDAChunk("peer-d", duplicateChunk)
	requireDAErr(t, err, errDARelayDuplicateChunk)
	duplicateChunk.txBytes[0] = 'X'
	wantOrphanBytes := record.wireBytes + uint64(len(chunk.payload))
	if len(state.sets[daID].chunks) != 1 || state.orphanBytes != wantOrphanBytes {
		t.Fatalf("duplicate chunk mutated state: chunks=%d orphan=%d want orphan=%d", len(state.sets[daID].chunks), state.orphanBytes, wantOrphanBytes)
	}
	if !reflect.DeepEqual(state.sets[daID].chunks[0].txBytes, []byte{'a', 1, 'b'}) {
		t.Fatalf("duplicate chunk mutated stored tx bytes: %q", state.sets[daID].chunks[0].txBytes)
	}
}

func TestDARelayDuplicateCommitAfterOrphanChunksKeepsFirstSeenState(t *testing.T) {
	daID := daRelayTestID(92)
	state := newDARelayStateForTest(t, defaultDARelayCaps())

	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 7))
	payload0 := []byte{1}
	payload1 := []byte{2}
	record := mustAddDACommit(t, state, "peer-b", daRelayTestCommitWithTxBytes(daID, 3, []byte("first-commit"), payload0, payload1))

	duplicate := daRelayTestCommitWithTxBytes(daID, 11, []byte("duplicate-commit"), payload0, payload1)
	err := state.addDACommit("peer-c", duplicate)
	requireDAErr(t, err, errDARelayDuplicateCommit)
	duplicate.txBytes[0] = 'X'
	stored := state.sets[daID]
	if stored.commit.wireBytes != record.commit.wireBytes || stored.commit.peerQuotaKey != "peer-b" {
		t.Fatalf("duplicate commit replaced first commit: wire=%d peer=%q", stored.commit.wireBytes, stored.commit.peerQuotaKey)
	}
	if !reflect.DeepEqual(stored.commit.txBytes, []byte("first-commit")) {
		t.Fatalf("duplicate commit mutated stored tx bytes: %q", stored.commit.txBytes)
	}
	if stored.receivedTime != record.receivedTime || state.nextReceivedTime != record.receivedTime {
		t.Fatalf("duplicate commit time record=%d state=%d want %d", stored.receivedTime, state.nextReceivedTime, record.receivedTime)
	}
	if _, ok := stored.chunks[0]; !ok {
		t.Fatal("duplicate commit dropped first-seen orphan chunk")
	}
	if got := state.orphanBytesForPeerQuotaKey("peer-c"); got != 0 {
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
	if got := state.orphanBytesForPeerQuotaKey("peer-a"); got != 0 {
		t.Fatalf("expiry left peer-a bytes=%d", got)
	}
	if got := state.orphanBytesForPeerQuotaKey("peer-b"); got != 0 {
		t.Fatalf("expiry left peer-b bytes=%d", got)
	}
	if err := state.AdvanceOrphanTTL(); err != nil {
		t.Fatalf("public ttl advance: %v", err)
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
	if len(expired) != 1 || expired[0].daID != daID || expired[0].state != daRelayStateStagedCommit || expired[0].commitPeerQuotaKey != "peer-b" {
		t.Fatalf("expired=%+v, want staged commit attribution to peer-b", expired)
	}
	if _, ok := state.sets[daID]; ok {
		t.Fatalf("expired staged commit da_id record was retained")
	}
	if state.orphanBytes != 0 || state.orphanBytesForDAID(daID) != 0 || state.orphanCommitOverheadBytes != 0 {
		t.Fatalf("expiry left accounting global=%d da=%d commit=%d", state.orphanBytes, state.orphanBytesForDAID(daID), state.orphanCommitOverheadBytes)
	}
	if got := state.orphanBytesForPeerQuotaKey("peer-a"); got != 0 {
		t.Fatalf("expiry left chunk peer bytes=%d", got)
	}
	if got := state.orphanBytesForPeerQuotaKey("peer-b"); got != 0 {
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
	state.orphanBytesByDAID[decrementID] = decrementRecord.wireBytes
	expired, err := state.advanceOrphanTTL()
	if err != nil {
		t.Fatalf("ttl-only decrement should skip accounting projection: %v", err)
	}
	if len(expired) != 0 {
		t.Fatalf("ttl-only decrement expired=%+v, want none", expired)
	}
	if got := state.sets[decrementID].ttlBlocksRemaining; got != 1 {
		t.Fatalf("ttl-only decrement ttl=%d, want 1", got)
	}

	delete(state.sets, decrementID)
	delete(state.orphanBytesByDAID, decrementID)
	expireRecord := daRelayOverflowOrphanAccountingRecord(expireID)
	expireRecord.ttlBlocksRemaining = 1
	state.sets[expireID] = expireRecord
	state.orphanBytesByDAID[expireID] = expireRecord.wireBytes
	_, err = state.advanceOrphanTTL()
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if _, ok := state.sets[expireID]; !ok {
		t.Fatal("failed ttl expiry deleted corrupt record")
	}
}

func TestDARelayAdvanceOrphanTTLBatchErrorLeavesWholeImageUnchanged(t *testing.T) {
	t.Run("empty no-op", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		before := daRelayStateSnapshot(state)
		expired, err := state.advanceOrphanTTL()
		if err != nil || len(expired) != 0 {
			t.Fatalf("empty advance expired=%+v err=%v", expired, err)
		}
		requireDARelayStateUnchanged(t, state, before)
	})
	t.Run("decrement only", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(201)
		record := mustAddDAChunk(t, state, "peer-ttl", daRelayTestChunk(daID, 0, 7))
		record.ttlBlocksRemaining = 3
		state.sets[daID] = record
		expired, err := state.advanceOrphanTTL()
		if err != nil || len(expired) != 0 {
			t.Fatalf("decrement advance expired=%+v err=%v", expired, err)
		}
		if got := state.sets[daID]; got.ttlBlocksRemaining != 2 || got.receivedTime != record.receivedTime {
			t.Fatalf("record after decrement=%+v, want ttl 2 and receivedTime %d", got, record.receivedTime)
		}
	})
	t.Run("mixed sorted success", func(t *testing.T) {
		state, ids := newDARelayAtomicBatchState(t, "peer-ttl")
		twin, _ := newDARelayAtomicBatchState(t, "peer-ttl")
		twin.mempool = state.mempool
		for _, s := range []*DARelayState{state, twin} {
			record := s.sets[ids[1]]
			record.ttlBlocksRemaining = 2
			s.sets[ids[1]] = record
		}
		twin.mu.Lock()
		_, wantErr := twin.advanceOrphanTTLLocked()
		twin.mu.Unlock()
		if wantErr != nil {
			t.Fatalf("build ttl expected image: %v", wantErr)
		}
		want := daRelayStateSnapshot(twin)
		expired, err := state.advanceOrphanTTL()
		if err != nil {
			t.Fatalf("mixed advance: %v", err)
		}
		if len(expired) != 2 || expired[0].daID != ids[0] || expired[0].receivedTime != 1 || expired[1].daID != ids[2] || expired[1].receivedTime != 3 {
			t.Fatalf("mixed expired=%+v, want sorted first and final", expired)
		}
		if got := daRelayStateSnapshot(state); !reflect.DeepEqual(got, want) || got.nextReceivedTime != 5 { //nolint:govet // Complete private state-image equality requires structural comparison.
			t.Fatalf("ttl success image=%+v, want %+v", got, want)
		}
	})
	for _, tt := range []struct {
		name  string
		index int
	}{
		{name: "underflow first", index: 0},
		{name: "underflow middle", index: 1},
		{name: "underflow final", index: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state, ids := newDARelayAtomicBatchState(t, "peer-ttl")
			state.orphanBytesByDAID[ids[tt.index]] = 0
			before := daRelayStateSnapshot(state)
			expired, err := state.advanceOrphanTTL()
			if err != errDARelayArithmeticOverflow || expired != nil { //nolint:errorlint // Exact identity is part of the contract.
				t.Fatalf("underflow expired=%+v err=%v, want nil and %v", expired, err, errDARelayArithmeticOverflow)
			}
			requireDARelayStateUnchanged(t, state, before)
		})
	}
	t.Run("first error and public propagation", func(t *testing.T) {
		state, _ := newDARelayFirstErrorState(t)
		before := daRelayStateSnapshot(state)
		expired, err := state.advanceOrphanTTL()
		if err != errDARelayOrphanPeerCapExceeded || expired != nil { //nolint:errorlint // Exact identity is part of the contract.
			t.Fatalf("first ttl err=%v expired=%+v, want %v and nil", err, expired, errDARelayOrphanPeerCapExceeded)
		}
		requireDARelayStateUnchanged(t, state, before)
		if err := state.AdvanceOrphanTTL(); err != errDARelayOrphanPeerCapExceeded { //nolint:errorlint // Exact identity is part of the contract.
			t.Fatalf("public ttl err=%v, want %v", err, errDARelayOrphanPeerCapExceeded)
		}
		requireDARelayStateUnchanged(t, state, before)
	})
	t.Run("snapshot owns complete mutable image", func(t *testing.T) {
		state, ids := newDARelayAtomicBatchState(t, "peer-ttl")
		record := state.sets[ids[0]]
		chunk := record.chunks[0]
		record.commit.txBytes, chunk.txBytes = []byte{1}, []byte{2}
		record.chunks[0] = chunk
		state.sets[ids[0]] = record
		state.orphanCommitOverheadBytes, state.pinnedPayloadBytes = 17, 19
		wantPeer, wantDAID, before := state.orphanBytesByPeerQuotaKey["peer-ttl"], state.orphanBytesByDAID[ids[0]], daRelayStateSnapshot(state)
		state.orphanBytesByPeerQuotaKey["alias"], state.orphanBytesByDAID[daRelayTestID(250)] = 1, 1
		state.prefetch.indexes[ids[0]][0] = "changed"
		state.prefetch.expires[ids[0]] = time.Time{}
		record = state.sets[ids[0]]
		record.commit.txBytes[0] = 3
		chunk = record.chunks[0]
		chunk.payload[0], chunk.txBytes[0] = 4, 5
		record.chunks[0] = chunk
		state.sets[ids[0]] = record
		if got := before.prefetchIndexes[ids[0]][0]; got != "peer-prefetch-a" {
			t.Fatalf("snapshot nested prefetch key=%q, want peer-prefetch-a", got)
		}
		if got := before.prefetchExpires[ids[0]]; !got.Equal(time.Unix(1, 0)) {
			t.Fatalf("snapshot prefetch expiry=%v, want %v", got, time.Unix(1, 0))
		}
		captured := before.sets[ids[0]]
		if !reflect.DeepEqual(captured.commit.txBytes, []byte{1}) || captured.chunks[0].payload[0] != 1 || !reflect.DeepEqual(captured.chunks[0].txBytes, []byte{2}) || before.peerBytes["peer-ttl"] != wantPeer || before.daIDBytes[ids[0]] != wantDAID || before.peerBytes["alias"] != 0 || before.daIDBytes[daRelayTestID(250)] != 0 || before.mempool != state.mempool || before.caps != state.caps || before.nextReceivedTime != state.nextReceivedTime || before.orphanBytes != state.orphanBytes || before.commitBytes != state.orphanCommitOverheadBytes || before.pinnedPayloadBytes != state.pinnedPayloadBytes {
			t.Fatal("snapshot omitted or aliased mutable state")
		}
		state.mu.Lock()
		projected := state.cloneForAtomicBatchLocked()
		state.mu.Unlock()
		projected.prefetch.indexes[ids[0]][0] = "projected"
		if got := state.prefetch.indexes[ids[0]][0]; got != "changed" || projected.mempool != state.mempool {
			t.Fatalf("projection nested prefetch mutated live value=%q", got)
		}
	})
	t.Run("locked test snapshots preserve complete images", func(t *testing.T) {
		state, expected := newDARelayLockedSnapshotState(t, "peer-ttl"), newDARelayLockedSnapshotState(t, "peer-ttl")
		requireDARelayLockedSnapshotImages(t, state, expected, func(state *DARelayState) error {
			return state.AdvanceOrphanTTL()
		})
	})
}

func TestDARelayReleasePeerQuotaKeyBatchErrorLeavesWholeImageUnchanged(t *testing.T) {
	t.Run("nil and uncharged no-op", func(t *testing.T) {
		if err := (*DARelayState)(nil).ReleasePeerQuotaKey("peer-drop"); err != nil {
			t.Fatalf("nil release: %v", err)
		}
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustAddDAChunk(t, state, "peer-keep", daRelayTestChunk(daRelayTestID(211), 0, 7))
		before := daRelayStateSnapshot(state)
		if err := state.ReleasePeerQuotaKey("peer-drop"); err != nil {
			t.Fatalf("uncharged release: %v", err)
		}
		requireDARelayStateUnchanged(t, state, before)
	})
	t.Run("partial and whole cleanup", func(t *testing.T) {
		state := newDARelayPeerReleaseSuccessState(t)
		twin := newDARelayPeerReleaseSuccessState(t)
		twin.mempool = state.mempool
		twin.mu.Lock()
		wantErr := twin.releasePeerQuotaKeyLocked("peer-drop")
		twin.mu.Unlock()
		if wantErr != nil {
			t.Fatalf("build peer expected image: %v", wantErr)
		}
		completeWant, want := daRelayStateSnapshot(state).sets[daRelayTestID(215)], daRelayStateSnapshot(twin)
		if err := state.ReleasePeerQuotaKey("peer-drop"); err != nil {
			t.Fatalf("release peer: %v", err)
		}
		_, retained := state.sets[daRelayTestID(250)]
		if got := daRelayStateSnapshot(state); !reflect.DeepEqual(got, want) || got.nextReceivedTime != 5 || retained || got.sets[daRelayTestID(213)].state != daRelayStateOrphanChunks || got.sets[daRelayTestID(213)].wireBytes != 11 || got.sets[daRelayTestID(213)].commit.wireBytes != 0 || len(got.sets[daRelayTestID(213)].chunks) != 1 || got.sets[daRelayTestID(213)].chunks[1].peerQuotaKey != "peer-keep" || !reflect.DeepEqual(got.sets[daRelayTestID(215)], completeWant) { //nolint:govet // Complete private state-image equality requires structural comparison.
			t.Fatalf("peer success image=%+v, want %+v", got, want)
		}
	})
	for _, tt := range []struct {
		name  string
		index int
	}{
		{name: "underflow first", index: 0},
		{name: "underflow middle", index: 1},
		{name: "underflow final", index: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			state, ids := newDARelayAtomicBatchState(t, "peer-drop")
			state.orphanBytesByDAID[ids[tt.index]] = 0
			before := daRelayStateSnapshot(state)
			err := state.ReleasePeerQuotaKey("peer-drop")
			if err != errDARelayArithmeticOverflow { //nolint:errorlint // Exact identity is part of the contract.
				t.Fatalf("underflow err=%v, want %v", err, errDARelayArithmeticOverflow)
			}
			requireDARelayStateUnchanged(t, state, before)
		})
	}
	t.Run("overflow after valid prefix", func(t *testing.T) {
		state, ids := newDARelayAtomicBatchState(t, "peer-drop")
		mustAddDAChunk(t, state, "peer-keep", daRelayTestChunk(ids[0], 1, 11))
		record := state.sets[ids[0]]
		record.replaceableChunks = map[uint16]bool{0: true}
		state.sets[ids[0]] = record
		corrupt := daRelayOverflowOrphanAccountingRecord(ids[2])
		corrupt.commit.peerQuotaKey = "peer-keep"
		sibling := corrupt.chunks[0]
		sibling.peerQuotaKey = "peer-keep"
		corrupt.chunks[0] = sibling
		corrupt.chunks[1] = daRelayChunk{daID: ids[2], peerQuotaKey: "peer-drop", chunkIndex: 1, payload: []byte{1}, wireBytes: 1}
		state.sets[ids[2]] = corrupt
		state.orphanBytesByDAID[ids[2]] = corrupt.wireBytes
		before := daRelayStateSnapshot(state)
		err := state.ReleasePeerQuotaKey("peer-drop")
		if err != errDARelayArithmeticOverflow { //nolint:errorlint // Exact identity is part of the contract.
			t.Fatalf("overflow err=%v, want %v", err, errDARelayArithmeticOverflow)
		}
		requireDARelayStateUnchanged(t, state, before)
	})
	t.Run("first error wins", func(t *testing.T) {
		state, _ := newDARelayFirstErrorState(t)
		before := daRelayStateSnapshot(state)
		if err := state.ReleasePeerQuotaKey("peer-drop"); err != errDARelayOrphanPeerCapExceeded { //nolint:errorlint // Exact identity is part of the contract.
			t.Fatalf("first peer err=%v, want %v", err, errDARelayOrphanPeerCapExceeded)
		}
		requireDARelayStateUnchanged(t, state, before)
	})
	t.Run("locked test snapshots preserve complete images", func(t *testing.T) {
		state, expected := newDARelayLockedSnapshotState(t, "peer-drop"), newDARelayLockedSnapshotState(t, "peer-drop")
		requireDARelayLockedSnapshotImages(t, state, expected, func(state *DARelayState) error {
			return state.ReleasePeerQuotaKey("peer-drop")
		})
	})
}

// removeCompleteDASetForTest removes one retained COMPLETE_SET through
// removeDASetRecordLocked — the SAME locked removal primitive the canonical D
// image applies to its clone — and reports whether a complete record was there
// to remove.
//
// It exists because the exported ConsumeCompleteSet wrapper was deleted with its
// post-return caller: retained-DA removal is now selected inside the canonical
// transition, and this file's remaining rows are unit coverage of the removal
// primitive's accounting, not of a public writer. It is test scaffolding and
// confers no production authority; which records a canonical transition actually
// selects is pinned in sync_da_relay_test.go.
func removeCompleteDASetForTest(t *testing.T, state *DARelayState, daID [32]byte) bool {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	record, ok := state.sets[daID]
	if !ok || record.state != daRelayStateCompleteSet {
		return false
	}
	if err := state.removeDASetRecordLocked(record); err != nil {
		t.Fatalf("removeDASetRecordLocked(%x): %v", daID, err)
	}
	return true
}

func TestDARelayRemoveCompleteSetRemovesRecordAndPinnedAccounting(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	consumeID := daRelayTestID(99)
	keepID := daRelayTestID(100)
	consumePayload := []byte("consume-payload")
	missingPayload := []byte("missing")
	keepPayload := []byte("keep-payload")

	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(consumeID, 2, consumePayload, missingPayload))
	plans, diagnostic := state.PlanPrefetch(consumeID, []string{"peer-prefetch"}, time.Unix(1, 0))
	if diagnostic != "" || len(plans) != 1 {
		t.Fatalf("prefetch setup plans=%+v diagnostic=%q, want one plan", plans, diagnostic)
	}
	if got, _ := state.prefetch.bytesInFlight(); got == 0 {
		t.Fatal("prefetch setup did not reserve bytes")
	}
	state.ReleasePrefetchPlan(plans[0])
	if got, _ := state.prefetch.bytesInFlight(); got != 0 {
		t.Fatalf("released prefetch bytes=%d, want 0", got)
	}
	plans, diagnostic = state.PlanPrefetch(consumeID, []string{"peer-prefetch"}, time.Unix(1, 0))
	if diagnostic != "" || len(plans) != 1 {
		t.Fatalf("prefetch replan plans=%+v diagnostic=%q, want one plan", plans, diagnostic)
	}
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(consumeID, 0, uint64(len(consumePayload)), consumePayload))
	consumeRecord := mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(consumeID, 1, uint64(len(missingPayload)), missingPayload))
	consumePinned := mustPinnedPayloadAccounting(t, consumeRecord)
	mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(keepID, 3, keepPayload))
	keepRecord := mustAddDAChunk(t, state, "peer-d", daRelayTestChunkPayload(keepID, 0, uint64(len(keepPayload)), keepPayload))
	keepPinned := mustPinnedPayloadAccounting(t, keepRecord)
	if state.pinnedPayloadBytes != consumePinned+keepPinned {
		t.Fatalf("setup pinned=%d, want %d", state.pinnedPayloadBytes, consumePinned+keepPinned)
	}

	if !removeCompleteDASetForTest(t, state, consumeID) {
		t.Fatal("complete set was not present to remove")
	}
	if _, ok := state.sets[consumeID]; ok {
		t.Fatalf("removed complete set retained da_id")
	}
	if got := state.sets[keepID]; got.state != daRelayStateCompleteSet {
		t.Fatalf("unrelated complete set state=%v, want complete", got.state)
	}
	if state.pinnedPayloadBytes != keepPinned {
		t.Fatalf("pinned after removal=%d, want %d", state.pinnedPayloadBytes, keepPinned)
	}
	if _, ok := state.prefetch.indexes[consumeID]; ok {
		t.Fatal("removal retained da_id prefetch indexes")
	}
	if _, ok := state.prefetch.expires[consumeID]; ok {
		t.Fatal("removal retained da_id prefetch expiry")
	}
	if got, _ := state.prefetch.bytesInFlight(); got != 0 {
		t.Fatalf("prefetch bytes in flight after removal=%d, want 0", got)
	}

	if removeCompleteDASetForTest(t, state, consumeID) {
		t.Fatal("second removal reported an already-removed da_id as present")
	}
	if state.pinnedPayloadBytes != keepPinned {
		t.Fatalf("pinned after second removal=%d, want %d", state.pinnedPayloadBytes, keepPinned)
	}
}

func TestDARelayRemoveSetRecordReturnsPinnedProjectionErrorWithoutMutation(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	daID := daRelayTestID(99)
	record := daRelaySetRecord{
		daID:         daID,
		state:        daRelayStateCompleteSet,
		payloadBytes: 1,
	}
	state.sets[daID] = record
	state.prefetch.indexes = map[[32]byte]map[uint16]string{daID: {0: "peer-prefetch"}}
	state.prefetch.expires = map[[32]byte]time.Time{daID: time.Unix(1, 0)}

	state.mu.Lock()
	err := state.removeDASetRecordLocked(record)
	state.mu.Unlock()
	requireDAErr(t, err, errDARelayArithmeticOverflow)
	if _, ok := state.sets[daID]; !ok {
		t.Fatal("failed remove deleted corrupt complete record")
	}
	// The prefetch release is the LAST step of removeDASetRecordLocked, after
	// every checked projection, so a refused removal must not have reached it.
	if _, ok := state.prefetch.indexes[daID]; !ok {
		t.Fatal("failed remove released prefetch indexes")
	}
	if _, ok := state.prefetch.expires[daID]; !ok {
		t.Fatal("failed remove released prefetch expiry")
	}
}

func TestDARelayRejectedCandidatesDoNotMutateStoredChunks(t *testing.T) {
	daID := daRelayTestID(5)
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 0, 1))
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunk(daID, 2, 1))
	state.caps.orphanCommitOverheadBytes = 1
	err := state.addDACommit("peer-b", daRelayTestCommit(daID, 2, 2))
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
	err = state.addDAChunk("peer-b", chunk)
	requireDAErr(t, err, errDARelayOrphanDAIDCapExceeded)
	if _, ok := state.sets[daID].chunks[1]; ok {
		t.Fatalf("failed chunk insert mutated stored staged record")
	}
	chunk.chunkIndex = 2
	chunk.chunkHash[0] ^= 0xff
	err = state.addDAChunk("peer-b", chunk)
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
	if len(record.chunks[0].payload) != 0 || len(state.sets[daID].chunks[0].payload) != 0 {
		t.Fatalf("complete set retained chunk payload copy")
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
	err := cappedState.addDACommit("peer-c", daRelayTestCommitForPayloads(daID, 1, payload0))
	requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
	if cappedState.sets[daID].commit.chunkCount != 0 || cappedState.pinnedPayloadBytes != 0 {
		t.Fatalf("pinned cap rejection mutated commit=%d pinned=%d", cappedState.sets[daID].commit.chunkCount, cappedState.pinnedPayloadBytes)
	}
}

func TestDARelayCompleteSetCandidatesExposeOnlyCompleteImmutableOrdered(t *testing.T) {
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	orphanID, stagedID := daRelayTestID(31), daRelayTestID(32)
	lateID, earlyID := daRelayTestID(33), daRelayTestID(30)
	missingCommitID, missingChunkID := daRelayTestID(34), daRelayTestID(35)
	earlyPayload0, earlyPayload1 := []byte("early-0"), []byte("early-1")
	latePayload := []byte("late")

	mustAddDAChunk(t, state, "peer-o", daRelayTestChunkWithTxBytes(orphanID, 0, 6, []byte("chunk-orphan"), []byte("orphan")))
	mustAddDACommit(t, state, "peer-s", daRelayTestCommitWithTxBytes(stagedID, 6, []byte("commit-staged"), []byte("staged")))
	mustAddDACommit(t, state, "peer-l", daRelayTestCommitWithTxBytes(lateID, 7, []byte("commit-late"), latePayload))
	mustAddDAChunk(t, state, "peer-l", daRelayTestChunkWithTxBytes(lateID, 0, uint64(len(latePayload)), []byte("chunk-late"), latePayload))
	mustAddDACommit(t, state, "peer-e", daRelayTestCommitWithTxBytes(earlyID, 8, []byte("commit-early"), earlyPayload0, earlyPayload1))
	for _, chunk := range []daRelayChunk{
		daRelayTestChunkWithTxBytes(earlyID, 1, uint64(len(earlyPayload1)), []byte("chunk-early-1"), earlyPayload1),
		daRelayTestChunkWithTxBytes(earlyID, 0, uint64(len(earlyPayload0)), []byte("chunk-early-0"), earlyPayload0),
	} {
		mustAddDAChunk(t, state, "peer-e", chunk)
	}
	mustAddDACommit(t, state, "peer-mc", daRelayTestCommitForPayloads(missingCommitID, 1, latePayload))
	mustAddDAChunk(t, state, "peer-mc", daRelayTestChunkWithTxBytes(missingCommitID, 0, uint64(len(latePayload)), []byte("chunk-only"), latePayload))
	mustAddDACommit(t, state, "peer-mk", daRelayTestCommitWithTxBytes(missingChunkID, 1, []byte("commit-only"), latePayload))
	mustAddDAChunk(t, state, "peer-mk", daRelayTestChunkPayload(missingChunkID, 0, uint64(len(latePayload)), latePayload))
	if state.sets[missingCommitID].state != daRelayStateCompleteSet || state.sets[missingChunkID].state != daRelayStateCompleteSet {
		t.Fatal("invalid candidate fixtures are not complete")
	}

	candidates := state.CompleteSetCandidates(^uint64(0))
	if len(candidates) != 2 {
		t.Fatalf("complete candidates=%d, want 2", len(candidates))
	}
	if candidates[0].DAID != earlyID || candidates[1].DAID != lateID {
		t.Fatalf("candidate order=%x,%x want %x,%x", candidates[0].DAID, candidates[1].DAID, earlyID, lateID)
	}
	if got := candidates[0].PayloadBytes; got != uint64(len(earlyPayload0)+len(earlyPayload1)) {
		t.Fatalf("early payload bytes=%d, want %d", got, len(earlyPayload0)+len(earlyPayload1))
	}
	if !reflect.DeepEqual(candidates[0].CommitTx, []byte("commit-early")) {
		t.Fatalf("early commit tx=%q", candidates[0].CommitTx)
	}
	if len(candidates[0].Chunks) != 2 || candidates[0].Chunks[0].Index != 0 || candidates[0].Chunks[1].Index != 1 {
		t.Fatalf("early chunks=%+v, want indexes 0,1", candidates[0].Chunks)
	}
	candidates[0].CommitTx[0] = 'X'
	candidates[0].Chunks[0].Tx[0] = 'Y'
	again := state.CompleteSetCandidates(^uint64(0))
	if !reflect.DeepEqual(again[0].CommitTx, []byte("commit-early")) || !reflect.DeepEqual(again[0].Chunks[0].Tx, []byte("chunk-early-0")) {
		t.Fatalf("candidate snapshot aliases state: commit=%q chunk=%q", again[0].CommitTx, again[0].Chunks[0].Tx)
	}
	earlyPayloadBytes := uint64(len(earlyPayload0) + len(earlyPayload1))
	if got := state.CompleteSetCandidates(earlyPayloadBytes); len(got) != 1 || got[0].DAID != earlyID {
		t.Fatalf("bounded candidates=%+v, want only early da_id", got)
	}
	latePayloadBytes := uint64(len(latePayload))
	if got := state.CompleteSetCandidates(latePayloadBytes); len(got) != 1 || got[0].DAID != lateID {
		t.Fatalf("oversized early candidate blocked later fit=%+v, want only late da_id", got)
	}
}

func TestDARelayCompleteSetCandidatesNilSafe(t *testing.T) {
	if got := (*DARelayState)(nil).CompleteSetCandidates(1); got != nil {
		t.Fatalf("nil state candidates=%v, want nil", got)
	}
}

func TestDARelayPublicBoundaryNoopRows(t *testing.T) {
	if (*SyncEngine)(nil).DARelayState() != nil {
		t.Fatal("nil engine returned DA relay state")
	}
	if err := (*DARelayState)(nil).ReleasePeerQuotaKey("peer"); err != nil {
		t.Fatalf("nil state release: %v", err)
	}
	requireDAErr(t, ValidateDARelayChunk(DARelayChunk{}), errDARelayChunkPayloadSizeInvalid)
	payload := []byte("valid")
	if err := ValidateDARelayChunk(DARelayChunk{ChunkHash: sha3.Sum256(payload), Payload: payload, WireBytes: uint64(len(payload))}); err != nil {
		t.Fatalf("valid public chunk: %v", err)
	}
}

func TestDARelayCloneModesKeepStateCopiesShallowAndCallerCopiesDeep(t *testing.T) {
	daID := daRelayTestID(7)
	record := daRelaySetRecord{
		daID:   daID,
		commit: daRelayCommit{txBytes: []byte("commit-tx")},
		chunks: map[uint16]daRelayChunk{
			0: daRelayTestChunkWithTxBytes(daID, 0, 17, []byte("chunk-tx"), []byte("immutable-payload")),
		},
		replaceableChunks: map[uint16]bool{0: true},
	}

	stateClone := record.cloneForStateMutation()
	originalChunk := record.chunks[0]
	stateChunk := stateClone.chunks[0]
	if &stateChunk.payload[0] != &originalChunk.payload[0] {
		t.Fatalf("state mutation clone deep-copied payload")
	}
	if &stateChunk.txBytes[0] != &originalChunk.txBytes[0] {
		t.Fatalf("state mutation clone deep-copied tx bytes")
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
	if callerClone.commit.txBytes != nil || callerChunk.txBytes != nil {
		t.Fatalf("caller clone exposed internal tx bytes")
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
	requireDAErr(t, ValidateDARelayChunk(DARelayChunk{
		DAID: daID, ChunkHash: badChunk.chunkHash, Payload: badChunk.payload, WireBytes: badChunk.wireBytes,
	}), ErrDARelayChunkHashMismatch)
	err := state.addDAChunk("peer-a", badChunk)
	requireDAErr(t, err, errDARelayChunkHashMismatch)
	if len(state.sets) != 0 {
		t.Fatalf("hash mismatch mutated state")
	}
	err = state.addDAChunk("peer-a", daRelayTestChunkPayload(daID, 0, 1, nil))
	requireDAErr(t, err, errDARelayChunkPayloadSizeInvalid)
	err = state.addDAChunk("peer-a", daRelayTestChunkPayload(daID, 0, 1, make([]byte, consensus.CHUNK_BYTES+1)))
	requireDAErr(t, err, errDARelayChunkPayloadSizeInvalid)
	err = state.addDAChunk("peer-a", daRelayTestChunkPayload(daID, 0, 1, []byte("underreported")))
	requireDAErr(t, err, errDARelayWireBytesInvalid)
	err = state.addDACommit("peer-a", daRelayTestCommit(daID, 1, 0))
	requireDAErr(t, err, errDARelayWireBytesInvalid)
	if len(state.sets) != 0 {
		t.Fatalf("shape rejection mutated state")
	}

	payload0 := []byte("payload-a")
	payload1 := []byte("payload-b")
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
	err = state.addDACommit("peer-b", daRelayTestCommitForPayloads(daID, 1, payload1, payload0))
	requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
	record := state.sets[daID]
	if record.state != daRelayStateStagedCommit || record.commit.chunkCount != 2 || len(record.chunks) != 0 || state.orphanBytes != record.wireBytes || state.pinnedPayloadBytes != 0 {
		t.Fatalf("commitment mismatch failed to preserve first commit cleanly: state=%v commit=%d chunks=%d orphan=%d record=%d pinned=%d", record.state, record.commit.chunkCount, len(record.chunks), state.orphanBytes, record.wireBytes, state.pinnedPayloadBytes)
	}
	err = state.addDACommit("peer-d", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
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
	err = state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
	requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
	record = state.sets[daID]
	if _, ok := record.replaceableChunks[0]; ok || len(record.chunks) != 1 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("partial chunk mismatch tainted stale chunk replacement: replaceable=%v chunks=%d pinned=%d", record.replaceableChunks, len(record.chunks), state.pinnedPayloadBytes)
	}
	if state.nextReceivedTime != beforeMismatchTime || record.receivedTime != beforeMismatchTime {
		t.Fatalf("partial chunk mismatch time record=%d state=%d want first-seen %d", record.receivedTime, state.nextReceivedTime, beforeMismatchTime)
	}
	err = state.addDAChunk("peer-d", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	requireDAErr(t, err, errDARelayDuplicateChunk)

	state = newDARelayStateForTest(t, defaultDARelayCaps())
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
	mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	err = state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), []byte("payload-x")))
	requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
	if state.sets[daID].state != daRelayStateStagedCommit || len(state.sets[daID].chunks) != 1 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("chunk mismatch mutated staged chunks: state=%v chunks=%d pinned=%d", state.sets[daID].state, len(state.sets[daID].chunks), state.pinnedPayloadBytes)
	}
	record = mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), payload1))
	if record.state != daRelayStateCompleteSet {
		t.Fatalf("state after partial mismatch recovery=%v, want COMPLETE_SET", record.state)
	}
	if _, ok := record.replaceableChunks[0]; ok {
		t.Fatalf("partial mismatch marked valid chunk replaceable: replaceable=%v", record.replaceableChunks)
	}

	caps := defaultDARelayCaps()
	caps.pinnedPayloadBytes = 1
	state = newDARelayStateForTest(t, caps)
	mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0))
	err = state.addDAChunk("peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
	requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
	if state.sets[daID].state != daRelayStateStagedCommit || len(state.sets[daID].chunks) != 0 || state.pinnedPayloadBytes != 0 {
		t.Fatalf("pinned cap rejection mutated state: state=%v chunks=%d pinned=%d", state.sets[daID].state, len(state.sets[daID].chunks), state.pinnedPayloadBytes)
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

		err := state.addDACommit("peer-b", daRelayTestCommitForPayloads(daID, 1, payload))
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

		err := state.addDAChunk("peer-b", daRelayTestChunkPayload(daID, 0, 1, payload))
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
		state.orphanBytesByPeerQuotaKey["peer-a"] = 0

		err := state.addDACommit("peer-b", daRelayTestCommitForPayloads(daID, 1, payload1, payload0))
		requireDAErr(t, err, errDARelayArithmeticOverflow)

		record := state.sets[daID]
		if record.commit.chunkCount != 0 || len(record.chunks) != 2 {
			t.Fatalf("commit mismatch apply failure mutated record: commit=%d chunks=%d", record.commit.chunkCount, len(record.chunks))
		}
	})

	t.Run("chunk partial mismatch skips replaceable apply", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(58)
		payload0 := []byte("payload-a")
		payload1 := []byte("payload-b")
		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, payload0, payload1))
		mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(payload0)), payload0))
		state.orphanBytesByPeerQuotaKey["peer-b"] = 0

		err := state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(payload1)), []byte("wrong")))
		requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)

		record := state.sets[daID]
		if _, ok := record.replaceableChunks[0]; ok || len(record.chunks) != 1 || record.state != daRelayStateStagedCommit {
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
	staged, _, err := state.stageDAChunkRecordLocked("peer-b", chunk, chunk.payload, false)
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

func TestDARelayCompletionTransitionsRejectStaleSnapshots(t *testing.T) {
	t.Run("commit last", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(123)
		first, second := []byte("first"), []byte("second")
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(first)), first))
		mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 1, uint64(len(second)), second))
		commit, txBytesOwned := daRelayTestCommitForPayloads(daID, 1, first, second), false

		_, snapshot, complete, err := state.stageDACommitForCompletion("peer-c", &commit, &txBytesOwned)
		if err != nil || !complete {
			t.Fatalf("capture commit-last snapshot complete=%v err=%v", complete, err)
		}
		if err := state.ReleasePeerQuotaKey("peer-a"); err != nil {
			t.Fatalf("release snapshotted chunk: %v", err)
		}
		payloadBytes, _ := snapshot.payloadCommitment()
		_, retry, err := state.completeDACommitSnapshot("peer-c", &commit, &txBytesOwned, snapshot, payloadBytes)
		if err != nil || !retry {
			t.Fatalf("stale commit completion retry=%v err=%v, want true nil", retry, err)
		}
		record := state.sets[daID]
		if record.state == daRelayStateCompleteSet || record.commit.chunkCount != 0 || len(record.chunks) != 1 {
			t.Fatalf("stale commit published record=%+v", record)
		}
	})

	t.Run("chunk last", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(124)
		first, second := []byte("first"), []byte("second")
		mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(daID, 1, first, second))
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(first)), first))
		chunk, txBytesOwned := daRelayTestChunkPayload(daID, 1, uint64(len(second)), second), false
		payload := cloneBytes(chunk.payload)

		_, snapshot, complete, err := state.stageDAChunkForCompletion("peer-b", &chunk, payload, &txBytesOwned)
		if err != nil || !complete {
			t.Fatalf("capture chunk-last snapshot complete=%v err=%v", complete, err)
		}
		if err := state.ReleasePeerQuotaKey("peer-a"); err != nil {
			t.Fatalf("release snapshotted chunk: %v", err)
		}
		payloadBytes, _ := snapshot.payloadCommitment()
		_, retry, err := state.completeDAChunkSnapshot("peer-b", &chunk, payload, &txBytesOwned, snapshot, payloadBytes)
		if err != nil || !retry {
			t.Fatalf("stale chunk completion retry=%v err=%v, want true nil", retry, err)
		}
		record := state.sets[daID]
		if record.state != daRelayStateStagedCommit || record.commit.chunkCount != 2 || len(record.chunks) != 0 {
			t.Fatalf("stale chunk published record=%+v", record)
		}
	})
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

// TestDARelayPinnedPayloadAccountingUsesPayloadBytesOnly pins RUB-664: a
// retained COMPLETE_SET contributes exactly payloadBytes — the sum of its
// DA_CHUNK payload lengths — to the pinned relay cap, because
// RUBIN_COMPACT_BLOCKS §5.1 counts DA payload bytes only. Commit metadata,
// retained tx bytes, wire envelope overhead and chunk count never consume the
// cap, and admission projection, the committed counter and release all use
// that one value. Release underflow is pinned by
// TestDARelayRemoveSetRecordReturnsPinnedProjectionErrorWithoutMutation.
func TestDARelayPinnedPayloadAccountingUsesPayloadBytesOnly(t *testing.T) {
	whole := []byte("0123456789abcdef")
	head, tail := []byte("0123456789"), []byte("abcdef")
	wantPayload := uint64(len(whole))

	t.Run("incomplete and zero-payload records contribute zero", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		orphanID, stagedID := daRelayTestID(110), daRelayTestID(111)
		mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(orphanID, 0, wantPayload, whole))
		mustAddDACommit(t, state, "peer-b", daRelayTestCommitForPayloads(stagedID, 4096, head, tail))
		for _, daID := range [][32]byte{orphanID, stagedID} {
			if got := mustPinnedPayloadAccounting(t, state.sets[daID]); got != 0 {
				t.Fatalf("incomplete %x contribution=%d, want 0", daID, got)
			}
		}
		defensive := daRelaySetRecord{state: daRelayStateCompleteSet, wireBytes: 1 << 20, commit: daRelayCommit{chunkCount: 8, txBytes: []byte("commit-tx-bytes")}}
		if got := mustPinnedPayloadAccounting(t, defensive); got != 0 {
			t.Fatalf("zero-payload COMPLETE_SET contribution=%d, want 0", got)
		}
		if state.pinnedPayloadBytes != 0 {
			t.Fatalf("incomplete records pinned=%d, want 0", state.pinnedPayloadBytes)
		}
	})

	t.Run("complete sets contribute the payload sum whatever the metadata", func(t *testing.T) {
		stagers := []struct {
			name  string
			stage func(state *DARelayState, daID [32]byte) daRelaySetRecord
		}{
			{
				name: "chunk last, one chunk",
				stage: func(state *DARelayState, daID [32]byte) daRelaySetRecord {
					mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 1, whole))
					return mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, wantPayload, whole))
				},
			},
			{
				name: "commit last, two chunks, oversized commit wire bytes",
				stage: func(state *DARelayState, daID [32]byte) daRelaySetRecord {
					mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 0, uint64(len(head)), head))
					mustAddDAChunk(t, state, "peer-a", daRelayTestChunkPayload(daID, 1, uint64(len(tail)), tail))
					return mustAddDACommit(t, state, "peer-b", daRelayTestCommitForPayloads(daID, 4096, head, tail))
				},
			},
			{
				name: "chunk last, two chunks, retained tx bytes",
				stage: func(state *DARelayState, daID [32]byte) daRelaySetRecord {
					mustAddDACommit(t, state, "peer-a", daRelayTestCommitWithTxBytes(daID, 9, []byte("commit-tx-bytes"), head, tail))
					mustAddDAChunk(t, state, "peer-b", daRelayTestChunkWithTxBytes(daID, 0, uint64(len(head)), []byte("chunk-tx-bytes-0"), head))
					return mustAddDAChunk(t, state, "peer-b", daRelayTestChunkWithTxBytes(daID, 1, uint64(len(tail)), []byte("chunk-tx-bytes-1"), tail))
				},
			},
		}
		wireSeen := map[uint64]bool{}
		for _, stager := range stagers {
			state := newDARelayStateForTest(t, defaultDARelayCaps())
			daID := daRelayTestID(112)
			record := stager.stage(state, daID)
			if record.state != daRelayStateCompleteSet || record.payloadBytes != wantPayload {
				t.Fatalf("%s: state=%v payloadBytes=%d, want COMPLETE_SET %d", stager.name, record.state, record.payloadBytes, wantPayload)
			}
			if got := mustPinnedPayloadAccounting(t, record); got != wantPayload {
				t.Fatalf("%s: contribution=%d, want %d", stager.name, got, wantPayload)
			}
			if state.pinnedPayloadBytes != wantPayload {
				t.Fatalf("%s: committed pinned=%d, want %d", stager.name, state.pinnedPayloadBytes, wantPayload)
			}
			wireSeen[record.wireBytes] = true
		}
		if len(wireSeen) < 2 {
			t.Fatalf("rows shared one retained wire footprint %v, want differing metadata", wireSeen)
		}
	})

	t.Run("exact cap admits and cap plus one rejects atomically", func(t *testing.T) {
		caps := defaultDARelayCaps()
		caps.pinnedPayloadBytes = wantPayload + uint64(len(head))
		state := newDARelayStateForTest(t, caps)
		firstID, exactID, rejectID := daRelayTestID(113), daRelayTestID(114), daRelayTestID(115)

		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(firstID, 4096, head, tail))
		mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(firstID, 0, uint64(len(head)), head))
		record := mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(firstID, 1, uint64(len(tail)), tail))
		if record.state != daRelayStateCompleteSet || state.pinnedPayloadBytes != wantPayload {
			t.Fatalf("first admit state=%v pinned=%d, want COMPLETE_SET %d", record.state, state.pinnedPayloadBytes, wantPayload)
		}

		// previous_pinned + payloadBytes == cap is admitted and commits exactly the cap.
		mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(exactID, 1, head))
		record = mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(exactID, 0, uint64(len(head)), head))
		if record.state != daRelayStateCompleteSet || state.pinnedPayloadBytes != caps.pinnedPayloadBytes {
			t.Fatalf("exact cap state=%v pinned=%d, want COMPLETE_SET %d", record.state, state.pinnedPayloadBytes, caps.pinnedPayloadBytes)
		}

		// The same exact-cap landing reached commit-last, after releasing the chunk-last one.
		if !removeCompleteDASetForTest(t, state, exactID) {
			t.Fatal("release before commit-last exact cap found no complete set")
		}
		commitLastID := daRelayTestID(121)
		mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(commitLastID, 0, uint64(len(head)), head))
		record = mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(commitLastID, 1, head))
		if record.state != daRelayStateCompleteSet || state.pinnedPayloadBytes != caps.pinnedPayloadBytes {
			t.Fatalf("commit-last exact cap state=%v pinned=%d, want COMPLETE_SET %d", record.state, state.pinnedPayloadBytes, caps.pinnedPayloadBytes)
		}

		// One byte past the cap is rejected before any record or counter moves.
		mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(rejectID, 1, []byte{7}))
		before := daRelayStateSnapshot(state)
		err := state.addDAChunk("peer-d", daRelayTestChunkPayload(rejectID, 0, 1, []byte{7}))
		requireDAErr(t, err, errDARelayPinnedPayloadCapExceeded)
		if got := daRelayStateSnapshot(state); !reflect.DeepEqual(got, before) {
			t.Fatalf("rejected admission mutated state: got=%+v want=%+v", got, before)
		}
	})

	t.Run("integrity mismatch stays staged and unpinned until a valid retry", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		daID := daRelayTestID(120)
		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(daID, 2, head, tail))
		mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(daID, 0, uint64(len(head)), head))
		err := state.addDAChunk("peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(tail)), []byte("ABCDEF")))
		requireDAErr(t, err, errDARelayPayloadCommitmentMismatch)
		if state.sets[daID].state != daRelayStateStagedCommit || state.pinnedPayloadBytes != 0 {
			t.Fatalf("mismatch state=%v pinned=%d, want staged 0", state.sets[daID].state, state.pinnedPayloadBytes)
		}
		record := mustAddDAChunk(t, state, "peer-c", daRelayTestChunkPayload(daID, 1, uint64(len(tail)), tail))
		if record.state != daRelayStateCompleteSet || state.pinnedPayloadBytes != wantPayload {
			t.Fatalf("retry state=%v pinned=%d, want COMPLETE_SET %d", record.state, state.pinnedPayloadBytes, wantPayload)
		}
	})

	t.Run("release subtracts exactly payloadBytes once", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		consumeID, keepID, stagedID := daRelayTestID(116), daRelayTestID(117), daRelayTestID(118)
		mustAddDACommit(t, state, "peer-a", daRelayTestCommitForPayloads(consumeID, 4096, whole))
		mustAddDAChunk(t, state, "peer-b", daRelayTestChunkPayload(consumeID, 0, wantPayload, whole))
		mustAddDACommit(t, state, "peer-c", daRelayTestCommitForPayloads(keepID, 1, head))
		mustAddDAChunk(t, state, "peer-d", daRelayTestChunkPayload(keepID, 0, uint64(len(head)), head))
		mustAddDACommit(t, state, "peer-e", daRelayTestCommit(stagedID, 1, 1))
		wantKeep := uint64(len(head))
		if state.pinnedPayloadBytes != wantPayload+wantKeep {
			t.Fatalf("staged pinned=%d, want %d", state.pinnedPayloadBytes, wantPayload+wantKeep)
		}

		if !removeCompleteDASetForTest(t, state, consumeID) || state.pinnedPayloadBytes != wantKeep {
			t.Fatalf("first release pinned=%d, want %d", state.pinnedPayloadBytes, wantKeep)
		}
		// Already removed, never present, and present-but-incomplete: none of the
		// three is a complete record, so the release refuses. The REFUSAL is the
		// whole observable here — the helper's own state guard returns before
		// removeDASetRecordLocked, so a counter or record-state assertion on this
		// path could not be made to fail.
		for _, daID := range [][32]byte{consumeID, daRelayTestID(119), stagedID} {
			if removeCompleteDASetForTest(t, state, daID) {
				t.Fatalf("no-op release %x reported a complete record", daID)
			}
		}
	})

	t.Run("apply fails on projected counter overflow before the cap check", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		state.pinnedPayloadBytes = 1
		corrupt := daRelaySetRecord{daID: daRelayTestID(122), state: daRelayStateCompleteSet, payloadBytes: ^uint64(0)}
		before := daRelayStateSnapshot(state)
		state.mu.Lock()
		err := state.applyDASetRecordLocked(corrupt)
		state.mu.Unlock()
		requireDAErr(t, err, errDARelayArithmeticOverflow)
		if got := daRelayStateSnapshot(state); !reflect.DeepEqual(got, before) {
			t.Fatalf("failed apply mutated state: got=%+v want=%+v", got, before)
		}
	})
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

func daRelayTestCommitWithTxBytes(daID [32]byte, wireBytes uint64, txBytes []byte, payloads ...[]byte) daRelayCommit {
	commit := daRelayTestCommitForPayloads(daID, wireBytes, payloads...)
	commit.txBytes = cloneBytes(txBytes)
	return commit
}

func daRelayTestChunkWithTxBytes(daID [32]byte, index uint16, wireBytes uint64, txBytes []byte, payload []byte) daRelayChunk {
	chunk := daRelayTestChunkPayload(daID, index, wireBytes, payload)
	chunk.txBytes = cloneBytes(txBytes)
	return chunk
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

func newDARelayStateForTest(t *testing.T, caps daRelayCaps) *DARelayState {
	t.Helper()
	state, err := newDARelayState(nil, caps)
	if err != nil {
		t.Fatalf("new DA relay state: %v", err)
	}
	return state
}

func mustAddDAChunk(t *testing.T, state *DARelayState, peer string, chunk daRelayChunk) daRelaySetRecord {
	t.Helper()
	if err := state.StageChunk(peer, DARelayChunk{
		DAID: chunk.daID, ChunkHash: chunk.chunkHash, ChunkIndex: chunk.chunkIndex, Payload: chunk.payload,
		WireBytes: chunk.wireBytes, TxBytes: chunk.txBytes, HashChecked: chunk.hashChecked,
	}); err != nil {
		t.Fatalf("add DA chunk: %v", err)
	}
	return state.sets[chunk.daID].clone()
}

func mustAddDACommit(t *testing.T, state *DARelayState, peer string, commit daRelayCommit) daRelaySetRecord {
	t.Helper()
	if err := state.StageCommit(peer, DARelayCommit{
		DAID: commit.daID, PayloadCommitment: commit.payloadCommitment, ChunkCount: commit.chunkCount,
		WireBytes: commit.wireBytes, TxBytes: commit.txBytes,
	}); err != nil {
		t.Fatalf("add DA commit: %v", err)
	}
	return state.sets[commit.daID].clone()
}

func requireDAErr(t *testing.T, got error, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("err=%v, want %v", got, want)
	}
}

func requireAddDAChunkErrWithin(t *testing.T, state *DARelayState, peer string, chunk daRelayChunk, want error) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		err := state.addDAChunk(peer, chunk)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		requireDAErr(t, err, want)
	case <-time.After(2 * time.Second):
		t.Fatal("add DA chunk did not return")
	}
}

// daRelayStateView deep-copies every mutable DARelayState accounting field so a
// rejected operation can be compared against the whole prior state, matching
// the Rust mirror's `assert_eq!(state, before)`.
type daRelayStateView struct {
	mempool            *Mempool
	caps               daRelayCaps
	prefetchIndexes    map[[32]byte]map[uint16]string
	prefetchExpires    map[[32]byte]time.Time
	nextReceivedTime   uint64
	orphanBytes        uint64
	commitBytes        uint64
	pinnedPayloadBytes uint64
	peerBytes          map[string]uint64
	daIDBytes          map[[32]byte]uint64
	sets               map[[32]byte]daRelaySetRecord
	locators           map[[32]byte]daRelayLocator
	records            uint64
}

func daRelayStateSnapshot(state *DARelayState) daRelayStateView {
	state.mu.Lock()
	defer state.mu.Unlock()

	view := daRelayStateView{
		mempool:            state.mempool,
		caps:               state.caps,
		prefetchIndexes:    cloneDARelayPrefetchIndexes(state.prefetch.indexes),
		prefetchExpires:    maps.Clone(state.prefetch.expires),
		nextReceivedTime:   state.nextReceivedTime,
		orphanBytes:        state.orphanBytes,
		commitBytes:        state.orphanCommitOverheadBytes,
		pinnedPayloadBytes: state.pinnedPayloadBytes,
		peerBytes:          maps.Clone(state.orphanBytesByPeerQuotaKey),
		daIDBytes:          maps.Clone(state.orphanBytesByDAID),
		sets:               make(map[[32]byte]daRelaySetRecord, len(state.sets)),
		locators:           maps.Clone(state.locators),
		records:            state.records,
	}
	for daID, record := range state.sets {
		// cloneOwnerReady, not cloneForStateMutation: it copies every byte slice
		// and member, so an in-place edit through either stays visible to
		// requireDARelayStateUnchanged.
		view.sets[daID] = record.cloneOwnerReady()
	}
	return view
}

func cloneDARelayPrefetchIndexes(indexes map[[32]byte]map[uint16]string) map[[32]byte]map[uint16]string {
	clone := maps.Clone(indexes)
	for daID, reservations := range clone {
		clone[daID] = maps.Clone(reservations)
	}
	return clone
}

func requireDARelayStateUnchanged(t *testing.T, state *DARelayState, before daRelayStateView) {
	t.Helper()
	if got := daRelayStateSnapshot(state); !reflect.DeepEqual(got, before) { //nolint:govet // Complete private state-image equality requires structural comparison.
		t.Fatalf("state mutated: got=%+v want=%+v", got, before)
	}
}

func newDARelayAtomicBatchState(t *testing.T, peer string) (*DARelayState, [3][32]byte) {
	t.Helper()
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	state.mempool = &Mempool{}
	state.caps.orphanTTLBlocks = 1
	ids := [3][32]byte{daRelayTestID(221), daRelayTestID(222), daRelayTestID(223)}
	for _, daID := range ids {
		mustAddDAChunk(t, state, peer, daRelayTestChunk(daID, 0, 7))
	}
	record := mustAddDACommit(t, state, peer, daRelayTestCommit([32]byte{222, 1}, 1, 5))
	record.ttlBlocksRemaining = 2
	state.sets[record.daID] = record
	completeID, payload := daRelayTestID(225), []byte{1}
	mustAddDACommit(t, state, peer, daRelayTestCommitForPayloads(completeID, 1, payload))
	mustAddDAChunk(t, state, peer, daRelayTestChunkPayload(completeID, 0, 1, payload))
	state.prefetch.indexes = map[[32]byte]map[uint16]string{
		ids[0]: {0: "peer-prefetch-a", 1: "peer-prefetch-b"},
		ids[1]: {2: "peer-prefetch-c"},
	}
	state.prefetch.expires = map[[32]byte]time.Time{
		ids[0]: time.Unix(1, 0),
		ids[1]: time.Unix(2, 0),
	}
	return state, ids
}

func newDARelayPeerReleaseSuccessState(t *testing.T) *DARelayState {
	t.Helper()
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	state.mempool = &Mempool{}
	wholeID, partialID, keepID, completeID := daRelayTestID(212), daRelayTestID(213), daRelayTestID(214), daRelayTestID(215)
	mustAddDAChunk(t, state, "peer-drop", daRelayTestChunk(wholeID, 0, 7))
	mustAddDACommit(t, state, "peer-drop", daRelayTestCommit(partialID, 3, 5))
	mustAddDAChunk(t, state, "peer-drop", daRelayTestChunk(partialID, 0, 7))
	mustAddDAChunk(t, state, "peer-keep", daRelayTestChunk(partialID, 1, 11))
	mustAddDAChunk(t, state, "peer-keep", daRelayTestChunk(keepID, 0, 13))
	mustAddDAChunk(t, state, "peer-drop", daRelayTestChunk(daRelayTestID(250), 0, 7))
	payload := []byte("complete")
	mustAddDACommit(t, state, "peer-keep", daRelayTestCommitForPayloads(completeID, 5, payload))
	mustAddDAChunk(t, state, "peer-drop", daRelayTestChunkPayload(completeID, 0, uint64(len(payload)), payload))
	state.prefetch.indexes = map[[32]byte]map[uint16]string{wholeID: {0: "peer-prefetch"}, partialID: {2: "peer-prefetch"}}
	state.prefetch.expires = map[[32]byte]time.Time{wholeID: time.Unix(2, 0), partialID: time.Unix(3, 0)}
	return state
}

func newDARelayFirstErrorState(t *testing.T) (*DARelayState, [2][32]byte) {
	t.Helper()
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	state.caps.orphanTTLBlocks = 1
	ids := [2][32]byte{daRelayTestID(230), daRelayTestID(231)}
	mustAddDAChunk(t, state, "peer-drop", daRelayTestChunk(ids[0], 0, 7))
	mustAddDAChunk(t, state, "peer-early", daRelayTestChunk(ids[0], 1, 7))
	mustAddDAChunk(t, state, "peer-drop", daRelayTestChunk(ids[1], 0, 7))
	state.orphanBytesByPeerQuotaKey["peer-early"] = state.caps.orphanPoolPerPeerBytes + state.orphanBytesByPeerQuotaKey["peer-early"] + 1
	state.orphanBytesByDAID[ids[1]] = 0
	return state, ids
}

func newDARelayLockedSnapshotState(t *testing.T, peer string) *DARelayState {
	t.Helper()
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	state.caps.orphanTTLBlocks = 1
	for i := 0; i < 256; i++ {
		daID := daRelayTestID(byte(i))
		mustAddDAChunk(t, state, peer, daRelayTestChunk(daID, 0, 7))
	}
	payload := []byte{1}
	completeID := [32]byte{0, 1}
	mustAddDACommit(t, state, "peer-complete", daRelayTestCommitWithTxBytes(completeID, 1, []byte{1}, payload))
	mustAddDAChunk(t, state, "peer-complete", daRelayTestChunkWithTxBytes(completeID, 0, 1, []byte{2}, payload))
	return state
}

func requireDARelayLockedSnapshotImages(t *testing.T, state, expected *DARelayState, write func(*DARelayState) error) {
	t.Helper()
	before, candidates := daRelayStateSnapshot(state), state.CompleteSetCandidates(^uint64(0))
	if len(candidates) != 1 {
		t.Fatalf("public reader candidates=%d, want 1", len(candidates))
	}
	if err := write(expected); err != nil {
		t.Fatalf("build expected image: %v", err)
	}
	after := daRelayStateSnapshot(expected)
	const readers, snapshotsPerReader = 4, 16
	start, cancel := make(chan struct{}), make(chan struct{})
	warmed, snapshots := make(chan struct{}, readers), make(chan daRelayStateView, readers*(snapshotsPerReader+2))
	writerResult, writeDone := make(chan error, 1), make(chan struct{})
	readerErr, deadline := make(chan error, readers), time.NewTimer(2*time.Second)
	defer deadline.Stop()
	var readersDone sync.WaitGroup
	defer func() { close(cancel); readersDone.Wait() }()
	for i := 0; i < readers; i++ {
		readersDone.Add(1)
		go func() {
			defer readersDone.Done()
			for i := 0; i <= snapshotsPerReader; i++ {
				if !reflect.DeepEqual(state.CompleteSetCandidates(^uint64(0)), candidates) {
					readerErr <- errors.New("public reader result changed")
					return
				}
				snapshots <- daRelayStateSnapshot(state)
				if i == 0 {
					warmed <- struct{}{}
					select {
					case <-start:
					case <-cancel:
						return
					}
				}
			}
			select {
			case <-writeDone:
			case <-cancel:
				return
			}
			if !reflect.DeepEqual(state.CompleteSetCandidates(^uint64(0)), candidates) {
				readerErr <- errors.New("public reader result changed")
				return
			}
			snapshots <- daRelayStateSnapshot(state)
		}()
	}
	go func() {
		defer close(writeDone)
		select {
		case <-start:
		case <-cancel:
			return
		}
		writerErr := write(state)
		select {
		case writerResult <- writerErr:
		case <-cancel:
		}
	}()
	for i := 0; i < readers; i++ {
		select {
		case <-warmed:
		case err := <-readerErr:
			t.Fatal(err)
		case <-deadline.C:
			t.Fatal("reader warmup did not complete")
		}
	}
	close(start)
	var writerErr error
	select {
	case writerErr = <-writerResult:
	case <-deadline.C:
		t.Fatal("writer did not complete")
	}
	done := make(chan struct{})
	go func() { readersDone.Wait(); close(done) }()
	select {
	case <-done:
	case <-deadline.C:
		t.Fatal("readers did not complete")
	}
	close(snapshots)
	sawBefore, sawAfter, partialImage := false, false, false
	for got := range snapshots {
		if reflect.DeepEqual(got, before) { //nolint:govet // Complete private state-image equality requires structural comparison.
			sawBefore = true
		} else if reflect.DeepEqual(got, after) { //nolint:govet // Complete private state-image equality requires structural comparison.
			sawAfter = true
		} else {
			partialImage = true
		}
	}
	select {
	case err := <-readerErr:
		t.Fatal(err)
	default:
	}
	if writerErr != nil {
		t.Fatalf("image write: %v", writerErr)
	}
	if !sawBefore || !sawAfter {
		t.Fatal("locked snapshots did not observe both images")
	}
	if partialImage {
		t.Fatal("locked snapshot observed a partial image")
	}
	if got := daRelayStateSnapshot(state); !reflect.DeepEqual(got, after) { //nolint:govet // Complete private state-image equality requires structural comparison.
		t.Fatal("final locked snapshot differs from expected post-image")
	}
}

func mustPinnedPayloadAccounting(t *testing.T, record daRelaySetRecord) uint64 {
	t.Helper()
	return record.pinnedPayloadAccountingBytes()
}

func requirePortHopRejectedWithoutMutation(t *testing.T, state *DARelayState, rejectedID [32]byte, wantPeerBytes uint64) {
	t.Helper()
	if got := state.orphanBytesForPeerQuotaKey("127.0.0.1"); got != wantPeerBytes {
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

// --- RUB-1272: dormant owner-ready retained-DA record kernel -----------------

// installDASetRecordLocked returns no error, pinned at COMPILE time.
var _ func(daRelayRecordPlacement) = (*DARelayState)(nil).installDASetRecordLocked

func daRelayTestPeerProvenance(quota string) daProvenance {
	return daProvenance{kind: daProvenancePeer, peerIdentity: quota + "-addr", quotaIdentity: quota}
}

// daRelayTestIdentity builds one complete owner-ready identity. seed must stay
// below 0x80 so txid and wtxid differ.
func daRelayTestIdentity(seed byte, provenance daProvenance) daRelayMemberIdentity {
	return daRelayMemberIdentity{
		txid:  daRelayTestID(seed),
		wtxid: daRelayTestID(seed | 0x80),
		fee:   consensus.Uint128FromU64(uint64(seed)),
		// Descending Vout, so a walk that sorted or reordered the canonical
		// input set would be visible in the identity comparisons below.
		inputs:     []consensus.Outpoint{{Txid: daRelayTestID(seed), Vout: 9}, {Txid: daRelayTestID(seed), Vout: 2}},
		provenance: provenance,
	}
}

func daRelayTestOwnerReadyCommit(daID [32]byte, seed byte, provenance daProvenance, txBytes []byte) daRelayOwnerReadyMember {
	return daRelayOwnerReadyMember{
		locator: daRelayLocator{daID: daID, kind: daRelayLocatorCommit},
		member:  daRelayTestIdentity(seed, provenance),
		txBytes: txBytes,
	}
}

func daRelayTestOwnerReadyChunk(daID [32]byte, index uint16, seed byte, provenance daProvenance, txBytes, payload []byte) daRelayOwnerReadyMember {
	return daRelayOwnerReadyMember{
		locator: daRelayLocator{daID: daID, kind: daRelayLocatorChunk, chunkIndex: index},
		member:  daRelayTestIdentity(seed, provenance),
		txBytes: txBytes,
		payload: payload,
	}
}

func stageOwnerReadyMemberForTest(state *DARelayState, member daRelayOwnerReadyMember) daRelayRecordImage {
	pre, present := state.sets[member.locator.daID]
	return stageDAOwnerReadyMember(pre, present, member)
}

func projectOwnerReadyMember(state *DARelayState, member daRelayOwnerReadyMember) (daRelayRecordPlacement, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.projectDARecordImageLocked(stageOwnerReadyMemberForTest(state, member))
}

func mustInstallOwnerReadyMember(t *testing.T, state *DARelayState, member daRelayOwnerReadyMember) daRelayRecordPlacement {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	placement, err := state.projectDARecordImageLocked(stageOwnerReadyMemberForTest(state, member))
	if err != nil {
		t.Fatalf("project owner-ready member: %v", err)
	}
	state.installDASetRecordLocked(placement)
	return placement
}

// requireDAImageRejected pins both halves of one refusal: the exact error AND a
// live image no path touched.
func requireDAImageRejected(t *testing.T, state *DARelayState, image daRelayRecordImage, want error) {
	t.Helper()
	before := daRelayStateSnapshot(state)
	state.mu.Lock()
	_, err := state.projectDARecordImageLocked(image)
	state.mu.Unlock()
	requireDAErr(t, err, want)
	requireDARelayStateUnchanged(t, state, before)
}

func requireOwnerReadyMemberRejected(t *testing.T, state *DARelayState, member daRelayOwnerReadyMember, want error) {
	t.Helper()
	requireDAImageRejected(t, state, stageOwnerReadyMemberForTest(state, member), want)
}

func TestDAProvenanceClosedSet(t *testing.T) {
	t.Run("valid members carry their exact source", func(t *testing.T) {
		valid := []struct {
			name     string
			value    daProvenance
			quotaKey string
		}{
			{"peer", daRelayTestPeerProvenance("quota-a"), "quota-a"},
			{"local", daProvenance{kind: daProvenanceLocal}, ""},
			{"detached reorg", daProvenance{kind: daProvenanceDetachedReorg}, ""},
		}
		for _, row := range valid {
			if err := row.value.validate(); err != nil {
				t.Fatalf("%s provenance: %v", row.name, err)
			}
			if got := row.value.quotaKey(); got != row.quotaKey {
				t.Fatalf("%s quota key = %q, want %q", row.name, got, row.quotaKey)
			}
		}
	})

	t.Run("every junk value is refused", func(t *testing.T) {
		junk := []struct {
			name     string
			value    daProvenance
			quotaKey string
		}{
			{"zero value", daProvenance{}, ""},
			{"peer without peer identity", daProvenance{kind: daProvenancePeer, quotaIdentity: "quota"}, "quota"},
			{"peer without quota identity", daProvenance{kind: daProvenancePeer, peerIdentity: "addr"}, ""},
			{"local carrying a peer identity", daProvenance{kind: daProvenanceLocal, peerIdentity: "addr"}, ""},
			{"local carrying a quota identity", daProvenance{kind: daProvenanceLocal, quotaIdentity: "quota"}, ""},
			{"detached reorg carrying an identity", daProvenance{kind: daProvenanceDetachedReorg, quotaIdentity: "quota"}, ""},
			{"one kind past the last", daProvenance{kind: daProvenanceDetachedReorg + 1}, ""},
			{"maximum kind value", daProvenance{kind: daProvenanceKind(^uint8(0))}, ""},
		}
		for _, row := range junk {
			requireDAErr(t, row.value.validate(), errDAProvenanceInvalid)
			// Only a PEER derives a nonempty key; a malformed one derives its
			// own string and is kept out of the counters by the refusal above.
			if got := row.value.quotaKey(); got != row.quotaKey {
				t.Fatalf("%s derived quota key %q, want %q", row.name, got, row.quotaKey)
			}
		}
	})

	t.Run("a refused provenance never reaches a per-peer counter", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		member := daRelayTestOwnerReadyCommit(daRelayTestID(1), 2, daProvenance{kind: daProvenancePeer, quotaIdentity: "quota"}, []byte("commit-tx"))
		requireOwnerReadyMemberRejected(t, state, member, errDAProvenanceInvalid)
		if _, charged := state.orphanBytesByPeerQuotaKey["quota"]; charged {
			t.Fatalf("a refused provenance was charged: %+v", state.orphanBytesByPeerQuotaKey)
		}
	})
}

func TestDAOwnerReadyRecordImage(t *testing.T) {
	daID := daRelayTestID(11)
	commitTx := []byte("owner-ready-commit-tx")
	chunkTx := []byte("owner-ready-chunk-tx")
	chunkPayload := []byte("chunk-payload")

	t.Run("one member stages a complete placement and installs it", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		member := daRelayTestOwnerReadyCommit(daID, 21, daRelayTestPeerProvenance("quota-a"), commitTx)
		before := daRelayStateSnapshot(state)
		placement, err := projectOwnerReadyMember(state, member)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		requireDARelayStateUnchanged(t, state, before)

		charge := uint64(len(commitTx))
		if placement.record.revision != 1 || placement.remove {
			t.Fatalf("placement revision = %d remove = %v, want 1 false", placement.record.revision, placement.remove)
		}
		if !reflect.DeepEqual(placement.record.commit.member, &member.member) {
			t.Fatalf("placement member = %+v, want %+v", placement.record.commit.member, member.member)
		}
		wantInstall := []daRelayLocatorRow{{txid: member.member.txid, locator: member.locator}}
		if !reflect.DeepEqual(placement.install, wantInstall) || len(placement.retire) != 0 {
			t.Fatalf("locator rows install=%+v retire=%+v, want %+v and none", placement.install, placement.retire, wantInstall)
		}
		if placement.orphanBytes != charge || placement.commitBytes != charge || placement.daBytes != charge {
			t.Fatalf("byte totals = %d/%d/%d, want %d", placement.orphanBytes, placement.commitBytes, placement.daBytes, charge)
		}
		if placement.peerBytes["quota-a"] != charge || len(placement.peerBytes) != 1 {
			t.Fatalf("peer bytes = %+v, want only quota-a=%d", placement.peerBytes, charge)
		}

		state.mu.Lock()
		state.installDASetRecordLocked(placement)
		state.mu.Unlock()
		if got := state.sets[daID].revision; got != 1 || state.records != 1 {
			t.Fatalf("installed revision = %d, high-water = %d, want 1 and 1", got, state.records)
		}
		if got := state.locators[member.member.txid]; got != member.locator {
			t.Fatalf("locator row = %+v, want %+v", got, member.locator)
		}
		if state.orphanBytes != charge || state.orphanBytesByPeerQuotaKey["quota-a"] != charge {
			t.Fatalf("state totals = %d and %d, want %d", state.orphanBytes, state.orphanBytesByPeerQuotaKey["quota-a"], charge)
		}
		// The accepted sequence of Section 18.2 stays the live counter's: this
		// kernel neither reads nor advances it.
		if state.nextReceivedTime != 0 {
			t.Fatalf("the kernel advanced the accepted sequence to %d", state.nextReceivedTime)
		}
	})

	t.Run("the charge follows provenance and never the cached legacy key", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		commit := daRelayTestOwnerReadyCommit(daID, 22, daRelayTestPeerProvenance("prov-quota"), commitTx)
		mustInstallOwnerReadyMember(t, state, commit)

		legacy := state.sets[daID]
		legacy.commit.peerQuotaKey = "legacy-key"
		state.sets[daID] = legacy

		chunk := daRelayTestOwnerReadyChunk(daID, 0, 23, daRelayTestPeerProvenance("prov-quota"), chunkTx, chunkPayload)
		placement, err := projectOwnerReadyMember(state, chunk)
		if err != nil {
			t.Fatalf("project chunk: %v", err)
		}
		chunkCharge := uint64(len(chunkTx) + len(chunkPayload))
		wantPeer := uint64(len(commitTx)) + chunkCharge
		if placement.peerBytes["prov-quota"] != wantPeer {
			t.Fatalf("provenance-keyed charge = %d, want %d", placement.peerBytes["prov-quota"], wantPeer)
		}
		if _, charged := placement.peerBytes["legacy-key"]; charged {
			t.Fatalf("the cached legacy key was charged: %+v", placement.peerBytes)
		}
	})

	t.Run("a peerless member derives the empty key", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		member := daRelayTestOwnerReadyCommit(daID, 24, daProvenance{kind: daProvenanceLocal}, commitTx)
		placement, err := projectOwnerReadyMember(state, member)
		if err != nil {
			t.Fatalf("project: %v", err)
		}
		if placement.peerBytes[""] != uint64(len(commitTx)) || len(placement.peerBytes) != 1 {
			t.Fatalf("peerless charge = %+v, want only the empty key", placement.peerBytes)
		}
	})

	t.Run("a reserved token is carried verbatim", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		reserved := daRelayTestOwnerReadyChunk(daID, 0, 26, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
		reserved.member.token = PendingOutpointToken{seq: 9}
		placement := mustInstallOwnerReadyMember(t, state, reserved)
		if placement.record.chunks[0].member.token != (PendingOutpointToken{seq: 9}) {
			t.Fatalf("reserved token was not carried: %+v", placement.record.chunks[0].member.token)
		}
	})

	t.Run("an accounting underflow is refused before mutation", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		commit := daRelayTestOwnerReadyCommit(daID, 28, daRelayTestPeerProvenance("quota-a"), commitTx)
		mustInstallOwnerReadyMember(t, state, commit)
		state.orphanBytes = 0

		requireDAImageRejected(t, state, stageDAOwnerReadyRemoval(state.sets[daID], true), errDARelayArithmeticOverflow)
	})

	t.Run("a locator row the index does not account for is refused", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		commit := daRelayTestOwnerReadyCommit(daID, 31, daRelayTestPeerProvenance("quota-a"), commitTx)
		mustInstallOwnerReadyMember(t, state, commit)
		state.locators[commit.member.txid] = daRelayLocator{daID: daID, kind: daRelayLocatorChunk}

		chunk := daRelayTestOwnerReadyChunk(daID, 0, 32, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
		requireOwnerReadyMemberRejected(t, state, chunk, errDARelayLocatorMismatch)
	})

	t.Run("a txid another record already owns is refused", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		member := daRelayTestOwnerReadyCommit(daID, 33, daRelayTestPeerProvenance("quota-a"), commitTx)
		state.locators[member.member.txid] = daRelayLocator{daID: daRelayTestID(99), kind: daRelayLocatorCommit}
		requireOwnerReadyMemberRejected(t, state, member, errDARelayLocatorMismatch)
	})

	t.Run("two members of one record claiming one txid is a partial image", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		commit := daRelayTestOwnerReadyCommit(daID, 34, daRelayTestPeerProvenance("quota-a"), commitTx)
		mustInstallOwnerReadyMember(t, state, commit)

		chunk := daRelayTestOwnerReadyChunk(daID, 0, 35, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
		chunk.member.txid = commit.member.txid
		requireOwnerReadyMemberRejected(t, state, chunk, errDARelayLocatorMismatch)
	})

	t.Run("the record about to be installed is validated, not just the named member", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		member := daRelayTestOwnerReadyCommit(daID, 39, daRelayTestPeerProvenance("quota-a"), commitTx)
		corrupt := stageOwnerReadyMemberForTest(state, member)
		corrupt.next.commit.member.provenance = daProvenance{}
		disowned := stageOwnerReadyMemberForTest(state, member)
		disowned.next.commit.member.txid = daRelayTestID(40)
		// A pre-state read from another record: the refusal names the image, not
		// the locator row that would otherwise catch it two stages later.
		elsewhere := stageOwnerReadyMemberForTest(state, member)
		elsewhere.daID = daRelayTestID(99)

		before := daRelayStateSnapshot(state)
		state.mu.Lock()
		_, corruptErr := state.projectDARecordImageLocked(corrupt)
		_, disownedErr := state.projectDARecordImageLocked(disowned)
		_, elsewhereErr := state.projectDARecordImageLocked(elsewhere)
		state.mu.Unlock()
		requireDAErr(t, corruptErr, errDAProvenanceInvalid)
		requireDAErr(t, disownedErr, errDARelayMemberIncomplete)
		requireDAErr(t, elsewhereErr, errDARelayImageIncompatible)
		requireDARelayStateUnchanged(t, state, before)
	})

	t.Run("an incomplete member is refused component by component", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		base := daRelayTestOwnerReadyCommit(daID, 36, daRelayTestPeerProvenance("quota-a"), commitTx)
		omissions := []struct {
			name   string
			break_ func(*daRelayOwnerReadyMember)
		}{
			{"no locator kind", func(m *daRelayOwnerReadyMember) { m.locator.kind = 0 }},
			{"a kind past the last", func(m *daRelayOwnerReadyMember) { m.locator.kind = daRelayLocatorChunk + 1 }},
			{"a commit carrying a chunk index", func(m *daRelayOwnerReadyMember) { m.locator.chunkIndex = 1 }},
			{"a commit carrying a payload", func(m *daRelayOwnerReadyMember) { m.payload = chunkPayload }},
			{"no retained bytes", func(m *daRelayOwnerReadyMember) { m.txBytes = nil }},
			{"no txid", func(m *daRelayOwnerReadyMember) { m.member.txid = [32]byte{} }},
			{"no wtxid", func(m *daRelayOwnerReadyMember) { m.member.wtxid = [32]byte{} }},
			{"no ordered inputs", func(m *daRelayOwnerReadyMember) { m.member.inputs = nil }},
			{"more inputs than a tx may carry", func(m *daRelayOwnerReadyMember) {
				m.member.inputs = make([]consensus.Outpoint, consensus.MAX_TX_INPUTS+1)
			}},
			{"more retained bytes than the transport carries", func(m *daRelayOwnerReadyMember) {
				m.txBytes = make([]byte, consensus.MAX_RELAY_MSG_BYTES+1)
			}},
		}
		for _, row := range omissions {
			member := base
			row.break_(&member)
			t.Run(row.name, func(t *testing.T) {
				requireOwnerReadyMemberRejected(t, state, member, errDARelayMemberIncomplete)
			})
		}
		member := base
		member.member.provenance = daProvenance{}
		requireOwnerReadyMemberRejected(t, state, member, errDAProvenanceInvalid)

		chunk := daRelayTestOwnerReadyChunk(daID, 0, 37, daRelayTestPeerProvenance("quota-a"), chunkTx, nil)
		requireOwnerReadyMemberRejected(t, state, chunk, errDARelayMemberIncomplete)
	})

	t.Run("every cap is refused on its own", func(t *testing.T) {
		rows := []struct {
			name string
			caps func(*daRelayCaps)
			want error
		}{
			{"global", func(c *daRelayCaps) {
				c.orphanPoolBytes, c.orphanPoolPerPeerBytes, c.orphanPoolPerDAIDBytes, c.orphanCommitOverheadBytes = 8, 8, 8, 8
			}, errDARelayOrphanPoolCapExceeded},
			{"per da_id", func(c *daRelayCaps) { c.orphanPoolPerDAIDBytes = 8 }, errDARelayOrphanDAIDCapExceeded},
			{"commit overhead", func(c *daRelayCaps) { c.orphanCommitOverheadBytes = 8 }, errDARelayOrphanCommitCapExceeded},
			{"per peer", func(c *daRelayCaps) { c.orphanPoolPerPeerBytes = 8 }, errDARelayOrphanPeerCapExceeded},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				caps := defaultDARelayCaps()
				row.caps(&caps)
				state := newDARelayStateForTest(t, caps)
				member := daRelayTestOwnerReadyCommit(daID, 45, daRelayTestPeerProvenance("quota-a"), commitTx)
				requireOwnerReadyMemberRejected(t, state, member, row.want)
			})
		}
	})

	t.Run("refusal precedence holds on every doubly-violating pair", func(t *testing.T) {
		resident := daRelayTestOwnerReadyCommit(daID, 46, daRelayTestPeerProvenance("quota-a"), commitTx)
		chunkOf := func(seed byte) daRelayOwnerReadyMember {
			return daRelayTestOwnerReadyChunk(daID, 0, seed, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
		}
		rows := []struct {
			name    string
			arrange func(*testing.T, *DARelayState) daRelayRecordImage
			want    error
		}{
			{"incompatible outranks stale", func(t *testing.T, s *DARelayState) daRelayRecordImage {
				mustAddDACommit(t, s, "legacy-peer", daRelayTestCommit(daID, 2, 64))
				image := stageDAOwnerReadyMember(s.sets[daID], true, resident)
				image.baseline = 7
				return image
			}, errDARelayImageIncompatible},
			{"stale outranks candidate", func(t *testing.T, s *DARelayState) daRelayRecordImage {
				mustInstallOwnerReadyMember(t, s, resident)
				broken := chunkOf(47)
				broken.member.txid = [32]byte{}
				image := stageDAOwnerReadyMember(s.sets[daID], true, broken)
				image.baseline = 7
				return image
			}, errDARelayRecordStale},
			{"candidate outranks locator", func(t *testing.T, s *DARelayState) daRelayRecordImage {
				mustInstallOwnerReadyMember(t, s, resident)
				s.locators[resident.member.txid] = daRelayLocator{daID: daID, kind: daRelayLocatorChunk}
				broken := chunkOf(48)
				broken.member.inputs = nil
				return stageDAOwnerReadyMember(s.sets[daID], true, broken)
			}, errDARelayMemberIncomplete},
			{"locator outranks accounting", func(t *testing.T, s *DARelayState) daRelayRecordImage {
				mustInstallOwnerReadyMember(t, s, resident)
				s.locators[resident.member.txid] = daRelayLocator{daID: daID, kind: daRelayLocatorChunk}
				s.caps.orphanPoolBytes = 8
				return stageDAOwnerReadyMember(s.sets[daID], true, chunkOf(49))
			}, errDARelayLocatorMismatch},
			{"accounting outranks revision", func(t *testing.T, s *DARelayState) daRelayRecordImage {
				mustInstallOwnerReadyMember(t, s, resident)
				s.caps.orphanPoolBytes = 8
				s.records = ^uint64(0)
				return stageDAOwnerReadyMember(s.sets[daID], true, chunkOf(50))
			}, errDARelayOrphanPoolCapExceeded},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				state := newDARelayStateForTest(t, defaultDARelayCaps())
				requireDAImageRejected(t, state, row.arrange(t, state), row.want)
			})
		}
	})

	t.Run("an occupied slot is first-seen", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		commit := daRelayTestOwnerReadyCommit(daID, 58, daRelayTestPeerProvenance("quota-a"), commitTx)
		chunk := daRelayTestOwnerReadyChunk(daID, 0, 59, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
		mustInstallOwnerReadyMember(t, state, commit)
		mustInstallOwnerReadyMember(t, state, chunk)

		second := daRelayTestOwnerReadyCommit(daID, 60, daRelayTestPeerProvenance("quota-b"), commitTx)
		requireOwnerReadyMemberRejected(t, state, second, errDARelayDuplicateCommit)
		rechunk := daRelayTestOwnerReadyChunk(daID, 0, 61, daRelayTestPeerProvenance("quota-b"), chunkTx, chunkPayload)
		requireOwnerReadyMemberRejected(t, state, rechunk, errDARelayDuplicateChunk)
	})

	t.Run("a live locator row the retirement does not name is refused", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		commit := daRelayTestOwnerReadyCommit(daID, 51, daRelayTestPeerProvenance("quota-a"), commitTx)
		mustInstallOwnerReadyMember(t, state, commit)
		state.locators[daRelayTestID(52)] = daRelayLocator{daID: daID, kind: daRelayLocatorChunk, chunkIndex: 3}

		chunk := daRelayTestOwnerReadyChunk(daID, 0, 53, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
		requireOwnerReadyMemberRejected(t, state, chunk, errDARelayLocatorMismatch)
	})

	t.Run("a removal carrying a populated next is refused", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		commit := daRelayTestOwnerReadyCommit(daID, 54, daRelayTestPeerProvenance("quota-a"), commitTx)
		mustInstallOwnerReadyMember(t, state, commit)

		image := stageDAOwnerReadyRemoval(state.sets[daID], true)
		image.next = state.sets[daID].cloneOwnerReady()
		requireDAImageRejected(t, state, image, errDARelayMemberIncomplete)
	})

	t.Run("an incoherent record is refused component by component", func(t *testing.T) {
		rows := []struct {
			name    string
			corrupt func(*daRelaySetRecord)
		}{
			{"a chunk filed under another index", func(r *daRelaySetRecord) {
				chunk := r.chunks[0]
				delete(r.chunks, 0)
				r.chunks[1] = chunk
			}},
			{"a chunk naming another record", func(r *daRelaySetRecord) {
				chunk := r.chunks[0]
				chunk.daID = daRelayTestID(99)
				r.chunks[0] = chunk
			}},
			{"a chunk with no retained bytes", func(r *daRelaySetRecord) {
				chunk := r.chunks[0]
				chunk.txBytes = nil
				r.chunks[0] = chunk
			}},
			{"a chunk with no payload", func(r *daRelaySetRecord) {
				chunk := r.chunks[0]
				chunk.payload = nil
				r.chunks[0] = chunk
			}},
			{"a commit naming another record", func(r *daRelaySetRecord) { r.commit.daID = daRelayTestID(99) }},
			{"a commit with no retained bytes", func(r *daRelaySetRecord) { r.commit.txBytes = nil }},
		}
		for _, row := range rows {
			t.Run(row.name, func(t *testing.T) {
				state := newDARelayStateForTest(t, defaultDARelayCaps())
				mustInstallOwnerReadyMember(t, state, daRelayTestOwnerReadyCommit(daID, 55, daRelayTestPeerProvenance("quota-a"), commitTx))
				mustInstallOwnerReadyMember(t, state, daRelayTestOwnerReadyChunk(daID, 0, 56, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload))
				record := state.sets[daID].cloneOwnerReady()
				row.corrupt(&record)
				state.sets[daID] = record

				next := daRelayTestOwnerReadyChunk(daID, 1, 57, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
				requireDAImageRejected(t, state, stageDAOwnerReadyMember(record, true, next), errDARelayImageIncompatible)
			})
		}
	})

	t.Run("the absolute chunk bounds are refused at the edge", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		atCap := make([]byte, consensus.CHUNK_BYTES)
		for _, member := range []daRelayOwnerReadyMember{daRelayTestOwnerReadyChunk(daID, uint16(consensus.MAX_DA_CHUNK_COUNT-1), 71, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload), daRelayTestOwnerReadyChunk(daID, 0, 72, daRelayTestPeerProvenance("quota-a"), chunkTx, atCap)} {
			if _, err := projectOwnerReadyMember(state, member); err != nil {
				t.Fatalf("a legal member was refused: %v", err)
			}
		}
		requireOwnerReadyMemberRejected(t, state, daRelayTestOwnerReadyChunk(daID, uint16(consensus.MAX_DA_CHUNK_COUNT), 73, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload), errDARelayChunkIndexOutOfRange)
		requireOwnerReadyMemberRejected(t, state, daRelayTestOwnerReadyChunk(daID, ^uint16(0), 74, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload), errDARelayChunkIndexOutOfRange)
		requireOwnerReadyMemberRejected(t, state, daRelayTestOwnerReadyChunk(daID, 0, 75, daRelayTestPeerProvenance("quota-a"), chunkTx, append(atCap, 0)), errDARelayChunkPayloadSizeInvalid)
	})

	t.Run("a state with no locator index is refused rather than allocated", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		state.locators = nil
		member := daRelayTestOwnerReadyCommit(daID, 38, daRelayTestPeerProvenance("quota-a"), commitTx)
		requireOwnerReadyMemberRejected(t, state, member, errDARelayImageIncompatible)
	})
}

func TestDAOwnerReadyRecordImageRejectsLegacy(t *testing.T) {
	daID := daRelayTestID(41)
	commitTx := []byte("owner-ready-commit-tx")
	member := daRelayTestOwnerReadyCommit(daID, 42, daRelayTestPeerProvenance("quota-a"), commitTx)

	legacyResident := func(t *testing.T) *DARelayState {
		t.Helper()
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustAddDACommit(t, state, "legacy-peer", daRelayTestCommit(daID, 2, 64))
		if state.sets[daID].revision != 0 {
			t.Fatal("the legacy writer must not stamp a revision")
		}
		return state
	}

	t.Run("a legacy resident record is incompatible, never absent", func(t *testing.T) {
		state := legacyResident(t)
		// Residency and baseline agree, so only the owner-ready check refuses it.
		requireDAImageRejected(t, state, stageDAOwnerReadyMember(state.sets[daID], true, member), errDARelayImageIncompatible)
	})

	t.Run("claiming a legacy resident record is absent does not make it absent", func(t *testing.T) {
		state := legacyResident(t)
		requireDAImageRejected(t, state, stageDAOwnerReadyMember(daRelaySetRecord{}, false, member), errDARelayImageIncompatible)
	})

	t.Run("a stamped record holding an unusable member is incompatible", func(t *testing.T) {
		corruptions := []struct {
			name    string
			corrupt func(*daRelaySetRecord)
		}{
			{"a commit with no member", func(r *daRelaySetRecord) { r.commit.member = nil }},
			{"a commit with no identity", func(r *daRelaySetRecord) { r.commit.member.txid = [32]byte{} }},
			{"a commit with invalid provenance", func(r *daRelaySetRecord) { r.commit.member.provenance = daProvenance{} }},
			{"a commit with no ordered inputs", func(r *daRelaySetRecord) { r.commit.member.inputs = nil }},
			{"a revision of zero", func(r *daRelaySetRecord) { r.revision = 0 }},
			{"a chunk entry with no member", func(r *daRelaySetRecord) {
				r.chunks = map[uint16]daRelayChunk{0: {daID: r.daID, chunkIndex: 0, txBytes: []byte("x"), payload: []byte("y")}}
			}},
		}
		for _, row := range corruptions {
			t.Run(row.name, func(t *testing.T) {
				state := newDARelayStateForTest(t, defaultDARelayCaps())
				mustInstallOwnerReadyMember(t, state, member)
				record := state.sets[daID].cloneOwnerReady()
				row.corrupt(&record)
				state.sets[daID] = record

				next := daRelayTestOwnerReadyChunk(daID, 0, 43, daRelayTestPeerProvenance("quota-a"), []byte("chunk-tx"), []byte("chunk-payload"))
				requireDAImageRejected(t, state, stageDAOwnerReadyMember(record, true, next), errDARelayImageIncompatible)
			})
		}
	})

	t.Run("a complete set is outside this kernel's accounting domain", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, member)
		record := state.sets[daID].cloneOwnerReady()
		record.state = daRelayStateCompleteSet
		record.payloadBytes = 4
		state.sets[daID] = record

		before := daRelayStateSnapshot(state)
		update := daRelayTestOwnerReadyChunk(daID, 0, 44, daRelayTestPeerProvenance("quota-a"), []byte("chunk-tx"), []byte("chunk-payload"))
		state.mu.Lock()
		_, updateErr := state.projectDARecordImageLocked(stageDAOwnerReadyMember(record, true, update))
		_, removeErr := state.projectDARecordImageLocked(stageDAOwnerReadyRemoval(record, true))
		state.mu.Unlock()
		requireDAErr(t, updateErr, errDARelayImageIncompatible)
		requireDAErr(t, removeErr, errDARelayImageIncompatible)
		requireDARelayStateUnchanged(t, state, before)
	})

	t.Run("a memberless slot emits no locator row and is refused, never charged", func(t *testing.T) {
		record := daRelaySetRecord{daID: daID, state: daRelayStateOrphanChunks, chunks: map[uint16]daRelayChunk{
			0: {daID: daID, chunkIndex: 0, txBytes: []byte("x"), payload: []byte("y")},
		}}
		if rows := record.locatorRows(); len(rows) != 0 {
			t.Fatalf("a memberless record emitted locator rows: %+v", rows)
		}
		_, err := record.ownerReadyAccounting()
		requireDAErr(t, err, errDARelayMemberIncomplete)
	})
}

func TestDARecordRevisionPlacement(t *testing.T) {
	daID := daRelayTestID(51)
	commitTx := []byte("owner-ready-commit-tx")
	chunkTx := []byte("owner-ready-chunk-tx")
	chunkPayload := []byte("chunk-payload")
	commit := daRelayTestOwnerReadyCommit(daID, 52, daRelayTestPeerProvenance("quota-a"), commitTx)
	chunk := daRelayTestOwnerReadyChunk(daID, 0, 53, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)

	removeRecord := func(t *testing.T, state *DARelayState) daRelayRecordPlacement {
		t.Helper()
		state.mu.Lock()
		defer state.mu.Unlock()
		pre, present := state.sets[daID]
		placement, err := state.projectDARecordImageLocked(stageDAOwnerReadyRemoval(pre, present))
		if err != nil {
			t.Fatalf("project removal: %v", err)
		}
		state.installDASetRecordLocked(placement)
		return placement
	}

	t.Run("creation and partial update each consume one fresh nonzero revision", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		created := mustInstallOwnerReadyMember(t, state, commit)
		updated := mustInstallOwnerReadyMember(t, state, chunk)
		if created.record.revision != 1 || updated.record.revision != 2 {
			t.Fatalf("revisions = %d then %d, want 1 then 2", created.record.revision, updated.record.revision)
		}
		if state.sets[daID].revision != 2 || state.records != 2 {
			t.Fatalf("stored revision = %d, high-water = %d, want 2 and 2", state.sets[daID].revision, state.records)
		}
		// The update retires and reinstalls the commit's row in one placement,
		// so a txid the record keeps across the transition stays indexed.
		if state.locators[commit.member.txid] != commit.locator || state.locators[chunk.member.txid] != chunk.locator {
			t.Fatalf("locator index after the update = %+v", state.locators)
		}
	})

	t.Run("whole-record deletion retires the record and consumes no revision", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, commit)
		mustInstallOwnerReadyMember(t, state, chunk)

		placement := removeRecord(t, state)
		if !placement.remove || placement.record.revision != 0 {
			t.Fatalf("removal placement remove=%v revision=%d, want true and 0", placement.remove, placement.record.revision)
		}
		if state.records != 2 {
			t.Fatalf("removal consumed a revision: high-water = %d, want 2", state.records)
		}
		if _, resident := state.sets[daID]; resident {
			t.Fatal("the record survived its removal")
		}
		if len(state.locators) != 0 {
			t.Fatalf("dangling locator rows: %+v", state.locators)
		}
		if state.orphanBytes != 0 || len(state.orphanBytesByPeerQuotaKey) != 0 || len(state.orphanBytesByDAID) != 0 {
			t.Fatalf("dangling charges: %d %+v %+v", state.orphanBytes, state.orphanBytesByPeerQuotaKey, state.orphanBytesByDAID)
		}
	})

	t.Run("a removed da_id never reuses its predecessor's revision", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, commit)
		removeRecord(t, state)
		recreated := mustInstallOwnerReadyMember(t, state, commit)
		if recreated.record.revision != 2 {
			t.Fatalf("recreated revision = %d, want 2", recreated.record.revision)
		}
	})

	t.Run("a stale baseline is refused before mutation", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, commit)
		pre := state.sets[daID]
		mustInstallOwnerReadyMember(t, state, chunk)

		second := daRelayTestOwnerReadyChunk(daID, 1, 54, daRelayTestPeerProvenance("quota-a"), chunkTx, chunkPayload)
		requireDAImageRejected(t, state, stageDAOwnerReadyMember(pre, true, second), errDARelayRecordStale)
	})

	t.Run("a nonzero stamp source and a populated index survive the atomic batch", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, commit)
		mustInstallOwnerReadyMember(t, state, chunk)

		state.mu.Lock()
		projected := state.cloneForAtomicBatchLocked()
		state.records, state.locators = 0, nil
		state.publishAtomicBatchLocked(projected)
		state.mu.Unlock()
		if state.records != 2 || len(state.locators) != 2 {
			t.Fatalf("the batch dropped state: records=%d locators=%d, want 2 and 2", state.records, len(state.locators))
		}
	})

	t.Run("an exhausted revision space fails closed but still allows removal", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, commit)
		state.records = ^uint64(0)

		requireOwnerReadyMemberRejected(t, state, chunk, errDARelayArithmeticOverflow)

		placement := removeRecord(t, state)
		if !placement.remove || state.records != ^uint64(0) {
			t.Fatalf("removal at the ceiling remove=%v high-water=%d", placement.remove, state.records)
		}
	})
}

func TestDARecordImageMapOrder(t *testing.T) {
	daID := daRelayTestID(61)
	provenance := daRelayTestPeerProvenance("quota-a")
	state := newDARelayStateForTest(t, defaultDARelayCaps())
	mustInstallOwnerReadyMember(t, state, daRelayTestOwnerReadyCommit(daID, 62, provenance, []byte("owner-ready-commit-tx")))
	for index := uint16(0); index < 8; index++ {
		member := daRelayTestOwnerReadyChunk(daID, index, byte(63+index), provenance, []byte("chunk-tx"), []byte{byte(index + 1)})
		mustInstallOwnerReadyMember(t, state, member)
	}

	candidate := daRelayTestOwnerReadyChunk(daID, 8, 71, provenance, []byte("chunk-tx"), []byte{9})
	wantInstall := []daRelayLocatorRow{{txid: daRelayTestID(62), locator: daRelayLocator{daID: daID, kind: daRelayLocatorCommit}}}
	for index := uint16(0); index < 8; index++ {
		wantInstall = append(wantInstall, daRelayLocatorRow{txid: daRelayTestID(byte(63 + index)), locator: daRelayLocator{daID: daID, kind: daRelayLocatorChunk, chunkIndex: index}})
	}
	wantInstall = append(wantInstall, daRelayLocatorRow{txid: candidate.member.txid, locator: candidate.locator})
	first, err := projectOwnerReadyMember(state, candidate)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if !reflect.DeepEqual(first.install, wantInstall) {
		t.Fatalf("install rows = %+v, want %+v", first.install, wantInstall)
	}
	// Go re-randomises map iteration per range, so repeating the whole
	// projection is what would expose an order-dependent walk.
	for attempt := 1; attempt < 3; attempt++ {
		placement, err := projectOwnerReadyMember(state, candidate)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if !reflect.DeepEqual(placement, first) {
			t.Fatalf("attempt %d placement = %+v, want %+v", attempt, placement, first)
		}
	}
}

func TestDARecordImageCloneIsolation(t *testing.T) {
	daID := daRelayTestID(81)
	provenance := daRelayTestPeerProvenance("quota-a")

	// The live layer never reads a member and the orphan-pool caps count wire and
	// payload bytes only, so an unowned member must cost one word of resident heap
	// rather than the whole identity. Exact, not bounds: a bound admits one more
	// pointer field, the growth these pin. 64-bit literals; nothing builds 32-bit.
	t.Run("an unowned member costs one word and a retained one is cloned through", func(t *testing.T) {
		if got := unsafe.Sizeof(daRelayCommit{}); got != 128 {
			t.Fatalf("daRelayCommit = %d bytes, want exactly 128 (120 without its member word)", got)
		}
		if got := unsafe.Sizeof(daRelayChunk{}); got != 160 {
			t.Fatalf("daRelayChunk = %d bytes, want exactly 160 (152 without its member word)", got)
		}
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, daRelayTestOwnerReadyChunk(daID, 0, 90, provenance, []byte("chunk-tx"), []byte("chunk-payload")))
		record := state.sets[daID]
		if record.commit.member != nil {
			t.Fatalf("a record with no owner-ready commit carries a member: %+v", record.commit.member)
		}
		clone := record.cloneOwnerReady()
		if clone.commit.member != nil {
			t.Fatal("cloning invented a commit member")
		}
		if clone.chunks[0].member == record.chunks[0].member {
			t.Fatal("the clone shares the retained member pointer")
		}
	})

	t.Run("mutating the caller's member after staging changes no staged record", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		member := daRelayTestOwnerReadyChunk(daID, 0, 82, provenance, []byte("chunk-tx"), []byte("chunk-payload"))
		image := stageOwnerReadyMemberForTest(state, member)
		staged := image.next.chunks[0]

		member.txBytes[0] = 'X'
		member.payload[0] = 'X'
		member.member.inputs[0].Vout = 4242

		if staged.txBytes[0] == 'X' || staged.payload[0] == 'X' || staged.member.inputs[0].Vout == 4242 {
			t.Fatalf("the staged member aliases the caller's value: %+v", staged)
		}

		// image.member is a shallow copy; only image.next is isolated.
		if image.member.payload[0] != 'X' {
			t.Fatal("image.member stopped tracking the caller's payload")
		}
		commit := daRelayTestOwnerReadyCommit(daID, 83, provenance, []byte("owner-ready-commit-tx"))
		stagedCommit := stageOwnerReadyMemberForTest(state, commit).next.commit
		commit.txBytes[0] = 'X'
		commit.member.inputs[0].Vout = 4242
		if stagedCommit.txBytes[0] == 'X' || stagedCommit.member.inputs[0].Vout == 4242 {
			t.Fatalf("the staged commit aliases the caller's value: %+v", stagedCommit)
		}
	})

	t.Run("mutating the pre-state after staging changes no image", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		mustInstallOwnerReadyMember(t, state, daRelayTestOwnerReadyCommit(daID, 83, provenance, []byte("owner-ready-commit-tx")))
		mustInstallOwnerReadyMember(t, state, daRelayTestOwnerReadyChunk(daID, 0, 84, provenance, []byte("chunk-tx"), []byte("chunk-payload")))
		// Chunk 0 is already resident, so staging walks cloneOwnerReady's copy loop.
		pre := state.sets[daID]
		pre.replaceableChunks = map[uint16]bool{0: true}

		member := daRelayTestOwnerReadyChunk(daID, 1, 85, provenance, []byte("chunk-tx"), []byte("chunk-payload"))
		first := stageDAOwnerReadyMember(pre, true, member)
		second := stageDAOwnerReadyMember(pre, true, member)

		pre.chunks[0].payload[0] = 'X'
		pre.chunks[0].txBytes[0] = 'X'
		pre.chunks[0].member.inputs[0].Vout = 4242
		pre.commit.txBytes[0] = 'X'
		pre.replaceableChunks[0] = false

		if first.next.chunks[0].payload[0] == 'X' || first.next.chunks[0].txBytes[0] == 'X' {
			t.Fatalf("the image aliases an existing chunk's bytes: %+v", first.next.chunks[0])
		}
		if first.next.chunks[0].member.inputs[0].Vout == 4242 {
			t.Fatal("the image aliases an existing chunk's ordered inputs")
		}
		if first.next.commit.txBytes[0] == 'X' {
			t.Fatal("the image aliases the pre-state commit bytes")
		}
		if !first.next.replaceableChunks[0] {
			t.Fatal("the image aliases the pre-state replaceable flags")
		}
		delete(first.next.chunks, 0)
		if _, kept := second.next.chunks[0]; !kept {
			t.Fatal("two images staged from one pre-state share a chunk map")
		}
	})

	t.Run("mutating an installed image or its placement rows changes no live state", func(t *testing.T) {
		state := newDARelayStateForTest(t, defaultDARelayCaps())
		member := daRelayTestOwnerReadyCommit(daID, 85, provenance, []byte("owner-ready-commit-tx"))
		state.mu.Lock()
		image := stageOwnerReadyMemberForTest(state, member)
		placement, err := state.projectDARecordImageLocked(image)
		if err != nil {
			state.mu.Unlock()
			t.Fatalf("project: %v", err)
		}
		state.installDASetRecordLocked(placement)
		state.mu.Unlock()

		image.next.commit.txBytes[0] = 'X'
		image.next.commit.member.inputs[0].Vout = 4242
		placement.peerBytes["quota-a"] = 999
		placement.install[0].txid = daRelayTestID(89)
		placement.retire = nil

		live := state.sets[daID]
		if live.commit.txBytes[0] == 'X' || live.commit.member.inputs[0].Vout == 4242 {
			t.Fatalf("live state aliases the image: %+v", live.commit)
		}
		if state.orphanBytesByPeerQuotaKey["quota-a"] != uint64(len("owner-ready-commit-tx")) {
			t.Fatalf("live accounting aliases the placement: %d", state.orphanBytesByPeerQuotaKey["quota-a"])
		}
		if _, ok := state.locators[member.member.txid]; !ok {
			t.Fatalf("the live index aliases the placement rows: %+v", state.locators)
		}
		// placement.record IS live state by assignment: the single-use exception.
		placement.record.commit.txBytes[0] = 'Y'
		if state.sets[daID].commit.txBytes[0] != 'Y' {
			t.Fatal("placement.record stopped being the installed record")
		}
	})
}

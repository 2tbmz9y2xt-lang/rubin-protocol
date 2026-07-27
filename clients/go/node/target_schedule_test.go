package node

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type scheduleChain struct {
	headers map[[32]byte][]byte
	hashes  [][32]byte
	times   []uint64
}

func newScheduleChain(t *testing.T, count int, targetOld [32]byte) scheduleChain {
	t.Helper()
	c := scheduleChain{make(map[[32]byte][]byte, count), make([][32]byte, 0, count), make([]uint64, count)}
	var prev [32]byte
	for i := 0; i < count; i++ {
		target := consensus.POW_LIMIT
		if i == count-1 {
			target = targetOld
		}
		c.times[i] = 1_000_000 + uint64(i)*consensus.TARGET_BLOCK_INTERVAL
		raw, hash := scheduleHeader(t, prev, target, c.times[i], uint64(i+1))
		c.headers[hash] = raw
		c.hashes = append(c.hashes, hash)
		prev = hash
	}
	return c
}

func scheduleHeader(t *testing.T, prev, target [32]byte, timestamp, nonce uint64) ([]byte, [32]byte) {
	t.Helper()
	raw := consensus.AppendU32le(nil, 1)
	raw = append(raw, prev[:]...)
	raw = append(raw, make([]byte, 32)...)
	raw = consensus.AppendU64le(raw, timestamp)
	raw = append(raw, target[:]...)
	raw = consensus.AppendU64le(raw, nonce)
	return raw, mustHeaderHash(t, raw)
}

func (c scheduleChain) read(hash [32]byte) ([]byte, error) {
	raw, ok := c.headers[hash]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return raw, nil
}

func assertScheduleError(t *testing.T, err, class error, prefix string, cause error) {
	t.Helper()
	if !errors.Is(err, class) || !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("error=%v, want class %v and prefix %q", err, class, prefix)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("error=%v, want cause %v", err, cause)
	}
}

func TestExpectedTargetForCandidateInputContract(t *testing.T) {
	var nilEngine *SyncEngine
	_, err := expectedTargetForCandidate(nil, [32]byte{}, 1)
	assertScheduleError(t, err, errTargetLocalIO, errTargetLocalIO.Error(), nil)
	_, err = nilEngine.expectedTargetForCandidate([32]byte{}, 1)
	assertScheduleError(t, err, errTargetLocalIO, errTargetLocalIO.Error(), nil)
	reads := 0
	_, err = expectedTargetForCandidateWithReader(func([32]byte) ([]byte, error) {
		reads++
		return nil, errors.New("unexpected read")
	}, [32]byte{}, 0)
	assertScheduleError(t, err, errTargetHeightInvalid, errTargetHeightInvalid.Error(), nil)
	if reads != 0 {
		t.Fatalf("height zero reads=%d, want 0", reads)
	}
	target := [32]byte{0x40}
	raw, parent := scheduleHeader(t, [32]byte{}, target, 1_000_000, 1)
	store := mustOpenBlockStore(t, t.TempDir())
	if err := store.PutBlock(0, parent, raw, raw); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}
	snapshot := func() []any {
		index, indexErr := store.CanonicalIndexSnapshot()
		header, headerErr := store.GetHeaderByHash(parent)
		entries, entriesErr := os.ReadDir(store.headersDir)
		if indexErr != nil || headerErr != nil || entriesErr != nil {
			t.Fatalf("snapshot: index=%v header=%v entries=%v", indexErr, headerErr, entriesErr)
		}
		return []any{index, header, entries}
	}
	before := snapshot()
	coreTarget, coreErr := expectedTargetForCandidate(store, parent, 1)
	wrapperTarget, wrapperErr := (&SyncEngine{blockStore: store}).expectedTargetForCandidate(parent, 1)
	if coreTarget != wrapperTarget || coreTarget != target || coreErr != nil || wrapperErr != nil {
		t.Fatalf("wrapper/core success mismatch: core=%x/%v wrapper=%x/%v", coreTarget, coreErr, wrapperTarget, wrapperErr)
	}
	missing := [32]byte{0xff}
	_, coreErr = expectedTargetForCandidate(store, missing, 1)
	_, wrapperErr = (&SyncEngine{blockStore: store}).expectedTargetForCandidate(missing, 1)
	if !errors.Is(coreErr, ErrParentNotFound) || !errors.Is(wrapperErr, ErrParentNotFound) {
		t.Fatalf("wrapper/core error mismatch: core=%v wrapper=%v", coreErr, wrapperErr)
	}
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Fatalf("BlockStore changed: before=%v after=%v", before, after)
	}
}

func TestExpectedTargetForCandidateNonBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		height uint64
		target [32]byte
	}{
		{"h1_canonical", 1, [32]byte{0x20}},
		{"h10079_side", consensus.WINDOW_SIZE - 1, [32]byte{0x30}},
		{"max_height", ^uint64(0), [32]byte{0x40}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, parent := scheduleHeader(t, [32]byte{0xaa}, tc.target, 7, tc.height)
			reads := 0
			got, err := expectedTargetForCandidateWithReader(func(hash [32]byte) ([]byte, error) {
				reads++
				if hash != parent {
					t.Fatalf("read hash=%x, want selected parent %x", hash, parent)
				}
				return raw, nil
			}, parent, tc.height)
			if err != nil || got != tc.target || reads != 1 {
				t.Fatalf("target=%x err=%v reads=%d, want %x nil 1", got, err, reads, tc.target)
			}
		})
	}
}

func TestExpectedTargetForCandidateBoundary(t *testing.T) {
	targetOld := [32]byte{0x40}
	c := newScheduleChain(t, consensus.WINDOW_SIZE, targetOld)
	reads := 0
	got, err := expectedTargetForCandidateWithReader(func(hash [32]byte) ([]byte, error) {
		reads++
		return c.read(hash)
	}, c.hashes[len(c.hashes)-1], consensus.WINDOW_SIZE)
	want, wantErr := consensus.RetargetV1Clamped(targetOld, c.times)
	if err != nil || wantErr != nil {
		t.Fatalf("boundary=%v RetargetV1Clamped=%v", err, wantErr)
	}
	if got != want || reads != consensus.WINDOW_SIZE {
		t.Fatalf("target=%x want=%x reads=%d want=%d", got, want, reads, consensus.WINDOW_SIZE)
	}
}

func TestExpectedTargetForCandidateFailureClasses(t *testing.T) {
	targetOld := [32]byte{0x40}
	full := newScheduleChain(t, consensus.WINDOW_SIZE, targetOld)
	short := newScheduleChain(t, 3, targetOld)
	parent := full.hashes[len(full.hashes)-1]
	ioCause := errors.New("injected local I/O")
	mismatch, _ := scheduleHeader(t, [32]byte{0x77}, targetOld, 9, 9)
	cycle, _ := scheduleHeader(t, parent, targetOld, 9, 9)
	zeroRaw, zeroParent := scheduleHeader(t, full.hashes[len(full.hashes)-2], [32]byte{}, full.times[len(full.times)-1], 99)

	tests := []struct {
		name                  string
		chain                 scheduleChain
		parent, failHash      [32]byte
		failRead              int
		failRaw               []byte
		failErr, class, cause error
		wantReads             int
		wantTxError           bool
	}{
		{"immediate_absent", full, parent, [32]byte{}, 1, nil, fs.ErrNotExist, ErrParentNotFound, nil, 1, false},
		{"oldest_absent", full, parent, full.hashes[0], 0, nil, fs.ErrNotExist, errTargetHistoryMissing, nil, consensus.WINDOW_SIZE, false},
		{"intermediate_absent", full, parent, full.hashes[len(full.hashes)-7], 0, nil, fs.ErrNotExist, errTargetHistoryMissing, nil, 7, false},
		{"premature_zero", short, short.hashes[2], [32]byte{}, 0, nil, nil, errTargetHistoryMissing, nil, 3, false},
		{"malformed", full, parent, [32]byte{}, 1, []byte{1}, nil, errTargetHistoryCorrupt, nil, 1, false},
		{"hash_mismatch", full, parent, [32]byte{}, 1, mismatch, nil, errTargetHistoryCorrupt, nil, 1, false},
		{"cycle", full, parent, [32]byte{}, 1, cycle, nil, errTargetHistoryCorrupt, nil, 1, false},
		{"immediate_io", full, parent, [32]byte{}, 1, nil, ioCause, errTargetLocalIO, ioCause, 1, false},
		{"older_io", short, short.hashes[2], [32]byte{}, 2, nil, ioCause, errTargetLocalIO, ioCause, 2, false},
		{"retarget", full, zeroParent, zeroParent, 0, zeroRaw, nil, errTargetRetarget, nil, consensus.WINDOW_SIZE, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			_, err := expectedTargetForCandidateWithReader(func(h [32]byte) ([]byte, error) {
				reads++
				if reads == tc.failRead || h == tc.failHash {
					return tc.failRaw, tc.failErr
				}
				return tc.chain.read(h)
			}, tc.parent, consensus.WINDOW_SIZE)
			assertScheduleError(t, err, tc.class, tc.class.Error(), tc.cause)
			if reads != tc.wantReads || reads > consensus.WINDOW_SIZE {
				t.Fatalf("reads=%d, want %d and <=%d", reads, tc.wantReads, consensus.WINDOW_SIZE)
			}
			var txErr *consensus.TxError
			if tc.wantTxError && !errors.As(err, &txErr) {
				t.Fatalf("error=%v, want preserved *consensus.TxError", err)
			}
		})
	}
}

func TestExpectedTargetForCandidateBoundaryReadCap(t *testing.T) {
	parent := [32]byte{0x01}
	cycle, _ := scheduleHeader(t, parent, consensus.POW_LIMIT, 1, 1)
	reads := 0
	_, err := expectedTargetForCandidateWithReader(func([32]byte) ([]byte, error) {
		reads++
		return cycle, nil
	}, parent, consensus.WINDOW_SIZE)
	if !errors.Is(err, errTargetHistoryCorrupt) || reads != 1 || reads > consensus.WINDOW_SIZE {
		t.Fatalf("error=%v reads=%d", err, reads)
	}
}

//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func startupRaw(t *testing.T, w *replayWorld, rank uint8, key, value []byte) {
	t.Helper()
	if w.pre == nil {
		w.pre = w.image()
	}
	startupRawExpected(w, rank, key, value)
	if value == nil {
		logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.store, rank, key) == nil, "raw startup absence fixture")
		return
	}
	logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.store, rank, key, value) == nil, "raw startup fixture seed")
}

// Maintain the prepared logical image from its independently captured healthy
// preimage and the exact setup mutation. The product never receives this image.
func startupRawExpected(w *replayWorld, rank uint8, key, value []byte) {
	wantedKey := append([]byte{rank}, key...)
	for at, row := range w.pre {
		if bytes.Equal(row.Key, wantedKey) {
			if value != nil {
				w.pre[at].Value = bytes.Clone(value)
				return
			}
			w.pre = append(w.pre[:at], w.pre[at+1:]...)
			count := binary.BigEndian.Uint64(w.pre[0].Value[int(rank)*8:])
			binary.BigEndian.PutUint64(w.pre[0].Value[int(rank)*8:], count-1)
			return
		}
	}
	if value != nil {
		w.pre = append(w.pre, mdbx.PrefixRow{Key: wantedKey, Value: bytes.Clone(value)})
		count := binary.BigEndian.Uint64(w.pre[0].Value[int(rank)*8:])
		binary.BigEndian.PutUint64(w.pre[0].Value[int(rank)*8:], count+1)
	}
}

func startupRawImageEqual(t *testing.T, w *replayWorld) {
	t.Helper()
	inspection, err := w.store.Inspect()
	logicalMDBXAssert(t, err == nil, "prepared raw image inspect: %v", err)
	var counts []byte
	for _, dbi := range inspection.DBIs {
		counts = binary.BigEndian.AppendUint64(counts, dbi.Entries)
	}
	logicalMDBXAssert(t, bytes.Equal(counts, w.pre[0].Value), "prepared complete DBI cardinality changed")
	for _, row := range w.pre[1:] {
		equal, err := mdbx.FixtureRawRowEqual(w.store, row.Key[0], row.Key[1:], row.Value)
		logicalMDBXAssert(t, err == nil && equal, "prepared raw image row %d/%x changed: %v/%v", row.Key[0], row.Key[1:], equal, err)
	}
}

// Prepare a distinct target-only header with a legal partial APPLIED1 prefix.
// All setup effects enter the independently captured raw preimage, including
// deleted old owners and the new header; only a caller's later fault is invalid.
func startupTargetHeader(t *testing.T, w *replayWorld, work [40]byte, target byte) []byte {
	t.Helper()
	header := bytes.Clone(w.headers[1][:])
	header[115] ^= 1
	if target != 0 {
		clear(header[76:108])
		header[107] = target
	}
	hash, _ := BlockHash(header)
	oldCursor := w.authority().Replay.Cursor.Height
	w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
		a.Replay.Cursor = mdbx.ReplayCursorV1{Kind: 2, Height: 1, BlockHash: hash}
	})
	if oldCursor == 2 {
		startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(2, 2)), nil)
		startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[2])), nil)
	}
	startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[1])), nil)
	startupRaw(t, w, 3, hash[:], header)
	startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(2, 1)), mdbx.ChainValue(hash, w.hashes[0], work))
	startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, hash)), binary.BigEndian.AppendUint64(nil, 1))
	w.hashes, w.headers = append(w.hashes, hash), append(w.headers, [116]byte(header))
	return bytes.Clone(hash[:])
}

func startupRawPreserved(t *testing.T, w *replayWorld, rank uint8, key, value []byte) ReplayStartupOutcomeV1 {
	t.Helper()
	w.store = w.reopen()
	var out ReplayStartupOutcomeV1
	if rank == 0 {
		evidence, probeErr := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = startupRun(w) })
		e, native := out.Err.(*mdbx.EngineError)
		logicalMDBXAssert(t, probeErr == nil && evidence.OldPulls == ([8]uint64{}) && native && e.Class == "Integrity" && e.Operation == "get" && e.Code == -30793 && e.Diagnostic == "invalid storage authority" && e.Cause != nil, "authority full decoder before traversal: %+v/%v/%v", evidence, out.Err, probeErr)
	} else {
		out = startupRun(w)
	}
	startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
	if _, recorded := out.Err.(*mdbx.EngineError); recorded {
		logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("recorded native View callback"); return nil }) == out.Err, "recorded native cached View identity")
		_, _, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) {
			t.Fatal("recorded native Update callback")
			return mdbx.Batch{}, nil
		})
		logicalMDBXAssert(t, next == out.Err, "recorded native cached Update identity")
		w.store = w.reopen()
	} else {
		logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { return nil }) == nil, "application positive consumed original Store")
		startupFreshGuard(t, w, false)
	}
	equal, err := mdbx.FixtureRawRowEqual(w.store, rank, key, value)
	logicalMDBXAssert(t, err == nil && equal, "raw preimage changed: %v/%v", equal, err)
	startupRawImageEqual(t, w)
	startupFreshGuard(t, w, false)
	return out
}

func TestReplayStartupMDBXNativeRows(t *testing.T) {
	for _, g := range []uint64{1, 2} {
		t.Run(fmt.Sprintf("R04 g%d repeated forward hash", g), func(t *testing.T) {
			w := startupWorld(t, 2, 2)
			key := logicalMDBXMust(mdbx.HeightKey(g, 1))
			value := mdbx.ChainValue(w.hashes[0], w.hashes[0], sideWorldWork(2))
			startupRaw(t, w, 2, key, value)
			w.store = w.reopen()
			out := startupRun(w)
			startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			logicalMDBXAssert(t, out.Err.Error() == "startup parent mismatch", "first reachable repeated-hash relationship: %v", out.Err)
			startupRawImageEqual(t, w)
			startupFreshGuard(t, w, false)
		})
		t.Run(fmt.Sprintf("R05 H02 g%d first inverse disagreement", g), func(t *testing.T) {
			w := startupWorld(t, 0, 0)
			first := logicalMDBXMust(mdbx.CanonicalOwnerKey(g, [32]byte{0xfe}))
			later := logicalMDBXMust(mdbx.CanonicalOwnerKey(g, [32]byte{0xff}))
			startupRaw(t, w, 7, first, binary.BigEndian.AppendUint64(nil, 0))
			startupRaw(t, w, 7, later, make([]byte, 7))
			w.store = w.reopen()
			var out ReplayStartupOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageStartupPullEIO, 7, append(bytes.Clone(first), 0), func() { out = startupRun(w) })
			startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			logicalMDBXAssert(t, out.Err.Error() == "startup extra or disagreeing inverse" && evidence.Faults == 0 && err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed", "first inverse before later malformed/EIO: %+v/%v/%v", evidence, out.Err, err)
			startupRawImageEqual(t, w)
			startupFreshGuard(t, w, false)
		})
		for _, row := range []struct {
			name       string
			rank       uint8
			key, value func(*replayWorld) []byte
		}{
			{"forward short", 2, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(g, 0)) }, func(w *replayWorld) []byte { return make([]byte, 103) }},
			{"forward long", 2, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(g, 0)) }, func(w *replayWorld) []byte { return make([]byte, 105) }},
			{"forward key short", 2, func(w *replayWorld) []byte { return binary.BigEndian.AppendUint64(nil, g) }, func(w *replayWorld) []byte { return make([]byte, 104) }},
			{"forward key long", 2, func(w *replayWorld) []byte { return append(logicalMDBXMust(mdbx.HeightKey(g, 0)), 0) }, func(w *replayWorld) []byte { return make([]byte, 104) }},
			{"inverse absent", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, w.hashes[0])) }, func(w *replayWorld) []byte { return nil }},
			{"inverse short", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, w.hashes[0])) }, func(w *replayWorld) []byte { return make([]byte, 7) }},
			{"inverse long", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, w.hashes[0])) }, func(w *replayWorld) []byte { return make([]byte, 9) }},
			{"inverse wrong height", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, w.hashes[0])) }, func(w *replayWorld) []byte { return binary.BigEndian.AppendUint64(nil, 1) }},
			{"inverse extra", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, [32]byte{0x91})) }, func(w *replayWorld) []byte { return binary.BigEndian.AppendUint64(nil, 0) }},
			{"extra inverse short", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, [32]byte{0x91})) }, func(w *replayWorld) []byte { return make([]byte, 7) }},
			{"extra inverse long", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, [32]byte{0x91})) }, func(w *replayWorld) []byte { return make([]byte, 9) }},
			{"extra inverse absent forward", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, [32]byte{0x91})) }, func(w *replayWorld) []byte { return binary.BigEndian.AppendUint64(nil, 3) }},
			{"inverse height overflow", 7, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.CanonicalOwnerKey(g, [32]byte{0x91})) }, func(w *replayWorld) []byte { return binary.BigEndian.AppendUint64(nil, 0x100000000) }},
			{"header absent", 3, func(w *replayWorld) []byte { return w.hashes[0][:] }, func(w *replayWorld) []byte { return nil }},
			{"header short", 3, func(w *replayWorld) []byte { return w.hashes[0][:] }, func(w *replayWorld) []byte { return make([]byte, 115) }},
			{"header long", 3, func(w *replayWorld) []byte { return w.hashes[0][:] }, func(w *replayWorld) []byte { return make([]byte, 117) }},
			{"header misbound", 3, func(w *replayWorld) []byte { return w.hashes[0][:] }, func(w *replayWorld) []byte {
				header := bytes.Clone(w.headers[0][:])
				header[115] ^= 1
				return header
			}},
		} {
			t.Run(fmt.Sprintf("R03-R05 g%d %s", g, row.name), func(t *testing.T) {
				w := startupWorld(t, 2, 2)
				key, value := row.key(w), row.value(w)
				if g == 2 && row.rank == 3 {
					// Shared genesis belongs to active first. A distinct later target header reaches the target owner.
					key = startupTargetHeader(t, w, sideWorldWork(2), 0)
					if row.name == "header misbound" {
						value = bytes.Clone(w.headers[len(w.headers)-1][:])
						value[115] ^= 1
					}
				}
				startupRaw(t, w, row.rank, key, value)
				out := startupRawPreserved(t, w, row.rank, key, value)
				if row.name == "header misbound" {
					logicalMDBXAssert(t, out.Err.Error() == "startup header identity mismatch", "header binding owner was not reached: %v", out.Err)
				}
			})
		}
	}
	for _, rank := range []uint8{2, 7, 0} {
		t.Run(fmt.Sprintf("R07 PRE_GENESIS rank%d", rank), func(t *testing.T) {
			w := startupWorld(t, 0, -1)
			key, value := logicalMDBXMust(mdbx.HeightKey(2, 0)), mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(1))
			if rank == 0 {
				startupRaw(t, w, 2, key, value)
				rank = 7
			}
			if rank == 7 {
				key, value = logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[0])), binary.BigEndian.AppendUint64(nil, 0)
			}
			startupRaw(t, w, rank, key, value)
			startupRawPreserved(t, w, rank, key, value)
		})
	}
	for _, shape := range []string{"missing", "truncated", "trailing", "version", "phase", "lifecycle", "pending profile", "selected", "detached", "cleanup payload", "ordinary payload", "unsupported malformed", "empty exclusion", "same generation", "zero active", "zero target generation", "next zero", "target equals next", "cursor zero", "cursor unknown", "cursor beyond tip", "cursor genesis hash", "target height zero", "target height overflow", "target work zero", "target work overflow", "profile zero", "profile unknown", "pruned B0 U13681", "pruned B1 U13680", "archive B1 U0"} {
		t.Run("R02 authority "+shape, func(t *testing.T) {
			w := startupWorld(t, 0, 0)
			a := w.authority()
			raw, _ := a.Encode()
			map[string]func(){
				"missing":         func() { raw = nil },
				"truncated":       func() { raw = raw[:39] },
				"trailing":        func() { raw = append(raw, 0) },
				"version":         func() { raw[0] = 2 },
				"phase":           func() { raw[34] = 255 },
				"lifecycle":       func() { raw[35] = 1 },
				"pending profile": func() { raw = replayIllegalTail(t, raw, []byte{1, 2, 0, 0, 0}) },
				"selected": func() {
					work := sideWorldWork(1)
					selected := bytes.Join([][]byte{binary.BigEndian.AppendUint64(nil, 3), make([]byte, 8), binary.BigEndian.AppendUint64(nil, 1), bytes.Repeat([]byte{1}, 32), work[:], {0, 1}, binary.BigEndian.AppendUint64(nil, 1)}, nil)
					raw = replayIllegalTail(t, raw, []byte{0, 0, 1}, selected, []byte{0})
				},
				"detached": func() {
					detached := bytes.Join([][]byte{{0, 1}, binary.BigEndian.AppendUint64(nil, 1), bytes.Repeat([]byte{1}, 32), binary.BigEndian.AppendUint64(nil, 1), binary.BigEndian.AppendUint64(nil, 1), bytes.Repeat([]byte{1}, 32), {0, 1}, binary.BigEndian.AppendUint64(nil, 1)}, nil)
					raw = replayIllegalTail(t, raw, []byte{0, 0, 0, 1}, detached)
				},
				"cleanup payload": func() {
					raw = replayIllegalTail(t, raw, []byte{1, 1}, binary.BigEndian.AppendUint64(nil, 3), []byte{0, 0, 0, 0})
				},
				"ordinary payload":       func() { raw = replayIllegalTail(t, raw, []byte{2, 0, 0, 0, 0}) },
				"unsupported malformed":  func() { raw[34], raw[36] = 1, 255 },
				"same generation":        func() { binary.BigEndian.PutUint64(raw[37:45], 1) },
				"zero active":            func() { clear(raw[18:26]) },
				"zero target generation": func() { clear(raw[37:45]) },
				"next zero":              func() { clear(raw[26:34]) },
				"target equals next":     func() { binary.BigEndian.PutUint64(raw[26:34], 2) },
				"cursor zero":            func() { raw[189] = 0 },
				"cursor unknown":         func() { raw[189] = 255 },
				"cursor beyond tip":      func() { binary.BigEndian.PutUint64(raw[190:198], 2) },
				"cursor genesis hash":    func() { raw[198] ^= 1 },
				"target height zero":     func() { clear(raw[141:149]) },
				"target height overflow": func() { binary.BigEndian.PutUint64(raw[141:149], 0x100000000) },
				"target work zero":       func() { clear(raw[149:189]) },
				"target work overflow": func() {
					clear(raw[149:189])
					raw[152], raw[188] = 1, 1
				},
				"profile zero":    func() { raw[36] = 0 },
				"profile unknown": func() { raw[36] = 255 },
				"pruned B0 U13681": func() {
					raw[1] = 1
					binary.BigEndian.PutUint64(raw[2:10], 0)
					binary.BigEndian.PutUint64(raw[10:18], 13681)
				},
				"pruned B1 U13680": func() {
					raw[1] = 1
					binary.BigEndian.PutUint64(raw[2:10], 1)
					binary.BigEndian.PutUint64(raw[10:18], 13680)
				},
				"archive B1 U0": func() {
					raw[1] = 2
					binary.BigEndian.PutUint64(raw[2:10], 1)
					binary.BigEndian.PutUint64(raw[10:18], 0)
				},
				"empty exclusion": func() {
					a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, ExactConsensusError: []byte("x")}
					raw, _ = a.Encode()
					// Remove only the token byte, preserving both following absent
					// option tags and declaring an exact zero-length blob.
					raw = append(raw[:276], raw[277:]...)
					clear(raw[272:276])
				},
			}[shape]()
			startupRaw(t, w, 0, []byte{2}, raw)
			startupRawPreserved(t, w, 0, []byte{2}, raw)
		})
	}
}

func TestReplayStartupMDBXReachedReadOrder(t *testing.T) {
	for _, row := range []struct {
		name           string
		profile        mdbx.StorageProfileV1
		active, cursor int
		b, u, pulls    uint64
	}{
		{"R09 mixed profiles active15120 wrong B-U pair", 1, 15120, 0, 0, 13680, 15122},
		{"R09 mixed profiles active15120 wrong U", 2, 15120, 0, 0, 13680, 15122},
		{"R09 empty active wrong B-U pair", 1, -1, -1, 1, 13681, 1},
		{"R09 empty active wrong U", 2, -1, -1, 0, 1, 1},
		{"R09 H0 active wrong B-U pair", 1, 0, 0, 1, 13681, 2},
		{"R09 H0 active wrong U", 2, 0, 0, 0, 1, 2},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := startupWorld(t, row.active, row.cursor)
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				a.ActiveProfile, a.Replay.TargetProfile, a.B, a.U = row.profile, 3-row.profile, row.b, row.u
			})
			before := w.image()
			w.store = w.reopen()
			var out ReplayStartupOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = startupRun(w) })
			startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			// Each active index includes its EOF pull: empty=1, H0=2,
			// H15120=15122. Any target pull changes the exact rank2 count.
			logicalMDBXAssert(t, err == nil && out.Err.Error() == "startup active bounds mismatch" && evidence.OldPulls[2] == row.pulls && evidence.OldPulls[7] == row.pulls, "bounds before target: %+v/%v/%v", evidence, out.Err, err)
			replaySameImage(t, before, w.image(), "boundary bounds image")
			startupFreshGuard(t, w, false)
		})
	}
	for _, defect := range []string{"work", "extra inverse", "B", "U"} {
		t.Run("H02 active "+defect+" before target", func(t *testing.T) {
			w := startupWorld(t, 2, 2)
			if defect == "B" {
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.ActiveProfile, a.B, a.U = 1, 1, 13681 })
			}
			if defect == "U" {
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) { a.ActiveProfile, a.U = 2, 1 })
			}
			startupRaw(t, w, 3, startupTargetHeader(t, w, sideWorldWork(2), 0), nil)
			if defect == "work" {
				startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(2)))
			}
			if defect == "extra inverse" {
				startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(1, [32]byte{0x91})), binary.BigEndian.AppendUint64(nil, 0))
			}
			w.store = w.reopen()
			var out ReplayStartupOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = startupRun(w) })
			startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			want := map[string]string{"work": "startup cumulative work mismatch", "extra inverse": "startup extra or disagreeing inverse", "B": "startup active bounds mismatch", "U": "startup active bounds mismatch"}[defect]
			pulls := map[string]uint64{"work": 1, "extra inverse": 4, "B": 4, "U": 4}[defect]
			logicalMDBXAssert(t, err == nil && out.Err.Error() == want && evidence.OldPulls[2] == pulls, "active complete owner did not precede target: %+v/%v/%v", evidence, out.Err, err)
			startupRawImageEqual(t, w)
			startupFreshGuard(t, w, false)
		})
	}
	for _, source := range []string{"begin IO", "begin Transaction", "authority IO"} {
		t.Run("R08 "+source, func(t *testing.T) {
			w := startupWorld(t, 0, 0)
			w.store = w.reopen()
			before := w.image()
			scenario, key := mdbx.SelectedDamageScenario(3), []byte(nil)
			want, operation, code := "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", "view", 5
			if source == "begin Transaction" {
				scenario, want, code = 2, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", -30788
			}
			if source == "authority IO" {
				scenario, key, operation = mdbx.SelectedDamageGetEIO, []byte{2}, "get"
			}
			var out ReplayStartupOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, 0, key, func() { out = startupRun(w) })
			startupTuple(t, out, false, 2, want)
			e := out.Err.(*mdbx.EngineError)
			logicalMDBXAssert(t, err == nil && evidence.BeginOld == 1 && evidence.Faults == 1 && evidence.OldPulls == ([8]uint64{}) && e.Operation == operation && e.Code == code && e.Cause == nil, "begin/authority provenance: %+v/%v/%v", evidence, e, err)
			logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("consumed entry callback"); return nil }) == out.Err, "begin/authority cached identity")
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "begin/authority image")
			startupFreshGuard(t, w, false)
		})
	}
	t.Run("A09 H09 reservation admission and abort lifetime", func(t *testing.T) {
		for _, free := range []uint64{4095, 4096, 154611151} {
			w := startupWorld(t, 0, 0)
			w.store = w.reopen()
			before := w.image()
			var out ReplayStartupOutcomeV1
			var evidence mdbx.SelectedDamageEvidence
			err := w.owner.WithReservation(154611151-free, func() error {
				var fixtureErr error
				evidence, fixtureErr = mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = startupRun(w) })
				return fixtureErr
			})
			logicalMDBXAssert(t, err == nil, "reservation native probe: %v", err)
			if free == 4095 {
				startupTuple(t, out, false, 2, "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)")
				logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(out.Err) && evidence.BeginOld == 0 && evidence.OldGets == ([8]uint64{}) && evidence.OldPulls == ([8]uint64{}) && evidence.OldAborts == 0 && evidence.Probes == 0, "capacity denial entered native owner: %+v", evidence)
			} else {
				startupTuple(t, out, true, 1, "")
				logicalMDBXAssert(t, evidence.BeginOld == 1 && evidence.OldAborts == 1 && evidence.Probes == 2 && evidence.ProbeDenied == 2 && evidence.ProbeRan == 0, "grant retired before abort/publication: %+v", evidence)
			}
			logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "startup grant not released")
			replaySameImage(t, before, w.image(), "reservation prepared image")
		}
		for _, shape := range []string{"zero chainID", "zero genesis", "nil Store zero owner"} {
			w := startupWorld(t, 0, 0)
			w.store = w.reopen()
			before := w.image()
			store := map[string]*mdbx.Store{"zero chainID": w.store, "zero genesis": w.store, "nil Store zero owner": nil}[shape]
			owner := map[string]*mdbx.OperationReservationOwner{"zero chainID": w.owner, "zero genesis": w.owner, "nil Store zero owner": {}}[shape]
			chain := map[string][32]byte{"zero chainID": {}, "zero genesis": w.genesis.ChainID, "nil Store zero owner": w.genesis.ChainID}[shape]
			genesis := map[string][32]byte{"zero chainID": w.genesis.GenesisHash, "zero genesis": {}, "nil Store zero owner": w.genesis.GenesisHash}[shape]
			var out ReplayStartupOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = VerifyPersistedReplayStartupMDBX(store, owner, chain, genesis) })
			startupTuple(t, out, false, 0, "")
			logicalMDBXAssert(t, err == nil && evidence.BeginOld == 0 && evidence.OldGets == ([8]uint64{}) && evidence.OldPulls == ([8]uint64{}) && evidence.OldAborts == 0 && evidence.Probes == 0, "early admission reached native owner %s: %+v/%v", shape, evidence, err)
			if shape == "nil Store zero owner" {
				e := out.Err.(*mdbx.EngineError)
				logicalMDBXAssert(t, e.Class == "InvalidInput" && e.Operation == "view" && e.Code == 22 && e.Diagnostic == "nil Store", "nil Store before zero owner")
			} else {
				logicalMDBXAssert(t, out.Err == errInvalidStartupNetworkContext, "valid Store context precedence")
			}
			replaySameImage(t, before, w.image(), "early admission image")
			startupFreshGuard(t, w, false)
		}
	})
	for _, row := range []struct {
		name, edit, want string
		cursor           int
		tip              uint64
		work             [40]byte
		heights          []uint64
	}{
		{"generic PRE invalid work", "", "startup replay target work outside consistency bounds", -1, 1, [40]byte{39: 1}, []uint64{0}},
		{"tip equals genesis", "tip genesis", "startup replay target repeats a known hash", -1, 1, [40]byte{39: 2}, []uint64{0}},
		{"tip equals cursor", "tip cursor", "startup replay target repeats a known hash", 1, 3, [40]byte{39: 4}, []uint64{0}},
		{"cursor equals genesis", "cursor genesis", "startup replay target repeats a known hash", 1, 3, [40]byte{39: 4}, []uint64{0}},
		{"excluded genesis", "excluded genesis", "startup replay target contains excluded hash", -1, 1, [40]byte{39: 2}, []uint64{0, 0xffffffff}},
		{"excluded tip", "excluded tip", "startup replay target contains excluded hash", -1, 1, [40]byte{39: 2}, []uint64{0, 0xffffffff}},
		{"excluded cursor", "excluded cursor", "startup replay target contains excluded hash", 1, 3, [40]byte{39: 4}, []uint64{0, 0xffffffff}},
	} {
		for _, recordedHeight := range row.heights {
			t.Run(fmt.Sprintf("H11 %s height%d before first pull", row.name, recordedHeight), func(t *testing.T) {
				w := startupWorld(t, -1, row.cursor)
				w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
					target := &a.Replay.Target
					target.TipHeight, target.CumulativeChainwork = row.tip, row.work
					switch row.edit {
					case "tip genesis":
						target.TipHash = target.GenesisHash
					case "tip cursor":
						target.TipHash = a.Replay.Cursor.BlockHash
					case "cursor genesis":
						a.Replay.Cursor.BlockHash = target.GenesisHash
					}
					if hash, excluded := map[string][32]byte{"excluded genesis": target.GenesisHash, "excluded tip": target.TipHash, "excluded cursor": a.Replay.Cursor.BlockHash}[row.edit]; excluded {
						a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: recordedHeight, FirstInvalidBlockHash: hash, ExactConsensusError: []byte("BLOCK_ERR_PARSE")}
					}
				})
				before := w.image()
				w.store = w.reopen()
				var out ReplayStartupOutcomeV1
				evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageStartupPullEIO, 2, binary.BigEndian.AppendUint64(nil, 1), func() { out = startupRun(w) })
				startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
				logicalMDBXAssert(t, out.Err.Error() == row.want && evidence.BeginOld == 1 && evidence.OldAborts == 1 && evidence.Faults == 0 && evidence.OldGets == ([8]uint64{0: 1}) && evidence.OldPulls == ([8]uint64{}) && err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed", "metadata before canonical native read: %+v/%v/%v", evidence, out.Err, err)
				replaySameImage(t, before, w.image(), "metadata readonly image")
				startupFreshGuard(t, w, false)
				logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "metadata grant release")
			})
		}
	}
	for _, generation := range []uint64{1, 2} {
		for _, relation := range []string{"", "partial lower", "partial upper"} {
			for _, fault := range []string{"pull", "header", "inverse probe", "inverse pass", "forward probe"} {
				name := fmt.Sprintf("R08 g%d %s", generation, fault)
				if relation != "" {
					name = fmt.Sprintf("H13 g%d %s %s", generation, fault, relation)
				}
				t.Run(name, func(t *testing.T) {
					w := startupWorld(t, map[uint64]int{1: 1, 2: 0}[generation], 1)
					var targetHeader []byte
					if relation != "" {
						work, target := [40]byte{7: 1, 39: 1}, byte(1)
						declared := [40]byte{7: 1, 39: 2}
						if relation == "partial upper" {
							work, target, declared = [40]byte{8: 128, 39: 1}, 2, [40]byte{7: 2, 8: 128, 39: 2}
						}
						targetHeader = startupTargetHeader(t, w, work, target)
						w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
							a.Replay.Target.TipHeight, a.Replay.Target.CumulativeChainwork = 3, declared
						})
						w.pre = w.image()
					}
					w.store = w.reopen()
					before := w.image()
					rank, scenario := uint8(2), mdbx.SelectedDamageStartupPullEIO
					key := binary.BigEndian.AppendUint64(nil, generation)
					switch fault {
					case "header":
						rank, scenario, key = 3, mdbx.SelectedDamageGetEIO, w.hashes[0][:]
					case "inverse probe":
						rank, scenario, key = 7, mdbx.SelectedDamageGetEIO, logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, w.hashes[0]))
					case "inverse pass":
						rank = 7
					case "forward probe":
						scenario, key = mdbx.SelectedDamageGetEIO, logicalMDBXMust(mdbx.HeightKey(generation, 0))
					}
					if generation == 2 && fault == "header" {
						if relation == "" {
							targetHeader = startupTargetHeader(t, w, sideWorldWork(2), 0)
						}
						key, before = targetHeader, w.image()
					}
					var out ReplayStartupOutcomeV1
					evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { out = startupRun(w) })
					logicalMDBXAssert(t, err == nil && evidence.BeginOld == 1 && evidence.BeginWrite == 0 && evidence.BeginRead == 0 && evidence.Faults == 1 && evidence.OldAborts == 1 && evidence.Commits == 0, "actual startup transport: %+v/%v", evidence, err)
					resource := [3]string{"", "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)", "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"}[generation]
					startupTuple(t, out, false, 2, resource)
					e := out.Err.(*mdbx.EngineError)
					operation := map[mdbx.SelectedDamageScenario]string{mdbx.SelectedDamageStartupPullEIO: "prefix-page", mdbx.SelectedDamageGetEIO: "get"}[scenario]
					logicalMDBXAssert(t, e.Class == "IO" && e.Code == 5 && e.Operation == operation && e.Cause == nil && !e.ReopenRequired, "source raw tuple: %+v", e)
					logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("consumed View callback"); return nil }) == out.Err, "cached source identity")
					_, _, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { t.Fatal("consumed Update callback"); return mdbx.Batch{}, nil })
					logicalMDBXAssert(t, next == out.Err, "cached Update identity")
					w.store = w.reopen()
					replaySameImage(t, before, w.image(), "read EIO image")
					if w.pre != nil {
						startupRawImageEqual(t, w)
					}
					startupFreshGuard(t, w, false)
					if generation == 2 && fault == "header" && relation == "" {
						startupTuple(t, startupRun(w), true, 1, "")
						startupRawImageEqual(t, w)
					}
				})
			}
		}
	}
	for _, generation := range []uint64{1, 2} {
		for _, fact := range []string{"", "tip", "cursor", "excluded", "known G"} {
			for _, current := range []string{"clean", "work", "header", "inverse"} {
				if fact == "" && current == "clean" {
					continue
				}
				for _, tail := range []string{"armed EIO", "malformed width"} {
					if tail == "malformed width" && (fact != "" || current == "work") {
						continue
					}
					name := fmt.Sprintf("H12 current%s g%d before%s and successor", current, generation, fact)
					if fact == "" {
						name = fmt.Sprintf("H01 current %s before successor g%d %s", current, generation, tail)
					}
					t.Run(name, func(t *testing.T) {
						active, cursor, height := 1, 1, uint64(0)
						if fact != "" {
							active, cursor, height = map[uint64]int{1: 2, 2: 0}[generation], 2, 1
						}
						if fact == "known G" {
							active, cursor, height = map[uint64]int{1: 0, 2: -1}[generation], 0, 0
						}
						w := startupWorld(t, active, cursor)
						w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
							switch fact {
							case "tip":
								a.Replay.Target.TipHash = w.hashes[1]
							case "cursor":
								a.Replay.Cursor.BlockHash = w.hashes[1]
							case "excluded":
								a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 0xffffffff, FirstInvalidBlockHash: w.hashes[1], ExactConsensusError: []byte("BLOCK_ERR_PARSE")}
							case "known G":
								a.Replay.Target.CumulativeChainwork = [40]byte{7: 2}
							}
						})
						switch current {
						case "work":
							parent := [32]byte{}
							if height != 0 {
								parent = w.hashes[height-1]
							}
							startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(generation, height)), mdbx.ChainValue(w.hashes[height], parent, sideWorldWork(height+2)))
						case "header":
							key := w.hashes[height][:]
							if fact == "" && generation == 2 {
								key, height = startupTargetHeader(t, w, sideWorldWork(2), 0), 1
							}
							startupRaw(t, w, 3, key, nil)
						case "inverse":
							startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, w.hashes[height])), binary.BigEndian.AppendUint64(nil, height+1))
						}
						if current == "clean" && generation == 1 && fact == "excluded" {
							height = 2
						}
						if tail == "malformed width" {
							startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(generation, height+1)), make([]byte, 103))
						}
						before := w.pre
						if before == nil {
							before = w.image()
						}
						w.store = w.reopen()
						seek, scenario := append(logicalMDBXMust(mdbx.HeightKey(generation, height)), 0), mdbx.SelectedDamageStartupPullEIO
						if tail == "malformed width" {
							seek, scenario = nil, mdbx.SelectedDamageProbeOnly
						}
						var out ReplayStartupOutcomeV1
						evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, 2, seek, func() { out = startupRun(w) })
						startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
						want := map[string]string{"work": "startup cumulative work mismatch", "header": "startup required header is absent", "inverse": "startup inverse height mismatch"}[current]
						if current == "clean" {
							want = map[string]string{"tip": map[uint64]string{1: "startup known target tip mismatch", 2: "startup replay target repeats a known hash"}[generation], "cursor": "startup replay target repeats a known hash", "excluded": "startup replay target contains excluded hash", "known G": "startup replay target work outside consistency bounds"}[fact]
						}
						pulls := map[uint64]uint64{1: height + 1, 2: height + 3}[generation]
						if fact == "" && generation == 2 {
							pulls = height + 4
						}
						if fact == "known G" && generation == 2 {
							pulls = 2
						}
						if tail == "armed EIO" {
							logicalMDBXAssert(t, err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed", "successor EIO reachability: %v", err)
						} else {
							logicalMDBXAssert(t, err == nil, "malformed successor probe: %v", err)
						}
						logicalMDBXAssert(t, out.Err.Error() == want && evidence.Faults == 0 && evidence.OldPulls[2] == pulls && evidence.OldAborts == 1, "current complete owner before successor: %+v/%v", evidence, out.Err)
						logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { return nil }) == nil, "current application positive consumed original Store")
						if w.pre != nil {
							startupRawImageEqual(t, w)
						} else {
							replaySameImage(t, before, w.image(), "observed point readonly image")
						}
						startupFreshGuard(t, w, false)
						logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "observed point grant release")
					})
				}
			}
		}
	}
}

type startupCacheBytes []byte

func (startupCacheBytes) Error() string { return "noncomparable cached application" }

func TestReplayStartupMDBXCleanupProjection(t *testing.T) {
	for _, row := range []struct {
		name, positive, state, result string
		active                        int
		mode                          uint32
		busy, source                  bool
		decision                      uint8
		prepare                       string
		accepted                      bool
		diagnostic                    string
	}{
		{"H10 completed positive close BUSY abort0", "work", "OPEN", "TERMINAL_STORE_INTEGRITY(canonical)", 0, 0, true, false, 3, "", false, ""},
		{"H10 completed positive close BUSY abort9", "work", "CLOSE_BLOCKED", "TERMINAL_STORE_INTEGRITY(canonical)", 0, 9, true, false, 3, "", false, ""},
		{"H10 positivefalse mode9", "", "CLOSED", "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 0, 9, false, false, 2, "", false, ""},
		{"H10 positivefalse mode10", "", "POISONED_THREAD", "TERMINAL_LOCAL_INVARIANT(evidence)", 0, 10, false, false, 0, "", false, ""},
		{"H10 positivetrue mode9", "work", "CLOSED", "TERMINAL_STORE_INTEGRITY(canonical)", 0, 9, false, false, 3, "", false, ""},
		{"H10 positivetrue mode10", "work", "POISONED_THREAD", "TERMINAL_STORE_INTEGRITY(canonical)", 0, 10, false, false, 3, "", false, ""},
		{"H10 g1 read EIO close BUSY abort0", "", "CLOSE_BLOCKED", "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)", 0, 0, true, true, 2, "", false, ""},
		{"H10 g2 read EIO close BUSY abort0", "", "CLOSE_BLOCKED", "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)", -1, 0, true, true, 2, "", false, ""},
		{"H10 g1 read EIO close BUSY abort9", "", "CLOSE_BLOCKED", "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)", 0, 9, true, true, 2, "", false, ""},
		{"H10 g2 read EIO close BUSY abort9", "", "CLOSE_BLOCKED", "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)", -1, 9, true, true, 2, "", false, ""},
		{"H14 fixed tip cursor fork", "fork", "OPEN", "TERMINAL_STORE_INTEGRITY(canonical)", 3, 0, false, false, 3, "fork", false, "startup known target cursor ancestry mismatch"},
		{"H14 fixed tip cursor fork THREAD", "fork", "POISONED_THREAD", "TERMINAL_STORE_INTEGRITY(canonical)", 3, 10, false, false, 3, "fork", false, ""},
		{"A14 unknown tip cursor fork", "", "OPEN", "", 3, 0, false, false, 1, "fork unknown", true, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			cursor := map[string]int{"": 0, "fork": 1, "fork unknown": 1}[row.prepare]
			w := startupWorld(t, row.active, cursor)
			if row.prepare != "" {
				startupSemanticEdit(t, w, 2, "fork cursor")
				if row.prepare == "fork" {
					w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
						a.Replay.Target.TipHeight, a.Replay.Target.TipHash, a.Replay.Target.CumulativeChainwork = 3, w.hashes[3], [40]byte{39: 4}
					})
				}
			}
			if row.positive == "work" {
				startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(2)))
			}
			before := w.image()
			w.store = w.reopen()
			t.Cleanup(func() { _ = mdbx.FixtureStartupRelease(w.store) })
			var out ReplayStartupOutcomeV1
			run := func() {
				out = startupRun(w)
				if row.state != "OPEN" {
					for attempt := 0; attempt < 2; attempt++ {
						repeated := startupRun(w)
						startupTuple(t, repeated, false, 0, "TERMINAL_LOCAL_INVARIANT(evidence)")
						logicalMDBXAssert(t, repeated.Err == out.Err, "native cached raw identity")
						logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "repeat grant release")
					}
				}
			}
			state, verified, err := mdbx.FixtureStartupCleanup(w.store, row.mode, row.busy, func() {
				scenario := map[bool]mdbx.SelectedDamageScenario{false: mdbx.SelectedDamageProbeOnly, true: mdbx.SelectedDamageGetEIO}[row.source]
				counts, armedErr := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, 3, w.hashes[0][:], run)
				logicalMDBXAssert(t, armedErr == nil && counts.BeginOld == 1 && counts.BeginRead == 0 && counts.BeginWrite == 0 && counts.Faults == map[bool]uint64{false: 0, true: 1}[row.source], "cleanup source transport/repeat suppression: %+v/%v", counts, armedErr)
			})
			startupTuple(t, out, row.accepted, row.decision, row.result)
			logicalMDBXAssert(t, err == nil && state == row.state && verified == row.accepted, "actual cleanup state: %s/%v/%v", state, verified, err)
			if row.state == "OPEN" {
				want := row.diagnostic
				if row.positive == "work" {
					want = "startup cumulative work mismatch"
				}
				if want != "" {
					logicalMDBXAssert(t, out.Err.Error() == want, "positive successful abort diagnostic")
				}
			} else {
				e, _ := out.Err.(*mdbx.EngineError)
				if row.busy {
					logicalMDBXAssert(t, e != nil && e.Class == "Concurrency" && e.Operation == "close" && e.Code == -30778 && e.Cause != nil, "BUSY raw close PRIMARY cause")
				}
				if row.mode == 10 {
					logicalMDBXAssert(t, e != nil && e.Class == "LocalInvariant" && e.Operation == "abort" && e.Code == -30416 && (e.Cause != nil) == (row.positive != ""), "THREAD_MISMATCH raw head/PRIMARY cause")
					if row.prepare == "fork" {
						logicalMDBXAssert(t, e.Cause.Error() == "startup known target cursor ancestry mismatch", "new positive retained under THREAD cleanup")
					}
				}
				if row.source {
					read := e.Cause
					if row.mode == 9 {
						parts := e.Cause.(interface{ Unwrap() []error }).Unwrap()
						logicalMDBXAssert(t, len(parts) == 2, "BUSY read/abort join cardinality")
						abort := parts[1].(*mdbx.EngineError)
						logicalMDBXAssert(t, abort.Class == "IO" && abort.Operation == "abort" && abort.Code == 5 && abort.Cause == nil, "BUSY abort sibling identity/class")
						read = parts[0]
					}
					source := read.(*mdbx.EngineError)
					logicalMDBXAssert(t, source.Class == "IO" && source.Operation == "get" && source.Code == 5 && source.Diagnostic == "error 5" && source.Cause == nil, "BUSY first read identity/class")
				}
				logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("terminal callback"); return nil }) == out.Err, "cached View identity")
				_, _, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { t.Fatal("terminal Update callback"); return mdbx.Batch{}, nil })
				logicalMDBXAssert(t, next == out.Err, "cached Update identity")
				logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.store) == nil, "native cleanup teardown")
				w.store = w.reopen()
			}
			if w.pre != nil {
				startupRawImageEqual(t, w)
			} else {
				replaySameImage(t, before, w.image(), "native cleanup persisted image")
			}
			startupFreshGuard(t, w, row.accepted && row.state == "OPEN")
			logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "cleanup grant release")
		})
	}
	for _, origin := range []string{"View", "Update"} {
		for _, prior := range []bool{false, true} {
			for _, shape := range []string{"application", "EngineError Integrity", "EngineError BUSY", "EngineError unknown", "CommitError", "single wrapper", "custom multi-Unwrap", "Join one", "Join two", "Join nested", "Join mixed", "Join four", "typed nil", "noncomparable"} {
				t.Run(fmt.Sprintf("H10 cached %s prior%v %s", origin, prior, shape), func(t *testing.T) {
					w := startupWorld(t, 0, 0)
					w.store = w.reopen()
					if prior {
						startupTuple(t, startupRun(w), true, 1, "")
					}
					before := w.image()
					plain := errors.New("foreign cached application")
					integrity := &mdbx.EngineError{Class: "Integrity", Operation: "get", Code: -30796, Diagnostic: "application-shaped native"}
					busy := &mdbx.EngineError{Class: "Concurrency", Operation: "close", Code: -30778, Cause: plain}
					custom := &startupCustomJoin{children: []error{integrity, busy}}
					customBacking := &custom.children[0]
					payload := startupCacheBytes{0x31, 0x72}
					var typedNil *startupCustomJoin
					application := map[string]error{
						"application":           plain,
						"EngineError Integrity": integrity,
						"EngineError BUSY":      busy,
						"EngineError unknown":   &mdbx.EngineError{Class: "unknown", Operation: "get", Code: 781},
						"CommitError":           &mdbx.CommitError{Truth: 1, Cause: custom},
						"single wrapper":        fmt.Errorf("application wrapper: %w", custom),
						"custom multi-Unwrap":   custom,
						"Join one":              errors.Join(integrity),
						"Join two":              errors.Join(integrity, busy),
						"Join nested":           errors.Join(errors.Join(integrity, busy), errors.Join(plain)),
						"Join mixed":            errors.Join(busy, plain, integrity),
						"Join four":             errors.Join(busy, integrity, plain, custom),
						"typed nil":             typedNil,
						"noncomparable":         payload,
					}[shape]
					applicationPointer, applicationType := reflect.ValueOf(application).Pointer(), reflect.TypeOf(application)
					integrityBefore, busyBefore := *integrity, *busy
					var owned []error
					var ownedParents []error
					if reflect.TypeOf(application) == reflect.TypeOf(errors.Join(plain)) {
						owned = application.(interface{ Unwrap() []error }).Unwrap()
						ownedParents = append(ownedParents, application)
						for _, child := range owned {
							if reflect.TypeOf(child) == reflect.TypeOf(errors.Join(plain)) {
								ownedParents = append(ownedParents, child)
							}
						}
					}
					var ownedBackings, ownedBefore [][]error
					for _, parent := range ownedParents {
						children := parent.(interface{ Unwrap() []error }).Unwrap()
						ownedBackings = append(ownedBackings, children)
						ownedBefore = append(ownedBefore, append([]error(nil), children...))
					}
					var cached, cleanupErr error
					var state string
					var verified bool
					counts, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, []byte{0}, func() {
						state, verified, cleanupErr = mdbx.FixtureStartupCleanup(w.store, 9, false, func() {
							if origin == "View" {
								cached = w.store.View(func(*mdbx.Reader) error { return application })
							} else {
								truth, stage, raw := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { return mdbx.Batch{}, application })
								logicalMDBXAssert(t, truth == 1 && stage == 1, "cached Update origin truth/stage")
								cached = raw
							}
							parent := cached.(interface{ Unwrap() []error }).Unwrap()
							logicalMDBXAssert(t, len(parent) == 2 && reflect.TypeOf(parent[0]) == applicationType && reflect.ValueOf(parent[0]).Pointer() == applicationPointer, "cache origin application identity")
							abort := parent[1].(*mdbx.EngineError)
							logicalMDBXAssert(t, abort.Class == "IO" && abort.Operation == "abort" && abort.Code == 5 && abort.Cause == nil, "cache origin genuine abort sibling")
							parentBacking := &parent[0]
							for attempt := 0; attempt < 2; attempt++ {
								out := startupRun(w)
								startupTuple(t, out, false, 0, "TERMINAL_LOCAL_INVARIANT(evidence)")
								logicalMDBXAssert(t, out.Err == cached && custom.calls == 0, "cached identity/custom traversal changed")
								logicalMDBXAssert(t, len(custom.children) == 2 && &custom.children[0] == customBacking, "cached custom children backing changed")
								first, firstOK := custom.children[0].(*mdbx.EngineError)
								second, secondOK := custom.children[1].(*mdbx.EngineError)
								logicalMDBXAssert(t, firstOK && secondOK && first == integrity && second == busy, "cached custom children identity/order changed")
								if shape == "CommitError" {
									cause, ok := application.(*mdbx.CommitError).Cause.(*startupCustomJoin)
									logicalMDBXAssert(t, ok && cause == custom && application.(*mdbx.CommitError).Truth == 1, "cached CommitError Cause changed")
								}
								if shape == "single wrapper" {
									cause, ok := application.(interface{ Unwrap() error }).Unwrap().(*startupCustomJoin)
									logicalMDBXAssert(t, ok && cause == custom && custom.calls == 0, "cached single wrapper Cause changed")
								}
								children := cached.(interface{ Unwrap() []error }).Unwrap()
								logicalMDBXAssert(t, len(children) == 2 && &children[0] == parentBacking && reflect.TypeOf(children[0]) == applicationType && reflect.ValueOf(children[0]).Pointer() == applicationPointer && children[1].(*mdbx.EngineError) == abort, "cached raw tree/backing changed")
								logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("cached View callback"); return nil }) == cached, "cached View identity")
								truth, stage, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { t.Fatal("cached Update callback"); return mdbx.Batch{}, nil })
								logicalMDBXAssert(t, next == cached && truth == 1 && stage == 1, "cached Update identity/truth/stage")
								logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "cached grant release")
							}
						})
					})
					logicalMDBXAssert(t, err == nil && cleanupErr == nil && state == "CLOSED" && verified == prior && counts.BeginOld == 1 && counts.BeginRead == 0 && counts.BeginWrite == 0 && counts.OldGets == ([8]uint64{}) && counts.OldPulls == ([8]uint64{}) && counts.Faults == 0, "cached suppression/state/permission census: %+v/%s/%v/%v/%v", counts, state, verified, err, cleanupErr)
					logicalMDBXAssert(t, *integrity == integrityBefore && *busy == busyBefore && bytes.Equal(payload, []byte{0x31, 0x72}) && custom.calls == 0, "cached constituent fields/payload changed")
					for i, parent := range ownedParents {
						children := parent.(interface{ Unwrap() []error }).Unwrap()
						logicalMDBXAssert(t, len(children) == len(ownedBefore[i]) && &children[0] == &ownedBackings[i][0], "application join backing changed")
						for j, child := range children {
							logicalMDBXAssert(t, reflect.TypeOf(child) == reflect.TypeOf(ownedBefore[i][j]) && reflect.ValueOf(child).Pointer() == reflect.ValueOf(ownedBefore[i][j]).Pointer(), "application join child identity/order")
						}
					}
					w.store = w.reopen()
					replaySameImage(t, before, w.image(), "cached foreign readonly image")
					startupFreshGuard(t, w, false)
				})
			}
		}
	}
	t.Run("H10 early body visitor composition before outer View", func(t *testing.T) {
		w := startupWorld(t, 0, 0)
		startupRaw(t, w, 3, w.hashes[0][:], make([]byte, 117))
		body := bytes.Clone(w.genesis.Published)
		equal, bodyErr := mdbx.FixtureRawRowEqual(w.store, 4, w.hashes[0][:], body)
		logicalMDBXAssert(t, bodyErr == nil && equal && len(body) == 266, "prepared published genesis body rank4 is present: %v/%v", equal, bodyErr)
		w.pre = append(w.pre, mdbx.PrefixRow{Key: append([]byte{4}, w.hashes[0][:]...), Value: bytes.Clone(body)})
		w.store = w.reopen()
		var p, r, visited, cached, cleanupErr error
		var saved mdbx.LargeImageRowV1
		var callbacks int
		var state string
		var verified bool
		counts, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, []byte{0}, func() {
			state, verified, cleanupErr = mdbx.FixtureStartupCleanup(w.store, 9, false, func() {
				cached = w.store.View(func(reader *mdbx.Reader) error {
					visited = reader.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: 1, Hash: w.hashes[0]}, func(row mdbx.LargeImageRowV1) error {
						saved = row
						callbacks++
						logicalMDBXAssert(t, row.Present() && row.Length() == uint64(len(body)) && bytes.Equal(row.Key(), w.hashes[0][:]), "Kind1 body visitor route/presence/key/width")
						first := make([]byte, 1)
						n, readErr := row.ReadAt(first, 0)
						logicalMDBXAssert(t, readErr == nil && n == 1 && first[0] == body[0], "body rank4 bytes independent of malformed rank3 header")
						p = reader.VisitLargeImageV1(mdbx.LargeImageSelectorV1{}, nil)
						_, _, r = reader.Get(logicalMDBXDBIs[3], w.hashes[0][:])
						return p
					})
					return visited
				})
				inner := visited.(interface{ Unwrap() []error }).Unwrap()
				parent := cached.(interface{ Unwrap() []error }).Unwrap()
				outer := parent[0].(interface{ Unwrap() []error }).Unwrap()
				logicalMDBXAssert(t, len(inner) == 2 && inner[0] == p && inner[1] == r && len(outer) == 2 && outer[0] == visited && outer[1] == r, "early P/R and outer recorded-R order")
				abort := parent[1].(*mdbx.EngineError)
				logicalMDBXAssert(t, len(parent) == 2 && abort.Class == "IO" && abort.Operation == "abort" && abort.Code == 5 && abort.Cause == nil, "early actual consuming abort sibling")
				parentBacking, outerBacking, innerBacking := &parent[0], &outer[0], &inner[0]
				application := p.(*mdbx.EngineError)
				recorded := r.(*mdbx.EngineError)
				logicalMDBXAssert(t, application.Class == "InvalidInput" && application.Operation == "get" && application.Code == 22 && application.Diagnostic == "nil large image visitor" && recorded.Class == "Integrity" && recorded.Operation == "get" && recorded.Code == -30793 && recorded.Diagnostic == "stored value width outside SchemaV2 bound", "early distinct unrecorded/recorded native refusals")
				for attempt := 0; attempt < 2; attempt++ {
					out := startupRun(w)
					startupTuple(t, out, false, 0, "TERMINAL_LOCAL_INVARIANT(evidence)")
					now := cached.(interface{ Unwrap() []error }).Unwrap()
					nowOuter := now[0].(interface{ Unwrap() []error }).Unwrap()
					nowInner := nowOuter[0].(interface{ Unwrap() []error }).Unwrap()
					logicalMDBXAssert(t, out.Err == cached && len(now) == 2 && &now[0] == parentBacking && now[1].(*mdbx.EngineError) == abort && len(nowOuter) == 2 && &nowOuter[0] == outerBacking && len(nowInner) == 2 && &nowInner[0] == innerBacking && nowInner[0] == p && nowInner[1] == r && nowOuter[0] == visited && nowOuter[1] == r, "early cached identity/tree/backings")
					logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "early cached grant release")
				}
			})
		})
		logicalMDBXAssert(t, err == nil && cleanupErr == nil && state == "CLOSED" && !verified && callbacks == 1 && counts.BeginOld == 1 && counts.BeginRead == 0 && counts.BeginWrite == 0 && counts.OldPulls == ([8]uint64{}) && counts.OldGets == ([8]uint64{3: 1, 4: 2}) && counts.Faults == 0, "early visitor cleanup/state/permission/call census: %+v", counts)
		_, expired := saved.ReadAt(make([]byte, 1), 0)
		logicalMDBXAssert(t, expired.(*mdbx.EngineError).Diagnostic == "Reader is not active", "early row/span lifetime")
		logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("early cached View callback"); return nil }) == cached, "early cached View identity")
		_, _, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) {
			t.Fatal("early cached Update callback")
			return mdbx.Batch{}, nil
		})
		logicalMDBXAssert(t, next == cached, "early cached Update identity")
		w.store = w.reopen()
		startupRawImageEqual(t, w)
		startupFreshGuard(t, w, false)
	})
}

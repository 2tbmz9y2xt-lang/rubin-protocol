//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func startupRaw(t *testing.T, w *replayWorld, rank uint8, key, value []byte) {
	t.Helper()
	if w.pre == nil { w.pre = w.image() }
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
			if value != nil { w.pre[at].Value = bytes.Clone(value); return }
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
	for _, dbi := range inspection.DBIs { counts = binary.BigEndian.AppendUint64(counts, dbi.Entries) }
	logicalMDBXAssert(t, bytes.Equal(counts, w.pre[0].Value), "prepared complete DBI cardinality changed")
	for _, row := range w.pre[1:] {
		equal, err := mdbx.FixtureRawRowEqual(w.store, row.Key[0], row.Key[1:], row.Value)
		logicalMDBXAssert(t, err == nil && equal, "prepared raw image row %d/%x changed: %v/%v", row.Key[0], row.Key[1:], equal, err)
	}
}

func startupRawPreserved(t *testing.T, w *replayWorld, rank uint8, key, value []byte) {
	t.Helper()
	w.store = w.reopen()
	var out ReplayStartupOutcomeV1
	if rank == 0 {
		evidence, probeErr := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = startupRun(w) })
		e, native := out.Err.(*mdbx.EngineError)
		logicalMDBXAssert(t, probeErr == nil && evidence.OldPulls == ([8]uint64{}) && native && e.Class == "Integrity" && e.Operation == "get" && e.Code == -30796 && e.Diagnostic == "invalid storage authority" && e.Cause != nil, "authority full decoder before traversal: %+v/%v/%v", evidence, out.Err, probeErr)
	} else {
		out = startupRun(w)
	}
	startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
	if w.store.View(func(*mdbx.Reader) error { return nil }) != nil { w.store = w.reopen() }
	equal, err := mdbx.FixtureRawRowEqual(w.store, rank, key, value)
	logicalMDBXAssert(t, err == nil && equal, "raw preimage changed: %v/%v", equal, err)
	startupRawImageEqual(t, w)
	startupFreshGuard(t, w, false)
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
		for _, row := range []struct { name string; rank uint8; key, value func(*replayWorld) []byte }{
			{"forward short", 2, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(g, 0)) }, func(w *replayWorld) []byte { return make([]byte, 103) }},
			{"forward long", 2, func(w *replayWorld) []byte { return logicalMDBXMust(mdbx.HeightKey(g, 0)) }, func(w *replayWorld) []byte { return make([]byte, 105) }},
			{"forward key short", 2, func(w *replayWorld) []byte { return binary.BigEndian.AppendUint64(nil, g) }, func(w *replayWorld) []byte { return make([]byte, 104) }},
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
		} {
			t.Run(fmt.Sprintf("R03-R05 g%d %s", g, row.name), func(t *testing.T) {
				w := startupWorld(t, 2, 2)
				key, value := row.key(w), row.value(w)
				if g == 2 && row.rank == 3 {
					// Shared genesis belongs to active first. A distinct later target header reaches the target owner.
					header := bytes.Clone(w.headers[1][:]); header[115] ^= 1
					hash, _ := BlockHash(header)
					startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(2, 1)), mdbx.ChainValue(hash, w.hashes[0], sideWorldWork(2)))
					startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, hash)), binary.BigEndian.AppendUint64(nil, 1))
					key = hash[:]
					if value == nil { startupRaw(t, w, 3, key, header) }
				}
				startupRaw(t, w, row.rank, key, value)
				startupRawPreserved(t, w, row.rank, key, value)
			})
		}
	}
	for _, rank := range []uint8{2, 7, 0} {
		t.Run(fmt.Sprintf("R07 PRE_GENESIS rank%d", rank), func(t *testing.T) {
			w := startupWorld(t, 0, -1)
			var key, value []byte
			if rank == 0 {
				key, value = logicalMDBXMust(mdbx.HeightKey(2, 0)), mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(1))
				startupRaw(t, w, 2, key, value)
				rank = 7
			}
			if rank == 2 { key, value = logicalMDBXMust(mdbx.HeightKey(2, 0)), mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(1)) } else { key, value = logicalMDBXMust(mdbx.CanonicalOwnerKey(2, w.hashes[0])), binary.BigEndian.AppendUint64(nil, 0) }
			startupRaw(t, w, rank, key, value)
			startupRawPreserved(t, w, rank, key, value)
		})
	}
	for _, shape := range []string{"missing", "truncated", "trailing", "version", "phase", "lifecycle", "pending profile", "selected", "detached", "cleanup payload", "ordinary payload", "unsupported malformed", "empty exclusion", "same generation", "zero active", "zero target generation", "next zero", "target equals next", "cursor zero", "cursor unknown", "cursor beyond tip", "cursor genesis hash", "target height zero", "target height overflow", "target work zero", "target work overflow", "profile zero", "profile unknown"} {
		t.Run("R02 authority "+shape, func(t *testing.T) {
			w := startupWorld(t, 0, 0)
			a := w.authority()
			raw, _ := a.Encode()
			switch shape {
			case "missing": raw = nil
			case "truncated": raw = raw[:39]
			case "trailing": raw = append(raw, 0)
			case "version": raw[0] = 2
			case "phase": raw[34] = 255
			case "lifecycle": raw[35] = 1
			case "pending profile": raw = replayIllegalTail(t, raw, []byte{1, 2, 0, 0, 0})
			case "selected":
				work := sideWorldWork(1)
				selected := bytes.Join([][]byte{binary.BigEndian.AppendUint64(nil, 3), make([]byte, 8), binary.BigEndian.AppendUint64(nil, 1), bytes.Repeat([]byte{1}, 32), work[:], []byte{0, 1}, binary.BigEndian.AppendUint64(nil, 1)}, nil)
				raw = replayIllegalTail(t, raw, []byte{0, 0, 1}, selected, []byte{0})
			case "detached":
				detached := bytes.Join([][]byte{[]byte{0, 1}, binary.BigEndian.AppendUint64(nil, 1), bytes.Repeat([]byte{1}, 32), binary.BigEndian.AppendUint64(nil, 1), binary.BigEndian.AppendUint64(nil, 1), bytes.Repeat([]byte{1}, 32), []byte{0, 1}, binary.BigEndian.AppendUint64(nil, 1)}, nil)
				raw = replayIllegalTail(t, raw, []byte{0, 0, 0, 1}, detached)
			case "cleanup payload": raw = replayIllegalTail(t, raw, []byte{1, 1}, binary.BigEndian.AppendUint64(nil, 3), []byte{0, 0, 0, 0})
			case "ordinary payload": raw = replayIllegalTail(t, raw, []byte{2, 0, 0, 0, 0})
			case "unsupported malformed": raw[34], raw[36] = 1, 255
			case "same generation": binary.BigEndian.PutUint64(raw[37:45], 1)
			case "zero active": clear(raw[18:26])
			case "zero target generation": clear(raw[37:45])
			case "next zero": clear(raw[26:34])
			case "target equals next": binary.BigEndian.PutUint64(raw[26:34], 2)
			case "cursor zero": raw[189] = 0
			case "cursor unknown": raw[189] = 255
			case "cursor beyond tip": binary.BigEndian.PutUint64(raw[190:198], 2)
			case "cursor genesis hash": raw[198] ^= 1
			case "target height zero": clear(raw[141:149])
			case "target height overflow": binary.BigEndian.PutUint64(raw[141:149], 0x100000000)
			case "target work zero": clear(raw[149:189])
			case "target work overflow": clear(raw[149:189]); raw[152], raw[188] = 1, 1
			case "profile zero": raw[36] = 0
			case "profile unknown": raw[36] = 255
			case "empty exclusion":
				a.ExcludedInvalidBranch = &mdbx.InvalidBranchV1{FirstInvalidHeight: 1, ExactConsensusError: []byte("x")}
				raw, _ = a.Encode()
				// Remove only the token byte, preserving both following absent
				// option tags and declaring an exact zero-length blob.
				raw = append(raw[:276], raw[277:]...)
				clear(raw[272:276])
			}
			startupRaw(t, w, 0, []byte{2}, raw)
			startupRawPreserved(t, w, 0, []byte{2}, raw)
		})
	}
}

func TestReplayStartupMDBXReachedReadOrder(t *testing.T) {
	for _, bound := range []string{"B", "U"} {
		t.Run("R09 mixed profiles active15120 wrong "+bound, func(t *testing.T) {
			w := startupWorld(t, 15120, 0)
			w.setAuthority(func(a *mdbx.StorageAuthorityV1) {
				a.ActiveProfile, a.Replay.TargetProfile, a.B, a.U = 1, 2, 1, 13681
				if bound == "B" {
					a.B = 0
				} else {
					a.U = 13680
				}
			})
			before := w.image()
			w.store = w.reopen()
			var out ReplayStartupOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = startupRun(w) })
			startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			// 15121 active rows plus the active EOF, in each index. A
			// first target pull would add one to the exact rank2 count.
			logicalMDBXAssert(t, err == nil && out.Err.Error() == "startup active bounds mismatch" && evidence.OldPulls[2] == 15122 && evidence.OldPulls[7] == 15122, "bounds before target: %+v/%v/%v", evidence, out.Err, err)
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
			header := bytes.Clone(w.headers[1][:])
			header[115] ^= 1
			hash, _ := BlockHash(header)
			startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(2, 1)), mdbx.ChainValue(hash, w.hashes[0], sideWorldWork(2)))
			startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, hash)), binary.BigEndian.AppendUint64(nil, 1))
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
			want, pulls := "startup active bounds mismatch", uint64(4)
			if defect == "work" { want, pulls = "startup cumulative work mismatch", 1 }
			if defect == "extra inverse" { want = "startup extra or disagreeing inverse" }
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
	})
	for _, generation := range []uint64{1, 2} {
		for _, fault := range []string{"pull", "header", "inverse probe", "inverse pass", "forward probe"} {
			t.Run(fmt.Sprintf("R08 g%d %s", generation, fault), func(t *testing.T) {
				w := startupWorld(t, 1, 1)
				w.store = w.reopen()
				before := w.image()
				rank, scenario := uint8(2), mdbx.SelectedDamageStartupPullEIO
				key := binary.BigEndian.AppendUint64(nil, generation)
				switch fault {
				case "header": rank, scenario, key = 3, mdbx.SelectedDamageGetEIO, w.hashes[0][:]
				case "inverse probe": rank, scenario, key = 7, mdbx.SelectedDamageGetEIO, logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, w.hashes[0]))
				case "inverse pass": rank = 7
				case "forward probe": scenario, key = mdbx.SelectedDamageGetEIO, logicalMDBXMust(mdbx.HeightKey(generation, 0))
				}
				if generation == 2 && fault == "header" {
					header := bytes.Clone(w.headers[1][:]); header[115] ^= 1
					hash, _ := BlockHash(header)
					startupRaw(t, w, 3, hash[:], header)
					startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(2, 1)), mdbx.ChainValue(hash, w.hashes[0], sideWorldWork(2)))
					startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, hash)), binary.BigEndian.AppendUint64(nil, 1))
					key, before = hash[:], w.image()
				}
				var out ReplayStartupOutcomeV1
				evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, scenario, rank, key, func() { out = startupRun(w) })
				logicalMDBXAssert(t, err == nil && evidence.BeginOld == 1 && evidence.BeginWrite == 0 && evidence.BeginRead == 0 && evidence.Faults == 1 && evidence.OldAborts == 1 && evidence.Commits == 0, "actual startup transport: %+v/%v", evidence, err)
				resource := "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
				if generation == 2 { resource = "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)" }
				startupTuple(t, out, false, 2, resource)
				e := out.Err.(*mdbx.EngineError)
				operation := "get"; if scenario == mdbx.SelectedDamageStartupPullEIO { operation = "prefix-page" }
				logicalMDBXAssert(t, e.Class == "IO" && e.Code == 5 && e.Operation == operation && e.Cause == nil && e.ReopenRequired, "source raw tuple: %+v", e)
				logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("consumed View callback"); return nil }) == out.Err, "cached source identity")
				_, _, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { t.Fatal("consumed Update callback"); return mdbx.Batch{}, nil })
				logicalMDBXAssert(t, next == out.Err, "cached Update identity")
				w.store = w.reopen()
				replaySameImage(t, before, w.image(), "read EIO image")
				if w.pre != nil {
					startupRawImageEqual(t, w)
				}
				startupFreshGuard(t, w, false)
			})
		}
	}
	for _, generation := range []uint64{1, 2} {
		for _, defect := range []string{"work", "header", "inverse"} {
		t.Run(fmt.Sprintf("H01 current %s before successor g%d", defect, generation), func(t *testing.T) {
			w := startupWorld(t, 1, 1)
			current := mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(1))
			if defect == "work" {
				current[103]++
				startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(generation, 0)), current)
			} else if defect == "inverse" {
				startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(generation, w.hashes[0])), binary.BigEndian.AppendUint64(nil, 1))
			} else if generation == 1 {
				startupRaw(t, w, 3, w.hashes[0][:], nil)
			} else {
				// Use a target-only later header so active's shared genesis stays valid.
				header := bytes.Clone(w.headers[1][:])
				header[115] ^= 1
				hash, _ := BlockHash(header)
				startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(2, 1)), mdbx.ChainValue(hash, w.hashes[0], sideWorldWork(2)))
				startupRaw(t, w, 7, logicalMDBXMust(mdbx.CanonicalOwnerKey(2, hash)), binary.BigEndian.AppendUint64(nil, 1))
			}
			w.store = w.reopen()
			height := uint64(0)
			if generation == 2 && defect == "header" { height = 1 }
			seek := append(logicalMDBXMust(mdbx.HeightKey(generation, height)), 0)
			var out ReplayStartupOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageStartupPullEIO, 2, seek, func() { out = startupRun(w) })
			startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			wantPulls := uint64(1); if generation == 2 { wantPulls = 4 }; wantPulls += height
			logicalMDBXAssert(t, err != nil && err.Error() == "selected damage fixture site was not reached exactly as armed" && evidence.Faults == 0 && evidence.OldPulls[2] == wantPulls, "current work completed before armed successor EIO: %+v/%v", evidence, err)
			startupRawImageEqual(t, w)
		})
		}
	}
}

func TestReplayStartupMDBXCleanupProjection(t *testing.T) {
	for _, mode := range []uint32{0, 9} {
		t.Run(fmt.Sprintf("H10 completed positive close BUSY abort%d", mode), func(t *testing.T) {
			w := startupWorld(t, 0, 0)
			startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(2)))
			w.store = w.reopen()
			var out ReplayStartupOutcomeV1
			state, verified, err := mdbx.FixtureStartupCleanup(w.store, mode, true, func() { out = startupRun(w) })
			startupTuple(t, out, false, 3, "TERMINAL_STORE_INTEGRITY(canonical)")
			// A private application positive plus successful abort stays OPEN,
			// so only abort9 consumes and actually reaches the foreign writer.
			if mode == 0 {
				logicalMDBXAssert(t, err == nil && state == "OPEN" && !verified && out.Err.Error() == "startup cumulative work mismatch", "positive successful abort state")
				startupRawImageEqual(t, w)
			} else {
				e := out.Err.(*mdbx.EngineError)
				logicalMDBXAssert(t, err == nil && state == "CLOSE_BLOCKED" && !verified && e.Class == "Concurrency" && e.Operation == "close" && e.Code == -30778 && e.Cause != nil, "positive BUSY primary/state: %s/%v/%v", state, out.Err, err)
				logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("positive BUSY callback"); return nil }) == out.Err, "positive BUSY cache")
				logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.store) == nil, "positive BUSY teardown")
				w.store = w.reopen()
				startupRawImageEqual(t, w)
			}
			logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "positive cleanup grant release")
		})
	}
	for _, shape := range []string{"application", "CommitError", "custom multi-Unwrap"} {
		t.Run("H10 cached foreign "+shape, func(t *testing.T) {
			w := startupWorld(t, 0, 0)
			w.store = w.reopen()
			before := w.image()
			custom := &startupCustomJoin{children: []error{&mdbx.EngineError{Class: "Integrity"}}}
			var application error = fmt.Errorf("foreign cached application")
			if shape == "CommitError" { application = &mdbx.CommitError{Truth: 1, Cause: custom} }
			if shape == "custom multi-Unwrap" { application = custom }
			var cached error
			state, verified, err := mdbx.FixtureStartupCleanup(w.store, 9, false, func() {
				cached = w.store.View(func(*mdbx.Reader) error { return application })
			})
			logicalMDBXAssert(t, err == nil && state == "CLOSED" && !verified && cached != nil, "cached setup native state: %s/%v/%v", state, verified, err)
			for attempt := 0; attempt < 2; attempt++ {
				out := startupRun(w)
				startupTuple(t, out, false, 0, "TERMINAL_LOCAL_INVARIANT(evidence)")
				logicalMDBXAssert(t, out.Err == cached && custom.calls == 0, "cached identity/custom traversal changed")
				logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("cached View callback"); return nil }) == cached, "cached View identity")
				_, _, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { t.Fatal("cached Update callback"); return mdbx.Batch{}, nil })
				logicalMDBXAssert(t, next == cached, "cached Update identity")
			}
			logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "cached grant release")
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "cached foreign readonly image")
			startupFreshGuard(t, w, false)
		})
	}
	for _, positive := range []bool{false, true} {
		for _, mode := range []uint32{9, 10} {
			t.Run(fmt.Sprintf("H10 positive%v mode%d", positive, mode), func(t *testing.T) {
				w := startupWorld(t, 0, 0)
				if positive { startupRaw(t, w, 2, logicalMDBXMust(mdbx.HeightKey(1, 0)), mdbx.ChainValue(w.hashes[0], [32]byte{}, sideWorldWork(2))) }
				before := w.image()
				w.store = w.reopen()
				t.Cleanup(func() { _ = mdbx.FixtureStartupRelease(w.store) })
				var out ReplayStartupOutcomeV1
				state, verified, err := mdbx.FixtureStartupCleanup(w.store, mode, false, func() { out = startupRun(w) })
				logicalMDBXAssert(t, err == nil && !verified, "cleanup transport: %s/%v/%v", state, verified, err)
				result, decision := "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", uint8(2)
				if mode == 10 { result, decision = "TERMINAL_LOCAL_INVARIANT(evidence)", 0 }
				if positive { result, decision = "TERMINAL_STORE_INTEGRITY(canonical)", 3 }
				startupTuple(t, out, false, decision, result)
				want := "CLOSED"; if mode == 10 { want = "POISONED_THREAD" }
				logicalMDBXAssert(t, state == want, "actual native state=%s, want%s", state, want)
				logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("terminal callback"); return nil }) == out.Err, "native cached identity")
				_, _, next := w.store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { t.Fatal("terminal Update callback"); return mdbx.Batch{}, nil })
				logicalMDBXAssert(t, next == out.Err, "native Update cached identity")
				if mode == 10 {
					e := out.Err.(*mdbx.EngineError)
					logicalMDBXAssert(t, e.Class == "LocalInvariant" && e.Operation == "abort" && e.Code == -30416 && (e.Cause != nil) == positive, "THREAD_MISMATCH raw head/PRIMARY cause")
				}
				logicalMDBXAssert(t, w.owner.WithReservation(154611151, func() error { return nil }) == nil, "cleanup grant release")
				logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.store) == nil, "observed native cleanup teardown")
				w.store = w.reopen()
				if positive { startupRawImageEqual(t, w) } else { replaySameImage(t, before, w.image(), "native cleanup persisted image") }
				startupFreshGuard(t, w, false)
			})
		}
	}
	for _, mode := range []uint32{0, 9} {
		for _, generation := range []uint64{1, 2} {
		t.Run(fmt.Sprintf("H10 g%d read EIO close BUSY abort%d", generation, mode), func(t *testing.T) {
			active := 0
			if generation == 2 { active = -1 }
			w := startupWorld(t, active, 0)
			w.store = w.reopen()
			before := w.image()
			var out ReplayStartupOutcomeV1
			state, verified, err := mdbx.FixtureStartupCleanup(w.store, mode, true, func() {
				_, armedErr := mdbx.FixtureSelectedDamage(w.store, w.owner, mdbx.SelectedDamageGetEIO, 3, w.hashes[0][:], func() { out = startupRun(w) })
				logicalMDBXAssert(t, armedErr == nil, "BUSY source transport: %v", armedErr)
			})
			logicalMDBXAssert(t, err == nil && state == "CLOSE_BLOCKED" && !verified, "actual BUSY state: %s/%v/%v", state, verified, err)
			startupTuple(t, out, false, 2, "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)")
			e := out.Err.(*mdbx.EngineError)
			logicalMDBXAssert(t, e.Class == "Concurrency" && e.Operation == "close" && e.Code == -30778 && e.Cause != nil, "raw close PRIMARY cause: %v", e)
			read := e.Cause
			if mode == 9 {
				parts := e.Cause.(interface{ Unwrap() []error }).Unwrap()
				logicalMDBXAssert(t, len(parts) == 2, "BUSY read/abort join cardinality")
				read = parts[0]
				abort := parts[1].(*mdbx.EngineError)
				logicalMDBXAssert(t, abort.Class == "IO" && abort.Operation == "abort" && abort.Code == 5 && abort.Cause == nil, "BUSY abort sibling identity/class")
			}
			source := read.(*mdbx.EngineError)
			logicalMDBXAssert(t, source.Class == "IO" && source.Operation == "get" && source.Code == 5 && source.Diagnostic == "error 5" && source.Cause == nil, "BUSY first read identity/class")
			logicalMDBXAssert(t, w.store.View(func(*mdbx.Reader) error { t.Fatal("BUSY callback"); return nil }) == out.Err, "BUSY cache identity")
			logicalMDBXAssert(t, mdbx.FixtureStartupRelease(w.store) == nil, "BUSY post-observation teardown")
			w.store = w.reopen()
			replaySameImage(t, before, w.image(), "BUSY persisted image")
			startupFreshGuard(t, w, false)
		})
		}
	}
}

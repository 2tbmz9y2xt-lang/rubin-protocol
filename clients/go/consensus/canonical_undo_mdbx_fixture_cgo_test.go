//go:build cgo && (darwin || linux) && (amd64 || arm64) && rubin_mdbx_fixture

package consensus

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestCanonicalUndoFamilyNativeIO(t *testing.T) {
	for _, name := range []string{"E01KeyBeforeSource", "E02RefGetIO", "E03ManifestReadAtIO", "E04EntryReadAtIO", "E05ReadAndAbortIO", "H07RawWidth"} {
		t.Run(name, func(t *testing.T) { undoNativeCell(t, name) })
	}
}

// Only the comparator runs in the armed interval. All native row setup and
// full-image readback happens outside it; faults come from actual native sites.
func undoNativeCell(t *testing.T, name string) {
	t.Helper()
	width := 20
	if name == "H07RawWidth" {
		width = 65560
	}
	path := filepath.Join(t.TempDir(), "db")
	store, err := mdbx.Create(path, sideWorldConfig)
	logicalMDBXAssert(t, err == nil, "create native store: %v", err)
	t.Cleanup(func() { _ = store.Close() })
	hash, expected, physical, source := undoPhysicalRows(2, width)
	neighbor := undoLiteralManifest(hashWithPrefix(0x62), 9, Uint128{Lo: 91}, 1, 0)
	physical = append(physical, neighbor)
	scenario, rank, key, gets, faults := undoNativeDamage(name, expected, physical, source)
	seedSource := source
	if name == "E01KeyBeforeSource" {
		seedSource = source[1:]
	}
	logicalMDBXSeed(t, store, seedSource...)
	undoSeedFamily(t, store, physical)
	if name == "H07RawWidth" {
		raw := make([]byte, 131073)
		copy(raw, source[0].Literal)
		logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(store, 5, expected[1].Key, raw) == nil, "raw OLD seed")
		physical[1].Literal = raw
	}
	owner, err := mdbx.NewOperationReservationOwner(mdbx.MaxOperationDataBytes)
	logicalMDBXAssert(t, err == nil, "native reservation: %v", err)
	var equal bool
	var direct, outer error
	var truth mdbx.CommitTruth
	var stage mdbx.UpdateStage
	var original *mdbx.Reader
	before := logicalMDBXSnapshot(expected)
	originalHash := hash
	evidence, fixtureErr := mdbx.FixtureSelectedDamage(store, owner, scenario, rank, key, func() {
		grantErr := owner.WithReservation(mdbx.MaxOperationDataBytes, func() error {
			truth, stage, outer = store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
				original = reader
				equal, direct = canonicalUndoFamilyEqualV1(reader, &hash, expected)
				return mdbx.Batch{}, direct
			})
			return nil
		})
		logicalMDBXAssert(t, grantErr == nil, "native grant: %v", grantErr)
	})
	logicalMDBXAssert(t, fixtureErr == nil, "armed site not reached: %v %+v", fixtureErr, evidence)
	logicalMDBXAssert(t, hash == originalHash && reflect.DeepEqual(before, logicalMDBXSnapshot(expected)), "native comparison mutated original expected owners")
	logicalMDBXAssert(t, !equal && truth == mdbx.CommitTruthOld && stage == mdbx.UpdateStagePrewrite, "raw Update tuple: %t %v %v %v", equal, truth, stage, outer)
	undoNativeCounts(t, evidence, gets, faults)
	undoNativeResult(t, name, direct, outer)
	_, _, expired := original.Get(logicalMDBXDBIs[1], expected[1].RefKey)
	undoNativeEngine(t, expired, "get", mdbx.EngineInvalidInput, 22, "Reader is not active")
	if name != "E01KeyBeforeSource" && name != "H07RawWidth" {
		undoNativeConsumed(t, store, outer)
		_ = store.Close()
		store, err = mdbx.Open(path, sideWorldConfig)
		logicalMDBXAssert(t, err == nil, "native reopen: %v", err)
	} else {
		ran := false
		err := store.View(func(*mdbx.Reader) error { ran = true; return nil })
		logicalMDBXAssert(t, err == nil && ran, "application refusal consumed Store: %v", err)
	}
	undoNativeImages(t, store, physical, source)
	err = owner.WithReservation(mdbx.MaxOperationDataBytes, func() error { return nil })
	logicalMDBXAssert(t, err == nil, "native grant retained: %v", err)
}

func undoNativeDamage(name string, expected, physical, source []mdbx.Mutation) (mdbx.SelectedDamageScenario, uint8, []byte, [8]uint64, uint64) {
	scenario, rank, key := mdbx.SelectedDamageGetEIO, uint8(1), expected[1].RefKey
	gets, faults := [8]uint64{1: 1, 5: 2}, uint64(1)
	switch name {
	case "E01KeyBeforeSource":
		scenario, rank, key, gets, faults = mdbx.SelectedDamageProbeOnly, 0, nil, [8]uint64{5: 2}, 0
		physical[1].Key[36] = 2
		// A real absent source accompanies the key defect, which must win.
		source[0].AfterKind, source[0].Literal = mdbx.AfterAbsent, nil
	case "E02RefGetIO":
		// A later content defect cannot replace the first original Get error.
		physical[2].Literal[0] ^= 1
	case "E03ManifestReadAtIO":
		rank, key, gets = 5, expected[0].Key, [8]uint64{5: 1}
	case "E04EntryReadAtIO":
		rank, key, gets = 5, expected[1].Key, [8]uint64{1: 1, 5: 3}
	case "E05ReadAndAbortIO":
		scenario, faults = mdbx.SelectedDamageGetAbortEIO, 2
	case "H07RawWidth":
		scenario, rank, key, faults = mdbx.SelectedDamageProbeOnly, 0, nil, 0
	}
	return scenario, rank, key, gets, faults
}

func undoNativeCounts(t *testing.T, got mdbx.SelectedDamageEvidence, gets [8]uint64, faults uint64) {
	t.Helper()
	logicalMDBXAssert(t, got.BeginOld == 1 && got.BeginWrite == 0 && got.BeginRead == 0 && got.OldGets == gets && got.ReadGets == 0 && got.Faults == faults && got.Deletes == 0 && got.Commits == 0 && got.OldAborts == 1, "native counters: %+v want gets=%v faults=%d", got, gets, faults)
	logicalMDBXAssert(t, got.ProbeRan == 0 && got.ProbeDenied == got.Probes, "native OLD abort reservation overlap: %+v", got)
}

func undoNativeEngine(t *testing.T, err error, operation string, class mdbx.EngineClass, code int, diagnostic string) *mdbx.EngineError {
	t.Helper()
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, reflect.TypeOf(err) == reflect.TypeFor[*mdbx.EngineError]() && errors.As(err, &engine), "native interface was replaced/wrapped: %T %v", err, err)
	logicalMDBXAssert(t, engine.Operation == operation && engine.Class == class && engine.Code == code && engine.Diagnostic == diagnostic && engine.Cause == nil && !engine.ReopenRequired, "native original tuple: %+v", engine)
	return engine
}

func undoNativeResult(t *testing.T, name string, direct, outer error) {
	t.Helper()
	switch name {
	case "E01KeyBeforeSource":
		undoDefect(t, false, direct, "undo family has an unexpected member")
		logicalMDBXAssert(t, reflect.ValueOf(outer).Equal(reflect.ValueOf(direct)), "key defect interface replaced")
	case "H07RawWidth":
		undoDefect(t, false, direct, "undo value length differs")
		logicalMDBXAssert(t, reflect.ValueOf(outer).Equal(reflect.ValueOf(direct)), "width defect interface replaced")
	case "E05ReadAndAbortIO":
		undoNativeEngine(t, direct, "get", mdbx.EngineIO, 5, "error 5")
		parts := genesisMDBXCauses(outer)
		logicalMDBXAssert(t, len(parts) == 2 && reflect.ValueOf(parts[0]).Equal(reflect.ValueOf(direct)), "first cause identity/order: %v", outer)
		undoNativeEngine(t, parts[1], "abort", mdbx.EngineIO, 5, "error 5")
	default:
		undoNativeEngine(t, direct, "get", mdbx.EngineIO, 5, "error 5")
		logicalMDBXAssert(t, reflect.ValueOf(outer).Equal(reflect.ValueOf(direct)), "original Get/ReadAt error lost to cleanup: direct=%v outer=%v", direct, outer)
	}
}

func undoNativeConsumed(t *testing.T, store *mdbx.Store, original error) {
	t.Helper()
	ran := false
	truth, stage, next := store.Update(func(*mdbx.Reader) (mdbx.Batch, error) { ran = true; return mdbx.Batch{}, nil })
	logicalMDBXAssert(t, !ran && truth == mdbx.CommitTruthOld && stage == mdbx.UpdateStagePrewrite && reflect.ValueOf(next).Equal(reflect.ValueOf(original)), "consumed next Update: %t %v %v %v", ran, truth, stage, next)
	before, after := genesisMDBXCauses(original), genesisMDBXCauses(next)
	logicalMDBXAssert(t, len(before) == len(after), "cached cause tree length changed")
	for i := range before {
		logicalMDBXAssert(t, reflect.ValueOf(before[i]).Equal(reflect.ValueOf(after[i])), "cached cause %d identity changed", i)
	}
}

func undoNativeImages(t *testing.T, store *mdbx.Store, physical, source []mdbx.Mutation) {
	t.Helper()
	for _, row := range append(physical[:len(physical):len(physical)], source...) {
		equal, err := mdbx.FixtureRawRowEqual(store, row.DBI.Rank, row.Key, row.Literal)
		logicalMDBXAssert(t, err == nil && equal, "native full row changed rank=%d key=%x width=%d: %v", row.DBI.Rank, row.Key, len(row.Literal), err)
	}
	// The malformed OLD span stays actual131073 beside actual65560 source bytes;
	// prefix equality alone cannot establish complete family equality.
	if len(physical[1].Literal) == 131073 {
		logicalMDBXAssert(t, len(source[0].Literal) == 65560 && bytes.Equal(physical[1].Literal[:65560], source[0].Literal), "raw width witness lost its identical source prefix")
	}
}

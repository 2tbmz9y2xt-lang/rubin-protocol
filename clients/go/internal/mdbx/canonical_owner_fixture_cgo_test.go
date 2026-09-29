//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func canonicalFixtureDataFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path, "mdbx.dat"))
	mustEnvironment(t, err)
	return data
}

func TestCanonicalOwnerFixtureLegacySchemaRefused(t *testing.T) {
	cfg := environmentConfig()
	t.Run("seven DBIs and version one", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "db")
		mustEnvironment(t, fixtureLegacySchemaEnvironment(path, cfg))
		before := canonicalFixtureDataFile(t, path)
		store, err := Open(path, cfg)
		requireNoStore(t, store, err, EngineIntegrity, operationOpen, codeInvalid, "SchemaV2 main cardinality mismatch")
		if !bytes.Equal(before, canonicalFixtureDataFile(t, path)) {
			t.Fatal("refused legacy-schema environment was modified")
		}
	})
	t.Run("eight DBIs and version one", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "db")
		mustEnvironment(t, createAndClose(path, cfg))
		store, err := fixtureOpen(path, cfg, fixtureWrongSchemaVersion)
		requireNoStore(t, store, err, EngineIntegrity, operationOpen, codeInvalid, "invalid SchemaV2 version row")
		before := canonicalFixtureDataFile(t, path)
		store, err = Open(path, cfg)
		requireNoStore(t, store, err, EngineIntegrity, operationOpen, codeInvalid, "invalid SchemaV2 version row")
		if !bytes.Equal(before, canonicalFixtureDataFile(t, path)) {
			t.Fatal("refused version-one environment was modified")
		}
	})
}

func TestCanonicalOwnerFixtureBootstrapCensus(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	store, err := Create(path, cfg)
	mustEnvironment(t, err)
	mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: canonicalOwnerDBILiteral, key: canonicalOwnerKeyLiteral(1, [32]byte{0x0c}), value: []byte{0, 0, 0, 0, 0, 0, 0, 4}}))
	mustEnvironment(t, store.Close())
	store, err = Open(path, cfg)
	store = consultedTrack(t, store, err)
	truth, stage, bootstrapErr := store.BootstrapStorageV1(StorageProfilePrunedV1, bootstrapOwner(t))
	if stage != UpdateStagePrewrite {
		t.Fatalf("owner-row census stage drifted: %d", stage)
	}
	bootstrapNonemptyRefusal(t, "owner-row census", truth, bootstrapErr)
	bootstrapOpenUnchanged(t, store, "owner-row census")
	mustEnvironment(t, store.View(func(reader *Reader) error {
		result, lookupErr := reader.CanonicalOwnerV1(1, [32]byte{0x0d})
		canonicalRequireUnverified(t, reader, result, lookupErr, "failed census established verification")
		return nil
	}))
}

func TestCanonicalOwnerFixtureDisposal(t *testing.T) {
	x, y, work := [32]byte{0x41}, [32]byte{0x42}, [40]byte{39: 1}
	owner, forward := canonicalOwnerKeyLiteral(2, x), canonicalForwardKeyLiteral(2, 5)
	type rawRow struct {
		dbi        DBI
		key, value []byte
	}
	for _, row := range []struct {
		name   string
		seeds  []rawRow
		remove Mutation
	}{
		{"owner whose forward is absent", []rawRow{{canonicalOwnerDBILiteral, owner, []byte{0, 0, 0, 0, 0, 0, 0, 5}}}, canonicalDelete(Mutation{DBI: canonicalOwnerDBILiteral, Key: owner})},
		{"owner whose forward names another hash", []rawRow{{canonicalOwnerDBILiteral, owner, []byte{0, 0, 0, 0, 0, 0, 0, 5}}, {canonicalForwardDBILiteral, forward, canonicalForwardValueLiteral(y, work)}}, canonicalDelete(Mutation{DBI: canonicalOwnerDBILiteral, Key: owner})},
		{"owner whose forward is 103 bytes", []rawRow{{canonicalOwnerDBILiteral, owner, []byte{0, 0, 0, 0, 0, 0, 0, 5}}, {canonicalForwardDBILiteral, forward, canonicalForwardValueLiteral(x, work)[:103]}}, canonicalDelete(Mutation{DBI: canonicalOwnerDBILiteral, Key: owner})},
		{"owner value of 9 bytes", []rawRow{{canonicalOwnerDBILiteral, owner, []byte{0, 0, 0, 0, 0, 0, 0, 5, 0}}, {canonicalForwardDBILiteral, forward, canonicalForwardValueLiteral(x, work)}}, canonicalDelete(Mutation{DBI: canonicalOwnerDBILiteral, Key: owner})},
		{"forward whose owner is absent", []rawRow{{canonicalForwardDBILiteral, forward, canonicalForwardValueLiteral(x, work)}}, canonicalDelete(Mutation{DBI: canonicalForwardDBILiteral, Key: forward})},
		{"forward whose owner holds another height", []rawRow{{canonicalForwardDBILiteral, forward, canonicalForwardValueLiteral(x, work)}, {canonicalOwnerDBILiteral, owner, []byte{0, 0, 0, 0, 0, 0, 0, 6}}}, canonicalDelete(Mutation{DBI: canonicalForwardDBILiteral, Key: forward})},
	} {
		t.Run(row.name, func(t *testing.T) {
			store := newUpdateStore(t)
			defer func() { mustEnvironment(t, store.Close()) }()
			for _, seed := range row.seeds {
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, seed.dbi, seed.key, seed.value))
			}
			requireUpdateCommit(t, store, row.name, row.remove)
			requireUpdateValue(t, store, row.remove.DBI, row.remove.Key, nil, false)
		})
	}
}

func TestCanonicalOwnerFixtureReadback(t *testing.T) {
	hash := [32]byte{0x51}
	pair := []Mutation{canonicalForwardLiteral(3, 4, hash, [40]byte{39: 1}), canonicalOwnerLiteral(3, 4, hash)}
	t.Run("new", func(t *testing.T) {
		store := newUpdateStore(t)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, cleanup := fixtureUpdatePostCommitENOSPC(store, updateNativePlan(t, pair...))
		mustEnvironment(t, cleanup)
		_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		requireUpdateTruth(t, outcome, CommitTruthNew, true, outcome.primary, nil)
		canonicalRequireImage(t, store, pair, nil)
	})
	t.Run("forward removed by a third writer", func(t *testing.T) {
		store := newUpdateStore(t)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, cleanup := fixtureUpdatePostCommitENOSPCMissing(store, updateNativePlan(t, pair...))
		mustEnvironment(t, cleanup)
		_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		requireUpdateTruth(t, outcome, CommitTruthUnknown, true, outcome.primary, nil)
		canonicalRequireImage(t, store, pair[1:], pair[:1])
	})
}

func TestCanonicalOwnerFixtureInconsistent(t *testing.T) {
	x, y, work := [32]byte{0x61}, [32]byte{0x62}, [40]byte{39: 1}
	owner, forward := canonicalOwnerKeyLiteral(3, x), canonicalForwardKeyLiteral(3, 4)
	holds := []byte{0, 0, 0, 0, 0, 0, 0, 4}
	for _, row := range []struct {
		name, diagnostic string
		seeds            []fixtureRawRow
	}{
		{"forward absent", "canonical owner index inconsistency", []fixtureRawRow{{dbi: canonicalOwnerDBILiteral, key: owner, value: holds}}},
		{"forward names another hash", "canonical owner index inconsistency", []fixtureRawRow{{dbi: canonicalOwnerDBILiteral, key: owner, value: holds}, {dbi: canonicalForwardDBILiteral, key: forward, value: canonicalForwardValueLiteral(y, work)}}},
		{"owner value of 7 bytes", "stored value width outside SchemaV2 bound", []fixtureRawRow{{dbi: canonicalOwnerDBILiteral, key: owner, value: holds[:7]}, {dbi: canonicalForwardDBILiteral, key: forward, value: canonicalForwardValueLiteral(x, work)}}},
		{"owner value of 9 bytes", "stored value width outside SchemaV2 bound", []fixtureRawRow{{dbi: canonicalOwnerDBILiteral, key: owner, value: append(append([]byte(nil), holds...), 0)}, {dbi: canonicalForwardDBILiteral, key: forward, value: canonicalForwardValueLiteral(x, work)}}},
		{"forward value of 103 bytes", "stored value width outside SchemaV2 bound", []fixtureRawRow{{dbi: canonicalOwnerDBILiteral, key: owner, value: holds}, {dbi: canonicalForwardDBILiteral, key: forward, value: canonicalForwardValueLiteral(x, work)[:103]}}},
	} {
		t.Run(row.name, func(t *testing.T) {
			store := newUpdateStore(t)
			for _, seed := range row.seeds {
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, seed.dbi, seed.key, seed.value))
			}
			canonicalRequireRecorded(t, store, nil, 3, x, EngineIntegrity, codeInvalid, row.diagnostic, row.name)
		})
	}
}

func TestCanonicalOwnerFixtureRawWriteKeepsVerification(t *testing.T) {
	store := newUpdateStore(t)
	hash := [32]byte{0x63}
	forward := canonicalForwardLiteral(3, 4, hash, [40]byte{39: 1})
	requireUpdateCommit(t, store, "raw-write seed", forward, canonicalOwnerLiteral(3, 4, hash))
	mustEnvironment(t, fixtureDeletePrefixRow(store, forward.DBI, forward.Key))
	if !store.canonicalOwnerVerified {
		t.Fatal("fixture raw write changed canonical-owner verification")
	}
	canonicalRequireRecorded(t, store, nil, 3, hash, EngineIntegrity, codeInvalid, "canonical owner index inconsistency", "raw write keeps verification")
}

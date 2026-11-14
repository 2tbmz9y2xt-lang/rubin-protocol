//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Scratch boundaries are observed at native owner prefixes, including false obligations.
func TestCanonicalOwnerPairReadAccountingNativeV1(t *testing.T) {
	t.Run("O2-pre-key", canonicalPairReadPrekeyV1)
	t.Run("disposable-and-targeted", canonicalPairReadDisposableV1)
	t.Run("target-native-before-scratch", canonicalPairReadTargetErrorV1)
	hash, work := [32]byte{0x41}, [40]byte{39: 1}
	forward, owner := canonicalForwardLiteral(1, 5, hash, work), canonicalOwnerLiteral(1, 5, hash)
	for _, row := range []struct {
		name     string
		pair     []Mutation
		seed     []Mutation
		pc, free uint64
		capacity bool
		gets     [8]uint64
	}{
		{"N1-short", []Mutation{forward}, nil, 248, 39, true, [8]uint64{2: 1}},
		{"N1-funded", []Mutation{forward}, nil, 248, 40, false, [8]uint64{2: 1}},
		{"N2-short", []Mutation{owner}, nil, 176, 39, true, [8]uint64{7: 1}},
		{"N2-funded", []Mutation{owner}, nil, 176, 40, false, [8]uint64{7: 1}},
		{"O1-same-literal-prefix", []Mutation{forward, owner}, []Mutation{forward, owner}, 424, 175, true, [8]uint64{2: 2, 7: 1}},
		{"O1-partner-sequential", []Mutation{canonicalDelete(forward)}, []Mutation{forward, owner}, 144, 176, false, [8]uint64{2: 2, 7: 1}},
		{"O2-partner-short", []Mutation{canonicalDelete(owner)}, []Mutation{forward, owner}, 168, 191, true, [8]uint64{2: 1, 7: 2}},
		{"O2-partner-funded", []Mutation{canonicalDelete(owner)}, []Mutation{forward, owner}, 168, 192, false, [8]uint64{2: 1, 7: 2}},
	} {
		for _, credit := range []uint64{0, 17} {
			t.Run(fmt.Sprintf("%s/C%d", row.name, credit), func(t *testing.T) {
				s, path, o := tsNew(t)
				for _, m := range row.seed {
					treeNativeSeed(t, s, m.DBI.Rank, m.Key, m.Literal)
				}
				op := TreeOperationV1{Pair: TreePairV1{Mutations: row.pair, PrepaidReadBytes: credit}}
				var result tsResult
				var evidence SelectedDamageEvidence
				mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
					return a.WithReservation(1024+credit, func() error {
						return a.WithReservation(154611183-1024-row.pc-row.free, func() error {
							before := reservationLive(o)
							var err error
							evidence, err = FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() {
								result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil })
							})
							mustEnvironment(t, err)
							if reservationLive(o) != before {
								t.Fatal("canonical engine/caller cleanup")
							}
							return nil
						})
					})
				}))
				result.tuple(t, 1, 1, -1)
				if row.capacity {
					if !treeSameErrorV1(result.err, errOperationReservationCapacity) {
						t.Fatal("scratch capacity", result.err)
					}
				} else {
					treeNativeError(t, result.err, "update", "InvalidInput", 22, "unpaired canonical owner mutation", nil)
				}
				if evidence.OldGets != row.gets || evidence.Deletes != 0 || evidence.Commits != 0 || s.state != storeCLOSED {
					t.Fatalf("canonical native prefix %+v", evidence)
				}
				s = tsReopen(t, s, path)
				for _, m := range row.seed {
					equal, err := FixtureRawRowEqual(s, m.DBI.Rank, m.Key, m.Literal)
					if err != nil || !equal {
						t.Fatal("canonical durable OLD", err)
					}
				}
			})
		}
	}
}

func canonicalPairReadDisposableV1(t *testing.T) {
	hash := [32]byte{0x41}
	forward, owner := canonicalForwardLiteral(1, 5, hash, [40]byte{39: 1}), canonicalOwnerLiteral(1, 5, hash)
	badOwner, badForward := owner, forward
	badOwner.Literal = append(bytes.Clone(owner.Literal), 0)
	badForward.Literal = bytes.Clone(forward.Literal[:103])
	for _, row := range []struct {
		name       string
		pair, seed []Mutation
		pc, window uint64
		gets       [8]uint64
	}{
		{"wrong-target-width", []Mutation{canonicalDelete(owner)}, []Mutation{badOwner}, 168, 18, [8]uint64{7: 3}},
		{"wrong-partner-width", []Mutation{canonicalDelete(owner)}, []Mutation{badForward, owner}, 168, 88, [8]uint64{2: 1, 7: 3}},
		{"both-targeted", []Mutation{canonicalDelete(forward), canonicalDelete(owner)}, []Mutation{forward, owner}, 312, 208, [8]uint64{2: 3, 7: 3}},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, path, o := tsNew(t)
			for _, m := range row.seed {
				treeNativeSeed(t, s, m.DBI.Rank, m.Key, m.Literal)
			}
			op := TreeOperationV1{Pair: TreePairV1{Mutations: row.pair}}
			var result tsResult
			var evidence SelectedDamageEvidence
			mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
				return a.WithReservation(154611183-row.pc-row.window, func() error {
					var err error
					evidence, err = FixtureSelectedDamage(s, o, SelectedDamageProbeOnly, 0, nil, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
					return err
				})
			}))
			result.tuple(t, 2, 3, -1)
			mustEnvironment(t, result.err)
			if evidence.OldGets != row.gets {
				t.Fatal("metadata/target shortcut native gets", evidence)
			}
			s = tsReopen(t, s, path)
			for _, m := range row.pair {
				equal, err := FixtureRawRowEqual(s, m.DBI.Rank, m.Key, nil)
				if err != nil || !equal {
					t.Fatal("disposable durable absence", err)
				}
			}
		})
	}
}

func canonicalPairReadTargetErrorV1(t *testing.T) {
	s, _, o := tsNew(t)
	forward := canonicalForwardLiteral(1, 5, [32]byte{0x41}, [40]byte{39: 1})
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{forward}}}
	var result tsResult
	mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
		return a.WithReservation(154611183-248-39, func() error {
			evidence, err := FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 2, forward.Key, func() { result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil }) })
			if evidence.OldGets != ([8]uint64{2: 1}) || evidence.Deletes != 0 || evidence.Commits != 0 {
				t.Error("complete target qualification precedes scratch", evidence)
			}
			return err
		})
	}))
	result.tuple(t, 1, 1, -1)
	treeNativeError(t, result.err, "update", "IO", 5, "error 5", nil)
}

func canonicalPairReadPrekeyV1(t *testing.T) {
	for _, free := range []uint64{87, 88} {
		t.Run(fmt.Sprint(free), func(t *testing.T) {
			s, path, o := tsNew(t)
			hash := [32]byte{0x41}
			owner := canonicalOwnerLiteral(1, 5, hash)
			forward := canonicalForwardLiteral(1, 5, hash, [40]byte{39: 1})
			treeNativeSeed(t, s, 7, owner.Key, owner.Literal)
			treeNativeSeed(t, s, 2, forward.Key, forward.Literal)
			op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{canonicalDelete(owner)}}}
			var result tsResult
			var evidence SelectedDamageEvidence
			var fixtureErr error
			mustEnvironment(t, o.WithOperation(LaneOperation, func(a *OperationAccount) error {
				return a.WithReservation(154611183-168-free, func() error {
					evidence, fixtureErr = FixtureSelectedDamage(s, o, SelectedDamageGetEIO, 2, forward.Key, func() {
						result = tsInvoke(s, a, func(*Reader) (TreeOperationV1, error) { return op, nil })
					})
					return nil
				})
			}))
			result.tuple(t, 1, 1, -1)
			want := [8]uint64{7: 2}
			if free == 87 {
				tsfSlotUnreached(t, evidence, fixtureErr)
				if !treeSameErrorV1(result.err, errOperationReservationCapacity) {
					t.Fatal("O2 pre-key87 before partner get", result.err)
				}
			} else {
				mustEnvironment(t, fixtureErr)
				want[2] = 1
				treeNativeError(t, result.err, "update", "IO", 5, "error 5", nil)
			}
			if evidence.OldGets != want || s.state != storeCLOSED {
				t.Fatalf("pre-key native prefix %+v", evidence)
			}
			s = tsReopen(t, s, path)
			equal, err := FixtureRawRowEqual(s, 7, owner.Key, owner.Literal)
			if err != nil || !equal {
				t.Fatal("pre-key durable OLD", err)
			}
		})
	}
}

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

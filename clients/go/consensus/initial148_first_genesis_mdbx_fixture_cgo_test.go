//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

type fgWorld struct {
	*btWorld
	database     [32]byte
	current, lag uint64
	raw          []byte
	genesis      PublishedGenesisContextV1
}

func fgNew(t *testing.T, database [32]byte, current, lag uint64) *fgWorld {
	t.Helper()
	base := &btWorld{path: filepath.Join(t.TempDir(), "first-genesis"), cfg: mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}}
	var err error
	base.s, err = mdbx.CreateTreeV1(base.path, base.cfg, database)
	logicalMDBXAssert(t, err == nil, "create first genesis Store: %v", err)
	base.owner, err = mdbx.NewOperationReservationOwner(805306368)
	logicalMDBXAssert(t, err == nil, "first genesis owner: %v", err)
	t.Cleanup(func() { _ = base.s.Close() })
	w := &fgWorld{btWorld: base, database: database, current: current, lag: lag}
	w.raw = initial148BlockGenesis(t)
	w.genesis = fgContext(t, bytes.Clone(w.raw))
	a := mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: current, NextGenerationID: max(current, lag) + 1, Phase: 1, Lifecycle: 1}, LagGenerationID: lag}
	w.seedAuthority(t, a)
	for _, generation := range []uint64{current, lag} {
		w.seed(t, 0, btMeta(0x10, generation), mdbx.LogicalCounterValue(0, 0))
		w.seedBinding(t, generation, w.emptyBinding())
	}
	return w
}

func (w *fgWorld) seed(t *testing.T, rank uint8, key, value []byte) {
	t.Helper()
	key, value = bytes.Clone(key), bytes.Clone(value)
	var err error
	if value == nil {
		err = mdbx.FixtureStartupDeleteRow(w.s, rank, key)
	} else {
		err = mdbx.FixtureSeedRawRow(w.s, rank, key, value)
	}
	logicalMDBXAssert(t, err == nil, "seed rank%d key%x: %v", rank, key, err)
}

func (w *fgWorld) emptyBinding() mdbx.RootBindingV1 {
	return mdbx.RootBindingV1{
		DatabaseID: w.database, CommitmentVersion: 1, ChainID: w.genesis.ChainID, GenesisHash: w.genesis.GenesisHash,
		RootDigest: sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")), Assurance: mdbx.TreeAssuranceV1{Kind: 1},
	}
}

func (w *fgWorld) seedBinding(t *testing.T, g uint64, root mdbx.RootBindingV1) {
	t.Helper()
	raw, err := root.Encode()
	logicalMDBXAssert(t, err == nil, "binding encode: %v", err)
	w.seed(t, 0, btMeta(0x11, g), raw)
}

func (w *fgWorld) seedAuthority(t *testing.T, a mdbx.TreeAuthorityV1) {
	t.Helper()
	raw, err := a.Encode()
	logicalMDBXAssert(t, err == nil, "authority encode: %v", err)
	w.seed(t, 0, []byte{2}, raw)
}

func (w *fgWorld) call() Initial148FirstGenesisOutcomeV1 {
	return w.context(w.database, w.current)
}

func (w *fgWorld) context(database [32]byte, generation uint64) Initial148FirstGenesisOutcomeV1 {
	return ConnectPublishedInitial148GenesisMDBX(w.s, w.owner, w.raw, w.genesis.Published, w.genesis.ChainID, w.genesis.GenesisHash, database, generation)
}

func (w *fgWorld) reopen(t *testing.T) {
	t.Helper()
	_ = w.s.Close()
	var err error
	w.s, err = mdbx.OpenTreeV1(w.path, w.cfg, w.database)
	logicalMDBXAssert(t, err == nil, "first genesis reopen: %v", err)
}

func (w *fgWorld) outpoint(t *testing.T) Outpoint {
	t.Helper()
	parsed, err := ParseInitial148BlockBytes(w.raw)
	logicalMDBXAssert(t, err == nil && len(parsed.Txids) == 1, "first genesis outpoint: %v", err)
	return Outpoint{Txid: parsed.Txids[0]}
}

func (w *fgWorld) leafKey(t *testing.T) []byte {
	t.Helper()
	op := w.outpoint(t)
	var routing [36]byte
	copy(routing[:], op.Txid[:])
	key, err := mdbx.TreeNodeKey(w.current, mdbx.TreeNodeIDV1{Kind: 1, RoutingKey: routing, Depth: 288})
	logicalMDBXAssert(t, err == nil, "first genesis leaf key: %v", err)
	return key
}

// image covers every finite reachable write target and every DBI count of a
// healthy image. Damaged refusal images use complete physical byte snapshots.
func (w *fgWorld) image(t *testing.T) []mdbx.PrefixRow {
	t.Helper()
	inspection, err := w.s.Inspect()
	logicalMDBXAssert(t, err == nil, "first genesis inspect: %v", err)
	var counts []byte
	for _, dbi := range inspection.DBIs {
		counts = binary.BigEndian.AppendUint64(counts, dbi.Entries)
	}
	rows := []mdbx.PrefixRow{{Key: []byte{0xff}, Value: counts}}
	err = w.s.View(func(r *mdbx.Reader) error {
		for _, key := range [][]byte{{0}, {1}, {2}, {3}, btMeta(0x10, w.current), btMeta(0x10, w.lag), btMeta(0x11, w.current), btMeta(0x11, w.lag)} {
			if e := fgImageRow(r, &rows, 0, key); e != nil {
				return e
			}
		}
		canonical, _ := mdbx.HeightKey(w.current, 0)
		owner, _ := mdbx.CanonicalOwnerKey(w.current, w.genesis.GenesisHash)
		op := w.outpoint(t)
		for _, row := range []struct {
			rank int
			key  []byte
		}{{1, btUTXOKey(w.current, op)}, {1, btUTXOKey(w.current, Outpoint{Txid: op.Txid, Vout: 1})}, {2, canonical}, {3, w.genesis.GenesisHash[:]}, {5, mdbx.UndoManifestKey(w.genesis.GenesisHash)}, {7, owner}, {8, w.leafKey(t)}} {
			if e := fgImageRow(r, &rows, row.rank, row.key); e != nil {
				return e
			}
		}
		return fgImageRow(r, &rows, 4, w.genesis.GenesisHash[:])
	})
	logicalMDBXAssert(t, err == nil, "first genesis image: %v", err)
	return rows
}

func fgImageRow(r *mdbx.Reader, rows *[]mdbx.PrefixRow, rank int, key []byte) error {
	value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[rank], bytes.Clone(key))
	if err == nil && present {
		*rows = append(*rows, mdbx.PrefixRow{Key: append([]byte{byte(rank)}, key...), Value: bytes.Clone(value)})
	}
	return err
}

func fgSameImage(t *testing.T, before, after []mdbx.PrefixRow) {
	t.Helper()
	logicalMDBXAssert(t, reflect.DeepEqual(before, after), "first genesis changed OLD image:\nbefore %+v\nafter %+v", before, after)
}

func (w *fgWorld) applied(t *testing.T, before []mdbx.PrefixRow) {
	t.Helper()
	parsed, err := ParseInitial148BlockBytes(w.raw)
	logicalMDBXAssert(t, err == nil, "readback parse: %v", err)
	inspection, inspectErr := w.s.Inspect()
	logicalMDBXAssert(t, inspectErr == nil && len(inspection.DBIs) == 9, "readback DBIs: %v", inspectErr)
	counts := [9]uint64{8, 1, 1, 1, 1, 1, 0, 1, 1}
	for _, dbi := range inspection.DBIs {
		logicalMDBXAssert(t, dbi.Entries == counts[dbi.DBI.Rank], "readback rank%d entries %d", dbi.DBI.Rank, dbi.Entries)
	}
	w.read(t, 3, bytes.Clone(w.genesis.GenesisHash[:]), w.raw[:148])
	w.read(t, 4, bytes.Clone(w.genesis.GenesisHash[:]), w.raw)
	canonical, _ := mdbx.HeightKey(w.current, 0)
	owner, _ := mdbx.CanonicalOwnerKey(w.current, w.genesis.GenesisHash)
	w.read(t, 2, canonical, mdbx.ChainValue(w.genesis.GenesisHash, [32]byte{}, [40]byte{39: 1}))
	w.read(t, 7, owner, make([]byte, 8))
	w.read(t, 0, btMeta(0x10, w.current), mdbx.LogicalCounterValue(89, 1))
	w.read(t, 0, btMeta(0x10, w.lag), make([]byte, 16))
	w.read(t, 5, mdbx.UndoManifestKey(w.genesis.GenesisHash), mdbx.UndoManifestValue(0, [16]byte{}, 1, 0))
	op := Outpoint{Txid: parsed.Txids[0]}
	value := btValue(btFrame(parsed.Txs[0].Outputs[0].Value, parsed.Txs[0].Outputs[0].CovenantType, parsed.Txs[0].Outputs[0].CovenantData), 0, true)
	logicalMDBXAssert(t, len(value) == 53, "readback UTXO width %d", len(value))
	w.read(t, 1, btUTXOKey(w.current, op), value)
	w.read(t, 1, btUTXOKey(w.current, Outpoint{Txid: op.Txid, Vout: 1}), nil)
	root, rootErr := parseHex32("c53b167dd819e13c2442bde23729bfe6c09d899624ebaf7e98e0bb44466c694b")
	logicalMDBXAssert(t, rootErr == nil, "literal root: %v", rootErr)
	w.read(t, 8, w.leafKey(t), root[:])
	logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error {
		rawBinding, present, e := r.Get(mdbx.TreeSchemaV1DBIs()[0], btMeta(0x11, w.current))
		logicalMDBXAssert(t, e == nil && present && len(rawBinding) == 247, "CURRENT binding width: %d/%v", len(rawBinding), e)
		binding, present, e := r.ReadTreeRootBindingV1(w.current)
		logicalMDBXAssert(t, e == nil && present && binding.DatabaseID == w.database && binding.ChainID == w.genesis.ChainID && binding.GenesisHash == w.genesis.GenesisHash && binding.Endpoint == (mdbx.TreeEndpointV1{Kind: 1, BlockHash: w.genesis.GenesisHash, CumulativeChainwork: [40]byte{39: 1}}) && binding.CommitmentVersion == 1 && binding.RootDigest == root && binding.Top.Kind == 1 && binding.Top.Node != nil && binding.Top.Node.Kind == 1 && binding.Top.Node.Depth == 288 && binding.Assurance.Kind == 1 && binding.Assurance.Import == nil, "complete CURRENT binding: %+v / %v", binding, e)
		lag, present, e := r.ReadTreeRootBindingV1(w.lag)
		logicalMDBXAssert(t, e == nil && present && reflect.DeepEqual(lag, w.emptyBinding()), "LAG changed: %+v / %v", lag, e)
		return nil
	}) == nil, "readback bindings")
	for _, row := range before {
		if row.Key[0] == 0 && (len(row.Key) == 2 || bytes.Equal(row.Key[1:], btMeta(0x11, w.lag)) || bytes.Equal(row.Key[1:], btMeta(0x10, w.lag))) {
			w.read(t, 0, row.Key[1:], row.Value)
		}
	}
	btReservationsReleased(t, w.owner)
}

// G3/G4 cover the absent and both independently reused hash-global rows, and
// nondefault opening identity/generation. A second attempt must be a no-op.
func TestInitial148FirstGenesisCommitAndRepeat(t *testing.T) {
	for _, shape := range []string{"absent", "header", "body", "both", "nondefault"} {
		t.Run(shape, func(t *testing.T) {
			database, current, lag := [32]byte{7}, uint64(1), uint64(2)
			if shape == "nondefault" {
				database, current, lag = [32]byte{0xa5, 0x22}, 9, 11
			}
			w := fgNew(t, database, current, lag)
			if shape == "header" || shape == "both" {
				w.seed(t, 3, w.genesis.GenesisHash[:], w.raw[:148])
			}
			if shape == "body" || shape == "both" {
				w.seed(t, 4, w.genesis.GenesisHash[:], w.raw)
			}
			before := w.image(t)
			raw, published := bytes.Clone(w.raw), bytes.Clone(w.genesis.Published)
			fgTuple(t, w.call(), "ACCEPTED", 2, 3)
			logicalMDBXAssert(t, bytes.Equal(raw, w.raw) && bytes.Equal(published, w.genesis.Published), "accepted call mutated input")
			w.applied(t, before)
			after := w.image(t)
			fgTuple(t, w.call(), "STALE_LOCAL_PLAN", 1, 1)
			fgSameImage(t, after, w.image(t))
			w.reopen(t)
			fgSameImage(t, after, w.image(t))
			fgTuple(t, w.call(), "STALE_LOCAL_PLAN", 1, 1)
			btReservationsReleased(t, w.owner)
		})
	}
}

// G12 observes the real operation builder under W/B. Its validated and
// committing sources have equal immutable block identity/meta and final delta;
// the explicit kind/undo are the only semantic operation differences.
func TestInitial148FirstGenesisValidatedEffectEquality(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		w := fgNew(t, [32]byte{7}, 1, 2)
		if reuse {
			w.seed(t, 4, w.genesis.GenesisHash[:], w.raw)
		}
		before := w.image(t)
		err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
			input := initial148FirstGenesisInputV1(w.raw, w.genesis.Published, w.genesis.ChainID, w.genesis.GenesisHash, w.database, w.current)
			_, e := withInitial148CompleteBlockV1(a, input, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				return a.WithReservation(139146042, func() error {
					call := initial148FirstGenesisCallV1{input: input, account: a}
					var validated blockTreeEffectV1
					var transition *connectBlockInputViewResult
					call.validate = func(r *mdbx.Reader) (*initial148CompleteBlockResultV1, error) {
						got, e := validate(r)
						if got != nil {
							validated, transition = got.effect, got.transition
						}
						logicalMDBXAssert(t, icbHoldsExactlyV1(a, 158365814), "E or required scope survived validation before engine")
						return got, e
					}
					truth, stage, index, e := w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
						op, e := call.planV1(r)
						if e != nil {
							return op, e
						}
						fgPlanEquality(t, w, op, validated, transition, reuse)
						return op, nil
					})
					logicalMDBXAssert(t, e == nil && truth == 2 && stage == 3 && index == -1, "equality commit: %d/%d/%d/%v", truth, stage, index, e)
					return e
				})
			})
			return e
		})
		logicalMDBXAssert(t, err == nil, "equality enclosing W/B: %v", err)
		w.applied(t, before)
	}
}

func fgPlanEquality(t *testing.T, w *fgWorld, op mdbx.TreeOperationV1, validated blockTreeEffectV1, transition *connectBlockInputViewResult, reuse bool) {
	t.Helper()
	logicalMDBXAssert(t, len(op.Primitives) == 1 && op.Proof == nil && op.HeaderSlot == nil && op.Pair.ContextConsulted == nil && op.Pair.EntryInventory == nil, "first genesis added a non-owned domain")
	p := op.Primitives[0]
	logicalMDBXAssert(t, p.Kind == 4 && p.Undo == 1 && p.Direction == 1 && p.Generation == w.current && p.Height == 0 && p.Endpoint == (mdbx.TreeEndpointV1{Kind: 1, BlockHash: w.genesis.GenesisHash, CumulativeChainwork: [40]byte{39: 1}}), "committing primitive: %+v", p)
	v, c := *validated.Primitive.Coverage, *p.Coverage
	logicalMDBXAssert(t, validated.Primitive.Kind == 1 && validated.Primitive.Undo == 2 && v.DatabaseID == c.DatabaseID && v.Generation == c.Generation && v.Block == c.Block && v.Height == c.Height && v.HeaderBytes == c.HeaderBytes && v.BlockMeta == c.BlockMeta, "coverage identity/meta differs")
	logicalMDBXAssert(t, c.BlockMeta.TxCount == 1 && c.BlockMeta.EventCount == 1 && c.BlockMeta.Generated == ([16]byte{}), "frozen BEGIN differs: %+v", c.BlockMeta)
	logicalMDBXAssert(t, transition.alreadyGeneratedN1 == (Uint128{}) && transition.sumFees == (Uint128{}) && len(transition.createdUtxos) == 1, "validated final delta differs: %+v", transition)
	entry, present := transition.createdUtxos[w.outpoint(t)]
	wantEntry := UtxoEntry{Value: 100000000000000, CovenantType: 0, CovenantData: genesisMDBXHex("018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd7279"), CreatedByCoinbase: true}
	logicalMDBXAssert(t, present && reflect.DeepEqual(entry, wantEntry), "validated frozen CREATE differs: %+v", entry)
	if reuse {
		logicalMDBXAssert(t, c.BodyKind == 2 && c.CurrentBody == nil, "reused body payload: %+v", c)
	} else {
		logicalMDBXAssert(t, c.BodyKind == 1 && bytes.Equal(c.CurrentBody, w.raw), "new body payload")
	}
	fgPair(t, w, op.Pair, reuse)
}

func fgPair(t *testing.T, w *fgWorld, pair mdbx.TreePairV1, reuse bool) {
	t.Helper()
	wantMutations, wantConsulted := 4, 5
	if reuse {
		wantMutations, wantConsulted = 3, 6
	}
	logicalMDBXAssert(t, len(pair.Mutations) == wantMutations && len(pair.Consulted) == wantConsulted, "Pair cardinality %+v", pair)
	canonical, _ := mdbx.HeightKey(w.current, 0)
	owner, _ := mdbx.CanonicalOwnerKey(w.current, w.genesis.GenesisHash)
	want := []mdbx.Mutation{btMutation(2, canonical, mdbx.ChainValue(w.genesis.GenesisHash, [32]byte{}, [40]byte{39: 1})), btMutation(3, w.genesis.GenesisHash[:], w.raw[:148]), btMutation(7, owner, make([]byte, 8))}
	if !reuse {
		want = append(want, btMutation(4, w.genesis.GenesisHash[:], w.raw))
	}
	btSort(want)
	logicalMDBXAssert(t, reflect.DeepEqual(pair.Mutations, want), "Pair target bytes differ: %+v", pair.Mutations)
	keys := [][]byte{{0}, {1}, {2}, btMeta(0x10, w.lag), btMeta(0x11, w.lag)}
	for i, key := range keys {
		logicalMDBXAssert(t, pair.Consulted[i].DBI.Rank == 0 && bytes.Equal(pair.Consulted[i].Key, key), "Pair consulted %d: %+v", i, pair.Consulted[i])
	}
	if reuse {
		logicalMDBXAssert(t, pair.Consulted[5].DBI.Rank == 4 && bytes.Equal(pair.Consulted[5].Key, w.genesis.GenesisHash[:]), "body reuse not consulted")
	}
}

// G15 all ordered prestate and expected-context rows are exercised through the
// public entry. Each carries exact image preservation, no commit and release.
func TestInitial148FirstGenesisPrestateOrder(t *testing.T) {
	for _, name := range []string{"authority-absent", "authority-malformed", "phase", "lifecycle", "current-absent", "lag-absent", "current-malformed", "lag-malformed", "current-chain", "lag-chain", "current-hash", "lag-hash", "current-endpoint", "lag-endpoint", "current-assurance", "lag-assurance", "database-mismatch", "generation-mismatch", "both-context-mismatch", "stored-database-with-expected-mismatch", "lag-database-with-expected-mismatch", "stored-chain-with-expected-mismatch", "stored-hash-with-expected-mismatch", "foreign-chain-applied", "lag-counter", "lag-counter-bytes", "lag-counter-count", "lag-counter-absent", "lag-counter-malformed", "current-counter", "current-counter-bytes", "current-counter-count", "canonical", "owner", "header-different", "body-different", "body-long", "body-overbound"} {
		t.Run(name, func(t *testing.T) {
			w := fgNew(t, [32]byte{7}, 1, 2)
			expectedDB, expectedGeneration := w.database, w.current
			want := "TERMINAL_STORE_INTEGRITY(canonical)"
			skipBody := name == "body-overbound"
			fgPrestateCase(t, w, name, &expectedDB, &expectedGeneration, &want)
			before := fgDisk(t, w)
			rawSnapshot, publishedSnapshot := bytes.Clone(w.raw), bytes.Clone(w.genesis.Published)
			var out Initial148FirstGenesisOutcomeV1
			evidence, fixtureErr := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() { out = w.context(expectedDB, expectedGeneration) })
			logicalMDBXAssert(t, fixtureErr == nil && evidence.Commits == 0, "prestate native effects %s: %+v/%v", name, evidence, fixtureErr)
			fgTuple(t, out, want, 1, 1)
			fgPrestateCause(t, name, out, evidence)
			// Native shape failures consume their Reader/Store under the existing
			// disposition; reopen before observing. Application refusals stay open.
			if e := w.s.View(func(*mdbx.Reader) error { return nil }); e != nil {
				cached := w.context(expectedDB, expectedGeneration)
				logicalMDBXAssert(t, cached.Truth == out.Truth && cached.Stage == 1 && any(cached.Err) == any(out.Err), "cached prestate cause changed")
				if name != "authority-malformed" && name != "authority-absent" {
					w.reopen(t)
				} else {
					opened, openErr := mdbx.OpenTreeV1(w.path, w.cfg, w.database)
					var engine *mdbx.EngineError
					logicalMDBXAssert(t, opened == nil && errors.As(openErr, &engine) && engine.Class == mdbx.EngineIntegrity, "damaged authority reopened as qualified: %v", openErr)
				}
			}
			logicalMDBXAssert(t, bytes.Equal(before, fgDisk(t, w)) && bytes.Equal(rawSnapshot, w.raw) && bytes.Equal(publishedSnapshot, w.genesis.Published), "prestate refusal mutated committed bytes/input")
			btReservationsReleased(t, w.owner)
			if name == "database-mismatch" || name == "generation-mismatch" || name == "both-context-mismatch" {
				image := w.image(t)
				fgTuple(t, w.call(), "ACCEPTED", 2, 3)
				w.applied(t, image)
			}
			if skipBody {
				e := w.s.View(func(r *mdbx.Reader) error {
					_, _, e := r.Get(mdbx.TreeSchemaV1DBIs()[4], bytes.Clone(w.genesis.GenesisHash[:]))
					return e
				})
				var engine *mdbx.EngineError
				logicalMDBXAssert(t, errors.As(e, &engine) && engine.Class == mdbx.EngineIntegrity, "overbound Reader payload refusal: %v", e)
			}
		})
	}
}

func fgPrestateCase(t *testing.T, w *fgWorld, name string, database *[32]byte, generation *uint64, want *string) {
	t.Helper()
	if name == "authority-absent" {
		w.seed(t, 0, []byte{2}, nil)
		return
	}
	if name == "authority-malformed" {
		w.seed(t, 0, []byte{2}, []byte{0xff})
		return
	}
	if name == "phase" || name == "lifecycle" {
		a := mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: w.current, NextGenerationID: 3, Phase: 1, Lifecycle: 1}, LagGenerationID: w.lag}
		if name == "lifecycle" {
			a.Authority.Lifecycle = 2
			profile := a.Authority.ActiveProfile
			a.Authority.PendingTargetProfile = &profile
		} else {
			a.Authority.Phase = 2
			a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: mdbx.CleanupSpanGenerationV1, GenerationID: 3}}}
			a.Authority.NextGenerationID = 4
		}
		w.seedAuthority(t, a)
		*want = "STALE_LOCAL_PLAN"
		return
	}
	if name == "database-mismatch" {
		database[0] ^= 1
		*want = "STALE_LOCAL_PLAN"
		return
	}
	if name == "generation-mismatch" {
		*generation = 9
		*want = "STALE_LOCAL_PLAN"
		return
	}
	if name == "both-context-mismatch" {
		database[0] ^= 2
		*generation = 9
		*want = "STALE_LOCAL_PLAN"
		return
	}
	if name == "lag-counter-bytes" {
		w.seed(t, 0, btMeta(0x10, w.lag), mdbx.LogicalCounterValue(89, 0))
		return
	}
	if name == "lag-counter-count" {
		w.seed(t, 0, btMeta(0x10, w.lag), mdbx.LogicalCounterValue(0, 1))
		return
	}
	if name == "current-counter-bytes" {
		w.seed(t, 0, btMeta(0x10, w.current), mdbx.LogicalCounterValue(89, 0))
		return
	}
	if name == "current-counter-count" {
		w.seed(t, 0, btMeta(0x10, w.current), mdbx.LogicalCounterValue(0, 1))
		return
	}
	if name == "current-counter" {
		w.seed(t, 0, btMeta(0x10, w.current), mdbx.LogicalCounterValue(89, 1))
		return
	}
	if name == "lag-counter" {
		w.seed(t, 0, btMeta(0x10, w.lag), mdbx.LogicalCounterValue(89, 1))
		return
	}
	if name == "lag-counter-absent" {
		w.seed(t, 0, btMeta(0x10, w.lag), nil)
		return
	}
	if name == "lag-counter-malformed" {
		w.seed(t, 0, btMeta(0x10, w.lag), []byte{0xff})
		return
	}
	if name == "canonical" {
		key, _ := mdbx.HeightKey(w.current, 0)
		w.seed(t, 2, key, mdbx.ChainValue(w.genesis.GenesisHash, [32]byte{}, [40]byte{39: 1}))
		return
	}
	if name == "owner" {
		key, _ := mdbx.CanonicalOwnerKey(w.current, w.genesis.GenesisHash)
		w.seed(t, 7, key, make([]byte, 8))
		return
	}
	if name == "header-different" {
		value := bytes.Clone(w.raw[:148])
		value[0] ^= 1
		w.seed(t, 3, w.genesis.GenesisHash[:], value)
		return
	}
	if name == "body-different" || name == "body-long" || name == "body-overbound" {
		value := bytes.Clone(w.raw)
		switch name {
		case "body-different":
			value[200] ^= 1
		case "body-long":
			value = append(value, 0)
		case "body-overbound":
			value = make([]byte, 68_000_158)
		}
		w.seed(t, 4, w.genesis.GenesisHash[:], value)
		return
	}
	fgBindingCase(t, w, name, database, generation, want)
}

func fgBindingCase(t *testing.T, w *fgWorld, name string, database *[32]byte, generation *uint64, want *string) {
	t.Helper()
	role := w.current
	if len(name) >= 4 && name[:4] == "lag-" {
		role = w.lag
	}
	if name == "current-absent" || name == "lag-absent" {
		w.seed(t, 0, btMeta(0x11, role), nil)
		return
	}
	if name == "current-malformed" || name == "lag-malformed" {
		w.seed(t, 0, btMeta(0x11, role), []byte{0xff})
		return
	}
	root := w.emptyBinding()
	switch name {
	case "current-chain", "lag-chain":
		root.ChainID[0] ^= 1
	case "current-hash", "lag-hash":
		root.GenesisHash[0] ^= 1
	case "current-endpoint", "lag-endpoint":
		root.Endpoint = mdbx.TreeEndpointV1{Kind: 1, BlockHash: w.genesis.GenesisHash, CumulativeChainwork: [40]byte{39: 1}}
		*want = "STALE_LOCAL_PLAN"
	case "current-assurance", "lag-assurance":
		root.Assurance = mdbx.TreeAssuranceV1{Kind: 2, Import: &mdbx.TreeImportReferenceV1{OriginalDatabaseID: [32]byte{9}, OriginalCurrentID: 1, OriginalLagID: 2, OriginalRole: 1, EvidenceID: [32]byte{4}}}
		*want = "STALE_LOCAL_PLAN"
	case "stored-database-with-expected-mismatch", "lag-database-with-expected-mismatch":
		root.DatabaseID[0] ^= 1
		database[0] ^= 2
		*generation = 9
	case "stored-chain-with-expected-mismatch":
		root.ChainID[0] ^= 1
		database[0] ^= 2
		*generation = 9
	case "stored-hash-with-expected-mismatch":
		root.GenesisHash[0] ^= 1
		database[0] ^= 2
		*generation = 9
	case "foreign-chain-applied":
		root.ChainID[0] ^= 1
		root.Endpoint = mdbx.TreeEndpointV1{Kind: 1, BlockHash: w.genesis.GenesisHash, CumulativeChainwork: [40]byte{39: 1}}
	default:
		t.Fatalf("unowned prestate row %s", name)
	}
	w.seedBinding(t, role, root)
}

// G13 uses only the existing actual reservation owner and native probe.
func fgHeld(t *testing.T, owner *mdbx.OperationReservationOwner, held uint64, run func()) {
	t.Helper()
	if held == 0 {
		run()
		return
	}
	charge := min(held, uint64(402653184))
	err := owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(charge, func() error { fgHeld(t, owner, held-charge, run); return nil })
	})
	logicalMDBXAssert(t, err == nil, "external held capacity: %v", err)
}

func TestInitial148FirstGenesisReservationBoundaries(t *testing.T) {
	for _, row := range []struct {
		name     string
		residual uint64
		begins   uint64
		mutate   string
	}{{"B-one-short", 158365813, 0, ""}, {"B-exact", 158365814, 1, ""}, {"E-one-short", 159053970, 1, ""}, {"D-one-short", 159342482, 1, ""}, {"identity-before-B", 158365813, 0, "identity"}, {"zero-context-before-B", 158365813, 0, "context"}} {
		t.Run(row.name, func(t *testing.T) {
			w := fgNew(t, [32]byte{7}, 1, 2)
			before := w.image(t)
			var out Initial148FirstGenesisOutcomeV1
			var counts mdbx.SelectedDamageEvidence
			fgHeld(t, w.owner, 805306368-row.residual, func() {
				var fixtureErr error
				counts, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
					switch row.mutate {
					case "identity":
						hash := w.genesis.GenesisHash
						hash[0] ^= 1
						out = ConnectPublishedInitial148GenesisMDBX(w.s, w.owner, w.raw, w.genesis.Published, w.genesis.ChainID, hash, w.database, w.current)
					case "context":
						out = w.context([32]byte{}, w.current)
					default:
						out = w.call()
					}
				})
				logicalMDBXAssert(t, fixtureErr == nil, "boundary fixture: %v", fixtureErr)
			})
			want := "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
			if row.mutate != "" {
				want = "TERMINAL_LOCAL_INVARIANT(evidence)"
			}
			fgTuple(t, out, want, 1, 1)
			logicalMDBXAssert(t, counts.BeginOld == row.begins && counts.BeginWrite == 0 && counts.Commits == 0, "B/E acquired at wrong point: %+v", counts)
			fgSameImage(t, before, w.image(t))
			btReservationsReleased(t, w.owner)
			fgTuple(t, w.call(), "ACCEPTED", 2, 3)
			w.applied(t, before)
		})
	}
}

func TestInitial148FirstGenesisBorrowedLifetime(t *testing.T) {
	w := fgNew(t, [32]byte{7}, 1, 2)
	before := w.image(t)
	var out Initial148FirstGenesisOutcomeV1
	var evidence mdbx.SelectedDamageEvidence
	fgHeld(t, w.owner, 805306368-174807592, func() {
		var err error
		evidence, err = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageCommitNew, 0, nil, func() { out = w.call() })
		logicalMDBXAssert(t, err == nil, "borrowed lifetime fixture: %v", err)
	})
	fgTuple(t, out, "TERMINAL_PERSISTENCE(new)", 2, 3)
	logicalMDBXAssert(t, evidence.BeginOld == 1 && evidence.BeginWrite == 1 && evidence.Commits == 1 && evidence.BeginRead == 1 && evidence.OldAborts > 0 && evidence.Probes > 0 && evidence.ProbeDenied == evidence.Probes && evidence.ProbeRan == 0, "B ended before native last use: %+v", evidence)
	w.reopen(t)
	w.applied(t, before)
}

func TestInitial148FirstGenesisCrossedTruth(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario mdbx.SelectedDamageScenario
		truth    mdbx.CommitTruth
		result   string
		faults   uint64
	}{{"old", mdbx.SelectedDamageCommitOld, 1, "TERMINAL_PERSISTENCE(old)", 1}, {"new", mdbx.SelectedDamageCommitNew, 2, "TERMINAL_PERSISTENCE(new)", 1}, {"unreadable", mdbx.SelectedDamageCommitUnreadable, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", 2}, {"third", mdbx.SelectedDamageCommitThird, 3, "TERMINAL_PERSISTENCE(neither_or_unreadable)", 1}, {"abort", mdbx.SelectedDamageAbortEIO, 2, "TERMINAL_PERSISTENCE(new)", 1}} {
		t.Run(row.name, func(t *testing.T) {
			w := fgNew(t, [32]byte{7}, 1, 2)
			before := w.image(t)
			beforeDisk := fgDisk(t, w)
			var out Initial148FirstGenesisOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, row.scenario, 0, []byte{2}, func() { out = w.call() })
			readbacks := uint64(1)
			if row.name == "abort" {
				readbacks = 0
			}
			logicalMDBXAssert(t, err == nil && evidence.Faults == row.faults && evidence.Commits == 1 && evidence.BeginRead == readbacks, "crossed fixture: %+v / %v", evidence, err)
			fgTuple(t, out, row.result, row.truth, 3)
			var crossed *mdbx.CommitError
			if row.name == "abort" {
				_ = btfEngine(t, out.Err, "abort", mdbx.EngineIO, 5, "error 5")
			} else {
				logicalMDBXAssert(t, errors.As(out.Err, &crossed) && crossed.Truth == row.truth && crossed.Cause != nil, "raw crossed tuple: %v", out.Err)
			}
			cached := w.call()
			cachedResult := ""
			if row.truth == 1 {
				cachedResult = "LOCAL_RESOURCE_UNAVAILABLE(storage_io)"
			}
			logicalMDBXAssert(t, cached.Result == cachedResult && cached.Stage == 1 && cached.Truth == out.Truth && any(cached.Err) == any(out.Err), "cached tuple changed: %+v", cached)
			btReservationsReleased(t, w.owner)
			if row.name == "third" {
				opened, openErr := mdbx.OpenTreeV1(w.path, w.cfg, w.database)
				var engine *mdbx.EngineError
				logicalMDBXAssert(t, opened == nil && errors.As(openErr, &engine) && engine.Class == mdbx.EngineIntegrity, "UNKNOWN third image became qualified: %v", openErr)
				logicalMDBXAssert(t, !bytes.Equal(fgDisk(t, w), beforeDisk), "third image was reported as unchanged OLD")
				return
			}
			w.reopen(t)
			if row.truth == 1 {
				fgSameImage(t, before, w.image(t))
				fgTuple(t, w.call(), "ACCEPTED", 2, 3)
				w.applied(t, before)
			}
			if row.name == "new" || row.name == "unreadable" || row.name == "abort" {
				w.applied(t, before)
				fgTuple(t, w.call(), "STALE_LOCAL_PLAN", 1, 1)
			}
		})
	}
}

func TestInitial148FirstGenesisNativeRefusals(t *testing.T) {
	for _, row := range []struct {
		name     string
		scenario mdbx.SelectedDamageScenario
		rank     uint8
		result   string
		stage    mdbx.UpdateStage
		class    mdbx.EngineClass
	}{{"begin-io", mdbx.SelectedDamageBeginEIO, 0, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 1, mdbx.EngineIO}, {"begin-full", mdbx.SelectedDamageBeginTxnFull, 0, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", 1, mdbx.EngineTransaction}, {"write-begin-full", mdbx.SelectedDamageWriteBeginTxnFull, 0, "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", 1, mdbx.EngineTransaction}, {"get", mdbx.SelectedDamageGetEIO, 0, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 1, mdbx.EngineIO}, {"get-abort", mdbx.SelectedDamageGetAbortEIO, 0, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 1, mdbx.EngineIO}, {"counter-get", mdbx.SelectedDamageGetEIO, 0, "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 1, mdbx.EngineIO}, {"put", mdbx.SelectedDamagePutEIO, 1, "LOCAL_PERSISTENCE_ERROR(precommit)", 2, mdbx.EngineIO}} {
		t.Run(row.name, func(t *testing.T) {
			w := fgNew(t, [32]byte{7}, 1, 2)
			before := w.image(t)
			key := []byte{2}
			if row.name == "put" {
				key = btUTXOKey(w.current, w.outpoint(t))
			}
			if row.name == "counter-get" {
				key = btMeta(0x10, w.current)
			}
			var out Initial148FirstGenesisOutcomeV1
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, row.scenario, row.rank, key, func() { out = w.call() })
			faults := uint64(1)
			if row.name == "get-abort" {
				faults = 2
			}
			logicalMDBXAssert(t, err == nil && evidence.Faults == faults && evidence.Commits == 0, "native refusal site: %+v/%v", evidence, err)
			fgTuple(t, out, row.result, 1, row.stage)
			var engine *mdbx.EngineError
			logicalMDBXAssert(t, errors.As(out.Err, &engine) && engine.Class == row.class && engine.Code != 0 && engine.Diagnostic != "", "native cause fidelity: %v", out.Err)
			if row.name == "get-abort" {
				joined, ok := out.Err.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2, "read/cleanup shape: %v", out.Err)
				parts := joined.Unwrap()
				_ = btfEngine(t, parts[0], "get", mdbx.EngineIO, 5, "error 5")
				_ = btfEngine(t, parts[1], "abort", mdbx.EngineIO, 5, "error 5")
			}
			w.reopen(t)
			fgSameImage(t, before, w.image(t))
			btReservationsReleased(t, w.owner)
			fgTuple(t, w.call(), "ACCEPTED", 2, 3)
		})
	}
}

func TestInitial148FirstGenesisWriteSnapshotDrift(t *testing.T) {
	w := fgNew(t, [32]byte{7}, 1, 2)
	before := w.image(t)
	var out Initial148FirstGenesisOutcomeV1
	drifts, err := mdbx.FixtureWriteSnapshotDrift(w.s, 0, btMeta(0x11, w.lag), func() { out = w.call() })
	logicalMDBXAssert(t, err == nil && drifts == 1, "write snapshot fixture: %d/%v", drifts, err)
	fgTuple(t, out, "STALE_LOCAL_PLAN", 1, 1)
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(out.Err, &engine) && engine.Class == mdbx.EngineStateMismatch, "write snapshot raw cause: %v", out.Err)
	btReservationsReleased(t, w.owner)
	w.reopen(t)
	w.read(t, 2, binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, w.current), 0), nil)
	w.read(t, 4, bytes.Clone(w.genesis.GenesisHash[:]), nil)
	for _, row := range before {
		if row.Key[0] == 0 && !bytes.Equal(row.Key[1:], btMeta(0x11, w.lag)) {
			w.read(t, 0, row.Key[1:], row.Value)
		}
	}
	equal, rawErr := mdbx.FixtureRawRowEqual(w.s, 0, btMeta(0x11, w.lag), []byte{0x7f})
	logicalMDBXAssert(t, rawErr == nil && equal, "drifted row is not the external fixture image: %v", rawErr)
	inspection, inspectErr := w.s.Inspect()
	var counts []byte
	for _, dbi := range inspection.DBIs {
		counts = binary.BigEndian.AppendUint64(counts, dbi.Entries)
	}
	logicalMDBXAssert(t, inspectErr == nil && bytes.Equal(before[0].Value, counts), "write-snapshot refusal changed DBI cardinality: %v", inspectErr)
	w.read(t, 1, btUTXOKey(w.current, w.outpoint(t)), nil)
	w.read(t, 3, bytes.Clone(w.genesis.GenesisHash[:]), nil)
	w.read(t, 5, mdbx.UndoManifestKey(w.genesis.GenesisHash), nil)
	owner, _ := mdbx.CanonicalOwnerKey(w.current, w.genesis.GenesisHash)
	w.read(t, 7, owner, nil)
	w.read(t, 8, w.leafKey(t), nil)
	w.seedBinding(t, w.lag, w.emptyBinding())
	fgTuple(t, w.call(), "ACCEPTED", 2, 3)
}

// fgDisk observes the complete committed image even when malformed authority
// deliberately prevents reopening it through the qualified public factory.
func fgDisk(t *testing.T, w *fgWorld) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(w.path, "mdbx.dat"))
	logicalMDBXAssert(t, err == nil, "committed image: %v", err)
	return raw
}

// A control-only format-3 Store has genuinely absent authority. Absence does
// not grant PRE_GENESIS; it refuses before validation and stays reusable.
func TestInitial148FirstGenesisAbsentAuthority(t *testing.T) {
	w := fgNew(t, [32]byte{7}, 1, 2)
	for _, key := range [][]byte{{2}, btMeta(0x10, 1), btMeta(0x10, 2), btMeta(0x11, 1), btMeta(0x11, 2)} {
		w.seed(t, 0, key, nil)
	}
	before := fgDisk(t, w)
	fgTuple(t, w.call(), "TERMINAL_STORE_INTEGRITY(canonical)", 1, 1)
	logicalMDBXAssert(t, bytes.Equal(before, fgDisk(t, w)), "absent-authority refusal mutated control-only Store")
	logicalMDBXAssert(t, w.s.View(func(*mdbx.Reader) error { return nil }) == nil, "application refusal consumed reusable Store")
	btReservationsReleased(t, w.owner)
}

func (w *fgWorld) replaceArtifact(t *testing.T, raw []byte) {
	t.Helper()
	w.raw = raw
	w.genesis = fgContext(t, bytes.Clone(raw))
	w.seedBinding(t, w.current, w.emptyBinding())
	w.seedBinding(t, w.lag, w.emptyBinding())
}

// G6/G7 distinguish matching identity from complete validation, including a
// connect-stage refusal while E has insufficient capacity.
func TestInitial148FirstGenesisFullValidationAndRelease(t *testing.T) {
	for _, name := range []string{"root", "nonminimal-count", "coinbase-before-E"} {
		t.Run(name, func(t *testing.T) {
			w := fgNew(t, [32]byte{7}, 1, 2)
			raw := bytes.Clone(w.raw)
			code, message := BLOCK_ERR_UTXO_ROOT_MISMATCH, "utxo_root mismatch"
			switch name {
			case "root":
				raw[108] ^= 1
			case "nonminimal-count":
				raw[148] = 0xfd
				code, message = TX_ERR_PARSE, "non-minimal CompactSize (0xfd)"
			case "coinbase-before-E":
				binary.LittleEndian.PutUint16(raw[213:215], COV_TYPE_VAULT)
				id := sha3.Sum256(raw[149:296])
				merkle := sha3.Sum256(append([]byte{0}, id[:]...))
				copy(raw[36:68], merkle[:])
				code, message = BLOCK_ERR_COINBASE_INVALID, "coinbase must not create CORE_VAULT outputs"
			}
			w.replaceArtifact(t, raw)
			before := fgDisk(t, w)
			input, published := bytes.Clone(w.raw), bytes.Clone(w.genesis.Published)
			var out Initial148FirstGenesisOutcomeV1
			if name == "coinbase-before-E" {
				fgHeld(t, w.owner, 805306368-159053970, func() { out = w.call() })
			} else {
				out = w.call()
			}
			fgTuple(t, out, "CONSENSUS_INVALID", 1, 1)
			var tx *TxError
			logicalMDBXAssert(t, errors.As(out.Err, &tx) && tx.Code == code && tx.Msg == message, "identity-only acceptance bypassed %s validation: %v", name, out.Err)
			logicalMDBXAssert(t, bytes.Equal(before, fgDisk(t, w)) && bytes.Equal(input, w.raw) && bytes.Equal(published, w.genesis.Published), "validation refusal changed state/input")
			btReservationsReleased(t, w.owner)
			w.replaceArtifact(t, initial148BlockGenesis(t))
			image := w.image(t)
			fgTuple(t, w.call(), "ACCEPTED", 2, 3)
			w.applied(t, image)
		})
	}
}

// Exact cause and reached point counts distinguish equal-token prestate rows.
func fgPrestateCause(t *testing.T, name string, out Initial148FirstGenesisOutcomeV1, evidence mdbx.SelectedDamageEvidence) {
	t.Helper()
	message := map[string]string{
		"current-absent": "absent first genesis binding", "lag-absent": "absent first genesis binding",
		"current-chain": "first genesis binding identity differs", "lag-chain": "first genesis binding identity differs",
		"current-hash": "first genesis binding identity differs", "lag-hash": "first genesis binding identity differs",
		"stored-chain-with-expected-mismatch": "first genesis binding identity differs", "stored-hash-with-expected-mismatch": "first genesis binding identity differs",
		"foreign-chain-applied": "first genesis binding identity differs",
		"lag-counter":           "first genesis LAG counter differs", "lag-counter-bytes": "first genesis LAG counter differs", "lag-counter-count": "first genesis LAG counter differs", "lag-counter-absent": "first genesis LAG counter differs",
		"canonical": "first genesis index already present", "owner": "first genesis index already present",
		"header-different": "first genesis artifact differs", "body-different": "first genesis artifact differs", "body-long": "first genesis artifact differs",
	}[name]
	if out.Result == "STALE_LOCAL_PLAN" {
		logicalMDBXAssert(t, out.Err.Error() == "first genesis prestate changed", "stale cause %s: %v", name, out.Err)
	} else if message != "" {
		var logical *logicalStateFailure
		logicalMDBXAssert(t, errors.As(out.Err, &logical) && logical.kind == logicalStateFailureStoreIntegrity && logical.cause != nil && logical.cause.Error() == message, "canonical cause %s: %v", name, out.Err)
	} else {
		var engine *mdbx.EngineError
		op := "get"
		if name == "current-counter" || name == "current-counter-bytes" || name == "current-counter-count" {
			op = "update"
		}
		logicalMDBXAssert(t, errors.As(out.Err, &engine) && engine.Class == mdbx.EngineIntegrity && engine.Operation == op && engine.Code == -30796 && engine.Diagnostic == "invalid tree native representation" && !engine.ReopenRequired, "native integrity %s: %v", name, out.Err)
	}
	metadata := map[string]uint64{
		"authority-absent": 1, "authority-malformed": 1, "phase": 1, "lifecycle": 1, "current-absent": 2, "current-malformed": 2, "lag-absent": 3, "lag-malformed": 3,
		"current-chain": 3, "lag-chain": 3, "current-hash": 3, "lag-hash": 3, "current-endpoint": 3, "lag-endpoint": 3, "current-assurance": 3, "lag-assurance": 3, "database-mismatch": 3, "generation-mismatch": 3, "both-context-mismatch": 3,
		"stored-database-with-expected-mismatch": 2, "lag-database-with-expected-mismatch": 3, "stored-chain-with-expected-mismatch": 3, "stored-hash-with-expected-mismatch": 3, "foreign-chain-applied": 3,
		"lag-counter": 4, "lag-counter-bytes": 4, "lag-counter-count": 4, "lag-counter-absent": 4, "lag-counter-malformed": 4, "canonical": 4, "owner": 4, "header-different": 4, "body-different": 4, "body-long": 4, "body-overbound": 4,
	}[name]
	if metadata != 0 {
		logicalMDBXAssert(t, evidence.OldGets[0] == metadata && evidence.NodeGets == 0 && evidence.BeginWrite == 0, "ordered prestate points %s: %+v", name, evidence)
	}
	if name == "canonical" {
		logicalMDBXAssert(t, evidence.OldGets[2] == 1 && evidence.OldGets[7] == 0, "canonical/owner order: %+v", evidence)
	}
	if name == "owner" {
		logicalMDBXAssert(t, evidence.OldGets[2] == 1 && evidence.OldGets[7] == 1, "owner point: %+v", evidence)
	}
	if name == "header-different" {
		logicalMDBXAssert(t, evidence.OldGets[3] == 1 && evidence.OldGets[4] == 0, "header/body order: %+v", evidence)
	}
}

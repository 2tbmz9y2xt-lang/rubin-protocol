//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// rpStore observes the real native callback boundary. It never supplies a
// validation result, root, admission verdict or commit result itself.
type rpStore struct {
	store   *mdbx.Store
	calls   int
	reader  *mdbx.Reader
	account *mdbx.OperationAccount
	inspect func(mdbx.TreeOperationV1)
	native  btResult
}

func (s *rpStore) UpdateTreeV1(a *mdbx.OperationAccount, build func(*mdbx.Reader) (mdbx.TreeOperationV1, error)) (mdbx.CommitTruth, mdbx.UpdateStage, int, error) {
	s.calls++
	s.account = a
	s.native.truth, s.native.stage, s.native.index, s.native.err = s.store.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
		s.reader = r
		op, err := build(r)
		if err == nil && s.inspect != nil {
			s.inspect(op)
		}
		return op, err
	})
	return s.native.truth, s.native.stage, s.native.index, s.native.err
}

type rpCase struct {
	w          *btWorld
	in         initial148CompleteBlockInputV1
	request    replayPairRequestV1
	rows       replayPairRowsV1
	store      rpStore
	current    int
	lag        int
	result     *initial148CompleteBlockResultV1
	validation initial148CompleteBlockOutcomeV1
}

type rpTypedError struct{}

func (*rpTypedError) Error() string { return "typed nil application cause" }

// rpNew uses the existing complete genesis validator and native state fixture.
// Each case owns its fresh store and independently snapshots its input bytes.
func rpNew(t *testing.T, target uint64, body uint8, undo mdbx.TreeUndoEffectV1) *rpCase {
	t.Helper()
	w := btNew(t)
	in, _ := icbGenesisInputV1(t, -1)
	a := mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{
		Version: 1, ActiveProfile: 1, ActiveGenerationID: 3, NextGenerationID: 5,
		Phase: 3, Lifecycle: 2, Replay: &mdbx.ReplayV1{
			TargetProfile: 2, TargetGenerationID: 1,
			Target: mdbx.RecoveryTargetV1{
				ChainID: in.ChainID, GenesisHash: in.Endpoint.BlockHash,
				TipHeight: target, TipHash: [32]byte{9}, CumulativeChainwork: [40]byte{39: 99},
			},
			Cursor: mdbx.ReplayCursorV1{Kind: 1},
		},
	}, LagGenerationID: 4, TargetLagGenerationID: 2, SourceKind: 1}
	if body == 3 || undo == mdbx.UndoCompareV1 || undo == mdbx.UndoCompareDeleteV1 {
		a.Authority.Replay.TargetProfile = mdbx.StorageProfilePrunedV1
	}
	encoded, err := a.Encode()
	logicalMDBXAssert(t, err == nil, "replay authority encoding: %v", err)
	m := btMutation(0, []byte{2}, encoded)
	m.BeforePresent = true
	w.pair(t, m)
	c := &rpCase{w: w, in: in, request: replayPairRequestV1{Authority: a, Database: [32]byte{7}, Endpoint: in.Endpoint, Raw: in.Raw}, rows: replayPairRowsV1{BodyKind: body, Undo: undo}, store: rpStore{store: w.s}}
	if body == 2 {
		w.pair(t, btMutation(3, in.Endpoint.BlockHash[:], in.Raw[:148]), btMutation(4, in.Endpoint.BlockHash[:], in.Raw))
	}
	if undo == mdbx.UndoCompareV1 || undo == mdbx.UndoCompareDeleteV1 {
		r := btRequest(in.Raw, 0)
		w.pair(t, btMutation(5, append(bytes.Clone(r.Block[:]), 0), btManifest(r, 1, 0)))
	}
	return c
}

// prepare owns only real validation then the caller's already-decided rows.
func (c *rpCase) prepare(t *testing.T, validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) replayPairPrepareCurrentV1 {
	t.Helper()
	return func(r *mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error) {
		c.current++
		result, err := validate(r)
		if err != nil {
			return nil, replayPairRowsV1{}, err
		}
		c.result = result
		rows := c.rows
		rows.Pair = rpPair(t, c.request.Authority, c.in)
		return result, rows, nil
	}
}

// rpPair supplies the caller-owned replay cursor and header, with no LAG cursor.
func rpPair(t *testing.T, authority mdbx.TreeAuthorityV1, in initial148CompleteBlockInputV1) mdbx.TreePairV1 {
	t.Helper()
	replay := *authority.Authority.Replay
	replay.Cursor = mdbx.ReplayCursorV1{Kind: 2, Height: in.Height, BlockHash: in.Endpoint.BlockHash}
	authority.Authority.Replay = &replay
	encoded, err := authority.Encode()
	logicalMDBXAssert(t, err == nil, "planned replay authority: %v", err)
	m := btMutation(0, []byte{2}, encoded)
	m.BeforePresent = true
	return mdbx.TreePairV1{Mutations: []mdbx.Mutation{m, btMutation(3, in.Endpoint.BlockHash[:], in.Raw[:148])}}
}

func (c *rpCase) inputs(_ *mdbx.Reader, _ *initial148CompleteBlockResultV1, use func([]mdbx.TreeOutpointV1) error) error {
	c.lag++
	return use(nil)
}

// run keeps the complete validator's live result/M inside its native callback.
func (c *rpCase) run(t *testing.T, alter func(replayPairPrepareCurrentV1) replayPairPrepareCurrentV1, inputs replayPairWithLagInputsV1) replayPairOutcomeV1 {
	t.Helper()
	var got replayPairOutcomeV1
	err := c.w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(8388608, func() error {
			out, runErr := withInitial148CompleteBlockV1(a, c.in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
				prepare := c.prepare(t, validate)
				if alter != nil {
					prepare = alter(prepare)
				}
				got = applyReplayPairV1(&c.store, a, c.request, prepare, inputs)
				logicalMDBXAssert(t, c.store.account == a && c.store.calls == 1, "exactly one native call on one account")
				logicalMDBXAssert(t, got.Truth == c.store.native.truth && got.Stage == c.store.native.stage && got.Index == c.store.native.index && any(got.Err) == any(c.store.native.err), "composer preserves exact captured native product")
				return got.Err
			})
			logicalMDBXAssert(t, any(runErr) == any(got.Err), "complete/native error identity: %v/%v", runErr, got.Err)
			c.validation = out
			return nil
		})
	})
	logicalMDBXAssert(t, err == nil && c.store.calls == 1, "exactly one native call on one account: %v/%d", err, c.store.calls)
	btReservationsReleased(t, c.w.owner)
	return got
}

// TestReplayPairGenesis protects actual atomic role/body/undo/index effects.
// The old test-owned composer cannot cover this new production entrypoint;
// no test-only production hook or result substitute is required.
func TestReplayPairGenesis(t *testing.T) {
	for _, row := range []struct {
		name string
		body uint8
		undo mdbx.TreeUndoEffectV1
	}{
		{"archive-absent", 1, mdbx.UndoTransientV1},
		{"below-promise-absent", 3, mdbx.UndoTransientV1},
		{"archive-stored", 2, mdbx.UndoTransientV1},
		{"old-active-owner", 2, mdbx.UndoCompareV1},
		{"no-old-active-owner", 2, mdbx.UndoCompareDeleteV1},
	} {
		t.Run(row.name, func(t *testing.T) {
			c := rpNew(t, 15840, row.body, row.undo)
			before := bytes.Clone(c.in.Raw)
			unrelatedKey := append(make([]byte, 32), 0)
			unrelatedKey[0] = 0x77
			unrelated := btManifest(btRequest(c.in.Raw, 0), 1, 0)
			c.w.pair(t, btMutation(5, unrelatedKey, unrelated))
			c.store.inspect = func(op mdbx.TreeOperationV1) { rpAssertPlan(t, c, op, 2) }
			alter := rpStoredRows(t, c, row.name == "no-old-active-owner")
			got := c.run(t, alter, c.inputs)
			rpTuple(t, got, 2, 3, -1, nil, "")
			logicalMDBXAssert(t, c.current == 1 && c.lag == 1 && bytes.Equal(c.in.Raw, before), "single validation/LAG and immutable Raw")
			rpGenesisState(t, c, true)
			want := c.in.Raw
			if row.body == 3 || row.name == "no-old-active-owner" {
				want = nil
			}
			c.w.read(t, 4, c.in.Endpoint.BlockHash[:], want)
			manifest := append(bytes.Clone(c.in.Endpoint.BlockHash[:]), 0)
			var wantUndo []byte
			if row.undo == mdbx.UndoWriteOrReuseV1 || row.undo == mdbx.UndoCompareV1 {
				wantUndo = btManifest(btRequest(c.in.Raw, 0), 1, 0)
			}
			c.w.read(t, 5, manifest, wantUndo)
			c.w.read(t, 5, unrelatedKey, unrelated)
		})
	}
}

func rpStoredRows(t *testing.T, c *rpCase, remove bool) func(replayPairPrepareCurrentV1) replayPairPrepareCurrentV1 {
	t.Helper()
	return func(prepare replayPairPrepareCurrentV1) replayPairPrepareCurrentV1 {
		return func(r *mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error) {
			result, rows, err := prepare(r)
			if c.rows.BodyKind == 2 {
				rows.Pair.Mutations = rows.Pair.Mutations[:1] // Existing header remains unchanged.
			}
			if remove {
				rows.Pair.Mutations = append(rows.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: c.in.Endpoint.BlockHash[:], BeforePresent: true, AfterKind: mdbx.AfterAbsent})
			}
			return result, rows, err
		}
	}
}

func rpTuple(t *testing.T, got replayPairOutcomeV1, truth, stage uint8, index int, cause error, role string) {
	t.Helper()
	logicalMDBXAssert(t, uint8(got.Truth) == truth && uint8(got.Stage) == stage && got.Index == index && any(got.Err) == any(cause) && (role == "" || got.Role == role),
		"exact replay tuple: (%d,%d,%d,%v,%s), want (%d,%d,%d,%v,%s)", got.Truth, got.Stage, got.Index, got.Err, got.Role, truth, stage, index, cause, role)
}

func rpAssertPlan(t *testing.T, c *rpCase, op mdbx.TreeOperationV1, count int) {
	t.Helper()
	logicalMDBXAssert(t, len(op.Primitives) == count && op.Proof == nil && op.HeaderSlot == nil && op.Pair.EntryInventory == nil && op.Pair.PrepaidReadBytes == 0, "selected replay shape")
	for i, p := range op.Primitives {
		kind, undo := mdbx.TreeKindReplayNextV1, c.rows.Undo
		if i == 1 {
			kind, undo = mdbx.TreeKindLagForwardV1, mdbx.UndoTransientV1
		}
		logicalMDBXAssert(t, p.Kind == kind && p.Undo == undo && p.Generation == uint64(i+1) && p.Height == c.in.Height && p.Block == c.in.Endpoint.BlockHash && p.Endpoint == c.in.Endpoint, "role%d exact primitive kind/undo/generation/endpoint", i)
		source := p.Source.(*blockTreeSourceV1)
		v := c.result.effect.Primitive
		logicalMDBXAssert(t, v.Kind == mdbx.TreeKindDirectApplyV1 && p.Source != v.Source && source.coverage.BlockMeta == v.Coverage.BlockMeta && p.Coverage.BodyKind == c.rows.BodyKind, "F2 independent producer metadata/body equality")
		logicalMDBXAssert(t, p.Coverage.DatabaseID == v.Coverage.DatabaseID && p.Coverage.Generation == p.Generation && p.Coverage.Block == v.Coverage.Block && p.Coverage.Height == v.Coverage.Height && p.Coverage.HeaderBytes == 148, "separate producer complete coverage identity")
		validatedSource := v.Source.(*blockTreeSourceV1)
		logicalMDBXAssert(t, &validatedSource.Raw[0] == &c.in.Raw[0], "validated reference retains original immutable delta body")
		if c.rows.BodyKind == 2 {
			logicalMDBXAssert(t, source.Raw == nil && p.Coverage.CurrentBody == nil, "stored body nil payload")
		} else {
			logicalMDBXAssert(t, &source.Raw[0] == &c.in.Raw[0] && &p.Coverage.CurrentBody[0] == &c.in.Raw[0], "shared immutable role Raw backing")
		}
	}
	bodyRows, cursorRows := 0, 0
	for _, row := range op.Pair.Mutations {
		if row.DBI.Rank == 4 {
			bodyRows++
			if c.rows.BodyKind == 1 {
				logicalMDBXAssert(t, !row.BeforePresent && row.AfterKind == 2 && &row.Literal[0] == &c.in.Raw[0], "single shared expected-absent body literal")
			}
		}
		if row.DBI.Rank == 0 && bytes.Equal(row.Key, []byte{2}) {
			cursorRows++
		}
	}
	logicalMDBXAssert(t, cursorRows == 1 && (c.rows.BodyKind != 1 || bodyRows == 1) && (c.rows.BodyKind != 3 || bodyRows == 0), "one cursor/shared body effect; no below-promise write")
}

func rpGenesisState(t *testing.T, c *rpCase, paired bool) {
	t.Helper()
	tx, id, _, n, err := ParseTx(c.in.Raw[149:])
	logicalMDBXAssert(t, err == nil && n+149 == len(c.in.Raw), "independent genesis transaction: %v", err)
	rows := map[Outpoint]UtxoEntry{}
	for i, output := range tx.Outputs {
		if output.CovenantType != COV_TYPE_ANCHOR && output.CovenantType != COV_TYPE_DA_COMMIT {
			rows[Outpoint{Txid: id, Vout: uint32(i)}] = btEntry(output.Value, output.CovenantType, output.CovenantData, 0, true)
		}
	}
	btState(t, c.w, 1, c.in.Endpoint, rows)
	r := btRequest(c.in.Raw, 0)
	r.Endpoint = c.in.Endpoint
	btIndexes(t, c.w, r, true)
	if paired {
		btState(t, c.w, 2, c.in.Endpoint, rows)
		r.Generation = 2
		btIndexes(t, c.w, r, true)
	} else {
		btState(t, c.w, 2, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
	}
	err = c.w.s.View(func(r *mdbx.Reader) error {
		a, present, readErr := r.ReadTreeAuthorityV1()
		logicalMDBXAssert(t, readErr == nil && present && a.Authority.Replay.Cursor.Kind == 2 && a.Authority.Replay.Cursor.Height == 0 && a.Authority.Replay.Cursor.BlockHash == c.in.Endpoint.BlockHash, "single persisted replay cursor: %+v/%v", a.Authority.Replay, readErr)
		return readErr
	})
	logicalMDBXAssert(t, err == nil, "cursor read: %v", err)
}

// TestReplayPairCurrentOnly protects skipped LAG stages at fixed target edges.
// A pair accidentally enabled below 15120 reaches the forbidden callback.
func TestReplayPairCurrentOnly(t *testing.T) {
	for _, target := range []uint64{1, 15119} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			undo := mdbx.UndoTransientV1
			if target == 1 {
				undo = mdbx.UndoWriteOrReuseV1
			}
			c := rpNew(t, target, 1, undo)
			c.store.inspect = func(op mdbx.TreeOperationV1) { rpAssertPlan(t, c, op, 1) }
			got := c.run(t, nil, nil)
			rpTuple(t, got, 2, 3, -1, nil, "")
			logicalMDBXAssert(t, c.lag == 0, "CURRENT-only invoked LAG")
			rpGenesisState(t, c, false)
			var want []byte
			if target == 1 {
				want = btManifest(btRequest(c.in.Raw, 0), 1, 0)
			}
			c.w.read(t, 5, append(bytes.Clone(c.in.Endpoint.BlockHash[:]), 0), want)
		})
	}
}

// TestReplayPairCurrentRefusal protects callback order, exact causes and nil
// successful-result guards. Existing engine tests cannot cover composer stages.
func TestReplayPairCurrentRefusal(t *testing.T) {
	primary := errors.New("CURRENT classification")
	wrapped := fmt.Errorf("wrapped: %w", primary)
	for _, name := range []string{"nil-callback", "nil-result", "direct", "wrapped", "typed-nil", "validation", "F2-source"} {
		t.Run(name, func(t *testing.T) {
			c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
			if name == "validation" {
				c.in, _ = icbGenesisInputV1(t, 0)
				c.request.Raw, c.request.Endpoint = c.in.Raw, c.in.Endpoint
			}
			before := bytes.Clone(c.in.Raw)
			var want error
			alter := func(prepare replayPairPrepareCurrentV1) replayPairPrepareCurrentV1 {
				if name == "nil-callback" {
					return nil
				}
				return func(r *mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error) {
					switch name {
					case "nil-result":
						return nil, replayPairRowsV1{}, nil
					case "direct":
						want = primary
						return nil, replayPairRowsV1{}, want
					case "wrapped":
						want = wrapped
						return nil, replayPairRowsV1{}, want
					case "typed-nil":
						var typed *rpTypedError
						want = typed
						return nil, replayPairRowsV1{}, want
					}
					result, rows, err := prepare(r)
					if name == "F2-source" {
						rows.BodyKind = 0
					}
					return result, rows, err
				}
			}
			got := c.run(t, alter, c.inputs)
			logicalMDBXAssert(t, got.Err != nil && got.Truth == 1 && got.Stage == 1 && got.Index == -1 && got.Role == "CURRENT" && c.lag == 0, "CURRENT refusal must suppress every LAG stage: %+v calls%d", got, c.lag)
			if want != nil {
				logicalMDBXAssert(t, any(got.Err) == any(want), "CURRENT cause identity")
			}
			if name == "nil-callback" || name == "nil-result" || name == "F2-source" {
				var local *logicalStateFailure
				logicalMDBXAssert(t, errors.As(got.Err, &local), "typed local CURRENT refusal: %T", got.Err)
			}
			if name == "validation" {
				initial148BlockWantError(t, "composer CURRENT validation", got.Err, BLOCK_ERR_UTXO_ROOT_MISMATCH, "utxo_root mismatch")
				logicalMDBXAssert(t, c.current == 1 && c.result == nil && c.validation.attempted && any(c.validation.validationErr) == any(got.Err) && c.validation.required.derived, "actual CURRENT validator refusal reaches composer")
			}
			logicalMDBXAssert(t, bytes.Equal(c.request.Raw, before) && bytes.Equal(c.in.Raw, before), "refusal changed caller Raw")
			btState(t, c.w, 1, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
			btState(t, c.w, 2, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
			rpFollowing(t, c.w)
		})
	}
}

func rpFollowing(t *testing.T, w *btWorld) {
	t.Helper()
	var value []byte
	err := w.s.View(func(r *mdbx.Reader) error {
		v, _, readErr := r.Get(mdbx.TreeSchemaV1DBIs()[0], []byte{2})
		value = bytes.Clone(v)
		return readErr
	})
	logicalMDBXAssert(t, err == nil, "application refusal must retain usable Store: %v", err)
	m := btMutation(0, []byte{2}, value)
	m.BeforePresent = true
	w.pair(t, m)
}

// TestReplayPairLagInputs protects exact use-count/error precedence and native
// key-shape admission. Every case reaches real F3 through the composer.
func TestReplayPairLagInputs(t *testing.T) {
	for _, name := range []string{"nil", "zero", "one-nil", "one-empty", "repeat", "caller-error", "first-error", "shape", "plain-error", "wrapped-error", "typed-nil"} {
		t.Run(name, func(t *testing.T) {
			c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
			primary := errors.New("LAG input stage")
			if name == "wrapped-error" {
				primary = fmt.Errorf("wrapped LAG: %w", primary)
			}
			if name == "typed-nil" {
				var typed *rpTypedError
				primary = typed
			}
			var first error
			inputs := replayPairWithLagInputsV1(func(r *mdbx.Reader, result *initial148CompleteBlockResultV1, use func([]mdbx.TreeOutpointV1) error) error {
				c.lag++
				logicalMDBXAssert(t, r == c.store.reader && result == c.result, "same callback Reader/live result")
				switch name {
				case "zero":
					return nil
				case "plain-error", "wrapped-error", "typed-nil":
					return primary
				case "one-empty":
					return use([]mdbx.TreeOutpointV1{})
				case "shape", "first-error":
					first = use([]mdbx.TreeOutpointV1{{Txid: [32]byte{1}}})
					if name == "first-error" {
						_ = use(nil)
						return primary
					}
					return first
				}
				first = use(nil)
				if first != nil {
					return first
				}
				if name == "repeat" {
					_ = use(nil)
					return nil
				}
				if name == "caller-error" {
					return primary
				}
				return nil
			})
			if name == "nil" {
				inputs = nil
			}
			got := c.run(t, nil, inputs)
			if name == "one-nil" || name == "one-empty" {
				rpTuple(t, got, 2, 3, -1, nil, "")
				rpGenesisState(t, c, true)
				return
			}
			logicalMDBXAssert(t, got.Truth == 1 && got.Stage == 1 && got.Index == -1 && got.Role == "LAG" && got.Err != nil, "LAG input refusal exact stage/role: %+v", got)
			if name == "plain-error" || name == "wrapped-error" || name == "typed-nil" || name == "caller-error" {
				logicalMDBXAssert(t, any(got.Err) == any(primary), "LAG callback direct/wrapped/typed-nil cause identity")
			}
			if name == "first-error" || name == "shape" {
				logicalMDBXAssert(t, any(got.Err) == any(first), "first Derive error identity/priority")
			}
			if name == "caller-error" || name == "plain-error" {
				logicalMDBXAssert(t, any(got.Err) == any(primary), "plain caller error identity/no observation role")
			}
			if name == "nil" || name == "zero" || name == "repeat" {
				var local *logicalStateFailure
				logicalMDBXAssert(t, errors.As(got.Err, &local), "sticky typed LAG use-count refusal: %T", got.Err)
			}
			btState(t, c.w, 1, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
			btState(t, c.w, 2, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
			rpFollowing(t, c.w)
		})
	}
}

// TestReplayPairBoundaries supplies independent literal bounds, including the
// 32-bit maximum. Native coherent boundary corpus lives in the tagged fixture.
func TestReplayPairBoundaries(t *testing.T) {
	for _, row := range []struct{ target, bound uint64 }{{15120, 0}, {15839, 0}, {15840, 720}, {0xffffffff, 4294951920}} {
		logicalMDBXAssert(t, replayPairAppliesV1(row.target, row.bound), "pair at literal b(%d)=%d", row.target, row.bound)
		logicalMDBXAssert(t, !replayPairAppliesV1(row.target, row.bound+1), "no pair above literal b(%d)=%d", row.target, row.bound)
	}
	for _, target := range []uint64{0, 15119} {
		logicalMDBXAssert(t, !replayPairAppliesV1(target, 0) && !replayPairAppliesV1(target, 1), "below threshold never pairs: %d", target)
	}
}

// TestReplayPairPreEntry preserves raw native pre-entry outcomes without
// inventing a callback role. Existing native owner supplies cleanup semantics.
func TestReplayPairPreEntry(t *testing.T) {
	c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
	err := c.w.s.Close()
	logicalMDBXAssert(t, err == nil, "close before entry: %v", err)
	err = c.w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		got := applyReplayPairV1(&c.store, a, c.request, nil, nil)
		logicalMDBXAssert(t, got.Role == "" && got.Truth == 1 && got.Stage == 1 && got.Index == -1 && got.Err != nil && c.store.reader == nil, "pre-entry role/raw tuple: %+v", got)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "pre-entry owner cleanup: %v", err)
}

// TestReplayPairNativeShape consumes native rejection of an independent/first
// LAG primitive; composition itself always constructs CURRENT first.
func TestReplayPairNativeShape(t *testing.T) {
	c := rpNew(t, 15840, 1, mdbx.UndoTransientV1)
	c.store.inspect = func(op mdbx.TreeOperationV1) {
		op.Primitives[0].Kind = mdbx.TreeKindLagForwardV1
	}
	got := c.run(t, nil, c.inputs)
	var engine *mdbx.EngineError
	logicalMDBXAssert(t, got.Truth == 1 && got.Stage == 1 && got.Index == -1 && errors.As(got.Err, &engine) && engine.Diagnostic == "invalid Update Batch", "native refuses LAG at index0: %+v", got)
	btState(t, c.w, 1, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
	btState(t, c.w, 2, mdbx.TreeEndpointV1{}, map[Outpoint]UtxoEntry{})
}

//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

var errUndoAbort = errors.New("canonical undo test rollback")

// Independent physical literals pin fields whose production schema calls can
// change together. These helpers never call either canonical undo API/schema.
func undoLiteralManifest(hash [32]byte, height uint64, generated Uint128, txs, spends uint32) mdbx.Mutation {
	key, value := make([]byte, 33), make([]byte, 33)
	copy(key, hash[:])
	value[0] = 1
	binary.BigEndian.PutUint64(value[1:9], height)
	binary.BigEndian.PutUint64(value[9:17], generated.Hi)
	binary.BigEndian.PutUint64(value[17:25], generated.Lo)
	binary.BigEndian.PutUint32(value[25:29], txs)
	binary.BigEndian.PutUint32(value[29:33], spends)
	return mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: key, AfterKind: mdbx.AfterLiteral, Literal: value}
}

func undoLiteralKey(hash [32]byte, op Outpoint, tx, input uint32) []byte {
	key := make([]byte, 77)
	copy(key[:32], hash[:])
	key[32] = 1
	binary.BigEndian.PutUint32(key[33:37], tx)
	binary.BigEndian.PutUint32(key[37:41], input)
	copy(key[41:73], op.Txid[:])
	binary.BigEndian.PutUint32(key[73:77], op.Vout)
	return key
}

func undoLiteralTarget(op Outpoint) []byte {
	key := make([]byte, 44)
	binary.BigEndian.PutUint64(key[:8], 7)
	copy(key[8:40], op.Txid[:])
	binary.BigEndian.PutUint32(key[40:44], op.Vout)
	return key
}

func undoLocalFailure(t *testing.T, rows []mdbx.Mutation, err error, diagnostic string) {
	t.Helper()
	var failure *logicalStateFailure
	logicalMDBXAssert(t, reflect.TypeOf(err) == reflect.TypeFor[*logicalStateFailure]() && errors.As(err, &failure), "local error type: %T %v", err, err)
	logicalMDBXAssert(t, rows == nil && failure.kind == logicalStateFailureLocalInvariant && failure.cause != nil && failure.cause.Error() == diagnostic && failure.Error() == diagnostic, "local error tuple: rows=%v failure=%+v want=%q", rows, failure, diagnostic)
}

func undoDefect(t *testing.T, equal bool, err error, diagnostic string) {
	t.Helper()
	var failure *selectedSideFailure
	logicalMDBXAssert(t, reflect.TypeOf(err) == reflect.TypeFor[*selectedSideFailure]() && errors.As(err, &failure), "defect type: %T %v", err, err)
	logicalMDBXAssert(t, !equal && failure.result == "TERMINAL_STORE_INTEGRITY(canonical)" && failure.cause != nil && failure.cause.Error() == diagnostic && errors.Unwrap(failure) == failure.cause, "defect tuple: equal=%t failure=%+v want=%q", equal, failure, diagnostic)
}

func undoWantRows(t *testing.T, got, want []mdbx.Mutation, logical []mdbx.Mutation) {
	t.Helper()
	logicalMDBXAssert(t, len(got) == len(want) && cap(got) == len(want), "family count/capacity=%d/%d want=%d", len(got), cap(got), len(want))
	for i, row := range got {
		logicalMDBXAssert(t, reflect.DeepEqual(row, want[i]), "family row %d: %+v want %+v", i, row, want[i])
		if i == 0 {
			continue
		}
		found := false
		for _, target := range logical {
			if target.DBI.Rank == 1 && bytes.Equal(target.Key, row.RefKey) {
				found = true
				logicalMDBXAssert(t, &row.RefKey[0] == &target.Key[0], "reference key is a retained duplicate")
			}
		}
		logicalMDBXAssert(t, found, "reference did not name an original target")
	}
}

// Qualified cases compose the real counter/Lookup/connect/plan inside one
// original Reader callback; assertions never synthesize a successful observation.
func undoQualified(t *testing.T, input connectBlockBasicInMemorySuiteContext, pre map[Outpoint]UtxoEntry, generated Uint128, body func(*mdbx.Reader, *logicalMDBXStateView, *connectBlockInputViewResult, []mdbx.Mutation) (mdbx.Batch, error)) *mdbx.Store {
	t.Helper()
	store := logicalMDBXStore(t)
	seed, total := []mdbx.Mutation{}, uint64(0)
	for op, entry := range pre {
		seed = append(seed, logicalMDBXUTXORow(op, entry))
		total += 36 + uint64(len(logicalMDBXValue(entry)))
	}
	neighborSource := logicalMDBXUTXORow(Outpoint{Txid: hashWithPrefix(0x09), Vout: 77}, logicalMDBXEntry(0, 0x7a))
	neighborFamily := undoLiteralManifest(hashWithPrefix(0x60), 0, Uint128{}, 1, 0)
	seed = append(seed, neighborSource, neighborFamily)
	total += 36 + uint64(len(neighborSource.Literal))
	seed = append(seed, logicalMDBXCounterRow(false, total, uint64(len(pre)+1)))
	logicalMDBXSeed(t, store, seed...)
	var persisted []mdbx.Mutation
	truth, stage, err := store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
		view := newLogicalMDBXStateView(reader, 7, input.BlockHeight)
		logicalMDBXAssert(t, view.Counters().kind == logicalStateCountersPresent, "counter setup")
		result, err := inputViewQualifiedConnect(input, view, generated)
		logicalMDBXAssert(t, err == nil && result != nil, "qualified connect: %v", err)
		touched := undoTouched(result)
		plan, failure := buildLogicalStatePlan(input.BlockHeight, view, touched, newLogicalMDBXMetadata(view, nil))
		logicalMDBXAssert(t, failure == nil, "logical plan: %v", failure)
		batch, failure := logicalMDBXPlanToBatch(plan)
		logicalMDBXAssert(t, failure == nil, "logical targets: %v", failure)
		batch, err = body(reader, view, result, batch.Mutations)
		if err == nil && len(batch.Mutations) == 0 {
			return mdbx.Batch{}, errUndoAbort
		}
		for _, row := range batch.Mutations {
			value := row.Literal
			if row.AfterKind == mdbx.AfterOldValueRef {
				old, present, readErr := reader.Get(row.RefDBI, row.RefKey)
				logicalMDBXAssert(t, readErr == nil && present, "original native ref oracle: %v", readErr)
				value = old
			}
			persisted = append(persisted, mdbx.Mutation{DBI: row.DBI, Key: bytes.Clone(row.Key), Literal: bytes.Clone(value)})
		}
		return batch, err
	})
	if errors.Is(err, errUndoAbort) {
		logicalMDBXAssert(t, truth == mdbx.CommitTruthOld && stage == mdbx.UpdateStagePrewrite, "qualified rollback: %v %v %v", truth, stage, err)
		for _, row := range seed {
			undoPersisted(t, store, row.DBI, row.Key, row.Literal)
		}
	} else {
		logicalMDBXAssert(t, err == nil && truth == mdbx.CommitTruthNew, "qualified callback: %v %v %v", truth, stage, err)
		for _, row := range persisted {
			undoPersisted(t, store, row.DBI, row.Key, row.Literal)
		}
	}
	undoPersisted(t, store, neighborSource.DBI, neighborSource.Key, neighborSource.Literal)
	undoPersisted(t, store, neighborFamily.DBI, neighborFamily.Key, neighborFamily.Literal)
	return store
}

func undoTouched(result *connectBlockInputViewResult) []logicalTouchedState {
	touched := make([]logicalTouchedState, 0, len(result.spentInputs.spent)+len(result.createdUtxos))
	for op, length := range result.spentInputs.spent {
		if length > 0 {
			touched = append(touched, logicalTouchedState{Outpoint: op})
		}
	}
	for op, entry := range result.createdUtxos {
		touched = append(touched, logicalTouchedState{Outpoint: op, FinalPresent: true, Final: entry})
	}
	slices.SortFunc(touched, func(a, b logicalTouchedState) int {
		return cmp.Or(bytes.Compare(a.Outpoint.Txid[:], b.Outpoint.Txid[:]), cmp.Compare(a.Outpoint.Vout, b.Outpoint.Vout))
	})
	return touched
}

func undoNetworkInput(t *testing.T, count int, created bool) (connectBlockBasicInMemorySuiteContext, map[Outpoint]UtxoEntry, []Outpoint) {
	t.Helper()
	kp := mustMLDSA87Keypair(t)
	pre := map[Outpoint]UtxoEntry{}
	ops := make([]Outpoint, count)
	for i := range ops {
		ops[i] = Outpoint{Txid: hashWithPrefix(byte(0xf0 - i)), Vout: uint32(9 - i)}
		pre[ops[i]] = UtxoEntry{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}
	}
	var txs []*Tx
	if count > 0 {
		first := inputViewSignedTx(t, 1, pre, kp, ops[:min(2, count)]...)
		txs = append(txs, first)
		if created {
			op := Outpoint{Txid: testTxID(t, txBytesFromTx(t, first))}
			rows := map[Outpoint]UtxoEntry{op: {Value: first.Outputs[0].Value, CovenantType: COV_TYPE_P2PK, CovenantData: first.Outputs[0].CovenantData, CreationHeight: 2}}
			txs = append(txs, inputViewSignedTx(t, 2, rows, kp, op))
		}
		if count > 2 {
			txs = append(txs, inputViewSignedTx(t, uint64(len(txs)+1), pre, kp, ops[2:]...))
		}
	}
	return inputViewBlock(t, 2, 1, txs...), pre, ops
}

func undoExpected(hash [32]byte, height uint64, generated Uint128, txs uint32, ops []Outpoint) []mdbx.Mutation {
	rows := []mdbx.Mutation{undoLiteralManifest(hash, height, generated, txs, uint32(len(ops)))}
	for i, op := range ops {
		tx, input := uint32(1), uint32(i)
		if i >= 2 {
			tx, input = 2, uint32(i-2)
		}
		rows = append(rows, mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: undoLiteralKey(hash, op, tx, input), AfterKind: mdbx.AfterOldValueRef, RefDBI: logicalMDBXDBIs[1], RefKey: undoLiteralTarget(op)})
	}
	return rows
}

func undoImmutableCall(t *testing.T, input connectBlockBasicInMemorySuiteContext, view *logicalMDBXStateView, source *blockSpentInputSource, logical []mdbx.Mutation, hash *[32]byte, generated *Uint128, call func() ([]mdbx.Mutation, error)) ([]mdbx.Mutation, error) {
	t.Helper()
	raw, targets := bytes.Clone(input.BlockBytes), logicalMDBXSnapshot(logical)
	controls := slices.Clone(logical)
	observed := maps.Clone(view.rows)
	var originalHash [32]byte
	var originalSupply Uint128
	if hash != nil {
		originalHash = *hash
	}
	if generated != nil {
		originalSupply = *generated
	}
	rows, err := call()
	logicalMDBXAssert(t, bytes.Equal(input.BlockBytes, raw) && reflect.DeepEqual(logicalMDBXSnapshot(logical), targets) && reflect.DeepEqual(logical, controls) && reflect.DeepEqual(view.rows, observed), "producer changed original input owner")
	logicalMDBXAssert(t, hash == nil || *hash == originalHash, "producer changed original hash")
	logicalMDBXAssert(t, generated == nil || *generated == originalSupply, "producer changed supplied pre-block supply")
	if source != nil {
		assertInputViewSourceReleased(t, source)
	}
	return rows, err
}

func TestCanonicalUndoFamilyV1(t *testing.T) {
	t.Run("A01Genesis", func(t *testing.T) {
		hash, generated := hashWithPrefix(0x51), Uint128{}
		rows, err := canonicalUndoFamilyV1(7, 0, 1, &hash, &generated, nil, nil, nil)
		logicalMDBXAssert(t, err == nil, "genesis: %v", err)
		want := []mdbx.Mutation{undoLiteralManifest(hash, 0, generated, 1, 0)}
		undoWantRows(t, rows, want, nil)
		logicalMDBXAssert(t, bytes.Equal(rows[0].Literal, mdbx.UndoManifestValue(0, [16]byte{}, 1, 0)) && bytes.Equal(rows[0].Key, mdbx.UndoManifestKey(hash)), "existing genesis schema differs")
	})
	t.Run("A02CoinbaseOnly", undoTestCoinbase)
	t.Run("A03OneSpend", undoTestOneSpend)
	t.Run("A04CanonicalOrder", undoTestOrder)
	t.Run("A05CreatedThenSpent", undoTestCreated)
	t.Run("A06OverwrittenTarget", undoTestOverwritten)
	undoRejected(t)
}

func undoTestCoinbase(t *testing.T) {
	for _, height := range []uint64{1, 0xffffffff} {
		input := inputViewBlock(t, height, 1)
		hash, generated := hashWithPrefix(0x52), Uint128{}
		undoQualified(t, input, nil, generated, func(_ *mdbx.Reader, view *logicalMDBXStateView, result *connectBlockInputViewResult, logical []mdbx.Mutation) (mdbx.Batch, error) {
			logicalMDBXAssert(t, &result.spentInputs.raw[0] == &input.BlockBytes[0], "source copied B")
			rows, err := undoImmutableCall(t, input, view, result.spentInputs, logical, &hash, &generated, func() ([]mdbx.Mutation, error) {
				return canonicalUndoFamilyV1(7, height, 1, &hash, &generated, logical, view.rows, result.spentInputs)
			})
			logicalMDBXAssert(t, err == nil, "coinbase: %v", err)
			undoWantRows(t, rows, []mdbx.Mutation{undoLiteralManifest(hash, height, generated, 1, 0)}, logical)
			return mdbx.Batch{Mutations: append(logical, rows...)}, nil
		})
	}
}

func undoTestOneSpend(t *testing.T) {
	input, pre, ops := undoNetworkInput(t, 1, false)
	hash, generated := hashWithPrefix(0x53), Uint128{Lo: 12345}
	store := undoQualified(t, input, pre, generated, func(reader *mdbx.Reader, view *logicalMDBXStateView, result *connectBlockInputViewResult, logical []mdbx.Mutation) (mdbx.Batch, error) {
		rows, err := undoImmutableCall(t, input, view, result.spentInputs, logical, &hash, &generated, func() ([]mdbx.Mutation, error) {
			return canonicalUndoFamilyV1(7, 2, 2, &hash, &generated, logical, view.rows, result.spentInputs)
		})
		logicalMDBXAssert(t, err == nil, "one spend: %v", err)
		undoWantRows(t, rows, undoExpected(hash, 2, generated, 2, ops), logical)
		equal, err := canonicalUndoFamilyEqualV1(reader, &hash, rows)
		logicalMDBXAssert(t, !equal && err == nil, "new family existed in protected OLD")
		return mdbx.Batch{Mutations: append(logical, rows...)}, nil
	})
	undoPersisted(t, store, logicalMDBXDBIs[5], undoLiteralKey(hash, ops[0], 1, 0), logicalMDBXValue(pre[ops[0]]))
	undoPersisted(t, store, logicalMDBXDBIs[1], undoLiteralTarget(ops[0]), nil)
}

func undoTestOrder(t *testing.T) {
	input, pre, ops := undoNetworkInput(t, 3, false)
	hash, generated := hashWithPrefix(0x54), Uint128{Lo: 0x0102030405060708}
	var first [][]byte
	for _, order := range [][]int{{0, 1, 2}, {2, 0, 1}} {
		undoQualified(t, input, pre, generated, func(_ *mdbx.Reader, view *logicalMDBXStateView, result *connectBlockInputViewResult, logical []mdbx.Mutation) (mdbx.Batch, error) {
			// Change insertion order only; keep the very same source map owner.
			for _, op := range ops {
				delete(result.spentInputs.spent, op)
			}
			for _, i := range order {
				result.spentInputs.spent[ops[i]] = 89
			}
			rows, err := undoImmutableCall(t, input, view, result.spentInputs, logical, &hash, &generated, func() ([]mdbx.Mutation, error) {
				return canonicalUndoFamilyV1(7, 2, 3, &hash, &generated, logical, view.rows, result.spentInputs)
			})
			logicalMDBXAssert(t, err == nil, "ordered source: %v", err)
			undoWantRows(t, rows, undoExpected(hash, 2, generated, 3, ops), logical)
			if first != nil {
				logicalMDBXAssert(t, reflect.DeepEqual(first, logicalMDBXSnapshot(rows)), "map insertion changed canonical family")
			}
			first = logicalMDBXSnapshot(rows)
			return mdbx.Batch{Mutations: append(logical, rows...)}, nil
		})
	}
}

func undoTestCreated(t *testing.T) {
	input, pre, ops := undoNetworkInput(t, 1, true)
	hash, generated := hashWithPrefix(0x55), Uint128{}
	store := undoQualified(t, input, pre, generated, func(_ *mdbx.Reader, view *logicalMDBXStateView, result *connectBlockInputViewResult, logical []mdbx.Mutation) (mdbx.Batch, error) {
		logicalMDBXAssert(t, len(result.spentInputs.spent) == 2, "created tombstone not supplied by connector")
		rows, err := undoImmutableCall(t, input, view, result.spentInputs, logical, &hash, &generated, func() ([]mdbx.Mutation, error) {
			return canonicalUndoFamilyV1(7, 2, 3, &hash, &generated, logical, view.rows, result.spentInputs)
		})
		logicalMDBXAssert(t, err == nil, "created-spent: %v", err)
		undoWantRows(t, rows, undoExpected(hash, 2, generated, 3, ops), logical)
		return mdbx.Batch{Mutations: append(logical, rows...)}, nil
	})
	parsed, err := ParseBlockBytes(input.BlockBytes)
	logicalMDBXAssert(t, err == nil, "created-spent input oracle: %v", err)
	spent := parsed.Txs[2].Inputs[0]
	created := Outpoint{Txid: spent.PrevTxid, Vout: spent.PrevVout}
	undoPersisted(t, store, logicalMDBXDBIs[5], undoLiteralKey(hash, created, 2, 0), nil)
	undoPersisted(t, store, logicalMDBXDBIs[1], undoLiteralTarget(created), nil)
}

func undoTestOverwritten(t *testing.T) {
	input, pre, ops := undoNetworkInput(t, 1, false)
	hash, generated := hashWithPrefix(0x56), Uint128{Hi: 0x0102030405060708, Lo: 0x1112131415161718}
	replacementEntry := logicalMDBXEntry(2, 0x71)
	replacement := logicalMDBXValue(replacementEntry)
	store := undoQualified(t, input, pre, generated, func(_ *mdbx.Reader, view *logicalMDBXStateView, result *connectBlockInputViewResult, _ []mdbx.Mutation) (mdbx.Batch, error) {
		touched := undoTouched(result)
		for i := range touched {
			if touched[i].Outpoint == ops[0] {
				touched[i].FinalPresent, touched[i].Final = true, replacementEntry
			}
		}
		plan, failure := buildLogicalStatePlan(2, view, touched, newLogicalMDBXMetadata(view, nil))
		logicalMDBXAssert(t, failure == nil, "coalesced target plan: %v", failure)
		batch, failure := logicalMDBXPlanToBatch(plan)
		logicalMDBXAssert(t, failure == nil, "coalesced target conversion: %v", failure)
		logical := batch.Mutations
		rows, err := undoImmutableCall(t, input, view, result.spentInputs, logical, &hash, &generated, func() ([]mdbx.Mutation, error) {
			return canonicalUndoFamilyV1(7, 2, 2, &hash, &generated, logical, view.rows, result.spentInputs)
		})
		logicalMDBXAssert(t, err == nil, "overwritten: %v", err)
		undoWantRows(t, rows, undoExpected(hash, 2, generated, 2, ops), logical)
		return mdbx.Batch{Mutations: append(logical, rows...)}, nil
	})
	undoPersisted(t, store, logicalMDBXDBIs[5], undoLiteralKey(hash, ops[0], 1, 0), logicalMDBXValue(pre[ops[0]]))
	undoPersisted(t, store, logicalMDBXDBIs[1], undoLiteralTarget(ops[0]), replacement)
}

func undoPersisted(t *testing.T, store *mdbx.Store, dbi mdbx.DBI, key, want []byte) {
	t.Helper()
	err := store.View(func(reader *mdbx.Reader) error {
		got, present, err := reader.Get(dbi, key)
		logicalMDBXAssert(t, err == nil && present == (want != nil) && bytes.Equal(got, want), "persisted row rank=%d key=%x present=%t value=%x want=%x err=%v", dbi.Rank, key, present, got, want, err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "persisted view: %v", err)
}

func undoRejected(t *testing.T) {
	input, pre, ops := undoNetworkInput(t, 1, false)
	for _, name := range []string{"R01GenerationZero", "R02HeightWidth", "R04SourceCount", "R06MissingSource", "R07ShortLogical", "R08LongLogical", "R10DifferentLength", "R12AbsentBefore", "R13WrongAfter", "R14UnemittedPositive"} {
		t.Run(name, func(t *testing.T) { undoRejectCell(t, input, pre, ops[0], name, "") })
	}
	t.Run("R05PartialSource", func(t *testing.T) {
		for _, cell := range []string{"Advanced", "RawNil", "NextTx", "Current", "InputIndex", "TxIndex"} {
			t.Run(cell, func(t *testing.T) { undoRejectCell(t, input, pre, ops[0], "R05PartialSource", cell) })
		}
	})
	t.Run("R09MissingObservation", func(t *testing.T) {
		for _, cell := range []string{"Missing", "Nonpresent"} {
			t.Run(cell, func(t *testing.T) { undoRejectCell(t, input, pre, ops[0], "R09MissingObservation", cell) })
		}
	})
	t.Run("R03InitialPayload", func(t *testing.T) {
		for _, cell := range []string{"TxZero", "TxWidth", "NilHash", "NilGenerated", "GenesisSupply", "GenesisSource", "GenesisTxTwo"} {
			t.Run(cell, func(t *testing.T) { undoRejectCell(t, input, pre, ops[0], "R03InitialPayload", cell) })
		}
	})
	t.Run("R11MissingTarget", func(t *testing.T) {
		for _, cell := range []string{"Missing", "Generation", "Rank"} {
			t.Run(cell, func(t *testing.T) { undoRejectCell(t, input, pre, ops[0], "R11MissingTarget", cell) })
		}
	})
}

func undoRejectCell(t *testing.T, input connectBlockBasicInMemorySuiteContext, pre map[Outpoint]UtxoEntry, op Outpoint, name, cell string) {
	t.Helper()
	undoQualified(t, input, pre, Uint128{}, func(_ *mdbx.Reader, view *logicalMDBXStateView, result *connectBlockInputViewResult, logical []mdbx.Mutation) (mdbx.Batch, error) {
		generation, height, txs := uint64(7), uint64(2), uint64(2)
		hash, generated := hashWithPrefix(0x57), Uint128{}
		hashArg, generatedArg, source := &hash, &generated, result.spentInputs
		diagnostic := undoRejectInputs(name, cell, op, &generation, &height, &txs, &hashArg, &generatedArg, &source, view, logical)
		if name == "R11MissingTarget" {
			logical = undoRejectTarget(cell, logical, op)
		}
		rows, err := undoImmutableCall(t, input, view, result.spentInputs, logical, hashArg, generatedArg, func() ([]mdbx.Mutation, error) {
			return canonicalUndoFamilyV1(generation, height, txs, hashArg, generatedArg, logical, view.rows, source)
		})
		undoLocalFailure(t, rows, err, diagnostic)
		return mdbx.Batch{}, nil
	})
}

func undoRejectInputs(name, cell string, op Outpoint, generation, height, txs *uint64, hash **[32]byte, generated **Uint128, source **blockSpentInputSource, view *logicalMDBXStateView, logical []mdbx.Mutation) string {
	diagnostic := "invalid canonical undo input"
	switch name {
	case "R01GenerationZero":
		*generation = 0
	case "R02HeightWidth":
		*height = 0x100000000
	case "R03InitialPayload":
		undoRejectPayload(cell, height, txs, hash, generated, source)
	case "R04SourceCount":
		(*source).count++
	case "R05PartialSource":
		undoPartialSource(cell, *source)
	case "R06MissingSource":
		(*source).discard()
		*source = nil
	default:
		diagnostic = undoRejectRows(name, op, *source, view, logical)
		if name == "R09MissingObservation" && cell == "Nonpresent" {
			view.rows[op] = logicalMDBXRowObservation{entryBytes: 89}
		}
	}
	return diagnostic
}

func undoPartialSource(cell string, source *blockSpentInputSource) {
	switch cell {
	case "Advanced":
		_, _ = source.next()
	case "RawNil":
		source.raw = nil
	case "NextTx":
		source.nextTx = 2
	case "Current":
		source.current = &Tx{}
	case "InputIndex":
		source.inputIndex = 1
	case "TxIndex":
		source.txIndex = 1
	}
}

func undoRejectPayload(cell string, height, txs *uint64, hash **[32]byte, generated **Uint128, source **blockSpentInputSource) {
	switch cell {
	case "TxZero":
		*txs = 0
	case "TxWidth":
		*txs = 0x100000000
	case "NilHash":
		*hash = nil
	case "NilGenerated":
		*generated = nil
	case "GenesisSupply":
		*height, *txs = 0, 1
		(*generated).Lo = 1
		(*source).discard()
		*source = nil
	case "GenesisSource":
		*height, *txs = 0, 1
	case "GenesisTxTwo":
		*height = 0
		(*source).discard()
		*source = nil
	}
}

func undoRejectRows(name string, op Outpoint, source *blockSpentInputSource, view *logicalMDBXStateView, logical []mdbx.Mutation) string {
	switch name {
	case "R07ShortLogical":
		source.spent[op] = 55
		return "undo logical length outside domain"
	case "R08LongLogical":
		source.spent[op] = 65597
		return "undo logical length outside domain"
	case "R09MissingObservation":
		delete(view.rows, op)
		return "undo source length differs from observed target"
	case "R10DifferentLength":
		row := view.rows[op]
		row.entryBytes++
		view.rows[op] = row
		return "undo source length differs from observed target"
	case "R14UnemittedPositive":
		source.spent[Outpoint{Txid: hashWithPrefix(0x01)}] = 89
		return "undo source count differs"
	default:
		for i := range logical {
			if logical[i].DBI.Rank == 1 && bytes.Equal(logical[i].Key, undoLiteralTarget(op)) {
				if name == "R12AbsentBefore" {
					logical[i].BeforePresent = false
				}
				if name == "R13WrongAfter" {
					logical[i].AfterKind = mdbx.AfterOldValueRef
				}
			}
		}
		return "undo source is not a removed target row"
	}
}

func undoRejectTarget(cell string, logical []mdbx.Mutation, op Outpoint) []mdbx.Mutation {
	for i := range logical {
		if logical[i].DBI.Rank != 1 || !bytes.Equal(logical[i].Key, undoLiteralTarget(op)) {
			continue
		}
		switch cell {
		case "Missing":
			logical = slices.Delete(logical, i, i+1)
		case "Generation":
			logical[i].Key = bytes.Clone(logical[i].Key)
			logical[i].Key[7] = 8
		case "Rank":
			logical[i].DBI = logicalMDBXDBIs[2]
		}
		break
	}
	slices.SortFunc(logical, func(a, b mdbx.Mutation) int {
		return cmp.Or(cmp.Compare(a.DBI.Rank, b.DBI.Rank), bytes.Compare(a.Key, b.Key))
	})
	return logical
}

// Engineering families use real physical UTXO/UNDO rows, including >Consulted
// cardinality; they assert bytes and lifetimes without a block-validity claim.
func undoPhysical(t *testing.T, count, width int) (*mdbx.Store, [32]byte, []mdbx.Mutation, []mdbx.Mutation) {
	t.Helper()
	store := logicalMDBXStore(t)
	hash, expected, physical, source := undoPhysicalRows(count, width)
	// Each bounded native batch stays below 16384; the traversed family is whole.
	for start := 0; start < len(source); start += 8000 {
		logicalMDBXSeed(t, store, source[start:min(start+8000, len(source))]...)
	}
	logicalMDBXSeed(t, store, undoLiteralManifest(hashWithPrefix(0x62), 1, Uint128{}, 1, 0))
	return store, hash, expected, physical
}

func undoPhysicalRows(count, width int) ([32]byte, []mdbx.Mutation, []mdbx.Mutation, []mdbx.Mutation) {
	hash := hashWithPrefix(0x61)
	ops, source := make([]Outpoint, count), make([]mdbx.Mutation, count)
	for i := range ops {
		ops[i] = Outpoint{Txid: hashWithPrefix(0x81), Vout: uint32(i)}
		entry := logicalMDBXEntry(0, byte(i%127+1))
		if width == 65560 {
			entry = logicalMDBXEntry(65536, byte(i%127+1))
		}
		if width == 21 {
			entry = logicalMDBXEntry(1, byte(i%127+1))
		}
		source[i] = logicalMDBXUTXORow(ops[i], entry)
	}
	expected := []mdbx.Mutation{undoLiteralManifest(hash, 9, Uint128{Lo: 37}, uint32(max(2, (count+1023)/1024+1)), uint32(count))}
	physical := []mdbx.Mutation{expected[0]}
	for i, op := range ops {
		key := undoLiteralKey(hash, op, uint32(i/1024+1), uint32(i%1024))
		expected = append(expected, mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: key, AfterKind: mdbx.AfterOldValueRef, RefDBI: source[i].DBI, RefKey: source[i].Key})
		physical = append(physical, mdbx.Mutation{DBI: logicalMDBXDBIs[5], Key: bytes.Clone(key), AfterKind: mdbx.AfterLiteral, Literal: bytes.Clone(source[i].Literal)})
	}
	return hash, expected, physical, source
}

func undoSeedFamily(t *testing.T, store *mdbx.Store, rows []mdbx.Mutation) {
	t.Helper()
	for start := 0; start < len(rows); start += 8000 {
		undoSeedFamilyChunk(t, store, rows[start:min(start+8000, len(rows))])
	}
}

// Ordinary native Update admits entry refs, not entry literals. Seed the wanted
// physical bytes through real OLD refs, restoring each actual source in that
// same native commit. Caller physical literals remain independent byte oracles.
func undoSeedFamilyChunk(t *testing.T, store *mdbx.Store, rows []mdbx.Mutation) {
	t.Helper()
	targets := make([]mdbx.Mutation, 0, len(rows))
	for _, row := range rows {
		if len(row.Key) == 77 {
			op := Outpoint{Txid: [32]byte(row.Key[41:73]), Vout: binary.BigEndian.Uint32(row.Key[73:77])}
			targets = append(targets, mdbx.Mutation{DBI: logicalMDBXDBIs[1], Key: undoLiteralTarget(op), AfterKind: mdbx.AfterLiteral, Literal: row.Literal})
		}
	}
	slices.SortFunc(targets, func(a, b mdbx.Mutation) int { return bytes.Compare(a.Key, b.Key) })
	targets = slices.CompactFunc(targets, func(a, b mdbx.Mutation) bool {
		if !bytes.Equal(a.Key, b.Key) {
			return false
		}
		logicalMDBXAssert(t, bytes.Equal(a.Literal, b.Literal), "same source seeded with competing physical values")
		return true
	})
	restore := make([]mdbx.Mutation, len(targets))
	err := store.View(func(reader *mdbx.Reader) error {
		for i, target := range targets {
			old, present, err := reader.Get(target.DBI, target.Key)
			logicalMDBXAssert(t, err == nil, "physical source before seed: %v", err)
			targets[i].BeforePresent = present
			restore[i] = mdbx.Mutation{DBI: target.DBI, Key: target.Key, BeforePresent: true, AfterKind: mdbx.AfterAbsent}
			if present {
				restore[i].AfterKind, restore[i].Literal = mdbx.AfterLiteral, old
			}
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "physical source snapshot: %v", err)
	if len(targets) > 0 {
		logicalMDBXSeed(t, store, targets...)
	}
	batch := append([]mdbx.Mutation(nil), restore...)
	for _, row := range rows {
		if len(row.Key) == 77 {
			op := Outpoint{Txid: [32]byte(row.Key[41:73]), Vout: binary.BigEndian.Uint32(row.Key[73:77])}
			row.AfterKind, row.Literal, row.RefDBI, row.RefKey = mdbx.AfterOldValueRef, nil, logicalMDBXDBIs[1], undoLiteralTarget(op)
		}
		batch = append(batch, row)
	}
	logicalMDBXSeed(t, store, batch...)
}

func undoCompare(t *testing.T, store *mdbx.Store, hash [32]byte, expected []mdbx.Mutation) (equal bool, cause error) {
	t.Helper()
	before, controls := logicalMDBXSnapshot(expected), slices.Clone(expected)
	originalHash := hash
	err := store.View(func(reader *mdbx.Reader) error {
		equal, cause = canonicalUndoFamilyEqualV1(reader, &hash, expected)
		return cause
	})
	sameError := err == nil && cause == nil
	if err != nil && cause != nil {
		sameError = reflect.ValueOf(err).Equal(reflect.ValueOf(cause))
	}
	logicalMDBXAssert(t, sameError && hash == originalHash && reflect.DeepEqual(before, logicalMDBXSnapshot(expected)) && reflect.DeepEqual(controls, expected), "comparator replaced cause or changed original expected bytes")
	return equal, cause
}

func undoPhysicalPreserved(t *testing.T, store *mdbx.Store, expected, physical []mdbx.Mutation) {
	t.Helper()
	err := store.View(func(reader *mdbx.Reader) error {
		for i, row := range physical {
			got, present, err := reader.Get(row.DBI, row.Key)
			logicalMDBXAssert(t, err == nil && present && bytes.Equal(got, row.Literal), "protected family member %d changed: %v", i, err)
			if i == 0 {
				continue
			}
			ref := expected[i]
			got, present, err = reader.Get(ref.RefDBI, ref.RefKey)
			logicalMDBXAssert(t, err == nil && present && bytes.Equal(got, row.Literal), "protected source member %d changed: %v", i, err)
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "complete physical readback: %v", err)
	neighbor := undoLiteralManifest(hashWithPrefix(0x62), 1, Uint128{}, 1, 0)
	undoPersisted(t, store, neighbor.DBI, neighbor.Key, neighbor.Literal)
}

func TestCanonicalUndoFamilyEqualV1(t *testing.T) {
	for _, row := range []struct {
		name         string
		count, width int
	}{{"A07ManifestEqual", 0, 20}, {"A08CompleteEqual", 3, 20}, {"A09MinPhysical", 1, 20}, {"A10MaxPhysical", 1, 65560}, {"A12OverConsultedCount", 16385, 20}} {
		t.Run(row.name, func(t *testing.T) {
			store, hash, expected, physical := undoPhysical(t, row.count, row.width)
			undoSeedFamily(t, store, physical)
			equal, err := undoCompare(t, store, hash, expected)
			logicalMDBXAssert(t, equal && err == nil, "complete family count=%d width=%d: %t %v", row.count, row.width, equal, err)
			undoPhysicalPreserved(t, store, expected, physical)
			if row.count == 0 {
				changed := physical[0]
				changed.Literal = bytes.Clone(changed.Literal)
				changed.Literal[32] ^= 1
				logicalMDBXSeed(t, store, mdbx.Mutation{DBI: changed.DBI, Key: changed.Key, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
				logicalMDBXSeed(t, store, changed)
				equal, err = undoCompare(t, store, hash, expected)
				undoDefect(t, equal, err, "undo value differs")
				undoPersisted(t, store, changed.DBI, changed.Key, changed.Literal)
			}
		})
	}
	t.Run("A11AbsentFamily", func(t *testing.T) {
		store, hash, expected, physical := undoPhysical(t, 1, 20)
		neighbor := hash
		neighbor[0]++
		other := undoLiteralManifest(neighbor, 1, Uint128{}, 1, 0)
		equal, err := undoCompare(t, store, hash, expected)
		logicalMDBXAssert(t, !equal && err == nil, "absent family: %t %v", equal, err)
		undoPersisted(t, store, other.DBI, other.Key, other.Literal)
		undoPersisted(t, store, expected[1].RefDBI, expected[1].RefKey, physical[1].Literal)
	})
	for _, name := range []string{"H01MissingManifest", "H02MissingTail", "H03ExtraMember", "H04WrongCoordinate", "H05FirstByte", "H06LastByte", "H07DifferentWidth", "H08MissingRefSource"} {
		t.Run(name, func(t *testing.T) { undoCompareDefect(t, name) })
	}
}

func undoCompareDefect(t *testing.T, name string) {
	t.Helper()
	width := 20
	if name == "H06LastByte" {
		width = 65560
	}
	store, hash, expected, physical := undoPhysical(t, 2, width)
	originalSources := logicalMDBXSnapshot(physical)
	diagnostic := undoDamageFamily(name, &physical)
	undoSeedFamily(t, store, physical)
	if name == "H08MissingRefSource" {
		logicalMDBXSeed(t, store, mdbx.Mutation{DBI: expected[1].RefDBI, Key: expected[1].RefKey, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	}
	image := logicalMDBXSnapshot(physical)
	equal, err := undoCompare(t, store, hash, expected)
	undoDefect(t, equal, err, diagnostic)
	logicalMDBXAssert(t, reflect.DeepEqual(image, logicalMDBXSnapshot(physical)), "comparator modified physical oracle")
	for _, row := range physical {
		undoPersisted(t, store, row.DBI, row.Key, row.Literal)
	}
	if name == "H08MissingRefSource" {
		undoPersisted(t, store, expected[1].RefDBI, expected[1].RefKey, nil)
	}
	for i, row := range expected[1:] {
		if name != "H08MissingRefSource" || i != 0 {
			undoPersisted(t, store, row.RefDBI, row.RefKey, originalSources[3*(i+1)+1])
		}
	}
	neighbor := undoLiteralManifest(hashWithPrefix(0x62), 1, Uint128{}, 1, 0)
	undoPersisted(t, store, neighbor.DBI, neighbor.Key, neighbor.Literal)
	switch name {
	case "H01MissingManifest":
		undoPersisted(t, store, expected[0].DBI, expected[0].Key, nil)
	case "H02MissingTail":
		undoPersisted(t, store, expected[2].DBI, expected[2].Key, nil)
	case "H04WrongCoordinate":
		undoPersisted(t, store, expected[1].DBI, expected[1].Key, nil)
	}
}

func undoDamageFamily(name string, physical *[]mdbx.Mutation) string {
	rows := *physical
	diagnostic := "undo family has an unexpected member"
	switch name {
	case "H01MissingManifest":
		*physical = rows[1:]
	case "H02MissingTail":
		*physical = rows[:2]
		return "undo family is incomplete"
	case "H03ExtraMember":
		extra := rows[len(rows)-1]
		extra.Key, extra.Literal = bytes.Clone(extra.Key), bytes.Clone(extra.Literal)
		binary.BigEndian.PutUint32(extra.Key[37:41], 2)
		*physical = append(rows, extra)
	case "H04WrongCoordinate":
		rows[1].Key[36] = 2
	case "H05FirstByte":
		rows[1].Literal[0] ^= 1
		return "undo value differs"
	case "H06LastByte":
		rows[1].Literal[len(rows[1].Literal)-1] ^= 1
		return "undo value differs"
	case "H07DifferentWidth":
		rows[1].Literal = logicalMDBXValue(logicalMDBXEntry(1, 1))
		return "undo value length differs"
	case "H08MissingRefSource":
		return "undo source absent"
	}
	return diagnostic
}

//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func fgContext(t *testing.T, raw []byte) PublishedGenesisContextV1 {
	t.Helper()
	hash, err := Initial148BlockHash(raw[:148])
	logicalMDBXAssert(t, err == nil, "fixture header: %v", err)
	return PublishedGenesisContextV1{ChainID: sha3.Sum256(append([]byte("RUBIN-GENESIS-v1"), raw...)), GenesisHash: hash, Published: raw}
}

func fgTuple(t *testing.T, out Initial148FirstGenesisOutcomeV1, result string, truth mdbx.CommitTruth, stage mdbx.UpdateStage) {
	t.Helper()
	logicalMDBXAssert(t, out.Result == result && out.Truth == truth && out.Stage == stage, "first genesis tuple: %+v, want %s/%d/%d", out, result, truth, stage)
	logicalMDBXAssert(t, (out.Err == nil) == (result == "ACCEPTED"), "first genesis cause: %T %v", out.Err, out.Err)
}

// G5/G7 guard cases are each a single malformed dimension; the borrowed input
// snapshots and a closed Store distinguish a pure refusal from a native read.
func TestInitial148FirstGenesisInputOrder(t *testing.T) {
	for _, name := range []string{"nil-store", "nil-published", "short-published", "old-width", "zero-chain", "zero-hash", "candidate", "owner", "zero-owner", "hash", "chain", "root", "header", "body", "framing", "old-identity", "zero-database", "zero-generation", "both-zero", "candidate-before-owner", "owner-before-commitment", "commitment-before-context"} {
		t.Run(name, func(t *testing.T) {
			w := btNew(t)
			logicalMDBXAssert(t, w.s.Close() == nil, "close pure-guard Store")
			raw := initial148BlockGenesis(t)
			g := fgContext(t, raw)
			candidate, published := bytes.Clone(raw), bytes.Clone(raw)
			store, owner, database, generation := w.s, w.owner, [32]byte{7}, uint64(1)
			want, message := "TERMINAL_LOCAL_INVARIANT(evidence)", "invalid published genesis context"
			switch name {
			case "nil-store":
				store, message = nil, "nil genesis Store"
			case "nil-published":
				published = nil
			case "short-published":
				published = published[:297]
			case "old-width":
				published = append(bytes.Clone(raw[:108]), raw[140:]...)
			case "zero-chain":
				g.ChainID = [32]byte{}
			case "zero-hash":
				g.GenesisHash = [32]byte{}
			case "candidate", "candidate-before-owner":
				candidate[200] ^= 1
				want, message = "CONSENSUS_INVALID", "block does not match published genesis"
				if name == "candidate-before-owner" {
					owner = nil
				}
			case "owner":
				owner, message = nil, "invalid genesis reservation owner"
			case "zero-owner":
				owner, message = &mdbx.OperationReservationOwner{}, "invalid genesis reservation owner"
			case "hash":
				g.GenesisHash[0] ^= 1
				message = "published genesis context commitment mismatch"
			case "chain":
				g.ChainID[0] ^= 1
				message = "published genesis context commitment mismatch"
			case "root", "header", "body", "framing":
				offset := map[string]int{"root": 108, "header": 140, "body": 200, "framing": 148}[name]
				published[offset] ^= 1
				candidate = bytes.Clone(published)
				message = "published genesis context commitment mismatch"
			case "old-identity":
				g.ChainID, _ = parseHex32("88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103")
				g.GenesisHash, _ = parseHex32("8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff")
				message = "published genesis context commitment mismatch"
			case "zero-database":
				database, message = [32]byte{}, "invalid first genesis expected context"
			case "zero-generation":
				generation, message = 0, "invalid first genesis expected context"
			case "both-zero":
				database, generation, message = [32]byte{}, 0, "invalid first genesis expected context"
			case "owner-before-commitment":
				owner, message = nil, "invalid genesis reservation owner"
				g.GenesisHash[0] ^= 1
			case "commitment-before-context":
				database, message = [32]byte{}, "published genesis context commitment mismatch"
				g.GenesisHash[0] ^= 1
			}
			beforeRaw, beforePublished := bytes.Clone(candidate), bytes.Clone(published)
			out := ConnectPublishedInitial148GenesisMDBX(store, owner, candidate, published, g.ChainID, g.GenesisHash, database, generation)
			fgTuple(t, out, want, 1, 1)
			var tx *TxError
			if want == "CONSENSUS_INVALID" {
				logicalMDBXAssert(t, errors.As(out.Err, &tx) && tx.Code == BLOCK_ERR_LINKAGE_INVALID && tx.Msg == message, "candidate precedence: %v", out.Err)
			} else {
				logicalMDBXAssert(t, out.Err.Error() == message, "guard %s: %v, want %s", name, out.Err, message)
			}
			logicalMDBXAssert(t, bytes.Equal(candidate, beforeRaw) && bytes.Equal(published, beforePublished), "guard mutated caller bytes")
			btReservationsReleased(t, w.owner)
		})
	}
}

// G10 preserves both rejection owners; the direct/transient control is supplied
// with exactly the same otherwise valid recipe at each tested height.
func TestInitial148FirstGenesisRecipeGate(t *testing.T) {
	for _, height := range []uint64{0, 1, 19, 4294967295} {
		w := btNew(t)
		request := irRequestV1(height, 13)
		parent := mdbx.TreeEndpointV1{}
		if height != 0 {
			parent = mdbx.TreeEndpointV1{Kind: 1, Height: height - 1, BlockHash: [32]byte{3}, CumulativeChainwork: [40]byte{39: 1}}
		}
		icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
			logicalMDBXAssert(t, w.s.View(func(reader *mdbx.Reader) error {
				captured := irPrepareV1(t, reader, account, request, parent)
				logicalMDBXAssert(t, initial148RequiredShapeV1(captured), "direct/transient recipe h%d", height)
				before := captured.Primitive
				logicalMDBXAssert(t, reader.CheckTreeRootReadV1(account, mdbx.TreeRootReadV1{Primitive: before, Parent: parent}) == nil, "direct/transient native gate h%d", height)
				captured.Primitive.Kind, captured.Primitive.Undo = 4, 1
				logicalMDBXAssert(t, !initial148RequiredShapeV1(captured), "first genesis entered validation recipe h%d", height)
				err := reader.CheckTreeRootReadV1(account, mdbx.TreeRootReadV1{Primitive: captured.Primitive, Parent: parent})
				var engine *mdbx.EngineError
				logicalMDBXAssert(t, errors.As(err, &engine) && engine.Class == mdbx.EngineInvalidInput && engine.Operation == "update" && engine.Code == 22 && engine.Diagnostic == "invalid tree delta" && !engine.ReopenRequired && before.Kind == 1 && before.Undo == 2, "first genesis entered native root gate h%d: %v", height, err)
				return nil
			}) == nil, "recipe Reader")
		})
	}
}

// G16 covers raw tuples that the finite native fixture cannot manufacture.
// Each assertion pins a sibling result, stage, truth and original error object.
func TestInitial148FirstGenesisOutcomeProjection(t *testing.T) {
	cause := errors.New("native cause")
	var typedNil *mdbx.EngineError
	rows := []struct {
		name, result      string
		truth             mdbx.CommitTruth
		stage             mdbx.UpdateStage
		err               error
		entered, complete bool
	}{
		{"accepted", "ACCEPTED", 2, 3, nil, true, true},
		{"crossed-old", "TERMINAL_PERSISTENCE(old)", 1, 3, cause, true, true},
		{"crossed-new", "TERMINAL_PERSISTENCE(new)", 2, 3, cause, true, true},
		{"crossed-unknown", "TERMINAL_PERSISTENCE(neither_or_unreadable)", 3, 3, cause, true, true},
		{"cached-new", "", 2, 1, cause, false, false},
		{"cached-unknown", "", 3, 1, cause, false, false},
		{"nil-before", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, nil, true, false},
		{"nil-old-crossed", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 3, nil, true, true},
		{"nil-unknown-crossed", "TERMINAL_LOCAL_INVARIANT(evidence)", 3, 3, nil, true, true},
		{"crossed-not-entered", "TERMINAL_LOCAL_INVARIANT(evidence)", 2, 3, cause, false, true},
		{"crossed-incomplete", "TERMINAL_LOCAL_INVARIANT(evidence)", 2, 3, cause, true, false},
		{"typed-nil", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, typedNil, true, false},
		{"wrapped-typed-nil", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, fmt.Errorf("native: %w", typedNil), true, false},
		{"validation-then-cleanup", "CONSENSUS_INVALID", 1, 1, errors.Join(txerr(TX_ERR_PARSE, "framing"), &mdbx.EngineError{Class: mdbx.EngineIO}), true, false},
		{"cleanup-then-validation", "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", 1, 1, errors.Join(&mdbx.EngineError{Class: mdbx.EngineIO}, txerr(TX_ERR_PARSE, "framing")), true, false},
		{"validation-then-integrity", "TERMINAL_STORE_INTEGRITY(canonical)", 1, 1, errors.Join(txerr(TX_ERR_PARSE, "framing"), &mdbx.EngineError{Class: mdbx.EngineIntegrity}), true, false},
		{"invalid-truth", "TERMINAL_LOCAL_INVARIANT(evidence)", 0, 1, cause, true, false},
		{"invalid-stage", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 0, cause, true, false},
		{"above-truth", "TERMINAL_LOCAL_INVARIANT(evidence)", 4, 1, cause, true, false},
		{"above-stage", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 4, cause, true, false},
		{"new-before", "TERMINAL_LOCAL_INVARIANT(evidence)", 2, 2, cause, true, true},
		{"unknown-before", "TERMINAL_LOCAL_INVARIANT(evidence)", 3, 2, cause, true, true},
		{"validation", "CONSENSUS_INVALID", 1, 1, txerr(BLOCK_ERR_UTXO_ROOT_MISMATCH, "utxo_root mismatch"), true, false},
		{"wrapped-validation", "CONSENSUS_INVALID", 1, 1, fmt.Errorf("validation: %w", txerr(TX_ERR_PARSE, "framing")), true, false},
		{"unclassified", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, cause, true, false},
		{"mismatch-without-plan", "TERMINAL_LOCAL_INVARIANT(evidence)", 1, 1, &mdbx.EngineError{Class: mdbx.EngineStateMismatch}, true, false},
		{"mismatch-before-integrity", "STALE_LOCAL_PLAN", 1, 1, errors.Join(&mdbx.EngineError{Class: mdbx.EngineStateMismatch}, &mdbx.EngineError{Class: mdbx.EngineIntegrity}), true, true},
		{"integrity-before-mismatch", "TERMINAL_STORE_INTEGRITY(canonical)", 1, 1, errors.Join(&mdbx.EngineError{Class: mdbx.EngineIntegrity}, &mdbx.EngineError{Class: mdbx.EngineStateMismatch}), true, true},
	}
	for _, class := range []mdbx.EngineClass{mdbx.EngineCapacity, mdbx.EngineConcurrency, mdbx.EngineTransaction, mdbx.EngineIO, mdbx.EngineIntegrity, mdbx.EngineStateMismatch, mdbx.EngineInvalidInput, mdbx.EngineLocalInvariant} {
		for _, stage := range []mdbx.UpdateStage{1, 2} {
			result := map[mdbx.EngineClass]string{mdbx.EngineCapacity: "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", mdbx.EngineConcurrency: "LOCAL_RESOURCE_UNAVAILABLE(storage_concurrency)", mdbx.EngineTransaction: "LOCAL_RESOURCE_UNAVAILABLE(storage_transaction)", mdbx.EngineIO: "LOCAL_RESOURCE_UNAVAILABLE(storage_io)", mdbx.EngineIntegrity: "TERMINAL_STORE_INTEGRITY(canonical)", mdbx.EngineStateMismatch: "STALE_LOCAL_PLAN"}[class]
			if result == "" {
				result = "TERMINAL_LOCAL_INVARIANT(evidence)"
			}
			if stage == 2 && class != mdbx.EngineIntegrity && class != mdbx.EngineStateMismatch && result != "TERMINAL_LOCAL_INVARIANT(evidence)" {
				result = "LOCAL_PERSISTENCE_ERROR(precommit)"
			}
			err := &mdbx.EngineError{Class: class, Operation: "update", Code: 5, Diagnostic: "fixture", ReopenRequired: true, Cause: cause}
			rows = append(rows, struct {
				name, result      string
				truth             mdbx.CommitTruth
				stage             mdbx.UpdateStage
				err               error
				entered, complete bool
			}{string(class) + fmt.Sprint(stage), result, 1, stage, err, true, true})
			rows = append(rows, struct {
				name, result      string
				truth             mdbx.CommitTruth
				stage             mdbx.UpdateStage
				err               error
				entered, complete bool
			}{string(class) + fmt.Sprint(stage) + "-wrapped", result, 1, stage, fmt.Errorf("native: %w", err), true, true})
		}
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			raw := Initial148FirstGenesisOutcomeV1{Truth: row.truth, Stage: row.stage, Err: row.err}
			got := initial148FirstGenesisProjectV1(raw, row.entered, row.complete)
			logicalMDBXAssert(t, got.Result == row.result && got.Truth == raw.Truth && got.Stage == raw.Stage && any(got.Err) == any(raw.Err), "projection %s: %+v", row.name, got)
		})
	}
}

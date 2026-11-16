//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// replayPairStoreV1 is the existing native operation boundary, also allowing a
// caller to observe its single invocation without adding a native test seam.
type replayPairStoreV1 interface {
	UpdateTreeV1(*mdbx.OperationAccount, func(*mdbx.Reader) (mdbx.TreeOperationV1, error)) (mdbx.CommitTruth, mdbx.UpdateStage, int, error)
}

// replayPairRowsV1 contains caller-classified rows, never a row classifier.
// Pair excludes the two role indexes and the shared absent-body literal, which
// the producer supplies. Stored-body reuse/deletion stays in the supplied Pair.
// Returning rows transfers the operation-local Mutations slice for assembly;
// its Key/Literal bytes and all other Pair backing remain borrowed immutable.
type replayPairRowsV1 struct {
	Pair                           mdbx.TreePairV1
	Undo                           mdbx.TreeUndoEffectV1
	BodyKind                       uint8
	CurrentCanonical, CurrentOwner bool
	LagCanonical, LagOwner         bool
}

// replayPairRequestV1 borrows coherent GENESIS_REPLAY/REBUILT authority and a
// qualified immutable block/header/work. The caller owns h=cursor+1, admission,
// source order and complete-run W/M lifetime; this dormant stage parses none.
type replayPairRequestV1 struct {
	Authority mdbx.TreeAuthorityV1
	Database  [32]byte
	Height    uint64
	Endpoint  mdbx.TreeEndpointV1
	LagParent mdbx.TreeEndpointV1
	Raw       []byte
}

type replayPairPrepareCurrentV1 func(*mdbx.Reader) (*initial148CompleteBlockResultV1, replayPairRowsV1, error)
type replayPairWithLagInputsV1 func(*mdbx.Reader, *initial148CompleteBlockResultV1, func([]mdbx.TreeOutpointV1) error) error

// replayPairOutcomeV1 preserves the native tuple. Role is empty before callback
// entry, owns a CURRENT/LAG callback refusal, or projects native index 0/1.
// Enclosing native index -1 carries no inferred role; successful Role is unused.
type replayPairOutcomeV1 struct {
	Truth mdbx.CommitTruth
	Stage mdbx.UpdateStage
	Index int
	Err   error
	Role  string
}

// replayPairUnequalV1 is local accepted-prefix evidence, not block invalidity.
// The future replay admission owner supplies the terminal latch/conversion.
type replayPairUnequalV1 struct {
	Generation uint64
	Height     uint64
	Block      [32]byte
	Derived    [32]byte
	Accepted   [32]byte
}

func (e *replayPairUnequalV1) Error() string { return "replay LAG accepted endpoint root unequal" }

// replayPairAppliesV1 derives the fixed target bound with uint64 arithmetic.
func replayPairAppliesV1(target, height uint64) bool {
	if target < 15120 {
		return false
	}
	return height <= 720*((target-15120)/720)
}

// applyReplayPairV1 must run synchronously inside initial148CompleteRunV1.
// Sources and validated M remain live through its one native call and unwind.
func applyReplayPairV1(store replayPairStoreV1, account *mdbx.OperationAccount, request replayPairRequestV1, prepareCurrent replayPairPrepareCurrentV1, withLagInputs replayPairWithLagInputsV1) replayPairOutcomeV1 {
	c := replayPairCallV1{account: account, request: request, prepare: prepareCurrent, lagInputs: withLagInputs}
	out := replayPairOutcomeV1{Index: -1}
	out.Truth, out.Stage, out.Index, out.Err = store.UpdateTreeV1(account, c.planV1)
	out.Role = c.role
	switch out.Index {
	case 0:
		out.Role = "CURRENT"
	case 1:
		out.Role = "LAG"
	}
	return out
}

type replayPairCallV1 struct {
	account   *mdbx.OperationAccount
	request   replayPairRequestV1
	prepare   replayPairPrepareCurrentV1
	lagInputs replayPairWithLagInputsV1
	role      string
	sources   [2]blockTreeSourceV1
}

// planV1 preserves CURRENT validation -> F2 -> LAG source -> F3 -> key frame.
func (c *replayPairCallV1) planV1(reader *mdbx.Reader) (mdbx.TreeOperationV1, error) {
	c.role = "CURRENT"
	if c.prepare == nil {
		return mdbx.TreeOperationV1{}, localLogicalStateFailure("nil replay CURRENT preparation")
	}
	result, rows, err := c.prepare(reader)
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	if result == nil {
		return mdbx.TreeOperationV1{}, localLogicalStateFailure("nil replay CURRENT result")
	}
	req := c.currentRequestV1(result, rows)
	current, err := prepareBlockTreeEffectV1(&c.sources[0], reader, c.account, req)
	if err != nil {
		return mdbx.TreeOperationV1{}, err
	}
	op := mdbx.TreeOperationV1{Pair: rows.Pair, Primitives: []mdbx.TreePrimitiveV1{current.Primitive}}
	op.Pair.Mutations = append(op.Pair.Mutations, current.Index[:]...)
	if rows.BodyKind == 1 {
		op.Pair.Mutations = append(op.Pair.Mutations, current.CurrentBody)
	}
	if replayPairAppliesV1(c.request.Authority.Authority.Replay.Target.TipHeight, c.request.Height) {
		if err := c.lagV1(reader, result, rows, req, &op); err != nil {
			return mdbx.TreeOperationV1{}, err
		}
	}
	slices.SortFunc(op.Pair.Mutations, replayPairMutationCompareV1)
	c.role = ""
	return op, nil
}

// currentRequestV1 keeps F2 distinct from the validator's DirectApply producer.
func (c *replayPairCallV1) currentRequestV1(result *initial148CompleteBlockResultV1, rows replayPairRowsV1) blockTreeRequestV1 {
	r := c.request
	req := blockTreeRequestV1{
		DatabaseID: r.Database, Generation: r.Authority.Authority.Replay.TargetGenerationID,
		Block: r.Endpoint.BlockHash, Height: r.Height, HeaderBytes: 148,
		BodyKind: rows.BodyKind, Raw: r.Raw, Generated: &result.transition.alreadyGeneratedN1,
		Direction: mdbx.TreeForwardV1, Kind: mdbx.TreeKindReplayNextV1, Undo: rows.Undo, Endpoint: r.Endpoint,
		CanonicalBeforePresent: rows.CurrentCanonical, OwnerBeforePresent: rows.CurrentOwner,
	}
	if rows.BodyKind == 2 {
		req.Raw = nil
	}
	return req
}

// lagV1 selects LAG before every later fallible stage, independently of native
// callback index -1 and the root reader's observation primitive 0.
func (c *replayPairCallV1) lagV1(reader *mdbx.Reader, result *initial148CompleteBlockResultV1, rows replayPairRowsV1, req blockTreeRequestV1, op *mdbx.TreeOperationV1) error {
	c.role = "LAG"
	req.Generation, req.Kind, req.Undo = c.request.Authority.TargetLagGenerationID, mdbx.TreeKindLagForwardV1, mdbx.UndoTransientV1
	req.CanonicalBeforePresent, req.OwnerBeforePresent = rows.LagCanonical, rows.LagOwner
	lag, err := prepareBlockTreeEffectV1(&c.sources[1], reader, c.account, req)
	if err != nil {
		return err
	}
	req.Kind, req.BodyKind, req.Raw = mdbx.TreeKindDirectApplyV1, 1, c.request.Raw
	var source blockTreeSourceV1
	f3, err := prepareBlockTreeEffectV1(&source, reader, c.account, req)
	if err != nil {
		return err
	}
	if err := c.endpointV1(reader, result, f3.Primitive); err != nil {
		return err
	}
	op.Primitives = append(op.Primitives, lag.Primitive)
	op.Pair.Mutations = append(op.Pair.Mutations, lag.Index[:]...)
	return nil
}

// endpointV1 invokes the caller's lexical key/grant frame only after sources.
// Sticky first-use errors cannot be replaced by caller returns or repeated use.
func (c *replayPairCallV1) endpointV1(reader *mdbx.Reader, result *initial148CompleteBlockResultV1, primitive mdbx.TreePrimitiveV1) error {
	if c.lagInputs == nil {
		return localLogicalStateFailure("nil replay LAG inputs")
	}
	used := false
	var selected error
	err := c.lagInputs(reader, result, func(keys []mdbx.TreeOutpointV1) error {
		if selected != nil {
			return selected
		}
		if used {
			selected = localLogicalStateFailure("repeated replay LAG inputs")
			return selected
		}
		used = true
		selected = c.deriveV1(reader, primitive, keys)
		return selected
	})
	if selected != nil {
		return selected
	}
	if err != nil {
		return err
	}
	if !used {
		return localLogicalStateFailure("unused replay LAG inputs")
	}
	return nil
}

// deriveV1 reads protected LAG ORIGINAL OLD before native mutation.
func (c *replayPairCallV1) deriveV1(reader *mdbx.Reader, primitive mdbx.TreePrimitiveV1, keys []mdbx.TreeOutpointV1) error {
	root, err := reader.DeriveTreeRootV1(c.account, mdbx.TreeRootReadV1{Primitive: primitive, Parent: c.request.LagParent, Inputs: keys})
	if err != nil {
		return err
	}
	var accepted [32]byte
	copy(accepted[:], c.request.Raw[108:140])
	if root != accepted {
		return &replayPairUnequalV1{Generation: primitive.Generation, Height: primitive.Height, Block: primitive.Block, Derived: root, Accepted: accepted}
	}
	return nil
}

// replayPairMutationCompareV1 uses the native rank/key order without changing
// row identity or inventing conflict/duplicate admission owned by the engine.
func replayPairMutationCompareV1(a, b mdbx.Mutation) int {
	if a.DBI.Rank != b.DBI.Rank {
		return int(a.DBI.Rank) - int(b.DBI.Rank)
	}
	return bytes.Compare(a.Key, b.Key)
}

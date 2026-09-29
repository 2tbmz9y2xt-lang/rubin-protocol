//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"reflect"
	"sort"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// Dormant bridge from a logical-state plan to one private MDBX Update Batch. Only genesisMDBXBatch may compose it;
// the public genesis operation still has no production caller.
//
// Caller preconditions this file cannot observe: the view is built from the Reader of the same mdbx.Store Update
// callback, that Reader has not yet failed a read, the same declared height reaches the plan builder and this
// converter, the view given to buildLogicalStatePlan is also logicalMDBXMetadata.view, the Batch is returned before the
// callback returns, and at declared height zero the image has no UTXO rows and any existing counter was observed as zero.
// Extras already satisfy the complete mdbx mutation
// grammar and leave combined capacity for the counter row, every logical row and every extra; mdbx.Store.Update stays
// the sole defensive validator of that grammar and of every aggregate bound. Read outcomes follow CAP
// RUBIN_CONSENSUS_STATE_MACHINE.md section 2.5 through the logicalStateView contract; logicalStateFailureLocalInvariant
// returned here tags caller and shape bugs and is deliberately not the canonical section 2.5 LOCAL_INVARIANT
// classification, which the first non-test caller must resolve.
var _ logicalStateView = (*logicalMDBXStateView)(nil)

// logicalMDBXEntryPrefix is the outpoint prefix width of StateEntryBytes
// (CAP section 2.5): the stored utxo-v1 value is the exact remaining suffix.
const logicalMDBXEntryPrefix = 36

var (
	errLogicalMDBXAbsentCounter    = errors.New("logical counter absent above genesis")
	errLogicalMDBXUnclassifiedRead = errors.New("unclassified logical MDBX read failure")
	errLogicalMDBXCreateOnce       = errors.New("existing create-once row differs from the requested literal")
)

// logicalMDBXRowObservation is all the view keeps per outpoint: presence and the
// StateEntryBytes length, never the stored value bytes.
type logicalMDBXRowObservation struct {
	entryBytes uint64
	present    bool
}

type logicalMDBXStateView struct {
	reader         *mdbx.Reader
	rows           map[Outpoint]logicalMDBXRowObservation
	counters       logicalStateCounters
	imageID        uint64
	height         uint64
	counterPresent bool
}

func newLogicalMDBXStateView(reader *mdbx.Reader, imageID, height uint64) *logicalMDBXStateView {
	return &logicalMDBXStateView{reader: reader, rows: map[Outpoint]logicalMDBXRowObservation{}, imageID: imageID, height: height}
}

// read is the only Reader.Get call site here; an unbuildable key is the failure it prevents.
func (v *logicalMDBXStateView) read(dbi mdbx.DBI, key []byte, keyErr error) ([]byte, bool, error) {
	if keyErr != nil {
		return nil, false, keyErr
	}
	return v.reader.Get(dbi, key)
}

// Counters performs the logical-counter read, which the plan requires only above genesis. Postconditions: a present
// well formed row records the decoded counters once, every other outcome records nothing, and absence is store integrity.
func (v *logicalMDBXStateView) Counters() logicalStateCounterRead {
	key, keyErr := mdbx.MetaKey(0x10, v.imageID)
	value, present, err := v.read(mdbx.SchemaV2DBIs()[0], key, keyErr)
	if err != nil {
		kind, cause := classifyLogicalMDBXReadError(err)
		counterKind, _ := logicalMDBXReadKinds(kind)
		return logicalStateCounterRead{kind: counterKind, cause: cause}
	}
	if !present {
		return logicalStateCounterRead{kind: logicalStateCountersStoreIntegrity, cause: errLogicalMDBXAbsentCounter}
	}
	total, entries, decodeErr := mdbx.DecodeLogicalCounterValue(value)
	if decodeErr != nil {
		return logicalStateCounterRead{kind: logicalStateCountersStoreIntegrity, cause: decodeErr}
	}
	v.counters, v.counterPresent = logicalStateCounters{bytes: total, entries: entries}, true
	return logicalStateCounterRead{kind: logicalStateCountersPresent, counters: v.counters}
}

// Lookup performs one required row read. Postconditions: presence or definitive absence is recorded with the
// StateEntryBytes length; a failed read records nothing and the view never retains the stored value bytes.
func (v *logicalMDBXStateView) Lookup(op Outpoint) logicalStateRowRead {
	key, keyErr := mdbx.UTXOKey(v.imageID, op.Txid, op.Vout)
	value, present, err := v.read(mdbx.SchemaV2DBIs()[1], key, keyErr)
	if err != nil {
		kind, cause := classifyLogicalMDBXReadError(err)
		_, rowKind := logicalMDBXReadKinds(kind)
		return logicalStateRowRead{kind: rowKind, cause: cause}
	}
	if !present {
		v.rows[op] = logicalMDBXRowObservation{}
		return logicalStateRowRead{kind: logicalStateRowAbsent}
	}
	decoded, decodeErr := mdbx.DecodeUTXOValue(value)
	if decodeErr != nil {
		return logicalStateRowRead{kind: logicalStateRowStoreIntegrity, cause: decodeErr}
	}
	v.rows[op] = logicalMDBXRowObservation{entryBytes: logicalMDBXEntryPrefix + uint64(len(value)), present: true}
	entry := UtxoEntry{CovenantData: decoded.CovenantData, Value: decoded.Value, CreationHeight: decoded.CreationHeight, CovenantType: decoded.CovenantType, CreatedByCoinbase: decoded.Coinbase}
	return logicalStateRowRead{kind: logicalStateRowPresent, entry: entry}
}

// classifyLogicalMDBXReadError is the single mapping from a Reader.Get failure to a bridge read class.
// Postconditions: only a direct non-nil engine error carries its own class, the exact original cause
// survives, and a nil or typed-nil input yields one synthesized local cause.
func classifyLogicalMDBXReadError(err error) (logicalStateFailureKind, error) {
	engine, direct := err.(*mdbx.EngineError) //nolint:errorlint // A wrapped error is not the adapter's own direct classification.
	if engine == nil {
		if direct || err == nil {
			return logicalStateFailureLocalInvariant, errLogicalMDBXUnclassifiedRead
		}
		return logicalStateFailureLocalInvariant, err
	}
	switch engine.Class {
	case mdbx.EngineIntegrity:
		return logicalStateFailureStoreIntegrity, err
	case mdbx.EngineCapacity, mdbx.EngineConcurrency, mdbx.EngineIO:
		return logicalStateFailureUnavailable, err
	default:
		return logicalStateFailureLocalInvariant, err
	}
}

// logicalMDBXReadKinds names one failure class in both read vocabularies, so neither read
// depends on the declaration order of the PLAN read-kind enumerations.
func logicalMDBXReadKinds(kind logicalStateFailureKind) (logicalStateCounterReadKind, logicalStateRowReadKind) {
	switch kind {
	case logicalStateFailureUnavailable:
		return logicalStateCountersUnavailable, logicalStateRowUnavailable
	case logicalStateFailureStoreIntegrity:
		return logicalStateCountersStoreIntegrity, logicalStateRowStoreIntegrity
	default:
		return logicalStateCountersLocalInvariant, logicalStateRowLocalInvariant
	}
}

type logicalMDBXMetadata struct {
	view   *logicalMDBXStateView
	extras []mdbx.Mutation
}

// newLogicalMDBXMetadata binds the exact view and owns every extra byte slice, out of the caller's reach.
func newLogicalMDBXMetadata(view *logicalMDBXStateView, extras []mdbx.Mutation) logicalMDBXMetadata {
	owned := make([]mdbx.Mutation, len(extras))
	for i, extra := range extras {
		owned[i] = logicalMDBXCloneMutation(extra)
	}
	return logicalMDBXMetadata{view: view, extras: owned}
}

func logicalMDBXCloneMutation(m mdbx.Mutation) mdbx.Mutation {
	m.Key, m.Literal, m.RefKey = bytes.Clone(m.Key), bytes.Clone(m.Literal), bytes.Clone(m.RefKey)
	return m
}

// logicalMDBXRow is one coalesced logical outpoint: a DELETE, a PUT, or the one allowed replacement.
type logicalMDBXRow struct {
	op         Outpoint
	literal    []byte
	entryBytes uint32
	before     bool
	put        bool
}

// logicalMDBXPlanToBatch converts one merged plan into one owned Batch.
// Postconditions: either one nonempty Batch and no failure, or the zero Batch and
// one private failure; it mutates nothing and reads nothing after a failure.
func logicalMDBXPlanToBatch(plan logicalStatePlan[logicalMDBXMetadata]) (mdbx.Batch, *logicalStateFailure) {
	mutations, rows, failure := logicalMDBXPure(plan)
	if failure == nil {
		failure = logicalMDBXCheckObservations(plan, rows)
	}
	if failure == nil {
		mutations, failure = logicalMDBXCreateOnce(plan.Metadata.view, mutations)
	}
	if failure != nil {
		return mdbx.Batch{}, failure
	}
	return mdbx.Batch{Mutations: mutations}, nil
}

// logicalMDBXPure runs every check needing no read: view, declared-height form, plan shape, order, checked arithmetic, extras.
func logicalMDBXPure(plan logicalStatePlan[logicalMDBXMetadata]) ([]mdbx.Mutation, []logicalMDBXRow, *logicalStateFailure) {
	view := plan.Metadata.view
	if view == nil || view.imageID == 0 {
		return nil, nil, localLogicalStateFailure("nil logical MDBX metadata view or zero image identifier")
	}
	if failure := logicalMDBXCheckGenesis(view, plan.Parent, len(plan.Deletes)); failure != nil {
		return nil, nil, failure
	}
	rows, failure := logicalMDBXPlanRows(plan.Deletes, plan.Puts)
	if failure == nil {
		failure = logicalMDBXCheckArithmetic(plan.Parent, plan.Result, rows)
	}
	if failure != nil {
		return nil, nil, failure
	}
	mutations, failure := logicalMDBXWithExtras(logicalMDBXMutations(view, plan.Result, rows), plan.Metadata.extras, view)
	return mutations, rows, failure
}

// logicalMDBXPlanRows merges the two ordered plan slices once, refusing a PUT beyond the PLAN covenant bound before
// encoding it; unordered or duplicated input stays non-ascending.
func logicalMDBXPlanRows(deletes []logicalStateDelete, puts []logicalStatePut) ([]logicalMDBXRow, *logicalStateFailure) {
	rows := make([]logicalMDBXRow, 0, len(deletes)+len(puts))
	for d, p := 0, 0; d < len(deletes) || p < len(puts); {
		var row logicalMDBXRow
		order := logicalMDBXRowOrder(deletes, puts, d, p)
		if order <= 0 {
			row.op, row.before, row.entryBytes = deletes[d].Outpoint, true, deletes[d].EntryBytes
			d++
		}
		if order >= 0 {
			if len(puts[p].Entry.CovenantData) > MAX_COVENANT_DATA_PER_OUTPUT {
				return nil, localLogicalStateFailure("logical state plan entry exceeds the covenant data bound")
			}
			row.op, row.put, row.literal = puts[p].Outpoint, true, logicalStateEntryBytes(puts[p].Outpoint, puts[p].Entry)[logicalMDBXEntryPrefix:]
			p++
		}
		rows = append(rows, row)
	}
	for i := 1; i < len(rows); i++ {
		if !logicalOutpointLess(rows[i-1].op, rows[i].op) {
			return nil, localLogicalStateFailure("unordered or duplicate logical state plan rows")
		}
	}
	return rows, nil
}

func logicalMDBXRowOrder(deletes []logicalStateDelete, puts []logicalStatePut, d, p int) int {
	switch {
	case p >= len(puts):
		return -1
	case d >= len(deletes):
		return 1
	case deletes[d].Outpoint == puts[p].Outpoint:
		return 0
	case logicalOutpointLess(deletes[d].Outpoint, puts[p].Outpoint):
		return -1
	}
	return 1
}

// logicalMDBXCheckArithmetic re-derives the plan counter equations with checked arithmetic; a replacement
// counts in both sums, and any contradiction fails before the converter reads anything.
func logicalMDBXCheckArithmetic(parent, result logicalStateCounters, rows []logicalMDBXRow) *logicalStateFailure {
	var removed, removedBytes, added, addedBytes, carry uint64
	for _, row := range rows {
		if row.before {
			removed++
			if removedBytes, carry = bits.Add64(removedBytes, uint64(row.entryBytes), 0); carry != 0 {
				return localLogicalStateFailure("logical state plan counters overflow")
			}
		}
		if row.put {
			added++
			if addedBytes, carry = bits.Add64(addedBytes, logicalMDBXEntryPrefix+uint64(len(row.literal)), 0); carry != 0 {
				return localLogicalStateFailure("logical state plan counters overflow")
			}
		}
	}
	if removed > parent.entries || removedBytes > parent.bytes {
		return localLogicalStateFailure("logical state plan counters underflow")
	}
	return logicalMDBXCheckTotals(parent, result, removed, removedBytes, added, addedBytes)
}

func logicalMDBXCheckTotals(parent, result logicalStateCounters, removed, removedBytes, added, addedBytes uint64) *logicalStateFailure {
	entries, entriesCarry := bits.Add64(parent.entries-removed, added, 0)
	total, bytesCarry := bits.Add64(parent.bytes-removedBytes, addedBytes, 0)
	return logicalMDBXReject(entriesCarry|bytesCarry != 0 || entries != result.entries || total != result.bytes, "logical state plan counters do not match the plan rows")
}

// logicalMDBXMutations builds the always-present counter row then the coalesced rows, so a Batch is never empty.
// MetaKey and UTXOKey cannot fail here: a zero imageID was already rejected at step 1.
func logicalMDBXMutations(view *logicalMDBXStateView, result logicalStateCounters, rows []logicalMDBXRow) []mdbx.Mutation {
	dbis := mdbx.SchemaV2DBIs()
	counterKey, _ := mdbx.MetaKey(0x10, view.imageID)
	mutations := make([]mdbx.Mutation, 0, len(rows)+1)
	mutations = append(mutations, mdbx.Mutation{DBI: dbis[0], Key: counterKey, BeforePresent: view.counterPresent, AfterKind: mdbx.AfterLiteral, Literal: mdbx.LogicalCounterValue(result.bytes, result.entries)})
	for _, row := range rows {
		key, _ := mdbx.UTXOKey(view.imageID, row.op.Txid, row.op.Vout)
		mutation := mdbx.Mutation{DBI: dbis[1], Key: key, BeforePresent: true, AfterKind: mdbx.AfterAbsent}
		if row.put {
			mutation = mdbx.Mutation{DBI: dbis[1], Key: key, BeforePresent: row.before, AfterKind: mdbx.AfterLiteral, Literal: row.literal}
		}
		mutations = append(mutations, mutation)
	}
	return mutations
}

// logicalMDBXWithExtras applies the residual policy, owns every emitted extra and sorts once by (DBI.Rank, Key),
// rejecting any repeated target.
func logicalMDBXWithExtras(mutations, extras []mdbx.Mutation, view *logicalMDBXStateView) ([]mdbx.Mutation, *logicalStateFailure) {
	logical := mutations[:len(mutations):len(mutations)]
	for _, extra := range extras {
		if failure := logicalMDBXExtraPolicy(extra, view, logical); failure != nil {
			return nil, failure
		}
		// Cloned a second time so a later Batch mutation cannot reach the owned metadata; one copy per extra.
		mutations = append(mutations, logicalMDBXCloneMutation(extra))
	}
	sort.Slice(mutations, func(i, j int) bool { return logicalMDBXBefore(mutations[i], mutations[j]) })
	for i := 1; i < len(mutations); i++ {
		if !logicalMDBXBefore(mutations[i-1], mutations[i]) {
			return nil, localLogicalStateFailure("duplicate MDBX mutation target")
		}
	}
	return mutations, nil
}

func logicalMDBXBefore(previous, next mdbx.Mutation) bool {
	if previous.DBI.Rank != next.DBI.Rank {
		return previous.DBI.Rank < next.DBI.Rank
	}
	return bytes.Compare(previous.Key, next.Key) < 0
}

// logicalMDBXExtraPolicy is the complete bridge-owned residual check set: forbidden targets, image binding and
// undo provenance. Adapter action/payload grammar and every aggregate bound stay with mdbx.Store.Update.
func logicalMDBXExtraPolicy(extra mdbx.Mutation, view *logicalMDBXStateView, logical []mdbx.Mutation) *logicalStateFailure {
	switch extra.DBI.Rank {
	case 0:
		return logicalMDBXReject(len(extra.Key) == 9 && extra.Key[0] == 0x10, "extra targets a logical counter row")
	case 1:
		return localLogicalStateFailure("extra targets a bridge-owned logical row")
	case 2, 6:
		return logicalMDBXReject(logicalMDBXKeyImage(extra.Key) != view.imageID, "extra targets a different logical image")
	case 5:
		return logicalMDBXUndoPolicy(extra, view, logical)
	default:
		return nil
	}
}

func logicalMDBXReject(bad bool, message string) *logicalStateFailure {
	if bad {
		return localLogicalStateFailure(message)
	}
	return nil
}

// logicalMDBXUndoPolicy binds an undo reference to a logical row this Batch itself removes or overwrites, in this image.
func logicalMDBXUndoPolicy(extra mdbx.Mutation, view *logicalMDBXStateView, logical []mdbx.Mutation) *logicalStateFailure {
	if extra.AfterKind != mdbx.AfterOldValueRef {
		return nil
	}
	if extra.RefDBI.Rank != 1 || logicalMDBXKeyImage(extra.RefKey) != view.imageID {
		return localLogicalStateFailure("undo reference is not utxo-v1, is short or targets a different logical image")
	}
	for _, row := range logical {
		if row.BeforePresent && row.DBI == extra.RefDBI && bytes.Equal(row.Key, extra.RefKey) {
			return nil
		}
	}
	return localLogicalStateFailure("undo reference is not a removed logical row of this Batch")
}

// logicalMDBXKeyImage reads the leading image identifier; a key too short to carry one reports zero.
func logicalMDBXKeyImage(key []byte) uint64 {
	if len(key) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(key)
}

// logicalMDBXCheckObservations proves the plan against what this view observed; the genesis form was already proved at
// step 1, so declared height zero is the explicit exception and checks nothing here.
func logicalMDBXCheckObservations(plan logicalStatePlan[logicalMDBXMetadata], rows []logicalMDBXRow) *logicalStateFailure {
	view := plan.Metadata.view
	if view.height == 0 {
		return nil
	}
	if !view.counterPresent || view.counters != plan.Parent {
		return localLogicalStateFailure("logical counter observation does not match the plan")
	}
	for _, row := range rows {
		if !logicalMDBXRowObserved(view, row) {
			return localLogicalStateFailure("logical row observation does not match the plan")
		}
	}
	return nil
}

func logicalMDBXRowObserved(view *logicalMDBXStateView, row logicalMDBXRow) bool {
	observation, recorded := view.rows[row.op]
	if !recorded || observation.present != row.before {
		return false
	}
	return !row.before || observation.entryBytes == uint64(row.entryBytes)
}

// logicalMDBXCheckGenesis is the step-1 declared-height form: at height zero the builder reads nothing, so the view must
// have observed no rows and at most a zero counter; the plan starts from zero parent counters and deletes nothing.
// Above zero this check adds nothing. Counter before-presence remains the actual observation.
func logicalMDBXCheckGenesis(view *logicalMDBXStateView, parent logicalStateCounters, deletes int) *logicalStateFailure {
	return logicalMDBXReject(view.height == 0 && (view.counterPresent && view.counters != (logicalStateCounters{}) || len(view.rows) != 0 || parent != (logicalStateCounters{}) || deletes != 0),
		"genesis logical state form contradicts the view")
}

// logicalMDBXCreateOnce reads the create-once targets in final Batch order, stopping at the first failure.
func logicalMDBXCreateOnce(view *logicalMDBXStateView, mutations []mdbx.Mutation) ([]mdbx.Mutation, *logicalStateFailure) {
	kept := make([]mdbx.Mutation, 0, len(mutations))
	for _, mutation := range mutations {
		emit, failure := logicalMDBXCreateOnceEmit(view, mutation)
		if failure != nil {
			return nil, failure
		}
		if emit {
			kept = append(kept, mutation)
		}
	}
	return kept, nil
}

// logicalMDBXCreateOnceEmit decides one create-once row. Postconditions: an absent target keeps its create, an
// identical SchemaV2-valid present row is omitted, a differing or malformed one is a store-integrity failure, and a
// failed read carries the classifier's kind with its exact cause.
func logicalMDBXCreateOnceEmit(view *logicalMDBXStateView, mutation mdbx.Mutation) (bool, *logicalStateFailure) {
	if !logicalMDBXCreateOnceTarget(mutation) {
		return true, nil
	}
	value, present, err := view.read(mutation.DBI, mutation.Key, nil)
	if err != nil {
		kind, cause := classifyLogicalMDBXReadError(err)
		return false, &logicalStateFailure{kind: kind, cause: cause}
	}
	if !present {
		return true, nil
	}
	if rowErr := mdbx.ValidateRow(mutation.DBI, mutation.Key, value); rowErr != nil {
		return false, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: rowErr}
	}
	if !bytes.Equal(value, mutation.Literal) {
		return false, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: fmt.Errorf("%w: rank %d key %x", errLogicalMDBXCreateOnce, mutation.DBI.Rank, mutation.Key)}
	}
	return false, nil
}

// logicalMDBXCreateOnceTarget selects headers, blocks and the undo manifest, whose key is 33 bytes.
func logicalMDBXCreateOnceTarget(m mdbx.Mutation) bool {
	if m.AfterKind != mdbx.AfterLiteral || m.BeforePresent {
		return false
	}
	return m.DBI.Rank == 3 || m.DBI.Rank == 4 || (m.DBI.Rank == 5 && len(m.Key) == 33)
}

// GenesisMDBXOutcome retains the raw Update tuple and independently owned complete NEW payload.
type GenesisMDBXOutcome struct {
	Result  string
	Truth   mdbx.CommitTruth
	Stage   mdbx.UpdateStage
	State   *InMemoryChainState
	Summary *ConnectBlockBasicSummary
	Err     error
}

const (
	// Logical 68,070,690 (buffers 948, aliases save 382) leaves slack 186; authority/schema/config/keys are excluded control.
	// The canonical-owner pair adds 192 buffer bytes: its 40-byte key and 8-byte value as produced, as cloned by
	// newLogicalMDBXMetadata, as cloned again by logicalMDBXWithExtras and as cloned by Store.Update; pairing finds both
	// counterparts among the targets and reads or allocates nothing more.
	genesisMDBXOperationBytes uint64 = 68_070_876
	genesisMDBXInvariant             = "TERMINAL_LOCAL_INVARIANT(evidence)"
	genesisMDBXIntegrity             = "TERMINAL_STORE_INTEGRITY(canonical)"
)

// Dormant ConnectPublishedGenesisMDBX borrows immutable config synchronously; one reservation covers owned copy through projection, NEW transfers 89-byte state.
func ConnectPublishedGenesisMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, candidate, published []byte, chainID, genesisHash [32]byte) GenesisMDBXOutcome {
	out := GenesisMDBXOutcome{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	out.Result, out.Err = genesisMDBXInput(store, reservations, candidate, published, chainID, genesisHash)
	if out.Err != nil {
		return out
	}
	err := reservations.WithReservation(genesisMDBXOperationBytes, func() error {
		owned := bytes.Clone(candidate)
		var preimage [282]byte
		copy(preimage[:], "RUBIN-GENESIS-v1")
		copy(preimage[16:], owned)
		hash, _ := BlockHash(owned[:116]) // The exact 116-byte slice cannot fail BlockHash's length check.
		if hash != genesisHash || sha3_256(preimage[:]) != chainID {
			out.Result, out.Err = genesisMDBXInvariant, errors.New("published genesis context commitment mismatch")
			return nil
		}
		entered, complete := false, false
		out.Truth, out.Stage, out.Err = store.Update(func(reader *mdbx.Reader) (mdbx.Batch, error) {
			entered = true
			batch, batchErr := genesisMDBXBatch(reader, owned, chainID, genesisHash, &out)
			complete = batchErr == nil
			return batch, batchErr
		})
		out = genesisMDBXProject(out, entered, complete)
		return nil
	})
	if err != nil {
		out.Result, out.Err = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)", err
	}
	return out
}

func genesisMDBXInput(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, candidate, published []byte, chainID, hash [32]byte) (string, error) {
	if store == nil {
		return genesisMDBXInvariant, errors.New("nil genesis Store")
	}
	if len(published) != 266 || chainID == ([32]byte{}) || hash == ([32]byte{}) {
		return genesisMDBXInvariant, errors.New("invalid published genesis context")
	}
	if !bytes.Equal(candidate, published) {
		return "CONSENSUS_INVALID", txerr(BLOCK_ERR_LINKAGE_INVALID, "block does not match published genesis")
	}
	if reservations == nil || *reservations == (mdbx.OperationReservationOwner{}) {
		return genesisMDBXInvariant, errors.New("invalid genesis reservation owner")
	}
	return "", nil
}

// genesisMDBXBatch owns every bridge entry and the complete ordered worklist.
func genesisMDBXBatch(reader *mdbx.Reader, owned []byte, chainID, hash [32]byte, out *GenesisMDBXOutcome) (mdbx.Batch, error) {
	out.Result = "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
	prefix, consulted, err := genesisMDBXPrestate(reader, out)
	if err != nil {
		return mdbx.Batch{}, err
	}
	extras, reused, err := genesisMDBXArtifacts(reader, owned, hash)
	if err != nil {
		return mdbx.Batch{}, err
	}
	out.Result = "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)"
	g := binary.BigEndian.Uint64(prefix)
	view := newLogicalMDBXStateView(reader, g, 0)
	if err := genesisMDBXEmptyUTXO(reader, prefix); err != nil {
		return mdbx.Batch{}, err
	}
	if err := genesisMDBXZeroCounter(view.Counters()); err != nil {
		return mdbx.Batch{}, err
	}
	parsed, err := genesisMDBXValidate(owned, chainID, out)
	if err != nil {
		return mdbx.Batch{}, err
	}
	// Complete validation fixed the target to all FF: floor(2^256/(2^256-1))=1.
	key, _ := mdbx.HeightKey(g, 0) // The decoded authority already proved g != 0.
	owner, _ := mdbx.CanonicalOwnerKey(g, hash) // Same nonzero g: the pair is decided in this writing transaction.
	dbis := mdbx.SchemaV2DBIs()
	extras = append(extras, mdbx.Mutation{DBI: dbis[2], Key: key, AfterKind: mdbx.AfterLiteral, Literal: mdbx.ChainValue(hash, parsed.Header.PrevBlockHash, [40]byte{39: 1})},
		mdbx.Mutation{DBI: dbis[7], Key: owner, AfterKind: mdbx.AfterLiteral, Literal: mdbx.CanonicalOwnerValue(0)})
	op := Outpoint{Txid: parsed.Txids[0], Vout: 0}
	touched := []logicalTouchedState{{Outpoint: op, FinalPresent: true, Final: out.State.Utxos[op]}}
	plan, failure := buildLogicalStatePlan(0, view, touched, newLogicalMDBXMetadata(view, extras))
	if failure != nil {
		return mdbx.Batch{}, failure
	}
	out.Result = "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
	batch, failure := logicalMDBXPlanToBatch(plan)
	if failure != nil {
		return mdbx.Batch{}, failure
	}
	batch.Consulted = append(consulted, reused...)
	sort.Slice(batch.Consulted, func(i, j int) bool {
		a, b := batch.Consulted[i], batch.Consulted[j]
		return logicalMDBXBefore(mdbx.Mutation{DBI: a.DBI, Key: a.Key}, mdbx.Mutation{DBI: b.DBI, Key: b.Key})
	})
	out.Result = ""
	return batch, nil
}

func genesisMDBXPrestate(reader *mdbx.Reader, out *GenesisMDBXOutcome) ([]byte, []mdbx.ConsultedRow, error) {
	dbis, key := mdbx.SchemaV2DBIs(), []byte{2}
	value, _, err := reader.Get(dbis[0], key)
	if err != nil {
		return nil, nil, err
	}
	authority, err := mdbx.DecodeStorageAuthorityV1(value)
	if err != nil {
		return nil, nil, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: err}
	}
	if !genesisMDBXEligible(authority) {
		out.Result = "STALE_LOCAL_PLAN"
		return nil, nil, errors.New("genesis requires NONE/STABLE/PRE_GENESIS")
	}
	prefix := binary.BigEndian.AppendUint64(nil, authority.ActiveGenerationID)
	page, err := reader.PrefixPage(dbis[2], prefix, nil, 1, 120)
	if err != nil {
		return nil, nil, err
	}
	if page.Stop != mdbx.PrefixPageExhausted || len(page.Rows) != 0 {
		out.Result = "STALE_LOCAL_PLAN"
		return nil, nil, errors.New("genesis active canonical generation is not empty")
	}
	consulted, err := genesisMDBXControl(reader)
	return prefix, append(consulted, mdbx.ConsultedRow{DBI: dbis[0], Key: key}), err
}

func genesisMDBXEligible(a mdbx.StorageAuthorityV1) bool {
	return a.Phase == mdbx.StoragePhaseNoneV1 && a.Lifecycle == mdbx.StorageLifecycleStableV1 && a.B == 0 && a.U == 0
}

func genesisMDBXControl(reader *mdbx.Reader) ([]mdbx.ConsultedRow, error) {
	meta := mdbx.SchemaV2DBIs()[0]
	rows := []mdbx.ConsultedRow{{DBI: meta, Key: []byte{0}}, {DBI: meta, Key: []byte{1}}}
	for i, row := range rows {
		value, _, err := reader.Get(row.DBI, row.Key)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			err = mdbx.DecodeSchemaVersionValue(value)
		} else {
			_, err = mdbx.DecodeConfigV1(value)
		}
		if err != nil {
			return nil, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: err}
		}
	}
	return rows, nil
}

func genesisMDBXArtifacts(reader *mdbx.Reader, owned []byte, hash [32]byte) ([]mdbx.Mutation, []mdbx.ConsultedRow, error) {
	dbis := mdbx.SchemaV2DBIs()
	extras := []mdbx.Mutation{
		{DBI: dbis[3], Key: hash[:], AfterKind: mdbx.AfterLiteral, Literal: owned[:116]},
		{DBI: dbis[4], Key: hash[:], AfterKind: mdbx.AfterLiteral, Literal: owned},
		{DBI: dbis[5], Key: mdbx.UndoManifestKey(hash), AfterKind: mdbx.AfterLiteral, Literal: mdbx.UndoManifestValue(0, [16]byte{}, 1, 0)},
	}
	var consulted []mdbx.ConsultedRow
	for _, row := range extras {
		value, present, err := reader.Get(row.DBI, row.Key)
		if err != nil {
			return nil, nil, err
		}
		if !present {
			continue
		}
		// Length is qualified before any stored-body validation or additional copy.
		if len(value) != len(row.Literal) || !bytes.Equal(value, row.Literal) {
			return nil, nil, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: fmt.Errorf("genesis %s differs from published artifact", row.DBI.Name)}
		}
		consulted = append(consulted, mdbx.ConsultedRow{DBI: row.DBI, Key: row.Key})
	}
	return extras, consulted, nil
}

func genesisMDBXEmptyUTXO(reader *mdbx.Reader, prefix []byte) error {
	page, err := reader.PrefixPage(mdbx.SchemaV2DBIs()[1], prefix, nil, 1, 65_604)
	if err != nil {
		return err
	}
	if page.Stop != mdbx.PrefixPageExhausted || len(page.Rows) != 0 {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("genesis active UTXO generation is not empty")}
	}
	return nil
}

func genesisMDBXZeroCounter(read logicalStateCounterRead) error {
	if read.kind < logicalStateCountersPresent || read.kind > logicalStateCountersLocalInvariant {
		return localLogicalStateFailure("invalid genesis counter observation")
	}
	if (read.kind == logicalStateCountersPresent) == (read.cause != nil) {
		return localLogicalStateFailure("invalid genesis counter cause shape")
	}
	if read.kind == logicalStateCountersStoreIntegrity {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: read.cause}
	}
	if read.cause != nil {
		return read.cause
	}
	if read.counters != (logicalStateCounters{}) {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("genesis requires a present zero logical counter")}
	}
	return nil
}

func genesisMDBXValidate(owned []byte, chainID [32]byte, out *GenesisMDBXOutcome) (*ParsedBlock, error) {
	var previous, target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	out.State = &InMemoryChainState{Utxos: make(map[Outpoint]UtxoEntry)}
	var err error
	out.Summary, err = ConnectBlockBasicInMemoryAtHeightAndSuiteContext(owned, &previous, &target, 0, nil, out.State, chainID, nil, nil)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseBlockBytes(owned)
	if err != nil {
		return nil, localLogicalStateFailure("validated genesis metadata cannot be parsed")
	}
	return parsed, nil
}

// genesisMDBXProject preserves the raw tuple and NEW payload without Store reread; causes only select a result.
func genesisMDBXProject(out GenesisMDBXOutcome, entered, complete bool) GenesisMDBXOutcome {
	state, summary := out.State, out.Summary
	valid := genesisMDBXTupleValid(out, entered, complete)
	out.State, out.Summary = nil, nil
	if genesisMDBXCached(out, entered) {
		out.Result = ""
		return out
	}
	if !valid {
		out.Result = genesisMDBXInvariant
		return out
	}
	if out.Stage == mdbx.UpdateStageCommitMayHaveCrossed {
		out.Result = genesisMDBXCrossed(out.Truth, out.Err)
		if out.Truth == mdbx.CommitTruthNew {
			out.State, out.Summary = state, summary
		}
		return out
	}
	out.Result = genesisMDBXUncrossed(out.Err, out.Result, out.Stage)
	return out
}

func genesisMDBXCached(out GenesisMDBXOutcome, entered bool) bool {
	return !entered && out.Stage == mdbx.UpdateStagePrewrite && (out.Truth == mdbx.CommitTruthNew || out.Truth == mdbx.CommitTruthUnknown) && out.Err != nil && !genesisMDBXNilError(out.Err)
}

func genesisMDBXTupleValid(out GenesisMDBXOutcome, entered, complete bool) bool {
	if out.Truth < mdbx.CommitTruthOld || out.Truth > mdbx.CommitTruthUnknown || out.Stage < mdbx.UpdateStagePrewrite || out.Stage > mdbx.UpdateStageCommitMayHaveCrossed {
		return false
	}
	if out.Stage != mdbx.UpdateStageCommitMayHaveCrossed {
		return out.Truth == mdbx.CommitTruthOld && out.Err != nil
	}
	return genesisMDBXPlanValid(out, entered, complete)
}

func genesisMDBXPlanValid(out GenesisMDBXOutcome, entered, complete bool) bool {
	return entered && complete && out.State != nil && out.Summary != nil && (out.Truth == mdbx.CommitTruthNew || out.Err != nil) && !genesisMDBXNilError(out.Err)
}

func genesisMDBXCrossed(truth mdbx.CommitTruth, err error) string {
	if err == nil {
		return "ACCEPTED"
	}
	switch truth {
	case mdbx.CommitTruthOld:
		return "TERMINAL_PERSISTENCE(old)"
	case mdbx.CommitTruthNew:
		return "TERMINAL_PERSISTENCE(new)"
	default:
		return "TERMINAL_PERSISTENCE(neither_or_unreadable)"
	}
}

func genesisMDBXUncrossed(err error, step string, stage mdbx.UpdateStage) string {
	result := ""
	for _, part := range genesisMDBXCauses(err) {
		next := genesisMDBXErrorResult(part, step)
		if next == genesisMDBXInvariant || next == genesisMDBXIntegrity {
			return next
		}
		if result == "" {
			result = next
		}
	}
	if stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit && strings.HasPrefix(result, "LOCAL_RESOURCE_UNAVAILABLE(") {
		return "LOCAL_PERSISTENCE_ERROR(precommit)"
	}
	return result
}

// Flatten existing primary/secondary/cleanup causes in order; text, errno and CommitError never infer stage.
func genesisMDBXCauses(err error) []error {
	if err == nil || reflect.ValueOf(err).Kind() == reflect.Pointer && reflect.ValueOf(err).IsNil() {
		return []error{nil}
	}
	switch e := err.(type) { //nolint:errorlint // Direct composition preserves primary, readback and cleanup cause order.
	case *mdbx.CommitError:
		parts := genesisMDBXCauses(e.Cause)
		if e.ReadbackCause != nil {
			parts = append(parts, genesisMDBXCauses(e.ReadbackCause)...)
		}
		return parts
	case interface{ Unwrap() []error }:
		var parts []error
		for _, cause := range e.Unwrap() {
			parts = append(parts, genesisMDBXCauses(cause)...)
		}
		return parts
	}
	return []error{err}
}

func genesisMDBXNilError(err error) bool {
	if err == nil {
		return false
	}
	for _, part := range genesisMDBXCauses(err) {
		if part == nil {
			return true
		}
		if wrapped, ok := part.(interface{ Unwrap() error }); ok && genesisMDBXNilError(wrapped.Unwrap()) {
			return true
		}
	}
	return false
}

func genesisMDBXErrorResult(err error, step string) string {
	switch e := err.(type) { //nolint:errorlint // Classify only this cause before traversing the next source-ordered cause.
	case *logicalStateFailure:
		return genesisMDBXLogicalResult(e, step)
	case *TxError:
		if e != nil {
			return "CONSENSUS_INVALID"
		}
	case *mdbx.EngineError:
		return genesisMDBXEngineResult(e, step)
	case interface{ Unwrap() error }:
		return genesisMDBXUncrossed(e.Unwrap(), step, mdbx.UpdateStagePrewrite)
	}
	if step == "STALE_LOCAL_PLAN" && err != nil {
		return step
	}
	return genesisMDBXInvariant
}

func genesisMDBXLogicalResult(e *logicalStateFailure, step string) string {
	if e == nil {
		return genesisMDBXInvariant
	}
	switch e.kind {
	case logicalStateFailureUnavailable:
		return genesisMDBXUncrossed(e.cause, step, mdbx.UpdateStagePrewrite)
	case logicalStateFailureStoreIntegrity:
		if e.cause != nil && !genesisMDBXNilError(e.cause) {
			return genesisMDBXIntegrity
		}
	case logicalStateFailureLocalInvariant:
		return genesisMDBXBridgeReadResult(e.cause, step)
	}
	return genesisMDBXInvariant
}

func genesisMDBXBridgeReadResult(cause error, step string) string {
	e, _ := cause.(*mdbx.EngineError) //nolint:errorlint // Only the bridge's original direct required-read cause qualifies.
	if e != nil && e.Class == mdbx.EngineTransaction && step == "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)" {
		return step
	}
	return genesisMDBXInvariant
}

func genesisMDBXEngineResult(e *mdbx.EngineError, step string) string {
	if e == nil {
		return genesisMDBXInvariant
	}
	if e.Class == mdbx.EngineIntegrity {
		return genesisMDBXIntegrity
	}
	resource := map[mdbx.EngineClass]string{mdbx.EngineCapacity: "storage_capacity", mdbx.EngineConcurrency: "storage_concurrency", mdbx.EngineTransaction: "storage_transaction", mdbx.EngineIO: "storage_io"}[e.Class]
	if resource == "" {
		return genesisMDBXInvariant
	}
	if step == "LOCAL_RESOURCE_UNAVAILABLE(state_view_read)" || step == "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)" {
		return step
	}
	return "LOCAL_RESOURCE_UNAVAILABLE(" + resource + ")"
}

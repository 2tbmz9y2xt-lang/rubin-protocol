package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

const (
	maxLogicalStateBytes        uint64 = 412_316_860_416
	minLogicalStateEntryBytes   uint64 = 56
	maxLogicalStateEntryBytes   uint64 = 65_596
	maxCreatedLogicalStateBytes uint64 = 86_545_430
)

type logicalStateFailureKind uint8

const (
	logicalStateFailureUnavailable logicalStateFailureKind = iota + 1
	logicalStateFailureStoreIntegrity
	logicalStateFailureLocalInvariant
)

type logicalStateFailure struct {
	kind  logicalStateFailureKind
	cause error
}

func (f *logicalStateFailure) Error() string { return f.cause.Error() }

type logicalStateCounters struct{ bytes, entries uint64 }

type logicalStateRowReadKind uint8

const (
	logicalStateRowPresent logicalStateRowReadKind = iota + 1
	logicalStateRowAbsent
	logicalStateRowUnavailable
	logicalStateRowStoreIntegrity
	logicalStateRowLocalInvariant
)

type logicalStateRowRead struct {
	kind  logicalStateRowReadKind
	entry UtxoEntry
	cause error
}

type logicalStateCounterReadKind uint8

const (
	logicalStateCountersPresent logicalStateCounterReadKind = iota + 1
	logicalStateCountersUnavailable
	logicalStateCountersStoreIntegrity
	logicalStateCountersLocalInvariant
)

type logicalStateCounterRead struct {
	kind     logicalStateCounterReadKind
	counters logicalStateCounters
	cause    error
}

type logicalStateView interface {
	Counters() logicalStateCounterRead
	Lookup(Outpoint) logicalStateRowRead
}

type logicalTouchedState struct {
	Outpoint     Outpoint
	FinalPresent bool
	Final        UtxoEntry
}

type logicalStateDelete struct {
	Outpoint   Outpoint
	EntryBytes uint32
}

type logicalStatePut struct {
	Outpoint Outpoint
	Entry    UtxoEntry
}

type logicalStatePlan[M any] struct {
	Deletes  []logicalStateDelete
	Puts     []logicalStatePut
	Parent   logicalStateCounters
	Result   logicalStateCounters
	Metadata M
}

type logicalStateCapRegistryRow struct {
	chainID          []byte
	activationHeight uint64
}

type validatedLogicalStateCapRegistryRow struct {
	chainID          [32]byte
	activationHeight uint64
}

type validatedLogicalStateCapRegistry struct {
	rows []validatedLogicalStateCapRegistryRow
}

func validateLogicalStateCapRegistry(rawRows []logicalStateCapRegistryRow) (validatedLogicalStateCapRegistry, error) {
	var validated validatedLogicalStateCapRegistry
	validated.rows = make([]validatedLogicalStateCapRegistryRow, len(rawRows))
	for i, raw := range rawRows {
		if len(raw.chainID) != 32 || raw.activationHeight > uint64(^uint32(0)) {
			return validatedLogicalStateCapRegistry{}, fmt.Errorf("invalid logical state cap registry row %d", i)
		}
		copy(validated.rows[i].chainID[:], raw.chainID)
		validated.rows[i].activationHeight = raw.activationHeight
		if i > 0 && bytes.Compare(validated.rows[i-1].chainID[:], validated.rows[i].chainID[:]) >= 0 {
			return validatedLogicalStateCapRegistry{}, fmt.Errorf("logical state cap registry is not strictly ordered at row %d", i)
		}
	}
	return validated, nil
}

func (r validatedLogicalStateCapRegistry) active(chainID [32]byte, height uint64) bool {
	for _, row := range r.rows {
		order := bytes.Compare(row.chainID[:], chainID[:])
		if order == 0 {
			return height >= row.activationHeight
		}
		if order > 0 {
			return false
		}
	}
	return false
}

func logicalStateEntryBytes(op Outpoint, entry UtxoEntry) []byte {
	b := make([]byte, 0, 64+len(entry.CovenantData))
	b = append(b, op.Txid[:]...)
	b = AppendU32le(b, op.Vout)
	b = AppendU64le(b, entry.Value)
	b = AppendU16le(b, entry.CovenantType)
	b = AppendCompactSize(b, uint64(len(entry.CovenantData)))
	b = append(b, entry.CovenantData...)
	b = AppendU64le(b, entry.CreationHeight)
	if entry.CreatedByCoinbase {
		return append(b, 1)
	}
	return append(b, 0)
}

func buildLogicalStatePlan[M any](height uint64, view logicalStateView, touched []logicalTouchedState, metadata M) (logicalStatePlan[M], *logicalStateFailure) {
	parent, failure := readLogicalStateCounters(height, view)
	if failure != nil {
		return logicalStatePlan[M]{}, failure
	}
	ordered, failure := prepareLogicalTouchedState(touched)
	if failure != nil {
		return logicalStatePlan[M]{}, failure
	}
	work := logicalStatePlanWork{parent: parent, result: parent}
	for _, touch := range ordered {
		entry, present, readFailure := readLogicalStateRow(height, view, touch.Outpoint)
		if readFailure != nil {
			return logicalStatePlan[M]{}, readFailure
		}
		failure = work.apply(touch, entry, present)
		if failure != nil {
			return logicalStatePlan[M]{}, failure
		}
	}
	return logicalStatePlan[M]{Deletes: work.deletes, Puts: work.puts, Parent: parent, Result: work.result, Metadata: metadata}, nil
}

func prepareLogicalTouchedState(touched []logicalTouchedState) ([]logicalTouchedState, *logicalStateFailure) {
	ordered := append([]logicalTouchedState(nil), touched...)
	sort.Slice(ordered, func(i, j int) bool { return logicalOutpointLess(ordered[i].Outpoint, ordered[j].Outpoint) })
	for i, touch := range ordered {
		if i > 0 && touch.Outpoint == ordered[i-1].Outpoint {
			return nil, localLogicalStateFailure("duplicate touched outpoint")
		}
	}
	return ordered, nil
}

func readLogicalStateCounters(height uint64, view logicalStateView) (logicalStateCounters, *logicalStateFailure) {
	if height == 0 {
		return logicalStateCounters{}, nil
	}
	if view == nil {
		return logicalStateCounters{}, localLogicalStateFailure("nil logical state view")
	}
	read := view.Counters()
	switch read.kind {
	case logicalStateCountersPresent:
		if logicalStateCountersMalformed(read, height, true) {
			return logicalStateCounters{}, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("invalid logical state counters")}
		}
		return read.counters, nil
	case logicalStateCountersUnavailable, logicalStateCountersStoreIntegrity, logicalStateCountersLocalInvariant:
		if logicalStateCountersMalformed(read, height, false) {
			return logicalStateCounters{}, localLogicalStateFailure("malformed counter read")
		}
		return logicalStateCounters{}, &logicalStateFailure{kind: logicalStateFailureKind(read.kind-logicalStateCountersUnavailable) + 1, cause: read.cause}
	default:
		return logicalStateCounters{}, localLogicalStateFailure("unknown counter read kind")
	}
}

func validLogicalStateCounterEnvelope(c logicalStateCounters, height uint64) bool {
	if c.entries == 0 {
		return c.bytes == 0
	}
	if c.entries > ^uint64(0)/maxLogicalStateEntryBytes {
		return false
	}
	return c.bytes >= c.entries*minLogicalStateEntryBytes &&
		c.bytes <= c.entries*maxLogicalStateEntryBytes &&
		c.bytes <= height*maxCreatedLogicalStateBytes
}

func readLogicalStateRow(height uint64, view logicalStateView, op Outpoint) (UtxoEntry, bool, *logicalStateFailure) {
	if height == 0 {
		return UtxoEntry{}, false, nil
	}
	read := view.Lookup(op)
	switch read.kind {
	case logicalStateRowPresent:
		if logicalStateSuccessRowMalformed(read, true) {
			return UtxoEntry{}, false, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("invalid present logical state row")}
		}
		return read.entry, true, nil
	case logicalStateRowAbsent:
		if logicalStateSuccessRowMalformed(read, false) {
			return UtxoEntry{}, false, &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("invalid absent logical state row")}
		}
		return UtxoEntry{}, false, nil
	case logicalStateRowUnavailable, logicalStateRowStoreIntegrity, logicalStateRowLocalInvariant:
		if logicalStateFailedRowMalformed(read) {
			return UtxoEntry{}, false, localLogicalStateFailure("malformed row read")
		}
		return UtxoEntry{}, false, &logicalStateFailure{kind: logicalStateFailureKind(read.kind - logicalStateRowUnavailable + 1), cause: read.cause}
	default:
		return UtxoEntry{}, false, localLogicalStateFailure("unknown row read kind")
	}
}

type logicalStatePlanWork struct {
	deletes  []logicalStateDelete
	puts     []logicalStatePut
	parent   logicalStateCounters
	result   logicalStateCounters
	oldBytes uint64
	oldCount uint64
	putBytes uint64
}

func (w *logicalStatePlanWork) apply(touch logicalTouchedState, old UtxoEntry, oldPresent bool) *logicalStateFailure {
	entryBytes := logicalStateEntryLength(old)
	if logicalStateParentInsufficient(w, entryBytes, oldPresent) {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("parent counters are insufficient for present rows")}
	}
	if failure := logicalStateFinalFailure(touch); failure != nil {
		return failure
	}
	if oldPresent {
		if entryBytes > uint64(^uint32(0)) {
			return localLogicalStateFailure("logical state DELETE length exceeds uint32")
		}
		w.oldCount++
		w.oldBytes += entryBytes
		if logicalStateEntriesEqual(old, touch.Final, touch.FinalPresent) {
			return nil
		}
		w.result.entries--
		w.result.bytes -= entryBytes
		w.deletes = append(w.deletes, logicalStateDelete{Outpoint: touch.Outpoint, EntryBytes: uint32(entryBytes)})
	}
	if touch.FinalPresent {
		entryBytes := logicalStateEntryLength(touch.Final)
		if logicalStatePutOverflow(w, entryBytes) {
			return localLogicalStateFailure("derived logical state counters exceed bounds")
		}
		w.putBytes += entryBytes
		w.result.bytes += entryBytes
		w.result.entries++
		w.puts = append(w.puts, logicalStatePut{Outpoint: touch.Outpoint, Entry: cloneUtxoEntry(touch.Final)})
	}
	return nil
}

type logicalStateCapResult[M any] struct {
	active bool
	plan   logicalStatePlan[M]
}

func evaluateLogicalStateCap[M any](prior *TxError, registry validatedLogicalStateCapRegistry, chainID [32]byte, height uint64, view logicalStateView, touched []logicalTouchedState, metadata M) (logicalStateCapResult[M], error) {
	if prior != nil {
		return logicalStateCapResult[M]{}, prior
	}
	if !registry.active(chainID, height) {
		return logicalStateCapResult[M]{}, nil
	}
	plan, failure := buildLogicalStatePlan(height, view, touched, metadata)
	if failure != nil {
		return logicalStateCapResult[M]{}, failure
	}
	if (plan.Parent.bytes <= maxLogicalStateBytes && plan.Result.bytes > maxLogicalStateBytes) ||
		(plan.Parent.bytes > maxLogicalStateBytes && plan.Result.bytes > plan.Parent.bytes) {
		return logicalStateCapResult[M]{}, txerr(BLOCK_ERR_STATE_CAP_EXCEEDED, "logical state cap exceeded")
	}
	return logicalStateCapResult[M]{active: true, plan: plan}, nil
}

func logicalOutpointLess(a, b Outpoint) bool {
	if order := bytes.Compare(a.Txid[:], b.Txid[:]); order != 0 {
		return order < 0
	}
	return a.Vout < b.Vout
}

func logicalStateEntryLength(entry UtxoEntry) uint64 {
	return 55 + compactSizeLen(uint64(len(entry.CovenantData))) + uint64(len(entry.CovenantData))
}

func logicalStateEntryZero(entry UtxoEntry) bool {
	return entry.Value == 0 && entry.CovenantType == 0 && len(entry.CovenantData) == 0 && entry.CreationHeight == 0 && !entry.CreatedByCoinbase
}

func logicalStateEntriesEqual(a, b UtxoEntry, present bool) bool {
	return present && a.Value == b.Value && a.CovenantType == b.CovenantType && bytes.Equal(a.CovenantData, b.CovenantData) &&
		a.CreationHeight == b.CreationHeight && a.CreatedByCoinbase == b.CreatedByCoinbase
}

func localLogicalStateFailure(message string) *logicalStateFailure {
	return &logicalStateFailure{kind: logicalStateFailureLocalInvariant, cause: errors.New(message)}
}

func logicalStateCountersMalformed(r logicalStateCounterRead, h uint64, present bool) bool {
	return present && (r.cause != nil || !validLogicalStateCounterEnvelope(r.counters, h)) || !present && (r.cause == nil || r.counters != (logicalStateCounters{}))
}

func logicalStateSuccessRowMalformed(r logicalStateRowRead, present bool) bool {
	return r.cause != nil || present && len(r.entry.CovenantData) > MAX_COVENANT_DATA_PER_OUTPUT || !present && !logicalStateEntryZero(r.entry)
}

func logicalStateFailedRowMalformed(r logicalStateRowRead) bool {
	return r.cause == nil || !logicalStateEntryZero(r.entry)
}

func logicalStateFinalFailure(t logicalTouchedState) *logicalStateFailure {
	if !t.FinalPresent && !logicalStateEntryZero(t.Final) || t.FinalPresent && len(t.Final.CovenantData) > MAX_COVENANT_DATA_PER_OUTPUT {
		return localLogicalStateFailure("invalid logical state plan mutation")
	}
	return nil
}

func logicalStateParentInsufficient(w *logicalStatePlanWork, n uint64, present bool) bool {
	return present && (w.oldCount >= w.parent.entries || n > w.parent.bytes-w.oldBytes)
}

func logicalStatePutOverflow(w *logicalStatePlanWork, n uint64) bool {
	return n > maxCreatedLogicalStateBytes-w.putBytes || w.result.bytes > ^uint64(0)-n || w.result.entries == ^uint64(0)
}

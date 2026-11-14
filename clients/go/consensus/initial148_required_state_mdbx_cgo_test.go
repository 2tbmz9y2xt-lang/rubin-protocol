//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func irRequestV1(height uint64, salt byte) blockTreeRequestV1 {
	return irEventsRequestV1(height, salt, 1)
}

func irEventsRequestV1(height uint64, salt byte, events int) blockTreeRequestV1 {
	frames := make([][]byte, events)
	for i := range frames {
		frames[i] = btFrame(17, 0, []byte{salt})
	}
	tx := btTransaction(uint64(salt), 0, nil, frames, nil, []byte{0}, nil)
	r := btRequest(btBody(148, salt, [32]byte{}, tx), height)
	r.Kind, r.Undo = 1, 2
	return r
}

func irPrepareV1(t *testing.T, reader *mdbx.Reader, account *mdbx.OperationAccount, request blockTreeRequestV1, parent mdbx.TreeEndpointV1) initial148RequiredRequestV1 {
	t.Helper()
	source := new(blockTreeSourceV1)
	effect, err := prepareBlockTreeEffectV1(source, reader, account, request)
	logicalMDBXAssert(t, err == nil, "required source preparation: %v", err)
	return initial148RequiredRequestV1{Source: *source, Primitive: effect.Primitive, Parent: parent}
}

func irRunV1(t *testing.T, w *btWorld, request blockTreeRequestV1, parent mdbx.TreeEndpointV1, use func(logicalStateView, func() initial148RootReadOutcomeV1) error) error {
	t.Helper()
	result, outer := irObservedV1(t, w, request, parent, use)
	logicalMDBXAssert(t, any(outer) == any(result) || result != nil && errors.Is(outer, result), "outer View lost producer result: %v/%v", outer, result)
	return result
}

func irObservedV1(t *testing.T, w *btWorld, request blockTreeRequestV1, parent mdbx.TreeEndpointV1, use func(logicalStateView, func() initial148RootReadOutcomeV1) error) (error, error) {
	t.Helper()
	var result, outer error
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		outer = w.s.View(func(reader *mdbx.Reader) error {
			captured := irPrepareV1(t, reader, account, request, parent)
			result = withInitial148RequiredStateV1(reader, account, captured, use)
			return result
		})
		return nil
	})
	logicalMDBXAssert(t, err == nil, "required operation: %v", err)
	btReservationsReleased(t, w.owner)
	return result, outer
}

func irCounterV1(t *testing.T, w *btWorld, total, count uint64) {
	t.Helper()
	value := binary.BigEndian.AppendUint64(nil, total)
	value = binary.BigEndian.AppendUint64(value, count)
	row := btMutation(0, btMeta(0x10, 1), value)
	row.BeforePresent = true
	w.pair(t, row)
}

func irFailureV1(t *testing.T, err error, kind logicalStateFailureKind, text string) {
	t.Helper()
	var failure *logicalStateFailure
	logicalMDBXAssert(t, errors.As(err, &failure) && failure.kind == kind && failure.cause.Error() == text, "required failure %T %v, want %d/%s", err, err, kind, text)
}

func TestInitial148RequiredR(t *testing.T) {
	t.Run("full-record-and-decoder-ownership", func(t *testing.T) {
		for _, tc := range []struct {
			size     int
			length   uint32
			value    uint64
			covenant uint16
			height   uint64
		}{
			{0, 56, 0, 0, 0}, {1, 57, 37, 1, 99}, {252, 308, 37, 1, 99}, {253, 311, 37, 1, 99}, {65536, 65596, ^uint64(0), ^uint16(0), ^uint64(0)},
		} {
			for _, coinbase := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/coinbase-%v", tc.size, coinbase), func(t *testing.T) {
					size := tc.size
					w := btNew(t)
					op := Outpoint{Txid: [32]byte{42}, Vout: 7}
					frame := btFrame(tc.value, tc.covenant, bytes.Repeat([]byte{5}, size))
					value := btValue(frame, tc.height, coinbase)
					w.pair(t, btMutation(1, btUTXOKey(1, op), value))
					irCounterV1(t, w, uint64(tc.length), 1)
					err := irRunV1(t, w, irRequestV1(1, 2), mdbx.TreeEndpointV1{Kind: 1, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
						first := view.Lookup(op)
						logicalMDBXAssert(t, first.kind == logicalStateRowPresent && first.cause == nil && first.entry.Value == tc.value && first.entry.CovenantType == tc.covenant && first.entry.CreationHeight == tc.height && first.entry.CreatedByCoinbase == coinbase && bytes.Equal(first.entry.CovenantData, bytes.Repeat([]byte{5}, size)), "full decoded record lost a field")
						scope := view.(*initial148RequiredScopeV1)
						length, present, ok := scope.recordedV1(op)
						logicalMDBXAssert(t, ok && present && length == tc.length && len(scope.keys) == 1, "literal recorded length: %d/%v/%v", length, present, ok)
						if size != 0 {
							first.entry.CovenantData[0] = 9
						}
						logicalMDBXAssert(t, bytes.Equal(value, btValue(frame, tc.height, coinbase)), "decoded entry borrowed caller value")
						counter := view.Counters()
						logicalMDBXAssert(t, counter.kind == logicalStateCountersPresent && counter.counters == (logicalStateCounters{bytes: uint64(tc.length), entries: 1}), "record changed parent counters")
						return nil
					})
					logicalMDBXAssert(t, err == nil, "first R record refused: %v", err)
				})
			}
		}
	})
	t.Run("absent-repeat", func(t *testing.T) {
		w := btNew(t)
		err := irRunV1(t, w, irRequestV1(1, 3), mdbx.TreeEndpointV1{Kind: 1, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
			for range 2 {
				row := view.Lookup(Outpoint{Txid: [32]byte{99}})
				logicalMDBXAssert(t, row.kind == logicalStateRowAbsent && logicalStateEntryZero(row.entry) && row.cause == nil, "definitive absence changed")
			}
			logicalMDBXAssert(t, view.Counters().counters == (logicalStateCounters{}), "zero counters changed")
			return nil
		})
		logicalMDBXAssert(t, err == nil, "absent repeat: %v", err)
	})
	t.Run("distinct-residual-checkpoints", irResidualV1)
	t.Run("accumulated-distinct-residual", irDistinctResidualV1)
	t.Run("recorded-growth-boundary", irRecordedGrowthV1)
	t.Run("recorded-comparison-is-not-sticky", irRecordedRefusalV1)
	t.Run("distinct-fact-bound", func(t *testing.T) {
		w := btNew(t)
		var first error
		err := irRunV1(t, w, irRequestV1(0, 63), mdbx.TreeEndpointV1{}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
			logicalMDBXAssert(t, view.Lookup(Outpoint{}).kind == logicalStateRowAbsent, "first fact refused")
			first = view.Lookup(Outpoint{Vout: 1}).cause
			irFailureV1(t, first, logicalStateFailureLocalInvariant, "required state fact bound exceeded")
			logicalMDBXAssert(t, any(view.Counters().cause) == any(first), "fact bound lost sticky cause")
			return nil
		})
		logicalMDBXAssert(t, any(err) == any(first), "callback dropped fact-bound cause")
	})
}

func irRecordedRefusalV1(t *testing.T) {
	w := btNew(t)
	op := Outpoint{Txid: [32]byte{93}}
	w.pair(t, btMutation(1, btUTXOKey(1, op), btValue(btFrame(1, 0, []byte{3}), 0, false)))
	irCounterV1(t, w, 57, 1)
	err := irRunV1(t, w, irRequestV1(6, 64), mdbx.TreeEndpointV1{Kind: 1, Height: 5, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
		entry := view.Lookup(op)
		logicalMDBXAssert(t, entry.kind == logicalStateRowPresent, "comparison input resolution")
		_, failure := buildLogicalStatePlan(6, view, []logicalTouchedState{{Outpoint: op, FinalPresent: true, Final: entry.entry}}, 0)
		irFailureV1(t, failure, logicalStateFailureLocalInvariant, "recorded parent row cannot be compared with its final entry")
		scope := view.(*initial148RequiredScopeV1)
		length, present, known := scope.recordedV1(op)
		logicalMDBXAssert(t, scope.first == nil && scope.calls == 1 && length == 57 && present && known && view.Counters().cause == nil, "plan refusal poisoned scope")
		return nil
	})
	logicalMDBXAssert(t, err == nil, "comparison refusal escaped callback as sticky error: %v", err)
}

func irRecordedGrowthV1(t *testing.T) {
	for _, extra := range []int{0, 1} {
		w := btNew(t)
		op := Outpoint{Txid: [32]byte{70}}
		w.pair(t, btMutation(1, btUTXOKey(1, op), btValue(btFrame(1, 0, []byte{1}), 0, false)))
		irCounterV1(t, w, 57, 1)
		touched := []logicalTouchedState{{Outpoint: op}}
		for i := range 12 {
			size := 65536
			if i == 11 {
				size = 51563 + extra // 11*65596 + (58+51563) - 57 = 773120.
			}
			touched = append(touched, logicalTouchedState{Outpoint: Outpoint{Txid: [32]byte{byte(i + 71)}}, FinalPresent: true, Final: logicalStateTestEntry(size, 3)})
		}
		err := irRunV1(t, w, irEventsRequestV1(6, 62, 13), mdbx.TreeEndpointV1{Kind: 1, Height: 5, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
			logicalMDBXAssert(t, view.Lookup(op).kind == logicalStateRowPresent, "growth input resolution")
			registry, registryErr := validateLogicalStateCapRegistry(nil)
			logicalMDBXAssert(t, registryErr == nil, "growth registry")
			out, planErr := evaluateLogicalStateCap(nil, registry, [32]byte{}, 6, view, touched, 0)
			if extra == 0 {
				logicalMDBXAssert(t, planErr == nil && out.plan.Parent == (logicalStateCounters{bytes: 57, entries: 1}) && out.plan.Result == (logicalStateCounters{bytes: 773177, entries: 12}) && reflect.DeepEqual(out.plan.Deletes, []logicalStateDelete{{Outpoint: op, EntryBytes: 57}}), "record growth equality: %+v/%v", out.plan, planErr)
			} else {
				var tx *TxError
				logicalMDBXAssert(t, errors.As(planErr, &tx) && tx.Code == BLOCK_ERR_STATE_GROWTH_EXCEEDED && tx.Msg == "logical state growth exceeded", "record growth plus one: %v", planErr)
			}
			return nil
		})
		logicalMDBXAssert(t, err == nil, "growth record scope: %v", err)
	}
}

func irDistinctResidualV1(t *testing.T) {
	for _, total := range []uint64{200, 210} {
		for _, counterFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("total-%d/counter-first-%v", total, counterFirst), func(t *testing.T) {
				irDistinctResidualCaseV1(t, total, counterFirst)
			})
		}
	}
}

func irDistinctResidualCaseV1(t *testing.T, total uint64, counterFirst bool) {
	w := btNew(t)
	ops := [2]Outpoint{{Txid: [32]byte{61}}, {Txid: [32]byte{62}}}
	for i, size := range []int{44, 54} {
		value := btValue(btFrame(uint64(i+1), 0, bytes.Repeat([]byte{3}, size)), 0, true)
		logicalMDBXAssert(t, len(value)+36 == 100+10*i, "distinct row size differs")
		w.pair(t, btMutation(1, btUTXOKey(1, ops[i]), value))
	}
	irCounterV1(t, w, total, 2)
	tx := btTransaction(63, 0, nil, [][]byte{btFrame(1, 0, nil), btFrame(2, 0, nil)}, nil, []byte{0}, nil)
	request := btRequest(btBody(148, 63, [32]byte{}, tx), 1)
	request.Kind, request.Undo = 1, 2
	var failure error
	err := irRunV1(t, w, request, mdbx.TreeEndpointV1{Kind: 1, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
		failure = irAccumulateResidualV1(t, view, derive, ops, total, counterFirst)
		return nil // The producer must retain a refusal ignored by its callback.
	})
	logicalMDBXAssert(t, any(err) == any(failure), "accumulated residual primary replaced: %v/%v", err, failure)
	next := irRunV1(t, w, request, mdbx.TreeEndpointV1{Kind: 1, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
		logicalMDBXAssert(t, view.Lookup(ops[0]).kind == logicalStateRowPresent, "next scope lost first row")
		logicalMDBXAssert(t, view.Counters().kind == logicalStateCountersPresent, "next scope retained prior failure")
		return nil
	})
	logicalMDBXAssert(t, next == nil, "clean next scope refused: %v", next)
}

func irAccumulateResidualV1(t *testing.T, view logicalStateView, derive func() initial148RootReadOutcomeV1, ops [2]Outpoint, total uint64, counterFirst bool) error {
	t.Helper()
	if counterFirst {
		counter := view.Counters()
		logicalMDBXAssert(t, counter.kind == logicalStateCountersPresent && counter.counters == (logicalStateCounters{bytes: total, entries: 2}), "record-valid counter refused: %v", counter.cause)
	}
	first := view.Lookup(ops[0])
	logicalMDBXAssert(t, first.kind == logicalStateRowPresent && first.cause == nil && len(first.entry.CovenantData) == 44, "first distinct checkpoint refused")
	second := view.Lookup(ops[1])
	failure := second.cause
	if !counterFirst {
		logicalMDBXAssert(t, second.kind == logicalStateRowPresent && second.cause == nil && len(second.entry.CovenantData) == 54, "rows-before-counter checkpoint refused")
		failure = view.Counters().cause
	}
	if total == 210 {
		logicalMDBXAssert(t, second.kind == logicalStateRowPresent && failure == nil, "exact-zero accumulated residual refused: %v", failure)
		logicalMDBXAssert(t, view.Counters().counters == (logicalStateCounters{bytes: 210, entries: 2}), "accepted counter changed")
		return nil
	}
	irFailureV1(t, failure, logicalStateFailureStoreIntegrity, "required subset exceeds parent counters")
	logicalMDBXAssert(t, any(view.Lookup(ops[0]).cause) == any(failure) && any(view.Counters().cause) == any(failure), "accumulated first cause replaced")
	out := derive()
	logicalMDBXAssert(t, any(out.cause) == any(failure) && !out.derived && out.root == ([32]byte{}) && !out.hasObservation, "accumulated refusal produced root/localization")
	return failure
}

func irResidualV1(t *testing.T) {
	for _, tc := range []struct {
		name         string
		total, count uint64
		valid        bool
	}{
		{"zero-residual", 56, 1, true},
		{"lower", 112, 2, true},
		{"upper", 65652, 2, true},
		{"lower-minus-one", 112, 2, false},
		{"upper-plus-one", 65653, 2, false},
		{"count-exceeded", 0, 0, false},
		{"bytes-exceeded", 56, 1, false},
		{"zero-count-nonzero-residual", 57, 1, false},
	} {
		for _, counterFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/counter-first-%v", tc.name, counterFirst), func(t *testing.T) {
				w := btNew(t)
				op := Outpoint{Txid: [32]byte{1}}
				var data []byte
				if tc.name == "lower-minus-one" || tc.name == "bytes-exceeded" {
					data = []byte{1}
				}
				w.pair(t, btMutation(1, btUTXOKey(1, op), btValue(btFrame(1, 0, data), 0, true)))
				irCounterV1(t, w, tc.total, tc.count)
				var failure error
				err := irRunV1(t, w, irRequestV1(1, 7), mdbx.TreeEndpointV1{Kind: 1, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
					if counterFirst {
						counter := view.Counters()
						failure = counter.cause
					}
					if failure == nil {
						row := view.Lookup(op)
						failure = row.cause
					}
					if !counterFirst && failure == nil {
						failure = view.Counters().cause
					}
					logicalMDBXAssert(t, (failure == nil) == tc.valid, "residual checkpoint = %v", failure)
					if failure != nil {
						var logical *logicalStateFailure
						logicalMDBXAssert(t, errors.As(failure, &logical) && logical.kind == logicalStateFailureStoreIntegrity, "residual class %v", failure)
						want := "invalid required residual counters"
						if tc.name == "count-exceeded" || tc.name == "bytes-exceeded" {
							want = "required subset exceeds parent counters"
						}
						logicalMDBXAssert(t, logical.cause.Error() == want, "residual owning checkpoint %v, want %s", failure, want)
						out := derive()
						logicalMDBXAssert(t, any(out.cause) == any(failure) && !out.derived && out.root == ([32]byte{}), "residual refusal reached D")
					}
					return failure
				})
				logicalMDBXAssert(t, any(err) == any(failure), "residual primary replaced")
			})
		}
	}
}

func TestInitial148RequiredOrigin(t *testing.T) {
	t.Run("reversed-interleaved-inputs", irInputOrderV1)
	t.Run("genesis-literal-root", func(t *testing.T) {
		w := btNew(t)
		request := irRequestV1(0, 19)
		tx := btTransaction(19, 0, nil, [][]byte{btFrame(17, 0, []byte{19})}, nil, []byte{0}, nil)
		value := btValue(tx.frames[0], 0, true)
		var input bytes.Buffer
		input.WriteString("RUBIN_UTXO_TREE_V1\x01")
		input.Write(tx.id[:])
		input.Write([]byte{0, 0, 0, 0})
		input.Write(value)
		want := sha3.Sum256(input.Bytes())
		err := irRunV1(t, w, request, mdbx.TreeEndpointV1{}, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
			logicalMDBXAssert(t, view.Counters().counters == (logicalStateCounters{}), "genesis parent counters")
			out := derive()
			logicalMDBXAssert(t, out.derived && out.cause == nil && !out.hasObservation && out.root == want && out.root != sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")), "genesis computed root %x want%x cause%v", out.root, want, out.cause)
			return out.cause
		})
		logicalMDBXAssert(t, err == nil, "genesis derivation: %v", err)
	})
	t.Run("parent-input-versus-in-block", irOriginsV1)
	t.Run("captured-source-identity", func(t *testing.T) {
		for _, variant := range []string{"unchanged", "coverage", "backing"} {
			t.Run(variant, func(t *testing.T) {
				w := btNew(t)
				logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
					return w.s.View(func(reader *mdbx.Reader) error {
						request := irPrepareV1(t, reader, account, irRequestV1(0, 50), mdbx.TreeEndpointV1{})
						source := request.Primitive.Source.(*blockTreeSourceV1)
						var failure error
						result := withInitial148RequiredStateV1(reader, account, request, func(_ logicalStateView, derive func() initial148RootReadOutcomeV1) error {
							if variant == "coverage" {
								source.coverage.BlockMeta.EventCount++
							}
							if variant == "backing" {
								source.Raw = bytes.Clone(source.Raw)
							}
							out := derive()
							failure = out.cause
							if variant == "unchanged" {
								logicalMDBXAssert(t, out.derived && failure == nil && !out.hasObservation, "unchanged captured source refused")
							} else {
								logicalMDBXAssert(t, !out.derived && out.root == ([32]byte{}) && !out.hasObservation, "changed source produced root/localization")
								irFailureV1(t, failure, logicalStateFailureLocalInvariant, "invalid required state request")
							}
							return failure
						})
						logicalMDBXAssert(t, any(result) == any(failure), "source identity failure replaced")
						return nil
					})
				}) == nil, "source identity operation")
				btReservationsReleased(t, w.owner)
			})
		}
	})
	t.Run("earlier-consensus-error", func(t *testing.T) {
		w := btNew(t)
		primary := txerr(TX_ERR_MISSING_UTXO, "earlier established rejection")
		err := irRunV1(t, w, irRequestV1(6, 20), mdbx.TreeEndpointV1{Kind: 1, Height: 5, CumulativeChainwork: [40]byte{39: 1}}, func(logicalStateView, func() initial148RootReadOutcomeV1) error { return primary })
		logicalMDBXAssert(t, any(err) == any(primary), "earlier consensus error replaced by later parent read")
	})
}

func irOriginsV1(t *testing.T) {
	for _, origin := range []string{"parent-recorded", "parent-unresolved", "in-block"} {
		t.Run(origin, func(t *testing.T) {
			w := btNew(t)
			seedTx := btTransaction(31, 0, nil, [][]byte{btFrame(9, 0, nil)}, nil, []byte{0}, nil)
			seed := btRequest(btBody(148, 31, [32]byte{}, seedTx), 3)
			seedResult, _, _ := w.run(t, []blockTreeRequestV1{seed}, nil)
			logicalMDBXAssert(t, seedResult.err == nil, "origin seed: %v", seedResult.err)
			op := Outpoint{Txid: seedTx.id}
			coinbase := btTransaction(32, 0, nil, [][]byte{btFrame(10, 0, nil)}, nil, []byte{0}, nil)
			if origin == "in-block" {
				op = Outpoint{Txid: coinbase.id}
			}
			spend := btTransaction(33, 0, []Outpoint{op}, [][]byte{btFrame(11, 0, nil)}, nil, []byte{0}, nil)
			request := btRequest(btBody(148, 32, seed.Block, coinbase, spend), 4)
			request.Kind, request.Undo = 1, 2
			err := irRunV1(t, w, request, seed.Endpoint, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
				if origin == "parent-recorded" {
					logicalMDBXAssert(t, view.Lookup(op).kind == logicalStateRowPresent, "original resolution failed")
				}
				out := derive()
				logicalMDBXAssert(t, out.derived == (origin != "parent-unresolved"), "origin %s outcome %+v", origin, out)
				if origin == "parent-unresolved" {
					var engine *mdbx.EngineError
					logicalMDBXAssert(t, out.root == ([32]byte{}) && errors.As(out.cause, &engine) && engine.Class == mdbx.EngineIntegrity && !out.hasObservation, "unresolved original became usable root")
				}
				return out.cause
			})
			logicalMDBXAssert(t, (err == nil) == (origin != "parent-unresolved"), "origin result %v", err)
		})
	}
}

func TestInitial148RequiredScope(t *testing.T) {
	t.Run("early-native-admission", irAdmissionV1)
	t.Run("request-shapes", irShapesV1)
	t.Run("last-use-and-one-shot", irLifetimeV1)
	t.Run("capacity-before-callback", irCapacityV1)
	t.Run("callback-delivery", irDeliveryV1)
	t.Run("concurrent-independent-scopes", irConcurrentV1)
	t.Run("clean-Reader-reuse", irReusableV1)
	t.Run("record-size", irRecordSizeV1)
}

func irRecordSizeV1(t *testing.T) {
	w := btNew(t)
	err := irRunV1(t, w, irEventsRequestV1(0, 57, 7), mdbx.TreeEndpointV1{}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
		scope := view.(*initial148RequiredScopeV1)
		fields, held := 0, uintptr(0)
		value := reflect.ValueOf(scope).Elem()
		for i := range value.NumField() {
			field := value.Field(i)
			if field.Kind() == reflect.Slice {
				fields++
				element := field.Type().Elem()
				logicalMDBXAssert(t, element == reflect.TypeFor[mdbx.TreeOutpointV1]() || element == reflect.TypeFor[uint32](), "record retains another slice type: %v", element)
				held += uintptr(field.Cap()) * element.Size()
			}
		}
		logicalMDBXAssert(t, fields == 2 && held == 280 && held <= 336 && cap(scope.keys) == 7 && cap(scope.lengths) == 7 && unsafe.Sizeof(*scope) < 4096, "record/fixed allowance: %d slices %d bytes", fields, held)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "record size scope: %v", err)
}

func irAdmissionAttemptV1(t *testing.T, reader *mdbx.Reader, account, funding *mdbx.OperationAccount, request initial148RequiredRequestV1, operation, diagnostic string) {
	t.Helper()
	for _, held := range []uint64{0, 402653184} {
		for _, result := range []error{nil, txerr(TX_ERR_MISSING_UTXO, "chosen callback result")} {
			logicalMDBXAssert(t, funding.WithReservation(held, func() error {
				calls := 0
				err := withInitial148RequiredStateV1(reader, account, request, func(logicalStateView, func() initial148RootReadOutcomeV1) error { calls++; return result })
				var engine *mdbx.EngineError
				logicalMDBXAssert(t, reflect.TypeOf(err) == reflect.TypeFor[*mdbx.EngineError]() && errors.As(err, &engine) && engine.Operation == operation && string(engine.Class) == "InvalidInput" && engine.Code == 22 && engine.Diagnostic == diagnostic && engine.Cause == nil && !engine.ReopenRequired && engine.TreeObservation == nil && calls == 0, "early admission tuple/callback: %v calls%d", err, calls)
				return nil
			}) == nil, "admission capacity witness setup")
		}
	}
	logicalMDBXAssert(t, funding.WithReservation(402653184, func() error { return nil }) == nil, "admission retained account backing")
}

func irAdmissionV1(t *testing.T) {
	w := btNew(t)
	foreign, err := mdbx.CreateTreeV1(filepath.Join(t.TempDir(), "foreign"), w.cfg, [32]byte{8})
	logicalMDBXAssert(t, err == nil, "foreign tree setup: %v", err)
	t.Cleanup(func() { _ = foreign.Close() })
	legacy := logicalMDBXStore(t)
	var expired *mdbx.Reader
	logicalMDBXAssert(t, w.s.View(func(r *mdbx.Reader) error { expired = r; return nil }) == nil, "expired Reader setup")
	var closed *mdbx.OperationAccount
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error { closed = a; return nil }) == nil, "closed account setup")
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			for _, height := range []uint64{0, 6} {
				parent := mdbx.TreeEndpointV1{}
				if height != 0 {
					parent = mdbx.TreeEndpointV1{Kind: 1, Height: height - 1, CumulativeChainwork: [40]byte{39: 1}}
				}
				request := irPrepareV1(t, reader, a, irRequestV1(height, 52), parent)
				for _, store := range []*mdbx.Store{foreign, legacy} {
					logicalMDBXAssert(t, store.View(func(wrong *mdbx.Reader) error {
						op, diagnostic := "update", "invalid tree delta"
						if store == legacy {
							op, diagnostic = "get", "tree Reader required"
						}
						irAdmissionAttemptV1(t, wrong, a, a, request, op, diagnostic)
						return nil
					}) == nil, "admission changed foreign Reader/Store")
				}
				irAdmissionAttemptV1(t, expired, a, a, request, "get", "Reader is not active")
				for _, invalid := range []*mdbx.OperationAccount{{}, closed} {
					irAdmissionAttemptV1(t, reader, invalid, a, request, "update", "invalid tree delta")
				}
				logicalMDBXAssert(t, w.owner.WithOperation(mdbx.LaneOperation, func(lane *mdbx.OperationAccount) error {
					irAdmissionAttemptV1(t, reader, lane, a, request, "update", "invalid tree delta")
					return nil
				}) == nil, "wrong-kind account setup")
				logicalMDBXAssert(t, withInitial148RequiredStateV1(reader, a, request, func(logicalStateView, func() initial148RootReadOutcomeV1) error { return nil }) == nil, "admission disarmed same clean Reader/account")
			}
			return nil
		})
	}) == nil, "early admission operation")
	btReservationsReleased(t, w.owner)
}

func irInputOrderV1(t *testing.T) {
	w := btNew(t)
	frames := make([][]byte, 257)
	for i := range frames {
		frames[i] = btFrame(9, 0, []byte{4})
	}
	seedTx := btTransaction(53, 0, nil, frames, nil, []byte{0}, nil)
	seed := btRequest(btBody(148, 53, [32]byte{}, seedTx), 3)
	seedResult, _, _ := w.run(t, []blockTreeRequestV1{seed}, nil)
	logicalMDBXAssert(t, seedResult.err == nil, "ordered R seed: %v", seedResult.err)
	ops := []Outpoint{{Txid: seedTx.id, Vout: 255}, {Txid: seedTx.id, Vout: 256}}
	coinbase := btTransaction(54, 0, nil, [][]byte{btFrame(10, 0, nil)}, nil, []byte{0}, nil)
	spend := btTransaction(55, 0, ops, nil, nil, []byte{0}, nil)
	request := btRequest(btBody(148, 54, seed.Block, coinbase, spend), 4)
	request.Kind, request.Undo = 1, 2
	body := bytes.Clone(request.Raw)
	entries := make(map[Outpoint]UtxoEntry)
	for i := range 255 {
		entries[Outpoint{Txid: seedTx.id, Vout: uint32(i)}] = UtxoEntry{Value: 9, CovenantData: []byte{4}, CreationHeight: 3, CreatedByCoinbase: true}
	}
	entries[Outpoint{Txid: coinbase.id}] = UtxoEntry{Value: 10, CreationHeight: 4, CreatedByCoinbase: true}
	want := canonicalUTXORoot(entries)
	err := irRunV1(t, w, request, seed.Endpoint, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
		logicalMDBXAssert(t, view.Counters().kind == logicalStateCountersPresent, "ordered R counters")
		missing := Outpoint{Txid: coinbase.id}
		for _, op := range []Outpoint{ops[1], missing, ops[0]} {
			row := view.Lookup(op)
			logicalMDBXAssert(t, row.cause == nil && (row.kind == logicalStateRowPresent) == (op != missing), "interleaved R lookup %v", row.cause)
		}
		scope := view.(*initial148RequiredScopeV1)
		backing := &scope.keys[0]
		out := derive()
		logicalMDBXAssert(t, out.derived && out.cause == nil && out.root == want, "owned input sort root%x want%x cause%v", out.root, want, out.cause)
		logicalMDBXAssert(t, &scope.keys[0] == backing && reflect.DeepEqual(scope.keys[:2], []mdbx.TreeOutpointV1{{Txid: seedTx.id, Vout: 255}, {Txid: seedTx.id, Vout: 256}}), "in-place sorted present prefix: %+v", scope.keys)
		_, _, ok := scope.recordedV1(ops[0])
		logicalMDBXAssert(t, !ok, "sealed record stayed available")
		return out.cause
	})
	logicalMDBXAssert(t, err == nil, "ordered R derivation: %v", err)
	logicalMDBXAssert(t, bytes.Equal(request.Raw, body), "descriptor sort changed captured transaction/input order")
}

func irReusableV1(t *testing.T) {
	w := btNew(t)
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			request := irPrepareV1(t, reader, account, irRequestV1(0, 49), mdbx.TreeEndpointV1{})
			application := errors.New("application stop")
			for _, previous := range []error{nil, application} {
				result := withInitial148RequiredStateV1(reader, account, request, func(logicalStateView, func() initial148RootReadOutcomeV1) error { return previous })
				logicalMDBXAssert(t, any(result) == any(previous), "application identity changed")
				result = withInitial148RequiredStateV1(reader, account, request, func(_ logicalStateView, derive func() initial148RootReadOutcomeV1) error {
					out := derive()
					logicalMDBXAssert(t, out.derived && out.cause == nil, "clean same-Reader reuse refused: %v", out.cause)
					return out.cause
				})
				logicalMDBXAssert(t, result == nil, "fresh same-Reader scope failed: %v", result)
			}
			return nil
		})
	}) == nil, "clean Reader operation")
	btReservationsReleased(t, w.owner)
}

func irCapacityV1(t *testing.T) {
	w := btNew(t)
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			request := irPrepareV1(t, reader, account, irRequestV1(0, 48), mdbx.TreeEndpointV1{})
			return account.WithReservation(402653184-135240+1, func() error {
				err := withInitial148RequiredStateV1(reader, account, request, func(logicalStateView, func() initial148RootReadOutcomeV1) error {
					t.Fatal("R capacity refusal reached callback")
					return nil
				})
				logicalMDBXAssert(t, err != nil && err.Error() == "storage operation reservation capacity unavailable", "R capacity refusal %v", err)
				return nil
			})
		})
	}) == nil, "R capacity scope")
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			request := irPrepareV1(t, reader, account, irRequestV1(0, 51), mdbx.TreeEndpointV1{})
			var cause error
			result := withInitial148RequiredStateV1(reader, account, request, func(_ logicalStateView, derive func() initial148RootReadOutcomeV1) error {
				return account.WithReservation(402653184-135240-288504+1, func() error {
					out := derive()
					cause = out.cause
					logicalMDBXAssert(t, !out.derived && out.root == ([32]byte{}) && mdbx.IsOperationReservationCapacity(cause) && !out.hasObservation && out.observation == (mdbx.TreeObservationV1{}), "D capacity outcome %+v", out)
					return nil
				})
			})
			logicalMDBXAssert(t, any(result) == any(cause), "ignored D capacity lost raw cause")
			result = withInitial148RequiredStateV1(reader, account, request, func(_ logicalStateView, derive func() initial148RootReadOutcomeV1) error {
				out := derive()
				logicalMDBXAssert(t, out.derived && out.cause == nil && !out.hasObservation, "fresh same Reader/account after capacity %+v", out)
				return out.cause
			})
			logicalMDBXAssert(t, result == nil, "capacity refusal disarmed clean Reader/account")
			return nil
		})
	}) == nil, "scoped D capacity outcome")
	btReservationsReleased(t, w.owner)
	t.Run("large-event-tariff", irLargeCapacityV1)
}

func irLargeCapacityV1(t *testing.T) {
	w := btNew(t)
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			request := irPrepareV1(t, reader, account, irEventsRequestV1(0, 58, 2046), mdbx.TreeEndpointV1{})
			logicalMDBXAssert(t, request.Source.coverage.BlockMeta.EventCount == 2046, "large event boundary changed")
			for _, extra := range []uint64{0, 1} {
				called := false
				err := account.WithReservation(402653184-233400+extra, func() error {
					return withInitial148RequiredStateV1(reader, account, request, func(logicalStateView, func() initial148RootReadOutcomeV1) error {
						called = true
						logicalMDBXAssert(t, account.WithReservation(1, func() error { t.Fatal("large R reservation too small"); return nil }) != nil, "large R retained less than literal tariff")
						return nil
					})
				})
				logicalMDBXAssert(t, called == (extra == 0) && (err == nil) == (extra == 0), "large R exact/minus-one %d: %v/%v", extra, called, err)
				if extra != 0 {
					logicalMDBXAssert(t, err.Error() == "storage operation reservation capacity unavailable", "large R refusal: %v", err)
				}
			}
			return nil
		})
	}) == nil, "large R capacity scope")
	btReservationsReleased(t, w.owner)
}

func irShapesV1(t *testing.T) {
	variants := []string{"nil-reader", "nil-account", "nil-callback", "nil-source", "foreign-source", "nil-coverage", "raw-copy", "raw-length", "coverage-backing", "database", "generation", "block", "height", "header", "body-kind", "meta", "direction", "kind", "undo", "endpoint", "parent", "multiple-invalid", "invalid-shape-inactive"}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			w := btNew(t)
			logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
				return w.s.View(func(reader *mdbx.Reader) error {
					captured := irPrepareV1(t, reader, a, irRequestV1(0, 21), mdbx.TreeEndpointV1{})
					callback := func(logicalStateView, func() initial148RootReadOutcomeV1) error {
						t.Fatal("invalid wrapper reached callback")
						return nil
					}
					switch variant {
					case "nil-reader":
						reader = nil
					case "nil-account":
						a = nil
					case "nil-callback":
						callback = nil
					case "nil-source":
						captured.Primitive.Source = (*blockTreeSourceV1)(nil)
					case "foreign-source":
						captured.Primitive.Source = &btObserved{t: t, source: captured.Primitive.Source.(*blockTreeSourceV1)}
					case "nil-coverage":
						captured.Primitive.Coverage = nil
					case "raw-copy":
						captured.Source.Raw = bytes.Clone(captured.Source.Raw)
					case "raw-length":
						captured.Source.Raw = captured.Source.Raw[:len(captured.Source.Raw)-1]
					case "coverage-backing":
						captured.Source.coverage.CurrentBody = bytes.Clone(captured.Source.Raw)
					case "database":
						captured.Source.coverage.DatabaseID[0]++
					case "generation":
						captured.Primitive.Generation++
					case "block":
						captured.Primitive.Block[0]++
					case "height":
						captured.Primitive.Height++
					case "header":
						captured.Source.coverage.HeaderBytes = 116
					case "body-kind":
						captured.Source.coverage.BodyKind = 2
					case "meta":
						captured.Source.coverage.BlockMeta.EventCount++
					case "direction":
						captured.Primitive.Direction = 2
					case "kind":
						captured.Primitive.Kind = 2
					case "undo":
						captured.Primitive.Undo = 1
					case "endpoint":
						captured.Primitive.Endpoint.BlockHash[0]++
					case "parent":
						captured.Parent.Kind = 1
					case "multiple-invalid":
						captured.Source.Raw = nil
						captured.Primitive.Coverage = nil
					case "invalid-shape-inactive":
						reader = &mdbx.Reader{}
						captured.Source.Raw = nil
					}
					err := withInitial148RequiredStateV1(reader, a, captured, callback)
					irFailureV1(t, err, logicalStateFailureLocalInvariant, "invalid required state request")
					return nil
				})
			}) == nil, "shape operation")
			btReservationsReleased(t, w.owner)
		})
	}
}

func irLifetimeV1(t *testing.T) {
	w := btNew(t)
	var kept logicalStateView
	var derive func() initial148RootReadOutcomeV1
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			captured := irPrepareV1(t, reader, a, irRequestV1(0, 22), mdbx.TreeEndpointV1{})
			return withInitial148RequiredStateV1(reader, a, captured, func(view logicalStateView, root func() initial148RootReadOutcomeV1) error {
				kept, derive = view, root
				logicalMDBXAssert(t, a.WithReservation(402653184-135240, func() error { return nil }) == nil, "exact R reservation refused")
				logicalMDBXAssert(t, a.WithReservation(402653184-135240+1, func() error { t.Fatal("R allowance omitted records or transient backing"); return nil }) != nil, "R reservation too small")
				out := root()
				logicalMDBXAssert(t, out.derived && out.cause == nil, "first derive: %v", out.cause)
				logicalMDBXAssert(t, a.WithReservation(402653184-135240+1, func() error { t.Fatal("R released before final callback consumer"); return nil }) != nil, "R last use uncharged")
				second := root()
				logicalMDBXAssert(t, !second.derived && second.root == ([32]byte{}), "second derive returned root")
				irFailureV1(t, second.cause, logicalStateFailureLocalInvariant, "required root derive is not available")
				irFailureV1(t, view.Counters().cause, logicalStateFailureLocalInvariant, "required state scope is not active")
				_, _, known := view.(*initial148RequiredScopeV1).recordedV1(Outpoint{})
				_, failure := readLogicalStatePlanRow(1, view, Outpoint{})
				logicalMDBXAssert(t, !known && failure != nil && failure.kind == logicalStateFailureLocalInvariant && failure.cause.Error() == "required state scope is not active", "sealed record fallback changed")
				return nil
			})
		})
	})
	logicalMDBXAssert(t, err == nil, "lifetime operation: %v", err)
	irFailureV1(t, kept.Lookup(Outpoint{}).cause, logicalStateFailureLocalInvariant, "required state scope is not active")
	irFailureV1(t, derive().cause, logicalStateFailureLocalInvariant, "required root derive is not available")
	scope := kept.(*initial148RequiredScopeV1)
	_, _, known := scope.recordedV1(Outpoint{})
	logicalMDBXAssert(t, !known && scope.calls == 0 && scope.keys == nil && scope.lengths == nil, "expired scope retained records or counted lookup")
	btReservationsReleased(t, w.owner)
}

func irDeliveryV1(t *testing.T) {
	for _, delivery := range []string{"nil", "error", "panic", "goexit"} {
		for _, withFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure-%v", delivery, withFailure), func(t *testing.T) {
				w := btNew(t)
				primary, panicValue := errors.New("callback application error"), new(int)
				var result, failure error
				var recovered any
				var kept logicalStateView
				var root func() initial148RootReadOutcomeV1
				post := false
				run := func() {
					defer func() { recovered = recover() }()
					result = irRunV1(t, w, irRequestV1(0, 23), mdbx.TreeEndpointV1{}, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
						kept, root = view, derive
						if withFailure {
							for range 3 {
								failure = view.Lookup(Outpoint{}).cause
							}
							logicalMDBXAssert(t, failure != nil, "bounded point failure missing")
						}
						switch delivery {
						case "error":
							return primary
						case "panic":
							panic(panicValue)
						case "goexit":
							runtime.Goexit()
						}
						return nil
					})
					post = true
				}
				if delivery == "goexit" {
					done := make(chan struct{})
					go func() { defer close(done); run() }()
					<-done
				} else {
					run()
				}
				if delivery == "panic" {
					logicalMDBXAssert(t, recovered == panicValue && !post, "original panic was changed")
				}
				if delivery == "goexit" {
					logicalMDBXAssert(t, !post, "Goexit continued")
				}
				if delivery == "nil" && withFailure {
					logicalMDBXAssert(t, any(result) == any(failure), "ignored first failure lost")
				}
				if delivery == "nil" && !withFailure {
					logicalMDBXAssert(t, result == nil, "clean callback refused")
				}
				if delivery == "error" && !withFailure {
					logicalMDBXAssert(t, any(result) == any(primary), "application error identity changed")
				}
				if delivery == "error" && withFailure {
					joined, ok := result.(interface{ Unwrap() []error })
					logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2 && any(joined.Unwrap()[0]) == any(primary) && any(joined.Unwrap()[1]) == any(failure), "callback/first failure order: %v", result)
				}
				irFailureV1(t, kept.Counters().cause, logicalStateFailureLocalInvariant, "required state scope is not active")
				irFailureV1(t, root().cause, logicalStateFailureLocalInvariant, "required root derive is not available")
				btReservationsReleased(t, w.owner)
				logicalMDBXAssert(t, w.s.View(func(*mdbx.Reader) error { return nil }) == nil, "local callback refusal disarmed clean Reader/Store")
			})
		}
	}
}

func irConcurrentV1(t *testing.T) {
	worlds := []*btWorld{btNew(t), btNew(t), btNew(t)}
	var group sync.WaitGroup
	for i, w := range worlds {
		group.Add(1)
		go func() {
			defer group.Done()
			err := irRunV1(t, w, irRequestV1(0, byte(40+i)), mdbx.TreeEndpointV1{}, func(_ logicalStateView, derive func() initial148RootReadOutcomeV1) error {
				out := derive()
				logicalMDBXAssert(t, out.derived && out.cause == nil, "independent scope derive %v", out.cause)
				return out.cause
			})
			logicalMDBXAssert(t, err == nil, "independent scope %v", err)
		}()
	}
	group.Wait()
	for _, w := range worlds {
		btReservationsReleased(t, w.owner)
	}
}

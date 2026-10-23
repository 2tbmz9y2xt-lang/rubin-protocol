//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func irRequestV1(height uint64, salt byte) blockTreeRequestV1 {
	tx := btTransaction(uint64(salt), 0, nil, [][]byte{btFrame(17, 0, []byte{salt})}, nil, []byte{0}, nil)
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
	logicalMDBXAssert(t, outer == result || result != nil && errors.Is(outer, result), "outer View lost producer result: %v/%v", outer, result)
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
	t.Run("full-original-and-decoder-alias", func(t *testing.T) {
		for _, tc := range []struct { size int; value uint64; covenant uint16; height uint64; coinbase bool }{
			{0, 0, 0, 0, false}, {1, 37, 1, 99, true}, {65536, ^uint64(0), ^uint16(0), ^uint64(0), true},
		} {
			t.Run(fmt.Sprint(tc.size), func(t *testing.T) {
				size := tc.size
				w := btNew(t)
				op := Outpoint{Txid: [32]byte{42}, Vout: 7}
				frame := btFrame(tc.value, tc.covenant, bytes.Repeat([]byte{5}, size))
				value := btValue(frame, tc.height, tc.coinbase)
				w.pair(t, btMutation(1, btUTXOKey(1, op), value))
				irCounterV1(t, w, 36+uint64(len(value)), 1)
				err := irRunV1(t, w, irRequestV1(1, 2), mdbx.TreeEndpointV1{Kind: 1, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
					first := view.Lookup(op)
					logicalMDBXAssert(t, first.kind == logicalStateRowPresent && first.entry.Value == tc.value && first.entry.CovenantType == tc.covenant && first.entry.CreationHeight == tc.height && first.entry.CreatedByCoinbase == tc.coinbase && bytes.Equal(first.entry.CovenantData, bytes.Repeat([]byte{5}, size)), "full decoded record lost a field")
					scope := view.(*initial148RequiredScopeV1)
					logicalMDBXAssert(t, bytes.Equal(scope.facts[0].original, value), "retained original suffix differs")
					if size != 0 { first.entry.CovenantData[0] = 9 }
					second := view.Lookup(op)
					logicalMDBXAssert(t, second.kind == logicalStateRowPresent && bytes.Equal(scope.facts[0].original, value) && bytes.Equal(second.entry.CovenantData, bytes.Repeat([]byte{5}, size)), "decoded clone changed retained R backing")
					counter := view.Counters()
					logicalMDBXAssert(t, counter.kind == logicalStateCountersPresent && counter.counters == (logicalStateCounters{bytes: 36+uint64(len(value)), entries: 1}) && len(scope.facts) == 1, "repeat counted present Y twice")
					return nil
				})
				logicalMDBXAssert(t, err == nil, "equal R copies refused: %v", err)
			})
		}
	})
	t.Run("absent-repeat", func(t *testing.T) {
		w := btNew(t)
		err := irRunV1(t, w, irRequestV1(1, 3), mdbx.TreeEndpointV1{Kind: 1}, func(view logicalStateView, _ func() initial148RootReadOutcomeV1) error {
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
}

func irResidualV1(t *testing.T) {
	for _, tc := range []struct {
		name string
		total, count uint64
		valid bool
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
				if tc.name == "lower-minus-one" || tc.name == "bytes-exceeded" { data = []byte{1} }
				w.pair(t, btMutation(1, btUTXOKey(1, op), btValue(btFrame(1, 0, data), 0, true)))
				irCounterV1(t, w, tc.total, tc.count)
				var failure error
				err := irRunV1(t, w, irRequestV1(1, 7), mdbx.TreeEndpointV1{Kind: 1}, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
					if counterFirst {
						counter := view.Counters()
						failure = counter.cause
					}
					if failure == nil {
						row := view.Lookup(op)
						failure = row.cause
					}
					if !counterFirst && failure == nil { failure = view.Counters().cause }
					logicalMDBXAssert(t, (failure == nil) == tc.valid, "residual checkpoint = %v", failure)
					if failure != nil {
						var logical *logicalStateFailure
						logicalMDBXAssert(t, errors.As(failure, &logical) && logical.kind == logicalStateFailureStoreIntegrity, "residual class %v", failure)
						want := "invalid required residual counters"
						if tc.name == "count-exceeded" || tc.name == "bytes-exceeded" { want = "required subset exceeds parent counters" }
						logicalMDBXAssert(t, logical.cause.Error() == want, "residual owning checkpoint %v, want %s", failure, want)
						out := derive()
						logicalMDBXAssert(t, out.cause == failure && !out.derived && out.root == ([32]byte{}), "residual refusal reached D")
					}
					return failure
				})
				logicalMDBXAssert(t, err == failure, "residual primary replaced")
			})
		}
	}
}

func TestInitial148RequiredOrigin(t *testing.T) {
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
							if variant == "coverage" { source.coverage.BlockMeta.EventCount++ }
							if variant == "backing" { source.Raw = bytes.Clone(source.Raw) }
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
						logicalMDBXAssert(t, result == failure, "source identity failure replaced")
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
		logicalMDBXAssert(t, err == primary, "earlier consensus error replaced by later parent read")
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
			if origin == "in-block" { op = Outpoint{Txid: coinbase.id} }
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
	t.Run("request-shapes", irShapesV1)
	t.Run("last-use-and-one-shot", irLifetimeV1)
	t.Run("capacity-before-callback", irCapacityV1)
	t.Run("callback-delivery", irDeliveryV1)
	t.Run("concurrent-independent-scopes", irConcurrentV1)
	t.Run("clean-Reader-reuse", irReusableV1)
	logicalMDBXAssert(t, unsafe.Sizeof(initial148RequiredFactV1{}) <= 128 && unsafe.Sizeof(mdbx.TreeResolvedInputV1{}) <= 64 && unsafe.Sizeof(initial148RequiredScopeV1{}) < 4096, "captured fixed controls exceed their allowance")
}

func irReusableV1(t *testing.T) {
	w := btNew(t)
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		return w.s.View(func(reader *mdbx.Reader) error {
			request := irPrepareV1(t, reader, account, irRequestV1(0, 49), mdbx.TreeEndpointV1{})
			application := errors.New("application stop")
			for _, previous := range []error{nil, application} {
				result := withInitial148RequiredStateV1(reader, account, request, func(logicalStateView, func() initial148RootReadOutcomeV1) error { return previous })
				logicalMDBXAssert(t, result == previous, "application identity changed")
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
			return account.WithReservation(402653184-266480+1, func() error {
				err := withInitial148RequiredStateV1(reader, account, request, func(logicalStateView, func() initial148RootReadOutcomeV1) error { t.Fatal("R capacity refusal reached callback"); return nil })
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
				return account.WithReservation(402653184-266480-288504+1, func() error {
					out := derive()
					cause = out.cause
					logicalMDBXAssert(t, !out.derived && out.root == ([32]byte{}) && mdbx.IsOperationReservationCapacity(cause) && !out.hasObservation && out.observation == (mdbx.TreeObservationV1{}), "D capacity outcome %+v", out)
					return nil
				})
			})
			logicalMDBXAssert(t, result == cause, "ignored D capacity lost raw cause")
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
}

func irShapesV1(t *testing.T) {
	variants := []string{"nil-reader", "nil-account", "nil-callback", "nil-source", "foreign-source", "nil-coverage", "raw-copy", "raw-length", "coverage-backing", "database", "generation", "block", "height", "header", "body-kind", "meta", "direction", "kind", "undo", "endpoint", "parent", "multiple-invalid"}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			w := btNew(t)
			logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
				return w.s.View(func(reader *mdbx.Reader) error {
					captured := irPrepareV1(t, reader, a, irRequestV1(0, 21), mdbx.TreeEndpointV1{})
					callback := func(logicalStateView, func() initial148RootReadOutcomeV1) error { t.Fatal("invalid wrapper reached callback"); return nil }
					switch variant {
					case "nil-reader": reader = nil
					case "nil-account": a = nil
					case "nil-callback": callback = nil
					case "nil-source": captured.Primitive.Source = (*blockTreeSourceV1)(nil)
					case "foreign-source": captured.Primitive.Source = &btObserved{t: t, source: captured.Primitive.Source.(*blockTreeSourceV1)}
					case "nil-coverage": captured.Primitive.Coverage = nil
					case "raw-copy": captured.Source.Raw = bytes.Clone(captured.Source.Raw)
					case "raw-length": captured.Source.Raw = captured.Source.Raw[:len(captured.Source.Raw)-1]
					case "coverage-backing": captured.Source.coverage.CurrentBody = bytes.Clone(captured.Source.Raw)
					case "database": captured.Source.coverage.DatabaseID[0]++
					case "generation": captured.Primitive.Generation++
					case "block": captured.Primitive.Block[0]++
					case "height": captured.Primitive.Height++
					case "header": captured.Source.coverage.HeaderBytes = 116
					case "body-kind": captured.Source.coverage.BodyKind = 2
					case "meta": captured.Source.coverage.BlockMeta.EventCount++
					case "direction": captured.Primitive.Direction = 2
					case "kind": captured.Primitive.Kind = 2
					case "undo": captured.Primitive.Undo = 1
					case "endpoint": captured.Primitive.Endpoint.BlockHash[0]++
					case "parent": captured.Parent.Kind = 1
					case "multiple-invalid": captured.Source.Raw = nil; captured.Primitive.Coverage = nil
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
				logicalMDBXAssert(t, a.WithReservation(402653184-266480, func() error { return nil }) == nil, "exact R reservation refused")
				logicalMDBXAssert(t, a.WithReservation(402653184-266480+1, func() error { t.Fatal("R allowance omitted clone/repeat backing"); return nil }) != nil, "R reservation too small")
				out := root()
				logicalMDBXAssert(t, out.derived && out.cause == nil, "first derive: %v", out.cause)
				logicalMDBXAssert(t, a.WithReservation(402653184-266480+1, func() error { t.Fatal("R released before final callback consumer"); return nil }) != nil, "R last use uncharged")
				second := root()
				logicalMDBXAssert(t, !second.derived && second.root == ([32]byte{}), "second derive returned root")
				irFailureV1(t, second.cause, logicalStateFailureLocalInvariant, "required root derive is not available")
				irFailureV1(t, view.Counters().cause, logicalStateFailureLocalInvariant, "required state scope is not active")
				return nil
			})
		})
	})
	logicalMDBXAssert(t, err == nil, "lifetime operation: %v", err)
	irFailureV1(t, kept.Lookup(Outpoint{}).cause, logicalStateFailureLocalInvariant, "required state scope is not active")
	irFailureV1(t, derive().cause, logicalStateFailureLocalInvariant, "required root derive is not available")
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
							for range 3 { failure = view.Lookup(Outpoint{}).cause }
							logicalMDBXAssert(t, failure != nil, "bounded point failure missing")
						}
						switch delivery {
						case "error": return primary
						case "panic": panic(panicValue)
						case "goexit": runtime.Goexit()
						}
						return nil
					})
					post = true
				}
				if delivery == "goexit" {
					done := make(chan struct{})
					go func() { defer close(done); run() }()
					<-done
				} else { run() }
				if delivery == "panic" { logicalMDBXAssert(t, recovered == panicValue && !post, "original panic was changed") }
				if delivery == "goexit" { logicalMDBXAssert(t, !post, "Goexit continued") }
				if delivery == "nil" && withFailure { logicalMDBXAssert(t, result == failure, "ignored first failure lost") }
				if delivery == "nil" && !withFailure { logicalMDBXAssert(t, result == nil, "clean callback refused") }
				if delivery == "error" && !withFailure { logicalMDBXAssert(t, result == primary, "application error identity changed") }
				if delivery == "error" && withFailure {
					joined, ok := result.(interface{ Unwrap() []error })
					logicalMDBXAssert(t, ok && len(joined.Unwrap()) == 2 && joined.Unwrap()[0] == primary && joined.Unwrap()[1] == failure, "callback/first failure order: %v", result)
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

//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestInitial148RequiredFaultV1(t *testing.T) {
	t.Run("ignored-and-wrapped-native-read", irNativeFaultV1)
	t.Run("localized-D-copy", irLocalizedV1)
	t.Run("record-check-before-consumption", irMalformedV1)
	t.Run("genesis-and-earlier-stop-selectors", irSelectorsV1)
}

func irNativeFaultV1(t *testing.T) {
	for _, delivery := range []string{"ignored", "returned", "wrapped", "application", "panic", "goexit"} {
		t.Run(delivery, func(t *testing.T) {
			w := btNew(t)
			op := Outpoint{Txid: [32]byte{43}}
			var first, result, returned, outer error
			var observation initial148RootReadOutcomeV1
			var kept logicalStateView
			var derive func() initial148RootReadOutcomeV1
			var recovered any
			panicValue := new(int)
			post := false
			run := func() {
				defer func() { recovered = recover() }()
				result, outer = irObservedV1(t, w, irRequestV1(6, 44), mdbx.TreeEndpointV1{Kind: 1, Height: 5, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, root func() initial148RootReadOutcomeV1) error {
					kept, derive = view, root
					row := view.Lookup(op)
					first = row.cause
					logicalMDBXAssert(t, row.kind == logicalStateRowUnavailable && logicalStateEntryZero(row.entry), "native unavailable became absence/integrity")
					observation = root()
					logicalMDBXAssert(t, any(observation.cause) == any(first) && !observation.derived && observation.root == ([32]byte{}) && !observation.hasObservation && observation.observation == (mdbx.TreeObservationV1{}), "unavailable fabricated root/observation")
					switch delivery {
					case "returned":
						returned = first
					case "wrapped":
						returned = fmt.Errorf("callback: %w", first)
					case "application":
						returned = errors.New("application error")
					case "panic":
						panic(panicValue)
					case "goexit":
						runtime.Goexit()
					}
					return returned
				})
				post = true
			}
			var counts mdbx.SelectedDamageEvidence
			var fixtureErr error
			armed := func() {
				counts, fixtureErr = mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageGetEIO, 1, btUTXOKey(1, op), run)
			}
			if delivery == "goexit" {
				done := make(chan struct{})
				go func() { defer close(done); armed() }()
				<-done
			} else {
				armed()
			}
			// Goexit does not assign the outer fixture's returned evidence. Its
			// deferred release and the scoped account are still directly observed.
			if delivery != "goexit" {
				logicalMDBXAssert(t, fixtureErr == nil && counts.Faults == 1 && counts.Commits == 0 && counts.Deletes == 0 && counts.OldGets[0] == 0 && counts.NodeGets == 0 && counts.OldPulls == ([8]uint64{}), "first read/terminal selectors %+v/%v", counts, fixtureErr)
			}
			btfEngine(t, first, "get", mdbx.EngineIO, 5, "error 5")
			if delivery == "panic" {
				logicalMDBXAssert(t, recovered == panicValue && !post, "panic+native failure changed panic")
			}
			if delivery == "goexit" {
				logicalMDBXAssert(t, !post, "Goexit+failure continued")
			}
			if delivery == "ignored" || delivery == "returned" {
				logicalMDBXAssert(t, any(result) == any(first), "native identity replaced")
			}
			if delivery == "wrapped" || delivery == "application" {
				parts, ok := result.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(parts.Unwrap()) == 2 && any(parts.Unwrap()[0]) == any(returned) && any(parts.Unwrap()[1]) == any(first), "exact joined error order %v", result)
				viewParts, ok := outer.(interface{ Unwrap() []error })
				logicalMDBXAssert(t, ok && len(viewParts.Unwrap()) == 2 && any(viewParts.Unwrap()[0]) == any(result) && any(viewParts.Unwrap()[1]) == any(first), "outer View projection order %v", outer)
			}
			if delivery == "ignored" || delivery == "returned" {
				logicalMDBXAssert(t, any(outer) == any(first), "outer exact native cause changed")
			}
			irFailureV1(t, kept.Counters().cause, logicalStateFailureLocalInvariant, "required state scope is not active")
			irFailureV1(t, derive().cause, logicalStateFailureLocalInvariant, "required root derive is not available")
			btReservationsReleased(t, w.owner)
			w.reopen(t)
			logicalMDBXAssert(t, w.s.View(func(*mdbx.Reader) error { return nil }) == nil, "fresh independent Reader was refused")
		})
	}
}

func irLocalizedV1(t *testing.T) {
	for _, damage := range []string{"absent", "malformed", "endpoint"} {
		for _, delivery := range []string{"ignored", "returned", "wrapped"} {
			t.Run(damage+"/"+delivery, func(t *testing.T) {
				w := btNew(t)
				key := btMeta(0x11, 1)
				kind := mdbx.TreeObservationIdentityMismatchV1
				if damage == "absent" {
					logicalMDBXAssert(t, mdbx.FixtureStartupDeleteRow(w.s, 0, key) == nil, "binding absence setup")
					kind = mdbx.TreeObservationAbsentV1
				}
				if damage == "malformed" {
					logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, 0, key, []byte{0xff}) == nil, "binding malformed setup")
					kind = mdbx.TreeObservationMalformedV1
				}
				before, err := w.s.Inspect()
				logicalMDBXAssert(t, err == nil, "prestate inspection: %v", err)
				keys := [][]byte{{0}, {1}, {2}, {3}, btMeta(0x10, 1), btMeta(0x10, 2), btMeta(0x11, 1), btMeta(0x11, 2)}
				images := make([][]byte, len(keys))
				logicalMDBXAssert(t, w.s.View(func(reader *mdbx.Reader) error {
					for i, rowKey := range keys {
						if bytes.Equal(rowKey, key) && damage != "endpoint" {
							if damage == "malformed" {
								images[i] = []byte{0xff}
							}
							continue
						}
						value, _, readErr := reader.Get(mdbx.TreeSchemaV1DBIs()[0], rowKey)
						if readErr != nil {
							return readErr
						}
						images[i] = value
					}
					return nil
				}) == nil, "canonical/control byte snapshot")
				request := irRequestV1(6, 45)
				var cause, returned error
				var copied mdbx.TreeObservationV1
				result, outer := irObservedV1(t, w, request, mdbx.TreeEndpointV1{Kind: 1, Height: 5, CumulativeChainwork: [40]byte{39: 1}}, func(_ logicalStateView, derive func() initial148RootReadOutcomeV1) error {
					out := derive()
					cause, copied = out.cause, out.observation
					var engine *mdbx.EngineError
					logicalMDBXAssert(t, !out.derived && out.root == ([32]byte{}) && out.hasObservation && errors.As(cause, &engine) && engine.Class == mdbx.EngineIntegrity, "localized failure shape %+v", out)
					want := mdbx.TreeObservationV1{DatabaseID: [32]byte{7}, Generation: 1, Block: request.Block, Height: 6, Primitive: 0, Position: 1, Rank: 0, KeyLength: 9, Kind: kind, OriginalImage: true, OriginalReference: true}
					copy(want.Key[:], key)
					logicalMDBXAssert(t, copied == want && engine.TreeObservation != nil && *engine.TreeObservation == want, "all copied fields %+v want %+v", copied, want)
					engine.TreeObservation.Key[0] ^= 0x80
					logicalMDBXAssert(t, copied == want, "outcome aliases engine observation")
					if delivery == "returned" {
						returned = cause
					}
					if delivery == "wrapped" {
						returned = fmt.Errorf("callback: %w", cause)
					}
					return returned
				})
				if delivery != "wrapped" {
					logicalMDBXAssert(t, any(result) == any(cause), "localized first cause changed")
				}
				if delivery == "wrapped" {
					parts, ok := result.(interface{ Unwrap() []error })
					logicalMDBXAssert(t, ok && len(parts.Unwrap()) == 2 && any(parts.Unwrap()[0]) == any(returned) && any(parts.Unwrap()[1]) == any(cause), "localized wrap order %v", result)
					viewParts, ok := outer.(interface{ Unwrap() []error })
					logicalMDBXAssert(t, ok && len(viewParts.Unwrap()) == 2 && any(viewParts.Unwrap()[0]) == any(result) && any(viewParts.Unwrap()[1]) == any(cause), "localized outer View projection order %v", outer)
				}
				w.reopen(t)
				after, err := w.s.Inspect()
				logicalMDBXAssert(t, err == nil && reflect.DeepEqual(before, after), "no-result changed canonical/control cardinality")
				for i, rowKey := range keys {
					equal, err := mdbx.FixtureRawRowEqual(w.s, 0, rowKey, images[i])
					logicalMDBXAssert(t, err == nil && equal, "no-result changed original canonical/control bytes at %x", rowKey)
				}
			})
		}
	}
}

func irMalformedV1(t *testing.T) {
	for _, variant := range []string{"counter-15", "counter-17", "counter-height-bytes", "counter-height-count", "row-19", "row-65561", "row-coinbase", "row-compact"} {
		t.Run(variant, func(t *testing.T) {
			w := btNew(t)
			op := Outpoint{Txid: [32]byte{9}}
			key, rank := btUTXOKey(1, op), uint8(1)
			value := btValue(btFrame(7, 0, nil), 0, true)
			switch variant {
			case "counter-15":
				rank, key, value = 0, btMeta(0x10, 1), make([]byte, 15)
			case "counter-17":
				rank, key, value = 0, btMeta(0x10, 1), make([]byte, 17)
			case "counter-height-bytes":
				irCounterV1(t, w, 86545431, 2000)
				rank, key = 0, btMeta(0x10, 1)
			case "counter-height-count":
				irCounterV1(t, w, 56*1545455, 1545455)
				rank, key = 0, btMeta(0x10, 1)
			case "row-19":
				value = value[:19]
			case "row-65561":
				value = make([]byte, 65561)
			case "row-coinbase":
				value[len(value)-1] = 2
			case "row-compact":
				value[10] = 253
			}
			if variant != "counter-height-bytes" && variant != "counter-height-count" {
				logicalMDBXAssert(t, mdbx.FixtureSeedRawRow(w.s, rank, key, value) == nil, "malformed setup")
			}
			var cause error
			err := irRunV1(t, w, irRequestV1(1, 46), mdbx.TreeEndpointV1{Kind: 1, CumulativeChainwork: [40]byte{39: 1}}, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
				if rank == 0 {
					row := view.Counters()
					logicalMDBXAssert(t, row.kind == logicalStateCountersStoreIntegrity, "counter integrity before arithmetic: %+v", row)
					cause = row.cause
				} else {
					row := view.Lookup(op)
					logicalMDBXAssert(t, row.kind == logicalStateRowStoreIntegrity && logicalStateEntryZero(row.entry), "row integrity before consumption: %+v", row)
					cause = row.cause
				}
				out := derive()
				logicalMDBXAssert(t, any(out.cause) == any(cause) && !out.derived && out.root == ([32]byte{}) && !out.hasObservation, "malformed R promoted to D/localization")
				return cause
			})
			logicalMDBXAssert(t, any(err) == any(cause), "malformed R cause replaced: %v", err)
		})
	}
}

func irSelectorsV1(t *testing.T) {
	for _, variant := range []string{"genesis", "earlier-error", "counter-copies"} {
		t.Run(variant, func(t *testing.T) {
			w := btNew(t)
			primary := errors.New("earlier consensus rejection")
			request, parent := irRequestV1(0, 47), (mdbx.TreeEndpointV1{})
			if variant != "genesis" {
				request = irRequestV1(6, 47)
				parent = mdbx.TreeEndpointV1{Kind: 1, Height: 5, CumulativeChainwork: [40]byte{39: 1}}
			}
			if variant == "counter-copies" {
				irCounterV1(t, w, 112, 2)
			}
			var result error
			evidence, err := mdbx.FixtureSelectedDamage(w.s, w.owner, mdbx.SelectedDamageProbeOnly, 0, nil, func() {
				result = irRunV1(t, w, request, parent, func(view logicalStateView, derive func() initial148RootReadOutcomeV1) error {
					if variant == "earlier-error" {
						return primary
					}
					if variant == "counter-copies" {
						first := view.Counters()
						logicalMDBXAssert(t, first.kind == logicalStateCountersPresent && first.cause == nil && first.counters == (logicalStateCounters{bytes: 112, entries: 2}), "first captured pair %+v", first)
						first.counters.bytes, first.counters.entries = 113, 3
						second := view.Counters()
						logicalMDBXAssert(t, second.kind == logicalStateCountersPresent && second.cause == nil && second.counters == (logicalStateCounters{bytes: 112, entries: 2}), "counter copy changed original pair %+v", second)
						return nil
					}
					logicalMDBXAssert(t, view.Counters().counters == (logicalStateCounters{}), "genesis counters")
					logicalMDBXAssert(t, view.Lookup(Outpoint{}).kind == logicalStateRowAbsent, "genesis point absence")
					return derive().cause
				})
			})
			wantGets := [8]uint64{}
			if variant == "counter-copies" {
				wantGets[0] = 1
			}
			logicalMDBXAssert(t, err == nil && evidence.OldGets == wantGets && evidence.OldPulls == ([8]uint64{}) && evidence.NodeGets == 0 && evidence.NodePulls == 0 && evidence.Deletes == 0 && evidence.Commits == 0, "captured counter/genesis/terminal selectors: %+v/%v", evidence, err)
			if variant == "earlier-error" {
				logicalMDBXAssert(t, any(result) == any(primary), "earlier error identity")
			} else {
				logicalMDBXAssert(t, result == nil, "genesis producer refused: %v", result)
			}
		})
	}
}

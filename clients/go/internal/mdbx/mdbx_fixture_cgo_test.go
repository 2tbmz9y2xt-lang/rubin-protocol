//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

// The new adaptor's rejected inputs must not enter either native arming interval or run the operation.
func TestCanonicalTipStepFixtureInput(t *testing.T) {
	store, _, _ := consultedStore(t)
	key := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 1), 0)
	for _, row := range []struct {
		name       string
		scenario   uint8
		key, value []byte
		present    bool
		nilInput   uint8
	}{
		{"zero", 0, nil, nil, false, 0},
		{"unknown", 7, nil, nil, false, 0},
		{"max", 255, nil, nil, false, 0},
		{"census_key", 1, key, nil, false, 0},
		{"census_empty_key", 1, []byte{}, nil, false, 0},
		{"source_value", 2, nil, []byte{}, false, 0},
		{"source_present", 3, nil, nil, true, 0},
		{"drift_missing_key", 4, nil, nil, false, 0},
		{"drift_short_key", 4, key[:15], nil, false, 0},
		{"drift_long_key", 5, append(bytes.Clone(key), 0), nil, false, 0},
		{"drift_zero_generation", 6, make([]byte, 16), nil, false, 0},
		{"drift_height_overflow", 4, binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(nil, 1), 0x100000000), nil, false, 0},
		{"present_short", 4, key, make([]byte, 103), true, 0},
		{"present_long", 5, key, make([]byte, 105), true, 0},
		{"present_nil", 6, key, nil, true, 0},
		{"absent_value", 4, key, make([]byte, 104), false, 0},
		{"absent_empty", 5, key, []byte{}, false, 0},
		{"nil_store", 1, nil, nil, false, 1},
		{"zero_store", 1, nil, nil, false, 2},
		{"nil_run", 1, nil, nil, false, 3},
		{"unknown_and_payload", 255, key, make([]byte, 104), true, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			s, calls := store, 0
			run := func() { calls++ }
			if row.nilInput == 1 {
				s = nil
			}
			if row.nilInput == 2 {
				s = &Store{}
			}
			if row.nilInput == 3 {
				run = nil
			}
			before := fixtureLargeNativeCalls()
			evidence, err := FixtureCanonicalTipStep(s, row.scenario, row.key, row.value, row.present, run)
			if evidence != (CanonicalTipStepFixtureEvidence{}) || err == nil || err.Error() != "invalid canonical-tip step fixture" || calls != 0 || fixtureLargeNativeCalls() != before {
				t.Fatalf("rejected adaptor ran/armed: %+v %v calls=%d", evidence, err, calls)
			}
		})
	}
	calls := 0
	var sourceErr error
	evidence, err := FixtureCanonicalTipStep(store, 1, nil, nil, false, func() {
		calls++
		_, _, sourceErr = store.Update(func(r *Reader) (Batch, error) {
			_, err := r.CanonicalTipV1(1)
			if err != nil {
				return Batch{}, err
			}
			return Batch{}, errors.New("ordinary native invocation")
		})
	})
	if err != nil || calls != 1 || sourceErr == nil || sourceErr.Error() != "ordinary native invocation" || evidence.Opens != 1 || evidence.Closes != 1 || evidence.Queries != 1 || evidence.Faults != 0 {
		t.Fatalf("rejected adaptor leaked arming: %+v %v calls=%d cause=%v", evidence, err, calls, sourceErr)
	}
}

// Raw fixture-owner equality deliberately avoids Reader.Get on malformed rows.
func archiveRawEqual(t *testing.T, s *Store, rows []Mutation) {
	t.Helper()
	mustEnvironment(t, s.View(func(r *Reader) error {
		for _, row := range rows {
			image, err := updateOwnedImage(row.Literal)
			if err != nil {
				return err
			}
			equal, err := updateNativeEqual(r.txn, s.dbis[row.DBI.Rank], row.Key, image)
			if err != nil || !equal {
				t.Fatalf("archive raw image %s/%x: %v", row.DBI.Name, row.Key, err)
			}
		}
		return nil
	}))
}

func TestStartupCanonicalNativeFixtures(t *testing.T) {
	for _, begin := range []struct {
		scenario SelectedDamageScenario
		class    EngineClass
		code     int
	}{
		{SelectedDamageBeginTxnFull, EngineTransaction, -30788},
		{SelectedDamageBeginEIO, EngineIO, 5},
	} {
		t.Run(fmt.Sprintf("fresh begin %d before cached admission", begin.code), func(t *testing.T) {
			s := startupOpened(t)
			var raw error
			var cached bool
			called := 0
			evidence, err := FixtureSelectedDamage(s, bootstrapOwner(t), begin.scenario, 0, []byte{0}, func() {
				raw, cached = s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) { called++; return 1, nil })
				if cached || called != 0 || s.state != storeCLOSED || s.terminal != raw || s.env != nil || s.writer != nil || s.txn != nil || s.canonicalOwnerVerified {
					t.Fatal("first fresh begin failure flag/callback/state")
				}
				next, admitted := s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) { called++; return 1, nil })
				if !admitted || next != raw || called != 0 {
					t.Fatal("begin failure cached repeat flag/identity/callback")
				}
			})
			mustEnvironment(t, err)
			requireEngineError(t, raw, begin.class, operationView, begin.code)
			if evidence.BeginOld != 1 || evidence.BeginRead != 0 || evidence.BeginWrite != 0 || evidence.Faults != 1 || evidence.OldAborts != 0 || evidence.OldGets != ([8]uint64{}) || evidence.OldPulls != ([8]uint64{}) {
				t.Fatalf("no-checker fresh begin native census: %+v", evidence)
			}
		})
	}
	for _, abort := range []uint32{0, 9} {
		t.Run(fmt.Sprintf("H03 consumed close EIO abort%d", abort), func(t *testing.T) {
			s := startupOpened(t)
			var read, raw error
			var cached bool
			_, err := fixtureTipCursor(s, 1, 1, 1, 5, func() {
				mustEnvironment(t, fixtureTipCloseFault())
				run := func() {
					_, armErr := FixtureSelectedDamage(s, bootstrapOwner(t), SelectedDamageGetEIO, 0, []byte{0}, func() {
						raw, cached = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
							_, _, read = r.Get(readDBIsLiteral()[0], []byte{0})
							return 1, read
						})
					})
					mustEnvironment(t, armErr)
				}
				if abort == 0 {
					run()
				} else {
					_, armErr := fixtureLargeFault(s, abort, 0, []byte{0}, run)
					mustEnvironment(t, armErr)
				}
			})
			mustEnvironment(t, err)
			parts := raw.(interface{ Unwrap() []error }).Unwrap()
			if len(parts) != 2 {
				t.Fatal("consumed close join shape")
			}
			closeErr := requireEnvironmentError(t, parts[1], EngineIO, operationClose, 5, "error 5")
			if closeErr.Cause != nil {
				t.Fatal("consumed close diagnostic gained PRIMARY cause")
			}
			if abort == 0 && parts[0] != read {
				t.Fatal("consumed close lost original read")
			}
			if abort == 9 {
				primary := parts[0].(interface{ Unwrap() []error }).Unwrap()
				if len(primary) != 2 || primary[0] != read {
					t.Fatal("read/abort/close order")
				}
			}
			if cached || s.canonicalOwnerVerified || s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil || s.terminal != raw {
				t.Fatal("consumed close native resources")
			}
			if s.View(func(*Reader) error { t.Fatal("consumed close callback"); return nil }) != raw {
				t.Fatal("consumed close cached identity")
			}
			next, admitted := s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) {
				t.Fatal("consumed close cached checker")
				return 1, nil
			})
			if !admitted || next != raw || s.terminal != raw {
				t.Fatal("consumed close cached admission flag/identity")
			}
		})
	}
	t.Run("H03 actual writer release cache admission", func(t *testing.T) {
		s := startupOpened(t)
		called := 0
		_, err := fixtureLargeFault(s, 9, 0, []byte{0}, func() {
			raw, cached := s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) {
				called++
				mustEnvironment(t, fixtureTipWriterReleaseFault(s))
				return 1, nil
			})
			if cached || called != 1 || s.canonicalOwnerVerified || s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil || s.config != (ConfigV1{}) || !reflect.ValueOf(s.dbis).IsZero() || s.terminal != raw {
				t.Fatal("first fresh writer release flag/callback/resources/cache")
			}
			parts := raw.(interface{ Unwrap() []error }).Unwrap()
			if len(parts) != 2 {
				t.Fatal("actual abort then writer release order")
			}
			abort := requireEnvironmentError(t, parts[0], EngineIO, operationAbort, 5, "error 5")
			release := requireEnvironmentError(t, parts[1], EngineIO, operationClose, 9, "release Rubin writer lock")
			if abort.Cause != nil || !errors.Is(release.Cause, syscall.EBADF) || abort.ReopenRequired || release.ReopenRequired {
				t.Fatal("actual writer release Cause/consumption")
			}
			backing, abortBefore, releaseBefore := &parts[0], *abort, *release
			before := fixtureLargeNativeCalls()
			for attempt := 0; attempt < 2; attempt++ {
				next, admitted := s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) { called++; return 1, nil })
				if !admitted || next != raw || called != 1 || s.terminal != raw || s.state != storeCLOSED || s.canonicalOwnerVerified || s.env != nil || s.writer != nil || s.txn != nil || s.config != (ConfigV1{}) || !reflect.ValueOf(s.dbis).IsZero() {
					t.Fatal("writer release cached flag/identity/resources")
				}
				children := next.(interface{ Unwrap() []error }).Unwrap()
				if len(children) != 2 || &children[0] != backing || children[0].(*EngineError) != abort || children[1].(*EngineError) != release || *abort != abortBefore || *release != releaseBefore {
					t.Fatal("writer release cached parent/children/backing changed")
				}
				if s.View(func(*Reader) error { t.Fatal("writer release cached View callback"); return nil }) != raw {
					t.Fatal("writer release cached View identity")
				}
				truth, stage, next := s.Update(func(*Reader) (Batch, error) { t.Fatal("writer release cached Update callback"); return Batch{}, nil })
				_, inspectionErr := s.Inspect()
				if truth != 1 || stage != 1 || next != raw || inspectionErr != raw || fixtureLargeNativeCalls() != before {
					t.Fatal("writer release next operation suppression/truth/stage")
				}
			}
		})
		mustEnvironment(t, err)
	})
	for _, completion := range []StartupCanonicalCompletionV1{0, 2, 255} {
		for _, application := range []string{"nil", "same", "different", "typed nil"} {
			for _, mode := range []uint32{0, 9, 10} {
				t.Run(fmt.Sprintf("H03 completion%d app%s abort%d", completion, application, mode), func(t *testing.T) {
					s := startupOpened(t)
					var reader *Reader
					var app, read, raw error
					var cached bool
					if application == "different" {
						app = errors.New("distinct application")
					}
					if application == "typed nil" {
						var typed *nilPointerError
						app = typed
					}
					run := func() {
						_, err := FixtureSelectedDamage(s, bootstrapOwner(t), SelectedDamageGetEIO, 0, []byte{0}, func() {
							raw, cached = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
								reader = r
								_, _, read = r.Get(readDBIsLiteral()[0], []byte{0})
								if application == "same" {
									app = read
								}
								return completion, app
							})
						})
						mustEnvironment(t, err)
					}
					if mode == 0 {
						run()
					} else {
						_, err := fixtureLargeFault(s, mode, 0, []byte{0}, run)
						mustEnvironment(t, err)
					}
					if cached || reader == nil || read == nil || reader.failure != read || reader.usable() || s.canonicalOwnerVerified || s.terminal != raw {
						t.Fatal("completion/read failure ownership")
					}
					primary := raw
					if mode == 10 {
						e := requireEnvironmentError(t, raw, EngineLocalInvariant, operationAbort, -30416, pinnedNegativeDiagnostics[-30416])
						primary = e.Cause
					} else if mode == 9 {
						parts := raw.(interface{ Unwrap() []error }).Unwrap()
						if len(parts) != 2 {
							t.Fatal("abort join shape")
						}
						primary = parts[0]
					}
					if completion == 0 && application == "same" {
						if primary != read {
							t.Fatal("exact same recorded leaf duplicated")
						}
					} else {
						parts := primary.(interface{ Unwrap() []error }).Unwrap()
						if len(parts) != 2 || parts[1] != read {
							t.Fatal("completion/read join order")
						}
						if completion > 1 || app == nil {
							e := requireEnvironmentError(t, parts[0], EngineLocalInvariant, operationView, -30779, "startup canonical verification did not complete")
							if e.Cause != app {
								t.Fatal("completion original callback Cause")
							}
						} else if parts[0] != app {
							t.Fatal("callback leaf identity")
						}
					}
					want := storeCLOSED
					if mode == 10 {
						want = storePOISONEDTHREAD
					}
					if s.state != want || s.View(func(*Reader) error { t.Fatal("completion terminal callback"); return nil }) != raw {
						t.Fatal("completion terminal cache/state")
					}
					mustEnvironment(t, fixtureLargeRelease(s))
				})
			}
		}
	}
	for _, recorded := range []bool{false, true} {
		for _, application := range []string{"nil", "same", "different", "typed nil"} {
			for _, mode := range []uint32{0, 9, 10, 24} {
				if mode == 24 && !recorded {
					continue
				}
				t.Run(fmt.Sprintf("H03 read%v app%s mode%d", recorded, application, mode), func(t *testing.T) {
					s := startupOpened(t)
					env, writer, cfg, dbis := s.env, s.writer, s.config, s.dbis
					key := []byte{0}
					var reader *Reader
					var readErr, appErr, raw error
					var cached bool
					var nativeCounts SelectedDamageEvidence
					if application == "different" {
						appErr = errors.New("application")
					}
					if application == "typed nil" {
						var typed *nilPointerError
						appErr = typed
					}
					liMode := mode
					run := func() {
						raw, cached = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
							reader = r
							if recorded {
								_, _, readErr = r.Get(readDBIsLiteral()[0], key)
								if readErr == nil && mode == 24 {
									_, _, readErr = r.Get(readDBIsLiteral()[0], key)
								}
								if readErr == nil {
									t.Fatal("recorded witness did not reach native failure")
								}
							}
							if application == "same" {
								appErr = readErr
							}
							return 1, appErr
						})
						if cached {
							t.Fatal("first fresh cleanup was labeled cached admission")
						}
						if s.state != storeOPEN {
							calls := fixtureLargeNativeCalls()
							for attempt := 0; attempt < 2; attempt++ {
								next, admitted := s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) { t.Fatal("armed cached checker"); return 1, nil })
								if !admitted || next != raw || fixtureLargeNativeCalls() != calls {
									t.Fatal("armed cached admission flag/identity/native suppression")
								}
							}
						}
					}
					if recorded && mode != 24 {
						armedRead := func() {
							var err error
							nativeCounts, err = FixtureSelectedDamage(s, bootstrapOwner(t), SelectedDamageGetEIO, 0, key, run)
							mustEnvironment(t, err)
						}
						if mode == 0 {
							armedRead()
						} else {
							_, fixtureErr := fixtureLargeFault(s, liMode, 0, key, armedRead)
							mustEnvironment(t, fixtureErr)
						}
					} else if mode != 0 {
						_, err := fixtureLargeFault(s, liMode, 0, key, run)
						mustEnvironment(t, err)
					} else {
						run()
					}
					if recorded && mode != 24 && (nativeCounts.BeginOld != 1 || nativeCounts.BeginRead != 0 || nativeCounts.BeginWrite != 0 || nativeCounts.Faults != 1) {
						t.Fatalf("cached repeat armed begin/read census: %+v", nativeCounts)
					}
					if cached || reader.usable() || s.canonicalOwnerVerified && (recorded || appErr != nil || mode != 0) {
						t.Fatal("failed startup published permission or retained Reader")
					}
					if mode == 10 {
						if s.state != storePOISONEDTHREAD || s.txn != reader.txn || s.env != env || s.writer != writer || s.config != (ConfigV1{}) || s.dbis != (Store{}).dbis {
							t.Fatal("retained abort native ownership")
						}
						e := requireEnvironmentError(t, raw, EngineLocalInvariant, operationAbort, -30416, pinnedNegativeDiagnostics[-30416])
						if recorded && e.Cause == nil || !recorded && appErr != nil && e.Cause != appErr {
							t.Fatal("retained abort primary identity")
						}
					} else if mode == 24 {
						if s.state != storeCLOSEBLOCKED || s.env != env || s.writer != writer || s.config != cfg || s.dbis != dbis || s.txn != nil {
							t.Fatal("retained close native ownership")
						}
						requireEngineError(t, raw, EngineConcurrency, operationClose, -30778)
					} else if mode == 9 || recorded {
						if s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil {
							t.Fatal("consumed native resources retained")
						}
						if mode == 0 && (application == "nil" || application == "same") && raw != readErr {
							t.Fatal("readPrimary direct identity changed")
						}
					} else {
						if s.state != storeOPEN || s.env != env || s.writer != writer || s.config != cfg || s.dbis != dbis || raw != appErr {
							t.Fatal("application result changed native ownership")
						}
					}
					if s.state != storeOPEN {
						if s.terminal != raw || s.View(func(*Reader) error { t.Fatal("terminal View callback"); return nil }) != raw {
							t.Fatal("terminal View identity")
						}
						truth, stage, next := s.Update(func(*Reader) (Batch, error) { t.Fatal("terminal Update callback"); return Batch{}, nil })
						if next != raw || truth != CommitTruthOld || stage != UpdateStagePrewrite {
							t.Fatal("terminal Update identity/truth/stage")
						}
						inspection, inspected := s.Inspect()
						if inspected != raw || inspection != (Inspection{}) {
							t.Fatal("terminal Inspect identity/zero result")
						}
						calls := fixtureLargeNativeCalls()
						state, txn, retainedConfig, retainedDBIs := s.state, s.txn, s.config, s.dbis
						for attempt := 0; attempt < 2; attempt++ {
							next, admitted := s.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) { t.Fatal("cached checker"); return 1, nil })
							if !admitted || next != raw || fixtureLargeNativeCalls() != calls || s.terminal != raw || s.canonicalOwnerVerified || s.state != state || s.txn != txn || s.config != retainedConfig || s.dbis != retainedDBIs {
								t.Fatal("cached admission flag/identity/native suppression")
							}
						}
						for _, invalid := range []*Store{{state: storeState("invalid"), terminal: raw}, {state: s.state, terminal: raw}} {
							next, admitted := invalid.StartupVerifyCanonicalV1(func(*Reader) (StartupCanonicalCompletionV1, error) {
								t.Fatal("invalid prestate checker")
								return 1, nil
							})
							diagnostic := "invalid Store resource shape"
							if invalid.state == storeState("invalid") {
								diagnostic = "invalid Store state"
							}
							requireEnvironmentError(t, next, EngineLocalInvariant, operationView, -30779, diagnostic)
							if admitted || fixtureLargeNativeCalls() != calls || invalid.terminal != raw {
								t.Fatal("invalid prestate was labeled cached admission")
							}
						}
						mustEnvironment(t, fixtureLargeRelease(s))
					}
				})
			}
		}
	}
	t.Run("H04 actual native drain before permission", func(t *testing.T) {
		s := startupOpened(t)
		tipSeed(t, s, tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1}))
		var old *Reader
		first := make(chan error, 1)
		var raw error
		var cached bool
		evidence, err := fixtureTipCursor(s, 13, 1, 2, 0, func() {
			raw, cached = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
				old = r
				go func() {
					point, getErr := r.CanonicalTipV1(7)
					if getErr == nil && (point == nil || point.Height != 37 || point.BlockHash != ([32]byte{0x44})) {
						t.Error("in-flight native endpoint changed")
					}
					first <- getErr
				}()
				fixtureTipWait()
				go func() {
					for r.active.Load() {
						runtime.Gosched()
					}
					if s.canonicalOwnerVerified {
						t.Error("published permission before native drain")
					}
					fixtureTipRelease()
				}()
				return 1, nil
			})
			mustEnvironment(t, <-first)
		})
		mustEnvironment(t, err)
		mustEnvironment(t, raw)
		tipCensus(t, evidence, 1, 2, 1, 0)
		if cached || old.usable() || old.ownerVerified || old.tip != nil {
			t.Fatal("drained checker Reader remained usable or retained tip")
		}
		startupPermission(t, s, true)
	})
	t.Run("H04 retained abort while native Get held", func(t *testing.T) {
		s := startupOpened(t)
		tipSeed(t, s, tipRow(7, 37, [32]byte{0x44}, [40]byte{39: 1}))
		env, writer := s.env, s.writer
		ready, done, got := make(chan *Reader, 1), make(chan struct{}), make(chan struct{})
		var old *Reader
		var point *AuthorityPointV1
		var raw, getErr, largeErr error
		var cached bool
		var large fixtureLargeEvidence
		early := false
		evidence, err := fixtureTipCursor(s, 13, 1, 2, 0, func() {
			large, largeErr = fixtureLargeFault(s, 10, 0, []byte{0}, func() {
				go func() {
					raw, cached = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
						go func() { point, getErr = r.CanonicalTipV1(7); close(got) }()
						fixtureTipWait()
						ready <- r
						return 1, nil
					})
					close(done)
				}()
				old = <-ready
				for old.active.Load() {
					runtime.Gosched()
				}
				deadline := time.NewTimer(time.Second)
				select {
				case <-done:
					early = true
				case <-deadline.C:
					// Expiration only releases the held native call; no latency assertion.
				}
				deadline.Stop()
				// Mode10 retains txn/env/writer even when a no-drain candidate
				// returns early. Join both calls before fixture disarm or cleanup.
				fixtureTipRelease()
				<-got
				<-done
			})
		})
		t.Cleanup(func() { mustEnvironment(t, fixtureLargeRelease(s)) })
		if early {
			t.Fatal("Startup returned while native Get was still held")
		}
		mustEnvironment(t, err)
		mustEnvironment(t, largeErr)
		mustEnvironment(t, getErr)
		tipCensus(t, evidence, 1, 2, 1, 0)
		if large != (fixtureLargeEvidence{aborts: 1}) {
			t.Fatalf("retained drain native census: %+v", large)
		}
		if point == nil || point.Height != 37 || point.BlockHash != ([32]byte{0x44}) {
			t.Fatal("held native endpoint changed")
		}
		e := requireEnvironmentError(t, raw, EngineLocalInvariant, operationAbort, -30416, pinnedNegativeDiagnostics[-30416])
		if cached || e.Cause != nil || !e.ReopenRequired || s.terminal != raw || s.canonicalOwnerVerified {
			t.Fatal("retained drain raw/cache/permission")
		}
		if s.state != storePOISONEDTHREAD || s.txn != old.txn || s.env != env || s.writer != writer || s.config != (ConfigV1{}) || s.dbis != (Store{}).dbis {
			t.Fatal("retained drain native resources")
		}
		if old.usable() || old.ownerVerified || old.tip != nil {
			t.Fatal("retained drain Reader lifetime")
		}
		if s.View(func(*Reader) error { t.Fatal("retained drain View callback"); return nil }) != raw {
			t.Fatal("retained drain View cache")
		}
		truth, stage, next := s.Update(func(*Reader) (Batch, error) { t.Fatal("retained drain Update callback"); return Batch{}, nil })
		if next != raw || truth != CommitTruthOld || stage != UpdateStagePrewrite {
			t.Fatal("retained drain Update cache/truth/stage")
		}
	})
	for _, recorded := range []bool{false, true} {
		for _, mode := range []uint32{0, 9, 10, 24} {
			if mode == 24 && !recorded {
				continue
			}
			for _, interrupt := range []string{"panic", "Goexit"} {
				t.Run(fmt.Sprintf("H05 read%v %s mode%d", recorded, interrupt, mode), func(t *testing.T) {
					s := startupOpened(t)
					owner := bootstrapOwner(t)
					done := make(chan struct{})
					var old *Reader
					go func() {
						defer close(done)
						defer func() {
							if p := recover(); interrupt == "panic" && p != "startup interruption" {
								t.Errorf("original panic=%v", p)
							}
						}()
						run := func() {
							_ = owner.WithReservation(4096, func() error {
								raw, _ := s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
									old = r
									if recorded && mode != 24 {
										_, _, _ = r.Get(readDBIsLiteral()[0], []byte{0})
									}
									if mode == 24 {
										_, _, _ = r.Get(readDBIsLiteral()[0], []byte{0})
										_, _, _ = r.Get(readDBIsLiteral()[0], []byte{0})
									}
									if interrupt == "panic" {
										panic("startup interruption")
									}
									runtime.Goexit()
									return 1, nil
								})
								return raw
							})
						}
						armed := run
						if recorded && mode != 24 {
							armed = func() { _, _ = FixtureSelectedDamage(s, owner, SelectedDamageGetEIO, 0, []byte{0}, run) }
						}
						if mode == 0 {
							armed()
						} else {
							_, _ = fixtureLargeFault(s, mode, 0, []byte{0}, armed)
						}
						t.Error("interrupted startup returned")
					}()
					<-done
					if s.canonicalOwnerVerified || old.usable() || owner.WithReservation(154611151, func() error { return nil }) != nil {
						t.Fatal("interrupted publication/lifetime/grant")
					}
					want := storeOPEN
					if recorded || mode == 9 {
						want = storeCLOSED
					}
					if mode == 10 {
						want = storePOISONEDTHREAD
					}
					if mode == 24 {
						want = storeCLOSEBLOCKED
					}
					if s.state != want {
						t.Fatalf("interrupted state=%s, want%s", s.state, want)
					}
					if s.state != storeOPEN {
						mustEnvironment(t, fixtureLargeRelease(s))
					} else {
						startupPermission(t, s, false)
					}
				})
			}
		}
	}
}

func TestStartupCanonicalNextNativeFixtures(t *testing.T) {
	for _, width := range []int{8, 17} {
		t.Run(fmt.Sprintf("forward key width%d", width), func(t *testing.T) {
			s := startupOpened(t)
			key := canonicalForwardKeyLiteral(1, 0)
			if width == 8 {
				key = key[:8]
			} else {
				key = append(key, 0)
			}
			mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[2], key, make([]byte, 104)))
			var recorded error
			err, cached := s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
				row, found, failure := r.StartupCanonicalNextV1(readDBIsLiteral()[2], 1, nil)
				e, native := failure.(*EngineError)
				if !native || e.Class != EngineIntegrity || e.Operation != "prefix-page" || e.Code != -30793 || e.Diagnostic != "stored key outside SchemaV2 prefix-page domain" || e.Cause != nil || found || !reflect.DeepEqual(row, PrefixRow{}) || r.failure != failure || r.usable() {
					t.Fatal("forward key width result/record/disarm")
				}
				recorded = failure
				return 1, nil
			})
			if cached || err != recorded || s.canonicalOwnerVerified || s.state != storeCLOSED {
				t.Fatal("recorded key width failure disappeared")
			}
			if s.View(func(*Reader) error { t.Fatal("key width cached callback"); return nil }) != err {
				t.Fatal("key width cached identity")
			}
		})
	}
	for _, rank := range []uint8{2, 7} {
		for _, width := range []int{-1, 0, 7, 9, 103, 105} {
			if rank == 2 && (width == 7 || width == 9) || rank == 7 && (width == 103 || width == 105) {
				continue
			}
			t.Run(fmt.Sprintf("current rank%d width%d", rank, width), func(t *testing.T) {
				s := startupOpened(t)
				key := canonicalForwardKeyLiteral(1, 0)
				if rank == 7 {
					key = canonicalOwnerKeyLiteral(1, [32]byte{7})
				}
				var raw []byte
				if width >= 0 {
					raw = make([]byte, width)
				}
				if width >= 0 {
					mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[rank], key, raw))
				}
				var recorded error
				err, cached := s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
					row, found, failure := r.StartupCanonicalNextV1(readDBIsLiteral()[rank], 1, nil)
					if width == -1 {
						if failure != nil || found || !reflect.DeepEqual(row, PrefixRow{}) {
							t.Fatal("NOTFOUND result")
						}
						return 1, nil
					}
					if failure == nil || found || !reflect.DeepEqual(row, PrefixRow{}) || r.failure != failure || r.usable() {
						t.Fatal("current-width failure/record/disarm")
					}
					recorded = failure
					return 1, nil
				})
				if cached {
					t.Fatal("fresh pull was labeled cached admission")
				}
				if width == -1 {
					mustEnvironment(t, err)
					startupPermission(t, s, true)
				} else if err != recorded || s.canonicalOwnerVerified || s.state != storeCLOSED {
					t.Fatal("ignored recorded pull failure disappeared")
				}
			})
		}
		t.Run(fmt.Sprintf("outside generation rank%d", rank), func(t *testing.T) {
			s := startupOpened(t)
			key := canonicalForwardKeyLiteral(2, 0)
			if rank == 7 {
				key = canonicalOwnerKeyLiteral(2, [32]byte{7})
			}
			mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[rank], key, []byte{0xff}))
			mustEnvironment(t, s.View(func(r *Reader) error {
				row, found, err := r.StartupCanonicalNextV1(readDBIsLiteral()[rank], 1, nil)
				if err != nil || found || !reflect.DeepEqual(row, PrefixRow{}) || r.failure != nil || !r.usable() {
					t.Fatal("outside generation parsed foreign value")
				}
				return nil
			}))
		})
	}
}

func TestArchiveProfileMalformed(t *testing.T) {
	for _, name := range []string{"A7", "H2a", "H2b", "H2c", "H2d", "H2e", "H6", "H16a", "H16b", "H16c", "H16d_empty", "H16d_one", "H17a", "H17b"} {
		t.Run(name, func(t *testing.T) {
			a := modelBase(1, 0, 0)
			if name == "A7" || name == "H17a" {
				a.ActiveProfile = 2
			}
			s, path, cfg, rows := archiveSeed(t, a, -1, modelWork(false))
			values := prunedImage(t, s, rows)
			for i := range rows {
				rows[i].Literal = values[i]
			}
			rows = append(rows, Mutation{DBI: readDBIsLiteral()[0], Key: []byte{0}, Literal: values[len(values)-2]}, Mutation{DBI: readDBIsLiteral()[0], Key: []byte{1}, Literal: values[len(values)-1]})
			value := append([]byte(nil), values[0]...)
			switch name {
			case "H2a":
				value = value[:39]
			case "H2b":
				value[0] = 2
			case "H2c", "H17a":
				value[36] = 2
				value = append(value[:37], append([]byte{2}, value[37:]...)...)
			case "H2d":
				value[34] = 2
				value = append(value[:36], append([]byte{0, 0}, value[36:]...)...)
			case "H2e":
				bad := modelBase(1, 0, 0)
				bad.NextGenerationID, bad.Phase = 4, 2
				bad.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 1, GenerationID: 3}}}
				bad.SelectedSide = modelSide(2, 0, 1, 1, 1)
				bad.DetachedSuffix = modelDetached(1, 1)
				value = nil
				encodeAuthority(&value, bad)
			}
			if name == "H17b" {
				value = value[:39]
			}
			if !bytes.Equal(value, values[0]) {
				mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[0], []byte{2}, value))
				rows[0].Literal = value
			}
			add := func(key, value []byte) {
				mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[2], key, value))
				rows = append(rows, Mutation{DBI: readDBIsLiteral()[2], Key: key, Literal: value})
			}
			g0 := []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}
			g1 := append([]byte(nil), g0...)
			g1[15] = 1
			g2 := append([]byte(nil), g0...)
			g2[15] = 2
			switch name {
			case "A7", "H6":
				add(g0, make([]byte, 103))
			case "H16a":
				add(g0, make([]byte, 104))
				add(g1, make([]byte, 103))
			case "H16b":
				add(append(g0, 0), make([]byte, 104))
			case "H16c":
				add(g0, ChainValue(modelHash(71), [32]byte{}, modelWork(false)))
				add(g1, ChainValue(modelHash(72), [32]byte{}, modelWork(false)))
				add(g2, make([]byte, 103))
			case "H16d_one":
				add(g0, ChainValue(modelHash(71), [32]byte{}, modelWork(false)))
			}
			archiveRawEqual(t, s, rows)
			owner := bootstrapOwner(t)
			var out ArchiveProfileOutcome
			if name == "H17b" {
				mustEnvironment(t, owner.WithReservation(154611151, func() error {
					out = s.SelectArchiveProfileV1(owner)
					if !sameError(out.Err, errOperationReservationCapacity) || out.Truth != 1 || out.Stage != 1 {
						t.Fatal("capacity before illegal authority")
					}
					archiveEmptyPayload(t, out)
					return nil
				}))
			} else {
				out = s.SelectArchiveProfileV1(owner)
			}
			switch name {
			case "A7":
				prunedDecision(t, out, "PROFILE_NOOP", name)
			case "H17b":
			case "H16c":
				bootstrapRefusal(t, name, out.Truth, out.Err, EngineStateMismatch, operationUpdate, codeProblem, "archive above genesis is owned by the selected-side and replay-entry leaves", nil, false)
				archiveEmptyPayload(t, out)
			case "H16d_empty", "H16d_one":
				if out.Truth != 2 || out.Stage != 3 || out.Err != nil || out.Decision != "" || !reflect.DeepEqual(out.Authority, func() *StorageAuthorityV1 { b := a; b.ActiveProfile = 2; return &b }()) {
					t.Fatalf("archive boundary: %+v", out)
				}
				rows[0].Literal = append([]byte(nil), rows[0].Literal...)
				rows[0].Literal[1] = 2
			default:
				diagnostic, op, cause := "invalid storage authority", operationGet, error(errSchema)
				if name == "H6" || name == "H16a" {
					diagnostic, op, cause = "stored value width outside SchemaV2 bound", operationPrefixPage, nil
				}
				if name == "H16b" {
					diagnostic, op, cause = "stored key outside SchemaV2 prefix-page domain", operationPrefixPage, nil
				}
				bootstrapRefusal(t, name, out.Truth, out.Err, EngineIntegrity, op, codeInvalid, diagnostic, cause, true)
				archiveEmptyPayload(t, out)
				if out.Stage != 1 || s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil {
					t.Fatal("malformed terminal resources")
				}
				archiveCached(t, s, out, owner)
			}
			if s.state == storeOPEN {
				bootstrapOpenUnchanged(t, s, name)
				archiveRawEqual(t, s, rows)
				if name == "A7" {
					prunedDecision(t, s.SelectArchiveProfileV1(owner), "PROFILE_NOOP", "malformed next noop")
				} else if name == "H16c" {
					next := s.SelectArchiveProfileV1(owner)
					if next.Stage != 1 {
						t.Fatal("bounded next tuple")
					}
					bootstrapRefusal(t, "bounded next tuple", next.Truth, next.Err, EngineStateMismatch, operationUpdate, codeProblem, "archive above genesis is owned by the selected-side and replay-entry leaves", nil, false)
					archiveEmptyPayload(t, next)
				}
				mustEnvironment(t, s.Close())
			}
			r, err := Open(path, cfg)
			mustEnvironment(t, err)
			defer func() { _ = r.Close() }()
			archiveRawEqual(t, r, rows)
			prunedReleased(t, owner)
		})
	}
}

func TestArchiveProfileNativeImages(t *testing.T) {
	for _, name := range []string{"H10_g0_write", "H10_g1_write", "H10_g0_final", "H10_g1_final", "H11a", "H11b", "H11c", "H11d", "H11e_unreadable", "H11e_g0", "H11e_g1"} {
		t.Run(name, func(t *testing.T) {
			a := modelBase(1, 0, 0)
			if name == "H11b" {
				a = archiveSide(2)
			}
			s, path, cfg, rows := archiveSeed(t, a, 0, modelWork(false))
			if name == "H11a" {
				mustEnvironment(t, s.Close())
				s, path, cfg, rows = archiveGenesis(t)
			}
			before := prunedImage(t, s, rows)
			counts := bootstrapCounts(t, s, "native before")
			primary := nativeError(operationUpdate, codeENOSPC)
			var native updateNativeOutcome
			var planned *StorageAuthorityV1
			var observed []byte
			var finalConsulted []ownedConsulted
			var finalValues [][]byte
			var finalImages []updateImage
			var changedRows []Mutation
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			mustEnvironment(t, s.View(func(reader *Reader) error {
				decision := ""
				batch, plan, err := archiveProfileBatch(reader, &decision, errors.New("decision"))
				if err != nil {
					return err
				}
				planned = plan
				mutations := updateNativePlan(t, batch.Mutations...)
				consulted := make([]ownedConsulted, len(batch.Consulted))
				for i, row := range batch.Consulted {
					consulted[i] = ownedConsulted{dbi: row.DBI, key: row.Key}
				}
				if _, err = updateNativeConsultedImages(reader.txn, s.dbis, consulted); err != nil {
					return err
				}
				if strings.HasSuffix(name, "_final") {
					finalConsulted = append([]ownedConsulted(nil), consulted...)
					for _, row := range batch.Consulted {
						value, present, readErr := reader.Get(row.DBI, row.Key)
						if readErr != nil {
							return readErr
						}
						finalValues = append(finalValues, value)
						image := updateImage{}
						if present {
							image, err = updateOwnedImage(value)
							if err != nil {
								return err
							}
						}
						finalImages = append(finalImages, image)
					}
				}
				changeCanonical := func(genesis bool) error {
					h := uint64(1)
					beforePresent := false
					if genesis {
						h = 0
						beforePresent = true
					}
					key, _ := HeightKey(1, h)
					hash := modelHash(900 + h)
					changes := []Mutation{{DBI: readDBIsLiteral()[2], Key: key, BeforePresent: beforePresent, AfterKind: AfterLiteral, Literal: ChainValue(hash, [32]byte{}, modelWork(false))}}
					if genesis {
						oldHash := modelHash(71)
						if name == "H11a" {
							oldHash = [32]byte(rows[3].Literal[:32])
						}
						changes = append(changes, canonicalDelete(canonicalOwnerLiteral(1, 0, oldHash)))
					}
					changes = append(changes, canonicalOwnerLiteral(1, h, hash))
					changedRows = changes
					requireUpdateTruth(t, s.updateNative(updateNativePlan(t, changes...), nil, reader.txn), 2, true, nil, nil)
					return nil
				}
				if strings.HasPrefix(name, "H10_") {
					mustEnvironment(t, changeCanonical(strings.Contains(name, "g0")))
					if !strings.HasSuffix(name, "_final") {
						native = s.updateNative(mutations, consulted, reader.txn)
					}
					return nil
				}
				if name != "H11c" {
					execute := append([]ownedMutation(nil), mutations...)
					if name == "H11d" {
						third := *plan
						third.NextGenerationID++
						execute[0].literal, err = third.Encode()
						if err != nil {
							return err
						}
					}
					requireUpdateTruth(t, s.updateNative(execute, consulted, reader.txn), 2, true, nil, nil)
				}
				if name == "H11e_g0" || name == "H11e_g1" {
					mustEnvironment(t, changeCanonical(name == "H11e_g0"))
				}
				handles := s.dbis
				if name == "H11e_unreadable" {
					handles[0] = ^handles[0]
				}
				native = updateNativeReadback(s.env, handles, mutations, consulted, reader.txn, primary)
				return nil
			}))
			if strings.HasSuffix(name, "_final") {
				// Separate final-match owner composition; there is no public injection seam.
				mustEnvironment(t, s.View(func(reader *Reader) error {
					var err error
					for i, row := range finalConsulted {
						err = updateNativeMatch(reader.txn, s.dbis[row.dbi.Rank], row.key, finalImages[i], "final update image mismatch")
						if err != nil {
							break
						}
					}
					if err == nil {
						t.Fatal("final consulted mismatch missing")
					}
					native = updateNativeConsumed(1, false, err, nil, 2)
					return nil
				}))
				runtime.KeepAlive(finalValues)
			}
			// Read back the actual observed authority before applying terminal disposition.
			observed, _ = bootstrapRow(t, s, []byte{2})
			wantTruth, wantStage := CommitTruth(3), UpdateStage(3)
			if strings.HasPrefix(name, "H10_") {
				wantTruth, wantStage = 1, native.stage
				engine := requireEngineError(t, native.primary, EngineStateMismatch, operationUpdate, codeProblem)
				wantDiagnostic := "OLD/write snapshot mismatch"
				if strings.HasSuffix(name, "_final") {
					wantDiagnostic = "final update image mismatch"
				}
				if engine.Cause != nil || engine.Diagnostic != wantDiagnostic {
					t.Fatal("consulted mismatch cause")
				}
			}
			if name == "H11a" || name == "H11b" {
				wantTruth = 2
			}
			if name == "H11c" {
				wantTruth = 1
			}
			if native.truth != wantTruth || native.stage != wantStage || native.valid() != nil {
				t.Fatalf("archive native truth/stage: %+v", native)
			}
			if !strings.HasPrefix(name, "H10_") && !sameError(native.primary, primary) {
				t.Fatal("native primary identity")
			}
			truth, stage, terminal := s.applyUpdateOutcome(native, nil, nil, false)
			out := archiveProfileOutcome(ArchiveProfileOutcome{Truth: truth, Stage: stage, Err: terminal}, planned, "", errors.New("decision"))
			if out.Truth != wantTruth || out.Stage != wantStage || !sameError(out.Err, terminal) || out.Decision != "" || (out.Authority != nil) != (wantTruth == 2) {
				t.Fatalf("native archive projection: %+v", out)
			}
			if wantTruth == 1 && !bytes.Equal(observed, before[0]) {
				t.Fatal("native OLD exact authority")
			}
			if wantTruth == 2 {
				want := append([]byte(nil), before[0]...)
				want[1] = 2
				if !bytes.Equal(observed, want) || !reflect.DeepEqual(out.Authority, planned) {
					t.Fatal("native NEW exact authority")
				}
			}
			if name == "H11d" && (bytes.Equal(observed, before[0]) || bytes.Equal(observed, func() []byte { b := append([]byte(nil), before[0]...); b[1] = 2; return b }())) {
				t.Fatal("third image was neither")
			}
			if strings.HasPrefix(name, "H11") {
				commit, ok := terminal.(*CommitError)
				if !ok || !sameError(commit.Cause, primary) || commit.Truth != wantTruth || !sameError(commit.ReadbackCause, native.secondary) {
					t.Fatal("commit cause/readback order")
				}
				if (native.secondary != nil) != (name == "H11e_unreadable") {
					t.Fatal("readback cause presence")
				}
				if name == "H11e_unreadable" {
					requireEnvironmentError(t, native.secondary, EngineLocalInvariant, operationUpdate, codeBadDBI, expectedNativeDiagnostic(codeBadDBI))
				}
			}
			if s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil {
				t.Fatal("native consumed resources")
			}
			archiveCached(t, s, out, bootstrapOwner(t))
			r, err := Open(path, cfg)
			mustEnvironment(t, err)
			defer func() { _ = r.Close() }()
			bootstrapRequireRow(t, r, []byte{2}, observed, "native persisted observation")
			for i, row := range rows {
				want := before[i]
				if i == 0 {
					want = observed
				}
				for _, change := range changedRows {
					if change.DBI == row.DBI && bytes.Equal(change.Key, row.Key) {
						want = change.Literal
						if change.AfterKind == AfterAbsent {
							want = nil
						}
					}
				}
				consultedRequireImage(t, r, row.DBI, row.Key, want, want != nil, "native unchanged/changed row")
			}
			for _, change := range changedRows {
				want := change.Literal
				if change.AfterKind == AfterAbsent {
					want = nil
				}
				consultedRequireImage(t, r, change.DBI, change.Key, want, want != nil, "native sibling row")
			}
			if strings.Contains(name, "g1") {
				counts[2]++
				counts[7]++
			}
			if bootstrapCounts(t, r, "native reopened") != counts {
				t.Fatal("native exact census")
			}
			bootstrapRequireRow(t, r, []byte{0}, before[len(before)-2], "native version")
			bootstrapRequireRow(t, r, []byte{1}, before[len(before)-1], "native config")
		})
	}
	t.Run("H15", testArchiveRetained)
}

func testArchiveRetained(t *testing.T) {
	for _, name := range []string{"commit_write", "abort_write", "read", "old_cleanup", "uncommitted_join", "commit_join", "cleanup_only", "close_busy"} {
		t.Run(name, func(t *testing.T) {
			s := newUpdateStore(t)
			cfg, dbis, env, writer := s.config, s.dbis, s.env, s.writer
			format, identity := s.format.Load(), s.databaseID
			primary := nativeError(operationUpdate, codeENOSPC)
			secondary := errors.Join(nativeError(operationAbort, codeEIO), nativeError(operationGet, codeCorrupted))
			cleanup := nativeError(operationAbort, codeThreadMismatch)
			var native updateNativeOutcome
			var release func() error
			var err error
			if name == "abort_write" {
				native, release, err = fixtureUpdateAbortWrongThread(s)
			} else {
				native, release, err = fixtureUpdateWrongThread(s)
			}
			mustEnvironment(t, err)
			defer func() {
				if release != nil {
					_ = release()
				}
			}()
			token := updateRetained(native)
			var oldCleanup error
			oldRetained := false
			switch name {
			case "read":
				native = updateNativeRetainedRead(primary, cleanup, token)
			case "old_cleanup":
				native = updateNativeConsumed(2, true, primary, nil, 3)
				oldCleanup, oldRetained = cleanup, true
			case "uncommitted_join":
				native = updateNativeRetainedWrite(false, primary, secondary, token, 1)
				oldCleanup = cleanup
			case "commit_join":
				native = updateNativeConsumed(2, true, primary, secondary, 3)
				oldCleanup, oldRetained = cleanup, true
			case "cleanup_only":
				native = updateNativeConsumed(2, true, nil, nil, 3)
				oldCleanup, oldRetained = cleanup, true
			case "close_busy":
				mustEnvironment(t, release())
				release = nil
				token = nil
				native = updateNativeConsumed(1, false, primary, nil, 1)
			}
			if name == "close_busy" {
				_, closeRelease, e := fixtureHeldUpdate(s)
				mustEnvironment(t, e)
				release = closeRelease
			}
			truth, stage, terminal := s.applyUpdateOutcome(native, token, oldCleanup, oldRetained)
			a := modelBase(2, 0, 0)
			out := archiveProfileOutcome(ArchiveProfileOutcome{Truth: truth, Stage: stage, Err: terminal}, &a, "", errors.New("decision"))
			if out.Truth != native.truth || out.Stage != native.stage || !sameError(out.Err, terminal) || out.Decision != "" || (out.Authority != nil) != (native.truth == 2 && native.stage == 3) {
				t.Fatal("retained raw projection")
			}
			if name == "close_busy" {
				engine := requireEngineError(t, terminal, EngineConcurrency, operationClose, codeBusy)
				if !sameError(engine.Cause, primary) || s.state != storeCLOSEBLOCKED || s.env != env || s.writer != writer {
					t.Fatal("close busy primary/retention")
				}
			} else if s.state != storePOISONEDTHREAD || s.txn != token || s.env != env || s.writer != writer || s.config != (ConfigV1{}) || s.dbis != (Store{}).dbis {
				t.Fatal("live retained resource shape")
			}
			switch name {
			case "uncommitted_join":
				parts := terminal.(interface{ Unwrap() []error }).Unwrap()
				if len(parts) != 3 || !sameError(parts[0], primary) || !sameError(parts[1], secondary) || !sameError(parts[2], cleanup) {
					t.Fatal("uncommitted nested join order")
				}
			case "commit_join":
				commit := terminal.(*CommitError)
				parts := commit.ReadbackCause.(interface{ Unwrap() []error }).Unwrap()
				if !sameError(commit.Cause, primary) || len(parts) != 2 || !sameError(parts[0], secondary) || !sameError(parts[1], cleanup) {
					t.Fatal("commit nested readback join")
				}
			case "cleanup_only":
				commit := terminal.(*CommitError)
				if !sameError(commit.Cause, cleanup) || commit.ReadbackCause != nil {
					t.Fatal("cleanup-only cause")
				}
			case "commit_write":
				commit := terminal.(*CommitError)
				e := requireEngineError(t, commit.Cause, EngineLocalInvariant, operationUpdate, codeThreadMismatch)
				if e.Cause != nil {
					t.Fatal("commit THREAD cause")
				}
			case "abort_write":
				parts := terminal.(interface{ Unwrap() []error }).Unwrap()
				if len(parts) != 2 || !sameError(parts[0], native.primary) || !sameError(parts[1], native.secondary) {
					t.Fatal("abort THREAD secondary")
				}
				e := requireEngineError(t, parts[1], EngineLocalInvariant, operationAbort, codeThreadMismatch)
				if e.Cause != nil {
					t.Fatal("abort THREAD is secondary")
				}
			case "read":
				commit := terminal.(*CommitError)
				if !sameError(commit.Cause, primary) || !sameError(commit.ReadbackCause, cleanup) {
					t.Fatal("retained read cause")
				}
			case "old_cleanup":
				commit := terminal.(*CommitError)
				if !sameError(commit.Cause, primary) || !sameError(commit.ReadbackCause, cleanup) {
					t.Fatal("old-helper cleanup cause")
				}
			}
			archiveCached(t, s, out, bootstrapOwner(t))
			if release != nil {
				mustEnvironment(t, release())
				release = nil
			}
			// Only the fixture owner releases live tokens; restoration follows release.
			s.state, s.txn, s.config, s.dbis, s.terminal, s.terminalTruth = storeOPEN, nil, cfg, dbis, nil, 0
			s.format.Store(format)
			s.databaseID = identity
			mustEnvironment(t, s.Close())
		})
	}
}

func TestFixtureModesAndFixedOperations(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic string
		mode             fixtureMode
		operation        engineOperation
	}{
		{"unexpected DBI", "SchemaV2 main cardinality mismatch", fixtureUnexpectedDBI, operationInit},
		{"third meta row", "SchemaV2 metadata cardinality mismatch", fixtureThirdMetaRow, operationInit},
		{"unnamed main row", "SchemaV2 main cardinality mismatch", fixtureUnnamedMainRow, operationOpen},
		{"wrong schema version", "invalid SchemaV2 version row", fixtureWrongSchemaVersion, operationOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "db")
			var store *Store
			var err error
			if tc.mode <= fixtureThirdMetaRow {
				store, err = fixtureCreate(path, environmentConfig(), tc.mode)
			} else {
				path = closedEnvironment(t)
				store, err = fixtureOpen(path, environmentConfig(), tc.mode)
			}
			engine := requireEnvironmentError(t, err, EngineIntegrity, tc.operation, -30793, tc.diagnostic)
			fixtureOwner.Lock()
			active := fixtureOwner.active
			fixtureOwner.Unlock()
			if store != nil || active || tc.mode == fixtureWrongSchemaVersion && engine.Cause != errSchema || tc.mode != fixtureWrongSchemaVersion && engine.Cause != nil {
				t.Fatalf("fixture retained state or Cause: %v/%v/%v", store, active, engine.Cause)
			}
			requireArtifact(t, path, 0o700, false)
			for _, name := range []string{"rubin-writer.lock", "mdbx.dat", "mdbx.lck"} {
				requireArtifact(t, filepath.Join(path, name), 0o600, name == "rubin-writer.lock")
			}
			handle, result, lockErr := filelock.AcquireDirectory(path)
			if lockErr != nil || result != "" || handle == nil {
				t.Fatalf("writer retained: %q %v", result, lockErr)
			}
			mustEnvironment(t, handle.Release())
		})
	}
	for _, mode := range []fixtureMode{0, 5} {
		if err := armFixture(filepath.Join(t.TempDir(), "db"), mode); err == nil {
			t.Fatalf("invalid fixture mode %d accepted", mode)
		}
	}
	t.Run("target-bound owner", func(t *testing.T) {
		target, sibling := filepath.Join(t.TempDir(), "target"), filepath.Join(t.TempDir(), "sibling")
		mustEnvironment(t, armFixture(target, fixtureUnexpectedDBI))
		defer clearFixture()
		if armFixture(sibling, fixtureThirdMetaRow) == nil || claimFixturePath(sibling) != 0 || claimFixturePath(target) != fixtureUnexpectedDBI || claimFixturePath(target) != 0 {
			t.Fatal("fixture owner was retargeted, prematurely consumed or reused")
		}
	})
	for _, mode := range []fixtureMode{fixtureUnnamedMainRow, fixtureWrongSchemaVersion} {
		if store, err := fixtureCreate(filepath.Join(t.TempDir(), "db"), environmentConfig(), mode); store != nil || err == nil {
			t.Fatalf("Create phase accepted mode %d", mode)
		}
	}
	for _, mode := range []fixtureMode{fixtureUnexpectedDBI, fixtureThirdMetaRow} {
		if store, err := fixtureOpen(filepath.Join(t.TempDir(), "db"), environmentConfig(), mode); store != nil || err == nil {
			t.Fatalf("Open phase accepted mode %d", mode)
		}
	}
	store, copied, err := fixtureOpenReverseUTXO(filepath.Join(t.TempDir(), "db"))
	requireNoStore(t, store, err, EngineIntegrity, operationOpen, -30793, "SchemaV2 DBI flags mismatch")
	if string(copied) != string(configBytes(environmentConfig())) {
		t.Fatalf("copied metadata changed: %x", copied)
	}
	store, err = fixtureOpenStoredReadersMismatch(filepath.Join(t.TempDir(), "db"))
	effective := requireNoStore(t, store, err, EngineIntegrity, operationOpen, -30793, "effective environment mismatch")
	if effective.Cause == nil || effective.Cause.Error() != "MaxReaders: got 493, want 492" {
		t.Fatalf("effective mismatch cause=%v", effective.Cause)
	}
	path := filepath.Join(t.TempDir(), "db")
	store, err = Create(path, environmentConfig())
	mustEnvironment(t, err)
	busy, abortErr, closeErr := fixtureCloseBusy(path, store)
	requireEnvironmentError(t, busy, EngineConcurrency, operationClose, -30778, expectedNativeDiagnostic(-30778))
	if abortErr != nil || closeErr != nil || store.state != storeCLOSED {
		t.Fatalf("Close-BUSY cleanup: %v/%v/%s", abortErr, closeErr, store.state)
	}
	store, err = Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	if rc, cleanup := fixtureWriteOwnerMismatch(store); rc != -30416 || cleanup != nil || store.state != storeOPEN {
		t.Fatalf("owner mismatch=%d cleanup=%v state=%s", rc, cleanup, store.state)
	}
	mustEnvironment(t, store.Close())
}

func fixturePrefixKey(rank uint8, id, tail byte, undoEntry bool) []byte {
	var width int
	switch rank {
	case 1:
		width = 44
	case 2, 6:
		width = 16
	case 5:
		width = 33
		if undoEntry {
			width = 77
		}
	}
	key := make([]byte, width)
	key[7] = id
	if rank == 5 {
		key[0], key[7] = id, 0
		if undoEntry {
			key[32] = 1
		}
	}
	key[len(key)-1] = tail
	return key
}

func fixturePrefixValue(rank uint8, undoEntry bool, maximum bool) []byte {
	switch rank {
	case 1:
		if maximum {
			return make([]byte, 65_560)
		}
		return make([]byte, 20)
	case 2, 6:
		return make([]byte, 104)
	default:
		if undoEntry {
			if maximum {
				return make([]byte, 65_560)
			}
			return make([]byte, 20)
		}
		value := make([]byte, 33)
		value[0] = 1
		return value
	}
}

func fixtureMalformedCanonicalKey(id, tail byte) []byte {
	key := make([]byte, 17)
	key[7], key[15] = id, tail
	return key
}

func readFixturePrefixPage(t *testing.T, store *Store, dbi DBI, prefix, after []byte, maxRows uint32, maxBytes uint64) PrefixPage {
	t.Helper()
	var page PrefixPage
	mustEnvironment(t, store.View(func(reader *Reader) error {
		var err error
		page, err = reader.PrefixPage(dbi, prefix, after, maxRows, maxBytes)
		return err
	}))
	return page
}

func requireFixturePage(t *testing.T, page PrefixPage, stop PrefixPageStop, keys ...[]byte) {
	t.Helper()
	if page.Stop != stop || len(page.Rows) != len(keys) {
		t.Fatalf("PrefixPage result=%#v, want stop=%d rows=%d", page, stop, len(keys))
	}
	for i, key := range keys {
		if !bytes.Equal(page.Rows[i].Key, key) {
			t.Fatalf("PrefixPage key[%d]=%x, want %x", i, page.Rows[i].Key, key)
		}
	}
}

func TestReaderPrefixPageNativeFixtures(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbis := readDBIsLiteral()
	before := make(map[uint8][]byte)
	wants := make(map[uint8][][]byte)
	wantValues := make(map[uint8][][]byte)
	rows := make([]fixtureRawRow, 0, 10)
	for _, rank := range []uint8{1, 2, 6} {
		before[rank] = fixturePrefixKey(rank, 2, 1, false)
		rows = append(rows, fixtureRawRow{dbi: dbis[rank], key: before[rank], value: fixturePrefixValue(rank, false, false)})
		for _, tail := range []byte{1, 2} {
			key := fixturePrefixKey(rank, 3, tail, false)
			value := fixturePrefixValue(rank, false, false)
			for i := range value {
				value[i] = byte(int(rank) + int(tail) + i)
			}
			wants[rank] = append(wants[rank], key)
			wantValues[rank] = append(wantValues[rank], value)
			rows = append(rows, fixtureRawRow{dbi: dbis[rank], key: key, value: value})
		}
		rows = append(rows, fixtureRawRow{dbi: dbis[rank], key: fixturePrefixKey(rank, 4, 1, false), value: fixturePrefixValue(rank, false, false)})
	}
	manifest := fixturePrefixKey(5, 3, 0, false)
	entry := fixturePrefixKey(5, 3, 1, true)
	before[5] = fixturePrefixKey(5, 2, 0, false)
	manifestValue := fixturePrefixValue(5, false, false)
	entryValue := fixturePrefixValue(5, true, false)
	for i := range manifestValue {
		manifestValue[i] = byte(31 + i)
	}
	for i := range entryValue {
		entryValue[i] = byte(63 + i)
	}
	wants[5] = [][]byte{manifest, entry}
	wantValues[5] = [][]byte{manifestValue, entryValue}
	rows = append(rows,
		fixtureRawRow{dbi: dbis[5], key: before[5], value: fixturePrefixValue(5, false, false)},
		fixtureRawRow{dbi: dbis[5], key: manifest, value: manifestValue},
		fixtureRawRow{dbi: dbis[5], key: entry, value: entryValue},
		fixtureRawRow{dbi: dbis[5], key: fixturePrefixKey(5, 4, 0, false), value: fixturePrefixValue(5, false, false)},
	)
	mustEnvironment(t, fixtureSeedRows(store, rows...))

	for _, rank := range []uint8{1, 2, 5, 6} {
		prefix, _, minimum := prefixPageRequest(rank, 3)
		if rank == 2 || rank == 6 {
			minimum = 1_000
		}
		page := readFixturePrefixPage(t, store, dbis[rank], prefix, nil, 10, minimum)
		for _, row := range page.Rows {
			if bytes.Equal(row.Key, before[rank]) {
				t.Fatalf("rank %d page included before-prefix sibling", rank)
			}
		}
		requireFixturePage(t, page, PrefixPageStop(1), wants[rank]...)
		for i, row := range page.Rows {
			if !bytes.Equal(row.Value, wantValues[rank][i]) {
				t.Fatalf("rank %d value[%d]=%x, want %x", rank, i, row.Value, wantValues[rank][i])
			}
		}
		emptyPrefix, _, emptyMinimum := prefixPageRequest(rank, 9)
		empty := readFixturePrefixPage(t, store, dbis[rank], emptyPrefix, nil, 10, emptyMinimum)
		if empty.Rows != nil || empty.Stop != PrefixPageStop(1) {
			t.Fatalf("rank %d empty page=%#v", rank, empty)
		}
	}

	maximumRows := []fixtureRawRow{
		{dbi: dbis[1], key: fixturePrefixKey(1, 8, 255, false), value: fixturePrefixValue(1, false, true)},
		{dbi: dbis[5], key: fixturePrefixKey(5, 8, 255, true), value: fixturePrefixValue(5, true, true)},
	}
	mustEnvironment(t, fixtureSeedRows(store, maximumRows...))
	for _, rank := range []uint8{1, 5} {
		prefix, _, minimum := prefixPageRequest(rank, 8)
		page := readFixturePrefixPage(t, store, dbis[rank], prefix, nil, 1, minimum)
		if len(page.Rows) != 1 || page.Stop != PrefixPageStop(1) || len(page.Rows[0].Key) != map[uint8]int{1: 44, 5: 77}[rank] || len(page.Rows[0].Value) != 65_560 {
			t.Fatalf("maximum rank %d page=%#v", rank, page)
		}
	}
}

func TestReaderPrefixPageResultMatrix(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	keys := [][]byte{
		fixturePrefixKey(2, 5, 1, false),
		fixturePrefixKey(2, 5, 2, false),
		fixturePrefixKey(2, 5, 3, false),
	}
	rows := make([]fixtureRawRow, 0, len(keys)+1)
	for _, key := range keys {
		rows = append(rows, fixtureRawRow{dbi: dbi, key: key, value: fixturePrefixValue(2, false, false)})
	}
	oneKey := fixturePrefixKey(2, 6, 1, false)
	rows = append(rows, fixtureRawRow{dbi: dbi, key: oneKey, value: fixturePrefixValue(2, false, false)})
	mustEnvironment(t, fixtureSeedRows(store, rows...))
	prefix, _, _ := prefixPageRequest(2, 5)

	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 1, 1_000), PrefixPageStop(2), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 10, 120), PrefixPageStop(3), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 10, 224), PrefixPageStop(3), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 1, 120), PrefixPageStop(2), keys[0])
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 2, 1_000), PrefixPageStop(2), keys[0], keys[1])
	onePrefix, _, _ := prefixPageRequest(2, 6)
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, onePrefix, nil, 1, 120), PrefixPageStop(1), oneKey)
}

func TestReaderPrefixPageContinuation(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	keys := [][]byte{
		fixturePrefixKey(2, 11, 10, false),
		fixturePrefixKey(2, 11, 11, false),
		fixturePrefixKey(2, 11, 20, false),
	}
	for _, key := range keys {
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: dbi, key: key, value: fixturePrefixValue(2, false, false)}))
	}
	prefix, _, _ := prefixPageRequest(2, 11)
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, nil, 10, 1_000), PrefixPageStop(1), keys...)
	var got [][]byte
	var after []byte
	exhausted := false
	for range 4 {
		page := readFixturePrefixPage(t, store, dbi, prefix, after, 1, 1_000)
		for _, row := range page.Rows {
			got = append(got, append([]byte(nil), row.Key...))
		}
		if page.Stop == PrefixPageStop(1) {
			exhausted = true
			break
		}
		if page.Stop != PrefixPageStop(2) || len(page.Rows) != 1 {
			t.Fatalf("continuation page=%#v", page)
		}
		after = page.Rows[0].Key
	}
	if !exhausted || len(got) != len(keys) {
		t.Fatalf("concatenated page exhausted/count=%v/%d", exhausted, len(got))
	}
	for i := range keys {
		if !bytes.Equal(got[i], keys[i]) {
			t.Fatalf("concatenated key[%d]=%x", i, got[i])
		}
	}
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, keys[0], 10, 1_000), PrefixPageStop(1), keys[1], keys[2])
	absent := fixturePrefixKey(2, 11, 15, false)
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, absent, 10, 1_000), PrefixPageStop(1), keys[2])
	mustEnvironment(t, fixtureDeletePrefixRow(store, dbi, keys[1]))
	requireFixturePage(t, readFixturePrefixPage(t, store, dbi, prefix, keys[1], 10, 1_000), PrefixPageStop(1), keys[2])
}

func TestReaderPrefixPageMixedUndoContinuation(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	undoDBI := readDBIsLiteral()[5]
	undoPrefix, _, undoMinimum := prefixPageRequest(5, 16)
	manifest := fixturePrefixKey(5, 16, 0, false)
	entry := fixturePrefixKey(5, 16, 1, true)
	absentEntry := fixturePrefixKey(5, 16, 0, true)
	mustEnvironment(t, fixtureSeedRows(store,
		fixtureRawRow{dbi: undoDBI, key: manifest, value: fixturePrefixValue(5, false, false)},
		fixtureRawRow{dbi: undoDBI, key: entry, value: fixturePrefixValue(5, true, false)},
	))
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, nil, 1, undoMinimum), PrefixPageStop(2), manifest)
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, manifest, 1, undoMinimum), PrefixPageStop(1), entry)
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, entry, 1, undoMinimum), PrefixPageStop(1))
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, absentEntry, 1, undoMinimum), PrefixPageStop(1), entry)
	mustEnvironment(t, fixtureDeletePrefixRow(store, undoDBI, entry))
	requireFixturePage(t, readFixturePrefixPage(t, store, undoDBI, undoPrefix, absentEntry, 1, undoMinimum), PrefixPageStop(1))
}

func TestReaderPrefixPageMaximumRows(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	prefix, _, _ := prefixPageRequest(2, 22)
	keys := make([][]byte, int(MaxPrefixPageRows)+1)
	rows := make([]fixtureRawRow, len(keys))
	for i := range keys {
		keys[i] = make([]byte, 16)
		copy(keys[i], prefix)
		binary.BigEndian.PutUint64(keys[i][8:], uint64(i+1))
		rows[i] = fixtureRawRow{dbi: dbi, key: keys[i], value: fixturePrefixValue(2, false, false)}
	}
	mustEnvironment(t, fixtureSeedRows(store, rows...))
	first := readFixturePrefixPage(t, store, dbi, prefix, nil, MaxPrefixPageRows, 1_000_000)
	if first.Stop != PrefixPageRowLimit || len(first.Rows) != int(MaxPrefixPageRows) {
		t.Fatalf("maximum-row first page=%d/%d", first.Stop, len(first.Rows))
	}
	for i, row := range first.Rows {
		if !bytes.Equal(row.Key, keys[i]) {
			t.Fatalf("maximum-row key[%d]=%x, want %x", i, row.Key, keys[i])
		}
	}
	last := readFixturePrefixPage(t, store, dbi, prefix, first.Rows[len(first.Rows)-1].Key, MaxPrefixPageRows, 1_000_000)
	requireFixturePage(t, last, PrefixPageExhausted, keys[len(keys)-1])
}

func TestReaderPrefixPageOwnership(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbi := readDBIsLiteral()[2]
	keys := [][]byte{fixturePrefixKey(2, 12, 1, false), fixturePrefixKey(2, 12, 2, false)}
	values := [][]byte{fixturePrefixValue(2, false, false), fixturePrefixValue(2, false, false)}
	values[0][0], values[1][0] = 31, 32
	mustEnvironment(t, fixtureSeedRows(store,
		fixtureRawRow{dbi: dbi, key: keys[0], value: values[0]},
		fixtureRawRow{dbi: dbi, key: keys[1], value: values[1]},
	))
	prefix, after, _ := prefixPageRequest(2, 12)
	after[len(after)-1] = 0
	var page PrefixPage
	mustEnvironment(t, store.View(func(reader *Reader) error {
		var pageErr error
		page, pageErr = reader.PrefixPage(dbi, prefix, after, 10, 1_000)
		if pageErr != nil {
			return pageErr
		}
		requireFixturePage(t, page, PrefixPageExhausted, keys...)
		nativeKey, nativeValue, addressErr := fixturePrefixNativeAddresses(reader, dbi, page.Rows[0].Key, len(page.Rows[0].Value))
		if addressErr != nil {
			return addressErr
		}
		if unsafe.Pointer(unsafe.SliceData(page.Rows[0].Key)) == nativeKey {
			t.Fatal("PrefixPage key aliases native backing")
		}
		if unsafe.Pointer(unsafe.SliceData(page.Rows[0].Value)) == nativeValue {
			t.Fatal("PrefixPage value aliases native backing")
		}
		return nil
	}))
	prefix[0], after[0] = 255, 255
	page.Rows[0].Key[0], page.Rows[0].Value[0] = 254, 253
	if page.Rows[1].Key[0] == 254 || page.Rows[1].Value[0] == 253 {
		t.Fatal("PrefixPage rows share backing storage")
	}
	freshPrefix, _, _ := prefixPageRequest(2, 12)
	fresh := readFixturePrefixPage(t, store, dbi, freshPrefix, nil, 10, 1_000)
	if len(fresh.Rows) != 2 || !bytes.Equal(fresh.Rows[0].Key, keys[0]) || !bytes.Equal(fresh.Rows[1].Key, keys[1]) || !bytes.Equal(fresh.Rows[0].Value, values[0]) || !bytes.Equal(fresh.Rows[1].Value, values[1]) {
		t.Fatal("PrefixPage returned borrowed or input-aliased bytes")
	}
}

func TestReaderPrefixPageMalformedDisposition(t *testing.T) {
	dbis := readDBIsLiteral()
	for mode := uint32(1); mode <= 5; mode++ {
		prefix, _, _ := prefixPageRequest(2, 1)
		var err error
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			err = fixturePrefixNativeShape(dbis[2], prefix, prefix, mode)
		}()
		if recovered != nil {
			t.Fatalf("native shape mode %d panicked: %v", mode, recovered)
		}
		if err == nil {
			t.Fatalf("native shape mode %d accepted", mode)
		} else {
			engine := requireEnvironmentError(t, err, EngineLocalInvariant, engineOperation("prefix-page"), codeProblem, "mdbx_get_equal_or_great returned invalid result shape")
			if engine.Cause != nil || engine.ReopenRequired {
				t.Fatalf("native shape mode %d Cause/Reopen=%v/%v", mode, engine.Cause, engine.ReopenRequired)
			}
		}
	}

	type malformedCase struct {
		name, diagnostic string
		class            EngineClass
		code             int
		reopen           bool
		rows             []fixtureRawRow
	}
	stored := func(name string, rank uint8, key, value []byte, diagnostic string) malformedCase {
		return malformedCase{name, diagnostic, EngineIntegrity, codeInvalid, true, []fixtureRawRow{{dbi: dbis[rank], key: key, value: value}}}
	}
	const keyDiagnostic = "stored key outside SchemaV2 prefix-page domain"
	const valueDiagnostic = "stored value width outside SchemaV2 bound"
	utxo, staged := fixturePrefixKey(1, 13, 1, false), fixturePrefixKey(6, 13, 1, false)
	manifest, entry := fixturePrefixKey(5, 13, 0, false), fixturePrefixKey(5, 13, 1, true)
	invalidManifest := append(append([]byte(nil), manifest...), 0)
	invalidEntry := append([]byte(nil), entry[:76]...)
	for _, tc := range []malformedCase{
		{
			name:       "native envelope key",
			diagnostic: "mdbx_get_equal_or_great returned invalid result shape",
			class:      EngineLocalInvariant,
			code:       codeProblem,
			rows:       []fixtureRawRow{{dbi: dbis[2], key: append(fixturePrefixKey(2, 13, 1, false), make([]byte, 62)...), value: make([]byte, 104)}},
		},
		{name: "native envelope sibling key", diagnostic: "mdbx_get_equal_or_great returned invalid result shape", class: EngineLocalInvariant, code: codeProblem, rows: []fixtureRawRow{{dbi: dbis[2], key: append(fixturePrefixKey(2, 14, 1, false), make([]byte, 62)...), value: make([]byte, 104)}}},
		stored("equal malformed key", 2, []byte{0, 0, 0, 0, 0, 0, 0, 13}, make([]byte, 104), keyDiagnostic),
		stored("invalid key", 2, fixtureMalformedCanonicalKey(13, 1), make([]byte, 104), keyDiagnostic),
		stored("invalid value", 2, fixturePrefixKey(2, 13, 1, false), make([]byte, 103), valueDiagnostic),
		stored("oversize value", 2, fixturePrefixKey(2, 13, 1, false), make([]byte, 105), valueDiagnostic),
		stored("utxo invalid key", 1, utxo[:43], make([]byte, 20), keyDiagnostic),
		stored("utxo value below minimum", 1, utxo, make([]byte, 19), valueDiagnostic),
		stored("utxo value above maximum", 1, utxo, make([]byte, 65_561), valueDiagnostic),
		stored("staged invalid key", 6, staged[:15], make([]byte, 104), keyDiagnostic),
		stored("staged value below minimum", 6, staged, make([]byte, 103), valueDiagnostic),
		stored("staged value above maximum", 6, staged, make([]byte, 105), valueDiagnostic),
		stored("undo manifest invalid key", 5, invalidManifest, fixturePrefixValue(5, false, false), keyDiagnostic),
		stored("undo manifest value below minimum", 5, manifest, make([]byte, 32), valueDiagnostic),
		stored("undo manifest value above maximum", 5, manifest, make([]byte, 34), valueDiagnostic),
		stored("undo entry invalid key", 5, invalidEntry, make([]byte, 20), keyDiagnostic),
		stored("undo entry value below minimum", 5, entry, make([]byte, 19), valueDiagnostic),
		stored("undo entry value above maximum", 5, entry, make([]byte, 65_561), valueDiagnostic),
		{
			name:       "lookahead discards rows",
			diagnostic: keyDiagnostic,
			class:      EngineIntegrity,
			code:       codeInvalid,
			reopen:     true,
			rows: []fixtureRawRow{
				{dbi: dbis[2], key: fixturePrefixKey(2, 13, 1, false), value: make([]byte, 104)},
				{dbi: dbis[2], key: fixtureMalformedCanonicalKey(13, 2), value: make([]byte, 104)},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rank := tc.rows[0].dbi.Rank
			path := filepath.Join(t.TempDir(), "db")
			store, err := Create(path, environmentConfig())
			mustEnvironment(t, err)
			for _, row := range tc.rows {
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, row.dbi, row.key, row.value))
			}
			prefix, _, minimum := prefixPageRequest(rank, 13)
			var page PrefixPage
			var recorded error
			returned := store.View(func(reader *Reader) error {
				page, recorded = reader.PrefixPage(dbis[rank], prefix, nil, 1, minimum)
				if page.Rows != nil || page.Stop != 0 {
					t.Fatalf("malformed PrefixPage returned partial rows: %#v", page)
				}
				engine := requireEnvironmentError(t, recorded, tc.class, engineOperation("prefix-page"), tc.code, tc.diagnostic)
				if engine.Cause != nil || engine.ReopenRequired != tc.reopen || reader.failure != recorded || reader.active.Load() {
					t.Fatal("PrefixPage failure was not latched exactly")
				}
				again, againErr := reader.PrefixPage(dbis[rank], prefix, nil, 1, minimum)
				requirePrefixPageError(t, again, againErr, "Reader is not active", nil)
				if reader.failure != recorded {
					t.Fatal("inactive PrefixPage replaced recorded failure")
				}
				_, _, getErr := reader.Get(dbis[0], []byte{1})
				requireEnvironmentError(t, getErr, EngineInvalidInput, operationGet, codeEINVAL, "Reader is not active")
				if reader.failure != recorded {
					t.Fatal("inactive Get replaced PrefixPage failure")
				}
				return nil
			})
			if returned != recorded || store.state != storeCLOSED || !sameError(store.terminal, recorded) || !validStoreShape(store) {
				t.Fatalf("malformed PrefixPage disposition=%v/%s", returned, store.state)
			}
			if next := store.View(func(*Reader) error { t.Fatal("terminal callback invoked"); return nil }); !sameError(next, recorded) {
				t.Fatal("PrefixPage terminal was not reusable")
			}
			if truth, _, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("terminal callback invoked"); return Batch{}, nil }); truth != CommitTruthOld || !sameError(next, recorded) {
				t.Fatal("PrefixPage consumed-read token was rejected")
			}
		})
	}

	t.Run("outside prefix ignores value", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[2], fixturePrefixKey(2, 15, 1, false), make([]byte, 103)))
		prefix, _, minimum := prefixPageRequest(2, 14)
		page := readFixturePrefixPage(t, store, dbis[2], prefix, nil, 1, minimum)
		if page.Rows != nil || page.Stop != PrefixPageStop(1) {
			t.Fatalf("outside-prefix value was decoded: %#v", page)
		}
	})

	t.Run("native error latches", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		prefix, _, minimum := prefixPageRequest(2, 1)
		var recorded error
		returned := store.View(func(reader *Reader) error {
			mustEnvironment(t, fixtureBreakPrefixReader(reader))
			page, pageErr := reader.PrefixPage(dbis[2], prefix, nil, 1, minimum)
			if page.Rows != nil || page.Stop != 0 {
				t.Fatalf("native PrefixPage error returned rows: %#v", page)
			}
			recorded = pageErr
			engine := requireEnvironmentError(t, recorded, EngineLocalInvariant, engineOperation("prefix-page"), codeBadTxn, expectedNativeDiagnostic(codeBadTxn))
			if engine.Cause != nil || engine.ReopenRequired {
				t.Fatalf("native PrefixPage Cause/Reopen=%v/%v", engine.Cause, engine.ReopenRequired)
			}
			return nil
		})
		if returned != recorded || store.state != storeCLOSED || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("native PrefixPage disposition=%v/%s", returned, store.state)
		}
	})
}

// SIDE images are checked on the same database after real Close/Open; Open is
// used only for raw inspection and never restores verified cleanup authority.
func sideRawImages(t *testing.T, s *Store, path string, cfg ConfigV1, rows []Mutation) {
	t.Helper()
	if s.state == storeOPEN {
		mustEnvironment(t, s.Close())
	}
	reopened, err := Open(path, cfg)
	mustEnvironment(t, err)
	defer func() { mustEnvironment(t, reopened.Close()) }()
	for _, row := range rows {
		equal, readErr := FixtureRawRowEqual(reopened, row.DBI.Rank, row.Key, row.Literal)
		if readErr != nil || !equal {
			t.Fatalf("SIDE raw image %d/%x changed: %v", row.DBI.Rank, row.Key, readErr)
		}
	}
}

func sideAuthorityRow(a StorageAuthorityV1) Mutation {
	var value []byte
	encodeAuthority(&value, a)
	return Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, Literal: value}
}

func sideNativeRejections(t *testing.T) {
	for _, name := range []string{"R1a/version", "R1a/phase", "R1a/lifecycle", "R1a/pending", "H1", "H2", "H3/active", "H3/selected", "H3/replay-target", "H4/two-SIDE", "H4/order", "R18c/BLOCKS", "R18c/UNDO", "R18c/carried-BLOCKS", "R18c/carried-UNDO"} {
		t.Run(name, func(t *testing.T) {
			a := sideAuthority(5, 5)
			_, _, rows := sideRows(2, 5)
			s, path := sideStore(t, a, rows...)
			cfg := s.config
			bad := sideAuthority(5, 5)
			var replayBytes []byte
			switch name {
			case "R1a/version":
				bad.Version = 2
			case "R1a/phase":
				bad.Phase = 5
			case "R1a/lifecycle":
				bad.Lifecycle = 3
			case "R1a/pending":
				pending := StorageProfileV1(3)
				bad.Lifecycle, bad.PendingTargetProfile = 2, &pending
			case "H1":
				bad.Cleanup.Spans[0].GenerationID = 1
			case "H2":
				bad.SelectedSide = modelSide(2, 0, 5, 5, 585)
			case "H3/active":
				bad.Cleanup.Spans = []CleanupSpanV1{{Kind: 1, GenerationID: 1}}
			case "H3/selected":
				bad.Cleanup.Spans = []CleanupSpanV1{{Kind: 1, GenerationID: 2}}
				bad.SelectedSide = modelSide(2, 0, 5, 5, 585)
			case "H3/replay-target":
				bad = modelReplay(1)
				var encodeErr error
				replayBytes, encodeErr = bad.Encode()
				mustEnvironment(t, encodeErr)
				decoded, decodeErr := DecodeStorageAuthorityV1(replayBytes)
				mustEnvironment(t, decodeErr)
				if !reflect.DeepEqual(decoded, bad) {
					t.Fatal("legal REPLAY authority did not round-trip")
				}
				// The phase codec cannot persist Replay and Cleanup together.
				bad.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 1, GenerationID: bad.Replay.TargetGenerationID}}}
				if got := ValidateStorageAuthorityV1(bad); got != errSchema {
					t.Fatalf("REPLAY with target cleanup validated: %v", got)
				}
				if encoded, got := bad.Encode(); encoded != nil || got != errSchema {
					t.Fatalf("REPLAY with target cleanup encoded: %x/%v", encoded, got)
				}
			case "H4/two-SIDE":
				bad.Cleanup.Spans = append(bad.Cleanup.Spans, bad.Cleanup.Spans[0])
			case "H4/order":
				bad.NextGenerationID = 4
				bad.Cleanup.Spans = append(bad.Cleanup.Spans, CleanupSpanV1{Kind: 1, GenerationID: 3})
			case "R18c/BLOCKS", "R18c/UNDO":
				bad.B, bad.U = 10, 13690
				span := CleanupSpanV1{Kind: 2, GenerationID: 1, LastHeight: 8}
				if name == "R18c/UNDO" {
					span.Kind, span.LastHeight = 3, 13688
				}
				bad.Cleanup.Spans = append([]CleanupSpanV1{span}, bad.Cleanup.Spans...)
			case "R18c/carried-BLOCKS", "R18c/carried-UNDO":
				bad = modelOrdinary(2, 1, 2, 15129, 1, 10, 13690)
				span := CleanupSpanV1{Kind: 2, GenerationID: 1, LastHeight: 8}
				if name == "R18c/carried-UNDO" {
					span.Kind, span.LastHeight = 3, 13688
				}
				bad.Ordinary.CarriedCleanup = &CleanupV1{Spans: []CleanupSpanV1{span}}
			}
			authority := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, Literal: replayBytes}
			if replayBytes == nil {
				authority = sideAuthorityRow(bad)
			}
			mustEnvironment(t, FixtureSeedRawRow(s, 0, []byte{2}, authority.Literal))
			owner := bootstrapOwner(t)
			var truth CommitTruth
			var stage UpdateStage
			var result error
			evidence, err := FixtureSelectedDamage(s, owner, SelectedDamageProbeOnly, 0, nil, func() { truth, stage, result = s.CleanupSideV1(owner) })
			if truth != CommitTruth(1) || stage != 1 {
				t.Fatalf("SIDE authority tuple: %s/%d/%v", truth, stage, result)
			}
			if name == "H3/replay-target" {
				mustEnvironment(t, result)
			} else {
				requireEnvironmentError(t, result, EngineClass("Integrity"), operationGet, -30793, "invalid storage authority")
			}
			mustEnvironment(t, err)
			if evidence.BeginWrite != 0 || evidence.OldGets != ([8]uint64{1}) {
				t.Fatalf("SIDE authority read before routing: %+v", evidence)
			}
			prunedReleased(t, owner)
			sideRawImages(t, s, path, cfg, append(rows, authority))
		})
	}
}

func sideNativeIdentity(t *testing.T) {
	for _, name := range []string{"R18a/absent", "R18a/width", "R18a/work", "R10", "R18b/absent", "R18b/width", "R18b/work"} {
		t.Run(name, func(t *testing.T) {
			a := sideAuthority(5, 5)
			hash, _, rows := sideRows(2, 5)
			var target Mutation
			diagnostic := "selected side link is absent"
			if strings.HasPrefix(name, "R18b/") {
				a, rows = sideSelected(t, 2, 1440)
				x, _, _ := sideRows(2, 1)
				rows[3].Literal = ChainValue(x, [32]byte{}, [40]byte{39: 1})
				target = rows[5] // after the early x match at height 2
			} else {
				target = rows[1]
			}
			if name == "R10" {
				a.B, a.U = 10, 13690
				key, _ := HeightKey(1, 11)
				target = Mutation{DBI: readDBIsLiteral()[2], Key: key, Literal: make([]byte, 103)}
				rows = append(rows, Mutation{DBI: target.DBI, Key: key, AfterKind: 2, Literal: ChainValue(hash, [32]byte{}, [40]byte{39: 1})}, canonicalOwnerLiteral(1, 11, hash))
				diagnostic = "stored value width outside SchemaV2 bound"
			} else if strings.HasSuffix(name, "/width") {
				target.Literal = make([]byte, 103)
				diagnostic = "stored value width outside SchemaV2 bound"
			} else if strings.HasSuffix(name, "/work") {
				target.Literal = bytes.Clone(target.Literal)
				clear(target.Literal[64:104])
				diagnostic = "selected side link identity is undecodable"
			} else {
				target.Literal = nil
			}
			s, path := sideStore(t, a, rows...)
			cfg := s.config
			if target.Literal == nil {
				mustEnvironment(t, fixtureDeletePrefixRow(s, target.DBI, target.Key))
			} else {
				mustEnvironment(t, FixtureSeedRawRow(s, target.DBI.Rank, target.Key, target.Literal))
			}
			for i := range rows {
				if rows[i].DBI == target.DBI && bytes.Equal(rows[i].Key, target.Key) {
					rows[i].Literal = target.Literal
				}
			}
			owner := bootstrapOwner(t)
			truth, stage, err := s.CleanupSideV1(owner)
			if truth != CommitTruth(1) || stage != 1 {
				t.Fatalf("SIDE identity tuple: %s/%d/%v", truth, stage, err)
			}
			requireEnvironmentError(t, err, EngineClass("Integrity"), operationGet, -30793, diagnostic)
			prunedReleased(t, owner)
			sideRawImages(t, s, path, cfg, append(rows, sideAuthorityRow(a)))
		})
	}
}

func sideNativeBodies(t *testing.T) {
	for _, size := range []int{0, 1, 115, 116, 68000126} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			a := sideAuthority(5, 5)
			hash, _, rows := sideRows(2, 5)
			s, path := sideStore(t, a, rows...)
			cfg := s.config
			mustEnvironment(t, FixtureSeedRawRow(s, 4, hash[:], make([]byte, size)))
			sideRun(t, s, CommitTruth(2))
			a.Cleanup, a.Phase = nil, 1
			rows[0].Literal, rows[1].Literal = nil, nil
			sideRawImages(t, s, path, cfg, append(rows, sideAuthorityRow(a)))
		})
	}
	t.Run("canonical", func(t *testing.T) {
		for _, size := range []int{-1, 1, 116, 68000126} {
			t.Run(fmt.Sprint(size), func(t *testing.T) {
				a := sideAuthority(5, 5)
				a.B, a.U = 10, 13690
				hash, _, rows := sideRows(2, 5)
				key, _ := HeightKey(1, 11)
				rows = append(rows, Mutation{DBI: readDBIsLiteral()[2], Key: key, AfterKind: 2, Literal: ChainValue(hash, [32]byte{}, [40]byte{39: 1})}, canonicalOwnerLiteral(1, 11, hash))
				s, path := sideStore(t, a, rows...)
				cfg := s.config
				rows[0].Literal = nil
				if size < 0 {
					mustEnvironment(t, fixtureDeletePrefixRow(s, readDBIsLiteral()[4], hash[:]))
				} else {
					rows[0].Literal = make([]byte, size)
					mustEnvironment(t, FixtureSeedRawRow(s, 4, hash[:], rows[0].Literal))
				}
				owner := bootstrapOwner(t)
				truth, stage, err := s.CleanupSideV1(owner)
				if truth != CommitTruth(1) || stage != 1 {
					t.Fatalf("canonical body tuple: %s/%d/%v", truth, stage, err)
				}
				requireEnvironmentError(t, err, EngineClass("Integrity"), operationGet, -30793, "invalid cleanup owed artifact")
				prunedReleased(t, owner)
				sideRawImages(t, s, path, cfg, append(rows, sideAuthorityRow(a)))
			})
		}
	})
}

func sideNativeFaults(t *testing.T) {
	for _, row := range []struct {
		name      string
		scenario  SelectedDamageScenario
		truth     CommitTruth
		stage     UpdateStage
		op        engineOperation
		class     EngineClass
		code      int
		secondary bool
	}{
		{"stage1-begin", 3, 1, 1, "update", "IO", 5, false},
		{"stage1-reader", 4, 1, 1, "get", "IO", 5, false},
		{"R18a-read", 4, 1, 1, "get", "IO", 5, false},
		{"R18b-read", 4, 1, 1, "get", "IO", 5, false},
		{"canonical-body-IO", 4, 1, 1, "get", "IO", 5, false},
		{"reader-cleanup-H10", 5, 1, 1, "get", "IO", 5, true},
		{"stage2", 6, 1, 2, "update", "IO", 5, false},
		{"crossed-OLD", 7, 1, 3, "update", "Capacity", 28, false},
		{"crossed-NEW", 8, 2, 3, "update", "Capacity", 28, false},
		{"crossed-unreadable", 9, 3, 3, "update", "Capacity", 28, true},
		{"R16a", 10, 3, 3, "update", "Capacity", 28, false},
		{"R15a", 11, 1, 1, "abort", "IO", 5, false},
		{"stage2-put", 12, 1, 2, "update", "IO", 5, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := sideAuthority(5, 5)
			hash, _, rows := sideRows(2, 5)
			rank, key := uint8(4), hash[:]
			if row.name == "R18a-read" {
				rank, key = 6, rows[1].Key
			}
			if row.name == "R18b-read" {
				a, rows = sideSelected(t, 2, 1440)
				x, _, _ := sideRows(2, 1)
				rows[3].Literal = ChainValue(x, [32]byte{}, [40]byte{39: 1})
				rank, key = 6, rows[5].Key
			}
			if row.name == "canonical-body-IO" {
				a.B, a.U = 10, 13690
				forward, _ := HeightKey(1, 11)
				rows = append(rows, Mutation{DBI: readDBIsLiteral()[2], Key: forward, AfterKind: 2, Literal: ChainValue(hash, [32]byte{}, [40]byte{39: 1})}, canonicalOwnerLiteral(1, 11, hash))
			}
			if row.scenario == 9 || row.scenario == 10 || row.scenario == 12 {
				rank, key = 0, []byte{2}
			}
			if row.name == "R15a" {
				a = modelBase(1, 0, 0)
			}
			s, path := sideStore(t, a, rows...)
			cfg := s.config
			owner := bootstrapOwner(t)
			var truth CommitTruth
			var stage UpdateStage
			var result error
			evidence, fixtureErr := FixtureSelectedDamage(s, owner, row.scenario, rank, key, func() { truth, stage, result = s.CleanupSideV1(owner) })
			if truth != row.truth || stage != row.stage || result == nil {
				t.Fatalf("SIDE native tuple: %s/%d/%v", truth, stage, result)
			}
			sideNativeCause(t, result, row.stage, row.truth, row.op, row.class, row.code, row.secondary, row.name == "R15a")
			mustEnvironment(t, fixtureErr)
			prunedReleased(t, owner)
			again, nextStage, cached := s.CleanupSideV1(owner)
			if again != truth || nextStage != 1 || !sameError(cached, result) {
				t.Fatalf("SIDE native cached tuple: %s/%d/%v", again, nextStage, cached)
			}
			prunedReleased(t, owner)
			if row.scenario != 3 && evidence.Probes == 0 || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 {
				t.Fatalf("SIDE grant ended before native completion: %+v", evidence)
			}
			if row.truth == 2 || row.scenario == 9 || row.scenario == 10 {
				a.Cleanup, a.Phase = nil, 1
				rows[0].Literal, rows[1].Literal = nil, nil
			}
			authority := sideAuthorityRow(a)
			if row.scenario == 10 {
				authority.Literal = []byte{0x7f}
			}
			sideRawImages(t, s, path, cfg, append(rows, authority))
		})
	}
}

func sideNativeCause(t *testing.T, err error, stage UpdateStage, truth CommitTruth, op engineOperation, class EngineClass, code int, secondary, noWork bool) {
	t.Helper()
	primary := err
	var cleanup error
	if stage == 3 {
		var commit *CommitError
		if reflect.TypeOf(err) != reflect.TypeFor[*CommitError]() || !errors.As(err, &commit) || commit.Truth != truth {
			t.Fatalf("SIDE direct crossed result: %v", err)
		}
		primary, cleanup = commit.Cause, commit.ReadbackCause
	} else if secondary || noWork {
		joined, ok := err.(interface{ Unwrap() []error })
		if !ok || len(joined.Unwrap()) != 2 {
			t.Fatalf("SIDE ordered causes: %v", err)
		}
		primary, cleanup = joined.Unwrap()[0], joined.Unwrap()[1]
	}
	if noWork {
		if primary.Error() != "cleanup SIDE has no selected work" {
			t.Fatalf("SIDE no-work cause lost: %v", err)
		}
		primary, cleanup = cleanup, nil
	}
	requireEngineError(t, primary, class, op, code)
	if secondary {
		cleanupOp := operationAbort
		if stage == 3 {
			cleanupOp = operationUpdate
		}
		requireEngineError(t, cleanup, EngineClass("IO"), cleanupOp, 5)
	} else if cleanup != nil {
		t.Fatalf("unexpected SIDE secondary: %v", cleanup)
	}
}

func TestCleanupSideV1Native(t *testing.T) {
	t.Run("authority", sideNativeRejections)
	t.Run("R18b", sideNativeIdentity)
	t.Run("P09-A7", func(t *testing.T) {
		a, rows := sideSelected(t, 2, 1440)
		x, _, _ := sideRows(2, 1)
		rows[3].Literal = ChainValue(x, [32]byte{}, [40]byte{39: 1})
		s, path := sideStore(t, a, rows...)
		cfg := s.config
		rows[0].Literal = []byte{0x7f}
		mustEnvironment(t, FixtureSeedRawRow(s, 4, x[:], rows[0].Literal))
		sideRun(t, s, CommitTruth(2))
		a.Cleanup, a.Phase = nil, 1
		rows[1].Literal = nil
		sideRawImages(t, s, path, cfg, append(rows, sideAuthorityRow(a)))
	})
	t.Run("P09-A8", sideNativeBodies)
	t.Run("X2", sideNativeFaults)
	t.Run("X2-invalid-stage", func(t *testing.T) {
		a := sideAuthority(5, 5)
		_, _, rows := sideRows(2, 5)
		s, path := sideStore(t, a, rows...)
		cfg := s.config
		cleanup := errors.New("cleanup")
		truth, stage, err := FixtureCleanupInvalidStage0(s, cleanup)
		joined, ok := err.(interface{ Unwrap() []error })
		if truth != CommitTruth(1) || stage != 0 || !ok || len(joined.Unwrap()) != 2 || !sameError(joined.Unwrap()[1], cleanup) {
			t.Fatalf("invalid native stage tuple: %s/%d/%v", truth, stage, err)
		}
		requireEnvironmentError(t, joined.Unwrap()[0], EngineClass("LocalInvariant"), operationUpdate, -30779, "invalid update native outcome shape")
		if s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil || s.terminalTruth != CommitTruth(1) || !sameError(s.terminal, err) {
			t.Fatal("invalid-stage producer did not consume the real owner")
		}
		cleanupOutcomeRefused(t, s, cleanup)
		owner := bootstrapOwner(t)
		again, nextStage, got := s.CleanupSideV1(owner)
		if again != truth || nextStage != 1 || !sameError(got, err) {
			t.Fatalf("SIDE invalid-stage cached tuple: %s/%d/%v", again, nextStage, got)
		}
		prunedReleased(t, owner)
		reopened, openErr := Open(path, cfg)
		mustEnvironment(t, openErr)
		defer func() { mustEnvironment(t, reopened.Close()) }()
		archiveRawEqual(t, reopened, append(rows, sideAuthorityRow(a)))
	})
	t.Run("H10", func(t *testing.T) {
		a := sideAuthority(5, 5)
		hash, _, rows := sideRows(2, 5)
		s, path := sideStore(t, a, rows...)
		cfg := s.config
		owner := bootstrapOwner(t)
		var recorded, result error
		var truth CommitTruth
		var stage UpdateStage
		_, err := FixtureSelectedDamage(s, owner, SelectedDamageGetEIO, 4, hash[:], func() {
			mustEnvironment(t, owner.WithReservation(154611151, func() error {
				truth, stage, result = s.Update(func(r *Reader) (Batch, error) {
					_, recorded = r.GetOptionalSide(readDBIsLiteral()[4], hash[:])
					return Batch{Mutations: []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: 1}}}, nil
				})
				return nil
			}))
		})
		if truth != CommitTruth(1) || stage != 1 || !sameError(result, recorded) {
			t.Fatalf("SIDE ignored Reader failure replaced: %s/%d/%v/%v", truth, stage, result, recorded)
		}
		requireEngineError(t, result, EngineClass("IO"), operationGet, 5)
		mustEnvironment(t, err)
		again, nextStage, cached := s.CleanupSideV1(owner)
		if again != truth || nextStage != stage || !sameError(cached, recorded) {
			t.Fatalf("SIDE first read cause lost: %s/%d/%v", again, nextStage, cached)
		}
		prunedReleased(t, owner)
		sideRawImages(t, s, path, cfg, append(rows, sideAuthorityRow(a)))
	})
	t.Run("X3", func(t *testing.T) {
		for _, a := range append([]authorityCase{{"SIDE", sideAuthority(5, 5)}}, sideRouteCases()...) {
			t.Run(a.name, func(t *testing.T) {
				_, _, rows := sideRows(2, 5)
				s, _ := sideStore(t, a.a, rows...)
				owner := bootstrapOwner(t)
				var truth CommitTruth
				var stage UpdateStage
				var result error
				evidence, err := FixtureSelectedDamage(s, owner, SelectedDamageProbeOnly, 0, nil, func() { truth, stage, result = s.CleanupSideV1(owner) })
				want := CommitTruth(1)
				if a.name == "SIDE" {
					want = 2
				}
				sideTuple(t, truth, stage, result, want)
				mustEnvironment(t, err)
				if evidence.Probes == 0 || evidence.ProbeDenied != evidence.Probes || evidence.ProbeRan != 0 {
					t.Fatalf("SIDE uncharged native boundary: %+v", evidence)
				}
				prunedReleased(t, owner)
			})
		}
		t.Run("capacity", func(t *testing.T) {
			a := sideAuthority(5, 5)
			_, _, rows := sideRows(2, 5)
			s, _ := sideStore(t, a, rows...)
			owner := bootstrapOwner(t)
			mustEnvironment(t, owner.WithReservation(1, func() error {
				var truth CommitTruth
				var stage UpdateStage
				var result error
				evidence, err := FixtureSelectedDamage(s, owner, SelectedDamageProbeOnly, 0, nil, func() { truth, stage, result = s.CleanupSideV1(owner) })
				if truth != CommitTruth(1) || stage != 1 || !sameError(result, errOperationReservationCapacity) {
					t.Fatalf("SIDE capacity native tuple: %s/%d/%v", truth, stage, result)
				}
				mustEnvironment(t, err)
				if evidence != (SelectedDamageEvidence{}) || owner.shared.live != 1 {
					t.Fatalf("SIDE capacity opened native Reader or changed charge: %+v", evidence)
				}
				return nil
			}))
			prunedReleased(t, owner)
			cleanupWantAuthority(t, s, a)
			sideImage(t, s, 2, 5, true, true)
		})
		t.Run("panic", func(t *testing.T) {
			a := sideAuthority(5, 5)
			_, _, rows := sideRows(2, 5)
			s, path := sideStore(t, a, rows...)
			cfg := s.config
			owner := bootstrapOwner(t)
			marker := &struct{}{}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				_, _ = FixtureSelectedDamage(s, owner, SelectedDamageProbeOnly, 0, nil, func() {
					_ = owner.WithReservation(154611151, func() error {
						_, _, _ = s.Update(func(r *Reader) (Batch, error) {
							_, err := cleanupSideBatch(r, errors.New("unexpected no work"))
							mustEnvironment(t, err)
							panic(marker)
						})
						return nil
					})
				})
			}()
			if recovered != marker || owner.shared.live != 0 {
				t.Fatal("SIDE panic identity or synchronous release changed")
			}
			prunedReleased(t, owner)
			sideRawImages(t, s, path, cfg, append(rows, sideAuthorityRow(a)))
		})
	})
}

func TestCleanupReadbackFixtureShape(t *testing.T) {
	t.Run("X2", func(t *testing.T) {
		store, _, _ := consultedStore(t)
		cleanup := errors.New("cleanup")
		cleanupOutcomeRefused(t, nil, cleanup)
		cleanupOutcomeRefused(t, store, nil)
		cleanupOutcomeRefused(t, &Store{}, cleanup)
		writer := store.writer
		store.writer = nil
		cleanupOutcomeRefused(t, store, cleanup)
		store.writer = writer
		store.operations.Lock()
		cleanupOutcomeRefused(t, store, cleanup)
		store.operations.Unlock()
		for rank := uint16(0); rank <= 255; rank++ {
			for _, length := range []int{0, 1, 31, 32, 33, 76, 77, 78, 65537} {
				if rank == 4 && length == 32 || rank == 5 && (length == 33 || length == 77) {
					continue
				}
				before, calls := fixtureLargeNativeCalls(), 0
				drift, err := FixtureCleanupReadbackDrift(store, uint8(rank), make([]byte, length), func() { calls++ })
				if drift != 0 || err == nil || err.Error() != "invalid cleanup readback fixture" || calls != 0 || fixtureLargeNativeCalls() != before {
					t.Fatalf("invalid fixture rank%d/len%d: %d/%v/calls%d", rank, length, drift, err, calls)
				}
			}
		}
		for _, flags := range []int{0, 1, 2} {
			before, calls := fixtureLargeNativeCalls(), 0
			s, run := store, func() { calls++ }
			if flags != 0 {
				s = nil
			}
			if flags != 1 {
				run = nil
			}
			drift, err := FixtureCleanupReadbackDrift(s, 4, make([]byte, 32), run)
			if drift != 0 || err == nil || err.Error() != "invalid cleanup readback fixture" || calls != 0 || fixtureLargeNativeCalls() != before {
				t.Fatalf("nil fixture argument: %d/%v/calls%d", drift, err, calls)
			}
		}
		for _, shape := range []struct {
			rank   uint8
			length int
		}{{4, 32}, {5, 33}, {5, 77}} {
			t.Run(fmt.Sprintf("valid-%d-%d", shape.rank, shape.length), func(t *testing.T) {
				s, path, cfg := consultedStore(t)
				cfg = s.config
				key := make([]byte, shape.length)
				selector := LargeImageSelectorV1{Kind: 1}
				if shape.rank == 5 {
					selector.Kind = 2
				}
				marker := &struct{}{}
				func() {
					defer func() {
						if recover() != marker {
							t.Fatal("fixture panic identity changed")
						}
					}()
					_, _ = FixtureCleanupReadbackDrift(s, shape.rank, key, func() { panic(marker) })
				}()
				// The next real mode3 invocation also proves serialized disarm/unwind.
				calls := 0
				var truth CommitTruth
				var stage UpdateStage
				var result error
				drift, err := FixtureCleanupReadbackDrift(s, shape.rank, key, func() {
					calls++
					truth, stage, result = s.Update(func(*Reader) (Batch, error) {
						return Batch{Mutations: []Mutation{consultedCounter(t, 1)}, LargeConsulted: []LargeImageSelectorV1{selector}}, nil
					})
				})
				commit, ok := result.(*CommitError)
				if !ok || truth != CommitTruth(3) || stage != 3 || commit.Truth != CommitTruth(3) || commit.ReadbackCause != nil {
					t.Fatalf("fixed-mode3 tuple: %s/%d/%v", truth, stage, result)
				}
				requireEngineError(t, commit.Cause, EngineClass("Capacity"), operationUpdate, 28)
				if err != nil || drift != 1 || calls != 1 || s.state != storeCLOSED || s.env != nil {
					t.Fatalf("fixed-mode3 delegate: %d/%v/calls%d/%s", drift, err, calls, s.state)
				}
				reopened, openErr := Open(path, cfg)
				consultedTrack(t, reopened, openErr)
				equal, rawErr := FixtureRawRowEqual(reopened, shape.rank, key, []byte{0x7f})
				if rawErr != nil || !equal {
					t.Fatalf("fixed-mode3 actual drift: %v/%v", equal, rawErr)
				}
			})
		}
	})
}

func cleanupOutcomeRefused(t *testing.T, store *Store, cleanup error) {
	t.Helper()
	s := store
	if s == nil {
		s = &Store{}
	}
	before := [10]any{s.self, s.env, s.writer, s.txn, s.config, s.dbis, s.state, s.terminal, s.terminalTruth, s.canonicalOwnerVerified}
	truth, stage, err := FixtureCleanupInvalidStage0(store, cleanup)
	if truth != CommitTruth(1) || stage != 1 || err == nil || err.Error() != "invalid cleanup outcome fixture" {
		t.Fatalf("invalid cleanup outcome refusal: %s/%d/%v", truth, stage, err)
	}
	after := [10]any{s.self, s.env, s.writer, s.txn, s.config, s.dbis, s.state, s.terminal, s.terminalTruth, s.canonicalOwnerVerified}
	if after != before {
		t.Fatal("cleanup outcome refusal changed the owner")
	}
}

func TestCleanupBURawEvidence(t *testing.T) {
	for _, row := range []struct {
		name, diagnostic string
		kind             CleanupSpanKindV1
		corrupt          func(*testing.T, *Store, [32]byte)
	}{
		{"authority before routing", "invalid cleanup authority", CleanupSpanBlocksV1, func(t *testing.T, s *Store, _ [32]byte) {
			bad := make([]byte, 40)
			bad[0] = 2
			mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: readDBIsLiteral()[0], key: []byte{2}, value: bad}))
		}},
		{"invalid index work", "invalid cleanup canonical evidence", CleanupSpanBlocksV1, func(t *testing.T, s *Store, _ [32]byte) {
			key, err := HeightKey(7, 0)
			mustEnvironment(t, err)
			mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: readDBIsLiteral()[2], key: key, value: make([]byte, 104)}))
		}},
		{"promise bound", "invalid cleanup authority", CleanupSpanBlocksV1, func(t *testing.T, s *Store, _ [32]byte) {
			bad, err := cleanupAuthority(CleanupSpanBlocksV1, 0, false).Encode()
			mustEnvironment(t, err)
			binary.BigEndian.PutUint64(bad[2:10], 0)
			binary.BigEndian.PutUint64(bad[10:18], 13680)
			mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: readDBIsLiteral()[0], key: []byte{2}, value: bad}))
		}},
		{"promise generation", "invalid cleanup authority", CleanupSpanBlocksV1, func(t *testing.T, s *Store, _ [32]byte) {
			bad, err := cleanupAuthority(CleanupSpanBlocksV1, 0, false).Encode()
			mustEnvironment(t, err)
			binary.BigEndian.PutUint64(bad[18:26], 8)
			mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: readDBIsLiteral()[0], key: []byte{2}, value: bad}))
		}},
		{"span tag", "invalid cleanup authority", CleanupSpanBlocksV1, func(t *testing.T, s *Store, _ [32]byte) {
			bad, err := cleanupAuthority(CleanupSpanBlocksV1, 0, false).Encode()
			mustEnvironment(t, err)
			bad[37] = 5
			mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: readDBIsLiteral()[0], key: []byte{2}, value: bad}))
		}},
		{"missing required canonical header", "invalid cleanup canonical evidence", CleanupSpanBlocksV1, func(t *testing.T, s *Store, hash [32]byte) {
			mustEnvironment(t, fixtureDeletePrefixRow(s, readDBIsLiteral()[3], hash[:]))
		}},
		{"invalid hash-bound header", "invalid cleanup owed artifact", CleanupSpanBlocksV1, func(t *testing.T, s *Store, hash [32]byte) {
			bad := make([]byte, 116)
			bad[0] = 7
			mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: readDBIsLiteral()[4], key: hash[:], value: bad}))
		}},
		{"over-bound body width", "stored value width outside SchemaV2 bound", CleanupSpanBlocksV1, func(t *testing.T, s *Store, hash [32]byte) {
			mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[4], hash[:], make([]byte, MaxBlockBytes+1)))
		}},
		{"invalid manifest version", "invalid cleanup owed artifact", CleanupSpanUndoV1, func(t *testing.T, s *Store, hash [32]byte) {
			bad := UndoManifestValue(0, [16]byte{}, 1, 0)
			bad[0] = 2
			mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: readDBIsLiteral()[5], key: UndoManifestKey(hash), value: bad}))
		}},
		{"invalid undo value", "invalid cleanup owed artifact", CleanupSpanUndoV1, func(t *testing.T, s *Store, hash [32]byte) {
			manifest := UndoManifestValue(0, [16]byte{}, 2, 1)
			var spent [32]byte
			spent[31] = 1
			bad := make([]byte, 20)
			bad[10] = 0xfd
			mustEnvironment(t, fixtureSeedRows(s,
				fixtureRawRow{dbi: readDBIsLiteral()[5], key: UndoManifestKey(hash), value: manifest},
				fixtureRawRow{dbi: readDBIsLiteral()[5], key: UndoEntryKey(hash, spent, 1, 0, 0), value: bad}))
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := cleanupAuthority(row.kind, 0, false)
			if row.name == "authority before routing" {
				a = modelBase(1, 0, 0)
			}
			s, path, hash, body := cleanupTestStore(t, a, 0, 0)
			cfg := s.config
			row.corrupt(t, s, hash)
			truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
			engine, ok := err.(*EngineError)
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Class != EngineIntegrity || engine.Operation != "get" || engine.Diagnostic != row.diagnostic {
				t.Fatalf("cleanup raw evidence provenance drifted: %s/%d/%v", truth, stage, err)
			}
			if row.name == "missing required canonical header" {
				reopened, openErr := Open(path, cfg)
				mustEnvironment(t, openErr)
				defer func() { mustEnvironment(t, reopened.Close()) }()
				cleanupWantAuthority(t, reopened, a)
				consultedRequireImage(t, reopened, readDBIsLiteral()[4], hash[:], body, true, "cleanup artifact changed after canonical refusal")
			}
		})
	}
	for _, width := range []int{0, 103} {
		t.Run(fmt.Sprintf("index width %d", width), func(t *testing.T) {
			a := cleanupAuthority(CleanupSpanBlocksV1, 0, false)
			s, _, _, _ := cleanupTestStore(t, a, 0, 0)
			key, err := HeightKey(7, 0)
			mustEnvironment(t, err)
			mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[2], key, make([]byte, width)))
			truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
			engine, ok := err.(*EngineError)
			if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Class != EngineIntegrity || engine.Operation != "get" || engine.Diagnostic != "stored value width outside SchemaV2 bound" {
				t.Fatalf("cleanup index width provenance drifted: %s/%d/%v", truth, stage, err)
			}
		})
	}
	t.Run("undo key width 76", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanUndoV1, 0, false)
		s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
		key := UndoEntryKey(hash, modelHash(1), 0, 0, 0)[:76]
		value, valueErr := (UTXOValue{Value: 1}).Encode()
		mustEnvironment(t, valueErr)
		mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[5], key, value))
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		engine, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Class != EngineIntegrity || engine.Operation != "prefix-page" || engine.Diagnostic != "stored key outside SchemaV2 prefix-page domain" {
			t.Fatalf("cleanup undo key width provenance drifted: %s/%d/%v", truth, stage, err)
		}
	})
	t.Run("undo hash key width 32", func(t *testing.T) {
		a := cleanupAuthority(CleanupSpanUndoV1, 0, false)
		s, path, hash, _ := cleanupTestStore(t, a, 0, 0)
		cfg := s.config
		manifest := UndoManifestKey(hash)
		manifestValue := UndoManifestValue(0, [16]byte{}, 1, 0)
		mustEnvironment(t, fixtureSeedPrefixRawRow(s, readDBIsLiteral()[5], hash[:], []byte{1}))
		truth, stage, err := s.CleanupBUV1(bootstrapOwner(t))
		engine, ok := err.(*EngineError)
		if truth != CommitTruthOld || stage != UpdateStagePrewrite || !ok || engine.Class != EngineIntegrity || engine.Operation != "prefix-page" || engine.Diagnostic != "stored key outside SchemaV2 prefix-page domain" {
			t.Fatalf("cleanup hash-prefix artifact accepted: %s/%d/%v", truth, stage, err)
		}
		reopened, openErr := Open(path, cfg)
		mustEnvironment(t, openErr)
		defer func() { mustEnvironment(t, reopened.Close()) }()
		cleanupWantAuthority(t, reopened, a)
		consultedRequireImage(t, reopened, readDBIsLiteral()[5], manifest, manifestValue, true, "cleanup manifest changed after refusal")
	})
}

func TestCleanupBUNativeImages(t *testing.T) {
	for _, mode := range []string{"old", "new", "third", "unreadable"} {
		t.Run(mode, func(t *testing.T) {
			a := cleanupAuthority(CleanupSpanBlocksV1, 0, true)
			s, _, hash, body := cleanupTestStore(t, a, 0, 0)
			var batch Batch
			mustEnvironment(t, s.View(func(reader *Reader) error {
				var err error
				batch, err = cleanupBUBatch(reader, errors.New("unexpected no-work"))
				return err
			}))
			key, keyErr := HeightKey(7, 0)
			mustEnvironment(t, keyErr)
			if len(batch.Consulted) != 2 || batch.Consulted[0].DBI.Rank != 2 || !bytes.Equal(batch.Consulted[0].Key, key) || batch.Consulted[1].DBI.Rank != 3 || !bytes.Equal(batch.Consulted[1].Key, hash[:]) {
				t.Fatal("cleanup strict readback drifted")
			}
			plan, planErr := updateOwnedBatch(batch)
			mustEnvironment(t, planErr)
			var outcome updateNativeOutcome
			var err error
			switch mode {
			case "old":
				outcome = fixtureUpdateResultTrue(s, plan)
			case "new":
				outcome, err = fixtureUpdatePostCommitENOSPC(s, plan)
			case "third":
				outcome, err = fixtureUpdatePostCommitENOSPCThird(s, plan)
			case "unreadable":
				outcome, err = fixtureUpdatePostCommitENOSPCUnreadable(s, plan)
			}
			mustEnvironment(t, err)
			truth, stage, result := updateResult(outcome, nil)
			if result == nil || mode != "old" && stage != UpdateStageCommitMayHaveCrossed || mode == "old" && stage != UpdateStagePrewrite {
				t.Fatalf("cleanup native stage or cause provenance drifted: %s/%d/%v", truth, stage, result)
			}
			if mode == "old" {
				if truth != CommitTruthOld {
					t.Fatalf("cleanup native OLD drifted: %s/%v", truth, result)
				}
				cleanupWantAuthority(t, s, a)
				consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], body, true, "cleanup native OLD image drifted")
			} else if mode == "new" {
				if truth != CommitTruthNew {
					t.Fatalf("cleanup native NEW-with-error drifted: %s/%v", truth, result)
				}
				a.Cleanup, a.Phase = nil, StoragePhaseNoneV1
				cleanupWantAuthority(t, s, a)
				consultedRequireImage(t, s, readDBIsLiteral()[4], hash[:], nil, false, "cleanup complete native image drifted")
				consultedRequireImage(t, s, readDBIsLiteral()[3], hash[:], body[:116], true, "cleanup strict readback drifted")
			} else if truth != CommitTruthUnknown {
				t.Fatalf("cleanup native UNKNOWN guessed image: %s/%v", truth, result)
			}
		})
	}
}

func TestCleanupBUOutcomeMatrix(t *testing.T) {
	a := cleanupAuthority(CleanupSpanBlocksV1, 0, true)
	s, _, hash, _ := cleanupTestStore(t, a, 0, 0)
	var batch Batch
	mustEnvironment(t, s.View(func(reader *Reader) error {
		var err error
		batch, err = cleanupBUBatch(reader, errors.New("unexpected no-work"))
		return err
	}))
	plan, planErr := updateOwnedBatch(batch)
	mustEnvironment(t, planErr)
	if len(plan) != 2 || plan[0].dbi.Rank != 0 || plan[1].dbi.Rank != 4 || !bytes.Equal(plan[1].key, hash[:]) {
		t.Fatal("cleanup outcome plan drifted")
	}

	primary := integrityError(operationGet, "cleanup owner cause", nil)
	callback := errors.New("cleanup callback refusal")
	abort := nativeError(operationAbort, codeEIO)
	cleanup := nativeError(operationClose, codeEIO)
	readback := nativeError(operationUpdate, codeENOSPC)
	for _, row := range []struct {
		name     string
		outcome  updateNativeOutcome
		cleanup  error
		want     CommitTruth
		ordered  []error
		commit   bool
		nextCall bool
	}{
		{"stage 1 same class", updateNativeConsumed(CommitTruthOld, false, primary, nil, UpdateStagePrewrite), nil, CommitTruthOld, []error{primary}, false, true},
		{"stage 2 same class", updateNativeConsumed(CommitTruthOld, false, primary, nil, UpdateStageWriteStartedDefinitelyPrecommit), nil, CommitTruthOld, []error{primary}, false, true},
		{"stage 3 same class", updateNativeConsumed(CommitTruthUnknown, true, primary, nil, UpdateStageCommitMayHaveCrossed), nil, CommitTruthUnknown, []error{primary}, true, true},
		{"callback abort cleanup", updateNativeConsumed(CommitTruthOld, false, callback, abort, UpdateStagePrewrite), cleanup, CommitTruthOld, []error{callback, abort, cleanup}, false, true},
		{"reader cleanup", updateNativeConsumed(CommitTruthOld, false, primary, nil, UpdateStagePrewrite), cleanup, CommitTruthOld, []error{primary, cleanup}, false, true},
		{"invalid stage 0", updateNativeOutcome{truth: CommitTruthOld, stage: UpdateStageInvalid, primary: primary}, cleanup, CommitTruthOld, nil, false, true},
		{"new joined cleanup", updateNativeConsumed(CommitTruthNew, true, primary, readback, UpdateStageCommitMayHaveCrossed), cleanup, CommitTruthNew, []error{primary, readback, cleanup}, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			truth, stage, result := updateResult(row.outcome, row.cleanup)
			if truth != row.want || stage != row.outcome.stage || result == nil {
				t.Fatalf("cleanup stage or cause provenance drifted: %s/%d/%v", truth, stage, result)
			}
			if row.name == "invalid stage 0" {
				parts, ok := result.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != cleanup {
					t.Fatalf("cleanup invalid outcome order drifted: %v", result)
				}
				shape, ok := parts.Unwrap()[0].(*EngineError)
				if !ok || shape.Class != EngineLocalInvariant || shape.Diagnostic != "invalid update native outcome shape" {
					t.Fatalf("cleanup invalid outcome provenance drifted: %v", result)
				}
			} else if row.commit {
				commit, ok := result.(*CommitError)
				if !ok || commit.Truth != row.want || commit.Cause != row.ordered[0] {
					t.Fatalf("cleanup commit cause drifted: %v", result)
				}
				if len(row.ordered) > 1 {
					parts, ok := commit.ReadbackCause.(interface{ Unwrap() []error })
					if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[0] != row.ordered[1] || parts.Unwrap()[1] != row.ordered[2] {
						t.Fatalf("cleanup joined cause order drifted: %v", result)
					}
				}
			} else if len(row.ordered) == 1 {
				if result != row.ordered[0] {
					t.Fatalf("cleanup direct cause identity drifted: %v", result)
				}
			} else {
				parts, ok := result.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != len(row.ordered) {
					t.Fatalf("cleanup joined cause shape drifted: %v", result)
				}
				for i, want := range row.ordered {
					if parts.Unwrap()[i] != want {
						t.Fatalf("cleanup joined cause order drifted: %v", result)
					}
				}
			}
			if row.name == "stage 1 same class" || row.name == "stage 2 same class" || row.name == "stage 3 same class" {
				var engine *EngineError
				if !errors.As(result, &engine) || engine.Class != EngineIntegrity || engine != primary {
					t.Fatalf("cleanup stage class drifted: %v", result)
				}
			}
			if row.nextCall {
				stateStore, _, _, _ := cleanupTestStore(t, a, 0, 0)
				appliedTruth, appliedStage, applied := stateStore.applyUpdateOutcome(row.outcome, nil, row.cleanup, false)
				if appliedTruth != truth || appliedStage != stage || applied == nil || applied.Error() != result.Error() || stateStore.state != storeCLOSED {
					t.Fatalf("cleanup owner terminal state drifted: %s/%d/%v", appliedTruth, appliedStage, applied)
				}
				nextTruth, nextStage, nextErr := stateStore.CleanupBUV1(bootstrapOwner(t))
				if nextTruth != truth || nextStage != UpdateStagePrewrite || nextErr != applied {
					t.Fatalf("cleanup next operation state drifted: %s/%d/%v", nextTruth, nextStage, nextErr)
				}
			}
		})
	}
}

//nolint:errorlint // Exact callback, infrastructure and panic identities are required.
func TestReaderPrefixPageCallbackLifecycle(t *testing.T) {
	dbi := readDBIsLiteral()[2]
	prefix, _, minimum := prefixPageRequest(2, 21)
	callbackErr, panicValue := errors.New("callback"), &struct{ name string }{"prefix-page"}
	for _, mode := range []string{"ignored", "exact", "wrapped", "distinct", "typed-nil", "panic"} {
		t.Run(mode, func(t *testing.T) {
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
			var recorded, returned error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				returned = store.View(func(reader *Reader) error {
					page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
					if page.Rows != nil || page.Stop != 0 {
						t.Fatalf("callback failure returned page: %#v", page)
					}
					recorded = pageErr
					switch mode {
					case "ignored":
						return nil
					case "exact":
						return recorded
					case "wrapped":
						return fmt.Errorf("wrapped: %w", recorded)
					case "distinct":
						return callbackErr
					case "typed-nil":
						var typed *nilPointerError
						return typed
					default:
						panic(panicValue)
					}
				})
			}()
			if store.state != storeCLOSED || !validStoreShape(store) {
				t.Fatalf("callback PrefixPage state=%s", store.state)
			}
			switch mode {
			case "ignored", "exact":
				if returned != recorded || !sameError(store.terminal, recorded) {
					t.Fatal("PrefixPage infrastructure identity was duplicated")
				}
			case "wrapped", "distinct", "typed-nil":
				parts, ok := returned.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != recorded || !sameError(store.terminal, returned) {
					t.Fatalf("PrefixPage callback order=%v", returned)
				}
				if mode == "distinct" && parts.Unwrap()[0] != callbackErr || mode == "wrapped" && !errors.Is(parts.Unwrap()[0], recorded) {
					t.Fatalf("PrefixPage callback identity=%v", returned)
				}
				if mode == "typed-nil" {
					_, ok := parts.Unwrap()[0].(*nilPointerError)
					if !ok || parts.Unwrap()[0] == nil {
						t.Fatal("PrefixPage typed-nil behavior changed")
					}
				}
			case "panic":
				if recovered != panicValue || returned != nil || !sameError(store.terminal, recorded) {
					t.Fatalf("PrefixPage panic disposition=%v/%v", recovered, returned)
				}
			}
			if next := store.View(func(*Reader) error { t.Fatal("terminal callback invoked"); return nil }); !sameError(next, store.terminal) {
				t.Fatal("PrefixPage terminal next View drifted")
			}
		})
	}

	t.Run("Goexit", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
		var recorded error
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = store.View(func(reader *Reader) error {
				_, recorded = reader.PrefixPage(dbi, prefix, nil, 1, minimum)
				runtime.Goexit()
				return nil
			})
		}()
		<-done
		if recorded == nil || store.state != storeCLOSED || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("PrefixPage Goexit disposition=%v/%s", recorded, store.state)
		}
	})

	t.Run("Update infrastructure matrix", func(t *testing.T) {
		for _, mode := range []string{"ignored", "exact", "wrapped", "distinct", "typed-nil", "panic"} {
			t.Run(mode, func(t *testing.T) {
				store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
				mustEnvironment(t, err)
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
				var recorded, returned error
				var recovered any
				truth := CommitTruthOld
				func() {
					defer func() { recovered = recover() }()
					truth, _, returned = store.Update(func(reader *Reader) (Batch, error) {
						page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
						if page.Rows != nil || page.Stop != 0 {
							t.Fatalf("Update callback failure returned page: %#v", page)
						}
						recorded = pageErr
						switch mode {
						case "ignored":
							return updateLifecycleBatch(), nil
						case "exact":
							return updateLifecycleBatch(), recorded
						case "wrapped":
							return updateLifecycleBatch(), fmt.Errorf("wrapped: %w", recorded)
						case "distinct":
							return updateLifecycleBatch(), callbackErr
						case "typed-nil":
							var typed *nilPointerError
							return updateLifecycleBatch(), typed
						default:
							panic(panicValue)
						}
					})
				}()
				if store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !validStoreShape(store) {
					t.Fatalf("Update PrefixPage state=%s/%s", store.state, store.terminalTruth)
				}
				switch mode {
				case "ignored", "exact":
					if truth != CommitTruthOld || returned != recorded || !sameError(store.terminal, recorded) {
						t.Fatal("Update PrefixPage infrastructure identity was duplicated")
					}
				case "wrapped", "distinct", "typed-nil":
					parts, ok := returned.(interface{ Unwrap() []error })
					if truth != CommitTruthOld || !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != recorded || !sameError(store.terminal, returned) {
						t.Fatalf("Update PrefixPage callback order=%v", returned)
					}
					if mode == "distinct" && parts.Unwrap()[0] != callbackErr || mode == "wrapped" && !errors.Is(parts.Unwrap()[0], recorded) {
						t.Fatalf("Update PrefixPage callback identity=%v", returned)
					}
					if mode == "typed-nil" {
						_, ok := parts.Unwrap()[0].(*nilPointerError)
						if !ok || parts.Unwrap()[0] == nil {
							t.Fatal("Update PrefixPage typed-nil behavior changed")
						}
					}
				case "panic":
					if recovered != panicValue || returned != nil || !sameError(store.terminal, recorded) {
						t.Fatalf("Update PrefixPage panic disposition=%v/%v", recovered, returned)
					}
				}
				if nextTruth, _, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("closed Update callback invoked"); return Batch{}, nil }); nextTruth != CommitTruthOld || !sameError(next, store.terminal) {
					t.Fatal("Update PrefixPage terminal next operation drifted")
				}
			})
		}
	})

	t.Run("Update Goexit", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
		var recorded error
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _, _ = store.Update(func(reader *Reader) (Batch, error) {
				_, recorded = reader.PrefixPage(dbi, prefix, nil, 1, minimum)
				runtime.Goexit()
				return Batch{}, nil
			})
		}()
		<-done
		if recorded == nil || store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("Update PrefixPage Goexit disposition=%v/%s", recorded, store.state)
		}
		if nextTruth, _, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("closed Update callback invoked"); return Batch{}, nil }); nextTruth != CommitTruthOld || !sameError(next, recorded) {
			t.Fatal("Update PrefixPage Goexit next operation drifted")
		}
	})

	t.Run("application-only", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		key := fixturePrefixKey(2, 21, 1, false)
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: dbi, key: key, value: make([]byte, 104)}))
		for _, mode := range []string{"nil", "direct", "wrapped", "typed-nil", "panic"} {
			var returned error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				returned = store.View(func(reader *Reader) error {
					page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
					if pageErr != nil || len(page.Rows) != 1 || page.Stop != PrefixPageStop(1) {
						return fmt.Errorf("successful PrefixPage callback=%#v/%w", page, pageErr)
					}
					switch mode {
					case "nil":
						return nil
					case "direct":
						return callbackErr
					case "wrapped":
						return fmt.Errorf("wrapped: %w", callbackErr)
					case "typed-nil":
						var typed *nilPointerError
						return typed
					default:
						panic(panicValue)
					}
				})
			}()
			if mode == "nil" && returned != nil || mode == "direct" && returned != callbackErr || mode == "panic" && recovered != panicValue || store.state != storeOPEN || store.terminal != nil {
				t.Fatalf("application-only PrefixPage=%s/%v/%v/%s", mode, returned, recovered, store.state)
			}
			if mode == "typed-nil" {
				_, ok := returned.(*nilPointerError)
				if !ok || returned == nil {
					t.Fatal("application-only typed nil changed")
				}
			}
			if mode == "wrapped" && (returned == callbackErr || !errors.Is(returned, callbackErr)) {
				t.Fatal("application-only wrapped error identity changed")
			}
		}
		truth, _, updateErr := store.Update(func(reader *Reader) (Batch, error) {
			page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
			if pageErr != nil || len(page.Rows) != 1 {
				return Batch{}, fmt.Errorf("Update PrefixPage=%#v/%w", page, pageErr)
			}
			return updateLifecycleBatch(), callbackErr
		})
		if truth != CommitTruthOld || updateErr != callbackErr || store.state != storeOPEN {
			t.Fatalf("application-only Update=%s/%v", truth, updateErr)
		}
	})

	t.Run("Update infrastructure rejects batch", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "db")
		store, err := Create(path, environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbi, fixturePrefixKey(2, 21, 1, false), make([]byte, 103)))
		var recorded error
		truth, _, returned := store.Update(func(reader *Reader) (Batch, error) {
			page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
			if page.Rows != nil || page.Stop != 0 {
				t.Fatalf("Update infrastructure returned page: %#v", page)
			}
			recorded = pageErr
			return updateLifecycleBatch(), nil
		})
		if truth != CommitTruthOld || returned != recorded || store.state != storeCLOSED || store.terminalTruth != CommitTruthOld || !sameError(store.terminal, recorded) || !validStoreShape(store) {
			t.Fatalf("Update infrastructure disposition=%s/%v/%s", truth, returned, store.state)
		}
		if nextTruth, _, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("closed Update callback invoked"); return Batch{}, nil }); nextTruth != CommitTruthOld || !sameError(next, recorded) {
			t.Fatal("Update terminal operation rejected PrefixPage")
		}
		reopened, openErr := Open(path, environmentConfig())
		mustEnvironment(t, openErr)
		defer func() { mustEnvironment(t, reopened.Close()) }()
		mustEnvironment(t, reopened.View(func(reader *Reader) error {
			value, present, getErr := reader.Get(readDBIsLiteral()[0], []byte{2})
			if getErr != nil || present || value != nil {
				t.Fatalf("ignored PrefixPage failure committed batch: %x/%v/%v", value, present, getErr)
			}
			return nil
		}))
	})

	t.Run("Update successful page commits batch", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		key := fixturePrefixKey(2, 21, 1, false)
		value := fixturePrefixValue(2, false, false)
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: dbi, key: key, value: value}))
		truth, _, updateErr := store.Update(func(reader *Reader) (Batch, error) {
			page, pageErr := reader.PrefixPage(dbi, prefix, nil, 1, minimum)
			if pageErr != nil || page.Stop != PrefixPageExhausted || len(page.Rows) != 1 || !bytes.Equal(page.Rows[0].Key, key) || !bytes.Equal(page.Rows[0].Value, value) {
				return Batch{}, fmt.Errorf("successful Update PrefixPage=%#v/%w", page, pageErr)
			}
			return updateLifecycleBatch(), nil
		})
		if truth != CommitTruthNew || updateErr != nil || store.state != storeOPEN || store.terminal != nil {
			t.Fatalf("successful Update PrefixPage disposition=%s/%v/%s", truth, updateErr, store.state)
		}
		mustEnvironment(t, store.View(func(reader *Reader) error {
			persisted, present, getErr := reader.Get(readDBIsLiteral()[0], []byte{2})
			if getErr != nil || !present || !bytes.Equal(persisted, admissionNone()) {
				t.Fatalf("successful Update PrefixPage mutation=%x/%v/%v", persisted, present, getErr)
			}
			return nil
		}))
	})
}

func TestReaderGetNativeFixtures(t *testing.T) {
	store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	dbis := readDBIsLiteral()
	emptyKey := []byte{2}
	counterKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
	counterValue := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	blockKey := make([]byte, 32)
	blockValue := make([]byte, 68_000_125)
	blockValue[0], blockValue[len(blockValue)-1] = 0x7a, 0x5c
	if err := fixtureSeedRows(store,
		fixtureRawRow{dbi: dbis[0], key: emptyKey, value: []byte{}},
		fixtureRawRow{dbi: dbis[0], key: counterKey, value: counterValue},
		fixtureRawRow{dbi: dbis[4], key: blockKey, value: blockValue},
	); err != nil {
		t.Fatal(err)
	}
	if err := fixtureSeedRows(store, fixtureRawRow{dbi: dbis[0], key: []byte{0}, value: make([]byte, 3)}); err == nil {
		t.Fatal("fixture accepted an overbound raw row")
	}
	panicValue := &struct{ name string }{"maximum"}
	var maximum []byte
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		viewErr := store.View(func(reader *Reader) error {
			value, present, getErr := reader.Get(dbis[4], blockKey)
			if getErr != nil || !present || len(value) != 68_000_125 {
				return fmt.Errorf("maximum native copy drifted: %d/%v/%w", len(value), present, getErr)
			}
			maximum = value
			panic(panicValue)
		})
		if viewErr != nil {
			t.Fatal(viewErr)
		}
	}()
	if recovered != panicValue || len(maximum) != 68_000_125 || maximum[0] != 0x7a || maximum[len(maximum)-1] != 0x5c {
		t.Fatalf("maximum panic cleanup drifted: %v/%d", recovered, len(maximum))
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		empty, present, getErr := reader.Get(dbis[0], emptyKey)
		if getErr != nil || !present || empty == nil || len(empty) != 0 {
			return fmt.Errorf("present-empty identity drifted: %#v/%v/%w", empty, present, getErr)
		}
		first, present, getErr := reader.Get(dbis[0], counterKey)
		if getErr != nil || !present || len(first) != 16 {
			return fmt.Errorf("independent copy setup drifted: %x/%v/%w", first, present, getErr)
		}
		first[0] = 0xff
		second, present, getErr := reader.Get(dbis[0], counterKey)
		if getErr != nil || !present || len(second) != 16 || second[0] != 1 {
			return fmt.Errorf("returned bytes alias MDBX: %x/%v/%w", second, present, getErr)
		}
		absentKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 2}
		absent, present, getErr := reader.Get(dbis[0], absentKey)
		if getErr != nil || present || absent != nil {
			return fmt.Errorf("absence identity drifted: %#v/%v/%w", absent, present, getErr)
		}
		return nil
	}))
	inspection, err := store.Inspect()
	mustEnvironment(t, err)
	if inspection.DBIs[0].Entries != 4 || inspection.DBIs[4].Entries != 1 || inspection.ReaderTableLength == 0 {
		t.Fatalf("Inspection provenance drifted: %+v", inspection)
	}
	mustEnvironment(t, store.Close())
}

//nolint:errorlint // Exact callback, infrastructure and panic identities are required.
func TestReaderGetMalformedDisposition(t *testing.T) {
	dbis, key := readDBIsLiteral(), []byte{0}
	callbackErr, panicValue := errors.New("callback"), &struct{ name string }{"panic"}
	for _, mode := range []string{"ignored", "exact", "wrapped", "distinct", "panic"} {
		t.Run(mode, func(t *testing.T) {
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			mustEnvironment(t, fixtureSeedMalformedStoredWidth(store))
			var recorded, returned error
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				returned = store.View(func(reader *Reader) error {
					_, _, recorded = reader.Get(dbis[0], key)
					requireEnvironmentError(t, recorded, EngineIntegrity, operationGet, codeInvalid, "stored value width outside SchemaV2 bound")
					if _, _, again := reader.Get(dbis[0], key); requireEnvironmentError(t, again, EngineInvalidInput, operationGet, codeEINVAL, "Reader is not active").Cause != nil {
						t.Fatal("failed Reader remained active")
					}
					switch mode {
					case "ignored":
						return nil
					case "exact":
						return recorded
					case "wrapped":
						return fmt.Errorf("wrapped: %w", recorded)
					case "distinct":
						return callbackErr
					default:
						panic(panicValue)
					}
				})
			}()
			if store.state != storeCLOSED || store.env != nil || store.writer != nil || store.txn != nil || store.config != (ConfigV1{}) || !sameError(store.terminal, returned) && mode != "panic" {
				t.Fatalf("post-native Get disposition drifted: %s/%v", store.state, returned)
			}
			switch mode {
			case "ignored", "exact":
				if returned != recorded {
					t.Fatalf("recorded failure identity/duplication drifted: %v", returned)
				}
			case "wrapped", "distinct":
				parts, ok := returned.(interface{ Unwrap() []error })
				if !ok || len(parts.Unwrap()) != 2 || parts.Unwrap()[1] != recorded || mode == "distinct" && parts.Unwrap()[0] != callbackErr || mode == "wrapped" && !errors.Is(parts.Unwrap()[0], recorded) {
					t.Fatalf("callback/recorded order drifted: %v", returned)
				}
			case "panic":
				if recovered != panicValue || returned != nil || store.terminal != recorded {
					t.Fatalf("panic disposition drifted: %v/%v/%v", recovered, returned, store.terminal)
				}
			}
			terminal := store.terminal
			if !sameError(store.View(func(*Reader) error { t.Fatal("closed callback invoked"); return nil }), terminal) {
				t.Fatal("closed View legality drifted")
			}
			if inspection, next := store.Inspect(); inspection != (Inspection{}) || !sameError(next, terminal) || !sameError(store.Close(), terminal) {
				t.Fatal("closed Inspect/Close legality drifted")
			}
		})
	}
}

func TestNativeUpdateFixtures(t *testing.T) {
	t.Run("stage_abort_retained", func(t *testing.T) {
		for _, stage := range []UpdateStage{1, 2} {
			store := newUpdateStore(t)
			txn, release, err := fixtureHeldUpdate(store)
			mustEnvironment(t, err)
			primary := nativeError(operationUpdate, codeNotFound)
			outcome := updateNativeAbort(txn, primary, stage)
			mustEnvironment(t, release())
			if outcome.stage != stage {
				t.Fatal("abort stage forwarding drifted")
			}
			if outcome.truth != 1 || outcome.commitAttempted || outcome.primary != primary || outcome.retainedWrite != txn || outcome.retainedRead != nil || outcome.valid() != nil {
				t.Fatal("abort ownership drifted")
			}
			requireEngineError(t, outcome.secondary, EngineLocalInvariant, operationAbort, codeThreadMismatch)
			mustEnvironment(t, store.Close())
		}
	})
	t.Run("source_ownership", func(t *testing.T) {
		source, err := os.ReadFile("mdbx_cgo.go")
		mustEnvironment(t, err)
		abort, commit := updateNativeBody(t, source, "updateNativeAbort"), updateNativeBody(t, source, "updateNativeCommit")
		if !strings.Contains(abort, "if rc == codeThreadMismatch {") || !strings.Contains(abort, "updateNativeRetainedWrite(false") || strings.Count(abort, "updateNativeRetainedWrite") != 1 {
			t.Fatal("abort ownership drifted")
		}
		if !strings.Contains(commit, "case codeThreadMismatch:") || !strings.Contains(commit, "updateNativeRetainedWrite(true") || strings.Count(commit, "updateNativeRetainedWrite") != 1 || !strings.Contains(commit, "case codePanic, codeEPerm, codeBadSignature, codeEINVAL, codeBadTxn, codeProblem:\n\t\treturn updateNativeConsumed(CommitTruthOld, true, commitErr, nil, stage)") {
			t.Fatal("commit ownership drifted")
		}
		truth := updateNativeBody(t, source, "updateNativeReadbackTruth")
		oldAt, newAt := strings.Index(truth, "if oldImage"), strings.Index(truth, "if newImage")
		if oldAt < 0 || newAt < 0 || oldAt > newAt {
			t.Fatal("readback tie-break drifted")
		}
		fixture, err := os.ReadFile("mdbx_fixture_cgo.go")
		mustEnvironment(t, err)
		post, unreadable := updateNativeBody(t, fixture, "fixtureUpdatePostCommitENOSPC"), updateNativeBody(t, fixture, "fixtureUpdatePostCommitENOSPCUnreadable")
		if strings.Count(post, "updateNativeReadback") != 1 || strings.Count(unreadable, "updateNativeReadback") != 1 {
			t.Fatal("readback truth drifted")
		}
	})
	t.Run("stage_wrong_thread", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, release, err := fixtureUpdateWrongThread(store)
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, release()) }()
		if outcome.stage != 1 {
			t.Fatal("definite OLD stage drifted")
		}
		engine := requireEngineError(t, outcome.primary, EngineLocalInvariant, operationUpdate, codeThreadMismatch)
		if engine.Diagnostic != expectedNativeDiagnostic(codeThreadMismatch) || outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite == nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("commit ownership drifted: %+v", outcome)
		}
		if locked := outcome.lockedOutcome(); !locked.poisoned || locked.err != nil {
			t.Fatalf("commit ownership drifted: %+v", locked)
		}
		both := outcome
		both.retainedRead = outcome.retainedWrite
		if both.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		wrongTruth := outcome
		wrongTruth.truth = CommitTruthNew
		if wrongTruth.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		retainedRead := updateNativeRetainedRead(outcome.primary, errors.New("cleanup"), outcome.retainedWrite)
		if retainedRead.valid() != nil {
			t.Fatalf("commit ownership drifted: %+v", retainedRead)
		}
		retainedRead.secondary = nil
		if retainedRead.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
		retainedRead.secondary = errors.New("cleanup")
		retainedRead.commitAttempted = false
		if retainedRead.valid() == nil {
			t.Fatal("commit stage drifted")
		}
		committed := outcome
		committed.secondary = errors.New("cleanup")
		if committed.valid() == nil {
			t.Fatal("commit ownership drifted")
		}
	})

	t.Run("wrong-thread abort retains write", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, store.Close()) }()
		outcome, release, err := fixtureUpdateAbortWrongThread(store)
		mustEnvironment(t, err)
		defer func() { mustEnvironment(t, release()) }()
		primary := requireEngineError(t, outcome.primary, EngineLocalInvariant, operationUpdate, codeNotFound)
		secondary := requireEngineError(t, outcome.secondary, EngineLocalInvariant, operationAbort, codeThreadMismatch)
		if primary.Diagnostic != expectedNativeDiagnostic(codeNotFound) || secondary.Diagnostic != expectedNativeDiagnostic(codeThreadMismatch) || outcome.truth != CommitTruthOld || outcome.commitAttempted || outcome.retainedWrite == nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("abort ownership drifted: %+v", outcome)
		}
	})

	t.Run("stage_result_true", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		plan := updateNativePlan(t, updatePlanBatch(t).Mutations[8])
		outcome := fixtureUpdateResultTrue(store, plan)
		if outcome.stage != 1 {
			t.Fatal("definite OLD stage drifted")
		}
		engine := requireEngineError(t, outcome.primary, EngineTransaction, operationUpdate, codeResultTrue)
		if engine.Diagnostic != expectedNativeDiagnostic(codeResultTrue) {
			t.Fatalf("RESULT_TRUE disposition drifted: %+v", engine)
		}
		if outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("RESULT_TRUE disposition drifted: %+v", outcome)
		}
		mustEnvironment(t, store.Close())
	})

	t.Run("stage_readback_old", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mutation := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: admissionNone()}
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: mutation.DBI, key: mutation.Key, value: mutation.Literal}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPC(store, updateNativePlan(t, mutation))
		if outcome.stage != 3 {
			t.Fatal("readback stage drifted")
		}
		mustEnvironment(t, cleanup)
		engine := requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		if engine.Diagnostic != expectedNativeDiagnostic(codeENOSPC) {
			t.Fatalf("readback truth drifted: %+v", engine)
		}
		if outcome.truth != CommitTruthOld || !outcome.commitAttempted || outcome.secondary != nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("readback truth drifted: %+v", outcome)
		}
		requireUpdateValue(t, store, mutation.DBI, mutation.Key, mutation.Literal, true)
		mustEnvironment(t, store.Close())
	})

	t.Run("post-commit ENOSPC unreadable", func(t *testing.T) {
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mutation := Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: admissionNone()}
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: mutation.DBI, key: mutation.Key, value: mutation.Literal}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPCUnreadable(store, updateNativePlan(t, mutation))
		if outcome.stage != 3 {
			t.Fatal("readback stage drifted")
		}
		mustEnvironment(t, cleanup)
		if outcome.truth != CommitTruthUnknown || !outcome.commitAttempted || outcome.primary == nil || outcome.secondary == nil || outcome.retainedWrite != nil || outcome.retainedRead != nil || outcome.valid() != nil {
			t.Fatalf("readback truth drifted: %+v", outcome)
		}
		_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		mustEnvironment(t, store.Close())
	})
}

func TestNativeUpdateImageFamilies(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "non-target reference", true: "target reference alias"}[alias], func(t *testing.T) {
			batch := updatePlanBatch(t)
			oldMeta := append([]byte(nil), batch.Mutations[1].Literal...)
			oldDelete := append([]byte(nil), batch.Mutations[3].Literal...)
			oldReference := append([]byte(nil), batch.Mutations[3].Literal...)
			oldMeta[len(oldMeta)-1], oldDelete[0], oldReference[len(oldReference)-1] = 1, 2, 3
			if alias {
				batch.Mutations[3].BeforePresent = true
				batch.Mutations[8].RefKey = append([]byte(nil), batch.Mutations[3].Key...)
				copy(batch.Mutations[8].Key[41:77], batch.Mutations[3].Key[8:44])
			}
			batch.Mutations = append(batch.Mutations, canonicalOwnerPairOf(batch.Mutations[4]))
			plan := updateNativePlan(t, batch.Mutations...)
			store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
			mustEnvironment(t, err)
			rows := []fixtureRawRow{
				{dbi: batch.Mutations[1].DBI, key: batch.Mutations[1].Key, value: oldMeta},
				{dbi: batch.Mutations[2].DBI, key: batch.Mutations[2].Key, value: oldDelete},
			}
			if alias {
				rows = append(rows, fixtureRawRow{dbi: batch.Mutations[3].DBI, key: batch.Mutations[3].Key, value: oldReference})
			} else {
				rows = append(rows, fixtureRawRow{dbi: batch.Mutations[8].RefDBI, key: batch.Mutations[8].RefKey, value: oldReference})
			}
			mustEnvironment(t, fixtureSeedRows(store, rows...))
			outcome, cleanup := fixtureUpdatePostCommitENOSPC(store, plan)
			if outcome.stage != 3 {
				t.Fatal("readback stage drifted")
			}
			mustEnvironment(t, cleanup)
			_ = requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
			requireUpdateTruth(t, outcome, CommitTruthNew, true, outcome.primary, nil)
			for i, mutation := range batch.Mutations {
				want, present := mutation.Literal, mutation.AfterKind != planAfterAbsent
				if mutation.AfterKind == planAfterOldValueRef {
					want = oldReference
				}
				requireUpdateValue(t, store, mutation.DBI, mutation.Key, want, present)
				if i == 8 && !alias {
					requireUpdateValue(t, store, mutation.RefDBI, mutation.RefKey, oldReference, true)
				}
			}
			mustEnvironment(t, store.Close())
		})
	}
}

func TestNativeUpdateUnknownImages(t *testing.T) {
	newPlan := func(t *testing.T, extra bool) ([]ownedMutation, []Mutation) {
		t.Helper()
		rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, AfterKind: planAfterLiteral, Literal: admissionNone()}}
		if extra {
			key, err := MetaKey(0x10, 1)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, Mutation{DBI: readDBIsLiteral()[0], Key: key, AfterKind: planAfterLiteral, Literal: LogicalCounterValue(0, 0)})
		}
		return updateNativePlan(t, rows...), rows
	}
	requireUnknown := func(t *testing.T, outcome updateNativeOutcome) {
		t.Helper()
		engine := requireEngineError(t, outcome.primary, EngineCapacity, operationUpdate, codeENOSPC)
		if engine.Diagnostic != expectedNativeDiagnostic(codeENOSPC) {
			t.Fatalf("UNKNOWN primary=%+v", engine)
		}
		requireUpdateTruth(t, outcome, CommitTruthUnknown, true, outcome.primary, nil)
	}
	t.Run("third image", func(t *testing.T) {
		plan, rows := newPlan(t, false)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		outcome, cleanup := fixtureUpdatePostCommitENOSPCThird(store, plan)
		if outcome.stage != 3 {
			t.Fatal("readback stage drifted")
		}
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, []byte{0x7f}, true)
		mustEnvironment(t, store.Close())
	})
	t.Run("mixed image", func(t *testing.T) {
		plan, rows := newPlan(t, true)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		outcome, cleanup := fixtureUpdatePostCommitENOSPCThird(store, plan)
		if outcome.stage != 3 {
			t.Fatal("readback stage drifted")
		}
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, []byte{0x7f}, true)
		requireUpdateValue(t, store, rows[1].DBI, rows[1].Key, rows[1].Literal, true)
		mustEnvironment(t, store.Close())
	})
	t.Run("missing image", func(t *testing.T) {
		rows := []Mutation{{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: planAfterLiteral, Literal: admissionNone()}}
		plan := updateNativePlan(t, rows...)
		store, err := Create(filepath.Join(t.TempDir(), "db"), environmentConfig())
		mustEnvironment(t, err)
		mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: rows[0].DBI, key: rows[0].Key, value: []byte{0x42}}))
		outcome, cleanup := fixtureUpdatePostCommitENOSPCMissing(store, plan)
		if outcome.stage != 3 {
			t.Fatal("readback stage drifted")
		}
		mustEnvironment(t, cleanup)
		requireUnknown(t, outcome)
		requireUpdateValue(t, store, rows[0].DBI, rows[0].Key, nil, false)
		mustEnvironment(t, store.Close())
	})
}

func TestPrunedProfileMalformed(t *testing.T) {
	for _, name := range []string{"absent", "empty", "short", "tag-payload", "canonical-width"} {
		t.Run(name, func(t *testing.T) {
			s, path, cfg := consultedStore(t)
			a := modelBase(2, 0, 0)
			encoded, err := a.Encode()
			mustEnvironment(t, err)
			tip, key := &AuthorityPointV1{}, []byte{2}
			dbi, value := readDBIsLiteral()[0], encoded
			switch name {
			case "empty":
				value = []byte{}
			case "short":
				value = []byte{1}
			case "tag-payload":
				value = append([]byte(nil), encoded...)
				value[34], value[36] = 9, 9
			case "canonical-width":
				mustEnvironment(t, fixtureSeedRows(s, fixtureRawRow{dbi: dbi, key: key, value: encoded}))
				dbi, key, value = readDBIsLiteral()[2], make([]byte, 16), make([]byte, 103)
				key[7] = 1
			}
			if name != "absent" {
				mustEnvironment(t, fixtureSeedPrefixRawRow(s, dbi, key, value))
			}
			before := updateImage{}
			if name != "absent" {
				before, err = updateOwnedImage(value)
				mustEnvironment(t, err)
			}
			mustEnvironment(t, s.View(func(reader *Reader) error {
				equal, readErr := updateNativeEqual(reader.txn, s.dbis[dbi.Rank], key, before)
				if readErr != nil || !equal {
					t.Fatalf("pruned profile malformed baseline drifted: %v", readErr)
				}
				return nil
			}))
			owner := bootstrapOwner(t)
			out := s.SelectPrunedProfileV1(true, tip, owner)
			diagnostic, cause := "invalid pruned profile authority", error(errSchema)
			if name == "canonical-width" {
				diagnostic, cause = "stored value width outside SchemaV2 bound", nil
			}
			bootstrapRefusal(t, "pruned profile malformed authority drifted", out.Truth, out.Err, EngineIntegrity, operationGet, codeInvalid, diagnostic, cause, true)
			if out.Stage != 1 || out.Decision != "" || out.Authority != nil || s.state != storeCLOSED {
				t.Fatal("pruned profile malformed authority drifted")
			}
			again := s.SelectPrunedProfileV1(true, tip, owner)
			if !sameError(again.Err, out.Err) || again.Truth != 1 || again.Stage != 1 {
				t.Fatal("pruned profile malformed terminal drifted")
			}
			prunedReleased(t, owner)
			reopened, openErr := Open(path, cfg)
			mustEnvironment(t, openErr)
			defer func() { _ = reopened.Close() }()
			mustEnvironment(t, reopened.View(func(reader *Reader) error {
				image := updateImage{}
				if name != "absent" {
					image, err = updateOwnedImage(value)
					if err != nil {
						return err
					}
				}
				equal, readErr := updateNativeEqual(reader.txn, reopened.dbis[dbi.Rank], key, image)
				if readErr != nil || !equal {
					t.Fatalf("pruned profile malformed old image drifted: %v", readErr)
				}
				return nil
			}))
		})
	}
}

func TestPrunedProfileNativeImages(t *testing.T) {
	for _, mode := range []string{"old", "new", "third", "unreadable", "selected", "exclusion", "progress", "tip"} {
		t.Run(mode, func(t *testing.T) {
			a := modelBase(2, 0, 13682)
			a.ActiveGenerationID, a.NextGenerationID = 7, 9
			a.SelectedSide = modelSide(8, 9, 11, 2, 3)
			a.ExcludedInvalidBranch = &InvalidBranchV1{ExactConsensusError: []byte{4}}
			tip := &AuthorityPointV1{Height: 15121, BlockHash: modelHash(61)}
			s, _, _, _ := prunedStore(t, a, tip, modelWork(false))
			primary := nativeError(operationUpdate, codeENOSPC)
			var outcome updateNativeOutcome
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			mustEnvironment(t, s.View(func(reader *Reader) error {
				decision := ""
				batch, err := prunedProfileBatch(reader, &a, true, tip, &decision, errors.New("decision"))
				if err != nil {
					return err
				}
				if len(batch.Mutations) != 1 || len(batch.Consulted) != 1 {
					t.Fatal("pruned profile strict readback drifted")
				}
				plan := updateNativePlan(t, batch.Mutations...)
				consulted := []ownedConsulted{{dbi: batch.Consulted[0].DBI, key: batch.Consulted[0].Key}}
				if _, err := updateNativeConsultedImages(reader.txn, s.dbis, consulted); err != nil {
					return err
				}
				if mode != "old" {
					execute := append([]ownedMutation(nil), plan...)
					changed := a
					switch mode {
					case "third":
						changed.NextGenerationID = 10
					case "selected":
						side := *a.SelectedSide
						side.LogicalBytes = 4
						changed.SelectedSide = &side
					case "exclusion":
						excluded := *a.ExcludedInvalidBranch
						excluded.ExactConsensusError = []byte{5}
						changed.ExcludedInvalidBranch = &excluded
					case "progress":
						changed.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 2, GenerationID: 7, LastHeight: 1, NextHeight: 1}}}
					}
					execute[0].literal, err = changed.Encode()
					if err != nil {
						return err
					}
					requireUpdateTruth(t, s.updateNative(execute, consulted, reader.txn), CommitTruthNew, true, nil, nil)
				}
				if mode == "tip" {
					change := updateNativePlan(t, Mutation{DBI: consulted[0].dbi, Key: consulted[0].key, BeforePresent: true, AfterKind: AfterLiteral, Literal: ChainValue(modelHash(62), [32]byte{}, modelWork(false))},
						canonicalDelete(canonicalOwnerLiteral(7, 15121, modelHash(61))), canonicalOwnerLiteral(7, 15121, modelHash(62)))
					requireUpdateTruth(t, s.updateNative(change, nil, reader.txn), CommitTruthNew, true, nil, nil)
				}
				handles := s.dbis
				if mode == "unreadable" {
					handles[0] = ^handles[0]
				}
				outcome = updateNativeReadback(s.env, handles, plan, consulted, reader.txn, primary)
				return nil
			}))
			want := CommitTruthUnknown
			if mode == "old" {
				want = CommitTruthOld
			}
			if mode == "new" {
				want = CommitTruthNew
			}
			if outcome.truth != want || outcome.stage != 3 || !sameError(outcome.primary, primary) || !outcome.commitAttempted || outcome.valid() != nil || (outcome.secondary != nil) != (mode == "unreadable") {
				t.Fatalf("pruned profile strict readback drifted: %+v", outcome)
			}
		})
	}
	// Native helper composition below is separate from public-operation execution.
	for _, mode := range []string{"result-true", "new-enospc", "unknown-enospc"} {
		t.Run(mode, func(t *testing.T) {
			a := modelBase(2, 0, 0)
			s, _, _, _ := prunedStore(t, a, nil, modelWork(false))
			a.ActiveProfile = 1
			encoded, err := a.Encode()
			mustEnvironment(t, err)
			plan := updateNativePlan(t, Mutation{DBI: readDBIsLiteral()[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded})
			var native updateNativeOutcome
			switch mode {
			case "result-true":
				native = fixtureUpdateResultTrue(s, plan)
			case "new-enospc":
				native, err = fixtureUpdatePostCommitENOSPC(s, plan)
			case "unknown-enospc":
				native, err = fixtureUpdatePostCommitENOSPCUnreadable(s, plan)
			}
			mustEnvironment(t, err)
			truth, stage, terminal := s.applyUpdateOutcome(native, nil, nil, false)
			out := prunedProfileOutcome(PrunedProfileOutcome{Truth: truth, Stage: stage, Err: terminal}, &a, "", errors.New("decision"))
			wantTruth, wantStage := CommitTruthNew, UpdateStage(3)
			if mode == "result-true" {
				wantTruth, wantStage = CommitTruthOld, 1
			}
			if mode == "unknown-enospc" {
				wantTruth = CommitTruthUnknown
			}
			if out.Truth != wantTruth || out.Stage != wantStage || !sameError(out.Err, terminal) || (out.Authority != nil) != (wantTruth == 2) || s.state != storeCLOSED {
				t.Fatal("pruned profile native outcome drifted")
			}
			again := s.SelectPrunedProfileV1(true, nil, bootstrapOwner(t))
			if again.Truth != wantTruth || again.Stage != 1 || !sameError(again.Err, terminal) || again.Authority != nil {
				t.Fatal("pruned profile native cached outcome drifted")
			}
		})
	}
	for _, mode := range []string{"retained-write", "retained-read", "new-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			s := newUpdateStore(t)
			cfg, dbis, env, writer := s.config, s.dbis, s.env, s.writer
			format, identity := s.format.Load(), s.databaseID
			a, sentinel := modelBase(1, 0, 0), errors.New("decision")
			primary, cleanup := nativeError(operationUpdate, codeENOSPC), nativeError(operationAbort, codeThreadMismatch)
			var native updateNativeOutcome
			var release func() error
			if mode == "new-cleanup" {
				native = updateNativeConsumed(CommitTruthNew, true, primary, nil, 3)
			} else {
				var err error
				native, release, err = fixtureUpdateWrongThread(s)
				mustEnvironment(t, err)
				if mode == "retained-read" {
					// The existing retained native token witnesses projection only; no public fault injection.
					native = updateNativeRetainedRead(primary, cleanup, native.retainedWrite)
				}
			}
			var oldCleanup error
			if mode == "new-cleanup" {
				oldCleanup = nativeError(operationAbort, codeEIO)
			}
			truth, stage, terminal := s.applyUpdateOutcome(native, nil, oldCleanup, false)
			out := prunedProfileOutcome(PrunedProfileOutcome{Truth: truth, Stage: stage, Err: terminal}, &a, "", sentinel)
			if !sameError(out.Err, terminal) || out.Truth != native.truth || out.Stage != native.stage || (out.Authority != nil) != (mode == "new-cleanup") {
				t.Fatal("pruned profile cleanup provenance drifted")
			}
			if mode == "new-cleanup" {
				commit, ok := terminal.(*CommitError)
				if !ok || !sameError(commit.Cause, primary) || !sameError(commit.ReadbackCause, oldCleanup) || s.state != storeCLOSED {
					t.Fatal("pruned profile cleanup provenance drifted")
				}
			} else if s.state != storePOISONEDTHREAD || s.txn != updateRetained(native) || s.env != env || s.writer != writer || s.config != (ConfigV1{}) || s.dbis != (Store{}).dbis {
				t.Fatal("pruned profile retained owner drifted")
			}
			again := s.SelectPrunedProfileV1(true, nil, bootstrapOwner(t))
			if !sameError(again.Err, terminal) || again.Truth != truth || again.Stage != 1 || again.Authority != nil {
				t.Fatal("pruned profile retained next call drifted")
			}
			if release != nil {
				mustEnvironment(t, release())
				// Test-only restoration after the fixture owner released the actual token.
				s.state, s.txn, s.config, s.dbis, s.terminal, s.terminalTruth = storeOPEN, nil, cfg, dbis, nil, 0
				s.format.Store(format)
				s.databaseID = identity
				mustEnvironment(t, s.Close())
			}
		})
	}
}

// This is adapter-image evidence for the exact genesis write/consulted set,
// independent of the consensus operation's payload projection.
func TestNativeUpdateGenesisImages(t *testing.T) {
	data, err := os.ReadFile("../../../../conformance/fixtures/CV-DEVNET-GENESIS.json")
	mustEnvironment(t, err)
	var fixture struct {
		Vectors []struct {
			Block string `json:"block_hex"`
			Hash  string `json:"block_hash"`
			Txid  string `json:"coinbase_txid"`
		} `json:"vectors"`
	}
	mustEnvironment(t, json.Unmarshal(data, &fixture))
	if len(fixture.Vectors) != 1 {
		t.Fatal("genesis literal fixture cardinality")
	}
	block, hash, txid := mustCodecHex(t, fixture.Vectors[0].Block), mustCodecHex(t, fixture.Vectors[0].Hash), mustCodecHex(t, fixture.Vectors[0].Txid)
	dbis := readDBIsLiteral()
	counterKey := []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}
	utxoKey := append(append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, txid...), 0, 0, 0, 0)
	chain := append(append([]byte(nil), hash...), make([]byte, 72)...)
	chain[103] = 1
	manifest := make([]byte, 33)
	manifest[0], manifest[28] = 1, 1
	artifacts := []Mutation{{DBI: dbis[3], Key: hash, AfterKind: AfterLiteral, Literal: block[:116]}, {DBI: dbis[4], Key: hash, AfterKind: AfterLiteral, Literal: block}, {DBI: dbis[5], Key: append(append([]byte(nil), hash...), 0), AfterKind: AfterLiteral, Literal: manifest}}
	base := []Mutation{{DBI: dbis[0], Key: counterKey, BeforePresent: true, AfterKind: AfterLiteral, Literal: []byte{0, 0, 0, 0, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0, 0, 1}}, {DBI: dbis[1], Key: utxoKey, AfterKind: AfterLiteral, Literal: mustCodecHex(t, "00407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd7279000000000000000001")}, {DBI: dbis[2], Key: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, AfterKind: AfterLiteral, Literal: chain}}
	for _, reuse := range []bool{false, true} {
		for _, mode := range []string{"old", "new", "third", "unreadable", "consulted0", "consulted1", "consulted2", "consulted3", "consulted4", "consulted5"} {
			if !reuse && (mode == "consulted3" || mode == "consulted4" || mode == "consulted5") {
				continue
			}
			t.Run(fmt.Sprintf("reuse%v/%s", reuse, mode), func(t *testing.T) {
				store := newUpdateStore(t)
				defer func() { _ = store.Close() }()
				mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: dbis[0], key: []byte{2}, value: admissionNone()}, fixtureRawRow{dbi: dbis[0], key: counterKey, value: make([]byte, 16)}))
				mutations := append([]Mutation(nil), base...)
				consulted := []ConsultedRow{{DBI: dbis[0], Key: []byte{0}}, {DBI: dbis[0], Key: []byte{1}}, {DBI: dbis[0], Key: []byte{2}}}
				for _, row := range artifacts {
					if reuse {
						mustEnvironment(t, fixtureSeedRows(store, fixtureRawRow{dbi: row.DBI, key: row.Key, value: row.Literal}))
						consulted = append(consulted, ConsultedRow{DBI: row.DBI, Key: row.Key})
					} else {
						mutations = append(mutations, row)
					}
				}
				mutations = append(mutations, Mutation{DBI: dbis[7], Key: append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, hash...), AfterKind: AfterLiteral, Literal: make([]byte, 8)})
				plan := updateNativePlan(t, mutations...)
				var outcome updateNativeOutcome
				primary := nativeError(operationUpdate, codeENOSPC)
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				mustEnvironment(t, store.View(func(reader *Reader) error {
					owned := make([]ownedConsulted, len(consulted))
					for i, row := range consulted {
						owned[i] = ownedConsulted{dbi: row.DBI, key: row.Key}
					}
					_, err := updateNativeConsultedImages(reader.txn, store.dbis, owned)
					if err != nil {
						return err
					}
					if mode != "old" {
						execute := append([]ownedMutation(nil), plan...)
						if mode == "third" {
							execute[1].literal = append([]byte(nil), execute[1].literal...)
							execute[1].literal[0] ^= 1
						}
						requireUpdateTruth(t, store.updateNative(execute, owned, reader.txn), CommitTruthNew, true, nil, nil)
					}
					if strings.HasPrefix(mode, "consulted") {
						row := consulted[int(mode[len(mode)-1]-'0')]
						change := []ownedMutation{{dbi: row.DBI, key: row.Key, beforePresent: true, after: AfterLiteral, literal: []byte{0x7f}}}
						requireUpdateTruth(t, store.updateNative(change, nil, reader.txn), CommitTruthNew, true, nil, nil)
					}
					handles := store.dbis
					if mode == "unreadable" {
						handles[0] = ^handles[0]
					}
					outcome = updateNativeReadback(store.env, handles, plan, owned, reader.txn, primary)
					return nil
				}))
				want := map[string]CommitTruth{"old": CommitTruthOld, "new": CommitTruthNew}[mode]
				if want == 0 {
					want = CommitTruthUnknown
				}
				if outcome.truth != want || outcome.stage != 3 || outcome.primary != primary || !outcome.commitAttempted || outcome.valid() != nil || (outcome.secondary != nil) != (mode == "unreadable") { //nolint:errorlint // Readback retains the exact primary cause.
					t.Fatalf("genesis strict readback drifted: %+v", outcome)
				}
			})
		}
	}
	t.Run("schema_invalid", func(t *testing.T) {
		wrongAuthority, wrongHeader := admissionNone(), append([]byte(nil), block[:116]...)
		wrongAuthority[0], wrongHeader[0] = 2, wrongHeader[0]^1
		for _, row := range []struct {
			name       string
			rank       uint8
			key, value []byte
			semantic   bool
		}{
			{"authority-empty", 0, []byte{2}, []byte{}, true},
			{"authority-09", 0, []byte{2}, []byte{9}, true},
			{"authority-version", 0, []byte{2}, wrongAuthority, true},
			{"counter-empty", 0, counterKey, []byte{}, false},
			{"counter-short", 0, counterKey, make([]byte, 15), false},
			{"counter-long", 0, counterKey, make([]byte, 17), false},
			{"header-different", 3, hash, wrongHeader, true},
			{"header-empty", 3, hash, []byte{}, false},
			{"body-empty", 4, hash, []byte{}, false},
			{"manifest-empty", 5, artifacts[2].Key, []byte{}, false},
		} {
			t.Run(row.name, func(t *testing.T) {
				path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
				store, createErr := Create(path, cfg)
				mustEnvironment(t, createErr)
				defer func() { _ = store.Close() }()
				truth, stage, err := store.Update(func(*Reader) (Batch, error) {
					return Batch{Mutations: []Mutation{{DBI: dbis[row.rank], Key: row.key, AfterKind: AfterLiteral, Literal: row.value}}}, nil
				})
				if truth != 1 || stage != 1 || err == nil {
					t.Fatalf("genesis schema admission drifted: %v/%v/%v", truth, stage, err)
				}
				requireEngineError(t, err, EngineInvalidInput, operationUpdate, codeEINVAL)
				mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[row.rank], row.key, row.value))
				image, imageErr := updateOwnedImage(row.value)
				mustEnvironment(t, imageErr)
				check := func(reader *Reader, label string) {
					equal, err := updateNativeEqual(reader.txn, store.dbis[row.rank], row.key, image)
					if err != nil || !equal {
						t.Fatalf("%s: %v/%v", label, equal, err)
					}
				}
				var observed error
				truth, stage, err = store.Update(func(reader *Reader) (Batch, error) {
					check(reader, "genesis raw OLD drifted")
					value, present, readErr := reader.Get(dbis[row.rank], row.key)
					if row.semantic {
						if readErr != nil || !present || !bytes.Equal(value, row.value) {
							t.Fatalf("genesis semantic read drifted: %v", readErr)
						}
						if row.rank == 0 {
							_, observed = DecodeStorageAuthorityV1(value)
						} else {
							_, observed = HashBoundValue([32]byte(hash), value, false)
						}
						if observed == nil {
							t.Fatal("genesis semantic decoder accepted malformed row")
						}
					} else {
						engine := requireEngineError(t, readErr, EngineIntegrity, operationGet, codeInvalid)
						if engine.Diagnostic != "stored value width outside SchemaV2 bound" || reader.active.Load() {
							t.Fatalf("genesis width read drifted: %+v", engine)
						}
						observed = readErr
					}
					check(reader, "genesis raw OLD drifted")
					return Batch{}, observed
				})
				if truth != 1 || stage != 1 || err != observed { //nolint:errorlint // The callback cause must survive unchanged.
					t.Fatalf("genesis raw refusal drifted: %v/%v/%v", truth, stage, err)
				}
				if !row.semantic {
					if store.state != storeCLOSED || store.env != nil || store.writer != nil {
						t.Fatal("genesis raw Reader failure retained its Store")
					}
					truth, stage, err = store.Update(func(*Reader) (Batch, error) { t.Fatal("genesis raw terminal callback entered"); return Batch{}, nil })
					if truth != 1 || stage != 1 || err != observed { //nolint:errorlint // The consumed Store returns its exact cached error.
						t.Fatal("genesis raw terminal tuple drifted")
					}
				}
				_ = store.Close()
				store, err = Open(path, cfg)
				mustEnvironment(t, err)
				mustEnvironment(t, store.View(func(reader *Reader) error {
					check(reader, "genesis durable raw OLD drifted")
					return nil
				}))
			})
		}
	})
}

// TestReaderGetOptionalSideRawWidth reads persisted widths at and beyond the SchemaV2 bounds: legal lower and upper
// widths copy with their native Length; zero, below-lower and above-upper widths are Present/InvalidWidth with their
// native Length, no copy and a usable Reader; the required SideLink width failure stays Get's record.
func TestReaderGetOptionalSideRawWidth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	store, err := Create(path, ConfigV1{1 << 20, 2 << 20, 256 << 20, 1 << 20, 2 << 20, 4096, 492})
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	rows := []struct {
		rank   uint8
		length int
		valid  bool
	}{{3, 0, false}, {3, 100, false}, {3, 116, true}, {3, 117, false}, {4, 115, false}, {4, 116, true}, {4, 68_000_125, true}, {4, 68_000_126, false}}
	for i, row := range rows {
		key := [32]byte{byte(i + 1)}
		mustEnvironment(t, FixtureSeedRawRow(store, row.rank, key[:], make([]byte, row.length)))
	}
	link, _ := HeightKey(2, 9)
	mustEnvironment(t, FixtureSeedRawRow(store, 6, link, make([]byte, 103)))
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for i, row := range rows {
			key := [32]byte{byte(i + 1)}
			got, err := reader.GetOptionalSide(schemaDBIs[row.rank], key[:])
			wantValue := len(got.Value) == row.length && !got.InvalidWidth
			if !row.valid {
				wantValue = got.Value == nil && got.InvalidWidth
			}
			if err != nil || !got.Present || got.Length != uint64(row.length) || !wantValue || reader.failure != nil || !reader.usable() {
				t.Fatalf("rank %d width %d = present %v invalid %v length %d copied %d, %v", row.rank, row.length, got.Present, got.InvalidWidth, got.Length, len(got.Value), err)
			}
		}
		return nil
	}))
	var recorded error
	viewErr := store.View(func(reader *Reader) error {
		_, err := reader.ReadRequiredSideLink(2, 9)
		requireEnvironmentError(t, err, EngineIntegrity, operationGet, codeInvalid, "stored value width outside SchemaV2 bound")
		if !sameError(reader.failure, err) || reader.usable() {
			t.Fatal("SideLink width failure was not Get's recorded object")
		}
		recorded = err
		return err
	})
	if !sameError(viewErr, recorded) {
		t.Fatalf("SideLink width raw disposition drifted: %v", viewErr)
	}
}

// TestReaderGetOptionalSideNativeShape pins the impossible native tuples before any copy: SUCCESS with a nil pointer
// and positive length, NOTFOUND with a pointer or length, and a native error are the distinct existing boundary errors.
func TestReaderGetOptionalSideNativeShape(t *testing.T) {
	for _, row := range []struct {
		name    string
		rc      int
		present bool
		length  uint64
	}{{"success nil pointer", codeSuccess, false, 5}, {"notfound pointer", codeNotFound, true, 0}, {"notfound length", codeNotFound, false, 3}} {
		_, err := fixtureOptionalSideShape(schemaDBIs[4], row.rc, row.present, row.length)
		requireEnvironmentError(t, err, EngineLocalInvariant, operationGet, codeProblem, "mdbx_get returned invalid result shape")
	}
	_, err := fixtureOptionalSideShape(schemaDBIs[3], codeEIO, false, 0)
	requireEngineError(t, err, EngineIO, operationGet, codeEIO)
	for _, length := range []uint64{0, 1} {
		got, err := fixtureOptionalSideShape(schemaDBIs[3], codeSuccess, true, length)
		if err != nil || got.Value != nil || got.Length != length || !got.Present || !got.InvalidWidth {
			t.Fatalf("length %d = %+v, %v", length, got, err)
		}
	}
}

func initial148NativeStore(t *testing.T) *Store {
	t.Helper()
	store, err := Create(filepath.Join(t.TempDir(), "db"), ConfigV1{1 << 20, 2 << 20, 256 << 20, 1 << 20, 2 << 20, 4096, 492})
	mustEnvironment(t, err)
	t.Cleanup(func() { _ = FixtureStartupRelease(store); _ = store.Close() })
	return store
}

func initial148NativeTuple(t *testing.T, got, want OptionalSideValueV1, err error, diagnostic string) {
	t.Helper()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got length=%d present=%v invalid=%v bytes=%d, want length=%d present=%v invalid=%v bytes=%d, %v", diagnostic, got.Length, got.Present, got.InvalidWidth, len(got.Value), want.Length, want.Present, want.InvalidWidth, len(want.Value), err)
	}
}

func initial148NativeRefusal(t *testing.T, reader *Reader, dbi DBI, key []byte, diagnostic string) {
	t.Helper()
	got, err := reader.GetInitial148OptionalSide(dbi, key)
	initial148NativeTuple(t, got, OptionalSideValueV1{}, nil, "initial148 refusal zero tuple")
	engine := requireEnvironmentError(t, err, EngineClass("InvalidInput"), engineOperation("get"), 22, diagnostic)
	if engine.Cause != nil || engine.ReopenRequired {
		t.Fatal("initial148 direct refusal error fields")
	}
}

func TestInitial148NativeReaderFixture(t *testing.T) {
	store, header := initial148NativeStore(t), initial148NativeLiteral(t)
	rows := []struct {
		rank   uint8
		length int
		valid  bool
	}{{3, 0, false}, {3, 116, false}, {3, 147, false}, {3, 148, true}, {3, 149, false}, {4, 0, false}, {4, 147, false}, {4, 148, true}, {4, 149, true}, {4, 68_000_157, true}, {4, 68_000_158, false}}
	for i, row := range rows {
		key, value := [32]byte{byte(i + 1)}, make([]byte, row.length)
		copy(value, header)
		mustEnvironment(t, FixtureSeedRawRow(store, row.rank, key[:], value))
	}
	var escaped *Reader
	var held []byte
	mustEnvironment(t, store.View(func(reader *Reader) error {
		escaped = reader
		for i, row := range rows {
			key, want := [32]byte{byte(i + 1)}, OptionalSideValueV1{Length: uint64(row.length), Present: true, InvalidWidth: !row.valid}
			if row.valid {
				want.Value = make([]byte, row.length)
				copy(want.Value, header)
			}
			got, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[row.rank], key[:])
			initial148NativeTuple(t, got, want, err, fmt.Sprintf("initial148 native tuple/bad width rank%d length%d", row.rank, row.length))
			if reader.failure != nil || !reader.usable() || key != ([32]byte{byte(i + 1)}) {
				t.Fatal("initial148 native bad width poisoned Reader")
			}
			if row.valid {
				got.Value[0] ^= 1
				got.Value[len(got.Value)-1] ^= 1
				again, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[row.rank], key[:])
				initial148NativeTuple(t, again, want, err, "initial148 native owned copy")
				if row.length == 149 {
					held = again.Value
				}
			}
			validKey := [32]byte{4}
			next, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[3], validKey[:])
			initial148NativeTuple(t, next, OptionalSideValueV1{Value: header, Length: 148, Present: true}, err, "initial148 next legal operation")
		}
		missing := [32]byte{255}
		for _, rank := range []uint8{3, 4} {
			got, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[rank], missing[:])
			initial148NativeTuple(t, got, OptionalSideValueV1{}, err, "initial148 native absent")
		}
		return nil
	}))
	for _, dbi := range []DBI{readDBIsLiteral()[3], {}} {
		for _, key := range [][]byte{make([]byte, 32), nil} {
			initial148NativeRefusal(t, escaped, dbi, key, "Reader is not active")
		}
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		key := [32]byte{4}
		got, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[3], key[:])
		initial148NativeTuple(t, got, OptionalSideValueV1{Value: header, Length: 148, Present: true}, err, "initial148 next legal operation sibling View")
		return nil
	}))
	mustEnvironment(t, store.Close())
	if escaped.active.Load() || escaped.failure != nil || !bytes.Equal(held, append(bytes.Clone(header), 0)) {
		t.Fatal("initial148 reader expires or owned copy changed after View/Close")
	}
}

func TestInitial148NativeInputs(t *testing.T) {
	key := make([]byte, 32)
	for _, reader := range []*Reader{nil, {}} {
		for _, dbi := range []DBI{readDBIsLiteral()[3], {}} {
			for _, input := range [][]byte{key, nil} {
				initial148NativeRefusal(t, reader, dbi, input, "Reader is not active")
			}
		}
	}
	store := initial148NativeStore(t)
	for _, rank := range []uint8{2, 3, 4, 5} {
		for _, length := range []int{31, 32, 33} {
			mustEnvironment(t, FixtureSeedRawRow(store, rank, make([]byte, length), make([]byte, 147)))
		}
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		copied := &Reader{self: reader, txn: reader.txn, dbis: reader.dbis}
		copied.active.Store(true)
		for _, dbi := range []DBI{readDBIsLiteral()[3], {}} {
			for _, input := range [][]byte{key, nil} {
				initial148NativeRefusal(t, copied, dbi, input, "Reader is not active")
			}
		}
		for _, row := range []struct {
			dbi DBI
			key []byte
		}{{readDBIsLiteral()[2], key}, {readDBIsLiteral()[5], key}, {DBI{"wrong", 3, 0}, key}, {DBI{"headers-v1", 3, 1}, key}, {DBI{"wrong", 4, 0}, key}, {DBI{"blocks-v1", 4, 1}, key}, {readDBIsLiteral()[3], nil}, {readDBIsLiteral()[3], key[:31]}, {readDBIsLiteral()[3], make([]byte, 33)}, {readDBIsLiteral()[4], key[:31]}, {readDBIsLiteral()[4], make([]byte, 33)}} {
			initial148NativeRefusal(t, reader, row.dbi, row.key, "invalid optional-side DBI or key")
			if reader.failure != nil || !reader.usable() {
				t.Fatal("initial148 direct input refusal recorded or disarmed")
			}
			got, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[3], key)
			initial148NativeTuple(t, got, OptionalSideValueV1{Length: 147, Present: true, InvalidWidth: true}, err, "initial148 next legal operation after input refusal")
		}
		return nil
	}))
}

func TestInitial148NativeShape(t *testing.T) {
	for _, rank := range []uint8{3, 4} {
		for _, row := range []struct {
			rc      int
			present bool
			length  uint64
		}{{0, false, 148}, {-30798, true, 0}, {-30798, false, 1}, {-30798, true, 1}} {
			got, err := fixtureInitial148OptionalSideShape(readDBIsLiteral()[rank], row.rc, row.present, row.length)
			initial148NativeTuple(t, got, OptionalSideValueV1{}, nil, "initial148 impossible native zero tuple")
			engine := requireEnvironmentError(t, err, EngineClass("LocalInvariant"), engineOperation("get"), -30779, "mdbx_get returned invalid result shape")
			if engine.Cause != nil || engine.ReopenRequired {
				t.Fatal("initial148 impossible native error tuple")
			}
		}
		got, err := fixtureInitial148OptionalSideShape(readDBIsLiteral()[rank], -30798, false, 0)
		initial148NativeTuple(t, got, OptionalSideValueV1{}, err, "initial148 native shape absence")
		for _, present := range []bool{false, true} {
			got, err := fixtureInitial148OptionalSideShape(readDBIsLiteral()[rank], 0, present, 0)
			initial148NativeTuple(t, got, OptionalSideValueV1{Present: true, InvalidWidth: true}, err, "initial148 native zero width")
		}
		for _, length := range []uint64{147, 68_000_158, 1 << 31, 1<<64 - 1} {
			got, err := fixtureInitial148OptionalSideShape(readDBIsLiteral()[rank], 0, true, length)
			initial148NativeTuple(t, got, OptionalSideValueV1{Length: length, Present: true, InvalidWidth: true}, err, "initial148 native narrowing refused")
		}
		got, err = fixtureInitial148OptionalSideShape(readDBIsLiteral()[rank], 5, false, 0)
		initial148NativeTuple(t, got, OptionalSideValueV1{}, nil, "initial148 EIO zero tuple")
		engine := requireEnvironmentError(t, err, EngineClass("IO"), engineOperation("get"), 5, "error 5")
		if engine.Cause != nil || engine.ReopenRequired {
			t.Fatal("initial148 EIO error tuple")
		}
	}
}

func TestInitial148NativeCallbackLifetime(t *testing.T) {
	for _, observation := range []string{"success", "bad width", "absent", "input refusal"} {
		for _, completion := range []string{"nil", "error", "panic"} {
			t.Run(observation+"/"+completion, func(t *testing.T) {
				store, header, key := initial148NativeStore(t), initial148NativeLiteral(t), [32]byte{1}
				mustEnvironment(t, FixtureSeedRawRow(store, 3, key[:], header))
				bad := [32]byte{2}
				mustEnvironment(t, FixtureSeedRawRow(store, 3, bad[:], header[:147]))
				application, marker := errors.New("initial148 application"), &struct{}{}
				var escaped *Reader
				var result error
				var panicked any
				func() {
					defer func() { panicked = recover() }()
					result = store.View(func(reader *Reader) error {
						escaped = reader
						selected, want := key, OptionalSideValueV1{Value: header, Length: 148, Present: true}
						switch observation {
						case "bad width":
							selected, want = bad, OptionalSideValueV1{Length: 147, Present: true, InvalidWidth: true}
						case "absent":
							selected, want = [32]byte{3}, OptionalSideValueV1{}
						case "input refusal":
							initial148NativeRefusal(t, reader, readDBIsLiteral()[2], key[:], "invalid optional-side DBI or key")
						}
						got, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[3], selected[:])
						initial148NativeTuple(t, got, want, err, "initial148 callback observation")
						next, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[3], key[:])
						initial148NativeTuple(t, next, OptionalSideValueV1{Value: header, Length: 148, Present: true}, err, "initial148 next legal operation in callback")
						if completion == "panic" {
							panic(marker)
						}
						if completion == "error" {
							return application
						}
						return nil
					})
				}()
				if completion == "panic" && panicked != marker || completion != "panic" && panicked != nil || (completion == "error") != sameError(result, application) || completion != "error" && result != nil || escaped.failure != nil || escaped.active.Load() || store.state != storeOPEN || !validStoreShape(store) {
					t.Fatal("initial148 reader expires: application outcome/resource shape")
				}
				initial148NativeRefusal(t, escaped, DBI{}, nil, "Reader is not active")
				mustEnvironment(t, store.View(func(reader *Reader) error {
					got, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[3], key[:])
					initial148NativeTuple(t, got, OptionalSideValueV1{Value: header, Length: 148, Present: true}, err, "initial148 next legal operation after callback")
					return nil
				}))
			})
		}
	}
}

func TestInitial148NativeFailureRecording(t *testing.T) {
	for _, route := range []struct{ update, tree, evidence bool }{{false, false, false}, {true, false, false}, {false, true, false}, {false, true, true}} {
		update := route.update
		for _, completion := range []string{"ignored", "returned", "wrapped", "application", "panic", "Goexit"} {
			for _, abort := range []uint32{0, 9, 10, 11} {
				name := fmt.Sprintf("tree%v/update%v/%s/abort%d", route.tree, update, completion, abort)
				if route.evidence {
					name += "/evidence12"
				}
				t.Run(name, func(t *testing.T) {
					store, key := initial148NativeStore(t), []byte{1}
					key = append(key, make([]byte, 31)...)
					rank := uint8(4)
					if route.tree {
						mustEnvironment(t, store.Close())
						store, _, _ = treeNativeStore(t)
						key, rank = []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 1}, 0
					}
					reference := TreeImportReferenceV1{OriginalDatabaseID: [32]byte{9}, OriginalCurrentID: 1, OriginalLagID: 2, OriginalRole: 1, EvidenceID: [32]byte{3}}
					if route.evidence {
						key = append([]byte{0x12}, reference.EvidenceID[:]...)
						// The reached native error must precede this malformed capsule.
						treeNativeSeed(t, store, 0, key, []byte{0})
					}
					env, writer := store.env, store.writer
					var escaped *Reader
					var recorded, returned, application error
					var panicked any
					marker := &struct{}{}
					callback := func(reader *Reader) error {
						escaped = reader
						initial148NativeRefusal(t, reader, readDBIsLiteral()[2], key, "invalid optional-side DBI or key")
						invalidKey := key[:len(key)-1]
						if route.evidence {
							invalidKey = key[:31]
						}
						initial148NativeRefusal(t, reader, readDBIsLiteral()[4], invalidKey, "invalid optional-side DBI or key")
						if reader.failure != nil || !reader.usable() {
							t.Fatal("initial148 direct refusal reached native/recording")
						}
						got, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[4], key)
						if route.evidence {
							evidence, evidenceErr := reader.ReadTreeEvidenceV1(reference)
							if !reflect.DeepEqual(evidence, TreeEvidenceV1{}) {
								t.Fatal("tree native error leaked evidence")
							}
							err = evidenceErr
						} else if route.tree {
							root, present, rootErr := reader.ReadTreeRootBindingV1(1)
							if root != (RootBindingV1{}) || present {
								t.Fatal("tree native error leaked root")
							}
							err = rootErr
						}
						initial148NativeTuple(t, got, OptionalSideValueV1{}, nil, "initial148 native failure zero tuple")
						engine := requireEnvironmentError(t, err, EngineClass("IO"), engineOperation("get"), 5, "error 5")
						if engine.Cause != nil || engine.ReopenRequired || !sameError(reader.failure, err) || reader.active.Load() || reader.usable() {
							t.Fatal("initial148 native failure recording")
						}
						recorded = err
						for _, dbi := range []DBI{readDBIsLiteral()[4], {}} {
							for _, input := range [][]byte{key, nil} {
								initial148NativeRefusal(t, reader, dbi, input, "Reader is not active")
							}
						}
						switch completion {
						case "returned":
							application = recorded
						case "wrapped":
							application = fmt.Errorf("initial148 wrapped: %w", recorded)
						case "application":
							application = errors.New("initial148 distinct application")
						case "panic":
							panic(marker)
						case "Goexit":
							runtime.Goexit()
						}
						return application
					}
					invoke := func() {
						defer func() { panicked = recover() }()
						if !update {
							returned = store.View(callback)
							return
						}
						truth, stage, err := store.Update(func(reader *Reader) (Batch, error) { return Batch{}, callback(reader) })
						returned = err
						if truth != CommitTruth(1) || stage != UpdateStage(1) {
							t.Fatal("initial148 native failure Update truth/stage")
						}
					}
					arm := func() {
						evidence, err := FixtureSelectedDamage(store, bootstrapOwner(t), SelectedDamageGetEIO, rank, key, invoke)
						mustEnvironment(t, err)
						wantGets := [8]uint64{}
						wantGets[rank] = 1
						if evidence.BeginOld != 1 || evidence.BeginRead != 0 || evidence.BeginWrite != 0 || evidence.OldGets != wantGets || evidence.ReadGets != 0 || evidence.Faults != 1 || evidence.Commits != 0 || evidence.Deletes != 0 {
							t.Fatalf("initial148 native failure recording census: %+v", evidence)
						}
					}
					run := func() {
						if abort == 0 {
							arm()
						} else {
							_, err := fixtureLargeFault(store, abort, rank, key, arm)
							mustEnvironment(t, err)
						}
					}
					if completion == "Goexit" {
						done := make(chan struct{})
						go func() { defer close(done); run() }()
						<-done
					} else {
						run()
					}
					if completion == "panic" && panicked != marker || completion != "panic" && panicked != nil || !sameError(escaped.failure, recorded) || escaped.active.Load() || !validStoreShape(store) {
						t.Fatal("initial148 native failure recording: enclosing outcome/Reader")
					}
					terminal, primary := store.terminal, store.terminal
					if completion != "panic" && completion != "Goexit" && !sameError(returned, terminal) {
						t.Fatal("initial148 enclosing error object replaced")
					}
					if abort == 11 {
						engine := requireEnvironmentError(t, terminal, EngineClass("Concurrency"), operationClose, -30778, expectedNativeDiagnostic(-30778))
						primary = engine.Cause
						if store.state != storeCLOSEBLOCKED || store.env != env || store.writer != writer || store.txn != nil || store.format.Load() == 0 || !store.config.valid() || !validStoreShape(store) {
							t.Fatal("initial148 close-BUSY retained published resource shape")
						}
					} else if abort == 10 {
						engine := requireEnvironmentError(t, terminal, EngineClass("LocalInvariant"), engineOperation("abort"), -30416, pinnedNegativeDiagnostics[-30416])
						primary = engine.Cause
						if store.state != storePOISONEDTHREAD || store.txn != escaped.txn || store.env != env || store.writer != writer || store.config != (ConfigV1{}) || !reflect.ValueOf(store.dbis).IsZero() || store.format.Load() != 0 || store.databaseID != ([32]byte{}) {
							t.Fatal("initial148 retained cleanup resource shape")
						}
					} else {
						if store.state != storeCLOSED || store.env != nil || store.writer != nil || store.txn != nil || store.config != (ConfigV1{}) || !reflect.ValueOf(store.dbis).IsZero() || store.format.Load() != 0 || store.databaseID != ([32]byte{}) {
							t.Fatal("initial148 consumed cleanup resource shape")
						}
						if abort == 9 {
							parts := terminal.(interface{ Unwrap() []error }).Unwrap()
							if len(parts) != 2 {
								t.Fatal("initial148 abort error order")
							}
							primary = parts[0]
							requireEnvironmentError(t, parts[1], EngineClass("IO"), engineOperation("abort"), 5, "error 5")
						}
					}
					if completion == "wrapped" || completion == "application" {
						parts := primary.(interface{ Unwrap() []error }).Unwrap()
						if len(parts) != 2 || !sameError(parts[0], application) || !sameError(parts[1], recorded) {
							t.Fatal("initial148 application/recorded source order or identity")
						}
					} else if !sameError(primary, recorded) {
						t.Fatal("initial148 exact recorded source identity")
					}
					initial148NativeRefusal(t, escaped, DBI{}, nil, "Reader is not active")
					if !sameError(store.View(func(*Reader) error { t.Fatal("terminal callback"); return nil }), terminal) {
						t.Fatal("initial148 next legal operation terminal View")
					}
					truth, stage, next := store.Update(func(*Reader) (Batch, error) { t.Fatal("terminal Update"); return Batch{}, nil })
					if truth != CommitTruth(1) || stage != UpdateStage(1) || !sameError(next, terminal) {
						t.Fatal("initial148 next legal operation terminal Update")
					}
					mustEnvironment(t, FixtureStartupRelease(store))
					if route.tree && abort == 10 {
						// Teardown preserves a retained abort terminal after releasing its handle;
						// that test-only CLOSED shape is not a production state transition.
						if store.self != store || store.state != storeCLOSED || store.env != nil || store.writer != nil || store.txn != nil || store.config != (ConfigV1{}) || !reflect.ValueOf(store.dbis).IsZero() || store.format.Load() != 0 || store.databaseID != ([32]byte{}) || !sameError(store.terminal, terminal) || store.terminalTruth != 0 {
							t.Fatal("tree fixture teardown resource/terminal preservation")
						}
					} else if route.tree {
						treeNativeZeroResources(t, store)
					}
				})
			}
		}
	}
}

func treeNativeKeyLiteral(t *testing.T, upper, code string) []byte {
	t.Helper()
	return mustCodecHex(t, "0000000000000001"+upper+code)
}

func treeNativeSeed(t *testing.T, store *Store, rank uint8, key, value []byte) {
	t.Helper()
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, TreeSchemaV1DBIs()[rank], key, value))
}

func treeNativeAuthorityBytes(t *testing.T, source TreeSourceKindV1, progress TreeProgressKindV1) []byte {
	t.Helper()
	authority := TreeAuthorityV1{
		Authority:       StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: 1, Lifecycle: 1},
		LagGenerationID: 2,
	}
	if source != 0 {
		authority.Authority = modelReplay(1)
		authority.Authority.NextGenerationID = 5
		authority.Authority.Replay.TargetGenerationID = 3
		authority.TargetLagGenerationID = 4
		authority.SourceKind = source
		if source == 1 {
			authority.Authority.Replay.Cursor.Kind = 1
		} else {
			authority.Authority.Replay.Cursor = ReplayCursorV1{}
			authority.Progress = TreeProgressV1{Kind: progress, Payload: []byte{0xde, 0xad}}
		}
	}
	encoded, err := authority.Encode()
	mustEnvironment(t, err)
	return encoded
}

func TestTreeNativeAbsentAuthorityCensus(t *testing.T) {
	for _, opening := range []bool{false, true} {
		for rank := range 9 {
			t.Run(fmt.Sprintf("open%v/extra rank%d", opening, rank), func(t *testing.T) {
				store, path, identity := treeNativeStore(t)
				key := []byte{0xfe}
				treeNativeSeed(t, store, uint8(rank), key, []byte{1})
				if opening {
					mustEnvironment(t, store.Close())
					got, err := OpenTreeV1(path, environmentConfig(), identity)
					if got != nil {
						t.Fatal("stray row published tree store")
					}
					treeNativeIntegrity(t, err, operationOpen, nil)
					return
				}
				var recorded error
				returned := store.View(func(reader *Reader) error {
					got, present, err := reader.ReadTreeAuthorityV1()
					if !reflect.DeepEqual(got, TreeAuthorityV1{}) || present {
						t.Fatal("tree absent authority census returned partial/absence success")
					}
					treeNativeIntegrity(t, err, operationGet, nil)
					recorded = err
					if reader.failure != err || reader.usable() {
						t.Fatal("tree census did not record exact failure")
					}
					_, _, next := reader.ReadTreeAuthorityV1()
					treeNativeError(t, next, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
					if reader.failure != recorded {
						t.Fatal("later census failure replaced first")
					}
					return nil
				})
				if returned != recorded || store.terminal != recorded || store.state != storeCLOSED {
					t.Fatal("tree absent census enclosing owner")
				}
				treeNativeZeroResources(t, store)
			})
		}
		for _, control := range []byte{0, 1, 3} {
			for _, defect := range []string{"missing", "width", "different"} {
				t.Run(fmt.Sprintf("open%v/control%02x/%s", opening, control, defect), func(t *testing.T) {
					store, path, identity := treeNativeStore(t)
					var cause error
					if defect == "missing" {
						mustEnvironment(t, fixtureDeletePrefixRow(store, readDBIsLiteral()[0], []byte{control}))
						// Keep count three, so the required-point read owns the refusal.
						treeNativeSeed(t, store, 0, []byte{0xfe}, []byte{1})
					} else {
						value := []byte{0, 0, 0, 4}
						switch control {
						case 0:
							cause = errSchema
						case 1:
							cfg := environmentConfig()
							cfg.MaxReaders++
							value = mustConfigBytes(t, cfg)
						case 3:
							value = bytes.Repeat([]byte{8}, 32)
						}
						if defect == "width" {
							value = value[:len(value)-1]
							cause = errSchema
						}
						treeNativeSeed(t, store, 0, []byte{control}, value)
					}
					if opening {
						mustEnvironment(t, store.Close())
						got, err := OpenTreeV1(path, environmentConfig(), identity)
						if got != nil {
							t.Fatal("invalid control published Store")
						}
						treeNativeIntegrity(t, err, operationOpen, cause)
						return
					}
					err := store.View(func(reader *Reader) error {
						got, present, err := reader.ReadTreeAuthorityV1()
						if present || !reflect.DeepEqual(got, TreeAuthorityV1{}) || reader.failure != err || reader.usable() {
							t.Fatal("tree control census error effects")
						}
						return err
					})
					treeNativeIntegrity(t, err, operationGet, cause)
				})
			}
		}
	}
}

func TestTreeNativeTypedPointsAndProvenance(t *testing.T) {
	store, path, identity := treeNativeStore(t)
	authority := mustCodecHex(t, "01000000000000000002000000000000000000000028"+
		"01010000000000000000000000000000000000000000000000010000000000000005010100000000"+
		"0000000000")
	treeNativeSeed(t, store, 0, []byte{2}, authority)
	for i, applied := range []bool{false, true} {
		root := treeRootFixture(t, applied)
		root.DatabaseID = identity
		encoded, err := root.Encode()
		mustEnvironment(t, err)
		key := binary.BigEndian.AppendUint64([]byte{0x11}, uint64(i+1))
		treeNativeSeed(t, store, 0, key, encoded)
	}
	capsule := treeEvidenceFixture()
	encoded, err := capsule.Encode()
	mustEnvironment(t, err)
	id := sha3.Sum256(encoded)
	reference := TreeImportReferenceV1{OriginalDatabaseID: capsule.OriginalDatabaseID, OriginalCurrentID: capsule.OriginalCurrentID, OriginalLagID: capsule.OriginalLagID, OriginalRole: 1, EvidenceID: id}
	for i, role := range []TreeOriginalRoleV1{1, 2} {
		root := treeRootFixture(t, true)
		root.DatabaseID = identity
		original := reference
		original.OriginalRole = role
		root.Assurance = TreeAssuranceV1{Kind: 2, Import: &original}
		if role == 2 {
			top := treeBranch(0, [36]byte{})
			root.Top = TreeTopV1{Kind: 2, Node: &top}
		}
		value, err := root.Encode()
		mustEnvironment(t, err)
		treeNativeSeed(t, store, 0, binary.BigEndian.AppendUint64([]byte{0x11}, uint64(i+3)), value)
	}
	treeNativeSeed(t, store, 0, append([]byte{0x12}, id[:]...), encoded)
	mustEnvironment(t, store.Close())
	store, err = OpenTreeV1(path, environmentConfig(), identity)
	mustEnvironment(t, err)
	defer func() { _ = store.Close() }()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		wantAuthority := TreeAuthorityV1{
			Authority:       StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: 1, Lifecycle: 1},
			LagGenerationID: 2,
		}
		legacy, err := reader.ReadStorageAuthorityV1()
		if !reflect.DeepEqual(legacy, StorageAuthorityV1{}) || reader.failure != nil || !reader.usable() {
			t.Fatal("populated tree legacy authority refusal changed Reader or leaked authority")
		}
		treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "tree Reader requires tree authority accessor", nil)
		got, present, err := reader.ReadTreeAuthorityV1()
		if err != nil || !present || !reflect.DeepEqual(got, wantAuthority) || reader.ownerVerified {
			t.Fatalf("tree authority envelope native point: %+v/%v/%v", got, present, err)
		}
		for i, applied := range []bool{false, true} {
			want := treeRootFixture(t, applied)
			want.DatabaseID = identity
			root, present, err := reader.ReadTreeRootBindingV1(uint64(i + 1))
			if err != nil || !present || !reflect.DeepEqual(root, want) {
				t.Fatalf("tree root PRE versus APPLIED0: %+v/%v/%v", root, present, err)
			}
			root.DatabaseID[0] ^= 1
		}
		for i, role := range []TreeOriginalRoleV1{1, 2} {
			root, present, err := reader.ReadTreeRootBindingV1(uint64(i + 3))
			want := reference
			want.OriginalRole = role
			if err != nil || !present || root.Assurance.Kind != 2 || root.Assurance.Import == nil || *root.Assurance.Import != want {
				t.Fatal("tree imported root retained original reference")
			}
			if role == 2 && (root.Top.Kind != 2 || root.Top.Node == nil || *root.Top.Node != treeBranch(0, [36]byte{})) {
				t.Fatal("tree maximum328 root point")
			}
			root.Assurance.Import.OriginalDatabaseID[0] ^= 1
			again, _, err := reader.ReadTreeRootBindingV1(uint64(i + 3))
			if err != nil || *again.Assurance.Import != want {
				t.Fatal("tree imported reference aliases native/another read")
			}
		}
		for _, role := range []TreeOriginalRoleV1{1, 2} {
			reference.OriginalRole = role
			evidence, err := reader.ReadTreeEvidenceV1(reference)
			if err != nil || !reflect.DeepEqual(evidence, capsule) || reference.OriginalDatabaseID == identity {
				t.Fatalf("tree original evidence role%d: %+v/%v", role, evidence, err)
			}
			evidence.Payload[0] ^= 1
		}
		evidence, err := reader.ReadTreeEvidenceV1(reference)
		if err != nil || !reflect.DeepEqual(evidence, capsule) {
			t.Fatal("tree evidence owned payload retention")
		}
		return nil
	}))
}

func TestTreeNativeTypedCorruption(t *testing.T) {
	for _, defect := range []string{"root foreign", "root version", "root width132", "root width329", "authority shape", "authority empty", "evidence missing", "evidence empty", "evidence malformed", "evidence hash", "evidence database", "evidence current", "evidence lag"} {
		t.Run(defect, func(t *testing.T) {
			store, _, identity := treeNativeStore(t)
			root := treeRootFixture(t, false)
			root.DatabaseID = identity
			if defect == "root foreign" {
				root.DatabaseID = [32]byte{9}
			}
			value, err := root.Encode()
			mustEnvironment(t, err)
			capsule := treeEvidenceFixture()
			encoded, err := capsule.Encode()
			mustEnvironment(t, err)
			id := sha3.Sum256(encoded)
			reference := TreeImportReferenceV1{OriginalDatabaseID: capsule.OriginalDatabaseID, OriginalCurrentID: capsule.OriginalCurrentID, OriginalLagID: capsule.OriginalLagID, OriginalRole: 1, EvidenceID: id}
			cause := error(nil)
			switch defect {
			case "root version":
				value[33] = 2
				cause = errSchema
			case "root width132":
				value = value[:132]
				cause = errSchema
			case "root width329":
				value = append(value, make([]byte, 329-len(value))...)
				cause = errSchema
			case "authority shape", "authority empty":
				container := []byte{0}
				if defect == "authority empty" {
					container = nil
				}
				treeNativeSeed(t, store, 0, []byte{2}, container)
				cause = errSchema
			case "evidence empty":
				encoded = nil
				cause = errSchema
			case "evidence malformed":
				encoded[0] = 0
				cause = errSchema
			case "evidence hash":
				encoded[len(encoded)-1] ^= 1
				cause = errSchema
			case "evidence database":
				reference.OriginalDatabaseID[0] ^= 1
			case "evidence current":
				reference.OriginalCurrentID = 9
			case "evidence lag":
				reference.OriginalLagID++
			}
			treeNativeSeed(t, store, 0, []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 1}, value)
			if defect != "evidence missing" {
				treeNativeSeed(t, store, 0, append([]byte{0x12}, id[:]...), encoded)
			}
			var recorded error
			returned := store.View(func(reader *Reader) error {
				switch {
				case strings.HasPrefix(defect, "root"):
					got, present, err := reader.ReadTreeRootBindingV1(1)
					if got != (RootBindingV1{}) || present {
						t.Fatal("tree destination identity partial output")
					}
					recorded = err
				case strings.HasPrefix(defect, "evidence"):
					got, err := reader.ReadTreeEvidenceV1(reference)
					if !reflect.DeepEqual(got, TreeEvidenceV1{}) {
						t.Fatal("tree evidence resolution partial output")
					}
					recorded = err
				default:
					got, present, err := reader.ReadTreeAuthorityV1()
					if !reflect.DeepEqual(got, TreeAuthorityV1{}) || present {
						t.Fatal("tree authority partial output")
					}
					recorded = err
				}
				treeNativeIntegrity(t, recorded, operationGet, cause)
				if reader.failure != recorded || reader.usable() {
					t.Fatal("tree typed first-failure identity/disarm")
				}
				return recorded
			})
			if returned != recorded || store.terminal != recorded || store.state != storeCLOSED {
				t.Fatal("tree typed enclosing effect")
			}
			treeNativeZeroResources(t, store)
		})
	}
}

func TestTreeNativePostorder(t *testing.T) {
	for _, fixture := range []string{"boundary", "shared_upper"} {
		t.Run(fixture, func(t *testing.T) {
			store, _, _ := treeNativeStore(t)
			allOnes := [36]byte{}
			for i := range allOnes {
				allOnes[i] = 0xff
			}
			identities := []TreeNodeIDV1{treeLeaf([36]byte{}), treeBranch(287, [36]byte{}), treeBranch(256, [36]byte{}), treeBranch(255, [36]byte{}), treeBranch(9, [36]byte{}), treeBranch(8, [36]byte{}), treeBranch(7, [36]byte{}), treeLeaf(allOnes), treeBranch(0, [36]byte{})}
			// Upper/code literals remain independent of the key producer transformed by M02.N.
			uppers := []string{strings.Repeat("00", 36), strings.Repeat("00", 35) + "01", strings.Repeat("00", 32) + strings.Repeat("ff", 4), strings.Repeat("00", 31) + "01" + strings.Repeat("ff", 4), "007f" + strings.Repeat("ff", 34), "00" + strings.Repeat("ff", 35), "01" + strings.Repeat("ff", 35), strings.Repeat("ff", 36), strings.Repeat("ff", 36)}
			codes := []string{"0000", "0001", "0020", "0021", "0117", "0118", "0119", "0000", "0120"}
			removed := []int{1, 3, 7}
			if fixture == "shared_upper" {
				// Every branch has an all-one upper bound. Depth-for-code mutants stay
				// decodable, so native paging reaches the independent order comparison.
				identities = []TreeNodeIDV1{treeLeaf(allOnes)}
				for _, row := range []struct {
					depth  uint16
					prefix string
				}{
					{287, strings.Repeat("ff", 35) + "fe"},
					{256, strings.Repeat("ff", 32) + strings.Repeat("00", 4)},
					{255, strings.Repeat("ff", 31) + "fe" + strings.Repeat("00", 4)},
					{9, "ff80" + strings.Repeat("00", 34)},
					{8, "ff" + strings.Repeat("00", 35)},
					{7, "fe" + strings.Repeat("00", 35)},
				} {
					prefix := [36]byte{}
					copy(prefix[:], mustCodecHex(t, row.prefix))
					identities = append(identities, treeBranch(row.depth, prefix))
				}
				uppers = []string{strings.Repeat("ff", 36), strings.Repeat("ff", 36), strings.Repeat("ff", 36), strings.Repeat("ff", 36), strings.Repeat("ff", 36), strings.Repeat("ff", 36), strings.Repeat("ff", 36)}
				codes = []string{"0000", "0001", "0020", "0021", "0117", "0118", "0119"}
				removed = []int{1, 3, 5}
			}
			markers := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
			keys, values := make([][]byte, len(identities)), make([][]byte, len(identities))
			for i := len(identities) - 1; i >= 0; i-- {
				key, err := TreeNodeKey(1, identities[i])
				mustEnvironment(t, err)
				keys[i] = treeNativeKeyLiteral(t, uppers[i], codes[i])
				width := 140
				if identities[i].Kind == 1 {
					width = 32
				}
				values[i] = bytes.Repeat([]byte{markers[i]}, width)
				// Raw insertion must reach native paging even under M02.N; no codec admission here.
				treeNativeSeed(t, store, 8, key, values[i])
			}
			for _, remnant := range []bool{false, true} {
				t.Run(fmt.Sprintf("remnant%v", remnant), func(t *testing.T) {
					if remnant {
						for _, index := range removed {
							key, err := TreeNodeKey(1, identities[index])
							mustEnvironment(t, err)
							mustEnvironment(t, fixtureDeletePrefixRow(store, DBI{Name: "tree-node-v1", Rank: 8}, key))
						}
					}
					mustEnvironment(t, store.View(func(reader *Reader) error {
						page, err := reader.PrefixPage(DBI{Name: "tree-node-v1", Rank: 8}, []byte{0, 0, 0, 0, 0, 0, 0, 1}, nil, 1440, 154611151)
						var expected []PrefixRow
						for i, key := range keys {
							if remnant && (i == removed[0] || i == removed[1] || i == removed[2]) {
								continue
							}
							expected = append(expected, PrefixRow{Key: key, Value: values[i]})
						}
						if err != nil {
							t.Fatalf("tree native paging failed before order comparison: %v", err)
						}
						if page.Stop != PrefixPageExhausted || !reflect.DeepEqual(page.Rows, expected) {
							t.Fatalf("tree postorder complete/remnant native observation: remnant%v page%+v error%v", remnant, page, err)
						}
						page.Rows[0].Key[0] ^= 1
						page.Rows[0].Value[0] ^= 1
						return nil
					}))
				})
			}
		})
	}
}

func TestTreeNativePagingBounds(t *testing.T) {
	for _, width := range []int{31, 32, 33, 139, 140, 141} {
		t.Run(fmt.Sprintf("node width%d", width), func(t *testing.T) {
			for _, raw := range []bool{false, true} {
				t.Run(fmt.Sprintf("raw%v", raw), func(t *testing.T) { treeNativeNodeWidth(t, width, raw) })
			}
		})
	}
	store, _, _ := treeNativeStore(t)
	mustEnvironment(t, store.View(func(reader *Reader) error {
		dbi, prefix := DBI{Name: "tree-node-v1", Rank: 8}, []byte{0, 0, 0, 0, 0, 0, 0, 1}
		key := treeNativeKeyLiteral(t, strings.Repeat("00", 36), "0000")
		for _, after := range [][]byte{key, treeNativeKeyLiteral(t, strings.Repeat("ff", 36), "0001")} {
			page, err := reader.PrefixPage(dbi, prefix, after, 1, 186)
			if err != nil || page.Stop != PrefixPageExhausted || len(page.Rows) != 0 {
				t.Fatal("tree native same-prefix continuation46")
			}
		}
		for _, row := range []struct {
			prefix, after []byte
			rows          uint32
			bytes         uint64
			diagnostic    string
		}{
			{prefix[:7], nil, 1, 186, "invalid prefix-page prefix"},
			{append(bytes.Clone(prefix), 0), nil, 1, 186, "invalid prefix-page prefix"},
			{make([]byte, 8), nil, 1, 186, "invalid prefix-page prefix"},
			{prefix, key[:45], 1, 186, "invalid prefix-page continuation"},
			{prefix, append(bytes.Clone(key), 0), 1, 186, "invalid prefix-page continuation"},
			{prefix, append([]byte{1}, key[1:]...), 1, 186, "invalid prefix-page continuation"},
			{prefix, treeNativeKeyLiteral(t, strings.Repeat("ff", 36), "0121"), 1, 186, "invalid prefix-page continuation"},
			{prefix, treeNativeKeyLiteral(t, strings.Repeat("ff", 35)+"fe", "0001"), 1, 186, "invalid prefix-page continuation"},
			{prefix, nil, 0, 186, "invalid prefix-page row limit"},
			{prefix, nil, 1441, 186, "invalid prefix-page row limit"},
			{prefix, nil, 1, 185, "invalid prefix-page byte limit"},
			{prefix, nil, 1, 154611152, "invalid prefix-page byte limit"},
		} {
			page, err := reader.PrefixPage(dbi, row.prefix, row.after, row.rows, row.bytes)
			requirePrefixPageError(t, page, err, row.diagnostic, nil)
			if !reader.usable() || reader.failure != nil {
				t.Fatal("tree page static refusal disarmed")
			}
		}
		page, err := reader.PrefixPage(dbi, prefix, key, 1, 186)
		if err != nil || page.Stop != PrefixPageExhausted || len(page.Rows) != 0 {
			t.Fatal("tree page static refusal prevented next valid read")
		}
		return err
	}))
}

func treeNativeNodeWidth(t *testing.T, width int, raw bool) {
	t.Helper()
	store, _, _ := treeNativeStore(t)
	upper, code := strings.Repeat("00", 36), "0000"
	if width >= 139 {
		upper, code = strings.Repeat("ff", 36), "0120"
	}
	key, value := treeNativeKeyLiteral(t, upper, code), bytes.Repeat([]byte{0x5a}, width)
	treeNativeSeed(t, store, 8, key, value)
	valid := width == 32 || width == 140
	var recorded error
	err := store.View(func(reader *Reader) error {
		for attempt := 0; attempt < 2; attempt++ {
			got, readErr := treeNativeNodeWidthRead(t, reader, key, raw, valid)
			if !valid {
				recorded = readErr
				if !sameError(reader.failure, recorded) || reader.active.Load() || reader.usable() {
					t.Fatal("tree native node width first failure/disarm")
				}
				return recorded
			}
			if readErr != nil || !bytes.Equal(got, value) || reader.failure != nil || !reader.usable() {
				t.Fatalf("tree native node width owned bytes: %x/%v", got, readErr)
			}
			got[0] ^= 1
		}
		return nil
	})
	if valid {
		mustEnvironment(t, err)
		return
	}
	if !sameError(err, recorded) || !sameError(store.terminal, recorded) || store.state != storeCLOSED {
		t.Fatal("tree native node width enclosing owner")
	}
	treeNativeZeroResources(t, store)
	if next := store.View(func(*Reader) error { t.Fatal("terminal node callback"); return nil }); !sameError(next, recorded) {
		t.Fatal("tree native node width next View")
	}
}

func treeNativeNodeWidthRead(t *testing.T, reader *Reader, key []byte, raw, valid bool) ([]byte, error) {
	t.Helper()
	dbi := DBI{Name: "tree-node-v1", Rank: 8}
	if raw {
		value, present, err := reader.Get(dbi, key)
		if !valid {
			treeNativeIntegrity(t, err, operationGet, errSchema)
		}
		if present != valid || !valid && value != nil {
			t.Fatal("tree native node Get zero/presence")
		}
		return value, err
	}
	page, err := reader.PrefixPage(dbi, key[:8], nil, 1, 186)
	if !valid {
		engine := requireEnvironmentError(t, err, EngineClass("Integrity"), operationPrefixPage, -30793, "stored value width outside SchemaV2 bound")
		if engine.Cause != nil || !engine.ReopenRequired {
			t.Fatal("tree native node page inherited Cause/ReopenRequired")
		}
		if page.Rows != nil || page.Stop != 0 {
			t.Fatal("tree native node page width refusal")
		}
		return nil, err
	}
	if err != nil || page.Stop != PrefixPageExhausted || len(page.Rows) != 1 || !bytes.Equal(page.Rows[0].Key, key) {
		t.Fatalf("tree native node page: %+v/%v", page, err)
	}
	page.Rows[0].Key[0] ^= 1
	return page.Rows[0].Value, err
}

func TestTreeNativeOpenNoRolePrefetch(t *testing.T) {
	for _, row := range []struct {
		source, progress byte
		currentFirst     bool
	}{
		{0, 0, false},
		{1, 0, false},
		{2, 1, false},
		{2, 2, false},
		{0, 0, true},
		{1, 0, true},
		{2, 1, true},
		{2, 2, true},
	} {
		t.Run(fmt.Sprintf("source%d/status%d/currentFirst%v", row.source, row.progress, row.currentFirst), func(t *testing.T) {
			store, path, identity := treeNativeStore(t)
			treeNativeSeed(t, store, 0, []byte{2}, treeNativeAuthorityBytes(t, TreeSourceKindV1(row.source), TreeProgressKindV1(row.progress)))
			// The authority is valid; unrequested rows are deliberately malformed or absent.
			for _, key := range [][]byte{
				{0x10, 0, 0, 0, 0, 0, 0, 0, 1},
				{0x11, 0, 0, 0, 0, 0, 0, 0, 1},
				{0x12, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			} {
				treeNativeSeed(t, store, 0, key, []byte{0})
			}
			want := treeRootFixture(t, false)
			want.DatabaseID = identity
			if row.currentFirst {
				encoded, err := want.Encode()
				mustEnvironment(t, err)
				treeNativeSeed(t, store, 0, []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 1}, encoded)
				treeNativeSeed(t, store, 0, []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 2}, []byte{0})
			}
			mustEnvironment(t, store.Close())
			opened, err := OpenTreeV1(path, environmentConfig(), identity)
			if err != nil || opened == nil {
				t.Fatalf("tree open has no role prefetch: %v", err)
			}
			if opened.canonicalOwnerVerified {
				t.Fatal("tree open granted canonical service")
			}
			wantAuthority := TreeAuthorityV1{
				Authority:       StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: 1, Lifecycle: 1},
				LagGenerationID: 2,
			}
			if row.source != 0 {
				wantAuthority.Authority.Phase, wantAuthority.Authority.Lifecycle = 3, 2
				wantAuthority.Authority.Replay = &ReplayV1{
					TargetProfile: 2, TargetGenerationID: 3,
					Target: RecoveryTargetV1{
						ChainID: [32]byte{31: 11}, GenesisHash: [32]byte{31: 12}, TipHash: [32]byte{31: 13},
						TipHeight: 2, CumulativeChainwork: [40]byte{39: 1},
					},
				}
				wantAuthority.TargetLagGenerationID = 4
				wantAuthority.SourceKind = TreeSourceKindV1(row.source)
				if row.source == 1 {
					wantAuthority.Authority.Replay.Cursor = ReplayCursorV1{Kind: 1}
				} else {
					wantAuthority.Progress = TreeProgressV1{Kind: TreeProgressKindV1(row.progress), Payload: []byte{0xde, 0xad}}
				}
			}
			var recorded error
			err = opened.View(func(reader *Reader) error {
				got, present, err := reader.ReadTreeAuthorityV1()
				if err != nil || !present || !reflect.DeepEqual(got, wantAuthority) {
					t.Fatalf("tree authority inferred role qualification: %+v/%v/%v", got, present, err)
				}
				if row.currentFirst {
					root, present, err := reader.ReadTreeRootBindingV1(1)
					if err != nil || !present || !reflect.DeepEqual(root, want) {
						t.Fatalf("tree CURRENT root before counter: %+v/%v/%v", root, present, err)
					}
					value, present, err := reader.Get(DBI{Name: "meta-v1", Rank: 0}, []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1})
					treeNativeIntegrity(t, err, operationGet, errSchema)
					recorded = err
					if value != nil || present || reader.failure != recorded || reader.usable() {
						t.Fatal("tree CURRENT counter width first-failure identity/disarm")
					}
					root, present, err = reader.ReadTreeRootBindingV1(2)
					treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
					if root != (RootBindingV1{}) || present || reader.failure != recorded {
						t.Fatal("later LAG read replaced CURRENT counter failure")
					}
					return recorded
				}
				root, present, err := reader.ReadTreeRootBindingV1(2)
				if root != (RootBindingV1{}) || present || err != nil {
					t.Fatal("missing unrequested LAG became qualified")
				}
				root, present, err = reader.ReadTreeRootBindingV1(1)
				if root != (RootBindingV1{}) || present {
					t.Fatal("reached malformed root returned value")
				}
				recorded = err
				return err
			})
			treeNativeIntegrity(t, err, operationGet, errSchema)
			if err != recorded || opened.terminal != recorded || opened.state != storeCLOSED {
				t.Fatal("tree no-prefetch enclosing View failure identity/resources")
			}
			treeNativeZeroResources(t, opened)
		})
	}
}

func TestTreeNativeRaw148Widths(t *testing.T) {
	for _, rank := range []uint8{3, 4} {
		for _, width := range []int{147, 148, 149, 68000157, 68000158} {
			t.Run(fmt.Sprintf("rank%d/width%d", rank, width), func(t *testing.T) {
				store, _, _ := treeNativeStore(t)
				key, value := [32]byte{0x77}, make([]byte, width)
				for i := range min(width, 148) {
					value[i] = byte(i)
				}
				treeNativeSeed(t, store, rank, key[:], value)
				valid := width == 148 || rank == 4 && width > 148 && width <= 68000157
				err := store.View(func(reader *Reader) error {
					optional, err := reader.GetInitial148OptionalSide(readDBIsLiteral()[rank], key[:])
					if err != nil || !optional.Present || optional.Length != uint64(width) || optional.InvalidWidth == valid || !valid && optional.Value != nil || valid && !bytes.Equal(optional.Value, value) || !reader.usable() || reader.failure != nil {
						t.Fatalf("tree initial148 raw status: %+v/%v", optional, err)
					}
					got, present, err := reader.Get(readDBIsLiteral()[rank], key[:])
					if valid {
						if err != nil || !present || !bytes.Equal(got, value) {
							t.Fatal("tree raw legal-width wrong-key rejected or changed")
						}
						got[0] ^= 1
						if optional.Value[0] != value[0] {
							t.Fatal("tree raw copies alias sibling observation")
						}
					} else if got != nil || present || reader.failure != err || reader.usable() {
						t.Fatal("tree raw invalid-width effects")
					}
					return err
				})
				if valid {
					mustEnvironment(t, err)
				} else {
					treeNativeIntegrity(t, err, operationGet, errSchema)
				}
			})
		}
	}
}

func TestTreeNativeLinkedShapes(t *testing.T) {
	for _, kinds := range [][2]byte{{1, 1}, {1, 2}, {2, 1}, {2, 2}} {
		t.Run(fmt.Sprintf("children%d/%d", kinds[0], kinds[1]), func(t *testing.T) {
			store, _, _ := treeNativeStore(t)
			parent := treeBranch(0, [36]byte{})
			children := [2]*TreeChildV1{}
			var expected []PrefixRow
			var deleteKey []byte
			for side, kind := range kinds {
				prefix := [36]byte{byte(side << 7)}
				id := treeLeaf(prefix)
				if kind == 2 {
					id = treeBranch(1, prefix)
					grandchildren := [2]*TreeChildV1{}
					for childSide := range 2 {
						key := prefix
						key[0] |= byte(childSide << 6)
						leaf := treeLeaf(key)
						value := bytes.Repeat([]byte{byte(1 + side*2 + childSide)}, 32)
						encodedKey, err := TreeNodeKey(1, leaf)
						mustEnvironment(t, err)
						treeNativeSeed(t, store, 8, encodedKey, value)
						literal := treeNativeKeyLiteral(t, fmt.Sprintf("%02x", key[0])+strings.Repeat("00", 35), "0000")
						expected = append(expected, PrefixRow{Key: literal, Value: value})
						grandchildren[childSide] = &TreeChildV1{ID: leaf, Digest: [32]byte{byte(childSide + 1)}}
					}
					value, err := (TreeNodeV1{Zero: grandchildren[0], One: grandchildren[1]}).Encode(id)
					mustEnvironment(t, err)
					encodedKey, err := TreeNodeKey(1, id)
					mustEnvironment(t, err)
					treeNativeSeed(t, store, 8, encodedKey, value)
					upper := "7f" + strings.Repeat("ff", 35)
					if side == 1 {
						upper = strings.Repeat("ff", 36)
					}
					literal := treeNativeKeyLiteral(t, upper, "011f")
					expected = append(expected, PrefixRow{Key: literal, Value: value})
					deleteKey = encodedKey
				} else {
					encodedKey, err := TreeNodeKey(1, id)
					mustEnvironment(t, err)
					value := bytes.Repeat([]byte{byte(side + 5)}, 32)
					treeNativeSeed(t, store, 8, encodedKey, value)
					literal := treeNativeKeyLiteral(t, fmt.Sprintf("%02x", prefix[0])+strings.Repeat("00", 35), "0000")
					expected = append(expected, PrefixRow{Key: literal, Value: value})
					deleteKey = encodedKey
				}
				children[side] = &TreeChildV1{ID: id, Digest: [32]byte{byte(side + 9)}}
			}
			value, err := (TreeNodeV1{Zero: children[0], One: children[1]}).Encode(parent)
			mustEnvironment(t, err)
			key, err := TreeNodeKey(1, parent)
			mustEnvironment(t, err)
			treeNativeSeed(t, store, 8, key, value)
			expected = append(expected, PrefixRow{Key: treeNativeKeyLiteral(t, strings.Repeat("ff", 36), "0120"), Value: value})
			for _, remnant := range []bool{false, true} {
				if remnant {
					mustEnvironment(t, fixtureDeletePrefixRow(store, DBI{Name: "tree-node-v1", Rank: 8}, deleteKey))
				}
				mustEnvironment(t, store.View(func(reader *Reader) error {
					page, err := reader.PrefixPage(DBI{Name: "tree-node-v1", Rank: 8}, []byte{0, 0, 0, 0, 0, 0, 0, 1}, nil, 1440, 154611151)
					want := expected
					if remnant {
						want = append(append([]PrefixRow{}, expected[:len(expected)-2]...), expected[len(expected)-1])
					}
					if err != nil || page.Stop != PrefixPageExhausted || !reflect.DeepEqual(page.Rows, want) {
						t.Fatalf("tree postorder linked complete/remnant: %+v/%v", page, err)
					}
					return nil
				}))
			}
		})
	}
}

func TestTreeNativeReachedMalformedKey(t *testing.T) {
	for _, badCode := range []uint16{289, 65535} {
		store, _, _ := treeNativeStore(t)
		first := mustCodecHex(t, "0000000000000001"+strings.Repeat("00", 38))
		bad := mustCodecHex(t, "0000000000000001"+strings.Repeat("00", 35)+"01"+"0000")
		binary.BigEndian.PutUint16(bad[44:], badCode)
		treeNativeSeed(t, store, 8, first, make([]byte, 32))
		treeNativeSeed(t, store, 8, bad, make([]byte, 140))
		// A later malformed row cannot preempt an earlier point read.
		err := store.View(func(reader *Reader) error {
			got, present, err := reader.Get(DBI{Name: "tree-node-v1", Rank: 8}, first)
			if err != nil || !present || len(got) != 32 {
				t.Fatal("tree malformed complete key prepass")
			}
			page, err := reader.PrefixPage(DBI{Name: "tree-node-v1", Rank: 8}, first[:8], first, 1, 186)
			if err == nil || page.Rows != nil || page.Stop != 0 || reader.failure != err || reader.usable() {
				t.Fatal("tree malformed complete key did not stop at reached position")
			}
			return err
		})
		engine := requireEnvironmentError(t, err, EngineIntegrity, operationPrefixPage, -30793, "stored key outside SchemaV2 prefix-page domain")
		_, direct := directTestEngineError(err)
		if !direct || engine.Cause != nil || !engine.ReopenRequired {
			t.Fatal("tree malformed complete key Cause/reopen tuple")
		}
	}
}

func TestTreeNativeRecognitionVersionAndOldBoundary(t *testing.T) {
	t.Run("authority envelope version", treeNativeRecognitionAuthorityVersion)
	for _, version := range [][]byte{nil, {0}, {0, 0, 0}, {0, 0, 0, 0}, {0, 0, 0, 1}, {0, 0, 0, 4}, {0, 0, 0, 3, 0}} {
		t.Run(fmt.Sprintf("version%x", version), func(t *testing.T) {
			store, path, identity := treeNativeStore(t)
			treeNativeSeed(t, store, 0, []byte{0}, version)
			mustEnvironment(t, store.Close())
			got, err := OpenTreeV1(path, environmentConfig(), identity)
			if got != nil {
				t.Fatal("tree version damage published Store")
			}
			treeNativeIntegrity(t, err, operationOpen, errSchema)
		})
	}
	store, path, identity := treeNativeStore(t)
	treeNativeSeed(t, store, 0, []byte{0}, []byte{0, 0, 0, 2})
	mustEnvironment(t, store.Close())
	got, err := OpenTreeV1(path, environmentConfig(), identity)
	if got != nil {
		t.Fatal("mixed schema2/nine families published")
	}
	treeNativeIntegrity(t, err, operationOpen, nil)
	oldPath := filepath.Join(t.TempDir(), "historical")
	historical, err := Create(oldPath, environmentConfig())
	mustEnvironment(t, err)
	// A recognized schema2 image is not authority/index qualification.
	mustEnvironment(t, fixtureSeedPrefixRawRow(historical, readDBIsLiteral()[0], []byte{2}, []byte{0xff}))
	mustEnvironment(t, fixtureSeedPrefixRawRow(historical, readDBIsLiteral()[2], []byte{0xff}, []byte{0xff}))
	mustEnvironment(t, historical.Close())
	before, err := os.ReadFile(filepath.Join(oldPath, "mdbx.dat"))
	mustEnvironment(t, err)
	got, err = OpenTreeV1(oldPath, environmentConfig(), identity)
	after, snapshotErr := os.ReadFile(filepath.Join(oldPath, "mdbx.dat"))
	mustEnvironment(t, snapshotErr)
	if !bytes.Equal(before, after) {
		t.Fatal("recognized schema2 refusal changed durable bytes")
	}
	if got != nil {
		t.Fatal("recognized schema2 exposed tree Store")
	}
	treeNativeError(t, err, operationOpen, EngineClass("StateMismatch"), -30779, "tree schema unavailable: recognized SchemaV2", nil)
	historical, err = Open(oldPath, environmentConfig())
	mustEnvironment(t, err)
	mustEnvironment(t, historical.Close())
}

func treeNativeRecognitionAuthorityVersion(t *testing.T) {
	t.Helper()
	store, path, identity := treeNativeStore(t)
	value := treeNativeAuthorityBytes(t, 0, 0)
	// Keep a legal raw width and every control valid; only the envelope
	// version is invalid, so the factory's authority decoder owns refusal.
	value[0] = 2
	treeNativeSeed(t, store, 0, []byte{2}, value)
	mustEnvironment(t, store.Close())
	before, err := os.ReadFile(filepath.Join(path, "mdbx.dat"))
	mustEnvironment(t, err)
	opened, err := OpenTreeV1(path, environmentConfig(), identity)
	if opened != nil {
		t.Fatal("invalid tree authority envelope published Store")
	}
	treeNativeIntegrity(t, err, operationOpen, errSchema)
	after, err := os.ReadFile(filepath.Join(path, "mdbx.dat"))
	mustEnvironment(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("tree authority envelope refusal changed durable bytes")
	}
	writer, result, err := filelock.AcquireDirectory(path)
	if err != nil || result != "" || writer == nil {
		t.Fatalf("tree authority envelope refusal retained writer: %s/%v", result, err)
	}
	mustEnvironment(t, writer.Release())
}

func TestTreeNativeRecognitionFamilies(t *testing.T) {
	for _, mode := range []uint32{1, 2} {
		t.Run(fmt.Sprintf("family mode%d", mode), func(t *testing.T) {
			store, copied, err := fixtureOpenReverseUTXO(filepath.Join(t.TempDir(), "db"), mode)
			if store != nil || len(copied) != 48 {
				t.Fatal("tree family fixture setup/Store publication")
			}
			// Mode1 has both reverse meta flags and malformed version1. Flags
			// must win with nil Cause; decoding version first yields errSchema.
			treeNativeIntegrity(t, err, operationOpen, nil)
		})
	}
}

func TestTreeNativeRecognitionEffectiveGeometry(t *testing.T) {
	cfg, physical := environmentConfig(), environmentConfig()
	physical.Upper = 512 << 20
	path, identity := filepath.Join(t.TempDir(), "db"), [32]byte{7}
	store, err := CreateTreeV1(path, physical, identity)
	mustEnvironment(t, err)
	// Stored and caller config agree; only the real environment differs.
	treeNativeSeed(t, store, 0, []byte{1}, mustConfigBytes(t, cfg))
	mustEnvironment(t, store.Close())
	before, err := os.ReadFile(filepath.Join(path, "mdbx.dat"))
	mustEnvironment(t, err)
	opened, err := OpenTreeV1(path, cfg, identity)
	if opened != nil {
		t.Fatal("tree effective geometry mismatch published Store")
	}
	treeNativeIntegrity(t, err, operationOpen, nil)
	after, err := os.ReadFile(filepath.Join(path, "mdbx.dat"))
	mustEnvironment(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("tree effective geometry refusal changed durable bytes")
	}
	writer, result, err := filelock.AcquireDirectory(path)
	if err != nil || result != "" || writer == nil {
		t.Fatalf("tree effective geometry refusal retained writer: %s/%v", result, err)
	}
	mustEnvironment(t, writer.Release())
}

func TestTreeNativeRecognitionSourceOrder(t *testing.T) {
	for _, historical := range []bool{false, true} {
		store, _, identity := treeNativeStore(t)
		if historical {
			mustEnvironment(t, store.Close())
			var err error
			store, err = Create(filepath.Join(t.TempDir(), "old"), environmentConfig())
			mustEnvironment(t, err)
		}
		// Version bytes would be positive damage if reached. The real native
		// version read is failed first on the same recognition helper Open uses.
		mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[0], []byte{0}, []byte{0, 0, 0, 4}))
		var reached, returned error
		evidence, err := FixtureSelectedDamage(store, bootstrapOwner(t), SelectedDamageGetEIO, 0, []byte{0}, func() {
			returned = store.View(func(reader *Reader) error {
				_, reached = inspectTreeSchema(store.env, reader.txn, environmentConfig(), identity)
				return reached
			})
		})
		mustEnvironment(t, err)
		treeNativeError(t, reached, operationOpen, EngineClass("IO"), 5, "error 5", nil)
		if returned != reached || evidence.BeginOld != 1 || evidence.OldGets != ([8]uint64{1}) || evidence.Faults != 1 {
			t.Fatal("tree recognition source precedence/identity")
		}
		mustEnvironment(t, store.Close())
	}
}

func TestTreeNativeCensusControlSource(t *testing.T) {
	for position, control := range []byte{0, 1, 3} {
		store, _, _ := treeNativeStore(t)
		// The reached source error must precede damaged bytes from that read.
		value := []byte{0xff}
		treeNativeSeed(t, store, 0, []byte{control}, value)
		var recorded, returned error
		evidence, err := FixtureSelectedDamage(store, bootstrapOwner(t), SelectedDamageGetEIO, 0, []byte{control}, func() {
			returned = store.View(func(reader *Reader) error {
				got, present, err := reader.ReadTreeAuthorityV1()
				if present || !reflect.DeepEqual(got, TreeAuthorityV1{}) || reader.failure != err || reader.usable() {
					t.Fatal("tree census control source zero/first failure")
				}
				recorded = err
				return nil
			})
		})
		mustEnvironment(t, err)
		treeNativeError(t, recorded, operationGet, EngineClass("IO"), 5, "error 5", nil)
		if evidence.OldGets != ([8]uint64{uint64(position + 2)}) || returned != recorded || store.terminal != recorded || evidence.Faults != 1 {
			t.Fatal("tree census controls 00/01/03 source order")
		}
		treeNativeZeroResources(t, store)
	}
}

func TestTreeNativeCensusStatSource(t *testing.T) {
	t.Run("meta count precedes rank2 stat", treeNativeCensusCountBeforeStat)
	for rank := 1; rank < 9; rank++ {
		store, _, _ := treeNativeStore(t)
		var recorded error
		returned := store.View(func(reader *Reader) error {
			// An invalid native handle reaches the existing MDBX stat source.
			// All other handles/context remain valid and distinct.
			reader.dbis[rank] = ^reader.dbis[rank] & 0xffffffff
			got, present, err := reader.ReadTreeAuthorityV1()
			if present || !reflect.DeepEqual(got, TreeAuthorityV1{}) || reader.failure != err || reader.usable() {
				t.Fatal("tree stat source zero/first failure")
			}
			recorded = err
			return nil
		})
		treeNativeError(t, recorded, operationGet, EngineClass("LocalInvariant"), -30780, expectedNativeDiagnostic(-30780), nil)
		if returned != recorded || store.terminal != recorded {
			t.Fatal("tree stat failure object wrapped")
		}
		treeNativeZeroResources(t, store)
	}
}

func treeNativeCensusCountBeforeStat(t *testing.T) {
	t.Helper()
	store, _, _ := treeNativeStore(t)
	// Absent02 and valid controls remain; this fourth meta row must be
	// reached before the independent invalid native rank2 stat handle.
	treeNativeSeed(t, store, 0, []byte{0xfe}, []byte{1})
	var recorded error
	returned := store.View(func(reader *Reader) error {
		reader.dbis[2] = ^reader.dbis[2] & 0xffffffff
		got, present, err := reader.ReadTreeAuthorityV1()
		treeNativeIntegrity(t, err, operationGet, nil)
		if present || !reflect.DeepEqual(got, TreeAuthorityV1{}) || reader.failure != err || reader.usable() {
			t.Fatal("tree count before stat zero/first failure")
		}
		recorded = err
		_, _, next := reader.ReadTreeAuthorityV1()
		treeNativeError(t, next, operationGet, EngineClass("InvalidInput"), 22, "Reader is not active", nil)
		if reader.failure != recorded {
			t.Fatal("tree count before stat replaced first failure")
		}
		return nil
	})
	if returned != recorded || store.terminal != recorded || store.state != storeCLOSED {
		t.Fatal("tree count before stat enclosing owner")
	}
	treeNativeZeroResources(t, store)
	if next := store.View(func(*Reader) error { t.Fatal("terminal callback"); return nil }); next != recorded {
		t.Fatal("tree count before stat next operation")
	}
}

func TestTreeNativeTypedStaticNoIO(t *testing.T) {
	for _, row := range []struct {
		name      string
		reference *TreeImportReferenceV1
	}{
		{"root generation zero", nil},
		{"database zero", &TreeImportReferenceV1{OriginalCurrentID: 3, OriginalLagID: 4, OriginalRole: 1}},
		{"current zero", &TreeImportReferenceV1{OriginalDatabaseID: [32]byte{1}, OriginalLagID: 4, OriginalRole: 1}},
		{"lag zero", &TreeImportReferenceV1{OriginalDatabaseID: [32]byte{1}, OriginalCurrentID: 3, OriginalRole: 1}},
		{"equal pair", &TreeImportReferenceV1{OriginalDatabaseID: [32]byte{1}, OriginalCurrentID: 3, OriginalLagID: 3, OriginalRole: 1}},
		{"role zero", &TreeImportReferenceV1{OriginalDatabaseID: [32]byte{1}, OriginalCurrentID: 3, OriginalLagID: 4}},
		{"role three", &TreeImportReferenceV1{OriginalDatabaseID: [32]byte{1}, OriginalCurrentID: 3, OriginalLagID: 4, OriginalRole: 3}},
	} {
		t.Run(row.name, func(t *testing.T) { treeNativeTypedStaticNoIO(t, row.reference) })
	}
}

func treeNativeTypedStaticNoIO(t *testing.T, reference *TreeImportReferenceV1) {
	t.Helper()
	store, _, _ := treeNativeStore(t)
	evidence, err := FixtureSelectedDamage(store, bootstrapOwner(t), SelectedDamageProbeOnly, 0, nil, func() {
		mustEnvironment(t, store.View(func(reader *Reader) error {
			if reference == nil {
				got, present, err := reader.ReadTreeRootBindingV1(0)
				if got != (RootBindingV1{}) || present {
					t.Fatal("static root refusal leaked result")
				}
				treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "invalid tree generation", nil)
			} else {
				got, err := reader.ReadTreeEvidenceV1(*reference)
				if !reflect.DeepEqual(got, TreeEvidenceV1{}) {
					t.Fatal("static evidence refusal leaked result")
				}
				treeNativeError(t, err, operationGet, EngineClass("InvalidInput"), 22, "invalid tree evidence reference", nil)
			}
			if reader.failure != nil || !reader.usable() {
				t.Fatal("static typed refusal recorded failure/disarmed Reader")
			}
			got, present, err := reader.ReadTreeRootBindingV1(1)
			if got != (RootBindingV1{}) || present || err != nil || reader.failure != nil || !reader.usable() {
				t.Fatal("static typed refusal prevented next legal root read")
			}
			return nil
		}))
	})
	mustEnvironment(t, err)
	// The legal absent generation1 root accounts for the only meta Get.
	// Normal View cleanup probes the unreserved owner twice around abort.
	want := SelectedDamageEvidence{BeginOld: 1, OldGets: [8]uint64{1}, OldAborts: 1, Probes: 2, ProbeRan: 2}
	if evidence != want {
		t.Fatalf("static typed refusal added native work: %+v, want %+v", evidence, want)
	}
	mustEnvironment(t, store.View(func(*Reader) error { return nil }))
	_, err = store.Inspect()
	mustEnvironment(t, err)
}

func TestTreeNativeRootDoesNotResolveEvidence(t *testing.T) {
	store, _, identity := treeNativeStore(t)
	root := treeRootFixture(t, true)
	root.DatabaseID = identity
	reference := *treeImportFixture()
	root.Assurance = TreeAssuranceV1{Kind: 2, Import: &reference}
	encoded, err := root.Encode()
	mustEnvironment(t, err)
	treeNativeSeed(t, store, 0, []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 1}, encoded)
	err = store.View(func(reader *Reader) error {
		got, present, err := reader.ReadTreeRootBindingV1(1)
		if err != nil || !present || !reflect.DeepEqual(got, root) || !reader.usable() {
			t.Fatal("tree root eagerly resolved absent evidence")
		}
		evidence, err := reader.ReadTreeEvidenceV1(reference)
		if !reflect.DeepEqual(evidence, TreeEvidenceV1{}) {
			t.Fatal("missing original evidence returned payload")
		}
		return err
	})
	treeNativeIntegrity(t, err, operationGet, nil)
}

func TestTreeNativePointerAndLengthProjection(t *testing.T) {
	for _, mode := range []uint32{17, 18} {
		store, _, identity := treeNativeStore(t)
		root := treeRootFixture(t, false)
		root.DatabaseID = identity
		encoded, err := root.Encode()
		mustEnvironment(t, err)
		key := []byte{0x11, 0, 0, 0, 0, 0, 0, 0, 1}
		treeNativeSeed(t, store, 0, key, encoded)
		var recorded, returned error
		evidence, err := fixtureLargeFault(store, mode, 0, key, func() {
			returned = store.View(func(reader *Reader) error {
				got, present, err := reader.ReadTreeRootBindingV1(1)
				if got != (RootBindingV1{}) || present || reader.failure != err || reader.usable() {
					t.Fatal("tree pointer/length projection partial state")
				}
				recorded = err
				return nil
			})
		})
		mustEnvironment(t, err)
		if mode == 17 {
			treeNativeError(t, recorded, operationGet, EngineClass("LocalInvariant"), -30779, "mdbx_get returned invalid result shape", nil)
		} else {
			treeNativeIntegrity(t, recorded, operationGet, errSchema)
		}
		if evidence.gets != 1 || returned != recorded || store.terminal != recorded || store.state != storeCLOSED {
			t.Fatal("tree pointer/length source/resource effects")
		}
		treeNativeZeroResources(t, store)
		if next := store.View(func(*Reader) error { t.Fatal("terminal callback"); return nil }); next != recorded {
			t.Fatal("tree pointer/length next operation")
		}
	}
}

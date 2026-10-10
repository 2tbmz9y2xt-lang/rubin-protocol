//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

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
	for _, abort := range []uint32{0, 9} {
		t.Run(fmt.Sprintf("H03 consumed close EIO abort%d", abort), func(t *testing.T) {
			s := startupOpened(t)
			var read, raw error
			_, err := fixtureTipCursor(s, 1, 1, 1, 5, func() {
				mustEnvironment(t, fixtureTipCloseFault())
				run := func() {
					_, armErr := FixtureSelectedDamage(s, bootstrapOwner(t), SelectedDamageGetEIO, 0, []byte{0}, func() {
						raw = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
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
			if s.canonicalOwnerVerified || s.state != storeCLOSED || s.env != nil || s.writer != nil || s.txn != nil || s.terminal != raw {
				t.Fatal("consumed close native resources")
			}
			if s.View(func(*Reader) error { t.Fatal("consumed close callback"); return nil }) != raw {
				t.Fatal("consumed close cached identity")
			}
		})
	}
	for _, completion := range []StartupCanonicalCompletionV1{0, 2, 255} {
		for _, application := range []string{"nil", "same", "different", "typed nil"} {
			for _, mode := range []uint32{0, 9, 10} {
				t.Run(fmt.Sprintf("H03 completion%d app%s abort%d", completion, application, mode), func(t *testing.T) {
					s := startupOpened(t)
					var reader *Reader
					var app, read, raw error
					if application == "different" {
						app = errors.New("distinct application")
					}
					if application == "typed nil" {
						var typed *nilPointerError
						app = typed
					}
					run := func() {
						_, err := FixtureSelectedDamage(s, bootstrapOwner(t), SelectedDamageGetEIO, 0, []byte{0}, func() {
							raw = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
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
					if reader == nil || read == nil || reader.failure != read || reader.usable() || s.canonicalOwnerVerified || s.terminal != raw {
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
					if application == "different" {
						appErr = errors.New("application")
					}
					if application == "typed nil" {
						var typed *nilPointerError
						appErr = typed
					}
					liMode := mode
					run := func() {
						raw = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
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
					}
					if recorded && mode != 24 {
						armedRead := func() {
							_, err := FixtureSelectedDamage(s, bootstrapOwner(t), SelectedDamageGetEIO, 0, key, run)
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
					if reader.usable() || s.canonicalOwnerVerified && (recorded || appErr != nil || mode != 0) {
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
		evidence, err := fixtureTipCursor(s, 13, 1, 2, 0, func() {
			raw = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
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
		if old.usable() || old.ownerVerified || old.tip != nil {
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
		var large fixtureLargeEvidence
		early := false
		evidence, err := fixtureTipCursor(s, 13, 1, 2, 0, func() {
			large, largeErr = fixtureLargeFault(s, 10, 0, []byte{0}, func() {
				go func() {
					raw = s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
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
		if e.Cause != nil || !e.ReopenRequired || s.terminal != raw || s.canonicalOwnerVerified {
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
								return s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
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
			err := s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
				row, found, failure := r.StartupCanonicalNextV1(readDBIsLiteral()[2], 1, nil)
				e, native := failure.(*EngineError)
				if !native || e.Class != EngineIntegrity || e.Operation != "prefix-page" || e.Code != -30796 || e.Diagnostic != "stored key outside SchemaV2 prefix-page domain" || e.Cause != nil || found || !reflect.DeepEqual(row, PrefixRow{}) || r.failure != failure || r.usable() {
					t.Fatal("forward key width result/record/disarm")
				}
				recorded = failure
				return 1, nil
			})
			if err != recorded || s.canonicalOwnerVerified || s.state != storeCLOSED {
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
				err := s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
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

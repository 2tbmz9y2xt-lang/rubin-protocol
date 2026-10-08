//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"testing"
)

func obsoleteRawImage(t *testing.T, store *Store, rank uint8, key, want []byte) {
	t.Helper()
	equal, err := FixtureRawRowEqual(store, rank, key, want)
	if err != nil || !equal {
		t.Fatalf("raw committed image rank%d/%x differs from %x: %v", rank, key, want, err)
	}
}

func obsoleteSeed(t *testing.T, store *Store, rank uint8, key, value []byte) {
	t.Helper()
	mustEnvironment(t, fixtureSeedPrefixRawRow(store, readDBIsLiteral()[rank], key, value))
}

func obsoleteProjectionSeed(t *testing.T, store *Store, g, height uint64) ([]byte, []byte, [32]byte, []byte) {
	t.Helper()
	header := make([]byte, 116)
	header[0], header[115] = 3, 7
	hash := sha3.Sum256(header)
	key := binary.BigEndian.AppendUint64(obsoleteGenerationLiteral(g), height)
	entry := append(append(bytes.Clone(hash[:]), make([]byte, 32)...), make([]byte, 40)...)
	entry[103] = 1
	obsoleteSeed(t, store, 2, key, entry)
	obsoleteSeed(t, store, 3, hash[:], header)
	return key, entry, hash, header
}

func obsoleteIndexPage(t *testing.T, reader *Reader, g uint64) ObsoletePageV1 {
	t.Helper()
	page, err := reader.ObsoleteGenerationPageV1(g, 2, nil, 1440)
	mustEnvironment(t, err)
	if len(page.Rows) != 1 {
		t.Fatalf("expected single seeded index: %d", len(page.Rows))
	}
	return page
}

func obsoleteCollectUndo(t *testing.T, reader *Reader, index ObsoleteRowV1) Batch {
	t.Helper()
	batch := Batch{}
	var next []byte
	for {
		page, err := reader.ObsoleteUndoPageV1(index, next, 1440)
		mustEnvironment(t, err)
		if uint8(page.Projection) != 3 || page.Witness == (ObsoletePageWitnessV1{}) {
			t.Fatal("own projection lost during sequential pages")
		}
		batch.ObsoleteDeletes = append(batch.ObsoleteDeletes, page.Rows...)
		batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, page.Witness)
		if uint8(page.Stop) == 1 {
			return batch
		}
		next = page.Next
	}
}

func TestObsoleteGenerationV1Physical(t *testing.T) {
	for _, class := range []ObsoleteClassV1{1, 2, 3, 4} {
		for _, g := range []uint64{5, math.MaxUint64} {
			t.Run(fmt.Sprintf("class%d/g%d", class, g), func(t *testing.T) {
				store, _, _ := consultedStore(t)
				rank := map[ObsoleteClassV1]uint8{1: 1, 2: 2, 3: 0, 4: 7}[class]
				prefix := obsoleteGenerationLiteral(g)
				keys := [][]byte{bytes.Clone(prefix), append(bytes.Clone(prefix), 0), append(bytes.Clone(prefix), 0xff, 0xff)}
				foreign := [][]byte{bytes.Clone(prefix[:7]), make([]byte, 8), obsoleteGenerationLiteral(6)}
				if class == 3 {
					keys = [][]byte{append([]byte{0x10}, prefix...)}
					foreign = [][]byte{append(bytes.Clone(keys[0]), 0), append([]byte{0x11}, prefix...), append([]byte{0x10}, make([]byte, 8)...), {0x10, 1}}
				}
				for i, key := range keys {
					value := bytes.Repeat([]byte{byte(0x31 + i)}, i)
					obsoleteSeed(t, store, rank, key, value)
				}
				for _, key := range foreign {
					obsoleteSeed(t, store, rank, key, []byte{0x66})
				}
				truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
					page, err := reader.ObsoleteGenerationPageV1(g, class, nil, 1440)
					mustEnvironment(t, err)
					obsoleteRequirePage(t, page, 1, 1, keys...)
					for i, row := range page.Rows {
						buffer := make([]byte, 2)
						n, err := row.ReadAt(buffer, 0)
						wantErr := error(io.EOF)
						if i == 2 {
							wantErr = nil
						}
						if row.Length() != uint64(i) || n != i || err != wantErr || !bytes.Equal(buffer[:n], bytes.Repeat([]byte{byte(0x31 + i)}, i)) {
							t.Fatal("physical malformed value", i, n, err)
						}
					}
					return obsoleteBatch(page), nil
				})
				if truth.String() != "NEW" || int(stage) != 3 || err != nil || string(store.state) != "OPEN" {
					t.Fatal("physical raw-only commit", truth, stage, err, store.state)
				}
				for _, key := range keys {
					obsoleteRawImage(t, store, rank, key, nil)
				}
				for _, key := range foreign {
					obsoleteRawImage(t, store, rank, key, []byte{0x66})
				}
			})
		}
	}
}

func TestObsoleteGenerationV1PageBounds(t *testing.T) {
	store, _, _ := consultedStore(t)
	prefix := obsoleteGenerationLiteral(math.MaxUint64)
	keys := make([][]byte, 33)
	for i := range keys {
		keys[i] = append(bytes.Clone(prefix), bytes.Repeat([]byte{0xff}, 2014)...)
		keys[i][8] = byte(i)
		obsoleteSeed(t, store, 1, keys[i], []byte{byte(i)})
	}
	mustEnvironment(t, store.View(func(reader *Reader) error {
		for _, count := range []uint32{1, 7, 32, 1440} {
			page, err := reader.ObsoleteGenerationPageV1(math.MaxUint64, 1, nil, count)
			mustEnvironment(t, err)
			rows, stop := int(count), uint8(2)
			if count == 1440 {
				rows, stop = 32, 3
			}
			obsoleteRequirePage(t, page, stop, 1, keys[:rows]...)
			page.Next[8] ^= 0xff
			copyKey := page.Rows[rows-1].Key()
			copyKey[8] ^= 0x7f
			if !bytes.Equal(page.Rows[rows-1].Key(), keys[rows-1]) {
				t.Fatal("Next/Key alias corrupted private proof")
			}
			last, err := reader.ObsoleteGenerationPageV1(math.MaxUint64, 1, keys[31], 1)
			mustEnvironment(t, err)
			obsoleteRequirePage(t, last, 1, 1, keys[32])
			// The earlier page row remains readable after the next page.
			buffer := make([]byte, 1)
			if n, err := page.Rows[0].ReadAt(buffer, 0); n != 1 || err != nil || buffer[0] != 0 {
				t.Fatal("sequential page row lifetime")
			}
		}
		allFF := bytes.Repeat([]byte{0xff}, 2022)
		page, err := reader.ObsoleteGenerationPageV1(math.MaxUint64, 1, allFF, 1440)
		mustEnvironment(t, err)
		obsoleteRequirePage(t, page, 1, 1)
		page, err = reader.ObsoleteGenerationPageV1(math.MaxUint64, 1, append(allFF, 0), 1)
		obsoleteRequireZero(t, page)
		obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation page bounds")
		return nil
	}))
	// The complete all-ff K-byte row proves bounded successor exhaustion without wrap.
	maximum := bytes.Repeat([]byte{0xff}, 2022)
	obsoleteSeed(t, store, 7, maximum, []byte{0x5a})
	mustEnvironment(t, store.View(func(reader *Reader) error {
		page, err := reader.ObsoleteGenerationPageV1(math.MaxUint64, 4, nil, 1)
		mustEnvironment(t, err)
		obsoleteRequirePage(t, page, 1, 1, maximum)
		return nil
	}))
}

func TestObsoleteGenerationV1Projection(t *testing.T) {
	for _, variant := range []string{"valid", "height-max", "work-max", "key15", "key17", "height-over", "value103", "value105", "work-zero", "work-over", "work-high", "header-absent", "header-empty", "header115", "header117", "header-hash", "header-parent"} {
		t.Run(variant, func(t *testing.T) {
			store, _, _ := consultedStore(t)
			key, entry, hash, header := obsoleteProjectionSeed(t, store, 9, 1)
			originalKey := bytes.Clone(key)
			switch variant {
			case "height-max":
				binary.BigEndian.PutUint64(key[8:], 0xffffffff)
			case "key15":
				key = key[:15]
			case "key17":
				key = append(key, 1)
			case "height-over":
				binary.BigEndian.PutUint64(key[8:], 0x100000000)
			case "value103":
				entry = entry[:103]
			case "value105":
				entry = append(entry, 1)
			case "work-zero":
				entry[103] = 0
			case "work-max":
				entry[67], entry[103] = 1, 0
			case "work-over":
				entry[67] = 1
			case "work-high":
				entry[66] = 1
			case "header-absent":
				mustEnvironment(t, fixtureDeletePrefixRow(store, readDBIsLiteral()[3], hash[:]))
			case "header-empty":
				header = []byte{}
			case "header115":
				header = header[:115]
			case "header117":
				header = append(header, 1)
			case "header-hash":
				header[0] ^= 1
			case "header-parent":
				entry[32] = 1
			}
			if !bytes.Equal(key, originalKey) {
				mustEnvironment(t, fixtureDeletePrefixRow(store, readDBIsLiteral()[2], originalKey))
			}
			obsoleteSeed(t, store, 2, key, entry)
			if variant != "header-absent" {
				obsoleteSeed(t, store, 3, hash[:], header)
			}
			undo := [][]byte{bytes.Clone(hash[:]), append(bytes.Clone(hash[:]), 0), append(bytes.Clone(hash[:]), 2, 0xff)}
			for i, k := range undo {
				obsoleteSeed(t, store, 5, k, []byte{byte(i)})
			}
			proven := variant == "valid" || variant == "height-max" || variant == "work-max"
			if !proven {
				obsoleteInvalidProjectionTrace(t, store, variant, hash)
			}
			truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
				index := obsoleteIndexPage(t, reader, 9)
				before := fixtureLargeNativeCalls()
				page, err := reader.ObsoleteUndoPageV1(index.Rows[0], nil, 1)
				mustEnvironment(t, err)
				if proven {
					obsoleteRequirePage(t, page, 2, 3, undo[0])
					continued, err := reader.ObsoleteUndoPageV1(index.Rows[0], undo[0], 7)
					mustEnvironment(t, err)
					obsoleteRequirePage(t, continued, 1, 3, undo[1:]...)
					batch := obsoleteBatch(page)
					batch.ObsoleteDeletes = append(batch.ObsoleteDeletes, continued.Rows...)
					batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, continued.Witness)
					return batch, nil
				}
				obsoleteRequirePage(t, page, 1, 2)
				if before != 0 {
					t.Fatal("unarmed native counter unexpectedly active")
				}
				refused, err := reader.ObsoleteUndoPageV1(index.Rows[0], undo[0], 7)
				obsoleteRequireZero(t, refused)
				obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation page bounds")
				if !reader.usable() || reader.failure != nil {
					t.Fatal("invalid own projection disarmed Reader")
				}
				return Batch{ObsoleteDeletes: index.Rows, ObsoleteConsulted: []ObsoletePageWitnessV1{index.Witness, page.Witness}}, nil
			})
			if truth.String() != "NEW" || int(stage) != 3 || err != nil {
				t.Fatal("projection public Update", truth, stage, err)
			}
			if proven {
				obsoleteRawImage(t, store, 2, key, entry)
				for _, k := range undo {
					obsoleteRawImage(t, store, 5, k, nil)
				}
			} else {
				obsoleteRawImage(t, store, 2, key, nil)
				for i, k := range undo {
					obsoleteRawImage(t, store, 5, k, []byte{byte(i)})
				}
			}
		})
	}
}

func obsoleteInvalidProjectionTrace(t *testing.T, store *Store, variant string, hash [32]byte) {
	t.Helper()
	evidence, err := fixtureLargeFault(store, 20, 5, hash[:], func() {
		mustEnvironment(t, store.View(func(reader *Reader) error {
			index := obsoleteIndexPage(t, reader, 9)
			before := fixtureLargeNativeCalls()
			page, err := reader.ObsoleteUndoPageV1(index.Rows[0], append(bytes.Clone(hash[:]), 1), 7)
			obsoleteRequireZero(t, page)
			obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation page bounds")
			proofReads := uint32(1)
			if len(variant) >= 6 && variant[:6] == "header" {
				proofReads = 2
			}
			if fixtureLargeNativeCalls()-before != proofReads || reader.failure != nil || !reader.usable() {
				t.Fatalf("fixed proof before invalid continuation: reads%d want%d", fixtureLargeNativeCalls()-before, proofReads)
			}
			for _, query := range []struct {
				after []byte
				count uint32
			}{{nil, 0}, {nil, 1441}, {[]byte{}, 1}, {make([]byte, 31), 1}, {make([]byte, 2023), 1}} {
				before = fixtureLargeNativeCalls()
				page, err = reader.ObsoleteUndoPageV1(index.Rows[0], query.after, query.count)
				obsoleteRequireZero(t, page)
				obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation page bounds")
				if fixtureLargeNativeCalls() != before {
					t.Fatal("cheap bounds performed proof reads")
				}
			}
			page, err = reader.ObsoleteUndoPageV1(index.Rows[0], nil, 1)
			mustEnvironment(t, err)
			obsoleteRequirePage(t, page, 1, 2)
			return nil
		}))
	})
	mustEnvironment(t, err)
	if evidence.gets != 0 || evidence.commits != 0 || evidence.aborts != 1 || string(store.state) != "OPEN" {
		t.Fatal("invalid projection traversed undo or consumed owner", evidence, store.state)
	}
}

func TestObsoleteGenerationV1ProofOrder(t *testing.T) {
	for _, variant := range []string{"backend", "wrong-header", "proven-foreign", "proven-valid"} {
		t.Run(variant, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			key, entry, hash, header := obsoleteProjectionSeed(t, store, 9, 1)
			undoKey := append(bytes.Clone(hash[:]), 2)
			obsoleteSeed(t, store, 5, undoKey, []byte{0x51})
			if variant == "wrong-header" {
				header[0] ^= 1
				obsoleteSeed(t, store, 3, hash[:], header)
			}
			mode := uint32(20)
			rank, faultKey := uint8(5), undoKey
			if variant == "backend" {
				mode, rank, faultKey = 28, 3, hash[:]
			}
			// Shape interception applies only to dependent undo. Valid traversal uses no fault.
			if variant == "proven-valid" {
				mode, rank, faultKey = 28, 6, []byte{0xaa}
			}
			var page ObsoletePageV1
			var result, recorded error
			var truth CommitTruth
			var stage UpdateStage
			evidence, fixtureErr := fixtureLargeFault(store, mode, rank, faultKey, func() {
				truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
					index := obsoleteIndexPage(t, reader, 9)
					before := fixtureLargeNativeCalls()
					after := bytes.Clone(hash[:])
					if variant != "backend" && variant != "proven-valid" {
						after[0] ^= 1
					}
					var err error
					page, err = reader.ObsoleteUndoPageV1(index.Rows[0], after, 7)
					recorded = reader.failure
					if variant == "backend" {
						obsoleteRequireZero(t, page)
						if err != recorded || reader.usable() {
							t.Fatal("first proof backend error was masked")
						}
						obsoleteRequireError(t, err, "get", "IO", 5, expectedNativeDiagnostic(5))
					} else if variant == "proven-valid" {
						mustEnvironment(t, err)
						obsoleteRequirePage(t, page, 1, 3, undoKey)
					} else {
						obsoleteRequireZero(t, page)
						obsoleteRequireError(t, err, "prefix-page", "InvalidInput", 22, "invalid obsolete generation page bounds")
						if fixtureLargeNativeCalls()-before != 2 || reader.failure != nil || !reader.usable() {
							t.Fatal("post-proof refusal ordering")
						}
					}
					return Batch{}, err
				})
				if variant == "backend" {
					largeNativeCached(t, store)
				}
			})
			mustEnvironment(t, fixtureErr)
			if truth.String() != "OLD" || int(stage) != 1 || evidence.commits != 0 {
				t.Fatal("proof refusal wrote", truth, stage, evidence)
			}
			if variant == "backend" {
				if result != recorded || evidence.gets != 1 || evidence.aborts != 1 || string(store.state) != "CLOSED" {
					t.Fatal("proof fault disposition", result, evidence, store.state)
				}
				store, result = Open(path, cfg)
				consultedTrack(t, store, result)
			} else {
				if string(store.state) != "OPEN" {
					t.Fatal("proof input refusal consumed store")
				}
				if variant == "proven-valid" {
					obsoleteRequireError(t, result, "update", "InvalidInput", 22, "invalid Update Batch")
				}
			}
			obsoleteRawImage(t, store, 2, key, entry)
			obsoleteRawImage(t, store, 3, hash[:], header)
			obsoleteRawImage(t, store, 5, undoKey, []byte{0x51})
		})
	}
}

func TestObsoleteGenerationV1CanonicalPair(t *testing.T) {
	for _, variant := range []string{"lone-forward", "lone-derived", "paired", "forward-key15", "forward-key17", "derived-key39", "derived-key41", "forward-width103", "forward-width105", "derived-width7", "derived-width9", "absent-owner", "different-height", "different-hash", "partner-error"} {
		t.Run(variant, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			forward := canonicalForwardKeyLiteral(9, 1)
			hash := [32]byte{0x41}
			derived := canonicalOwnerKeyLiteral(9, hash)
			entry := canonicalForwardValueLiteral(hash, [40]byte{}) // zero work must not waive O1/O2.
			height := binary.BigEndian.AppendUint64(nil, 1)
			deleteClass := ObsoleteClassV1(2)
			deleteRank, deleteKey := uint8(2), forward
			switch variant {
			case "lone-derived":
				deleteClass, deleteRank, deleteKey = 4, 7, derived
			case "forward-key15":
				forward = forward[:15]
				deleteKey = forward
			case "forward-key17":
				forward = append(forward, 1)
				deleteKey = forward
			case "derived-key39":
				derived = derived[:39]
				deleteClass, deleteRank, deleteKey = 4, 7, derived
			case "derived-key41":
				derived = append(derived, 1)
				deleteClass, deleteRank, deleteKey = 4, 7, derived
			case "forward-width103":
				entry = entry[:103]
			case "forward-width105":
				entry = append(entry, 1)
			case "derived-width7":
				height = height[:7]
			case "derived-width9":
				height = append(height, 1)
			case "different-height":
				height[7] = 2
			case "different-hash":
				entry[0] = 0x42
			}
			obsoleteSeed(t, store, 2, forward, entry)
			if variant != "absent-owner" {
				obsoleteSeed(t, store, 7, derived, height)
			}
			var truth CommitTruth
			var stage UpdateStage
			var result error
			mode := uint32(28)
			faultRank, faultKey := uint8(7), derived
			if variant != "partner-error" {
				faultRank, faultKey = 6, []byte{0xaa}
			}
			run := func() {
				truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
					page, err := reader.ObsoleteGenerationPageV1(9, deleteClass, nil, 1)
					mustEnvironment(t, err)
					batch := obsoleteBatch(page)
					if variant == "paired" {
						owner, err := reader.ObsoleteGenerationPageV1(9, 4, nil, 1)
						mustEnvironment(t, err)
						batch.ObsoleteDeletes = append(batch.ObsoleteDeletes, owner.Rows...)
						batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, owner.Witness)
					}
					return batch, nil
				})
				if string(store.state) != "OPEN" {
					largeNativeCached(t, store)
				}
			}
			// Count paired-target reads without faulting the required O1/O2 own-target reads.
			evidence := fixtureLargeEvidence{}
			pairedEvidence := SelectedDamageEvidence{}
			if variant == "paired" {
				owner, err := NewOperationReservationOwner(MaxOperationDataBytes)
				mustEnvironment(t, err)
				pairedEvidence, err = FixtureSelectedDamage(store, owner, SelectedDamageProbeOnly, 0, nil, run)
				mustEnvironment(t, err)
			} else if variant == "lone-forward" || variant == "lone-derived" || variant == "partner-error" {
				var fixtureErr error
				evidence, fixtureErr = fixtureLargeFault(store, mode, faultRank, faultKey, run)
				mustEnvironment(t, fixtureErr)
			} else {
				run()
			}
			refused := variant == "lone-forward" || variant == "lone-derived" || variant == "partner-error"
			if refused {
				if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "CLOSED" || evidence.commits != 0 || store.env != nil || store.writer != nil || store.txn != nil {
					t.Fatal("canonical refusal resource/result", truth, stage, result, evidence, store.state)
				}
				if variant == "partner-error" {
					obsoleteRequireError(t, result, "update", "IO", 5, expectedNativeDiagnostic(5))
				} else {
					obsoleteRequireError(t, result, "update", "InvalidInput", 22, "unpaired canonical owner mutation")
				}
				store, result = Open(path, cfg)
				consultedTrack(t, store, result)
				obsoleteRawImage(t, store, 2, forward, entry)
				obsoleteRawImage(t, store, 7, derived, height)
				return
			}
			if truth.String() != "NEW" || int(stage) != 3 || result != nil || string(store.state) != "OPEN" {
				t.Fatal("canonical shape/exemption commit", truth, stage, result, evidence, store.state)
			}
			if variant == "paired" && (pairedEvidence.OldGets != ([8]uint64{0, 0, 3, 0, 0, 0, 0, 3}) || pairedEvidence.Commits != 1) {
				t.Fatal("paired target read/commit census or extra partner lookup", pairedEvidence)
			}
			obsoleteRawImage(t, store, deleteRank, deleteKey, nil)
			if variant == "paired" {
				obsoleteRawImage(t, store, 7, derived, nil)
			}
		})
	}
}

func TestObsoleteGenerationV1Callbacks(t *testing.T) {
	for _, fault := range []uint32{1, 2, 24} {
		for _, variant := range []string{"nil", "ignored", "exact", "wrapped", "distinct", "typed-nil", "cause-bearing", "panic"} {
			t.Run(fmt.Sprintf("fault%d/%s", fault, variant), func(t *testing.T) {
				store, path, cfg := consultedStore(t)
				seed := consultedCounter(t, 9)
				largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
				var recorded, application, result error
				originalCause := errors.New("retained application cause")
				var saved ObsoleteRowV1
				var recovered any
				var truth CommitTruth
				var stage UpdateStage
				payload := &struct{ text string }{"obsolete native panic"}
				var evidence fixtureLargeEvidence
				func() {
					defer func() { recovered = recover() }()
					var fixtureErr error
					evidence, fixtureErr = fixtureLargeFault(store, fault, 0, seed.Key, func() {
						truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
							page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
							mustEnvironment(t, err)
							saved = page.Rows[0]
							before := fixtureLargeNativeCalls()
							for _, query := range []struct {
								size   int
								offset uint64
								eof    bool
							}{{0, math.MaxUint64, false}, {1, 16, true}, {1, math.MaxUint64, true}} {
								n, err := saved.ReadAt(make([]byte, query.size), query.offset)
								wantErr := error(nil)
								if query.eof {
									wantErr = io.EOF
								}
								if n != 0 || err != wantErr {
									t.Fatal("input/EOF before native failure", n, err)
								}
							}
							n, err := saved.ReadAt(make([]byte, 65_537), 0)
							if n != 0 {
								t.Fatal("invalid window copied")
							}
							obsoleteRequireError(t, err, "get", "InvalidInput", 22, "ReadAt buffer exceeds 65536 bytes")
							if fixtureLargeNativeCalls() != before || !reader.usable() || reader.failure != nil {
								t.Fatal("cheap read called native")
							}
							n, recorded = saved.ReadAt(make([]byte, 1), 0)
							if n != 0 || reader.failure != recorded || reader.usable() {
								t.Fatal("native read failure not recorded")
							}
							obsoleteRequireError(t, recorded, "get", "IO", 5, expectedNativeDiagnostic(5))
							switch variant {
							case "exact":
								application = recorded
							case "wrapped":
								application = fmt.Errorf("obsolete wrapper: %w", recorded)
							case "distinct":
								application = errors.New("obsolete distinct application")
							case "typed-nil":
								application = (*largeTypedNil)(nil)
							case "cause-bearing":
								application = &EngineError{Operation: "get", Class: EngineIO, Code: 5, Diagnostic: "existing application", Cause: originalCause}
							case "panic":
								panic(payload)
							}
							if variant == "ignored" {
								return obsoleteBatch(page), nil
							}
							return Batch{}, application
						})
						largeNativeCached(t, store)
					})
					mustEnvironment(t, fixtureErr)
				}()
				if variant == "panic" {
					if recovered != payload || result != nil {
						t.Fatal("native panic payload", recovered, result)
					}
					largeCallbackCauses(t, store.terminal, nil, recorded, fault)
				} else {
					if truth.String() != "OLD" || int(stage) != 1 || evidence.gets != 2 || evidence.aborts != 1 || evidence.commits != 0 {
						t.Fatal("native callback stage", truth, stage, evidence)
					}
					largeCallbackCauses(t, result, application, recorded, fault)
				}
				if variant == "cause-bearing" && application.(*EngineError).Cause != originalCause {
					t.Fatal("original application Cause changed with infrastructure", fault)
				}
				wantState := map[uint32]string{1: "CLOSED", 2: "POISONED_THREAD", 24: "CLOSE_BLOCKED"}[fault]
				if string(store.state) != wantState || !validStoreShape(store) {
					t.Fatal("actual native resource state", store.state)
				}
				if fault == 1 && (store.env != nil || store.writer != nil || store.txn != nil) {
					t.Fatal("consumed native resources retained")
				}
				if fault == 2 && (store.env == nil || store.writer == nil || store.txn == nil || store.config != (ConfigV1{}) || store.dbis != (Store{}).dbis) {
					t.Fatal("retained native transaction lost")
				}
				if fault == 24 && (store.env == nil || store.writer == nil || store.txn != nil || store.config == (ConfigV1{}) || store.dbis == (Store{}).dbis) {
					t.Fatal("retained environment shape")
				}
				largeNativeCached(t, store)
				_, expired := saved.ReadAt(make([]byte, 65_537), math.MaxUint64)
				obsoleteRequireError(t, expired, "get", "InvalidInput", 22, "Reader is not active")
				mustEnvironment(t, fixtureLargeRelease(store))
				reopened, err := Open(path, cfg)
				consultedTrack(t, reopened, err)
				obsoleteRawImage(t, reopened, 0, seed.Key, seed.Literal)
			})
		}
	}
}

func TestObsoleteGenerationV1NativeShapes(t *testing.T) {
	for _, mode := range []uint32{20, 21, 22, 25, 27} {
		store, _, _ := consultedStore(t)
		key := append(obsoleteGenerationLiteral(9), bytes.Repeat([]byte{0x44}, 2014)...)
		obsoleteSeed(t, store, 1, key, []byte{1})
		var result error
		evidence, err := fixtureLargeFault(store, mode, 1, key, func() {
			result = store.View(func(reader *Reader) error {
				page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, 1)
				obsoleteRequireZero(t, page)
				if reader.usable() || reader.failure != err {
					t.Fatal("native page shape not recorded")
				}
				return err
			})
			largeNativeCached(t, store)
		})
		mustEnvironment(t, err)
		obsoleteRequireError(t, result, "prefix-page", "LocalInvariant", -30779, "invalid native obsolete generation result")
		if evidence.gets != 1 || evidence.aborts != 1 || string(store.state) != "CLOSED" {
			t.Fatal("native page shape lifecycle", evidence, store.state)
		}
	}
	for _, mode := range []uint32{17, 18} {
		store, _, _ := consultedStore(t)
		key := append(obsoleteGenerationLiteral(9), 1)
		obsoleteSeed(t, store, 1, key, []byte{1})
		var result error
		evidence, err := fixtureLargeFault(store, mode, 1, key, func() {
			result = store.View(func(reader *Reader) error {
				page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, 1)
				mustEnvironment(t, err)
				n, err := page.Rows[0].ReadAt(make([]byte, 1), 0)
				if n != 0 || reader.failure != err || reader.usable() {
					t.Fatal("native ReadAt shape lifecycle")
				}
				return err
			})
		})
		mustEnvironment(t, err)
		obsoleteRequireError(t, result, "get", "LocalInvariant", -30779, "invalid native obsolete generation result")
		if evidence.gets != 1 || evidence.aborts != 1 || string(store.state) != "CLOSED" {
			t.Fatal("native ReadAt shape disposition", evidence, store.state)
		}
	}
}

func TestObsoleteGenerationV1Scale(t *testing.T) {
	for _, kind := range []uint32{2, 3, 6} {
		t.Run(fmt.Sprintf("actual-key-width-kind%d", kind), func(t *testing.T) {
			path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
			cfg.Upper = 512 << 20
			store, err := Create(path, cfg)
			consultedTrack(t, store, err)
			_, _, hash, _ := obsoleteProjectionSeed(t, store, 9, 1)
			mustEnvironment(t, fixtureLargeBulk(store, kind, 414_634, 20, hash))
			manifestKey := append(bytes.Clone(hash[:]), 0)
			obsoleteSeed(t, store, 5, manifestKey, []byte{0x31})
			width := 77
			if kind == 3 {
				width = 333
			}
			if kind == 6 {
				width = 37
			}
			first := make([]byte, width)
			copy(first, hash[:])
			first[32] = 1
			last := bytes.Clone(first)
			binary.BigEndian.PutUint32(last[33:], 414_633)
			value := append([]byte{0x5a}, make([]byte, 19)...)
			truth, stage, result := store.Update(func(reader *Reader) (Batch, error) {
				index := obsoleteIndexPage(t, reader, 9)
				batch := obsoleteCollectUndo(t, reader, index.Rows[0])
				if len(batch.ObsoleteDeletes) != 414_635 {
					t.Fatal("legal complete family count", len(batch.ObsoleteDeletes))
				}
				for i, row := range batch.ObsoleteDeletes {
					want := width
					if i == 0 {
						want = 33
					}
					if len(row.Key()) != want {
						t.Fatalf("actual key width %d=%d want%d", i, len(row.Key()), want)
					}
				}
				return batch, nil
			})
			if kind == 3 {
				obsoleteRequireError(t, result, "update", "Capacity", -30417, "Update Batch exceeds bound")
				if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
					t.Fatal("333-key overcap stage", truth, stage, store.state)
				}
				obsoleteRawImage(t, store, 5, manifestKey, []byte{0x31})
				obsoleteRawImage(t, store, 5, first, value)
				obsoleteRawImage(t, store, 5, last, value)
				largeCommit(t, store, Batch{Mutations: []Mutation{consultedCounter(t, 11)}})
			} else {
				if truth.String() != "NEW" || int(stage) != 3 || result != nil {
					t.Fatal("legal 414634+manifest refused", truth, stage, result)
				}
				obsoleteRawImage(t, store, 5, manifestKey, nil)
				obsoleteRawImage(t, store, 5, first, nil)
				obsoleteRawImage(t, store, 5, last, nil)
			}
		})
	}
}

func TestObsoleteGenerationV1Images(t *testing.T) {
	for _, variant := range []string{"empty-extra", "lookahead", "missing", "changed", "third-target", "OLD", "NEW", "preflight", "final", "proof", "invalid-proof", "counter-passed"} {
		t.Run(variant, func(t *testing.T) {
			store, path, cfg := consultedStore(t)
			first := append(obsoleteGenerationLiteral(9), 1)
			second := append(obsoleteGenerationLiteral(9), 2)
			faultKey, rank, mode := second, uint8(1), uint32(5)
			if variant != "empty-extra" {
				obsoleteSeed(t, store, 1, first, []byte{0x41})
				obsoleteSeed(t, store, 1, second, []byte{0x51})
			}
			switch variant {
			case "empty-extra":
				mode = 3
			case "missing":
				mode = 4
			case "third-target":
				mode, faultKey = 6, first
			case "OLD":
				mode = 7
			case "NEW":
				mode = 12
			case "preflight":
				mode = 14
			case "final":
				mode = 13
			}
			var indexKey, entry, header []byte
			var hash [32]byte
			if variant == "proof" || variant == "invalid-proof" {
				indexKey, entry, hash, header = obsoleteProjectionSeed(t, store, 9, 1)
				if variant == "invalid-proof" {
					header = []byte{0x31}
					obsoleteSeed(t, store, 3, hash[:], header)
				}
				faultKey, rank = hash[:], 3
				obsoleteSeed(t, store, 5, append(bytes.Clone(hash[:]), 2), []byte{0x61})
			}
			if variant == "counter-passed" {
				counter := consultedCounter(t, 9)
				obsoleteSeed(t, store, 0, counter.Key, counter.Literal)
				faultKey, rank = counter.Key, 0
			}
			var truth CommitTruth
			var stage UpdateStage
			var result error
			evidence, fixtureErr := fixtureLargeFault(store, mode, rank, faultKey, func() {
				truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
					batch := Batch{Mutations: []Mutation{consultedCounter(t, 1)}}
					if variant == "proof" || variant == "invalid-proof" {
						index := obsoleteIndexPage(t, reader, 9)
						page, err := reader.ObsoleteUndoPageV1(index.Rows[0], nil, 1440)
						mustEnvironment(t, err)
						batch.ObsoleteConsulted = []ObsoletePageWitnessV1{page.Witness}
						batch.ObsoleteDeletes = page.Rows
						return batch, nil
					}
					if variant == "counter-passed" {
						page, err := reader.ObsoleteGenerationPageV1(9, 3, faultKey, 1)
						mustEnvironment(t, err)
						obsoleteRequirePage(t, page, 1, 1)
						batch.ObsoleteConsulted = []ObsoletePageWitnessV1{page.Witness}
						return batch, nil
					}
					count := uint32(1440)
					if variant == "lookahead" {
						count = 1
					}
					page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, count)
					mustEnvironment(t, err)
					batch.ObsoleteConsulted = []ObsoletePageWitnessV1{page.Witness}
					if variant != "empty-extra" {
						batch.ObsoleteDeletes = page.Rows[:1]
					}
					return batch, nil
				})
				largeNativeCached(t, store)
			})
			mustEnvironment(t, fixtureErr)
			want := "UNKNOWN"
			if variant == "OLD" || variant == "preflight" || variant == "final" {
				want = "OLD"
			}
			if variant == "NEW" {
				want = "NEW"
			}
			wantStage := 3
			if variant == "preflight" {
				wantStage = 1
			}
			if variant == "final" {
				wantStage = 2
			}
			if truth.String() != want || int(stage) != wantStage || string(store.state) != "CLOSED" || store.terminalTruth.String() != want {
				t.Fatal("scoped image truth", variant, truth, stage, result, evidence, store.state)
			}
			if variant == "preflight" || variant == "final" {
				diagnostic := "OLD/write snapshot mismatch"
				if variant == "final" {
					diagnostic = "final update image mismatch"
				}
				obsoleteRequireError(t, result, "update", "StateMismatch", -30779, diagnostic)
				if evidence.commits != 0 {
					t.Fatal("scoped precommit mismatch reached commit")
				}
			} else {
				commit, ok := result.(*CommitError)
				if !ok || commit.Truth.String() != want || commit.ReadbackCause != nil || evidence.commits != 1 {
					t.Fatal("scoped crossed CommitError", result, evidence)
				}
				obsoleteRequireError(t, commit.Cause, "update", "Capacity", 28, expectedNativeDiagnostic(28))
			}
			reopened, err := Open(path, cfg)
			consultedTrack(t, reopened, err)
			if variant == "OLD" || variant == "preflight" || variant == "final" {
				obsoleteRawImage(t, reopened, 1, first, []byte{0x41})
			} else if variant == "third-target" {
				obsoleteRawImage(t, reopened, 1, first, []byte{0x7f})
			} else if variant != "empty-extra" && variant != "proof" && variant != "invalid-proof" && variant != "counter-passed" {
				obsoleteRawImage(t, reopened, 1, first, nil)
			}
			if variant == "proof" || variant == "invalid-proof" {
				obsoleteRawImage(t, reopened, 2, indexKey, entry)
				obsoleteRawImage(t, reopened, 3, hash[:], []byte{0x7f})
			} else if variant != "OLD" && variant != "NEW" && variant != "final" && variant != "third-target" {
				wantBytes := []byte{0x7f}
				if variant == "missing" {
					wantBytes = nil
				}
				obsoleteRawImage(t, reopened, rank, faultKey, wantBytes)
			}
		})
	}
}

func TestObsoleteGenerationV1Cleanup(t *testing.T) {
	for _, mode := range []uint32{9, 10, 11, 15, 16, 19} {
		store, path, cfg := consultedStore(t)
		seed := consultedCounter(t, 9)
		largeCommit(t, store, Batch{Mutations: []Mutation{seed}})
		var truth CommitTruth
		var stage UpdateStage
		var result error
		_, fixtureErr := fixtureLargeFault(store, mode, 0, seed.Key, func() {
			truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
				page, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
				return obsoleteBatch(page), err
			})
			largeNativeCached(t, store)
		})
		mustEnvironment(t, fixtureErr)
		wantTruth, wantState := "NEW", "CLOSED"
		if mode == 19 {
			wantTruth = "OLD"
		}
		if mode == 10 || mode == 15 || mode == 19 {
			wantState = "POISONED_THREAD"
		}
		if mode == 11 {
			wantState = "CLOSE_BLOCKED"
		}
		var commit *CommitError
		if truth.String() != wantTruth || int(stage) != 3 || !errors.As(result, &commit) || commit.Truth.String() != wantTruth || string(store.state) != wantState || !validStoreShape(store) {
			t.Fatal("cleanup result/resource", mode, truth, stage, result, store.state)
		}
		if mode == 11 {
			closeErr := requireEnvironmentError(t, result, EngineClass("Concurrency"), operationClose, -30778, expectedNativeDiagnostic(-30778))
			if closeErr.Cause != commit || closeErr.ReopenRequired {
				t.Fatal("retained close lost original commit")
			}
		} else {
			class, code := "IO", 5
			if mode == 10 || mode == 15 || mode == 19 {
				class, code = "LocalInvariant", -30416
			}
			abortErr := requireEnvironmentError(t, commit.ReadbackCause, EngineClass(class), operationAbort, code, expectedNativeDiagnostic(code))
			if commit.ReadbackCause != abortErr || abortErr.Cause != nil || abortErr.ReopenRequired != (code == -30416) {
				t.Fatal("cleanup native Cause/Reopen", mode, abortErr)
			}
		}
		obsoleteRequireError(t, commit.Cause, "update", "Capacity", 28, expectedNativeDiagnostic(28))
		mustEnvironment(t, fixtureLargeRelease(store))
		reopened, err := Open(path, cfg)
		consultedTrack(t, reopened, err)
		want := []byte(nil)
		if mode == 19 {
			want = seed.Literal
		}
		obsoleteRawImage(t, reopened, 0, seed.Key, want)
	}
}

func TestObsoleteGenerationV1Roles(t *testing.T) {
	for _, role := range []string{"active", "replay-target", "selected"} {
		store, _, _ := consultedStore(t)
		authority, g := modelBase(1, 0, 0), uint64(1)
		if role == "replay-target" {
			authority, g = modelReplay(1), 2
		}
		if role == "selected" {
			authority.NextGenerationID, authority.SelectedSide, g = 3, modelSide(2, 0, 1, 1, 1), 2
		}
		encoded, err := authority.Encode()
		mustEnvironment(t, err)
		obsoleteSeed(t, store, 0, []byte{2}, encoded)
		key := append(obsoleteGenerationLiteral(g), 1)
		obsoleteSeed(t, store, 1, key, []byte{0x31})
		truth, stage, err := store.Update(func(reader *Reader) (Batch, error) {
			page, err := reader.ObsoleteGenerationPageV1(g, 1, nil, 1)
			obsoleteRequirePage(t, page, 1, 1, key)
			return obsoleteBatch(page), err
		})
		if truth.String() != "NEW" || int(stage) != 3 || err != nil {
			t.Fatal("native role enforcement added", role, truth, stage, err)
		}
		obsoleteRawImage(t, store, 0, []byte{2}, encoded)
		obsoleteRawImage(t, store, 1, key, nil)
	}
}

func TestObsoleteGenerationV1ConsultedOverlap(t *testing.T) {
	for _, variant := range []string{"point", "interval-match", "interval-changed", "interval-missing", "interval-extra", "interval-preflight", "interval-final"} {
		t.Run(variant, func(t *testing.T) {
			var pointCalls uint32
			for _, shared := range []bool{false, true} {
				if shared && variant != "point" {
					continue
				}
				store, path, cfg := consultedStore(t)
				counter := consultedCounter(t, 9)
				largeCommit(t, store, Batch{Mutations: []Mutation{counter}})
				target := append(obsoleteGenerationLiteral(9), 1)
				index := canonicalForwardKeyLiteral(9, 1)
				extra := canonicalForwardKeyLiteral(9, 2)
				obsoleteSeed(t, store, 1, target, []byte{0x41})
				obsoleteSeed(t, store, 2, index, []byte{0x51})
				mode, rank, faultKey := uint32(12), uint8(2), index
				switch variant {
				case "interval-changed":
					mode = 5
				case "interval-missing":
					mode = 4
				case "interval-extra":
					mode, faultKey = 3, extra
				case "interval-preflight":
					mode = 14
				case "interval-final":
					mode = 13
				}
				var truth CommitTruth
				var stage UpdateStage
				var result error
				var nativeCalls uint32
				evidence, fixtureErr := fixtureLargeFault(store, mode, rank, faultKey, func() {
					truth, stage, result = store.Update(func(reader *Reader) (Batch, error) {
						page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, 1)
						mustEnvironment(t, err)
						batch := obsoleteBatch(page)
						batch.Mutations = []Mutation{consultedCounter(t, 1)}
						if variant == "point" {
							point, err := reader.ObsoleteGenerationPageV1(9, 3, nil, 1)
							mustEnvironment(t, err)
							batch.Consulted = []ConsultedRow{{DBI: counter.DBI, Key: counter.Key}}
							if shared {
								batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, point.Witness)
							}
						} else {
							interval, err := reader.ObsoleteGenerationPageV1(9, 2, nil, 7)
							mustEnvironment(t, err)
							obsoleteRequirePage(t, interval, 1, 1, index)
							batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, interval.Witness)
							batch.Consulted = []ConsultedRow{{DBI: readDBIsLiteral()[2], Key: index}}
						}
						return batch, nil
					})
					largeNativeCached(t, store)
					nativeCalls = fixtureLargeNativeCalls()
				})
				mustEnvironment(t, fixtureErr)
				wantTruth, wantStage := "UNKNOWN", 3
				if mode == 12 {
					wantTruth = "NEW"
				}
				if mode == 14 || mode == 13 {
					wantTruth, wantStage = "OLD", 1
					if mode == 13 {
						wantStage = 2
					}
					diagnostic := "OLD/write snapshot mismatch"
					if mode == 13 {
						diagnostic = "final update image mismatch"
					}
					obsoleteRequireError(t, result, "update", "StateMismatch", -30779, diagnostic)
					if evidence.commits != 0 {
						t.Fatal("ordinary mismatch lost precommit priority")
					}
				} else {
					commit, ok := result.(*CommitError)
					if !ok || commit.Truth.String() != wantTruth || commit.ReadbackCause != nil || evidence.commits != 1 {
						t.Fatal("ordinary/raw crossed predicates", result, evidence)
					}
					obsoleteRequireError(t, commit.Cause, "update", "Capacity", 28, expectedNativeDiagnostic(28))
				}
				if truth.String() != wantTruth || int(stage) != wantStage || string(store.state) != "CLOSED" {
					t.Fatal("ordinary/raw result", truth, stage, result, evidence, store.state)
				}
				if variant == "point" && !shared {
					pointCalls = nativeCalls
				}
				if shared && (pointCalls == 0 || nativeCalls != pointCalls) {
					t.Fatal("shared exact point repeated native work", nativeCalls, pointCalls)
				}
				reopened, err := Open(path, cfg)
				consultedTrack(t, reopened, err)
				wantTarget := []byte(nil)
				if wantTruth == "OLD" {
					wantTarget = []byte{0x41}
				}
				obsoleteRawImage(t, reopened, 1, target, wantTarget)
				wantIndex := []byte{0x51}
				if mode == 4 {
					wantIndex = nil
				}
				if mode == 5 || mode == 14 {
					wantIndex = []byte{0x7f}
				}
				obsoleteRawImage(t, reopened, 2, index, wantIndex)
				wantExtra := []byte(nil)
				if variant == "interval-extra" {
					wantExtra = []byte{0x7f}
				}
				obsoleteRawImage(t, reopened, 2, extra, wantExtra)
				obsoleteRawImage(t, reopened, 0, counter.Key, counter.Literal)
				written := consultedCounter(t, 1)
				wantWritten := written.Literal
				if wantTruth == "OLD" {
					wantWritten = nil
				}
				obsoleteRawImage(t, reopened, 0, written.Key, wantWritten)
			}
		})
	}
}

func TestObsoleteGenerationV1ControlBound(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 4 << 30
	store, err := Create(path, cfg)
	consultedTrack(t, store, err)
	mustEnvironment(t, fixtureLargeBulk(store, 4, 2*67_821, 20))
	// Each distinct g retains its 8-byte prefix and 2022-byte actual lookahead.
	// 67820*2030=137674600 fits; 67821*2030=137676630 exceeds 137676154.
	for _, count := range []uint64{67_821, 67_820} {
		truth, stage, result := store.Update(func(reader *Reader) (Batch, error) {
			batch := Batch{}
			for g := uint64(1); g <= count; g++ {
				page, err := reader.ObsoleteGenerationPageV1(g, 1, nil, 1)
				mustEnvironment(t, err)
				if uint8(page.Stop) != 2 || len(page.Rows) != 1 || len(page.Rows[0].Key()) != 2022 {
					t.Fatal("control witness actual page", g, page.Stop, len(page.Rows))
				}
				batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, page.Witness)
				if g == 1 {
					batch.ObsoleteDeletes = page.Rows
				}
			}
			return batch, nil
		})
		key := append(obsoleteGenerationLiteral(1), make([]byte, 2014)...)
		key[2021] = 1
		if count == 67_821 {
			obsoleteRequireError(t, result, "update", "Capacity", -30417, "Update Batch exceeds bound")
			if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
				t.Fatal("retained control bound after effect", truth, stage, result)
			}
			obsoleteRawImage(t, store, 1, key, append([]byte{0x5a}, make([]byte, 19)...))
		} else {
			if truth.String() != "NEW" || int(stage) != 3 || result != nil {
				t.Fatal("retained control within bound refused", truth, stage, result)
			}
			obsoleteRawImage(t, store, 1, key, nil)
		}
	}
}

func TestObsoleteGenerationV1LargeWindows(t *testing.T) {
	store, _, _ := consultedStore(t)
	key := append(obsoleteGenerationLiteral(9), 1)
	value := bytes.Repeat([]byte{0x61}, 131_073)
	value[65_536], value[131_072] = 0x62, 0x63
	obsoleteSeed(t, store, 1, key, value)
	mustEnvironment(t, store.View(func(reader *Reader) error {
		page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, 1)
		mustEnvironment(t, err)
		obsoleteRequirePage(t, page, 1, 1, key)
		row := page.Rows[0]
		if row.Length() != 131_073 {
			t.Fatal("raw value length truncated")
		}
		for _, offset := range []uint64{0, 65_536, 131_072, 131_073, math.MaxUint64} {
			buffer := make([]byte, 65_536)
			n, err := row.ReadAt(buffer, offset)
			wantCount, wantErr := 65_536, error(nil)
			if offset == 131_072 {
				wantCount, wantErr = 1, io.EOF
			}
			if offset >= 131_073 {
				wantCount, wantErr = 0, io.EOF
			}
			if n != wantCount || err != wantErr {
				t.Fatal("bounded native window", offset, n, err, wantCount, wantErr)
			}
			if n != 0 && !bytes.Equal(buffer[:n], value[int(offset):int(offset)+n]) {
				t.Fatal("native window bytes", offset)
			}
		}
		return nil
	}))
}

func TestObsoleteGenerationV1BackendFailure(t *testing.T) {
	store, path, cfg := consultedStore(t)
	key := append(obsoleteGenerationLiteral(9), 1)
	obsoleteSeed(t, store, 1, key, []byte{0x31})
	var recorded error
	truth, stage, result := store.Update(func(reader *Reader) (Batch, error) {
		mustEnvironment(t, fixtureBreakPrefixReader(reader))
		page, err := reader.ObsoleteGenerationPageV1(9, 1, nil, 1440)
		obsoleteRequireZero(t, page)
		obsoleteRequireError(t, err, "prefix-page", "LocalInvariant", -30782, expectedNativeDiagnostic(-30782))
		if reader.usable() || reader.failure != err {
			t.Fatal("generation backend refusal was converted to absence")
		}
		recorded = err
		// Ignoring the page error cannot admit an unrelated mutation.
		return Batch{Mutations: []Mutation{consultedCounter(t, 11)}}, nil
	})
	if truth.String() != "OLD" || int(stage) != 1 || result != recorded || string(store.state) != "CLOSED" {
		t.Fatal("generation backend failure disposition", truth, stage, result, store.state)
	}
	largeNativeCached(t, store)
	reopened, err := Open(path, cfg)
	consultedTrack(t, reopened, err)
	obsoleteRawImage(t, reopened, 1, key, []byte{0x31})
	obsoleteRawImage(t, reopened, 0, consultedCounter(t, 11).Key, nil)
}

func TestObsoleteGenerationV1JointUTXOLimit(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 512 << 20
	store, err := Create(path, cfg)
	consultedTrack(t, store, err)
	mustEnvironment(t, fixtureLargeBulk(store, 5, 414_634, 20))
	first := append(obsoleteGenerationLiteral(9), make([]byte, 36)...)
	last := bytes.Clone(first)
	binary.BigEndian.PutUint32(last[8:], 414_633)
	value := append([]byte{0x5a}, make([]byte, 19)...)
	for _, mixed := range []bool{true, false} {
		truth, stage, result := store.Update(func(reader *Reader) (Batch, error) {
			batch := Batch{}
			var next []byte
			for {
				page, err := reader.ObsoleteGenerationPageV1(9, 1, next, 1440)
				mustEnvironment(t, err)
				batch.ObsoleteDeletes = append(batch.ObsoleteDeletes, page.Rows...)
				batch.ObsoleteConsulted = append(batch.ObsoleteConsulted, page.Witness)
				if uint8(page.Stop) == 1 {
					break
				}
				next = page.Next
			}
			if len(batch.ObsoleteDeletes) != 414_634 {
				t.Fatal("actual UTXO family cardinality", len(batch.ObsoleteDeletes))
			}
			if mixed {
				key := append(obsoleteGenerationLiteral(10), make([]byte, 36)...)
				batch.Mutations = []Mutation{{DBI: readDBIsLiteral()[1], Key: key, BeforePresent: true, AfterKind: AfterKind(1)}}
			}
			return batch, nil
		})
		if mixed {
			obsoleteRequireError(t, result, "update", "Capacity", -30417, "Update Batch exceeds bound")
			if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
				t.Fatal("raw plus legacy UTXO overcap after effect", truth, stage, result, store.state)
			}
			obsoleteRawImage(t, store, 1, first, value)
			obsoleteRawImage(t, store, 1, last, value)
		} else {
			if truth.String() != "NEW" || int(stage) != 3 || result != nil {
				t.Fatal("exact414634 raw UTXO family refused", truth, stage, result)
			}
			obsoleteRawImage(t, store, 1, first, nil)
			obsoleteRawImage(t, store, 1, last, nil)
		}
	}
}

func TestObsoleteGenerationV1UndoLimit(t *testing.T) {
	path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
	cfg.Upper = 512 << 20
	store, err := Create(path, cfg)
	consultedTrack(t, store, err)
	_, _, hash, _ := obsoleteProjectionSeed(t, store, 9, 1)
	mustEnvironment(t, fixtureLargeBulk(store, 6, 414_635, 20, hash))
	manifest := append(bytes.Clone(hash[:]), 0)
	obsoleteSeed(t, store, 5, manifest, []byte{0x31})
	truth, stage, result := store.Update(func(reader *Reader) (Batch, error) {
		index := obsoleteIndexPage(t, reader, 9)
		batch := obsoleteCollectUndo(t, reader, index.Rows[0])
		if len(batch.ObsoleteDeletes) != 414_636 {
			t.Fatal("actual malformed undo family cardinality", len(batch.ObsoleteDeletes))
		}
		return batch, nil
	})
	obsoleteRequireError(t, result, "update", "Capacity", -30417, "Update Batch exceeds bound")
	if truth.String() != "OLD" || int(stage) != 1 || string(store.state) != "OPEN" {
		t.Fatal("malformed undo family overcap after effect", truth, stage, result, store.state)
	}
	first := append(bytes.Clone(hash[:]), 1, 0, 0, 0, 0)
	last := bytes.Clone(first)
	binary.BigEndian.PutUint32(last[33:], 414_634)
	value := append([]byte{0x5a}, make([]byte, 19)...)
	obsoleteRawImage(t, store, 5, manifest, []byte{0x31})
	obsoleteRawImage(t, store, 5, first, value)
	obsoleteRawImage(t, store, 5, last, value)
}

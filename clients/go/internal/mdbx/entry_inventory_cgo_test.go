//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

// These fixtures persist real bytes through the ordinary public writer. The
// expected observations below are independent literal control/error tuples.
type eiScene struct {
	s        *Store
	o        *OperationReservationOwner
	old      TreeAuthorityV1
	next     TreeAuthorityV1
	pair     TreePairV1
	oldBytes []byte
	values   [4][]byte
}

func eiEncoded(t *testing.T, a TreeAuthorityV1) []byte {
	t.Helper()
	b, err := a.Encode()
	mustEnvironment(t, err)
	return b
}

func eiNew(t *testing.T, d, c int, lagApplied bool) *eiScene {
	t.Helper()
	s, _, o := tsNew(t)
	old := TreeAuthorityV1{Authority: StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: 1, Lifecycle: 1}, LagGenerationID: 2}
	next := old
	next.Authority = modelOrdinary(1, d, c, uint64(d), 1, 0, 0)
	next.Authority.ActiveGenerationID, next.Authority.NextGenerationID = 1, 5
	if d >= 1440 {
		old.Authority.U, next.Authority.U = uint64(d)-1439, uint64(d)-1439
		for i := range next.Authority.Ordinary.NewSuffix {
			next.Authority.Ordinary.NewSuffix[i].BlockHash = modelHash(3000 + uint64(i))
		}
		next.Authority.Ordinary.Target = next.Authority.Ordinary.NewSuffix[c-1]
		next.Authority.Ordinary.CapturedSelectedSide.TipHash = next.Authority.Ordinary.Target.BlockHash
	}
	next.Authority.Ordinary.CapturedSelectedSide.GenerationID = 3
	if d == 0 {
		next.Authority.Ordinary.Stage = 2
	}
	if c == 1 {
		next.Authority.NextGenerationID = 6
		next.Authority.Ordinary.CapturedSelectedSide.GenerationID = 5
	} else {
		side := *next.Authority.Ordinary.CapturedSelectedSide
		old.Authority.SelectedSide = &side
	}
	x := &eiScene{s: s, o: o, old: old, next: next}
	x.oldBytes = eiEncoded(t, old)
	x.values[0] = []byte{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9}
	x.values[1] = tsRootBytes(t, TreeEndpointV1{})
	x.values[2] = []byte{0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6}
	x.values[3] = bytes.Clone(x.values[1]) // equal root, distinct CURRENT/LAG IDs
	if lagApplied {
		x.values[3] = tsRootBytes(t, TreeEndpointV1{Kind: 1, Height: 8, BlockHash: [32]byte{0x71}, CumulativeChainwork: [40]byte{39: 1}})
	}
	mutations := []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: 2, Literal: x.oldBytes}}
	for i, key := range [][]byte{tsCounterKey(1), tsRootKey(1), tsCounterKey(2), tsRootKey(2)} {
		mutations = append(mutations, Mutation{DBI: TreeSchemaV1DBIs()[0], Key: key, AfterKind: 2, Literal: x.values[i]})
	}
	// meta10 precedes meta11 regardless of role.
	mutations[2], mutations[3] = mutations[3], mutations[2]
	r := tsRun(t, s, o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: mutations}})
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
	x.retarget(t)
	return x
}

func (x *eiScene) retarget(t *testing.T) {
	t.Helper()
	x.pair = TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: 2, Literal: eiEncoded(t, x.next)}}}
	if x.next.Authority.Ordinary != nil && len(x.next.Authority.Ordinary.NewSuffix) == 1 && x.old.Authority.SelectedSide == nil {
		p := x.next.Authority.Ordinary.NewSuffix[0]
		key := binary.BigEndian.AppendUint64(nil, x.next.Authority.Ordinary.CapturedSelectedSide.GenerationID)
		key = binary.BigEndian.AppendUint64(key, p.Height)
		value := make([]byte, 104)
		copy(value, p.BlockHash[:])
		x.pair.Mutations = append(x.pair.Mutations, Mutation{DBI: TreeSchemaV1DBIs()[6], Key: key, AfterKind: 2, Literal: value})
	}
}

func (x *eiScene) run(t *testing.T, f func(*Reader, *OperationAccount) (TreeOperationV1, error)) tsResult {
	t.Helper()
	var result tsResult
	before := reservationLive(x.o)
	mustEnvironment(t, x.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		result = tsInvoke(x.s, a, func(r *Reader) (TreeOperationV1, error) { return f(r, a) })
		return nil
	}))
	if reservationLive(x.o) != before {
		t.Fatal("ENTRY hold did not return to baseline")
	}
	return result
}

func eiInput(t *testing.T, err error) {
	t.Helper()
	treeNativeError(t, err, "update", "InvalidInput", 22, "invalid ENTRY inventory", nil)
}

func (x *eiScene) unchanged(t *testing.T) {
	t.Helper()
	if x.s.state != storeOPEN || x.s.terminal != nil || reservationLive(x.o) != 0 {
		t.Fatalf("ENTRY refusal disposition %s/%v", x.s.state, x.s.terminal)
	}
	tsRead(t, x.s, TreeSchemaV1DBIs()[0], []byte{2}, x.oldBytes)
	for _, m := range x.pair.Mutations[1:] {
		tsRead(t, x.s, m.DBI, m.Key, nil)
	}
	tsFollowing(t, x.s, x.o)
}

func eiPrepare(t *testing.T, r *Reader, a *OperationAccount, pair TreePairV1) EntryInventoryV1 {
	t.Helper()
	token, failure, err := r.PrepareEntryInventoryV1(a, pair)
	if err != nil || failure != nil || token.scope == nil {
		t.Fatalf("preparation = %v/%+v/%v", token.scope, failure, err)
	}
	return token
}

func eiRowInput(t *testing.T, row EntryInventoryRowV1, diagnostic string) {
	t.Helper()
	n, err := row.ReadAt(nil, 0)
	if n != 0 {
		t.Fatal("inactive row returned bytes")
	}
	treeNativeError(t, err, "get", "InvalidInput", 22, diagnostic, nil)
}

func eiAwait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Goexit did not finish callback retirement, native cleanup and grant release")
	}
}

func TestEntryInventoryV1Controls(t *testing.T) {
	for _, lagApplied := range []bool{false, true} {
		t.Run(fmt.Sprintf("prefix-lag-applied%v", lagApplied), func(t *testing.T) {
			x := eiNew(t, 1, 1, lagApplied)
			var kept EntryInventoryRowV1
			var reader *Reader
			var token EntryInventoryV1
			calls := 0
			result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
				reader = r
				token = eiPrepare(t, r, a, x.pair)
				if reservationLive(x.o) != 8192+6*r.maxKey {
					t.Fatal("ENTRY backing not held through visitor")
				}
				failure, err := r.VisitEntryInventoryV1(token, func(row EntryInventoryRowV1) error {
					want := [4][4]uint64{{1, 2, 1, 1}, {2, 11, 1, 1}, {3, 2, 2, 2}, {4, 11, 2, 2}}[calls]
					if [4]uint64{uint64(row.Source), uint64(row.Artifact), uint64(row.Role), row.Generation} != want {
						t.Fatalf("event%d tuple %+v", calls, row)
					}
					key := [][]byte{{0x10, 0, 0, 0, 0, 0, 0, 0, 1}, {0x11, 0, 0, 0, 0, 0, 0, 0, 1}, {0x10, 0, 0, 0, 0, 0, 0, 0, 2}, {0x11, 0, 0, 0, 0, 0, 0, 0, 2}}[calls]
					indexCount := uint64(0)
					if calls == 3 && lagApplied {
						indexCount = 9
					}
					if !bytes.Equal(row.Key, key) || !row.Present || row.Length != uint64(len(x.values[calls])) || row.IndexCount != indexCount {
						t.Fatalf("event%d key/presence/length/index %+v", calls, row)
					}
					if row.Height != 0 || row.Hash != ([32]byte{}) || row.Node != (TreeNodeIDV1{}) || row.Count != 0 || row.Projection != 0 {
						t.Fatal("controls emitted unrelated payload")
					}
					if calls != 0 {
						eiRowInput(t, kept, "ENTRY inventory row is not active")
					}
					eiReadBoundaries(t, row, x.values[calls])
					if calls == 0 {
						eiMetadataCopy(t, row)
					}
					kept = row
					calls++
					return nil
				})
				if failure != nil || calls != 4 || token.scope.completed {
					t.Fatalf("prefix completion %d/%+v/%v", calls, failure, token.scope.completed)
				}
				eiInput(t, err)
				eiRowInput(t, kept, "ENTRY inventory row is not active")
				failure, err = r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
					t.Fatal("second Visit emitted")
					return nil
				})
				if failure != nil {
					t.Fatal("pure repeated Visit invented a failure")
				}
				eiInput(t, err)
				pair := x.pair
				pair.EntryInventory = &token
				return TreeOperationV1{Pair: pair}, nil // ignored unsupported refusal
			})
			result.tuple(t, 1, 1, -1)
			eiInput(t, result.err)
			eiRowInput(t, kept, "ENTRY inventory row is not active")
			eiRetired(t, token)
			_, failure, err := reader.PrepareEntryInventoryV1(nil, x.pair)
			if failure != nil {
				t.Fatal("expired Reader produced sidecar")
			}
			eiInput(t, err)
			x.unchanged(t)
		})
	}
	t.Run("row-zero", func(t *testing.T) { eiRowInput(t, EntryInventoryRowV1{}, "invalid ENTRY inventory row") })
	t.Run("API-identities", eiAPIIdentities)
	t.Run("account-binding", eiAccountBinding)
	t.Run("preparation-and-attachment", eiPreparationAndAttachment)
	t.Run("descriptor-shapes", eiDescriptorShapes)
	t.Run("pure-transition-relations", eiPureRelations)
	t.Run("active-noninitial-Readers", eiNoninitialReaders)
	t.Run("funding", eiFunding)
	t.Run("application-lifecycle", eiApplicationLifecycle)
}

func (x *eiScene) storeOld(t *testing.T) {
	t.Helper()
	x.oldBytes = eiEncoded(t, x.old)
	op := TreeOperationV1{Pair: TreePairV1{Mutations: []Mutation{{DBI: TreeSchemaV1DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: 2, Literal: x.oldBytes}}}}
	mustEnvironment(t, tsRun(t, x.s, x.o, TreeOperation, op).err)
}

func eiPureRelations(t *testing.T) {
	for _, mode := range []string{"carried-cleanup", "exclusion", "old-live-C1", "header-and-body", "wrong-carried", "wrong-exclusion", "old-recovery", "authority-absent", "B-mismatch", "U-mismatch", "old-detached", "next-none", "disconnect-cursor", "rollback3", "rollback4", "live-sequence", "live-work", "exclusion-height", "exclusion-hash", "exclusion-error", "body-C2", "body-old-live"} {
		t.Run(mode, func(t *testing.T) {
			d, c := 1, 1
			switch mode {
			case "rollback4":
				d = 2
			case "body-C2":
				c = 2
			}
			x := eiNew(t, d, c, false)
			switch mode {
			case "carried-cleanup", "wrong-carried", "old-detached":
				x.old.Authority.Phase = 2
				x.old.Authority.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 1, GenerationID: 4}}}
				if mode != "wrong-carried" {
					x.next.Authority.Ordinary.CarriedCleanup = x.old.Authority.Cleanup
				}
				if mode == "old-detached" {
					x.old.Authority.DetachedSuffix = modelDetached(1, 1)
				}
			case "next-none":
				x.next = x.old
			case "disconnect-cursor":
				point := x.next.Authority.Ordinary.OldSuffix[0]
				x.next.Authority.Ordinary.Cursor = &point
			case "rollback3", "rollback4":
				x.next.Authority = modelOrdinary(map[string]byte{"rollback3": 3, "rollback4": 4}[mode], d, c, uint64(d), 1, 0, 0)
				x.next.Authority.NextGenerationID = 6
				x.next.Authority.Ordinary.CapturedSelectedSide.GenerationID = 5
			case "exclusion", "wrong-exclusion", "exclusion-height", "exclusion-hash", "exclusion-error":
				x.old.Authority.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 3, FirstInvalidBlockHash: [32]byte{9}, ExactConsensusError: []byte("invalid")}
				if mode != "wrong-exclusion" {
					branch := *x.old.Authority.ExcludedInvalidBranch
					x.next.Authority.ExcludedInvalidBranch = &branch
				}
			case "old-live-C1", "live-sequence", "live-work", "body-old-live":
				x.next.Authority.Ordinary.CapturedSelectedSide.GenerationID = 3
				side := *x.next.Authority.Ordinary.CapturedSelectedSide
				x.old.Authority.SelectedSide = &side
				x.next.Authority.NextGenerationID = 5
			case "old-recovery":
				profile := StorageProfileV1(2)
				x.old.Authority.Lifecycle, x.old.Authority.PendingTargetProfile = 2, &profile
			case "B-mismatch":
				x.old.Authority.B, x.next.Authority.B, x.old.Authority.U, x.next.Authority.U = 1, 2, 13681, 13682
				o := x.next.Authority.Ordinary
				o.OldSuffix[0].Height, o.NewSuffix[0].Height, o.Target.Height = 15121, 15121, 15121
				o.CapturedSelectedSide.F, o.CapturedSelectedSide.TipHeight = 15120, 15121
			case "U-mismatch":
				x.old.Authority.U = 1
			}
			switch mode {
			case "live-sequence":
				x.next.Authority.NextGenerationID++
			case "live-work":
				x.next.Authority.Ordinary.CapturedSelectedSide.CumulativeChainwork[39]++
			case "exclusion-height":
				x.next.Authority.ExcludedInvalidBranch.FirstInvalidHeight++
			case "exclusion-hash":
				x.next.Authority.ExcludedInvalidBranch.FirstInvalidBlockHash[0]++
			case "exclusion-error":
				x.next.Authority.ExcludedInvalidBranch.ExactConsensusError = []byte("different")
			}
			x.storeOld(t)
			x.retarget(t)
			if mode == "header-and-body" || mode == "body-C2" || mode == "body-old-live" {
				body := append(initial148NativeLiteral(t), tdFrame(1, 0, nil)...)
				body[140] ^= 0x40 // a genuinely absent HEADER identity, distinct from tsEntry
				hash := sha3.Sum256(body[:148])
				x.next.Authority.Ordinary.NewSuffix[0].BlockHash = hash
				if c == 1 {
					x.next.Authority.Ordinary.Target.BlockHash = hash
					x.next.Authority.Ordinary.CapturedSelectedSide.TipHash = hash
				}
				if mode == "body-old-live" {
					x.old.Authority.SelectedSide.TipHash = hash
					x.storeOld(t)
				}
				x.retarget(t)
				targets := x.pair.Mutations[1:]
				x.pair.Mutations = append(x.pair.Mutations[:1:1], Mutation{DBI: TreeSchemaV1DBIs()[3], Key: hash[:], AfterKind: 2, Literal: body[:148]}, Mutation{DBI: TreeSchemaV1DBIs()[4], Key: hash[:], AfterKind: 2, Literal: body})
				x.pair.Mutations = append(x.pair.Mutations, targets...)
			}
			if mode == "authority-absent" {
				x.pair.Mutations[0].BeforePresent = false
			}
			accepted := mode == "carried-cleanup" || mode == "exclusion" || mode == "old-live-C1" || mode == "header-and-body"
			oldInput, nextInput := bytes.Clone(x.oldBytes), bytes.Clone(x.pair.Mutations[0].Literal)
			mustEnvironment(t, inspectTreeAuthorityV1(oldInput))
			mustEnvironment(t, inspectTreeAuthorityV1(nextInput))
			result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
				mustEnvironment(t, treeAdmitV1(TreeOperationV1{Pair: x.pair}, a, r.databaseID))
				token, f, err := r.PrepareEntryInventoryV1(a, x.pair)
				if accepted {
					if token.scope == nil || f != nil || err != nil {
						t.Fatalf("structurally valid preparation refused %s/%v", mode, err)
					}
				} else {
					if token.scope != nil || f != nil || r.entry.inventory == nil {
						t.Fatal("pure relation refusal missed registered owner")
					}
					eiInput(t, err)
				}
				return TreeOperationV1{Pair: x.pair}, nil
			})
			eiInput(t, result.err)
			if !bytes.Equal(x.oldBytes, oldInput) || !bytes.Equal(x.pair.Mutations[0].Literal, nextInput) {
				t.Fatal("Prepare mutated OLD or prospective input")
			}
			x.unchanged(t)
		})
	}
}

func eiNoninitialReaders(t *testing.T) {
	x := eiNew(t, 1, 1, false)
	mustEnvironment(t, x.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		return x.s.View(func(r *Reader) error {
			token, f, err := r.PrepareEntryInventoryV1(a, x.pair)
			if token.scope != nil || f != nil || reservationLive(x.o) != 0 {
				t.Fatal("active View acquired ENTRY backing")
			}
			eiInput(t, err)
			return nil
		})
	}))
	providerCalls := 0
	s, _, o := tsNew(t)
	tsRoots(t, s, o, 1, 2)
	provider := tsSource(func(_ TreePositionV1, r *Reader, sink *TreeDeltaSinkV1) error {
		providerCalls++
		if r.entry != nil {
			t.Fatal("provider inherited initial ENTRY frame")
		}
		_, f, err := r.PrepareEntryInventoryV1(nil, x.pair)
		if f != nil {
			t.Fatal("provider invented sidecar")
		}
		eiInput(t, err)
		return sink.BeginV1(TreeBlockV1{TxCount: 1})
	})
	result := tsRun(t, s, o, TreeOperation, tsOperation(t, provider))
	mustEnvironment(t, result.err)
	if providerCalls != 1 {
		t.Fatal("provider identity test missed actual owner")
	}
}

func eiReadBoundaries(t *testing.T, row EntryInventoryRowV1, want []byte) {
	t.Helper()
	for _, size := range []int{0, 1, len(want), len(want) + 1, 65536, 65537} {
		dst := bytes.Repeat([]byte{0xa5}, size)
		n, err := row.ReadAt(dst, 0)
		if size == 65537 {
			treeNativeError(t, err, "get", "InvalidInput", 22, "ReadAt buffer exceeds 65536 bytes", nil)
			if n != 0 || !bytes.Equal(dst, bytes.Repeat([]byte{0xa5}, size)) {
				t.Fatal("oversize read touched destination")
			}
			continue
		}
		wantN := min(size, len(want))
		if n != wantN || !bytes.Equal(dst[:n], want[:n]) || treeSameErrorV1(err, io.EOF) != (size > len(want)) || err != nil && !treeSameErrorV1(err, io.EOF) {
			t.Fatalf("ReadAt size%d = %d/%v", size, n, err)
		}
		if !bytes.Equal(dst[n:], bytes.Repeat([]byte{0xa5}, size-n)) {
			t.Fatal("short read overwrote sentinel")
		}
	}
	for _, offset := range []uint64{uint64(len(want) - 1), uint64(len(want)), ^uint64(0)} {
		dst := []byte{0xa5, 0xa5}
		n, err := row.ReadAt(dst, offset)
		wantN := 0
		if offset == uint64(len(want)-1) {
			wantN = 1
			if dst[0] != want[len(want)-1] {
				t.Fatal("last-byte read drift")
			}
		}
		if n != wantN || !treeSameErrorV1(err, io.EOF) || dst[1] != 0xa5 {
			t.Fatalf("ReadAt offset%d = %d/%v/%x", offset, n, err, dst)
		}
	}
}

func eiMetadataCopy(t *testing.T, row EntryInventoryRowV1) {
	t.Helper()
	row.Source, row.Artifact, row.Role, row.Projection = 255, 255, 255, 255
	row.Generation, row.Height, row.Count, row.IndexCount = ^uint64(0), 99, 99, 99
	row.Hash, row.Node = [32]byte{9}, TreeNodeIDV1{Kind: 99}
	row.Key, row.Present, row.Length = []byte{2}, false, ^uint64(0)
	dst := bytes.Repeat([]byte{0xa5}, 17)
	n, err := row.ReadAt(dst, 0)
	want := []byte{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 9, 0xa5}
	if n != 16 || !treeSameErrorV1(err, io.EOF) || !bytes.Equal(dst, want) {
		t.Fatalf("public Row metadata redirected read %d/%v/%x", n, err, dst)
	}
}

func eiRetired(t *testing.T, token EntryInventoryV1) {
	t.Helper()
	s := token.scope
	if !s.retired || s.completed || s.reader != nil || s.entry != nil || s.account != nil || s.oldBytes != nil || s.nextBytes != nil || s.mutations != nil || s.consulted != nil {
		t.Fatal("retained mutable preparation borrow")
	}
	if s.access.mu == nil || s.access.reader != nil || s.access.image != (updateImage{}) || s.access.key != nil || s.access.active {
		t.Fatal("retained native row borrow or lost immutable mutex locator")
	}
	if !reflect.ValueOf(s.decode).IsZero() || !reflect.ValueOf(s.inspection).IsZero() || !reflect.ValueOf(s.authority).IsZero() || !reflect.ValueOf(s.roots).IsZero() || !reflect.ValueOf(s.rootControl).IsZero() {
		t.Fatal("retained authority/root borrows")
	}
}

func eiAPIIdentities(t *testing.T) {
	x := eiNew(t, 1, 1, false)
	other := eiNew(t, 1, 1, false)
	var view, initial *Reader
	mustEnvironment(t, x.s.View(func(r *Reader) error {
		view = r
		return nil
	}))
	result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
		initial = r
		// Deliberately copy the actual value, including its unchanged self
		// identity. Reflection avoids using any copied mutex or atomic method.
		copied := new(Reader)
		reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(r).Elem())
		for _, invalid := range []*Reader{nil, {}, view, copied} {
			token, failure, err := invalid.PrepareEntryInventoryV1(a, x.pair)
			if token.scope != nil || failure != nil || reservationLive(x.o) != 0 {
				t.Fatal("invalid Reader acquired preparation")
			}
			eiInput(t, err)
		}
		token := eiPrepare(t, r, a, x.pair)
		for _, invalid := range []*Reader{nil, {}, view, copied} {
			f, err := invalid.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
				t.Fatal("invalid Reader visited")
				return nil
			})
			if f != nil {
				t.Fatal("invalid Reader invented sidecar")
			}
			eiInput(t, err)
		}
		foreignResult := other.run(t, func(foreign *Reader, _ *OperationAccount) (TreeOperationV1, error) {
			f, err := foreign.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
				t.Fatal("active foreign Reader visited")
				return nil
			})
			if f != nil {
				t.Fatal("foreign identity read another frame's failure")
			}
			eiInput(t, err)
			return tsPair(34), nil
		})
		mustEnvironment(t, foreignResult.err)
		for _, invalid := range []EntryInventoryV1{{}} {
			_, err := r.VisitEntryInventoryV1(invalid, func(EntryInventoryRowV1) error {
				t.Fatal("zero token visited")
				return nil
			})
			eiInput(t, err)
		}
		_, err := r.VisitEntryInventoryV1(token, nil)
		eiInput(t, err)
		_, err = r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
			t.Fatal("nil visitor did not consume the allocated visit")
			return nil
		})
		eiInput(t, err)
		return TreeOperationV1{Pair: x.pair}, nil
	})
	eiInput(t, result.err)
	// A real token from another completed callback is foreign, never fabricated.
	var foreign EntryInventoryV1
	result = x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
		foreign = eiPrepare(t, r, a, x.pair)
		return TreeOperationV1{Pair: x.pair}, nil
	})
	eiInput(t, result.err)
	result = x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
		_, err := r.VisitEntryInventoryV1(foreign, func(EntryInventoryRowV1) error {
			t.Fatal("foreign token visited")
			return nil
		})
		eiInput(t, err)
		_, err = initial.VisitEntryInventoryV1(foreign, func(EntryInventoryRowV1) error {
			t.Fatal("expired token visited")
			return nil
		})
		eiInput(t, err)
		return tsPair(12), nil
	})
	mustEnvironment(t, result.err)
	x.unchanged(t)
}

func eiAccountBinding(t *testing.T) {
	for _, mode := range []string{"foreign-same-owner", "wrong-kind", "nil", "zero", "closed", "wrapper-copy"} {
		t.Run(mode, func(t *testing.T) {
			x := eiNew(t, 1, 1, false)
			var closed *OperationAccount
			mustEnvironment(t, x.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				closed = a
				return nil
			}))
			kind := TreeOperation
			if mode == "wrong-kind" {
				kind = LaneOperation
			}
			mustEnvironment(t, x.o.WithOperation(kind, func(a *OperationAccount) error {
				run := func(supplied *OperationAccount) {
					before := reservationLive(x.o)
					result := tsInvoke(x.s, a, func(r *Reader) (TreeOperationV1, error) {
						token, f, err := r.PrepareEntryInventoryV1(supplied, x.pair)
						if mode == "wrapper-copy" {
							if err != nil || f != nil || token.scope == nil {
								t.Fatalf("same shared state copy refused %v", err)
							}
						} else {
							if token.scope != nil || f != nil || r.entry.inventory != nil || reservationLive(x.o) != before {
								t.Fatal("account identity/kind guard did not precede E/source25")
							}
							eiInput(t, err)
						}
						return TreeOperationV1{Pair: x.pair}, nil
					})
					if mode == "wrapper-copy" {
						eiInput(t, result.err)
					} else if result.err != nil {
						t.Fatalf("unregistered refusal latched ordinary path %v", result.err)
					}
				}
				if mode == "foreign-same-owner" {
					return x.o.WithOperation(TreeOperation, func(b *OperationAccount) error {
						return b.WithReservation(65536, func() error {
							run(b)
							return nil
						})
					})
				}
				supplied := a
				switch mode {
				case "nil":
					supplied = nil
				case "zero":
					supplied = &OperationAccount{}
				case "closed":
					supplied = closed
				case "wrapper-copy":
					copy := *a
					supplied = &copy
				}
				run(supplied)
				return nil
			}))
			if reservationLive(x.o) != 0 {
				t.Fatal("account guard leaked grant")
			}
		})
	}
}

func eiPreparationAndAttachment(t *testing.T) {
	for _, mode := range []string{"discard", "attached-zero", "attached-prepared", "prepare-twice", "ordinary-shape-priority", "prepare-shape-priority"} {
		t.Run(mode, func(t *testing.T) {
			x := eiNew(t, 1, 1, false)
			var token EntryInventoryV1
			result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
				pair := x.pair
				if mode == "prepare-shape-priority" {
					bad := pair
					bad.Mutations = append([]Mutation(nil), pair.Mutations...)
					bad.Mutations[0].AfterKind = 0
					_, f, err := r.PrepareEntryInventoryV1(a, bad)
					if f != nil || r.entry.inventory != nil || reservationLive(x.o) != 0 {
						t.Fatal("Pair grammar ran after allocation/source")
					}
					tsRefusal(t, tsResult{1, 1, -1, err}, false)
					return TreeOperationV1{Pair: bad}, nil
				}
				if mode != "attached-zero" {
					token = eiPrepare(t, r, a, pair)
				}
				if mode == "prepare-twice" {
					before := reservationLive(x.o)
					second, f, err := r.PrepareEntryInventoryV1(a, pair)
					if second.scope != nil || f != nil || reservationLive(x.o) != before {
						t.Fatal("second preparation allocated/read")
					}
					eiInput(t, err)
				}
				if mode == "attached-zero" || mode == "attached-prepared" {
					pair.EntryInventory = &token
				}
				if mode == "ordinary-shape-priority" {
					pair.Mutations = nil
				}
				return TreeOperationV1{Pair: pair}, nil
			})
			result.tuple(t, 1, 1, -1)
			if mode == "ordinary-shape-priority" || mode == "prepare-shape-priority" {
				tsRefusal(t, result, false)
			} else {
				eiInput(t, result.err)
			}
			if token.scope != nil {
				eiRetired(t, token)
			}
			x.unchanged(t)
		})
	}
}

func eiDescriptorShapes(t *testing.T) {
	for _, counts := range [][2]int{{0, 2}, {1, 1}, {2, 2}, {1440, 1440}} {
		t.Run(fmt.Sprint(counts), func(t *testing.T) {
			x := eiNew(t, counts[0], counts[1], false)
			result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
				_ = eiPrepare(t, r, a, x.pair)
				return TreeOperationV1{Pair: x.pair}, nil
			})
			eiInput(t, result.err)
			x.unchanged(t)
		})
	}
	for _, mode := range []string{"profile", "B", "U", "current", "lag", "sequence", "capture", "missing-link", "wrong-link-hash", "wrong-link-owner", "wrong-link-height", "present-link", "delete-link", "foreign-header", "present-header", "foreign-body", "counter-target", "root-target", "UTXO-target", "undo-target", "index-target", "nil-authority", "bad-authority-tag", "attached-on-prepare"} {
		t.Run(mode, func(t *testing.T) {
			x := eiNew(t, 1, 1, false)
			pair := x.pair
			switch mode {
			case "profile":
				x.next.Authority.ActiveProfile = 2
			case "current":
				x.next.Authority.ActiveGenerationID = 4
			case "lag":
				x.next.LagGenerationID = 4
			case "sequence":
				x.next.Authority.NextGenerationID = 7
			case "capture":
				x.next.Authority.Ordinary.CapturedSelectedSide.GenerationID = 4
			}
			if mode == "profile" || mode == "current" || mode == "lag" || mode == "sequence" || mode == "capture" {
				pair.Mutations[0].Literal = eiEncoded(t, x.next)
			}
			switch mode {
			case "B":
				pair.Mutations[0].Literal = bytes.Clone(pair.Mutations[0].Literal)
				pair.Mutations[0].Literal[31] = 1
			case "U":
				pair.Mutations[0].Literal = bytes.Clone(pair.Mutations[0].Literal)
				pair.Mutations[0].Literal[39] = 1
			case "missing-link":
				pair.Mutations = pair.Mutations[:1]
			case "wrong-link-hash":
				pair.Mutations[1].Literal[0] ^= 1
			case "wrong-link-owner":
				pair.Mutations[1].Key[7] = 4
			case "wrong-link-height":
				pair.Mutations[1].Key[15]++
			case "present-link":
				pair.Mutations[1].BeforePresent = true
			case "delete-link":
				pair.Mutations[1].BeforePresent, pair.Mutations[1].AfterKind, pair.Mutations[1].Literal = true, 1, nil
			case "foreign-header", "present-header":
				header := initial148NativeLiteral(t)
				if mode == "foreign-header" {
					header[140] ^= 0x40
				}
				hash := sha3.Sum256(header)
				if mode == "present-header" {
					x.next.Authority.Ordinary.NewSuffix[0].BlockHash = hash
					x.next.Authority.Ordinary.Target.BlockHash = hash
					x.next.Authority.Ordinary.CapturedSelectedSide.TipHash = hash
					pair.Mutations[0].Literal = eiEncoded(t, x.next)
					copy(pair.Mutations[1].Literal, hash[:])
				}
				m := Mutation{DBI: TreeSchemaV1DBIs()[3], Key: hash[:], BeforePresent: mode == "present-header", AfterKind: 2, Literal: header}
				pair.Mutations = append(pair.Mutations[:1:1], m, pair.Mutations[1])
			case "foreign-body":
				body := append(initial148NativeLiteral(t), tdFrame(1, 0, nil)...)
				hash := sha3.Sum256(body[:148])
				pair.Mutations[1] = Mutation{DBI: TreeSchemaV1DBIs()[4], Key: hash[:], AfterKind: 2, Literal: body}
			case "counter-target":
				pair.Mutations[1] = Mutation{DBI: TreeSchemaV1DBIs()[0], Key: tsCounterKey(1), AfterKind: 2, Literal: make([]byte, 16)}
			case "root-target":
				pair.Mutations[1] = Mutation{DBI: TreeSchemaV1DBIs()[0], Key: tsRootKey(1), AfterKind: 2, Literal: x.values[1]}
			case "UTXO-target":
				pair.Mutations[1] = Mutation{DBI: TreeSchemaV1DBIs()[1], Key: append(binary.BigEndian.AppendUint64(nil, 1), make([]byte, 36)...), BeforePresent: true, AfterKind: 1}
			case "undo-target":
				pair.Mutations[1] = Mutation{DBI: TreeSchemaV1DBIs()[5], Key: make([]byte, 33), BeforePresent: true, AfterKind: 1}
			case "index-target":
				pair.Mutations[1] = Mutation{DBI: TreeSchemaV1DBIs()[2], Key: append(binary.BigEndian.AppendUint64(nil, 1), make([]byte, 8)...), BeforePresent: true, AfterKind: 1}
			case "nil-authority":
				pair.Mutations[0].Literal = nil
			case "bad-authority-tag":
				pair.Mutations[0].Literal = bytes.Clone(pair.Mutations[0].Literal)
				pair.Mutations[0].Literal[0] = 2
			case "attached-on-prepare":
				pair.EntryInventory = &EntryInventoryV1{}
			}
			result := x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
				token, f, err := r.PrepareEntryInventoryV1(a, pair)
				if token.scope != nil || f != nil || err == nil {
					t.Fatalf("invalid descriptor %s admitted %+v/%v", mode, f, err)
				}
				ordinary := mode == "B" || mode == "U" || mode == "present-header" || mode == "nil-authority" || mode == "bad-authority-tag"
				if ordinary {
					tsRefusal(t, tsResult{1, 1, -1, err}, false)
				} else {
					eiInput(t, err)
				}
				registered := !ordinary && mode != "attached-on-prepare"
				if (r.entry.inventory != nil) != registered {
					t.Fatal("descriptor rejection crossed the wrong registration frontier")
				}
				if registered {
					_, _, repeated := r.PrepareEntryInventoryV1(a, x.pair)
					eiInput(t, repeated)
				}
				return TreeOperationV1{Pair: x.pair}, errors.New("stop after refused preparation")
			})
			result.tuple(t, 1, 1, -1)
			if x.s.state != storeOPEN || reservationLive(x.o) != 0 {
				t.Fatal("descriptor refusal cleanup")
			}
			tsRead(t, x.s, TreeSchemaV1DBIs()[0], []byte{2}, x.oldBytes)
		})
	}
}

func eiFunding(t *testing.T) {
	for _, limit := range []uint64{805306367, 805306368, 900000000} {
		for _, short := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("R%d-short%d", limit, short), func(t *testing.T) {
				x := eiNew(t, 1, 1, false)
				x.o = reservationOwner(t, limit)
				mustEnvironment(t, x.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
					e := uint64(8192) + 6*uint64(limitsForPage(x.s.config.PageSize).maxKey)
					filler := uint64(402653184) - e + short
					if limit < 805306368 {
						filler = 0
					}
					run := func() error {
						result := tsInvoke(x.s, a, func(r *Reader) (TreeOperationV1, error) {
							token, f, err := r.PrepareEntryInventoryV1(a, x.pair)
							if short == 1 || limit < 805306368 {
								if token.scope != nil || f != nil || r.entry.inventory != nil || any(err) != any(errOperationReservationCapacity) || reservationLive(x.o) != filler {
									t.Fatal("E refused after allocation/source or changed capacity identity")
								}
								return TreeOperationV1{}, err
							}
							if token.scope == nil || f != nil || err != nil || reservationLive(x.o) != filler+e {
								t.Fatalf("exact E admission %v", err)
							}
							return TreeOperationV1{Pair: x.pair}, nil
						})
						result.tuple(t, 1, 1, -1)
						if reservationLive(x.o) != filler {
							t.Fatal("E did not release to caller backing")
						}
						return nil
					}
					if filler == 0 {
						return run()
					}
					return a.WithReservation(filler, run)
				}))
				x.o = reservationOwner(t, 805306368)
				x.unchanged(t)
			})
		}
	}
	if unsafe.Sizeof(Reader{}) != 216 || unsafe.Sizeof(entryInventoryStateV1{}) != 3688 || unsafe.Sizeof(entryRowAccessV1{}) != 80 || unsafe.Sizeof(EntryInventoryRowV1{}) != 208 || unsafe.Sizeof(EntryInventoryFailureV1{}) != 120 || unsafe.Sizeof(treePublicEntryV1{}) != 40 || unsafe.Sizeof(operationHold{}) != 24 {
		t.Fatal("funded typed-live layout changed")
	}
}

func eiApplicationLifecycle(t *testing.T) {
	for _, mode := range []string{"nil", "direct", "wrapped", "typed-nil", "panic", "panic-nil", "goexit"} {
		visits := []uint8{0, 1}
		if mode == "panic" || mode == "panic-nil" || mode == "goexit" {
			visits = append(visits, 2)
		}
		for _, visited := range visits {
			t.Run(fmt.Sprintf("%s-visited%v", mode, visited), func(t *testing.T) {
				x := eiNew(t, 1, 1, false)
				marker, panicValue := errors.New("application"), new(int)
				application := marker
				if mode == "wrapped" {
					application = fmt.Errorf("outer: %w", marker)
				}
				if mode == "typed-nil" {
					var p *nilPointerError
					application = p
				}
				var token EntryInventoryV1
				var row EntryInventoryRowV1
				var result tsResult
				var recovered any
				returned := false
				calls := 0
				unwind := func() {
					switch mode {
					case "panic":
						panic(panicValue)
					case "panic-nil":
						panic(treeCallNilPanicValue)
					case "goexit":
						runtime.Goexit()
					}
				}
				run := func() {
					defer func() { recovered = recover() }()
					result = x.run(t, func(r *Reader, a *OperationAccount) (TreeOperationV1, error) {
						token = eiPrepare(t, r, a, x.pair)
						if visited != 0 {
							_, err := r.VisitEntryInventoryV1(token, func(v EntryInventoryRowV1) error {
								calls++
								row = v
								if visited == 2 {
									unwind()
								}
								return marker
							})
							if any(err) != any(marker) {
								t.Fatal("visitor application interface changed")
							}
						}
						unwind()
						switch mode {
						case "nil":
							return TreeOperationV1{Pair: x.pair}, nil
						default:
							return TreeOperationV1{Pair: x.pair}, application
						}
					})
					returned = true
				}
				if mode == "goexit" {
					done := make(chan struct{})
					go func() {
						defer close(done)
						run()
					}()
					eiAwait(t, done)
				} else {
					run()
				}
				switch mode {
				case "panic":
					if returned || recovered != panicValue {
						t.Fatal("panic identity/resumption")
					}
				case "panic-nil":
					if returned || recovered == nil {
						t.Fatal("panic(nil) lost")
					}
				case "goexit":
					if returned || recovered != nil {
						t.Fatal("Goexit changed")
					}
				case "nil":
					eiInput(t, result.err)
				default:
					if any(result.err) != any(application) {
						t.Fatal("application error interface changed")
					}
				}
				eiRetired(t, token)
				if visited != 0 {
					if calls != 1 {
						t.Fatalf("application stop emitted %d events", calls)
					}
					eiRowInput(t, row, "ENTRY inventory row is not active")
				}
				x.unchanged(t)
			})
		}
	}
}

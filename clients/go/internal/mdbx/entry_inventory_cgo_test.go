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
	"sort"
	"testing"
	"time"
	"unsafe"
)

// These fixtures own persisted bytes and independently check the complete
// canonical bijection before the real startup owner publishes permission.
type eisFixture struct {
	s       *Store
	path    string
	o       *OperationReservationOwner
	old     TreeAuthorityV1
	headers [][]byte
	hashes  [][32]byte
	height  uint64
}

func eisHeader(height uint64, parent [32]byte, branch byte) []byte {
	b := make([]byte, 148)
	binary.LittleEndian.PutUint32(b, 1)
	copy(b[4:36], parent[:])
	b[36], b[68], b[100] = branch, 2, 3
	binary.LittleEndian.PutUint64(b[140:], height+17)
	return b
}

func eisWork(height uint64) [40]byte {
	var work [40]byte
	binary.BigEndian.PutUint64(work[32:], height+1)
	return work
}

func eisChain(hash, parent [32]byte, height uint64) []byte {
	b := make([]byte, 104)
	copy(b, hash[:])
	copy(b[32:], parent[:])
	w := eisWork(height)
	copy(b[64:], w[:])
	return b
}

func eisHeight(g, h uint64) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b, g)
	binary.BigEndian.PutUint64(b[8:], h)
	return b
}

func eisOwner(g uint64, hash [32]byte) []byte {
	b := make([]byte, 40)
	binary.BigEndian.PutUint64(b, g)
	copy(b[8:], hash[:])
	return b
}

func eisMutation(rank uint8, key, value []byte) Mutation {
	return Mutation{DBI: TreeSchemaV1DBIs()[rank], Key: bytes.Clone(key), AfterKind: 2, Literal: bytes.Clone(value)}
}

func eisSeed(t *testing.T, f *eisFixture, rows []Mutation) {
	t.Helper()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DBI.Rank != rows[j].DBI.Rank {
			return rows[i].DBI.Rank < rows[j].DBI.Rank
		}
		return bytes.Compare(rows[i].Key, rows[j].Key) < 0
	})
	r := tsRun(t, f.s, f.o, TreeOperation, TreeOperationV1{Pair: TreePairV1{Mutations: rows}})
	r.tuple(t, 2, 3, -1)
	mustEnvironment(t, r.err)
}

func eisNew(t *testing.T, height uint64, profile byte, cleanup []CleanupSpanV1) *eisFixture {
	t.Helper()
	s, path, _ := treeNativeStore(t)
	f := &eisFixture{s: s, path: path, o: reservationOwner(t, 805306368), height: height}
	f.old = TreeAuthorityV1{Authority: StorageAuthorityV1{Version: 1, ActiveProfile: StorageProfileV1(profile), ActiveGenerationID: 11, NextGenerationID: 21, Phase: 1, Lifecycle: 1}, LagGenerationID: 13}
	if height >= 1440 {
		f.old.Authority.U = height - 1439
	}
	if profile == 1 && height >= 15120 {
		f.old.Authority.B = height - 15119
	}
	if len(cleanup) != 0 {
		f.old.Authority.Phase, f.old.Authority.Cleanup = 2, &CleanupV1{Spans: cleanup}
	}
	var parent [32]byte
	var rows []Mutation
	for h := uint64(0); h <= height; h++ {
		header := eisHeader(h, parent, 1)
		hash := sha3.Sum256(header)
		f.headers, f.hashes = append(f.headers, header), append(f.hashes, hash)
		rows = append(rows, eisMutation(2, eisHeight(11, h), eisChain(hash, parent, h)), eisMutation(3, hash[:], header), eisMutation(4, hash[:], header), eisMutation(7, eisOwner(11, hash), CanonicalOwnerValue(h)))
		if h >= f.old.Authority.U {
			rows = append(rows, eisMutation(5, append(bytes.Clone(hash[:]), 0), UndoManifestValue(h, [16]byte{}, 0, 0)))
		}
		parent = hash
		if h%1000 == 999 {
			eisSeed(t, f, rows)
			rows = nil
		}
	}
	lag := uint64(0)
	if height >= 15120 {
		lag = 720*((height-15120)/720) + 1
	}
	for h := uint64(0); h < lag; h++ {
		p := [32]byte{}
		if h != 0 {
			p = f.hashes[h-1]
		}
		rows = append(rows, eisMutation(2, eisHeight(13, h), eisChain(f.hashes[h], p, h)), eisMutation(7, eisOwner(13, f.hashes[h]), CanonicalOwnerValue(h)))
	}
	a, err := f.old.Encode()
	mustEnvironment(t, err)
	rows = append(rows, eisMutation(0, []byte{2}, a))
	for i, g := range []uint64{11, 13} {
		root := RootBindingV1{DatabaseID: [32]byte{7}, CommitmentVersion: 1, ChainID: [32]byte{4}, GenesisHash: f.hashes[0], RootDigest: treeEmptyDigest(t), Assurance: TreeAssuranceV1{Kind: 1}}
		if i == 0 {
			root.Endpoint = TreeEndpointV1{Kind: 1, Height: height, BlockHash: f.hashes[height], CumulativeChainwork: eisWork(height)}
		}
		if i == 1 && lag != 0 {
			root.Endpoint = TreeEndpointV1{Kind: 1, Height: lag - 1, BlockHash: f.hashes[lag-1], CumulativeChainwork: eisWork(lag - 1)}
		}
		value, encodeErr := root.Encode()
		mustEnvironment(t, encodeErr)
		rows = append(rows, eisMutation(0, tsCounterKey(g), make([]byte, 16)), eisMutation(0, binary.BigEndian.AppendUint64([]byte{0x11}, g), value))
	}
	eisSeed(t, f, rows)
	eisQualify(t, f)
	return f
}

func eisQualify(t *testing.T, f *eisFixture, additional ...func(*Reader) error) {
	t.Helper()
	err, cached := f.s.StartupVerifyCanonicalV1(func(r *Reader) (StartupCanonicalCompletionV1, error) {
		a, present, err := r.ReadTreeAuthorityV1()
		if err != nil || !present || a.Authority.ActiveGenerationID != 11 || a.LagGenerationID != 13 {
			return 0, errors.New("seeded pair authority mismatch")
		}
		for _, g := range []uint64{11, 13} {
			root, found, rootErr := r.ReadTreeRootBindingV1(g)
			if rootErr != nil || !found || root.DatabaseID != ([32]byte{7}) {
				return 0, errors.New("seeded binding mismatch")
			}
			count := uint64(0)
			if root.Endpoint.Kind == 1 {
				count = root.Endpoint.Height + 1
			}
			for h := uint64(0); h < count; h++ {
				forward, exists, readErr := r.Get(TreeSchemaV1DBIs()[2], eisHeight(g, h))
				if readErr != nil || !exists || len(forward) != 104 || [32]byte(forward[:32]) != f.hashes[h] {
					return 0, errors.New("seeded forward mismatch")
				}
				owner, exists, readErr := r.Get(TreeSchemaV1DBIs()[7], eisOwner(g, f.hashes[h]))
				if readErr != nil || !exists || !bytes.Equal(owner, CanonicalOwnerValue(h)) {
					return 0, errors.New("seeded reverse mismatch")
				}
				header, exists, readErr := r.Get(TreeSchemaV1DBIs()[3], f.hashes[h][:])
				if readErr != nil || !exists || sha3.Sum256(header) != f.hashes[h] {
					return 0, errors.New("seeded header mismatch")
				}
			}
			prefix := eisHeight(g, 0)[:8]
			for _, rank := range []uint8{2, 7} {
				var after []byte
				var actual uint64
				for {
					page, pageErr := r.PrefixPage(TreeSchemaV1DBIs()[rank], prefix, after, 256, 65596)
					if pageErr != nil {
						return 0, pageErr
					}
					actual += uint64(len(page.Rows))
					if page.Stop == PrefixPageExhausted {
						break
					}
					after = page.Rows[len(page.Rows)-1].Key
				}
				if actual != count {
					return 0, errors.New("seeded canonical keyset mismatch")
				}
			}
		}
		for _, check := range additional {
			if err := check(r); err != nil {
				return 0, err
			}
		}
		return 1, nil
	})
	if err != nil || cached {
		t.Fatalf("actual startup qualification: %v/%v", err, cached)
	}
}

// Capture uses the ordinary authority codec, including its frozen SIDE union.
// No source answer or inventory token is supplied by this fixture.
func eisCapture(t *testing.T, f *eisFixture, d, c int, rolling, reuse bool) TreePairV1 {
	t.Helper()
	boundary := f.height - uint64(d)
	var old, next []AuthorityPointV1
	for i := range d {
		h := f.height - uint64(i)
		old = append(old, AuthorityPointV1{Height: h, BlockHash: f.hashes[h]})
	}
	parent := f.hashes[boundary]
	var rows, targets []Mutation
	for i := range c {
		h := boundary + uint64(i) + 1
		header := eisHeader(h, parent, 9)
		hash := sha3.Sum256(header)
		next = append(next, AuthorityPointV1{Height: h, BlockHash: hash})
		member := []Mutation{eisMutation(3, hash[:], header), eisMutation(4, hash[:], header), eisMutation(6, eisHeight(21, h), eisChain(hash, parent, h))}
		if c == 1 {
			targets = append(targets, member...)
			if reuse {
				rows = append(rows, member[:2]...)
				targets = targets[2:]
			}
		} else {
			rows = append(rows, member...)
		}
		parent = hash
	}
	tip := next[len(next)-1]
	count := c
	if rolling {
		count = 1439
		f.old.Authority.Phase = 2
		f.old.Authority.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 4, GenerationID: 21, FirstHeight: boundary + 1, NextHeight: boundary + 1, LastHeight: boundary + 1}}}
	}
	side := &SelectedSideV1{GenerationID: 21, F: boundary, TipHeight: tip.Height, TipHash: tip.BlockHash, CumulativeChainwork: eisWork(tip.Height), RowCount: uint16(count), LogicalBytes: uint64(count) * 148}
	if c > 1 {
		f.old.Authority.SelectedSide = side
		f.old.Authority.NextGenerationID = 22
		control := eisMutation(0, []byte{2}, eiEncoded(t, f.old))
		control.BeforePresent = true
		rows = append(rows, control)
	}
	if len(rows) != 0 {
		eisSeed(t, f, rows)
	}
	entry := f.old
	entry.Authority.Phase, entry.Authority.Lifecycle, entry.Authority.Cleanup, entry.Authority.SelectedSide = 4, 2, nil, nil
	entry.Authority.NextGenerationID = 22
	stage := OrdinaryStageDisconnectV1
	if d == 0 {
		stage = OrdinaryStageConnectV1
	}
	entry.Authority.Ordinary = &OrdinaryApplyV1{Stage: stage, Target: tip, OldSuffix: old, NewSuffix: next, CarriedCleanup: f.old.Authority.Cleanup, CapturedSelectedSide: side}
	control := eisMutation(0, []byte{2}, eiEncoded(t, entry))
	control.BeforePresent = true
	return TreePairV1{Mutations: append([]Mutation{control}, targets...)}
}

func eisInvoke(t *testing.T, f *eisFixture, pair TreePairV1, visit func(EntryInventoryRowV1) error) (tsResult, EntryInventoryV1, *EntryInventoryFailureV1, error) {
	t.Helper()
	var token EntryInventoryV1
	var failure *EntryInventoryFailureV1
	var visitErr error
	var result tsResult
	mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		result = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
			token = eiPrepare(t, r, a, pair)
			failure, visitErr = r.VisitEntryInventoryV1(token, visit)
			if token.scope.completed != (failure == nil && visitErr == nil) {
				t.Fatal("completion differs from the whole no-GEN outcome")
			}
			// Omit the token: PREPARED alone must refuse even completed queries.
			return TreeOperationV1{Pair: pair}, nil
		})
		return nil
	}))
	if reservationLive(f.o) != 0 {
		t.Fatal("source operation retained its hold")
	}
	result.tuple(t, 1, 1, -1)
	return result, token, failure, visitErr
}

func eisSuccess(t *testing.T, f *eisFixture, pair TreePairV1, visit func(EntryInventoryRowV1) error) {
	t.Helper()
	entry, err := DecodeTreeAuthorityV1(pair.Mutations[0].Literal)
	mustEnvironment(t, err)
	result, token, failure, err := eicInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
		eisPayload(t, f, entry.Authority.Ordinary.NewSuffix, row)
		return visit(row)
	})
	if failure != nil || err != nil || !token.scope.completed {
		t.Fatalf("full query %+v/%v/completed%v", failure, err, token.scope.completed)
	}
	result.tuple(t, 2, 3, -1)
	mustEnvironment(t, result.err)
	for _, m := range pair.Mutations {
		tsRead(t, f.s, m.DBI, m.Key, m.Literal)
	}
	if f.s.state != storeOPEN {
		t.Fatal("prepared successful query changed Store state")
	}
	tsFollowing(t, f.s, f.o)
}

func eisPayload(t *testing.T, f *eisFixture, points []AuthorityPointV1, row EntryInventoryRowV1) {
	t.Helper()
	if row.Source < 5 {
		return
	}
	if row.Source > 15 {
		t.Fatal("unsupported successful inventory source")
	}
	artifact := [11]uint8{8, 6, 7, 7, 8, 8, 6, 7, 9, 7, 9}[row.Source-5]
	role, generation := uint8(1), uint64(11)
	if row.Source >= 11 {
		role, generation = 0, 21
	}
	if row.Artifact != artifact || row.Role != role || row.Generation != generation || row.IndexCount != 0 || row.Node != (TreeNodeIDV1{}) || row.Projection != 0 {
		t.Fatalf("source%d output tuple %+v", row.Source, row)
	}
	if row.Source == 6 {
		if row.Count != f.height+1 || row.Height != 0 || row.Hash != ([32]byte{}) || row.Key != nil || row.Present || row.Length != 0 {
			t.Fatalf("nonphysical header group payload %+v", row)
		}
		return
	}
	if !row.Present || row.Count != 0 {
		t.Fatalf("physical source payload %+v", row)
	}
	if row.Source <= 10 {
		if row.Height > f.height {
			t.Fatal("canonical source height outside the qualified domain")
		}
		if row.Hash != f.hashes[row.Height] {
			t.Fatal("canonical/owed/O hash differs from independent persisted fixture")
		}
	} else {
		if row.Height < points[0].Height || row.Height-points[0].Height >= uint64(len(points)) {
			t.Fatal("captured source height outside the admitted N")
		}
		if row.Hash != points[row.Height-points[0].Height].BlockHash {
			t.Fatal("captured source hash differs from the admitted immutable N")
		}
	}
	switch artifact {
	case 6, 7:
		if !bytes.Equal(row.Key, row.Hash[:]) || row.Length < 148 || artifact == 6 && row.Length != 148 {
			t.Fatal("header/body physical key or length changed")
		}
	case 8:
		if !bytes.HasPrefix(row.Key, row.Hash[:]) || len(row.Key) != 33 && len(row.Key) != 77 || len(row.Key) == 33 && row.Length != 33 {
			t.Fatal("raw compact-undo physical key or length changed")
		}
	case 9:
		if !bytes.Equal(row.Key, eisHeight(21, row.Height)) || row.Length != 104 {
			t.Fatal("captured SideLink physical key or length changed")
		}
	}
}

func TestEntryInventoryV1(t *testing.T) {
	t.Run("ArchiveComplete", eisArchive)
	t.Run("Order", eisOwed)
	t.Run("UnionOwners", eisRolling)
	t.Run("FreshC1", eisProspective)
	t.Run("GENCompletion", eisGEN)
	t.Run("native-and-literal-ReadAt", eisReads)
	t.Run("admitted-boundaries", eisBoundaries)
	t.Run("body-window-backing", eisBodyWindows)
	t.Run("OwnProjection", eicProjection)
	t.Run("LowerBodyOwner", eicLowerBody)
	t.Run("NodeRemnant", eicNodes)
	t.Run("TokenBinding", eicToken)
	t.Run("Lifetime", eicLifetime)
	if unsafe.Sizeof(entryWalkV1{}) != 80 || unsafe.Sizeof(entryCursorV1{}) != 80 || unsafe.Sizeof(entryStreamV1{}) != 184 {
		t.Fatal("fixed source walker/cursor/stream differs from 80/80/184")
	}
}

func eisArchive(t *testing.T) {
	f := eisNew(t, 17000, 2, nil)
	pair := eisCapture(t, f, 1, 1, false, false)
	var count, last uint64
	counts := [16]int{}
	eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
		if row.Source >= 16 || row.Projection != 0 || row.Node != (TreeNodeIDV1{}) {
			t.Fatalf("unexpected non-GEN payload %+v", row)
		}
		counts[row.Source]++
		if row.Source == 7 {
			if row.Height != count || row.Hash != f.hashes[count] || row.Length != 148 || !row.Present || row.Artifact != 7 || row.Role != 1 || row.Generation != 11 || !bytes.Equal(row.Key, f.hashes[count][:]) {
				t.Fatalf("ARCHIVE literal source%d at%d: %+v", count, row.Height, row)
			}
			count++
			last = row.Height
		}
		if row.Source == 6 {
			if row.Count != 17001 || row.Key != nil || row.Present || row.Length != 0 || row.Height != 0 || row.Hash != ([32]byte{}) || row.IndexCount != 0 {
				t.Fatalf("group-only source6 %+v", row)
			}
			eiRowInput(t, row, "ENTRY inventory row is not active")
		}
		return nil
	})
	if count != 17001 || last != 17000 || counts != ([16]int{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 17001, 9: 1439, 11: 1, 12: 1, 13: 1}) {
		t.Fatalf("ARCHIVE full frontier %d/%d/%v", count, last, counts)
	}
}

func eisOwed(t *testing.T) {
	spans := []CleanupSpanV1{{Kind: 2, GenerationID: 11, FirstHeight: 0, NextHeight: 3, LastHeight: 4}, {Kind: 3, GenerationID: 11, FirstHeight: 0, NextHeight: 2, LastHeight: 3}}
	f := eisNew(t, 15125, 1, spans)
	// UNDO duties below U need their actual manifests; these are not O aliases.
	for _, h := range []uint64{2, 3} {
		eisSeed(t, f, []Mutation{eisMutation(5, UndoManifestKey(f.hashes[h]), UndoManifestValue(h, [16]byte{}, 0, 0))})
	}
	pair := eisCapture(t, f, 2, 2, false, false)
	phase, last := uint8(0), uint64(0)
	counts := [16]int{}
	eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
		counts[row.Source]++
		if row.Source <= 4 {
			return nil
		}
		if row.Source < phase && (phase != 13 || row.Source != 11) {
			t.Fatalf("source order %d -> %d", phase, row.Source)
		}
		if row.Source != phase {
			last = row.Height
		} else if row.Source == 5 {
			if row.Height+1 != last {
				t.Fatal("O undo is not tip down")
			}
			last = row.Height
		} else if row.Source >= 7 && row.Source <= 10 {
			if row.Height != last+1 {
				t.Fatalf("source%d ascending %d -> %d", row.Source, last, row.Height)
			}
			last = row.Height
		}
		phase = row.Source
		if row.Source == 7 && counts[7] == 1 && row.Height != 1 {
			t.Fatal("L_body substituted service B for APPLIED LAG+1")
		}
		if row.Source == 8 && row.Height != uint64(counts[8]+2) {
			t.Fatal("nondefault BLOCKS next_height not observed")
		}
		if row.Source == 10 && row.Height != uint64(counts[10]+1) {
			t.Fatal("nondefault UNDO next_height not observed")
		}
		return nil
	})
	if counts[5] != 2 || counts[8] != 2 || counts[10] != 2 || counts[9] != 1438 || counts[11] != 2 || counts[12] != 2 || counts[13] != 2 {
		t.Fatalf("distinct owed/O/capture counts %v", counts)
	}
}

func eisRolling(t *testing.T) {
	f := eisNew(t, 3, 1, nil)
	pair := eisCapture(t, f, 1, 1440, true, false)
	counts := [16]int{}
	index, position := uint64(0), 0
	eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
		counts[row.Source]++
		if row.Source < 11 {
			return nil
		}
		want := [3]uint8{11, 12, 13}
		if index == 0 {
			want = [3]uint8{11, 14, 15}
		}
		if row.Source != want[position] || row.Height != index+3 || row.Role != 0 || row.Generation != 21 || !row.Present || row.IndexCount != 0 || row.Count != 0 {
			t.Fatalf("captured N%d position%d %+v", index, position, row)
		}
		if position == 2 && (row.Artifact != 9 || row.Length != 104 || !bytes.Equal(row.Key, eisHeight(21, index+3))) {
			t.Fatal("SideLink is not the actual 16/104 physical row")
		}
		position++
		if position == 3 {
			position = 0
			index++
		}
		return nil
	})
	if index != 1440 || counts[11] != 1440 || counts[12] != 1439 || counts[13] != 1439 || counts[14] != 1 || counts[15] != 1 {
		t.Fatalf("rolling1439+SIDE1 union %v", counts)
	}
}

func eisProspective(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse%v", reuse), func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, reuse)
			for _, m := range pair.Mutations[1:] {
				tsRead(t, f.s, m.DBI, m.Key, nil)
			}
			var count int
			eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
				if row.Source >= 11 {
					count++
					if row.Height != 3 || row.Generation != 21 || row.Role != 0 {
						t.Fatal("prospective/reused source identity changed")
					}
				}
				return nil
			})
			if count != 3 {
				t.Fatal("fresh/reused source omitted")
			}
		})
	}
	for _, owner := range []struct{ rank, index, source, artifact, last uint8 }{{3, 1, 11, 6, 9}, {4, 2, 12, 7, 11}, {6, 3, 13, 9, 9}} {
		for _, same := range []bool{false, true} {
			if !same && owner.rank != 6 {
				continue // malformed hash-bound rows require the native fixture owner
			}
			t.Run(fmt.Sprintf("present-rank%d-rewrite-same%v", owner.rank, same), func(t *testing.T) {
				f := eisNew(t, 3, 1, nil)
				pair := eisCapture(t, f, 1, 1, false, false)
				m := pair.Mutations[owner.index]
				value := bytes.Clone(m.Literal)
				if !same {
					value[len(value)-1] ^= 1
				}
				eisSeed(t, f, []Mutation{eisMutation(owner.rank, m.Key, value)})
				last := uint8(0)
				result, _, failure, err := eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
					last = row.Source
					return nil
				})
				eiInput(t, result.err)
				if last != owner.last {
					t.Fatal("present rewrite reached a later source")
				}
				if same {
					eiInput(t, err)
					if failure != nil {
						t.Fatal("identical unsupported rewrite invented physical failure")
					}
				} else if err != nil || failure == nil || failure.Source != owner.source || failure.Artifact != owner.artifact || failure.Observation != 4 || failure.SourceError != nil || failure.Role != 0 || failure.Generation != 21 || failure.Height != 3 || !bytes.Equal(failure.Key, m.Key) {
					t.Fatalf("differing required bytes lost positive failure %+v/%v", failure, err)
				}
			})
		}
	}
}

func eisGEN(t *testing.T) {
	for _, application := range []string{"nil", "direct", "wrapped", "typed-nil"} {
		t.Run(application, func(t *testing.T) {
			f := eisNew(t, 3, 1, []CleanupSpanV1{{Kind: 1, GenerationID: 5}})
			pair := eisCapture(t, f, 1, 1, false, false)
			marker := errors.New("supported visitor result")
			var app error
			last := uint8(0)
			result, token, failure, err := eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
				last = row.Source
				if row.Source == 13 {
					switch application {
					case "direct":
						app = marker
					case "wrapped":
						app = fmt.Errorf("visitor: %w", marker)
					case "typed-nil":
						var typed *nilPointerError
						app = typed
					}
				}
				return app
			})
			eiInput(t, result.err)
			if failure != nil || token.scope.completed != (app == nil) {
				t.Fatalf("GEN completion/frontier %+v/%v/%d", failure, token.scope.completed, last)
			}
			if app == nil {
				if err != nil || last != 24 {
					t.Fatalf("complete empty GEN: %v/last%d", err, last)
				}
			} else if any(err) != any(app) {
				t.Fatal("late GEN refusal overwrote earlier visitor interface")
			}
		})
	}
	t.Run("returned-refusal", func(t *testing.T) {
		f := eisNew(t, 3, 1, []CleanupSpanV1{{Kind: 1, GenerationID: 5}})
		pair := eisCapture(t, f, 1, 1, false, false)
		last := uint8(0)
		mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			result := tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
				token := eiPrepare(t, r, a, pair)
				failure, err := r.VisitEntryInventoryV1(token, func(row EntryInventoryRowV1) error {
					last = row.Source
					return nil
				})
				if failure != nil || !token.scope.completed || last != 24 || err != nil {
					t.Fatal("complete GEN changed its final frontier")
				}
				pair.EntryInventory = &token
				return TreeOperationV1{Pair: pair}, nil
			})
			result.tuple(t, 2, 3, -1)
			mustEnvironment(t, result.err)
			return nil
		}))
		if reservationLive(f.o) != 0 || f.s.state != storeOPEN {
			t.Fatal("returned pure GEN refusal did not cleanly release")
		}
		tsFollowing(t, f.s, f.o)
	})
}

func eisReads(t *testing.T) {
	f := eisNew(t, 3, 1, nil)
	pair := eisCapture(t, f, 1, 1, false, false)
	var expired EntryInventoryRowV1
	eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
		if row.Source != 5 && row.Source != 7 && row.Source < 11 {
			return nil
		}
		want := f.headers[row.Height]
		if row.Source == 5 {
			want = UndoManifestValue(row.Height, [16]byte{}, 0, 0)
		} else if row.Source >= 11 {
			for _, m := range pair.Mutations[1:] {
				if bytes.Equal(row.Key, m.Key) {
					want = m.Literal
				}
			}
		}
		eiReadBoundaries(t, row, want)
		copyRow := row
		copyRow.Key, copyRow.Source, copyRow.Artifact, copyRow.Length, copyRow.Present = []byte{2}, 255, 255, 0, false
		dst := bytes.Repeat([]byte{0xa5}, len(want)+1)
		n, err := copyRow.ReadAt(dst, 0)
		if n != len(want) || !treeSameErrorV1(err, io.EOF) || !bytes.Equal(dst[:n], want) || dst[n] != 0xa5 {
			t.Fatal("metadata value copy redirected native/literal source")
		}
		expired = row
		return nil
	})
	eiRowInput(t, expired, "ENTRY inventory row is not active")
}

func eisBoundaries(t *testing.T) {
	for _, counts := range [][2]int{{0, 2}, {2, 1}, {2, 3}} {
		t.Run(fmt.Sprint(counts), func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, counts[0], counts[1], false, false)
			old, next := 0, 0
			eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
				if row.Source == 5 {
					old++
				}
				if row.Source == 11 {
					next++
				}
				return nil
			})
			if old != counts[0] || next != counts[1] {
				t.Fatalf("D/N boundary %d/%d, want %v", old, next, counts)
			}
		})
	}
	for _, variant := range []string{"wrong-O-descriptor", "header-parent", "link-parent", "link-zero-work", "link-tip-work"} {
		t.Run(variant, func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			before := eiEncoded(t, f.old)
			entry, err := DecodeTreeAuthorityV1(pair.Mutations[0].Literal)
			mustEnvironment(t, err)
			switch variant {
			case "wrong-O-descriptor":
				entry.Authority.Ordinary.OldSuffix[0].BlockHash = [32]byte{0x44}
			case "header-parent":
				pair.Mutations[1].Literal[4] ^= 1
				hash := sha3.Sum256(pair.Mutations[1].Literal)
				for i := 1; i <= 2; i++ {
					pair.Mutations[i].Key = bytes.Clone(hash[:])
				}
				pair.Mutations[2].Literal = bytes.Clone(pair.Mutations[1].Literal)
				copy(pair.Mutations[3].Literal[:32], hash[:])
				entry.Authority.Ordinary.NewSuffix[0].BlockHash = hash
				entry.Authority.Ordinary.Target.BlockHash = hash
				entry.Authority.Ordinary.CapturedSelectedSide.TipHash = hash
			case "link-parent":
				pair.Mutations[3].Literal[32] ^= 1
			case "link-zero-work":
				clear(pair.Mutations[3].Literal[64:])
			case "link-tip-work":
				pair.Mutations[3].Literal[103] = 9 // valid nonzero work, wrong admitted tip
			}
			pair.Mutations[0].Literal = eiEncoded(t, entry)
			last := uint8(0)
			result, _, failure, visitErr := eisInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
				last = row.Source
				return nil
			})
			eiInput(t, result.err)
			want := uint8(9)
			if variant == "wrong-O-descriptor" {
				want = 4
			}
			if failure != nil || last != want {
				t.Fatalf("pure identity/work refusal invented source failure %+v/%d", failure, last)
			}
			eiInput(t, visitErr)
			(&eiScene{s: f.s, o: f.o, pair: pair, oldBytes: before}).unchanged(t)
		})
	}
}

func eisBodyWindows(t *testing.T) {
	for _, literal := range []bool{false, true} {
		t.Run(fmt.Sprintf("literal%v", literal), func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			body, source, height := bytes.Clone(f.headers[0]), uint8(7), uint64(0)
			if literal {
				body, source, height = bytes.Clone(pair.Mutations[2].Literal), 12, 3
			}
			for i := range 65536 {
				body = append(body, byte(i%251))
			}
			if literal {
				pair.Mutations[2].Literal = body
				entry, err := DecodeTreeAuthorityV1(pair.Mutations[0].Literal)
				mustEnvironment(t, err)
				entry.Authority.Ordinary.CapturedSelectedSide.LogicalBytes = uint64(len(body))
				pair.Mutations[0].Literal = eiEncoded(t, entry)
			} else {
				remove := Mutation{DBI: TreeSchemaV1DBIs()[4], Key: bytes.Clone(f.hashes[0][:]), BeforePresent: true, AfterKind: 1}
				eisSeed(t, f, []Mutation{remove})
				eisSeed(t, f, []Mutation{eisMutation(4, f.hashes[0][:], body)})
			}
			reached := false
			eisSuccess(t, f, pair, func(row EntryInventoryRowV1) error {
				if row.Source == source && row.Height == height {
					reached = true
					dst := make([]byte, 65536)
					n, err := row.ReadAt(dst, 0)
					if row.Length != 65684 || n != 65536 || err != nil || !bytes.Equal(dst, body[:65536]) {
						t.Fatal("native/literal full window changed")
					}
					dst = bytes.Repeat([]byte{0xa5}, 200)
					n, err = row.ReadAt(dst, 65536)
					if n != 148 || !treeSameErrorV1(err, io.EOF) || !bytes.Equal(dst[:148], body[65536:]) || !bytes.Equal(dst[148:], bytes.Repeat([]byte{0xa5}, 52)) {
						t.Fatal("native/literal nonzero offset EOF boundary changed")
					}
				}
				return nil
			})
			if !reached {
				t.Fatal("body window source was omitted")
			}
		})
	}
}

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
			prefixDone := errors.New("four controls observed")
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
					if calls == 4 {
						return prefixDone
					}
					return nil
				})
				if failure != nil || calls != 4 || token.scope.completed {
					t.Fatalf("prefix completion %d/%+v/%v", calls, failure, token.scope.completed)
				}
				if any(err) != any(prefixDone) {
					t.Fatal("control visitor sentinel identity changed")
				}
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
	if !reflect.ValueOf(s.decode).IsZero() || !reflect.ValueOf(s.inspection).IsZero() || !reflect.ValueOf(s.authority).IsZero() || !reflect.ValueOf(s.endpoints).IsZero() || !reflect.ValueOf(s.rootControl).IsZero() {
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
	if unsafe.Sizeof(Reader{}) != 216 || unsafe.Sizeof(entryInventoryStateV1{}) != 3192 || unsafe.Sizeof(entryRowAccessV1{}) != 80 || unsafe.Sizeof(EntryInventoryRowV1{}) != 208 || unsafe.Sizeof(EntryInventoryFailureV1{}) != 120 || unsafe.Sizeof(treePublicEntryV1{}) != 40 || unsafe.Sizeof(operationHold{}) != 24 || unsafe.Sizeof(TreeOperationV1{}) != 88 || unsafe.Sizeof(treePlanV1{}) != 96 {
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

// eicInvoke exercises Prepare/Visit/attach through the real native owner and sole clone.
func eicInvoke(t *testing.T, f *eisFixture, pair TreePairV1, visit func(EntryInventoryRowV1) error) (tsResult, EntryInventoryV1, *EntryInventoryFailureV1, error) {
	t.Helper()
	var token EntryInventoryV1
	var failure *EntryInventoryFailureV1
	var visitErr error
	var result tsResult
	mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		result = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
			token = eiPrepare(t, r, a, pair)
			failure, visitErr = r.VisitEntryInventoryV1(token, visit)
			if failure == nil && visitErr == nil {
				if !token.scope.completed || token.scope.stream != nil || token.scope.access.active || token.scope.access.reader != nil || token.scope.access.key != nil || token.scope.access.image != (updateImage{}) {
					t.Fatal("completed public walk retained a source before owned rebind")
				}
			}
			attached := token // a token value copy shares the genuine preparation
			pair.EntryInventory = &attached
			return TreeOperationV1{Pair: pair}, visitErr
		})
		return nil
	}))
	if reservationLive(f.o) != 0 {
		t.Fatal("complete ENTRY retained its operation hold")
	}
	return result, token, failure, visitErr
}

// eicProjection distinguishes raw Invalid from prior dedup at the full native operation boundary.
func eicProjection(t *testing.T) {
	for _, variant := range []string{"missing-header", "proven", "prior-owner", "prior-parent-invalid", "later-parent-invalid", "prospective-header"} {
		t.Run(variant, func(t *testing.T) {
			spans := []CleanupSpanV1{{Kind: 1, GenerationID: 5}}
			if variant == "prior-owner" || variant == "prior-parent-invalid" || variant == "later-parent-invalid" {
				spans = append(spans, CleanupSpanV1{Kind: 1, GenerationID: 7})
			}
			f := eisNew(t, 3, 1, spans)
			pair := eisCapture(t, f, 1, 1, false, false)
			header := eisHeader(9, [32]byte{0x77}, 0x61)
			hash, height := sha3.Sum256(header), uint64(9)
			if variant == "prospective-header" {
				header, height = pair.Mutations[1].Literal, 3
				hash = [32]byte(pair.Mutations[1].Key)
			}
			parent := [32]byte(header[4:36])
			dependentGeneration := uint64(5)
			if variant == "prior-parent-invalid" {
				dependentGeneration = 7
			}
			var rows []Mutation
			for _, span := range spans {
				rows = append(rows, eisMutation(0, tsCounterKey(span.GenerationID), make([]byte, 16)))
				forwardParent := parent
				if variant == "prior-parent-invalid" && span.GenerationID == 5 || variant == "later-parent-invalid" && span.GenerationID == 7 {
					forwardParent[0] ^= 1
				}
				rows = append(rows, eisMutation(2, eisHeight(span.GenerationID, height), eisChain(hash, forwardParent, height)), eisMutation(7, eisOwner(span.GenerationID, hash), CanonicalOwnerValue(height)))
			}
			if variant != "missing-header" && variant != "prospective-header" {
				rows = append(rows, eisMutation(3, hash[:], header), eisMutation(4, hash[:], header))
			}
			rows = append(rows, eisMutation(5, UndoManifestKey(hash), UndoManifestValue(height, [16]byte{}, 0, 0)))
			eisSeed(t, f, rows)
			counts := [25]int{}
			var projection uint8
			result, token, failure, visitErr := eicInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
				counts[row.Source]++
				if row.Source < 16 {
					return nil
				}
				if row.Role != 0 || row.Count != 0 || row.IndexCount != 0 || row.Node != (TreeNodeIDV1{}) {
					t.Fatalf("GEN inherited sibling payload %+v", row)
				}
				if row.Source == 17 {
					if counts[17] > len(spans) {
						t.Fatal("duplicate obsolete index observation")
					}
					g := spans[counts[17]-1].GenerationID
					if row.Artifact != 4 || row.Generation != g || !row.Present || row.Length != 104 || !bytes.Equal(row.Key, eisHeight(g, height)) {
						t.Fatalf("obsolete index lost its exact source payload %+v", row)
					}
					projection = row.Projection
					if variant == "missing-header" || variant == "prior-parent-invalid" && g == 5 || variant == "later-parent-invalid" && g == 7 {
						if row.Projection != 1 || row.Hash != ([32]byte{}) || row.Height != 0 {
							t.Fatal("invalid projection retained a dependent identity")
						}
					} else if row.Projection != 3 || row.Height != height || row.Hash != hash {
						t.Fatalf("own forward/header/reverse did not establish exact Proven identity %+v", row)
					}
				} else if row.Projection != 0 {
					t.Fatal("projection tag leaked into a sibling source")
				}
				if row.Source >= 20 && row.Source <= 22 {
					if row.Generation != dependentGeneration || row.Height != height || row.Hash != hash || row.Artifact != [3]uint8{6, 7, 8}[row.Source-20] {
						t.Fatalf("dependent source escaped its complete own projection %+v", row)
					}
				}
				return nil
			})
			result.tuple(t, 2, 3, -1)
			mustEnvironment(t, result.err)
			if failure != nil || visitErr != nil || !token.scope.completed {
				t.Fatalf("complete GEN did not commit %+v/%v", failure, visitErr)
			}
			switch variant {
			case "missing-header":
				if projection != 1 || counts[20]+counts[21]+counts[22] != 0 {
					t.Fatal("invalid header reached reverse or dependent source")
				}
			case "prospective-header":
				if counts[11] != 1 || counts[20] != 0 || counts[21] != 0 || counts[22] != 1 || projection != 3 {
					t.Fatalf("owned prospective header failed to enable own undo: %v", counts)
				}
			default:
				if counts[20] != 1 || counts[21] != 1 || counts[22] != 1 || counts[17] != len(spans) {
					t.Fatalf("earlier complete owner was omitted or duplicated: %v", counts)
				}
			}
			if f.s.state != storeOPEN {
				t.Fatal("raw projection changed native disposition")
			}
			for _, m := range pair.Mutations {
				tsRead(t, f.s, m.DBI, m.Key, m.Literal)
			}
			tsFollowing(t, f.s, f.o)
		})
	}
}

func eicNodes(t *testing.T) {
	f := eisNew(t, 3, 1, []CleanupSpanV1{{Kind: 1, GenerationID: 5}, {Kind: 1, GenerationID: 7}})
	pair := eisCapture(t, f, 1, 1, false, false)
	var controls [][3]uint64
	result, _, failure, err := eicInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
		if row.Source >= 16 {
			controls = append(controls, [3]uint64{uint64(row.Source), uint64(row.Artifact), row.Generation})
			if row.Present || row.Length != 0 || row.Node.Kind != 0 || row.Projection != 0 || row.Height != 0 || row.Hash != ([32]byte{}) {
				t.Fatal("empty generation fabricated a physical row")
			}
		}
		return nil
	})
	result.tuple(t, 2, 3, -1)
	mustEnvironment(t, result.err)
	if err != nil || failure != nil || !reflect.DeepEqual(controls, [][3]uint64{{19, 2, 5}, {24, 11, 5}, {19, 2, 7}, {24, 11, 7}}) {
		t.Fatalf("ascending contiguous GEN controls/root-last: %v/%+v/%v", controls, failure, err)
	}
}

func eicToken(t *testing.T) {
	for _, mode := range []string{"complete", "missing", "zero", "incomplete", "incomplete-proof", "ordinary-shape", "failed-visitor", "changed-authority", "changed-consulted", "proof", "primitive", "discard-after-complete", "discard-after-prepare"} {
		t.Run(mode, func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			var token EntryInventoryV1
			var result tsResult
			marker := errors.New("discarded ENTRY")
			proofCalls, sourceCalls := 0, 0
			mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				result = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
					token = eiPrepare(t, r, a, pair)
					if mode == "discard-after-prepare" {
						return TreeOperationV1{}, marker
					}
					if mode != "incomplete" && mode != "incomplete-proof" {
						failure, err := r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error {
							if mode == "failed-visitor" {
								return marker
							}
							return nil
						})
						if failure != nil || mode != "failed-visitor" && err != nil || mode == "failed-visitor" && any(err) != any(marker) {
							t.Fatalf("token preparation source outcome %+v/%v", failure, err)
						}
					}
					op := TreeOperationV1{Pair: pair}
					op.Pair.EntryInventory = &token
					switch mode {
					case "ordinary-shape":
						op.Pair.Mutations = nil
					case "missing":
						op.Pair.EntryInventory = nil
					case "zero":
						zero := EntryInventoryV1{}
						op.Pair.EntryInventory = &zero
					case "changed-authority":
						op.Pair.Mutations = append([]Mutation(nil), pair.Mutations...)
						next, err := DecodeTreeAuthorityV1(pair.Mutations[0].Literal)
						mustEnvironment(t, err)
						next.Authority.NextGenerationID++
						op.Pair.Mutations[0].Literal = eiEncoded(t, next)
					case "changed-consulted":
						op.Pair.Consulted = []ConsultedRow{{DBI: TreeSchemaV1DBIs()[0], Key: tsCounterKey(11)}}
					case "proof", "incomplete-proof":
						op.Proof = func(*TreeDeltaReportV1) error {
							proofCalls++
							return nil
						}
					case "primitive":
						p, body := tsPrimitive(t, tsSource(func(TreePositionV1, *Reader, *TreeDeltaSinkV1) error {
							sourceCalls++
							return nil
						}))
						p.Generation = 11
						op.Primitives = []TreePrimitiveV1{p}
						op.Pair.Mutations = append(append([]Mutation(nil), pair.Mutations...), body)
						sort.Slice(op.Pair.Mutations, func(i, j int) bool { return updateOrdered(op.Pair.Mutations[i], op.Pair.Mutations[j]) })
					case "discard-after-complete":
						return TreeOperationV1{}, marker
					}
					return op, nil
				})
				return nil
			}))
			if mode == "complete" {
				result.tuple(t, 2, 3, -1)
				mustEnvironment(t, result.err)
				tsRead(t, f.s, TreeSchemaV1DBIs()[0], []byte{2}, pair.Mutations[0].Literal)
			} else {
				result.tuple(t, 1, 1, -1)
				switch mode {
				case "proof", "ordinary-shape":
					tsRefusal(t, result, false)
				case "discard-after-complete", "discard-after-prepare":
					if any(result.err) != any(marker) {
						t.Fatal("callback discard interface changed")
					}
				default:
					eiInput(t, result.err)
				}
				tsRead(t, f.s, TreeSchemaV1DBIs()[0], []byte{2}, eiEncoded(t, f.old))
			}
			if proofCalls != 0 || sourceCalls != 0 || reservationLive(f.o) != 0 || f.s.state != storeOPEN || !token.scope.retired || token.scope.stream != nil || token.scope.reader != nil || token.scope.access.active {
				t.Fatal("token/Proof/primitive refusal crossed an effect or retained a source")
			}
			tsFollowing(t, f.s, f.o)
		})
	}
}

func eicLifetime(t *testing.T) {
	t.Run("owned-descriptor-backing", func(t *testing.T) { eicOwnedBacking(t) })
	t.Run("closed-after-complete-before-grow", eicClosedComplete)
	for _, short := range []uint64{0, 1} {
		t.Run(fmt.Sprint(short), func(t *testing.T) {
			f := eisNew(t, 3, 1, nil)
			pair := eisCapture(t, f, 1, 1, false, false)
			pc := uint64(128 * len(pair.Mutations))
			for _, m := range pair.Mutations {
				pc += uint64(len(m.Key) + len(m.Literal))
			}
			e := uint64(8192) + 6*uint64(limitsForPage(f.s.config.PageSize).maxKey)
			filler := uint64(402653184) - e - pc + short
			var result tsResult
			var token EntryInventoryV1
			var kept EntryInventoryRowV1
			mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
				return a.WithReservation(filler, func() error {
					result = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
						token = eiPrepare(t, r, a, pair)
						failure, err := r.VisitEntryInventoryV1(token, func(row EntryInventoryRowV1) error {
							if reservationLive(f.o) != filler+e {
								t.Fatal("PC was charged before full ordinary admission")
							}
							kept = row
							return nil
						})
						if failure != nil || err != nil || !token.scope.completed || token.scope.stream != nil || token.scope.access.reader != nil || token.scope.access.key != nil {
							t.Fatal("public sources survived completed Visit into rebind")
						}
						pair.EntryInventory = &token
						return TreeOperationV1{Pair: pair}, nil
					})
					if reservationLive(f.o) != filler {
						t.Fatal("one hold did not release E and PC exactly once")
					}
					return nil
				})
			}))
			if short == 0 {
				result.tuple(t, 2, 3, -1)
				mustEnvironment(t, result.err)
			} else {
				result.tuple(t, 1, 1, -1)
				if any(result.err) != any(errOperationReservationCapacity) {
					t.Fatal("one-byte-short PC lost the original capacity singleton")
				}
				tsRead(t, f.s, TreeSchemaV1DBIs()[0], []byte{2}, eiEncoded(t, f.old))
			}
			eiRowInput(t, kept, "ENTRY inventory row is not active")
			if !token.scope.retired || token.scope.stream != nil || token.scope.access.image != (updateImage{}) || token.scope.reader != nil || reservationLive(f.o) != 0 {
				t.Fatal("native cleanup left an ENTRY read capability or reservation")
			}
			tsFollowing(t, f.s, f.o)
		})
	}
}

func eicClosedComplete(t *testing.T) {
	f := eisNew(t, 3, 1, nil)
	pair := eisCapture(t, f, 1, 1, false, false)
	ready, closeNow, closed := make(chan *OperationAccount, 1), make(chan struct{}), make(chan struct{})
	released := false
	release := func() {
		if !released {
			close(closeNow)
			released = true
		}
	}
	t.Cleanup(func() {
		release()
		eiAwait(t, closed)
	})
	go func() {
		defer close(closed)
		_ = f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
			ready <- a
			<-closeNow
			return nil
		})
	}()
	var account *OperationAccount
	select {
	case account = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("same-account operation did not enter")
	}
	var token EntryInventoryV1
	result := tsInvoke(f.s, account, func(r *Reader) (TreeOperationV1, error) {
		token = eiPrepare(t, r, account, pair)
		failure, err := r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error { return nil })
		if failure != nil || err != nil || !token.scope.completed {
			t.Fatal("account-close fixture did not complete its genuine sources")
		}
		release()
		eiAwait(t, closed)
		pair.EntryInventory = &token
		return TreeOperationV1{Pair: pair}, nil
	})
	result.tuple(t, 1, 1, -1)
	if any(result.err) != any(errOperationReservationInput) || !token.scope.retired || token.scope.stream != nil || reservationLive(f.o) != 0 || f.s.state != storeOPEN {
		t.Fatal("completed token reordered the existing post-admission closed-account singleton")
	}
	tsRead(t, f.s, TreeSchemaV1DBIs()[0], []byte{2}, eiEncoded(t, f.old))
	tsFollowing(t, f.s, f.o)
}

func eicOwnedBacking(t *testing.T, observe ...func(*entryInventoryStateV1, *treePlanV1, *Reader)) {
	f := eisNew(t, 3, 1, []CleanupSpanV1{{Kind: 1, GenerationID: 5}})
	pair := eisCapture(t, f, 1, 1, false, false)
	pair.Consulted = []ConsultedRow{{DBI: TreeSchemaV1DBIs()[0], Key: tsCounterKey(11)}}
	before := bytes.Clone(pair.Mutations[0].Literal)
	pc := uint64(128*len(pair.Mutations) + 48*len(pair.Consulted))
	for _, m := range pair.Mutations {
		pc += uint64(len(m.Key) + len(m.Literal))
	}
	pc += uint64(len(pair.Consulted[0].Key))
	sentinel := errors.New("owned rebind observed")
	var result tsResult
	var token EntryInventoryV1
	mustEnvironment(t, f.o.WithOperation(TreeOperation, func(a *OperationAccount) error {
		return a.WithReservation(pc, func() error {
			result = tsInvoke(f.s, a, func(r *Reader) (TreeOperationV1, error) {
				token = eiPrepare(t, r, a, pair)
				failure, err := r.VisitEntryInventoryV1(token, func(EntryInventoryRowV1) error { return nil })
				if failure != nil || err != nil || !token.scope.completed || token.scope.stream != nil {
					t.Fatal("owner-focused rebind did not receive a completed genuine descriptor")
				}
				plan := treeOwnPlanV1(TreeOperationV1{Pair: pair})
				token.scope.ownV1(&plan)
				s := token.scope
				if &s.nextBytes[0] != &plan.pair[0].literal[0] || &s.nextBytes[0] == &pair.Mutations[0].Literal[0] || s.mutations != nil || s.consulted != nil || !bytes.Equal(before, pair.Mutations[0].Literal) {
					t.Fatal("descriptor rebind retained the original Pair or acquired a second image")
				}
				base := uintptr(unsafe.Pointer(&plan.pair[0].literal[0]))
				end := base + uintptr(len(plan.pair[0].literal))
				for _, view := range [][]byte{s.inspection[1].old.encoded, s.inspection[1].new.encoded, s.inspection[1].carried.encoded} {
					at := uintptr(unsafe.Pointer(&view[0]))
					if at < base || at+uintptr(len(view)) > end {
						t.Fatal("nested prospective descriptor view did not rebind into the owned Pair")
					}
				}
				if plan.proof != nil || plan.report != nil || reservationLive(f.o) != pc+8192+6*r.maxKey {
					t.Fatal("ENTRY rebind acquired Proof/report/Undo backing or lost its funding interval")
				}
				for _, check := range observe {
					check(s, &plan, r)
				}
				return TreeOperationV1{}, sentinel
			})
			if reservationLive(f.o) != pc || !token.scope.retired || token.scope.nextBytes != nil {
				t.Fatal("test-owned plan funding ended before descriptor retirement")
			}
			return nil
		})
	}))
	result.tuple(t, 1, 1, -1)
	if any(result.err) != any(sentinel) || !bytes.Equal(before, pair.Mutations[0].Literal) {
		t.Fatal("rebind observation changed the immutable input or callback interface")
	}
	tsRead(t, f.s, TreeSchemaV1DBIs()[0], []byte{2}, eiEncoded(t, f.old))
	tsFollowing(t, f.s, f.o)
}

func eicLowerBody(t *testing.T) {
	for _, k := range []uint64{0, 3} {
		t.Run(fmt.Sprintf("canonical-k%d-disposal-h9", k), func(t *testing.T) {
			f := eisNew(t, 15125, 1, []CleanupSpanV1{{Kind: 1, GenerationID: 5}})
			pair := eisCapture(t, f, 1, 1, false, false)
			hash, parent := f.hashes[k], [32]byte(f.headers[k][4:36])
			eisSeed(t, f, []Mutation{eisMutation(2, eisHeight(5, 9), eisChain(hash, parent, 9)), eisMutation(7, eisOwner(5, hash), CanonicalOwnerValue(9)), eisMutation(5, UndoManifestKey(hash), UndoManifestValue(9, [16]byte{}, 0, 0))})
			body, header := 0, 0
			result, _, failure, err := eicInvoke(t, f, pair, func(row EntryInventoryRowV1) error {
				if row.Source == 20 {
					header++
				}
				if row.Source == 21 {
					body++
					if row.Height != 9 || row.Hash != hash || !row.Present || row.Length != 148 {
						t.Fatal("obsolete reference height replaced actual canonical ownership")
					}
				}
				return nil
			})
			result.tuple(t, 2, 3, -1)
			mustEnvironment(t, result.err)
			want := 0
			if k == 0 {
				want = 1
			}
			if failure != nil || err != nil || body != want || header != 0 || f.old.Authority.B != 6 {
				t.Fatalf("actual L_body1 vs serviceB6/disposal h9: body%d/header%d/%+v/%v", body, header, failure, err)
			}
		})
	}
}

package node

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type compactStandardFixture struct {
	mp     *Mempool
	state  *ChainState
	signer *consensus.MLDSA87Keypair
	raw    [][]byte
	ids    []CompactCandidateIdentity
}

// Detached fixture projections preserve literal keys and nil payloads.
func mempoolTestEntries(mp *Mempool) map[[32]byte]*mempoolEntry {
	if mp.relations.forward == nil {
		return nil
	}
	entries := make(map[[32]byte]*mempoolEntry, len(mp.relations.forward))
	for key, row := range mp.relations.forward {
		entries[key] = row.entry
	}
	return entries
}

func mempoolTestReverse(mp *Mempool) map[[32]byte][32]byte {
	if mp.relations.reverse == nil {
		return nil
	}
	reverse := make(map[[32]byte][32]byte, len(mp.relations.reverse))
	for key, row := range mp.relations.reverse {
		reverse[key] = row.txid
	}
	return reverse
}

func mempoolTestEntry(mp *Mempool, key [32]byte) *mempoolEntry {
	entry, _ := mp.relations.entry(key)
	return entry
}

func mempoolTestTarget(mp *Mempool, key [32]byte) [32]byte {
	target, _ := mp.relations.reverseTarget(key)
	return target
}

func newCompactStandardFixture(t *testing.T, count int) compactStandardFixture {
	t.Helper()
	signer := mustNodeMLDSA87Keypair(t)
	address := consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes())
	state, outpoints := testSpendableChainState(address, slices.Repeat([]uint64{1_000_000}, count))
	cfg := DefaultMempoolConfig()
	cfg.MaxTransactions, cfg.MaxBytes = count+1, 256_000_000
	mp, err := NewMempoolWithConfig(state, nil, devnetGenesisChainID, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := compactStandardFixture{mp: mp, state: state, signer: signer}
	for i, outpoint := range outpoints {
		raw := mustBuildSignedTransferTx(t, state.Utxos, []consensus.Outpoint{outpoint}, 100_000, 100_000, uint64(i+1), signer, address, address)
		if err := mp.AddTx(raw); err != nil {
			t.Fatal(err)
		}
		_, txid, wtxid, consumed, err := consensus.ParseTx(raw)
		if err != nil || consumed != len(raw) {
			t.Fatalf("fixture canonical parse=(%d,%v)", consumed, err)
		}
		f.raw = append(f.raw, raw)
		f.ids = append(f.ids, CompactCandidateIdentity{TxID: txid, WTxID: wtxid})
	}
	return f
}

func requireCompactCandidateRead(t *testing.T, got CompactCandidateRead, disposition uint8, raw []byte) {
	t.Helper()
	if uint8(got.Disposition) != disposition || !bytes.Equal(got.Raw, raw) || (raw == nil && got.Raw != nil) {
		t.Fatalf("read=(%d,%x), want (%d,%x)", got.Disposition, got.Raw, disposition, raw)
	}
}

func compactStandardImage(t *testing.T, mp *Mempool) []any {
	t.Helper()
	if mp == nil {
		return nil
	}
	nilRaw := map[[32]byte]bool{}
	metadata := map[[32]byte][3][32]byte{}
	for key, row := range mp.relations.forward {
		metadata[key] = [3][32]byte{row.key, row.txid, row.wtxid}
	}
	for id, entry := range mempoolTestEntries(mp) {
		if entry != nil {
			nilRaw[id] = entry.raw == nil
		}
	}
	return []any{canonicalMOImageFingerprint(t, mp, 0), mp.AdmissionCounts(), mp.evictedResidentTotal.Load(), mp.relations.forward == nil, mp.relations.reverse == nil, nilRaw, metadata}
}

func requireCompactStandardPreservedRead(t *testing.T, mp *Mempool, id CompactCandidateIdentity, maxBytes uint64, disposition uint8, raw []byte) {
	t.Helper()
	before := compactStandardImage(t, mp)
	requireCompactCandidateRead(t, mp.ReadCompactStandard(id, maxBytes), disposition, raw)
	if !reflect.DeepEqual(before, compactStandardImage(t, mp)) {
		t.Fatal("read changed owner image/counters")
	}
}

func TestCompactCandidateStandard(t *testing.T) {
	t.Run("complete_population", func(t *testing.T) {
		f := newCompactStandardFixture(t, 1001)
		before, err := snapshotMempool(f.mp)
		if err != nil {
			t.Fatal(err)
		}
		ids, ok := f.mp.CompactStandardIdentities()
		if !ok || len(ids) != 1001 {
			t.Fatalf("complete population=(%d,%v), want1001,true", len(ids), ok)
		}
		want := make(map[CompactCandidateIdentity]bool, 1001)
		var rawBytes int
		for i, id := range f.ids {
			want[id] = true
			rawBytes += len(f.raw[i])
		}
		for _, id := range ids {
			if !want[id] {
				t.Fatalf("unexpected identity=%+v", id)
			}
			delete(want, id)
		}
		if len(want) != 0 || rawBytes <= 1<<20 {
			t.Fatalf("missing=%d raw=%d", len(want), rawBytes)
		}
		ids[0] = CompactCandidateIdentity{}
		fresh, ok := f.mp.CompactStandardIdentities()
		after, err := snapshotMempool(f.mp)
		if !ok || len(fresh) != 1001 || err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("snapshot changed owner or next operation")
		}
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[1000], uint64(len(f.raw[1000]))), 1, f.raw[1000])
		reversed, err := NewMempoolWithConfig(f.state, nil, devnetGenesisChainID, f.mp.policy)
		if err != nil {
			t.Fatal(err)
		}
		for i := len(f.raw) - 1; i >= 0; i-- {
			if err := reversed.AddTx(f.raw[i]); err != nil {
				t.Fatal(err)
			}
		}
		reversedIDs, ok := reversed.CompactStandardIdentities()
		want = make(map[CompactCandidateIdentity]bool, len(f.ids))
		for _, id := range f.ids {
			want[id] = true
		}
		for _, id := range reversedIDs {
			if !want[id] {
				t.Fatal("opposite-order snapshot changed literal identity set")
			}
			delete(want, id)
		}
		if !ok || len(want) != 0 || len(reversedIDs) != 1001 {
			t.Fatal("opposite-order capture omitted admitted rows")
		}
		requireCompactStandardPreservedRead(t, reversed, f.ids[1000], uint64(len(f.raw[1000])), 1, f.raw[1000])
	})
	t.Run("immutable_bytes", func(t *testing.T) {
		f := newCompactStandardFixture(t, 1)
		got := f.mp.ReadCompactStandard(f.ids[0], uint64(len(f.raw[0])))
		requireCompactCandidateRead(t, got, 1, f.raw[0])
		got.Raw[0] ^= 0xff
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[0], uint64(len(f.raw[0]))), 1, f.raw[0])
		if err := f.mp.EvictConfirmedParsed(&consensus.ParsedBlock{Txids: [][32]byte{f.ids[0].TxID}}); err != nil {
			t.Fatal(err)
		}
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[0], ^uint64(0)), 2, nil)
		if got.Raw[0] != f.raw[0][0]^0xff {
			t.Fatal("owner removal mutated caller copy")
		}
	})
	t.Run("coherent_replacement", compactStandardReplacement)
	t.Run("observed_pair_integrity", compactStandardIntegrity)
	t.Run("removed_associations", compactStandardRemoved)
	t.Run("unavailable_and_empty", func(t *testing.T) {
		for i, mp := range []*Mempool{nil, {}, {relations: buildMempoolRelations(map[[32]byte]*mempoolEntry{}, nil)}, {relations: buildMempoolRelations(nil, map[[32]byte][32]byte{})}, {relations: buildMempoolRelations(map[[32]byte]*mempoolEntry{}, map[[32]byte][32]byte{})}} {
			before := compactStandardImage(t, mp)
			ids, ok := mp.CompactStandardIdentities()
			if ok != (i == 4) || (i != 4 && ids != nil) || len(ids) != 0 {
				t.Fatalf("owner%d snapshot=(%v,%v)", i, ids, ok)
			}
			if !reflect.DeepEqual(before, compactStandardImage(t, mp)) {
				t.Fatal("snapshot changed unavailable/empty owner")
			}
			want := uint8(3)
			if i == 4 {
				want = 2
			}
			requireCompactStandardPreservedRead(t, mp, CompactCandidateIdentity{TxID: [32]byte{7}, WTxID: [32]byte{8}}, 0, want, nil)
		}
	})
	t.Run("size_before_copy", func(t *testing.T) {
		f := newCompactStandardFixture(t, 1)
		mempoolTestEntry(f.mp, f.ids[0].TxID).raw = bytes.Repeat([]byte{0x71}, 8<<20)
		mempoolTestEntry(f.mp, f.ids[0].TxID).size = 8 << 20
		image := compactStandardImage(t, f.mp)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		got := f.mp.ReadCompactStandard(f.ids[0], (8<<20)-1)
		runtime.ReadMemStats(&after)
		requireCompactCandidateRead(t, got, 4, nil)
		if after.TotalAlloc-before.TotalAlloc >= 1<<20 {
			t.Fatalf("overlength copied bytes=%d", after.TotalAlloc-before.TotalAlloc)
		}
		if !reflect.DeepEqual(image, compactStandardImage(t, f.mp)) {
			t.Fatal("large size refusal changed owner/counters")
		}
		runtime.ReadMemStats(&before)
		got = f.mp.ReadCompactStandard(f.ids[0], 8<<20)
		runtime.ReadMemStats(&after)
		requireCompactCandidateRead(t, got, 3, nil)
		if after.TotalAlloc-before.TotalAlloc < 8<<20 {
			t.Fatalf("wide admitted copy control allocated=%d, want >=8MiB", after.TotalAlloc-before.TotalAlloc)
		}
		mempoolTestEntry(f.mp, f.ids[0].TxID).raw, mempoolTestEntry(f.mp, f.ids[0].TxID).size = slices.Clone(f.raw[0]), len(f.raw[0])
		requireCompactStandardPreservedRead(t, f.mp, f.ids[0], 0, 4, nil)
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[0], uint64(len(f.raw[0]))), 1, f.raw[0])
	})
	t.Run("canonical_and_domain", compactStandardCanonical)
	t.Run("coherent_concurrency", compactStandardConcurrency)
	t.Run("publication_boundary", compactStandardPublicationBoundary)
	t.Run("unsigned_budget_bounds", func(t *testing.T) {
		f := newCompactStandardFixture(t, 1)
		for i, budget := range []uint64{0, uint64(len(f.raw[0]) - 1), uint64(len(f.raw[0])), ^uint64(0)} {
			want, raw := uint8(4), []byte(nil)
			if i >= 2 {
				want, raw = 1, f.raw[0]
			}
			requireCompactStandardPreservedRead(t, f.mp, f.ids[0], budget, want, raw)
		}
	})
}

func compactStandardIntegrity(t *testing.T) {
	f := newCompactStandardFixture(t, 2)
	compactStandardAssociations(t, f, f.ids[0], mempoolTestEntry(f.mp, f.ids[0].TxID), f.raw[0])
	for _, mutation := range []string{"nil_entry", "embedded_txid", "size", "reverse_missing", "reverse_wrong", "reverse_wrong_foreign", "extra_reverse"} {
		t.Run(mutation, func(t *testing.T) {
			f := newCompactStandardFixture(t, 2)
			id := f.ids[0]
			original := cloneMempoolEntry(mempoolTestEntry(f.mp, id.TxID))
			switch mutation {
			case "nil_entry":
				f.mp.relations.putEntry(id.TxID, nil)
			case "embedded_txid":
				mempoolTestEntry(f.mp, id.TxID).txid[0] ^= 1
			case "size":
				mempoolTestEntry(f.mp, id.TxID).size++
			case "reverse_missing":
				f.mp.relations.deleteReverse(id.WTxID)
			case "reverse_wrong":
				f.mp.relations.putReverse(id.WTxID, f.ids[1].TxID)
			case "reverse_wrong_foreign":
				f.mp.relations.putReverse(id.WTxID, [32]byte{0xe7})
			case "extra_reverse":
				f.mp.relations.putReverse([32]byte{0xa9}, [32]byte{0xb9})
			}
			before := compactStandardImage(t, f.mp)
			if ids, ok := f.mp.CompactStandardIdentities(); ok || ids != nil {
				t.Fatal("inconsistent snapshot returned prefix")
			}
			if !reflect.DeepEqual(before, compactStandardImage(t, f.mp)) {
				t.Fatal("snapshot changed inconsistent image")
			}
			for _, different := range []bool{false, true} {
				observed := id
				if different {
					observed.WTxID[0] ^= 1
				}
				for _, maxBytes := range []uint64{0, uint64(len(f.raw[0]))} {
					want, raw := uint8(3), []byte(nil)
					if mutation == "extra_reverse" {
						want = 2
						if !different {
							want = 4
							if maxBytes != 0 {
								want, raw = 1, f.raw[0]
							}
						}
					}
					requireCompactStandardPreservedRead(t, f.mp, observed, maxBytes, want, raw)
				}
			}
			siblingDisposition, siblingRaw := uint8(1), f.raw[1]
			if mutation == "reverse_wrong" {
				siblingDisposition, siblingRaw = 3, nil
			}
			requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), siblingDisposition, siblingRaw)
			f.mp.relations.putEntry(id.TxID, &original)
			f.mp.relations.putReverse(id.WTxID, id.TxID)
			f.mp.relations.deleteReverse([32]byte{0xa9})
			requireCompactStandardPreservedRead(t, f.mp, id, uint64(len(f.raw[0])), 1, f.raw[0])
			requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), 1, f.raw[1])
		})
	}
}

func compactStandardRemoved(t *testing.T) {
	f := newCompactStandardFixture(t, 2)
	retired := mempoolTestEntry(f.mp, f.ids[0].TxID)
	if err := f.mp.EvictConfirmedParsed(&consensus.ParsedBlock{Txids: [][32]byte{f.ids[0].TxID}}); err != nil {
		t.Fatal(err)
	}
	compactStandardAssociations(t, f, f.ids[0], retired, f.raw[0])
	for reverse := 0; reverse < 4; reverse++ {
		for extra, name := range []string{"extrafalse", "extratrue", "extraunrelated"} {
			t.Run(fmt.Sprintf("reverse%d/%s", reverse, name), func(t *testing.T) {
				f := newCompactStandardFixture(t, 2)
				id := f.ids[0]
				f.mp.relations.deleteForward(id.TxID)
				f.mp.relations.deleteReverse(id.WTxID)
				values := [][32]byte{{}, id.TxID, f.ids[1].TxID, {0xe7}}
				if reverse != 0 {
					f.mp.relations.putReverse(id.WTxID, values[reverse])
				}
				if extra != 0 {
					f.mp.relations.putReverse([32]byte{0xe8}, values[extra])
				}
				want := uint8(3)
				if reverse == 0 && extra != 1 {
					want = 2
				}
				for _, maxBytes := range []uint64{0, uint64(len(f.raw[0]))} {
					requireCompactStandardPreservedRead(t, f.mp, id, maxBytes, want, nil)
				}
				f.mp.relations.deleteReverse(id.WTxID)
				f.mp.relations.deleteReverse([32]byte{0xe8})
				requireCompactStandardPreservedRead(t, f.mp, id, 0, 2, nil)
				requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), 1, f.raw[1])
			})
		}
	}
}

func compactStandardReplacement(t *testing.T) {
	f := newCompactStandardFixture(t, 2)
	tx, _, _, _, err := consensus.ParseTx(f.raw[0])
	require(t, err == nil, "parse original witness: %v", err)
	if err := consensus.SignTransaction(tx, f.state.Utxos, devnetGenesisChainID, f.signer); err != nil {
		t.Fatal(err)
	}
	raw := mustMarshalTxForNodeTest(t, tx)
	_, txid, wtxid, _, err := consensus.ParseTx(raw)
	require(t, err == nil && txid == f.ids[0].TxID && wtxid != f.ids[0].WTxID, "alternate genuine witness not established: %v", err)
	other, err := NewMempool(f.state, nil, devnetGenesisChainID)
	require(t, err == nil, "replacement mempool: %v", err)
	if err := other.AddTx(raw); err != nil {
		t.Fatal(err)
	}
	f.mp.mu.Lock()
	entry := mempoolTestEntry(f.mp, txid)
	entry.raw, entry.wtxid, entry.size = slices.Clone(raw), wtxid, len(raw)
	f.mp.relations.putEntry(txid, entry)
	f.mp.relations.putReverse(wtxid, txid)
	f.mp.relations.deleteReverse(f.ids[0].WTxID)
	f.mp.mu.Unlock()
	compactStandardAssociations(t, f, f.ids[0], entry, raw)
	for _, stale := range []struct {
		name string
		txid [32]byte
	}{
		{"clean", [32]byte{}},
		{"stale_selected_txid", txid},
		{"stale_other_txid", f.ids[1].TxID},
		{"stale_missing_txid", [32]byte{0xe7}},
	} {
		for extra, name := range []string{"extrafalse", "extratrue", "extraunrelated"} {
			t.Run(stale.name+"/"+name, func(t *testing.T) {
				f.mp.relations.deleteReverse(f.ids[0].WTxID)
				if stale.name != "clean" {
					f.mp.relations.putReverse(f.ids[0].WTxID, stale.txid)
				}
				if extra != 0 {
					indexed := txid
					if extra == 2 {
						indexed = f.ids[1].TxID
					}
					f.mp.relations.putReverse([32]byte{0xe8}, indexed)
				}
				want := uint8(2)
				if stale.name != "clean" || extra == 1 {
					want = 3
				}
				for _, maxBytes := range []uint64{0, uint64(len(raw))} {
					requireCompactStandardPreservedRead(t, f.mp, f.ids[0], maxBytes, want, nil)
				}
				f.mp.relations.deleteReverse([32]byte{0xe8})
				f.mp.relations.deleteReverse(f.ids[0].WTxID)
				requireCompactStandardPreservedRead(t, f.mp, CompactCandidateIdentity{TxID: txid, WTxID: wtxid}, uint64(len(raw)), 1, raw)
				requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), 1, f.raw[1])
			})
		}
	}
	f.mp.relations.deleteReverse(f.ids[0].WTxID)
	requireCompactStandardPreservedRead(t, f.mp, f.ids[0], 0, 2, nil)
	started, reads := make(chan struct{}), make(chan CompactCandidateRead, 1)
	f.mp.mu.Lock()
	go func() {
		close(started)
		reads <- f.mp.ReadCompactStandard(CompactCandidateIdentity{TxID: txid, WTxID: wtxid}, 0)
	}()
	<-started
	entry.raw, entry.wtxid, entry.size = slices.Clone(f.raw[0]), f.ids[0].WTxID, len(f.raw[0])
	f.mp.relations.putEntry(txid, entry)
	f.mp.relations.deleteReverse(wtxid)
	f.mp.relations.putReverse(f.ids[0].WTxID, txid)
	f.mp.mu.Unlock()
	requireCompactCandidateRead(t, <-reads, 2, nil)
	requireCompactStandardPreservedRead(t, f.mp, f.ids[0], uint64(len(f.raw[0])), 1, f.raw[0])
}

func compactStandardAssociations(t *testing.T, f compactStandardFixture, observed CompactCandidateIdentity, retained *mempoolEntry, restoredRaw []byte) {
	t.Helper()
	txs, wtxids := mempoolTestEntries(f.mp), mempoolTestReverse(f.mp)
	if ids, ok := f.mp.CompactStandardIdentities(); !ok || len(ids) != len(txs) {
		t.Fatal("association fixture lacks a complete coherent initial snapshot")
	}
	for _, row := range []struct {
		name  string
		fault bool
	}{
		{"clean", false},
		{"nil_member", false},
		{"unrelated_member", false},
		{"txid", true},
		{"wtxid", true},
		{"both", true},
		{"pointer", true},
		{"current_pair", true},
		{"reverse_alias", true},
		{"many", true},
		{"same_count_forward", true},
		{"same_count_reverse", true},
		{"unrelated_reverse", false},
		{"same_count_forward_wtxid", true},
		{"same_count_reverse_replace", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			f.mp.relations = buildMempoolRelations(maps.Clone(txs), maps.Clone(wtxids))
			key := [32]byte{0xe5}
			member := *retained
			member.txid, member.wtxid = observed.TxID, observed.WTxID
			switch row.name {
			case "nil_member":
				f.mp.relations.putEntry(key, nil)
			case "unrelated_member":
				member.txid, member.wtxid = [32]byte{0xe6}, [32]byte{0xe7}
				f.mp.relations.putEntry(key, &member)
				f.mp.relations.putReverse(member.wtxid, key)
			case "txid", "wtxid", "both", "current_pair", "same_count_forward", "same_count_forward_wtxid", "many":
				if row.name == "txid" {
					member.wtxid = [32]byte{0xe7}
				}
				if row.name == "wtxid" {
					member.txid = [32]byte{0xe6}
				}
				if row.name == "current_pair" {
					member = *retained
				}
				if row.name == "same_count_forward" || row.name == "same_count_forward_wtxid" {
					key = f.ids[1].TxID
				}
				if row.name == "same_count_forward_wtxid" {
					member.txid = [32]byte{0xe6}
				}
				f.mp.relations.putEntry(key, &member)
			case "pointer":
				f.mp.relations.putEntry(key, retained)
			}
			if row.name == "same_count_reverse" {
				f.mp.relations.deleteReverse(f.ids[1].WTxID)
			}
			if row.name == "same_count_reverse_replace" {
				f.mp.relations.putReverse(f.ids[1].WTxID, observed.TxID)
			}
			if row.name == "reverse_alias" || row.name == "same_count_reverse" || row.name == "many" {
				f.mp.relations.putReverse([32]byte{0xe8}, observed.TxID)
			}
			if row.name == "many" {
				for i := uint64(0); i < 4096; i++ {
					key := [32]byte{0xfc}
					binary.LittleEndian.PutUint64(key[1:9], i)
					member := *retained
					member.txid, member.wtxid = key, observed.WTxID
					f.mp.relations.putEntry(key, &member)
					f.mp.relations.putReverse(key, observed.TxID)
				}
			}
			if (row.name == "same_count_forward" || row.name == "same_count_forward_wtxid") && len(f.mp.relations.forward) != len(txs) {
				t.Fatal("same-count forward fixture changed literal cardinality")
			}
			if (row.name == "same_count_reverse" || row.name == "same_count_reverse_replace") && len(f.mp.relations.reverse) != len(wtxids) {
				t.Fatal("same-count reverse fixture changed literal cardinality")
			}
			if row.name == "unrelated_reverse" {
				f.mp.relations.putReverse([32]byte{0xe8}, [32]byte{0xe6})
			}
			if row.name != "clean" {
				before := compactStandardImage(t, f.mp)
				if ids, ok := f.mp.CompactStandardIdentities(); ok || ids != nil {
					t.Fatal("full incoherent D2 returned success or a prefix")
				}
				if !reflect.DeepEqual(before, compactStandardImage(t, f.mp)) {
					t.Fatal("incoherent D2 changed owner image")
				}
			}
			for _, maxBytes := range []uint64{0, uint64(len(restoredRaw))} {
				want, raw := uint8(2), []byte(nil)
				if current := txs[observed.TxID]; current != nil && current.wtxid == observed.WTxID {
					want = 4
					if maxBytes != 0 {
						want, raw = 1, restoredRaw
					}
				}
				if row.fault {
					want, raw = 3, nil
				}
				requireCompactStandardPreservedRead(t, f.mp, observed, maxBytes, want, raw)
			}
			f.mp.relations = buildMempoolRelations(maps.Clone(txs), maps.Clone(wtxids))
			f.mp.relations.putEntry(observed.TxID, retained)
			f.mp.relations.putReverse(retained.wtxid, observed.TxID)
			restored := CompactCandidateIdentity{TxID: observed.TxID, WTxID: retained.wtxid}
			requireCompactStandardPreservedRead(t, f.mp, restored, uint64(len(restoredRaw)), 1, restoredRaw)
			requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), 1, f.raw[1])
		})
	}
	f.mp.relations = buildMempoolRelations(txs, wtxids)
}

func compactStandardCanonical(t *testing.T) {
	for _, row := range []struct {
		name string
		bad  func([]byte) []byte
	}{
		{"nil", func([]byte) []byte { return nil }},
		{"empty", func([]byte) []byte { return []byte{} }},
		{"trailing", func(raw []byte) []byte { return append(raw, 0) }},
		{"truncated", func(raw []byte) []byte { return raw[:len(raw)-1] }},
		{"noncanonical", func(raw []byte) []byte { raw[0] ^= 0xff; return raw }},
		{"nonminimal", func(raw []byte) []byte { return append(append(slices.Clone(raw[:13]), 0xfd, 1, 0), raw[14:]...) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newCompactStandardFixture(t, 2)
			entry := mempoolTestEntry(f.mp, f.ids[0].TxID)
			entry.raw = row.bad(slices.Clone(entry.raw))
			entry.size = len(entry.raw)
			ids, ok := f.mp.CompactStandardIdentities()
			if !ok || len(ids) != 2 {
				t.Fatal("unread bytes received integrity verdict")
			}
			requireCompactStandardPreservedRead(t, f.mp, f.ids[0], uint64(len(entry.raw)), 3, nil)
			if len(entry.raw) != 0 {
				requireCompactStandardPreservedRead(t, f.mp, f.ids[0], uint64(len(entry.raw)-1), 4, nil)
			}
			requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[1], ^uint64(0)), 1, f.raw[1])
		})
	}
	for _, mutation := range []string{"kind", "txid", "wtxid"} {
		f := newCompactStandardFixture(t, 2)
		id := f.ids[0]
		entry := mempoolTestEntry(f.mp, id.TxID)
		switch mutation {
		case "kind":
			da := newDAAdmissionCandidateFixture(t, 2)
			da.admission.Close()
			f.mp.relations.deleteForward(id.TxID)
			f.mp.relations.deleteReverse(id.WTxID)
			entry.raw, entry.txid, entry.wtxid, entry.size = slices.Clone(da.raw), da.txid, da.wtxid, len(da.raw)
			id = CompactCandidateIdentity{TxID: da.txid, WTxID: da.wtxid}
			f.mp.relations.putEntry(id.TxID, entry)
			f.mp.relations.putReverse(id.WTxID, id.TxID)
		case "txid":
			f.mp.relations.deleteForward(id.TxID)
			f.mp.relations.deleteReverse(id.WTxID)
			id.TxID[0] ^= 1
			entry.txid = id.TxID
			f.mp.relations.putEntry(id.TxID, entry)
			f.mp.relations.putReverse(id.WTxID, id.TxID)
		case "wtxid":
			f.mp.relations.deleteReverse(id.WTxID)
			id.WTxID[0] ^= 1
			entry.wtxid = id.WTxID
			f.mp.relations.putEntry(id.TxID, entry)
			f.mp.relations.putReverse(id.WTxID, id.TxID)
		}
		if ids, ok := f.mp.CompactStandardIdentities(); !ok || len(ids) != 2 {
			t.Fatalf("%s raw obtained snapshot verdict", mutation)
		}
		requireCompactStandardPreservedRead(t, f.mp, id, uint64(len(entry.raw)), 3, nil)
		requireCompactStandardPreservedRead(t, f.mp, id, uint64(len(entry.raw)-1), 4, nil)
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[1], ^uint64(0)), 1, f.raw[1])
	}
}

func compactStandardPublicationBoundary(t *testing.T) {
	f := newCompactStandardFixture(t, 2)
	before := compactStandardImage(t, f.mp)
	identity := f.ids[0]
	input := *f.mp.relations.forward[identity.TxID]
	f.mp.mu.Lock()
	f.mp.relations.putForward(input)
	f.mp.mu.Unlock()
	published := f.mp.relations.forward[identity.TxID]
	head := f.mp.relations.wtxids[identity.WTxID].head
	input.key, input.txid, input.wtxid = [32]byte{0xe1}, [32]byte{0xe2}, [32]byte{0xe3}
	if published.key != identity.TxID || published.txid != identity.TxID || published.wtxid != identity.WTxID {
		t.Fatal("edited input row changed published identity values")
	}
	requireCompactStandardPreservedRead(t, f.mp, identity, uint64(len(f.raw[0])), 1, f.raw[0])
	snapshot, err := snapshotMempool(f.mp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := canonicalMempoolPlanContextOf(f.mp)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := buildCanonicalMempoolPlan(snapshot.entries, snapshot, ctx, 0, f.mp.usedBytes)
	if err != nil {
		t.Fatal(err)
	}
	planRow, planHead := plan.relations.forward[identity.TxID], plan.relations.wtxids[identity.WTxID].head
	input = *plan.relations.forward[identity.TxID]
	input.wtxid = [32]byte{0xe4}
	plan.relations.putForward(input)
	plan.relations.putReverse([32]byte{0xe5}, identity.TxID)
	plan.relations.deleteForward(f.ids[1].TxID)
	plan.relations.deleteReverse(f.ids[1].WTxID)
	plan = canonicalMempoolPlan{}
	if !reflect.DeepEqual(before, compactStandardImage(t, f.mp)) || f.mp.relations.wtxids[identity.WTxID].head != head || f.mp.relations.wtxids[identity.WTxID].count != 1 {
		t.Fatal("editing/discarding unpublished plan changed live owner")
	}
	ids, ok := f.mp.CompactStandardIdentities()
	if !ok || len(ids) != 2 {
		t.Fatal("plan discard changed next coherent capture")
	}
	requireCompactStandardPreservedRead(t, f.mp, identity, uint64(len(f.raw[0])), 1, f.raw[0])
	requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), 1, f.raw[1])
	if planRow == published || planHead == head {
		t.Fatal("unpublished plan aliases mutable live rows or bucket nodes")
	}
	entry := mempoolTestEntry(f.mp, identity.TxID)
	entry.wtxid[0] ^= 1
	requireCompactStandardPreservedRead(t, f.mp, identity, 0, 3, nil)
	entry.wtxid = identity.WTxID
	requireCompactStandardPreservedRead(t, f.mp, identity, uint64(len(f.raw[0])), 1, f.raw[0])
}

func compactStandardConcurrency(t *testing.T) {
	f := newCompactStandardFixture(t, 1)
	for i := 0; i < 10; i++ {
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[0], ^uint64(0)), 1, f.raw[0])
		if ids, ok := f.mp.CompactStandardIdentities(); !ok || len(ids) != 1 || ids[0] != f.ids[0] {
			t.Fatal("next phase did not observe admitted pair")
		}
		started := make(chan struct{}, 3)
		reads, snapshots, removed := make(chan CompactCandidateRead, 1), make(chan []CompactCandidateIdentity, 1), make(chan error, 1)
		f.mp.mu.Lock()
		go func() {
			started <- struct{}{}
			ids, ok := f.mp.CompactStandardIdentities()
			if !ok {
				t.Error("torn snapshot")
			}
			snapshots <- ids
		}()
		go func() { started <- struct{}{}; reads <- f.mp.ReadCompactStandard(f.ids[0], ^uint64(0)) }()
		go func() {
			started <- struct{}{}
			removed <- f.mp.EvictConfirmedParsed(&consensus.ParsedBlock{Txids: [][32]byte{f.ids[0].TxID}})
		}()
		for range 3 {
			<-started
		}
		f.mp.mu.Unlock()
		ids, read, err := <-snapshots, <-reads, <-removed
		if err != nil || len(ids) > 1 || (len(ids) == 1 && ids[0] != f.ids[0]) {
			t.Fatal("concurrent snapshot/removal is incoherent")
		}
		if uint8(read.Disposition) != 1 && uint8(read.Disposition) != 2 {
			t.Errorf("torn read=%+v", read)
		}
		if uint8(read.Disposition) == 1 && !bytes.Equal(read.Raw, f.raw[0]) {
			t.Error("mixed raw")
		}
		if uint8(read.Disposition) == 2 && read.Raw != nil {
			t.Error("concurrent absence retained raw")
		}
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[0], ^uint64(0)), 2, nil)
		if err := f.mp.AddTx(f.raw[0]); err != nil {
			t.Fatal(err)
		}
	}
	requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[0], ^uint64(0)), 1, f.raw[0])
}

func TestMempoolTxIDsLimitBoundsSnapshot(t *testing.T) {
	mp := &Mempool{
		relations: buildMempoolRelations(map[[32]byte]*mempoolEntry{
			{0x01}: {},
			{0x02}: {},
			{0x03}: {},
		}, nil),
	}
	if got := mp.TxIDsLimit(2); len(got) != 2 {
		t.Fatalf("TxIDsLimit len=%d, want 2", len(got))
	}
	if got := mp.TxIDsLimit(0); got != nil {
		t.Fatalf("TxIDsLimit(0)=%v, want nil", got)
	}
	if got := mp.AllTxIDs(); len(got) != 3 {
		t.Fatalf("AllTxIDs len=%d, want 3", len(got))
	}
}

package node

import (
	"bytes"
	"fmt"
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
	for id, entry := range mp.txs {
		if entry != nil {
			nilRaw[id] = entry.raw == nil
		}
	}
	return []any{canonicalMOImageFingerprint(t, mp, 0), mp.AdmissionCounts(), mp.evictedResidentTotal.Load(), mp.txs == nil, mp.wtxids == nil, nilRaw}
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
		for i, mp := range []*Mempool{nil, {}, {txs: map[[32]byte]*mempoolEntry{}}, {wtxids: map[[32]byte][32]byte{}}, {txs: map[[32]byte]*mempoolEntry{}, wtxids: map[[32]byte][32]byte{}}} {
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
		f.mp.txs[f.ids[0].TxID].raw = bytes.Repeat([]byte{0x71}, 8<<20)
		f.mp.txs[f.ids[0].TxID].size = 8 << 20
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
		f.mp.txs[f.ids[0].TxID].raw, f.mp.txs[f.ids[0].TxID].size = slices.Clone(f.raw[0]), len(f.raw[0])
		requireCompactStandardPreservedRead(t, f.mp, f.ids[0], 0, 4, nil)
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[0], uint64(len(f.raw[0]))), 1, f.raw[0])
	})
	t.Run("canonical_and_domain", compactStandardCanonical)
	t.Run("coherent_concurrency", compactStandardConcurrency)
}

func compactStandardIntegrity(t *testing.T) {
	for _, mutation := range []string{"nil_entry", "embedded_txid", "size", "reverse_missing", "reverse_wrong", "extra_reverse"} {
		t.Run(mutation, func(t *testing.T) {
			f := newCompactStandardFixture(t, 2)
			id := f.ids[0]
			switch mutation {
			case "nil_entry":
				f.mp.txs[id.TxID] = nil
			case "embedded_txid":
				f.mp.txs[id.TxID].txid[0] ^= 1
			case "size":
				f.mp.txs[id.TxID].size++
			case "reverse_missing":
				delete(f.mp.wtxids, id.WTxID)
			case "reverse_wrong":
				f.mp.wtxids[id.WTxID] = f.ids[1].TxID
			case "extra_reverse":
				f.mp.wtxids[[32]byte{0xa9}] = [32]byte{0xb9}
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
					if mutation != "extra_reverse" {
						requireCompactStandardPreservedRead(t, f.mp, observed, maxBytes, 3, nil)
					}
				}
			}
			requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), 1, f.raw[1])
		})
	}
}

func compactStandardRemoved(t *testing.T) {
	for reverse := 0; reverse < 4; reverse++ {
		for _, extra := range []bool{false, true} {
			t.Run(fmt.Sprintf("reverse%d/extra%v", reverse, extra), func(t *testing.T) {
				f := newCompactStandardFixture(t, 2)
				id := f.ids[0]
				delete(f.mp.txs, id.TxID)
				delete(f.mp.wtxids, id.WTxID)
				values := [][32]byte{{}, id.TxID, f.ids[1].TxID, {0xe7}}
				if reverse != 0 {
					f.mp.wtxids[id.WTxID] = values[reverse]
				}
				if extra {
					f.mp.wtxids[[32]byte{0xe8}] = id.TxID
				}
				want := uint8(3)
				if reverse == 0 && !extra {
					want = 2
				}
				requireCompactStandardPreservedRead(t, f.mp, id, 0, want, nil)
				delete(f.mp.wtxids, id.WTxID)
				delete(f.mp.wtxids, [32]byte{0xe8})
				requireCompactStandardPreservedRead(t, f.mp, id, 0, 2, nil)
				requireCompactStandardPreservedRead(t, f.mp, f.ids[1], uint64(len(f.raw[1])), 1, f.raw[1])
			})
		}
	}
}

func compactStandardReplacement(t *testing.T) {
	f := newCompactStandardFixture(t, 1)
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
	entry := f.mp.txs[txid]
	entry.raw, entry.wtxid, entry.size = slices.Clone(raw), wtxid, len(raw)
	f.mp.wtxids[wtxid] = txid
	f.mp.mu.Unlock()
	otherTxID := txid
	otherTxID[0] ^= 1
	for _, stale := range []struct {
		name string
		txid [32]byte
	}{
		{"clean", [32]byte{}},
		{"stale_selected_txid", txid},
		{"stale_other_txid", otherTxID},
	} {
		t.Run(stale.name, func(t *testing.T) {
			delete(f.mp.wtxids, f.ids[0].WTxID)
			want := uint8(2)
			if stale.name != "clean" {
				f.mp.wtxids[f.ids[0].WTxID] = stale.txid
				want = 3
			}
			for _, maxBytes := range []uint64{0, uint64(len(raw))} {
				requireCompactStandardPreservedRead(t, f.mp, f.ids[0], maxBytes, want, nil)
			}
			requireCompactStandardPreservedRead(t, f.mp, CompactCandidateIdentity{TxID: txid, WTxID: wtxid}, uint64(len(raw)), 1, raw)
		})
	}
	delete(f.mp.wtxids, f.ids[0].WTxID)
	requireCompactStandardPreservedRead(t, f.mp, f.ids[0], 0, 2, nil)
	started, reads := make(chan struct{}), make(chan CompactCandidateRead, 1)
	f.mp.mu.Lock()
	go func() {
		close(started)
		reads <- f.mp.ReadCompactStandard(CompactCandidateIdentity{TxID: txid, WTxID: wtxid}, 0)
	}()
	<-started
	entry.raw, entry.wtxid, entry.size = slices.Clone(f.raw[0]), f.ids[0].WTxID, len(f.raw[0])
	delete(f.mp.wtxids, wtxid)
	f.mp.wtxids[f.ids[0].WTxID] = txid
	f.mp.mu.Unlock()
	requireCompactCandidateRead(t, <-reads, 2, nil)
	requireCompactStandardPreservedRead(t, f.mp, f.ids[0], uint64(len(f.raw[0])), 1, f.raw[0])
}

func compactStandardCanonical(t *testing.T) {
	for _, row := range []struct {
		name string
		bad  func([]byte) []byte
	}{
		{"nil", func([]byte) []byte { return nil }}, {"empty", func([]byte) []byte { return []byte{} }}, {"trailing", func(raw []byte) []byte { return append(raw, 0) }},
		{"truncated", func(raw []byte) []byte { return raw[:len(raw)-1] }}, {"noncanonical", func(raw []byte) []byte { raw[0] ^= 0xff; return raw }}, {"nonminimal", func(raw []byte) []byte { return append(append(slices.Clone(raw[:13]), 0xfd, 1, 0), raw[14:]...) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newCompactStandardFixture(t, 2)
			entry := f.mp.txs[f.ids[0].TxID]
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
		entry := f.mp.txs[id.TxID]
		switch mutation {
		case "kind":
			da := newDAAdmissionCandidateFixture(t, 2)
			da.admission.Close()
			delete(f.mp.txs, id.TxID)
			delete(f.mp.wtxids, id.WTxID)
			entry.raw, entry.txid, entry.wtxid, entry.size = slices.Clone(da.raw), da.txid, da.wtxid, len(da.raw)
			id = CompactCandidateIdentity{TxID: da.txid, WTxID: da.wtxid}
			f.mp.txs[id.TxID], f.mp.wtxids[id.WTxID] = entry, id.TxID
		case "txid":
			delete(f.mp.txs, id.TxID)
			delete(f.mp.wtxids, id.WTxID)
			id.TxID[0] ^= 1
			entry.txid = id.TxID
			f.mp.txs[id.TxID], f.mp.wtxids[id.WTxID] = entry, id.TxID
		case "wtxid":
			delete(f.mp.wtxids, id.WTxID)
			id.WTxID[0] ^= 1
			entry.wtxid = id.WTxID
			f.mp.wtxids[id.WTxID] = id.TxID
		}
		if ids, ok := f.mp.CompactStandardIdentities(); !ok || len(ids) != 2 {
			t.Fatalf("%s raw obtained snapshot verdict", mutation)
		}
		requireCompactStandardPreservedRead(t, f.mp, id, uint64(len(entry.raw)), 3, nil)
		requireCompactStandardPreservedRead(t, f.mp, id, uint64(len(entry.raw)-1), 4, nil)
		requireCompactCandidateRead(t, f.mp.ReadCompactStandard(f.ids[1], ^uint64(0)), 1, f.raw[1])
	}
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
	mp := &Mempool{txs: map[[32]byte]*mempoolEntry{
		{0x01}: {},
		{0x02}: {},
		{0x03}: {},
	}}
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

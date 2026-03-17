package consensus

import (
	"sync"
	"testing"
)

// --------------- helpers ---------------

func testOutpoint(txidByte byte, vout uint32) Outpoint {
	var id [32]byte
	id[0] = txidByte
	return Outpoint{Txid: id, Vout: vout}
}

func testEntry(value uint64, covType uint16) UtxoEntry {
	return UtxoEntry{
		Value:        value,
		CovenantType: covType,
	}
}

func testUtxoSet() map[Outpoint]UtxoEntry {
	return map[Outpoint]UtxoEntry{
		testOutpoint(0xAA, 0): testEntry(1000, 0),
		testOutpoint(0xAA, 1): testEntry(2000, 0),
		testOutpoint(0xBB, 0): testEntry(3000, 1),
		testOutpoint(0xCC, 0): testEntry(4000, 2),
	}
}

// --------------- NewUtxoSnapshot ---------------

func TestUtxoSnapshot_Nil(t *testing.T) {
	snap := NewUtxoSnapshot(nil)
	if snap.Count() != 0 {
		t.Fatalf("Count=%d, want 0", snap.Count())
	}
	_, ok := snap.Get(testOutpoint(0xAA, 0))
	if ok {
		t.Fatal("expected not found in nil snapshot")
	}
}

func TestUtxoSnapshot_Empty(t *testing.T) {
	snap := NewUtxoSnapshot(make(map[Outpoint]UtxoEntry))
	if snap.Count() != 0 {
		t.Fatalf("Count=%d, want 0", snap.Count())
	}
}

func TestUtxoSnapshot_BasicLookup(t *testing.T) {
	snap := NewUtxoSnapshot(testUtxoSet())
	if snap.Count() != 4 {
		t.Fatalf("Count=%d, want 4", snap.Count())
	}

	e, ok := snap.Get(testOutpoint(0xAA, 0))
	if !ok {
		t.Fatal("expected to find (0xAA, 0)")
	}
	if e.Value != 1000 {
		t.Fatalf("Value=%d, want 1000", e.Value)
	}

	e, ok = snap.Get(testOutpoint(0xBB, 0))
	if !ok {
		t.Fatal("expected to find (0xBB, 0)")
	}
	if e.Value != 3000 || e.CovenantType != 1 {
		t.Fatalf("entry mismatch: value=%d type=%d", e.Value, e.CovenantType)
	}

	_, ok = snap.Get(testOutpoint(0xFF, 0))
	if ok {
		t.Fatal("expected not found for (0xFF, 0)")
	}
}

func TestUtxoSnapshot_Contains(t *testing.T) {
	snap := NewUtxoSnapshot(testUtxoSet())
	if !snap.Contains(testOutpoint(0xAA, 0)) {
		t.Fatal("expected Contains=true for (0xAA, 0)")
	}
	if snap.Contains(testOutpoint(0xFF, 0)) {
		t.Fatal("expected Contains=false for (0xFF, 0)")
	}
}

// --------------- immutability ---------------

func TestUtxoSnapshot_ImmutableAfterCreation(t *testing.T) {
	original := testUtxoSet()
	snap := NewUtxoSnapshot(original)

	// Mutate the original map — snapshot should be unaffected.
	delete(original, testOutpoint(0xAA, 0))
	original[testOutpoint(0xFF, 0)] = testEntry(9999, 0)

	// Snapshot still has original entries.
	if snap.Count() != 4 {
		t.Fatalf("Count=%d after mutation, want 4", snap.Count())
	}
	e, ok := snap.Get(testOutpoint(0xAA, 0))
	if !ok || e.Value != 1000 {
		t.Fatalf("snapshot corrupted by original mutation: ok=%v value=%d", ok, e.Value)
	}
	// Snapshot does NOT have the new entry.
	if snap.Contains(testOutpoint(0xFF, 0)) {
		t.Fatal("snapshot leaked mutation from original")
	}
}

// --------------- concurrent reads ---------------

func TestUtxoSnapshot_ConcurrentReads(t *testing.T) {
	snap := NewUtxoSnapshot(testUtxoSet())
	ops := []Outpoint{
		testOutpoint(0xAA, 0),
		testOutpoint(0xAA, 1),
		testOutpoint(0xBB, 0),
		testOutpoint(0xCC, 0),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			op := ops[idx%len(ops)]
			e, ok := snap.Get(op)
			if !ok {
				t.Errorf("goroutine %d: not found for %v", idx, op)
				return
			}
			if e.Value == 0 {
				t.Errorf("goroutine %d: zero value", idx)
			}
		}(i)
	}
	wg.Wait()
}

// --------------- Shard ---------------

func TestShard_ZeroShards(t *testing.T) {
	if s := Shard(testOutpoint(0xAA, 0), 0); s != 0 {
		t.Fatalf("Shard(0)=%d, want 0", s)
	}
	if s := Shard(testOutpoint(0xAA, 0), -1); s != 0 {
		t.Fatalf("Shard(-1)=%d, want 0", s)
	}
}

func TestShard_OneShard(t *testing.T) {
	if s := Shard(testOutpoint(0xAA, 0), 1); s != 0 {
		t.Fatalf("Shard(1)=%d, want 0", s)
	}
}

func TestShard_Deterministic(t *testing.T) {
	op := testOutpoint(0xAB, 3)
	s1 := Shard(op, 8)
	s2 := Shard(op, 8)
	if s1 != s2 {
		t.Fatalf("Shard not deterministic: %d != %d", s1, s2)
	}
}

func TestShard_Distribution(t *testing.T) {
	// 256 outpoints with realistic txid distribution across 4 shards.
	// Use all 4 bytes of txid to get meaningful distribution.
	counts := make([]int, 4)
	for i := 0; i < 256; i++ {
		var id [32]byte
		// Spread across all 4 bytes used by Shard.
		id[0] = byte(i)
		id[1] = byte(i * 7)
		id[2] = byte(i * 13)
		id[3] = byte(i * 31)
		op := Outpoint{Txid: id, Vout: 0}
		s := Shard(op, 4)
		if s < 0 || s >= 4 {
			t.Fatalf("Shard out of range: %d", s)
		}
		counts[s]++
	}
	for i, c := range counts {
		if c == 0 {
			t.Fatalf("shard %d got 0 entries", i)
		}
	}
}

func TestShard_DifferentOutpointsSamePrefix(t *testing.T) {
	// Same txid byte but different vout → same shard (shard uses txid only).
	s1 := Shard(testOutpoint(0xAA, 0), 8)
	s2 := Shard(testOutpoint(0xAA, 1), 8)
	if s1 != s2 {
		t.Fatalf("same txid different vout → different shards: %d != %d", s1, s2)
	}
}

// --------------- ResolveInputs ---------------

func TestResolveInputs_AllFound(t *testing.T) {
	snap := NewUtxoSnapshot(testUtxoSet())
	tx := &Tx{
		Inputs: []TxInput{
			{PrevTxid: testOutpoint(0xAA, 0).Txid, PrevVout: testOutpoint(0xAA, 0).Vout},
			{PrevTxid: testOutpoint(0xBB, 0).Txid, PrevVout: testOutpoint(0xBB, 0).Vout},
		},
	}
	entries, err := snap.ResolveInputs(tx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Value != 1000 {
		t.Fatalf("entries[0].Value=%d, want 1000", entries[0].Value)
	}
	if entries[1].Value != 3000 {
		t.Fatalf("entries[1].Value=%d, want 3000", entries[1].Value)
	}
}

func TestResolveInputs_MissingUtxo(t *testing.T) {
	snap := NewUtxoSnapshot(testUtxoSet())
	tx := &Tx{
		Inputs: []TxInput{
			{PrevTxid: testOutpoint(0xAA, 0).Txid, PrevVout: testOutpoint(0xAA, 0).Vout},
			{PrevTxid: testOutpoint(0xFF, 0).Txid, PrevVout: testOutpoint(0xFF, 0).Vout}, // missing
		},
	}
	_, err := snap.ResolveInputs(tx)
	if err == nil {
		t.Fatal("expected error for missing UTXO")
	}
}

func TestResolveInputs_EmptyInputs(t *testing.T) {
	snap := NewUtxoSnapshot(testUtxoSet())
	tx := &Tx{}
	entries, err := snap.ResolveInputs(tx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

// --------------- ForEach ---------------

func TestForEach(t *testing.T) {
	snap := NewUtxoSnapshot(testUtxoSet())
	var count int
	var totalValue uint64
	snap.ForEach(func(_ Outpoint, e UtxoEntry) {
		count++
		totalValue += e.Value
	})
	if count != 4 {
		t.Fatalf("ForEach count=%d, want 4", count)
	}
	if totalValue != 10000 { // 1000+2000+3000+4000
		t.Fatalf("ForEach totalValue=%d, want 10000", totalValue)
	}
}

// --------------- sequential vs parallel parity ---------------

func TestUtxoSnapshot_SequentialParallelParity(t *testing.T) {
	// Build snapshot, then verify both sequential and concurrent reads
	// return identical results.
	utxos := make(map[Outpoint]UtxoEntry, 100)
	for i := 0; i < 100; i++ {
		utxos[testOutpoint(byte(i), 0)] = testEntry(uint64(i*100), uint16(i%3))
	}
	snap := NewUtxoSnapshot(utxos)

	// Sequential results.
	seqResults := make(map[Outpoint]UtxoEntry, 100)
	for i := 0; i < 100; i++ {
		op := testOutpoint(byte(i), 0)
		e, ok := snap.Get(op)
		if !ok {
			t.Fatalf("seq: not found for byte %d", i)
		}
		seqResults[op] = e
	}

	// Parallel results.
	parResults := make(map[Outpoint]UtxoEntry, 100)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			op := testOutpoint(byte(idx), 0)
			e, ok := snap.Get(op)
			if !ok {
				t.Errorf("par: not found for byte %d", idx)
				return
			}
			mu.Lock()
			parResults[op] = e
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Compare.
	for op, seqE := range seqResults {
		parE, ok := parResults[op]
		if !ok {
			t.Fatalf("parity: missing parallel result for %v", op)
		}
		if seqE.Value != parE.Value || seqE.CovenantType != parE.CovenantType {
			t.Fatalf("parity mismatch at %v: seq=%+v par=%+v", op, seqE, parE)
		}
	}
}

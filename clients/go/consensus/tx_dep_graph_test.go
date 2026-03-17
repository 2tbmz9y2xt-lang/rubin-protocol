package consensus

import (
	"testing"
)

// --------------- helpers ---------------

func makeTxContext(idx int, txid byte, outpoints []Outpoint) TxValidationContext {
	var id [32]byte
	id[0] = txid
	return TxValidationContext{
		TxIndex:        idx + 1, // 1-based (non-coinbase)
		Txid:           id,
		InputOutpoints: outpoints,
	}
}

func op(txidByte byte, vout uint32) Outpoint {
	var id [32]byte
	id[0] = txidByte
	return Outpoint{Txid: id, Vout: vout}
}

// --------------- tests ---------------

func TestBuildTxDepGraph_Empty(t *testing.T) {
	g := BuildTxDepGraph(nil)
	if g.TxCount != 0 {
		t.Fatalf("TxCount=%d, want 0", g.TxCount)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("Edges=%d, want 0", len(g.Edges))
	}
}

func TestBuildTxDepGraph_SingleTx(t *testing.T) {
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if g.TxCount != 1 {
		t.Fatalf("TxCount=%d, want 1", g.TxCount)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("Edges=%d, want 0", len(g.Edges))
	}
	if g.MaxLevel != 0 {
		t.Fatalf("MaxLevel=%d, want 0", g.MaxLevel)
	}
	if len(g.LevelOrder) != 1 || g.LevelOrder[0] != 0 {
		t.Fatalf("LevelOrder=%v, want [0]", g.LevelOrder)
	}
}

func TestBuildTxDepGraph_IndependentTxs(t *testing.T) {
	// 3 txs, each spending different external outpoints — no deps.
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0x02, 0)}),
		makeTxContext(2, 0xCC, []Outpoint{op(0x03, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if len(g.Edges) != 0 {
		t.Fatalf("Edges=%d, want 0", len(g.Edges))
	}
	if g.MaxLevel != 0 {
		t.Fatalf("MaxLevel=%d, want 0", g.MaxLevel)
	}
	// All at level 0.
	for i, l := range g.Levels {
		if l != 0 {
			t.Fatalf("Levels[%d]=%d, want 0", i, l)
		}
	}
}

func TestBuildTxDepGraph_ParentChild(t *testing.T) {
	// tx[0] creates output, tx[1] spends it.
	// tx[0] txid = 0xAA, tx[1] spends outpoint (0xAA, 0).
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0xAA, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if len(g.Edges) != 1 {
		t.Fatalf("Edges=%d, want 1", len(g.Edges))
	}
	e := g.Edges[0]
	if e.ProducerIdx != 0 || e.ConsumerIdx != 1 || e.Kind != DepParentChild {
		t.Fatalf("edge: producer=%d consumer=%d kind=%d, want 0,1,ParentChild",
			e.ProducerIdx, e.ConsumerIdx, e.Kind)
	}
	if g.Levels[0] != 0 || g.Levels[1] != 1 {
		t.Fatalf("Levels=%v, want [0,1]", g.Levels)
	}
	if g.MaxLevel != 1 {
		t.Fatalf("MaxLevel=%d, want 1", g.MaxLevel)
	}
}

func TestBuildTxDepGraph_ParentChildChain(t *testing.T) {
	// tx[0] → tx[1] → tx[2]: 3-level chain.
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0xAA, 0)}),
		makeTxContext(2, 0xCC, []Outpoint{op(0xBB, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if len(g.Edges) != 2 {
		t.Fatalf("Edges=%d, want 2", len(g.Edges))
	}
	if g.Levels[0] != 0 || g.Levels[1] != 1 || g.Levels[2] != 2 {
		t.Fatalf("Levels=%v, want [0,1,2]", g.Levels)
	}
	if g.MaxLevel != 2 {
		t.Fatalf("MaxLevel=%d, want 2", g.MaxLevel)
	}
}

func TestBuildTxDepGraph_SamePrevout(t *testing.T) {
	// tx[0] and tx[1] both spend outpoint (0x01, 0) — same-prevout conflict.
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0x01, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if len(g.Edges) != 1 {
		t.Fatalf("Edges=%d, want 1", len(g.Edges))
	}
	e := g.Edges[0]
	if e.ProducerIdx != 0 || e.ConsumerIdx != 1 || e.Kind != DepSamePrevout {
		t.Fatalf("edge: producer=%d consumer=%d kind=%d, want 0,1,SamePrevout",
			e.ProducerIdx, e.ConsumerIdx, e.Kind)
	}
	// Same-prevout creates a dependency: tx[1] at level 1.
	if g.Levels[0] != 0 || g.Levels[1] != 1 {
		t.Fatalf("Levels=%v, want [0,1]", g.Levels)
	}
}

func TestBuildTxDepGraph_MixedEdges(t *testing.T) {
	// tx[0]: spends external (0x01, 0), creates 0xAA outputs
	// tx[1]: spends external (0x01, 0) — same-prevout with tx[0]
	// tx[2]: spends (0xAA, 0) — parent-child from tx[0]
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0x01, 0)}),
		makeTxContext(2, 0xCC, []Outpoint{op(0xAA, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if len(g.Edges) != 2 {
		t.Fatalf("Edges=%d, want 2", len(g.Edges))
	}

	// tx[0] → tx[1] (same-prevout), tx[0] → tx[2] (parent-child)
	// Both at level 1.
	if g.Levels[0] != 0 {
		t.Fatalf("Levels[0]=%d, want 0", g.Levels[0])
	}
	if g.Levels[1] != 1 {
		t.Fatalf("Levels[1]=%d, want 1", g.Levels[1])
	}
	if g.Levels[2] != 1 {
		t.Fatalf("Levels[2]=%d, want 1", g.Levels[2])
	}
}

func TestBuildTxDepGraph_LevelOrderDeterministic(t *testing.T) {
	// 3 independent txs at level 0, ordered by txid lexicographically.
	// txids: 0xCC, 0xAA, 0xBB → sorted order should be 0xAA, 0xBB, 0xCC.
	contexts := []TxValidationContext{
		makeTxContext(0, 0xCC, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xAA, []Outpoint{op(0x02, 0)}),
		makeTxContext(2, 0xBB, []Outpoint{op(0x03, 0)}),
	}
	g := BuildTxDepGraph(contexts)

	// LevelOrder should be [1, 2, 0] (by txid: 0xAA=idx1, 0xBB=idx2, 0xCC=idx0)
	if len(g.LevelOrder) != 3 {
		t.Fatalf("LevelOrder len=%d, want 3", len(g.LevelOrder))
	}
	if g.LevelOrder[0] != 1 || g.LevelOrder[1] != 2 || g.LevelOrder[2] != 0 {
		t.Fatalf("LevelOrder=%v, want [1,2,0]", g.LevelOrder)
	}
}

func TestBuildTxDepGraph_LevelOrderMultiLevel(t *testing.T) {
	// tx[0](0xBB) → tx[1](0xAA) parent-child, tx[2](0xCC) independent
	// Level 0: tx[0], tx[2]; Level 1: tx[1]
	// Level 0 order by txid: tx[0](0xBB), tx[2](0xCC) → [0, 2]
	// Level 1: tx[1](0xAA) → [1]
	// Full order: [0, 2, 1]
	contexts := []TxValidationContext{
		makeTxContext(0, 0xBB, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xAA, []Outpoint{op(0xBB, 0)}),
		makeTxContext(2, 0xCC, []Outpoint{op(0x02, 0)}),
	}
	g := BuildTxDepGraph(contexts)

	if g.MaxLevel != 1 {
		t.Fatalf("MaxLevel=%d, want 1", g.MaxLevel)
	}
	if g.LevelOrder[0] != 0 || g.LevelOrder[1] != 2 || g.LevelOrder[2] != 1 {
		t.Fatalf("LevelOrder=%v, want [0,2,1]", g.LevelOrder)
	}
}

func TestBuildTxDepGraph_DiamondDependency(t *testing.T) {
	// Diamond: tx[0] → tx[1], tx[0] → tx[2], tx[1] → tx[3], tx[2] → tx[3]
	// tx[0] creates outputs spent by tx[1] and tx[2], both create outputs spent by tx[3].
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0xAA, 0)}),
		makeTxContext(2, 0xCC, []Outpoint{op(0xAA, 1)}),
		makeTxContext(3, 0xDD, []Outpoint{op(0xBB, 0), op(0xCC, 0)}),
	}
	g := BuildTxDepGraph(contexts)

	// tx[0]=level 0, tx[1]=level 1, tx[2]=level 1, tx[3]=level 2
	if g.Levels[0] != 0 || g.Levels[1] != 1 || g.Levels[2] != 1 || g.Levels[3] != 2 {
		t.Fatalf("Levels=%v, want [0,1,1,2]", g.Levels)
	}
	if g.MaxLevel != 2 {
		t.Fatalf("MaxLevel=%d, want 2", g.MaxLevel)
	}
	if len(g.Edges) != 4 {
		t.Fatalf("Edges=%d, want 4", len(g.Edges))
	}
}

func TestBuildTxDepGraph_EdgesSorted(t *testing.T) {
	// Verify edges are sorted by (ConsumerIdx, ProducerIdx, Kind).
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0xAA, 0)}),
		makeTxContext(2, 0xCC, []Outpoint{op(0x01, 0), op(0xAA, 1)}),
	}
	g := BuildTxDepGraph(contexts)

	for i := 1; i < len(g.Edges); i++ {
		prev, cur := g.Edges[i-1], g.Edges[i]
		if prev.ConsumerIdx > cur.ConsumerIdx {
			t.Fatalf("edges not sorted by ConsumerIdx at %d", i)
		}
		if prev.ConsumerIdx == cur.ConsumerIdx && prev.ProducerIdx > cur.ProducerIdx {
			t.Fatalf("edges not sorted by ProducerIdx at %d", i)
		}
	}
}

func TestBuildTxDepGraph_NoSelfEdge(t *testing.T) {
	// A tx spending its own output would be invalid in practice,
	// but verify the graph doesn't create self-edges.
	// tx[0] txid=0xAA spends (0xAA, 0) — this is itself, but txidToIdx[0xAA]=0
	// and producerIdx=0 is NOT < 0, so no edge.
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0xAA, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if len(g.Edges) != 0 {
		t.Fatalf("Edges=%d, want 0 (no self-edge)", len(g.Edges))
	}
}

func TestBuildTxDepGraph_ThreeSamePrevout(t *testing.T) {
	// 3 txs all spending same outpoint. Edges: 0→1, 0→2 (first consumer is 0).
	contexts := []TxValidationContext{
		makeTxContext(0, 0xAA, []Outpoint{op(0x01, 0)}),
		makeTxContext(1, 0xBB, []Outpoint{op(0x01, 0)}),
		makeTxContext(2, 0xCC, []Outpoint{op(0x01, 0)}),
	}
	g := BuildTxDepGraph(contexts)
	if len(g.Edges) != 2 {
		t.Fatalf("Edges=%d, want 2", len(g.Edges))
	}
	// Both edges from producer 0.
	for _, e := range g.Edges {
		if e.ProducerIdx != 0 {
			t.Fatalf("expected producer=0, got %d", e.ProducerIdx)
		}
		if e.Kind != DepSamePrevout {
			t.Fatalf("expected SamePrevout, got %d", e.Kind)
		}
	}
}

func TestBuildTxDepGraph_LargeIndependent(t *testing.T) {
	// 100 independent txs — all at level 0.
	n := 100
	contexts := make([]TxValidationContext, n)
	for i := 0; i < n; i++ {
		contexts[i] = makeTxContext(i, byte(i+1), []Outpoint{op(byte(i+1), uint32(i))})
	}
	g := BuildTxDepGraph(contexts)
	if g.TxCount != n {
		t.Fatalf("TxCount=%d, want %d", g.TxCount, n)
	}
	if len(g.Edges) != 0 {
		t.Fatalf("Edges=%d, want 0", len(g.Edges))
	}
	if g.MaxLevel != 0 {
		t.Fatalf("MaxLevel=%d, want 0", g.MaxLevel)
	}
}

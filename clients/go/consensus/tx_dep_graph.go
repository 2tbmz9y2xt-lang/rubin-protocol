package consensus

import (
	"bytes"
	"sort"
)

// TxDepEdge represents a dependency between two non-coinbase transactions
// within the same block. ProducerIdx and ConsumerIdx are 0-based indices
// into the non-coinbase transaction slice (i.e. pb.Txs[1:]).
type TxDepEdge struct {
	ProducerIdx int
	ConsumerIdx int
	Kind        TxDepEdgeKind
}

// TxDepEdgeKind classifies dependency edges.
type TxDepEdgeKind uint8

const (
	// DepParentChild means ConsumerIdx spends an output created by ProducerIdx
	// within the same block.
	DepParentChild TxDepEdgeKind = iota

	// DepSamePrevout means both transactions attempt to spend the same
	// pre-existing UTXO. In a valid block only one can succeed; the graph
	// records the ordering constraint so that parallel validation can
	// detect the conflict deterministically.
	DepSamePrevout
)

// TxDepGraph is a deterministic dependency graph over non-coinbase transactions
// in a single block. It supports topological-level assignment for parallel
// validation scheduling.
type TxDepGraph struct {
	// TxCount is the number of non-coinbase transactions.
	TxCount int

	// Edges is the complete list of dependency edges, sorted deterministically.
	Edges []TxDepEdge

	// Levels assigns each transaction to a topological level (0-based).
	// Transactions at the same level have no inter-dependencies and may be
	// validated in parallel. Level 0 transactions depend only on the
	// block-start UTXO snapshot.
	Levels []int

	// LevelOrder is a deterministic ordering of transaction indices, grouped
	// by level. Within each level, transactions are sorted by their txid
	// (lexicographic, ascending) for deterministic tie-breaking.
	LevelOrder []int

	// MaxLevel is the highest level in the graph (0-based).
	MaxLevel int
}

// BuildTxDepGraph constructs a deterministic dependency graph from precomputed
// transaction contexts. The contexts slice corresponds to non-coinbase
// transactions (pb.Txs[1:]).
//
// Two types of edges are detected:
//  1. Parent-child: tx[j] spends an output created by tx[i] where i < j.
//     Detected via txid match between input outpoints and earlier tx outputs.
//  2. Same-prevout: tx[i] and tx[j] both spend the same outpoint from the
//     block-start UTXO snapshot. The lower-index tx is the "producer" for
//     ordering purposes.
//
// After edge construction, the graph computes topological levels using the
// longest-path algorithm, then produces a deterministic LevelOrder using
// lexicographic txid tie-breaking within each level.
func BuildTxDepGraph(contexts []TxValidationContext) *TxDepGraph {
	n := len(contexts)
	if n == 0 {
		return &TxDepGraph{}
	}

	// Map txid → context index for parent-child detection.
	txidToIdx := make(map[[32]byte]int, n)
	for i := range contexts {
		txidToIdx[contexts[i].Txid] = i
	}

	// Map outpoint → first consumer index for same-prevout detection.
	outpointFirstConsumer := make(map[Outpoint]int)

	var edges []TxDepEdge

	for i := range contexts {
		for _, op := range contexts[i].InputOutpoints {
			// Parent-child: does this outpoint reference an earlier tx in the block?
			if producerIdx, ok := txidToIdx[op.Txid]; ok && producerIdx < i {
				edges = append(edges, TxDepEdge{
					ProducerIdx: producerIdx,
					ConsumerIdx: i,
					Kind:        DepParentChild,
				})
				continue
			}

			// Same-prevout: another tx already consumed this outpoint.
			if firstIdx, ok := outpointFirstConsumer[op]; ok && firstIdx != i {
				// Lower index is always "producer" for determinism.
				lo, hi := firstIdx, i
				if lo > hi {
					lo, hi = hi, lo
				}
				edges = append(edges, TxDepEdge{
					ProducerIdx: lo,
					ConsumerIdx: hi,
					Kind:        DepSamePrevout,
				})
			} else if !ok {
				outpointFirstConsumer[op] = i
			}
		}
	}

	// Sort edges deterministically: by ConsumerIdx, then ProducerIdx, then Kind.
	sort.Slice(edges, func(a, b int) bool {
		if edges[a].ConsumerIdx != edges[b].ConsumerIdx {
			return edges[a].ConsumerIdx < edges[b].ConsumerIdx
		}
		if edges[a].ProducerIdx != edges[b].ProducerIdx {
			return edges[a].ProducerIdx < edges[b].ProducerIdx
		}
		return edges[a].Kind < edges[b].Kind
	})

	// Compute topological levels using longest-path from roots.
	levels := make([]int, n)
	for _, e := range edges {
		if levels[e.ProducerIdx]+1 > levels[e.ConsumerIdx] {
			levels[e.ConsumerIdx] = levels[e.ProducerIdx] + 1
		}
	}

	maxLevel := 0
	for _, l := range levels {
		if l > maxLevel {
			maxLevel = l
		}
	}

	// Build level order with lexicographic txid tie-break.
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		la, lb := levels[order[a]], levels[order[b]]
		if la != lb {
			return la < lb
		}
		return bytes.Compare(contexts[order[a]].Txid[:], contexts[order[b]].Txid[:]) < 0
	})

	return &TxDepGraph{
		TxCount:    n,
		Edges:      edges,
		Levels:     levels,
		LevelOrder: order,
		MaxLevel:   maxLevel,
	}
}

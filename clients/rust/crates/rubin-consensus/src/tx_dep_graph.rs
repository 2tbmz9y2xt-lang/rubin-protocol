use crate::utxo_basic::Outpoint;

/// Immutable per-transaction context needed to build deterministic same-block
/// dependency ordering for the future parallel validation path.
///
/// This starts with the graph-critical subset of the Go precompute context and
/// will be extended by the precompute slice without changing graph semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxValidationContext {
    /// 1-based transaction position inside the block; coinbase is index 0 and
    /// excluded from this context slice.
    pub tx_index: usize,
    /// Canonical transaction identifier.
    pub txid: [u8; 32],
    /// Input outpoints in input order.
    pub input_outpoints: Vec<Outpoint>,
}

/// Dependency kind between two non-coinbase transactions in the same block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TxDepEdgeKind {
    /// Consumer spends an output created by Producer inside the same block.
    ParentChild = 0,
    /// Both transactions spend the same pre-existing UTXO from the block-start
    /// snapshot. The lower index wins for deterministic ordering.
    SamePrevout = 1,
}

/// Deterministic edge between two non-coinbase transactions in the same block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxDepEdge {
    pub producer_idx: usize,
    pub consumer_idx: usize,
    pub kind: TxDepEdgeKind,
}

/// Deterministic scheduling graph for same-block read-only validation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxDepGraph {
    pub tx_count: usize,
    pub edges: Vec<TxDepEdge>,
    pub levels: Vec<usize>,
    pub level_order: Vec<usize>,
    pub max_level: usize,
}

fn tx_dep_edge_sort_key(edge: &TxDepEdge) -> (usize, usize, TxDepEdgeKind) {
    (edge.consumer_idx, edge.producer_idx, edge.kind)
}

fn sort_tx_dep_edges(edges: &mut [TxDepEdge]) {
    let mut i = 1usize;
    while i < edges.len() {
        let current = edges[i];
        let mut j = i;
        while j > 0 && tx_dep_edge_sort_key(&current) < tx_dep_edge_sort_key(&edges[j - 1]) {
            edges[j] = edges[j - 1];
            j -= 1;
        }
        edges[j] = current;
        i += 1;
    }
}

fn compute_tx_dep_levels(tx_count: usize, edges: &[TxDepEdge]) -> (Vec<usize>, usize) {
    let mut levels = vec![0usize; tx_count];
    for edge in edges {
        levels[edge.consumer_idx] = levels[edge.consumer_idx].max(levels[edge.producer_idx] + 1);
    }
    let max_level = levels.iter().copied().max().unwrap_or(0);
    (levels, max_level)
}

fn tx_dep_level_order_key(
    contexts: &[TxValidationContext],
    levels: &[usize],
    idx: usize,
) -> (usize, [u8; 32]) {
    (levels[idx], contexts[idx].txid)
}

fn compute_tx_dep_level_order(contexts: &[TxValidationContext], levels: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..contexts.len()).collect();
    let mut i = 1usize;
    while i < order.len() {
        let current = order[i];
        let mut j = i;
        while j > 0
            && tx_dep_level_order_key(contexts, levels, current)
                < tx_dep_level_order_key(contexts, levels, order[j - 1])
        {
            order[j] = order[j - 1];
            j -= 1;
        }
        order[j] = current;
        i += 1;
    }
    order
}

/// Build the deterministic dependency graph over non-coinbase transactions.
///
/// The graph detects:
/// - parent-child edges, where a later transaction spends an output created by
///   an earlier transaction in the same block;
/// - same-prevout conflicts, where multiple transactions spend the same
///   block-start outpoint.
///
/// Levels are assigned using longest-path semantics. Level ordering is
/// deterministic: first by level, then by txid lexicographic order.
pub fn build_tx_dep_graph(contexts: &[TxValidationContext]) -> TxDepGraph {
    let tx_count = contexts.len();
    if tx_count == 0 {
        return TxDepGraph::default();
    }

    let mut outpoint_first_consumer: Vec<(Outpoint, usize)> = Vec::new();
    let mut edges = Vec::new();

    let mut consumer_idx = 0usize;
    while consumer_idx < tx_count {
        let ctx = &contexts[consumer_idx];
        for outpoint in &ctx.input_outpoints {
            let mut parent_idx = None;
            let mut scan_idx = 0usize;
            while scan_idx < consumer_idx {
                if contexts[scan_idx].txid == outpoint.txid {
                    parent_idx = Some(scan_idx);
                    break;
                }
                scan_idx += 1;
            }

            if let Some(producer_idx) = parent_idx {
                edges.push(TxDepEdge {
                    producer_idx,
                    consumer_idx,
                    kind: TxDepEdgeKind::ParentChild,
                });
                continue;
            }

            let mut first_consumer_idx = None;
            let mut seen_idx = 0usize;
            while seen_idx < outpoint_first_consumer.len() {
                let (seen_outpoint, first_idx) = &outpoint_first_consumer[seen_idx];
                if seen_outpoint == outpoint {
                    first_consumer_idx = Some(*first_idx);
                    break;
                }
                seen_idx += 1;
            }

            match first_consumer_idx {
                Some(first_idx) if first_idx != consumer_idx => {
                    let (producer_idx, consumer_idx) = if first_idx < consumer_idx {
                        (first_idx, consumer_idx)
                    } else {
                        (consumer_idx, first_idx)
                    };
                    edges.push(TxDepEdge {
                        producer_idx,
                        consumer_idx,
                        kind: TxDepEdgeKind::SamePrevout,
                    });
                }
                None => {
                    outpoint_first_consumer.push((outpoint.clone(), consumer_idx));
                }
                Some(_) => {}
            }
        }

        consumer_idx += 1;
    }

    sort_tx_dep_edges(&mut edges);
    let (levels, max_level) = compute_tx_dep_levels(tx_count, &edges);
    let level_order = compute_tx_dep_level_order(contexts, &levels);

    TxDepGraph {
        tx_count,
        edges,
        levels,
        level_order,
        max_level,
    }
}

#[cfg(kani)]
mod verification {
    use super::{
        compute_tx_dep_level_order, compute_tx_dep_levels, tx_dep_edge_sort_key, TxDepEdge,
        TxDepEdgeKind, TxValidationContext,
    };
    use crate::utxo_basic::Outpoint;

    fn make_tx_context(idx: usize, txid_byte: u8, outpoints: &[(u8, u32)]) -> TxValidationContext {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        TxValidationContext {
            tx_index: idx + 1,
            txid,
            input_outpoints: outpoints
                .iter()
                .map(|(outpoint_txid, vout)| {
                    let mut outpoint_id = [0u8; 32];
                    outpoint_id[0] = *outpoint_txid;
                    Outpoint {
                        txid: outpoint_id,
                        vout: *vout,
                    }
                })
                .collect(),
        }
    }

    fn assert_sorted_edges(edges: &[TxDepEdge]) {
        for window in edges.windows(2) {
            let prev = window[0];
            let cur = window[1];
            assert!(prev.consumer_idx <= cur.consumer_idx);
            if prev.consumer_idx == cur.consumer_idx {
                assert!(prev.producer_idx <= cur.producer_idx);
                if prev.producer_idx == cur.producer_idx {
                    assert!(prev.kind <= cur.kind);
                }
            }
        }
    }

    fn assert_level_order(contexts: &[TxValidationContext], levels: &[usize], order: &[usize]) {
        for window in order.windows(2) {
            let left = window[0];
            let right = window[1];
            let left_level = levels[left];
            let right_level = levels[right];
            assert!(left_level <= right_level);
            if left_level == right_level {
                assert!(contexts[left].txid <= contexts[right].txid);
            }
        }
    }

    fn assert_edge_and_level_invariants(tx_count: usize, edges: &[TxDepEdge], levels: &[usize]) {
        assert_eq!(levels.len(), tx_count);
        for edge in edges {
            assert!(edge.producer_idx < edge.consumer_idx);
            assert!(edge.consumer_idx < tx_count);
            assert!(levels[edge.producer_idx] < levels[edge.consumer_idx]);
        }
        assert_sorted_edges(edges);
    }

    #[kani::proof]
    fn verify_tx_dep_edge_sort_key_orders_consumer_then_producer_then_kind() {
        let early = TxDepEdge {
            producer_idx: 0,
            consumer_idx: 1,
            kind: TxDepEdgeKind::ParentChild,
        };
        let late = TxDepEdge {
            producer_idx: 1,
            consumer_idx: 2,
            kind: TxDepEdgeKind::SamePrevout,
        };

        assert!(tx_dep_edge_sort_key(&early) < tx_dep_edge_sort_key(&late));
    }

    #[kani::proof]
    fn verify_compute_tx_dep_levels_parent_child_chain_is_acyclic() {
        let edges = vec![
            TxDepEdge {
                producer_idx: 0,
                consumer_idx: 1,
                kind: TxDepEdgeKind::ParentChild,
            },
            TxDepEdge {
                producer_idx: 1,
                consumer_idx: 2,
                kind: TxDepEdgeKind::ParentChild,
            },
        ];
        let (levels, max_level) = compute_tx_dep_levels(3, &edges);

        assert_edge_and_level_invariants(3, &edges, &levels);
        assert_eq!(levels, vec![0, 1, 2]);
        assert_eq!(max_level, 2);
    }

    #[kani::proof]
    fn verify_compute_tx_dep_levels_same_prevout_fanout_is_stable() {
        let edges = vec![
            TxDepEdge {
                producer_idx: 0,
                consumer_idx: 1,
                kind: TxDepEdgeKind::SamePrevout,
            },
            TxDepEdge {
                producer_idx: 0,
                consumer_idx: 2,
                kind: TxDepEdgeKind::SamePrevout,
            },
        ];
        let (levels, max_level) = compute_tx_dep_levels(3, &edges);

        assert_edge_and_level_invariants(3, &edges, &levels);
        assert_eq!(levels, vec![0, 1, 1]);
        assert_eq!(max_level, 1);
        for edge in &edges {
            assert_eq!(edge.producer_idx, 0);
            assert_eq!(edge.kind, TxDepEdgeKind::SamePrevout);
        }
    }

    #[kani::proof]
    fn verify_compute_tx_dep_level_order_uses_level_then_txid() {
        let contexts = vec![
            make_tx_context(0, 0xcc, &[(0x01, 0)]),
            make_tx_context(1, 0xaa, &[(0x02, 0)]),
            make_tx_context(2, 0xbb, &[(0x03, 0)]),
        ];
        let levels = vec![0, 0, 0];
        let order = compute_tx_dep_level_order(&contexts, &levels);

        assert_level_order(&contexts, &levels, &order);
        assert_eq!(order, vec![1, 2, 0]);
    }
}

#[cfg(test)]
mod tests {
    use super::{build_tx_dep_graph, TxDepEdgeKind, TxValidationContext};
    use crate::utxo_basic::Outpoint;

    fn make_tx_context(idx: usize, txid_byte: u8, outpoints: &[(u8, u32)]) -> TxValidationContext {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        TxValidationContext {
            tx_index: idx + 1,
            txid,
            input_outpoints: outpoints
                .iter()
                .map(|(outpoint_txid, vout)| {
                    let mut outpoint_id = [0u8; 32];
                    outpoint_id[0] = *outpoint_txid;
                    Outpoint {
                        txid: outpoint_id,
                        vout: *vout,
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn build_tx_dep_graph_empty() {
        let graph = build_tx_dep_graph(&[]);
        assert_eq!(graph.tx_count, 0);
        assert!(graph.edges.is_empty());
        assert!(graph.levels.is_empty());
        assert!(graph.level_order.is_empty());
        assert_eq!(graph.max_level, 0);
    }

    #[test]
    fn build_tx_dep_graph_single_tx() {
        let contexts = vec![make_tx_context(0, 0xaa, &[(0x01, 0)])];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.tx_count, 1);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.levels, vec![0]);
        assert_eq!(graph.level_order, vec![0]);
        assert_eq!(graph.max_level, 0);
    }

    #[test]
    fn build_tx_dep_graph_independent_txs() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0x02, 0)]),
            make_tx_context(2, 0xcc, &[(0x03, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert!(graph.edges.is_empty());
        assert_eq!(graph.levels, vec![0, 0, 0]);
        assert_eq!(graph.max_level, 0);
    }

    #[test]
    fn build_tx_dep_graph_parent_child() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0xaa, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].producer_idx, 0);
        assert_eq!(graph.edges[0].consumer_idx, 1);
        assert_eq!(graph.edges[0].kind, TxDepEdgeKind::ParentChild);
        assert_eq!(graph.levels, vec![0, 1]);
        assert_eq!(graph.max_level, 1);
    }

    #[test]
    fn build_tx_dep_graph_parent_child_chain() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0xaa, 0)]),
            make_tx_context(2, 0xcc, &[(0xbb, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.edges.len(), 2);
        assert_eq!(graph.levels, vec![0, 1, 2]);
        assert_eq!(graph.max_level, 2);
    }

    #[test]
    fn build_tx_dep_graph_same_prevout() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0x01, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].producer_idx, 0);
        assert_eq!(graph.edges[0].consumer_idx, 1);
        assert_eq!(graph.edges[0].kind, TxDepEdgeKind::SamePrevout);
        assert_eq!(graph.levels, vec![0, 1]);
    }

    #[test]
    fn build_tx_dep_graph_mixed_edges() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0x01, 0)]),
            make_tx_context(2, 0xcc, &[(0xaa, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.edges.len(), 2);
        assert_eq!(graph.levels, vec![0, 1, 1]);
    }

    #[test]
    fn build_tx_dep_graph_level_order_deterministic() {
        let contexts = vec![
            make_tx_context(0, 0xcc, &[(0x01, 0)]),
            make_tx_context(1, 0xaa, &[(0x02, 0)]),
            make_tx_context(2, 0xbb, &[(0x03, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.level_order, vec![1, 2, 0]);
    }

    #[test]
    fn build_tx_dep_graph_level_order_multi_level() {
        let contexts = vec![
            make_tx_context(0, 0xbb, &[(0x01, 0)]),
            make_tx_context(1, 0xaa, &[(0xbb, 0)]),
            make_tx_context(2, 0xcc, &[(0x02, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.max_level, 1);
        assert_eq!(graph.level_order, vec![0, 2, 1]);
    }

    #[test]
    fn build_tx_dep_graph_diamond_dependency() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0xaa, 0)]),
            make_tx_context(2, 0xcc, &[(0xaa, 1)]),
            make_tx_context(3, 0xdd, &[(0xbb, 0), (0xcc, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.levels, vec![0, 1, 1, 2]);
        assert_eq!(graph.max_level, 2);
        assert_eq!(graph.edges.len(), 4);
    }

    #[test]
    fn build_tx_dep_graph_edges_sorted() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0xaa, 0)]),
            make_tx_context(2, 0xcc, &[(0x01, 0), (0xaa, 1)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        for window in graph.edges.windows(2) {
            let prev = window[0];
            let cur = window[1];
            assert!(prev.consumer_idx <= cur.consumer_idx);
            if prev.consumer_idx == cur.consumer_idx {
                assert!(prev.producer_idx <= cur.producer_idx);
                if prev.producer_idx == cur.producer_idx {
                    assert!(prev.kind <= cur.kind);
                }
            }
        }
    }

    #[test]
    fn build_tx_dep_graph_no_self_edge() {
        let contexts = vec![make_tx_context(0, 0xaa, &[(0xaa, 0)])];
        let graph = build_tx_dep_graph(&contexts);
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn build_tx_dep_graph_three_same_prevout() {
        let contexts = vec![
            make_tx_context(0, 0xaa, &[(0x01, 0)]),
            make_tx_context(1, 0xbb, &[(0x01, 0)]),
            make_tx_context(2, 0xcc, &[(0x01, 0)]),
        ];
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.edges.len(), 2);
        for edge in &graph.edges {
            assert_eq!(edge.producer_idx, 0);
            assert_eq!(edge.kind, TxDepEdgeKind::SamePrevout);
        }
    }

    #[test]
    fn build_tx_dep_graph_large_independent() {
        let contexts: Vec<_> = (0..100usize)
            .map(|idx| make_tx_context(idx, (idx + 1) as u8, &[((idx + 1) as u8, idx as u32)]))
            .collect();
        let graph = build_tx_dep_graph(&contexts);

        assert_eq!(graph.tx_count, 100);
        assert!(graph.edges.is_empty());
        assert_eq!(graph.max_level, 0);
    }
}

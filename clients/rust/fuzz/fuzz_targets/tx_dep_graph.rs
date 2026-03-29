#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Cap input to avoid OOM.
    if data.len() > 8192 || data.is_empty() {
        return;
    }

    // Decode tx_count from first byte: 1–8 transactions.
    let tx_count = (data[0] % 8) as usize + 1;
    let rest = &data[1..];

    // Build TxValidationContexts from fuzz data, mirroring Go FuzzTxDepGraphBuild.
    let mut contexts = Vec::with_capacity(tx_count);
    for i in 0..tx_count {
        let mut txid = [0u8; 32];
        txid[0] = i as u8;

        let mut input_outpoints = Vec::new();

        // Parent-child edge: reference a previous tx's output.
        if i > 0 && rest.len() > i {
            let prev_idx = rest[i] as usize % i;
            let mut prev_txid = [0u8; 32];
            prev_txid[0] = prev_idx as u8;
            input_outpoints.push(rubin_consensus::Outpoint {
                txid: prev_txid,
                vout: 0,
            });
        }

        // Same-prevout conflict: reference an external outpoint.
        let edge_b_offset = tx_count;
        if rest.len() > edge_b_offset + i {
            let mut ext_txid = [0u8; 32];
            ext_txid[0] = 0xFF;
            ext_txid[1] = rest[edge_b_offset + i];
            input_outpoints.push(rubin_consensus::Outpoint {
                txid: ext_txid,
                vout: 0,
            });
        }

        contexts.push(rubin_consensus::TxValidationContext {
            tx_index: i + 1, // 1-based, coinbase excluded
            txid,
            input_outpoints,
        });
    }

    let graph = rubin_consensus::build_tx_dep_graph(&contexts);

    // Invariant: TxCount matches input.
    assert_eq!(
        graph.tx_count, tx_count,
        "tx_count mismatch: got {} want {}",
        graph.tx_count, tx_count
    );

    // Invariant: Levels length matches TxCount.
    assert_eq!(
        graph.levels.len(),
        tx_count,
        "levels length mismatch"
    );

    // Invariant: all levels are non-negative and ≤ max_level.
    for (idx, &lvl) in graph.levels.iter().enumerate() {
        assert!(
            lvl <= graph.max_level,
            "level {} exceeds max_level {} at index {}",
            lvl,
            graph.max_level,
            idx
        );
    }

    // Invariant: level_order is a valid permutation of [0..tx_count).
    assert_eq!(
        graph.level_order.len(),
        tx_count,
        "level_order length mismatch"
    );
    let mut seen = vec![false; tx_count];
    for &idx in &graph.level_order {
        assert!(
            idx < tx_count,
            "level_order index out of range: {}",
            idx
        );
        assert!(!seen[idx], "level_order duplicate: {}", idx);
        seen[idx] = true;
    }

    // Invariant: level_order is sorted by level (non-decreasing).
    for w in graph.level_order.windows(2) {
        assert!(
            graph.levels[w[0]] <= graph.levels[w[1]],
            "level_order not sorted by level"
        );
    }

    // Invariant: edges respect level ordering (producer < consumer in levels).
    for edge in &graph.edges {
        assert!(
            graph.levels[edge.producer_idx] < graph.levels[edge.consumer_idx],
            "edge level violation: producer level {} >= consumer level {}",
            graph.levels[edge.producer_idx],
            graph.levels[edge.consumer_idx]
        );
    }

    // Determinism: second call must produce identical graph.
    let graph2 = rubin_consensus::build_tx_dep_graph(&contexts);
    assert_eq!(graph, graph2, "non-deterministic graph");
});

use std::collections::HashMap;

use sha3::{Digest, Sha3_256};

use crate::block_basic::{
    median_time_past, parse_block_bytes, validate_block_basic_with_context_at_height,
    validate_coinbase_apply_outputs, validate_coinbase_value_bound,
};
use crate::compactsize::encode_compact_size;
use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use crate::core_ext::CoreExtDeploymentProfiles;
use crate::error::{ErrorCode, TxError};
use crate::sig_queue::SigCheckQueue;
use crate::subsidy::block_subsidy;
use crate::suite_registry::{RotationProvider, SuiteRegistry};
use crate::utxo_basic::{
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context,
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks,
    Outpoint, UtxoEntry,
};

const UTXO_SET_HASH_DST: &[u8] = b"RUBINv1-utxo-set-hash/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InMemoryChainState {
    pub utxos: HashMap<Outpoint, UtxoEntry>,
    /// already_generated(h): subsidy-only (excluding fees).
    pub already_generated: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectBlockBasicSummary {
    pub sum_fees: u64,
    pub already_generated: u128,
    pub already_generated_n1: u128,
    pub utxo_count: u64,
    /// Post-state UTXO set digest (SHA3-256) for parity checks.
    pub post_state_digest: [u8; 32],
    /// Number of queued signature-verification tasks. Zero for sequential path.
    pub sig_task_count: u64,
    /// Number of recovered worker panics. Zero on successful validation.
    pub worker_panics: u64,
}

/// ConnectBlockBasicInMemoryAtHeight connects a block against an in-memory chainstate and enforces
/// the coinbase subsidy/value bound using locally computed fees.
///
/// This intentionally does not provide any on-disk persistence.
pub fn connect_block_basic_in_memory_at_height(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_basic_in_memory_at_height_and_core_ext_deployments(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        &CoreExtDeploymentProfiles::empty(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_basic_in_memory_at_height_and_core_ext_deployments(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        core_ext_deployments,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<ConnectBlockBasicSummary, TxError> {
    // Stateless checks first.
    validate_block_basic_with_context_at_height(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
    )?;

    let pb = parse_block_bytes(block_bytes)?;
    if pb.txs.is_empty() || pb.txids.len() != pb.txs.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "invalid parsed block",
        ));
    }

    let already_generated = state.already_generated;
    let block_mtp = median_time_past(block_height, prev_timestamps)?.unwrap_or(pb.header.timestamp);
    let core_ext_profiles = core_ext_deployments.active_profiles_at_height(block_height)?;
    let mut work_utxos = None;

    let mut sum_fees: u64 = 0;
    for i in 1..pb.txs.len() {
        let base_utxos = work_utxos.as_ref().unwrap_or(&state.utxos);
        let (next_utxos, s) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context(
                &pb.txs[i],
                pb.txids[i],
                base_utxos,
                block_height,
                pb.header.timestamp,
                block_mtp,
                chain_id,
                &core_ext_profiles,
                rotation,
                registry,
            )?;
        work_utxos = Some(next_utxos);
        sum_fees = sum_fees
            .checked_add(s.fee)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "sum_fees overflow"))?;
    }

    let mut work_utxos = work_utxos.unwrap_or_else(|| state.utxos.clone());

    validate_coinbase_value_bound(&pb, block_height, already_generated, sum_fees)?;
    validate_coinbase_apply_outputs(&pb.txs[0])?;

    // Add coinbase spendable outputs to UTXO set.
    let coinbase_txid = pb.txids[0];
    for (i, out) in pb.txs[0].outputs.iter().enumerate() {
        if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
            continue;
        }
        work_utxos.insert(
            Outpoint {
                txid: coinbase_txid,
                vout: i as u32,
            },
            UtxoEntry {
                value: out.value,
                covenant_type: out.covenant_type,
                covenant_data: out.covenant_data.clone(),
                creation_height: block_height,
                created_by_coinbase: true,
            },
        );
    }

    let mut already_generated_n1 = already_generated;
    if block_height != 0 {
        let subsidy = block_subsidy(block_height, already_generated);
        already_generated_n1 = already_generated
            .checked_add(u128::from(subsidy))
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "already_generated overflow"))?;
    }

    state.utxos = work_utxos;
    if block_height != 0 {
        state.already_generated = already_generated_n1;
    }

    let post_state_digest = utxo_set_hash(&state.utxos);

    Ok(ConnectBlockBasicSummary {
        sum_fees,
        already_generated,
        already_generated_n1,
        utxo_count: state.utxos.len() as u64,
        post_state_digest,
        sig_task_count: 0,
        worker_panics: 0,
    })
}

/// Go-style block-level deferred signature orchestration. Structural and
/// state-mutation checks stay sequential; only expensive native signature
/// verification is deferred and flushed once per block.
#[allow(clippy::too_many_arguments)]
pub fn connect_block_parallel_sig_verify(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    workers: usize,
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_parallel_sig_verify_and_core_ext_deployments(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        &CoreExtDeploymentProfiles::empty(),
        workers,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_parallel_sig_verify_and_core_ext_deployments(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
    workers: usize,
) -> Result<ConnectBlockBasicSummary, TxError> {
    connect_block_parallel_sig_verify_and_core_ext_deployments_with_suite_context(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        state,
        chain_id,
        core_ext_deployments,
        None,
        None,
        workers,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn connect_block_parallel_sig_verify_and_core_ext_deployments_with_suite_context(
    block_bytes: &[u8],
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    state: &mut InMemoryChainState,
    chain_id: [u8; 32],
    core_ext_deployments: &CoreExtDeploymentProfiles,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
    workers: usize,
) -> Result<ConnectBlockBasicSummary, TxError> {
    validate_block_basic_with_context_at_height(
        block_bytes,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
    )?;

    let pb = parse_block_bytes(block_bytes)?;
    if pb.txs.is_empty() || pb.txids.len() != pb.txs.len() {
        return Err(TxError::new(
            ErrorCode::BlockErrParse,
            "invalid parsed block",
        ));
    }

    let already_generated = state.already_generated;
    let block_mtp = median_time_past(block_height, prev_timestamps)?.unwrap_or(pb.header.timestamp);
    let core_ext_profiles = core_ext_deployments.active_profiles_at_height(block_height)?;
    let mut work_utxos = state.utxos.clone();
    let mut sig_queue = match registry {
        Some(registry) => SigCheckQueue::new(workers).with_registry(registry),
        None => SigCheckQueue::new(workers),
    };

    let mut sum_fees: u64 = 0;
    for i in 1..pb.txs.len() {
        let (next_utxos, summary) =
            apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles_and_suite_context_queued_sigchecks(
                &pb.txs[i],
                pb.txids[i],
                &work_utxos,
                block_height,
                pb.header.timestamp,
                block_mtp,
                chain_id,
                &core_ext_profiles,
                rotation,
                registry,
                &mut sig_queue,
            )?;
        work_utxos = next_utxos;
        sum_fees = sum_fees
            .checked_add(summary.fee)
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "sum_fees overflow"))?;
    }

    let sig_task_count = sig_queue.len() as u64;
    sig_queue.flush()?;

    validate_coinbase_value_bound(&pb, block_height, already_generated, sum_fees)?;
    validate_coinbase_apply_outputs(&pb.txs[0])?;

    let coinbase_txid = pb.txids[0];
    for (i, out) in pb.txs[0].outputs.iter().enumerate() {
        if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
            continue;
        }
        work_utxos.insert(
            Outpoint {
                txid: coinbase_txid,
                vout: i as u32,
            },
            UtxoEntry {
                value: out.value,
                covenant_type: out.covenant_type,
                covenant_data: out.covenant_data.clone(),
                creation_height: block_height,
                created_by_coinbase: true,
            },
        );
    }

    let mut already_generated_n1 = already_generated;
    if block_height != 0 {
        let subsidy = block_subsidy(block_height, already_generated);
        already_generated_n1 = already_generated
            .checked_add(u128::from(subsidy))
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "already_generated overflow"))?;
    }

    state.utxos = work_utxos;
    if block_height != 0 {
        state.already_generated = already_generated_n1;
    }

    let post_state_digest = utxo_set_hash(&state.utxos);

    Ok(ConnectBlockBasicSummary {
        sum_fees,
        already_generated,
        already_generated_n1,
        utxo_count: state.utxos.len() as u64,
        post_state_digest,
        sig_task_count,
        worker_panics: 0,
    })
}

/// utxo_set_hash computes a deterministic SHA3-256 digest over the UTXO set.
/// Must match Go consensus.UtxoSetHash and rubin-node chainstate for parity.
pub(crate) fn utxo_set_hash(utxos: &HashMap<Outpoint, UtxoEntry>) -> [u8; 32] {
    let mut items: Vec<([u8; 36], &UtxoEntry)> = Vec::with_capacity(utxos.len());
    for (outpoint, entry) in utxos {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(&outpoint.txid);
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        items.push((key, entry));
    }
    items.sort_by_key(|a| a.0);

    let mut buf = Vec::with_capacity(UTXO_SET_HASH_DST.len() + 8 + items.len() * 64);
    buf.extend_from_slice(UTXO_SET_HASH_DST);
    buf.extend_from_slice(&(items.len() as u64).to_le_bytes());

    for (key, entry) in items {
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&entry.value.to_le_bytes());
        buf.extend_from_slice(&entry.covenant_type.to_le_bytes());
        encode_compact_size(entry.covenant_data.len() as u64, &mut buf);
        buf.extend_from_slice(&entry.covenant_data);
        buf.extend_from_slice(&entry.creation_height.to_le_bytes());
        buf.push(u8::from(entry.created_by_coinbase));
    }

    Sha3_256::digest(&buf).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    fn make_outpoint(txid_byte: u8, vout: u32) -> Outpoint {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        Outpoint { txid, vout }
    }

    fn make_entry(
        value: u64,
        cov_type: u16,
        cov_data: &[u8],
        height: u64,
        coinbase: bool,
    ) -> UtxoEntry {
        UtxoEntry {
            value,
            covenant_type: cov_type,
            covenant_data: cov_data.to_vec(),
            creation_height: height,
            created_by_coinbase: coinbase,
        }
    }

    // =============================================================
    // Empty UTXO set
    // =============================================================

    #[test]
    fn state_digest_empty_set() {
        let utxos = HashMap::new();
        let digest = utxo_set_hash(&utxos);
        // DST + count(0) = "RUBINv1-utxo-set-hash/" + 0u64 LE
        let mut expected_buf = Vec::new();
        expected_buf.extend_from_slice(UTXO_SET_HASH_DST);
        expected_buf.extend_from_slice(&0u64.to_le_bytes());
        let expected: [u8; 32] = Sha3_256::digest(&expected_buf).into();
        assert_eq!(digest, expected);
    }

    // =============================================================
    // Single UTXO — manual preimage construction
    // =============================================================

    #[test]
    fn state_digest_single_utxo_manual() {
        let mut utxos = HashMap::new();
        let op = make_outpoint(0x42, 7);
        let entry = make_entry(1_000_000, 0x0000, &[], 100, false);
        utxos.insert(op.clone(), entry);

        let digest = utxo_set_hash(&utxos);

        // Reconstruct preimage manually
        let mut buf = Vec::new();
        buf.extend_from_slice(UTXO_SET_HASH_DST);
        buf.extend_from_slice(&1u64.to_le_bytes()); // count = 1
                                                    // key: txid || vout_le
        let mut key = [0u8; 36];
        key[0] = 0x42;
        key[32..].copy_from_slice(&7u32.to_le_bytes());
        buf.extend_from_slice(&key);
        // value
        buf.extend_from_slice(&1_000_000u64.to_le_bytes());
        // covenant_type
        buf.extend_from_slice(&0x0000u16.to_le_bytes());
        // covenant_data length (compact_size 0)
        buf.push(0x00);
        // creation_height
        buf.extend_from_slice(&100u64.to_le_bytes());
        // created_by_coinbase
        buf.push(0x00);

        let expected: [u8; 32] = Sha3_256::digest(&buf).into();
        assert_eq!(digest, expected);
    }

    // =============================================================
    // Determinism: insertion order does NOT affect hash
    // =============================================================

    #[test]
    fn state_digest_deterministic_insertion_order() {
        let op_a = make_outpoint(0x01, 0);
        let op_b = make_outpoint(0x02, 0);
        let op_c = make_outpoint(0x03, 0);
        let entry_a = make_entry(100, 0x0000, &[], 1, false);
        let entry_b = make_entry(200, 0x0100, &[0xAB], 2, true);
        let entry_c = make_entry(300, 0x0101, &[0xCD, 0xEF], 3, false);

        // Forward insertion
        let mut forward = HashMap::new();
        forward.insert(op_a.clone(), entry_a.clone());
        forward.insert(op_b.clone(), entry_b.clone());
        forward.insert(op_c.clone(), entry_c.clone());

        // Reverse insertion
        let mut reverse = HashMap::new();
        reverse.insert(op_c.clone(), entry_c.clone());
        reverse.insert(op_b.clone(), entry_b.clone());
        reverse.insert(op_a.clone(), entry_a.clone());

        assert_eq!(utxo_set_hash(&forward), utxo_set_hash(&reverse));
    }

    // =============================================================
    // Different UTXO sets produce different hashes
    // =============================================================

    #[test]
    fn state_digest_different_sets_differ() {
        let op = make_outpoint(0x01, 0);
        let entry_a = make_entry(100, 0x0000, &[], 1, false);
        let entry_b = make_entry(101, 0x0000, &[], 1, false); // different value

        let mut set_a = HashMap::new();
        set_a.insert(op.clone(), entry_a);

        let mut set_b = HashMap::new();
        set_b.insert(op.clone(), entry_b);

        assert_ne!(utxo_set_hash(&set_a), utxo_set_hash(&set_b));
    }

    // =============================================================
    // Sensitivity to each UtxoEntry field
    // =============================================================

    #[test]
    fn state_digest_sensitive_to_value() {
        let op = make_outpoint(0x01, 0);
        let mut s1 = HashMap::new();
        s1.insert(op.clone(), make_entry(100, 0, &[], 0, false));
        let mut s2 = HashMap::new();
        s2.insert(op.clone(), make_entry(101, 0, &[], 0, false));
        assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
    }

    #[test]
    fn state_digest_sensitive_to_covenant_type() {
        let op = make_outpoint(0x01, 0);
        let mut s1 = HashMap::new();
        s1.insert(op.clone(), make_entry(100, 0x0000, &[], 0, false));
        let mut s2 = HashMap::new();
        s2.insert(op.clone(), make_entry(100, 0x0100, &[], 0, false));
        assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
    }

    #[test]
    fn state_digest_sensitive_to_covenant_data() {
        let op = make_outpoint(0x01, 0);
        let mut s1 = HashMap::new();
        s1.insert(op.clone(), make_entry(100, 0, &[0x01], 0, false));
        let mut s2 = HashMap::new();
        s2.insert(op.clone(), make_entry(100, 0, &[0x02], 0, false));
        assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
    }

    #[test]
    fn state_digest_sensitive_to_creation_height() {
        let op = make_outpoint(0x01, 0);
        let mut s1 = HashMap::new();
        s1.insert(op.clone(), make_entry(100, 0, &[], 10, false));
        let mut s2 = HashMap::new();
        s2.insert(op.clone(), make_entry(100, 0, &[], 11, false));
        assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
    }

    #[test]
    fn state_digest_sensitive_to_coinbase_flag() {
        let op = make_outpoint(0x01, 0);
        let mut s1 = HashMap::new();
        s1.insert(op.clone(), make_entry(100, 0, &[], 0, false));
        let mut s2 = HashMap::new();
        s2.insert(op.clone(), make_entry(100, 0, &[], 0, true));
        assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
    }

    #[test]
    fn state_digest_sensitive_to_txid() {
        let op_a = make_outpoint(0x01, 0);
        let op_b = make_outpoint(0x02, 0);
        let entry = make_entry(100, 0, &[], 0, false);
        let mut s1 = HashMap::new();
        s1.insert(op_a, entry.clone());
        let mut s2 = HashMap::new();
        s2.insert(op_b, entry);
        assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
    }

    #[test]
    fn state_digest_sensitive_to_vout() {
        let op_a = make_outpoint(0x01, 0);
        let op_b = make_outpoint(0x01, 1);
        let entry = make_entry(100, 0, &[], 0, false);
        let mut s1 = HashMap::new();
        s1.insert(op_a, entry.clone());
        let mut s2 = HashMap::new();
        s2.insert(op_b, entry);
        assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
    }

    // =============================================================
    // Sorting correctness: outpoints with same txid, different vout
    // =============================================================

    #[test]
    fn state_digest_sorting_by_outpoint() {
        // Insert in descending vout order, verify hash equals ascending order
        let op_0 = make_outpoint(0x01, 0);
        let op_1 = make_outpoint(0x01, 1);
        let op_2 = make_outpoint(0x01, 2);
        let e0 = make_entry(100, 0, &[], 0, false);
        let e1 = make_entry(200, 0, &[], 0, false);
        let e2 = make_entry(300, 0, &[], 0, false);

        let mut desc = HashMap::new();
        desc.insert(op_2.clone(), e2.clone());
        desc.insert(op_1.clone(), e1.clone());
        desc.insert(op_0.clone(), e0.clone());

        let mut asc = HashMap::new();
        asc.insert(op_0, e0);
        asc.insert(op_1, e1);
        asc.insert(op_2, e2);

        assert_eq!(utxo_set_hash(&desc), utxo_set_hash(&asc));
    }

    // =============================================================
    // Large covenant_data uses multi-byte CompactSize
    // =============================================================

    #[test]
    fn state_digest_large_covenant_data() {
        let op = make_outpoint(0x01, 0);
        let cov_data = vec![0xABu8; 300]; // 300 bytes → 0xfd prefix (3-byte compact size)
        let entry = make_entry(500, 0x0102, &cov_data, 42, true);

        let mut utxos = HashMap::new();
        utxos.insert(op.clone(), entry);

        let digest = utxo_set_hash(&utxos);

        // Reconstruct manually
        let mut buf = Vec::new();
        buf.extend_from_slice(UTXO_SET_HASH_DST);
        buf.extend_from_slice(&1u64.to_le_bytes());
        let mut key = [0u8; 36];
        key[0] = 0x01;
        key[32..].copy_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&500u64.to_le_bytes());
        buf.extend_from_slice(&0x0102u16.to_le_bytes());
        // 300 as compact_size: 0xfd, 0x2c, 0x01
        buf.push(0xfd);
        buf.extend_from_slice(&300u16.to_le_bytes());
        buf.extend_from_slice(&cov_data);
        buf.extend_from_slice(&42u64.to_le_bytes());
        buf.push(0x01); // coinbase=true

        let expected: [u8; 32] = Sha3_256::digest(&buf).into();
        assert_eq!(digest, expected);
    }

    // =============================================================
    // Consistency: same set hashed twice returns same result
    // =============================================================

    #[test]
    fn state_digest_idempotent() {
        let mut utxos = HashMap::new();
        utxos.insert(make_outpoint(0x01, 0), make_entry(100, 0, &[], 1, false));
        utxos.insert(
            make_outpoint(0x02, 5),
            make_entry(200, 0x0100, &[0xFF], 2, true),
        );

        let h1 = utxo_set_hash(&utxos);
        let h2 = utxo_set_hash(&utxos);
        assert_eq!(h1, h2);
    }

    // =============================================================
    // DST prefix is included (hash without DST differs)
    // =============================================================

    #[test]
    fn state_digest_includes_dst() {
        let utxos = HashMap::new();
        let digest = utxo_set_hash(&utxos);

        // Hash of just count=0 (no DST) must differ
        let no_dst: [u8; 32] = Sha3_256::digest(0u64.to_le_bytes()).into();
        assert_ne!(digest, no_dst);
    }

    // =============================================================
    // Count is encoded in preimage (adding/removing entry changes hash)
    // =============================================================

    #[test]
    fn state_digest_count_changes_hash() {
        let op_a = make_outpoint(0x01, 0);
        let op_b = make_outpoint(0x02, 0);
        let entry = make_entry(100, 0, &[], 0, false);

        let mut one = HashMap::new();
        one.insert(op_a.clone(), entry.clone());

        let mut two = HashMap::new();
        two.insert(op_a, entry.clone());
        two.insert(op_b, entry);

        assert_ne!(utxo_set_hash(&one), utxo_set_hash(&two));
    }

    // =============================================================
    // Coinbase flag encoding: true=0x01, false=0x00
    // =============================================================

    #[test]
    fn state_digest_coinbase_flag_encoding() {
        let op = make_outpoint(0x01, 0);
        let entry = make_entry(100, 0, &[], 0, true);

        let mut utxos = HashMap::new();
        utxos.insert(op.clone(), entry);

        let digest = utxo_set_hash(&utxos);

        // Manual: coinbase byte must be 0x01
        let mut buf = Vec::new();
        buf.extend_from_slice(UTXO_SET_HASH_DST);
        buf.extend_from_slice(&1u64.to_le_bytes());
        let mut key = [0u8; 36];
        key[0] = 0x01;
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0x00); // empty cov_data length
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(0x01); // coinbase = true → 1

        let expected: [u8; 32] = Sha3_256::digest(&buf).into();
        assert_eq!(digest, expected);
    }

    // =============================================================
    // Max-value entries don't panic
    // =============================================================

    #[test]
    fn state_digest_max_values_no_panic() {
        let txid = [0xFFu8; 32];
        let op = Outpoint {
            txid,
            vout: u32::MAX,
        };
        let entry = make_entry(u64::MAX, u16::MAX, &[0xFF; 252], u64::MAX, true);

        let mut utxos = HashMap::new();
        utxos.insert(op, entry);

        // Must not panic
        let _digest = utxo_set_hash(&utxos);
    }

    // =============================================================
    // Multiple entries sorted correctly by full 36-byte key
    // =============================================================

    #[test]
    fn state_digest_sort_by_txid_then_vout() {
        // op_a: txid[0]=0x01, vout=5
        // op_b: txid[0]=0x01, vout=3
        // op_c: txid[0]=0x02, vout=0
        // Expected sort: op_b (01..., vout=3) < op_a (01..., vout=5) < op_c (02..., vout=0)
        let op_a = make_outpoint(0x01, 5);
        let op_b = make_outpoint(0x01, 3);
        let op_c = make_outpoint(0x02, 0);

        let e_a = make_entry(100, 0, &[], 0, false);
        let e_b = make_entry(200, 0, &[], 0, false);
        let e_c = make_entry(300, 0, &[], 0, false);

        let mut utxos = HashMap::new();
        utxos.insert(op_a.clone(), e_a.clone());
        utxos.insert(op_b.clone(), e_b.clone());
        utxos.insert(op_c.clone(), e_c.clone());

        let digest = utxo_set_hash(&utxos);

        // Verify by constructing expected preimage in sorted order:
        // key_b (txid=0x01, vout=3) < key_a (txid=0x01, vout=5) < key_c (txid=0x02, vout=0)
        // vout is LE: 3→[03,00,00,00], 5→[05,00,00,00]
        // At offset 32: 03 < 05, so b before a. Then txid 02 > 01, so c last.
        let mut buf = Vec::new();
        buf.extend_from_slice(UTXO_SET_HASH_DST);
        buf.extend_from_slice(&3u64.to_le_bytes());

        // Entry b (sorted first)
        let mut key_b = [0u8; 36];
        key_b[0] = 0x01;
        key_b[32..].copy_from_slice(&3u32.to_le_bytes());
        buf.extend_from_slice(&key_b);
        buf.extend_from_slice(&200u64.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(0x00);

        // Entry a (sorted second)
        let mut key_a = [0u8; 36];
        key_a[0] = 0x01;
        key_a[32..].copy_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(&key_a);
        buf.extend_from_slice(&100u64.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(0x00);

        // Entry c (sorted third)
        let mut key_c = [0u8; 36];
        key_c[0] = 0x02;
        key_c[32..].copy_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&key_c);
        buf.extend_from_slice(&300u64.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(0x00);

        let expected: [u8; 32] = Sha3_256::digest(&buf).into();
        assert_eq!(digest, expected);
    }
}

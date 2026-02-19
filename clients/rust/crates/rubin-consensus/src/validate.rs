use std::collections::{HashMap, HashSet};

use rubin_crypto::CryptoProvider;

use crate::encode::{tx_no_witness_bytes, witness_bytes};
use crate::pow::{
    block_expected_target, block_header_hash, block_reward_for_height, median_past_timestamp,
};
use crate::sighash::sighash_v1_digest;
use crate::util::{
    add_u64, is_coinbase_tx, is_script_sig_zero_len, is_zero_outpoint, parse_u64_le, sub_u64,
    validate_coinbase_tx_inputs, validate_htlc_script_sig_len,
};
use crate::{
    BLOCK_ERR_ANCHOR_BYTES_EXCEEDED, BLOCK_ERR_COINBASE_INVALID, BLOCK_ERR_LINKAGE_INVALID,
    BLOCK_ERR_MERKLE_INVALID, BLOCK_ERR_POW_INVALID, BLOCK_ERR_SUBSIDY_EXCEEDED,
    BLOCK_ERR_TARGET_INVALID, BLOCK_ERR_TIMESTAMP_FUTURE, BLOCK_ERR_TIMESTAMP_OLD,
    BLOCK_ERR_WEIGHT_EXCEEDED, Block, BlockValidationContext, COINBASE_MATURITY, CORE_ANCHOR,
    CORE_HTLC_V1, CORE_HTLC_V2, CORE_P2PK, CORE_RESERVED_FUTURE, CORE_TIMELOCK_V1, CORE_VAULT_V1,
    MAX_ANCHOR_BYTES_PER_BLOCK, MAX_ANCHOR_PAYLOAD_SIZE, MAX_BLOCK_WEIGHT, MAX_FUTURE_DRIFT,
    MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_WITNESS_BYTES_PER_TX, MAX_WITNESS_ITEMS,
    ML_DSA_PUBKEY_BYTES, ML_DSA_SIG_BYTES, SLH_DSA_PUBKEY_BYTES, SLH_DSA_SIG_MAX_BYTES,
    SUITE_ID_ML_DSA, SUITE_ID_SENTINEL, SUITE_ID_SLH_DSA, TIMELOCK_MODE_HEIGHT,
    TIMELOCK_MODE_TIMESTAMP, TX_COINBASE_PREVOUT_VOUT, TX_ERR_COINBASE_IMMATURE,
    TX_ERR_NONCE_REPLAY, TX_ERR_SEQUENCE_INVALID, TX_ERR_TX_NONCE_INVALID, TX_ERR_WITNESS_OVERFLOW,
    TX_MAX_SEQUENCE, TX_NONCE_ZERO, Tx, TxOutPoint, TxOutput, UtxoEntry, WitnessItem,
};

pub fn compute_key_id(provider: &dyn CryptoProvider, pubkey: &[u8]) -> Result<[u8; 32], String> {
    provider.sha3_256(pubkey)
}

fn check_witness_format(
    item: &WitnessItem,
    suite_activation_slh_active: bool,
) -> Result<(), String> {
    if item.suite_id == SUITE_ID_SENTINEL {
        if !item.pubkey.is_empty() || !item.signature.is_empty() {
            return Err("TX_ERR_PARSE".into());
        }
        return Ok(());
    }
    if item.suite_id == SUITE_ID_ML_DSA {
        if item.pubkey.len() != ML_DSA_PUBKEY_BYTES || item.signature.len() != ML_DSA_SIG_BYTES {
            return Err("TX_ERR_SIG_NONCANONICAL".into());
        }
        return Ok(());
    }
    if item.suite_id == SUITE_ID_SLH_DSA {
        if !suite_activation_slh_active {
            return Err("TX_ERR_DEPLOYMENT_INACTIVE".into());
        }
        if item.pubkey.len() != SLH_DSA_PUBKEY_BYTES
            || item.signature.is_empty()
            || item.signature.len() > SLH_DSA_SIG_MAX_BYTES
        {
            return Err("TX_ERR_SIG_NONCANONICAL".into());
        }
        return Ok(());
    }
    Err("TX_ERR_SIG_ALG_INVALID".into())
}

fn satisfy_lock(lock_mode: u8, lock_value: u64, height: u64, timestamp: u64) -> Result<(), String> {
    match lock_mode {
        TIMELOCK_MODE_HEIGHT => {
            if height >= lock_value {
                Ok(())
            } else {
                Err("TX_ERR_TIMELOCK_NOT_MET".into())
            }
        }
        TIMELOCK_MODE_TIMESTAMP => {
            if timestamp >= lock_value {
                Ok(())
            } else {
                Err("TX_ERR_TIMELOCK_NOT_MET".into())
            }
        }
        _ => Err("TX_ERR_PARSE".into()),
    }
}

fn validate_output_covenant_constraints(output: &TxOutput) -> Result<(), String> {
    match output.covenant_type {
        CORE_P2PK => {
            if output.covenant_data.len() != 33 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_TIMELOCK_V1 => {
            if output.covenant_data.len() != 9 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_ANCHOR => {
            if output.value != 0 {
                return Err("TX_ERR_COVENANT_TYPE_INVALID".into());
            }
            if output.covenant_data.is_empty()
                || output.covenant_data.len() > MAX_ANCHOR_PAYLOAD_SIZE
            {
                return Err("TX_ERR_COVENANT_TYPE_INVALID".into());
            }
        }
        CORE_HTLC_V1 => {
            if output.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_HTLC_V2 => {
            if output.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
            let claim_key_id = &output.covenant_data[41..73];
            let refund_key_id = &output.covenant_data[73..105];
            if claim_key_id == refund_key_id {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_VAULT_V1 => {
            if output.covenant_data.len() != 73 && output.covenant_data.len() != 81 {
                return Err("TX_ERR_PARSE".into());
            }
        }
        CORE_RESERVED_FUTURE => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
        _ => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
    }
    Ok(())
}

pub fn tx_weight(tx: &Tx) -> Result<u64, String> {
    let base = tx_no_witness_bytes(tx).len();
    let witness = witness_bytes(&tx.witness).len();
    let mut sig_cost: u64 = 0;
    for (i, item) in tx.witness.witnesses.iter().enumerate() {
        if i < tx.inputs.len() {
            match item.suite_id {
                SUITE_ID_ML_DSA => sig_cost = sig_cost.saturating_add(crate::VERIFY_COST_ML_DSA),
                SUITE_ID_SLH_DSA => sig_cost = sig_cost.saturating_add(crate::VERIFY_COST_SLH_DSA),
                _ => {}
            }
        }
    }
    let base_weight = (base as u64)
        .checked_mul(4)
        .ok_or_else(|| "TX_ERR_PARSE".to_string())?;
    add_u64(add_u64(base_weight, witness as u64)?, sig_cost)
}

pub fn txid(provider: &dyn CryptoProvider, tx: &Tx) -> Result<[u8; 32], String> {
    provider.sha3_256(&tx_no_witness_bytes(tx))
}

fn merkle_root_txids(provider: &dyn CryptoProvider, txs: &[Tx]) -> Result<[u8; 32], String> {
    if txs.is_empty() {
        return Err(BLOCK_ERR_MERKLE_INVALID.into());
    }
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
    for tx in txs {
        let tid = txid(provider, tx)?;
        let mut leaf = Vec::with_capacity(1 + 32);
        leaf.push(0x00);
        leaf.extend_from_slice(&tid);
        level.push(provider.sha3_256(&leaf)?);
    }
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 == level.len() {
                next.push(level[i]);
                i += 1;
                continue;
            }
            let mut concat = Vec::with_capacity(1 + 32 + 32);
            concat.push(0x01);
            concat.extend_from_slice(&level[i]);
            concat.extend_from_slice(&level[i + 1]);
            next.push(provider.sha3_256(&concat)?);
            i += 2;
        }
        level = next;
    }
    Ok(level[0])
}

fn tx_sums(tx: &Tx, utxo: &HashMap<TxOutPoint, UtxoEntry>) -> Result<(u64, u64), String> {
    let mut input_sum = 0u64;
    let mut output_sum = 0u64;
    for input in &tx.inputs {
        let prev = TxOutPoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        let entry = utxo
            .get(&prev)
            .ok_or_else(|| "TX_ERR_MISSING_UTXO".to_string())?;
        input_sum = add_u64(input_sum, entry.output.value)?;
    }
    for output in &tx.outputs {
        output_sum = add_u64(output_sum, output.value)?;
    }
    Ok((input_sum, output_sum))
}

pub fn apply_block(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    block: &Block,
    utxo: &mut HashMap<TxOutPoint, UtxoEntry>,
    ctx: &BlockValidationContext,
) -> Result<(), String> {
    if block.transactions.is_empty() {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }

    if ctx.height > 0 && ctx.ancestor_headers.is_empty() {
        return Err(BLOCK_ERR_LINKAGE_INVALID.into());
    }

    if ctx.height == 0 {
        if block.header.prev_block_hash != [0u8; 32] {
            return Err(BLOCK_ERR_LINKAGE_INVALID.into());
        }
    } else {
        let parent = ctx
            .ancestor_headers
            .last()
            .ok_or_else(|| BLOCK_ERR_LINKAGE_INVALID.to_string())?;
        let parent_hash = block_header_hash(provider, parent)?;
        if block.header.prev_block_hash != parent_hash {
            return Err(BLOCK_ERR_LINKAGE_INVALID.into());
        }
    }

    let expected_target =
        block_expected_target(&ctx.ancestor_headers, ctx.height, &block.header.target)?;
    if expected_target != block.header.target {
        return Err(BLOCK_ERR_TARGET_INVALID.into());
    }

    let bhash = block_header_hash(provider, &block.header)?;
    if bhash.as_slice() >= block.header.target.as_slice() {
        return Err(BLOCK_ERR_POW_INVALID.into());
    }

    let merkle = merkle_root_txids(provider, &block.transactions)?;
    if merkle != block.header.merkle_root {
        return Err(BLOCK_ERR_MERKLE_INVALID.into());
    }

    if ctx.height > 0 {
        let median_ts = median_past_timestamp(&ctx.ancestor_headers, ctx.height)?;
        if block.header.timestamp <= median_ts {
            return Err(BLOCK_ERR_TIMESTAMP_OLD.into());
        }
        if ctx.local_time_set && block.header.timestamp > ctx.local_time + MAX_FUTURE_DRIFT {
            return Err(BLOCK_ERR_TIMESTAMP_FUTURE.into());
        }
    }

    let mut coinbase_count = 0u64;
    for (i, tx) in block.transactions.iter().enumerate() {
        if is_coinbase_tx(tx, ctx.height) {
            coinbase_count += 1;
            if i != 0 {
                return Err(BLOCK_ERR_COINBASE_INVALID.into());
            }
        }
    }
    if coinbase_count != 1 {
        return Err(BLOCK_ERR_COINBASE_INVALID.into());
    }

    let mut working_utxo = utxo.clone();
    let mut total_weight = 0u64;
    let mut total_anchor_bytes = 0u64;
    let mut total_fees = 0u64;
    let mut seen_nonces: HashSet<u64> = HashSet::with_capacity(block.transactions.len());

    for tx in &block.transactions {
        total_weight = add_u64(total_weight, tx_weight(tx)?)?;

        let is_coinbase = is_coinbase_tx(tx, ctx.height);
        if !is_coinbase {
            if tx.tx_nonce == TX_NONCE_ZERO {
                return Err(TX_ERR_TX_NONCE_INVALID.into());
            }
            if seen_nonces.contains(&tx.tx_nonce) {
                return Err(TX_ERR_NONCE_REPLAY.into());
            }
            seen_nonces.insert(tx.tx_nonce);
        }

        apply_tx(
            provider,
            chain_id,
            tx,
            &working_utxo,
            ctx.height,
            block.header.timestamp,
            ctx.htlc_v2_active,
            ctx.suite_id_02_active,
        )?;

        if !is_coinbase {
            let (in_sum, out_sum) = tx_sums(tx, &working_utxo)?;
            let fee = sub_u64(in_sum, out_sum)?;
            total_fees = add_u64(total_fees, fee)?;

            for input in &tx.inputs {
                working_utxo.remove(&TxOutPoint {
                    txid: input.prev_txid,
                    vout: input.prev_vout,
                });
            }
        }

        let txid_v = txid(provider, tx)?;
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.covenant_type == CORE_ANCHOR {
                total_anchor_bytes = add_u64(total_anchor_bytes, out.covenant_data.len() as u64)?;
                continue;
            }
            working_utxo.insert(
                TxOutPoint {
                    txid: txid_v,
                    vout: vout as u32,
                },
                UtxoEntry {
                    output: out.clone(),
                    creation_height: ctx.height,
                    created_by_coinbase: is_coinbase,
                },
            );
        }
    }

    if total_weight > MAX_BLOCK_WEIGHT {
        return Err(BLOCK_ERR_WEIGHT_EXCEEDED.into());
    }
    if total_anchor_bytes > MAX_ANCHOR_BYTES_PER_BLOCK {
        return Err(BLOCK_ERR_ANCHOR_BYTES_EXCEEDED.into());
    }

    let mut coinbase_value = 0u64;
    for out in &block.transactions[0].outputs {
        coinbase_value = add_u64(coinbase_value, out.value)?;
    }
    if ctx.height != 0 {
        let max_coinbase = add_u64(block_reward_for_height(ctx.height), total_fees)?;
        if coinbase_value > max_coinbase {
            return Err(BLOCK_ERR_SUBSIDY_EXCEEDED.into());
        }
    }

    utxo.clear();
    for (k, v) in working_utxo {
        utxo.insert(k, v);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_input_authorization(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    tx: &Tx,
    input_index: usize,
    prev_value: u64,
    prevout: &TxOutput,
    prev_creation_height: u64,
    chain_height: u64,
    chain_timestamp: u64,
    htlc_v2_active: bool,
    suite_id_02_active: bool,
) -> Result<(), String> {
    if tx.inputs.is_empty() || input_index >= tx.inputs.len() {
        return Err("TX_ERR_PARSE".into());
    }
    if input_index >= tx.witness.witnesses.len() {
        return Err("TX_ERR_PARSE".into());
    }
    let input = &tx.inputs[input_index];
    let witness = &tx.witness.witnesses[input_index];

    match prevout.covenant_type {
        CORE_P2PK => {
            is_script_sig_zero_len("CORE_P2PK", input.script_sig.len())?;
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            if prevout.covenant_data.len() != 33 {
                return Err("TX_ERR_PARSE".into());
            }
            let suite_id = prevout.covenant_data[0];
            if suite_id != witness.suite_id {
                return Err("TX_ERR_SIG_INVALID".into());
            }
            let expected_key_id = &prevout.covenant_data[1..33];
            let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
            if actual_key_id.as_slice() != expected_key_id {
                return Err("TX_ERR_SIG_INVALID".into());
            }
        }
        CORE_TIMELOCK_V1 => {
            is_script_sig_zero_len("CORE_TIMELOCK_V1", input.script_sig.len())?;
            if witness.suite_id != SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            if prevout.covenant_data.len() != 9 {
                return Err("TX_ERR_PARSE".into());
            }
            let lock_mode = prevout.covenant_data[0];
            let lock_value = parse_u64_le(&prevout.covenant_data, 1, "covenant_lock_value")?;
            satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
            return Ok(());
        }
        CORE_HTLC_V1 => {
            validate_htlc_script_sig_len(input.script_sig.len())?;
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            if prevout.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
            let claim_key_id = &prevout.covenant_data[41..73];
            let refund_key_id = &prevout.covenant_data[73..105];
            if claim_key_id == refund_key_id {
                return Err("TX_ERR_PARSE".into());
            }
            let lock_mode = prevout.covenant_data[32];
            if lock_mode != TIMELOCK_MODE_HEIGHT && lock_mode != TIMELOCK_MODE_TIMESTAMP {
                return Err("TX_ERR_PARSE".into());
            }
            let lock_value = parse_u64_le(&prevout.covenant_data, 33, "htlc_lock_value")?;
            if input.script_sig.len() == 32 {
                let expected_hash = &prevout.covenant_data[0..32];
                let script_hash = provider.sha3_256(&input.script_sig)?;
                if script_hash.as_slice() != expected_hash {
                    return Err("TX_ERR_SIG_INVALID".into());
                }
                let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                if actual_key_id.as_slice() != claim_key_id {
                    return Err("TX_ERR_SIG_INVALID".into());
                }
            } else {
                let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                if actual_key_id.as_slice() != refund_key_id {
                    return Err("TX_ERR_SIG_INVALID".into());
                }
                satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
            }
        }
        CORE_HTLC_V2 => {
            if !htlc_v2_active {
                return Err("TX_ERR_DEPLOYMENT_INACTIVE".into());
            }
            if !input.script_sig.is_empty() {
                return Err("TX_ERR_PARSE".into());
            }
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            if prevout.covenant_data.len() != 105 {
                return Err("TX_ERR_PARSE".into());
            }
            let claim_key_id = &prevout.covenant_data[41..73];
            let refund_key_id = &prevout.covenant_data[73..105];
            if claim_key_id == refund_key_id {
                return Err("TX_ERR_PARSE".into());
            }

            let expected_hash = &prevout.covenant_data[0..32];
            let lock_mode = prevout.covenant_data[32];
            let lock_value = parse_u64_le(&prevout.covenant_data, 33, "htlc2_lock_value")?;

            const HTLC_V2_PREFIX: &[u8] = b"RUBINv1-htlc-preimage/";
            const HTLC_V2_ENVELOPE_LEN: usize = 54;

            let mut matching_anchors = 0usize;
            let mut matching_anchor: Option<&[u8]> = None;
            for out in &tx.outputs {
                if out.covenant_type != CORE_ANCHOR {
                    continue;
                }
                if out.covenant_data.len() != HTLC_V2_ENVELOPE_LEN {
                    continue;
                }
                if &out.covenant_data[0..HTLC_V2_PREFIX.len()] != HTLC_V2_PREFIX {
                    continue;
                }
                matching_anchors += 1;
                matching_anchor = Some(&out.covenant_data);
                if matching_anchors >= 2 {
                    break;
                }
            }

            match matching_anchors {
                0 => {
                    let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                    if actual_key_id.as_slice() != refund_key_id {
                        return Err("TX_ERR_SIG_INVALID".into());
                    }
                    satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
                }
                1 => {
                    let env = matching_anchor.ok_or_else(|| "TX_ERR_PARSE".to_string())?;
                    let preimage32 = &env[HTLC_V2_PREFIX.len()..];
                    let preimage_hash = provider.sha3_256(preimage32)?;
                    if preimage_hash.as_slice() != expected_hash {
                        return Err("TX_ERR_SIG_INVALID".into());
                    }
                    let actual_key_id = compute_key_id(provider, &witness.pubkey)?;
                    if actual_key_id.as_slice() != claim_key_id {
                        return Err("TX_ERR_SIG_INVALID".into());
                    }
                }
                _ => {
                    return Err("TX_ERR_PARSE".into());
                }
            }
        }
        CORE_VAULT_V1 => {
            is_script_sig_zero_len("CORE_VAULT_V1", input.script_sig.len())?;
            if witness.suite_id == SUITE_ID_SENTINEL {
                return Err("TX_ERR_SIG_ALG_INVALID".into());
            }
            check_witness_format(witness, suite_id_02_active)?;

            let (owner_key_id, spend_delay, lock_mode, lock_value, recovery_key_id) = match prevout
                .covenant_data
                .len()
            {
                73 => {
                    let owner_key_id = &prevout.covenant_data[0..32];
                    let lock_mode = prevout.covenant_data[32];
                    let lock_value = parse_u64_le(&prevout.covenant_data, 33, "vault_lock_value")?;
                    let recovery_key_id = &prevout.covenant_data[41..73];
                    (owner_key_id, 0u64, lock_mode, lock_value, recovery_key_id)
                }
                81 => {
                    let owner_key_id = &prevout.covenant_data[0..32];
                    let spend_delay =
                        parse_u64_le(&prevout.covenant_data, 32, "vault_spend_delay")?;
                    let lock_mode = prevout.covenant_data[40];
                    let lock_value = parse_u64_le(&prevout.covenant_data, 41, "vault_lock_value")?;
                    let recovery_key_id = &prevout.covenant_data[49..81];
                    (
                        owner_key_id,
                        spend_delay,
                        lock_mode,
                        lock_value,
                        recovery_key_id,
                    )
                }
                _ => return Err("TX_ERR_PARSE".into()),
            };
            if lock_mode != TIMELOCK_MODE_HEIGHT && lock_mode != TIMELOCK_MODE_TIMESTAMP {
                return Err("TX_ERR_PARSE".into());
            }
            if owner_key_id == recovery_key_id {
                return Err("TX_ERR_PARSE".into());
            }
            let actual_key_id = compute_key_id(provider, &witness.pubkey)?;

            if actual_key_id.as_slice() != owner_key_id
                && actual_key_id.as_slice() != recovery_key_id
            {
                return Err("TX_ERR_SIG_INVALID".into());
            }
            if actual_key_id.as_slice() == owner_key_id
                && spend_delay > 0
                && chain_height < prev_creation_height + spend_delay
            {
                return Err("TX_ERR_TIMELOCK_NOT_MET".into());
            }
            if actual_key_id.as_slice() == recovery_key_id {
                satisfy_lock(lock_mode, lock_value, chain_height, chain_timestamp)?;
            }
        }
        CORE_ANCHOR => return Err("TX_ERR_MISSING_UTXO".into()),
        CORE_RESERVED_FUTURE => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
        _ => return Err("TX_ERR_COVENANT_TYPE_INVALID".into()),
    };

    let digest = sighash_v1_digest(provider, chain_id, tx, input_index as u32, prev_value)?;
    match witness.suite_id {
        SUITE_ID_ML_DSA => {
            let valid = provider
                .verify_mldsa87(&witness.pubkey, &witness.signature, &digest)
                .map_err(|_| "TX_ERR_SIG_INVALID".to_string())?;
            if valid {
                Ok(())
            } else {
                Err("TX_ERR_SIG_INVALID".into())
            }
        }
        SUITE_ID_SLH_DSA => {
            let valid = provider
                .verify_slhdsa_shake_256f(&witness.pubkey, &witness.signature, &digest)
                .map_err(|_| "TX_ERR_SIG_INVALID".to_string())?;
            if valid {
                Ok(())
            } else {
                Err("TX_ERR_SIG_INVALID".into())
            }
        }
        SUITE_ID_SENTINEL => Ok(()),
        _ => Err("TX_ERR_SIG_ALG_INVALID".into()),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn apply_tx(
    provider: &dyn CryptoProvider,
    chain_id: &[u8; 32],
    tx: &Tx,
    utxo: &HashMap<TxOutPoint, UtxoEntry>,
    chain_height: u64,
    chain_timestamp: u64,
    htlc_v2_active: bool,
    suite_id_02_active: bool,
) -> Result<(), String> {
    if tx.inputs.len() > MAX_TX_INPUTS || tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err("TX_ERR_PARSE".to_string());
    }
    if tx.witness.witnesses.len() > MAX_WITNESS_ITEMS {
        return Err(TX_ERR_WITNESS_OVERFLOW.to_string());
    }
    if witness_bytes(&tx.witness).len() > MAX_WITNESS_BYTES_PER_TX {
        return Err(TX_ERR_WITNESS_OVERFLOW.to_string());
    }
    if is_coinbase_tx(tx, chain_height) {
        validate_coinbase_tx_inputs(tx)?;
        for out in &tx.outputs {
            validate_output_covenant_constraints(out)?;
        }
        return Ok(());
    }

    if tx.tx_nonce == TX_NONCE_ZERO {
        return Err(TX_ERR_TX_NONCE_INVALID.to_string());
    }
    if tx.inputs.len() != tx.witness.witnesses.len() {
        return Err("TX_ERR_PARSE".to_string());
    }
    for out in &tx.outputs {
        validate_output_covenant_constraints(out)?;
    }

    let mut seen = HashSet::with_capacity(tx.inputs.len());
    let mut total_inputs = 0u64;
    let mut total_outputs = 0u64;

    for (input_index, input) in tx.inputs.iter().enumerate() {
        if input.sequence == TX_COINBASE_PREVOUT_VOUT || input.sequence > TX_MAX_SEQUENCE {
            return Err(TX_ERR_SEQUENCE_INVALID.to_string());
        }
        let prevout = TxOutPoint {
            txid: input.prev_txid,
            vout: input.prev_vout,
        };
        if is_zero_outpoint(&prevout.txid, prevout.vout) {
            return Err("TX_ERR_PARSE".to_string());
        }
        if !seen.insert(prevout.clone()) {
            return Err("TX_ERR_PARSE".to_string());
        }

        let prev = utxo
            .get(&prevout)
            .ok_or_else(|| "TX_ERR_MISSING_UTXO".to_string())?;

        validate_input_authorization(
            provider,
            chain_id,
            tx,
            input_index,
            prev.output.value,
            &prev.output,
            prev.creation_height,
            chain_height,
            chain_timestamp,
            htlc_v2_active,
            suite_id_02_active,
        )?;

        if prev.created_by_coinbase && chain_height < prev.creation_height + COINBASE_MATURITY {
            return Err(TX_ERR_COINBASE_IMMATURE.to_string());
        }

        total_inputs = add_u64(total_inputs, prev.output.value)?;
    }

    for output in &tx.outputs {
        total_outputs = add_u64(total_outputs, output.value)?;
    }

    if total_outputs > total_inputs {
        return Err("TX_ERR_VALUE_CONSERVATION".into());
    }
    Ok(())
}

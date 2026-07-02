use crate::constants::{
    COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
    SIMPLICITY_BASE_VERIFY_COST, SUITE_ID_ML_DSA_87, SUITE_ID_SENTINEL,
    SUITE_ID_SIMPLICITY_ENVELOPE, VERIFY_COST_ML_DSA_87, VERIFY_COST_UNKNOWN_SUITE,
    WITNESS_DISCOUNT_DIVISOR,
};
use crate::error::{ErrorCode, TxError};
use crate::suite_registry::{RotationProvider, SuiteRegistry};
use crate::tx::{da_core_fields_bytes, Tx, TxInput, TxOutput, WitnessItem};

/// Shared weight-computation skeleton. `sig_cost_fn` receives each witness item
/// and returns its verification cost (same pattern as Go `txWeightComponents`).
fn tx_weight_components<F>(tx: &Tx, sig_cost_fn: F) -> Result<(u64, u64, u64), TxError>
where
    F: Fn(&WitnessItem) -> Result<u64, TxError>,
{
    let (base_size, anchor_bytes) = tx_base_size(tx)?;
    let (witness_size, sig_cost) = tx_witness_size_and_sig_cost(tx, sig_cost_fn)?;
    let (da_size, da_bytes) = tx_da_size_and_bytes(tx)?;
    let weight = tx_weight(base_size, witness_size, da_size, sig_cost)?;
    Ok((weight, da_bytes, anchor_bytes))
}

fn tx_base_size(tx: &Tx) -> Result<(u64, u64), TxError> {
    let mut base_size = checked_add(4 + 1 + 8, compact_size_len(tx.inputs.len() as u64))?;
    base_size = add_input_sizes(base_size, &tx.inputs)?;
    base_size = checked_add(base_size, compact_size_len(tx.outputs.len() as u64))?;
    let (base_size, anchor_bytes) = add_output_sizes(base_size, &tx.outputs)?;
    let base_size = checked_add(base_size, 4)?;
    let base_size = checked_add(base_size, da_core_fields_bytes(tx)?.len() as u64)?;
    Ok((base_size, anchor_bytes))
}

fn add_input_sizes(mut base_size: u64, inputs: &[TxInput]) -> Result<u64, TxError> {
    for input in inputs {
        base_size = checked_add(base_size, 32 + 4)?;
        base_size = checked_add(base_size, compact_size_len(input.script_sig.len() as u64))?;
        base_size = checked_add(base_size, input.script_sig.len() as u64)?;
        base_size = checked_add(base_size, 4)?;
    }
    Ok(base_size)
}

fn add_output_sizes(mut base_size: u64, outputs: &[TxOutput]) -> Result<(u64, u64), TxError> {
    let mut anchor_bytes = 0;
    for output in outputs {
        base_size = checked_add(base_size, 8 + 2)?;
        let covenant_len = output.covenant_data.len() as u64;
        base_size = checked_add(base_size, compact_size_len(covenant_len))?;
        base_size = checked_add(base_size, covenant_len)?;
        if is_anchor_counted_output(output) {
            anchor_bytes = checked_add(anchor_bytes, covenant_len)?;
        }
    }
    Ok((base_size, anchor_bytes))
}

fn is_anchor_counted_output(output: &TxOutput) -> bool {
    matches!(output.covenant_type, COV_TYPE_ANCHOR | COV_TYPE_DA_COMMIT)
}

fn tx_witness_size_and_sig_cost<F>(tx: &Tx, sig_cost_fn: F) -> Result<(u64, u64), TxError>
where
    F: Fn(&WitnessItem) -> Result<u64, TxError>,
{
    let mut witness_size = compact_size_len(tx.witness.len() as u64);
    let mut sig_cost = 0;
    for witness in &tx.witness {
        witness_size = add_witness_item_size(witness_size, witness)?;
        sig_cost = checked_add(sig_cost, sig_cost_fn(witness)?)?;
    }
    Ok((witness_size, sig_cost))
}

fn add_witness_item_size(mut witness_size: u64, witness: &WitnessItem) -> Result<u64, TxError> {
    witness_size = checked_add(witness_size, 1)?;
    witness_size = checked_add(witness_size, compact_size_len(witness.pubkey.len() as u64))?;
    witness_size = checked_add(witness_size, witness.pubkey.len() as u64)?;
    witness_size = checked_add(
        witness_size,
        compact_size_len(witness.signature.len() as u64),
    )?;
    checked_add(witness_size, witness.signature.len() as u64)
}

fn tx_da_size_and_bytes(tx: &Tx) -> Result<(u64, u64), TxError> {
    let da_len = tx.da_payload.len() as u64;
    let da_size = checked_add(compact_size_len(da_len), da_len)?;
    let da_bytes = if tx.tx_kind != 0x00 { da_len } else { 0 };
    Ok((da_size, da_bytes))
}

fn tx_weight(
    base_size: u64,
    witness_size: u64,
    da_size: u64,
    sig_cost: u64,
) -> Result<u64, TxError> {
    let base_weight = WITNESS_DISCOUNT_DIVISOR
        .checked_mul(base_size)
        .ok_or_else(weight_overflow)?;
    let weight = checked_add(base_weight, witness_size)?;
    let weight = checked_add(weight, da_size)?;
    checked_add(weight, sig_cost)
}

/// Legacy weight with hardcoded per-suite costs.
pub(super) fn tx_weight_and_stats(tx: &Tx) -> Result<(u64, u64, u64), TxError> {
    tx_weight_components(tx, legacy_sig_cost)
}

fn legacy_sig_cost(witness: &WitnessItem) -> Result<u64, TxError> {
    Ok(match witness.suite_id {
        SUITE_ID_SENTINEL => 0,
        // CANONICAL §9 / mirror of Go `txWeightAndStats`: a 0xF0 Simplicity
        // envelope witness is priced at its own base cost, not the
        // unknown-suite floor (numerically equal today; see the constant).
        SUITE_ID_SIMPLICITY_ENVELOPE => SIMPLICITY_BASE_VERIFY_COST,
        SUITE_ID_ML_DSA_87 if has_expected_mldsa87_shape(witness) => VERIFY_COST_ML_DSA_87,
        SUITE_ID_ML_DSA_87 => 0,
        _ => VERIFY_COST_UNKNOWN_SUITE,
    })
}

pub fn tx_weight_and_stats_public(tx: &Tx) -> Result<(u64, u64, u64), TxError> {
    tx_weight_and_stats(tx)
}

/// Suite-aware weight calculation using registry verify costs and
/// rotation-aware native spend suites. Parity with Go
/// `TxWeightAndStatsAtHeight`. When rotation or registry is None,
/// falls back to the legacy hardcoded calculation.
pub fn tx_weight_and_stats_at_height(
    tx: &Tx,
    height: u64,
    rotation: Option<&dyn RotationProvider>,
    registry: Option<&SuiteRegistry>,
) -> Result<(u64, u64, u64), TxError> {
    let (rotation, registry) = match (rotation, registry) {
        (Some(r), Some(reg)) => (r, reg),
        _ => return tx_weight_and_stats(tx),
    };
    let native_spend = rotation.native_spend_suites(height);
    tx_weight_components(tx, |witness| {
        registry_sig_cost(witness, &native_spend, registry)
    })
}

fn registry_sig_cost(
    witness: &WitnessItem,
    native_spend: &crate::suite_registry::NativeSuiteSet,
    registry: &SuiteRegistry,
) -> Result<u64, TxError> {
    if witness.suite_id == SUITE_ID_SENTINEL {
        return Ok(0);
    }
    // CANONICAL §9 / mirror of Go `txWeightAndStatsWithRegistry`: the 0xF0
    // Simplicity envelope is priced BEFORE the native-spend/registry lookup
    // (it is a structural carrier, never a native crypto suite).
    if witness.suite_id == SUITE_ID_SIMPLICITY_ENVELOPE {
        return Ok(SIMPLICITY_BASE_VERIFY_COST);
    }
    if !native_spend.contains(witness.suite_id) {
        return Ok(VERIFY_COST_UNKNOWN_SUITE);
    }
    let Some(params) = registry.lookup(witness.suite_id) else {
        return Ok(VERIFY_COST_UNKNOWN_SUITE);
    };
    if witness.pubkey.len() as u64 == params.pubkey_len
        && witness.signature.len() as u64 == params.sig_len + 1
    {
        return Ok(params.verify_cost);
    }
    Ok(0)
}

fn has_expected_mldsa87_shape(witness: &WitnessItem) -> bool {
    witness.pubkey.len() as u64 == ML_DSA_87_PUBKEY_BYTES
        && witness.signature.len() as u64 == ML_DSA_87_SIG_BYTES + 1
}

fn compact_size_len(n: u64) -> u64 {
    match n {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn checked_add(a: u64, b: u64) -> Result<u64, TxError> {
    a.checked_add(b).ok_or_else(weight_overflow)
}

fn weight_overflow() -> TxError {
    TxError::new(ErrorCode::TxErrParse, "u64 overflow")
}

#[cfg(kani)]
mod verification {
    use super::compact_size_len;
    use crate::compactsize::encode_compact_size;

    #[kani::proof]
    fn verify_compact_size_len_matches_encode() {
        let n: u64 = kani::any();
        let mut buf = Vec::new();
        encode_compact_size(n, &mut buf);
        assert_eq!(compact_size_len(n), buf.len() as u64);
    }
}

use crate::constants::COV_TYPE_CORE_EXT;
use crate::core_ext::{parse_core_ext_covenant_data, CoreExtProfiles};
use crate::error::{ErrorCode, TxError};
use crate::tx::{Tx, TxOutput};
use crate::utxo_basic::UtxoEntry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

pub const TXCONTEXT_MAX_CONTINUING_OUTPUTS: usize = 2;
const TXCONTEXT_TOO_MANY_CONTINUING_OUTPUTS: &str =
    "too many continuing outputs for txcontext ext_id";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uint128 {
    pub lo: u64,
    pub hi: u64,
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_uint128_from_native_to_native_roundtrips_full_domain() {
        let value: u128 = kani::any();
        let split = Uint128::from_native(value);
        assert_eq!(split.to_native(), value);
    }

    #[kani::proof]
    fn verify_uint128_to_native_from_native_roundtrips_full_domain() {
        let lo: u64 = kani::any();
        let hi: u64 = kani::any();
        let split = Uint128 { lo, hi };
        assert_eq!(Uint128::from_native(split.to_native()), split);
    }

    #[kani::proof]
    fn verify_txcontext_get_output_checked_accepts_highest_valid_index() {
        let mut continuing = TxContextContinuing::default();
        continuing.continuing_output_count = 2;
        continuing.continuing_outputs[0] = Some(TxOutputView {
            value: 11,
            ext_payload: Arc::from(&[0x71][..]),
        });
        continuing.continuing_outputs[1] = Some(TxOutputView {
            value: 12,
            ext_payload: Arc::from(&[0x72][..]),
        });

        let output = continuing.get_output_checked(1).expect("index 1");
        assert_eq!(output.value, 12);
        assert_eq!(output.ext_payload.as_ref(), &[0x72]);
    }

    #[kani::proof]
    fn verify_txcontext_get_output_checked_rejects_count_boundary_index() {
        let mut continuing = TxContextContinuing::default();
        continuing.continuing_output_count = 2;
        continuing.continuing_outputs[0] = Some(TxOutputView {
            value: 11,
            ext_payload: Arc::from(&[0x71][..]),
        });
        continuing.continuing_outputs[1] = Some(TxOutputView {
            value: 12,
            ext_payload: Arc::from(&[0x72][..]),
        });

        let err = continuing
            .get_output_checked(TXCONTEXT_MAX_CONTINUING_OUTPUTS)
            .expect_err("boundary index must fail");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(err.msg, "txcontext continuing output index out of bounds");
    }
}

impl Uint128 {
    pub fn from_native(value: u128) -> Self {
        Self {
            lo: value as u64,
            hi: (value >> 64) as u64,
        }
    }

    pub fn to_native(self) -> u128 {
        ((self.hi as u128) << 64) | (self.lo as u128)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxContextBase {
    pub total_in: Uint128,
    pub total_out: Uint128,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutputView {
    pub value: u64,
    pub ext_payload: Arc<[u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtIdCacheEntry {
    pub ext_id: u16,
    pub vout_index: u32,
    pub ext_payload: Arc<[u8]>,
    pub value: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxContextContinuing {
    pub continuing_output_count: u8,
    pub continuing_outputs: [Option<TxOutputView>; TXCONTEXT_MAX_CONTINUING_OUTPUTS],
}

impl TxContextContinuing {
    pub fn valid_outputs(&self) -> &[Option<TxOutputView>] {
        &self.continuing_outputs[..self.continuing_output_count as usize]
    }

    pub fn get_output_checked(&self, index: usize) -> Result<&TxOutputView, TxError> {
        if index >= self.continuing_output_count as usize {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "txcontext continuing output index out of bounds",
            ));
        }
        self.continuing_outputs[index].as_ref().ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrSigInvalid,
                "txcontext continuing output missing",
            )
        })
    }
}

#[derive(Clone, Debug)]
pub struct TxContextBundle {
    pub base: Arc<TxContextBase>,
    continuing: HashMap<u16, Arc<TxContextContinuing>>,
}

impl TxContextBundle {
    pub fn get_continuing(&self, ext_id: u16) -> Option<Arc<TxContextContinuing>> {
        self.continuing.get(&ext_id).cloned()
    }

    pub fn sorted_ext_ids(&self) -> Vec<u16> {
        let mut ids: Vec<u16> = self.continuing.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}

fn sum_input_values(resolved_inputs: &[UtxoEntry]) -> Result<u128, TxError> {
    resolved_inputs.iter().try_fold(0u128, |acc, entry| {
        acc.checked_add(entry.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))
    })
}

fn sum_output_values(outputs: &[TxOutput]) -> Result<u128, TxError> {
    outputs.iter().try_fold(0u128, |acc, output| {
        acc.checked_add(output.value as u128)
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, "u128 overflow"))
    })
}

pub fn build_tx_context_output_ext_id_cache(
    tx: &Tx,
) -> Result<BTreeMap<u16, Vec<ExtIdCacheEntry>>, TxError> {
    let mut cache = BTreeMap::new();
    for (vout_index, output) in tx.outputs.iter().enumerate() {
        if output.covenant_type != COV_TYPE_CORE_EXT {
            continue;
        }
        let covenant = parse_core_ext_covenant_data(&output.covenant_data)?;
        cache
            .entry(covenant.ext_id)
            .or_insert_with(Vec::new)
            .push(ExtIdCacheEntry {
                ext_id: covenant.ext_id,
                vout_index: vout_index as u32,
                ext_payload: Arc::from(covenant.ext_payload),
                value: output.value,
            });
    }
    Ok(cache)
}

pub(crate) fn collect_txcontext_ext_ids(
    resolved_inputs: &[UtxoEntry],
    profiles_at_height: &CoreExtProfiles,
) -> Result<Vec<u16>, TxError> {
    let mut ext_ids = BTreeSet::new();
    for entry in resolved_inputs {
        if entry.covenant_type != COV_TYPE_CORE_EXT {
            continue;
        }
        let covenant = parse_core_ext_covenant_data(&entry.covenant_data)?;
        let Some(profile) = profiles_at_height.lookup_active_profile(covenant.ext_id)? else {
            continue;
        };
        if !profile.tx_context_enabled {
            continue;
        }
        ext_ids.insert(covenant.ext_id);
    }
    Ok(ext_ids.into_iter().collect())
}

pub fn build_tx_context(
    tx: &Tx,
    resolved_inputs: &[UtxoEntry],
    output_ext_id_cache: Option<&BTreeMap<u16, Vec<ExtIdCacheEntry>>>,
    height: u64,
    profiles_at_height: &CoreExtProfiles,
) -> Result<Option<TxContextBundle>, TxError> {
    if tx.inputs.len() != resolved_inputs.len() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "txcontext resolved input count mismatch",
        ));
    }

    let ext_ids = collect_txcontext_ext_ids(resolved_inputs, profiles_at_height)?;
    if ext_ids.is_empty() {
        return Ok(None);
    }

    let output_ext_id_cache = output_ext_id_cache.ok_or_else(|| {
        TxError::new(
            ErrorCode::TxErrCovenantTypeInvalid,
            "txcontext output cache missing",
        )
    })?;

    let base = Arc::new(TxContextBase {
        total_in: Uint128::from_native(sum_input_values(resolved_inputs)?),
        total_out: Uint128::from_native(sum_output_values(&tx.outputs)?),
        height,
    });

    let mut continuing = HashMap::with_capacity(ext_ids.len());
    for ext_id in ext_ids {
        let mut bundle = TxContextContinuing::default();
        if let Some(entries) = output_ext_id_cache.get(&ext_id) {
            for entry in entries {
                if bundle.continuing_output_count as usize >= TXCONTEXT_MAX_CONTINUING_OUTPUTS {
                    return Err(TxError::new(
                        ErrorCode::TxErrCovenantTypeInvalid,
                        TXCONTEXT_TOO_MANY_CONTINUING_OUTPUTS,
                    ));
                }
                let index = bundle.continuing_output_count as usize;
                bundle.continuing_outputs[index] = Some(TxOutputView {
                    value: entry.value,
                    ext_payload: Arc::clone(&entry.ext_payload),
                });
                bundle.continuing_output_count += 1;
            }
        }
        continuing.insert(ext_id, Arc::new(bundle));
    }

    Ok(Some(TxContextBundle { base, continuing }))
}

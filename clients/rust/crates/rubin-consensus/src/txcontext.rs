use crate::constants::COV_TYPE_EXT;
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
        if output.covenant_type != COV_TYPE_EXT {
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

fn collect_txcontext_ext_ids(
    resolved_inputs: &[UtxoEntry],
    profiles_at_height: &CoreExtProfiles,
) -> Result<Vec<u16>, TxError> {
    let mut ext_ids = BTreeSet::new();
    for entry in resolved_inputs {
        if entry.covenant_type != COV_TYPE_EXT {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_ext::{CoreExtActiveProfile, CoreExtProfiles, CoreExtVerificationBinding};
    use crate::tx::{Tx, TxInput, TxOutput};

    fn core_ext_covdata(ext_id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ext_id.to_le_bytes());
        crate::compactsize::encode_compact_size(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    fn static_profiles(entries: &[(u16, bool)]) -> CoreExtProfiles {
        CoreExtProfiles {
            active: entries
                .iter()
                .map(|(ext_id, tx_context_enabled)| CoreExtActiveProfile {
                    ext_id: *ext_id,
                    tx_context_enabled: *tx_context_enabled,
                    allowed_suite_ids: vec![0x42],
                    verification_binding: CoreExtVerificationBinding::VerifySigExtAccept,
                    verify_sig_ext_tx_context_fn: None,
                    binding_descriptor: b"accept".to_vec(),
                    ext_payload_schema: b"schema".to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn build_tx_context_output_ext_id_cache_rejects_malformed_output() {
        let tx = Tx {
            version: 1,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 10,
                covenant_type: COV_TYPE_EXT,
                covenant_data: vec![0x01],
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };

        let err = build_tx_context_output_ext_id_cache(&tx).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn build_tx_context_returns_none_without_txcontext_enabled_inputs() {
        let tx = Tx {
            version: 1,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 33,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(7, &[0xaa]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        let resolved_inputs = vec![UtxoEntry {
            value: 50,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0xbb]),
            creation_height: 0,
            created_by_coinbase: false,
        }];

        let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
        let bundle = build_tx_context(
            &tx,
            &resolved_inputs,
            Some(&cache),
            12,
            &static_profiles(&[(7, false)]),
        )
        .unwrap();
        assert!(bundle.is_none());
    }

    #[test]
    fn build_tx_context_requires_output_cache_when_enabled() {
        let tx = Tx {
            version: 1,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 33,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(7, &[]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        let resolved_inputs = vec![UtxoEntry {
            value: 50,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0xbb]),
            creation_height: 0,
            created_by_coinbase: false,
        }];

        let err = build_tx_context(
            &tx,
            &resolved_inputs,
            None,
            12,
            &static_profiles(&[(7, true)]),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }

    #[test]
    fn build_tx_context_builds_base_and_deterministic_continuations() {
        let tx = Tx {
            version: 1,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![
                TxInput {
                    prev_txid: [1u8; 32],
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0,
                },
                TxInput {
                    prev_txid: [2u8; 32],
                    prev_vout: 1,
                    script_sig: vec![],
                    sequence: 0,
                },
                TxInput {
                    prev_txid: [3u8; 32],
                    prev_vout: 2,
                    script_sig: vec![],
                    sequence: 0,
                },
            ],
            outputs: vec![
                TxOutput {
                    value: 11,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[0x07, 0x01]),
                },
                TxOutput {
                    value: 12,
                    covenant_type: crate::constants::COV_TYPE_P2PK,
                    covenant_data: vec![0x01],
                },
                TxOutput {
                    value: 13,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(5, &[0x05, 0x01]),
                },
                TxOutput {
                    value: 14,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[0x07, 0x02]),
                },
                TxOutput {
                    value: 15,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(5, &[0x05, 0x02]),
                },
            ],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        let resolved_inputs = vec![
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(7, &[0xaa]),
                creation_height: 0,
                created_by_coinbase: false,
            },
            UtxoEntry {
                value: 200,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(5, &[0xbb]),
                creation_height: 0,
                created_by_coinbase: false,
            },
            UtxoEntry {
                value: 300,
                covenant_type: crate::constants::COV_TYPE_P2PK,
                covenant_data: vec![0x01],
                creation_height: 0,
                created_by_coinbase: false,
            },
        ];

        let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
        let bundle = build_tx_context(
            &tx,
            &resolved_inputs,
            Some(&cache),
            222,
            &static_profiles(&[(5, true), (7, true)]),
        )
        .unwrap()
        .expect("bundle");
        assert_eq!(bundle.base.total_in, Uint128 { lo: 600, hi: 0 });
        assert_eq!(bundle.base.total_out, Uint128 { lo: 65, hi: 0 });
        assert_eq!(bundle.base.height, 222);
        assert_eq!(bundle.sorted_ext_ids(), vec![5, 7]);

        let ext5 = bundle.get_continuing(5).expect("ext 5");
        assert_eq!(ext5.continuing_output_count, 2);
        assert_eq!(ext5.get_output_checked(0).unwrap().value, 13);
        assert_eq!(
            ext5.get_output_checked(0).unwrap().ext_payload.as_ref(),
            &[0x05, 0x01]
        );
        assert_eq!(ext5.get_output_checked(1).unwrap().value, 15);

        let ext7 = bundle.get_continuing(7).expect("ext 7");
        assert_eq!(ext7.continuing_output_count, 2);
        assert_eq!(ext7.get_output_checked(0).unwrap().value, 11);
        assert_eq!(ext7.get_output_checked(1).unwrap().value, 14);
    }

    #[test]
    fn build_tx_context_preserves_empty_payload_as_empty_vec() {
        let tx = Tx {
            version: 1,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: 0,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 33,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(7, &[]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        let resolved_inputs = vec![UtxoEntry {
            value: 50,
            covenant_type: COV_TYPE_EXT,
            covenant_data: core_ext_covdata(7, &[0xaa]),
            creation_height: 0,
            created_by_coinbase: false,
        }];
        let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
        let bundle = build_tx_context(
            &tx,
            &resolved_inputs,
            Some(&cache),
            12,
            &static_profiles(&[(7, true)]),
        )
        .unwrap()
        .expect("bundle");
        let output = bundle
            .get_continuing(7)
            .unwrap()
            .get_output_checked(0)
            .unwrap()
            .ext_payload
            .clone();
        assert!(output.is_empty());
    }

    #[test]
    fn build_tx_context_rejects_third_output_for_lowest_ext_id() {
        let tx = Tx {
            version: 1,
            tx_kind: 0,
            tx_nonce: 1,
            inputs: vec![
                TxInput {
                    prev_txid: [1u8; 32],
                    prev_vout: 0,
                    script_sig: vec![],
                    sequence: 0,
                },
                TxInput {
                    prev_txid: [2u8; 32],
                    prev_vout: 1,
                    script_sig: vec![],
                    sequence: 0,
                },
            ],
            outputs: vec![
                TxOutput {
                    value: 1,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(9, &[0x91]),
                },
                TxOutput {
                    value: 2,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[0x71]),
                },
                TxOutput {
                    value: 3,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(9, &[0x92]),
                },
                TxOutput {
                    value: 4,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[0x72]),
                },
                TxOutput {
                    value: 5,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(7, &[0x73]),
                },
                TxOutput {
                    value: 6,
                    covenant_type: COV_TYPE_EXT,
                    covenant_data: core_ext_covdata(9, &[0x93]),
                },
            ],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![],
            da_payload: vec![],
        };
        let resolved_inputs = vec![
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(9, &[0xaa]),
                creation_height: 0,
                created_by_coinbase: false,
            },
            UtxoEntry {
                value: 200,
                covenant_type: COV_TYPE_EXT,
                covenant_data: core_ext_covdata(7, &[0xbb]),
                creation_height: 0,
                created_by_coinbase: false,
            },
        ];
        let cache = build_tx_context_output_ext_id_cache(&tx).unwrap();
        let err = build_tx_context(
            &tx,
            &resolved_inputs,
            Some(&cache),
            12,
            &static_profiles(&[(7, true), (9, true)]),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
        assert!(err
            .to_string()
            .contains(TXCONTEXT_TOO_MANY_CONTINUING_OUTPUTS));
    }
}

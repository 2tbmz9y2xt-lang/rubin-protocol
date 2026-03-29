#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::constants::{COV_TYPE_EXT, COV_TYPE_P2PK};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let input_count = (data[0] % 4) as usize;
    let output_count = (data[1] % 5) as usize;
    let height = data[2] as u64;

    let mk_cov = |ext_id: u16, payload: &[u8]| {
        let mut out = Vec::with_capacity(2 + 1 + payload.len());
        out.extend_from_slice(&ext_id.to_le_bytes());
        if payload.len() < 0xfd {
            out.push(payload.len() as u8);
        } else {
            return vec![0x00];
        }
        out.extend_from_slice(payload);
        out
    };

    let mut cursor = 3usize;
    let mut take = |n: usize| {
        let end = cursor.saturating_add(n).min(data.len());
        let chunk = &data[cursor..end];
        cursor = end;
        chunk
    };

    let mut inputs = Vec::with_capacity(input_count);
    let mut resolved_inputs = Vec::with_capacity(input_count);
    for i in 0..input_count {
        let ext_id = 1 + (take(1).first().copied().unwrap_or(0) % 3) as u16;
        let payload_len = (take(1).first().copied().unwrap_or(0) % 3) as usize;
        let payload = take(payload_len);
        let is_ext = take(1).first().copied().unwrap_or(0) % 2 == 0;
        inputs.push(rubin_consensus::TxInput {
            prev_txid: [i as u8; 32],
            prev_vout: i as u32,
            script_sig: Vec::new(),
            sequence: 0,
        });
        resolved_inputs.push(rubin_consensus::UtxoEntry {
            value: 1 + take(1).first().copied().unwrap_or(0) as u64,
            covenant_type: if is_ext { COV_TYPE_EXT } else { COV_TYPE_P2PK },
            covenant_data: if is_ext {
                mk_cov(ext_id, payload)
            } else {
                vec![0u8; 33]
            },
            creation_height: 0,
            created_by_coinbase: false,
        });
    }

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let ext_id = 1 + (take(1).first().copied().unwrap_or(0) % 3) as u16;
        let payload_len = (take(1).first().copied().unwrap_or(0) % 3) as usize;
        let payload = take(payload_len);
        let is_ext = take(1).first().copied().unwrap_or(0) % 2 == 0;
        outputs.push(rubin_consensus::TxOutput {
            value: take(1).first().copied().unwrap_or(0) as u64,
            covenant_type: if is_ext { COV_TYPE_EXT } else { COV_TYPE_P2PK },
            covenant_data: if is_ext {
                mk_cov(ext_id, payload)
            } else {
                vec![0u8; 33]
            },
        });
    }

    let tx = rubin_consensus::Tx {
        version: 1,
        tx_kind: 0,
        tx_nonce: 0,
        inputs,
        outputs,
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: Vec::new(),
        da_payload: Vec::new(),
    };

    let profiles = rubin_consensus::CoreExtProfiles {
        active: (1..=3)
            .map(|ext_id| rubin_consensus::CoreExtActiveProfile {
                ext_id,
                tx_context_enabled: ((data.len() + ext_id as usize) & 1) == 0,
                allowed_suite_ids: vec![0x42],
                verification_binding: rubin_consensus::CoreExtVerificationBinding::VerifySigExtAccept,
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: b"accept".to_vec(),
                ext_payload_schema: b"schema".to_vec(),
            })
            .collect(),
    };

    let cache1 = rubin_consensus::build_tx_context_output_ext_id_cache(&tx);
    let cache2 = rubin_consensus::build_tx_context_output_ext_id_cache(&tx);
    assert_eq!(cache1, cache2);

    if let Ok(ref cache) = cache1 {
        let bundle1 =
            rubin_consensus::build_tx_context(&tx, &resolved_inputs, Some(cache), height, &profiles);
        let bundle2 =
            rubin_consensus::build_tx_context(&tx, &resolved_inputs, Some(cache), height, &profiles);
        assert_eq!(bundle1.is_ok(), bundle2.is_ok());
        if let (Ok(left), Ok(right)) = (&bundle1, &bundle2) {
            assert_eq!(left.is_some(), right.is_some());
            if let (Some(left), Some(right)) = (left, right) {
                assert_eq!(left.base, right.base);
                assert_eq!(left.sorted_ext_ids(), right.sorted_ext_ids());
                let ids = left.sorted_ext_ids();
                assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
                for ext_id in ids {
                    let continuing = left.get_continuing(ext_id).expect("ext bundle");
                    assert!(
                        continuing.continuing_output_count as usize
                            <= rubin_consensus::TXCONTEXT_MAX_CONTINUING_OUTPUTS
                    );
                    for output in continuing.valid_outputs() {
                        let output = output.as_ref().expect("present output");
                        let _ = output.ext_payload.len();
                    }
                }
            }
        }
    }
});

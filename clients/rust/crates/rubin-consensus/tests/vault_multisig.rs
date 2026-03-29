use rubin_consensus::{
    output_descriptor_bytes, parse_multisig_covenant_data, parse_vault_covenant_data,
    witness_slots, ErrorCode,
};

// --- helpers ---

fn sorted_keys(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut k = [0u8; 32];
            k[0] = (i + 1) as u8;
            k
        })
        .collect()
}

fn build_vault_data(
    owner: [u8; 32],
    threshold: u8,
    keys: &[[u8; 32]],
    whitelist: &[[u8; 32]],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&owner);
    out.push(threshold);
    out.push(keys.len() as u8);
    for k in keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&(whitelist.len() as u16).to_le_bytes());
    for w in whitelist {
        out.extend_from_slice(w);
    }
    out
}

fn build_multisig_data(threshold: u8, keys: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(threshold);
    out.push(keys.len() as u8);
    for k in keys {
        out.extend_from_slice(k);
    }
    out
}

// =============================================================
// parse_vault_covenant_data
// =============================================================

#[test]
fn vault_parse_valid_1of1() {
    let owner = [0xaa; 32];
    let keys = sorted_keys(1);
    // whitelist entry must be > owner for sorted order
    let wl = [[0xbb; 32]];
    let data = build_vault_data(owner, 1, &keys, &wl);
    let v = parse_vault_covenant_data(&data).expect("valid 1of1");
    assert_eq!(v.owner_lock_id, owner);
    assert_eq!(v.threshold, 1);
    assert_eq!(v.key_count, 1);
    assert_eq!(v.keys, keys);
    assert_eq!(v.whitelist_count, 1);
    assert_eq!(v.whitelist, wl);
}

#[test]
fn vault_parse_valid_2of3() {
    let owner = [0x00; 32];
    let keys = sorted_keys(3);
    let wl_entries: Vec<[u8; 32]> = (1..=3u8)
        .map(|i| {
            let mut h = [0x80; 32];
            h[0] = 0x80 + i;
            h
        })
        .collect();
    let data = build_vault_data(owner, 2, &keys, &wl_entries);
    let v = parse_vault_covenant_data(&data).expect("valid 2of3");
    assert_eq!(v.threshold, 2);
    assert_eq!(v.key_count, 3);
    assert_eq!(v.whitelist_count, 3);
}

#[test]
fn vault_parse_too_short() {
    let data = vec![0u8; 33]; // < 34
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultMalformed);
    assert!(err.msg.contains("too short"));
}

#[test]
fn vault_parse_key_count_zero() {
    let mut data = vec![0u8; 34];
    data[32] = 1; // threshold
    data[33] = 0; // key_count = 0
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
    assert!(err.msg.contains("key_count"));
}

#[test]
fn vault_parse_key_count_exceeds_max() {
    let mut data = vec![0u8; 34];
    data[32] = 1; // threshold
    data[33] = 13; // key_count = 13 > MAX_VAULT_KEYS(12)
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
}

#[test]
fn vault_parse_threshold_zero() {
    let mut data = vec![0u8; 34];
    data[32] = 0; // threshold = 0
    data[33] = 1; // key_count = 1
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
    assert!(err.msg.contains("threshold"));
}

#[test]
fn vault_parse_threshold_exceeds_key_count() {
    let mut data = vec![0u8; 34];
    data[32] = 3; // threshold = 3
    data[33] = 2; // key_count = 2
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
    assert!(err.msg.contains("threshold"));
}

#[test]
fn vault_parse_truncated_keys() {
    let mut data = vec![0u8; 34];
    data[32] = 1; // threshold
    data[33] = 1; // key_count = 1 → expects 32 more bytes
                  // no key data → truncated
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultMalformed);
    assert!(err.msg.contains("truncated"));
}

#[test]
fn vault_parse_keys_not_sorted() {
    let owner = [0u8; 32];
    let k1 = [0x02; 32];
    let k2 = [0x01; 32]; // k2 < k1 → not sorted
    let wl = [[0xcc; 32]];
    let data = build_vault_data(owner, 1, &[k1, k2], &wl);
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultKeysNotCanonical);
}

#[test]
fn vault_parse_keys_duplicate() {
    let owner = [0u8; 32];
    let k = [0x01; 32];
    let wl = [[0xcc; 32]];
    let data = build_vault_data(owner, 1, &[k, k], &wl); // duplicate
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultKeysNotCanonical);
}

#[test]
fn vault_parse_missing_whitelist_count() {
    // Valid header + 1 key but no whitelist_count bytes
    let mut data = vec![0u8; 32]; // owner
    data.push(1); // threshold
    data.push(1); // key_count
    data.extend_from_slice(&[0x01; 32]); // 1 key
                                         // missing 2-byte whitelist_count
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultMalformed);
    assert!(err.msg.contains("whitelist_count"));
}

#[test]
fn vault_parse_whitelist_count_zero() {
    let mut data = vec![0u8; 32]; // owner
    data.push(1); // threshold
    data.push(1); // key_count
    data.extend_from_slice(&[0x01; 32]); // key
    data.extend_from_slice(&0u16.to_le_bytes()); // whitelist_count = 0
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
    assert!(err.msg.contains("whitelist_count"));
}

#[test]
fn vault_parse_whitelist_count_exceeds_max() {
    let mut data = vec![0u8; 32]; // owner
    data.push(1);
    data.push(1);
    data.extend_from_slice(&[0x01; 32]); // key
    data.extend_from_slice(&1025u16.to_le_bytes()); // > 1024
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultParamsInvalid);
}

#[test]
fn vault_parse_length_mismatch() {
    let owner = [0u8; 32];
    let keys = sorted_keys(1);
    let wl = [[0xcc; 32]];
    let mut data = build_vault_data(owner, 1, &keys, &wl);
    data.push(0xff); // trailing byte → length mismatch
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultMalformed);
    assert!(err.msg.contains("length mismatch"));
}

#[test]
fn vault_parse_whitelist_not_sorted() {
    let owner = [0u8; 32];
    let keys = sorted_keys(1);
    let w1 = [0xcc; 32];
    let w2 = [0xbb; 32]; // w2 < w1
    let data = build_vault_data(owner, 1, &keys, &[w1, w2]);
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultWhitelistNotCanonical);
}

#[test]
fn vault_parse_whitelist_contains_owner() {
    let owner = [0x50; 32];
    let keys = sorted_keys(1);
    // whitelist contains owner_lock_id
    let w1 = [0x40; 32]; // < owner
    let w2 = owner; // == owner
    let data = build_vault_data(owner, 1, &keys, &[w1, w2]);
    let err = parse_vault_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrVaultOwnerDestinationForbidden);
}

#[test]
fn vault_parse_whitelist_duplicate_entries() {
    let owner = [0u8; 32];
    let keys = sorted_keys(1);
    let dup = [0xaa; 32];
    let data = build_vault_data(owner, 1, &keys, &[dup, dup]);
    let err = parse_vault_covenant_data(&data).unwrap_err();
    // Duplicates violate strictly_sorted_unique — same check as unsorted
    assert_eq!(err.code, ErrorCode::TxErrVaultWhitelistNotCanonical);
}

// NOTE: parse_vault_covenant_data_for_spend is pub(crate) — tested via
// inline unit tests in vault.rs, not reachable from integration tests.

#[test]
fn vault_struct_clone_eq() {
    let owner = [0xaa; 32];
    let keys = sorted_keys(1);
    let wl = [[0xbb; 32]];
    let data = build_vault_data(owner, 1, &keys, &wl);
    let v = parse_vault_covenant_data(&data).unwrap();
    let v2 = v.clone();
    assert_eq!(v, v2);
}

#[test]
fn vault_struct_debug() {
    let owner = [0xaa; 32];
    let keys = sorted_keys(1);
    let wl = [[0xbb; 32]];
    let data = build_vault_data(owner, 1, &keys, &wl);
    let v = parse_vault_covenant_data(&data).unwrap();
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("VaultCovenant"));
}

// =============================================================
// parse_multisig_covenant_data
// =============================================================

#[test]
fn multisig_parse_valid_1of1() {
    let keys = sorted_keys(1);
    let data = build_multisig_data(1, &keys);
    let m = parse_multisig_covenant_data(&data).expect("valid 1of1");
    assert_eq!(m.threshold, 1);
    assert_eq!(m.key_count, 1);
    assert_eq!(m.keys, keys);
}

#[test]
fn multisig_parse_valid_2of3() {
    let keys = sorted_keys(3);
    let data = build_multisig_data(2, &keys);
    let m = parse_multisig_covenant_data(&data).expect("valid 2of3");
    assert_eq!(m.threshold, 2);
    assert_eq!(m.key_count, 3);
}

#[test]
fn multisig_parse_too_short() {
    let data = vec![0u8; 33]; // < 34
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("too short"));
}

#[test]
fn multisig_parse_key_count_zero() {
    let mut data = vec![0u8; 34];
    data[0] = 1; // threshold
    data[1] = 0; // key_count = 0
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("key_count"));
}

#[test]
fn multisig_parse_key_count_exceeds_max() {
    let mut data = vec![0u8; 34];
    data[0] = 1;
    data[1] = 13; // > MAX_MULTISIG_KEYS(12)
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn multisig_parse_threshold_zero() {
    let mut data = vec![0u8; 34];
    data[0] = 0; // threshold = 0
    data[1] = 1;
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("threshold"));
}

#[test]
fn multisig_parse_threshold_exceeds_key_count() {
    let mut data = vec![0u8; 34];
    data[0] = 3; // threshold
    data[1] = 2; // key_count
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("threshold"));
}

#[test]
fn multisig_parse_length_mismatch() {
    let keys = sorted_keys(1);
    let mut data = build_multisig_data(1, &keys);
    data.push(0xff); // trailing byte
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("length mismatch"));
}

#[test]
fn multisig_parse_keys_not_sorted() {
    let k1 = [0x02; 32];
    let k2 = [0x01; 32]; // k2 < k1
    let data = build_multisig_data(1, &[k1, k2]);
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    assert!(err.msg.contains("not strictly sorted"));
}

#[test]
fn multisig_parse_keys_duplicate() {
    let k = [0x01; 32];
    let data = build_multisig_data(1, &[k, k]);
    let err = parse_multisig_covenant_data(&data).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

#[test]
fn multisig_struct_clone_eq() {
    let keys = sorted_keys(2);
    let data = build_multisig_data(1, &keys);
    let m = parse_multisig_covenant_data(&data).unwrap();
    let m2 = m.clone();
    assert_eq!(m, m2);
}

#[test]
fn multisig_struct_debug() {
    let keys = sorted_keys(1);
    let data = build_multisig_data(1, &keys);
    let m = parse_multisig_covenant_data(&data).unwrap();
    let dbg = format!("{:?}", m);
    assert!(dbg.contains("MultisigCovenant"));
}

// =============================================================
// witness_slots
// =============================================================

#[test]
fn witness_slots_p2pk() {
    assert_eq!(witness_slots(0x0000, &[]).unwrap(), 1); // COV_TYPE_P2PK
}

#[test]
fn witness_slots_ext() {
    assert_eq!(witness_slots(0x0102, &[]).unwrap(), 1); // COV_TYPE_EXT
}

#[test]
fn witness_slots_stealth() {
    assert_eq!(witness_slots(0x0105, &[]).unwrap(), 1); // COV_TYPE_STEALTH (CORE_STEALTH_WITNESS_SLOTS=1)
}

#[test]
fn witness_slots_htlc() {
    assert_eq!(witness_slots(0x0100, &[]).unwrap(), 2); // COV_TYPE_HTLC
}

#[test]
fn witness_slots_multisig_from_payload() {
    let mut data = vec![0u8; 2];
    data[1] = 5; // key_count at byte[1]
    assert_eq!(witness_slots(0x0104, &data).unwrap(), 5); // COV_TYPE_MULTISIG
}

#[test]
fn witness_slots_multisig_short_payload() {
    assert_eq!(witness_slots(0x0104, &[]).unwrap(), 1); // defaults to 1
}

#[test]
fn witness_slots_vault_from_payload() {
    let mut data = vec![0u8; 34];
    data[33] = 3; // key_count at byte[33]
    assert_eq!(witness_slots(0x0101, &data).unwrap(), 3); // COV_TYPE_VAULT
}

#[test]
fn witness_slots_vault_short_payload() {
    assert_eq!(witness_slots(0x0101, &[0u8; 33]).unwrap(), 1); // defaults to 1
}

#[test]
fn witness_slots_unknown_covenant_rejected() {
    let err = witness_slots(0xffff, &[]).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
}

// =============================================================
// output_descriptor_bytes
// =============================================================

#[test]
fn output_descriptor_bytes_p2pk_shape() {
    let cov_data = vec![0xaa; 33];
    let desc = output_descriptor_bytes(0x0000, &cov_data); // COV_TYPE_P2PK
                                                           // type(2) + compactsize(1, since 33 < 253) + data(33) = 36
    assert_eq!(desc.len(), 36);
    assert_eq!(desc[0..2], 0x0000u16.to_le_bytes());
    assert_eq!(desc[2], 33); // compact size
    assert_eq!(&desc[3..], &cov_data[..]);
}

#[test]
fn output_descriptor_bytes_empty_data() {
    let desc = output_descriptor_bytes(0x0101, &[]); // COV_TYPE_VAULT
    assert_eq!(desc.len(), 3); // type(2) + compactsize(1, value 0)
    assert_eq!(desc[2], 0);
}

// =============================================================
// vault boundary: max keys (12)
// =============================================================

#[test]
fn vault_parse_max_keys() {
    let owner = [0u8; 32];
    let keys = sorted_keys(12);
    let wl = [[0xff; 32]]; // single whitelist > owner
    let data = build_vault_data(owner, 1, &keys, &wl);
    let v = parse_vault_covenant_data(&data).expect("max keys valid");
    assert_eq!(v.key_count, 12);
}

#[test]
fn multisig_parse_max_keys() {
    let keys = sorted_keys(12);
    let data = build_multisig_data(12, &keys); // 12-of-12
    let m = parse_multisig_covenant_data(&data).expect("max keys valid");
    assert_eq!(m.key_count, 12);
    assert_eq!(m.threshold, 12);
}

// =============================================================
// DeepSeek R2 findings — coverage gaps
// =============================================================

#[test]
fn vault_parse_max_whitelist_count_1024() {
    let owner = [0u8; 32];
    let keys = sorted_keys(1);
    // Build 1024 sorted unique whitelist entries
    let wl: Vec<[u8; 32]> = (0..1024u16)
        .map(|i| {
            let mut h = [0u8; 32];
            // Encode i as big-endian in first 2 bytes for lexicographic sort
            h[0] = (i >> 8) as u8;
            h[1] = (i & 0xff) as u8;
            // Ensure > owner ([0;32]) — first entry has h[0]=0,h[1]=0 which == owner
            // Shift all by +1 in last byte to avoid collision with owner
            h[31] = 1;
            h
        })
        .collect();
    let data = build_vault_data(owner, 1, &keys, &wl);
    let v = parse_vault_covenant_data(&data).expect("max whitelist valid");
    assert_eq!(v.whitelist_count, 1024);
}

#[test]
fn vault_whitelist_count_le_byte_order() {
    let owner = [0u8; 32];
    let keys = sorted_keys(1);
    let wl = [[0xbb; 32]]; // single entry
    let data = build_vault_data(owner, 1, &keys, &wl);
    // whitelist_count at offset 32(owner) + 1(threshold) + 1(key_count) + 32(key) = 66
    let wl_offset = 32 + 1 + 1 + 32;
    assert_eq!(data[wl_offset], 1); // LE: low byte = 1
    assert_eq!(data[wl_offset + 1], 0); // LE: high byte = 0
}

#[test]
fn witness_slots_vault_max_keys() {
    let mut data = vec![0u8; 34];
    data[33] = 12; // key_count = MAX_VAULT_KEYS
    assert_eq!(witness_slots(0x0101, &data).unwrap(), 12); // COV_TYPE_VAULT
}

#[test]
fn witness_slots_multisig_max_keys() {
    let mut data = vec![0u8; 2];
    data[1] = 12; // key_count = MAX_MULTISIG_KEYS
    assert_eq!(witness_slots(0x0104, &data).unwrap(), 12); // COV_TYPE_MULTISIG
}

#[test]
fn output_descriptor_bytes_large_data_3byte_compact_size() {
    let cov_data = vec![0x42; 300]; // 300 >= 253 → 3-byte compact size
    let desc = output_descriptor_bytes(0x0101, &cov_data); // COV_TYPE_VAULT
                                                           // type(2) + compactsize(3: 0xfd + u16 LE) + data(300) = 305
    assert_eq!(desc.len(), 305);
    assert_eq!(desc[0..2], 0x0101u16.to_le_bytes());
    assert_eq!(desc[2], 0xfd); // compact size marker for 253..65535
    assert_eq!(desc[3..5], 300u16.to_le_bytes()); // 300 as u16 LE
    assert_eq!(&desc[5..], &cov_data[..]);
}

use super::*;
use sha3::{Digest, Sha3_256};

macro_rules! make_outpoint {
    ($txid_byte:expr, $vout:expr) => {{
        let mut txid = [0u8; 32];
        txid[0] = $txid_byte;
        Outpoint { txid, vout: $vout }
    }};
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
    let op = make_outpoint!(0x42, 7);
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
    let op_a = make_outpoint!(0x01, 0);
    let op_b = make_outpoint!(0x02, 0);
    let op_c = make_outpoint!(0x03, 0);
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
    let op = make_outpoint!(0x01, 0);
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
    let op = make_outpoint!(0x01, 0);
    let mut s1 = HashMap::new();
    s1.insert(op.clone(), make_entry(100, 0, &[], 0, false));
    let mut s2 = HashMap::new();
    s2.insert(op.clone(), make_entry(101, 0, &[], 0, false));
    assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
}

#[test]
fn state_digest_sensitive_to_covenant_type() {
    let op = make_outpoint!(0x01, 0);
    let mut s1 = HashMap::new();
    s1.insert(op.clone(), make_entry(100, 0x0000, &[], 0, false));
    let mut s2 = HashMap::new();
    s2.insert(op.clone(), make_entry(100, 0x0100, &[], 0, false));
    assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
}

#[test]
fn state_digest_sensitive_to_covenant_data() {
    let op = make_outpoint!(0x01, 0);
    let mut s1 = HashMap::new();
    s1.insert(op.clone(), make_entry(100, 0, &[0x01], 0, false));
    let mut s2 = HashMap::new();
    s2.insert(op.clone(), make_entry(100, 0, &[0x02], 0, false));
    assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
}

#[test]
fn state_digest_sensitive_to_creation_height() {
    let op = make_outpoint!(0x01, 0);
    let mut s1 = HashMap::new();
    s1.insert(op.clone(), make_entry(100, 0, &[], 10, false));
    let mut s2 = HashMap::new();
    s2.insert(op.clone(), make_entry(100, 0, &[], 11, false));
    assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
}

#[test]
fn state_digest_sensitive_to_coinbase_flag() {
    let op = make_outpoint!(0x01, 0);
    let mut s1 = HashMap::new();
    s1.insert(op.clone(), make_entry(100, 0, &[], 0, false));
    let mut s2 = HashMap::new();
    s2.insert(op.clone(), make_entry(100, 0, &[], 0, true));
    assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
}

#[test]
fn state_digest_sensitive_to_txid() {
    let op_a = make_outpoint!(0x01, 0);
    let op_b = make_outpoint!(0x02, 0);
    let entry = make_entry(100, 0, &[], 0, false);
    let mut s1 = HashMap::new();
    s1.insert(op_a, entry.clone());
    let mut s2 = HashMap::new();
    s2.insert(op_b, entry);
    assert_ne!(utxo_set_hash(&s1), utxo_set_hash(&s2));
}

#[test]
fn state_digest_sensitive_to_vout() {
    let op_a = make_outpoint!(0x01, 0);
    let op_b = make_outpoint!(0x01, 1);
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
    let op_0 = make_outpoint!(0x01, 0);
    let op_1 = make_outpoint!(0x01, 1);
    let op_2 = make_outpoint!(0x01, 2);
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
    let op = make_outpoint!(0x01, 0);
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
    utxos.insert(make_outpoint!(0x01, 0), make_entry(100, 0, &[], 1, false));
    utxos.insert(
        make_outpoint!(0x02, 5),
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
    let op_a = make_outpoint!(0x01, 0);
    let op_b = make_outpoint!(0x02, 0);
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
    let op = make_outpoint!(0x01, 0);
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
    let op_a = make_outpoint!(0x01, 5);
    let op_b = make_outpoint!(0x01, 3);
    let op_c = make_outpoint!(0x02, 0);

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

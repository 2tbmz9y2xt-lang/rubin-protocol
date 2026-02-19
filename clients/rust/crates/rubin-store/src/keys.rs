//! Canonical byte encoding and decoding for KV table keys and values.
//!
//! All integers are little-endian. Layouts are deterministic and must
//! match the Go implementation byte-for-byte for cross-client parity.

use rubin_consensus::{
    compact_size_decode, compact_size_encode, BlockHeader, TxOutPoint, TxOutput, UtxoEntry,
};

// ---------------------------------------------------------------------------
// Block index status enum
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockStatus {
    Unknown = 0,
    Valid = 1,
    Invalid = 2,
    Orphaned = 3,
}

impl BlockStatus {
    pub fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Valid),
            2 => Ok(Self::Invalid),
            3 => Ok(Self::Orphaned),
            _ => Err(format!("invalid block status byte: {v}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Block index entry
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockIndexEntry {
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub cumulative_work: u128,
    pub status: BlockStatus,
}

/// Encode block index entry: height[8] || prev_hash[32] || cumulative_work[16] || status[1] = 57 bytes.
pub fn encode_block_index(entry: &BlockIndexEntry) -> [u8; 57] {
    let mut buf = [0u8; 57];
    buf[0..8].copy_from_slice(&entry.height.to_le_bytes());
    buf[8..40].copy_from_slice(&entry.prev_hash);
    buf[40..56].copy_from_slice(&entry.cumulative_work.to_le_bytes());
    buf[56] = entry.status as u8;
    buf
}

pub fn decode_block_index(data: &[u8]) -> Result<BlockIndexEntry, String> {
    if data.len() != 57 {
        return Err(format!(
            "block_index: expected 57 bytes, got {}",
            data.len()
        ));
    }
    let height = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&data[8..40]);
    let cumulative_work = u128::from_le_bytes(data[40..56].try_into().unwrap());
    let status = BlockStatus::from_u8(data[56])?;
    Ok(BlockIndexEntry {
        height,
        prev_hash,
        cumulative_work,
        status,
    })
}

// ---------------------------------------------------------------------------
// Outpoint key: txid[32] || vout_le[4] = 36 bytes
// ---------------------------------------------------------------------------

pub fn encode_outpoint_key(outpoint: &TxOutPoint) -> [u8; 36] {
    let mut buf = [0u8; 36];
    buf[0..32].copy_from_slice(&outpoint.txid);
    buf[32..36].copy_from_slice(&outpoint.vout.to_le_bytes());
    buf
}

pub fn decode_outpoint_key(data: &[u8]) -> Result<TxOutPoint, String> {
    if data.len() != 36 {
        return Err(format!("outpoint key: expected 36 bytes, got {}", data.len()));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&data[0..32]);
    let vout = u32::from_le_bytes(data[32..36].try_into().unwrap());
    Ok(TxOutPoint { txid, vout })
}

// ---------------------------------------------------------------------------
// UTXO entry value: value[8] || covenant_type[2] || creation_height[8]
//                   || coinbase_flag[1] || covenant_data[var]
// ---------------------------------------------------------------------------

pub fn encode_utxo_entry(entry: &UtxoEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(19 + entry.output.covenant_data.len());
    buf.extend_from_slice(&entry.output.value.to_le_bytes());
    buf.extend_from_slice(&entry.output.covenant_type.to_le_bytes());
    buf.extend_from_slice(&entry.creation_height.to_le_bytes());
    buf.push(if entry.created_by_coinbase { 1 } else { 0 });
    buf.extend_from_slice(&entry.output.covenant_data);
    buf
}

pub fn decode_utxo_entry(data: &[u8]) -> Result<UtxoEntry, String> {
    if data.len() < 19 {
        return Err(format!(
            "utxo entry: expected >= 19 bytes, got {}",
            data.len()
        ));
    }
    let value = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let covenant_type = u16::from_le_bytes(data[8..10].try_into().unwrap());
    let creation_height = u64::from_le_bytes(data[10..18].try_into().unwrap());
    let created_by_coinbase = data[18] != 0;
    let covenant_data = data[19..].to_vec();
    Ok(UtxoEntry {
        output: TxOutput {
            value,
            covenant_type,
            covenant_data,
        },
        creation_height,
        created_by_coinbase,
    })
}

// ---------------------------------------------------------------------------
// Undo record:
//   compact_size(n_spent) || [outpoint(36) || utxo_entry_bytes]* ||
//   compact_size(n_created) || [outpoint(36)]*
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndoEntry {
    pub outpoint: TxOutPoint,
    pub restored_entry: UtxoEntry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndoRecord {
    pub spent: Vec<UndoEntry>,
    pub created: Vec<TxOutPoint>,
}

pub fn encode_undo_record(record: &UndoRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    // spent count
    buf.extend_from_slice(&compact_size_encode(record.spent.len() as u64));
    for item in &record.spent {
        buf.extend_from_slice(&encode_outpoint_key(&item.outpoint));
        let entry_bytes = encode_utxo_entry(&item.restored_entry);
        buf.extend_from_slice(&compact_size_encode(entry_bytes.len() as u64));
        buf.extend_from_slice(&entry_bytes);
    }
    // created count
    buf.extend_from_slice(&compact_size_encode(record.created.len() as u64));
    for outpoint in &record.created {
        buf.extend_from_slice(&encode_outpoint_key(outpoint));
    }
    buf
}

pub fn decode_undo_record(data: &[u8]) -> Result<UndoRecord, String> {
    let mut offset = 0;

    let (n_spent, consumed) =
        compact_size_decode(&data[offset..]).map_err(|e| format!("undo spent count: {e}"))?;
    offset += consumed;

    let mut spent = Vec::with_capacity(n_spent as usize);
    for _ in 0..n_spent {
        if offset + 36 > data.len() {
            return Err("undo: truncated spent outpoint".into());
        }
        let outpoint = decode_outpoint_key(&data[offset..offset + 36])?;
        offset += 36;

        let (entry_len, consumed) = compact_size_decode(&data[offset..])
            .map_err(|e| format!("undo spent entry len: {e}"))?;
        offset += consumed;
        let entry_len = entry_len as usize;

        if offset + entry_len > data.len() {
            return Err("undo: truncated spent entry".into());
        }
        let restored_entry = decode_utxo_entry(&data[offset..offset + entry_len])?;
        offset += entry_len;

        spent.push(UndoEntry {
            outpoint,
            restored_entry,
        });
    }

    let (n_created, consumed) =
        compact_size_decode(&data[offset..]).map_err(|e| format!("undo created count: {e}"))?;
    offset += consumed;

    let mut created = Vec::with_capacity(n_created as usize);
    for _ in 0..n_created {
        if offset + 36 > data.len() {
            return Err("undo: truncated created outpoint".into());
        }
        let outpoint = decode_outpoint_key(&data[offset..offset + 36])?;
        offset += 36;
        created.push(outpoint);
    }

    Ok(UndoRecord { spent, created })
}

// ---------------------------------------------------------------------------
// Block header bytes: 116 bytes canonical encoding
// ---------------------------------------------------------------------------

pub fn encode_block_header(header: &BlockHeader) -> [u8; 116] {
    rubin_consensus::block_header_bytes(header)
}

pub fn decode_block_header(data: &[u8]) -> Result<BlockHeader, String> {
    if data.len() != 116 {
        return Err(format!(
            "block header: expected 116 bytes, got {}",
            data.len()
        ));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(&data[4..36]);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&data[36..68]);
    let timestamp = u64::from_le_bytes(data[68..76].try_into().unwrap());
    let mut target = [0u8; 32];
    target.copy_from_slice(&data[76..108]);
    let nonce = u64::from_le_bytes(data[108..116].try_into().unwrap());
    Ok(BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        timestamp,
        target,
        nonce,
    })
}

// ---------------------------------------------------------------------------
// Header work: floor(2^256 / target)
// ---------------------------------------------------------------------------

/// Compute proof-of-work for a single header: floor(2^256 / target).
/// Returns u128 which is sufficient for practical chain lengths.
pub fn header_work(target: &[u8; 32]) -> u128 {
    // target is 32 bytes big-endian (as stored in BlockHeader).
    // We need 2^256 / target. Since we cannot represent 2^256 in a u256
    // directly, use the identity: floor(2^256 / t) = floor((2^256 - 1) / t) + 1
    // when t > 0. For t == 0, return 0 (should never happen for valid blocks).

    // Check if target is zero.
    if target.iter().all(|&b| b == 0) {
        return 0;
    }

    // Convert target to u256 (4 x u64, big-endian limbs).
    let t = u256_from_be(target);

    // Compute (2^256 - 1) as [u64::MAX; 4].
    let max256: [u64; 4] = [u64::MAX; 4];

    // floor(max256 / t) + 1
    let quotient = u256_div(max256, t);
    // Check for overflow: if quotient is all-MAX, +1 would wrap to zero.
    if quotient == [u64::MAX; 4] {
        return u128::MAX;
    }
    u256_to_u128_saturating(u256_add_1(quotient))
}

// Minimal u256 arithmetic (big-endian limb order: [0] = most significant)

#[allow(clippy::needless_range_loop)]
fn u256_from_be(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let offset = i * 8;
        limbs[i] = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
    }
    limbs
}

fn u256_is_zero(a: &[u64; 4]) -> bool {
    a.iter().all(|&x| x == 0)
}

fn u256_add_1(a: [u64; 4]) -> [u64; 4] {
    let mut result = a;
    for i in (0..4).rev() {
        let (val, overflow) = result[i].overflowing_add(1);
        result[i] = val;
        if !overflow {
            break;
        }
    }
    result
}

fn u256_div(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    if u256_is_zero(&b) {
        return [0u64; 4];
    }

    // Simple binary long division for u256.
    let mut quotient = [0u64; 4];
    let mut remainder = [0u64; 4];

    for bit in 0..256 {
        // Shift remainder left by 1.
        let mut carry = 0u64;
        for i in (0..4).rev() {
            let new_carry = remainder[i] >> 63;
            remainder[i] = (remainder[i] << 1) | carry;
            carry = new_carry;
        }

        // Set the lowest bit of remainder to the current bit of a.
        let limb_idx = bit / 64;
        let bit_idx = 63 - (bit % 64);
        let a_bit = (a[limb_idx] >> bit_idx) & 1;
        remainder[3] |= a_bit;

        // If remainder >= b, subtract b and set quotient bit.
        if u256_gte(&remainder, &b) {
            remainder = u256_sub(remainder, b);
            let q_limb = bit / 64;
            let q_bit = 63 - (bit % 64);
            quotient[q_limb] |= 1u64 << q_bit;
        }
    }

    quotient
}

fn u256_gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in 0..4 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

fn u256_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in (0..4).rev() {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    result
}

fn u256_to_u128_saturating(a: [u64; 4]) -> u128 {
    // If high limbs are nonzero, saturate.
    if a[0] != 0 || a[1] != 0 {
        return u128::MAX;
    }
    ((a[2] as u128) << 64) | (a[3] as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_index_roundtrip() {
        let entry = BlockIndexEntry {
            height: 42,
            prev_hash: [0xab; 32],
            cumulative_work: 123456789,
            status: BlockStatus::Valid,
        };
        let encoded = encode_block_index(&entry);
        let decoded = decode_block_index(&encoded).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn test_outpoint_key_roundtrip() {
        let op = TxOutPoint {
            txid: [0xcd; 32],
            vout: 7,
        };
        let encoded = encode_outpoint_key(&op);
        let decoded = decode_outpoint_key(&encoded).unwrap();
        assert_eq!(op, decoded);
    }

    #[test]
    fn test_utxo_entry_roundtrip() {
        let entry = UtxoEntry {
            output: TxOutput {
                value: 5000,
                covenant_type: 0x0001,
                covenant_data: vec![0x01, 0x02, 0x03],
            },
            creation_height: 100,
            created_by_coinbase: true,
        };
        let encoded = encode_utxo_entry(&entry);
        let decoded = decode_utxo_entry(&encoded).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn test_undo_record_roundtrip() {
        let record = UndoRecord {
            spent: vec![UndoEntry {
                outpoint: TxOutPoint {
                    txid: [0x11; 32],
                    vout: 0,
                },
                restored_entry: UtxoEntry {
                    output: TxOutput {
                        value: 1000,
                        covenant_type: 0x0001,
                        covenant_data: vec![0xaa; 33],
                    },
                    creation_height: 5,
                    created_by_coinbase: false,
                },
            }],
            created: vec![TxOutPoint {
                txid: [0x22; 32],
                vout: 1,
            }],
        };
        let encoded = encode_undo_record(&record);
        let decoded = decode_undo_record(&encoded).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn test_header_work_basic() {
        // target = 1 → work = 2^256
        // But saturated to u128::MAX since 2^256 > u128::MAX
        let mut target = [0u8; 32];
        target[31] = 1;
        let w = header_work(&target);
        assert_eq!(w, u128::MAX); // saturated

        // target = 2^255 (0x80 followed by 31 zeros) → work = 2^256 / 2^255 = 2
        let mut target2 = [0u8; 32];
        target2[0] = 0x80;
        let w2 = header_work(&target2);
        assert_eq!(w2, 2);

        // target = 0 → work = 0
        let target_zero = [0u8; 32];
        assert_eq!(header_work(&target_zero), 0);
    }
}

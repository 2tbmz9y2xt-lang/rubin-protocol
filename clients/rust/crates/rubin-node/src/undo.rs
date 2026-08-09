use std::collections::HashSet;
use std::fmt;

use rubin_consensus::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use rubin_consensus::{block_hash, parse_block_bytes, Outpoint, UtxoEntry};
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha3::{Digest, Sha3_256};

use crate::blockstore::valid_canonical_hash_hex;
use crate::chainstate::ChainState;
use crate::io_utils::{parse_hex32, UNDO_FILE_MAX_BYTES};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentUndo {
    pub outpoint: Outpoint,
    pub entry: UtxoEntry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxUndo {
    pub spent: Vec<SpentUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockUndo {
    pub block_height: u64,
    pub previous_already_generated: u128,
    pub txs: Vec<TxUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStateDisconnectSummary {
    pub disconnected_height: u64,
    pub block_hash: [u8; 32],
    pub new_height: u64,
    pub new_tip_hash: [u8; 32],
    pub has_tip: bool,
    pub already_generated: u128,
    pub utxo_count: u64,
}

// ---------------------------------------------------------------------------
// Build undo
// ---------------------------------------------------------------------------

fn is_spendable_output(covenant_type: u16) -> bool {
    covenant_type != COV_TYPE_ANCHOR && covenant_type != COV_TYPE_DA_COMMIT
}

/// Build an undo record by replaying UTXO mutations against an immutable
/// captured previous chain state. It may run after live `connect_block` when
/// `prev_state` was captured before that connection.
pub fn build_block_undo(
    prev_state: &ChainState,
    block_bytes: &[u8],
    block_height: u64,
) -> Result<BlockUndo, String> {
    let pb = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
    if pb.txs.len() != pb.txids.len() {
        return Err("parsed block txid length mismatch".into());
    }

    // Membership-only sets: undo ordering still follows canonical tx/input order.
    let mut spent_prev_outpoints = HashSet::new();
    let mut block_outputs = HashSet::new();
    let mut tx_undos = Vec::with_capacity(pb.txs.len());

    for (i, tx) in pb.txs.iter().enumerate() {
        let mut spent = Vec::with_capacity(tx.inputs.len());
        // Coinbase (index 0) has no real inputs to consume.
        if i > 0 {
            for input in &tx.inputs {
                let op = Outpoint {
                    txid: input.prev_txid,
                    vout: input.prev_vout,
                };
                if block_outputs.remove(&op) {
                    continue;
                }
                let entry = prev_state.utxos.get(&op).ok_or_else(|| {
                    format!("undo missing utxo for {}:{}", hex::encode(op.txid), op.vout)
                })?;
                if !spent_prev_outpoints.insert(op.clone()) {
                    return Err(format!(
                        "undo duplicate prev-state spend for {}:{}",
                        hex::encode(op.txid),
                        op.vout
                    ));
                }
                spent.push(SpentUndo {
                    outpoint: op,
                    entry: entry.clone(),
                });
            }
        }
        // Track new spendable outputs so later txs can consume them without
        // cloning the full previous-state UTXO map.
        for (output_index, out) in tx.outputs.iter().enumerate() {
            if !is_spendable_output(out.covenant_type) {
                continue;
            }
            block_outputs.insert(Outpoint {
                txid: pb.txids[i],
                vout: output_index as u32,
            });
        }
        tx_undos.push(TxUndo { spent });
    }

    Ok(BlockUndo {
        block_height,
        previous_already_generated: prev_state.already_generated,
        txs: tx_undos,
    })
}

// ---------------------------------------------------------------------------
// Disconnect block
// ---------------------------------------------------------------------------

impl ChainState {
    /// Reverse the effects of a single block, restoring the UTXO set and
    /// chain-level accumulators to the state immediately before this block
    /// was connected.
    pub fn disconnect_block(
        &mut self,
        block_bytes: &[u8],
        undo: &BlockUndo,
    ) -> Result<ChainStateDisconnectSummary, String> {
        if !self.has_tip {
            return Err("chainstate has no tip".into());
        }
        // Cheap invariant checks before parsing.
        if self.height != undo.block_height {
            return Err(format!(
                "disconnect height mismatch: chainstate={} undo={}",
                self.height, undo.block_height
            ));
        }

        let pb = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        if pb.txs.len() != pb.txids.len() {
            return Err("parsed block txid length mismatch".into());
        }
        if undo.txs.len() != pb.txs.len() {
            return Err("undo tx count mismatch".into());
        }

        let bh = block_hash(&pb.header_bytes).map_err(|e| e.to_string())?;
        if self.tip_hash != bh {
            return Err("disconnect block is not current tip".into());
        }

        let mut created_outpoints = HashSet::new();
        let mut same_block_spent_outpoints = HashSet::new();
        for (tx_index, tx) in pb.txs.iter().enumerate() {
            if tx_index > 0 {
                for input in &tx.inputs {
                    let op = Outpoint {
                        txid: input.prev_txid,
                        vout: input.prev_vout,
                    };
                    if created_outpoints.contains(&op) {
                        same_block_spent_outpoints.insert(op);
                    }
                }
            }
            for (output_index, out) in tx.outputs.iter().enumerate() {
                if !is_spendable_output(out.covenant_type) {
                    continue;
                }
                created_outpoints.insert(Outpoint {
                    txid: pb.txids[tx_index],
                    vout: output_index as u32,
                });
            }
        }

        let mut work = self.utxos.clone();
        let mut restored_outpoints = HashSet::new();
        // Process transactions in **reverse** order.
        for tx_index in (0..pb.txs.len()).rev() {
            let tx = &pb.txs[tx_index];
            let txid = pb.txids[tx_index];

            // 1. Remove outputs created by this tx.
            for (output_index, out) in tx.outputs.iter().enumerate() {
                if !is_spendable_output(out.covenant_type) {
                    continue;
                }
                let created_outpoint = Outpoint {
                    txid,
                    vout: output_index as u32,
                };
                if work.remove(&created_outpoint).is_none()
                    && !same_block_spent_outpoints.contains(&created_outpoint)
                {
                    return Err(format!(
                        "disconnect missing created output for {}:{}",
                        hex::encode(created_outpoint.txid),
                        created_outpoint.vout
                    ));
                }
            }

            // 2. Restore spent inputs from the undo record.
            for spent in &undo.txs[tx_index].spent {
                if !restored_outpoints.insert(spent.outpoint.clone()) {
                    return Err(format!(
                        "undo duplicate restore entry for {}:{}",
                        hex::encode(spent.outpoint.txid),
                        spent.outpoint.vout
                    ));
                }
                if work.contains_key(&spent.outpoint) {
                    return Err(format!(
                        "undo restore target already present for {}:{}",
                        hex::encode(spent.outpoint.txid),
                        spent.outpoint.vout
                    ));
                }
                work.insert(spent.outpoint.clone(), spent.entry.clone());
            }
        }
        self.utxos = work;
        self.already_generated = undo.previous_already_generated;

        if self.height == 0 {
            self.has_tip = false;
            self.height = 0;
            self.tip_hash = [0u8; 32];
        } else {
            self.height -= 1;
            self.tip_hash = pb.header.prev_block_hash;
        }

        Ok(ChainStateDisconnectSummary {
            disconnected_height: undo.block_height,
            block_hash: bh,
            new_height: self.height,
            new_tip_hash: self.tip_hash,
            has_tip: self.has_tip,
            already_generated: self.already_generated,
            utxo_count: self.utxos.len() as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// JSON serialization (disk format)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BlockUndoDisk {
    block_height: u64,
    previous_already_generated: u64,
    txs: Vec<TxUndoDisk>,
}

#[derive(Debug, Clone, Serialize)]
struct BlockUndoDiskV2 {
    block_height: u64,
    #[serde(serialize_with = "rubin_consensus::uint128_json::serialize")]
    previous_already_generated: u128,
    txs: Vec<TxUndoDisk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockUndoDiskRaw {
    block_height: u64,
    #[serde(rename = "previous_already_generated")]
    _previous_already_generated: IgnoredAny,
    txs: Vec<TxUndoDisk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockUndoPayloadShape {
    #[serde(rename = "block_height")]
    _block_height: IgnoredAny,
    #[serde(rename = "previous_already_generated")]
    _previous_already_generated: IgnoredAny,
    #[serde(rename = "txs")]
    _txs: Vec<TxUndoPayloadShape>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TxUndoPayloadShape {
    #[serde(rename = "spent")]
    _spent: Vec<SpentUndoPayloadShape>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpentUndoPayloadShape {
    #[serde(rename = "txid")]
    _txid: IgnoredAny,
    #[serde(rename = "vout")]
    _vout: IgnoredAny,
    #[serde(rename = "value")]
    _value: IgnoredAny,
    #[serde(rename = "covenant_type")]
    _covenant_type: IgnoredAny,
    #[serde(rename = "covenant_data")]
    _covenant_data: IgnoredAny,
    #[serde(rename = "creation_height")]
    _creation_height: IgnoredAny,
    #[serde(rename = "created_by_coinbase")]
    _created_by_coinbase: IgnoredAny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxUndoDisk {
    spent: Vec<SpentUndoDisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpentUndoDisk {
    txid: String,
    vout: u32,
    value: u64,
    covenant_type: u16,
    covenant_data: String,
    creation_height: u64,
    created_by_coinbase: bool,
}

#[derive(Debug)]
enum UndoSupplyToken {
    Unsigned(u64),
    String { value: String, unescaped: bool },
    Other,
}

struct UndoSupplyTokenVisitor;

impl<'de> Visitor<'de> for UndoSupplyTokenVisitor {
    type Value = UndoSupplyToken;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one undo supply JSON token")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::Other)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::Other)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::Unsigned(value))
    }

    fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E> {
        Ok(u64::try_from(value).map_or(UndoSupplyToken::Other, UndoSupplyToken::Unsigned))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::Other)
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::Other)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::Other)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::Other)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::String {
            value: value.to_owned(),
            unescaped: true,
        })
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::String {
            value: value.to_owned(),
            unescaped: false,
        })
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UndoSupplyToken::String {
            value,
            unescaped: false,
        })
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(UndoSupplyToken::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(UndoSupplyToken::Other)
    }
}

impl<'de> Deserialize<'de> for UndoSupplyToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UndoSupplyTokenVisitor)
    }
}

const UNDO_INVALID_V1_SUPPLY: &str =
    "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64";
const UNDO_INVALID_V2_SUPPLY: &str =
    "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128";
const UNDO_PAYLOAD_NOT_CANONICAL: &str = "decode undo: payload is not the canonical encoding";

struct UndoSupplyProbe(UndoSupplyToken);

struct UndoSupplyProbeVisitor;

impl<'de> Visitor<'de> for UndoSupplyProbeVisitor {
    type Value = UndoSupplyProbe;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an undo payload JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut supply = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "previous_already_generated" {
                if supply.is_some() {
                    return Err(serde::de::Error::duplicate_field(
                        "previous_already_generated",
                    ));
                }
                supply = Some(map.next_value::<UndoSupplyToken>()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        supply
            .map(UndoSupplyProbe)
            .ok_or_else(|| serde::de::Error::missing_field("previous_already_generated"))
    }
}

impl<'de> Deserialize<'de> for UndoSupplyProbe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(UndoSupplyProbeVisitor)
    }
}

fn decode_block_undo_supply(
    raw: &[u8],
    invalid_supply_error: &'static str,
) -> Result<UndoSupplyToken, String> {
    serde_json::from_slice::<BlockUndoPayloadShape>(raw)
        .map_err(|_| UNDO_PAYLOAD_NOT_CANONICAL.to_string())?;
    let supply = serde_json::from_slice::<UndoSupplyProbe>(raw)
        .map_err(|_| invalid_supply_error.to_string())?
        .0;
    Ok(supply)
}

fn decode_block_undo_typed(raw: &[u8]) -> Result<BlockUndoDiskRaw, String> {
    serde_json::from_slice(raw).map_err(|_| UNDO_PAYLOAD_NOT_CANONICAL.to_string())
}

/// Canonical undo PAYLOAD: compact JSON in `BlockUndoDisk` field order with no
/// trailing whitespace or newline. This is NOT the on-disk record —
/// a versioned undo envelope wraps these bytes and binds them to a block hash.
/// This public helper retains the v1 payload shape for compatibility tests;
/// new durable writes use the v2 helper below. Go twin: `marshalBlockUndo`.
pub fn marshal_block_undo(undo: &BlockUndo) -> Result<Vec<u8>, String> {
    let disk = block_undo_to_disk(undo)?;
    serde_json::to_vec(&disk).map_err(|e| format!("encode undo: {e}"))
}

fn marshal_block_undo_v2(undo: &BlockUndo) -> Result<Vec<u8>, String> {
    let disk = block_undo_to_disk_v2(undo);
    serde_json::to_vec(&disk).map_err(|e| format!("encode undo: {e}"))
}

/// Strictly decode a canonical payload. A field/container-shape pass runs before
/// the version-specific supply token is interpreted, so an unknown, duplicate,
/// missing or invalid container at any nesting level wins over a simultaneous
/// supply defect and parser wording never escapes. Remaining scalar conversion
/// follows supply classification, then the typed disk value is re-encoded to pin
/// field order and whitespace byte-for-byte.
///
/// The whole decision happens BEFORE `block_undo_from_disk`, so a checksum-valid
/// but non-canonical payload is refused without allocating the runtime spent
/// entries. The contract orders strict rejection ahead of `BlockUndo` conversion;
/// converting first satisfied that only by accident. Go twin: `unmarshalBlockUndo`.
pub fn unmarshal_block_undo(raw: &[u8]) -> Result<BlockUndo, String> {
    let supply = decode_block_undo_supply(raw, UNDO_INVALID_V1_SUPPLY)?;
    let previous_already_generated = match supply {
        UndoSupplyToken::Unsigned(value) => value,
        _ => return Err(UNDO_INVALID_V1_SUPPLY.to_string()),
    };
    let decoded = decode_block_undo_typed(raw)?;
    let disk = BlockUndoDisk {
        block_height: decoded.block_height,
        previous_already_generated,
        txs: decoded.txs,
    };
    check_undo_txs_canonical_fields(&disk.txs)?;
    if serde_json::to_vec(&disk).map_err(|e| format!("encode undo: {e}"))? != raw {
        return Err(UNDO_PAYLOAD_NOT_CANONICAL.into());
    }
    block_undo_from_disk(disk)
}

fn unmarshal_block_undo_v2(raw: &[u8]) -> Result<BlockUndo, String> {
    let supply = decode_block_undo_supply(raw, UNDO_INVALID_V2_SUPPLY)?;
    let previous_already_generated = match supply {
        UndoSupplyToken::String {
            value,
            unescaped: true,
        } => rubin_consensus::uint128_json::parse_canonical_decimal(&value)
            .ok_or_else(|| UNDO_INVALID_V2_SUPPLY.to_string())?,
        _ => return Err(UNDO_INVALID_V2_SUPPLY.to_string()),
    };
    let decoded = decode_block_undo_typed(raw)?;
    let disk = BlockUndoDiskV2 {
        block_height: decoded.block_height,
        previous_already_generated,
        txs: decoded.txs,
    };
    check_undo_txs_canonical_fields(&disk.txs)?;
    if serde_json::to_vec(&disk).map_err(|e| format!("encode undo: {e}"))? != raw {
        return Err(UNDO_PAYLOAD_NOT_CANONICAL.into());
    }
    block_undo_from_parts(disk.block_height, previous_already_generated, disk.txs)
}

/// Covers the property the disk-level byte comparison is blind to, allocating
/// nothing: hex strings pass through the disk struct verbatim, so an uppercase
/// txid survives the round trip, and two spellings of one undo must not both be
/// canonical when a checksum is bound to the bytes. The Go twin also rejects nil
/// slices here — `Vec` has no nil, so `serde` refused a JSON null already. It
/// used to be enforced by re-encoding the CONVERTED value; stating it is what
/// lets the decision precede conversion.
fn check_undo_txs_canonical_fields(txs: &[TxUndoDisk]) -> Result<(), String> {
    for (tx_index, tx_undo) in txs.iter().enumerate() {
        for (spent_index, spent) in tx_undo.spent.iter().enumerate() {
            if !valid_canonical_hash_hex(&spent.txid) || !valid_lowercase_hex(&spent.covenant_data)
            {
                return Err(format!(
                    "decode undo: txs[{tx_index}].spent[{spent_index}] txid/covenant_data must be lowercase hex"
                ));
            }
        }
    }
    Ok(())
}

/// An even number of lowercase hex digits, any length. `valid_canonical_hash_hex`
/// in blockstore.rs is the fixed-32-byte sibling.
fn valid_lowercase_hex(value: &str) -> bool {
    value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn block_undo_txs_to_disk(src: &[TxUndo]) -> Vec<TxUndoDisk> {
    src.iter()
        .map(|tx_undo| TxUndoDisk {
            spent: tx_undo
                .spent
                .iter()
                .map(|s| SpentUndoDisk {
                    txid: hex::encode(s.outpoint.txid),
                    vout: s.outpoint.vout,
                    value: s.entry.value,
                    covenant_type: s.entry.covenant_type,
                    covenant_data: hex::encode(&s.entry.covenant_data),
                    creation_height: s.entry.creation_height,
                    created_by_coinbase: s.entry.created_by_coinbase,
                })
                .collect(),
        })
        .collect()
}

fn block_undo_to_disk(undo: &BlockUndo) -> Result<BlockUndoDisk, String> {
    let previous_already_generated = u64::try_from(undo.previous_already_generated)
        .map_err(|_| UNDO_INVALID_V1_SUPPLY.to_string())?;
    Ok(BlockUndoDisk {
        block_height: undo.block_height,
        previous_already_generated,
        txs: block_undo_txs_to_disk(&undo.txs),
    })
}

fn block_undo_to_disk_v2(undo: &BlockUndo) -> BlockUndoDiskV2 {
    BlockUndoDiskV2 {
        block_height: undo.block_height,
        previous_already_generated: undo.previous_already_generated,
        txs: block_undo_txs_to_disk(&undo.txs),
    }
}

fn block_undo_from_disk(disk: BlockUndoDisk) -> Result<BlockUndo, String> {
    block_undo_from_parts(
        disk.block_height,
        u128::from(disk.previous_already_generated),
        disk.txs,
    )
}

fn block_undo_from_parts(
    block_height: u64,
    previous_already_generated: u128,
    disk_txs: Vec<TxUndoDisk>,
) -> Result<BlockUndo, String> {
    let mut txs = Vec::with_capacity(disk_txs.len());
    for (tx_index, tx_undo) in disk_txs.into_iter().enumerate() {
        let mut spent = Vec::with_capacity(tx_undo.spent.len());
        for (spent_index, s) in tx_undo.spent.into_iter().enumerate() {
            let txid = parse_hex32(
                &format!("undo[{tx_index}].spent[{spent_index}].txid"),
                &s.txid,
            )?;
            let covenant_data = hex::decode(&s.covenant_data)
                .map_err(|e| format!("undo[{tx_index}].spent[{spent_index}].covenant_data: {e}"))?;
            spent.push(SpentUndo {
                outpoint: Outpoint { txid, vout: s.vout },
                entry: UtxoEntry {
                    value: s.value,
                    covenant_type: s.covenant_type,
                    covenant_data,
                    creation_height: s.creation_height,
                    created_by_coinbase: s.created_by_coinbase,
                },
            });
        }
        txs.push(TxUndo { spent });
    }
    Ok(BlockUndo {
        block_height,
        previous_already_generated,
        txs,
    })
}

// ---------------------------------------------------------------------------
// undo_envelope_v1/v2 (RUB-1132, RUB-1153)
//
// The stored undo record is one compact JSON object binding the canonical
// payload bytes to the block hash they were built for:
//
//   {"version":<1|2>,"block_hash":"<64hex>","payload_b64":"<b64>","checksum":"<64hex>"}\n
//
// checksum = SHA3-256(version_domain || block_hash[32] ||
// uint64_be(payload.len()) || payload), where version_domain is exactly
// "RUBIN_BLOCK_UNDO_V1" or "RUBIN_BLOCK_UNDO_V2". The length prefix makes
// the preimage encoding unambiguous: no two distinct (hash, payload) pairs
// serialize to the same preimage bytes, so concatenation cannot alias one
// frame into another.
// The trailing LF counts against the read bound but is NOT in the preimage.
//
// Go twin: the same section in clients/go/node/undo.go. Both clients must emit
// byte-identical envelopes. The shared v1 artifact pins compatibility and the
// shared v2 artifact pins the new checksum domain, payload and envelope bytes.
//
// Claim boundary: this detects accidental, torn, misnamed and parse-valid local
// corruption before an undo is used. It is NOT authentication — a local actor
// able to rewrite the payload can recompute the checksum. There is no secret
// here and none is claimed.
// ---------------------------------------------------------------------------

/// Stable cross-client prefix of the envelope, version, hash, base64 and
/// checksum rejection classes named in the issue's error_contract. Go's
/// `ErrUndoIntegrity` carries the same identity through `errors.Is`; here the
/// error channel is `String`, so the prefix IS the identity and `get_undo`
/// returns these messages verbatim.
///
/// The payload-conversion class is deliberately OUTSIDE this prefix. A record
/// that clears the checksum is intact on disk; a failure past that point is a
/// schema fault, not a storage-integrity fault, and the contract does not put it
/// under the prefix.
pub const UNDO_INTEGRITY_PREFIX: &str = "UNDO_INTEGRITY";

/// Pinned cross-client messages. Go returns these same strings. Deliberately no
/// repair command: this build ships no `--reindex`.
pub const UNDO_LEGACY_ERR: &str =
    "UNDO_INTEGRITY: legacy/unversioned undo; pre-devnet datadir reset and full resync required";
pub const UNDO_BLOCK_HASH_MISMATCH_ERR: &str = "UNDO_INTEGRITY: block hash mismatch";
pub const UNDO_CHECKSUM_MISMATCH_ERR: &str = "UNDO_INTEGRITY: checksum mismatch";

const UNDO_ENVELOPE_VERSION_V1: u32 = 1;
const UNDO_ENVELOPE_VERSION: u32 = 2;
const UNDO_ENVELOPE_DOMAIN_V1: &[u8] = b"RUBIN_BLOCK_UNDO_V1";
const UNDO_ENVELOPE_DOMAIN_V2: &[u8] = b"RUBIN_BLOCK_UNDO_V2";
const UNDO_HASH_HEX_LEN: usize = 64;

/// The canonical envelope's byte layout is fully determined by these fixed
/// segments plus the two 64-character hex fields, so the reader validates the
/// layout by index arithmetic instead of decoding JSON. That is what keeps peak
/// memory near the file size: no value is materialized on the accept path and
/// `payload_b64` is a SLICE of the caller's buffer, never a copy. Go twin:
/// `undoEnvelopePrefix` and friends in clients/go/node/undo.go.
const UNDO_ENVELOPE_PREFIX_V1: &[u8] = br#"{"version":1,"block_hash":""#;
const UNDO_ENVELOPE_PREFIX_V2: &[u8] = br#"{"version":2,"block_hash":""#;
const UNDO_ENVELOPE_PAYLOAD_SEP: &[u8] = br#"","payload_b64":""#;
const UNDO_ENVELOPE_CHECKSUM_SEP: &[u8] = br#"","checksum":""#;
const UNDO_ENVELOPE_SUFFIX: &[u8] = b"\"}\n";

/// The envelope minus the base64 body. Derived from the segments above rather
/// than written down, so a format edit cannot leave the bound behind.
/// Cross-checked against a real envelope by `undo_envelope_bound_derivation`.
const UNDO_ENVELOPE_FRAME_BYTES: usize = UNDO_ENVELOPE_PREFIX_V2.len()
    + UNDO_HASH_HEX_LEN
    + UNDO_ENVELOPE_PAYLOAD_SEP.len()
    + UNDO_ENVELOPE_CHECKSUM_SEP.len()
    + UNDO_HASH_HEX_LEN
    + UNDO_ENVELOPE_SUFFIX.len();

/// Decoded-payload ceiling, run BACKWARDS from the unchanged undo class bound: a
/// payload of n bytes occupies ceil(n/3)*4 base64 characters, so the largest n
/// whose complete envelope still fits is 3*floor((UNDO_FILE_MAX_BYTES - frame)/4).
/// The floor MUST come before the multiply — `(bound-frame)*3/4` overshoots by
/// two bytes and would let `put_undo` emit a 2_000_000_001-byte envelope that
/// `get_undo` then refuses.
///
/// The envelope reuses `UNDO_FILE_MAX_BYTES` itself as the outer read/save bound
/// rather than the raw derivation (~2.67e9): every storage-read bound in this
/// crate must stay below 2^31-2 because the reader probes with `max_bytes + 1`,
/// and 2e9 already admits the consensus-reachable envelope maximum
/// (1_371_851_881 bytes) with ~1.46x margin. Revision conditions are recorded in
/// the issue's bound-audit amendment.
pub(crate) const UNDO_PAYLOAD_MAX_BYTES: u64 =
    3 * ((UNDO_FILE_MAX_BYTES - UNDO_ENVELOPE_FRAME_BYTES as u64) / 4);

/// The writer's shape; the reader never decodes into it. Field ORDER is part of
/// the format: `serde` emits struct fields in declaration order and
/// `encoding/json` does the same, which is what makes the two clients' bytes
/// identical — and what the segment constants above mirror.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UndoEnvelopeDisk {
    version: u32,
    block_hash: String,
    payload_b64: String,
    checksum: String,
}

/// Classification probe. Only `version` is captured; `serde` skips the other
/// fields without materializing them, so even a maximum-size hostile record
/// costs no proportional allocation here.
#[derive(Deserialize)]
struct UndoVersionProbe {
    version: Option<u32>,
}

#[cfg(test)]
fn undo_envelope_checksum(block_hash: [u8; 32], payload: &[u8]) -> [u8; 32] {
    undo_envelope_checksum_for_version(UNDO_ENVELOPE_VERSION_V1, block_hash, payload)
}

fn undo_envelope_checksum_for_version(
    version: u32,
    block_hash: [u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    let domain = if version == UNDO_ENVELOPE_VERSION_V1 {
        UNDO_ENVELOPE_DOMAIN_V1
    } else {
        UNDO_ENVELOPE_DOMAIN_V2
    };
    hasher.update(domain);
    hasher.update(block_hash);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

/// Also enforces the SAVE-side bounds, so the node can never persist a record it
/// would refuse to read back. Both ends test the same two quantities — decoded
/// payload and complete envelope — which is what makes the refusal boundary
/// byte-symmetric rather than off by a rounding step.
pub fn marshal_undo_envelope(block_hash: [u8; 32], undo: &BlockUndo) -> Result<Vec<u8>, String> {
    marshal_undo_envelope_version(UNDO_ENVELOPE_VERSION, block_hash, undo)
}

#[cfg(test)]
pub(crate) fn marshal_undo_envelope_v1(
    block_hash: [u8; 32],
    undo: &BlockUndo,
) -> Result<Vec<u8>, String> {
    marshal_undo_envelope_version(UNDO_ENVELOPE_VERSION_V1, block_hash, undo)
}

fn marshal_undo_envelope_version(
    version: u32,
    block_hash: [u8; 32],
    undo: &BlockUndo,
) -> Result<Vec<u8>, String> {
    let payload = if version == UNDO_ENVELOPE_VERSION_V1 {
        marshal_block_undo(undo)?
    } else {
        marshal_block_undo_v2(undo)?
    };
    if payload.len() as u64 > UNDO_PAYLOAD_MAX_BYTES {
        return Err(format!(
            "refusing to save undo: payload is {} bytes, class bound {UNDO_PAYLOAD_MAX_BYTES}",
            payload.len()
        ));
    }
    let envelope = UndoEnvelopeDisk {
        version,
        block_hash: hex::encode(block_hash),
        payload_b64: base64_encode(&payload),
        checksum: hex::encode(undo_envelope_checksum_for_version(
            version, block_hash, &payload,
        )),
    };
    let mut raw =
        serde_json::to_vec(&envelope).map_err(|e| format!("encode undo envelope: {e}"))?;
    raw.push(b'\n');
    if raw.len() as u64 > UNDO_FILE_MAX_BYTES {
        return Err(format!(
            "refusing to save undo: envelope is {} bytes, class bound {UNDO_FILE_MAX_BYTES}",
            raw.len()
        ));
    }
    Ok(raw)
}

/// Runs the validation order: bound, canonical layout (which subsumes shape,
/// version-literal, duplicate, unknown, missing, null, ordering, whitespace and
/// trailing-token rejection), hash equality against the hash the CALLER asked
/// for, canonical base64, decoded payload bound, checksum — and only then the
/// payload decode and `BlockUndo` conversion.
///
/// MEMORY: everything before the checksum decision allocates exactly ONE
/// payload-sized buffer — the base64 output, which is unavoidable because the
/// checksum covers those bytes. Nothing copies or re-encodes the base64 body,
/// the hash is streamed rather than fed a concatenated preimage, and the hex
/// fields borrow from `raw`. Peak resident before the decision is the caller's
/// buffer plus at most 3/4 of it, ~1.75x the file; the Go twin measures 0.750x
/// in 7 allocations on an 11.9 MB envelope and this path is structurally
/// identical. The payload decode past the checksum is far more expensive and
/// runs only once the bytes are proven intact.
pub fn unmarshal_undo_envelope(block_hash: [u8; 32], raw: &[u8]) -> Result<BlockUndo, String> {
    if raw.len() as u64 > UNDO_FILE_MAX_BYTES {
        return Err(format!(
            "{UNDO_INTEGRITY_PREFIX}: undo record is {} bytes, class bound {UNDO_FILE_MAX_BYTES}",
            raw.len()
        ));
    }
    let (version, hash_hex, payload_b64, checksum_hex) = split_undo_envelope_versioned(raw)?;
    if hash_hex != hex::encode(block_hash).as_bytes() {
        return Err(UNDO_BLOCK_HASH_MISMATCH_ERR.to_string());
    }
    let payload = base64_decode_canonical(payload_b64)?;
    if payload.len() as u64 > UNDO_PAYLOAD_MAX_BYTES {
        return Err(format!(
            "{UNDO_INTEGRITY_PREFIX}: decoded payload is {} bytes, class bound {UNDO_PAYLOAD_MAX_BYTES}",
            payload.len()
        ));
    }
    // `split_undo_envelope` already proved this is 64 lowercase hex characters.
    let stored = parse_hex32(
        "undo envelope checksum",
        &String::from_utf8_lossy(checksum_hex),
    )
    .map_err(|_| format!("{UNDO_INTEGRITY_PREFIX}: checksum is not hexadecimal"))?;
    if !constant_time_eq32(
        &stored,
        &undo_envelope_checksum_for_version(version, block_hash, &payload),
    ) {
        return Err(UNDO_CHECKSUM_MISMATCH_ERR.to_string());
    }
    if version == UNDO_ENVELOPE_VERSION_V1 {
        unmarshal_block_undo(&payload)
    } else {
        unmarshal_block_undo_v2(&payload)
    }
}

/// Validates the canonical layout and returns sub-slices of `raw`. The body
/// length is DERIVED (`raw.len() - frame`) rather than searched for, so the whole
/// check is a handful of fixed-length comparisons: any inserted, removed,
/// reordered, duplicated or renamed field shifts the trailing segments and
/// fails. On failure it hands off to `classify_undo_envelope_failure` for the
/// operator-facing reason, which is the only path that parses JSON at all.
#[allow(clippy::type_complexity)] // three borrowed slices of one input, not a nested structure.
#[cfg(test)]
fn split_undo_envelope(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8]), String> {
    let (_, hash_hex, payload_b64, checksum_hex) = split_undo_envelope_versioned(raw)?;
    Ok((hash_hex, payload_b64, checksum_hex))
}

#[allow(clippy::type_complexity)]
fn split_undo_envelope_versioned(raw: &[u8]) -> Result<(u32, &[u8], &[u8], &[u8]), String> {
    let Some(body) = raw.len().checked_sub(UNDO_ENVELOPE_FRAME_BYTES) else {
        return Err(classify_undo_envelope_failure(raw));
    };
    let (version, prefix) = if raw.starts_with(UNDO_ENVELOPE_PREFIX_V1) {
        (UNDO_ENVELOPE_VERSION_V1, UNDO_ENVELOPE_PREFIX_V1)
    } else if raw.starts_with(UNDO_ENVELOPE_PREFIX_V2) {
        (UNDO_ENVELOPE_VERSION, UNDO_ENVELOPE_PREFIX_V2)
    } else {
        return Err(classify_undo_envelope_failure(raw));
    };
    let hash_at = prefix.len();
    let payload_sep_at = hash_at + UNDO_HASH_HEX_LEN;
    let payload_at = payload_sep_at + UNDO_ENVELOPE_PAYLOAD_SEP.len();
    let checksum_sep_at = payload_at + body;
    let checksum_at = checksum_sep_at + UNDO_ENVELOPE_CHECKSUM_SEP.len();
    let suffix_at = checksum_at + UNDO_HASH_HEX_LEN;
    if &raw[..hash_at] != prefix
        || &raw[payload_sep_at..payload_at] != UNDO_ENVELOPE_PAYLOAD_SEP
        || &raw[checksum_sep_at..checksum_at] != UNDO_ENVELOPE_CHECKSUM_SEP
        || &raw[suffix_at..] != UNDO_ENVELOPE_SUFFIX
    {
        return Err(classify_undo_envelope_failure(raw));
    }
    let hash_hex = &raw[hash_at..payload_sep_at];
    let checksum_hex = &raw[checksum_at..suffix_at];
    if !valid_canonical_hash_hex(&String::from_utf8_lossy(hash_hex))
        || !valid_canonical_hash_hex(&String::from_utf8_lossy(checksum_hex))
    {
        return Err(format!(
            "{UNDO_INTEGRITY_PREFIX}: block_hash and checksum must be 64 lowercase hex characters"
        ));
    }
    Ok((
        version,
        hash_hex,
        &raw[payload_at..checksum_sep_at],
        checksum_hex,
    ))
}

/// Names WHY a record that failed the layout check failed it. It runs only on
/// records already being rejected, so its JSON scan is never paid on the accept
/// path. It deserializes ONE value and does NOT require EOF, so an unversioned
/// record with trailing garbage still reports the actionable legacy message
/// instead of a generic one. The Go twin classifies identically.
fn classify_undo_envelope_failure(raw: &[u8]) -> String {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let Ok(probe) = UndoVersionProbe::deserialize(&mut deserializer) else {
        return format!("{UNDO_INTEGRITY_PREFIX}: undo record is not a single JSON object");
    };
    match probe.version {
        None => UNDO_LEGACY_ERR.to_string(),
        Some(version)
            if version == UNDO_ENVELOPE_VERSION_V1 || version == UNDO_ENVELOPE_VERSION =>
        {
            format!("{UNDO_INTEGRITY_PREFIX}: envelope is not the canonical encoding")
        }
        Some(other) => {
            format!("{UNDO_INTEGRITY_PREFIX}: unsupported undo envelope version {other}")
        }
    }
}

/// Data-independent comparison of the stored and computed digests. No `subtle`
/// crate is available and this contract forbids adding one, so the fold is
/// written out; both inputs are fixed-size arrays, so no length term leaks.
fn constant_time_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Canonical padded RFC 4648 base64. Hand-written because `base64` is not a
/// dependency of this crate and this contract forbids adding one; the Go twin
/// uses `encoding/base64`.
pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    for chunk in input.chunks(3) {
        // `chunks(3)` never yields an empty slice, so index 0 is present; the
        // other two are optional and pad to zero.
        let packed = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for (position, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if position > chunk.len() {
                out.push('=');
                continue;
            }
            let symbol_index = ((packed >> shift) & 0x3f) as usize;
            // 6 bits index a 64-entry table, so this cannot be out of range.
            out.push(char::from(BASE64_ALPHABET[symbol_index]));
        }
    }
    out
}

fn base64_symbol_value(symbol: u8) -> Option<u32> {
    let value = match symbol {
        b'A'..=b'Z' => u32::from(symbol - b'A'),
        b'a'..=b'z' => u32::from(symbol - b'a') + 26,
        b'0'..=b'9' => u32::from(symbol - b'0') + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(value)
}

/// Accepts only the one padded RFC 4648 spelling of the payload. Canonicality is
/// enforced without re-encoding, which matters because the body can be ~1.5 GB:
/// non-alphabet bytes are rejected symbol by symbol (so JSON-escaped whitespace
/// a permissive decoder would skip cannot slip through), and the bits the
/// padding discards must be zero (so "Zh==" cannot stand in for "Zg=="). Go twin
/// `decodeCanonicalBase64` gets the same two properties from
/// `StdEncoding.Strict()` plus an `EncodedLen` equality.
fn base64_decode_canonical(value: &[u8]) -> Result<Vec<u8>, String> {
    let not_canonical =
        || format!("{UNDO_INTEGRITY_PREFIX}: payload_b64 is not canonical padded base64");
    if !value.len().is_multiple_of(4) {
        return Err(not_canonical());
    }
    let quads = value.len() / 4;
    let mut out = Vec::with_capacity(quads.saturating_mul(3));
    for (index, quad) in value.chunks_exact(4).enumerate() {
        // Padding is legal only in the final quad; anywhere else `=` is not an
        // alphabet symbol and fails below.
        let pad = if index + 1 != quads {
            0
        } else if quad[3] == b'=' {
            if quad[2] == b'=' {
                2
            } else {
                1
            }
        } else {
            0
        };
        let mut packed = 0u32;
        for symbol in &quad[..4 - pad] {
            packed = (packed << 6) | base64_symbol_value(*symbol).ok_or_else(not_canonical)?;
        }
        // The final quad carries 6*(4-pad) bits but only 8*(3-pad) are data; the
        // 2*pad low bits are padding and a canonical encoder leaves them zero.
        if packed & ((1u32 << (2 * pad)) - 1) != 0 {
            return Err(not_canonical());
        }
        packed <<= 6 * pad;
        out.push((packed >> 16) as u8);
        if pad < 2 {
            out.push((packed >> 8) as u8);
        }
        if pad < 1 {
            out.push(packed as u8);
        }
    }
    Ok(out)
}

/// Flips one interior base64 symbol of a stored undo record: the file stays
/// well-formed JSON and canonical base64, the payload still decodes, and only
/// the checksum comparison can catch it. Returns (corrupted, original) so a
/// caller can prove a refusal did not rewrite the record AND restore it to
/// prove the same path accepts a valid versioned record. Go twin:
/// `corruptStoredUndoChecksum`.
#[cfg(test)]
pub(crate) fn corrupt_stored_undo_checksum(
    undo_dir: &std::path::Path,
    block_hash: [u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let path = undo_dir.join(format!("{}.json", hex::encode(block_hash)));
    let original = std::fs::read(&path).expect("read stored undo");
    let envelope: UndoEnvelopeDisk =
        serde_json::from_slice(&original).expect("stored undo is not a versioned envelope");
    let flipped = flip_base64_symbol(&envelope.payload_b64);
    let corrupted = String::from_utf8(original.clone())
        .expect("undo record is utf-8")
        .replacen(&envelope.payload_b64, &flipped, 1)
        .into_bytes();
    assert_ne!(corrupted, original, "undo corruption was a no-op");
    std::fs::write(&path, &corrupted).expect("write corrupted undo");
    (corrupted, original)
}

/// Changes one interior symbol to a different valid one, so the result is still
/// canonical base64 of the same length and fails at the checksum rather than at
/// the encoding check. Go twin: `flipBase64Symbol`.
#[cfg(test)]
pub(crate) fn flip_base64_symbol(value: &str) -> String {
    let replacement = if value.as_bytes()[1] == b'A' {
        'B'
    } else {
        'A'
    };
    format!("{}{replacement}{}", &value[..1], &value[2..])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::blockstore::BlockStore;
    use crate::io_utils::unique_temp_path;

    /// Rust half of the cross-client parity proof: every byte the Go client must
    /// emit for the same input is pinned in
    /// conformance/fixtures/protocol/undo_integrity_v1.json, and this test
    /// recomputes all of them from the payload alone. Go half:
    /// `TestUndoEnvelopeV1CrossClientVector`.
    #[test]
    fn undo_envelope_v1_cross_client_vector() {
        #[derive(Deserialize)]
        struct Vector {
            id: String,
            block_hash: String,
            payload_json: String,
            payload_b64: String,
            checksum: String,
            envelope: String,
        }
        #[derive(Deserialize)]
        struct Fixture {
            cases: Vec<Vector>,
        }
        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../conformance/fixtures/protocol/undo_integrity_v1.json"
        ))
        .expect("read shared undo fixture");
        let fixture: Fixture = serde_json::from_slice(&raw).expect("decode shared undo fixture");
        // An emptied or renamed fixture must fail loudly rather than let the
        // per-case loop below pass vacuously.
        assert!(
            fixture.cases.len() >= 3,
            "shared undo fixture has {} cases, want at least 3",
            fixture.cases.len()
        );

        for case in &fixture.cases {
            let block_hash = parse_hex32("vector block_hash", &case.block_hash).expect("hash");
            let undo = unmarshal_block_undo(case.payload_json.as_bytes())
                .unwrap_or_else(|e| panic!("{}: payload_json not canonical: {e}", case.id));

            let payload = marshal_block_undo(&undo).expect("marshal payload");
            assert_eq!(
                String::from_utf8(payload.clone()).expect("payload is utf-8"),
                case.payload_json,
                "{}: canonical payload",
                case.id
            );
            assert_eq!(
                base64_encode(&payload),
                case.payload_b64,
                "{}: base64",
                case.id
            );
            assert_eq!(
                hex::encode(undo_envelope_checksum(block_hash, &payload)),
                case.checksum,
                "{}: checksum",
                case.id
            );

            let envelope =
                marshal_undo_envelope_v1(block_hash, &undo).expect("marshal v1 envelope");
            assert_eq!(
                String::from_utf8(envelope.clone()).expect("envelope is utf-8"),
                case.envelope,
                "{}: envelope bytes",
                case.id
            );
            assert!(
                envelope.ends_with(b"\n") && envelope.iter().filter(|b| **b == b'\n').count() == 1,
                "{}: envelope must carry exactly one trailing LF",
                case.id
            );
            assert_eq!(
                unmarshal_undo_envelope(block_hash, case.envelope.as_bytes()).expect("round trip"),
                undo,
                "{}: round trip",
                case.id
            );

            let parent = unique_temp_path("rubin-undo-v1-vector");
            std::fs::create_dir_all(&parent).expect("create v1 vector parent");
            let root = parent.join("blockstore");
            let store = BlockStore::create(&root).expect("create v1 vector blockstore");
            let undo_path = root.join("undo").join(format!("{}.json", case.block_hash));
            std::fs::write(&undo_path, case.envelope.as_bytes()).expect("seed v1 undo envelope");
            assert_eq!(
                store.get_undo(block_hash).expect("read seeded v1 undo"),
                undo,
                "{}: public BlockStore v1 read",
                case.id
            );
            drop(store);
            std::fs::remove_dir_all(&parent).expect("cleanup v1 vector blockstore");
        }
    }

    /// Rust half of the v2 cross-client parity proof. In addition to pinning the
    /// production codec and checksum bytes, every row passes through the public
    /// BlockStore reader and the default absent-path writer.
    #[test]
    fn undo_envelope_v2_cross_client_vector() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Vector {
            id: String,
            note: String,
            block_hash: String,
            payload_json: String,
            payload_b64: String,
            checksum: String,
            envelope: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fixture {
            contract_version: u32,
            fixture_kind: String,
            description: String,
            checksum_domain_ascii: String,
            envelope_version: u32,
            cases: Vec<Vector>,
        }

        let raw = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../../conformance/fixtures/protocol/undo_integrity_v2.json"
        ))
        .expect("read shared v2 undo fixture");
        let fixture: Fixture = serde_json::from_slice(&raw).expect("decode shared v2 undo fixture");
        assert_eq!(fixture.contract_version, 1, "fixture contract_version");
        assert_eq!(fixture.fixture_kind, "undo_integrity_v2", "fixture kind");
        assert_eq!(
            fixture.checksum_domain_ascii, "RUBIN_BLOCK_UNDO_V2",
            "fixture checksum domain"
        );
        assert_eq!(
            fixture.envelope_version, UNDO_ENVELOPE_VERSION,
            "fixture envelope version"
        );
        assert!(
            !fixture.description.is_empty(),
            "fixture description is empty"
        );
        assert_eq!(fixture.cases.len(), 4, "fixture must contain four cases");

        let mut covenant_data = vec![0x00];
        covenant_data.extend_from_slice(&[0x22; 32]);
        let expected_undos = [
            BlockUndo {
                block_height: 0,
                previous_already_generated: 0,
                txs: Vec::new(),
            },
            BlockUndo {
                block_height: 1,
                previous_already_generated: u128::from(u64::MAX),
                txs: vec![TxUndo { spent: Vec::new() }],
            },
            BlockUndo {
                block_height: 2,
                previous_already_generated: u128::from(u64::MAX) + 1,
                txs: vec![TxUndo { spent: Vec::new() }],
            },
            BlockUndo {
                block_height: 3,
                previous_already_generated: u128::MAX,
                txs: vec![
                    TxUndo { spent: Vec::new() },
                    TxUndo {
                        spent: vec![SpentUndo {
                            outpoint: Outpoint {
                                txid: [0x11; 32],
                                vout: 0,
                            },
                            entry: UtxoEntry {
                                value: 4_999_999_000,
                                covenant_type: 1,
                                covenant_data,
                                creation_height: 1,
                                created_by_coinbase: true,
                            },
                        }],
                    },
                ],
            },
        ];
        let expected_ids = [
            "empty-undo-zero-supply",
            "u64-max-supply",
            "above-u64-supply",
            "multi-tx-one-spend",
        ];
        let mut ids = HashSet::new();
        let mut block_hashes = HashSet::new();

        for (index, case) in fixture.cases.iter().enumerate() {
            assert_eq!(case.id, expected_ids[index], "case {index} id");
            assert!(
                ids.insert(case.id.as_str()),
                "duplicate case id: {}",
                case.id
            );
            assert!(!case.note.is_empty(), "{}: empty note", case.id);
            assert!(!case.payload_json.is_empty(), "{}: empty payload", case.id);
            assert!(!case.payload_b64.is_empty(), "{}: empty base64", case.id);
            assert!(!case.checksum.is_empty(), "{}: empty checksum", case.id);
            assert!(!case.envelope.is_empty(), "{}: empty envelope", case.id);

            let block_hash = parse_hex32("vector block_hash", &case.block_hash).expect("hash");
            assert!(
                block_hashes.insert(block_hash),
                "duplicate block hash: {}",
                case.block_hash
            );
            let undo = unmarshal_block_undo_v2(case.payload_json.as_bytes())
                .unwrap_or_else(|e| panic!("{}: payload_json not canonical: {e}", case.id));
            assert_eq!(undo, expected_undos[index], "{}: decoded undo", case.id);

            let payload = marshal_block_undo_v2(&undo).expect("marshal v2 payload");
            assert_eq!(
                payload,
                case.payload_json.as_bytes(),
                "{}: canonical payload",
                case.id
            );
            assert_eq!(
                base64_encode(&payload),
                case.payload_b64,
                "{}: canonical padded base64",
                case.id
            );
            assert_eq!(
                hex::encode(undo_envelope_checksum_for_version(
                    UNDO_ENVELOPE_VERSION,
                    block_hash,
                    &payload,
                )),
                case.checksum,
                "{}: v2 checksum",
                case.id
            );

            let envelope = marshal_undo_envelope(block_hash, &undo).expect("marshal v2 envelope");
            assert_eq!(
                envelope,
                case.envelope.as_bytes(),
                "{}: envelope bytes",
                case.id
            );
            assert!(
                envelope.ends_with(b"\n") && envelope.iter().filter(|b| **b == b'\n').count() == 1,
                "{}: envelope must carry exactly one trailing LF",
                case.id
            );
            assert_eq!(
                unmarshal_undo_envelope(block_hash, &envelope).expect("round trip v2 envelope"),
                undo,
                "{}: envelope round trip",
                case.id
            );

            let read_parent = unique_temp_path("rubin-undo-v2-vector-read");
            std::fs::create_dir_all(&read_parent).expect("create v2 read parent");
            let read_root = read_parent.join("blockstore");
            let read_store = BlockStore::create(&read_root).expect("create v2 reader blockstore");
            let read_path = read_root
                .join("undo")
                .join(format!("{}.json", case.block_hash));
            std::fs::write(&read_path, case.envelope.as_bytes()).expect("seed v2 undo envelope");
            assert_eq!(
                read_store
                    .get_undo(block_hash)
                    .expect("read seeded v2 undo"),
                undo,
                "{}: public BlockStore v2 read",
                case.id
            );
            drop(read_store);
            std::fs::remove_dir_all(&read_parent).expect("cleanup v2 reader blockstore");

            let write_parent = unique_temp_path("rubin-undo-v2-vector-write");
            std::fs::create_dir_all(&write_parent).expect("create v2 write parent");
            let write_root = write_parent.join("blockstore");
            let write_store = BlockStore::create(&write_root).expect("create v2 writer blockstore");
            write_store
                .put_undo(block_hash, &undo)
                .expect("write absent v2 undo");
            let write_path = write_root
                .join("undo")
                .join(format!("{}.json", case.block_hash));
            assert_eq!(
                std::fs::read(&write_path).expect("read written v2 undo envelope"),
                case.envelope.as_bytes(),
                "{}: public BlockStore v2 write bytes",
                case.id
            );
            assert_eq!(
                write_store
                    .get_undo(block_hash)
                    .expect("read written v2 undo"),
                undo,
                "{}: public BlockStore v2 write/read",
                case.id
            );
            drop(write_store);
            std::fs::remove_dir_all(&write_parent).expect("cleanup v2 writer blockstore");
        }
    }

    fn envelope_over(version: u32, block_hash: [u8; 32], payload: &[u8]) -> Vec<u8> {
        let envelope = UndoEnvelopeDisk {
            version,
            block_hash: hex::encode(block_hash),
            payload_b64: base64_encode(payload),
            checksum: hex::encode(undo_envelope_checksum_for_version(
                version, block_hash, payload,
            )),
        };
        let mut raw = serde_json::to_vec(&envelope).expect("encode test envelope");
        raw.push(b'\n');
        raw
    }

    #[test]
    fn undo_envelope_v2_round_trip_and_checksum_domain() {
        let block_hash = [0x91; 32];
        let undo = BlockUndo {
            block_height: 11,
            previous_already_generated: u128::MAX,
            txs: Vec::new(),
        };
        let raw = marshal_undo_envelope(block_hash, &undo).expect("marshal v2");
        let (version, _, payload_b64, checksum_hex) =
            split_undo_envelope_versioned(&raw).expect("split v2");
        assert_eq!(version, UNDO_ENVELOPE_VERSION);
        assert!(raw.starts_with(UNDO_ENVELOPE_PREFIX_V2));
        let payload = base64_decode_canonical(payload_b64).expect("decode payload");
        let expected_payload = br#"{"block_height":11,"previous_already_generated":"340282366920938463463374607431768211455","txs":[]}"#;
        assert_eq!(payload, expected_payload);
        let mut hasher = Sha3_256::new();
        hasher.update(b"RUBIN_BLOCK_UNDO_V2");
        hasher.update(block_hash);
        hasher.update((expected_payload.len() as u64).to_be_bytes());
        hasher.update(expected_payload);
        let expected_checksum: [u8; 32] = hasher.finalize().into();
        let expected_envelope = format!(
            "{{\"version\":2,\"block_hash\":\"{}\",\"payload_b64\":\"{}\",\"checksum\":\"{}\"}}\n",
            hex::encode(block_hash),
            base64_encode(expected_payload),
            hex::encode(expected_checksum)
        );
        assert_eq!(raw, expected_envelope.as_bytes());
        let v1_checksum = undo_envelope_checksum(block_hash, &payload);
        let v2_checksum = undo_envelope_checksum_for_version(version, block_hash, &payload);
        assert_ne!(v1_checksum, v2_checksum);
        assert_eq!(
            hex::encode(v2_checksum),
            String::from_utf8_lossy(checksum_hex)
        );
        assert_eq!(
            unmarshal_undo_envelope(block_hash, &raw).expect("read v2"),
            undo
        );
    }

    #[test]
    fn undo_envelope_supply_types_and_boundaries() {
        let block_hash = [0x92; 32];
        let cases = [
            (
                "v1_u64_max",
                1,
                r#"{"block_height":0,"previous_already_generated":18446744073709551615,"txs":[]}"#,
                None,
                u128::from(u64::MAX),
            ),
            (
                "v1_string",
                1,
                r#"{"block_height":0,"previous_already_generated":"0","txs":[]}"#,
                Some(UNDO_INVALID_V1_SUPPLY),
                0,
            ),
            (
                "v1_negative",
                1,
                r#"{"block_height":0,"previous_already_generated":-1,"txs":[]}"#,
                Some(UNDO_INVALID_V1_SUPPLY),
                0,
            ),
            (
                "v1_fraction",
                1,
                r#"{"block_height":0,"previous_already_generated":0.0,"txs":[]}"#,
                Some(UNDO_INVALID_V1_SUPPLY),
                0,
            ),
            (
                "v1_overflow",
                1,
                r#"{"block_height":0,"previous_already_generated":18446744073709551616,"txs":[]}"#,
                Some(UNDO_INVALID_V1_SUPPLY),
                0,
            ),
            (
                "v1_extreme_exponent",
                1,
                r#"{"block_height":0,"previous_already_generated":1e400,"txs":[]}"#,
                Some(UNDO_INVALID_V1_SUPPLY),
                0,
            ),
            (
                "v2_u128_max",
                2,
                r#"{"block_height":0,"previous_already_generated":"340282366920938463463374607431768211455","txs":[]}"#,
                None,
                u128::MAX,
            ),
            (
                "v2_number",
                2,
                r#"{"block_height":0,"previous_already_generated":0,"txs":[]}"#,
                Some(UNDO_INVALID_V2_SUPPLY),
                0,
            ),
            (
                "v2_extreme_number",
                2,
                r#"{"block_height":0,"previous_already_generated":1e400,"txs":[]}"#,
                Some(UNDO_INVALID_V2_SUPPLY),
                0,
            ),
            (
                "v2_extreme_block_height",
                2,
                r#"{"block_height":1e400,"previous_already_generated":0,"txs":[]}"#,
                Some(UNDO_INVALID_V2_SUPPLY),
                0,
            ),
            (
                "v2_null",
                2,
                r#"{"block_height":0,"previous_already_generated":null,"txs":[]}"#,
                Some(UNDO_INVALID_V2_SUPPLY),
                0,
            ),
            (
                "v2_missing",
                2,
                r#"{"block_height":0,"txs":[]}"#,
                Some(UNDO_PAYLOAD_NOT_CANONICAL),
                0,
            ),
            (
                "v2_leading_zero",
                2,
                r#"{"block_height":0,"previous_already_generated":"00","txs":[]}"#,
                Some(UNDO_INVALID_V2_SUPPLY),
                0,
            ),
            (
                "v2_escaped_zero",
                2,
                r#"{"block_height":0,"previous_already_generated":"\u0030","txs":[]}"#,
                Some(UNDO_INVALID_V2_SUPPLY),
                0,
            ),
            (
                "v2_overflow",
                2,
                r#"{"block_height":0,"previous_already_generated":"340282366920938463463374607431768211456","txs":[]}"#,
                Some(UNDO_INVALID_V2_SUPPLY),
                0,
            ),
        ];

        for (name, version, payload, want_error, want_supply) in cases {
            let raw = envelope_over(version, block_hash, payload.as_bytes());
            match want_error {
                Some(want) => assert_eq!(
                    unmarshal_undo_envelope(block_hash, &raw).unwrap_err(),
                    want,
                    "{name}"
                ),
                None => assert_eq!(
                    unmarshal_undo_envelope(block_hash, &raw)
                        .unwrap_or_else(|error| panic!("{name}: {error}"))
                        .previous_already_generated,
                    want_supply,
                    "{name}"
                ),
            }
        }

        for (name, payload) in [
            (
                "v2_duplicate_supply",
                r#"{"block_height":0,"previous_already_generated":"0","previous_already_generated":"0","txs":[]}"#,
            ),
            (
                "v2_trailing_json_content",
                r#"{"block_height":0,"previous_already_generated":"0","txs":[]}{}"#,
            ),
        ] {
            let raw = envelope_over(2, block_hash, payload.as_bytes());
            let error = unmarshal_undo_envelope(block_hash, &raw).unwrap_err();
            assert_eq!(error, UNDO_PAYLOAD_NOT_CANONICAL, "{name}");
            assert!(
                !error.starts_with(UNDO_INTEGRITY_PREFIX),
                "{name}: checksum-valid payload gained UNDO_INTEGRITY: {error}"
            );
        }
    }

    #[test]
    fn undo_checksum_and_hash_precede_payload_schema() {
        let requested_hash = [0xa3; 32];
        let stored_hash = [0xa4; 32];
        let payload = br#"{"block_height":0,"previous_already_generated":0,"txs":[]}"#;
        let mut wrong_hash = envelope_over(2, stored_hash, payload);
        let payload_at =
            UNDO_ENVELOPE_PREFIX_V2.len() + UNDO_HASH_HEX_LEN + UNDO_ENVELOPE_PAYLOAD_SEP.len();
        wrong_hash[payload_at] = b'*';
        assert_eq!(
            unmarshal_undo_envelope(requested_hash, &wrong_hash).unwrap_err(),
            UNDO_BLOCK_HASH_MISMATCH_ERR
        );

        let mut wrong_checksum = envelope_over(2, requested_hash, payload);
        let checksum_at = wrong_checksum.len() - UNDO_ENVELOPE_SUFFIX.len() - UNDO_HASH_HEX_LEN;
        wrong_checksum[checksum_at] = if wrong_checksum[checksum_at] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert_eq!(
            unmarshal_undo_envelope(requested_hash, &wrong_checksum).unwrap_err(),
            UNDO_CHECKSUM_MISMATCH_ERR
        );
    }

    #[test]
    fn disconnect_summary_restores_full_u128_supply_boundaries() {
        let genesis = crate::genesis::devnet_genesis_block_bytes();
        for supply in [0, u128::from(u64::MAX), u128::from(u64::MAX) + 1, u128::MAX] {
            let mut state = ChainState::new();
            state
                .connect_block(
                    &genesis,
                    Some(rubin_consensus::constants::POW_LIMIT),
                    None,
                    crate::genesis::devnet_genesis_chain_id(),
                )
                .expect("connect genesis");
            let undo = BlockUndo {
                block_height: 0,
                previous_already_generated: supply,
                txs: vec![TxUndo { spent: Vec::new() }],
            };
            let summary = state.disconnect_block(&genesis, &undo).expect("disconnect");
            assert_eq!(summary.already_generated, supply);
            assert_eq!(state.already_generated, supply);
        }
    }

    /// Pins the bound arithmetic. The two multi-gigabyte hostile rows ("maximum
    /// legal payload at the bound" and "one decoded byte above it") are
    /// discharged HERE, by exact derivation rather than by materializing ~2 GB
    /// in a unit test. Go twin: `TestUndoEnvelopeBoundDerivation`.
    #[test]
    fn undo_envelope_bound_derivation() {
        let base64_len = |n: u64| n.div_ceil(3) * 4;

        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: Vec::new(),
        };
        let envelope = marshal_undo_envelope([0u8; 32], &undo).expect("marshal");
        let payload = marshal_block_undo_v2(&undo).expect("marshal payload");
        let frame = envelope.len() - base64_encode(&payload).len();
        assert_eq!(frame, UNDO_ENVELOPE_FRAME_BYTES, "measured envelope frame");
        // The writer's bytes must satisfy the segment constants the reader indexes by.
        split_undo_envelope(&envelope).expect("writer output does not satisfy the reader layout");

        // The envelope reuses the UNCHANGED undo class bound. A future edit that
        // raises it past 2^31-2 breaks the reader's max_bytes+1 probe on a
        // 32-bit build, so this row exists to make that edit fail loudly first.
        assert_eq!(UNDO_FILE_MAX_BYTES, 2_000_000_000);
        // A const block, so raising the bound past 2^31-2 is a COMPILE failure
        // rather than a test failure someone can skip.
        const { assert!(UNDO_FILE_MAX_BYTES <= (1u64 << 31) - 2) };
        assert_eq!(
            UNDO_PAYLOAD_MAX_BYTES,
            3 * ((UNDO_FILE_MAX_BYTES - UNDO_ENVELOPE_FRAME_BYTES as u64) / 4)
        );
        assert_eq!(UNDO_PAYLOAD_MAX_BYTES, 1_499_999_856);

        // The floor must precede the multiply. The naive spelling overshoots by
        // two bytes, and those two bytes are exactly the save/read asymmetry
        // this ceiling exists to close — so pin that it would in fact break.
        let naive = (UNDO_FILE_MAX_BYTES - UNDO_ENVELOPE_FRAME_BYTES as u64) * 3 / 4;
        assert!(
            naive > UNDO_PAYLOAD_MAX_BYTES,
            "naive ceiling no longer overshoots"
        );
        assert!(
            base64_len(naive) + UNDO_ENVELOPE_FRAME_BYTES as u64 > UNDO_FILE_MAX_BYTES,
            "naive ceiling {naive} would fit after all; re-derive"
        );

        // The two bound rows, arithmetically: the largest legal payload's
        // complete envelope fits exactly, and one byte more does not.
        let at_bound = base64_len(UNDO_PAYLOAD_MAX_BYTES) + UNDO_ENVELOPE_FRAME_BYTES as u64;
        assert_eq!(at_bound, 1_999_999_997);
        assert!(at_bound <= UNDO_FILE_MAX_BYTES);
        let over_bound = base64_len(UNDO_PAYLOAD_MAX_BYTES + 1) + UNDO_ENVELOPE_FRAME_BYTES as u64;
        assert!(
            over_bound > UNDO_FILE_MAX_BYTES,
            "one byte over the payload ceiling still fits in {over_bound} bytes"
        );
    }

    /// Canonical base64 round-trip over every residue class, plus the
    /// non-canonical spellings the decoder must refuse. Go relies on
    /// `encoding/base64` for this; the hand-written Rust codec needs its own row
    /// or a padding bug would only ever surface as a checksum mismatch.
    #[test]
    fn base64_codec_is_canonical() {
        for len in 0..48usize {
            let input: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let encoded = base64_encode(&input);
            assert_eq!(encoded.len() % 4, 0, "len {len} is not padded to a quad");
            assert_eq!(
                base64_decode_canonical(encoded.as_bytes()).expect("round trip"),
                input,
                "len {len}"
            );
        }
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        for bad in [
            "Zg=",    // not a whole quad
            "Zg",     // unpadded
            "Zh==",   // non-zero padding bits: decodes, re-encodes as Zg==
            "Z\ng==", // embedded newline a permissive decoder would skip
            "Zg*=",   // symbol outside the alphabet
            "Zg=A",   // padding followed by data
        ] {
            assert!(
                base64_decode_canonical(bad.as_bytes()).is_err(),
                "accepted non-canonical base64 {bad:?}"
            );
        }
    }
    use std::collections::HashMap;

    use crate::devnet_genesis_chain_id;
    use crate::test_helpers::block_with_txs;

    use super::*;
    use rubin_consensus::constants::{COV_TYPE_P2PK, POW_LIMIT, TX_WIRE_VERSION};
    use rubin_consensus::{
        marshal_tx, p2pk_covenant_data_for_pubkey, parse_tx, sign_transaction, Mldsa87Keypair, Tx,
        TxInput, TxOutput,
    };

    fn sample_outpoint(seed: u8) -> Outpoint {
        Outpoint {
            txid: [seed; 32],
            vout: seed as u32,
        }
    }

    fn sample_entry(value: u64) -> UtxoEntry {
        UtxoEntry {
            value,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: vec![0xAB; 33],
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn same_block_spend_fixture() -> (ChainState, Outpoint, Vec<u8>, u64) {
        let funding_key = Mldsa87Keypair::generate().expect("funding key");
        let funding_address = p2pk_covenant_data_for_pubkey(&funding_key.pubkey_bytes());
        let middle_key = Mldsa87Keypair::generate().expect("middle key");
        let middle_address = p2pk_covenant_data_for_pubkey(&middle_key.pubkey_bytes());
        let final_key = Mldsa87Keypair::generate().expect("final key");
        let final_address = p2pk_covenant_data_for_pubkey(&final_key.pubkey_bytes());

        let source_outpoint = Outpoint {
            txid: [0x11; 32],
            vout: 0,
        };
        let mut prev_state = ChainState {
            has_tip: true,
            height: 42,
            tip_hash: [0x22; 32],
            already_generated: 7,
            utxos: HashMap::new(),
        };
        prev_state.utxos.insert(
            source_outpoint.clone(),
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: funding_address,
                creation_height: 1,
                created_by_coinbase: false,
            },
        );

        let mut parent = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: source_outpoint.txid,
                prev_vout: source_outpoint.vout,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: middle_address.clone(),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(
            &mut parent,
            &prev_state.utxos,
            devnet_genesis_chain_id(),
            &funding_key,
        )
        .expect("sign parent");
        let parent_bytes = marshal_tx(&parent).expect("marshal parent");
        let (_parent_tx, parent_txid, _parent_wtxid, parent_consumed) =
            parse_tx(&parent_bytes).expect("parse parent");
        assert_eq!(parent_consumed, parent_bytes.len());

        let mut middle_view = prev_state.utxos.clone();
        middle_view.remove(&source_outpoint);
        middle_view.insert(
            Outpoint {
                txid: parent_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: middle_address,
                creation_height: prev_state.height + 1,
                created_by_coinbase: false,
            },
        );

        let mut child = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 2,
            inputs: vec![TxInput {
                prev_txid: parent_txid,
                prev_vout: 0,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 80,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: final_address,
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(
            &mut child,
            &middle_view,
            devnet_genesis_chain_id(),
            &middle_key,
        )
        .expect("sign child");
        let child_bytes = marshal_tx(&child).expect("marshal child");

        let block_height = prev_state.height + 1;
        let block_bytes = block_with_txs(
            block_height,
            prev_state.already_generated,
            prev_state.tip_hash,
            1_777_000_123,
            &[parent_bytes, child_bytes],
        );

        (prev_state, source_outpoint, block_bytes, block_height)
    }

    fn duplicate_prev_state_spend_fixture() -> (ChainState, Vec<u8>, u64) {
        let funding_key = Mldsa87Keypair::generate().expect("funding key");
        let funding_address = p2pk_covenant_data_for_pubkey(&funding_key.pubkey_bytes());
        let recv_key = Mldsa87Keypair::generate().expect("recv key");
        let recv_address = p2pk_covenant_data_for_pubkey(&recv_key.pubkey_bytes());
        let source_outpoint = Outpoint {
            txid: [0x33; 32],
            vout: 0,
        };
        let mut prev_state = ChainState {
            has_tip: true,
            height: 7,
            tip_hash: [0x44; 32],
            already_generated: 3,
            utxos: HashMap::new(),
        };
        prev_state.utxos.insert(
            source_outpoint.clone(),
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: funding_address.clone(),
                creation_height: 1,
                created_by_coinbase: false,
            },
        );

        let mut tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![
                TxInput {
                    prev_txid: source_outpoint.txid,
                    prev_vout: source_outpoint.vout,
                    script_sig: Vec::new(),
                    sequence: 0,
                },
                TxInput {
                    prev_txid: source_outpoint.txid,
                    prev_vout: source_outpoint.vout,
                    script_sig: Vec::new(),
                    sequence: 0,
                },
            ],
            outputs: vec![TxOutput {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: recv_address,
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(
            &mut tx,
            &prev_state.utxos,
            devnet_genesis_chain_id(),
            &funding_key,
        )
        .expect("sign tx");
        let tx_bytes = marshal_tx(&tx).expect("marshal tx");
        let block_height = prev_state.height + 1;
        let block_bytes = block_with_txs(
            block_height,
            prev_state.already_generated,
            prev_state.tip_hash,
            1_777_000_456,
            &[tx_bytes],
        );
        (prev_state, block_bytes, block_height)
    }

    #[test]
    fn test_undo_roundtrip_serialization() {
        let undo = BlockUndo {
            block_height: 42,
            previous_already_generated: 1000,
            txs: vec![
                TxUndo { spent: vec![] }, // coinbase — no spent
                TxUndo {
                    spent: vec![SpentUndo {
                        outpoint: sample_outpoint(0x01),
                        entry: sample_entry(500),
                    }],
                },
                TxUndo {
                    spent: vec![
                        SpentUndo {
                            outpoint: sample_outpoint(0x02),
                            entry: sample_entry(200),
                        },
                        SpentUndo {
                            outpoint: sample_outpoint(0x03),
                            entry: sample_entry(300),
                        },
                    ],
                },
            ],
        };

        let raw = marshal_block_undo(&undo).expect("marshal");
        let decoded = unmarshal_block_undo(&raw).expect("unmarshal");
        assert_eq!(undo, decoded);
    }

    #[test]
    fn test_undo_empty_block() {
        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };
        let raw = marshal_block_undo(&undo).expect("marshal");
        let decoded = unmarshal_block_undo(&raw).expect("unmarshal");
        assert_eq!(undo, decoded);
    }

    #[test]
    fn test_is_spendable_output() {
        assert!(is_spendable_output(0x0001)); // P2PK
        assert!(is_spendable_output(0x0100)); // HTLC
        assert!(!is_spendable_output(COV_TYPE_ANCHOR));
        assert!(!is_spendable_output(COV_TYPE_DA_COMMIT));
    }

    #[test]
    fn test_disconnect_height_mismatch() {
        let mut cs = ChainState {
            has_tip: true,
            height: 5,
            tip_hash: [0xAA; 32],
            already_generated: 100,
            utxos: HashMap::new(),
        };
        let undo = BlockUndo {
            block_height: 3, // mismatched
            previous_already_generated: 50,
            txs: vec![],
        };
        let err = cs.disconnect_block(&[], &undo).expect_err("should fail");
        assert!(err.contains("disconnect height mismatch"));
    }

    #[test]
    fn test_disconnect_no_tip() {
        let mut cs = ChainState::new();
        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![],
        };
        let err = cs.disconnect_block(&[], &undo).expect_err("should fail");
        assert!(err.contains("has no tip"));
    }

    #[test]
    fn test_unmarshal_invalid_json() {
        let err = unmarshal_block_undo(b"not json").expect_err("should fail");
        assert!(err.contains("decode undo"));
    }

    #[test]
    fn test_unmarshal_invalid_hex_txid() {
        let json = r#"{
            "block_height": 1,
            "previous_already_generated": 0,
            "txs": [{"spent": [{"txid": "ZZZZ", "vout": 0, "value": 0, "covenant_type": 1, "covenant_data": "", "creation_height": 0, "created_by_coinbase": false}]}]
        }"#;
        let err = unmarshal_block_undo(json.as_bytes()).expect_err("should fail");
        assert!(err.contains("txid"));
    }

    #[test]
    fn build_block_undo_ignores_same_block_spends() {
        let (prev_state, source_outpoint, block_bytes, block_height) = same_block_spend_fixture();

        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");

        assert_eq!(undo.txs.len(), 3, "coinbase + parent + child");
        assert!(undo.txs[0].spent.is_empty(), "coinbase has no undo inputs");
        assert_eq!(
            undo.txs[1].spent.len(),
            1,
            "parent spends previous-state utxo"
        );
        assert_eq!(undo.txs[1].spent[0].outpoint, source_outpoint);
        assert!(
            undo.txs[2].spent.is_empty(),
            "child spends same-block output and must not require prev-state undo"
        );
    }

    #[test]
    fn build_block_undo_errors_on_missing_prev_state_utxo() {
        let (mut prev_state, source_outpoint, block_bytes, block_height) =
            same_block_spend_fixture();
        prev_state.utxos.remove(&source_outpoint);

        let err =
            build_block_undo(&prev_state, &block_bytes, block_height).expect_err("missing utxo");
        assert!(err.contains("undo missing utxo"));
    }

    #[test]
    fn build_block_undo_errors_on_duplicate_prev_state_spend() {
        let (prev_state, block_bytes, block_height) = duplicate_prev_state_spend_fixture();

        let err =
            build_block_undo(&prev_state, &block_bytes, block_height).expect_err("duplicate spend");
        assert!(err.contains("undo duplicate prev-state spend"));
    }

    #[test]
    fn disconnect_block_restores_prev_state_after_same_block_spend() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");

        let summary = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect("disconnect block");

        assert_eq!(connected_state, prev_state);
        assert_eq!(summary.new_height, prev_state.height);
        assert_eq!(summary.new_tip_hash, prev_state.tip_hash);
        assert_eq!(summary.utxo_count, prev_state.utxos.len() as u64);
    }

    #[test]
    fn disconnect_block_rejects_undo_tx_count_mismatch() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let mut undo =
            build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        undo.txs.pop();
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("undo tx count mismatch");
        assert!(err.contains("undo tx count mismatch"));
    }

    #[test]
    fn disconnect_block_rejects_tip_mismatch() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");
        connected_state.tip_hash = [0xAA; 32];

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("tip mismatch");
        assert!(err.contains("disconnect block is not current tip"));
    }

    #[test]
    fn disconnect_block_rejects_restore_collision() {
        let (prev_state, source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");
        connected_state
            .utxos
            .insert(source_outpoint, sample_entry(77));

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("restore collision");
        assert!(err.contains("undo restore target already present"));
    }

    #[test]
    fn disconnect_block_rejects_duplicate_restore_entries_in_undo() {
        let (prev_state, source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let mut undo =
            build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let duplicate = undo.txs[1].spent[0].clone();
        undo.txs[1].spent.push(duplicate);

        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");
        connected_state.utxos.remove(&source_outpoint);

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("duplicate restore");
        assert!(err.contains("undo duplicate restore entry"));
    }

    #[test]
    fn disconnect_block_rejects_duplicate_created_restore_entries_in_undo() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let mut undo =
            build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let pb = parse_block_bytes(&block_bytes).expect("parse block");
        let duplicate = SpentUndo {
            outpoint: Outpoint {
                txid: pb.txids[1],
                vout: 0,
            },
            entry: sample_entry(55),
        };
        undo.txs[2].spent.push(duplicate.clone());
        undo.txs[2].spent.push(duplicate);

        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("duplicate created restore");
        assert!(err.contains("undo duplicate restore entry"));
    }

    #[test]
    fn disconnect_block_rejects_missing_created_output() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let pb = parse_block_bytes(&block_bytes).expect("parse block");

        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");
        connected_state.utxos.remove(&Outpoint {
            txid: pb.txids[2],
            vout: 0,
        });

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("missing created output");
        assert!(err.contains("disconnect missing created output"));
    }
}

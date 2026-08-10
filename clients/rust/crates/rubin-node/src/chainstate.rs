use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use rubin_consensus::{
    block_hash,
    connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context,
    encode_compact_size, parse_block_bytes, ConnectBlockBasicSummary, InMemoryChainState, Outpoint,
    RotationProvider, SuiteRegistry, UtxoEntry,
};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha3::{Digest, Sha3_256};

use crate::genesis::validate_genesis_identity;
use crate::io_utils::{
    atomic_write_error_before, parse_hex32, reclaim_atomic_write_parent,
    reclaim_atomic_write_scratch, write_file_atomic_typed, AtomicWriteError, AtomicWriteOperation,
};
use crate::store_envelope::{
    marshal_store_envelope, open_store_envelope, STORE_ENVELOPE_CHAIN_STATE,
};

pub const CHAIN_STATE_FILE_NAME: &str = "chainstate.json";
const CHAIN_STATE_DISK_VERSION_V1: u32 = 1;
const CHAIN_STATE_DISK_VERSION: u32 = 2;
pub const UTXO_SET_HASH_DST: &[u8] = b"RUBINv1-utxo-set-hash/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainState {
    pub has_tip: bool,
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub already_generated: u128,
    pub utxos: HashMap<Outpoint, UtxoEntry>,
}

/// Identifies one block a canonical apply committed, plus the complete DA-set
/// IDs that block carries. It deliberately holds NO raw block bytes: a reorg
/// summary accumulates one record per newly-canonical block, and a block is up
/// to `MAX_BLOCK_BYTES`, so retaining bytes made summary size grow with reorg
/// depth times block size. `complete_da_ids` is bounded by
/// `MAX_DA_BATCHES_PER_BLOCK` fixed-width IDs, which is all any consumer ever
/// needed from the bytes.
///
/// The no-bytes bound is on the SHAPE, not on a field name: no byte-slice field
/// of any name may be reintroduced here. Go twin:
/// `clients/go/node/chainstate.go` `CanonicalAppliedBlock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalAppliedBlock {
    pub hash: [u8; 32],
    pub complete_da_ids: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStateConnectSummary {
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub sum_fees: u128,
    pub already_generated: u128,
    pub already_generated_n1: u128,
    pub utxo_count: u64,
    /// Populated ONLY by the `SyncEngine` canonical-apply path
    /// (`SyncEngine::apply_block_with_target`), in canonical order: a direct
    /// apply reports the single connected block, a reorg reports every
    /// newly-canonical branch block, and a stored-but-not-switched side branch
    /// reports none. The `ChainState` connect entry points leave it EMPTY —
    /// connecting to an in-memory state is not by itself a canonical-application
    /// event, and both the reorg preview (`prepare_preferred_branch`) and the
    /// startup replay (`chainstate_recovery`) connect blocks that must never be
    /// reported. Go twin: `ChainStateConnectSummary.CanonicalAppliedBlocks`.
    pub canonical_applied_blocks: Vec<CanonicalAppliedBlock>,
}

#[derive(Debug, Clone, Serialize)]
struct ChainStateDisk {
    tip_hash: String,
    utxos: Vec<UtxoDiskEntry>,
    height: u64,
    #[serde(serialize_with = "rubin_consensus::uint128_json::serialize")]
    already_generated: u128,
    version: u32,
    has_tip: bool,
}

const CHAINSTATE_MISSING_VERSION: &str = "CHAINSTATE_SCHEMA: missing version";
const CHAINSTATE_DUPLICATE_VERSION: &str = "CHAINSTATE_SCHEMA: duplicate version";
const CHAINSTATE_INVALID_VERSION: &str =
    "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32";
const CHAINSTATE_UNSUPPORTED_VERSION_PREFIX: &str = "CHAINSTATE_SCHEMA: unsupported version ";
const CHAINSTATE_MISSING_SUPPLY: &str = "CHAINSTATE_SCHEMA: missing already_generated";
const CHAINSTATE_DUPLICATE_SUPPLY: &str = "CHAINSTATE_SCHEMA: duplicate already_generated";
const CHAINSTATE_INVALID_V1_SUPPLY: &str =
    "CHAINSTATE_SCHEMA: v1 already_generated must be a nonnegative JSON integer through u64";
const CHAINSTATE_INVALID_V2_SUPPLY: &str =
    "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128";
const CHAINSTATE_PAYLOAD_NOT_CANONICAL: &str =
    "CHAINSTATE_SCHEMA: payload is not the canonical encoding";

enum ChainStateScalarToken {
    Null,
    Unsigned(u64),
    String { value: String, unescaped: bool },
    Other,
}

impl ChainStateScalarToken {
    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

struct ChainStateScalarVisitor;

impl<'de> Visitor<'de> for ChainStateScalarVisitor {
    type Value = ChainStateScalarToken;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::Null)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::Unsigned(value))
    }

    fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E> {
        Ok(u64::try_from(value).map_or(
            ChainStateScalarToken::Other,
            ChainStateScalarToken::Unsigned,
        ))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::Other)
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::Other)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::Other)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::Other)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::String {
            value: value.to_owned(),
            unescaped: true,
        })
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::String {
            value: value.to_owned(),
            unescaped: false,
        })
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(ChainStateScalarToken::String {
            value,
            unescaped: false,
        })
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(ChainStateScalarToken::Other)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(ChainStateScalarToken::Other)
    }
}

impl<'de> Deserialize<'de> for ChainStateScalarToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ChainStateScalarVisitor)
    }
}

fn json_number_out_of_range(error: &impl fmt::Display) -> bool {
    error.to_string().starts_with("number out of range")
}

fn validate_chainstate_version<E: serde::de::Error>(
    version_seen: bool,
    version_duplicate: bool,
    version_null: bool,
    version: Option<ChainStateScalarToken>,
) -> Result<u32, E> {
    if let Some(error) =
        chainstate_version_presence_error(version_seen, version_duplicate, version_null)
    {
        return Err(E::custom(error));
    }
    let version = match version {
        Some(ChainStateScalarToken::Unsigned(value)) => {
            u32::try_from(value).map_err(|_| E::custom(CHAINSTATE_INVALID_VERSION))?
        }
        _ => return Err(E::custom(CHAINSTATE_INVALID_VERSION)),
    };
    if version != CHAIN_STATE_DISK_VERSION_V1 && version != CHAIN_STATE_DISK_VERSION {
        return Err(E::custom(format!(
            "{CHAINSTATE_UNSUPPORTED_VERSION_PREFIX}{version}"
        )));
    }
    Ok(version)
}

fn chainstate_version_presence_error(
    version_seen: bool,
    version_duplicate: bool,
    version_null: bool,
) -> Option<&'static str> {
    if !version_seen || version_null {
        Some(CHAINSTATE_MISSING_VERSION)
    } else if version_duplicate {
        Some(CHAINSTATE_DUPLICATE_VERSION)
    } else {
        None
    }
}

fn chainstate_supply_presence_error(
    supply_seen: bool,
    supply_duplicate: bool,
    supply_null: bool,
) -> Option<&'static str> {
    if !supply_seen || supply_null {
        Some(CHAINSTATE_MISSING_SUPPLY)
    } else if supply_duplicate {
        Some(CHAINSTATE_DUPLICATE_SUPPLY)
    } else {
        None
    }
}

#[derive(Default)]
struct ChainStateTargetPresence {
    version_seen: bool,
    version_duplicate: bool,
    version_null: bool,
    supply_seen: bool,
    supply_duplicate: bool,
    supply_null: bool,
}

struct ChainStateTargetPresenceVisitor;

impl<'de> Visitor<'de> for ChainStateTargetPresenceVisitor {
    type Value = ChainStateTargetPresence;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a chainstate JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut presence = ChainStateTargetPresence::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "version" => {
                    let is_null = map.next_value::<Option<IgnoredAny>>()?.is_none();
                    presence.version_duplicate |= presence.version_seen;
                    presence.version_seen = true;
                    presence.version_null |= is_null;
                }
                "already_generated" => {
                    let is_null = map.next_value::<Option<IgnoredAny>>()?.is_none();
                    presence.supply_duplicate |= presence.supply_seen;
                    presence.supply_seen = true;
                    presence.supply_null |= is_null;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(presence)
    }
}

impl<'de> Deserialize<'de> for ChainStateTargetPresence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ChainStateTargetPresenceVisitor)
    }
}

struct ChainStateVersion(u32);

struct ChainStateVersionVisitor;

impl<'de> Visitor<'de> for ChainStateVersionVisitor {
    type Value = ChainStateVersion;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a chainstate JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut version = None;
        let mut version_seen = false;
        let mut version_duplicate = false;
        let mut version_null = false;

        while let Some(key) = map.next_key::<String>()? {
            if key == "version" {
                let token = map.next_value::<ChainStateScalarToken>().map_err(|error| {
                    if json_number_out_of_range(&error) {
                        serde::de::Error::custom(CHAINSTATE_INVALID_VERSION)
                    } else {
                        error
                    }
                })?;
                let token_null = token.is_null();
                if version_seen {
                    version_duplicate = true;
                } else {
                    version = Some(token);
                }
                version_seen = true;
                version_null |= token_null;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }

        validate_chainstate_version(version_seen, version_duplicate, version_null, version)
            .map(ChainStateVersion)
    }
}

impl<'de> Deserialize<'de> for ChainStateVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ChainStateVersionVisitor)
    }
}

struct ChainStateSupplySeed(u32);

struct ChainStateSupplyVisitor {
    version: u32,
}

impl<'de> Visitor<'de> for ChainStateSupplyVisitor {
    type Value = u128;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a chainstate JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut supply = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "already_generated" {
                let token = map.next_value::<ChainStateScalarToken>().map_err(|error| {
                    if json_number_out_of_range(&error) {
                        serde::de::Error::custom(if self.version == CHAIN_STATE_DISK_VERSION_V1 {
                            CHAINSTATE_INVALID_V1_SUPPLY
                        } else {
                            CHAINSTATE_INVALID_V2_SUPPLY
                        })
                    } else {
                        error
                    }
                })?;
                if supply.is_none() {
                    supply = Some(token);
                }
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        validate_chainstate_supply(self.version, supply)
    }
}

impl<'de> DeserializeSeed<'de> for ChainStateSupplySeed {
    type Value = u128;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ChainStateSupplyVisitor { version: self.0 })
    }
}

fn validate_chainstate_supply<E: serde::de::Error>(
    version: u32,
    supply: Option<ChainStateScalarToken>,
) -> Result<u128, E> {
    match (version, supply) {
        (CHAIN_STATE_DISK_VERSION_V1, Some(ChainStateScalarToken::Unsigned(value))) => {
            Ok(u128::from(value))
        }
        (CHAIN_STATE_DISK_VERSION_V1, _) => Err(E::custom(CHAINSTATE_INVALID_V1_SUPPLY)),
        (
            CHAIN_STATE_DISK_VERSION,
            Some(ChainStateScalarToken::String {
                value,
                unescaped: true,
            }),
        ) => rubin_consensus::uint128_json::parse_canonical_decimal(&value)
            .ok_or_else(|| E::custom(CHAINSTATE_INVALID_V2_SUPPLY)),
        (CHAIN_STATE_DISK_VERSION, _) => Err(E::custom(CHAINSTATE_INVALID_V2_SUPPLY)),
        _ => unreachable!("supported chainstate version checked above"),
    }
}

struct ChainStateDiskVisitor;

impl<'de> Visitor<'de> for ChainStateDiskVisitor {
    type Value = ChainStateDisk;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a chainstate JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut version = None;
        let mut version_seen = false;
        let mut version_duplicate = false;
        let mut version_null = false;
        let mut already_generated = None;
        let mut supply_seen = false;
        let mut supply_duplicate = false;
        let mut supply_null = false;
        let mut has_tip = None;
        let mut height = None;
        let mut tip_hash = None;
        let mut utxos = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "version" => {
                    let token = map.next_value::<ChainStateScalarToken>()?;
                    let token_null = token.is_null();
                    if version_seen {
                        version_duplicate = true;
                    } else {
                        version = Some(token);
                    }
                    version_seen = true;
                    version_null |= token_null;
                }
                "already_generated" => {
                    let token = map.next_value::<ChainStateScalarToken>()?;
                    let token_null = token.is_null();
                    if supply_seen {
                        supply_duplicate = true;
                    } else {
                        already_generated = Some(token);
                    }
                    supply_seen = true;
                    supply_null |= token_null;
                }
                "has_tip" => {
                    if has_tip.is_some() {
                        return Err(serde::de::Error::duplicate_field("has_tip"));
                    }
                    has_tip = Some(map.next_value()?);
                }
                "height" => {
                    if height.is_some() {
                        return Err(serde::de::Error::duplicate_field("height"));
                    }
                    height = Some(map.next_value()?);
                }
                "tip_hash" => {
                    if tip_hash.is_some() {
                        return Err(serde::de::Error::duplicate_field("tip_hash"));
                    }
                    tip_hash = Some(map.next_value()?);
                }
                "utxos" => {
                    if utxos.is_some() {
                        return Err(serde::de::Error::duplicate_field("utxos"));
                    }
                    utxos = Some(map.next_value()?);
                }
                _ => {
                    return Err(serde::de::Error::custom(CHAINSTATE_PAYLOAD_NOT_CANONICAL));
                }
            }
        }

        let version =
            validate_chainstate_version(version_seen, version_duplicate, version_null, version)?;

        if let Some(error) =
            chainstate_supply_presence_error(supply_seen, supply_duplicate, supply_null)
        {
            return Err(serde::de::Error::custom(error));
        }
        let already_generated = validate_chainstate_supply(version, already_generated)?;

        Ok(ChainStateDisk {
            version,
            has_tip: has_tip.ok_or_else(|| serde::de::Error::missing_field("has_tip"))?,
            height: height.ok_or_else(|| serde::de::Error::missing_field("height"))?,
            tip_hash: tip_hash.ok_or_else(|| serde::de::Error::missing_field("tip_hash"))?,
            already_generated,
            utxos: utxos.ok_or_else(|| serde::de::Error::missing_field("utxos"))?,
        })
    }
}

impl<'de> Deserialize<'de> for ChainStateDisk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ChainStateDiskVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UtxoDiskEntry {
    txid: String,
    covenant_data: String,
    value: u64,
    creation_height: u64,
    vout: u32,
    covenant_type: u16,
    created_by_coinbase: bool,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            has_tip: false,
            height: 0,
            tip_hash: [0u8; 32],
            already_generated: 0,
            utxos: HashMap::new(),
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        self.save_atomic(path).map_err(|error| error.to_string())
    }

    pub(crate) fn save_atomic<P: AsRef<Path>>(&self, path: P) -> Result<(), AtomicWriteError> {
        let path = path.as_ref();
        let disk = state_to_disk(self).map_err(|error| {
            atomic_write_error_before(path, AtomicWriteOperation::Overwrite, error)
        })?;
        let mut payload = serde_json::to_vec_pretty(&disk).map_err(|error| {
            atomic_write_error_before(
                path,
                AtomicWriteOperation::Overwrite,
                format!("encode chainstate: {error}"),
            )
        })?;
        payload.push(b'\n');
        // RUB-1153 canonicalizes the inner-v2 bytes; RUB-1134's outer
        // RUBIN_CHAINSTATE_V1 envelope and atomic write path stay unchanged.
        let raw =
            marshal_store_envelope(STORE_ENVELOPE_CHAIN_STATE, &payload).map_err(|error| {
                atomic_write_error_before(path, AtomicWriteOperation::Overwrite, error)
            })?;
        // Parent creation is delegated to `write_file_atomic`, which
        // runs `fs::create_dir_all(effective_parent(path))` on the
        // actual write target. `effective_parent` maps a bare-filename
        // input (`Path::new("chainstate.json").parent() == Some("")`)
        // to `Some(".")` so the `create_dir_all` call always receives
        // a non-empty directory. Running an explicit
        // `fs::create_dir_all(path.parent())` here — as an earlier
        // version did — instead passed `""` to `create_dir_all` on
        // bare-filename callers and failed with an I/O error; this
        // helper's own `effective_parent` is the correct layer.
        //
        // Raw `write_file_atomic`. Paired with `load_chain_state`'s
        // raw `fs::read` — both use the caller-supplied path
        // directly, with no per-helper `lexical_clean` step.
        //
        // For the node binary, `path` originates from
        // `chain_state_path(cfg.data_dir)` after `cfg.data_dir` was
        // cleaned at the CLI parse site, so the startup read and
        // every subsequent save land on one on-disk file even for
        // operator `--data-dir` values that cross a symlink
        // combined with `..`. Other callers of `ChainState::save`
        // are responsible for their own path hygiene — see
        // `load_chain_state` for the mirror note.
        write_file_atomic_typed(path, &raw)
    }

    pub fn connect_block(
        &mut self,
        block_bytes: &[u8],
        expected_target: Option<[u8; 32]>,
        prev_timestamps: Option<&[u64]>,
        chain_id: [u8; 32],
    ) -> Result<ChainStateConnectSummary, String> {
        self.connect_block_with_suite_context(
            block_bytes,
            expected_target,
            prev_timestamps,
            chain_id,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_block_with_suite_context(
        &mut self,
        block_bytes: &[u8],
        expected_target: Option<[u8; 32]>,
        prev_timestamps: Option<&[u64]>,
        chain_id: [u8; 32],
        rotation: Option<&dyn RotationProvider>,
        registry: Option<&SuiteRegistry>,
    ) -> Result<ChainStateConnectSummary, String> {
        let (block_height, expected_prev_hash) = self.next_block_context()?;
        validate_genesis_identity(block_height, chain_id, block_bytes)?;
        let mut work_state = InMemoryChainState {
            utxos: copy_utxo_set(&self.utxos),
            already_generated: self.already_generated,
        };

        let connect_summary: ConnectBlockBasicSummary =
            connect_block_basic_in_memory_at_height_and_core_ext_deployments_with_suite_context(
                block_bytes,
                expected_prev_hash,
                expected_target,
                block_height,
                prev_timestamps,
                &mut work_state,
                chain_id,
                rotation,
                registry,
            )
            .map_err(|e| e.to_string())?;

        let parsed = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        let tip_hash = block_hash(&parsed.header_bytes).map_err(|e| e.to_string())?;

        apply_connected_block(self, block_height, tip_hash, work_state, connect_summary)
    }

    pub fn utxo_set_hash(&self) -> [u8; 32] {
        utxo_set_hash(&self.utxos)
    }

    pub fn state_digest(&self) -> [u8; 32] {
        self.utxo_set_hash()
    }

    /// Defensive-copy read path for a single UTXO entry. Mirrors the Go twin
    /// `copyUtxoEntry` contract in `clients/go/node/chainstate.go`: callers
    /// receive an owned `UtxoEntry` whose mutation cannot reach the canonical
    /// `self.utxos` map. Returns `None` for missing outpoints.
    ///
    /// Prefer this read path for code that needs to mutate the returned entry
    /// or forward it across trust boundaries. Direct reads from `self.utxos`
    /// also exist (the field is `pub`), including read-only fast paths such as
    /// iteration in `utxo_set_hash` and `indexed_suite_ids`, but those callers
    /// do not get the defensive-copy guarantee provided by this method.
    pub fn lookup_utxo_owned(&self, outpoint: &Outpoint) -> Option<UtxoEntry> {
        self.utxos.get(outpoint).map(copy_utxo_entry)
    }

    /// Returns the sorted suite IDs that are explicitly bound in current UTXO
    /// covenant data. Today this covers explicit suite_id carriers such as
    /// CORE_P2PK outputs.
    pub fn indexed_suite_ids(&self) -> Vec<u8> {
        let mut ids = Vec::new();
        for entry in self.utxos.values() {
            if let Some(suite_id) = explicit_suite_id_for_utxo_entry(entry) {
                ids.push(suite_id);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Returns deterministically sorted outpoints whose covenant data
    /// explicitly binds to suite_id.
    pub fn utxo_outpoints_by_suite_id(&self, suite_id: u8) -> Vec<Outpoint> {
        let mut outpoints = Vec::new();
        for (outpoint, entry) in &self.utxos {
            if utxo_entry_explicitly_uses_suite(entry, suite_id) {
                outpoints.push(outpoint.clone());
            }
        }
        outpoints.sort_by(|a, b| match a.txid.cmp(&b.txid) {
            Ordering::Equal => a.vout.cmp(&b.vout),
            other => other,
        });
        outpoints
    }

    /// Returns how many current UTXOs explicitly bind to suite_id.
    pub fn utxo_exposure_count_by_suite_id(&self, suite_id: u8) -> u64 {
        self.utxos
            .values()
            .filter(|entry| utxo_entry_explicitly_uses_suite(entry, suite_id))
            .count() as u64
    }

    fn next_block_context(&self) -> Result<(u64, Option<[u8; 32]>), String> {
        if !self.has_tip {
            return Ok((0, None));
        }
        if self.height == u64::MAX {
            return Err("height overflow".to_string());
        }
        Ok((self.height + 1, Some(self.tip_hash)))
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_connected_block(
    state: &mut ChainState,
    block_height: u64,
    tip_hash: [u8; 32],
    work_state: InMemoryChainState,
    connect_summary: ConnectBlockBasicSummary,
) -> Result<ChainStateConnectSummary, String> {
    let summary = ChainStateConnectSummary {
        block_height,
        block_hash: tip_hash,
        sum_fees: connect_summary.sum_fees,
        already_generated: connect_summary.already_generated,
        already_generated_n1: connect_summary.already_generated_n1,
        utxo_count: connect_summary.utxo_count,
        // Left EMPTY on purpose: connecting to an in-memory chain state is
        // not a canonical-application event. Only the SyncEngine
        // canonical-apply site mints these records, so the reorg preview,
        // the startup replay, and side-branch connects — all of which land
        // here — structurally cannot report a canonical-applied block.
        canonical_applied_blocks: Vec::new(),
    };

    state.has_tip = true;
    state.height = block_height;
    state.tip_hash = tip_hash;
    state.already_generated = work_state.already_generated;
    state.utxos = work_state.utxos;

    Ok(summary)
}

/// Canonical deep-copy helper for a single UTXO entry. Mirrors the Go twin
/// `copyUtxoEntry` in `clients/go/node/chainstate.go`. Implemented in terms
/// of `entry.clone()` so future fields added to `UtxoEntry` are deep-copied
/// by construction (the derived `Clone` already deep-copies
/// `covenant_data: Vec<u8>`); the named helper preserves the explicit
/// defensive-copy intent at call sites and makes the contract greppable.
pub(crate) fn copy_utxo_entry(entry: &UtxoEntry) -> UtxoEntry {
    entry.clone()
}

/// Defensive deep-copy of a full UTXO set. Mirrors the Go twin `copyUtxoSet`.
/// Used by `connect_block_with_suite_context` to
/// build the `work_state` replay map without sharing entries with the
/// canonical `ChainState.utxos` map. Implemented as `src.clone()` to avoid
/// a manual per-entry `insert` loop and preserve the source `HashMap`'s
/// hasher / configuration. The exact rehashing behaviour of `HashMap::clone`
/// is not a documented stdlib guarantee, so this comment makes only the
/// weaker claim — but in practice both `std` and `hashbrown` reuse the
/// existing layout, which is the implementation reason for picking
/// `src.clone()` over a hand-rolled re-insert.
pub(crate) fn copy_utxo_set(src: &HashMap<Outpoint, UtxoEntry>) -> HashMap<Outpoint, UtxoEntry> {
    src.clone()
}

pub fn chain_state_path<P: AsRef<Path>>(data_dir: P) -> PathBuf {
    data_dir.as_ref().join(CHAIN_STATE_FILE_NAME)
}

/// Startup scratch reclaim runs after store open/create under the datadir lock.
pub fn reclaim_atomic_scratch<P: AsRef<Path>>(data_dir: P) -> Result<(), String> {
    reclaim_atomic_write_scratch(data_dir.as_ref())
}

/// Fresh-store startup reclaims only its existing datadir parent.
pub fn reclaim_atomic_scratch_parent<P: AsRef<Path>>(parent: P) -> Result<(), String> {
    reclaim_atomic_write_parent(parent.as_ref())
}

pub fn load_chain_state<P: AsRef<Path>>(path: P) -> Result<ChainState, String> {
    let path = path.as_ref();
    // Raw `fs::read` on a caller-supplied path. Mirrors the Go
    // `LoadChainState` reader in `clients/go/node/chainstate.go`,
    // which also uses a caller-supplied path directly.
    //
    // For the node binary's own call site, `path` originates from
    // `chain_state_path(cfg.data_dir)` after `cfg.data_dir` was
    // lexically cleaned at the CLI parse site (`normalize_data_dir`
    // in `main.rs`), so the startup read and subsequent
    // `ChainState::save` writes land on exactly one on-disk file
    // regardless of whether the operator `--data-dir` contained
    // symlink+`..` segments. Other callers of this public function
    // are responsible for their own path hygiene — this helper does
    // NOT canonicalise or sandbox its input.
    let raw = match fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ChainState::new()),
        Err(e) => return Err(format!("read chainstate {}: {e}", path.display())),
    };
    // RUB-1134: an ABSENT file keeps the `ChainState::new()`-plus-full-replay
    // repair path above; every PRESENT file must clear the strict envelope
    // BEFORE the inner `ChainStateDisk` decode runs. This is a different arm
    // from the NotFound branch, so a corrupt file can never ride the
    // absent-file fallback; the STORE_INTEGRITY message is Go's verbatim.
    let payload = open_store_envelope(STORE_ENVELOPE_CHAIN_STATE, &raw)?;
    if payload
        .iter()
        .copied()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .is_some_and(|byte| byte != b'{')
    {
        let mut syntax_deserializer = serde_json::Deserializer::from_slice(&payload);
        if IgnoredAny::deserialize(&mut syntax_deserializer).is_ok() {
            return Err("decode chainstate: top-level value must be an object".to_string());
        }
    }
    // Presence/null/duplicate classification uses `IgnoredAny`, so a later
    // syntactically valid extreme number cannot preempt the target-field order.
    let mut presence_deserializer = serde_json::Deserializer::from_slice(&payload);
    let presence = ChainStateTargetPresence::deserialize(&mut presence_deserializer)
        .map_err(chainstate_decode_error)?;
    presence_deserializer
        .end()
        .map_err(|_| "decode chainstate: trailing content".to_string())?;
    if let Some(error) = chainstate_version_presence_error(
        presence.version_seen,
        presence.version_duplicate,
        presence.version_null,
    ) {
        return Err(error.to_string());
    }
    let mut version_deserializer = serde_json::Deserializer::from_slice(&payload);
    let version = ChainStateVersion::deserialize(&mut version_deserializer)
        .map_err(chainstate_decode_error)?
        .0;
    if let Some(error) = chainstate_supply_presence_error(
        presence.supply_seen,
        presence.supply_duplicate,
        presence.supply_null,
    ) {
        return Err(error.to_string());
    }
    let mut supply_deserializer = serde_json::Deserializer::from_slice(&payload);
    ChainStateSupplySeed(version)
        .deserialize(&mut supply_deserializer)
        .map_err(chainstate_decode_error)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&payload);
    let disk = ChainStateDisk::deserialize(&mut deserializer)
        .map_err(|_| CHAINSTATE_PAYLOAD_NOT_CANONICAL.to_string())?;
    deserializer
        .end()
        .map_err(|_| "decode chainstate: trailing content".to_string())?;
    if chainstate_has_edge_ascii_whitespace(&disk) {
        return Err(CHAINSTATE_PAYLOAD_NOT_CANONICAL.to_string());
    }
    chain_state_from_disk(disk)
}

fn chainstate_has_edge_ascii_whitespace(disk: &ChainStateDisk) -> bool {
    let whitespace = [' ', '\t', '\n', '\r', '\u{000b}', '\u{000c}'];
    let has_edge = |value: &str| value.trim_matches(&whitespace[..]) != value;
    has_edge(&disk.tip_hash)
        || disk
            .utxos
            .iter()
            .any(|item| has_edge(&item.txid) || has_edge(&item.covenant_data))
}

fn chainstate_decode_error(error: serde_json::Error) -> String {
    let rendered = error.to_string();
    for exact in [
        CHAINSTATE_MISSING_VERSION,
        CHAINSTATE_DUPLICATE_VERSION,
        CHAINSTATE_INVALID_VERSION,
        CHAINSTATE_MISSING_SUPPLY,
        CHAINSTATE_DUPLICATE_SUPPLY,
        CHAINSTATE_INVALID_V1_SUPPLY,
        CHAINSTATE_INVALID_V2_SUPPLY,
    ] {
        if rendered.starts_with(exact) {
            return exact.to_string();
        }
    }
    if let Some(rest) = rendered.strip_prefix(CHAINSTATE_UNSUPPORTED_VERSION_PREFIX) {
        if let Some(version) = rest.split_ascii_whitespace().next() {
            return format!("{CHAINSTATE_UNSUPPORTED_VERSION_PREFIX}{version}");
        }
    }
    format!("decode chainstate: {rendered}")
}

fn state_to_disk(s: &ChainState) -> Result<ChainStateDisk, String> {
    let mut utxos: Vec<UtxoDiskEntry> = s
        .utxos
        .iter()
        .map(|(op, entry)| UtxoDiskEntry {
            txid: hex::encode(op.txid),
            covenant_data: hex::encode(&entry.covenant_data),
            value: entry.value,
            creation_height: entry.creation_height,
            vout: op.vout,
            covenant_type: entry.covenant_type,
            created_by_coinbase: entry.created_by_coinbase,
        })
        .collect();
    utxos.sort_by(|a, b| match a.txid.cmp(&b.txid) {
        Ordering::Equal => a.vout.cmp(&b.vout),
        other => other,
    });

    Ok(ChainStateDisk {
        tip_hash: hex::encode(s.tip_hash),
        utxos,
        height: s.height,
        already_generated: s.already_generated,
        version: CHAIN_STATE_DISK_VERSION,
        has_tip: s.has_tip,
    })
}

fn utxo_set_hash(utxos: &HashMap<Outpoint, UtxoEntry>) -> [u8; 32] {
    let mut items: Vec<([u8; 36], &UtxoEntry)> = Vec::with_capacity(utxos.len());
    for (outpoint, entry) in utxos {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(&outpoint.txid);
        key[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
        items.push((key, entry));
    }
    // sort_unstable_by avoids decorate/sort/undecorate copies of the
    // [u8; 36] key that sort_by_key/sort_unstable_by_key would do —
    // important on the consensus digest path with large UTXO sets.
    #[allow(clippy::unnecessary_sort_by)]
    items.sort_unstable_by(|a, b| a.0.cmp(&b.0));

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

fn explicit_suite_id_for_utxo_entry(entry: &UtxoEntry) -> Option<u8> {
    match entry.covenant_type {
        rubin_consensus::constants::COV_TYPE_P2PK
            if entry.covenant_data.len()
                == rubin_consensus::constants::MAX_P2PK_COVENANT_DATA as usize =>
        {
            Some(entry.covenant_data[0])
        }
        _ => None,
    }
}

fn utxo_entry_explicitly_uses_suite(entry: &UtxoEntry, suite_id: u8) -> bool {
    explicit_suite_id_for_utxo_entry(entry) == Some(suite_id)
}

fn chain_state_from_disk(disk: ChainStateDisk) -> Result<ChainState, String> {
    if disk.version != CHAIN_STATE_DISK_VERSION_V1 && disk.version != CHAIN_STATE_DISK_VERSION {
        return Err(format!(
            "{}{}",
            CHAINSTATE_UNSUPPORTED_VERSION_PREFIX, disk.version
        ));
    }

    let tip_hash = parse_hex32("tip_hash", &disk.tip_hash)?;
    let mut utxos = HashMap::with_capacity(disk.utxos.len());
    for item in disk.utxos {
        let txid = parse_hex32("utxo.txid", &item.txid)?;
        let covenant_data = parse_hex("utxo.covenant_data", &item.covenant_data)?;
        let outpoint = Outpoint {
            txid,
            vout: item.vout,
        };
        if utxos.contains_key(&outpoint) {
            return Err(format!(
                "duplicate utxo outpoint: {}:{}",
                item.txid, item.vout
            ));
        }
        utxos.insert(
            outpoint,
            UtxoEntry {
                value: item.value,
                covenant_type: item.covenant_type,
                covenant_data,
                creation_height: item.creation_height,
                created_by_coinbase: item.created_by_coinbase,
            },
        );
    }

    Ok(ChainState {
        has_tip: disk.has_tip,
        height: disk.height,
        tip_hash,
        already_generated: disk.already_generated,
        utxos,
    })
}

fn parse_hex(name: &str, value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(format!("{name}: odd-length hex"));
    }
    hex::decode(trimmed).map_err(|e| format!("{name}: {e}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::coinbase::{build_coinbase_tx, default_mine_address};
    use crate::genesis::{devnet_genesis_block_bytes, devnet_genesis_chain_id};
    use crate::io_utils::unique_temp_path;

    use super::{
        apply_connected_block, chain_state_from_disk, chain_state_path, copy_utxo_entry,
        copy_utxo_set, load_chain_state, state_to_disk, ChainState, CHAINSTATE_DUPLICATE_SUPPLY,
        CHAINSTATE_DUPLICATE_VERSION, CHAINSTATE_INVALID_V1_SUPPLY, CHAINSTATE_INVALID_V2_SUPPLY,
        CHAINSTATE_INVALID_VERSION, CHAINSTATE_MISSING_SUPPLY, CHAINSTATE_MISSING_VERSION,
        CHAINSTATE_PAYLOAD_NOT_CANONICAL, CHAIN_STATE_FILE_NAME, STORE_ENVELOPE_CHAIN_STATE,
    };
    use rubin_consensus::constants::{
        EMISSION_SPEED_FACTOR, MINEABLE_CAP, POW_LIMIT, TAIL_EMISSION_PER_BLOCK,
    };
    use rubin_consensus::merkle::{witness_commitment_hash, witness_merkle_root_wtxids};
    use rubin_consensus::{
        apply_non_coinbase_tx_basic_with_mtp, block_hash, block_subsidy, encode_compact_size,
        merkle_root_txids, parse_block_bytes, parse_tx, ConnectBlockBasicSummary,
        InMemoryChainState, Outpoint, UtxoEntry, BLOCK_HEADER_BYTES,
    };
    use serde::{Deserialize, Serialize};

    const GENESIS_ONLY_STATE_DIGEST_HEX: &str =
        "8b172fb3a5e70b56de9ae78ce750c04eccbc4dd8b3be55751252e5a1b4f2e752";
    const GENESIS_PLUS_HEIGHT_ONE_STATE_DIGEST_HEX: &str =
        "a26ade4263f7659ef250d13c05a05137c61e223d1fdd585d0c70a5165a94bb5e";

    fn reachable_maximum_accumulated_subsidy() -> u128 {
        let mut height = 1u64;
        let mut accumulated = 0u64;
        loop {
            let base_reward = (MINEABLE_CAP - accumulated) >> EMISSION_SPEED_FACTOR;
            let subsidy = base_reward.max(TAIL_EMISSION_PER_BLOCK);
            if subsidy == TAIL_EMISSION_PER_BLOCK {
                break;
            }
            accumulated = accumulated.checked_add(subsidy).expect("pre-tail supply");
            height = height.checked_add(1).expect("pre-tail height");
        }

        assert_eq!(height, 5_771_107, "first tail subsidy height");
        assert_eq!(
            accumulated, 4_880_049_936_696_791,
            "accumulated subsidy before first tail block"
        );
        assert_eq!(
            block_subsidy(height, u128::from(accumulated)),
            TAIL_EMISSION_PER_BLOCK
        );
        let tail_blocks = u128::from(u64::MAX - height + 1);
        let total = u128::from(accumulated) + tail_blocks * u128::from(TAIL_EMISSION_PER_BLOCK);
        assert_eq!(total, 350_965_446_908_158_964_928_367_166);
        total
    }
    const DEVNET_GENESIS_FIXTURE_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/fixtures/CV-DEVNET-GENESIS.json"
    ));
    const DEVNET_CHAIN_FIXTURE_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/fixtures/CV-DEVNET-CHAIN.json"
    ));
    const DEVNET_SUBSIDY_FIXTURE_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/fixtures/CV-DEVNET-SUBSIDY.json"
    ));
    const DEVNET_MATURITY_FIXTURE_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/fixtures/CV-DEVNET-MATURITY.json"
    ));

    #[derive(Debug, Deserialize)]
    struct FixtureFile<T> {
        vectors: Vec<T>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct FixtureUtxo {
        txid: String,
        vout: u32,
        value: u64,
        covenant_type: u16,
        covenant_data: String,
        creation_height: u64,
        created_by_coinbase: bool,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ChainStateAfterFixture {
        tip_hash: String,
        height: u64,
        already_generated: String,
        version: u32,
        has_tip: bool,
        utxos: Vec<FixtureUtxo>,
    }

    #[derive(Debug, Deserialize)]
    struct DevnetConnectBlockVector {
        id: String,
        block_hex: String,
        chain_id: String,
        height: u64,
        #[serde(deserialize_with = "rubin_consensus::uint128_json::deserialize")]
        already_generated: u128,
        utxos: Vec<FixtureUtxo>,
        prev_timestamps: Vec<u64>,
        expected_prev_hash: Option<String>,
        expected_target: String,
        expect_ok: bool,
        // `expect_sum_fees` is a widened (u128) fee field shared with the
        // Python conformance runner (`exact_uint` in
        // conformance/runner/run_cv_bundle.py). A plain `u128` derive would
        // diverge from it in both directions: it would reject the canonical
        // decimal string form that fixed_json_rule mandates and accept a bare
        // numeric token above u64 that every other reader rejects.
        #[serde(deserialize_with = "rubin_consensus::uint128_json::deserialize")]
        expect_sum_fees: u128,
        expect_utxo_count: u64,
        #[serde(deserialize_with = "rubin_consensus::uint128_json::deserialize")]
        expect_already_generated: u128,
        #[serde(deserialize_with = "rubin_consensus::uint128_json::deserialize")]
        expect_already_generated_n1: u128,
        block_hash: String,
        chainstate_after: Option<ChainStateAfterFixture>,
    }

    #[derive(Debug, Deserialize)]
    struct DevnetMaturityVector {
        id: String,
        tx_hex: String,
        chain_id: String,
        height: u64,
        block_timestamp: u64,
        utxos: Vec<FixtureUtxo>,
        expect_ok: bool,
        expect_err: String,
    }

    fn parse_hex32_test(name: &str, value: &str) -> [u8; 32] {
        let raw = hex::decode(value).unwrap_or_else(|e| panic!("{name} hex: {e}"));
        assert_eq!(raw.len(), 32, "{name} must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    }

    fn fixture_utxos_to_map(items: &[FixtureUtxo]) -> HashMap<Outpoint, UtxoEntry> {
        let mut out = HashMap::with_capacity(items.len());
        for item in items {
            let txid = parse_hex32_test("fixture utxo txid", &item.txid);
            let covenant_data =
                hex::decode(&item.covenant_data).expect("fixture covenant_data hex");
            out.insert(
                Outpoint {
                    txid,
                    vout: item.vout,
                },
                UtxoEntry {
                    value: item.value,
                    covenant_type: item.covenant_type,
                    covenant_data,
                    creation_height: item.creation_height,
                    created_by_coinbase: item.created_by_coinbase,
                },
            );
        }
        out
    }

    fn fixture_chainstate(value: &ChainStateAfterFixture) -> ChainState {
        let already_generated = value.already_generated.parse().expect("u128 supply");
        ChainState {
            has_tip: value.has_tip,
            height: value.height,
            tip_hash: parse_hex32_test("chainstate_after tip_hash", &value.tip_hash),
            already_generated,
            utxos: fixture_utxos_to_map(&value.utxos),
        }
    }

    fn load_fixture_chainstate(id: &str, value: &ChainStateAfterFixture) -> ChainState {
        assert_eq!(value.version, 2, "{id}");
        let dir = unique_temp_path(&format!("rubin-chainstate-fixture-{id}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = chain_state_path(&dir);
        let payload = serde_json::to_vec(value).expect("encode chainstate_after");
        write_chainstate_payload(&path, &payload);
        let loaded = load_chain_state(&path).unwrap_or_else(|error| panic!("{id}: {error}"));
        std::fs::remove_dir_all(&dir).expect("cleanup");
        loaded
    }

    fn chainstate_from_connect_fixture(v: &DevnetConnectBlockVector) -> ChainState {
        let mut state = ChainState::new();
        state.already_generated = v.already_generated;
        state.utxos = fixture_utxos_to_map(&v.utxos);
        if v.height > 0 {
            state.has_tip = true;
            state.height = v.height - 1;
            state.tip_hash = parse_hex32_test(
                "expected_prev_hash",
                v.expected_prev_hash
                    .as_deref()
                    .expect("non-genesis vector must provide expected_prev_hash"),
            );
        }
        state
    }

    fn build_block_bytes(
        prev_hash: [u8; 32],
        merkle_root: [u8; 32],
        target: [u8; 32],
        timestamp: u64,
        txs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(BLOCK_HEADER_BYTES);
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&prev_hash);
        header.extend_from_slice(&merkle_root);
        header.extend_from_slice(&timestamp.to_le_bytes());
        header.extend_from_slice(&target);
        header.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(header.len(), BLOCK_HEADER_BYTES);

        let mut block = header;
        encode_compact_size(txs.len() as u64, &mut block);
        for tx in txs {
            block.extend_from_slice(tx);
        }
        block
    }

    fn coinbase_only_block_with_supply(
        height: u64,
        already_generated: u128,
        prev_hash: [u8; 32],
    ) -> Vec<u8> {
        let witness_root = witness_merkle_root_wtxids(&[[0u8; 32]]).expect("witness root");
        let witness_commitment = witness_commitment_hash(witness_root);
        let coinbase = build_coinbase_tx(
            height,
            already_generated,
            &default_mine_address(),
            witness_commitment,
        )
        .expect("coinbase");
        let (_, coinbase_txid, _, consumed) = parse_tx(&coinbase).expect("parse coinbase");
        assert_eq!(consumed, coinbase.len());
        let merkle_root = merkle_root_txids(&[coinbase_txid]).expect("merkle root");
        build_block_bytes(prev_hash, merkle_root, POW_LIMIT, 1, &[coinbase])
    }

    fn height_one_coinbase_only_block(prev_hash: [u8; 32]) -> Vec<u8> {
        coinbase_only_block_with_supply(1, 0, prev_hash)
    }

    fn nonzero_chainstate_for_supply_overflow() -> ChainState {
        let mut state = ChainState {
            has_tip: true,
            height: 41,
            tip_hash: [0x41; 32],
            already_generated: 73,
            utxos: HashMap::new(),
        };
        state.utxos.insert(
            Outpoint {
                txid: [0x42; 32],
                vout: 3,
            },
            UtxoEntry {
                value: 99,
                covenant_type: 1,
                covenant_data: vec![0x43; 4],
                creation_height: 7,
                created_by_coinbase: false,
            },
        );
        state
    }

    fn connect_summary_with_supply(
        already_generated: u128,
        already_generated_n1: u128,
    ) -> ConnectBlockBasicSummary {
        ConnectBlockBasicSummary {
            sum_fees: 17,
            already_generated,
            already_generated_n1,
            utxo_count: 2,
            post_state_digest: [0x44; 32],
            sig_task_count: 0,
            worker_panics: 0,
        }
    }

    #[test]
    fn chainstate_roundtrip_with_utxos() {
        let dir = unique_temp_path("rubin-chainstate-test");
        let path = chain_state_path(&dir);
        assert_eq!(
            path.file_name().and_then(|s| s.to_str()),
            Some(CHAIN_STATE_FILE_NAME)
        );

        let mut st = ChainState::new();
        st.has_tip = true;
        st.height = 42;
        st.tip_hash = [0x11; 32];
        st.already_generated = 77;
        st.utxos.insert(
            Outpoint {
                txid: [0x22; 32],
                vout: 3,
            },
            UtxoEntry {
                value: 123,
                covenant_type: 0,
                covenant_data: vec![0x01; 33],
                creation_height: 10,
                created_by_coinbase: false,
            },
        );

        st.save(&path).expect("save");
        let got = load_chain_state(&path).expect("load");
        assert_eq!(got, st);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// `ChainState::save` must accept a bare-filename path (e.g.
    /// `"chainstate.json"`) without the pre-write `create_dir_all`
    /// running against `""`. An earlier version of `save` called
    /// `fs::create_dir_all(path.parent())` directly; for a
    /// bare-filename input `path.parent()` is `Some("")` on Unix,
    /// and `create_dir_all("")` fails with an I/O error. Parent
    /// creation is delegated to `write_file_atomic` which uses
    /// `effective_parent` (maps `""` → `.`), so `save("file.json")`
    /// from the current working directory succeeds.
    #[test]
    fn save_accepts_bare_filename_via_effective_parent() {
        use std::path::Path;
        use std::process::Command;

        const CHILD_ENV: &str = "RUBIN_CHAINSTATE_BARE_FILENAME_CHILD";

        if std::env::var_os(CHILD_ENV).is_some() {
            let st = ChainState::new();
            st.save(Path::new("chainstate.json"))
                .expect("save with bare filename must not error on empty parent");
            return;
        }

        let dir = unique_temp_path("rubin-chainstate-bare-filename");
        std::fs::create_dir_all(&dir).expect("mkdir");

        // Rust's test harness `--exact` mode matches against the
        // FULLY-QUALIFIED test name (`module::path::test_name`). Just
        // the leaf name would filter to zero tests, the child process
        // would exit successfully without running anything, and the
        // parent `assert!(status.success())` would pass — leaving
        // this regression test as a silent no-op. Pass the full path
        // so the child actually re-enters this function through the
        // `CHILD_ENV`-set branch above.
        let status = Command::new(std::env::current_exe().expect("current test binary"))
            .current_dir(&dir)
            .env(CHILD_ENV, "1")
            .arg("--exact")
            .arg("chainstate::tests::save_accepts_bare_filename_via_effective_parent")
            .status()
            .expect("spawn child test process");

        assert!(
            status.success(),
            "child test process failed for bare filename save"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn chainstate_suite_exposure_queries_by_explicit_suite_id() {
        let mut st = ChainState::new();
        let first = Outpoint {
            txid: [0x03; 32],
            vout: 2,
        };
        let second = Outpoint {
            txid: [0x01; 32],
            vout: 0,
        };
        let third = Outpoint {
            txid: [0x02; 32],
            vout: 1,
        };
        let ignored = Outpoint {
            txid: [0xaa; 32],
            vout: 9,
        };

        let mut first_cov = vec![0x01; 33];
        first_cov[0] = rubin_consensus::constants::SUITE_ID_ML_DSA_87;
        st.utxos.insert(
            first.clone(),
            UtxoEntry {
                value: 10,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: first_cov,
                creation_height: 3,
                created_by_coinbase: false,
            },
        );
        let mut rotated_cov = vec![0x11; 33];
        rotated_cov[0] = 0x42;
        st.utxos.insert(
            second.clone(),
            UtxoEntry {
                value: 11,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: rotated_cov.clone(),
                creation_height: 4,
                created_by_coinbase: false,
            },
        );
        st.utxos.insert(
            third.clone(),
            UtxoEntry {
                value: 12,
                covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
                covenant_data: rotated_cov,
                creation_height: 5,
                created_by_coinbase: false,
            },
        );
        st.utxos.insert(
            ignored,
            UtxoEntry {
                value: 7,
                covenant_type: rubin_consensus::constants::COV_TYPE_HTLC,
                covenant_data: vec![
                    0x00;
                    rubin_consensus::constants::MAX_HTLC_COVENANT_DATA as usize
                ],
                creation_height: 6,
                created_by_coinbase: false,
            },
        );

        assert_eq!(
            st.indexed_suite_ids(),
            vec![rubin_consensus::constants::SUITE_ID_ML_DSA_87, 0x42]
        );
        assert_eq!(st.utxo_exposure_count_by_suite_id(0x42), 2);
        assert_eq!(
            st.utxo_outpoints_by_suite_id(0x42),
            vec![second.clone(), third.clone()]
        );
        assert_eq!(st.utxo_exposure_count_by_suite_id(0x99), 0);
    }

    /// Every malformed, legacy, checksum-mismatched or parse-valid-but-edited
    /// `chainstate.json` fails BEFORE the inner decode with the pinned identity
    /// and never rides the absent-file fallback.
    #[test]
    fn load_chainstate_rejects_integrity_failures() {
        use crate::store_envelope::tests::{
            restamp_payload_keeping_checksum, rewrap, run_store_integrity_rows, shared_reject_rows,
            StoreIntegrityRow,
        };
        use crate::store_envelope::{STORE_CHECKSUM_MISMATCH_ERR, STORE_LEGACY_CHAINSTATE_ERR};

        let dir = unique_temp_path("rubin-chainstate-integrity");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = chain_state_path(&dir);
        let mut state = ChainState::new();
        state.has_tip = true;
        state.height = 9;
        state.already_generated = 4_200;
        state.tip_hash = [0x11; 32];
        state.save(&path).expect("save chainstate");
        let valid = std::fs::read(&path).expect("read chainstate");
        let payload =
            crate::store_envelope::open_store_envelope(STORE_ENVELOPE_CHAIN_STATE, &valid)
                .expect("open valid envelope");

        let mut rows = shared_reject_rows();
        rows.push(StoreIntegrityRow {
            name: "legacy_unversioned_chainstate",
            body: Box::new(|_, payload| payload.to_vec()),
            want_msg: Some(STORE_LEGACY_CHAINSTATE_ERR),
            want_sub: None,
            not_integrity: false,
        });
        rows.push(StoreIntegrityRow {
            name: "legacy_unversioned_with_trailing_garbage",
            body: Box::new(|_, payload| {
                let mut out = payload.to_vec();
                out.extend_from_slice(b"trailing");
                out
            }),
            want_msg: Some(STORE_LEGACY_CHAINSTATE_ERR),
            want_sub: None,
            not_integrity: false,
        });
        rows.push(StoreIntegrityRow {
            // `already_generated` is a SCALAR outside the UTXO set and the tip
            // is preserved, so every downstream check passes and only the
            // stale checksum catches it.
            name: "already_generated_edited_stale_checksum",
            body: Box::new(|valid, payload| {
                let edited = String::from_utf8_lossy(payload).replacen(
                    "\"already_generated\": \"4200\"",
                    "\"already_generated\": \"4201\"",
                    1,
                );
                assert_ne!(edited.as_bytes(), payload, "the edit did not apply");
                restamp_payload_keeping_checksum(valid, edited.as_bytes())
            }),
            want_msg: Some(STORE_CHECKSUM_MISMATCH_ERR),
            want_sub: None,
            not_integrity: false,
        });
        rows.push(StoreIntegrityRow {
            // Checksum-VALID envelope, malformed payload: a schema fault.
            name: "inner_payload_malformed",
            body: Box::new(|_, _| rewrap(STORE_ENVELOPE_CHAIN_STATE, b"{not json")),
            want_msg: None,
            want_sub: Some("decode chainstate"),
            not_integrity: true,
        });

        run_store_integrity_rows(
            &path,
            &valid,
            &payload,
            || load_chain_state(&path).map(|_| ()),
            &rows,
        );

        std::fs::write(&path, &valid).expect("restore valid envelope");
        let loaded = load_chain_state(&path).expect("valid envelope must load");
        assert_eq!(
            (loaded.has_tip, loaded.height, loaded.already_generated),
            (true, 9, 4_200)
        );
        // An ABSENT file keeps the fresh-state repair path; a corrupt one cannot.
        std::fs::remove_file(&path).expect("remove chainstate");
        assert_eq!(
            load_chain_state(&path).expect("absent chainstate"),
            ChainState::new()
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_chainstate_rejects_wrong_version() {
        let dir = unique_temp_path("rubin-chainstate-version-test");
        let path = chain_state_path(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        let payload = format!(
            r#"{{"version":999,"has_tip":false,"height":0,"tip_hash":"{}","already_generated":"0","utxos":[]}}"#,
            "00".repeat(32)
        );
        // RUB-1134: planted INSIDE a valid frame, so this row still tests the
        // INNER version check rather than the envelope's legacy verdict.
        std::fs::write(
            &path,
            crate::store_envelope::tests::rewrap(STORE_ENVELOPE_CHAIN_STATE, payload.as_bytes()),
        )
        .expect("write");

        let err = load_chain_state(&path).unwrap_err();
        assert_eq!(err, "CHAINSTATE_SCHEMA: unsupported version 999");
        let mut disk = state_to_disk(&ChainState::new()).expect("disk");
        disk.version = 999;
        assert_eq!(chain_state_from_disk(disk).unwrap_err(), err);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn write_chainstate_payload(path: &std::path::Path, payload: &[u8]) {
        std::fs::write(
            path,
            crate::store_envelope::tests::rewrap(STORE_ENVELOPE_CHAIN_STATE, payload),
        )
        .expect("write wrapped chainstate payload");
    }

    #[test]
    fn chainstate_v1_read_and_v2_u128_round_trip() {
        let dir = unique_temp_path("rubin-chainstate-v2-roundtrip");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = chain_state_path(&dir);
        let v1 = format!(
            r#"{{"tip_hash":"{}","utxos":[],"height":9,"already_generated":18446744073709551615,"version":1,"has_tip":true}}"#,
            "00".repeat(32)
        );
        write_chainstate_payload(&path, v1.as_bytes());
        let mut state = load_chain_state(&path).expect("load v1");
        assert_eq!(state.already_generated, u128::from(u64::MAX));

        let reachable_max = reachable_maximum_accumulated_subsidy();
        state.already_generated = reachable_max;
        state.save(&path).expect("save v2");
        let raw = std::fs::read(&path).expect("read v2");
        let payload = crate::store_envelope::open_store_envelope(STORE_ENVELOPE_CHAIN_STATE, &raw)
            .expect("open v2 envelope");
        let payload_text = String::from_utf8(payload).expect("v2 payload utf8");
        assert!(payload_text.contains("\"version\": 2"), "{payload_text}");
        assert!(
            payload_text.contains("\"already_generated\": \"350965446908158964928367166\""),
            "{payload_text}"
        );
        let loaded = load_chain_state(&path).expect("load v2");
        assert_eq!(loaded.already_generated, reachable_max);

        state.already_generated = u128::MAX;
        state.save(&path).expect("save v2 u128 max");
        let raw = std::fs::read(&path).expect("read v2 u128 max");
        let payload = crate::store_envelope::open_store_envelope(STORE_ENVELOPE_CHAIN_STATE, &raw)
            .expect("open v2 u128 max envelope");
        assert!(String::from_utf8(payload)
            .expect("v2 u128 max payload utf8")
            .contains("\"already_generated\": \"340282366920938463463374607431768211455\""));
        assert_eq!(
            load_chain_state(&path)
                .expect("load v2 u128 max")
                .already_generated,
            u128::MAX
        );

        const CANONICAL_V2_PAYLOAD: &str = r#"{
  "tip_hash": "1111111111111111111111111111111111111111111111111111111111111111",
  "utxos": [
    {
      "txid": "2222222222222222222222222222222222222222222222222222222222222222",
      "covenant_data": "aabb",
      "value": 9,
      "creation_height": 5,
      "vout": 3,
      "covenant_type": 1,
      "created_by_coinbase": false
    }
  ],
  "height": 7,
  "already_generated": "18446744073709551615",
  "version": 2,
  "has_tip": true
}
"#;
        const CANONICAL_V2_ENVELOPE: &str = r#"{"version":1,"payload_b64":"ewogICJ0aXBfaGFzaCI6ICIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwKICAidXR4b3MiOiBbCiAgICB7CiAgICAgICJ0eGlkIjogIjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLAogICAgICAiY292ZW5hbnRfZGF0YSI6ICJhYWJiIiwKICAgICAgInZhbHVlIjogOSwKICAgICAgImNyZWF0aW9uX2hlaWdodCI6IDUsCiAgICAgICJ2b3V0IjogMywKICAgICAgImNvdmVuYW50X3R5cGUiOiAxLAogICAgICAiY3JlYXRlZF9ieV9jb2luYmFzZSI6IGZhbHNlCiAgICB9CiAgXSwKICAiaGVpZ2h0IjogNywKICAiYWxyZWFkeV9nZW5lcmF0ZWQiOiAiMTg0NDY3NDQwNzM3MDk1NTE2MTUiLAogICJ2ZXJzaW9uIjogMiwKICAiaGFzX3RpcCI6IHRydWUKfQo=","checksum":"30b3867741b76acdc408c8e668a5c015dec9660a4403df4cdb8451f0379c737b"}
"#;
        const HISTORICAL_GO_V1: &str = r#"{"tip_hash":"1111111111111111111111111111111111111111111111111111111111111111","utxos":[{"txid":"2222222222222222222222222222222222222222222222222222222222222222","covenant_data":"aabb","value":9,"creation_height":5,"vout":3,"covenant_type":1,"created_by_coinbase":false}],"height":7,"already_generated":18446744073709551615,"version":1,"has_tip":true}"#;
        const HISTORICAL_RUST_V1: &str = r#"{"version":1,"has_tip":true,"height":7,"tip_hash":"1111111111111111111111111111111111111111111111111111111111111111","already_generated":18446744073709551615,"utxos":[{"txid":"2222222222222222222222222222222222222222222222222222222222222222","vout":3,"value":9,"covenant_type":1,"covenant_data":"aabb","creation_height":5,"created_by_coinbase":false}]}"#;
        let mut expected = ChainState {
            has_tip: true,
            height: 7,
            tip_hash: [0x11; 32],
            already_generated: u128::from(u64::MAX),
            utxos: HashMap::new(),
        };
        expected.utxos.insert(
            Outpoint {
                txid: [0x22; 32],
                vout: 3,
            },
            UtxoEntry {
                value: 9,
                covenant_type: 1,
                covenant_data: vec![0xaa, 0xbb],
                creation_height: 5,
                created_by_coinbase: false,
            },
        );
        expected.save(&path).expect("save canonical v2");
        assert_eq!(
            std::fs::read(&path).expect("read canonical v2"),
            CANONICAL_V2_ENVELOPE.as_bytes()
        );
        assert_eq!(
            crate::store_envelope::open_store_envelope(
                STORE_ENVELOPE_CHAIN_STATE,
                CANONICAL_V2_ENVELOPE.as_bytes(),
            )
            .expect("open canonical v2"),
            CANONICAL_V2_PAYLOAD.as_bytes()
        );
        for (name, raw, enveloped) in [
            ("canonical_v2", CANONICAL_V2_ENVELOPE, true),
            ("historical_go_v1", HISTORICAL_GO_V1, false),
            ("historical_rust_v1", HISTORICAL_RUST_V1, false),
        ] {
            if enveloped {
                std::fs::write(&path, raw).expect("seed canonical envelope");
            } else {
                write_chainstate_payload(&path, raw.as_bytes());
            }
            let before = std::fs::read(&path).expect("read before load");
            let loaded =
                load_chain_state(&path).unwrap_or_else(|error| panic!("load {name}: {error}"));
            assert_eq!(loaded, expected, "{name}");
            assert_eq!(
                std::fs::read(&path).expect("read after load"),
                before,
                "{name}"
            );
            loaded
                .save(&path)
                .unwrap_or_else(|error| panic!("save {name}: {error}"));
            assert_eq!(
                std::fs::read(&path).expect("read migrated v2"),
                CANONICAL_V2_ENVELOPE.as_bytes(),
                "{name}"
            );
        }
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn chainstate_schema_errors_are_exact_and_version_precedes_supply() {
        let non_object = "decode chainstate: top-level value must be an object";
        let mut cases: Vec<(&str, String, &str)> = [
            ("top_level_non_object", "[]", non_object),
            ("top_level_non_object_trailing", "[]{}", non_object),
            ("missing_version", "{}", CHAINSTATE_MISSING_VERSION),
            (
                "null_version",
                r#"{"version":null,"already_generated":"bad"}"#,
                CHAINSTATE_MISSING_VERSION,
            ),
            (
                "null_duplicate_version",
                r#"{"version":null,"version":2,"already_generated":"0"}"#,
                CHAINSTATE_MISSING_VERSION,
            ),
            (
                "duplicate_version",
                r#"{"version":2,"version":2,"already_generated":null}"#,
                CHAINSTATE_DUPLICATE_VERSION,
            ),
            (
                "duplicate_version_later_extreme",
                r#"{"version":2,"version":1e400,"already_generated":"0"}"#,
                CHAINSTATE_DUPLICATE_VERSION,
            ),
            (
                "null_version_later_extreme",
                r#"{"version":null,"version":1e400,"already_generated":"0"}"#,
                CHAINSTATE_MISSING_VERSION,
            ),
            (
                "extreme_version_then_duplicate",
                r#"{"version":1e400,"version":2,"already_generated":"0"}"#,
                CHAINSTATE_DUPLICATE_VERSION,
            ),
            (
                "extreme_version_then_null",
                r#"{"version":1e400,"version":null,"already_generated":"0","has_tip":false,"height":0,"tip_hash":"0000000000000000000000000000000000000000000000000000000000000000","utxos":[]}"#,
                CHAINSTATE_MISSING_VERSION,
            ),
            (
                "invalid_version_before_supply",
                r#"{"version":"2","already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "supply_first_invalid_version",
                r#"{"already_generated":null,"version":"2"}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "bool_version_before_supply",
                r#"{"version":false,"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "array_version_before_supply",
                r#"{"version":[],"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "object_version_before_supply",
                r#"{"version":{},"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "negative_version_before_supply",
                r#"{"version":-1,"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "fractional_version_before_supply",
                r#"{"version":2.0,"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "exponent_version_before_supply",
                r#"{"version":2e0,"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "extreme_exponent_version_before_supply",
                r#"{"version":1e400,"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "version_range_before_supply",
                r#"{"version":4294967296,"already_generated":null}"#,
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "unsupported_before_supply",
                r#"{"version":3,"already_generated":null}"#,
                "CHAINSTATE_SCHEMA: unsupported version 3",
            ),
            (
                "missing_supply",
                r#"{"version":2}"#,
                CHAINSTATE_MISSING_SUPPLY,
            ),
            (
                "null_supply",
                r#"{"version":2,"already_generated":null}"#,
                CHAINSTATE_MISSING_SUPPLY,
            ),
            (
                "null_duplicate_supply",
                r#"{"version":2,"already_generated":null,"already_generated":"0"}"#,
                CHAINSTATE_MISSING_SUPPLY,
            ),
            (
                "duplicate_supply",
                r#"{"version":2,"already_generated":"0","already_generated":"0"}"#,
                CHAINSTATE_DUPLICATE_SUPPLY,
            ),
            (
                "duplicate_supply_later_extreme",
                r#"{"version":2,"already_generated":"0","already_generated":1e400}"#,
                CHAINSTATE_DUPLICATE_SUPPLY,
            ),
            (
                "null_supply_later_extreme",
                r#"{"version":2,"already_generated":null,"already_generated":1e400}"#,
                CHAINSTATE_MISSING_SUPPLY,
            ),
            (
                "extreme_supply_then_duplicate",
                r#"{"version":2,"already_generated":1e400,"already_generated":"0"}"#,
                CHAINSTATE_DUPLICATE_SUPPLY,
            ),
            (
                "extreme_supply_then_null",
                r#"{"version":2,"already_generated":1e400,"already_generated":null,"has_tip":false,"height":0,"tip_hash":"0000000000000000000000000000000000000000000000000000000000000000","utxos":[]}"#,
                CHAINSTATE_MISSING_SUPPLY,
            ),
            (
                "v1_string",
                r#"{"version":1,"already_generated":"0"}"#,
                CHAINSTATE_INVALID_V1_SUPPLY,
            ),
            (
                "v1_negative",
                r#"{"version":1,"already_generated":-1}"#,
                CHAINSTATE_INVALID_V1_SUPPLY,
            ),
            (
                "v1_fraction",
                r#"{"version":1,"already_generated":0.0}"#,
                CHAINSTATE_INVALID_V1_SUPPLY,
            ),
            (
                "v1_overflow",
                r#"{"version":1,"already_generated":18446744073709551616}"#,
                CHAINSTATE_INVALID_V1_SUPPLY,
            ),
            (
                "v1_extreme_exponent",
                r#"{"version":1,"already_generated":1e400}"#,
                CHAINSTATE_INVALID_V1_SUPPLY,
            ),
            (
                "v2_number",
                r#"{"version":2,"already_generated":0}"#,
                CHAINSTATE_INVALID_V2_SUPPLY,
            ),
            (
                "v2_extreme_number",
                r#"{"version":2,"already_generated":1e400}"#,
                CHAINSTATE_INVALID_V2_SUPPLY,
            ),
            (
                "remaining_before_invalid_v2_supply",
                r#"{"height":1e400,"version":2,"already_generated":0}"#,
                CHAINSTATE_INVALID_V2_SUPPLY,
            ),
            (
                "invalid_v2_supply_before_remaining",
                r#"{"version":2,"already_generated":0,"height":1e400}"#,
                CHAINSTATE_INVALID_V2_SUPPLY,
            ),
            (
                "v2_leading_zero",
                r#"{"version":2,"already_generated":"00"}"#,
                CHAINSTATE_INVALID_V2_SUPPLY,
            ),
            (
                "v2_escaped_zero",
                r#"{"version":2,"already_generated":"\u0030"}"#,
                CHAINSTATE_INVALID_V2_SUPPLY,
            ),
            (
                "v2_overflow",
                r#"{"version":2,"already_generated":"340282366920938463463374607431768211456"}"#,
                CHAINSTATE_INVALID_V2_SUPPLY,
            ),
            (
                "empty_object_with_trailing_object",
                r#"{}{}"#,
                "decode chainstate: trailing content",
            ),
        ]
        .into_iter()
        .map(|(name, payload, want)| (name, payload.to_string(), want))
        .collect();

        let zero_hash = "00".repeat(32);
        let valid_utxo = format!(
            r#"{{"txid":"{}","covenant_data":"","value":1,"creation_height":0,"vout":0,"covenant_type":0,"created_by_coinbase":false}}"#,
            "11".repeat(32)
        );
        let wrap_v2 = |utxos: &str| {
            format!(
                r#"{{"tip_hash":"{zero_hash}","utxos":{utxos},"height":0,"already_generated":"0","version":2,"has_tip":false}}"#
            )
        };
        let valid_v2 = wrap_v2("[]");
        cases.extend([
            (
                "remaining_missing",
                valid_v2.replacen(",\"has_tip\":false", "", 1),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "remaining_null",
                valid_v2.replacen("\"has_tip\":false", "\"has_tip\":null", 1),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "remaining_duplicate",
                valid_v2.replacen("\"height\":0", "\"height\":0,\"height\":0", 1),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "remaining_unknown",
                valid_v2.replacen('{', "{\"extra\":0,", 1),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "remaining_wrong_range",
                valid_v2.replacen("\"height\":0", "\"height\":1e400", 1),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxos_null",
                wrap_v2("null"),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxos_non_array",
                wrap_v2("{}"),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxo_non_object",
                wrap_v2("[0]"),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxo_missing",
                wrap_v2(&format!(
                    "[{}]",
                    valid_utxo.replacen(",\"created_by_coinbase\":false", "", 1)
                )),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxo_null",
                wrap_v2(&format!(
                    "[{}]",
                    valid_utxo.replacen(
                        "\"created_by_coinbase\":false",
                        "\"created_by_coinbase\":null",
                        1,
                    )
                )),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxo_duplicate",
                wrap_v2(&format!(
                    "[{}]",
                    valid_utxo.replacen("\"vout\":0", "\"vout\":0,\"vout\":0", 1)
                )),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxo_unknown",
                wrap_v2(&format!(
                    "[{}]",
                    valid_utxo.replacen('}', ",\"extra\":0}", 1)
                )),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxo_wrong_range",
                wrap_v2(&format!(
                    "[{}]",
                    valid_utxo.replacen("\"vout\":0", "\"vout\":4294967296", 1)
                )),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "utxo_wrong_token",
                wrap_v2(&format!(
                    "[{}]",
                    valid_utxo.replacen(
                        "\"created_by_coinbase\":false",
                        "\"created_by_coinbase\":0",
                        1,
                    )
                )),
                CHAINSTATE_PAYLOAD_NOT_CANONICAL,
            ),
            (
                "mixed_invalid_targets_and_remaining",
                valid_v2
                    .replacen("\"version\":2", "\"version\":\"2\"", 1)
                    .replacen("\"already_generated\":\"0\"", "\"already_generated\":0", 1)
                    .replacen("\"height\":0", "\"height\":1e400", 1),
                CHAINSTATE_INVALID_VERSION,
            ),
            (
                "malformed_trailing_content",
                valid_v2.clone() + "x",
                "decode chainstate: trailing content",
            ),
        ]);

        let nonempty_utxo =
            valid_utxo.replacen("\"covenant_data\":\"\"", "\"covenant_data\":\"aa\"", 1);
        for (names, payload, value) in [
            (
                [
                    "tip_hash_leading",
                    "tip_hash_trailing",
                    "tip_hash_vertical_tab",
                ],
                valid_v2.clone(),
                zero_hash.clone(),
            ),
            (
                [
                    "utxo_txid_leading",
                    "utxo_txid_trailing",
                    "utxo_txid_vertical_tab",
                ],
                wrap_v2(&format!("[{valid_utxo}]")),
                "11".repeat(32),
            ),
            (
                [
                    "utxo_covenant_leading",
                    "utxo_covenant_trailing",
                    "utxo_covenant_vertical_tab",
                ],
                wrap_v2(&format!("[{nonempty_utxo}]")),
                "aa".to_string(),
            ),
        ] {
            for (name, replacement) in names.into_iter().zip([
                format!(" {value}"),
                format!("{value} "),
                format!("\\u000b{value}"),
            ]) {
                cases.push((
                    name,
                    payload.replacen(&value, &replacement, 1),
                    CHAINSTATE_PAYLOAD_NOT_CANONICAL,
                ));
            }
        }

        for (name, payload, want) in cases {
            let dir = unique_temp_path(&format!("rubin-chainstate-schema-{name}"));
            std::fs::create_dir_all(&dir).expect("mkdir");
            let path = chain_state_path(&dir);
            write_chainstate_payload(&path, payload.as_bytes());
            assert_eq!(load_chain_state(&path).unwrap_err(), want, "{name}");
            std::fs::remove_dir_all(&dir).expect("cleanup");
        }

        let dir = unique_temp_path("rubin-chainstate-schema-trailing");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = chain_state_path(&dir);
        let trailing = format!(
            r#"{{"version":2,"already_generated":"0","has_tip":false,"height":0,"tip_hash":"{}","utxos":[]}}{{}}"#,
            "00".repeat(32)
        );
        write_chainstate_payload(&path, trailing.as_bytes());
        assert_eq!(
            load_chain_state(&path).unwrap_err(),
            "decode chainstate: trailing content"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn chainstate_connect_block_rejects_wrong_non_zero_genesis_chain_id() {
        let mut st = ChainState::new();
        let err = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                [0x11; 32],
            )
            .unwrap_err();
        assert_eq!(err, "genesis chain_id mismatch");
        assert_eq!(st, ChainState::new());
    }

    #[test]
    fn chainstate_connect_block_accepts_zero_chain_id_at_genesis() {
        let mut st = ChainState::new();
        let summary = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                [0u8; 32],
            )
            .expect("connect genesis");
        assert_eq!(summary.block_height, 0);
        assert_eq!(summary.already_generated, 0);
        assert_eq!(summary.already_generated_n1, 0);
        assert_eq!(
            hex::encode(st.state_digest()),
            GENESIS_ONLY_STATE_DIGEST_HEX
        );
    }

    #[test]
    fn chainstate_connect_block_accepts_expected_non_zero_genesis_chain_id() {
        let mut st = ChainState::new();
        let summary = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                devnet_genesis_chain_id(),
            )
            .expect("connect genesis");
        assert_eq!(summary.block_height, 0);
        assert!(st.has_tip);
    }

    #[test]
    fn chainstate_state_digest_matches_genesis_plus_height_one_parity_vector() {
        let mut st = ChainState::new();
        let genesis_summary = st
            .connect_block(
                &devnet_genesis_block_bytes(),
                Some(POW_LIMIT),
                None,
                [0u8; 32],
            )
            .expect("connect genesis");
        let parsed_genesis =
            parse_block_bytes(&devnet_genesis_block_bytes()).expect("parse genesis block");
        let genesis_hash = block_hash(&parsed_genesis.header_bytes).expect("genesis hash");
        assert_eq!(genesis_summary.block_hash, genesis_hash);
        assert_eq!(
            hex::encode(st.state_digest()),
            GENESIS_ONLY_STATE_DIGEST_HEX
        );

        let block1 = height_one_coinbase_only_block(genesis_hash);
        let summary = st
            .connect_block(&block1, Some(POW_LIMIT), None, [0u8; 32])
            .expect("connect height 1");
        // The connect entry point mints NO canonical-applied record: connecting
        // to an in-memory chain state is not a canonical-application event, and
        // the reorg preview and startup replay both land here. Only the
        // SyncEngine canonical-apply site populates this field.
        assert!(
            summary.canonical_applied_blocks.is_empty(),
            "the connect layer must not report canonical-applied blocks"
        );
        assert_eq!(summary.block_height, 1);
        assert_eq!(summary.already_generated, 0);
        assert_eq!(
            summary.already_generated_n1,
            u128::from(block_subsidy(1, 0))
        );
        assert_eq!(st.already_generated, u128::from(block_subsidy(1, 0)));
        assert_eq!(
            hex::encode(st.state_digest()),
            GENESIS_PLUS_HEIGHT_ONE_STATE_DIGEST_HEX
        );
    }

    #[test]
    fn chainstate_supply_preserves_full_u128_in_state_and_summary() {
        for supply in [
            0,
            u128::from(u64::MAX),
            u128::from(u64::MAX) + 1,
            reachable_maximum_accumulated_subsidy(),
            u128::MAX,
        ] {
            let mut state = nonzero_chainstate_for_supply_overflow();
            let mut work_utxos = HashMap::new();
            work_utxos.insert(
                Outpoint {
                    txid: [0x99; 32],
                    vout: 1,
                },
                UtxoEntry {
                    value: 1,
                    covenant_type: 0,
                    covenant_data: vec![0x98],
                    creation_height: 42,
                    created_by_coinbase: true,
                },
            );

            let result = apply_connected_block(
                &mut state,
                42,
                [0x97; 32],
                InMemoryChainState {
                    utxos: work_utxos,
                    already_generated: supply,
                },
                connect_summary_with_supply(supply, supply),
            )
            .expect("u128 supply must not narrow");

            assert_eq!(result.already_generated, supply);
            assert_eq!(result.already_generated_n1, supply);
            assert_eq!(state.already_generated, supply);
        }
    }

    #[test]
    fn chainstate_connect_supply_overflow_preserves_nonzero_state() {
        const FIRST_TAIL_SUBSIDY_HEIGHT: u64 = 5_771_107;

        let mut state = nonzero_chainstate_for_supply_overflow();
        state.height = FIRST_TAIL_SUBSIDY_HEIGHT - 1;
        state.tip_hash = [0x55; 32];
        state.already_generated = u128::MAX;
        let before = state.clone();
        let block =
            coinbase_only_block_with_supply(FIRST_TAIL_SUBSIDY_HEIGHT, u128::MAX, state.tip_hash);

        let result = state.connect_block(&block, Some(POW_LIMIT), None, [0u8; 32]);

        assert_eq!(
            result.unwrap_err(),
            "BLOCK_ERR_PARSE: already_generated overflow"
        );
        assert_eq!(state, before);
    }

    /// RUB-1127: the reader contract for the shared widened `expect_sum_fees`
    /// field, driven through the real `DevnetConnectBlockVector` deserializer
    /// on the real fixture bytes.
    ///
    /// Every row mirrors `exact_uint` in conformance/runner/run_cv_bundle.py,
    /// which reads this same field of these same fixtures, and Go
    /// `consensus.Uint128.UnmarshalJSON`: a legacy numeric token is accepted
    /// only through u64, the canonical decimal string form through u128, and
    /// every other spelling is a fixture defect.
    #[test]
    fn devnet_expect_sum_fees_reads_the_canonical_json_contract() {
        fn read(token: &str) -> Option<u128> {
            const NEEDLE: &str = "\"expect_sum_fees\": 0";
            assert_eq!(
                DEVNET_GENESIS_FIXTURE_JSON.matches(NEEDLE).count(),
                1,
                "fixture no longer carries exactly one {NEEDLE} to splice"
            );
            let patched = DEVNET_GENESIS_FIXTURE_JSON
                .replace(NEEDLE, &format!("\"expect_sum_fees\": {token}"));
            serde_json::from_str::<FixtureFile<DevnetConnectBlockVector>>(&patched)
                .ok()
                .and_then(|doc| doc.vectors.into_iter().next())
                .map(|v| v.expect_sum_fees)
        }

        // Legacy numeric token: accepted only through u64.
        assert_eq!(read("0"), Some(0));
        assert_eq!(read("18446744073709551615"), Some(u128::from(u64::MAX)));
        assert_eq!(read("18446744073709551616"), None);

        // Canonical decimal string: accepted through u128.
        assert_eq!(read("\"0\""), Some(0));
        assert_eq!(read("\"18446744073709551616\""), Some(1u128 << 64));
        assert_eq!(
            read("\"340282366920938463463374607431768211455\""),
            Some(u128::MAX)
        );

        // Every other spelling is rejected.
        for bad in [
            "-1",
            "1.0",
            "\"\"",
            "\"00\"",
            "\"01\"",
            "\"+1\"",
            "\"-1\"",
            "\" 1\"",
            "\"1 \"",
            "\"1.0\"",
            "\"1e3\"",
            // u128 max + 1
            "\"340282366920938463463374607431768211456\"",
        ] {
            assert_eq!(read(bad), None, "accepted {bad}");
        }
    }

    #[test]
    fn chainstate_replays_devnet_genesis_fixture() {
        assert!(!DEVNET_GENESIS_FIXTURE_JSON.contains("\\u"));
        let fixture: FixtureFile<DevnetConnectBlockVector> =
            serde_json::from_str(DEVNET_GENESIS_FIXTURE_JSON).expect("parse genesis fixture");
        let vector = fixture
            .vectors
            .into_iter()
            .next()
            .expect("genesis fixture vector");
        assert!(vector.expect_ok, "{} should be positive fixture", vector.id);

        let mut st = chainstate_from_connect_fixture(&vector);
        let block_bytes = hex::decode(&vector.block_hex).expect("genesis block hex");
        let summary = st
            .connect_block(
                &block_bytes,
                Some(parse_hex32_test("expected_target", &vector.expected_target)),
                None,
                parse_hex32_test("chain_id", &vector.chain_id),
            )
            .expect("connect genesis fixture");

        assert_eq!(summary.block_height, vector.height, "{}", vector.id);
        assert_eq!(summary.sum_fees, vector.expect_sum_fees, "{}", vector.id);
        assert_eq!(
            summary.utxo_count, vector.expect_utxo_count,
            "{}",
            vector.id
        );
        assert_eq!(
            summary.already_generated, vector.expect_already_generated,
            "{}",
            vector.id
        );
        assert_eq!(
            summary.already_generated_n1, vector.expect_already_generated_n1,
            "{}",
            vector.id
        );
        assert_eq!(
            hex::encode(summary.block_hash),
            vector.block_hash,
            "{}",
            vector.id
        );

        let expected_state = vector.chainstate_after.expect("genesis chainstate_after");
        let loaded = load_fixture_chainstate(&vector.id, &expected_state);
        assert_eq!(loaded, st, "{} production load versus replay", vector.id);
        assert_eq!(st, fixture_chainstate(&expected_state), "{}", vector.id);
    }

    #[test]
    fn chainstate_loads_devnet_chain_snapshots() {
        assert!(!DEVNET_CHAIN_FIXTURE_JSON.contains("\\u"));
        let fixture: FixtureFile<DevnetConnectBlockVector> =
            serde_json::from_str(DEVNET_CHAIN_FIXTURE_JSON).expect("parse chain fixture");
        assert_eq!(fixture.vectors.len(), 10, "chain fixture vector count");
        for vector in &fixture.vectors {
            let expected = vector.chainstate_after.as_ref().expect("chainstate_after");
            let loaded = load_fixture_chainstate(&vector.id, expected);
            assert!(!loaded.utxos.is_empty(), "{} empty snapshot", vector.id);
            assert_eq!(loaded, fixture_chainstate(expected), "{}", vector.id);
        }
    }

    #[test]
    fn chainstate_replays_devnet_subsidy_vectors() {
        let fixture: FixtureFile<DevnetConnectBlockVector> =
            serde_json::from_str(DEVNET_SUBSIDY_FIXTURE_JSON).expect("parse subsidy fixture");

        for vector in fixture.vectors {
            assert!(vector.expect_ok, "{} should be positive fixture", vector.id);
            let mut st = chainstate_from_connect_fixture(&vector);
            let block_bytes = hex::decode(&vector.block_hex).expect("subsidy block hex");
            let summary = st
                .connect_block(
                    &block_bytes,
                    Some(parse_hex32_test("expected_target", &vector.expected_target)),
                    Some(vector.prev_timestamps.as_slice()),
                    parse_hex32_test("chain_id", &vector.chain_id),
                )
                .unwrap_or_else(|e| panic!("{} connect_block failed: {e}", vector.id));

            assert_eq!(summary.block_height, vector.height, "{}", vector.id);
            assert_eq!(summary.sum_fees, vector.expect_sum_fees, "{}", vector.id);
            assert_eq!(
                summary.utxo_count, vector.expect_utxo_count,
                "{}",
                vector.id
            );
            assert_eq!(
                summary.already_generated, vector.expect_already_generated,
                "{}",
                vector.id
            );
            assert_eq!(
                summary.already_generated_n1, vector.expect_already_generated_n1,
                "{}",
                vector.id
            );
            assert_eq!(
                hex::encode(summary.block_hash),
                vector.block_hash,
                "{}",
                vector.id
            );
            assert_eq!(st.height, vector.height, "{}", vector.id);
            assert_eq!(st.tip_hash, summary.block_hash, "{}", vector.id);
            assert_eq!(
                st.already_generated, vector.expect_already_generated_n1,
                "{}",
                vector.id
            );
            assert_eq!(
                st.utxos.len() as u64,
                vector.expect_utxo_count,
                "{}",
                vector.id
            );
        }
    }

    #[test]
    fn chainstate_replays_devnet_maturity_fixture() {
        let fixture: FixtureFile<DevnetMaturityVector> =
            serde_json::from_str(DEVNET_MATURITY_FIXTURE_JSON).expect("parse maturity fixture");
        let vector = fixture
            .vectors
            .into_iter()
            .next()
            .expect("maturity fixture vector");
        assert!(
            !vector.expect_ok,
            "{} should be negative fixture",
            vector.id
        );

        let tx_bytes = hex::decode(&vector.tx_hex).expect("maturity tx hex");
        let (tx, txid, _, consumed) = parse_tx(&tx_bytes).expect("parse maturity tx");
        assert_eq!(consumed, tx_bytes.len(), "{}", vector.id);

        let err = apply_non_coinbase_tx_basic_with_mtp(
            &tx,
            txid,
            &fixture_utxos_to_map(&vector.utxos),
            vector.height,
            vector.block_timestamp,
            vector.block_timestamp,
            parse_hex32_test("chain_id", &vector.chain_id),
        )
        .expect_err("maturity fixture must reject");
        assert_eq!(err.code.as_str(), vector.expect_err, "{}", vector.id);
    }

    // ---------- E.9: Rust UTXO defensive-copy helper twin (Go parity) ----------
    //
    // These tests pin the contract that mirrors `copyUtxoEntry`,
    // `copyUtxoSet`, and the snapshot-isolation invariants in
    // `clients/go/node/chainstate.go`.

    fn sample_entry(value: u64, covenant_byte: u8) -> UtxoEntry {
        UtxoEntry {
            value,
            covenant_type: 0x0001,
            covenant_data: vec![covenant_byte; 4],
            creation_height: 7,
            created_by_coinbase: false,
        }
    }

    fn sample_outpoint(byte: u8) -> Outpoint {
        Outpoint {
            txid: [byte; 32],
            vout: 0,
        }
    }

    #[test]
    fn copy_utxo_entry_deep_copies_covenant_data() {
        // Mutating the copy's covenant_data must not touch the source.
        let src = sample_entry(100, 0xAA);
        let mut dst = copy_utxo_entry(&src);
        dst.covenant_data[0] = 0xFF;
        dst.value = 999;
        assert_eq!(src.covenant_data, vec![0xAA; 4]);
        assert_eq!(src.value, 100);
    }

    #[test]
    fn copy_utxo_set_deep_copies_all_entries() {
        let mut src = HashMap::new();
        src.insert(sample_outpoint(1), sample_entry(10, 0x11));
        src.insert(sample_outpoint(2), sample_entry(20, 0x22));

        let mut dst = copy_utxo_set(&src);
        // Mutate every entry in the copy.
        for entry in dst.values_mut() {
            entry.covenant_data[0] = 0x00;
            entry.value = 0;
        }
        // Insert a new entry into the copy; canonical map must be unaffected.
        dst.insert(sample_outpoint(3), sample_entry(30, 0x33));

        assert_eq!(src.len(), 2);
        assert_eq!(src[&sample_outpoint(1)].covenant_data, vec![0x11; 4]);
        assert_eq!(src[&sample_outpoint(1)].value, 10);
        assert_eq!(src[&sample_outpoint(2)].covenant_data, vec![0x22; 4]);
        assert_eq!(src[&sample_outpoint(2)].value, 20);
        assert!(!src.contains_key(&sample_outpoint(3)));
    }

    #[test]
    fn lookup_utxo_owned_returns_none_for_missing_outpoint() {
        // Mirrors the Go twin's presence-check / skip-missing semantics
        // for absent UTXOs (cf. `copySelectedUtxoSet` in
        // `clients/go/node/chainstate.go`, which uses `value, ok := m[op]`
        // and skips when `!ok` rather than treating zero-value entries as
        // present).
        let st = ChainState::new();
        assert!(st.lookup_utxo_owned(&sample_outpoint(0xEE)).is_none());
    }

    #[test]
    fn lookup_utxo_owned_returns_owned_copy_caller_mutation_isolated() {
        // Caller mutates the returned entry; canonical map must be unaffected.
        let mut st = ChainState::new();
        let op = sample_outpoint(7);
        st.utxos.insert(op.clone(), sample_entry(500, 0xBB));

        let mut owned = st.lookup_utxo_owned(&op).expect("present");
        owned.covenant_data.fill(0x00);
        owned.value = 1;

        let canonical = st.utxos.get(&op).expect("still present");
        assert_eq!(canonical.value, 500);
        assert_eq!(canonical.covenant_data, vec![0xBB; 4]);
    }

    #[test]
    fn lookup_utxo_owned_drop_does_not_leak_or_panic() {
        // Caller drops the copy; canonical map remains intact.
        let mut st = ChainState::new();
        let op = sample_outpoint(9);
        st.utxos.insert(op.clone(), sample_entry(42, 0xCC));
        {
            let owned = st.lookup_utxo_owned(&op).expect("present");
            assert_eq!(owned.value, 42);
        } // owned dropped here
        assert_eq!(st.utxos.get(&op).expect("still present").value, 42);
    }
}

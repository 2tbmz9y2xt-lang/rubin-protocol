use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use rubin_consensus::constants::{CHUNK_BYTES, MAX_DA_CHUNK_COUNT};
use rubin_consensus::constants::{COV_TYPE_DA_COMMIT, TX_WIRE_VERSION};
use rubin_consensus::{parse_block_bytes, parse_tx, Tx, TxError};
use sha3::{Digest, Sha3_256};

pub const DA_ORPHAN_POOL_BYTES: u64 = 64 << 20;
pub const DA_ORPHAN_POOL_PER_PEER_BYTES: u64 = 4 << 20;
pub const DA_ORPHAN_POOL_PER_DA_ID_BYTES: u64 = 8 << 20;
pub const DA_ORPHAN_COMMIT_OVERHEAD_BYTES: u64 = 8 << 20;
pub const DA_ORPHAN_TTL_BLOCKS: u64 = 3;
pub const DA_PINNED_PAYLOAD_BYTES: u64 = 96_000_000;
const DA_COMPLETE_SET_RECORD_FOOTPRINT: u64 = 256;
const DA_COMPLETE_SET_CHUNK_FOOTPRINT: u64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaRelayCaps {
    orphan_pool_bytes: u64,
    orphan_pool_per_peer_bytes: u64,
    orphan_pool_per_da_id_bytes: u64,
    orphan_commit_overhead_bytes: u64,
    orphan_ttl_blocks: u64,
    pinned_payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaRelayError {
    InvalidCaps,
    AccountingUnderflow,
    AccountingOverflow,
    AccountingCapExceeded,
    DuplicateCommit,
    DuplicateChunk,
    InvalidCommitChunkCount,
    InvalidWireBytes,
    ChunkIndexOutOfRange,
    ChunkIndexOutsideCommit,
    ChunkPayloadSizeInvalid,
    ChunkHashMismatch,
    PayloadCommitmentMismatch,
}

type DaRelayResult<T = ()> = Result<T, DaRelayError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DaRelaySetState {
    OrphanChunks,
    StagedCommit,
    CompleteSet,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaRelayCommit {
    da_id: [u8; 32],
    payload_commitment: [u8; 32],
    peer_quota_key: PeerQuotaKey,
    chunk_count: u16,
    wire_bytes: u64,
    tx_bytes: Arc<[u8]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaRelayChunk {
    da_id: [u8; 32],
    chunk_hash: [u8; 32],
    peer_quota_key: PeerQuotaKey,
    chunk_index: u16,
    payload: Arc<[u8]>,
    wire_bytes: u64,
    tx_bytes: Arc<[u8]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaRelaySetRecord {
    da_id: [u8; 32],
    state: DaRelaySetState,
    received_time: u64,
    payload_bytes: u64,
    ttl_blocks_remaining: u64,
    wire_bytes: u64,
    peer_bytes: BTreeMap<PeerQuotaKey, u64>,
    commit: Option<DaRelayCommit>,
    chunks: BTreeMap<u16, DaRelayChunk>,
    replaceable_chunks: BTreeSet<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DaRelayEvictionAccounting {
    pub(crate) da_id: [u8; 32],
    pub(crate) payload_bytes: u64,
    pub(crate) wire_bytes: u64,
    pub(crate) received_time: u64,
}

struct DaRelayTtlExpiryProjection {
    orphan_bytes: u64,
    orphan_commit_overhead_bytes: u64,
    peer_bytes: Vec<(PeerQuotaKey, u64)>,
    da_id_bytes: Vec<([u8; 32], u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerQuotaKey(String);

/// Caller-owned snapshot of one relay-complete DA set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteDaSetCandidate {
    pub da_id: [u8; 32],
    pub payload_bytes: u64,
    pub commit_tx: Vec<u8>,
    pub chunks: Vec<CompleteDaSetChunkCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompleteDaSetChunkCandidate {
    pub index: u16,
    pub tx: Vec<u8>,
}

pub trait CompleteDaSetProvider {
    fn complete_da_set_candidates(&self, max_payload_bytes: u64) -> Vec<CompleteDaSetCandidate>;
}

/// Foundation container; future mutation paths need exclusive access or owner-side synchronization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaRelayState {
    caps: DaRelayCaps,
    next_received_time: u64,
    orphan_bytes: u64,
    orphan_bytes_by_peer_quota_key: BTreeMap<PeerQuotaKey, u64>,
    orphan_bytes_by_da_id: BTreeMap<[u8; 32], u64>,
    orphan_commit_overhead_bytes: u64,
    pinned_payload_bytes: u64,
    sets_by_da_id: BTreeMap<[u8; 32], DaRelaySetRecord>,
}

impl Default for DaRelayCaps {
    fn default() -> Self {
        Self {
            orphan_pool_bytes: DA_ORPHAN_POOL_BYTES,
            orphan_pool_per_peer_bytes: DA_ORPHAN_POOL_PER_PEER_BYTES,
            orphan_pool_per_da_id_bytes: DA_ORPHAN_POOL_PER_DA_ID_BYTES,
            orphan_commit_overhead_bytes: DA_ORPHAN_COMMIT_OVERHEAD_BYTES,
            orphan_ttl_blocks: DA_ORPHAN_TTL_BLOCKS,
            pinned_payload_bytes: DA_PINNED_PAYLOAD_BYTES,
        }
    }
}

impl DaRelayCaps {
    pub fn validate(self) -> Result<(), DaRelayError> {
        if [
            self.orphan_pool_bytes,
            self.orphan_pool_per_peer_bytes,
            self.orphan_pool_per_da_id_bytes,
            self.orphan_commit_overhead_bytes,
            self.orphan_ttl_blocks,
            self.pinned_payload_bytes,
        ]
        .contains(&0)
            || self.orphan_pool_per_peer_bytes > self.orphan_pool_bytes
            || self.orphan_pool_per_da_id_bytes > self.orphan_pool_bytes
            || self.orphan_commit_overhead_bytes > self.orphan_pool_bytes
        {
            return Err(DaRelayError::InvalidCaps);
        }
        Ok(())
    }
}

impl PeerQuotaKey {
    pub fn from_peer_addr(addr: &str) -> Self {
        if addr.is_empty() {
            return Self(String::new());
        }
        Self(normalize_peer_host(split_peer_host(addr)))
    }

    /// The host-only quota key string (used by DA prefetch peer enumeration to
    /// build the quota-key -> addr map).
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

fn split_peer_host(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, port)) = rest.rsplit_once("]:") {
            if !host.contains(['[', ']']) && !port.contains(':') && !port.contains(['[', ']']) {
                return host;
            }
        }
        return addr;
    }
    if let Some((host, _port)) = addr.rsplit_once(':').filter(|(host, port)| {
        !host.contains(':') && !host.contains(['[', ']']) && !port.contains(['[', ']'])
    }) {
        return host;
    }
    addr
}

fn normalize_peer_host(host: &str) -> String {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.to_string();
    }
    if let Some((without_zone, _zone)) = host.split_once('%').filter(|(_, zone)| !zone.is_empty()) {
        if let Ok(ip) = without_zone.parse::<Ipv6Addr>() {
            return ip.to_string();
        }
    }
    host.to_owned()
}

#[allow(dead_code)]
impl DaRelaySetRecord {
    fn new(da_id: [u8; 32]) -> Self {
        Self {
            da_id,
            state: DaRelaySetState::OrphanChunks,
            received_time: 0,
            payload_bytes: 0,
            ttl_blocks_remaining: 0,
            wire_bytes: 0,
            peer_bytes: BTreeMap::new(),
            commit: None,
            chunks: BTreeMap::new(),
            replaceable_chunks: BTreeSet::new(),
        }
    }
    fn validate_chunk_insert(&self, chunk_index: u16) -> DaRelayResult {
        if self.chunks.contains_key(&chunk_index) {
            if self.replaceable_chunks.contains(&chunk_index) {
                return Ok(());
            }
            return Err(DaRelayError::DuplicateChunk);
        }
        if let Some(commit) = &self.commit {
            if chunk_index >= commit.chunk_count {
                return Err(DaRelayError::ChunkIndexOutsideCommit);
            }
        }
        Ok(())
    }
    fn prune_chunks_outside_commit(&mut self) {
        if let Some(commit) = &self.commit {
            self.chunks
                .retain(|index, _chunk| *index < commit.chunk_count);
            self.replaceable_chunks
                .retain(|index| *index < commit.chunk_count);
        }
    }
    fn recompute_wire_bytes(&mut self) -> DaRelayResult {
        self.peer_bytes.clear();
        let mut total = 0;
        if let Some(commit) = &self.commit {
            total = retained_tx_accounting_bytes(commit.wire_bytes, &commit.tx_bytes);
            self.peer_bytes.insert(commit.peer_quota_key.clone(), total);
        }
        let peer_bytes = &mut self.peer_bytes;
        for chunk in self.chunks.values() {
            total = checked_add(
                total,
                retained_tx_accounting_bytes(chunk.wire_bytes, &chunk.tx_bytes),
            )?;
            let chunk_bytes = orphan_chunk_accounting_bytes(chunk)?;
            let entry = peer_bytes.entry(chunk.peer_quota_key.clone()).or_default();
            *entry = checked_add(*entry, chunk_bytes)?;
        }
        self.wire_bytes = total;
        Ok(())
    }
    fn completion_snapshot(&self) -> Option<DaRelayCompletionSnapshot> {
        let commit = self.commit.as_ref()?;
        if self.state == DaRelaySetState::CompleteSet {
            return None;
        }
        let mut chunks = Vec::with_capacity(usize::from(commit.chunk_count));
        for index in 0..commit.chunk_count {
            if self.replaceable_chunks.contains(&index) {
                return None;
            }
            let chunk = self.chunks.get(&index)?;
            chunks.push(DaRelayCompletionChunk {
                chunk_index: index,
                chunk_hash: chunk.chunk_hash,
                payload: Arc::clone(&chunk.payload),
            });
        }
        Some(DaRelayCompletionSnapshot {
            payload_commitment_expected: commit.payload_commitment,
            chunks,
        })
    }
    /// The still-missing chunk indexes of this set (mirror of Go
    /// `daRelaySetRecord.missingChunkIndexes`): empty if there is no commit, the
    /// commit declares no chunks, or the set is already complete; otherwise every
    /// index not yet retained, plus any marked replaceable.
    fn missing_chunk_indexes(&self) -> Vec<u16> {
        let Some(commit) = self.commit.as_ref() else {
            return Vec::new();
        };
        if commit.chunk_count == 0 || self.state == DaRelaySetState::CompleteSet {
            return Vec::new();
        }
        (0..commit.chunk_count)
            .filter(|index| {
                !self.chunks.contains_key(index) || self.replaceable_chunks.contains(index)
            })
            .collect()
    }
    fn mark_complete(&mut self, payload_bytes: u64) {
        self.payload_bytes = payload_bytes;
        self.state = DaRelaySetState::CompleteSet;
        self.ttl_blocks_remaining = 0;
        self.replaceable_chunks.clear();
        for chunk in self.chunks.values_mut() {
            chunk.payload = Arc::from([]);
        }
    }
    fn mark_chunks_replaceable(&mut self, indexes: impl IntoIterator<Item = u16>) {
        self.replaceable_chunks.extend(indexes);
    }
    fn orphan_wire_bytes(&self) -> DaRelayResult<u64> {
        if self.state == DaRelaySetState::CompleteSet {
            Ok(0)
        } else {
            self.peer_bytes
                .values()
                .try_fold(0u64, |total, bytes| checked_add(total, *bytes))
        }
    }
    fn orphan_commit_bytes(&self) -> u64 {
        if self.state == DaRelaySetState::CompleteSet {
            0
        } else {
            self.commit.as_ref().map_or(0, |commit| {
                retained_tx_accounting_bytes(commit.wire_bytes, &commit.tx_bytes)
            })
        }
    }
    fn orphan_peer_bytes(&self) -> Option<&BTreeMap<PeerQuotaKey, u64>> {
        (self.state != DaRelaySetState::CompleteSet).then_some(&self.peer_bytes)
    }
    fn without_peer_quota_key(&self, key: &PeerQuotaKey) -> DaRelayResult<Option<Self>> {
        if self.state == DaRelaySetState::CompleteSet || self.wire_bytes == 0 {
            return Ok(None);
        }
        let drop_commit = self
            .commit
            .as_ref()
            .is_some_and(|commit| commit.wire_bytes != 0 && &commit.peer_quota_key == key);
        let indexes = self
            .chunks
            .iter()
            .filter_map(|(index, chunk)| {
                (chunk.wire_bytes != 0 && &chunk.peer_quota_key == key).then_some(*index)
            })
            .collect::<Vec<_>>();
        if !drop_commit && indexes.is_empty() {
            return Ok(None);
        }
        let mut updated = self.clone();
        if drop_commit {
            updated.commit = None;
            updated.replaceable_chunks.clear();
        }
        for index in &indexes {
            updated.chunks.remove(index);
            updated.replaceable_chunks.remove(index);
        }
        updated.payload_bytes = 0;
        if updated.commit.is_none() {
            updated.state = DaRelaySetState::OrphanChunks;
            updated.replaceable_chunks.clear();
        }
        if updated.empty_incomplete() {
            updated.wire_bytes = 0;
            updated.peer_bytes.clear();
            return Ok(Some(updated));
        }
        updated.recompute_wire_bytes()?;
        Ok(Some(updated))
    }
    fn empty_incomplete(&self) -> bool {
        self.state != DaRelaySetState::CompleteSet
            && self.commit.is_none()
            && self.chunks.is_empty()
    }
    fn pinned_payload_accounting_bytes(&self) -> DaRelayResult<u64> {
        if self.state != DaRelaySetState::CompleteSet || self.payload_bytes == 0 {
            return Ok(0);
        }
        let footprint = if self.wire_bytes == 0 {
            self.payload_bytes
        } else {
            self.wire_bytes
        };
        let footprint = checked_add(footprint, DA_COMPLETE_SET_RECORD_FOOTPRINT)?;
        let chunk_count = self.commit.as_ref().map_or(0, |commit| commit.chunk_count);
        let chunk_footprint = u64::from(chunk_count)
            .checked_mul(DA_COMPLETE_SET_CHUNK_FOOTPRINT)
            .ok_or(DaRelayError::AccountingOverflow)?;
        checked_add(footprint, chunk_footprint)
    }

    pub(crate) fn eviction_accounting(&self) -> Option<DaRelayEvictionAccounting> {
        if self.state != DaRelaySetState::CompleteSet
            || self.payload_bytes == 0
            || self.wire_bytes == 0
            || self.received_time == 0
        {
            return None;
        }
        Some(DaRelayEvictionAccounting {
            da_id: self.da_id,
            payload_bytes: self.payload_bytes,
            wire_bytes: self.wire_bytes,
            received_time: self.received_time,
        })
    }

    fn complete_da_set_candidate(&self) -> Option<CompleteDaSetCandidate> {
        if self.state != DaRelaySetState::CompleteSet {
            return None;
        }
        let commit = self.commit.as_ref()?;
        if commit.chunk_count == 0 || commit.tx_bytes.is_empty() {
            return None;
        }
        let mut chunks = Vec::with_capacity(usize::from(commit.chunk_count));
        for index in 0..commit.chunk_count {
            let chunk = self.chunks.get(&index)?;
            if chunk.tx_bytes.is_empty() {
                return None;
            }
            chunks.push(CompleteDaSetChunkCandidate {
                index,
                tx: chunk.tx_bytes.as_ref().to_vec(),
            });
        }
        Some(CompleteDaSetCandidate {
            da_id: self.da_id,
            payload_bytes: self.payload_bytes,
            commit_tx: commit.tx_bytes.as_ref().to_vec(),
            chunks,
        })
    }
}

#[derive(Clone)]
struct DaRelayCompletionSnapshot {
    payload_commitment_expected: [u8; 32],
    chunks: Vec<DaRelayCompletionChunk>,
}

#[derive(Clone)]
struct DaRelayCompletionChunk {
    chunk_index: u16,
    chunk_hash: [u8; 32],
    payload: Arc<[u8]>,
}

impl DaRelayCompletionSnapshot {
    fn payload_commitment(&self) -> DaRelayResult<(u64, [u8; 32])> {
        let mut hasher = Sha3_256::new();
        let mut payload_bytes = 0u64;
        for chunk in &self.chunks {
            payload_bytes = checked_add(payload_bytes, chunk.payload.len() as u64)?;
            hasher.update(chunk.payload.as_ref());
        }
        Ok((payload_bytes, hasher.finalize().into()))
    }
    fn matching_chunk_indexes(&self, record: &DaRelaySetRecord) -> Option<Vec<u16>> {
        let mut indexes = Vec::new();
        for snapshot_chunk in &self.chunks {
            let Some(chunk) = record.chunks.get(&snapshot_chunk.chunk_index) else {
                continue;
            };
            if chunk.chunk_hash != snapshot_chunk.chunk_hash
                || chunk.payload.len() != snapshot_chunk.payload.len()
            {
                return None;
            }
            indexes.push(snapshot_chunk.chunk_index);
        }
        Some(indexes)
    }
}

enum CompletionMismatchAction {
    DropMatchingChunks,
    MarkMatchingChunksReplaceable,
}
#[allow(dead_code)]
impl DaRelayState {
    pub fn new(caps: DaRelayCaps) -> DaRelayResult<Self> {
        caps.validate()?;
        Ok(Self {
            caps,
            next_received_time: 0,
            orphan_bytes: 0,
            orphan_bytes_by_peer_quota_key: BTreeMap::new(),
            orphan_bytes_by_da_id: BTreeMap::new(),
            orphan_commit_overhead_bytes: 0,
            pinned_payload_bytes: 0,
            sets_by_da_id: BTreeMap::new(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.orphan_bytes == 0
            && self.orphan_bytes_by_peer_quota_key.is_empty()
            && self.orphan_bytes_by_da_id.is_empty()
            && self.orphan_commit_overhead_bytes == 0
            && self.pinned_payload_bytes == 0
            && self.sets_by_da_id.is_empty()
    }

    pub(crate) fn validate_relay_da_tx_for_admission(tx_bytes: &[u8]) -> DaRelayResult {
        if relay_da_tx_kind_prefix(tx_bytes) != Some(0x02) {
            return Ok(());
        }
        let (tx, _txid, _wtxid, consumed) =
            parse_tx(tx_bytes).map_err(|_| DaRelayError::InvalidWireBytes)?;
        if consumed != tx_bytes.len() {
            return Err(DaRelayError::InvalidWireBytes);
        }
        let wire_bytes =
            u64::try_from(tx_bytes.len()).map_err(|_| DaRelayError::AccountingOverflow)?;
        validate_relay_da_chunk_for_admission(&tx, wire_bytes)
    }

    /// Still-missing chunk indexes for a DA set, read live by da_id (empty if the
    /// set is absent or complete) — the DA prefetch planner input. Mirror of Go
    /// reading sets[daID].missingChunkIndexes().
    pub(crate) fn missing_chunk_indexes(&self, da_id: [u8; 32]) -> Vec<u16> {
        self.sets_by_da_id
            .get(&da_id)
            .map(DaRelaySetRecord::missing_chunk_indexes)
            .unwrap_or_default()
    }

    #[rustfmt::skip]
    pub(crate) fn stage_relay_da_tx_bytes(&mut self, peer_addr: &str, tx_bytes: Vec<u8>) -> DaRelayResult { self.stage_relay_da_tx_bytes_checked(peer_addr, tx_bytes, false).1 }

    /// Stage a relay DA tx, returning the schedulable da_id with the staging result
    /// from this single parse (so the caller drives `finish_da_prefetch` without a
    /// second `parse_tx`). The da_id is `Some` only for a DA chunk or a commit with a
    /// well-formed DA_COMMIT covenant (mirror of Go `stageRelayDACommitTx` gating
    /// `finishDAPrefetch`); it is returned even on a staging error (e.g. a payload-
    /// commitment mismatch driving a snapshot reschedule).
    #[rustfmt::skip]
    pub(crate) fn stage_relay_da_tx_bytes_checked(&mut self, peer_addr: &str, tx_bytes: Vec<u8>, chunk_hash_prevalidated: bool) -> (Option<[u8; 32]>, DaRelayResult) {
        let Ok(wire_bytes) = u64::try_from(tx_bytes.len()) else { return (None, Err(DaRelayError::AccountingOverflow)); };
        let Ok((tx, _txid, _wtxid, consumed)) = parse_tx(&tx_bytes) else { return (None, Err(DaRelayError::InvalidWireBytes)); };
        if consumed != tx_bytes.len() {
            return (None, Err(DaRelayError::InvalidWireBytes));
        }
        match tx.tx_kind {
            0x01 => {
                let Some(core) = tx.da_commit_core.as_ref() else { return (None, Ok(())); };
                let Some(payload_commitment) = relay_da_commit_payload_commitment(&tx) else { return (None, Ok(())); };
                let da_id = core.da_id;
                let result = self.stage_incomplete_da_commit(
                    peer_addr,
                    DaRelayCommit {
                        da_id,
                        payload_commitment,
                        peer_quota_key: PeerQuotaKey::from_peer_addr(peer_addr),
                        chunk_count: core.chunk_count,
                        wire_bytes,
                        tx_bytes: Arc::from(tx_bytes.into_boxed_slice()),
                    },
                );
                (Some(da_id), result)
            }
            0x02 => {
                let Some(core) = tx.da_chunk_core.as_ref() else { return (None, Ok(())); };
                let da_id = core.da_id;
                let result = self.stage_incomplete_da_chunk_inner(
                    peer_addr,
                    DaRelayChunk {
                        da_id,
                        chunk_hash: core.chunk_hash,
                        peer_quota_key: PeerQuotaKey::from_peer_addr(peer_addr),
                        chunk_index: core.chunk_index,
                        payload: Arc::from(tx.da_payload.into_boxed_slice()),
                        wire_bytes,
                        tx_bytes: Arc::from(tx_bytes.into_boxed_slice()),
                    },
                    chunk_hash_prevalidated,
                );
                (Some(da_id), result)
            }
            _ => (None, Ok(())),
        }
    }

    #[cfg(test)]
    #[rustfmt::skip]
    pub(crate) fn test_record_summary(&self, da_id: [u8; 32]) -> Option<(bool, usize, u64)> { let record = self.sets_by_da_id.get(&da_id)?; Some((record.commit.is_some(), record.chunks.len(), record.wire_bytes)) }

    #[cfg(test)]
    pub(crate) fn test_stage_incomplete_da_commit(
        &mut self,
        peer_addr: &str,
        da_id: [u8; 32],
        chunk_count: u16,
        wire_bytes: u64,
    ) -> DaRelayResult {
        self.stage_incomplete_da_commit(
            peer_addr,
            DaRelayCommit {
                da_id,
                payload_commitment: [0u8; 32],
                peer_quota_key: PeerQuotaKey::from_peer_addr(peer_addr),
                chunk_count,
                wire_bytes,
                tx_bytes: Arc::from([]),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn test_stage_incomplete_da_chunk(
        &mut self,
        peer_addr: &str,
        da_id: [u8; 32],
        chunk_index: u16,
        payload: &[u8],
        wire_bytes: u64,
    ) -> DaRelayResult {
        self.stage_incomplete_da_chunk(
            peer_addr,
            DaRelayChunk {
                da_id,
                chunk_hash: sha3_256(payload),
                peer_quota_key: PeerQuotaKey::from_peer_addr(peer_addr),
                chunk_index,
                payload: Arc::from(payload),
                wire_bytes,
                tx_bytes: Arc::from([]),
            },
        )
    }

    pub(crate) fn complete_set_eviction_candidates(
        &self,
        max_payload_bytes: u64,
    ) -> impl Iterator<Item = DaRelayEvictionAccounting> + '_ {
        let mut payload_bytes = 0u64;
        let limit = if max_payload_bytes == 0 {
            0
        } else {
            usize::MAX
        };
        self.sets_by_da_id
            .values()
            .take(limit)
            .filter_map(move |record| {
                let candidate = record.eviction_accounting()?;
                if candidate.payload_bytes > max_payload_bytes.saturating_sub(payload_bytes) {
                    return None;
                }
                payload_bytes += candidate.payload_bytes;
                Some(candidate)
            })
    }

    pub fn complete_da_set_candidates(
        &self,
        max_payload_bytes: u64,
    ) -> Vec<CompleteDaSetCandidate> {
        if max_payload_bytes == 0 {
            return Vec::new();
        }
        let mut candidates = Vec::new();
        let mut payload_bytes = 0u64;
        for record in self.sets_by_da_id.values() {
            if record.state != DaRelaySetState::CompleteSet {
                continue;
            }
            let Some(next_payload_bytes) = payload_bytes.checked_add(record.payload_bytes) else {
                continue;
            };
            if next_payload_bytes > max_payload_bytes {
                continue;
            }
            let Some(candidate) = record.complete_da_set_candidate() else {
                continue;
            };
            candidates.push(candidate);
            payload_bytes = next_payload_bytes;
        }
        candidates
    }

    pub(crate) fn advance_orphan_ttl(&mut self) -> DaRelayResult<Vec<[u8; 32]>> {
        self.advance_orphan_ttl_by(1)
    }

    pub(crate) fn advance_orphan_ttl_by(&mut self, blocks: usize) -> DaRelayResult<Vec<[u8; 32]>> {
        if blocks == 0 {
            return Ok(Vec::new());
        }
        let blocks = blocks as u64;
        let mut decrementing_da_ids = Vec::new();
        let mut expiring_records = Vec::new();
        for da_id in self.orphan_bytes_by_da_id.keys().copied() {
            let Some(record) = self.sets_by_da_id.get(&da_id) else {
                continue;
            };
            if record.state == DaRelaySetState::CompleteSet {
                continue;
            }
            if record.ttl_blocks_remaining > blocks {
                decrementing_da_ids.push(da_id);
            } else {
                expiring_records.push(record.clone());
            }
        }

        let projection = if expiring_records.is_empty() {
            None
        } else {
            Some(self.project_ttl_expiry(&expiring_records)?)
        };
        let expired = expiring_records
            .iter()
            .map(|record| record.da_id)
            .collect::<Vec<_>>();
        for da_id in decrementing_da_ids {
            let record = self
                .sets_by_da_id
                .get_mut(&da_id)
                .ok_or(DaRelayError::AccountingUnderflow)?;
            record.ttl_blocks_remaining = record
                .ttl_blocks_remaining
                .checked_sub(blocks)
                .ok_or(DaRelayError::AccountingUnderflow)?;
        }
        let Some(projection) = projection else {
            return Ok(Vec::new());
        };
        self.apply_ttl_expiry_projection(projection, expiring_records);
        Ok(expired)
    }

    pub(crate) fn release_peer_quota_key(&mut self, key: &PeerQuotaKey) -> DaRelayResult {
        if matches!(
            self.orphan_bytes_by_peer_quota_key.get(key),
            None | Some(&0)
        ) {
            return Ok(());
        }
        let da_ids: Vec<_> = self.orphan_bytes_by_da_id.keys().copied().collect();
        for da_id in da_ids {
            let updated = {
                let Some(record) = self.sets_by_da_id.get(&da_id) else {
                    continue;
                };
                if record.state == DaRelaySetState::CompleteSet {
                    continue;
                }
                let Some(updated) = record.without_peer_quota_key(key)? else {
                    continue;
                };
                updated
            };
            if updated.empty_incomplete() {
                let old = self
                    .sets_by_da_id
                    .get(&da_id)
                    .cloned()
                    .ok_or(DaRelayError::AccountingUnderflow)?;
                let projection = self.project_ttl_expiry(std::slice::from_ref(&old))?;
                self.apply_ttl_expiry_projection(projection, vec![old]);
            } else {
                self.apply_record(updated)?;
            }
        }
        Ok(())
    }

    /// Consume (remove) the COMPLETE_SET record matching `da_id` exactly once,
    /// releasing its pinned payload accounting. Returns `Ok(true)` when a
    /// complete set was removed, `Ok(false)` when no record exists or it is not
    /// in `CompleteSet` state. Idempotent: a second consume of the same `da_id`
    /// is an `Ok(false)` no-op and cannot underflow accounting. Mirrors merged
    /// Go `daRelayState.consumeCompleteSet` (RUB-428): a complete set contributes
    /// only pinned payload bytes (its orphan/peer/commit accounting was released
    /// on completion), and the release is projected before any mutation so a
    /// projection error leaves the state unchanged.
    pub(crate) fn consume_complete_set(&mut self, da_id: [u8; 32]) -> DaRelayResult<bool> {
        let Some(record) = self.sets_by_da_id.get(&da_id) else {
            return Ok(false);
        };
        if record.state != DaRelaySetState::CompleteSet {
            return Ok(false);
        }
        let pinned = record.pinned_payload_accounting_bytes()?;
        // project_counter returns Err on underflow/overflow/cap; the counter and
        // the record below are written only after it succeeds.
        let pinned_payload_bytes = Self::project_counter(
            self.pinned_payload_bytes,
            pinned,
            0,
            self.caps.pinned_payload_bytes,
        )?;
        self.pinned_payload_bytes = pinned_payload_bytes;
        self.sets_by_da_id.remove(&da_id);
        Ok(true)
    }

    pub(crate) fn stage_incomplete_da_commit(
        &mut self,
        peer_addr: &str,
        mut commit: DaRelayCommit,
    ) -> DaRelayResult {
        if commit.chunk_count == 0 || u64::from(commit.chunk_count) > MAX_DA_CHUNK_COUNT {
            return Err(DaRelayError::InvalidCommitChunkCount);
        }
        if commit.wire_bytes == 0 {
            return Err(DaRelayError::InvalidWireBytes);
        }
        commit.peer_quota_key = PeerQuotaKey::from_peer_addr(peer_addr);
        let old = self.sets_by_da_id.get(&commit.da_id);
        if old.is_some_and(|record| record.commit.is_some()) {
            return Err(DaRelayError::DuplicateCommit);
        }
        let mut record = old
            .cloned()
            .unwrap_or_else(|| DaRelaySetRecord::new(commit.da_id));
        record.commit = Some(commit);
        record.state = DaRelaySetState::StagedCommit;
        record.ttl_blocks_remaining = self.caps.orphan_ttl_blocks;
        record.prune_chunks_outside_commit();
        self.prepare_and_apply_record(record, CompletionMismatchAction::DropMatchingChunks)
    }
    #[rustfmt::skip]
    pub(crate) fn stage_incomplete_da_chunk(&mut self, peer_addr: &str, chunk: DaRelayChunk) -> DaRelayResult { self.stage_incomplete_da_chunk_inner(peer_addr, chunk, false) }
    #[rustfmt::skip]
    fn stage_incomplete_da_chunk_inner(&mut self, peer_addr: &str, chunk: DaRelayChunk, chunk_hash_prevalidated: bool) -> DaRelayResult {
        let mut chunk = chunk;
        validate_da_chunk(&chunk)?;
        let current = self.sets_by_da_id.get(&chunk.da_id);
        if let Some(record) = current {
            record.validate_chunk_insert(chunk.chunk_index)?;
        }
        if !chunk_hash_prevalidated && sha3_256(chunk.payload.as_ref()) != chunk.chunk_hash {
            return Err(DaRelayError::ChunkHashMismatch);
        }
        let chunk_index = chunk.chunk_index;
        chunk.peer_quota_key = PeerQuotaKey::from_peer_addr(peer_addr);
        let mut record = current
            .cloned()
            .unwrap_or_else(|| DaRelaySetRecord::new(chunk.da_id));
        if record.commit.is_none() {
            record.state = DaRelaySetState::OrphanChunks;
            record.ttl_blocks_remaining = self.caps.orphan_ttl_blocks;
        }
        record.chunks.insert(chunk_index, chunk);
        record.replaceable_chunks.remove(&chunk_index);
        self.prepare_and_apply_record(
            record,
            CompletionMismatchAction::MarkMatchingChunksReplaceable,
        )
    }
    fn project_counter(current: u64, remove: u64, add: u64, cap: u64) -> DaRelayResult<u64> {
        let next = current
            .checked_sub(remove)
            .ok_or(DaRelayError::AccountingUnderflow)?
            .checked_add(add)
            .ok_or(DaRelayError::AccountingOverflow)?;
        if next > cap {
            return Err(DaRelayError::AccountingCapExceeded);
        }
        Ok(next)
    }

    fn prepare_and_apply_record(
        &mut self,
        mut record: DaRelaySetRecord,
        mismatch_action: CompletionMismatchAction,
    ) -> DaRelayResult {
        record.recompute_wire_bytes()?;
        if record.received_time == 0 {
            record.received_time = self
                .next_received_time
                .checked_add(1)
                .ok_or(DaRelayError::AccountingOverflow)?;
        }
        if let Some(snapshot) = record.completion_snapshot() {
            let (payload_bytes, payload_commitment) = snapshot.payload_commitment()?;
            if payload_commitment == snapshot.payload_commitment_expected {
                record.mark_complete(payload_bytes);
            } else {
                match mismatch_action {
                    CompletionMismatchAction::DropMatchingChunks => {
                        if let Some(indexes) = snapshot.matching_chunk_indexes(&record) {
                            for index in indexes {
                                record.chunks.remove(&index);
                                record.replaceable_chunks.remove(&index);
                            }
                        }
                        record.payload_bytes = 0;
                        record.state = DaRelaySetState::StagedCommit;
                        record.recompute_wire_bytes()?;
                        self.apply_record(record)?;
                    }
                    CompletionMismatchAction::MarkMatchingChunksReplaceable => {
                        if let Some(old_record) = self.sets_by_da_id.get(&record.da_id) {
                            let mut record = old_record.clone();
                            let indexes = snapshot.matching_chunk_indexes(&record);
                            if let Some(indexes) = indexes {
                                if indexes.len() == snapshot.chunks.len() {
                                    record.mark_chunks_replaceable(indexes);
                                    self.apply_record(record)?;
                                }
                            }
                        }
                    }
                }
                return Err(DaRelayError::PayloadCommitmentMismatch);
            }
        }
        self.apply_record(record)?;
        Ok(())
    }

    fn apply_record(&mut self, record: DaRelaySetRecord) -> DaRelayResult {
        let old = self.sets_by_da_id.get(&record.da_id);
        let old_bytes = old.map_or(Ok(0), DaRelaySetRecord::orphan_wire_bytes)?;
        let old_commit_bytes = old.map_or(0, DaRelaySetRecord::orphan_commit_bytes);
        let old_pinned_bytes =
            old.map_or(Ok(0), DaRelaySetRecord::pinned_payload_accounting_bytes)?;
        let new_bytes = record.orphan_wire_bytes()?;
        let new_commit_bytes = record.orphan_commit_bytes();
        let new_pinned_bytes = record.pinned_payload_accounting_bytes()?;
        let peer_bytes = self.project_peer_bytes(old, &record)?;
        let da_id_current = self
            .orphan_bytes_by_da_id
            .get(&record.da_id)
            .copied()
            .unwrap_or(0);
        let orphan_bytes = Self::project_counter(
            self.orphan_bytes,
            old_bytes,
            new_bytes,
            self.caps.orphan_pool_bytes,
        )?;
        let da_id_bytes = Self::project_counter(
            da_id_current,
            old_bytes,
            new_bytes,
            self.caps.orphan_pool_per_da_id_bytes,
        )?;
        let commit_overhead = Self::project_counter(
            self.orphan_commit_overhead_bytes,
            old_commit_bytes,
            new_commit_bytes,
            self.caps.orphan_commit_overhead_bytes,
        )?;
        let pinned_payload_bytes = Self::project_counter(
            self.pinned_payload_bytes,
            old_pinned_bytes,
            new_pinned_bytes,
            self.caps.pinned_payload_bytes,
        )?;
        self.orphan_bytes = orphan_bytes;
        self.orphan_commit_overhead_bytes = commit_overhead;
        self.pinned_payload_bytes = pinned_payload_bytes;
        if record.received_time > self.next_received_time {
            self.next_received_time = record.received_time;
        }
        for (key, bytes) in peer_bytes {
            if bytes == 0 {
                self.orphan_bytes_by_peer_quota_key.remove(&key);
            } else {
                self.orphan_bytes_by_peer_quota_key.insert(key, bytes);
            }
        }
        if da_id_bytes == 0 {
            self.orphan_bytes_by_da_id.remove(&record.da_id);
        } else {
            self.orphan_bytes_by_da_id.insert(record.da_id, da_id_bytes);
        }
        self.sets_by_da_id.insert(record.da_id, record);
        Ok(())
    }

    fn project_peer_counter(
        &self,
        key: &PeerQuotaKey,
        remove: u64,
        add: u64,
    ) -> DaRelayResult<(PeerQuotaKey, u64)> {
        let current = self
            .orphan_bytes_by_peer_quota_key
            .get(key)
            .copied()
            .unwrap_or(0);
        Ok((
            key.clone(),
            Self::project_counter(current, remove, add, self.caps.orphan_pool_per_peer_bytes)?,
        ))
    }

    fn project_peer_bytes(
        &self,
        old: Option<&DaRelaySetRecord>,
        new: &DaRelaySetRecord,
    ) -> DaRelayResult<Vec<(PeerQuotaKey, u64)>> {
        let mut projected = Vec::new();
        let new_peer_bytes = new.orphan_peer_bytes();
        let old_peer_bytes = old.and_then(DaRelaySetRecord::orphan_peer_bytes);
        if let Some(old_peer_bytes) = old_peer_bytes {
            for (key, old_bytes) in old_peer_bytes {
                let new_bytes = new_peer_bytes
                    .and_then(|m| m.get(key))
                    .copied()
                    .unwrap_or(0);
                projected.push(self.project_peer_counter(key, *old_bytes, new_bytes)?);
            }
        }
        if let Some(new_peer_bytes) = new_peer_bytes {
            for (key, new_bytes) in new_peer_bytes {
                if !old_peer_bytes.is_some_and(|old_bytes| old_bytes.contains_key(key)) {
                    projected.push(self.project_peer_counter(key, 0, *new_bytes)?);
                }
            }
        }
        Ok(projected)
    }

    fn project_ttl_expiry(
        &self,
        records: &[DaRelaySetRecord],
    ) -> DaRelayResult<DaRelayTtlExpiryProjection> {
        let mut remove_orphan_bytes = 0u64;
        let mut remove_commit_overhead_bytes = 0u64;
        let mut remove_peer_bytes = BTreeMap::new();
        let mut da_id_bytes = Vec::with_capacity(records.len());
        for record in records {
            let orphan_wire_bytes = record.orphan_wire_bytes()?;
            remove_orphan_bytes = checked_add(remove_orphan_bytes, orphan_wire_bytes)?;
            remove_commit_overhead_bytes =
                checked_add(remove_commit_overhead_bytes, record.orphan_commit_bytes())?;
            da_id_bytes.push((
                record.da_id,
                Self::project_counter(
                    self.orphan_bytes_by_da_id
                        .get(&record.da_id)
                        .copied()
                        .unwrap_or(0),
                    orphan_wire_bytes,
                    0,
                    self.caps.orphan_pool_per_da_id_bytes,
                )?,
            ));
            if let Some(peer_bytes) = record.orphan_peer_bytes() {
                for (key, bytes) in peer_bytes {
                    let entry = remove_peer_bytes.entry(key.clone()).or_default();
                    *entry = checked_add(*entry, *bytes)?;
                }
            }
        }
        let peer_bytes = remove_peer_bytes
            .into_iter()
            .map(|(key, bytes)| {
                let projected = self.project_peer_counter(&key, bytes, 0)?.1;
                Ok((key, projected))
            })
            .collect::<DaRelayResult<_>>()?;
        Ok(DaRelayTtlExpiryProjection {
            orphan_bytes: Self::project_counter(
                self.orphan_bytes,
                remove_orphan_bytes,
                0,
                self.caps.orphan_pool_bytes,
            )?,
            orphan_commit_overhead_bytes: Self::project_counter(
                self.orphan_commit_overhead_bytes,
                remove_commit_overhead_bytes,
                0,
                self.caps.orphan_commit_overhead_bytes,
            )?,
            peer_bytes,
            da_id_bytes,
        })
    }

    fn apply_ttl_expiry_projection(
        &mut self,
        projection: DaRelayTtlExpiryProjection,
        records: Vec<DaRelaySetRecord>,
    ) {
        self.orphan_bytes = projection.orphan_bytes;
        self.orphan_commit_overhead_bytes = projection.orphan_commit_overhead_bytes;
        for (key, bytes) in projection.peer_bytes {
            if bytes == 0 {
                self.orphan_bytes_by_peer_quota_key.remove(&key);
            } else {
                self.orphan_bytes_by_peer_quota_key.insert(key, bytes);
            }
        }
        for (da_id, bytes) in projection.da_id_bytes {
            if bytes == 0 {
                self.orphan_bytes_by_da_id.remove(&da_id);
            } else {
                self.orphan_bytes_by_da_id.insert(da_id, bytes);
            }
        }
        for record in records {
            self.sets_by_da_id.remove(&record.da_id);
        }
    }
}

impl CompleteDaSetProvider for DaRelayState {
    fn complete_da_set_candidates(&self, max_payload_bytes: u64) -> Vec<CompleteDaSetCandidate> {
        DaRelayState::complete_da_set_candidates(self, max_payload_bytes)
    }
}

fn validate_da_chunk(chunk: &DaRelayChunk) -> DaRelayResult {
    if u64::from(chunk.chunk_index) >= MAX_DA_CHUNK_COUNT {
        return Err(DaRelayError::ChunkIndexOutOfRange);
    }
    let payload_len = chunk.payload.len() as u64;
    if payload_len == 0 || payload_len > CHUNK_BYTES {
        return Err(DaRelayError::ChunkPayloadSizeInvalid);
    }
    if chunk.wire_bytes == 0 || chunk.wire_bytes < payload_len {
        return Err(DaRelayError::InvalidWireBytes);
    }
    Ok(())
}

pub(crate) fn relay_da_tx_kind_prefix(tx_bytes: &[u8]) -> Option<u8> {
    let version = u32::from_le_bytes(tx_bytes.get(..4)?.try_into().ok()?);
    let kind = tx_bytes.get(4).copied()?;
    (version == TX_WIRE_VERSION).then_some(kind)
}

fn validate_relay_da_chunk_for_admission(tx: &Tx, wire_bytes: u64) -> DaRelayResult {
    if tx.tx_kind != 0x02 {
        return Ok(());
    }
    let Some(core) = tx.da_chunk_core.as_ref() else {
        return Ok(());
    };
    let payload_len =
        u64::try_from(tx.da_payload.len()).map_err(|_| DaRelayError::AccountingOverflow)?;
    if u64::from(core.chunk_index) >= MAX_DA_CHUNK_COUNT {
        return Err(DaRelayError::ChunkIndexOutOfRange);
    }
    if payload_len == 0 || payload_len > CHUNK_BYTES {
        return Err(DaRelayError::ChunkPayloadSizeInvalid);
    }
    if wire_bytes < payload_len {
        return Err(DaRelayError::InvalidWireBytes);
    }
    if sha3_256(&tx.da_payload) != core.chunk_hash {
        return Err(DaRelayError::ChunkHashMismatch);
    }
    Ok(())
}

fn relay_da_commit_payload_commitment(tx: &Tx) -> Option<[u8; 32]> {
    let mut outputs = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_type == COV_TYPE_DA_COMMIT);
    let output = outputs.next()?;
    if output.covenant_data.len() != 32 || outputs.next().is_some() {
        return None;
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&output.covenant_data);
    Some(commitment)
}

fn checked_add(left: u64, right: u64) -> DaRelayResult<u64> {
    left.checked_add(right)
        .ok_or(DaRelayError::AccountingOverflow)
}

fn retained_tx_accounting_bytes(wire_bytes: u64, tx_bytes: &[u8]) -> u64 {
    if tx_bytes.is_empty() {
        wire_bytes
    } else {
        tx_bytes.len() as u64
    }
}

fn orphan_chunk_accounting_bytes(chunk: &DaRelayChunk) -> DaRelayResult<u64> {
    let mut bytes = retained_tx_accounting_bytes(chunk.wire_bytes, &chunk.tx_bytes);
    if !chunk.tx_bytes.is_empty() && !chunk.payload.is_empty() {
        bytes = checked_add(bytes, chunk.payload.len() as u64)?;
    }
    Ok(bytes)
}

fn sha3_256(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
}

/// Deterministically extract the `da_id` of every COMPLETE DA set carried by an
/// already-accepted block, in ascending `da_id` order. A set is complete when
/// the block contains exactly one DA commit for the `da_id` whose `chunk_count`
/// is in `(0, MAX_DA_CHUNK_COUNT]`, plus a DA chunk tx for every index
/// `0..chunk_count`. Read-only: it parses block bytes and never mutates relay
/// state. Mirrors merged Go `extractAcceptedBlockDAIDs` (RUB-429).
pub(crate) fn extract_accepted_block_da_ids(block_bytes: &[u8]) -> Result<Vec<[u8; 32]>, TxError> {
    let parsed = parse_block_bytes(block_bytes)?;
    let mut sets: BTreeMap<[u8; 32], AcceptedBlockDaSet> = BTreeMap::new();
    for tx in &parsed.txs {
        record_accepted_block_da_tx(&mut sets, tx);
    }
    // BTreeMap iterates by ascending key, so the surviving da_ids are returned
    // sorted and unique (one entry per da_id) without an explicit sort.
    Ok(sets
        .into_iter()
        .filter(|(_, set)| set.complete())
        .map(|(da_id, _)| da_id)
        .collect())
}

fn record_accepted_block_da_tx(sets: &mut BTreeMap<[u8; 32], AcceptedBlockDaSet>, tx: &Tx) {
    match tx.tx_kind {
        0x01 => {
            if let Some(commit) = &tx.da_commit_core {
                let set = sets.entry(commit.da_id).or_default();
                set.commit_count += 1;
                set.chunk_count = commit.chunk_count;
            }
        }
        0x02 => {
            if let Some(chunk) = &tx.da_chunk_core {
                sets.entry(chunk.da_id)
                    .or_default()
                    .chunks
                    .insert(chunk.chunk_index);
            }
        }
        _ => {}
    }
}

#[derive(Default)]
struct AcceptedBlockDaSet {
    commit_count: u32,
    chunk_count: u16,
    chunks: BTreeSet<u16>,
}

impl AcceptedBlockDaSet {
    fn complete(&self) -> bool {
        if self.commit_count != 1
            || self.chunk_count == 0
            || u64::from(self.chunk_count) > MAX_DA_CHUNK_COUNT
        {
            return false;
        }
        if self.chunks.len() != usize::from(self.chunk_count) {
            return false;
        }
        (0..self.chunk_count).all(|index| self.chunks.contains(&index))
    }
}

/// Consume every COMPLETE DA set included in an already-applied block: extract
/// the block's complete DA ids (RUB-434) and consume each from the locked relay
/// (RUB-433), aborting on the first error (fail-closed). Used by the Rust
/// /mine_next consume wiring (RUB-435) — the mirror of Go
/// `ConsumeAcceptedBlockDASets`.
pub fn consume_accepted_block_da_sets(
    da_relay: &Mutex<DaRelayState>,
    block_bytes: &[u8],
) -> Result<(), String> {
    let da_ids = extract_accepted_block_da_ids(block_bytes).map_err(|err| err.to_string())?;
    let mut relay = da_relay
        .lock()
        .map_err(|_| "DA relay lock poisoned during accepted-block DA consume".to_string())?;
    for da_id in da_ids {
        relay
            .consume_complete_set(da_id)
            .map_err(|err| format!("consume accepted DA set: {err:?}"))?;
    }
    Ok(())
}

/// Consume the complete DA sets included in every block reported
/// canonical-applied by the sync engine (RUB-436): a direct apply reports the
/// single connected block, a reorg reports every newly-canonical branch block,
/// and a stored-but-not-switched side branch reports none (so nothing is
/// consumed). Best-effort across blocks — every block is attempted and the
/// first error is returned — so one block's accounting failure cannot skip DA
/// cleanup for the remaining canonical blocks. Used by the Rust P2P
/// accepted-block consume hook (RUB-437) — the mirror of Go
/// `consumeCanonicalAppliedDASets`.
pub fn consume_canonical_applied_da_sets(
    da_relay: &Mutex<DaRelayState>,
    canonical_applied_blocks: &[crate::chainstate::CanonicalAppliedBlock],
) -> Result<(), String> {
    let mut first_err: Option<String> = None;
    for block in canonical_applied_blocks {
        if let Err(err) = consume_accepted_block_da_sets(da_relay, &block.block_bytes) {
            first_err.get_or_insert_with(|| {
                format!(
                    "consume canonical-applied DA sets for block {}: {err}",
                    hex::encode(block.hash)
                )
            });
        }
    }
    first_err.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::{DaRelayError::*, *};

    #[test]
    fn da_relay_rejects_invalid_caps() {
        macro_rules! invalid_caps {
            ($($field:ident = $value:expr),+ $(,)?) => {$({
                let mut caps = DaRelayCaps::default();
                caps.$field = $value;
                assert_eq!(DaRelayState::new(caps), Err(InvalidCaps));
            })+};
        }
        invalid_caps!(
            orphan_pool_bytes = 0,
            orphan_pool_per_peer_bytes = 0,
            orphan_pool_per_da_id_bytes = 0,
            orphan_commit_overhead_bytes = 0,
            orphan_ttl_blocks = 0,
            pinned_payload_bytes = 0,
            orphan_pool_per_peer_bytes = DA_ORPHAN_POOL_BYTES + 1,
            orphan_pool_per_da_id_bytes = DA_ORPHAN_POOL_BYTES + 1,
            orphan_commit_overhead_bytes = DA_ORPHAN_POOL_BYTES + 1,
        );
    }

    #[test]
    fn da_relay_default_caps_match_go_reference() {
        let caps = DaRelayCaps::default();
        assert_eq!(caps.orphan_pool_bytes, 64 << 20);
        assert_eq!(caps.orphan_pool_per_peer_bytes, 4 << 20);
        assert_eq!(caps.orphan_pool_per_da_id_bytes, 8 << 20);
        assert_eq!(caps.orphan_commit_overhead_bytes, 8 << 20);
        assert_eq!(caps.orphan_ttl_blocks, 3);
        assert_eq!(caps.pinned_payload_bytes, 96_000_000);
        let mut state = DaRelayState::new(caps).expect("valid caps");
        assert!(state.is_empty());
        state.next_received_time = 1;
        assert!(state.is_empty());
    }

    #[rustfmt::skip]
    fn relay_test_tx(tx_kind: u8, outputs: Vec<rubin_consensus::TxOutput>, da_commit_core: Option<rubin_consensus::DaCommitCore>, da_chunk_core: Option<rubin_consensus::DaChunkCore>, da_payload: Vec<u8>) -> Vec<u8> { rubin_consensus::marshal_tx(&rubin_consensus::Tx { version: rubin_consensus::constants::TX_WIRE_VERSION, tx_kind, tx_nonce: 7, inputs: Vec::new(), outputs, locktime: 0, da_commit_core, da_chunk_core, witness: Vec::new(), da_payload }).expect("marshal relay test tx") }

    #[rustfmt::skip]
    fn relay_commit_core(da_id: [u8; 32], chunk_count: u16) -> rubin_consensus::DaCommitCore { rubin_consensus::DaCommitCore { da_id, chunk_count, retl_domain_id: [0x10; 32], batch_number: 1, tx_data_root: [0x11; 32], state_root: [0x12; 32], withdrawals_root: [0x13; 32], batch_sig_suite: 0, batch_sig: Vec::new() } }

    #[rustfmt::skip]
    fn relay_chunk_core(da_id: [u8; 32], chunk_index: u16, payload: &[u8]) -> rubin_consensus::DaChunkCore { rubin_consensus::DaChunkCore { da_id, chunk_index, chunk_hash: sha3_256(payload) } }

    #[rustfmt::skip]
    fn da_commit_output(commitment: [u8; 32]) -> rubin_consensus::TxOutput { rubin_consensus::TxOutput { value: 0, covenant_type: rubin_consensus::constants::COV_TYPE_DA_COMMIT, covenant_data: commitment.to_vec() } }

    #[test]
    #[rustfmt::skip]
    fn stage_relay_da_tx_bytes_contract_matrix() {
        let peer = "peer-a:8333"; let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); let non_da = relay_test_tx(0x00, Vec::new(), None, None, Vec::new()); state.stage_relay_da_tx_bytes(peer, non_da.clone()).unwrap(); let (non_da_tx, _, _, _) = parse_tx(&non_da).unwrap(); assert_eq!(validate_relay_da_chunk_for_admission(&non_da_tx, non_da.len() as u64), Ok(())); assert!(state.is_empty());
        let bad_commit_output = rubin_consensus::TxOutput { value: 0, covenant_type: rubin_consensus::constants::COV_TYPE_DA_COMMIT, covenant_data: vec![4u8; 31] }; let bad_commit = relay_test_tx(0x01, vec![bad_commit_output], Some(relay_commit_core([4u8; 32], 1)), None, Vec::new()); state.stage_relay_da_tx_bytes(peer, bad_commit).unwrap(); assert!(state.is_empty());
        let da_id = [1u8; 32]; let commitment = [2u8; 32]; let commit_tx = relay_test_tx(0x01, vec![da_commit_output(commitment)], Some(relay_commit_core(da_id, 1)), None, Vec::new()); state.stage_relay_da_tx_bytes(peer, commit_tx.clone()).unwrap(); let commit = state.sets_by_da_id[&da_id].commit.as_ref().unwrap(); assert_eq!(commit.payload_commitment, commitment); assert_eq!(commit.tx_bytes.as_ref(), commit_tx.as_slice());
        let payload = b"relay chunk".to_vec(); let mut bad_core = relay_chunk_core([6u8; 32], 0, &payload); bad_core.chunk_hash = [7u8; 32]; let bad_chunk = relay_test_tx(0x02, Vec::new(), None, Some(bad_core), payload.clone()); let mut reject_state = DaRelayState::new(DaRelayCaps::default()).unwrap(); assert_eq!(DaRelayState::validate_relay_da_tx_for_admission(&bad_chunk), Err(ChunkHashMismatch)); assert_eq!(reject_state.stage_relay_da_tx_bytes(peer, bad_chunk), Err(ChunkHashMismatch)); assert!(reject_state.is_empty());
        let mut trailing_chunk = relay_test_tx(0x02, Vec::new(), None, Some(relay_chunk_core([8u8; 32], 0, &payload)), payload.clone()); trailing_chunk.push(0); assert_eq!(DaRelayState::validate_relay_da_tx_for_admission(&trailing_chunk), Err(InvalidWireBytes)); assert_eq!(reject_state.stage_relay_da_tx_bytes(peer, trailing_chunk), Err(InvalidWireBytes)); assert!(reject_state.is_empty());
        let good_tx = relay_test_tx(0x02, Vec::new(), None, Some(relay_chunk_core([7u8; 32], 0, &payload)), payload.clone()); reject_state.stage_relay_da_tx_bytes(peer, good_tx.clone()).unwrap(); assert_eq!(reject_state.test_record_summary([7u8; 32]), Some((false, 1, good_tx.len() as u64))); assert_eq!(reject_state.sets_by_da_id[&[7u8; 32]].chunks[&0].tx_bytes.as_ref(), good_tx.as_slice());
        let (good_chunk_tx, _, _, _) = parse_tx(&good_tx).unwrap(); let mut edge_tx = good_chunk_tx.clone(); edge_tx.da_chunk_core.as_mut().unwrap().chunk_index = MAX_DA_CHUNK_COUNT as u16; assert_eq!(validate_relay_da_chunk_for_admission(&edge_tx, good_tx.len() as u64), Err(ChunkIndexOutOfRange)); edge_tx.da_chunk_core.as_mut().unwrap().chunk_index = 0; edge_tx.da_payload.clear(); assert_eq!(validate_relay_da_chunk_for_admission(&edge_tx, good_tx.len() as u64), Err(ChunkPayloadSizeInvalid)); edge_tx.da_payload = payload.clone(); assert_eq!(validate_relay_da_chunk_for_admission(&edge_tx, 0), Err(InvalidWireBytes));
        let caps = DaRelayCaps { orphan_pool_per_peer_bytes: good_tx.len() as u64 + payload.len() as u64 - 1, ..DaRelayCaps::default() }; let mut cap_state = DaRelayState::new(caps).unwrap(); assert_eq!(cap_state.stage_relay_da_tx_bytes(peer, good_tx), Err(AccountingCapExceeded)); assert!(cap_state.is_empty());
    }

    #[test]
    #[rustfmt::skip]
    fn stage_returns_schedulable_da_id() {
        let peer = "peer-a:8333"; let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        // non-DA tx -> no schedulable da_id
        let non_da = relay_test_tx(0x00, Vec::new(), None, None, Vec::new()); assert_eq!(state.stage_relay_da_tx_bytes_checked(peer, non_da, false).0, None);
        // commit with a malformed (31-byte) DA_COMMIT covenant -> gated out, no da_id (mirror Go stageRelayDACommitTx)
        let bad_out = rubin_consensus::TxOutput { value: 0, covenant_type: rubin_consensus::constants::COV_TYPE_DA_COMMIT, covenant_data: vec![4u8; 31] }; let bad_commit = relay_test_tx(0x01, vec![bad_out], Some(relay_commit_core([4u8; 32], 1)), None, Vec::new()); assert_eq!(state.stage_relay_da_tx_bytes_checked(peer, bad_commit, false).0, None);
        // well-formed commit -> its da_id with an Ok stage
        let commit_tx = relay_test_tx(0x01, vec![da_commit_output([2u8; 32])], Some(relay_commit_core([1u8; 32], 1)), None, Vec::new()); assert_eq!(state.stage_relay_da_tx_bytes_checked(peer, commit_tx, false), (Some([1u8; 32]), Ok(())));
        // DA chunk -> its da_id
        let payload = b"relay chunk".to_vec(); let chunk_tx = relay_test_tx(0x02, Vec::new(), None, Some(relay_chunk_core([7u8; 32], 0, &payload)), payload.clone()); assert_eq!(state.stage_relay_da_tx_bytes_checked(peer, chunk_tx, false).0, Some([7u8; 32]));
    }

    #[test]
    fn peer_quota_key_normalizes_hostile_matrix() {
        for (addr, expected) in [
            ("", ""),
            ("127.0.0.1:8333", "127.0.0.1"),
            ("127.0.0.1:65536", "127.0.0.1"),
            ("127.0.0.1%zone:8333", "127.0.0.1%zone"),
            (":8333", ""),
            ("example.com:8333", "example.com"),
            ("example.com:", "example.com"),
            ("[::1]:8333", "::1"),
            ("[::1]:", "::1"),
            ("[::1]:https", "::1"),
            ("[::1]:65536", "::1"),
            ("[::1]:8333:extra", "[::1]:8333:extra"),
            ("[::1]:8333]", "[::1]:8333]"),
            ("fe80::1%en0", "fe80::1"),
            ("fe80::1%", "fe80::1%"),
            ("fe80::1%en0:8333", "fe80::1"),
            ("[fe80::1%en0]:8333", "fe80::1"),
            ("[fe80::1%en0]:", "fe80::1"),
            ("[fe80::1%]:8333", "fe80::1%"),
            ("[example.com%zone]:8333", "example.com%zone"),
            ("[a[b]:8333", "[a[b]:8333"),
            ("example[.com]:8333", "example[.com]:8333"),
            ("example.com%zone:8333", "example.com%zone"),
        ] {
            assert_eq!(PeerQuotaKey::from_peer_addr(addr).0, expected);
        }
    }
    #[test]
    fn da_relay_accounting_projection_fails_closed() {
        let project_counter = DaRelayState::project_counter;
        for (current, remove, add, cap, expected) in [
            (0, 1, 0, 10, Err(AccountingUnderflow)),
            (u64::MAX, 0, 1, u64::MAX, Err(AccountingOverflow)),
            (9, 0, 2, 10, Err(AccountingCapExceeded)),
            (9, 4, 2, 10, Ok(7)),
        ] {
            assert_eq!(project_counter(current, remove, add, cap), expected);
        }
    }

    fn payload_commitment(payloads: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        for payload in payloads {
            hasher.update(payload);
        }
        hasher.finalize().into()
    }

    #[test]
    #[rustfmt::skip]
    fn da_relay_staged_mutation_matrix() {
        let peer = "peer-a:8333"; let pk = || PeerQuotaKey::from_peer_addr(peer); let stage_commit = |state: &mut DaRelayState, commit| state.stage_incomplete_da_commit(peer, commit); let stage_chunk = |state: &mut DaRelayState, chunk| state.stage_incomplete_da_chunk(peer, chunk); let commit = |da_id, chunk_count, wire_bytes| DaRelayCommit { da_id, payload_commitment: [0; 32], peer_quota_key: pk(), chunk_count, wire_bytes, tx_bytes: Arc::from([]) }; let chunk = |da_id, chunk_index, payload: &[u8], wire_bytes| DaRelayChunk { da_id, chunk_hash: sha3_256(payload), peer_quota_key: pk(), chunk_index, payload: Arc::from(payload), wire_bytes, tx_bytes: Arc::from([]) }; let reject = |got: Result<(), DaRelayError>, want| assert_eq!(got, Err(want));
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); let mut forged_commit = commit([13; 32], 1, 2); forged_commit.peer_quota_key = PeerQuotaKey::from_peer_addr("peer-b:8333"); stage_commit(&mut state, forged_commit).unwrap(); let mut forged_chunk = chunk([14; 32], 0, b"owned", 6); forged_chunk.peer_quota_key = PeerQuotaKey::from_peer_addr("peer-b:8333"); stage_chunk(&mut state, forged_chunk).unwrap(); assert!(state.orphan_bytes_by_peer_quota_key.contains_key(&pk()) && !state.orphan_bytes_by_peer_quota_key.contains_key(&PeerQuotaKey::from_peer_addr("peer-b:8333")));
        stage_commit(&mut state, commit([1; 32], 3, 2)).unwrap(); assert!(state.sets_by_da_id[&[1; 32]].commit.is_some()); stage_chunk(&mut state, chunk([1; 32], 0, b"payload-a", 9)).unwrap(); stage_chunk(&mut state, chunk([1; 32], 1, b"payload-b", 9)).unwrap(); assert_eq!(state.sets_by_da_id[&[1; 32]].chunks.len(), 2);
        stage_chunk(&mut state, chunk([2; 32], 0, b"payload-a", 9)).unwrap(); stage_chunk(&mut state, chunk([2; 32], 1, b"payload-b", 9)).unwrap(); stage_commit(&mut state, commit([2; 32], 3, 1)).unwrap(); let record = &state.sets_by_da_id[&[2; 32]]; assert!(record.commit.is_some() && record.chunks.len() == 2); assert_eq!(state.orphan_bytes_by_da_id[&[2; 32]], record.wire_bytes);
        stage_chunk(&mut state, chunk([12; 32], 0, b"keep", 4)).unwrap(); stage_chunk(&mut state, chunk([12; 32], 2, b"prune", 5)).unwrap(); stage_commit(&mut state, commit([12; 32], 2, 1)).unwrap(); let record = &state.sets_by_da_id[&[12; 32]]; assert!(record.chunks.contains_key(&0) && !record.chunks.contains_key(&2)); assert_eq!(state.orphan_bytes_by_da_id[&[12; 32]], record.wire_bytes);
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); reject(stage_commit(&mut state, commit([3; 32], 0, 1)), InvalidCommitChunkCount); reject(stage_commit(&mut state, commit([3; 32], 1, 0)), InvalidWireBytes); assert!(state.sets_by_da_id.is_empty());
        stage_commit(&mut state, commit([3; 32], 2, 1)).unwrap(); let before = state.clone(); let mut bad_hash = chunk([3; 32], 0, b"payload", 7); bad_hash.chunk_hash[0] ^= 0xff;
        reject(stage_commit(&mut state, commit([3; 32], 1, 1)), DuplicateCommit); reject(stage_chunk(&mut state, chunk([3; 32], 2, b"payload", 7)), ChunkIndexOutsideCommit); reject(stage_chunk(&mut state, bad_hash), ChunkHashMismatch); reject(stage_chunk(&mut state, chunk([3; 32], 0, b"", 1)), ChunkPayloadSizeInvalid); reject(stage_chunk(&mut state, chunk([3; 32], 0, b"payload", 1)), InvalidWireBytes); assert_eq!(state, before);
        stage_chunk(&mut state, chunk([3; 32], 0, b"payload", 7)).unwrap(); let before = state.clone(); reject(stage_chunk(&mut state, chunk([3; 32], 0, b"other", 5)), DuplicateChunk); assert_eq!(state, before);
        let caps = DaRelayCaps { orphan_pool_per_peer_bytes: 3, ..DaRelayCaps::default() }; let mut state = DaRelayState::new(caps).unwrap(); stage_chunk(&mut state, chunk([4; 32], 0, b"ab", 2)).unwrap();
        let before = state.clone(); reject(stage_chunk(&mut state, chunk([5; 32], 0, b"cd", 2)), AccountingCapExceeded); assert_eq!(state, before);
        let mut state = DaRelayState::new(caps).unwrap(); stage_chunk(&mut state, chunk([6; 32], 0, b"a", 1)).unwrap(); let before = state.clone(); reject(stage_commit(&mut state, commit([6; 32], 2, 3)), AccountingCapExceeded); assert_eq!(state, before);
    }

    #[test]
    fn da_relay_duplicate_first_seen_matrix() {
        let peer_a = "peer-a:8333";
        let peer_b = "peer-b:8333";
        let peer_c = "peer-c:8333";
        let commit = |da_id, payloads: &[&[u8]], wire_bytes| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_count: payloads.len() as u16,
            wire_bytes,
            tx_bytes: Arc::from([]),
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
            tx_bytes: Arc::from([]),
        };

        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_chunk(peer_a, chunk([60; 32], 0, b"first-chunk", 12))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer_b, commit([60; 32], &[b"first-chunk", b"tail"], 7))
            .unwrap();
        let before = state.clone();
        assert_eq!(
            state.stage_incomplete_da_commit(peer_c, commit([60; 32], &[b"other"], 99)),
            Err(DuplicateCommit)
        );
        assert_eq!(state, before);
        let record = &state.sets_by_da_id[&[60; 32]];
        assert_eq!(
            record.commit.as_ref().map(|commit| &commit.peer_quota_key),
            Some(&PeerQuotaKey::from_peer_addr(peer_b))
        );
        assert_eq!(record.chunks[&0].payload.as_ref(), b"first-chunk");
        assert!(!state
            .orphan_bytes_by_peer_quota_key
            .contains_key(&PeerQuotaKey::from_peer_addr(peer_c)));

        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_chunk(peer_a, chunk([61; 32], 0, b"first", 5))
            .unwrap();
        let before = state.clone();
        let mut duplicate = chunk([61; 32], 0, b"conflict", 8);
        duplicate.chunk_hash[0] ^= 0xff;
        assert_eq!(
            state.stage_incomplete_da_chunk(peer_b, duplicate),
            Err(DuplicateChunk)
        );
        assert_eq!(state, before);
        let record = &state.sets_by_da_id[&[61; 32]];
        assert_eq!(record.chunks[&0].payload.as_ref(), b"first");
        assert_eq!(
            record.chunks[&0].peer_quota_key,
            PeerQuotaKey::from_peer_addr(peer_a)
        );
        assert!(!record.replaceable_chunks.contains(&0));
        assert!(!state
            .orphan_bytes_by_peer_quota_key
            .contains_key(&PeerQuotaKey::from_peer_addr(peer_b)));
    }

    #[test]
    fn da_relay_retained_tx_byte_accounting_matrix() {
        let peer_commit = "commit-peer:8333";
        let peer_chunk = "chunk-peer:8333";
        let peer_dup = "duplicate-peer:8333";
        let payload = b"retained-payload";
        let payload_wire = payload.len() as u64;
        let commit_tx = b"canonical-commit-tx";
        let chunk_tx = b"canonical-chunk-tx";
        let commit = |da_id, payloads: &[&[u8]], wire_bytes, tx_bytes: &[u8]| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_count: payloads.len() as u16,
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes, tx_bytes: &[u8]| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };

        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        let invalid_commit = commit([68; 32], &[payload], 0, b"invalid-commit-tx");
        assert_eq!(
            state.stage_incomplete_da_commit(peer_commit, invalid_commit),
            Err(InvalidWireBytes)
        );

        let mut invalid_hash = chunk([69; 32], 0, payload, payload_wire, b"invalid-chunk-tx");
        invalid_hash.chunk_hash[0] ^= 0xff;
        assert_eq!(
            state.stage_incomplete_da_chunk(peer_chunk, invalid_hash),
            Err(ChunkHashMismatch)
        );
        assert!(state.sets_by_da_id.is_empty());

        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_commit(
                peer_commit,
                commit([70; 32], &[payload, b"tail"], 1, commit_tx),
            )
            .unwrap();
        state
            .stage_incomplete_da_chunk(
                peer_chunk,
                chunk([70; 32], 0, payload, payload_wire, chunk_tx),
            )
            .unwrap();
        let record = &state.sets_by_da_id[&[70; 32]];
        let retained_wire = (commit_tx.len() + chunk_tx.len()) as u64;
        assert_eq!(record.wire_bytes, retained_wire);
        assert_eq!(state.orphan_commit_overhead_bytes, commit_tx.len() as u64);
        assert_eq!(state.orphan_bytes, retained_wire + payload.len() as u64);
        assert_eq!(state.orphan_bytes_by_da_id[&[70; 32]], state.orphan_bytes);
        assert_eq!(
            record.peer_bytes[&PeerQuotaKey::from_peer_addr(peer_commit)],
            commit_tx.len() as u64
        );
        assert_eq!(
            record.peer_bytes[&PeerQuotaKey::from_peer_addr(peer_chunk)],
            (chunk_tx.len() + payload.len()) as u64
        );

        let before = state.clone();
        assert_eq!(
            state.stage_incomplete_da_commit(
                peer_dup,
                commit([70; 32], &[b"other"], 99, b"duplicate-commit-tx"),
            ),
            Err(DuplicateCommit)
        );
        assert_eq!(state, before);

        let mut duplicate_chunk = chunk([70; 32], 0, b"conflict", 99, b"duplicate-chunk-tx");
        duplicate_chunk.chunk_hash[0] ^= 0xff;
        assert_eq!(
            state.stage_incomplete_da_chunk(peer_dup, duplicate_chunk),
            Err(DuplicateChunk)
        );
        assert_eq!(state, before);

        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_commit(peer_commit, commit([71; 32], &[payload], 1, commit_tx))
            .unwrap();
        state
            .stage_incomplete_da_chunk(
                peer_chunk,
                chunk([71; 32], 0, payload, payload_wire, chunk_tx),
            )
            .unwrap();
        let record = &state.sets_by_da_id[&[71; 32]];
        assert_eq!(record.state, DaRelaySetState::CompleteSet);
        let chunk_count = u64::from(record.commit.as_ref().unwrap().chunk_count);
        assert!(record.chunks.values().all(|chunk| chunk.payload.is_empty()));
        let pinned = retained_wire
            + DA_COMPLETE_SET_RECORD_FOOTPRINT
            + chunk_count * DA_COMPLETE_SET_CHUNK_FOOTPRINT;
        assert_eq!(state.pinned_payload_bytes, pinned);
        assert_eq!(state.orphan_bytes, 0);

        let tight_caps = DaRelayCaps {
            orphan_commit_overhead_bytes: 1,
            ..DaRelayCaps::default()
        };
        let mut state = DaRelayState::new(tight_caps).unwrap();
        state
            .stage_incomplete_da_chunk(peer_chunk, chunk([74; 32], 0, b"x", 1, &[]))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer_commit, commit([74; 32], &[b"x"], 1, commit_tx))
            .unwrap();
        assert_eq!(
            state.sets_by_da_id[&[74; 32]].state,
            DaRelaySetState::CompleteSet
        );

        let caps = DaRelayCaps {
            pinned_payload_bytes: 1,
            ..DaRelayCaps::default()
        };
        let mut state = DaRelayState::new(caps).unwrap();
        state
            .stage_incomplete_da_commit(peer_commit, commit([72; 32], &[payload], 1, commit_tx))
            .unwrap();
        let before = state.clone();
        assert_eq!(
            state.stage_incomplete_da_chunk(
                peer_chunk,
                chunk([72; 32], 0, payload, payload_wire, chunk_tx)
            ),
            Err(AccountingCapExceeded)
        );
        assert_eq!(state, before);

        let mut state = DaRelayState::new(caps).unwrap();
        state
            .stage_incomplete_da_chunk(peer_chunk, chunk([73; 32], 0, payload, payload_wire, &[]))
            .unwrap();
        let before = state.clone();
        assert_eq!(
            state.stage_incomplete_da_commit(
                peer_commit,
                commit([73; 32], &[payload], 1, commit_tx),
            ),
            Err(AccountingCapExceeded)
        );
        assert_eq!(state, before);
    }

    #[test]
    #[rustfmt::skip]
    fn da_relay_ttl_expiry_matrix() {
        let peer = "peer-a:8333"; let pk = PeerQuotaKey::from_peer_addr(peer);
        let commit = |da_id, payloads: &[&[u8]], wire_bytes| DaRelayCommit { da_id, payload_commitment: payload_commitment(payloads), peer_quota_key: pk.clone(), chunk_count: payloads.len() as u16, wire_bytes, tx_bytes: Arc::from([]) };
        let chunk = |da_id, index, payload: &[u8], wire_bytes| DaRelayChunk { da_id, chunk_hash: sha3_256(payload), peer_quota_key: pk.clone(), chunk_index: index, payload: Arc::from(payload), wire_bytes, tx_bytes: Arc::from([]) };
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([3; 32], 0, b"orphan", 6)).unwrap(); state.stage_incomplete_da_commit(peer, commit([2; 32], &[b"staged"], 7)).unwrap(); state.stage_incomplete_da_commit(peer, commit([1; 32], &[b"complete"], 8)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([1; 32], 0, b"complete", 8)).unwrap();
        let complete_before = state.sets_by_da_id[&[1; 32]].clone(); let orphan_before = state.orphan_bytes; assert!(state.advance_orphan_ttl().unwrap().is_empty()); assert_eq!(state.sets_by_da_id[&[3; 32]].ttl_blocks_remaining, 2); assert_eq!(state.sets_by_da_id[&[2; 32]].ttl_blocks_remaining, 2); assert_eq!(state.sets_by_da_id[&[1; 32]], complete_before); assert_eq!(state.orphan_bytes, orphan_before);
        let mut batch = DaRelayState::new(DaRelayCaps::default()).unwrap(); batch.stage_incomplete_da_chunk(peer, chunk([6; 32], 0, b"batch", 5)).unwrap(); assert!(batch.advance_orphan_ttl_by(0).unwrap().is_empty()); assert_eq!(batch.sets_by_da_id[&[6; 32]].ttl_blocks_remaining, 3); assert!(batch.advance_orphan_ttl_by(2).unwrap().is_empty()); assert_eq!(batch.sets_by_da_id[&[6; 32]].ttl_blocks_remaining, 1); assert_eq!(batch.advance_orphan_ttl_by(2).unwrap(), vec![[6; 32]]); assert!(batch.is_empty());
        state.sets_by_da_id.get_mut(&[3; 32]).unwrap().ttl_blocks_remaining = 1; state.sets_by_da_id.get_mut(&[2; 32]).unwrap().ttl_blocks_remaining = 0; let expired = state.advance_orphan_ttl().unwrap();
        assert_eq!(expired, vec![[2; 32], [3; 32]]);
        assert_eq!(state.sets_by_da_id.get(&[1; 32]), Some(&complete_before)); assert!(!state.sets_by_da_id.contains_key(&[2; 32])); assert!(!state.sets_by_da_id.contains_key(&[3; 32])); assert_eq!(state.orphan_bytes, 0); assert!(state.orphan_bytes_by_da_id.is_empty()); assert!(state.orphan_bytes_by_peer_quota_key.is_empty()); assert_eq!(state.orphan_commit_overhead_bytes, 0); assert_eq!(state.pinned_payload_bytes, complete_before.pinned_payload_accounting_bytes().unwrap()); let before_noop = state.clone(); assert!(state.advance_orphan_ttl().unwrap().is_empty()); assert_eq!(state, before_noop);
        state.stage_incomplete_da_chunk(peer, chunk([4; 32], 0, b"corrupt", 7)).unwrap(); state.sets_by_da_id.get_mut(&[4; 32]).unwrap().ttl_blocks_remaining = 1; state.orphan_bytes = 0; let before = state.clone();
        assert_eq!(state.advance_orphan_ttl(), Err(AccountingUnderflow)); assert_eq!(state, before);
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([4; 32], 0, b"early", 5)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([5; 32], 0, b"late", 7)).unwrap(); state.sets_by_da_id.get_mut(&[4; 32]).unwrap().ttl_blocks_remaining = 1; state.sets_by_da_id.get_mut(&[5; 32]).unwrap().ttl_blocks_remaining = 1; state.orphan_bytes_by_da_id.insert([5; 32], 0); let before = state.clone();
        assert_eq!(state.advance_orphan_ttl(), Err(AccountingUnderflow)); assert_eq!(state, before);
    }

    #[test]
    fn da_relay_peer_quota_release_helper_releases_peer_owned_incomplete_records_only() {
        let peer_a = "peer-a:8333";
        let peer_b = "peer-b:8333";
        let key_a = PeerQuotaKey::from_peer_addr(peer_a);
        let key_b = PeerQuotaKey::from_peer_addr(peer_b);
        let commit = |da_id, payloads: &[&[u8]], wire_bytes| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_count: payloads.len() as u16,
            wire_bytes,
            tx_bytes: Arc::from([]),
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
            tx_bytes: Arc::from([]),
        };

        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_commit(peer_a, commit([80; 32], &[b"owned"], 5))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer_a, chunk([81; 32], 0, b"owned", 5))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer_a, commit([82; 32], &[b"keep", b"tail"], 6))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer_b, chunk([82; 32], 0, b"keep", 7))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer_b, chunk([83; 32], 0, b"unrelated", 9))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer_a, commit([84; 32], &[b"complete"], 8))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer_a, chunk([84; 32], 0, b"complete", 8))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer_b, commit([85; 32], &[b"stay", b"drop"], 11))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer_a, chunk([85; 32], 1, b"drop", 13))
            .unwrap();
        let complete_before = state.sets_by_da_id[&[84; 32]].clone();
        let peer_b_before = state.orphan_bytes_by_peer_quota_key[&key_b];

        state.release_peer_quota_key(&key_a).unwrap();

        assert!(!state.sets_by_da_id.contains_key(&[80; 32]));
        assert!(!state.sets_by_da_id.contains_key(&[81; 32]));
        let mixed = &state.sets_by_da_id[&[82; 32]];
        assert_eq!(mixed.state, DaRelaySetState::OrphanChunks);
        assert!(mixed.commit.is_none());
        assert_eq!(mixed.chunks[&0].peer_quota_key, key_b);
        assert_eq!(mixed.peer_bytes.len(), 1);
        assert_eq!(mixed.peer_bytes[&key_b], 7);
        assert_eq!(
            state.sets_by_da_id[&[83; 32]].chunks[&0].peer_quota_key,
            key_b
        );
        assert_eq!(state.sets_by_da_id[&[84; 32]], complete_before);
        let reverse_mixed = &state.sets_by_da_id[&[85; 32]];
        assert_eq!(reverse_mixed.state, DaRelaySetState::StagedCommit);
        assert_eq!(
            reverse_mixed
                .commit
                .as_ref()
                .map(|commit| &commit.peer_quota_key),
            Some(&key_b)
        );
        assert!(reverse_mixed.chunks.is_empty());
        assert_eq!(reverse_mixed.peer_bytes.len(), 1);
        assert_eq!(reverse_mixed.peer_bytes[&key_b], 11);
        assert!(!state.orphan_bytes_by_da_id.contains_key(&[84; 32]));
        assert!(!state.orphan_bytes_by_peer_quota_key.contains_key(&key_a));
        assert_eq!(state.orphan_bytes_by_peer_quota_key[&key_b], peer_b_before);
        assert_eq!(
            state.orphan_bytes,
            state.sets_by_da_id[&[82; 32]].orphan_wire_bytes().unwrap()
                + state.sets_by_da_id[&[83; 32]].orphan_wire_bytes().unwrap()
                + state.sets_by_da_id[&[85; 32]].orphan_wire_bytes().unwrap()
        );
        let after = state.clone();
        state.release_peer_quota_key(&key_a).unwrap();
        assert_eq!(state, after);
    }

    #[test]
    #[rustfmt::skip]
    fn da_relay_complete_integrity_matrix() {
        let peer = "peer-a:8333"; let pk = || PeerQuotaKey::from_peer_addr(peer); let commit = |da_id, payloads: &[&[u8]], wire_bytes| DaRelayCommit { da_id, payload_commitment: payload_commitment(payloads), peer_quota_key: pk(), chunk_count: payloads.len() as u16, wire_bytes, tx_bytes: Arc::from([]) }; let chunk = |da_id, index, payload: &[u8], wire_bytes| DaRelayChunk { da_id, chunk_hash: sha3_256(payload), peer_quota_key: pk(), chunk_index: index, payload: Arc::from(payload), wire_bytes, tx_bytes: Arc::from([]) };
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_commit(peer, commit([20; 32], &[b"aa", b"bb"], 2)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([20; 32], 0, b"aa", 2)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([20; 32], 1, b"bb", 2)).unwrap(); let record = &state.sets_by_da_id[&[20; 32]]; let chunk_count = u64::from(record.commit.as_ref().unwrap().chunk_count); assert_eq!(record.state, DaRelaySetState::CompleteSet); assert_eq!(record.payload_bytes, 4); assert_eq!(record.ttl_blocks_remaining, 0); assert!(record.chunks.values().all(|chunk| chunk.payload.is_empty())); assert_eq!(state.orphan_bytes, 0); assert!(!state.orphan_bytes_by_da_id.contains_key(&[20; 32])); assert_eq!(state.pinned_payload_bytes, record.wire_bytes + DA_COMPLETE_SET_RECORD_FOOTPRINT + chunk_count * DA_COMPLETE_SET_CHUNK_FOOTPRINT);
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_commit(peer, commit([21; 32], &[b"good"], 1)).unwrap(); assert_eq!(state.stage_incomplete_da_chunk(peer, chunk([21; 32], 0, b"bad", 3)), Err(PayloadCommitmentMismatch)); let record = &state.sets_by_da_id[&[21; 32]]; assert_eq!(record.state, DaRelaySetState::StagedCommit); assert_eq!(record.payload_bytes, 0); assert!(record.chunks.is_empty() && record.replaceable_chunks.is_empty()); assert_eq!(state.pinned_payload_bytes, 0); state.stage_incomplete_da_chunk(peer, chunk([21; 32], 0, b"good", 4)).unwrap(); let record = &state.sets_by_da_id[&[21; 32]]; assert_eq!(record.state, DaRelaySetState::CompleteSet); assert!(record.replaceable_chunks.is_empty());
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([22; 32], 0, b"bad", 3)).unwrap(); assert_eq!(state.stage_incomplete_da_commit(peer, commit([22; 32], &[b"good"], 1)), Err(PayloadCommitmentMismatch)); let record = &state.sets_by_da_id[&[22; 32]]; assert_eq!(record.state, DaRelaySetState::StagedCommit); assert!(record.chunks.is_empty()); assert_eq!(state.pinned_payload_bytes, 0); state.stage_incomplete_da_chunk(peer, chunk([22; 32], 0, b"good", 4)).unwrap(); assert_eq!(state.sets_by_da_id[&[22; 32]].state, DaRelaySetState::CompleteSet);
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_commit(peer, commit([23; 32], &[b"aa", b"bb"], 1)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([23; 32], 0, b"aa", 2)).unwrap(); assert_eq!(state.stage_incomplete_da_chunk(peer, chunk([23; 32], 1, b"xx", 2)), Err(PayloadCommitmentMismatch)); let record = &state.sets_by_da_id[&[23; 32]]; assert_eq!(record.state, DaRelaySetState::StagedCommit); assert!(record.chunks.contains_key(&0) && !record.chunks.contains_key(&1)); assert!(record.replaceable_chunks.is_empty()); assert_eq!(state.pinned_payload_bytes, 0); state.stage_incomplete_da_chunk(peer, chunk([23; 32], 1, b"bb", 2)).unwrap(); assert_eq!(state.sets_by_da_id[&[23; 32]].state, DaRelaySetState::CompleteSet);
        let caps = DaRelayCaps { pinned_payload_bytes: 1, ..DaRelayCaps::default() }; let mut state = DaRelayState::new(caps).unwrap(); state.stage_incomplete_da_commit(peer, commit([24; 32], &[b"aa"], 1)).unwrap(); let before = state.clone(); assert_eq!(state.stage_incomplete_da_chunk(peer, chunk([24; 32], 0, b"aa", 2)), Err(AccountingCapExceeded)); assert_eq!(state, before);
    }

    #[test]
    fn complete_da_set_provider_returns_complete_owned_ordered_snapshots() {
        let peer = "peer-a:8333";
        let pk = || PeerQuotaKey::from_peer_addr(peer);
        let commit = |da_id, payloads: &[&[u8]], tx_bytes: &[u8]| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: pk(),
            chunk_count: payloads.len() as u16,
            wire_bytes: tx_bytes.len().max(1) as u64,
            tx_bytes: Arc::from(tx_bytes),
        };
        let chunk = |da_id, index, payload: &[u8], tx_bytes: &[u8]| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: pk(),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes: payload.len() as u64,
            tx_bytes: Arc::from(tx_bytes),
        };
        let early_payload_0: &[u8] = b"early-0";
        let early_payload_1: &[u8] = b"early-1";
        let late_payload: &[u8] = b"late";
        let early_id = [30; 32];
        let staged_id = [32; 32];
        let late_id = [33; 32];
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();

        let empty = DaRelayState::new(DaRelayCaps::default()).unwrap();
        assert!(empty.complete_da_set_candidates(1).is_empty());
        state
            .stage_incomplete_da_chunk(peer, chunk([29; 32], 0, b"orphan", b"orphan-chunk-tx"))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer, commit(staged_id, &[b"staged"], b"staged-commit"))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer, commit(late_id, &[late_payload], b"commit-late"))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer, chunk(late_id, 0, late_payload, b"chunk-late"))
            .unwrap();
        state
            .stage_incomplete_da_commit(
                peer,
                commit(
                    early_id,
                    &[early_payload_0, early_payload_1],
                    b"commit-early",
                ),
            )
            .unwrap();
        for (index, payload, tx) in [
            (1, early_payload_1, b"chunk-early-1".as_slice()),
            (0, early_payload_0, b"chunk-early-0".as_slice()),
        ] {
            state
                .stage_incomplete_da_chunk(peer, chunk(early_id, index, payload, tx))
                .unwrap();
        }

        let mut candidates = CompleteDaSetProvider::complete_da_set_candidates(&state, u64::MAX);
        assert_eq!(
            candidates.iter().map(|c| c.da_id).collect::<Vec<_>>(),
            vec![early_id, late_id]
        );
        assert_eq!(
            candidates[0].payload_bytes,
            (early_payload_0.len() + early_payload_1.len()) as u64
        );
        assert_eq!(candidates[0].commit_tx, b"commit-early");
        assert_eq!(candidates[0].chunks[0].index, 0);
        assert_eq!(candidates[0].chunks[0].tx, b"chunk-early-0");
        assert_eq!(candidates[0].chunks[1].index, 1);
        assert_eq!(candidates[0].chunks[1].tx, b"chunk-early-1");

        candidates[0].commit_tx[0] = b'X';
        candidates[0].chunks[0].tx[0] = b'Y';
        let again = state.complete_da_set_candidates(u64::MAX);
        assert_eq!(again[0].commit_tx, b"commit-early");
        assert_eq!(again[0].chunks[0].tx, b"chunk-early-0");

        let ids_for = |budget| {
            state
                .complete_da_set_candidates(budget)
                .into_iter()
                .map(|candidate| candidate.da_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids_for((early_payload_0.len() + early_payload_1.len()) as u64),
            vec![early_id]
        );
        assert_eq!(ids_for(late_payload.len() as u64), vec![late_id]);
        assert!(state.complete_da_set_candidates(0).is_empty());
    }

    #[test]
    fn extract_accepted_block_da_ids_matrix() {
        use crate::test_helpers::block_with_txs;
        let prev = [0u8; 32];
        let payload = b"da-payload".to_vec();
        let commit_for = |da_id, chunk_count| {
            relay_test_tx(
                0x01,
                vec![da_commit_output([2u8; 32])],
                Some(relay_commit_core(da_id, chunk_count)),
                None,
                Vec::new(),
            )
        };
        let chunk_for = |da_id, index| {
            relay_test_tx(
                0x02,
                Vec::new(),
                None,
                Some(relay_chunk_core(da_id, index, &payload)),
                payload.clone(),
            )
        };

        // Coinbase-only block carries no DA txs.
        let empty_block = block_with_txs(1, 0, prev, 1_000, &[]);
        assert!(extract_accepted_block_da_ids(&empty_block)
            .unwrap()
            .is_empty());

        // One complete DA set for a single da_id.
        let one_id = [5u8; 32];
        let one_block = block_with_txs(
            1,
            0,
            prev,
            1_001,
            &[commit_for(one_id, 1), chunk_for(one_id, 0)],
        );
        assert_eq!(
            extract_accepted_block_da_ids(&one_block).unwrap(),
            vec![one_id]
        );

        // Two complete sets; the higher da_id is staged first in the block.
        let lo = [3u8; 32];
        let hi = [9u8; 32];
        let multi_block = block_with_txs(
            1,
            0,
            prev,
            1_002,
            &[
                commit_for(hi, 1),
                chunk_for(hi, 0),
                commit_for(lo, 1),
                chunk_for(lo, 0),
            ],
        );
        assert_eq!(
            extract_accepted_block_da_ids(&multi_block).unwrap(),
            vec![lo, hi]
        );

        // Commit declares 2 chunks but only chunk index 0 is present.
        let inc = [7u8; 32];
        let inc_block = block_with_txs(1, 0, prev, 1_003, &[commit_for(inc, 2), chunk_for(inc, 0)]);
        assert!(extract_accepted_block_da_ids(&inc_block)
            .unwrap()
            .is_empty());

        // Unparseable block bytes.
        assert!(extract_accepted_block_da_ids(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn consume_accepted_block_da_sets_consumes_included_complete_sets() {
        use crate::test_helpers::block_with_txs;
        let payload: &[u8] = b"mine-next-payload";
        let payload_wire = payload.len() as u64;
        let commit_tx = b"canonical-commit-tx";
        let chunk_tx = b"canonical-chunk-tx";
        let commit = |da_id, payloads: &[&[u8]], wire_bytes, tx_bytes: &[u8]| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_count: payloads.len() as u16,
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes, tx_bytes: &[u8]| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };

        let da_id = [80u8; 32];
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_commit(
                "commit-peer:8333",
                commit(da_id, &[payload], payload_wire, commit_tx),
            )
            .unwrap();
        state
            .stage_incomplete_da_chunk(
                "chunk-peer:8333",
                chunk(da_id, 0, payload, payload_wire, chunk_tx),
            )
            .unwrap();
        assert_eq!(
            state.sets_by_da_id[&da_id].state,
            DaRelaySetState::CompleteSet
        );
        assert!(state.pinned_payload_bytes > 0);

        // A block whose DA txs reference the same da_id (one commit + chunk 0).
        let block = block_with_txs(
            1,
            0,
            [0u8; 32],
            1_000,
            &[
                relay_test_tx(
                    0x01,
                    vec![da_commit_output([2u8; 32])],
                    Some(relay_commit_core(da_id, 1)),
                    None,
                    Vec::new(),
                ),
                relay_test_tx(
                    0x02,
                    Vec::new(),
                    None,
                    Some(relay_chunk_core(da_id, 0, payload)),
                    payload.to_vec(),
                ),
            ],
        );

        let relay = Arc::new(Mutex::new(state));
        consume_accepted_block_da_sets(&relay, &block).expect("consume");
        let relay = relay.lock().unwrap();
        assert!(!relay.sets_by_da_id.contains_key(&da_id));
        assert_eq!(relay.pinned_payload_bytes, 0);
    }

    #[test]
    fn consume_canonical_applied_da_sets_consumes_all_canonical_blocks() {
        use crate::chainstate::CanonicalAppliedBlock;
        use crate::test_helpers::block_with_txs;
        let payload: &[u8] = b"p2p-accept-payload";
        let payload_wire = payload.len() as u64;
        let commit_tx = b"canonical-commit-tx";
        let chunk_tx = b"canonical-chunk-tx";
        let commit = |da_id, payloads: &[&[u8]], wire_bytes, tx_bytes: &[u8]| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_count: payloads.len() as u16,
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes, tx_bytes: &[u8]| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };
        let block_for = |da_id, ts| {
            block_with_txs(
                1,
                0,
                [0u8; 32],
                ts,
                &[
                    relay_test_tx(
                        0x01,
                        vec![da_commit_output([2u8; 32])],
                        Some(relay_commit_core(da_id, 1)),
                        None,
                        Vec::new(),
                    ),
                    relay_test_tx(
                        0x02,
                        Vec::new(),
                        None,
                        Some(relay_chunk_core(da_id, 0, payload)),
                        payload.to_vec(),
                    ),
                ],
            )
        };

        let id_a = [81u8; 32];
        let id_b = [82u8; 32];
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        for (id, c, k) in [
            (id_a, "commit-a:8333", "chunk-a:8333"),
            (id_b, "commit-b:8333", "chunk-b:8333"),
        ] {
            state
                .stage_incomplete_da_commit(c, commit(id, &[payload], payload_wire, commit_tx))
                .unwrap();
            state
                .stage_incomplete_da_chunk(k, chunk(id, 0, payload, payload_wire, chunk_tx))
                .unwrap();
        }
        let relay = Mutex::new(state);

        // Side branch: empty canonical-applied list consumes nothing.
        consume_canonical_applied_da_sets(&relay, &[]).expect("side branch no-op");
        assert_eq!(relay.lock().unwrap().sets_by_da_id.len(), 2);

        // Both canonical-applied blocks consume their complete sets, in order.
        let blocks = vec![
            CanonicalAppliedBlock {
                hash: [0xa0; 32],
                block_bytes: block_for(id_a, 1_000),
            },
            CanonicalAppliedBlock {
                hash: [0xb0; 32],
                block_bytes: block_for(id_b, 1_001),
            },
        ];
        consume_canonical_applied_da_sets(&relay, &blocks).expect("consume canonical");
        let guard = relay.lock().unwrap();
        assert!(!guard.sets_by_da_id.contains_key(&id_a));
        assert!(!guard.sets_by_da_id.contains_key(&id_b));
        assert_eq!(guard.pinned_payload_bytes, 0);
        drop(guard);

        // Fail-closed: a malformed canonical block surfaces an error.
        let relay2 = Mutex::new(DaRelayState::new(DaRelayCaps::default()).unwrap());
        let bad = vec![CanonicalAppliedBlock {
            hash: [0xee; 32],
            block_bytes: vec![0x01, 0x02],
        }];
        assert!(consume_canonical_applied_da_sets(&relay2, &bad).is_err());

        // Best-effort: a malformed block between two valid canonical blocks does
        // not skip the others; the first error (naming that block) is surfaced.
        let id_c = [83u8; 32];
        let id_d = [84u8; 32];
        let mut state3 = DaRelayState::new(DaRelayCaps::default()).unwrap();
        for (id, c, k) in [
            (id_c, "commit-c:8333", "chunk-c:8333"),
            (id_d, "commit-d:8333", "chunk-d:8333"),
        ] {
            state3
                .stage_incomplete_da_commit(c, commit(id, &[payload], payload_wire, commit_tx))
                .unwrap();
            state3
                .stage_incomplete_da_chunk(k, chunk(id, 0, payload, payload_wire, chunk_tx))
                .unwrap();
        }
        let relay3 = Mutex::new(state3);
        let mixed = vec![
            CanonicalAppliedBlock {
                hash: [0xc0; 32],
                block_bytes: block_for(id_c, 1_002),
            },
            CanonicalAppliedBlock {
                hash: [0xee; 32],
                block_bytes: vec![0x01, 0x02],
            },
            CanonicalAppliedBlock {
                hash: [0xd0; 32],
                block_bytes: block_for(id_d, 1_003),
            },
        ];
        let err = consume_canonical_applied_da_sets(&relay3, &mixed)
            .expect_err("malformed middle block surfaces an error");
        assert!(
            err.contains(&hex::encode([0xee; 32])),
            "first error names the malformed block: {err}"
        );
        let guard3 = relay3.lock().unwrap();
        assert!(
            !guard3.sets_by_da_id.contains_key(&id_c),
            "block before the malformed one is consumed"
        );
        assert!(
            !guard3.sets_by_da_id.contains_key(&id_d),
            "block after the malformed one is still consumed (best-effort)"
        );
        assert_eq!(guard3.pinned_payload_bytes, 0);
    }

    #[test]
    fn da_relay_consume_complete_set_matrix() {
        let peer_commit = "commit-peer:8333";
        let peer_chunk = "chunk-peer:8333";
        let payload: &[u8] = b"consume-payload";
        let payload_wire = payload.len() as u64;
        let commit_tx = b"canonical-commit-tx";
        let chunk_tx = b"canonical-chunk-tx";
        let commit = |da_id, payloads: &[&[u8]], wire_bytes, tx_bytes: &[u8]| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_count: payloads.len() as u16,
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes, tx_bytes: &[u8]| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: PeerQuotaKey::from_peer_addr("forged:8333"),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
            tx_bytes: Arc::from(tx_bytes),
        };

        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_commit(
                peer_commit,
                commit([71; 32], &[payload], payload_wire, commit_tx),
            )
            .unwrap();
        state
            .stage_incomplete_da_chunk(
                peer_chunk,
                chunk([71; 32], 0, payload, payload_wire, chunk_tx),
            )
            .unwrap();
        assert_eq!(
            state.sets_by_da_id[&[71; 32]].state,
            DaRelaySetState::CompleteSet
        );
        let pinned_one = state.pinned_payload_bytes;
        assert!(pinned_one > 0);

        // Second, unrelated complete set with identical pinned footprint.
        state
            .stage_incomplete_da_commit(
                peer_commit,
                commit([73; 32], &[payload], payload_wire, commit_tx),
            )
            .unwrap();
        state
            .stage_incomplete_da_chunk(
                peer_chunk,
                chunk([73; 32], 0, payload, payload_wire, chunk_tx),
            )
            .unwrap();
        assert_eq!(state.pinned_payload_bytes, pinned_one * 2);

        // Mirror of Go RUB-428: consume removes the matching COMPLETE_SET and
        // releases its pinned payload bytes; the unrelated set is untouched.
        assert_eq!(state.consume_complete_set([71; 32]), Ok(true));
        assert!(!state.sets_by_da_id.contains_key(&[71; 32]));
        assert_eq!(
            state.sets_by_da_id[&[73; 32]].state,
            DaRelaySetState::CompleteSet
        );
        assert_eq!(state.pinned_payload_bytes, pinned_one);

        // Second consume cannot underflow: no-op false, accounting unchanged.
        assert_eq!(state.consume_complete_set([71; 32]), Ok(false));
        assert_eq!(state.pinned_payload_bytes, pinned_one);

        // Incomplete set (chunk only, no commit) is not consumed.
        state
            .stage_incomplete_da_chunk(
                peer_chunk,
                chunk([72; 32], 0, payload, payload_wire, chunk_tx),
            )
            .unwrap();
        assert_ne!(
            state.sets_by_da_id[&[72; 32]].state,
            DaRelaySetState::CompleteSet
        );
        assert_eq!(state.consume_complete_set([72; 32]), Ok(false));
        assert!(state.sets_by_da_id.contains_key(&[72; 32]));

        // Absent da_id is a no-op.
        assert_eq!(state.consume_complete_set([99; 32]), Ok(false));
    }

    #[test]
    fn da_relay_eviction_accounting_matrix() {
        let peer = "peer-a:8333";
        let pk = || PeerQuotaKey::from_peer_addr(peer);
        let commit = |da_id, payloads: &[&[u8]], wire_bytes| DaRelayCommit {
            da_id,
            payload_commitment: payload_commitment(payloads),
            peer_quota_key: pk(),
            chunk_count: payloads.len() as u16,
            wire_bytes,
            tx_bytes: Arc::from([]),
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: pk(),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
            tx_bytes: Arc::from([]),
        };
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        state
            .stage_incomplete_da_commit(peer, commit([42; 32], &[b"aa", b"bb"], 3))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer, chunk([42; 32], 0, b"aa", 4))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer, chunk([42; 32], 1, b"bb", 5))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer, commit([41; 32], &[b"staged"], 6))
            .unwrap();
        state
            .stage_incomplete_da_commit(peer, commit([40; 32], &[b"cccccc"], 7))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer, chunk([40; 32], 0, b"cccccc", 8))
            .unwrap();
        state
            .stage_incomplete_da_chunk(peer, chunk([39; 32], 0, b"orphan", 6))
            .unwrap();

        let record = &state.sets_by_da_id[&[42; 32]];
        let accounting = record
            .eviction_accounting()
            .expect("complete set accounting");
        assert_eq!(
            accounting,
            DaRelayEvictionAccounting {
                da_id: [42; 32],
                payload_bytes: 4,
                wire_bytes: record.wire_bytes,
                received_time: record.received_time
            }
        );
        assert!(state.sets_by_da_id[&[41; 32]]
            .eviction_accounting()
            .is_none());
        assert!(state.sets_by_da_id[&[39; 32]]
            .eviction_accounting()
            .is_none());
        let mut suppressed = record.clone();
        suppressed.payload_bytes = 0;
        assert!(suppressed.eviction_accounting().is_none());
        let mut suppressed = record.clone();
        suppressed.wire_bytes = 0;
        assert!(suppressed.eviction_accounting().is_none());
        let mut suppressed = record.clone();
        suppressed.received_time = 0;
        assert!(suppressed.eviction_accounting().is_none());
        let candidate_ids: Vec<_> = state
            .complete_set_eviction_candidates(u64::MAX)
            .map(|candidate| candidate.da_id)
            .collect();
        assert_eq!(candidate_ids, vec![[40; 32], [42; 32]]);
        let bounded_ids: Vec<_> = state
            .complete_set_eviction_candidates(6)
            .map(|candidate| candidate.da_id)
            .collect();
        assert_eq!(bounded_ids, vec![[40; 32]]);
        let later_fit_ids: Vec<_> = state
            .complete_set_eviction_candidates(4)
            .map(|candidate| candidate.da_id)
            .collect();
        assert_eq!(later_fit_ids, vec![[42; 32]]);
        let mut zero_budget = state.complete_set_eviction_candidates(0);
        assert_eq!(zero_budget.size_hint(), (0, Some(0)));
        assert!(zero_budget.next().is_none());
    }
}

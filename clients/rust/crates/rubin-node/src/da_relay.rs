use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use rubin_consensus::constants::{CHUNK_BYTES, MAX_DA_CHUNK_COUNT};
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
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaRelayChunk {
    da_id: [u8; 32],
    chunk_hash: [u8; 32],
    peer_quota_key: PeerQuotaKey,
    chunk_index: u16,
    payload: Arc<[u8]>,
    wire_bytes: u64,
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerQuotaKey(String);

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
            total = commit.wire_bytes;
            self.peer_bytes
                .insert(commit.peer_quota_key.clone(), commit.wire_bytes);
        }
        let peer_bytes = &mut self.peer_bytes;
        for chunk in self.chunks.values() {
            total = checked_add(total, chunk.wire_bytes)?;
            let entry = peer_bytes.entry(chunk.peer_quota_key.clone()).or_default();
            *entry = checked_add(*entry, chunk.wire_bytes)?;
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
    fn orphan_wire_bytes(&self) -> u64 {
        if self.state == DaRelaySetState::CompleteSet {
            0
        } else {
            self.wire_bytes
        }
    }
    fn orphan_commit_bytes(&self) -> u64 {
        if self.state == DaRelaySetState::CompleteSet {
            0
        } else {
            self.commit.as_ref().map_or(0, |commit| commit.wire_bytes)
        }
    }
    fn orphan_peer_bytes(&self) -> Option<&BTreeMap<PeerQuotaKey, u64>> {
        (self.state != DaRelaySetState::CompleteSet).then_some(&self.peer_bytes)
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
        checked_add(
            footprint,
            u64::from(chunk_count) * DA_COMPLETE_SET_CHUNK_FOOTPRINT,
        )
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
    pub(crate) fn stage_incomplete_da_chunk(
        &mut self,
        peer_addr: &str,
        mut chunk: DaRelayChunk,
    ) -> DaRelayResult {
        validate_da_chunk(&chunk)?;
        let current = self.sets_by_da_id.get(&chunk.da_id);
        if let Some(record) = current {
            record.validate_chunk_insert(chunk.chunk_index)?;
        }
        if sha3_256(chunk.payload.as_ref()) != chunk.chunk_hash {
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
        let old_bytes = old.map_or(0, DaRelaySetRecord::orphan_wire_bytes);
        let old_commit_bytes = old.map_or(0, DaRelaySetRecord::orphan_commit_bytes);
        let old_pinned_bytes =
            old.map_or(Ok(0), DaRelaySetRecord::pinned_payload_accounting_bytes)?;
        let new_bytes = record.orphan_wire_bytes();
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

fn checked_add(left: u64, right: u64) -> DaRelayResult<u64> {
    left.checked_add(right)
        .ok_or(DaRelayError::AccountingOverflow)
}

fn sha3_256(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
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
        let peer = "peer-a:8333"; let pk = || PeerQuotaKey::from_peer_addr(peer); let stage_commit = |state: &mut DaRelayState, commit| state.stage_incomplete_da_commit(peer, commit); let stage_chunk = |state: &mut DaRelayState, chunk| state.stage_incomplete_da_chunk(peer, chunk); let commit = |da_id, chunk_count, wire_bytes| DaRelayCommit { da_id, payload_commitment: [0; 32], peer_quota_key: pk(), chunk_count, wire_bytes }; let chunk = |da_id, chunk_index, payload: &[u8], wire_bytes| DaRelayChunk { da_id, chunk_hash: sha3_256(payload), peer_quota_key: pk(), chunk_index, payload: Arc::from(payload), wire_bytes }; let reject = |got: Result<(), DaRelayError>, want| assert_eq!(got, Err(want));
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
    #[rustfmt::skip]
    fn da_relay_complete_integrity_matrix() {
        let peer = "peer-a:8333"; let pk = || PeerQuotaKey::from_peer_addr(peer); let commit = |da_id, payloads: &[&[u8]], wire_bytes| DaRelayCommit { da_id, payload_commitment: payload_commitment(payloads), peer_quota_key: pk(), chunk_count: payloads.len() as u16, wire_bytes }; let chunk = |da_id, index, payload: &[u8], wire_bytes| DaRelayChunk { da_id, chunk_hash: sha3_256(payload), peer_quota_key: pk(), chunk_index: index, payload: Arc::from(payload), wire_bytes };
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_commit(peer, commit([20; 32], &[b"aa", b"bb"], 2)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([20; 32], 0, b"aa", 2)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([20; 32], 1, b"bb", 2)).unwrap(); let record = &state.sets_by_da_id[&[20; 32]]; let chunk_count = u64::from(record.commit.as_ref().unwrap().chunk_count); assert_eq!(record.state, DaRelaySetState::CompleteSet); assert_eq!(record.payload_bytes, 4); assert_eq!(record.ttl_blocks_remaining, 0); assert!(record.chunks.values().all(|chunk| chunk.payload.is_empty())); assert_eq!(state.orphan_bytes, 0); assert!(!state.orphan_bytes_by_da_id.contains_key(&[20; 32])); assert_eq!(state.pinned_payload_bytes, record.wire_bytes + DA_COMPLETE_SET_RECORD_FOOTPRINT + chunk_count * DA_COMPLETE_SET_CHUNK_FOOTPRINT);
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_commit(peer, commit([21; 32], &[b"good"], 1)).unwrap(); assert_eq!(state.stage_incomplete_da_chunk(peer, chunk([21; 32], 0, b"bad", 3)), Err(PayloadCommitmentMismatch)); let record = &state.sets_by_da_id[&[21; 32]]; assert_eq!(record.state, DaRelaySetState::StagedCommit); assert_eq!(record.payload_bytes, 0); assert!(record.chunks.is_empty() && record.replaceable_chunks.is_empty()); assert_eq!(state.pinned_payload_bytes, 0); state.stage_incomplete_da_chunk(peer, chunk([21; 32], 0, b"good", 4)).unwrap(); let record = &state.sets_by_da_id[&[21; 32]]; assert_eq!(record.state, DaRelaySetState::CompleteSet); assert!(record.replaceable_chunks.is_empty());
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([22; 32], 0, b"bad", 3)).unwrap(); assert_eq!(state.stage_incomplete_da_commit(peer, commit([22; 32], &[b"good"], 1)), Err(PayloadCommitmentMismatch)); let record = &state.sets_by_da_id[&[22; 32]]; assert_eq!(record.state, DaRelaySetState::StagedCommit); assert!(record.chunks.is_empty()); assert_eq!(state.pinned_payload_bytes, 0); state.stage_incomplete_da_chunk(peer, chunk([22; 32], 0, b"good", 4)).unwrap(); assert_eq!(state.sets_by_da_id[&[22; 32]].state, DaRelaySetState::CompleteSet);
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_commit(peer, commit([23; 32], &[b"aa", b"bb"], 1)).unwrap(); state.stage_incomplete_da_chunk(peer, chunk([23; 32], 0, b"aa", 2)).unwrap(); assert_eq!(state.stage_incomplete_da_chunk(peer, chunk([23; 32], 1, b"xx", 2)), Err(PayloadCommitmentMismatch)); let record = &state.sets_by_da_id[&[23; 32]]; assert_eq!(record.state, DaRelaySetState::StagedCommit); assert!(record.chunks.contains_key(&0) && !record.chunks.contains_key(&1)); assert!(record.replaceable_chunks.is_empty()); assert_eq!(state.pinned_payload_bytes, 0); state.stage_incomplete_da_chunk(peer, chunk([23; 32], 1, b"bb", 2)).unwrap(); assert_eq!(state.sets_by_da_id[&[23; 32]].state, DaRelaySetState::CompleteSet);
        let caps = DaRelayCaps { pinned_payload_bytes: 1, ..DaRelayCaps::default() }; let mut state = DaRelayState::new(caps).unwrap(); state.stage_incomplete_da_commit(peer, commit([24; 32], &[b"aa"], 1)).unwrap(); let before = state.clone(); assert_eq!(state.stage_incomplete_da_chunk(peer, chunk([24; 32], 0, b"aa", 2)), Err(AccountingCapExceeded)); assert_eq!(state, before);
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
        };
        let chunk = |da_id, index, payload: &[u8], wire_bytes| DaRelayChunk {
            da_id,
            chunk_hash: sha3_256(payload),
            peer_quota_key: pk(),
            chunk_index: index,
            payload: Arc::from(payload),
            wire_bytes,
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

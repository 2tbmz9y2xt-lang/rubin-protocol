use std::collections::BTreeMap;
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
    CompleteSetRequiresOwner,
}

type DaRelayResult<T = ()> = Result<T, DaRelayError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaRelayCommit {
    da_id: [u8; 32],
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
    wire_bytes: u64,
    peer_bytes: BTreeMap<PeerQuotaKey, u64>,
    commit: Option<DaRelayCommit>,
    chunks: BTreeMap<u16, DaRelayChunk>,
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
            wire_bytes: 0,
            peer_bytes: BTreeMap::new(),
            commit: None,
            chunks: BTreeMap::new(),
        }
    }

    fn validate_chunk_insert(&self, chunk_index: u16) -> DaRelayResult {
        if self.chunks.contains_key(&chunk_index) {
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

    pub(crate) fn stage_incomplete_da_commit(&mut self, commit: DaRelayCommit) -> DaRelayResult {
        if commit.chunk_count == 0 || u64::from(commit.chunk_count) > MAX_DA_CHUNK_COUNT {
            return Err(DaRelayError::InvalidCommitChunkCount);
        }
        if commit.wire_bytes == 0 {
            return Err(DaRelayError::InvalidWireBytes);
        }
        let old = self.sets_by_da_id.get(&commit.da_id);
        if old.is_some_and(|record| record.commit.is_some()) {
            return Err(DaRelayError::DuplicateCommit);
        }
        let mut record = old
            .cloned()
            .unwrap_or_else(|| DaRelaySetRecord::new(commit.da_id));
        record.commit = Some(commit);
        record.prune_chunks_outside_commit();
        self.prepare_and_apply_incomplete_record(record)
    }

    pub(crate) fn stage_incomplete_da_chunk(&mut self, chunk: DaRelayChunk) -> DaRelayResult {
        validate_da_chunk(&chunk)?;
        let current = self.sets_by_da_id.get(&chunk.da_id);
        if let Some(record) = current {
            record.validate_chunk_insert(chunk.chunk_index)?;
        }
        if sha3_256(chunk.payload.as_ref()) != chunk.chunk_hash {
            return Err(DaRelayError::ChunkHashMismatch);
        }
        let mut record = current
            .cloned()
            .unwrap_or_else(|| DaRelaySetRecord::new(chunk.da_id));
        record.chunks.insert(chunk.chunk_index, chunk);
        self.prepare_and_apply_incomplete_record(record)
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

    fn prepare_and_apply_incomplete_record(
        &mut self,
        mut record: DaRelaySetRecord,
    ) -> DaRelayResult {
        if record.commit.as_ref().is_some_and(|commit| {
            (0..commit.chunk_count).all(|index| record.chunks.contains_key(&index))
        }) {
            return Err(DaRelayError::CompleteSetRequiresOwner);
        }
        record.recompute_wire_bytes()?;
        let old = self.sets_by_da_id.get(&record.da_id);
        let old_bytes = old.map_or(0, |old| old.wire_bytes);
        let old_commit_bytes = old.map_or(0, |old| old.commit.as_ref().map_or(0, |c| c.wire_bytes));
        let new_commit_bytes = record.commit.as_ref().map_or(0, |c| c.wire_bytes);
        let peer_bytes = self.project_peer_bytes(old, &record)?;
        let da_id_current = self
            .orphan_bytes_by_da_id
            .get(&record.da_id)
            .copied()
            .unwrap_or(0);
        let orphan_bytes = Self::project_counter(
            self.orphan_bytes,
            old_bytes,
            record.wire_bytes,
            self.caps.orphan_pool_bytes,
        )?;
        let da_id_bytes = Self::project_counter(
            da_id_current,
            old_bytes,
            record.wire_bytes,
            self.caps.orphan_pool_per_da_id_bytes,
        )?;
        let commit_overhead = Self::project_counter(
            self.orphan_commit_overhead_bytes,
            old_commit_bytes,
            new_commit_bytes,
            self.caps.orphan_commit_overhead_bytes,
        )?;
        self.orphan_bytes = orphan_bytes;
        self.orphan_commit_overhead_bytes = commit_overhead;
        for (key, bytes) in peer_bytes {
            if bytes == 0 {
                self.orphan_bytes_by_peer_quota_key.remove(&key);
            } else {
                self.orphan_bytes_by_peer_quota_key.insert(key, bytes);
            }
        }
        self.orphan_bytes_by_da_id.insert(record.da_id, da_id_bytes);
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
        if let Some(old_record) = old {
            for (key, old_bytes) in &old_record.peer_bytes {
                let new_bytes = new.peer_bytes.get(key).copied().unwrap_or(0);
                projected.push(self.project_peer_counter(key, *old_bytes, new_bytes)?);
            }
        }
        for (key, new_bytes) in &new.peer_bytes {
            if old.is_some_and(|old_record| old_record.peer_bytes.contains_key(key)) {
                continue;
            }
            projected.push(self.project_peer_counter(key, 0, *new_bytes)?);
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

    #[test]
    #[rustfmt::skip]
    fn da_relay_staged_mutation_matrix() {
        let pk = || PeerQuotaKey::from_peer_addr("peer-a"); let commit = |da_id, chunk_count, wire_bytes| DaRelayCommit { da_id, peer_quota_key: pk(), chunk_count, wire_bytes }; let chunk = |da_id, chunk_index, payload: &[u8], wire_bytes| DaRelayChunk { da_id, chunk_hash: sha3_256(payload), peer_quota_key: pk(), chunk_index, payload: Arc::from(payload), wire_bytes }; let reject = |got: Result<(), DaRelayError>, want| assert_eq!(got, Err(want));
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap(); state.stage_incomplete_da_commit(commit([1; 32], 2, 2)).unwrap(); assert!(state.sets_by_da_id[&[1; 32]].commit.is_some()); state.stage_incomplete_da_chunk(chunk([1; 32], 0, b"payload-a", 9)).unwrap(); assert_eq!(state.sets_by_da_id[&[1; 32]].chunks.len(), 1);
        state.stage_incomplete_da_chunk(chunk([2; 32], 0, b"keep", 4)).unwrap(); state.stage_incomplete_da_chunk(chunk([2; 32], 2, b"prune", 5)).unwrap(); let before = state.clone(); reject(state.stage_incomplete_da_commit(commit([2; 32], 1, 1)), CompleteSetRequiresOwner); assert_eq!(state, before); state.stage_incomplete_da_commit(commit([2; 32], 2, 1)).unwrap(); let record = &state.sets_by_da_id[&[2; 32]]; assert!(record.chunks.contains_key(&0) && !record.chunks.contains_key(&2)); assert_eq!(state.orphan_bytes_by_da_id[&[2; 32]], record.wire_bytes);
        let mut state = DaRelayState::new(DaRelayCaps::default()).unwrap();
        reject(state.stage_incomplete_da_commit(commit([3; 32], 0, 1)), InvalidCommitChunkCount); reject(state.stage_incomplete_da_commit(commit([3; 32], 1, 0)), InvalidWireBytes); assert!(state.sets_by_da_id.is_empty());
        state.stage_incomplete_da_commit(commit([3; 32], 2, 1)).unwrap(); let before = state.clone(); let mut bad_hash = chunk([3; 32], 0, b"payload", 7); bad_hash.chunk_hash[0] ^= 0xff;
        reject(state.stage_incomplete_da_commit(commit([3; 32], 1, 1)), DuplicateCommit); reject(state.stage_incomplete_da_chunk(chunk([3; 32], 2, b"payload", 7)), ChunkIndexOutsideCommit); reject(state.stage_incomplete_da_chunk(bad_hash), ChunkHashMismatch); reject(state.stage_incomplete_da_chunk(chunk([3; 32], 0, b"", 1)), ChunkPayloadSizeInvalid); reject(state.stage_incomplete_da_chunk(chunk([3; 32], 0, b"payload", 1)), InvalidWireBytes); assert_eq!(state, before);
        state.stage_incomplete_da_chunk(chunk([3; 32], 0, b"payload", 7)).unwrap(); let before = state.clone(); reject(state.stage_incomplete_da_chunk(chunk([3; 32], 0, b"other", 5)), DuplicateChunk); assert_eq!(state, before);
        let caps = DaRelayCaps { orphan_pool_per_peer_bytes: 3, ..DaRelayCaps::default() };
        let mut state = DaRelayState::new(caps).unwrap(); state.stage_incomplete_da_chunk(chunk([4; 32], 0, b"ab", 2)).unwrap();
        let before = state.clone(); reject(state.stage_incomplete_da_chunk(chunk([5; 32], 0, b"cd", 2)), AccountingCapExceeded); assert_eq!(state, before);
        let mut state = DaRelayState::new(caps).unwrap(); state.stage_incomplete_da_chunk(chunk([6; 32], 0, b"a", 1)).unwrap();
        let before = state.clone(); reject(state.stage_incomplete_da_commit(commit([6; 32], 2, 3)), AccountingCapExceeded); assert_eq!(state, before);
    }
}

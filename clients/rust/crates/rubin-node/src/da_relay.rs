use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use rubin_consensus::constants::MAX_DA_BATCHES_PER_BLOCK;

pub const DA_ORPHAN_POOL_BYTES: u64 = 64 << 20;
pub const DA_ORPHAN_POOL_PER_PEER_BYTES: u64 = 4 << 20;
pub const DA_ORPHAN_POOL_PER_DA_ID_BYTES: u64 = 8 << 20;
pub const DA_ORPHAN_COMMIT_OVERHEAD_BYTES: u64 = 8 << 20;
pub const DA_ORPHAN_TTL_BLOCKS: u64 = 3;
pub const DA_PINNED_PAYLOAD_BYTES: u64 = 96_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaRelayCaps {
    pub orphan_pool_bytes: u64,
    pub orphan_pool_per_peer_bytes: u64,
    pub orphan_pool_per_da_id_bytes: u64,
    pub orphan_commit_overhead_bytes: u64,
    pub orphan_ttl_blocks: u64,
    pub pinned_payload_bytes: u64,
    pub max_complete_sets: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaRelayError {
    InvalidCaps,
    AccountingUnderflow,
    AccountingOverflow,
    AccountingCapExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerQuotaKey(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaRelayState {
    caps: DaRelayCaps,
    next_received_time: u64,
    orphan_bytes: u64,
    orphan_bytes_by_peer_quota_key: BTreeMap<PeerQuotaKey, u64>,
    orphan_bytes_by_da_id: BTreeMap<[u8; 32], u64>,
    orphan_commit_overhead_bytes: u64,
    pinned_payload_bytes: u64,
    sets_by_da_id: BTreeMap<[u8; 32], ()>,
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
            max_complete_sets: MAX_DA_BATCHES_PER_BLOCK,
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
            self.max_complete_sets,
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
        let host = addr
            .parse::<SocketAddr>()
            .map(|socket_addr| socket_addr.ip().to_string())
            .unwrap_or_else(|_| split_peer_host(addr).to_owned());
        Self(normalize_peer_host(&host))
    }
}

fn split_peer_host(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, _port)) = rest.split_once("]:") {
            return host;
        }
    }
    if addr.matches(':').count() == 1 {
        return addr.rsplit_once(':').map_or(addr, |(host, _port)| host);
    }
    addr
}

fn normalize_peer_host(host: &str) -> String {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.to_string();
    }
    if host.contains(':') {
        if let Some((without_zone, _zone)) = host.split_once('%') {
            if let Ok(ip) = without_zone.parse::<IpAddr>() {
                return ip.to_string();
            }
        }
    }
    host.to_owned()
}

impl DaRelayState {
    pub fn new(caps: DaRelayCaps) -> Result<Self, DaRelayError> {
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

    pub fn project_counter(
        current: u64,
        remove: u64,
        add: u64,
        cap: u64,
    ) -> Result<u64, DaRelayError> {
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
                assert_eq!(caps.validate(), Err(InvalidCaps));
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
            max_complete_sets = 0,
            orphan_pool_per_peer_bytes = DA_ORPHAN_POOL_BYTES + 1,
            orphan_pool_per_da_id_bytes = DA_ORPHAN_POOL_BYTES + 1,
            orphan_commit_overhead_bytes = DA_ORPHAN_POOL_BYTES + 1,
        );
    }

    #[test]
    fn da_relay_state_initializes_empty_accounting_maps() {
        let mut state = DaRelayState::new(DaRelayCaps::default()).expect("valid caps");
        assert_eq!(state.next_received_time, 0);
        assert!(state.is_empty());
        state.next_received_time = 1;
        assert!(state.is_empty());
    }

    #[test]
    fn peer_quota_key_normalizes_hostile_matrix() {
        for (addr, expected) in [
            ("", ""),
            ("127.0.0.1:8333", "127.0.0.1"),
            ("127.0.0.1:9444", "127.0.0.1"),
            ("127.0.0.1%zone:8333", "127.0.0.1%zone"),
            ("[::1]:8333", "::1"),
            ("fe80::1", "fe80::1"),
            ("fe80::1%en0", "fe80::1"),
            ("[fe80::1%en0]:8333", "fe80::1"),
            ("example.com:8333", "example.com"),
            ("[example.com]:8333", "example.com"),
            ("example.com", "example.com"),
            ("example.com%zone:8333", "example.com%zone"),
            ("[example.com%zone]:8333", "example.com%zone"),
            ("example.com%zone", "example.com%zone"),
        ] {
            assert_eq!(PeerQuotaKey::from_peer_addr(addr).0, expected);
        }
    }

    #[test]
    fn da_relay_accounting_projection_fails_closed() {
        for (current, remove, add, cap, expected) in [
            (0, 1, 0, 10, Err(AccountingUnderflow)),
            (u64::MAX, 0, 1, u64::MAX, Err(AccountingOverflow)),
            (9, 0, 2, 10, Err(AccountingCapExceeded)),
            (9, 4, 2, 10, Ok(7)),
        ] {
            assert_eq!(
                DaRelayState::project_counter(current, remove, add, cap),
                expected
            );
        }
    }
}

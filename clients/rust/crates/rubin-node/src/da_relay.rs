use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

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
            if !host.contains(']') && !port.contains(':') && !port.contains(['[', ']']) {
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

    #[allow(dead_code)]
    fn project_counter(current: u64, remove: u64, add: u64, cap: u64) -> Result<u64, DaRelayError> {
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
}

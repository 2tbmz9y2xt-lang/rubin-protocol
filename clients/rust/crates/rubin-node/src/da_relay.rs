use std::collections::BTreeMap;

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
    OrphanPoolBytesZero,
    OrphanPoolPerPeerBytesZero,
    OrphanPoolPerDaIdBytesZero,
    OrphanCommitOverheadBytesZero,
    OrphanTtlBlocksZero,
    PinnedPayloadBytesZero,
    MaxCompleteSetsZero,
    OrphanPoolPerPeerExceedsGlobal,
    OrphanPoolPerDaIdExceedsGlobal,
    OrphanCommitOverheadExceedsGlobal,
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
        macro_rules! reject_zero {
            ($field:ident, $err:expr) => {
                if self.$field == 0 {
                    return Err($err);
                }
            };
        }
        reject_zero!(orphan_pool_bytes, DaRelayError::OrphanPoolBytesZero);
        reject_zero!(
            orphan_pool_per_peer_bytes,
            DaRelayError::OrphanPoolPerPeerBytesZero
        );
        reject_zero!(
            orphan_pool_per_da_id_bytes,
            DaRelayError::OrphanPoolPerDaIdBytesZero
        );
        reject_zero!(
            orphan_commit_overhead_bytes,
            DaRelayError::OrphanCommitOverheadBytesZero
        );
        reject_zero!(orphan_ttl_blocks, DaRelayError::OrphanTtlBlocksZero);
        reject_zero!(pinned_payload_bytes, DaRelayError::PinnedPayloadBytesZero);
        reject_zero!(max_complete_sets, DaRelayError::MaxCompleteSetsZero);
        if self.orphan_pool_per_peer_bytes > self.orphan_pool_bytes {
            return Err(DaRelayError::OrphanPoolPerPeerExceedsGlobal);
        }
        if self.orphan_pool_per_da_id_bytes > self.orphan_pool_bytes {
            return Err(DaRelayError::OrphanPoolPerDaIdExceedsGlobal);
        }
        if self.orphan_commit_overhead_bytes > self.orphan_pool_bytes {
            return Err(DaRelayError::OrphanCommitOverheadExceedsGlobal);
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
            .parse::<std::net::SocketAddr>()
            .map(|socket_addr| socket_addr.ip().to_string())
            .unwrap_or_else(|_| split_peer_host(addr).to_owned());
        let host = strip_ipv6_zone(&host);
        host.parse::<std::net::IpAddr>()
            .map(|ip| Self(ip.to_string()))
            .unwrap_or_else(|_| Self(host.to_owned()))
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

fn strip_ipv6_zone(host: &str) -> &str {
    host.split_once('%').map_or(host, |(addr, _zone)| addr)
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

    pub fn caps(&self) -> DaRelayCaps {
        self.caps
    }

    pub fn is_empty(&self) -> bool {
        self.next_received_time == 0
            && self.orphan_bytes == 0
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
        let after_remove = current
            .checked_sub(remove)
            .ok_or(DaRelayError::AccountingUnderflow)?;
        let next = after_remove
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
    use super::*;
    use DaRelayError::*;

    #[test]
    fn da_relay_default_caps_match_go_reference() {
        let caps = DaRelayCaps::default();

        assert_eq!(caps.orphan_pool_bytes, 64 << 20);
        assert_eq!(caps.orphan_pool_per_peer_bytes, 4 << 20);
        assert_eq!(caps.orphan_pool_per_da_id_bytes, 8 << 20);
        assert_eq!(caps.orphan_commit_overhead_bytes, 8 << 20);
        assert_eq!(caps.orphan_ttl_blocks, 3);
        assert_eq!(caps.pinned_payload_bytes, 96_000_000);
        assert_eq!(caps.max_complete_sets, MAX_DA_BATCHES_PER_BLOCK);
    }

    #[test]
    fn da_relay_rejects_invalid_caps() {
        macro_rules! invalid {
            ($field:ident = $value:expr, $expected:expr) => {{
                let mut caps = DaRelayCaps::default();
                caps.$field = $value;
                let expected = $expected;
                assert_eq!(caps.validate(), Err(expected));
                assert_eq!(DaRelayState::new(caps), Err(expected));
            }};
        }

        invalid!(orphan_pool_bytes = 0, OrphanPoolBytesZero);
        invalid!(orphan_pool_per_peer_bytes = 0, OrphanPoolPerPeerBytesZero);
        invalid!(orphan_pool_per_da_id_bytes = 0, OrphanPoolPerDaIdBytesZero);
        invalid!(
            orphan_commit_overhead_bytes = 0,
            OrphanCommitOverheadBytesZero
        );
        invalid!(orphan_ttl_blocks = 0, OrphanTtlBlocksZero);
        invalid!(pinned_payload_bytes = 0, PinnedPayloadBytesZero);
        invalid!(max_complete_sets = 0, MaxCompleteSetsZero);
        invalid!(
            orphan_pool_per_peer_bytes = DA_ORPHAN_POOL_BYTES + 1,
            OrphanPoolPerPeerExceedsGlobal
        );
        invalid!(
            orphan_pool_per_da_id_bytes = DA_ORPHAN_POOL_BYTES + 1,
            OrphanPoolPerDaIdExceedsGlobal
        );
        invalid!(
            orphan_commit_overhead_bytes = DA_ORPHAN_POOL_BYTES + 1,
            OrphanCommitOverheadExceedsGlobal
        );
    }

    #[test]
    fn da_relay_state_initializes_empty_accounting_maps() {
        let caps = DaRelayCaps::default();
        let state = DaRelayState::new(caps).expect("valid caps");

        assert_eq!(state.caps(), caps);
        assert!(state.is_empty());
    }

    #[test]
    fn peer_quota_key_normalizes_port_variants() {
        assert_eq!(
            PeerQuotaKey::from_peer_addr("127.0.0.1:8333"),
            PeerQuotaKey::from_peer_addr("127.0.0.1:9444")
        );
        assert_eq!(
            PeerQuotaKey::from_peer_addr("[::1]:8333"),
            PeerQuotaKey("::1".to_owned())
        );
        assert_eq!(
            PeerQuotaKey::from_peer_addr("example.com:8333"),
            PeerQuotaKey("example.com".to_owned())
        );
        assert_eq!(
            PeerQuotaKey::from_peer_addr(""),
            PeerQuotaKey(String::new())
        );
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

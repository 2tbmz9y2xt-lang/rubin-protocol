//! Bounded DA relay prefetch scheduler (RUB-404) — Rust mirror of the Go
//! `daRelayPrefetchState` planner in `da_relay_state.go`. Reserves missing DA
//! chunks across peers under per-peer, global, TTL, and concurrent-set caps
//! without re-requesting fulfilled or in-flight chunks. The caller supplies the
//! currently-missing chunk indexes and candidate peer keys; this module owns
//! only reservation bookkeeping — never the DA set records, wire codec,
//! provider/miner, or runtime send/serve paths.

use std::collections::{BTreeMap, BTreeSet};

use rubin_consensus::constants::CHUNK_BYTES;

// Caps mirror the Go `daPrefetch*` constants.
const DA_PREFETCH_PER_PEER_BYTES: u64 = 4_000_000;
const DA_PREFETCH_GLOBAL_BYTES: u64 = 32_000_000;
const DA_PREFETCH_MAX_CONCURRENT_SETS: usize = 8;
// `daPrefetchRequestTTL` = 1s; time is supplied by the caller in nanoseconds so
// planning stays deterministic for tests.
const DA_PREFETCH_REQUEST_TTL_NANOS: u64 = 1_000_000_000;

/// Per-peer prefetch request: chunk indexes reserved for `peer_key` of `da_id`
/// (mirror of Go `daRelayPrefetchPlan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaRelayPrefetchPlan {
    pub da_id: [u8; 32],
    pub peer_key: String,
    pub indexes: Vec<u16>,
}

/// In-flight DA chunk prefetch reservations (mirror of Go `daRelayPrefetchState`).
#[derive(Debug, Default)]
pub struct DaRelayPrefetchState {
    /// da_id -> { chunk_index -> reserved peer key }.
    indexes: BTreeMap<[u8; 32], BTreeMap<u16, String>>,
    /// da_id -> reservation expiry (ns); absent means no live plan.
    expires: BTreeMap<[u8; 32], u64>,
}

impl DaRelayPrefetchState {
    /// Plan prefetch for the currently-missing chunks of `da_id` across
    /// `peer_keys` (mirror of Go `planDAPrefetch`). The runtime caller must
    /// supply host-only per-peer quota keys (as Go's allDAPrefetchPeersLocked
    /// does via peerQuotaKey) so the byte cap is not bypassed by source port.
    /// `missing` (sorted+deduped) and `peer_keys` (empty-filtered + deduped,
    /// order preserved) are normalized internally, so planning is deterministic
    /// and emits no duplicate per-peer plan. An empty `missing` releases the set.
    pub fn plan_da_prefetch(
        &mut self,
        da_id: [u8; 32],
        missing: &[u16],
        peer_keys: &[String],
        now_nanos: u64,
    ) -> (Vec<DaRelayPrefetchPlan>, String) {
        // Normalize missing (sorted-unique) and peers (non-empty, order-preserving
        // unique) so planning is deterministic and never duplicates a per-peer plan.
        let mut missing: Vec<u16> = missing.to_vec();
        missing.sort_unstable();
        missing.dedup();
        let mut peers: Vec<String> = Vec::new();
        for key in peer_keys {
            if !key.is_empty() && !peers.contains(key) {
                peers.push(key.clone());
            }
        }
        self.release_expired(now_nanos);
        if missing.is_empty() {
            self.release_set(da_id);
            return (Vec::new(), String::new());
        }
        self.release_fulfilled(da_id, &missing);
        if peers.is_empty() {
            return (Vec::new(), String::new());
        }
        // Concurrent-set cap: only a brand-new set counts against it.
        if !self.indexes.contains_key(&da_id)
            && self.indexes.len() >= DA_PREFETCH_MAX_CONCURRENT_SETS
        {
            return (
                Vec::new(),
                "da prefetch global set cap exceeded".to_string(),
            );
        }
        let (plans_by_peer, diagnostic) = self.reserve_missing(da_id, &missing, &peers, now_nanos);
        (
            build_da_prefetch_plans(da_id, &peers, &plans_by_peer),
            diagnostic,
        )
    }

    /// Release a failed send's reservations, but only those still owned by the
    /// plan's peer (mirror of Go `releaseDAPrefetchPlan`).
    pub fn release_da_prefetch_plan(&mut self, plan: &DaRelayPrefetchPlan) {
        let Some(set) = self.indexes.get_mut(&plan.da_id) else {
            return;
        };
        for index in &plan.indexes {
            if set.get(index) == Some(&plan.peer_key) {
                set.remove(index);
            }
        }
        if set.is_empty() {
            self.release_set(plan.da_id);
        }
    }

    fn release_expired(&mut self, now_nanos: u64) {
        let expired: Vec<[u8; 32]> = self
            .expires
            .iter()
            .filter(|(_, &at)| at != 0 && now_nanos >= at)
            .map(|(&da_id, _)| da_id)
            .collect();
        for da_id in expired {
            self.release_set(da_id);
        }
    }

    fn release_fulfilled(&mut self, da_id: [u8; 32], missing: &[u16]) {
        let Some(set) = self.indexes.get_mut(&da_id) else {
            return;
        };
        if set.is_empty() {
            return;
        }
        let still_missing: BTreeSet<u16> = missing.iter().copied().collect();
        set.retain(|index, _| still_missing.contains(index));
        if set.is_empty() {
            self.release_set(da_id);
        }
    }

    fn reserve_missing(
        &mut self,
        da_id: [u8; 32],
        missing: &[u16],
        peer_keys: &[String],
        now_nanos: u64,
    ) -> (BTreeMap<String, Vec<u16>>, String) {
        let (mut global_bytes, mut peer_bytes) = self.bytes_in_flight();
        let mut plans_by_peer: BTreeMap<String, Vec<u16>> = BTreeMap::new();
        let mut peer_index = 0usize;
        for &index in missing {
            let in_flight = self
                .indexes
                .get(&da_id)
                .is_some_and(|set| set.contains_key(&index));
            if in_flight {
                continue;
            }
            let (peer_key, reason) =
                next_da_prefetch_peer(peer_keys, &peer_bytes, global_bytes, &mut peer_index);
            let Some(peer_key) = peer_key else {
                self.expire_planned(da_id, &plans_by_peer, now_nanos);
                return (plans_by_peer, reason);
            };
            self.indexes
                .entry(da_id)
                .or_default()
                .insert(index, peer_key.clone());
            global_bytes += CHUNK_BYTES;
            *peer_bytes.entry(peer_key.clone()).or_default() += CHUNK_BYTES;
            plans_by_peer.entry(peer_key).or_default().push(index);
        }
        self.expire_planned(da_id, &plans_by_peer, now_nanos);
        (plans_by_peer, String::new())
    }

    fn expire_planned(
        &mut self,
        da_id: [u8; 32],
        plans_by_peer: &BTreeMap<String, Vec<u16>>,
        now_nanos: u64,
    ) {
        if !plans_by_peer.is_empty() {
            self.expires
                .insert(da_id, now_nanos + DA_PREFETCH_REQUEST_TTL_NANOS);
        }
    }

    fn release_set(&mut self, da_id: [u8; 32]) {
        self.indexes.remove(&da_id);
        self.expires.remove(&da_id);
    }

    fn bytes_in_flight(&self) -> (u64, BTreeMap<String, u64>) {
        let mut peer_bytes: BTreeMap<String, u64> = BTreeMap::new();
        let mut global_bytes = 0u64;
        for set in self.indexes.values() {
            for peer_key in set.values() {
                global_bytes += CHUNK_BYTES;
                *peer_bytes.entry(peer_key.clone()).or_default() += CHUNK_BYTES;
            }
        }
        (global_bytes, peer_bytes)
    }
}

/// Next peer that can accept another chunk under the global then per-peer byte
/// caps, rotating from `peer_index` (mirror of Go `nextDAPrefetchPeer`).
fn next_da_prefetch_peer(
    peer_keys: &[String],
    peer_bytes: &BTreeMap<String, u64>,
    global_bytes: u64,
    peer_index: &mut usize,
) -> (Option<String>, String) {
    if peer_keys.is_empty() {
        return (None, String::new());
    }
    if global_bytes + CHUNK_BYTES > DA_PREFETCH_GLOBAL_BYTES {
        return (None, "da prefetch global byte cap exceeded".to_string());
    }
    for checked in 0..peer_keys.len() {
        let idx = (*peer_index + checked) % peer_keys.len();
        let key = &peer_keys[idx];
        if peer_bytes.get(key).copied().unwrap_or(0) + CHUNK_BYTES <= DA_PREFETCH_PER_PEER_BYTES {
            *peer_index = idx + 1;
            return (Some(key.clone()), String::new());
        }
    }
    (None, "da prefetch per-peer byte cap exceeded".to_string())
}

/// Per-peer plans in `peer_keys` order, dropping empties (mirror of Go
/// `buildDAPrefetchPlans`).
fn build_da_prefetch_plans(
    da_id: [u8; 32],
    peer_keys: &[String],
    plans_by_peer: &BTreeMap<String, Vec<u16>>,
) -> Vec<DaRelayPrefetchPlan> {
    let mut plans = Vec::new();
    for peer_key in peer_keys {
        match plans_by_peer.get(peer_key) {
            Some(indexes) if !indexes.is_empty() => plans.push(DaRelayPrefetchPlan {
                da_id,
                peer_key: peer_key.clone(),
                indexes: indexes.clone(),
            }),
            _ => {}
        }
    }
    plans
}

#[cfg(test)]
mod tests {
    use super::*;

    const DA: [u8; 32] = [0x42; 32];

    fn keys(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }
    fn total(plans: &[DaRelayPrefetchPlan]) -> usize {
        plans.iter().map(|p| p.indexes.len()).sum()
    }

    #[test]
    fn plans_missing_only_and_skips_in_flight_on_retry() {
        let mut s = DaRelayPrefetchState::default();
        let (plans, diag) = s.plan_da_prefetch(DA, &[0, 1, 2], &keys(&["peer-a"]), 1_000);
        assert!(diag.is_empty() && total(&plans) == 3);
        // In-flight chunks are not re-requested on a retry within TTL.
        let (retry, diag) = s.plan_da_prefetch(DA, &[0, 1, 2], &keys(&["peer-a"]), 1_000);
        assert!(diag.is_empty() && total(&retry) == 0);
    }

    #[test]
    fn releases_fulfilled_chunks_before_replanning() {
        let mut s = DaRelayPrefetchState::default();
        assert_eq!(
            total(
                &s.plan_da_prefetch(DA, &[0, 1, 2, 3], &keys(&["peer-a"]), 1_000)
                    .0
            ),
            4
        );
        // Chunk 0 fulfilled: caller now reports only 1,2,3 missing.
        let (retry, diag) = s.plan_da_prefetch(DA, &[1, 2, 3], &keys(&["peer-a"]), 1_000);
        assert!(diag.is_empty() && total(&retry) == 0);
        assert!(!s.indexes[&DA].contains_key(&0) && s.indexes[&DA].len() == 3);
    }

    #[test]
    fn empty_missing_releases_completed_set() {
        let mut s = DaRelayPrefetchState::default();
        s.plan_da_prefetch(DA, &[0, 1], &keys(&["peer-a"]), 1_000);
        let (plans, diag) = s.plan_da_prefetch(DA, &[], &keys(&["peer-a"]), 1_000);
        assert!(plans.is_empty() && diag.is_empty() && !s.indexes.contains_key(&DA));
    }

    #[test]
    fn expired_reservation_is_released_then_replanned() {
        let mut s = DaRelayPrefetchState::default();
        s.plan_da_prefetch(DA, &[0], &keys(&["peer-a"]), 1_000);
        let now = 1_000 + DA_PREFETCH_REQUEST_TTL_NANOS;
        let (plans, diag) = s.plan_da_prefetch(DA, &[0], &keys(&["peer-a"]), now);
        assert!(diag.is_empty() && total(&plans) == 1);
    }

    #[test]
    fn per_peer_cap_bounds_one_peer_with_diagnostic() {
        let mut s = DaRelayPrefetchState::default();
        let cap = (DA_PREFETCH_PER_PEER_BYTES / CHUNK_BYTES) as u16; // 7
        let missing: Vec<u16> = (0..=cap).collect(); // one over the per-peer cap
        let (plans, diag) = s.plan_da_prefetch(DA, &missing, &keys(&["peer-a"]), 1_000);
        assert_eq!(total(&plans), cap as usize);
        assert_eq!(diag, "da prefetch per-peer byte cap exceeded");
    }

    #[test]
    fn global_cap_bounds_total_across_peers() {
        let mut s = DaRelayPrefetchState::default();
        let cap = (DA_PREFETCH_GLOBAL_BYTES / CHUNK_BYTES) as usize; // 61
        let peers: Vec<String> = (0..200).map(|i| format!("peer-{i}")).collect();
        let missing: Vec<u16> = (0..(cap as u16 + 5)).collect();
        let (plans, diag) = s.plan_da_prefetch(DA, &missing, &peers, 1_000);
        assert_eq!(total(&plans), cap);
        assert_eq!(diag, "da prefetch global byte cap exceeded");
    }

    #[test]
    fn concurrent_set_cap_rejects_a_ninth_set() {
        let mut s = DaRelayPrefetchState::default();
        // Distinct peer per set so only the concurrent-set cap can bound it.
        for i in 0..DA_PREFETCH_MAX_CONCURRENT_SETS as u8 {
            let mut da = [0u8; 32];
            da[0] = i;
            let (plans, diag) = s.plan_da_prefetch(da, &[0], &keys(&[&format!("p{i}")]), 1_000);
            assert!(total(&plans) == 1 && diag.is_empty());
        }
        let (plans, diag) = s.plan_da_prefetch([0xFF; 32], &[0], &keys(&["pz"]), 1_000);
        assert!(plans.is_empty());
        assert_eq!(diag, "da prefetch global set cap exceeded");
    }

    #[test]
    fn deterministic_peer_rotation_round_robins() {
        let mut s = DaRelayPrefetchState::default();
        // Unordered+duplicate missing and empty/duplicate peer keys are normalized
        // (missing -> [0,1,2]; peers -> unique [peer-a,peer-b,peer-c]), so rotation
        // is deterministic and no peer gets a duplicate plan.
        let (plans, diag) = s.plan_da_prefetch(
            DA,
            &[2, 0, 2, 1],
            &keys(&["peer-a", "", "peer-b", "peer-a", "peer-c"]),
            1_000,
        );
        assert!(diag.is_empty());
        assert_eq!(plans.len(), 3, "one plan per unique peer, no duplicates");
        let by_peer: BTreeMap<&str, &Vec<u16>> = plans
            .iter()
            .map(|p| (p.peer_key.as_str(), &p.indexes))
            .collect();
        assert_eq!(
            (by_peer[&"peer-a"], by_peer[&"peer-b"], by_peer[&"peer-c"]),
            (&vec![0], &vec![1], &vec![2])
        );
    }

    #[test]
    fn send_failure_release_only_releases_matching_reservations() {
        let mut s = DaRelayPrefetchState::default();
        let plan = s
            .plan_da_prefetch(DA, &[0, 1], &keys(&["peer-a"]), 1_000)
            .0
            .into_iter()
            .next()
            .expect("one plan");
        // A stale plan citing the wrong peer releases nothing.
        s.release_da_prefetch_plan(&DaRelayPrefetchPlan {
            da_id: DA,
            peer_key: "peer-b".to_string(),
            indexes: vec![0, 1],
        });
        assert_eq!(s.indexes[&DA].len(), 2);
        // The real failed send releases exactly its reservations and clears the set.
        s.release_da_prefetch_plan(&plan);
        assert!(!s.indexes.contains_key(&DA));
    }

    #[test]
    fn no_peers_plans_nothing_without_reserving() {
        let mut s = DaRelayPrefetchState::default();
        let (plans, diag) = s.plan_da_prefetch(DA, &[0, 1], &[], 1_000);
        assert!(plans.is_empty() && diag.is_empty() && !s.indexes.contains_key(&DA));
    }
}

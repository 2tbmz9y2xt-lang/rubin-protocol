use std::collections::HashMap;
use std::sync::Mutex;

/// Default maximum relay pool size (matches Go `defaultMaxTxPoolSize` in `mempool.go`).
const DEFAULT_MAX_RELAY_POOL_SIZE: usize = 1000;

/// P2P relay transaction pool — separate from the consensus `TxPool`.
///
/// Stores raw transaction bytes for GETDATA responses. Evicts by fee-rate
/// when full (lowest fee-rate tx is replaced if the incoming tx has higher
/// fee-rate). Matches Go's `MemoryTxPool` in `p2p/mempool.go`.
pub struct RelayTxPool {
    inner: Mutex<RelayTxPoolInner>,
}

struct RelayTxPoolInner {
    txs: HashMap<[u8; 32], RelayTxEntry>,
    max_size: usize,
}

struct RelayTxEntry {
    raw: Vec<u8>,
    fee: u64,
    size: usize,
}

impl Default for RelayTxPool {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayTxPool {
    pub fn new() -> Self {
        Self::new_with_limit(DEFAULT_MAX_RELAY_POOL_SIZE)
    }

    pub fn new_with_limit(max_size: usize) -> Self {
        let max_size = if max_size == 0 {
            DEFAULT_MAX_RELAY_POOL_SIZE
        } else {
            max_size
        };
        Self {
            inner: Mutex::new(RelayTxPoolInner {
                txs: HashMap::with_capacity(max_size),
                max_size,
            }),
        }
    }

    /// Store a transaction in the relay pool. Returns `true` if accepted.
    ///
    /// If the pool is full, the lowest fee-rate tx is evicted — but only if
    /// the incoming tx has strictly higher priority. Matches Go `Put`.
    pub fn put(&self, txid: [u8; 32], raw: &[u8], fee: u64, size: usize) -> bool {
        let size = if size == 0 { raw.len() } else { size };
        if size == 0 {
            return false;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if inner.txs.contains_key(&txid) {
            return false;
        }
        if inner.txs.len() >= inner.max_size {
            let (worst_txid, worst_fee, worst_size) = match find_worst(&inner.txs) {
                Some(w) => w,
                None => return false,
            };
            if compare_relay_priority(fee, size, txid, worst_fee, worst_size, worst_txid) <= 0 {
                return false;
            }
            inner.txs.remove(&worst_txid);
        }
        inner.txs.insert(
            txid,
            RelayTxEntry {
                raw: raw.to_vec(),
                fee,
                size,
            },
        );
        true
    }

    /// Retrieve raw tx bytes by txid.
    pub fn get(&self, txid: &[u8; 32]) -> Option<Vec<u8>> {
        let Ok(inner) = self.inner.lock() else {
            return None;
        };
        inner.txs.get(txid).map(|e| e.raw.clone())
    }

    /// Returns `true` if txid is in the pool.
    pub fn has(&self, txid: &[u8; 32]) -> bool {
        let Ok(inner) = self.inner.lock() else {
            return false;
        };
        inner.txs.contains_key(txid)
    }

    /// Returns current pool size.
    pub fn len(&self) -> usize {
        let Ok(inner) = self.inner.lock() else {
            return 0;
        };
        inner.txs.len()
    }

    /// Returns `true` if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Find the worst (lowest priority) entry in the pool.
fn find_worst(txs: &HashMap<[u8; 32], RelayTxEntry>) -> Option<([u8; 32], u64, usize)> {
    let mut worst: Option<([u8; 32], u64, usize)> = None;
    for (&txid, entry) in txs {
        match worst {
            None => worst = Some((txid, entry.fee, entry.size)),
            Some((w_txid, w_fee, w_size)) => {
                if compare_relay_priority(entry.fee, entry.size, txid, w_fee, w_size, w_txid) < 0 {
                    worst = Some((txid, entry.fee, entry.size));
                }
            }
        }
    }
    worst
}

/// Compare relay priority of two transactions.
///
/// Returns negative if a < b, positive if a > b, zero if equal.
/// Order: fee-rate (cross-multiply) → raw fee → txid (reversed: lower txid = higher priority).
/// Matches Go `compareRelayPriority` in `p2p/mempool.go`.
pub fn compare_relay_priority(
    a_fee: u64,
    a_size: usize,
    a_txid: [u8; 32],
    b_fee: u64,
    b_size: usize,
    b_txid: [u8; 32],
) -> i32 {
    let cmp = compare_relay_fee_rate(a_fee, a_size, b_fee, b_size);
    if cmp != 0 {
        return cmp;
    }
    if a_fee != b_fee {
        return if a_fee > b_fee { 1 } else { -1 };
    }
    // Reversed txid comparison: lower txid = higher priority (matches Go).
    match a_txid.cmp(&b_txid) {
        std::cmp::Ordering::Less => 1,
        std::cmp::Ordering::Greater => -1,
        std::cmp::Ordering::Equal => 0,
    }
}

/// Compare fee rates using cross-multiplication to avoid floating point.
/// a_fee/a_size vs b_fee/b_size → a_fee * b_size vs b_fee * a_size.
/// Uses u128 multiplication matching Go's `bits.Mul64`.
fn compare_relay_fee_rate(a_fee: u64, a_size: usize, b_fee: u64, b_size: usize) -> i32 {
    if a_size == 0 || b_size == 0 {
        return 0;
    }
    let a_cross = (a_fee as u128) * (b_size as u128);
    let b_cross = (b_fee as u128) * (a_size as u128);
    match a_cross.cmp(&b_cross) {
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_roundtrip() {
        let pool = RelayTxPool::new_with_limit(10);
        let txid = [1u8; 32];
        let raw = vec![0xDE, 0xAD];
        assert!(pool.put(txid, &raw, 100, 50));
        assert_eq!(pool.get(&txid).unwrap(), raw);
    }

    #[test]
    fn put_returns_false_for_duplicate() {
        let pool = RelayTxPool::new_with_limit(10);
        let txid = [2u8; 32];
        assert!(pool.put(txid, &[1], 100, 50));
        assert!(!pool.put(txid, &[1], 100, 50));
    }

    #[test]
    fn put_returns_false_for_zero_size_empty_raw() {
        let pool = RelayTxPool::new_with_limit(10);
        let txid = [3u8; 32];
        assert!(!pool.put(txid, &[], 100, 0));
    }

    #[test]
    fn eviction_when_full_by_fee_rate() {
        let pool = RelayTxPool::new_with_limit(2);
        let low = [1u8; 32];
        let mid = [2u8; 32];
        let high = [3u8; 32];

        // Fill pool with low and mid fee-rate txs.
        assert!(pool.put(low, &[0x01], 10, 100)); // fee_rate = 0.1
        assert!(pool.put(mid, &[0x02], 50, 100)); // fee_rate = 0.5

        // High fee-rate tx should evict the lowest.
        assert!(pool.put(high, &[0x03], 200, 100)); // fee_rate = 2.0
        assert_eq!(pool.len(), 2);
        assert!(!pool.has(&low)); // Evicted.
        assert!(pool.has(&mid));
        assert!(pool.has(&high));
    }

    #[test]
    fn eviction_rejects_lower_priority_than_worst() {
        let pool = RelayTxPool::new_with_limit(1);
        let existing = [1u8; 32];
        let incoming = [2u8; 32];

        assert!(pool.put(existing, &[0x01], 100, 100)); // fee_rate = 1.0
                                                        // Incoming has lower fee-rate — should be rejected.
        assert!(!pool.put(incoming, &[0x02], 10, 100)); // fee_rate = 0.1
        assert!(pool.has(&existing));
        assert!(!pool.has(&incoming));
    }

    #[test]
    fn has_reflects_current_state() {
        let pool = RelayTxPool::new_with_limit(10);
        let txid = [4u8; 32];
        assert!(!pool.has(&txid));
        pool.put(txid, &[1], 100, 50);
        assert!(pool.has(&txid));
    }

    #[test]
    fn is_empty_works() {
        let pool = RelayTxPool::new();
        assert!(pool.is_empty());
        pool.put([1u8; 32], &[1], 100, 50);
        assert!(!pool.is_empty());
    }

    #[test]
    fn compare_relay_fee_rate_cross_multiply() {
        // a: fee=3, size=2 → rate=1.5
        // b: fee=2, size=2 → rate=1.0
        assert_eq!(compare_relay_fee_rate(3, 2, 2, 2), 1);
        assert_eq!(compare_relay_fee_rate(2, 2, 3, 2), -1);
        assert_eq!(compare_relay_fee_rate(2, 2, 2, 2), 0);
    }

    #[test]
    fn compare_relay_fee_rate_zero_size() {
        assert_eq!(compare_relay_fee_rate(100, 0, 100, 100), 0);
        assert_eq!(compare_relay_fee_rate(100, 100, 100, 0), 0);
    }

    #[test]
    fn compare_relay_priority_tiebreak_by_fee_then_txid() {
        let a = [1u8; 32]; // lower txid = higher priority
        let b = [2u8; 32];
        // Same fee-rate, same fee → compare txids (reversed).
        assert_eq!(compare_relay_priority(100, 50, a, 100, 50, b), 1); // a > b
        assert_eq!(compare_relay_priority(100, 50, b, 100, 50, a), -1); // b < a
    }

    #[test]
    fn compare_relay_priority_fee_tiebreak() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        // Same fee-rate (both 1.0) but different raw fees.
        assert_eq!(compare_relay_priority(200, 200, a, 100, 100, b), 1); // higher fee wins
        assert_eq!(compare_relay_priority(100, 100, a, 200, 200, b), -1);
    }

    #[test]
    fn default_capacity_when_zero() {
        let pool = RelayTxPool::new_with_limit(0);
        // Should use DEFAULT_MAX_RELAY_POOL_SIZE (1000).
        let txid = [42u8; 32];
        assert!(pool.put(txid, &[1], 100, 50));
        assert!(pool.has(&txid));
    }
}

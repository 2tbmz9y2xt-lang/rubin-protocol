use std::collections::HashMap;

use crate::error::{ErrorCode, TxError};
use crate::tx::Tx;
use crate::utxo_basic::{Outpoint, UtxoEntry};

/// Immutable block-start view of the UTXO set for read-only input resolution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UtxoSnapshot {
    utxos: HashMap<Outpoint, UtxoEntry>,
    count: usize,
}

impl UtxoSnapshot {
    pub fn new(utxos: Option<&HashMap<Outpoint, UtxoEntry>>) -> Self {
        match utxos {
            Some(utxos) => {
                let utxos = utxos.clone();
                let count = utxos.len();
                Self { utxos, count }
            }
            None => Self::default(),
        }
    }

    pub fn get(&self, op: &Outpoint) -> Option<&UtxoEntry> {
        self.utxos.get(op)
    }

    pub fn contains(&self, op: &Outpoint) -> bool {
        self.utxos.contains_key(op)
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn resolve_inputs(&self, tx: &Tx) -> Result<Vec<UtxoEntry>, TxError> {
        let mut entries = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let op = Outpoint {
                txid: input.prev_txid,
                vout: input.prev_vout,
            };
            let entry = self.get(&op).cloned().ok_or_else(|| {
                TxError::new(ErrorCode::TxErrMissingUtxo, "input references missing UTXO")
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(Outpoint, UtxoEntry),
    {
        for (op, entry) in &self.utxos {
            f(op.clone(), entry.clone());
        }
    }
}

pub fn utxo_snapshot_shard(op: &Outpoint, num_shards: usize) -> usize {
    if num_shards <= 1 {
        return 0;
    }

    let h = u32::from(op.txid[0]) << 24
        | u32::from(op.txid[1]) << 16
        | u32::from(op.txid[2]) << 8
        | u32::from(op.txid[3]);
    (h % num_shards as u32) as usize
}

#[cfg(kani)]
mod verification {
    use super::utxo_snapshot_shard;
    use crate::utxo_basic::Outpoint;

    #[kani::proof]
    fn verify_utxo_snapshot_shard_zero_and_one_return_zero_for_any_outpoint() {
        let txid: [u8; 32] = kani::any();
        let vout: u32 = kani::any();
        let op = Outpoint { txid, vout };

        assert_eq!(utxo_snapshot_shard(&op, 0), 0);
        assert_eq!(utxo_snapshot_shard(&op, 1), 0);
    }

    #[kani::proof]
    fn verify_utxo_snapshot_shard_is_bounded_and_deterministic_for_representative_count() {
        let txid: [u8; 32] = kani::any();
        let vout: u32 = kani::any();
        let op = Outpoint { txid, vout };
        let num_shards = 17usize;
        let shard = utxo_snapshot_shard(&op, num_shards);

        assert!(shard < num_shards);
        assert_eq!(shard, utxo_snapshot_shard(&op, num_shards));
    }

    #[kani::proof]
    fn verify_utxo_snapshot_shard_ignores_vout_for_representative_count() {
        let txid: [u8; 32] = kani::any();
        let vout_a: u32 = kani::any();
        let vout_b: u32 = kani::any();
        let op_a = Outpoint { txid, vout: vout_a };
        let op_b = Outpoint { txid, vout: vout_b };
        let num_shards = 31usize;

        assert_eq!(
            utxo_snapshot_shard(&op_a, num_shards),
            utxo_snapshot_shard(&op_b, num_shards)
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use crate::tx::{Tx, TxInput};
    use crate::utxo_basic::{Outpoint, UtxoEntry};

    use super::{utxo_snapshot_shard, UtxoSnapshot};

    fn test_outpoint(txid_byte: u8, vout: u32) -> Outpoint {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        Outpoint { txid, vout }
    }

    fn test_entry(value: u64, covenant_type: u16) -> UtxoEntry {
        UtxoEntry {
            value,
            covenant_type,
            covenant_data: Vec::new(),
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn test_utxo_set() -> HashMap<Outpoint, UtxoEntry> {
        HashMap::from([
            (test_outpoint(0xaa, 0), test_entry(1000, 0)),
            (test_outpoint(0xaa, 1), test_entry(2000, 0)),
            (test_outpoint(0xbb, 0), test_entry(3000, 1)),
            (test_outpoint(0xcc, 0), test_entry(4000, 2)),
        ])
    }

    fn tx_with_inputs(inputs: &[(u8, u32)]) -> Tx {
        Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: inputs
                .iter()
                .map(|(txid_byte, vout)| TxInput {
                    prev_txid: test_outpoint(*txid_byte, *vout).txid,
                    prev_vout: *vout,
                    script_sig: Vec::new(),
                    sequence: 0,
                })
                .collect(),
            outputs: Vec::new(),
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        }
    }

    #[test]
    fn utxo_snapshot_nil_is_empty() {
        let snapshot = UtxoSnapshot::new(None);
        assert_eq!(snapshot.count(), 0);
        assert!(snapshot.get(&test_outpoint(0xaa, 0)).is_none());
    }

    #[test]
    fn utxo_snapshot_empty_map_is_empty() {
        let utxos = HashMap::new();
        let snapshot = UtxoSnapshot::new(Some(&utxos));
        assert_eq!(snapshot.count(), 0);
    }

    #[test]
    fn utxo_snapshot_basic_lookup_and_contains() {
        let utxos = test_utxo_set();
        let snapshot = UtxoSnapshot::new(Some(&utxos));

        assert_eq!(snapshot.count(), 4);
        assert_eq!(snapshot.get(&test_outpoint(0xaa, 0)).unwrap().value, 1000);
        assert_eq!(snapshot.get(&test_outpoint(0xbb, 0)).unwrap().value, 3000);
        assert_eq!(
            snapshot.get(&test_outpoint(0xbb, 0)).unwrap().covenant_type,
            1
        );
        assert!(snapshot.contains(&test_outpoint(0xaa, 0)));
        assert!(!snapshot.contains(&test_outpoint(0xff, 0)));
        assert!(snapshot.get(&test_outpoint(0xff, 0)).is_none());
    }

    #[test]
    fn utxo_snapshot_is_immutable_after_creation() {
        let mut utxos = test_utxo_set();
        let snapshot = UtxoSnapshot::new(Some(&utxos));

        utxos.remove(&test_outpoint(0xaa, 0));
        utxos.insert(test_outpoint(0xff, 0), test_entry(9999, 0));

        assert_eq!(snapshot.count(), 4);
        assert_eq!(snapshot.get(&test_outpoint(0xaa, 0)).unwrap().value, 1000);
        assert!(!snapshot.contains(&test_outpoint(0xff, 0)));
    }

    #[test]
    fn utxo_snapshot_concurrent_reads_are_stable() {
        let snapshot = Arc::new(UtxoSnapshot::new(Some(&test_utxo_set())));
        let ops = vec![
            test_outpoint(0xaa, 0),
            test_outpoint(0xaa, 1),
            test_outpoint(0xbb, 0),
            test_outpoint(0xcc, 0),
        ];

        let mut handles = Vec::new();
        for i in 0..100usize {
            let snapshot = Arc::clone(&snapshot);
            let ops = ops.clone();
            handles.push(std::thread::spawn(move || {
                let op = &ops[i % ops.len()];
                let entry = snapshot.get(op).expect("snapshot entry");
                assert!(entry.value > 0);
            }));
        }

        for handle in handles {
            handle.join().expect("join");
        }
    }

    #[test]
    fn utxo_snapshot_shard_zero_and_one_shard_return_zero() {
        let op = test_outpoint(0xaa, 0);
        assert_eq!(utxo_snapshot_shard(&op, 0), 0);
        assert_eq!(utxo_snapshot_shard(&op, 1), 0);
    }

    #[test]
    fn utxo_snapshot_shard_is_deterministic() {
        let op = test_outpoint(0xab, 3);
        assert_eq!(utxo_snapshot_shard(&op, 8), utxo_snapshot_shard(&op, 8));
    }

    #[test]
    fn utxo_snapshot_shard_distributes_nontrivially() {
        let mut counts = [0usize; 4];
        for i in 0..256u16 {
            let mut txid = [0u8; 32];
            txid[0] = i as u8;
            txid[1] = (i * 7) as u8;
            txid[2] = (i * 13) as u8;
            txid[3] = (i * 31) as u8;
            let shard = utxo_snapshot_shard(&Outpoint { txid, vout: 0 }, 4);
            assert!(shard < 4);
            counts[shard] += 1;
        }
        assert!(counts.iter().all(|count| *count > 0));
    }

    #[test]
    fn utxo_snapshot_same_txid_different_vout_same_shard() {
        assert_eq!(
            utxo_snapshot_shard(&test_outpoint(0xaa, 0), 8),
            utxo_snapshot_shard(&test_outpoint(0xaa, 1), 8)
        );
    }

    #[test]
    fn utxo_snapshot_resolve_inputs_all_found() {
        let snapshot = UtxoSnapshot::new(Some(&test_utxo_set()));
        let tx = tx_with_inputs(&[(0xaa, 0), (0xbb, 0)]);

        let entries = snapshot.resolve_inputs(&tx).expect("resolve inputs");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, 1000);
        assert_eq!(entries[1].value, 3000);
    }

    #[test]
    fn utxo_snapshot_resolve_inputs_missing_utxo() {
        let snapshot = UtxoSnapshot::new(Some(&test_utxo_set()));
        let tx = tx_with_inputs(&[(0xaa, 0), (0xff, 0)]);

        let err = snapshot.resolve_inputs(&tx).unwrap_err();
        assert_eq!(err.code.as_str(), "TX_ERR_MISSING_UTXO");
    }

    #[test]
    fn utxo_snapshot_resolve_inputs_empty_inputs() {
        let snapshot = UtxoSnapshot::new(Some(&test_utxo_set()));
        let tx = tx_with_inputs(&[]);

        let entries = snapshot.resolve_inputs(&tx).expect("empty inputs");
        assert!(entries.is_empty());
    }

    #[test]
    fn utxo_snapshot_for_each_visits_all_entries() {
        let snapshot = UtxoSnapshot::new(Some(&test_utxo_set()));
        let total_value = Arc::new(Mutex::new(0u64));
        let count = Arc::new(Mutex::new(0usize));

        let total_value_ref = Arc::clone(&total_value);
        let count_ref = Arc::clone(&count);
        snapshot.for_each(|_, entry| {
            *count_ref.lock().unwrap() += 1;
            *total_value_ref.lock().unwrap() += entry.value;
        });

        assert_eq!(*count.lock().unwrap(), 4);
        assert_eq!(*total_value.lock().unwrap(), 10_000);
    }

    #[test]
    fn utxo_snapshot_sequential_parallel_parity() {
        let mut utxos = HashMap::with_capacity(100);
        for i in 0..100u8 {
            utxos.insert(
                test_outpoint(i, 0),
                test_entry((i as u64) * 100, (i % 3) as u16),
            );
        }
        let snapshot = Arc::new(UtxoSnapshot::new(Some(&utxos)));

        let mut sequential = HashMap::new();
        for i in 0..100u8 {
            let op = test_outpoint(i, 0);
            sequential.insert(op.clone(), snapshot.get(&op).unwrap().clone());
        }

        let parallel = Arc::new(Mutex::new(HashMap::new()));
        let mut handles = Vec::new();
        for i in 0..100u8 {
            let snapshot = Arc::clone(&snapshot);
            let parallel = Arc::clone(&parallel);
            handles.push(std::thread::spawn(move || {
                let op = test_outpoint(i, 0);
                let entry = snapshot.get(&op).expect("parallel entry").clone();
                parallel.lock().unwrap().insert(op, entry);
            }));
        }

        for handle in handles {
            handle.join().expect("join");
        }

        let parallel = parallel.lock().unwrap();
        for (op, entry) in sequential {
            assert_eq!(parallel.get(&op), Some(&entry));
        }
    }
}

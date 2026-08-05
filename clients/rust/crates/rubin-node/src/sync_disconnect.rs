use std::collections::HashSet;

use rubin_consensus::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use rubin_consensus::{parse_block_header_bytes, Outpoint};

use crate::chainstate::ChainState;
use crate::io_utils::is_atomic_write_post_commit;
use crate::sync::SyncEngine;
use crate::sync_reorg::{load_verified_stored_block, VerifiedStoredBlock};
use crate::undo::{BlockUndo, ChainStateDisconnectSummary};

impl ChainState {
    /// Disconnect one already-loaded stored block without parsing its bytes a
    /// second time. This preserves `disconnect_block`'s validation and
    /// copy-before-mutation order for the retained parsed representation.
    fn disconnect_verified_stored_block(
        &mut self,
        stored: &VerifiedStoredBlock,
        undo: &BlockUndo,
    ) -> Result<ChainStateDisconnectSummary, String> {
        if !self.has_tip {
            return Err("chainstate has no tip".into());
        }
        if self.height != undo.block_height {
            return Err(format!(
                "disconnect height mismatch: chainstate={} undo={}",
                self.height, undo.block_height
            ));
        }

        let pb = &stored.parsed;
        if pb.txs.len() != pb.txids.len() {
            return Err("parsed block txid length mismatch".into());
        }
        if undo.txs.len() != pb.txs.len() {
            return Err("undo tx count mismatch".into());
        }
        if self.tip_hash != stored.lookup_hash {
            return Err("disconnect block is not current tip".into());
        }

        let mut created_outpoints = HashSet::new();
        let mut same_block_spent_outpoints = HashSet::new();
        for (tx_index, tx) in pb.txs.iter().enumerate() {
            if tx_index > 0 {
                for input in &tx.inputs {
                    let outpoint = Outpoint {
                        txid: input.prev_txid,
                        vout: input.prev_vout,
                    };
                    if created_outpoints.contains(&outpoint) {
                        same_block_spent_outpoints.insert(outpoint);
                    }
                }
            }
            for (output_index, out) in tx.outputs.iter().enumerate() {
                if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
                    continue;
                }
                created_outpoints.insert(Outpoint {
                    txid: pb.txids[tx_index],
                    vout: output_index as u32,
                });
            }
        }

        let mut work = self.utxos.clone();
        let mut restored_outpoints = HashSet::new();
        for tx_index in (0..pb.txs.len()).rev() {
            let tx = &pb.txs[tx_index];
            let txid = pb.txids[tx_index];
            for (output_index, out) in tx.outputs.iter().enumerate() {
                if out.covenant_type == COV_TYPE_ANCHOR || out.covenant_type == COV_TYPE_DA_COMMIT {
                    continue;
                }
                let created_outpoint = Outpoint {
                    txid,
                    vout: output_index as u32,
                };
                if work.remove(&created_outpoint).is_none()
                    && !same_block_spent_outpoints.contains(&created_outpoint)
                {
                    return Err(format!(
                        "disconnect missing created output for {}:{}",
                        hex::encode(created_outpoint.txid),
                        created_outpoint.vout
                    ));
                }
            }
            for spent in &undo.txs[tx_index].spent {
                if !restored_outpoints.insert(spent.outpoint.clone()) {
                    return Err(format!(
                        "undo duplicate restore entry for {}:{}",
                        hex::encode(spent.outpoint.txid),
                        spent.outpoint.vout
                    ));
                }
                if work.contains_key(&spent.outpoint) {
                    return Err(format!(
                        "undo restore target already present for {}:{}",
                        hex::encode(spent.outpoint.txid),
                        spent.outpoint.vout
                    ));
                }
                work.insert(spent.outpoint.clone(), spent.entry.clone());
            }
        }

        self.utxos = work;
        self.already_generated = undo.previous_already_generated;
        if self.height == 0 {
            self.has_tip = false;
            self.height = 0;
            self.tip_hash = [0u8; 32];
        } else {
            self.height -= 1;
            self.tip_hash = pb.header.prev_block_hash;
        }

        Ok(ChainStateDisconnectSummary {
            disconnected_height: undo.block_height,
            block_hash: stored.lookup_hash,
            new_height: self.height,
            new_tip_hash: self.tip_hash,
            has_tip: self.has_tip,
            already_generated: self.already_generated,
            utxo_count: self.utxos.len() as u64,
        })
    }
}

impl SyncEngine {
    /// Disconnect the current canonical tip block, restoring the chain state
    /// to the parent. Returns a summary of the disconnection.
    pub fn disconnect_tip(&mut self) -> Result<ChainStateDisconnectSummary, String> {
        let stored = self.prepare_disconnect_tip()?;
        self.disconnect_prepared_tip(&stored)
    }

    fn prepare_disconnect_tip(&self) -> Result<VerifiedStoredBlock, String> {
        self.mutation_allowed()?;
        let (_, tip_hash) = self.current_disconnect_tip()?;
        let block_store = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?;
        load_verified_stored_block(block_store, tip_hash).map_err(|err| err.render(tip_hash))
    }

    fn current_disconnect_tip(&self) -> Result<(u64, [u8; 32]), String> {
        let (tip_height, tip_hash) = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?
            .tip()?
            .ok_or("blockstore has no canonical tip")?;
        if !self.chain_state.has_tip
            || self.chain_state.height != tip_height
            || self.chain_state.tip_hash != tip_hash
        {
            return Err("chainstate tip does not match blockstore tip".into());
        }
        Ok((tip_height, tip_hash))
    }

    fn parent_timestamp(
        &self,
        tip_height: u64,
        stored: &VerifiedStoredBlock,
    ) -> Result<u64, String> {
        if tip_height == 0 {
            return Ok(0);
        }
        let parent_header_bytes = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?
            .get_header_by_hash(stored.parsed.header.prev_block_hash)?;
        Ok(parse_block_header_bytes(&parent_header_bytes)
            .map_err(|err| err.to_string())?
            .timestamp)
    }

    fn disconnect_prepared_tip(
        &mut self,
        stored: &VerifiedStoredBlock,
    ) -> Result<ChainStateDisconnectSummary, String> {
        let (tip_height, tip_hash) = self.current_disconnect_tip()?;
        if tip_hash != stored.lookup_hash {
            return Err("disconnect block is not current canonical tip".into());
        }
        let undo = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?
            .get_undo(tip_hash)?;
        let new_tip_timestamp = self.parent_timestamp(tip_height, stored)?;
        let rollback = self.capture_rollback_state();
        let summary = self
            .chain_state
            .disconnect_verified_stored_block(stored, &undo)?;

        // Truncate canonical index FIRST, then persist chain state — matching
        // Go DisconnectTip ordering (B.7 fix, issue #1170).  A crash between
        // truncate and save leaves the canonical index short while chainstate
        // still has the old tip; the mismatch guard at the top of this
        // function detects and rejects this on restart.
        let truncate_result = self
            .block_store
            .as_mut()
            .ok_or("sync engine has no blockstore")?
            .truncate_canonical_typed(rollback.canonical_len.saturating_sub(1));
        if let Err(error) = truncate_result {
            if is_atomic_write_post_commit(&error) {
                return Err(self.handle_persistence_error(error, true, false));
            }
            // truncate_canonical leaves the canonical index unchanged on
            // failure because BlockStore::truncate_canonical updates its
            // in-memory canonical only after the disk write succeeds.
            // Restore the captured in-memory snapshot directly.  Going
            // through rollback_apply_block would re-call
            // truncate_canonical(rb.canonical_len), which can fail again
            // under the same root cause and short-circuit before
            // restoring chain_state, leaving the engine desynced.
            self.chain_state = rollback.chain_state;
            self.tip_timestamp = rollback.tip_timestamp;
            self.best_known_height = rollback.best_known_height;
            return Err(error.to_string());
        }

        // Test-only seam to exercise the otherwise-unreachable
        // blockstore-missing branch in the save-failure recovery below.
        #[cfg(test)]
        if self.drop_block_store_after_truncate {
            self.block_store = None;
        }

        if let Some(path) = self.cfg.chain_state_path.as_ref() {
            if let Err(error) = self.chain_state.save_atomic(path) {
                if is_atomic_write_post_commit(&error) {
                    return Err(self.handle_persistence_error(error, false, true));
                }
                let err = error.to_string();
                // Restore canonical tip directly, then restore in-memory
                // state inline.  Going through rollback_apply_block here
                // would trigger a second canonical write (light-rollback
                // truncate_canonical(rb.canonical_len)) on an already
                // restored index, which can fail independently and leave
                // chain_state un-rolled-back.
                //
                // Blockstore presence is an invariant at this point (it
                // was Some at function entry and the successful truncate
                // above proves it still is), but we propagate a normal
                // error if it's somehow missing rather than panic in a
                // sync hot path.
                let canonical_restore = self.block_store.as_mut().map(|bs| {
                    bs.rollback_canonical_typed(
                        rollback.canonical_len.saturating_sub(1),
                        vec![hex::encode(tip_hash)],
                    )
                });
                let canonical_rb = match canonical_restore {
                    Some(Ok(())) => None,
                    Some(Err(error)) if is_atomic_write_post_commit(&error) => {
                        let error = self.handle_persistence_error(error, true, false);
                        self.chain_state = rollback.chain_state;
                        self.tip_timestamp = rollback.tip_timestamp;
                        self.best_known_height = rollback.best_known_height;
                        return Err(error);
                    }
                    Some(Err(error)) => Some(format!("canonical restore failed: {error}")),
                    None => {
                        // Canonical restore cannot be attempted; align the
                        // in-memory tip with the disconnected parent and
                        // surface both errors via err_with_rollback.
                        self.tip_timestamp = new_tip_timestamp;
                        return Err(SyncEngine::err_with_rollback(
                            err,
                            Some("blockstore missing after canonical truncate".into()),
                        ));
                    }
                };
                // Only restore in-memory state if canonical rollback succeeded.
                // If canonical is still truncated and we restore chain_state to
                // the pre-disconnect tip, the next operation hits the
                // mismatch guard at the top of disconnect_tip.  Leaving
                // chain_state in its post-disconnect_block state keeps it
                // aligned with the truncated canonical (both at parent tip).
                if canonical_rb.is_none() {
                    self.chain_state = rollback.chain_state;
                    self.tip_timestamp = rollback.tip_timestamp;
                    self.best_known_height = rollback.best_known_height;
                } else {
                    // Canonical stays truncated; align tip_timestamp with the
                    // disconnected parent so is_in_ibd() and other freshness
                    // metadata don't keep reporting the old tip.
                    self.tip_timestamp = new_tip_timestamp;
                }
                return Err(SyncEngine::err_with_rollback(err, canonical_rb));
            }
        }

        self.tip_timestamp = new_tip_timestamp;
        Ok(summary)
    }

    /// Disconnect blocks from the canonical chain down to (but not including)
    /// the given ancestor height. Returns the disconnected block bytes in
    /// tip-to-ancestor order.
    pub fn disconnect_canonical_to_ancestor(
        &mut self,
        common_ancestor_height: u64,
    ) -> Result<Vec<Vec<u8>>, String> {
        let mut preview_state = self.chain_state.clone();
        let prepared =
            self.prepare_canonical_disconnect_packet(&mut preview_state, common_ancestor_height)?;
        Ok(self
            .disconnect_prepared_canonical_to_ancestor(prepared)?
            .into_iter()
            .map(|stored| stored.block_bytes)
            .collect())
    }

    fn prepare_canonical_disconnect_packet(
        &self,
        preview_state: &mut ChainState,
        common_ancestor_height: u64,
    ) -> Result<Vec<VerifiedStoredBlock>, String> {
        self.mutation_allowed()?;
        let (tip_height, _) = self.current_disconnect_tip()?;
        if common_ancestor_height >= tip_height {
            return Ok(Vec::new());
        }
        let block_store = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?;
        let mut packet = Vec::new();
        for height in ((common_ancestor_height + 1)..=tip_height).rev() {
            let hash = block_store
                .canonical_hash(height)?
                .ok_or("blockstore has no canonical tip")?;
            let stored =
                load_verified_stored_block(block_store, hash).map_err(|err| err.render(hash))?;
            packet.push(stored);
        }
        self.preview_disconnect_packet(preview_state, &packet)?;
        Ok(packet)
    }

    /// Non-mutating preview: disconnect a copy of chain state down to a common
    /// ancestor. Used by `prepare_heavier_branch()` for dry-run validation.
    pub(crate) fn preview_disconnect_canonical_to_ancestor(
        &self,
        preview_state: &mut ChainState,
        common_ancestor_height: u64,
    ) -> Result<Vec<VerifiedStoredBlock>, String> {
        self.prepare_canonical_disconnect_packet(preview_state, common_ancestor_height)
    }

    fn preview_disconnect_packet(
        &self,
        state: &mut ChainState,
        packet: &[VerifiedStoredBlock],
    ) -> Result<(), String> {
        let block_store = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?;
        for stored in packet {
            let undo = block_store.get_undo(stored.lookup_hash)?;
            state.disconnect_verified_stored_block(stored, &undo)?;
        }
        Ok(())
    }

    pub(crate) fn disconnect_prepared_canonical_to_ancestor(
        &mut self,
        packet: Vec<VerifiedStoredBlock>,
    ) -> Result<Vec<VerifiedStoredBlock>, String> {
        self.mutation_allowed()?;
        let mut disconnected = Vec::with_capacity(packet.len());
        for stored in packet {
            self.disconnect_prepared_tip(&stored)?;
            disconnected.push(stored);
        }
        Ok(disconnected)
    }
}

#[cfg(test)]
mod tests {
    use rubin_consensus::constants::POW_LIMIT;
    use rubin_consensus::{block_hash, BLOCK_HEADER_BYTES};

    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, ChainState};
    use crate::io_utils::unique_temp_path;
    use crate::sync::{default_sync_config, SyncEngine};
    use crate::sync_reorg::BRANCH_STORE_CORRUPT_ERR;
    use crate::test_helpers::{
        coinbase_only_block_with_gen, genesis_info, height_one_coinbase_only_block,
    };
    use crate::undo::UNDO_INTEGRITY_PREFIX;

    #[derive(Debug, PartialEq, Eq)]
    struct DisconnectSnapshot {
        state: ChainState,
        tip: Option<(u64, [u8; 32])>,
        index: Vec<[u8; 32]>,
        timestamp: u64,
    }

    fn engine_with_store(suffix: &str) -> (SyncEngine, std::path::PathBuf) {
        let dir = unique_temp_path(suffix);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let store = BlockStore::create(block_store_path(&dir)).expect("create blockstore");
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], Some(chain_state_path(&dir)));
        let engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("new sync");
        (engine, dir)
    }

    fn disconnect_snapshot(engine: &SyncEngine) -> DisconnectSnapshot {
        let store = engine.block_store.as_ref().expect("blockstore");
        DisconnectSnapshot {
            state: engine.chain_state.clone(),
            tip: store.tip().expect("tip"),
            index: (0..store.canonical_len())
                .map(|height| {
                    store
                        .canonical_hash(height as u64)
                        .expect("canonical")
                        .expect("hash")
                })
                .collect(),
            timestamp: engine.tip_timestamp,
        }
    }

    /// Pins RUB-1132 step 7 on the standalone disconnect path: a parse-valid but
    /// checksum-broken undo record must be refused BEFORE any canonical
    /// mutation, leaving chainstate, the canonical index, the blockstore tip and
    /// the persisted snapshot exactly as they were. The tail restores the record
    /// and disconnects for real, so a change that made this path reject
    /// everything could not pass. Go twin:
    /// `TestDisconnectCorruptUndoLeavesStateUnchanged`.
    #[test]
    fn disconnect_corrupt_undo_leaves_state_unchanged() {
        use crate::undo::{corrupt_stored_undo_checksum, UNDO_CHECKSUM_MISMATCH_ERR};

        let (mut engine, dir) = engine_with_store("rubin-disc-corrupt-undo");
        let (genesis, genesis_hash, gen_ts) = genesis_info();
        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        let block1_hash =
            rubin_consensus::block_hash(&block1[..BLOCK_HEADER_BYTES]).expect("block1 hash");
        engine.apply_block(&block1, None).expect("block 1");

        let before = disconnect_snapshot(&engine);
        let chain_state_path = chain_state_path(&dir);
        let before_snapshot = std::fs::read(&chain_state_path).expect("read chainstate snapshot");

        let undo_dir = engine
            .block_store
            .as_ref()
            .expect("blockstore")
            .root_dir()
            .join("undo");
        let (corrupt, original) = corrupt_stored_undo_checksum(&undo_dir, block1_hash);

        let err = engine
            .disconnect_tip()
            .expect_err("disconnect accepted a checksum-broken undo record");
        assert_eq!(err, UNDO_CHECKSUM_MISMATCH_ERR);

        assert_eq!(
            disconnect_snapshot(&engine),
            before,
            "refused disconnect mutated chainstate, tip, or canonical index"
        );
        assert_eq!(
            std::fs::read(&chain_state_path).expect("re-read chainstate snapshot"),
            before_snapshot,
            "refused disconnect rewrote the persisted chainstate"
        );
        assert_eq!(
            std::fs::read(undo_dir.join(format!("{}.json", hex::encode(block1_hash))))
                .expect("re-read undo"),
            corrupt,
            "refused disconnect rewrote the undo record"
        );

        // Positive control: the same disconnect must succeed once the record is
        // valid again, so the rejection above is attributable to the corruption.
        std::fs::write(
            undo_dir.join(format!("{}.json", hex::encode(block1_hash))),
            &original,
        )
        .expect("restore undo");
        let summary = engine.disconnect_tip().expect("disconnect after restore");
        assert_eq!(summary.disconnected_height, 1);
        assert_eq!(engine.chain_state.height, 0);
        assert_eq!(engine.chain_state.tip_hash, genesis_hash);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn disconnect_tip_restores_genesis_state() {
        let (mut engine, dir) = engine_with_store("rubin-disc-tip");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine.apply_block(&block1, None).expect("block 1");
        assert_eq!(engine.chain_state.height, 1);
        let utxos_h1 = engine.chain_state.utxos.len();

        let summary = engine.disconnect_tip().expect("disconnect");
        assert_eq!(summary.disconnected_height, 1);
        assert_eq!(summary.new_height, 0);
        assert_eq!(summary.new_tip_hash, genesis_hash);
        assert!(summary.has_tip);
        assert_eq!(engine.chain_state.height, 0);
        assert!(engine.chain_state.utxos.len() < utxos_h1);

        let tip = engine
            .block_store
            .as_ref()
            .unwrap()
            .tip()
            .expect("tip")
            .expect("some");
        assert_eq!(tip.0, 0);
        assert_eq!(tip.1, genesis_hash);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn disconnect_tip_to_pre_genesis() {
        let (mut engine, dir) = engine_with_store("rubin-disc-gen");
        let (genesis, _, _) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        assert!(engine.chain_state.has_tip);

        let summary = engine.disconnect_tip().expect("disconnect genesis");
        assert_eq!(summary.disconnected_height, 0);
        assert!(!summary.has_tip);
        assert!(!engine.chain_state.has_tip);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn disconnect_canonical_to_ancestor_unwinds() {
        let (mut engine, dir) = engine_with_store("rubin-disc-anc");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine.apply_block(&block1, None).expect("block 1");
        assert_eq!(engine.chain_state.height, 1);

        let disconnected = engine
            .disconnect_canonical_to_ancestor(0)
            .expect("disconnect to ancestor");
        assert_eq!(disconnected.len(), 1);
        assert_eq!(engine.chain_state.height, 0);
        assert_eq!(engine.chain_state.tip_hash, genesis_hash);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn canonical_disconnect_packet_rejects_later_corruption_before_mutation() {
        for (name, kind, malformed, want) in [
            ("body", 'b', None, BRANCH_STORE_CORRUPT_ERR),
            ("parent header missing", 'h', None, "read header"),
            (
                "parent header malformed",
                'h',
                Some(b"bad".as_slice()),
                "block header length mismatch",
            ),
            ("tip undo missing", 'u', None, "read undo"),
            // RUB-1132: a malformed record is now refused by the envelope
            // reader before any payload decode, so the stable cross-client
            // UNDO_INTEGRITY identity is what this row pins.
            (
                "tip undo malformed",
                'u',
                Some(b"{".as_slice()),
                UNDO_INTEGRITY_PREFIX,
            ),
        ] {
            let (mut engine, dir) = engine_with_store(&format!("rubin-disc-packet-{name}"));
            let (genesis, genesis_hash, gen_ts) = genesis_info();
            engine.apply_block(&genesis, None).expect("genesis");
            let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
            engine.apply_block(&block1, None).expect("block 1");
            let block1_hash = block_hash(&block1[..BLOCK_HEADER_BYTES]).expect("block 1 hash");
            let subsidy = rubin_consensus::subsidy::block_subsidy(1, 0);
            let block2 = coinbase_only_block_with_gen(2, subsidy, block1_hash, gen_ts + 2);
            let block2_hash = block_hash(&block2[..BLOCK_HEADER_BYTES]).expect("block 2 hash");
            engine.apply_block(&block2, None).expect("block 2");
            let before = disconnect_snapshot(&engine);
            let packet = if kind != 'b' {
                let mut preview = engine.chain_state.clone();
                let packet = engine
                    .preview_disconnect_canonical_to_ancestor(&mut preview, 0)
                    .expect("preview");
                assert_eq!(packet.len(), 2);
                assert_eq!(preview.tip_hash, genesis_hash);
                packet
            } else {
                Vec::new()
            };
            let (sidecar, extension, hash, bytes) = match kind {
                'h' => ("headers", "bin", block1_hash, malformed.map(Vec::from)),
                'u' => ("undo", "json", block2_hash, malformed.map(Vec::from)),
                _ => {
                    let mut corrupt = block1;
                    corrupt[36] ^= 1;
                    ("blocks", "bin", block1_hash, Some(corrupt))
                }
            };
            let path = block_store_path(&dir).join(sidecar).join(format!(
                "{}.{}",
                hex::encode(hash),
                extension
            ));
            match bytes {
                Some(bytes) => std::fs::write(path, bytes).expect("overwrite sidecar"),
                None => std::fs::remove_file(path).expect("remove sidecar"),
            }
            let err = if kind != 'b' {
                engine
                    .disconnect_prepared_canonical_to_ancestor(packet)
                    .expect_err(name)
            } else {
                let mut preview = engine.chain_state.clone();
                let preview_err = engine
                    .preview_disconnect_canonical_to_ancestor(&mut preview, 0)
                    .expect_err("preview must reject corrupt lower packet member");
                assert!(preview_err.starts_with(BRANCH_STORE_CORRUPT_ERR));
                assert_eq!(
                    preview, before.state,
                    "preview must not partially disconnect"
                );
                engine.disconnect_canonical_to_ancestor(0).expect_err(name)
            };
            assert!(err.contains(want), "{name}: {err}");
            assert_eq!(disconnect_snapshot(&engine), before, "{name}: mutation");
            std::fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn disconnect_tip_no_blockstore_fails() {
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], None);
        let mut engine = SyncEngine::new(ChainState::new(), None, cfg).expect("new");
        let err = engine.disconnect_tip().unwrap_err();
        assert!(err.contains("no blockstore"));
    }

    #[test]
    fn disconnect_tip_rejects_chainstate_blockstore_mismatch() {
        let (mut engine, dir) = engine_with_store("rubin-disc-mismatch");
        let (genesis, _, _) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");

        // Desynchronize: mutate chainstate tip_hash so it diverges from blockstore.
        engine.chain_state.tip_hash = [0xdd; 32];

        let err = engine.disconnect_tip().unwrap_err();
        assert!(
            err.contains("does not match"),
            "expected mismatch error, got: {err}"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn disconnect_tip_truncate_error_propagates_with_rollback() {
        // truncate_canonical fails (force_truncate_error inject); per
        // BlockStore::truncate_canonical's atomic-write-and-reload contract
        // the canonical index stays unchanged on disk.  disconnect_tip
        // restores the captured in-memory snapshot directly (without going
        // through rollback_apply_block, whose phase-1 truncate would
        // re-fail and short-circuit).  After the failure both canonical and
        // in-memory state are at the pre-disconnect tip — engine usable.
        let (mut engine, dir) = engine_with_store("rubin-disc-trunc-err");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine.apply_block(&block1, None).expect("block 1");

        // Capture pre-disconnect state for post-error verification.
        let tip_before = engine
            .block_store
            .as_ref()
            .unwrap()
            .tip()
            .expect("tip")
            .expect("some");

        // Inject forced truncate error.
        engine.block_store.as_mut().unwrap().force_truncate_error = true;

        let err = engine.disconnect_tip().unwrap_err();
        assert!(
            err.contains("forced truncate error"),
            "expected forced truncate error, got: {err}"
        );

        // Disarm so cleanup succeeds.
        engine.block_store.as_mut().unwrap().force_truncate_error = false;

        // Canonical never mutated — inject returns before the in-memory
        // truncate happens.  Verify both height AND hash, not just length.
        let tip = engine
            .block_store
            .as_ref()
            .unwrap()
            .tip()
            .expect("tip")
            .expect("some");
        assert_eq!(
            tip.0, tip_before.0,
            "canonical height should be unchanged after truncate failure"
        );
        assert_eq!(
            tip.1, tip_before.1,
            "canonical tip hash should be unchanged after truncate failure"
        );

        // In-memory chain_state must be restored to the pre-disconnect tip
        // so the engine stays consistent with the unchanged canonical index.
        assert!(
            engine.chain_state.has_tip,
            "chain_state.has_tip should be restored after truncate failure"
        );
        assert_eq!(
            engine.chain_state.height, tip_before.0,
            "chain_state.height should be restored to pre-disconnect tip"
        );
        assert_eq!(
            engine.chain_state.tip_hash, tip_before.1,
            "chain_state.tip_hash should be restored to pre-disconnect tip"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn disconnect_tip_save_failure_restores_canonical() {
        // Save fails after truncate: rollback_canonical re-appends tip_hash,
        // then in-memory chain_state is restored inline.  rollback_apply_block
        // is NOT called in the save-failure branch (it is called only on
        // truncate failure, but that path tests its own assertions in
        // disconnect_tip_truncate_error_propagates_with_rollback).
        let (mut engine, dir) = engine_with_store("rubin-disc-save-fail");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine.apply_block(&block1, None).expect("block 1");

        // Canonical index should have 2 entries (genesis + block1).
        let tip_before = engine
            .block_store
            .as_ref()
            .unwrap()
            .tip()
            .expect("tip")
            .expect("some");
        assert_eq!(tip_before.0, 1);

        // Point chain_state_path under a regular file so save() fails
        // deterministically when atomic write tries to create the temp
        // file in the parent directory.  Blockstore truncate_canonical
        // operates on its own writable dir, so truncate succeeds before
        // save fails — exercising the rollback_canonical recovery path.
        let cs_parent_file = dir.join("chainstate-parent-file");
        std::fs::write(&cs_parent_file, b"not a directory").expect("create parent file");
        engine.cfg.chain_state_path = Some(cs_parent_file.join("state.bin"));

        // disconnect_tip should fail (save error — platform-specific message).
        let err = engine.disconnect_tip().unwrap_err();
        assert!(!err.is_empty(), "expected save error, got empty string");

        // Canonical index should be restored — tip still at block1.
        let tip_after = engine
            .block_store
            .as_ref()
            .unwrap()
            .tip()
            .expect("tip")
            .expect("some");
        assert_eq!(
            tip_after.0, tip_before.0,
            "canonical index height should be restored after save failure"
        );
        assert_eq!(
            tip_after.1, tip_before.1,
            "canonical tip hash should be restored after save failure"
        );

        // In-memory chain_state must also be restored to pre-disconnect tip.
        assert!(
            engine.chain_state.has_tip,
            "chain_state.has_tip not restored"
        );
        assert_eq!(
            engine.chain_state.height, tip_before.0,
            "chain_state.height not restored after save failure"
        );
        assert_eq!(
            engine.chain_state.tip_hash, tip_before.1,
            "chain_state.tip_hash not restored after save failure"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn disconnect_tip_save_and_canonical_rollback_both_fail() {
        // Double-failure case: save() fails AND rollback_canonical() fails.
        // chain_state must NOT be restored to pre-disconnect tip — that would
        // create a mismatch with the truncated canonical.  Engine remains in
        // post-disconnect state (parent tip, canonical missing original tip).
        let (mut engine, dir) = engine_with_store("rubin-disc-double-fail");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine.apply_block(&block1, None).expect("block 1");

        // Point chain_state_path at a child of a regular file so save() fails
        // deterministically (parent is not a directory — works under any
        // privileges).  Arm rollback inject so canonical restore also fails
        // after truncate succeeds.
        let invalid_parent = dir.join("not-a-dir");
        std::fs::write(&invalid_parent, b"not a directory").expect("create invalid parent file");
        engine.cfg.chain_state_path = Some(invalid_parent.join("state.bin"));
        engine.block_store.as_mut().unwrap().force_rollback_error = true;

        let err = engine.disconnect_tip().unwrap_err();
        // Composite error must mention both failures.
        assert!(
            err.contains("rollback failed"),
            "expected rollback failure note, got: {err}"
        );
        assert!(
            err.contains("canonical restore failed"),
            "expected canonical restore failure note, got: {err}"
        );

        // Disarm so cleanup succeeds.
        engine.block_store.as_mut().unwrap().force_rollback_error = false;

        // Canonical was truncated and rollback failed — tip is now genesis.
        let tip = engine
            .block_store
            .as_ref()
            .unwrap()
            .tip()
            .expect("tip")
            .expect("some");
        assert_eq!(
            tip.0, 0,
            "canonical should be at genesis after failed rollback"
        );
        assert_eq!(tip.1, genesis_hash, "canonical tip should be genesis hash");

        // chain_state must align with truncated canonical (not pre-disconnect).
        assert_eq!(
            engine.chain_state.height, 0,
            "chain_state must NOT be restored when canonical rollback failed"
        );
        assert_eq!(
            engine.chain_state.tip_hash, genesis_hash,
            "chain_state tip must align with truncated canonical (genesis)"
        );
        // tip_timestamp must also be aligned with the disconnected parent
        // (genesis) so is_in_ibd() / freshness metadata stay coherent.
        assert_eq!(
            engine.tip_timestamp, gen_ts,
            "tip_timestamp must be parent's (genesis) when canonical rollback failed"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn disconnect_tip_save_failure_with_blockstore_dropped_propagates_error() {
        // Test-only seam: drop block_store between truncate and save so the
        // save-failure recovery hits the otherwise-unreachable None branch.
        // Verifies the branch propagates a normal error (no panic) and
        // aligns tip_timestamp with the disconnected parent.
        let (mut engine, dir) = engine_with_store("rubin-disc-bs-dropped");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine.apply_block(&block1, None).expect("block 1");

        // Force save() to fail deterministically (regular file as parent).
        let cs_parent_file = dir.join("chainstate-parent-file");
        std::fs::write(&cs_parent_file, b"not a directory").expect("create parent file");
        engine.cfg.chain_state_path = Some(cs_parent_file.join("state.bin"));
        // Arm the test seam: drop block_store after the first truncate so the
        // save-failure recovery cannot re-borrow it.
        engine.drop_block_store_after_truncate = true;

        let err = engine.disconnect_tip().unwrap_err();
        // Composite error must mention both the save error and the
        // blockstore-missing rollback note.
        assert!(
            err.contains("rollback failed"),
            "expected rollback failure note, got: {err}"
        );
        assert!(
            err.contains("blockstore missing after canonical truncate"),
            "expected blockstore-missing note, got: {err}"
        );
        // tip_timestamp must align with the disconnected parent (genesis).
        assert_eq!(
            engine.tip_timestamp, gen_ts,
            "tip_timestamp must be parent's (genesis) on blockstore-missing branch"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn preview_disconnect_canonical() {
        let (mut engine, dir) = engine_with_store("rubin-disc-preview");
        let (genesis, genesis_hash, gen_ts) = genesis_info();

        engine.apply_block(&genesis, None).expect("genesis");
        let block1 = height_one_coinbase_only_block(genesis_hash, gen_ts + 1);
        engine.apply_block(&block1, None).expect("block 1");

        let mut preview = engine.chain_state.clone();
        let disconnected = engine
            .preview_disconnect_canonical_to_ancestor(&mut preview, 0)
            .expect("preview");
        assert_eq!(disconnected.len(), 1);
        assert_eq!(preview.height, 0);
        assert_eq!(preview.tip_hash, genesis_hash);

        // Original engine state unchanged.
        assert_eq!(engine.chain_state.height, 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}

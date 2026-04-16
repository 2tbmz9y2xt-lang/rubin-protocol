use rubin_consensus::{parse_block_bytes, parse_block_header_bytes};

use crate::chainstate::ChainState;
use crate::sync::SyncEngine;
use crate::undo::ChainStateDisconnectSummary;

impl SyncEngine {
    /// Disconnect the current canonical tip block, restoring the chain state
    /// to the parent. Returns a summary of the disconnection.
    pub fn disconnect_tip(&mut self) -> Result<ChainStateDisconnectSummary, String> {
        let block_store = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?;

        let (tip_height, tip_hash) = block_store
            .tip()?
            .ok_or("blockstore has no canonical tip")?;

        if !self.chain_state.has_tip
            || self.chain_state.height != tip_height
            || self.chain_state.tip_hash != tip_hash
        {
            return Err("chainstate tip does not match blockstore tip".into());
        }

        let block_bytes = block_store.get_block_by_hash(tip_hash)?;
        let undo = block_store.get_undo(tip_hash)?;
        let pb = parse_block_bytes(&block_bytes).map_err(|e| e.to_string())?;

        let rollback = self.capture_rollback_state();

        // Determine the parent timestamp for updating tip_timestamp after
        // disconnect. Genesis block disconnect results in timestamp = 0.
        let new_tip_timestamp = if tip_height > 0 {
            let parent_header_bytes = block_store.get_header_by_hash(pb.header.prev_block_hash)?;
            let parent_header =
                parse_block_header_bytes(&parent_header_bytes).map_err(|e| e.to_string())?;
            parent_header.timestamp
        } else {
            0
        };

        let summary = self.chain_state.disconnect_block(&block_bytes, &undo)?;

        // Truncate canonical index FIRST, then persist chain state — matching
        // Go DisconnectTip ordering (B.7 fix, issue #1170).  A crash between
        // truncate and save leaves the canonical index short while chainstate
        // still has the old tip; the mismatch guard at the top of this
        // function detects and rejects this on restart.
        let bs = self
            .block_store
            .as_mut()
            .ok_or("sync engine has no blockstore")?;
        if let Err(err) = bs.truncate_canonical(rollback.canonical_len.saturating_sub(1)) {
            return Err(SyncEngine::err_with_rollback(
                err,
                self.rollback_apply_block(rollback),
            ));
        }

        // Test-only seam to exercise the otherwise-unreachable
        // blockstore-missing branch in the save-failure recovery below.
        #[cfg(test)]
        if self.drop_block_store_after_truncate {
            self.block_store = None;
        }

        if let Some(path) = self.cfg.chain_state_path.as_ref() {
            if let Err(err) = self.chain_state.save(path) {
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
                let canonical_rb = match self.block_store.as_mut() {
                    Some(bs) => bs
                        .rollback_canonical(
                            rollback.canonical_len.saturating_sub(1),
                            vec![hex::encode(tip_hash)],
                        )
                        .err()
                        .map(|e| format!("canonical restore failed: {e}")),
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
        let (mut current_height, _) = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?
            .tip()?
            .ok_or("blockstore has no canonical tip")?;

        let mut disconnected_blocks = Vec::new();
        while current_height > common_ancestor_height {
            let tip_hash = self
                .block_store
                .as_ref()
                .ok_or("sync engine has no blockstore")?
                .tip()?
                .ok_or("blockstore has no canonical tip")?
                .1;

            let block_bytes = self
                .block_store
                .as_ref()
                .ok_or("sync engine has no blockstore")?
                .get_block_by_hash(tip_hash)?;

            disconnected_blocks.push(block_bytes);
            self.disconnect_tip()?;
            current_height -= 1;
        }
        Ok(disconnected_blocks)
    }

    /// Non-mutating preview: disconnect a copy of chain state down to a common
    /// ancestor. Used by `prepare_heavier_branch()` for dry-run validation.
    pub(crate) fn preview_disconnect_canonical_to_ancestor(
        &self,
        preview_state: &mut ChainState,
        common_ancestor_height: u64,
    ) -> Result<Vec<Vec<u8>>, String> {
        let block_store = self
            .block_store
            .as_ref()
            .ok_or("sync engine has no blockstore")?;

        let mut current_height = preview_state.height;
        let mut disconnected_blocks = Vec::new();

        while current_height > common_ancestor_height {
            let tip_hash = preview_state.tip_hash;
            let block_bytes = block_store.get_block_by_hash(tip_hash)?;
            let undo = block_store.get_undo(tip_hash)?;
            preview_state.disconnect_block(&block_bytes, &undo)?;
            disconnected_blocks.push(block_bytes);
            current_height -= 1;
        }
        Ok(disconnected_blocks)
    }
}

#[cfg(test)]
mod tests {
    use rubin_consensus::constants::POW_LIMIT;

    use crate::blockstore::{block_store_path, BlockStore};
    use crate::chainstate::{chain_state_path, ChainState};
    use crate::io_utils::unique_temp_path;
    use crate::sync::{default_sync_config, SyncEngine};
    use crate::test_helpers::{genesis_info, height_one_coinbase_only_block};

    fn engine_with_store(suffix: &str) -> (SyncEngine, std::path::PathBuf) {
        let dir = unique_temp_path(suffix);
        let store = BlockStore::open(block_store_path(&dir)).expect("open blockstore");
        let cfg = default_sync_config(Some(POW_LIMIT), [0u8; 32], Some(chain_state_path(&dir)));
        let engine = SyncEngine::new(ChainState::new(), Some(store), cfg).expect("new sync");
        (engine, dir)
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
        // Both the initial truncate AND the rollback_apply_block phase-1
        // truncate fail (force_truncate_error stays armed for both calls),
        // so the composite error reports both failures.  Engine state ends
        // up at post-disconnect_block (chain_state.height=0) while canonical
        // is still untouched ([genesis, block1]) — verified after disarm.
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
        // Composite error must surface BOTH the main error and the
        // rollback-phase failure (rollback_apply_block also tried to
        // truncate and got the same injected error).
        assert!(
            err.contains("rollback failed"),
            "expected rollback failure note, got: {err}"
        );

        // Disarm so cleanup succeeds.
        engine.block_store.as_mut().unwrap().force_truncate_error = false;

        // Canonical never mutated — both truncate calls failed before write.
        // Verify both height AND hash, not just length.
        let tip = engine
            .block_store
            .as_ref()
            .unwrap()
            .tip()
            .expect("tip")
            .expect("some");
        assert_eq!(
            tip.0, tip_before.0,
            "canonical height should be unchanged after both truncate failures"
        );
        assert_eq!(
            tip.1, tip_before.1,
            "canonical tip hash should be unchanged after both truncate failures"
        );

        // chain_state was mutated by disconnect_block (height 1 → 0), and
        // rollback_apply_block phase-1 truncate failed before phase-2 ran,
        // so the in-memory state remains in the post-disconnect_block state.
        // Document this asymmetry: canonical at block1, chain_state at genesis.
        assert_eq!(
            engine.chain_state.height, 0,
            "chain_state.height should be 0 (rollback aborted at phase 1)"
        );
        assert_eq!(
            engine.chain_state.tip_hash, genesis_hash,
            "chain_state.tip_hash should be genesis (rollback aborted at phase 1)"
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

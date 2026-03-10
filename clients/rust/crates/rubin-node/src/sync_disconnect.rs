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

        // Persist chain state BEFORE truncating canonical index so that a
        // save failure can be rolled back without losing canonical entries.
        //
        // Crash-consistency note: a crash between `save` and `truncate_canonical`
        // leaves persisted chain_state at the parent while the canonical index
        // still references the old tip.  On restart the mismatch guard at the top
        // of this function will reject the stale canonical tip, requiring an
        // index rebuild.  True atomicity would need a write-ahead log.
        if let Some(path) = self.cfg.chain_state_path.as_ref() {
            if let Err(err) = self.chain_state.save(path) {
                self.rollback_apply_block(rollback);
                return Err(err);
            }
        }

        // Truncate canonical index (remove the tip entry).
        if let Some(bs) = self.block_store.as_mut() {
            if let Err(err) = bs.truncate_canonical(rollback.canonical_len.saturating_sub(1)) {
                self.rollback_apply_block(rollback);
                return Err(err);
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

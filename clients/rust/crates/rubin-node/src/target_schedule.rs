use std::collections::HashSet;

use rubin_consensus::constants::WINDOW_SIZE;
use rubin_consensus::{block_hash, parse_block_header_bytes, retarget_v1_clamped, BlockHeader};

use crate::blockstore::BlockStore;
use crate::sync::SyncEngine;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TargetScheduleError {
    ParentUnknown,
    HistoryMissing,
    HistoryCorrupt,
    HeightInvalid,
    Retarget(String),
    LocalIo(String),
}

enum TargetHeaderRead {
    Bytes(Vec<u8>),
    NotFound,
    LocalIo(String),
}

fn parse_header(raw: &[u8]) -> Result<BlockHeader, TargetScheduleError> {
    parse_block_header_bytes(raw).map_err(|_| TargetScheduleError::HistoryCorrupt)
}

fn verify_header_hash(raw: &[u8], lookup: [u8; 32]) -> Result<(), TargetScheduleError> {
    let actual = block_hash(raw).map_err(|_| TargetScheduleError::HistoryCorrupt)?;
    if actual != lookup {
        return Err(TargetScheduleError::HistoryCorrupt);
    }
    Ok(())
}

fn expected_target_for_candidate_with_reader(
    mut read: impl FnMut([u8; 32]) -> TargetHeaderRead,
    parent_hash: [u8; 32],
    candidate_height: u64,
) -> Result<[u8; 32], TargetScheduleError> {
    if candidate_height == 0 {
        return Err(TargetScheduleError::HeightInvalid);
    }

    let boundary = candidate_height.is_multiple_of(WINDOW_SIZE);
    let window = if boundary { WINDOW_SIZE as usize } else { 1 };
    let mut timestamps = vec![0u64; window];
    let mut visited = HashSet::with_capacity(window);
    let mut current = parent_hash;
    let mut target_old = [0u8; 32];

    for index in 0..window {
        if !visited.insert(current) {
            return Err(TargetScheduleError::HistoryCorrupt);
        }
        let raw = match read(current) {
            TargetHeaderRead::Bytes(raw) => raw,
            TargetHeaderRead::NotFound if index == 0 => {
                return Err(TargetScheduleError::ParentUnknown)
            }
            TargetHeaderRead::NotFound => return Err(TargetScheduleError::HistoryMissing),
            TargetHeaderRead::LocalIo(error) => return Err(TargetScheduleError::LocalIo(error)),
        };
        let header = parse_header(&raw)?;
        if visited.contains(&header.prev_block_hash) {
            return Err(TargetScheduleError::HistoryCorrupt);
        }
        verify_header_hash(&raw, current)?;
        if index == 0 {
            target_old = header.target;
        }
        timestamps[window - 1 - index] = header.timestamp;
        current = header.prev_block_hash;
        if boundary && index + 1 < window && current == [0u8; 32] {
            return Err(TargetScheduleError::HistoryMissing);
        }
    }

    if !boundary {
        return Ok(target_old);
    }
    retarget_v1_clamped(target_old, &timestamps)
        .map_err(|error| TargetScheduleError::Retarget(error.to_string()))
}

pub(crate) fn expected_target_for_candidate(
    block_store: &BlockStore,
    parent_hash: [u8; 32],
    candidate_height: u64,
) -> Result<[u8; 32], TargetScheduleError> {
    expected_target_for_candidate_with_reader(
        |lookup| match block_store.try_has_block(lookup) {
            Ok(false) => TargetHeaderRead::NotFound,
            Err(error) => TargetHeaderRead::LocalIo(error),
            Ok(true) => match block_store.get_header_by_hash(lookup) {
                Ok(raw) => TargetHeaderRead::Bytes(raw),
                Err(error) => TargetHeaderRead::LocalIo(error),
            },
        },
        parent_hash,
        candidate_height,
    )
}

impl SyncEngine {
    pub(crate) fn expected_target_for_candidate(
        &self,
        parent_hash: [u8; 32],
        candidate_height: u64,
    ) -> Result<[u8; 32], TargetScheduleError> {
        let block_store = self
            .block_store
            .as_ref()
            .ok_or_else(|| TargetScheduleError::LocalIo("block store unavailable".to_string()))?;
        expected_target_for_candidate(block_store, parent_hash, candidate_height)
    }
}

const _: () = {
    let _ = expected_target_for_candidate;
    let _ = SyncEngine::expected_target_for_candidate;
};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rubin_consensus::constants::{POW_LIMIT, TARGET_BLOCK_INTERVAL};
    use rubin_consensus::{block_hash, retarget_v1_clamped};

    use super::*;
    use crate::chainstate::ChainState;
    use crate::sync::default_sync_config;

    type TestChain = (HashMap<[u8; 32], Vec<u8>>, Vec<[u8; 32]>, Vec<u64>);

    fn header(prev: [u8; 32], target: [u8; 32], timestamp: u64, nonce: u64) -> Vec<u8> {
        let mut raw = 1u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&prev);
        raw.extend_from_slice(&[0u8; 32]);
        raw.extend_from_slice(&timestamp.to_le_bytes());
        raw.extend_from_slice(&target);
        raw.extend_from_slice(&nonce.to_le_bytes());
        raw
    }

    fn chain(count: usize, target_old: [u8; 32]) -> TestChain {
        let mut headers = HashMap::with_capacity(count);
        let mut hashes = Vec::with_capacity(count);
        let mut timestamps = Vec::with_capacity(count);
        let mut prev = [0u8; 32];
        for index in 0..count {
            let timestamp = 1_000_000 + index as u64 * TARGET_BLOCK_INTERVAL;
            let target = [POW_LIMIT, target_old][usize::from(index + 1 == count)];
            let raw = header(prev, target, timestamp, index as u64 + 1);
            let hash = block_hash(&raw).expect("test header hash");
            headers.insert(hash, raw);
            hashes.push(hash);
            timestamps.push(timestamp);
            prev = hash;
        }
        (headers, hashes, timestamps)
    }

    fn from_map(headers: &HashMap<[u8; 32], Vec<u8>>, lookup: [u8; 32]) -> TargetHeaderRead {
        headers
            .get(&lookup)
            .cloned()
            .map_or(TargetHeaderRead::NotFound, TargetHeaderRead::Bytes)
    }

    fn assert_non_boundary(height: u64, prev: [u8; 32], target: [u8; 32]) {
        let raw = header(prev, target, 7, height);
        let parent = block_hash(&raw).expect("test header hash");
        let mut reads = 0;
        let got = expected_target_for_candidate_with_reader(
            |lookup| {
                reads += 1;
                assert_eq!(lookup, parent);
                TargetHeaderRead::Bytes(raw.clone())
            },
            parent,
            height,
        )
        .expect("selected parent target");
        assert_eq!((got, reads), (target, 1));
    }

    #[test]
    fn expected_target_for_candidate_rejects_genesis_height_like_go() {
        let error = expected_target_for_candidate_with_reader(
            |_| panic!("height zero must not read"),
            [0u8; 32],
            0,
        )
        .unwrap_err();
        assert_eq!(error, TargetScheduleError::HeightInvalid);
    }

    #[test]
    fn expected_target_for_candidate_non_boundary_uses_selected_parent() {
        assert_non_boundary(1, [0xaa; 32], [0x20; 32]);
    }

    #[test]
    fn expected_target_for_candidate_does_not_read_candidate_header_parent() {
        assert_non_boundary(2, [0xbb; 32], [0x30; 32]);
    }

    #[test]
    fn expected_target_for_candidate_retarget_boundary_matches_go() {
        let target_old = [0x40; 32];
        let (headers, hashes, timestamps) = chain(WINDOW_SIZE as usize, target_old);
        let got = expected_target_for_candidate_with_reader(
            |lookup| from_map(&headers, lookup),
            *hashes.last().expect("parent"),
            WINDOW_SIZE,
        )
        .expect("boundary target");
        assert_eq!(
            got,
            retarget_v1_clamped(target_old, &timestamps).expect("reference retarget")
        );
    }

    #[test]
    fn expected_target_for_candidate_side_parent_matches_go() {
        assert_non_boundary(1, [0xcc; 32], [0x50; 32]);
    }

    #[test]
    fn expected_target_for_candidate_missing_history_errors() {
        let immediate =
            expected_target_for_candidate_with_reader(|_| TargetHeaderRead::NotFound, [1u8; 32], 1)
                .unwrap_err();
        let raw = header([9u8; 32], POW_LIMIT, 1, 1);
        let parent = block_hash(&raw).expect("parent hash");
        let older_headers = HashMap::from([(parent, raw)]);
        let older = expected_target_for_candidate_with_reader(
            |lookup| from_map(&older_headers, lookup),
            parent,
            WINDOW_SIZE,
        )
        .unwrap_err();
        let (headers, hashes, _) = chain(3, [0x40; 32]);
        let premature_zero = expected_target_for_candidate_with_reader(
            |lookup| from_map(&headers, lookup),
            *hashes.last().expect("parent"),
            WINDOW_SIZE,
        )
        .unwrap_err();
        assert_eq!(immediate, TargetScheduleError::ParentUnknown);
        assert_eq!(older, TargetScheduleError::HistoryMissing);
        assert_eq!(premature_zero, TargetScheduleError::HistoryMissing);
    }

    #[test]
    fn expected_target_for_candidate_malformed_header_errors() {
        let error = expected_target_for_candidate_with_reader(
            |_| TargetHeaderRead::Bytes(vec![1]),
            [1u8; 32],
            1,
        )
        .unwrap_err();
        assert_eq!(error, TargetScheduleError::HistoryCorrupt);
    }

    #[test]
    fn expected_target_for_candidate_header_hash_mismatch_errors() {
        let error = expected_target_for_candidate_with_reader(
            |_| TargetHeaderRead::Bytes(header([0u8; 32], POW_LIMIT, 1, 1)),
            [2u8; 32],
            1,
        )
        .unwrap_err();
        assert_eq!(error, TargetScheduleError::HistoryCorrupt);
    }

    #[test]
    fn expected_target_for_candidate_cycle_is_bounded() {
        let parent = [1u8; 32];
        let mut reads = 0;
        let error = expected_target_for_candidate_with_reader(
            |_| {
                reads += 1;
                TargetHeaderRead::Bytes(header(parent, POW_LIMIT, 1, 1))
            },
            parent,
            WINDOW_SIZE,
        )
        .unwrap_err();
        assert_eq!(error, TargetScheduleError::HistoryCorrupt);
        assert_eq!(reads, 1);
    }

    #[test]
    fn expected_target_for_candidate_retarget_error_matches_go_class() {
        let (headers, hashes, _) = chain(WINDOW_SIZE as usize, [0u8; 32]);
        let error = expected_target_for_candidate_with_reader(
            |lookup| from_map(&headers, lookup),
            *hashes.last().expect("parent"),
            WINDOW_SIZE,
        )
        .unwrap_err();
        assert!(matches!(error, TargetScheduleError::Retarget(_)));
    }

    #[test]
    fn expected_target_for_candidate_non_boundary_reads_exactly_one_header() {
        assert_non_boundary(u64::MAX, [3u8; 32], [0x60; 32]);
    }

    #[test]
    fn expected_target_for_candidate_boundary_reads_exactly_window_on_success() {
        let (headers, hashes, _) = chain(WINDOW_SIZE as usize, [0x40; 32]);
        let mut reads = 0;
        expected_target_for_candidate_with_reader(
            |lookup| {
                reads += 1;
                from_map(&headers, lookup)
            },
            *hashes.last().expect("parent"),
            WINDOW_SIZE,
        )
        .expect("boundary target");
        assert_eq!(reads, WINDOW_SIZE);
    }

    #[test]
    fn expected_target_for_candidate_boundary_read_count_is_capped() {
        let mut reads = 0;
        let error = expected_target_for_candidate_with_reader(
            |_| {
                reads += 1;
                TargetHeaderRead::Bytes(header([9u8; 32], POW_LIMIT, 1, reads))
            },
            [8u8; 32],
            WINDOW_SIZE,
        )
        .unwrap_err();
        assert_eq!((error, reads), (TargetScheduleError::HistoryCorrupt, 1));
    }

    #[test]
    fn expected_target_for_candidate_local_io_matches_go_class() {
        let error = expected_target_for_candidate_with_reader(
            |_| TargetHeaderRead::LocalIo("injected I/O".to_string()),
            [1u8; 32],
            1,
        )
        .unwrap_err();
        assert!(
            matches!(error, TargetScheduleError::LocalIo(message) if message == "injected I/O")
        );
    }

    #[test]
    fn sync_engine_wrapper_matches_core() {
        static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rubin-target-schedule-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let mut store = BlockStore::create(&path).expect("create blockstore");
        let raw = header([0u8; 32], [0x70; 32], 1, 1);
        let parent = block_hash(&raw).expect("parent hash");
        store
            .put_block(0, parent, &raw, &raw)
            .expect("store parent");
        let core = expected_target_for_candidate(&store, parent, 1);
        let cfg = default_sync_config(None, [0u8; 32], None);
        let engine = SyncEngine::new(ChainState::new(), Some(store.clone()), cfg.clone())
            .expect("new engine");
        assert_eq!(engine.expected_target_for_candidate(parent, 1), core);
        assert_eq!(store.get_header_by_hash(parent).expect("read after"), raw);
        let missing = [0xff; 32];
        let core_error = expected_target_for_candidate(&store, missing, 1);
        assert_eq!(engine.expected_target_for_candidate(missing, 1), core_error);
        assert_eq!(core_error, Err(TargetScheduleError::ParentUnknown));

        let absent = SyncEngine::new(ChainState::new(), None, cfg)
            .expect("new engine without store")
            .expected_target_for_candidate(parent, 1);
        assert!(
            matches!(absent, Err(TargetScheduleError::LocalIo(message)) if message == "block store unavailable")
        );
        drop(engine);
        drop(store);
        fs::remove_dir_all(path).expect("remove test blockstore");
    }
}

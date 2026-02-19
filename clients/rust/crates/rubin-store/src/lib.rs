//! `rubin-store` — persistent storage layer for the Rubin node.
//!
//! Provides a redb-backed KV store with canonical byte layouts,
//! MANIFEST.json crash recovery, block import pipeline (Stages 0–5),
//! reorg (disconnect/connect), and utxo_set_hash computation.

pub mod db;
pub mod keys;
pub mod manifest;
pub mod pipeline;
pub mod reorg;
pub mod utxo_hash;

pub use db::{Store, WriteBatch};
pub use keys::{BlockIndexEntry, BlockStatus, UndoEntry, UndoRecord};
pub use manifest::Manifest;
pub use pipeline::{import_block, ImportResult};
pub use utxo_hash::utxo_set_hash;

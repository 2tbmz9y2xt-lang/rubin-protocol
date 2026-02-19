//! redb-backed persistent storage for the Rubin node.
//!
//! Wraps five logical tables (see `RUBIN_NODE_STORAGE_MODEL_v1.1.md`):
//! - `headers_by_hash`
//! - `blocks_by_hash`
//! - `block_index_by_hash`
//! - `utxo_by_outpoint`
//! - `undo_by_block_hash`

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};

use crate::keys::{
    decode_block_header, decode_block_index, decode_undo_record, decode_utxo_entry,
    encode_block_header, encode_block_index, encode_outpoint_key, encode_undo_record,
    encode_utxo_entry, BlockIndexEntry, UndoRecord,
};
use rubin_consensus::{BlockHeader, TxOutPoint, UtxoEntry};

// ---------------------------------------------------------------------------
// Table definitions (fixed key/value byte slices)
// ---------------------------------------------------------------------------

const HEADERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("headers_by_hash");
const BLOCKS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks_by_hash");
const BLOCK_INDEX_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("block_index_by_hash");
const UTXO_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("utxo_by_outpoint");
const UNDO_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("undo_by_block_hash");

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct Store {
    db: Database,
}

impl Store {
    /// Open (or create) a redb database at `path`.
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = Database::create(path).map_err(|e| format!("redb open: {e}"))?;
        // Ensure all tables exist by opening a write transaction.
        let tx = db
            .begin_write()
            .map_err(|e| format!("redb begin_write: {e}"))?;
        // Open each table (creates if absent).
        tx.open_table(HEADERS_TABLE)
            .map_err(|e| format!("create headers table: {e}"))?;
        tx.open_table(BLOCKS_TABLE)
            .map_err(|e| format!("create blocks table: {e}"))?;
        tx.open_table(BLOCK_INDEX_TABLE)
            .map_err(|e| format!("create block_index table: {e}"))?;
        tx.open_table(UTXO_TABLE)
            .map_err(|e| format!("create utxo table: {e}"))?;
        tx.open_table(UNDO_TABLE)
            .map_err(|e| format!("create undo table: {e}"))?;
        tx.commit().map_err(|e| format!("redb commit: {e}"))?;
        Ok(Self { db })
    }

    /// Begin a redb write transaction. Caller uses the returned `WriteBatch`
    /// to stage mutations, then calls `commit()`.
    pub fn begin_write(&self) -> Result<WriteBatch, String> {
        let tx = self
            .db
            .begin_write()
            .map_err(|e| format!("begin_write: {e}"))?;
        Ok(WriteBatch { tx })
    }

    // ── Headers ─────────────────────────────────────────────────────────

    pub fn get_header(&self, block_hash: &[u8; 32]) -> Result<Option<BlockHeader>, String> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("begin_read: {e}"))?;
        let table = tx
            .open_table(HEADERS_TABLE)
            .map_err(|e| format!("open headers: {e}"))?;
        match table
            .get(block_hash.as_slice())
            .map_err(|e| format!("get header: {e}"))?
        {
            Some(guard) => Ok(Some(decode_block_header(guard.value())?)),
            None => Ok(None),
        }
    }

    // ── Block bytes ─────────────────────────────────────────────────────

    pub fn get_block_bytes(&self, block_hash: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("begin_read: {e}"))?;
        let table = tx
            .open_table(BLOCKS_TABLE)
            .map_err(|e| format!("open blocks: {e}"))?;
        match table
            .get(block_hash.as_slice())
            .map_err(|e| format!("get block: {e}"))?
        {
            Some(guard) => Ok(Some(guard.value().to_vec())),
            None => Ok(None),
        }
    }

    // ── Block index ─────────────────────────────────────────────────────

    pub fn get_block_index(
        &self,
        block_hash: &[u8; 32],
    ) -> Result<Option<BlockIndexEntry>, String> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("begin_read: {e}"))?;
        let table = tx
            .open_table(BLOCK_INDEX_TABLE)
            .map_err(|e| format!("open block_index: {e}"))?;
        match table
            .get(block_hash.as_slice())
            .map_err(|e| format!("get block_index: {e}"))?
        {
            Some(guard) => Ok(Some(decode_block_index(guard.value())?)),
            None => Ok(None),
        }
    }

    // ── UTXO ────────────────────────────────────────────────────────────

    pub fn get_utxo(&self, outpoint: &TxOutPoint) -> Result<Option<UtxoEntry>, String> {
        let key = encode_outpoint_key(outpoint);
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("begin_read: {e}"))?;
        let table = tx
            .open_table(UTXO_TABLE)
            .map_err(|e| format!("open utxo: {e}"))?;
        match table
            .get(key.as_slice())
            .map_err(|e| format!("get utxo: {e}"))?
        {
            Some(guard) => Ok(Some(decode_utxo_entry(guard.value())?)),
            None => Ok(None),
        }
    }

    /// Iterate all UTXOs in lexicographic key order.
    /// Calls `f(outpoint_key_bytes, utxo_entry_bytes)` for each entry.
    pub fn iter_utxos<F>(&self, mut f: F) -> Result<(), String>
    where
        F: FnMut(&[u8], &[u8]),
    {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("begin_read: {e}"))?;
        let table = tx
            .open_table(UTXO_TABLE)
            .map_err(|e| format!("open utxo: {e}"))?;
        let iter = table.iter().map_err(|e| format!("utxo iter: {e}"))?;
        for result in iter {
            let (key_guard, val_guard) = result.map_err(|e| format!("utxo next: {e}"))?;
            f(key_guard.value(), val_guard.value());
        }
        Ok(())
    }

    /// Count all UTXO entries.
    pub fn utxo_count(&self) -> Result<u64, String> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("begin_read: {e}"))?;
        let table = tx
            .open_table(UTXO_TABLE)
            .map_err(|e| format!("open utxo: {e}"))?;
        table.len().map_err(|e| format!("utxo len: {e}"))
    }

    // ── Undo ────────────────────────────────────────────────────────────

    pub fn get_undo(&self, block_hash: &[u8; 32]) -> Result<Option<UndoRecord>, String> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| format!("begin_read: {e}"))?;
        let table = tx
            .open_table(UNDO_TABLE)
            .map_err(|e| format!("open undo: {e}"))?;
        match table
            .get(block_hash.as_slice())
            .map_err(|e| format!("get undo: {e}"))?
        {
            Some(guard) => Ok(Some(decode_undo_record(guard.value())?)),
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// WriteBatch — wraps a redb WriteTransaction for atomic multi-table writes
// ---------------------------------------------------------------------------

pub struct WriteBatch {
    tx: WriteTransaction,
}

impl WriteBatch {
    pub fn put_header(&self, block_hash: &[u8; 32], header: &BlockHeader) -> Result<(), String> {
        let mut table = self
            .tx
            .open_table(HEADERS_TABLE)
            .map_err(|e| format!("open headers: {e}"))?;
        let value = encode_block_header(header);
        table
            .insert(block_hash.as_slice(), value.as_slice())
            .map_err(|e| format!("put header: {e}"))?;
        Ok(())
    }

    pub fn put_block_bytes(
        &self,
        block_hash: &[u8; 32],
        block_bytes: &[u8],
    ) -> Result<(), String> {
        let mut table = self
            .tx
            .open_table(BLOCKS_TABLE)
            .map_err(|e| format!("open blocks: {e}"))?;
        table
            .insert(block_hash.as_slice(), block_bytes)
            .map_err(|e| format!("put block: {e}"))?;
        Ok(())
    }

    pub fn put_block_index(
        &self,
        block_hash: &[u8; 32],
        entry: &BlockIndexEntry,
    ) -> Result<(), String> {
        let mut table = self
            .tx
            .open_table(BLOCK_INDEX_TABLE)
            .map_err(|e| format!("open block_index: {e}"))?;
        let value = encode_block_index(entry);
        table
            .insert(block_hash.as_slice(), value.as_slice())
            .map_err(|e| format!("put block_index: {e}"))?;
        Ok(())
    }

    pub fn put_utxo(&self, outpoint: &TxOutPoint, entry: &UtxoEntry) -> Result<(), String> {
        let key = encode_outpoint_key(outpoint);
        let value = encode_utxo_entry(entry);
        let mut table = self
            .tx
            .open_table(UTXO_TABLE)
            .map_err(|e| format!("open utxo: {e}"))?;
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(|e| format!("put utxo: {e}"))?;
        Ok(())
    }

    pub fn delete_utxo(&self, outpoint: &TxOutPoint) -> Result<(), String> {
        let key = encode_outpoint_key(outpoint);
        let mut table = self
            .tx
            .open_table(UTXO_TABLE)
            .map_err(|e| format!("open utxo: {e}"))?;
        table
            .remove(key.as_slice())
            .map_err(|e| format!("delete utxo: {e}"))?;
        Ok(())
    }

    pub fn put_undo(&self, block_hash: &[u8; 32], record: &UndoRecord) -> Result<(), String> {
        let value = encode_undo_record(record);
        let mut table = self
            .tx
            .open_table(UNDO_TABLE)
            .map_err(|e| format!("open undo: {e}"))?;
        table
            .insert(block_hash.as_slice(), value.as_slice())
            .map_err(|e| format!("put undo: {e}"))?;
        Ok(())
    }

    pub fn delete_undo(&self, block_hash: &[u8; 32]) -> Result<(), String> {
        let mut table = self
            .tx
            .open_table(UNDO_TABLE)
            .map_err(|e| format!("open undo: {e}"))?;
        table
            .remove(block_hash.as_slice())
            .map_err(|e| format!("delete undo: {e}"))?;
        Ok(())
    }

    /// Commit the write batch atomically.
    pub fn commit(self) -> Result<(), String> {
        self.tx.commit().map_err(|e| format!("commit: {e}"))
    }
}

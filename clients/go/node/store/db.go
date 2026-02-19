package store

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"rubin.dev/node/consensus"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketHeaders = []byte("headers_by_hash")
	bucketBlocks  = []byte("blocks_by_hash")
	bucketIndex   = []byte("block_index_by_hash")
	bucketUtxo    = []byte("utxo_by_outpoint")
	bucketUndo    = []byte("undo_by_block_hash")
)

type BlockStatus byte

const (
	BlockStatusUnknown  BlockStatus = 0
	BlockStatusValid    BlockStatus = 1
	BlockStatusInvalid  BlockStatus = 2
	BlockStatusOrphaned BlockStatus = 3
)

type BlockIndexEntry struct {
	Height         uint64
	PrevHash       [32]byte
	CumulativeWork *big.Int // non-negative
	Status         BlockStatus
}

type DB struct {
	chainDir string
	db       *bolt.DB
	manifest *Manifest
}

func Open(datadir string, chainIDHex string) (*DB, error) {
	if datadir == "" {
		return nil, fmt.Errorf("datadir required")
	}
	if chainIDHex == "" {
		return nil, fmt.Errorf("chain_id_hex required")
	}

	chainDir := ChainDir(datadir, chainIDHex)
	if err := ensureDir(chainDir); err != nil {
		return nil, err
	}
	if err := ensureDir(filepath.Join(chainDir, "db")); err != nil {
		return nil, err
	}

	path := filepath.Join(chainDir, "db", "kv.db")
	bdb, err := bolt.Open(path, 0o600, &bolt.Options{
		Timeout: 1 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("open bbolt: %w", err)
	}

	d := &DB{chainDir: chainDir, db: bdb}

	if err := d.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketHeaders, bucketBlocks, bucketIndex, bucketUtxo, bucketUndo} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return fmt.Errorf("create bucket %s: %w", string(b), err)
			}
		}
		return nil
	}); err != nil {
		_ = bdb.Close()
		return nil, err
	}

	m, err := readManifest(chainDir)
	if err != nil {
		if os.IsNotExist(err) {
			return d, nil // uninitialized chain; caller must InitGenesis.
		}
		_ = bdb.Close()
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if m.SchemaVersion > SchemaVersionV1 {
		_ = bdb.Close()
		return nil, fmt.Errorf("manifest schema_version %d > supported %d", m.SchemaVersion, SchemaVersionV1)
	}
	d.manifest = m
	return d, nil
}

func (d *DB) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

func (d *DB) ChainDir() string { return d.chainDir }

func (d *DB) Manifest() *Manifest {
	if d == nil {
		return nil
	}
	return d.manifest
}

func (d *DB) SetManifest(m *Manifest) error {
	if d == nil {
		return fmt.Errorf("db: nil")
	}
	if err := writeManifestAtomic(d.chainDir, m); err != nil {
		return err
	}
	d.manifest = m
	return nil
}

func (d *DB) PutHeader(hash [32]byte, headerBytes []byte) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketHeaders).Put(hash[:], headerBytes)
	})
}

func (d *DB) PutBlockBytes(hash [32]byte, blockBytes []byte) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBlocks).Put(hash[:], blockBytes)
	})
}

func (d *DB) GetBlockBytes(hash [32]byte) ([]byte, bool, error) {
	var out []byte
	err := d.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketBlocks).Get(hash[:])
		if v == nil {
			return nil
		}
		out = append([]byte(nil), v...)
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		return nil, false, nil
	}
	return out, true, nil
}

func (d *DB) PutIndex(hash [32]byte, e BlockIndexEntry) error {
	b, err := encodeIndexEntry(e)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketIndex).Put(hash[:], b)
	})
}

func (d *DB) GetIndex(hash [32]byte) (*BlockIndexEntry, bool, error) {
	var out *BlockIndexEntry
	err := d.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketIndex).Get(hash[:])
		if v == nil {
			return nil
		}
		e, err := decodeIndexEntry(v)
		if err != nil {
			return err
		}
		out = e
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		return nil, false, nil
	}
	return out, true, nil
}

func (d *DB) GetUTXO(point consensus.TxOutPoint) (consensus.UtxoEntry, bool, error) {
	var out consensus.UtxoEntry
	var ok bool
	key := encodeOutpointKey(point)
	err := d.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketUtxo).Get(key)
		if v == nil {
			return nil
		}
		e, err := decodeUtxoEntry(v)
		if err != nil {
			return err
		}
		out = e
		ok = true
		return nil
	})
	return out, ok, err
}

func (d *DB) PutUTXO(point consensus.TxOutPoint, e consensus.UtxoEntry) error {
	key := encodeOutpointKey(point)
	val, err := encodeUtxoEntry(e)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUtxo).Put(key, val)
	})
}

func (d *DB) DeleteUTXO(point consensus.TxOutPoint) error {
	key := encodeOutpointKey(point)
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUtxo).Delete(key)
	})
}

func (d *DB) PutUndo(blockHash [32]byte, u UndoRecord) error {
	val, err := encodeUndoRecord(u)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUndo).Put(blockHash[:], val)
	})
}

func (d *DB) GetUndo(blockHash [32]byte) (*UndoRecord, bool, error) {
	var out *UndoRecord
	err := d.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketUndo).Get(blockHash[:])
		if v == nil {
			return nil
		}
		u, err := decodeUndoRecord(v)
		if err != nil {
			return err
		}
		out = u
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		return nil, false, nil
	}
	return out, true, nil
}

func encodeIndexEntry(e BlockIndexEntry) ([]byte, error) {
	if e.CumulativeWork == nil || e.CumulativeWork.Sign() < 0 {
		return nil, fmt.Errorf("index: cumulative_work required")
	}
	work := e.CumulativeWork.Bytes()
	if len(work) > 0xffff {
		return nil, fmt.Errorf("index: cumulative_work too large")
	}
	// Layout:
	// height u64le | prev_hash 32 | status u8 | work_len u16le | work_bytes
	out := make([]byte, 8+32+1+2+len(work))
	binary.LittleEndian.PutUint64(out[0:8], e.Height)
	copy(out[8:40], e.PrevHash[:])
	out[40] = byte(e.Status)
	binary.LittleEndian.PutUint16(out[41:43], uint16(len(work))) // #nosec G115 -- len(work) checked against 0xffff above.
	copy(out[43:], work)
	return out, nil
}

func decodeIndexEntry(b []byte) (*BlockIndexEntry, error) {
	if len(b) < 8+32+1+2 {
		return nil, fmt.Errorf("index: truncated")
	}
	height := binary.LittleEndian.Uint64(b[0:8])
	var prev [32]byte
	copy(prev[:], b[8:40])
	status := BlockStatus(b[40])
	workLen := int(binary.LittleEndian.Uint16(b[41:43]))
	if 43+workLen != len(b) {
		return nil, fmt.Errorf("index: bad work len")
	}
	work := new(big.Int).SetBytes(b[43:])
	return &BlockIndexEntry{
		Height:         height,
		PrevHash:       prev,
		CumulativeWork: work,
		Status:         status,
	}, nil
}

func hex32(b32 [32]byte) string {
	return hex.EncodeToString(b32[:])
}

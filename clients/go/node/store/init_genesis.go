package store

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"

	bolt "go.etcd.io/bbolt"
)

// InitGenesis initializes an empty chain DB by applying the genesis block and writing
// all required persistence entities (utxo/index/undo/manifest).
//
// Caller MUST ensure genesisBlockBytes and chainID correspond to the same chain-instance profile.
func (d *DB) InitGenesis(p crypto.CryptoProvider, chainID [32]byte, genesisBlockBytes []byte) error {
	if d == nil {
		return fmt.Errorf("db: nil")
	}
	if p == nil {
		return fmt.Errorf("crypto provider required")
	}
	if d.manifest != nil {
		return fmt.Errorf("chain already initialized (manifest exists)")
	}
	if len(genesisBlockBytes) == 0 {
		return fmt.Errorf("genesis block bytes required")
	}

	block, err := consensus.ParseBlockBytes(genesisBlockBytes)
	if err != nil {
		return err
	}
	headerHash, err := consensus.BlockHeaderHash(p, block.Header)
	if err != nil {
		return err
	}
	work, err := WorkFromTarget(block.Header.Target)
	if err != nil {
		return err
	}

	utxo := make(map[consensus.TxOutPoint]consensus.UtxoEntry)
	if err := consensus.ApplyBlock(p, chainID, &block, utxo, consensus.BlockValidationContext{Height: 0}); err != nil {
		return err
	}

	undo, created, err := computeUndoForBlock(p, 0, &block, nil)
	if err != nil {
		return err
	}
	undo.Created = created

	index := BlockIndexEntry{
		Height:         0,
		PrevHash:       [32]byte{},
		CumulativeWork: new(big.Int).Set(work),
		Status:         BlockStatusValid,
	}

	chainIDHex := hex.EncodeToString(chainID[:])
	m := &Manifest{
		SchemaVersion: SchemaVersionV1,
		ChainIDHex:    chainIDHex,

		TipHashHex:           hex32(headerHash),
		TipHeight:            0,
		TipCumulativeWorkDec: work.Text(10),

		LastAppliedBlockHashHex: hex32(headerHash),
		LastAppliedHeight:       0,
	}

	headerBytes := consensus.BlockHeaderBytes(block.Header)

	// Deterministic iteration for persistence (stable ordering).
	type kv struct {
		k consensus.TxOutPoint
		v consensus.UtxoEntry
	}
	items := make([]kv, 0, len(utxo))
	for k, v := range utxo {
		items = append(items, kv{k: k, v: v})
	}
	sort.Slice(items, func(i, j int) bool {
		ki := encodeOutpointKey(items[i].k)
		kj := encodeOutpointKey(items[j].k)
		return bytes.Compare(ki, kj) < 0
	})

	undoBytes, err := encodeUndoRecord(undo)
	if err != nil {
		return err
	}
	indexBytes, err := encodeIndexEntry(index)
	if err != nil {
		return err
	}

	if err := d.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketHeaders).Put(headerHash[:], headerBytes); err != nil {
			return err
		}
		if err := tx.Bucket(bucketBlocks).Put(headerHash[:], genesisBlockBytes); err != nil {
			return err
		}
		if err := tx.Bucket(bucketIndex).Put(headerHash[:], indexBytes); err != nil {
			return err
		}
		if err := tx.Bucket(bucketUndo).Put(headerHash[:], undoBytes); err != nil {
			return err
		}
		bu := tx.Bucket(bucketUtxo)
		for _, it := range items {
			val, err := encodeUtxoEntry(it.v)
			if err != nil {
				return err
			}
			if err := bu.Put(encodeOutpointKey(it.k), val); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return d.SetManifest(m)
}

func computeUndoForBlock(
	p crypto.CryptoProvider,
	height uint64,
	block *consensus.Block,
	utxo map[consensus.TxOutPoint]consensus.UtxoEntry, // pre-state; may be nil for genesis
) (UndoRecord, []consensus.TxOutPoint, error) {
	if block == nil {
		return UndoRecord{}, nil, fmt.Errorf("block nil")
	}
	undo := UndoRecord{}
	created := make([]consensus.TxOutPoint, 0, 16)

	for txi := range block.Transactions {
		tx := &block.Transactions[txi]
		isCoinbase := isCoinbaseLike(tx, height)

		if !isCoinbase {
			for _, in := range tx.Inputs {
				op := consensus.TxOutPoint{TxID: in.PrevTxid, Vout: in.PrevVout}
				if utxo == nil {
					return UndoRecord{}, nil, fmt.Errorf("undo: missing utxo map for non-coinbase")
				}
				prev, ok := utxo[op]
				if !ok {
					return UndoRecord{}, nil, fmt.Errorf("undo: missing utxo %x:%d", op.TxID, op.Vout)
				}
				undo.Spent = append(undo.Spent, UndoSpent{OutPoint: op, RestoredEntry: prev})
			}
		}

		txid, err := consensus.TxID(p, tx)
		if err != nil {
			return UndoRecord{}, nil, err
		}
		for vout, out := range tx.Outputs {
			if out.CovenantType == consensus.CORE_ANCHOR {
				continue
			}
			created = append(created, consensus.TxOutPoint{TxID: txid, Vout: uint32(vout)})
			_ = isCoinbase // created_by_coinbase is stored in utxo entry during Apply; undo only needs outpoints for deletes.
		}
	}
	return undo, created, nil
}

func isCoinbaseLike(tx *consensus.Tx, blockHeight uint64) bool {
	if tx == nil {
		return false
	}
	if len(tx.Inputs) != 1 {
		return false
	}
	if uint64(tx.Locktime) != blockHeight {
		return false
	}
	if tx.TxNonce != 0 {
		return false
	}
	if len(tx.Witness.Witnesses) != 0 {
		return false
	}
	in := tx.Inputs[0]
	if len(in.ScriptSig) != 0 {
		return false
	}
	zero := ([32]byte{})
	return in.PrevTxid == zero &&
		in.PrevVout == consensus.TX_COINBASE_PREVOUT_VOUT &&
		in.Sequence == consensus.TX_COINBASE_PREVOUT_VOUT
}


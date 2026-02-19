package store

import (
	"encoding/binary"
	"fmt"

	"rubin.dev/node/consensus"

	bolt "go.etcd.io/bbolt"
)

func parseBlockHeaderBytesStrict(b []byte) (consensus.BlockHeader, error) {
	if len(b) != 4+32+32+8+32+8 {
		return consensus.BlockHeader{}, fmt.Errorf("block-header-bytes: expected 116 bytes, got %d", len(b))
	}
	var h consensus.BlockHeader
	h.Version = binary.LittleEndian.Uint32(b[0:4])
	copy(h.PrevBlockHash[:], b[4:36])
	copy(h.MerkleRoot[:], b[36:68])
	h.Timestamp = binary.LittleEndian.Uint64(b[68:76])
	copy(h.Target[:], b[76:108])
	h.Nonce = binary.LittleEndian.Uint64(b[108:116])
	return h, nil
}

func (d *DB) GetHeader(hash [32]byte) (*consensus.BlockHeader, bool, error) {
	var out *consensus.BlockHeader
	err := d.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketHeaders).Get(hash[:])
		if v == nil {
			return nil
		}
		h, err := parseBlockHeaderBytesStrict(v)
		if err != nil {
			return err
		}
		out = &h
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

func (d *DB) LoadUTXOSet() (map[consensus.TxOutPoint]consensus.UtxoEntry, error) {
	utxo := make(map[consensus.TxOutPoint]consensus.UtxoEntry)
	err := d.db.View(func(tx *bolt.Tx) error {
		bu := tx.Bucket(bucketUtxo)
		return bu.ForEach(func(k, v []byte) error {
			p, err := decodeOutpointKey(k)
			if err != nil {
				return err
			}
			e, err := decodeUtxoEntry(v)
			if err != nil {
				return err
			}
			utxo[p] = e
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return utxo, nil
}

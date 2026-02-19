package store

import (
	"fmt"
	"math/big"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"

	bolt "go.etcd.io/bbolt"
)

// ReorgToTip performs the Phase 1 disconnect/connect procedure to move the applied tip
// from the manifest tip to newTipHash (which must be present in block_index_by_hash).
//
// This mutates persistent chainstate (utxo + undo + manifest). It is deterministic given
// the stored blocks and index.
func (d *DB) ReorgToTip(p crypto.CryptoProvider, chainID [32]byte, newTipHash [32]byte, opts ApplyOptions) error {
	if d == nil || d.db == nil || d.manifest == nil {
		return fmt.Errorf("db not ready")
	}
	if p == nil {
		return fmt.Errorf("crypto provider required")
	}

	oldTipHash, err := parseHex32(d.manifest.TipHashHex)
	if err != nil {
		return err
	}
	if oldTipHash == newTipHash {
		return nil
	}

	forkHash, err := d.findForkPoint(oldTipHash, newTipHash)
	if err != nil {
		return err
	}

	// Disconnect old chain tip -> fork+1.
	cur := oldTipHash
	for cur != forkHash {
		idx, ok, err := d.GetIndex(cur)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}

		undo, ok, err := d.GetUndo(cur)
		if err != nil {
			return err
		}
		if !ok || undo == nil {
			return fmt.Errorf("REORG_ERR_UNDO_MISSING")
		}

		// Apply undo atomically (DB batch), then advance manifest to parent as commit point.
		if err := d.db.Update(func(tx *bolt.Tx) error {
			bu := tx.Bucket(bucketUtxo)
			for _, c := range undo.Created {
				if err := bu.Delete(encodeOutpointKey(c)); err != nil {
					return err
				}
			}
			for _, s := range undo.Spent {
				val, err := encodeUtxoEntry(s.RestoredEntry)
				if err != nil {
					return err
				}
				if err := bu.Put(encodeOutpointKey(s.OutPoint), val); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}

		parentHash := idx.PrevHash
		parentIdx, ok, err := d.GetIndex(parentHash)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}
		m := &Manifest{
			SchemaVersion: SchemaVersionV1,
			ChainIDHex:    d.manifest.ChainIDHex,

			TipHashHex:           hex32(parentHash),
			TipHeight:            parentIdx.Height,
			TipCumulativeWorkDec: parentIdx.CumulativeWork.Text(10),

			LastAppliedBlockHashHex: hex32(parentHash),
			LastAppliedHeight:       parentIdx.Height,
		}
		if err := d.SetManifest(m); err != nil {
			return err
		}
		cur = parentHash
	}

	// Connect fork+1 -> new tip.
	path, err := d.pathFromAncestor(forkHash, newTipHash)
	if err != nil {
		return err
	}
	for _, h := range path {
		blockBytes, ok, err := d.GetBlockBytes(h)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("REORG_ERR_BLOCK_MISSING")
		}
		// Direct connect: must extend current manifest tip by construction.
		decision, err := d.applyBlockAsNewTip(p, chainID, blockBytes, opts)
		if err != nil {
			// Mark INVALID_BODY on failure and stop reorg; applied tip stays consistent.
			idx, ok2, _ := d.GetIndex(h)
			if ok2 {
				idx.Status = BlockStatusInvalid
				_ = d.PutIndex(h, *idx)
			}
			return err
		}
		if decision != ApplyAppliedAsTip {
			return fmt.Errorf("reorg: unexpected decision %s", decision)
		}
	}
	return nil
}

func (d *DB) findForkPoint(oldTip [32]byte, newTip [32]byte) ([32]byte, error) {
	a := oldTip
	b := newTip

	ha, ok, err := d.GetIndex(a)
	if err != nil {
		return [32]byte{}, err
	}
	if !ok {
		return [32]byte{}, fmt.Errorf("REORG_ERR_INDEX_MISSING")
	}
	hb, ok, err := d.GetIndex(b)
	if err != nil {
		return [32]byte{}, err
	}
	if !ok {
		return [32]byte{}, fmt.Errorf("REORG_ERR_INDEX_MISSING")
	}

	for ha.Height > hb.Height {
		a = ha.PrevHash
		ha, ok, err = d.GetIndex(a)
		if err != nil {
			return [32]byte{}, err
		}
		if !ok {
			return [32]byte{}, fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}
	}
	for hb.Height > ha.Height {
		b = hb.PrevHash
		hb, ok, err = d.GetIndex(b)
		if err != nil {
			return [32]byte{}, err
		}
		if !ok {
			return [32]byte{}, fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}
	}
	for a != b {
		a = ha.PrevHash
		b = hb.PrevHash
		ha, ok, err = d.GetIndex(a)
		if err != nil {
			return [32]byte{}, err
		}
		if !ok {
			return [32]byte{}, fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}
		hb, ok, err = d.GetIndex(b)
		if err != nil {
			return [32]byte{}, err
		}
		if !ok {
			return [32]byte{}, fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}
	}
	return a, nil
}

// pathFromAncestor returns the hashes from ancestor's child up to tip (ascending height).
func (d *DB) pathFromAncestor(ancestor [32]byte, tip [32]byte) ([][32]byte, error) {
	if ancestor == tip {
		return nil, nil
	}
	// Walk back from tip to ancestor, then reverse.
	cur := tip
	out := make([][32]byte, 0, 16)
	for cur != ancestor {
		out = append(out, cur)
		idx, ok, err := d.GetIndex(cur)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}
		cur = idx.PrevHash
		if cur == ([32]byte{}) {
			return nil, fmt.Errorf("REORG_ERR_INDEX_MISSING")
		}
	}
	// Reverse.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// applyBlockAsNewTip applies a block that is expected to directly extend the current applied tip.
func (d *DB) applyBlockAsNewTip(
	p crypto.CryptoProvider,
	chainID [32]byte,
	blockBytes []byte,
	opts ApplyOptions,
) (ApplyDecision, error) {
	// This is the "direct connect" half of ApplyBlockIfBestTip, without Stage0-3.
	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return "", err
	}
	blockHash, err := consensus.BlockHeaderHash(p, block.Header)
	if err != nil {
		return "", err
	}
	tipHash, err := parseHex32(d.manifest.TipHashHex)
	if err != nil {
		return "", err
	}
	if block.Header.PrevBlockHash != tipHash {
		return "", fmt.Errorf("REORG_ERR_LINKAGE")
	}

	parentIndex, ok, err := d.GetIndex(tipHash)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("REORG_ERR_INDEX_MISSING")
	}
	height := parentIndex.Height + 1

	utxo, err := d.LoadUTXOSet()
	if err != nil {
		return "", err
	}
	ancestorHeaders, err := d.loadAncestorHeadersForParent(tipHash, height)
	if err != nil {
		return "", err
	}
	ctx := consensus.BlockValidationContext{
		Height:           height,
		AncestorHeaders:  ancestorHeaders,
		LocalTime:        opts.LocalTime,
		LocalTimeSet:     opts.LocalTimeSet,
		SuiteIDSLHActive: opts.SuiteIDSLHActive,
		HTLCV2Active:     opts.HTLCV2Active,
	}
	if err := consensus.ApplyBlock(p, chainID, &block, utxo, ctx); err != nil {
		return "", err
	}

	preUtxo, err := d.LoadUTXOSet()
	if err != nil {
		return "", err
	}
	undo, created, err := computeUndoForBlock(p, height, &block, preUtxo)
	if err != nil {
		return "", err
	}
	undo.Created = created

	createdEntries, err := computeCreatedEntries(p, height, &block)
	if err != nil {
		return "", err
	}
	undoBytes, err := encodeUndoRecord(undo)
	if err != nil {
		return "", err
	}

	idx, ok, err := d.GetIndex(blockHash)
	if err != nil {
		return "", err
	}
	if !ok {
		// If index wasn't set, compute minimal here.
		w, err := WorkFromTarget(block.Header.Target)
		if err != nil {
			return "", err
		}
		idx = &BlockIndexEntry{
			Height:         height,
			PrevHash:       tipHash,
			CumulativeWork: new(big.Int).Add(parentIndex.CumulativeWork, w),
			Status:         BlockStatusValid,
		}
	} else {
		idx.Height = height
		idx.PrevHash = tipHash
		idx.Status = BlockStatusValid
	}
	indexBytes, err := encodeIndexEntry(*idx)
	if err != nil {
		return "", err
	}

	if err := d.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketUndo).Put(blockHash[:], undoBytes); err != nil {
			return err
		}
		bu := tx.Bucket(bucketUtxo)
		for _, s := range undo.Spent {
			if err := bu.Delete(encodeOutpointKey(s.OutPoint)); err != nil {
				return err
			}
		}
		for _, ce := range createdEntries {
			val, err := encodeUtxoEntry(ce.Entry)
			if err != nil {
				return err
			}
			if err := bu.Put(encodeOutpointKey(ce.Point), val); err != nil {
				return err
			}
		}
		if err := tx.Bucket(bucketIndex).Put(blockHash[:], indexBytes); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return "", err
	}

	m := &Manifest{
		SchemaVersion: SchemaVersionV1,
		ChainIDHex:    d.manifest.ChainIDHex,

		TipHashHex:           hex32(blockHash),
		TipHeight:            idx.Height,
		TipCumulativeWorkDec: idx.CumulativeWork.Text(10),

		LastAppliedBlockHashHex: hex32(blockHash),
		LastAppliedHeight:       idx.Height,
	}
	if err := d.SetManifest(m); err != nil {
		return "", err
	}
	return ApplyAppliedAsTip, nil
}


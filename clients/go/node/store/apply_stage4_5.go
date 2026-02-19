package store

import (
	"fmt"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"

	bolt "go.etcd.io/bbolt"
)

type ApplyDecision string

const (
	ApplyStoredNotSelected ApplyDecision = "STORED_NOT_SELECTED"
	ApplyOrphaned          ApplyDecision = "ORPHANED"
	ApplyInvalidAncestry   ApplyDecision = "INVALID_ANCESTRY"
	ApplyAppliedAsTip      ApplyDecision = "APPLIED_AS_NEW_TIP"
	ApplyReorgRequired     ApplyDecision = "REORG_REQUIRED"
)

type ApplyOptions struct {
	LocalTime        uint64
	LocalTimeSet     bool
	SuiteIDSLHActive bool
	HTLCV2Active     bool
}

func (d *DB) ApplyBlockIfBestTip(
	p crypto.CryptoProvider,
	chainID [32]byte,
	blockBytes []byte,
	opts ApplyOptions,
) (ApplyDecision, error) {
	// Stage 0-3.
	st03, err := d.ImportStage0To3(p, blockBytes)
	if err != nil {
		return "", err
	}
	switch st03.Decision {
	case Stage03Orphaned:
		return ApplyOrphaned, nil
	case Stage03InvalidAncestry:
		return ApplyInvalidAncestry, nil
	case Stage03NotSelected:
		return ApplyStoredNotSelected, nil
	case Stage03CandidateBest:
	default:
		return "", fmt.Errorf("unknown stage03 decision")
	}

	// Candidate is best tip; decide whether direct connect is possible.
	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return "", err
	}
	blockHash, err := consensus.BlockHeaderHash(p, block.Header)
	if err != nil {
		return "", err
	}
	prev := block.Header.PrevBlockHash
	tipHash, err := parseHex32(d.manifest.TipHashHex)
	if err != nil {
		return "", err
	}
	if prev != tipHash {
		if err := d.ReorgToTip(p, chainID, blockHash, opts); err != nil {
			return "", err
		}
		return ApplyAppliedAsTip, nil
	}

	parentIndex, ok, err := d.GetIndex(prev)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("missing parent index for applied tip")
	}
	height := parentIndex.Height + 1

	utxo, err := d.LoadUTXOSet()
	if err != nil {
		return "", err
	}

	ancestorHeaders, err := d.loadAncestorHeadersForParent(prev, height)
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
	// Stage 4: full validation + compute next utxo.
	if err := consensus.ApplyBlock(p, chainID, &block, utxo, ctx); err != nil {
		// Mark invalid body.
		// NOTE: For Phase 1 we store INVALID in index; reason token plumbing is future.
		idx, ok, _ := d.GetIndex(blockHash)
		if ok {
			idx.Status = BlockStatusInvalid
			_ = d.PutIndex(blockHash, *idx)
		}
		return "", err
	}

	// Stage 5: atomic persist utxo/index/undo then manifest.
	preUtxo, err := d.LoadUTXOSet()
	if err != nil {
		return "", err
	}
	undo, created, err := computeUndoForBlock(p, height, &block, preUtxo)
	if err != nil {
		return "", err
	}
	undo.Created = created

	// Build created outputs with entries for persistence (deterministic order).
	createdEntries, err := computeCreatedEntries(p, height, &block)
	if err != nil {
		return "", err
	}

	undoBytes, err := encodeUndoRecord(undo)
	if err != nil {
		return "", err
	}

	// Index must already exist from Stage 0-3.
	idx, ok, err := d.GetIndex(blockHash)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("missing index entry for candidate")
	}
	idx.Status = BlockStatusValid
	indexBytes, err := encodeIndexEntry(*idx)
	if err != nil {
		return "", err
	}

	if err := d.db.Update(func(tx *bolt.Tx) error {
		// undo
		if err := tx.Bucket(bucketUndo).Put(blockHash[:], undoBytes); err != nil {
			return err
		}
		// utxo: delete spent, insert created
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
		// index status -> VALID
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

type createdEntry struct {
	Point consensus.TxOutPoint
	Entry consensus.UtxoEntry
}

func computeCreatedEntries(p crypto.CryptoProvider, height uint64, block *consensus.Block) ([]createdEntry, error) {
	if block == nil {
		return nil, fmt.Errorf("block nil")
	}
	out := make([]createdEntry, 0, 16)
	for txi := range block.Transactions {
		tx := &block.Transactions[txi]
		isCoinbase := isCoinbaseLike(tx, height)
		txid, err := consensus.TxID(p, tx)
		if err != nil {
			return nil, err
		}
		for vout, o := range tx.Outputs {
			if o.CovenantType == consensus.CORE_ANCHOR {
				continue
			}
			out = append(out, createdEntry{
				Point: consensus.TxOutPoint{TxID: txid, Vout: uint32(vout)},
				Entry: consensus.UtxoEntry{
					Output:            o,
					CreationHeight:    height,
					CreatedByCoinbase: isCoinbase,
				},
			})
		}
	}
	return out, nil
}

func (d *DB) loadAncestorHeadersForParent(parentHash [32]byte, height uint64) ([]consensus.BlockHeader, error) {
	// ApplyBlock expects AncestorHeaders to include parent as the last element when height>0.
	// We load up to max(WINDOW_SIZE, 11) headers ending at the parent by walking prev_hash.
	if height == 0 {
		return nil, nil
	}
	const need11 = 11
	need := uint64(consensus.WINDOW_SIZE)
	if need < need11 {
		need = need11
	}
	if height < need {
		need = height
	}
	headers := make([]consensus.BlockHeader, 0, need)
	cur := parentHash
	for i := uint64(0); i < need; i++ {
		h, ok, err := d.GetHeader(cur)
		if err != nil {
			return nil, err
		}
		if !ok || h == nil {
			return nil, fmt.Errorf("missing header for ancestor %s", hex32(cur))
		}
		headers = append(headers, *h)
		cur = h.PrevBlockHash
		if cur == ([32]byte{}) {
			break
		}
	}
	// Reverse to oldest->newest.
	for i, j := 0, len(headers)-1; i < j; i, j = i+1, j-1 {
		headers[i], headers[j] = headers[j], headers[i]
	}
	return headers, nil
}

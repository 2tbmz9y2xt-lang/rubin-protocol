package store

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"

	bolt "go.etcd.io/bbolt"
)

type Stage03Decision string

const (
	Stage03Orphaned        Stage03Decision = "ORPHANED"
	Stage03InvalidHeader   Stage03Decision = "INVALID_HEADER"
	Stage03InvalidAncestry Stage03Decision = "INVALID_ANCESTRY"
	Stage03NotSelected     Stage03Decision = "STORED_NOT_SELECTED"
	Stage03CandidateBest   Stage03Decision = "CANDIDATE_BEST"
)

type Stage03Result struct {
	Decision       Stage03Decision
	BlockHash      [32]byte
	Height         uint64
	CumulativeWork *big.Int
}

type Stage03Options struct {
	LocalTime    uint64
	LocalTimeSet bool
}

func parseHex32(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func betterThanTip(candidateWork *big.Int, candidateHash [32]byte, tipWork *big.Int, tipHash [32]byte) bool {
	cmp := candidateWork.Cmp(tipWork)
	if cmp > 0 {
		return true
	}
	if cmp < 0 {
		return false
	}
	// Tie-break: lexicographically smaller block_hash wins (bytewise big-endian).
	return bytes.Compare(candidateHash[:], tipHash[:]) < 0
}

// ImportStage0To3 parses a block, persists header+block bytes, performs Stage 2/3
// (ancestry + fork-choice candidate selection), and persists block_index_by_hash.
//
// Stage 4/5 (full validation + apply/reorg) are handled by higher-level import/reorg code.
func (d *DB) ImportStage0To3(p crypto.CryptoProvider, blockBytes []byte, opts Stage03Options) (*Stage03Result, error) {
	if d == nil || d.db == nil {
		return nil, fmt.Errorf("db: not open")
	}
	if d.manifest == nil {
		return nil, fmt.Errorf("db: chain not initialized (missing manifest)")
	}
	if p == nil {
		return nil, fmt.Errorf("crypto provider required")
	}

	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	blockHash, err := consensus.BlockHeaderHash(p, block.Header)
	if err != nil {
		return nil, err
	}
	headerBytes := consensus.BlockHeaderBytes(block.Header)

	// Stage 0 persistence (optional, but we do it in Phase 1 to enable later connect/reorg).
	if err := d.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketHeaders).Put(blockHash[:], headerBytes); err != nil {
			return err
		}
		if err := tx.Bucket(bucketBlocks).Put(blockHash[:], blockBytes); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	prev := block.Header.PrevBlockHash

	// Stage 1: header-level validation (PoW/target/timestamp/merkle).
	// For orphan blocks we only have enough context for PoW+merkle; target/timestamp are validated once ancestry is known.
	{
		var ctx consensus.BlockValidationContext
		if prev != ([32]byte{}) {
			parent, ok, err := d.GetIndex(prev)
			if err != nil {
				return nil, err
			}
			if ok {
				height := parent.Height + 1
				ancestorHeaders, err := d.loadAncestorHeadersForParent(prev, height)
				if err != nil {
					return nil, err
				}
				ctx = consensus.BlockValidationContext{
					Height:          height,
					AncestorHeaders: ancestorHeaders,
					LocalTime:       opts.LocalTime,
					LocalTimeSet:    opts.LocalTimeSet,
				}
			}
		}
		if err := consensus.ValidateBlockHeaderStage1(p, &block, ctx); err != nil {
			// Mark invalid header in index (even if orphan).
			work, werr := WorkFromTarget(block.Header.Target)
			if werr != nil {
				work = big.NewInt(0)
			}

			var height uint64
			cumulative := new(big.Int).Set(work)
			if prev != ([32]byte{}) {
				parent, ok, _ := d.GetIndex(prev)
				if ok && parent != nil && parent.CumulativeWork != nil {
					height = parent.Height + 1
					cumulative = new(big.Int).Add(parent.CumulativeWork, work)
				}
			}

			putErr := d.PutIndex(blockHash, BlockIndexEntry{
				Height:         height,
				PrevHash:       prev,
				CumulativeWork: cumulative,
				Status:         BlockStatusInvalidHeader,
			})
			if putErr != nil {
				return nil, putErr
			}
			return &Stage03Result{
				Decision:       Stage03InvalidHeader,
				BlockHash:      blockHash,
				Height:         height,
				CumulativeWork: cumulative,
			}, err
		}
	}

	var height uint64
	var cumulative *big.Int

	// Genesis special-case: must have zero prev.
	if prev == ([32]byte{}) {
		height = 0
		w, err := WorkFromTarget(block.Header.Target)
		if err != nil {
			return nil, err
		}
		cumulative = w
	} else {
		parent, ok, err := d.GetIndex(prev)
		if err != nil {
			return nil, err
		}
		if !ok {
			// Stage 2: unknown parent => ORPHANED.
			w, err := WorkFromTarget(block.Header.Target)
			if err != nil {
				return nil, err
			}
			cumulative = w
			entry := BlockIndexEntry{
				Height:         0, // unknown in Phase 1 until parent arrives
				PrevHash:       prev,
				CumulativeWork: new(big.Int).Set(cumulative),
				Status:         BlockStatusOrphaned,
			}
			_ = d.PutIndex(blockHash, entry)
			return &Stage03Result{
				Decision:       Stage03Orphaned,
				BlockHash:      blockHash,
				Height:         0,
				CumulativeWork: cumulative,
			}, nil
		}
		if parent.Status.IsInvalid() {
			// Stage 2: invalid ancestry.
			w, err := WorkFromTarget(block.Header.Target)
			if err != nil {
				return nil, err
			}
			cumulative = new(big.Int).Add(parent.CumulativeWork, w)
			entry := BlockIndexEntry{
				Height:         parent.Height + 1,
				PrevHash:       prev,
				CumulativeWork: new(big.Int).Set(cumulative),
				Status:         BlockStatusInvalidAncestry,
			}
			_ = d.PutIndex(blockHash, entry)
			return &Stage03Result{
				Decision:       Stage03InvalidAncestry,
				BlockHash:      blockHash,
				Height:         entry.Height,
				CumulativeWork: cumulative,
			}, nil
		}

		height = parent.Height + 1
		w, err := WorkFromTarget(block.Header.Target)
		if err != nil {
			return nil, err
		}
		cumulative = new(big.Int).Add(parent.CumulativeWork, w)
	}

	// Persist index for this block (stored, not yet applied).
	if err := d.PutIndex(blockHash, BlockIndexEntry{
		Height:         height,
		PrevHash:       prev,
		CumulativeWork: new(big.Int).Set(cumulative),
		Status:         BlockStatusUnknown,
	}); err != nil {
		return nil, err
	}

	tipHash, err := parseHex32(d.manifest.TipHashHex)
	if err != nil {
		return nil, fmt.Errorf("manifest tip_hash: %w", err)
	}
	tipWork := new(big.Int)
	if _, ok := tipWork.SetString(d.manifest.TipCumulativeWorkDec, 10); !ok {
		return nil, fmt.Errorf("manifest tip_cumulative_work: parse")
	}

	decision := Stage03NotSelected
	if betterThanTip(cumulative, blockHash, tipWork, tipHash) {
		decision = Stage03CandidateBest
	}
	return &Stage03Result{
		Decision:       decision,
		BlockHash:      blockHash,
		Height:         height,
		CumulativeWork: cumulative,
	}, nil
}

//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

// storedCommitmentFrontier folds tagged Merkle leaves left to right, keeping at most one pending node per level. root
// promotes an odd node unchanged, reproducing merkleRootTagged without a per-transaction id list.
type storedCommitmentFrontier struct {
	leafTag, nodeTag byte
	pending          [64][32]byte
	present          uint64 // bit i is set while pending[i] holds a node
}

func (f *storedCommitmentFrontier) join(left, right [32]byte) [32]byte {
	var preimage [65]byte
	preimage[0] = f.nodeTag
	copy(preimage[1:33], left[:])
	copy(preimage[33:], right[:])
	return sha3_256(preimage[:])
}

// add appends one leaf; a body of at most MaxBlockBytes cannot carry 2^64 transactions, so the carry stays below 64.
func (f *storedCommitmentFrontier) add(id [32]byte) {
	var leaf [33]byte
	leaf[0] = f.leafTag
	copy(leaf[1:], id[:])
	node := sha3_256(leaf[:])
	level := 0
	for f.present&(1<<level) != 0 {
		node = f.join(f.pending[level], node)
		f.present &^= 1 << level
		level++
	}
	f.pending[level] = node
	f.present |= 1 << level
}

// root combines pending nodes from the lowest level up; a lower node is the right child of the next higher one.
func (f *storedCommitmentFrontier) root() [32]byte {
	var carry [32]byte
	have := false
	for level := 0; level < 64; level++ {
		if f.present&(1<<level) == 0 {
			continue
		}
		if have {
			carry = f.join(f.pending[level], carry)
		} else {
			carry, have = f.pending[level], true
		}
	}
	return carry
}

// verifyStoredBlockCommitmentsStream is ParseBlockBytes followed by ValidateStoredBlockCommitments with the same result
// and error order (RUBIN_L1_CANONICAL.md Sections 10.4, 10.4.1, 10.5): complete framing and trailing bytes first, then
// coinbase, transaction root and witness commitment. It retains only the first and current transaction and two fixed
// frontiers; the witness tree uses a zero id for the coinbase.
func verifyStoredBlockCommitmentsStream(b []byte) error {
	header, off, count, err := storedCommitmentFrame(b)
	if err != nil {
		return err
	}
	first, txRoot, witnessRoot, err := storedCommitmentTransactions(b, off, count)
	if err != nil {
		return err
	}
	return storedCommitmentChecks(first, header.MerkleRoot, txRoot, witnessRoot)
}

// storedCommitmentFrame is ParseBlockBytes' header and transaction-count framing in its order.
func storedCommitmentFrame(b []byte) (BlockHeader, int, uint64, error) {
	if len(b) < BLOCK_HEADER_BYTES+1 {
		return BlockHeader{}, 0, 0, txerr(BLOCK_ERR_PARSE, "block too short")
	}
	header, err := ParseBlockHeaderBytes(b[:BLOCK_HEADER_BYTES])
	if err != nil {
		return BlockHeader{}, 0, 0, txerr(BLOCK_ERR_PARSE, "invalid block header")
	}
	off := BLOCK_HEADER_BYTES
	count, _, err := readCompactSize(b, &off)
	if err != nil {
		return BlockHeader{}, 0, 0, txerr(BLOCK_ERR_PARSE, "invalid tx_count")
	}
	if count == 0 {
		return BlockHeader{}, 0, 0, txerr(BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
	}
	return header, off, count, nil
}

// storedCommitmentTransactions parses every declared transaction with parseBlockTx, folding ids into the two frontiers,
// and rejects trailing bytes before any commitment decision.
func storedCommitmentTransactions(b []byte, off int, count uint64) (*Tx, [32]byte, [32]byte, error) {
	txids := storedCommitmentFrontier{leafTag: 0x00, nodeTag: 0x01}
	wtxids := storedCommitmentFrontier{leafTag: 0x02, nodeTag: 0x03}
	var first *Tx
	for i := uint64(0); i < count; i++ {
		tx, txid, wtxid, _, err := parseBlockTx(b, &off)
		if err != nil {
			return nil, [32]byte{}, [32]byte{}, err
		}
		if i == 0 {
			first, wtxid = tx, [32]byte{}
		}
		txids.add(txid)
		wtxids.add(wtxid)
	}
	if off != len(b) {
		return nil, [32]byte{}, [32]byte{}, txerr(BLOCK_ERR_PARSE, "trailing bytes after tx list")
	}
	return first, txids.root(), wtxids.root(), nil
}

func storedCommitmentChecks(first *Tx, merkleRoot, txRoot, witnessRoot [32]byte) error {
	if !isCoinbaseTx(first) {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "first tx must be canonical coinbase")
	}
	if txRoot != merkleRoot {
		return txerr(BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch")
	}
	if countWitnessCommitmentMatches(first.Outputs, WitnessCommitmentHash(witnessRoot)) != 1 {
		return txerr(BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated")
	}
	return nil
}

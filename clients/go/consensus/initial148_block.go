package consensus

import "errors"

// Initial148ParsedBlock is one dormant fixed148 complete block frame. Header is a
// value; HeaderBytes is an independent 148-byte copy. Transaction variable-byte
// fields keep ParseTx's read-only borrow of raw: the caller must keep raw
// immutable for the lifetime of the parsed block. The container slices are new
// and grow only after each successful transaction parse.
type Initial148ParsedBlock struct {
	Header      Initial148Header
	HeaderBytes []byte
	Txs         []*Tx
	Txids       [][32]byte
	Wtxids      [][32]byte
	TxCount     uint64
}

// ErrInitial148BlockCapacity is the local raw-size refusal (len(raw) > 68000157);
// it is not a consensus ErrorCode.
var ErrInitial148BlockCapacity = errors.New("initial148 block: raw block exceeds 68000157 bytes")

// initial148BlockMaxBytes is the local complete-frame bound M (RUBIN_COMPACT_BLOCKS.md
// Section 10) for the fixed148 frame.
const initial148BlockMaxBytes = 68_000_157

// ParseInitial148BlockBytes decodes exactly one fixed148 complete block frame
// without semantic checks: the count at offset 148, exactly that many
// transactions and no trailing bytes. Every refusal returns a nil result.
func ParseInitial148BlockBytes(raw []byte) (*Initial148ParsedBlock, error) {
	header, headerBytes, off, count, err := initial148Frame(raw)
	if err != nil {
		return nil, err
	}
	txs := make([]*Tx, 0)
	txids := make([][32]byte, 0)
	wtxids := make([][32]byte, 0)
	for i := uint64(0); i < count; i++ {
		tx, txid, wtxid, _, err := parseBlockTx(raw, &off)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
		txids = append(txids, txid)
		wtxids = append(wtxids, wtxid)
	}
	if off != len(raw) {
		return nil, txerr(BLOCK_ERR_PARSE, "trailing bytes after tx list")
	}
	return &Initial148ParsedBlock{
		Header:      header,
		HeaderBytes: headerBytes,
		Txs:         txs,
		Txids:       txids,
		Wtxids:      wtxids,
		TxCount:     count,
	}, nil
}

// ValidateInitial148BlockBodyCommitments checks the local capacity bound, the
// complete fixed148 frame with all transactions and trailing bytes, then the
// existing stored-block coinbase, txid and witness commitment order. It
// materializes no parsed block and does not derive Root(U).
func ValidateInitial148BlockBodyCommitments(raw []byte) error {
	if len(raw) > initial148BlockMaxBytes {
		return ErrInitial148BlockCapacity
	}
	header, _, off, count, err := initial148Frame(raw)
	if err != nil {
		return err
	}
	first, txRoot, witnessRoot, err := storedCommitmentTransactions(raw, off, count)
	if err != nil {
		return err
	}
	// CANONICAL Section 10.5 requires output_count >= 1. The inherited
	// isCoinbaseTx omits that predicate, so this entry rejects the missing
	// outputs locally before reusing the unchanged commitment checks.
	if len(first.Outputs) == 0 {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "first tx must be canonical coinbase")
	}
	return storedCommitmentChecks(first, header.MerkleRoot, txRoot, witnessRoot)
}

// ValidateInitial148BlockSteps1To12 checks capacity, then supplied context, then
// the complete fixed148 parse, then Section 25 steps 2-12 in order. The parsed
// header Target is supplied to the actual Initial148PowCheck; expectedTarget is
// only the retarget comparison. Every non-nil error returns the zero summary.
func ValidateInitial148BlockSteps1To12(raw []byte, parentHash [32]byte, expectedTarget [32]byte, height uint64, parentTimestamps []uint64) (BlockBasicSummary, error) {
	if len(raw) > initial148BlockMaxBytes {
		return BlockBasicSummary{}, ErrInitial148BlockCapacity
	}
	if !blockStepsContextValid(expectedTarget, height, parentTimestamps) {
		return BlockBasicSummary{}, ErrBlockSteps1To12Context
	}
	p, err := initial148FirstPass(raw)
	if err != nil {
		return BlockBasicSummary{}, err
	}
	if err := initial148StepsHeader(raw, &p, parentHash, expectedTarget, parentTimestamps); err != nil {
		return BlockBasicSummary{}, err
	}
	if err := blockStepsResources(&p); err != nil {
		return BlockBasicSummary{}, err
	}
	if err := blockStepsDA(raw, &p); err != nil {
		return BlockBasicSummary{}, err
	}
	hash, err := Initial148BlockHash(raw[:Initial148HeaderBytes])
	if err != nil {
		return BlockBasicSummary{}, err
	}
	return BlockBasicSummary{TxCount: p.count, SumWeight: p.stats.sumWeight, SumDa: p.stats.sumDa, BlockHash: hash}, nil
}

// initial148Frame is the fixed148 header and transaction-count framing in the
// Section 25 step1 order. The returned header bytes are one independent copy.
func initial148Frame(raw []byte) (Initial148Header, []byte, int, uint64, error) {
	if len(raw) < Initial148HeaderBytes+1 {
		return Initial148Header{}, nil, 0, 0, txerr(BLOCK_ERR_PARSE, "block too short")
	}
	headerBytes := append([]byte(nil), raw[:Initial148HeaderBytes]...)
	header, err := ParseInitial148HeaderBytes(headerBytes)
	if err != nil {
		return Initial148Header{}, nil, 0, 0, txerr(BLOCK_ERR_PARSE, "invalid block header")
	}
	off := Initial148HeaderBytes
	count, _, err := readCompactSize(raw, &off)
	if err != nil {
		return Initial148Header{}, nil, 0, 0, txerr(BLOCK_ERR_PARSE, "invalid tx_count")
	}
	if count == 0 {
		return Initial148Header{}, nil, 0, 0, txerr(BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
	}
	return header, headerBytes, off, count, nil
}

// initial148FirstPass projects the fixed148 header into the common BlockHeader
// for the unchanged after-frame pass loop; the full header remains the PoW and
// hash preimage.
func initial148FirstPass(raw []byte) (blockStepsPass, error) {
	header, _, off, count, err := initial148Frame(raw)
	if err != nil {
		return blockStepsPass{}, err
	}
	return blockStepsTransactions(raw, header.blockHeader(), off, count)
}

// blockHeader copies the common step fields by value. UtxoRoot has no step
// projection because steps 2-12 never read it.
func (h Initial148Header) blockHeader() BlockHeader {
	return BlockHeader{
		Version:       h.Version,
		PrevBlockHash: h.PrevBlockHash,
		MerkleRoot:    h.MerkleRoot,
		Timestamp:     h.Timestamp,
		Target:        h.Target,
		Nonce:         h.Nonce,
	}
}

// initial148StepsHeader is steps 2-7 over the full148 frame: actual Initial148
// PoW over the parsed Target, expected target, parent, Merkle root, witness
// commitment and MTP.
func initial148StepsHeader(raw []byte, p *blockStepsPass, parentHash, expectedTarget [32]byte, parentTimestamps []uint64) error {
	if err := Initial148PowCheck(raw[:Initial148HeaderBytes], p.header.Target); err != nil {
		return err
	}
	if p.header.Target != expectedTarget {
		return txerr(BLOCK_ERR_TARGET_INVALID, "target mismatch")
	}
	if p.header.PrevBlockHash != parentHash {
		return txerr(BLOCK_ERR_LINKAGE_INVALID, "prev_block_hash mismatch")
	}
	if err := blockStepsCommitments(p.header, p.first, p.txRoot, p.witnessRoot); err != nil {
		return err
	}
	return blockStepsTimestamp(p.header.Timestamp, parentTimestamps)
}

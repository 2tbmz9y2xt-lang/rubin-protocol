package consensus

import (
	"bytes"
	"errors"
	"sort"
)

// Supplied-context block qualification through RUBIN_L1_CANONICAL.md Section 25 steps 1-12. Neither entry evaluates
// step 13 (coinbase structure, transaction semantics, UTXO or covenant rules), so steps1-12-valid/step13-invalid data is
// admitted. Both entries borrow raw and parentTimestamps read-only for the call and return no alias of either.

var (
	// ErrBlockSteps1To12Capacity is the local raw-size refusal (len(raw) > 68000125); it is not a consensus ErrorCode.
	ErrBlockSteps1To12Capacity = errors.New("block steps 1-12: raw block exceeds 68000125 bytes")
	// ErrBlockSteps1To12Context is the local supplied-context refusal (height 0, expected target outside 1..POW_LIMIT or
	// len(parentTimestamps) != min(height, 11)); it is not a consensus ErrorCode.
	ErrBlockSteps1To12Context = errors.New("block steps 1-12: invalid supplied context")
)

// blockSteps1To12MaxBytes is the stored-body bound M (RUBIN_COMPACT_BLOCKS.md Section 10); the checked offsets below
// stay under 2^32 because of it.
const blockSteps1To12MaxBytes = 68_000_125

// step12DARecord is one DA transaction's fixed 56-byte record: no payload pointer, only checked offsets into raw.
type step12DARecord struct {
	ID                                              [32]byte
	TxOffset, PayloadOffset, PayloadLength, Ordinal uint32
	ChunkIndex, ChunkCount                          uint16
	Kind                                            uint8
}

// step12DARecords orders records in place by ID, Kind (commit 0x01 before chunk 0x02), ChunkIndex and Ordinal.
type step12DARecords []step12DARecord

func (r step12DARecords) Len() int      { return len(r) }
func (r step12DARecords) Swap(i, j int) { r[i], r[j] = r[j], r[i] }
func (r step12DARecords) Less(i, j int) bool {
	if c := bytes.Compare(r[i].ID[:], r[j].ID[:]); c != 0 {
		return c < 0
	}
	if r[i].Kind != r[j].Kind {
		return r[i].Kind < r[j].Kind
	}
	if r[i].ChunkIndex != r[j].ChunkIndex {
		return r[i].ChunkIndex < r[j].ChunkIndex
	}
	return r[i].Ordinal < r[j].Ordinal
}

// blockStepsPass is the complete first pass: header, tx count, first transaction, both tagged roots, resource sums with
// the first deferred computation error, and the DA record count. Only the first and current Tx are ever retained.
type blockStepsPass struct {
	header              BlockHeader
	first               *Tx
	start               int
	count, daRecords    uint64
	txRoot, witnessRoot [32]byte
	stats               blockTxStats
	statErr             error
}

// ValidateBlockSteps1To12 checks capacity, then supplied context, then the complete parse, then Section 25 steps 2-12
// in order. Every non-nil error returns the zero summary.
func ValidateBlockSteps1To12(raw []byte, parentHash [32]byte, expectedTarget [32]byte, height uint64, parentTimestamps []uint64) (BlockBasicSummary, error) {
	if len(raw) > blockSteps1To12MaxBytes {
		return BlockBasicSummary{}, ErrBlockSteps1To12Capacity
	}
	if !blockStepsContextValid(expectedTarget, height, parentTimestamps) {
		return BlockBasicSummary{}, ErrBlockSteps1To12Context
	}
	p, err := blockStepsFirstPass(raw)
	if err != nil {
		return BlockBasicSummary{}, err
	}
	if err := blockStepsHeader(raw, &p, parentHash, expectedTarget, parentTimestamps); err != nil {
		return BlockBasicSummary{}, err
	}
	if err := blockStepsResources(&p); err != nil {
		return BlockBasicSummary{}, err
	}
	if err := blockStepsDA(raw, &p); err != nil {
		return BlockBasicSummary{}, err
	}
	hash, err := BlockHash(raw[:BLOCK_HEADER_BYTES])
	if err != nil {
		return BlockBasicSummary{}, err
	}
	return BlockBasicSummary{TxCount: p.count, SumWeight: p.stats.sumWeight, SumDa: p.stats.sumDa, BlockHash: hash}, nil
}

// ValidateBlockBodyCommitments is the commitment-only entry: the same raw bound, complete frame/Tx/trailing parse,
// tx-root equality, then the witness commitment. It has no context and no coinbase-structure check.
func ValidateBlockBodyCommitments(raw []byte) error {
	if len(raw) > blockSteps1To12MaxBytes {
		return ErrBlockSteps1To12Capacity
	}
	header, off, count, err := storedCommitmentFrame(raw)
	if err != nil {
		return err
	}
	first, txRoot, witnessRoot, err := storedCommitmentTransactions(raw, off, count)
	if err != nil {
		return err
	}
	return blockStepsCommitments(header, first, txRoot, witnessRoot)
}

func blockStepsContextValid(expectedTarget [32]byte, height uint64, parentTimestamps []uint64) bool {
	if height == 0 || expectedTarget == ([32]byte{}) || bytes.Compare(expectedTarget[:], POW_LIMIT[:]) > 0 {
		return false
	}
	return uint64(len(parentTimestamps)) == min(height, 11)
}

// blockStepsFirstPass parses every declared transaction and the trailing bytes before any later decision.
func blockStepsFirstPass(raw []byte) (blockStepsPass, error) {
	header, off, count, err := storedCommitmentFrame(raw)
	if err != nil {
		return blockStepsPass{}, err
	}
	p := blockStepsPass{header: header, start: off, count: count}
	txids := storedCommitmentFrontier{leafTag: 0x00, nodeTag: 0x01}
	wtxids := storedCommitmentFrontier{leafTag: 0x02, nodeTag: 0x03}
	for i := uint64(0); i < count; i++ {
		tx, txid, wtxid, _, err := parseBlockTx(raw, &off)
		if err != nil {
			return blockStepsPass{}, err
		}
		if i == 0 {
			p.first, wtxid = tx, [32]byte{}
		}
		txids.add(txid)
		wtxids.add(wtxid)
		p.account(tx)
	}
	if off != len(raw) {
		return blockStepsPass{}, txerr(BLOCK_ERR_PARSE, "trailing bytes after tx list")
	}
	p.txRoot, p.witnessRoot = txids.root(), wtxids.root()
	return p, nil
}

// account adds one transaction's weight, DA and anchor bytes, deferring the first computation error to step 8.
func (p *blockStepsPass) account(tx *Tx) {
	if tx.TxKind != 0x00 {
		p.daRecords++
	}
	if p.statErr != nil {
		return
	}
	weight, da, anchor, err := txWeightAndStats(tx)
	if err == nil {
		p.stats.sumWeight, err = addBlockResourceStat(p.stats.sumWeight, weight, "sum_weight overflow")
	}
	if err == nil {
		p.stats.sumDa, err = addBlockResourceStat(p.stats.sumDa, da, "sum_da overflow")
	}
	if err == nil {
		p.stats.sumAnchor, err = addBlockResourceStat(p.stats.sumAnchor, anchor, "sum_anchor overflow")
	}
	p.statErr = err
}

// blockStepsHeader is steps 2-7: target range then PoW, expected target, parent, Merkle root, witness commitment, MTP.
func blockStepsHeader(raw []byte, p *blockStepsPass, parentHash, expectedTarget [32]byte, parentTimestamps []uint64) error {
	if err := PowCheck(raw[:BLOCK_HEADER_BYTES], p.header.Target); err != nil {
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

func blockStepsCommitments(header BlockHeader, first *Tx, txRoot, witnessRoot [32]byte) error {
	if txRoot != header.MerkleRoot {
		return txerr(BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch")
	}
	if countWitnessCommitmentMatches(first.Outputs, WitnessCommitmentHash(witnessRoot)) != 1 {
		return txerr(BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated")
	}
	return nil
}

// blockStepsTimestamp takes the lower median of the supplied min(h,11) window (validated non-empty) in a fixed array,
// then the saturating future bound; no clock is read.
func blockStepsTimestamp(timestamp uint64, parentTimestamps []uint64) error {
	var window [11]uint64
	n := copy(window[:], parentTimestamps)
	for i := 1; i < n; i++ {
		for j := i; j > 0 && window[j] < window[j-1]; j-- {
			window[j], window[j-1] = window[j-1], window[j]
		}
	}
	median := window[(n-1)/2]
	if timestamp <= median {
		return txerr(BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median")
	}
	upper := median + MAX_FUTURE_DRIFT
	if upper < median {
		upper = ^uint64(0)
	}
	if timestamp > upper {
		return txerr(BLOCK_ERR_TIMESTAMP_FUTURE, "timestamp exceeds future drift")
	}
	return nil
}

// blockStepsResources is steps 8-9: the first deferred computation error, then weight, DA bytes and anchor bytes.
func blockStepsResources(p *blockStepsPass) error {
	if p.statErr != nil {
		return p.statErr
	}
	return validateBlockResourceLimits(&p.stats)
}

// blockStepsDA is steps 10-12 over exactly D records allocated once after the resource pass.
func blockStepsDA(raw []byte, p *blockStepsPass) error {
	if p.daRecords == 0 {
		return nil
	}
	records := make(step12DARecords, p.daRecords)
	if err := step10DAChunks(raw, p.start, p.count, records); err != nil {
		return err
	}
	sort.Sort(records)
	if err := step11DASets(records); err != nil {
		return err
	}
	return step11EachSet(records, func(set []step12DARecord) error { return step12DAPayload(raw, set) })
}

// step10DAChunks reparses one transaction at a time in original order, checks each chunk hash and fills offsets only.
func step10DAChunks(raw []byte, off int, count uint64, records []step12DARecord) error {
	n := 0
	for ordinal := uint64(0); ordinal < count; ordinal++ {
		txOff := off
		tx, _, _, _, err := parseBlockTx(raw, &off)
		if err != nil {
			return err
		}
		if tx.TxKind == 0x00 {
			continue
		}
		if tx.TxKind == 0x02 && sha3_256(tx.DaPayload) != tx.DaChunkCore.ChunkHash {
			return txerr(BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch")
		}
		records[n] = step12Record(tx, txOff, off, ordinal)
		n++
	}
	return nil
}

// step12Record fills one record; the payload is the transaction's final field, so it ends at the transaction end.
func step12Record(tx *Tx, txOff, end int, ordinal uint64) step12DARecord {
	// raw <= 68000125 < 2^32 bounds every offset, length and ordinal, so each conversion is exact.
	record := step12DARecord{TxOffset: uint32(txOff), PayloadOffset: uint32(end - len(tx.DaPayload)), PayloadLength: uint32(len(tx.DaPayload)), Ordinal: uint32(ordinal), Kind: tx.TxKind} // #nosec G115 -- bounded by raw <= 68000125.
	if tx.TxKind == 0x01 {
		record.ID, record.ChunkCount = tx.DaCommitCore.DaID, tx.DaCommitCore.ChunkCount
	} else {
		record.ID, record.ChunkIndex = tx.DaChunkCore.DaID, tx.DaChunkCore.ChunkIndex
	}
	return record
}

// step11DASets keeps the existing step-11 order over the whole block: orphan IDs, duplicate commits, per-ID
// completeness, set cap, chunk-count bound.
func step11DASets(records step12DARecords) error {
	for _, check := range [...]func([]step12DARecord) error{step11Orphan, step11DuplicateCommit, step11Complete} {
		if err := step11EachSet(records, check); err != nil {
			return err
		}
	}
	sets := 1
	for k := 1; k < len(records); k++ {
		if records[k].ID != records[k-1].ID {
			sets++
		}
	}
	if sets > MAX_DA_BATCHES_PER_BLOCK {
		return txerr(BLOCK_ERR_DA_BATCH_EXCEEDED, "too many DA commits in block")
	}
	return step11EachSet(records, step11ChunkBound)
}

// step11EachSet applies check to each contiguous same-ID group in lexical ID order and stops at the first error.
func step11EachSet(records []step12DARecord, check func([]step12DARecord) error) error {
	for i := 0; i < len(records); {
		j := i + 1
		for j < len(records) && records[j].ID == records[i].ID {
			j++
		}
		if err := check(records[i:j]); err != nil {
			return err
		}
		i = j
	}
	return nil
}

func step11Orphan(set []step12DARecord) error {
	if set[0].Kind != 0x01 {
		return txerr(BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit")
	}
	return nil
}

func step11DuplicateCommit(set []step12DARecord) error {
	if len(set) > 1 && set[1].Kind == 0x01 {
		return txerr(BLOCK_ERR_DA_SET_INVALID, "duplicate DA commit for da_id")
	}
	return nil
}

// step11Complete runs after orphan and duplicate-commit rejection, so set[0] is the only commit and set[1:] are its
// chunks sorted by index: duplicate index, then distinct count, then the first missing expected index.
func step11Complete(set []step12DARecord) error {
	chunks := set[1:]
	for k := 1; k < len(chunks); k++ {
		if chunks[k].ChunkIndex == chunks[k-1].ChunkIndex {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "duplicate DA chunk index")
		}
	}
	if len(chunks) != int(set[0].ChunkCount) {
		return txerr(BLOCK_ERR_DA_INCOMPLETE, "DA chunk count mismatch")
	}
	for k := range chunks {
		if int(chunks[k].ChunkIndex) != k {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "missing DA chunk index")
		}
	}
	return nil
}

func step11ChunkBound(set []step12DARecord) error {
	if invalidDaCommitChunkCount(set[0].ChunkCount) {
		return txerr(TX_ERR_PARSE, "chunk_count out of range for tx_kind=0x01")
	}
	return nil
}

// step12DAPayload reparses the set's commit, checks its one 32-byte DA commitment output, then hashes exactly the
// chunk payload bytes concatenated by chunk index; the buffer is released before the next set.
func step12DAPayload(raw []byte, set []step12DARecord) error {
	off := int(set[0].TxOffset)
	commit, _, _, _, err := parseBlockTx(raw, &off)
	if err != nil {
		return err
	}
	want, err := step12CommitmentOutput(commit.Outputs)
	if err != nil {
		return err
	}
	total := 0
	for _, chunk := range set[1:] {
		total += int(chunk.PayloadLength)
	}
	concat := make([]byte, 0, total)
	for _, chunk := range set[1:] {
		concat = append(concat, raw[chunk.PayloadOffset:chunk.PayloadOffset+chunk.PayloadLength]...)
	}
	if sha3_256(concat) != want {
		return txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "payload commitment mismatch")
	}
	return nil
}

// step12CommitmentOutput rejects the first DA commitment output of invalid length, then a missing or duplicated one.
func step12CommitmentOutput(outputs []TxOutput) ([32]byte, error) {
	var got [32]byte
	found := 0
	for _, out := range outputs {
		if out.CovenantType != COV_TYPE_DA_COMMIT {
			continue
		}
		found++
		if len(out.CovenantData) != 32 {
			return [32]byte{}, txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "DA commitment output has invalid length")
		}
		copy(got[:], out.CovenantData)
	}
	if found != 1 {
		return [32]byte{}, txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "DA commitment output missing or duplicated")
	}
	return got, nil
}

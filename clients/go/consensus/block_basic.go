package consensus

import (
	"bytes"
	"math/big"
	"sort"
)

type ParsedBlock struct {
	HeaderBytes []byte
	Txs         []*Tx
	Txids       [][32]byte
	Wtxids      [][32]byte
	Header      BlockHeader
	TxCount     uint64
}

type BlockBasicSummary struct {
	TxCount   uint64
	SumWeight uint64
	SumDa     uint64
	BlockHash [32]byte
}

type blockTxStats struct {
	sumWeight uint64
	sumDa     uint64
	sumAnchor uint64
}

func isCoinbasePrevout(in TxInput) bool {
	var zero [32]byte
	return in.PrevTxid == zero && in.PrevVout == ^uint32(0)
}

func isCoinbaseTx(tx *Tx) bool {
	if tx == nil {
		return false
	}
	if tx.TxKind != 0x00 {
		return false
	}
	if tx.TxNonce != 0 {
		return false
	}
	if len(tx.Inputs) != 1 {
		return false
	}
	if len(tx.Witness) != 0 {
		return false
	}
	if len(tx.DaPayload) != 0 {
		return false
	}
	return isCoinbaseTxInput(tx.Inputs[0])
}

func isCoinbaseTxInput(in TxInput) bool {
	return isCoinbasePrevout(in) && len(in.ScriptSig) == 0 && in.Sequence == ^uint32(0)
}

func ParseBlockBytes(b []byte) (*ParsedBlock, error) {
	if len(b) < BLOCK_HEADER_BYTES+1 {
		return nil, txerr(BLOCK_ERR_PARSE, "block too short")
	}

	headerBytes := append([]byte(nil), b[:BLOCK_HEADER_BYTES]...)
	header, err := ParseBlockHeaderBytes(headerBytes)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "invalid block header")
	}

	off := BLOCK_HEADER_BYTES
	txCount, _, err := readCompactSize(b, &off)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "invalid tx_count")
	}
	if txCount == 0 {
		return nil, txerr(BLOCK_ERR_COINBASE_INVALID, "empty block tx list")
	}

	txs := make([]*Tx, 0)
	txids := make([][32]byte, 0)
	wtxids := make([][32]byte, 0)
	for i := uint64(0); i < txCount; i++ {
		tx, txid, wtxid, _, err := parseBlockTx(b, &off)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
		txids = append(txids, txid)
		wtxids = append(wtxids, wtxid)
	}

	if off != len(b) {
		return nil, txerr(BLOCK_ERR_PARSE, "trailing bytes after tx list")
	}

	return &ParsedBlock{
		Header:      header,
		HeaderBytes: headerBytes,
		TxCount:     txCount,
		Txs:         txs,
		Txids:       txids,
		Wtxids:      wtxids,
	}, nil
}

// parseBlockTx parses a single transaction from b at the given offset,
// advances off past the consumed bytes, and returns the parsed tx.
func parseBlockTx(b []byte, off *int) (*Tx, [32]byte, [32]byte, int, error) {
	if *off >= len(b) {
		return nil, [32]byte{}, [32]byte{}, 0, txerr(BLOCK_ERR_PARSE, "unexpected EOF in tx list")
	}
	tx, txid, wtxid, n, err := ParseTx(b[*off:])
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, 0, err
	}
	*off += n
	return tx, txid, wtxid, n, nil
}

func ValidateBlockBasic(blockBytes []byte, expectedPrevHash *[32]byte, expectedTarget *[32]byte) (*BlockBasicSummary, error) {
	return ValidateBlockBasicAtHeight(blockBytes, expectedPrevHash, expectedTarget, 0)
}

func ValidateBlockBasicAtHeight(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
) (*BlockBasicSummary, error) {
	return ValidateBlockBasicWithContextAtHeight(blockBytes, expectedPrevHash, expectedTarget, blockHeight, nil)
}

func ValidateBlockBasicWithContextAtHeight(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
) (*BlockBasicSummary, error) {
	return ValidateBlockBasicWithContextAtHeightAndRotation(blockBytes, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps, nil)
}

func ValidateBlockBasicWithContextAtHeightAndRotation(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	rotation RotationProvider,
) (*BlockBasicSummary, error) {
	_, summary, err := parseAndValidateBlockBasicWithContextAtHeight(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		rotation,
	)
	return summary, err
}

func parseAndValidateBlockBasicWithContextAtHeight(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	rotation RotationProvider,
) (*ParsedBlock, *BlockBasicSummary, error) {
	pb, err := ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, nil, err
	}
	summary, err := validateParsedBlockBasicWithContextAtHeight(pb, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps, rotation)
	if err != nil {
		return nil, nil, err
	}
	return pb, summary, nil
}

func validateParsedBlockBasicWithContextAtHeight(
	pb *ParsedBlock,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	rotation RotationProvider,
) (*BlockBasicSummary, error) {
	blockHash, stats, err := validateParsedBlockChecks(pb, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps, rotation)
	if err != nil {
		return nil, err
	}

	return &BlockBasicSummary{
		TxCount:   pb.TxCount,
		SumWeight: stats.sumWeight,
		SumDa:     stats.sumDa,
		BlockHash: blockHash,
	}, nil
}

// validateParsedBlockChecks runs all basic block validation checks and returns
// the block hash and resource stats on success.
func validateParsedBlockChecks(
	pb *ParsedBlock,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	rotation RotationProvider,
) ([32]byte, *blockTxStats, error) {
	if pb == nil {
		return [32]byte{}, nil, txerr(BLOCK_ERR_PARSE, "nil parsed block")
	}
	if err := validateBlockHeaderChecks(pb, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps); err != nil {
		return [32]byte{}, nil, err
	}
	stats, err := validateBlockBodyChecks(pb, blockHeight, rotation)
	if err != nil {
		return [32]byte{}, nil, err
	}
	blockHash, err := BlockHash(pb.HeaderBytes)
	if err != nil {
		return [32]byte{}, nil, txerr(BLOCK_ERR_PARSE, "failed to hash block header")
	}
	return blockHash, stats, nil
}

func validateBlockHeaderChecks(pb *ParsedBlock, expectedPrevHash *[32]byte, expectedTarget *[32]byte, blockHeight uint64, prevTimestamps []uint64) error {
	if err := validateHeaderCommitments(pb, expectedPrevHash, expectedTarget); err != nil {
		return err
	}
	if err := validateCoinbaseWitnessCommitment(pb); err != nil {
		return err
	}
	return validateTimestampRules(pb.Header.Timestamp, blockHeight, prevTimestamps)
}

func validateBlockBodyChecks(pb *ParsedBlock, blockHeight uint64, rotation RotationProvider) (*blockTxStats, error) {
	stats, err := accumulateBlockResourceStats(pb)
	if err != nil {
		return nil, err
	}
	if err := validateBlockResourceLimits(stats); err != nil {
		return nil, err
	}
	if err := validateDASetIntegrity(pb.Txs); err != nil {
		return nil, err
	}
	if err := validateBlockTxSemantics(pb, blockHeight, rotation); err != nil {
		return nil, err
	}
	return stats, nil
}

// ValidateBlockBasicWithContextAndFeesAtHeight extends basic block validation with the
// coinbase subsidy/value bound (CANONICAL §19.2).
//
// sumFees MUST be the sum of (sum_in - sum_out) over all non-coinbase transactions in the block.
// alreadyGenerated MUST be already_generated(h) per CANONICAL §19.1 (subsidy-only, excluding fees).
//
// This does not compute fees; it only enforces the bound once fees are known.
func ValidateBlockBasicWithContextAndFeesAtHeight(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	alreadyGenerated uint64,
	sumFees uint64,
) (*BlockBasicSummary, error) {
	return ValidateBlockBasicWithContextAndFeesAtHeightAndRotation(blockBytes, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps, alreadyGenerated, sumFees, nil)
}

func ValidateBlockBasicWithContextAndFeesAtHeightAndRotation(blockBytes []byte, expectedPrevHash *[32]byte, expectedTarget *[32]byte, blockHeight uint64, prevTimestamps []uint64, alreadyGenerated uint64, sumFees uint64, rotation RotationProvider) (*BlockBasicSummary, error) {
	pb, s, err := parseAndValidateBlockBasicWithContextAtHeight(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		rotation,
	)
	if err != nil {
		return nil, err
	}
	if err := validateCoinbaseValueBound(pb, blockHeight, new(big.Int).SetUint64(alreadyGenerated), sumFees); err != nil {
		return nil, err
	}
	return s, nil
}

type daCommitSet struct {
	tx         *Tx
	chunkCount uint16
}

func validateBlockResourceLimits(stats *blockTxStats) error {
	if stats.sumWeight > MAX_BLOCK_WEIGHT {
		return txerr(BLOCK_ERR_WEIGHT_EXCEEDED, "block weight exceeded")
	}
	if stats.sumDa > MAX_DA_BYTES_PER_BLOCK {
		return txerr(BLOCK_ERR_WEIGHT_EXCEEDED, "DA bytes exceeded")
	}
	if stats.sumAnchor > MAX_ANCHOR_BYTES_PER_BLOCK {
		return txerr(BLOCK_ERR_ANCHOR_BYTES_EXCEEDED, "anchor bytes exceeded")
	}
	return nil
}

func validateDASetIntegrity(txs []*Tx) error {
	commits, chunks, err := collectDACommitsAndChunks(txs)
	if err != nil {
		return err
	}
	if err := validateDACommitCompleteness(commits, chunks); err != nil {
		return err
	}
	return validateDAPayloadCommitments(commits, chunks)
}

func collectDACommitsAndChunks(txs []*Tx) (map[[32]byte]daCommitSet, map[[32]byte]map[uint16]*Tx, error) {
	commits := make(map[[32]byte]daCommitSet)
	chunks := make(map[[32]byte]map[uint16]*Tx)
	for _, tx := range txs {
		switch tx.TxKind {
		case 0x01:
			if err := addDACommit(commits, tx); err != nil {
				return nil, nil, err
			}
		case 0x02:
			if err := addDAChunk(chunks, tx); err != nil {
				return nil, nil, err
			}
		}
	}
	return commits, chunks, nil
}

func addDACommit(commits map[[32]byte]daCommitSet, tx *Tx) error {
	if tx.DaCommitCore == nil {
		return txerr(TX_ERR_PARSE, "missing da_commit_core for tx_kind=0x01")
	}
	daID := tx.DaCommitCore.DaID
	if _, exists := commits[daID]; exists {
		return txerr(BLOCK_ERR_DA_SET_INVALID, "duplicate DA commit for da_id")
	}
	commits[daID] = daCommitSet{tx: tx, chunkCount: tx.DaCommitCore.ChunkCount}
	return nil
}

func addDAChunk(chunks map[[32]byte]map[uint16]*Tx, tx *Tx) error {
	if tx.DaChunkCore == nil {
		return txerr(TX_ERR_PARSE, "missing da_chunk_core for tx_kind=0x02")
	}
	daID := tx.DaChunkCore.DaID
	idx := tx.DaChunkCore.ChunkIndex
	if sha3_256(tx.DaPayload) != tx.DaChunkCore.ChunkHash {
		return txerr(BLOCK_ERR_DA_CHUNK_HASH_INVALID, "chunk_hash mismatch")
	}
	if chunks[daID] == nil {
		chunks[daID] = make(map[uint16]*Tx)
	}
	if _, exists := chunks[daID][idx]; exists {
		return txerr(BLOCK_ERR_DA_SET_INVALID, "duplicate DA chunk index")
	}
	chunks[daID][idx] = tx
	return nil
}

func validateDACommitCompleteness(commits map[[32]byte]daCommitSet, chunks map[[32]byte]map[uint16]*Tx) error {
	if len(commits) > MAX_DA_BATCHES_PER_BLOCK {
		return txerr(BLOCK_ERR_DA_BATCH_EXCEEDED, "too many DA commits in block")
	}
	if err := validateDACommitChunkOrphans(commits, chunks); err != nil {
		return err
	}
	return validateDACommitChunkIntegrity(commits, chunks)
}

func validateDACommitChunkOrphans(commits map[[32]byte]daCommitSet, chunks map[[32]byte]map[uint16]*Tx) error {
	for _, daID := range sortedDAIDs(chunks) {
		if _, exists := commits[daID]; !exists {
			return txerr(BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit")
		}
	}
	return nil
}

func validateDACommitChunkIntegrity(commits map[[32]byte]daCommitSet, chunks map[[32]byte]map[uint16]*Tx) error {
	for _, daID := range sortedDAIDs(commits) {
		commit := commits[daID]
		if commit.chunkCount == 0 {
			return txerr(TX_ERR_PARSE, "chunk_count out of range for tx_kind=0x01")
		}
		if uint64(commit.chunkCount) > MAX_DA_CHUNK_COUNT {
			return txerr(TX_ERR_PARSE, "chunk_count out of range for tx_kind=0x01")
		}
		set := chunks[daID]
		if set == nil {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "DA commit without chunks")
		}
		if len(set) != int(commit.chunkCount) {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "DA chunk count mismatch")
		}
		if err := validateDACommitChunkIndexes(set, commit.chunkCount); err != nil {
			return err
		}
	}
	return nil
}

func validateDACommitChunkIndexes(set map[uint16]*Tx, chunkCount uint16) error {
	for i := uint16(0); i < chunkCount; i++ {
		if _, exists := set[i]; !exists {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "missing DA chunk index")
		}
	}
	return nil
}

func validateDAPayloadCommitments(commits map[[32]byte]daCommitSet, chunks map[[32]byte]map[uint16]*Tx) error {
	commitIDs := sortedDAIDs(commits)
	for _, daID := range commitIDs {
		commit := commits[daID]
		set := chunks[daID]
		var concat []byte
		for i := uint16(0); i < commit.chunkCount; i++ {
			concat = append(concat, set[i].DaPayload...)
		}
		payloadCommitment := sha3_256(concat)
		daCommitOutputs := 0
		var gotCommitment [32]byte
		for _, out := range commit.tx.Outputs {
			if out.CovenantType != COV_TYPE_DA_COMMIT {
				continue
			}
			daCommitOutputs++
			if len(out.CovenantData) != 32 {
				return txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "DA commitment output has invalid length")
			}
			copy(gotCommitment[:], out.CovenantData)
		}
		if daCommitOutputs != 1 {
			return txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "DA commitment output missing or duplicated")
		}
		if gotCommitment != payloadCommitment {
			return txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "payload commitment mismatch")
		}
	}
	return nil
}

func sortedDAIDs[T any](m map[[32]byte]T) [][32]byte {
	ids := make([][32]byte, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return bytes.Compare(ids[i][:], ids[j][:]) < 0
	})
	return ids
}

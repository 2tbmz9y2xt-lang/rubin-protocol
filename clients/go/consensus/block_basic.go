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
	if tx.TxKind != 0x00 || tx.TxNonce != 0 {
		return false
	}
	if len(tx.Inputs) != 1 || len(tx.Witness) != 0 || len(tx.DaPayload) != 0 {
		return false
	}
	in := tx.Inputs[0]
	if !isCoinbasePrevout(in) || len(in.ScriptSig) != 0 || in.Sequence != ^uint32(0) {
		return false
	}
	return true
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
		if off >= len(b) {
			return nil, txerr(BLOCK_ERR_PARSE, "unexpected EOF in tx list")
		}
		tx, txid, wtxid, n, err := ParseTx(b[off:])
		if err != nil {
			return nil, err
		}
		off += n
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
	pb, err := ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	return validateParsedBlockBasicWithContextAtHeight(pb, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps)
}

func validateParsedBlockBasicWithContextAtHeight(
	pb *ParsedBlock,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
) (*BlockBasicSummary, error) {
	if pb == nil {
		return nil, txerr(BLOCK_ERR_PARSE, "nil parsed block")
	}

	if err := validateHeaderCommitments(pb, expectedPrevHash, expectedTarget); err != nil {
		return nil, err
	}
	if err := validateCoinbaseWitnessCommitment(pb); err != nil {
		return nil, err
	}
	if err := validateTimestampRules(pb.Header.Timestamp, blockHeight, prevTimestamps); err != nil {
		return nil, err
	}
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
	if err := validateBlockTxSemantics(pb, blockHeight); err != nil {
		return nil, err
	}

	blockHash, err := BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "failed to hash block header")
	}

	return &BlockBasicSummary{
		TxCount:   pb.TxCount,
		SumWeight: stats.sumWeight,
		SumDa:     stats.sumDa,
		BlockHash: blockHash,
	}, nil
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
	pb, err := ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	s, err := validateParsedBlockBasicWithContextAtHeight(pb, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps)
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
	commits := make(map[[32]byte]daCommitSet)
	chunks := make(map[[32]byte]map[uint16]*Tx)

	for _, tx := range txs {
		switch tx.TxKind {
		case 0x01:
			if tx.DaCommitCore == nil {
				return txerr(TX_ERR_PARSE, "missing da_commit_core for tx_kind=0x01")
			}
			daID := tx.DaCommitCore.DaID
			if _, exists := commits[daID]; exists {
				return txerr(BLOCK_ERR_DA_SET_INVALID, "duplicate DA commit for da_id")
			}
			commits[daID] = daCommitSet{tx: tx, chunkCount: tx.DaCommitCore.ChunkCount}
		case 0x02:
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
		}
	}

	commitIDs := sortedDAIDs(commits)
	chunkIDs := sortedDAIDs(chunks)

	for _, daID := range chunkIDs {
		if _, exists := commits[daID]; !exists {
			return txerr(BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit")
		}
	}

	for _, daID := range commitIDs {
		commit := commits[daID]
		if commit.chunkCount == 0 || uint64(commit.chunkCount) > MAX_DA_CHUNK_COUNT {
			return txerr(TX_ERR_PARSE, "chunk_count out of range for tx_kind=0x01")
		}
		set := chunks[daID]
		if set == nil {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "DA commit without chunks")
		}
		if len(set) != int(commit.chunkCount) {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "DA chunk count mismatch")
		}

		for i := uint16(0); i < commit.chunkCount; i++ {
			_, exists := set[i]
			if !exists {
				return txerr(BLOCK_ERR_DA_INCOMPLETE, "missing DA chunk index")
			}
		}
	}

	if len(commits) > MAX_DA_BATCHES_PER_BLOCK {
		return txerr(BLOCK_ERR_DA_BATCH_EXCEEDED, "too many DA commits in block")
	}

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
			if len(out.CovenantData) == 32 {
				copy(gotCommitment[:], out.CovenantData)
			}
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

func txWeightAndStats(tx *Tx) (uint64, uint64, uint64, error) {
	if tx == nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "nil tx")
	}

	var err error
	var baseSize uint64
	baseSize = 4 + 1 + 8
	baseSize, err = addU64(baseSize, compactSizeLen(uint64(len(tx.Inputs))))
	if err != nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "tx base size overflow")
	}
	for _, in := range tx.Inputs {
		baseSize, err = addU64(baseSize, 32+4)
		if err != nil {
			return 0, 0, 0, err
		}
		baseSize, err = addU64(baseSize, compactSizeLen(uint64(len(in.ScriptSig))))
		if err != nil {
			return 0, 0, 0, err
		}
		baseSize, err = addU64(baseSize, uint64(len(in.ScriptSig)))
		if err != nil {
			return 0, 0, 0, err
		}
		baseSize, err = addU64(baseSize, 4)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	baseSize, err = addU64(baseSize, compactSizeLen(uint64(len(tx.Outputs))))
	if err != nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "tx base size overflow")
	}
	var anchorBytes uint64
	for _, out := range tx.Outputs {
		baseSize, err = addU64(baseSize, 8+2)
		if err != nil {
			return 0, 0, 0, err
		}
		covLen := uint64(len(out.CovenantData))
		baseSize, err = addU64(baseSize, compactSizeLen(covLen))
		if err != nil {
			return 0, 0, 0, err
		}
		baseSize, err = addU64(baseSize, covLen)
		if err != nil {
			return 0, 0, 0, err
		}
		if out.CovenantType == COV_TYPE_ANCHOR || out.CovenantType == COV_TYPE_DA_COMMIT {
			anchorBytes, err = addU64(anchorBytes, covLen)
			if err != nil {
				return 0, 0, 0, err
			}
		}
	}
	baseSize, err = addU64(baseSize, 4)
	if err != nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "tx base size overflow")
	}
	daCoreBytes, err := daCoreFieldsBytes(tx)
	if err != nil {
		return 0, 0, 0, err
	}
	baseSize, err = addU64(baseSize, uint64(len(daCoreBytes)))
	if err != nil {
		return 0, 0, 0, err
	}

	witnessSize := compactSizeLen(uint64(len(tx.Witness)))
	var mlCount uint64
	var unknownSuiteCount uint64
	for _, w := range tx.Witness {
		witnessSize, err = addU64(witnessSize, 1)
		if err != nil {
			return 0, 0, 0, err
		}
		witnessSize, err = addU64(witnessSize, compactSizeLen(uint64(len(w.Pubkey))))
		if err != nil {
			return 0, 0, 0, err
		}
		witnessSize, err = addU64(witnessSize, uint64(len(w.Pubkey)))
		if err != nil {
			return 0, 0, 0, err
		}
		witnessSize, err = addU64(witnessSize, compactSizeLen(uint64(len(w.Signature))))
		if err != nil {
			return 0, 0, 0, err
		}
		witnessSize, err = addU64(witnessSize, uint64(len(w.Signature)))
		if err != nil {
			return 0, 0, 0, err
		}
		switch w.SuiteID {
		case SUITE_ID_ML_DSA_87:
			if len(w.Pubkey) == ML_DSA_87_PUBKEY_BYTES && len(w.Signature) == ML_DSA_87_SIG_BYTES+1 {
				mlCount++
			}
		case SUITE_ID_SENTINEL:
		default:
			unknownSuiteCount++
		}
	}

	daLen := uint64(len(tx.DaPayload))
	daSize, err := addU64(compactSizeLen(daLen), daLen)
	if err != nil {
		return 0, 0, 0, err
	}
	daBytes := uint64(0)
	if tx.TxKind != 0x00 {
		daBytes = daLen
	}

	mlCost, err := mulU64(mlCount, VERIFY_COST_ML_DSA_87)
	if err != nil {
		return 0, 0, 0, err
	}
	sigCost := mlCost
	unknownCost, err := mulU64(unknownSuiteCount, VERIFY_COST_UNKNOWN_SUITE)
	if err != nil {
		return 0, 0, 0, err
	}
	sigCost, err = addU64(sigCost, unknownCost)
	if err != nil {
		return 0, 0, 0, err
	}

	baseWeight, err := mulU64(WITNESS_DISCOUNT_DIVISOR, baseSize)
	if err != nil {
		return 0, 0, 0, err
	}
	weight, err := addU64(baseWeight, witnessSize)
	if err != nil {
		return 0, 0, 0, err
	}
	weight, err = addU64(weight, daSize)
	if err != nil {
		return 0, 0, 0, err
	}
	weight, err = addU64(weight, sigCost)
	if err != nil {
		return 0, 0, 0, err
	}

	return weight, daBytes, anchorBytes, nil
}

func compactSizeLen(n uint64) uint64 {
	switch {
	case n < 0xfd:
		return 1
	case n <= 0xffff:
		return 3
	case n <= 0xffff_ffff:
		return 5
	default:
		return 9
	}
}

func addU64(a uint64, b uint64) (uint64, error) {
	if a > ^uint64(0)-b {
		return 0, txerr(TX_ERR_PARSE, "u64 overflow")
	}
	return a + b, nil
}

func mulU64(a uint64, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > ^uint64(0)/b {
		return 0, txerr(TX_ERR_PARSE, "u64 overflow")
	}
	return a * b, nil
}

// TxWeightAndStats exposes consensus weight accounting for conformance and formal tooling.
// It is a pure function of a parsed Tx and does not consult chainstate.
func TxWeightAndStats(tx *Tx) (uint64, uint64, uint64, error) {
	return txWeightAndStats(tx)
}

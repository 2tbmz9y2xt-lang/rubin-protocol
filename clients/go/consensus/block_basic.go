package consensus

import (
	"bytes"
	"math/bits"
	"sort"
)

type ParsedBlock struct {
	Header      BlockHeader
	HeaderBytes []byte
	TxCount     uint64
	Txs         []*Tx
	Txids       [][32]byte
	Wtxids      [][32]byte
}

type BlockBasicSummary struct {
	TxCount   uint64
	SumWeight uint64
	SumDa     uint64
	BlockHash [32]byte
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

	if expectedPrevHash != nil && pb.Header.PrevBlockHash != *expectedPrevHash {
		return nil, txerr(BLOCK_ERR_LINKAGE_INVALID, "prev_block_hash mismatch")
	}

	root, err := MerkleRootTxids(pb.Txids)
	if err != nil {
		return nil, txerr(BLOCK_ERR_MERKLE_INVALID, "failed to compute merkle root")
	}
	if root != pb.Header.MerkleRoot {
		return nil, txerr(BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch")
	}

	if err := PowCheck(pb.HeaderBytes, pb.Header.Target); err != nil {
		return nil, err
	}

	if expectedTarget != nil && pb.Header.Target != *expectedTarget {
		return nil, txerr(BLOCK_ERR_TARGET_INVALID, "target mismatch")
	}

	var sumWeight uint64
	var sumDa uint64
	var sumAnchor uint64
	if len(pb.Txs) == 0 || !isCoinbaseTx(pb.Txs[0]) {
		return nil, txerr(BLOCK_ERR_COINBASE_INVALID, "first tx must be canonical coinbase")
	}
	if pb.Txs[0].Locktime != uint32(blockHeight) {
		return nil, txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase locktime must equal block height")
	}
	seenNonces := make(map[uint64]struct{}, len(pb.Txs))
	for i, tx := range pb.Txs {
		if err := validateWitnessSuiteActivation(tx, i, blockHeight); err != nil {
			return nil, err
		}
		if i > 0 && isCoinbaseTx(tx) {
			return nil, txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase-like tx is only allowed at index 0")
		}
		// Non-coinbase transactions must carry at least one input.
		if i > 0 && len(tx.Inputs) == 0 {
			return nil, txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
		}
		if i > 0 {
			if _, exists := seenNonces[tx.TxNonce]; exists {
				return nil, txerr(TX_ERR_NONCE_REPLAY, "duplicate tx_nonce in block")
			}
			seenNonces[tx.TxNonce] = struct{}{}
		}
		if err := ValidateTxCovenantsGenesis(tx, blockHeight); err != nil {
			return nil, err
		}
		w, da, anchorBytes, err := txWeightAndStats(tx)
		if err != nil {
			return nil, err
		}
		sumWeight, err = addU64(sumWeight, w)
		if err != nil {
			return nil, err
		}
		sumDa, err = addU64(sumDa, da)
		if err != nil {
			return nil, err
		}
		sumAnchor, err = addU64(sumAnchor, anchorBytes)
		if err != nil {
			return nil, err
		}
	}
	if err := validateCoinbaseWitnessCommitment(pb); err != nil {
		return nil, err
	}
	if err := validateTimestampRules(pb.Header.Timestamp, blockHeight, prevTimestamps); err != nil {
		return nil, err
	}
	if err := validateDASetIntegrity(pb.Txs); err != nil {
		return nil, err
	}

	if sumDa > MAX_DA_BYTES_PER_BLOCK {
		return nil, txerr(BLOCK_ERR_WEIGHT_EXCEEDED, "DA bytes exceeded")
	}
	if sumAnchor > MAX_ANCHOR_BYTES_PER_BLOCK {
		return nil, txerr(BLOCK_ERR_ANCHOR_BYTES_EXCEEDED, "anchor bytes exceeded")
	}
	if sumWeight > MAX_BLOCK_WEIGHT {
		return nil, txerr(BLOCK_ERR_WEIGHT_EXCEEDED, "block weight exceeded")
	}

	blockHash, err := BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, txerr(BLOCK_ERR_PARSE, "failed to hash block header")
	}

	return &BlockBasicSummary{
		TxCount:   pb.TxCount,
		SumWeight: sumWeight,
		SumDa:     sumDa,
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
	s, err := ValidateBlockBasicWithContextAtHeight(blockBytes, expectedPrevHash, expectedTarget, blockHeight, prevTimestamps)
	if err != nil {
		return nil, err
	}
	pb, err := ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	if err := validateCoinbaseValueBound(pb, blockHeight, alreadyGenerated, sumFees); err != nil {
		return nil, err
	}
	return s, nil
}

func validateCoinbaseValueBound(pb *ParsedBlock, blockHeight uint64, alreadyGenerated uint64, sumFees uint64) error {
	if pb == nil || len(pb.Txs) == 0 {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "missing coinbase")
	}
	if blockHeight == 0 {
		return nil
	}
	coinbase := pb.Txs[0]
	if coinbase == nil {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "nil coinbase")
	}

	var sumCoinbase u128
	for _, out := range coinbase.Outputs {
		var err error
		sumCoinbase, err = addU64ToU128Block(sumCoinbase, out.Value)
		if err != nil {
			return err
		}
	}
	subsidy := BlockSubsidy(blockHeight, alreadyGenerated)
	limit := u128{hi: 0, lo: subsidy}
	limit, err := addU64ToU128Block(limit, sumFees)
	if err != nil {
		return err
	}
	if cmpU128(sumCoinbase, limit) > 0 {
		return txerr(BLOCK_ERR_SUBSIDY_EXCEEDED, "coinbase outputs exceed subsidy+fees bound")
	}
	return nil
}

func addU64ToU128Block(x u128, v uint64) (u128, error) {
	lo, carry := bits.Add64(x.lo, v, 0)
	hi, carry2 := bits.Add64(x.hi, 0, carry)
	if carry2 != 0 {
		return u128{}, txerr(BLOCK_ERR_PARSE, "u128 overflow")
	}
	return u128{hi: hi, lo: lo}, nil
}

func validateWitnessSuiteActivation(tx *Tx, txIndex int, blockHeight uint64) error {
	if tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}
	if txIndex == 0 {
		// Coinbase witness is structurally empty in genesis profile.
		return nil
	}
	for _, w := range tx.Witness {
		if w.SuiteID == SUITE_ID_SLH_DSA_SHAKE_256F && blockHeight < SLH_DSA_ACTIVATION_HEIGHT {
			return txerr(TX_ERR_SIG_ALG_INVALID, "SLH-DSA suite inactive at this height")
		}
	}
	return nil
}

func validateCoinbaseWitnessCommitment(pb *ParsedBlock) error {
	if pb == nil || len(pb.Txs) == 0 || len(pb.Wtxids) == 0 {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "missing coinbase")
	}

	wroot, err := WitnessMerkleRootWtxids(pb.Wtxids)
	if err != nil {
		return txerr(BLOCK_ERR_WITNESS_COMMITMENT, "failed to compute witness merkle root")
	}
	expected := WitnessCommitmentHash(wroot)

	matches := 0
	for _, out := range pb.Txs[0].Outputs {
		if out.CovenantType != COV_TYPE_ANCHOR || len(out.CovenantData) != 32 {
			continue
		}
		if bytes.Equal(out.CovenantData, expected[:]) {
			matches++
		}
	}

	if matches != 1 {
		return txerr(BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated")
	}
	return nil
}

func validateTimestampRules(headerTimestamp uint64, blockHeight uint64, prevTimestamps []uint64) error {
	median, ok, err := medianTimePast(blockHeight, prevTimestamps)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if headerTimestamp <= median {
		return txerr(BLOCK_ERR_TIMESTAMP_OLD, "timestamp <= MTP median")
	}
	upperBound := median + MAX_FUTURE_DRIFT
	if upperBound < median {
		upperBound = ^uint64(0)
	}
	if headerTimestamp > upperBound {
		return txerr(BLOCK_ERR_TIMESTAMP_FUTURE, "timestamp exceeds future drift")
	}
	return nil
}

func medianTimePast(blockHeight uint64, prevTimestamps []uint64) (uint64, bool, error) {
	if blockHeight == 0 || len(prevTimestamps) == 0 {
		return 0, false, nil
	}
	k := int(blockHeight)
	if k > 11 {
		k = 11
	}
	if len(prevTimestamps) < k {
		return 0, false, txerr(BLOCK_ERR_PARSE, "insufficient prev_timestamps context")
	}
	window := append([]uint64(nil), prevTimestamps[:k]...)
	sort.Slice(window, func(i, j int) bool { return window[i] < window[j] })
	return window[(len(window)-1)/2], true, nil
}

type daCommitSet struct {
	tx         *Tx
	chunkCount uint16
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

	if len(commits) > MAX_DA_BATCHES_PER_BLOCK {
		return txerr(BLOCK_ERR_DA_BATCH_EXCEEDED, "too many DA commits in block")
	}

	for daID := range chunks {
		if _, exists := commits[daID]; !exists {
			return txerr(BLOCK_ERR_DA_SET_INVALID, "DA chunks without DA commit")
		}
	}

	for daID, commit := range commits {
		set := chunks[daID]
		if set == nil {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "DA commit without chunks")
		}
		if len(set) != int(commit.chunkCount) {
			return txerr(BLOCK_ERR_DA_INCOMPLETE, "DA chunk count mismatch")
		}

		var concat []byte
		for i := uint16(0); i < commit.chunkCount; i++ {
			chunkTx, exists := set[i]
			if !exists {
				return txerr(BLOCK_ERR_DA_INCOMPLETE, "missing DA chunk index")
			}
			concat = append(concat, chunkTx.DaPayload...)
		}
		payloadCommitment := sha3_256(concat)
		if payloadCommitment != commit.tx.DaCommitCore.PayloadCommitment {
			return txerr(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID, "payload commitment mismatch")
		}
	}

	return nil
}

func txWeightAndStats(tx *Tx) (uint64, uint64, uint64, error) {
	if tx == nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "nil tx")
	}

	var err error
	var baseSize uint64
	baseSize = 4 + 1 + 8 // version + tx_kind + tx_nonce
	baseSize, err = addU64(baseSize, compactSizeLen(uint64(len(tx.Inputs))))
	if err != nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "tx base size overflow")
	}
	for _, in := range tx.Inputs {
		var err error
		baseSize, err = addU64(baseSize, 32+4) // prevout
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
		baseSize, err = addU64(baseSize, 4) // sequence
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
		var err error
		baseSize, err = addU64(baseSize, 8+2) // value + covenant_type
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
	baseSize, err = addU64(baseSize, 4) // locktime
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

	var witnessSize uint64
	witnessSize = compactSizeLen(uint64(len(tx.Witness)))
	var mlCount uint64
	var slhCount uint64
	for _, w := range tx.Witness {
		var err error
		witnessSize, err = addU64(witnessSize, 1) // suite_id
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
			if len(w.Pubkey) == ML_DSA_87_PUBKEY_BYTES && len(w.Signature) == ML_DSA_87_SIG_BYTES {
				mlCount++
			}
		case SUITE_ID_SLH_DSA_SHAKE_256F:
			if len(w.Pubkey) == SLH_DSA_SHAKE_256F_PUBKEY_BYTES && len(w.Signature) > 0 && len(w.Signature) <= MAX_SLH_DSA_SIG_BYTES {
				slhCount++
			}
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
	slhCost, err := mulU64(slhCount, VERIFY_COST_SLH_DSA_SHAKE_256F)
	if err != nil {
		return 0, 0, 0, err
	}
	sigCost, err := addU64(mlCost, slhCost)
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

package consensus

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
	for _, tx := range pb.Txs {
		if err := ValidateTxCovenantsGenesis(tx); err != nil {
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

func txWeightAndStats(tx *Tx) (uint64, uint64, uint64, error) {
	if tx == nil {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "nil tx")
	}

	var baseSize uint64
	baseSize = 4 + 1 + 8 // version + tx_kind + tx_nonce
	baseSize, _ = addU64(baseSize, compactSizeLen(uint64(len(tx.Inputs))))
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
	baseSize, _ = addU64(baseSize, compactSizeLen(uint64(len(tx.Outputs))))
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
		if out.CovenantType == COV_TYPE_ANCHOR {
			anchorBytes, err = addU64(anchorBytes, covLen)
			if err != nil {
				return 0, 0, 0, err
			}
		}
	}
	baseSize, _ = addU64(baseSize, 4) // locktime

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
			mlCount++
		case SUITE_ID_SLH_DSA_SHAKE_256F:
			slhCount++
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

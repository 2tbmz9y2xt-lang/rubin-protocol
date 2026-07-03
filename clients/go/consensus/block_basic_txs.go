package consensus

func accumulateBlockResourceStats(pb *ParsedBlock) (*blockTxStats, error) {
	stats := &blockTxStats{}
	for _, tx := range pb.Txs {
		w, da, anchorBytes, err := txWeightAndStats(tx)
		if err != nil {
			return nil, err
		}
		stats.sumWeight, err = addBlockResourceStat(stats.sumWeight, w, "sum_weight overflow")
		if err != nil {
			return nil, err
		}
		stats.sumDa, err = addBlockResourceStat(stats.sumDa, da, "sum_da overflow")
		if err != nil {
			return nil, err
		}
		stats.sumAnchor, err = addBlockResourceStat(stats.sumAnchor, anchorBytes, "sum_anchor overflow")
		if err != nil {
			return nil, err
		}
	}
	return stats, nil
}

func addBlockResourceStat(a uint64, b uint64, msg string) (uint64, error) {
	sum, err := addU64(a, b)
	if err != nil {
		return 0, txerr(TX_ERR_PARSE, msg)
	}
	return sum, nil
}

func validateBlockTxSemantics(pb *ParsedBlock, blockHeight uint64, rotation RotationProvider) error {
	if err := validateCoinbaseStructure(pb, blockHeight); err != nil {
		return err
	}
	seenNonces := make(map[uint64]struct{}, len(pb.Txs))
	for i, tx := range pb.Txs {
		if i > 0 {
			if err := validateNonCoinbaseBlockTx(tx, seenNonces); err != nil {
				return err
			}
		}
		// Block-body validation carries no SimplicityDeploymentProvider, so no
		// CORE_SIMPLICITY deployment activates and chain_id is unused here (the live
		// apply path passes the real one).
		if err := ValidateTxCovenantsGenesis(tx, [32]byte{}, blockHeight, rotation); err != nil {
			return err
		}
	}
	return nil
}

func validateNonCoinbaseBlockTx(tx *Tx, seenNonces map[uint64]struct{}) error {
	if isCoinbaseTx(tx) {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase-like tx is only allowed at index 0")
	}
	if len(tx.Inputs) == 0 {
		return txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}
	if _, exists := seenNonces[tx.TxNonce]; exists {
		return txerr(TX_ERR_NONCE_REPLAY, "duplicate tx_nonce in block")
	}
	seenNonces[tx.TxNonce] = struct{}{}
	return nil
}

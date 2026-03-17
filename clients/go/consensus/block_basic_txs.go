package consensus

func accumulateBlockResourceStats(pb *ParsedBlock) (*blockTxStats, error) {
	stats := &blockTxStats{}
	for _, tx := range pb.Txs {
		w, da, anchorBytes, err := txWeightAndStats(tx)
		if err != nil {
			return nil, err
		}
		stats.sumWeight, err = addU64(stats.sumWeight, w)
		if err != nil {
			return nil, err
		}
		stats.sumDa, err = addU64(stats.sumDa, da)
		if err != nil {
			return nil, err
		}
		stats.sumAnchor, err = addU64(stats.sumAnchor, anchorBytes)
		if err != nil {
			return nil, err
		}
	}
	return stats, nil
}

func validateBlockTxSemantics(pb *ParsedBlock, blockHeight uint64) error {
	if err := validateCoinbaseStructure(pb, blockHeight); err != nil {
		return err
	}
	seenNonces := make(map[uint64]struct{}, len(pb.Txs))
	for i, tx := range pb.Txs {
		if i > 0 && isCoinbaseTx(tx) {
			return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase-like tx is only allowed at index 0")
		}
		if i > 0 && len(tx.Inputs) == 0 {
			return txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
		}
		if i > 0 {
			if _, exists := seenNonces[tx.TxNonce]; exists {
				return txerr(TX_ERR_NONCE_REPLAY, "duplicate tx_nonce in block")
			}
			seenNonces[tx.TxNonce] = struct{}{}
		}
		if err := ValidateTxCovenantsGenesis(tx, blockHeight, nil); err != nil {
			return err
		}
	}
	return nil
}

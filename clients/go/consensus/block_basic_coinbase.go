package consensus

import (
	"bytes"
	"math/big"
)

func validateCoinbaseStructure(pb *ParsedBlock, blockHeight uint64) error {
	if len(pb.Txs) == 0 || !isCoinbaseTx(pb.Txs[0]) {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "first tx must be canonical coinbase")
	}
	if len(pb.Txs[0].Outputs) == 0 {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase must have at least one output")
	}
	if blockHeight > uint64(^uint32(0)) {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "block height exceeds coinbase locktime range")
	}
	if pb.Txs[0].Locktime != uint32(blockHeight) {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase locktime must equal block height")
	}
	return nil
}

// validateCoinbaseValueBound enforces CANONICAL §19.2: the coinbase output
// total must not exceed block_subsidy(h)+sum_fees. The bound is computed in
// checked u128 from the exact u128 sum_fees, so the exact bound is accepted
// and only bound+1 yields BLOCK_ERR_SUBSIDY_EXCEEDED.
func validateCoinbaseValueBound(pb *ParsedBlock, blockHeight uint64, alreadyGenerated *big.Int, sumFees Uint128) error {
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

	sumCoinbase, err := sumCoinbaseOutputValues(coinbase.Outputs)
	if err != nil {
		return err
	}
	subsidy := BlockSubsidyBig(blockHeight, alreadyGenerated)
	limit, ok := Uint128FromU64(subsidy).CheckedAdd(sumFees)
	if !ok {
		return txerr(BLOCK_ERR_PARSE, "u128 overflow")
	}
	if cmpU128(sumCoinbase, uint128ToInternal(limit)) > 0 {
		return txerr(BLOCK_ERR_SUBSIDY_EXCEEDED, "coinbase outputs exceed subsidy+fees bound")
	}
	return nil
}

func sumCoinbaseOutputValues(outputs []TxOutput) (u128, error) {
	var total u128
	for _, out := range outputs {
		next, err := addU64ToU128Block(total, out.Value)
		if err != nil {
			return u128{}, err
		}
		total = next
	}
	return total, nil
}

func validateCoinbaseApplyOutputs(coinbase *Tx) error {
	if coinbase == nil {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "nil coinbase")
	}
	for _, out := range coinbase.Outputs {
		if err := validateCoinbaseApplyOutput(out); err != nil {
			return err
		}
	}
	return nil
}

func validateCoinbaseApplyOutput(out TxOutput) error {
	if out.CovenantType == COV_TYPE_VAULT {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase must not create CORE_VAULT outputs")
	}
	return nil
}

func addU64ToU128Block(x u128, v uint64) (u128, error) {
	return addU64ToU128WithCode(x, v, BLOCK_ERR_PARSE)
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

	matches := countWitnessCommitmentMatches(pb.Txs[0].Outputs, expected)
	if matches != 1 {
		return txerr(BLOCK_ERR_WITNESS_COMMITMENT, "coinbase witness commitment missing or duplicated")
	}
	return nil
}

func countWitnessCommitmentMatches(outputs []TxOutput, expected [32]byte) int {
	matches := 0
	for _, out := range outputs {
		if out.CovenantType != COV_TYPE_ANCHOR || len(out.CovenantData) != 32 {
			continue
		}
		if bytes.Equal(out.CovenantData, expected[:]) {
			matches++
		}
	}
	return matches
}

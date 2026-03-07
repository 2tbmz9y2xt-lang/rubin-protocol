package consensus

import (
	"bytes"
	"math/big"
	"math/bits"
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

func validateCoinbaseValueBound(pb *ParsedBlock, blockHeight uint64, alreadyGenerated *big.Int, sumFees uint64) error {
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
	subsidy := BlockSubsidyBig(blockHeight, alreadyGenerated)
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

func validateCoinbaseApplyOutputs(coinbase *Tx) error {
	if coinbase == nil {
		return txerr(BLOCK_ERR_COINBASE_INVALID, "nil coinbase")
	}
	for _, out := range coinbase.Outputs {
		if out.CovenantType == COV_TYPE_VAULT {
			return txerr(BLOCK_ERR_COINBASE_INVALID, "coinbase must not create CORE_VAULT outputs")
		}
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

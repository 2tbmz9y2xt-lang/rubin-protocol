package node

import (
	"errors"
	"math"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func canonicalTxWeight(raw []byte, label string) (uint64, error) {
	tx, _, _, err := parseCanonicalTx(raw, label+" serialization is non-canonical")
	if err != nil {
		return 0, err
	}
	txWeight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		return 0, err
	}
	return txWeight, nil
}

func parseCanonicalTx(raw []byte, nonCanonicalMsg string) (*consensus.Tx, [32]byte, [32]byte, error) {
	tx, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil {
		return nil, [32]byte{}, [32]byte{}, err
	}
	if consumed != len(raw) {
		return nil, [32]byte{}, [32]byte{}, errors.New(nonCanonicalMsg)
	}
	return tx, txid, wtxid, nil
}

func (m *Miner) prevTimestamps(nextHeight uint64) ([]uint64, error) {
	return prevTimestampsFromStore(m.blockStore, nextHeight)
}

func chooseValidTimestamp(nextHeight uint64, prevTimestamps []uint64, now uint64) uint64 {
	if nextHeight == 0 || len(prevTimestamps) == 0 {
		if now == 0 {
			return 1
		}
		return now
	}
	median := mtpMedian(nextHeight, prevTimestamps)
	if now > median && now <= median+consensus.MAX_FUTURE_DRIFT {
		return now
	}
	return median + 1
}

func mtpMedian(nextHeight uint64, prevTimestamps []uint64) uint64 {
	k := uint64(11)
	if nextHeight < k {
		k = nextHeight
	}
	if uint64(len(prevTimestamps)) < k {
		if len(prevTimestamps) == 0 {
			return 0
		}
		k = uint64(len(prevTimestamps))
	}
	window := append([]uint64(nil), prevTimestamps[:int(k)]...)
	sort.Slice(window, func(i, j int) bool { return window[i] < window[j] })
	return window[(len(window)-1)/2]
}

func makeHeaderPrefix(prevHash [32]byte, merkleRoot [32]byte, timestamp uint64, target [32]byte) []byte {
	header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
	header = consensus.AppendU32le(header, 1)
	header = append(header, prevHash[:]...)
	header = append(header, merkleRoot[:]...)
	header = consensus.AppendU64le(header, timestamp)
	header = append(header, target[:]...)
	return header
}

func buildCoinbaseTx(height uint64, alreadyGenerated uint64, mineAddress []byte, witnessCommitment [32]byte) ([]byte, error) {
	if height > math.MaxUint32 {
		return nil, errors.New("block height exceeds coinbase locktime range")
	}
	subsidy := consensus.BlockSubsidy(height, alreadyGenerated)
	if subsidy > 0 {
		if err := validateMineAddress(mineAddress); err != nil {
			return nil, err
		}
	}

	tx := make([]byte, 0, 256+len(mineAddress))
	tx = consensus.AppendU32le(tx, 1)
	tx = append(tx, 0x00) // tx_kind
	tx = consensus.AppendU64le(tx, 0)

	tx = consensus.AppendCompactSize(tx, 1)    // input_count
	tx = append(tx, make([]byte, 32)...)       // prev_txid
	tx = consensus.AppendU32le(tx, ^uint32(0)) // prev_vout
	tx = consensus.AppendCompactSize(tx, 0)    // script_sig_len
	tx = consensus.AppendU32le(tx, ^uint32(0)) // sequence
	outputCount := uint64(1)
	if subsidy > 0 {
		outputCount++
	}
	tx = consensus.AppendCompactSize(tx, outputCount) // output_count
	if subsidy > 0 {
		tx = consensus.AppendU64le(tx, subsidy)
		tx = consensus.AppendU16le(tx, consensus.COV_TYPE_P2PK)
		tx = consensus.AppendCompactSize(tx, uint64(len(mineAddress)))
		tx = append(tx, mineAddress...)
	}
	tx = consensus.AppendU64le(tx, 0)                         // output value
	tx = consensus.AppendU16le(tx, consensus.COV_TYPE_ANCHOR) // covenant_type
	tx = consensus.AppendCompactSize(tx, 32)                  // covenant_data_len
	tx = append(tx, witnessCommitment[:]...)
	tx = consensus.AppendU32le(tx, uint32(height)) // locktime == block height
	tx = consensus.AppendCompactSize(tx, 0)        // witness_count
	tx = consensus.AppendCompactSize(tx, 0)        // da_payload_len
	return tx, nil
}

func unixNowU64() uint64 {
	now := unixNow()
	if now <= 0 {
		return 0
	}
	return uint64(now)
}

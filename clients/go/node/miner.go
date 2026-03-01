package node

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var unixNow = func() int64 { return time.Now().Unix() }

type MinerConfig struct {
	TimestampSource func() uint64
	MaxTxPerBlock   int
	Target          [32]byte

	// PolicyRejectCoreExtPreActivation controls non-consensus guardrails for CORE_EXT (COV_TYPE_CORE_EXT).
	// When enabled, the miner will exclude transactions that create or spend CORE_EXT outputs
	// whose profile(ext_id, height) is not ACTIVE. This is a safety policy to avoid pre-activation
	// anyone-can-spend risk; consensus validity is unaffected.
	//
	// If CoreExtProfiles is nil, all CORE_EXT profiles are treated as not ACTIVE.
	PolicyRejectCoreExtPreActivation bool

	// CoreExtProfiles is the chain-config profile mapping used by policy checks.
	// Consensus uses a canonical source for profile(ext_id, height); this is policy-only.
	CoreExtProfiles consensus.CoreExtProfileProvider
}

type MinedBlock struct {
	Height    uint64
	Hash      [32]byte
	Timestamp uint64
	Nonce     uint64
	TxCount   int
}

type Miner struct {
	chainState *ChainState
	blockStore *BlockStore
	sync       *SyncEngine
	cfg        MinerConfig
}

func DefaultMinerConfig() MinerConfig {
	return MinerConfig{
		Target: consensus.POW_LIMIT,
		TimestampSource: func() uint64 {
			return unixNowU64()
		},
		MaxTxPerBlock:                    1024,
		PolicyRejectCoreExtPreActivation: true,
	}
}

func NewMiner(chainState *ChainState, blockStore *BlockStore, sync *SyncEngine, cfg MinerConfig) (*Miner, error) {
	if chainState == nil {
		return nil, errors.New("nil chainstate")
	}
	if blockStore == nil {
		return nil, errors.New("nil blockstore")
	}
	if sync == nil {
		return nil, errors.New("nil sync engine")
	}
	if cfg.TimestampSource == nil {
		cfg.TimestampSource = func() uint64 { return unixNowU64() }
	}
	if cfg.MaxTxPerBlock <= 0 {
		cfg.MaxTxPerBlock = 1024
	}
	return &Miner{
		chainState: chainState,
		blockStore: blockStore,
		sync:       sync,
		cfg:        cfg,
	}, nil
}

func (m *Miner) MineN(ctx context.Context, blocks int, txs [][]byte) ([]MinedBlock, error) {
	if blocks < 0 {
		return nil, errors.New("blocks must be >= 0")
	}
	out := make([]MinedBlock, 0, blocks)
	for i := 0; i < blocks; i++ {
		mb, err := m.MineOne(ctx, txs)
		if err != nil {
			return nil, err
		}
		out = append(out, *mb)
	}
	return out, nil
}

func (m *Miner) MineOne(ctx context.Context, txs [][]byte) (*MinedBlock, error) {
	if m == nil || m.chainState == nil || m.blockStore == nil || m.sync == nil {
		return nil, errors.New("miner is not initialized")
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	nextHeight, expectedPrev, err := nextBlockContext(m.chainState)
	if err != nil {
		return nil, err
	}
	var prevHash [32]byte
	if expectedPrev != nil {
		prevHash = *expectedPrev
	}

	maxTx := len(txs)
	if maxTx > m.cfg.MaxTxPerBlock {
		maxTx = m.cfg.MaxTxPerBlock
	}
	selectedTxs := txs[:maxTx]

	type parsedTx struct {
		raw   []byte
		txid  [32]byte
		wtxid [32]byte
	}
	parsed := make([]parsedTx, 0, len(selectedTxs))
	for _, raw := range selectedTxs {
		tx, txid, wtxid, consumed, parseErr := consensus.ParseTx(raw)
		if parseErr != nil {
			return nil, parseErr
		}
		if consumed != len(raw) {
			return nil, errors.New("non-canonical tx bytes in miner input")
		}
		if m.cfg.PolicyRejectCoreExtPreActivation {
			reject, _, err := RejectCoreExtTxPreActivation(tx, m.chainState.Utxos, nextHeight, m.cfg.CoreExtProfiles)
			if err != nil || reject {
				continue
			}
		}
		parsed = append(parsed, parsedTx{
			raw:   append([]byte(nil), raw...),
			txid:  txid,
			wtxid: wtxid,
		})
	}

	wtxids := make([][32]byte, 1, 1+len(parsed))
	for _, p := range parsed {
		wtxids = append(wtxids, p.wtxid)
	}
	witnessRoot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		return nil, err
	}
	witnessCommitment := consensus.WitnessCommitmentHash(witnessRoot)

	coinbase, err := buildCoinbaseTx(nextHeight, witnessCommitment)
	if err != nil {
		return nil, err
	}
	_, coinbaseTxid, _, consumed, err := consensus.ParseTx(coinbase)
	if err != nil {
		return nil, err
	}
	if consumed != len(coinbase) {
		return nil, errors.New("coinbase serialization is non-canonical")
	}

	txids := make([][32]byte, 0, 1+len(parsed))
	txids = append(txids, coinbaseTxid)
	for _, p := range parsed {
		txids = append(txids, p.txid)
	}
	merkleRoot, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		return nil, err
	}

	prevTimestamps, err := m.prevTimestamps(nextHeight)
	if err != nil {
		return nil, err
	}
	now := m.cfg.TimestampSource()
	timestamp := chooseValidTimestamp(nextHeight, prevTimestamps, now)

	blockWithoutNonce := makeHeaderPrefix(prevHash, merkleRoot, timestamp, m.cfg.Target)
	var nonce uint64
	var headerBytes []byte
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}
		headerBytes = consensus.AppendU64le(append([]byte(nil), blockWithoutNonce...), nonce)
		if err := consensus.PowCheck(headerBytes, m.cfg.Target); err == nil {
			break
		}
		nonce++
	}

	blockBytes := make([]byte, 0, len(headerBytes)+4+len(coinbase))
	blockBytes = append(blockBytes, headerBytes...)
	blockBytes = consensus.AppendCompactSize(blockBytes, uint64(1+len(parsed)))
	blockBytes = append(blockBytes, coinbase...)
	for _, p := range parsed {
		blockBytes = append(blockBytes, p.raw...)
	}

	summary, err := m.sync.ApplyBlock(blockBytes, prevTimestamps)
	if err != nil {
		return nil, err
	}
	return &MinedBlock{
		Height:    summary.BlockHeight,
		Hash:      summary.BlockHash,
		Timestamp: timestamp,
		Nonce:     nonce,
		TxCount:   1 + len(parsed),
	}, nil
}

func (m *Miner) prevTimestamps(nextHeight uint64) ([]uint64, error) {
	if nextHeight == 0 {
		return nil, nil
	}
	k := uint64(11)
	if nextHeight < k {
		k = nextHeight
	}
	out := make([]uint64, 0, k)
	for i := uint64(0); i < k; i++ {
		h := nextHeight - 1 - i
		hash, ok, err := m.blockStore.CanonicalHash(h)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("missing canonical header for timestamp context")
		}
		headerBytes, err := m.blockStore.GetHeaderByHash(hash)
		if err != nil {
			return nil, err
		}
		header, err := consensus.ParseBlockHeaderBytes(headerBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, header.Timestamp)
	}
	return out, nil
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

func buildCoinbaseTx(height uint64, witnessCommitment [32]byte) ([]byte, error) {
	if height > math.MaxUint32 {
		return nil, errors.New("block height exceeds coinbase locktime range")
	}
	tx := make([]byte, 0, 196)
	tx = consensus.AppendU32le(tx, 1)
	tx = append(tx, 0x00) // tx_kind
	tx = consensus.AppendU64le(tx, 0)

	tx = consensus.AppendCompactSize(tx, 1)                   // input_count
	tx = append(tx, make([]byte, 32)...)                      // prev_txid
	tx = consensus.AppendU32le(tx, ^uint32(0))                // prev_vout
	tx = consensus.AppendCompactSize(tx, 0)                   // script_sig_len
	tx = consensus.AppendU32le(tx, ^uint32(0))                // sequence
	tx = consensus.AppendCompactSize(tx, 1)                   // output_count
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

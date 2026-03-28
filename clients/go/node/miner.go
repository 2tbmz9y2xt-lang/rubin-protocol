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
	// MineAddress is canonical CORE_P2PK covenant_data (suite_id || key_id)
	// used for the subsidy-bearing coinbase output.
	MineAddress []byte

	// PolicyDaAnchorAntiAbuse enables non-consensus miner policy hardening for DA/anchor abuse mitigation.
	// Consensus validity rules are unchanged; this only affects which transactions the miner includes.
	PolicyDaAnchorAntiAbuse bool

	// PolicyRejectNonCoinbaseAnchorOutputs rejects transactions that create CORE_ANCHOR outputs.
	// (Non-coinbase CORE_ANCHOR is treated as non-standard by policy.)
	PolicyRejectNonCoinbaseAnchorOutputs bool

	// PolicyMaxDaBytesPerBlock caps total DA payload bytes included in a block template (policy-only).
	// This is independent from the consensus DA byte cap.
	PolicyMaxDaBytesPerBlock uint64

	// PolicyDaSurchargePerByte enforces a minimum fee for DA-bearing transactions:
	//   fee(tx) MUST be >= da_bytes(tx) * PolicyDaSurchargePerByte
	// where da_bytes(tx) is the canonical DA payload length counted by consensus weight accounting.
	// Set to 0 to disable the fee surcharge check.
	PolicyDaSurchargePerByte uint64

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

type minedCandidate struct {
	raw    []byte
	txid   [32]byte
	wtxid  [32]byte
	weight uint64
}

type miningBuildContext struct {
	prevHash         [32]byte
	remainingWeight  uint64
	nextHeight       uint64
	alreadyGenerated uint64
	utxos            map[consensus.Outpoint]consensus.UtxoEntry
	candidateTxs     [][]byte
}

func DefaultMinerConfig() MinerConfig {
	return MinerConfig{
		Target: consensus.POW_LIMIT,
		TimestampSource: func() uint64 {
			return unixNowU64()
		},
		MineAddress:                          defaultMineAddress(),
		MaxTxPerBlock:                        1024,
		PolicyDaAnchorAntiAbuse:              true,
		PolicyRejectNonCoinbaseAnchorOutputs: true,
		PolicyMaxDaBytesPerBlock:             consensus.MAX_DA_BYTES_PER_BLOCK / 4, // 25% policy budget (issue #353 draft)
		PolicyDaSurchargePerByte:             0,                                    // controller-tunable; disabled by default
		PolicyRejectCoreExtPreActivation:     true,
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
	mineAddress, err := normalizeMineAddress(cfg.MineAddress)
	if err != nil {
		return nil, err
	}
	cfg.MineAddress = mineAddress
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

	blockBytes, prevTimestamps, timestamp, nonce, txCount, err := m.buildBlock(ctx, txs)
	if err != nil {
		return nil, err
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
		TxCount:   txCount,
	}, nil
}

func (m *Miner) buildBlock(ctx context.Context, txs [][]byte) ([]byte, []uint64, uint64, uint64, int, error) {
	buildCtx, err := m.buildContext(txs)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}

	parsed, err := m.selectCandidateTransactions(buildCtx.candidateTxs, buildCtx.utxos, buildCtx.nextHeight, buildCtx.remainingWeight)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	witnessCommitment, err := buildWitnessCommitment(parsed)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	coinbase, merkleRoot, err := m.buildCoinbaseAndMerkleRoot(buildCtx.nextHeight, buildCtx.alreadyGenerated, witnessCommitment, parsed)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	prevTimestamps, timestamp, headerBytes, nonce, err := m.mineHeader(ctx, buildCtx.nextHeight, buildCtx.prevHash, merkleRoot)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	blockBytes := assembleBlockBytes(headerBytes, coinbase, parsed)
	return blockBytes, prevTimestamps, timestamp, nonce, 1 + len(parsed), nil
}

func (m *Miner) buildContext(txs [][]byte) (miningBuildContext, error) {
	state := cloneChainState(m.chainState)
	if state == nil {
		return miningBuildContext{}, errors.New("nil chainstate")
	}
	nextHeight, expectedPrev, err := nextBlockContext(state)
	if err != nil {
		return miningBuildContext{}, err
	}
	var prevHash [32]byte
	if expectedPrev != nil {
		prevHash = *expectedPrev
	}
	remainingWeight, err := m.remainingWeightBudget(nextHeight, state.AlreadyGenerated)
	if err != nil {
		return miningBuildContext{}, err
	}
	return miningBuildContext{
		nextHeight:       nextHeight,
		prevHash:         prevHash,
		remainingWeight:  remainingWeight,
		alreadyGenerated: state.AlreadyGenerated,
		utxos:            state.Utxos,
		candidateTxs:     m.candidateTransactions(txs),
	}, nil
}

func (m *Miner) candidateTransactions(txs [][]byte) [][]byte {
	candidateTxs := txs
	maxSelected := m.cfg.MaxTxPerBlock - 1
	if maxSelected < 0 {
		maxSelected = 0
	}
	if len(candidateTxs) == 0 && m.sync != nil && m.sync.mempool != nil && maxSelected > 0 {
		candidateTxs = m.sync.mempool.SelectTransactions(maxSelected, int(consensus.MAX_BLOCK_WEIGHT))
	}
	if maxSelected >= 0 && len(candidateTxs) > maxSelected {
		candidateTxs = candidateTxs[:maxSelected]
	}
	return candidateTxs
}

func (m *Miner) remainingWeightBudget(nextHeight uint64, alreadyGenerated uint64) (uint64, error) {
	coinbaseTemplate, err := buildCoinbaseTx(nextHeight, alreadyGenerated, m.cfg.MineAddress, [32]byte{})
	if err != nil {
		return 0, err
	}
	coinbaseWeight, err := canonicalTxWeight(coinbaseTemplate, "coinbase")
	if err != nil {
		return 0, err
	}
	return consensus.MAX_BLOCK_WEIGHT - coinbaseWeight, nil
}

func (m *Miner) selectCandidateTransactions(candidateTxs [][]byte, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64, remainingWeight uint64) ([]minedCandidate, error) {
	parsed := make([]minedCandidate, 0, len(candidateTxs))
	var selectedWeight uint64
	var policyDaIncluded uint64
	for _, raw := range candidateTxs {
		candidate, err := m.parseMiningCandidate(raw)
		if err != nil {
			return nil, err
		}
		reject, nextDaIncluded, err := m.rejectCandidate(candidate.tx, utxos, nextHeight, policyDaIncluded)
		if err != nil {
			// Policy checks should never abort block construction.
			// Treat policy evaluation errors as a rejected candidate and continue.
			continue
		}
		if reject {
			continue
		}
		if candidate.minedCandidate.weight > remainingWeight-selectedWeight {
			continue
		}
		selectedWeight += candidate.minedCandidate.weight
		policyDaIncluded = nextDaIncluded
		parsed = append(parsed, candidate.minedCandidate)
	}
	return parsed, nil
}

type miningCandidate struct {
	tx             *consensus.Tx
	minedCandidate minedCandidate
}

func (m *Miner) parseMiningCandidate(raw []byte) (miningCandidate, error) {
	tx, txid, wtxid, err := parseCanonicalTx(raw, "non-canonical tx bytes in miner input")
	if err != nil {
		return miningCandidate{}, err
	}
	txWeight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		return miningCandidate{}, err
	}
	return miningCandidate{
		tx: tx,
		minedCandidate: minedCandidate{
			raw:    append([]byte(nil), raw...),
			txid:   txid,
			wtxid:  wtxid,
			weight: txWeight,
		},
	}, nil
}

func (m *Miner) rejectCandidate(tx *consensus.Tx, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64, policyDaIncluded uint64) (bool, uint64, error) {
	if m.cfg.PolicyDaAnchorAntiAbuse {
		reject, daBytes, _, err := RejectDaAnchorTxPolicy(tx, utxos, m.cfg.PolicyDaSurchargePerByte)
		if err != nil {
			return false, policyDaIncluded, err
		}
		if reject {
			return true, policyDaIncluded, nil
		}
		nextDaIncluded, ok := updatedPolicyDaBytes(policyDaIncluded, daBytes, m.cfg.PolicyMaxDaBytesPerBlock)
		if !ok {
			return true, policyDaIncluded, nil
		}
		policyDaIncluded = nextDaIncluded
		if m.cfg.PolicyRejectNonCoinbaseAnchorOutputs {
			reject, _, err := RejectNonCoinbaseAnchorOutputs(tx)
			if err != nil {
				return false, policyDaIncluded, err
			}
			if reject {
				return true, policyDaIncluded, nil
			}
		}
	}
	if m.cfg.PolicyRejectCoreExtPreActivation {
		reject, _, err := RejectCoreExtTxPreActivation(tx, utxos, nextHeight, m.cfg.CoreExtProfiles)
		if err != nil {
			return false, policyDaIncluded, err
		}
		if reject {
			return true, policyDaIncluded, nil
		}
	}
	return false, policyDaIncluded, nil
}

func updatedPolicyDaBytes(current uint64, daBytes uint64, maxPerBlock uint64) (uint64, bool) {
	if daBytes == 0 || maxPerBlock == 0 {
		return current, true
	}
	next := current + daBytes
	if next < current || next > maxPerBlock {
		return current, false
	}
	return next, true
}

func buildWitnessCommitment(parsed []minedCandidate) ([32]byte, error) {
	wtxids := make([][32]byte, 1, 1+len(parsed))
	for _, p := range parsed {
		wtxids = append(wtxids, p.wtxid)
	}
	witnessRoot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		return [32]byte{}, err
	}
	return consensus.WitnessCommitmentHash(witnessRoot), nil
}

func (m *Miner) buildCoinbaseAndMerkleRoot(nextHeight uint64, alreadyGenerated uint64, witnessCommitment [32]byte, parsed []minedCandidate) ([]byte, [32]byte, error) {
	coinbase, err := buildCoinbaseTx(nextHeight, alreadyGenerated, m.cfg.MineAddress, witnessCommitment)
	if err != nil {
		return nil, [32]byte{}, err
	}
	_, coinbaseTxid, _, err := parseCanonicalTx(coinbase, "coinbase serialization is non-canonical")
	if err != nil {
		return nil, [32]byte{}, err
	}
	txids := make([][32]byte, 0, 1+len(parsed))
	txids = append(txids, coinbaseTxid)
	for _, p := range parsed {
		txids = append(txids, p.txid)
	}
	merkleRoot, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return coinbase, merkleRoot, nil
}

func (m *Miner) mineHeader(ctx context.Context, nextHeight uint64, prevHash [32]byte, merkleRoot [32]byte) ([]uint64, uint64, []byte, uint64, error) {
	prevTimestamps, err := m.prevTimestamps(nextHeight)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	now := m.cfg.TimestampSource()
	timestamp := chooseValidTimestamp(nextHeight, prevTimestamps, now)
	blockWithoutNonce := makeHeaderPrefix(prevHash, merkleRoot, timestamp, m.cfg.Target)
	headerBytes, nonce, err := mineHeaderNonce(ctx, blockWithoutNonce, m.cfg.Target)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	return prevTimestamps, timestamp, headerBytes, nonce, nil
}

func assembleBlockBytes(headerBytes []byte, coinbase []byte, parsed []minedCandidate) []byte {
	blockBytes := make([]byte, 0, len(headerBytes)+4+len(coinbase))
	blockBytes = append(blockBytes, headerBytes...)
	blockBytes = consensus.AppendCompactSize(blockBytes, uint64(1+len(parsed)))
	blockBytes = append(blockBytes, coinbase...)
	for _, p := range parsed {
		blockBytes = append(blockBytes, p.raw...)
	}
	return blockBytes
}

func mineHeaderNonce(ctx context.Context, blockWithoutNonce []byte, target [32]byte) ([]byte, uint64, error) {
	var nonce uint64
	for {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			default:
			}
		}
		headerBytes := consensus.AppendU64le(append([]byte(nil), blockWithoutNonce...), nonce)
		if err := consensus.PowCheck(headerBytes, target); err == nil {
			return headerBytes, nonce, nil
		}
		nonce++
	}
}

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

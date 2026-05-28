package node

import (
	"context"
	"errors"
	"math"
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

	// PolicyDaAnchorAntiAbuse is the master switch for the whole DA/anchor
	// anti-abuse miner-template policy package. When false,
	// PolicyRejectNonCoinbaseAnchorOutputs is ignored. This is policy-only
	// and does not change consensus validity.
	PolicyDaAnchorAntiAbuse bool

	// PolicyRejectNonCoinbaseAnchorOutputs rejects transactions that create
	// CORE_ANCHOR outputs when PolicyDaAnchorAntiAbuse is enabled.
	// (Non-coinbase CORE_ANCHOR is treated as non-standard by policy.)
	PolicyRejectNonCoinbaseAnchorOutputs bool

	// PolicyMaxDaBytesPerBlock caps total DA payload bytes included in a block template (policy-only).
	// This is independent from the consensus DA byte cap.
	PolicyMaxDaBytesPerBlock uint64

	// PolicyDaSurchargePerByte is the operator-tunable DA per-byte surcharge
	// added on top of the spec-side DA floor in
	// POLICY_MEMPOOL_ADMISSION_GENESIS.md Stage C:
	//   da_required_fee(tx) = da_payload_len(tx) * (MinDaFeeRate + PolicyDaSurchargePerByte)
	// Setting it to 0 disables only the surcharge term, not the DA floor;
	// the DA floor still uses MinDaFeeRate.
	PolicyDaSurchargePerByte uint64

	// MinDaFeeRate is the spec-side per-byte DA fee floor
	// (POLICY_MEMPOOL_ADMISSION_GENESIS.md Stage C `min_da_fee_rate`,
	// default 1). Together with PolicyDaSurchargePerByte it composes the
	// DA half of the Stage C admission contract:
	//   da_required_fee(tx) = da_payload_len(tx) * (MinDaFeeRate + PolicyDaSurchargePerByte)
	// Setting it to 0 disables only the spec floor; the surcharge term
	// still applies when PolicyDaSurchargePerByte > 0.
	MinDaFeeRate uint64

	// CurrentMempoolMinFeeRate is the static fallback for the rolling
	// local floor when CurrentMempoolMinFeeRateFn is nil. Standalone
	// miner builds with no live mempool keep this at
	// DefaultMempoolMinFeeRate (the #1336 baseline). Live nodes SHOULD
	// set CurrentMempoolMinFeeRateFn instead so the miner template
	// reflects the rolling floor as it rises and decays.
	CurrentMempoolMinFeeRate uint64

	// CurrentMempoolMinFeeRateFn returns the live rolling local floor
	// for the relay-fee half of the Stage C admission contract:
	//   relay_fee_floor(tx) = weight(tx) * <floor returned by Fn>
	// Production wiring sets this to Mempool.CurrentMinFeeRateSnapshot
	// so the miner template stays aligned with the admission predicate
	// as the rolling floor changes. When nil the miner falls back to
	// CurrentMempoolMinFeeRate above.
	CurrentMempoolMinFeeRateFn func() uint64

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

type miningChainStateSnapshot struct {
	hasTip           bool
	height           uint64
	tipHash          [32]byte
	alreadyGenerated uint64
	utxos            map[consensus.Outpoint]consensus.UtxoEntry
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
		MinDaFeeRate:                         DefaultMinDaFeeRate,                  // Stage C spec-side per-byte DA floor
		CurrentMempoolMinFeeRate:             DefaultMempoolMinFeeRate,             // baseline for the rolling floor when no live mempool is bound
		PolicyRejectCoreExtPreActivation:     true,
	}
}

func NewMiner(chainState *ChainState, blockStore *BlockStore, sync *SyncEngine, cfg MinerConfig) (*Miner, error) {
	// Validate inputs
	if err := validateNewMinerInputs(chainState, blockStore, sync); err != nil {
		return nil, err
	}

	// Validate alias requirements
	if err := validateMinerAliasRequirements(chainState, blockStore, sync); err != nil {
		return nil, err
	}

	// Normalize configuration
	if err := normalizeMinerConfig(&cfg); err != nil {
		return nil, err
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
	// Validate miner state
	if err := m.validateMineOneInput(); err != nil {
		return nil, err
	}

	// Check context cancellation
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	// Bootstrap genesis if needed
	if err := m.bootstrapGenesisIfNeeded(); err != nil {
		return nil, err
	}

	// Execute mining
	return m.executeMineOne(ctx, txs)
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
	state, err := m.snapshotBuildContextState()
	if err != nil {
		return miningBuildContext{}, err
	}
	nextHeight, expectedPrev, err := nextBlockContextFromFields(state.hasTip, state.height, state.tipHash)
	if err != nil {
		return miningBuildContext{}, err
	}
	var prevHash [32]byte
	if expectedPrev != nil {
		prevHash = *expectedPrev
	}
	remainingWeight, err := m.remainingWeightBudget(nextHeight, state.alreadyGenerated)
	if err != nil {
		return miningBuildContext{}, err
	}
	return miningBuildContext{
		nextHeight:       nextHeight,
		prevHash:         prevHash,
		remainingWeight:  remainingWeight,
		alreadyGenerated: state.alreadyGenerated,
		utxos:            state.utxos,
		candidateTxs:     m.candidateTransactions(txs),
	}, nil
}

func (m *Miner) snapshotBuildContextState() (miningChainStateSnapshot, error) {
	if m == nil || m.chainState == nil {
		return miningChainStateSnapshot{}, errors.New("nil chainstate")
	}
	state := m.chainState
	state.mu.RLock()
	defer state.mu.RUnlock()

	snapshot := miningChainStateSnapshot{
		hasTip:           state.HasTip,
		height:           state.Height,
		tipHash:          state.TipHash,
		alreadyGenerated: state.AlreadyGenerated,
	}
	if m.policyNeedsReadonlyUtxoSnapshot() {
		snapshot.utxos = copyUtxoSet(state.Utxos)
	}
	return snapshot, nil
}

func (m *Miner) candidateTransactions(txs [][]byte) [][]byte {
	maxSelected := m.maxSelectedTransactions()
	if maxSelected == 0 {
		return nil
	}
	if len(txs) != 0 {
		return pickFlatCandidateRaw(txs, maxSelected)
	}
	if m.sync == nil || m.sync.mempool == nil {
		return nil
	}
	return m.mempoolCandidateTransactions(maxSelected)
}

func (m *Miner) maxSelectedTransactions() int {
	maxSelected := m.cfg.MaxTxPerBlock - 1
	if maxSelected < 0 {
		return 0
	}
	return maxSelected
}

func (m *Miner) policyNeedsReadonlyUtxoSnapshot() bool {
	if m == nil {
		return false
	}
	if m.cfg.PolicyRejectCoreExtPreActivation {
		return true
	}
	// DA anti-abuse policy always runs RejectDaAnchorTxPolicy to account for
	// per-template DA bytes, even when the surcharge floor is disabled. Keep
	// a readonly snapshot available for that path so custom configs cannot
	// accidentally call into policy with a nil UTXO map.
	return m.cfg.PolicyDaAnchorAntiAbuse
}

func (m *Miner) remainingWeightBudget(nextHeight uint64, alreadyGenerated uint64) (uint64, error) {
	coinbaseWeight, err := canonicalCoinbaseWeight(nextHeight, alreadyGenerated, m.cfg.MineAddress)
	if err != nil {
		return 0, err
	}
	return remainingWeightFromCoinbase(coinbaseWeight)
}

func canonicalCoinbaseWeight(height uint64, alreadyGenerated uint64, mineAddress []byte) (uint64, error) {
	if height > math.MaxUint32 {
		return 0, errors.New("block height exceeds coinbase locktime range")
	}
	subsidy := consensus.BlockSubsidy(height, alreadyGenerated)
	if subsidy > 0 {
		if err := validateMineAddress(mineAddress); err != nil {
			return 0, err
		}
	}

	outputCount := uint64(1)
	strippedSize := uint64(4 + 1 + 8) // version + tx_kind + tx_nonce
	parts := []uint64{
		compactSizeLenForMiner(1),
		32 + 4 + compactSizeLenForMiner(0) + 4,
	}
	if subsidy > 0 {
		outputCount++
		addrLen := uint64(len(mineAddress))
		parts = append(parts, 8+2+compactSizeLenForMiner(addrLen)+addrLen)
	}
	parts = append(parts,
		compactSizeLenForMiner(outputCount),
		8+2+compactSizeLenForMiner(32)+32,
		4,
	)
	if err := addCoinbaseBaseSize(&strippedSize, parts...); err != nil {
		return 0, err
	}

	// Canonical coinbase carries zero witness items and no DA payload, so the
	// discounted trailer still contributes one CompactSize byte for each field.
	witnessSize := compactSizeLenForMiner(0)
	daSize := compactSizeLenForMiner(0)
	return finalizeCoinbaseWeight(strippedSize, witnessSize, daSize)
}

func addCoinbaseBaseSize(dst *uint64, values ...uint64) error {
	for _, value := range values {
		if err := addU64NoOverflow(dst, value); err != nil {
			return errors.New("coinbase weight overflow")
		}
	}
	return nil
}

func finalizeCoinbaseWeight(strippedSize uint64, witnessSize uint64, daSize uint64) (uint64, error) {
	extraWeight, err := addU64NoOverflowValue(witnessSize, daSize)
	if err != nil {
		return 0, errors.New("coinbase weight overflow")
	}
	if strippedSize > (math.MaxUint64-extraWeight)/consensus.WITNESS_DISCOUNT_DIVISOR {
		return 0, errors.New("coinbase weight overflow")
	}
	return uint64(consensus.WITNESS_DISCOUNT_DIVISOR)*strippedSize + extraWeight, nil
}

func remainingWeightFromCoinbase(coinbaseWeight uint64) (uint64, error) {
	if coinbaseWeight > consensus.MAX_BLOCK_WEIGHT {
		return 0, errors.New("coinbase weight exceeds max block weight")
	}
	return consensus.MAX_BLOCK_WEIGHT - coinbaseWeight, nil
}

func addU64NoOverflowValue(left uint64, right uint64) (uint64, error) {
	if right > math.MaxUint64-left {
		return 0, errors.New("u64 overflow")
	}
	return left + right, nil
}

func compactSizeLenForMiner(n uint64) uint64 {
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

func (m *Miner) selectCandidateTransactions(candidateTxs [][]byte, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64, remainingWeight uint64) ([]minedCandidate, error) {
	maxSelected := m.maxSelectedTransactions()
	parsed := make([]minedCandidate, 0, min(len(candidateTxs), maxSelected))
	var selectedWeight uint64
	var policyDaIncluded uint64
	for _, raw := range candidateTxs {
		if len(parsed) >= maxSelected {
			break
		}
		candidate, nextDaIncluded, ok, err := m.trySelectFlatCandidate(raw, utxos, nextHeight, selectedWeight, remainingWeight, policyDaIncluded)
		if err != nil {
			return nil, err
		}
		if ok {
			selectedWeight += candidate.weight
			policyDaIncluded = nextDaIncluded
			parsed = append(parsed, candidate)
		}
	}
	return parsed, nil
}

func (m *Miner) trySelectFlatCandidate(raw []byte, utxos map[consensus.Outpoint]consensus.UtxoEntry, nextHeight uint64, selectedWeight uint64, remainingWeight uint64, policyDaIncluded uint64) (minedCandidate, uint64, bool, error) {
	candidate, err := m.parseMiningCandidate(raw)
	if err != nil {
		return minedCandidate{}, policyDaIncluded, false, err
	}
	if isMiningDATx(candidate.tx) {
		return minedCandidate{}, policyDaIncluded, false, nil
	}
	reject, nextDaIncluded, err := m.rejectCandidate(candidate.tx, utxos, nextHeight, policyDaIncluded)
	if err != nil || reject {
		return minedCandidate{}, policyDaIncluded, false, nil
	}
	if selectedWeight >= remainingWeight {
		return minedCandidate{}, policyDaIncluded, false, nil
	}
	availableWeight := remainingWeight - selectedWeight
	if candidate.minedCandidate.weight > availableWeight {
		return minedCandidate{}, policyDaIncluded, false, nil
	}
	return candidate.minedCandidate, nextDaIncluded, true, nil
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
	var reject bool
	var err error

	// PolicyDaAnchorAntiAbuse gates the full DA/anchor policy package,
	// including the non-coinbase CORE_ANCHOR sub-flag.
	if m.cfg.PolicyDaAnchorAntiAbuse {
		reject, policyDaIncluded, err = m.rejectCandidateDAPolicy(tx, utxos, policyDaIncluded)
		if err != nil {
			return false, policyDaIncluded, err
		}
		if reject {
			return true, policyDaIncluded, nil
		}

		reject, err = m.rejectCandidateAnchorPolicy(tx)
		if err != nil {
			return false, policyDaIncluded, err
		}
		if reject {
			return true, policyDaIncluded, nil
		}
	}

	// Apply CoreExt policy
	reject, err = m.rejectCandidateCoreExtPolicy(tx, utxos, nextHeight)
	if err != nil {
		return false, policyDaIncluded, err
	}
	if reject {
		return true, policyDaIncluded, nil
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

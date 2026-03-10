package devnetcv

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const (
	GateDevnetGenesis       = "CV-DEVNET-GENESIS"
	GateDevnetSubsidy       = "CV-DEVNET-SUBSIDY"
	GateDevnetChain         = "CV-DEVNET-CHAIN"
	GateDevnetMaturity      = "CV-DEVNET-MATURITY"
	GateDevnetSighashChain  = "CV-DEVNET-SIGHASH-CHAINID"
	fixedMinerTimestamp     = uint64(1)
	maturitySpendHeight     = uint64(100)
	sighashMutationLastByte = byte(0x01)
)

type FixtureDoc[T any] struct {
	Gate    string `json:"gate"`
	Vectors []T    `json:"vectors"`
}

type UtxoJSON struct {
	Txid              string `json:"txid"`
	CovenantData      string `json:"covenant_data"`
	Value             uint64 `json:"value"`
	CreationHeight    uint64 `json:"creation_height"`
	Vout              uint32 `json:"vout"`
	CovenantType      uint16 `json:"covenant_type"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

type ChainStateJSON struct {
	TipHash          string     `json:"tip_hash"`
	Utxos            []UtxoJSON `json:"utxos"`
	Height           uint64     `json:"height"`
	AlreadyGenerated uint64     `json:"already_generated"`
	Version          uint32     `json:"version"`
	HasTip           bool       `json:"has_tip"`
}

type ConnectBlockVector struct {
	ID                       string          `json:"id"`
	Op                       string          `json:"op"`
	BlockHex                 string          `json:"block_hex"`
	ChainID                  string          `json:"chain_id"`
	Height                   uint64          `json:"height"`
	AlreadyGenerated         uint64          `json:"already_generated"`
	Utxos                    []UtxoJSON      `json:"utxos"`
	PrevTimestamps           []uint64        `json:"prev_timestamps"`
	ExpectedPrevHash         string          `json:"expected_prev_hash,omitempty"`
	ExpectedTarget           string          `json:"expected_target"`
	ExpectOK                 bool            `json:"expect_ok"`
	ExpectSumFees            uint64          `json:"expect_sum_fees"`
	ExpectUtxoCount          uint64          `json:"expect_utxo_count"`
	ExpectAlreadyGenerated   uint64          `json:"expect_already_generated"`
	ExpectAlreadyGeneratedN1 uint64          `json:"expect_already_generated_n1"`
	BlockHash                string          `json:"block_hash"`
	CoinbaseTxid             string          `json:"coinbase_txid"`
	CoinbaseValue            uint64          `json:"coinbase_value"`
	ChainstateAfter          *ChainStateJSON `json:"chainstate_after,omitempty"`
	InitialUTXOSet           []UtxoJSON      `json:"initial_utxo_set,omitempty"`
}

type UtxoApplyVector struct {
	ID                string     `json:"id"`
	Op                string     `json:"op"`
	TxHex             string     `json:"tx_hex"`
	ChainID           string     `json:"chain_id"`
	Height            uint64     `json:"height"`
	BlockTimestamp    uint64     `json:"block_timestamp"`
	Utxos             []UtxoJSON `json:"utxos"`
	ExpectOK          bool       `json:"expect_ok"`
	ExpectErr         string     `json:"expect_err"`
	SourceBlockHeight uint64     `json:"source_block_height"`
	SourceBlockHash   string     `json:"source_block_hash"`
}

type SighashVector struct {
	ID           string `json:"id"`
	Op           string `json:"op"`
	TxHex        string `json:"tx_hex"`
	ChainID      string `json:"chain_id"`
	InputIndex   uint32 `json:"input_index"`
	InputValue   uint64 `json:"input_value"`
	ExpectOK     bool   `json:"expect_ok"`
	ExpectDigest string `json:"expect_digest"`
}

type Documents struct {
	Genesis      FixtureDoc[ConnectBlockVector]
	Subsidy      FixtureDoc[ConnectBlockVector]
	Chain        FixtureDoc[ConnectBlockVector]
	Maturity     FixtureDoc[UtxoApplyVector]
	SighashChain FixtureDoc[SighashVector]
}

type chainSample struct {
	Height             uint64
	BlockHex           string
	BlockHash          string
	ExpectedPrevHash   string
	PrevTimestamps     []uint64
	AlreadyGenerated   uint64
	AlreadyGeneratedN1 uint64
	CoinbaseTxid       string
	CoinbaseValue      uint64
	ChainstateBefore   ChainStateJSON
	ChainstateAfter    ChainStateJSON
	Timestamp          uint64
}

type devnetEnv struct {
	dir        string
	targetHex  string
	chainID    [32]byte
	chainIDHex string
	target     [32]byte
	chainState *node.ChainState
	blockStore *node.BlockStore
	sync       *node.SyncEngine
	miner      *node.Miner
}

func GateOrder() []string {
	return []string{
		GateDevnetGenesis,
		GateDevnetSubsidy,
		GateDevnetChain,
		GateDevnetMaturity,
		GateDevnetSighashChain,
	}
}

func Generate() (*Documents, error) {
	env, err := newDevnetEnv()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(env.dir)

	genesisVector, genesisSpend, err := env.buildGenesisVector()
	if err != nil {
		return nil, err
	}

	samples, err := env.mineChain(100)
	if err != nil {
		return nil, err
	}
	if len(samples) < 100 {
		return nil, errors.New("short devnet chain generation")
	}

	subsidyVectors := make([]ConnectBlockVector, 0, len(samples))
	chainVectors := make([]ConnectBlockVector, 0, 10)
	for _, sample := range samples {
		base := ConnectBlockVector{
			ID:                       fmt.Sprintf("DEVNET-SUBSIDY-%03d", sample.Height),
			Op:                       "connect_block_basic",
			BlockHex:                 sample.BlockHex,
			ChainID:                  env.chainIDHex,
			Height:                   sample.Height,
			AlreadyGenerated:         sample.AlreadyGenerated,
			Utxos:                    cloneUtxos(sample.ChainstateBefore.Utxos),
			PrevTimestamps:           cloneUint64s(sample.PrevTimestamps),
			ExpectedPrevHash:         sample.ExpectedPrevHash,
			ExpectedTarget:           env.targetHex,
			ExpectOK:                 true,
			ExpectSumFees:            0,
			ExpectUtxoCount:          uint64(len(sample.ChainstateAfter.Utxos)),
			ExpectAlreadyGenerated:   sample.AlreadyGenerated,
			ExpectAlreadyGeneratedN1: sample.AlreadyGeneratedN1,
			BlockHash:                sample.BlockHash,
			CoinbaseTxid:             sample.CoinbaseTxid,
			CoinbaseValue:            sample.CoinbaseValue,
		}
		subsidyVectors = append(subsidyVectors, base)

		if sample.Height <= 10 {
			base.ID = fmt.Sprintf("DEVNET-CHAIN-%02d", sample.Height)
			base.ChainstateAfter = cloneChainState(sample.ChainstateAfter)
			chainVectors = append(chainVectors, base)
		}
	}

	maturityVector, err := env.buildMaturityVector(samples[0])
	if err != nil {
		return nil, err
	}

	sighashVectors, err := env.buildSighashVectors(genesisSpend)
	if err != nil {
		return nil, err
	}
	if sighashVectors[0].ExpectDigest == sighashVectors[1].ExpectDigest {
		return nil, errors.New("devnet sighash chain_id mutation did not change digest")
	}

	return &Documents{
		Genesis: FixtureDoc[ConnectBlockVector]{
			Gate:    GateDevnetGenesis,
			Vectors: []ConnectBlockVector{genesisVector},
		},
		Subsidy: FixtureDoc[ConnectBlockVector]{
			Gate:    GateDevnetSubsidy,
			Vectors: subsidyVectors,
		},
		Chain: FixtureDoc[ConnectBlockVector]{
			Gate:    GateDevnetChain,
			Vectors: chainVectors,
		},
		Maturity: FixtureDoc[UtxoApplyVector]{
			Gate:    GateDevnetMaturity,
			Vectors: []UtxoApplyVector{maturityVector},
		},
		SighashChain: FixtureDoc[SighashVector]{
			Gate:    GateDevnetSighashChain,
			Vectors: sighashVectors,
		},
	}, nil
}

func WriteFixtures(repoRoot string) error {
	docs, err := Generate()
	if err != nil {
		return err
	}
	fixturesDir := filepath.Join(repoRoot, "conformance", "fixtures")
	if err := os.MkdirAll(fixturesDir, 0o750); err != nil {
		return err
	}
	ordered := []struct {
		gate string
		doc  any
	}{
		{GateDevnetGenesis, docs.Genesis},
		{GateDevnetSubsidy, docs.Subsidy},
		{GateDevnetChain, docs.Chain},
		{GateDevnetMaturity, docs.Maturity},
		{GateDevnetSighashChain, docs.SighashChain},
	}
	for _, item := range ordered {
		raw, err := marshalFixture(item.doc)
		if err != nil {
			return err
		}
		path := filepath.Join(fixturesDir, item.gate+".json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func marshalFixture(doc any) ([]byte, error) {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func MarshalFixtureForTest(doc any) ([]byte, error) {
	return marshalFixture(doc)
}

func newDevnetEnv() (*devnetEnv, error) {
	dir, err := os.MkdirTemp("", "rubin-devnet-cv-")
	if err != nil {
		return nil, err
	}
	target := consensus.POW_LIMIT
	chainID := node.DevnetGenesisChainID()
	chainState := node.NewChainState()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		return nil, err
	}
	chainStatePath := node.ChainStatePath(dir)
	syncCfg := node.DefaultSyncConfig(&target, chainID, chainStatePath)
	syncCfg.Network = "devnet"
	syncEngine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		return nil, err
	}
	genesisBlock := node.DevnetGenesisBlockBytes()
	if _, err := syncEngine.ApplyBlock(genesisBlock, nil); err != nil {
		return nil, err
	}

	minerCfg := node.DefaultMinerConfig()
	minerCfg.TimestampSource = func() uint64 { return fixedMinerTimestamp }
	miner, err := node.NewMiner(chainState, blockStore, syncEngine, minerCfg)
	if err != nil {
		return nil, err
	}

	return &devnetEnv{
		dir:        dir,
		targetHex:  hex.EncodeToString(target[:]),
		chainID:    chainID,
		chainIDHex: hex.EncodeToString(chainID[:]),
		target:     target,
		chainState: chainState,
		blockStore: blockStore,
		sync:       syncEngine,
		miner:      miner,
	}, nil
}

type spendableOutpoint struct {
	txid         [32]byte
	txidHex      string
	vout         uint32
	value        uint64
	covenantData []byte
}

func (e *devnetEnv) buildGenesisVector() (ConnectBlockVector, spendableOutpoint, error) {
	genesisBlock := node.DevnetGenesisBlockBytes()
	genesisState, err := snapshotChainState(e.chainState)
	if err != nil {
		return ConnectBlockVector{}, spendableOutpoint{}, err
	}
	txid, value, vout, covenantData, blockHash, err := spendableOutputFromBlock(genesisBlock)
	if err != nil {
		return ConnectBlockVector{}, spendableOutpoint{}, err
	}
	vector := ConnectBlockVector{
		ID:                       "DEVNET-GENESIS-01",
		Op:                       "connect_block_basic",
		BlockHex:                 hex.EncodeToString(genesisBlock),
		ChainID:                  e.chainIDHex,
		Height:                   0,
		AlreadyGenerated:         0,
		Utxos:                    []UtxoJSON{},
		PrevTimestamps:           []uint64{},
		ExpectedTarget:           e.targetHex,
		ExpectOK:                 true,
		ExpectSumFees:            0,
		ExpectUtxoCount:          uint64(len(genesisState.Utxos)),
		ExpectAlreadyGenerated:   0,
		ExpectAlreadyGeneratedN1: 0,
		BlockHash:                blockHash,
		CoinbaseTxid:             hex.EncodeToString(txid[:]),
		CoinbaseValue:            value,
		ChainstateAfter:          cloneChainState(genesisState),
		InitialUTXOSet:           cloneUtxos(genesisState.Utxos),
	}
	return vector, spendableOutpoint{
		txid:         txid,
		txidHex:      hex.EncodeToString(txid[:]),
		vout:         vout,
		value:        value,
		covenantData: append([]byte(nil), covenantData...),
	}, nil
}

func (e *devnetEnv) mineChain(count int) ([]chainSample, error) {
	samples := make([]chainSample, 0, count)
	for i := 0; i < count; i++ {
		beforeState, err := snapshotChainState(e.chainState)
		if err != nil {
			return nil, err
		}
		nextHeight := e.chainState.Height + 1
		prevHash := hex.EncodeToString(e.chainState.TipHash[:])
		prevTimestamps, err := collectPrevTimestamps(e.blockStore, nextHeight)
		if err != nil {
			return nil, err
		}
		alreadyGenerated := e.chainState.AlreadyGenerated

		mined, err := e.miner.MineOne(context.Background(), nil)
		if err != nil {
			return nil, err
		}
		blockBytes, err := e.blockStore.GetBlockByHash(mined.Hash)
		if err != nil {
			return nil, err
		}
		txid, value, _, _, _, err := spendableOutputFromBlock(blockBytes)
		if err != nil {
			return nil, err
		}
		afterState, err := snapshotChainState(e.chainState)
		if err != nil {
			return nil, err
		}
		samples = append(samples, chainSample{
			Height:             mined.Height,
			BlockHex:           hex.EncodeToString(blockBytes),
			BlockHash:          hex.EncodeToString(mined.Hash[:]),
			ExpectedPrevHash:   prevHash,
			PrevTimestamps:     prevTimestamps,
			AlreadyGenerated:   alreadyGenerated,
			AlreadyGeneratedN1: e.chainState.AlreadyGenerated,
			CoinbaseTxid:       hex.EncodeToString(txid[:]),
			CoinbaseValue:      value,
			ChainstateBefore:   beforeState,
			ChainstateAfter:    afterState,
			Timestamp:          mined.Timestamp,
		})
	}
	return samples, nil
}

func (e *devnetEnv) buildMaturityVector(sample chainSample) (UtxoApplyVector, error) {
	txidBytes, err := decodeHex32(sample.CoinbaseTxid)
	if err != nil {
		return UtxoApplyVector{}, err
	}
	mineAddress := append([]byte(nil), node.DefaultMinerConfig().MineAddress...)
	txHex, err := marshalSingleInputP2PKTx(txidBytes, 0, sample.CoinbaseValue, sample.CoinbaseValue, mineAddress, 1)
	if err != nil {
		return UtxoApplyVector{}, err
	}
	return UtxoApplyVector{
		ID:             "DEVNET-MATURITY-01",
		Op:             "utxo_apply_basic",
		TxHex:          txHex,
		ChainID:        e.chainIDHex,
		Height:         maturitySpendHeight,
		BlockTimestamp: sample.Timestamp,
		Utxos: []UtxoJSON{
			{
				Txid:              sample.CoinbaseTxid,
				CovenantData:      hex.EncodeToString(mineAddress),
				Value:             sample.CoinbaseValue,
				CreationHeight:    sample.Height,
				Vout:              0,
				CovenantType:      consensus.COV_TYPE_P2PK,
				CreatedByCoinbase: true,
			},
		},
		ExpectOK:          false,
		ExpectErr:         string(consensus.TX_ERR_COINBASE_IMMATURE),
		SourceBlockHeight: sample.Height,
		SourceBlockHash:   sample.BlockHash,
	}, nil
}

func (e *devnetEnv) buildSighashVectors(genesisSpend spendableOutpoint) ([]SighashVector, error) {
	txHex, err := marshalSingleInputP2PKTx(genesisSpend.txid, genesisSpend.vout, genesisSpend.value, genesisSpend.value-1, genesisSpend.covenantData, 7)
	if err != nil {
		return nil, err
	}
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, err
	}
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		return nil, err
	}
	devnetDigest, err := consensus.SighashV1Digest(tx, 0, genesisSpend.value, e.chainID)
	if err != nil {
		return nil, err
	}
	altChainID := alternateChainID(e.chainID)
	altDigest, err := consensus.SighashV1Digest(tx, 0, genesisSpend.value, altChainID)
	if err != nil {
		return nil, err
	}
	return []SighashVector{
		{
			ID:           "DEVNET-SIGHASH-CHAINID-01",
			Op:           "sighash_v1",
			TxHex:        txHex,
			ChainID:      e.chainIDHex,
			InputIndex:   0,
			InputValue:   genesisSpend.value,
			ExpectOK:     true,
			ExpectDigest: hex.EncodeToString(devnetDigest[:]),
		},
		{
			ID:           "DEVNET-SIGHASH-CHAINID-02",
			Op:           "sighash_v1",
			TxHex:        txHex,
			ChainID:      hex.EncodeToString(altChainID[:]),
			InputIndex:   0,
			InputValue:   genesisSpend.value,
			ExpectOK:     true,
			ExpectDigest: hex.EncodeToString(altDigest[:]),
		},
	}, nil
}

func collectPrevTimestamps(store *node.BlockStore, nextHeight uint64) ([]uint64, error) {
	if nextHeight == 0 {
		return []uint64{}, nil
	}
	k := uint64(11)
	if nextHeight < k {
		k = nextHeight
	}
	out := make([]uint64, 0, k)
	for i := uint64(0); i < k; i++ {
		h := nextHeight - 1 - i
		hash, ok, err := store.CanonicalHash(h)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("missing canonical hash at height %d", h)
		}
		headerBytes, err := store.GetHeaderByHash(hash)
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

func snapshotChainState(st *node.ChainState) (ChainStateJSON, error) {
	tmp, err := os.CreateTemp("", "rubin-chainstate-*.json")
	if err != nil {
		return ChainStateJSON{}, err
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		return ChainStateJSON{}, err
	}
	defer os.Remove(path)
	if err := st.Save(path); err != nil {
		return ChainStateJSON{}, err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from os.CreateTemp above.
	if err != nil {
		return ChainStateJSON{}, err
	}
	var snapshot ChainStateJSON
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return ChainStateJSON{}, err
	}
	if snapshot.Utxos == nil {
		snapshot.Utxos = []UtxoJSON{}
	}
	return snapshot, nil
}

func spendableOutputFromBlock(blockBytes []byte) ([32]byte, uint64, uint32, []byte, string, error) {
	var zero [32]byte
	parsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return zero, 0, 0, nil, "", err
	}
	if len(parsed.Txs) == 0 || len(parsed.Txids) == 0 {
		return zero, 0, 0, nil, "", errors.New("missing coinbase transaction")
	}
	coinbase := parsed.Txs[0]
	for idx, out := range coinbase.Outputs {
		if out.CovenantType == consensus.COV_TYPE_ANCHOR || out.CovenantType == consensus.COV_TYPE_DA_COMMIT {
			continue
		}
		blockHash, err := consensus.BlockHash(parsed.HeaderBytes)
		if err != nil {
			return zero, 0, 0, nil, "", err
		}
		return parsed.Txids[0], out.Value, uint32(idx), append([]byte(nil), out.CovenantData...), hex.EncodeToString(blockHash[:]), nil
	}
	return zero, 0, 0, nil, "", errors.New("missing spendable coinbase output")
}

func marshalSingleInputP2PKTx(prevTxid [32]byte, prevVout uint32, inputValue uint64, outputValue uint64, outputCovenant []byte, txNonce uint64) (string, error) {
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: txNonce,
		Inputs: []consensus.TxInput{
			{
				PrevTxid:  prevTxid,
				PrevVout:  prevVout,
				ScriptSig: nil,
				Sequence:  0,
			},
		},
		Outputs: []consensus.TxOutput{
			{
				Value:        outputValue,
				CovenantType: consensus.COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), outputCovenant...),
			},
		},
		Locktime: 0,
		Witness: []consensus.WitnessItem{
			placeholderMLDSAWitness(),
		},
		DaPayload: nil,
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		return "", err
	}
	parsed, _, _, consumed, err := consensus.ParseTx(raw)
	if err != nil {
		return "", err
	}
	if consumed != len(raw) || parsed == nil {
		return "", errors.New("generated tx is not canonical")
	}
	if outputValue > inputValue {
		return "", errors.New("output value exceeds input value")
	}
	return hex.EncodeToString(raw), nil
}

func placeholderMLDSAWitness() consensus.WitnessItem {
	return consensus.WitnessItem{
		SuiteID:   consensus.SUITE_ID_ML_DSA_87,
		Pubkey:    make([]byte, consensus.ML_DSA_87_PUBKEY_BYTES),
		Signature: make([]byte, consensus.ML_DSA_87_SIG_BYTES+1),
	}
}

func alternateChainID(chainID [32]byte) [32]byte {
	var alt [32]byte
	alt[31] = sighashMutationLastByte
	if alt == chainID {
		alt[0] = 0x42
	}
	return alt
}

func decodeHex32(hexStr string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return out, err
	}
	if len(raw) != len(out) {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func cloneUint64s(src []uint64) []uint64 {
	return append([]uint64(nil), src...)
}

func cloneUtxos(src []UtxoJSON) []UtxoJSON {
	out := make([]UtxoJSON, len(src))
	copy(out, src)
	return out
}

func cloneChainState(src ChainStateJSON) *ChainStateJSON {
	out := src
	out.Utxos = cloneUtxos(src.Utxos)
	return &out
}

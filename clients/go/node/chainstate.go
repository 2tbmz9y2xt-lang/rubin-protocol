package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	genesisHeaderHex = "0100000000000000000000000000000000000000000000000000000000000000000000006f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd406f2df91340e49e6900000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000"
	genesisTxHex     = "01000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd72790000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000"

	genesisChainIDHex     = "88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103"
	genesisBlockHashHex   = "8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff"
	genesisMagicSeparator = "RUBIN-GENESIS-v1"
)

var (
	devnetGenesisHeaderBytes = decodeHexToBytesExact(genesisHeaderHex, consensus.BLOCK_HEADER_BYTES)
	devnetGenesisTxBytes     = decodeHexToBytesExact(genesisTxHex, 149)
	devnetGenesisBlockBytes  = append(append([]byte{}, devnetGenesisHeaderBytes...), consensus.AppendCompactSize(nil, 1)...)
)

func init() {
	devnetGenesisBlockBytes = append(devnetGenesisBlockBytes, devnetGenesisTxBytes...)
}

var (
	devnetGenesisBlockHash  [32]byte
	devnetGenesisChainID    [32]byte
	genesisChainIDFromMagic [32]byte
)

func init() {
	devnetGenesisChainID = decodeHexToBytes32(genesisChainIDHex)
	devnetGenesisBlockHash = decodeHexToBytes32(genesisBlockHashHex)
	genesisChainIDFromMagic = deriveGenesisChainID(devnetGenesisHeaderBytes, devnetGenesisTxBytes)
	if !bytes.Equal(genesisChainIDFromMagic[:], devnetGenesisChainID[:]) {
		panic("genesis chain ID constant mismatch")
	}
}

const (
	chainStateDiskVersion = 1
	chainStateFileName    = "chainstate.json"
)

type ChainState struct {
	admissionMu      sync.RWMutex
	mu               sync.RWMutex
	Utxos            map[consensus.Outpoint]consensus.UtxoEntry
	Height           uint64
	AlreadyGenerated uint64
	TipHash          [32]byte
	HasTip           bool
	Rotation         consensus.RotationProvider
	Registry         *consensus.SuiteRegistry
}

type ChainStateConnectSummary struct {
	BlockHeight        uint64
	BlockHash          [32]byte
	SumFees            uint64
	AlreadyGenerated   uint64
	AlreadyGeneratedN1 uint64
	UtxoCount          uint64
	PostStateDigest    [32]byte
	SigTaskCount       uint64 // parallel path only; 0 for sequential
	WorkerPanics       uint64 // parallel path only; 0 for sequential
}

type chainStateDisk struct {
	TipHash          string          `json:"tip_hash"`
	Utxos            []utxoDiskEntry `json:"utxos"`
	Height           uint64          `json:"height"`
	AlreadyGenerated uint64          `json:"already_generated"`
	Version          uint32          `json:"version"`
	HasTip           bool            `json:"has_tip"`
}

type utxoDiskEntry struct {
	Txid              string `json:"txid"`
	CovenantData      string `json:"covenant_data"`
	Value             uint64 `json:"value"`
	CreationHeight    uint64 `json:"creation_height"`
	Vout              uint32 `json:"vout"`
	CovenantType      uint16 `json:"covenant_type"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

type chainStateView struct {
	hasTip           bool
	height           uint64
	tipHash          [32]byte
	alreadyGenerated uint64
	utxoCount        int
}

type chainStateAdmissionSnapshot struct {
	utxos   map[consensus.Outpoint]consensus.UtxoEntry
	hasTip  bool
	height  uint64
	tipHash [32]byte
}

func NewChainState() *ChainState {
	return &ChainState{
		Utxos: make(map[consensus.Outpoint]consensus.UtxoEntry),
	}
}

func (s *ChainState) view() chainStateView {
	if s == nil {
		return chainStateView{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return chainStateView{
		hasTip:           s.HasTip,
		height:           s.Height,
		tipHash:          s.TipHash,
		alreadyGenerated: s.AlreadyGenerated,
		utxoCount:        len(s.Utxos),
	}
}

func (s *ChainState) admissionSnapshot() *chainStateAdmissionSnapshot {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &chainStateAdmissionSnapshot{
		utxos:   copyUtxoSet(s.Utxos),
		hasTip:  s.HasTip,
		height:  s.Height,
		tipHash: s.TipHash,
	}
}

func (s *ChainState) admissionSnapshotForInputs(inputs []consensus.Outpoint) *chainStateAdmissionSnapshot {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &chainStateAdmissionSnapshot{
		utxos:   copySelectedUtxoSet(s.Utxos, inputs),
		hasTip:  s.HasTip,
		height:  s.Height,
		tipHash: s.TipHash,
	}
}

func (s *ChainState) replaceFrom(src *ChainState) {
	if s == nil || src == nil {
		return
	}
	snapshot := cloneChainState(src)
	if snapshot == nil {
		return
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Utxos = snapshot.Utxos
	s.Height = snapshot.Height
	s.AlreadyGenerated = snapshot.AlreadyGenerated
	s.TipHash = snapshot.TipHash
	s.HasTip = snapshot.HasTip
	s.Rotation = snapshot.Rotation
	s.Registry = snapshot.Registry
}

// rotationOrNil returns s.Rotation if set, otherwise nil.
// When nil, consensus functions internally fallback to DefaultRotationProvider,
// matching the Rust defaulting contract where SyncEngine passes None.
func (s *ChainState) rotationOrNil() consensus.RotationProvider {
	if s != nil {
		return s.Rotation
	}
	return nil
}

// registryOrNil returns s.Registry if set, otherwise nil.
// When nil, consensus functions internally fallback to DefaultSuiteRegistry,
// matching the Rust defaulting contract.
func (s *ChainState) registryOrNil() *consensus.SuiteRegistry {
	if s != nil {
		return s.Registry
	}
	return nil
}

// IndexedSuiteIDs returns the sorted suite IDs that are explicitly bound in
// UTXO covenant data. Today this covers covenant forms that carry suite_id
// directly in the output itself, such as CORE_P2PK.
func (s *ChainState) IndexedSuiteIDs() []uint8 {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[uint8]struct{})
	ids := make([]uint8, 0)
	for _, entry := range s.Utxos {
		for _, suiteID := range explicitSuiteIDsForUtxoEntry(entry) {
			if _, ok := seen[suiteID]; ok {
				continue
			}
			seen[suiteID] = struct{}{}
			ids = append(ids, suiteID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// UtxoOutpointsBySuiteID returns the deterministically sorted outpoints whose
// covenant data explicitly binds to suiteID.
func (s *ChainState) UtxoOutpointsBySuiteID(suiteID uint8) []consensus.Outpoint {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	outpoints := make([]consensus.Outpoint, 0)
	for op, entry := range s.Utxos {
		if utxoEntryExplicitlyUsesSuite(entry, suiteID) {
			outpoints = append(outpoints, op)
		}
	}
	sortOutpointsDeterministically(outpoints)
	return outpoints
}

// UtxoExposureCountBySuiteID reports how many current UTXOs explicitly bind to
// suiteID in their covenant data.
func (s *ChainState) UtxoExposureCountBySuiteID(suiteID uint8) uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count uint64
	for _, entry := range s.Utxos {
		if utxoEntryExplicitlyUsesSuite(entry, suiteID) {
			count++
		}
	}
	return count
}

func explicitSuiteIDsForUtxoEntry(entry consensus.UtxoEntry) []uint8 {
	switch entry.CovenantType {
	case consensus.COV_TYPE_P2PK:
		if len(entry.CovenantData) != consensus.MAX_P2PK_COVENANT_DATA {
			return nil
		}
		return []uint8{entry.CovenantData[0]}
	default:
		return nil
	}
}

func utxoEntryExplicitlyUsesSuite(entry consensus.UtxoEntry, suiteID uint8) bool {
	for _, id := range explicitSuiteIDsForUtxoEntry(entry) {
		if id == suiteID {
			return true
		}
	}
	return false
}

func sortOutpointsDeterministically(outpoints []consensus.Outpoint) {
	sort.Slice(outpoints, func(i, j int) bool {
		if bytes.Compare(outpoints[i].Txid[:], outpoints[j].Txid[:]) != 0 {
			return bytes.Compare(outpoints[i].Txid[:], outpoints[j].Txid[:]) < 0
		}
		return outpoints[i].Vout < outpoints[j].Vout
	})
}

func ChainStatePath(dataDir string) string {
	return filepath.Join(dataDir, chainStateFileName)
}

func LoadChainState(path string) (*ChainState, error) {
	raw, err := readFileByPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewChainState(), nil
	}
	if err != nil {
		return nil, err
	}
	var disk chainStateDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, fmt.Errorf("decode chainstate: %w", err)
	}
	return chainStateFromDisk(disk)
}

func (s *ChainState) Save(path string) error {
	if s == nil {
		return errors.New("nil chainstate")
	}
	disk, err := stateToDisk(s)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return fmt.Errorf("encode chainstate: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o600)
}

func (s *ChainState) ConnectBlock(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
) (*ChainStateConnectSummary, error) {
	return s.ConnectBlockWithCoreExtProfiles(blockBytes, expectedTarget, prevTimestamps, chainID, nil)
}

func (s *ChainState) ConnectBlockWithCoreExtProfiles(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles consensus.CoreExtProfileProvider,
) (*ChainStateConnectSummary, error) {
	return s.ConnectBlockWithCoreExtProfilesAndSuiteContext(
		blockBytes,
		expectedTarget,
		prevTimestamps,
		chainID,
		coreExtProfiles,
		s.rotationOrNil(),
		s.registryOrNil(),
	)
}

func (s *ChainState) ConnectBlockWithCoreExtProfilesAndSuiteContext(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles consensus.CoreExtProfileProvider,
	rotation consensus.RotationProvider,
	registry *consensus.SuiteRegistry,
) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("nil chainstate")
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHeight, expectedPrevHash, err := nextBlockContextFromFields(s.HasTip, s.Height, s.TipHash)
	if err != nil {
		return nil, err
	}
	if s.Utxos == nil {
		s.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry)
	}
	workState := consensus.InMemoryChainState{
		Utxos:            s.Utxos,
		AlreadyGenerated: new(big.Int).SetUint64(s.AlreadyGenerated),
	}
	summary, err := consensus.ConnectBlockBasicInMemoryAtHeightAndCoreExtProfilesAndSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		&workState,
		chainID,
		coreExtProfiles,
		rotation,
		registry,
	)
	if err != nil {
		return nil, err
	}

	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, err
	}

	// Fail-atomic: check overflow BEFORE any state mutation so that an error
	// does not leave ChainState partially updated.
	if !workState.AlreadyGenerated.IsUint64() {
		return nil, errors.New("already_generated overflow")
	}

	s.HasTip = true
	s.Height = blockHeight
	s.TipHash = blockHash
	s.AlreadyGenerated = workState.AlreadyGenerated.Uint64()
	s.Utxos = workState.Utxos

	return &ChainStateConnectSummary{
		BlockHeight:        blockHeight,
		BlockHash:          blockHash,
		SumFees:            summary.SumFees,
		AlreadyGenerated:   summary.AlreadyGenerated,
		AlreadyGeneratedN1: summary.AlreadyGeneratedN1,
		UtxoCount:          summary.UtxoCount,
		PostStateDigest:    summary.PostStateDigest,
	}, nil
}

// ConnectBlockParallelSigs connects a block using parallel signature
// verification. This is an IBD optimization: pre-checks are sequential,
// ML-DSA-87 signature verifications are batched and executed across a
// goroutine pool. See consensus.ConnectBlockParallelSigVerify for details.
//
// workers controls the goroutine pool size. If <= 0, defaults to GOMAXPROCS.
func (s *ChainState) ConnectBlockParallelSigs(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles consensus.CoreExtProfileProvider,
	workers int,
) (*ChainStateConnectSummary, error) {
	return s.ConnectBlockParallelSigsWithSuiteContext(
		blockBytes,
		expectedTarget,
		prevTimestamps,
		chainID,
		coreExtProfiles,
		s.rotationOrNil(),
		s.registryOrNil(),
		workers,
	)
}

func (s *ChainState) ConnectBlockParallelSigsWithSuiteContext(
	blockBytes []byte,
	expectedTarget *[32]byte,
	prevTimestamps []uint64,
	chainID [32]byte,
	coreExtProfiles consensus.CoreExtProfileProvider,
	rotation consensus.RotationProvider,
	registry *consensus.SuiteRegistry,
	workers int,
) (*ChainStateConnectSummary, error) {
	if s == nil {
		return nil, errors.New("nil chainstate")
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	blockHeight, expectedPrevHash, err := nextBlockContextFromFields(s.HasTip, s.Height, s.TipHash)
	if err != nil {
		return nil, err
	}
	if s.Utxos == nil {
		s.Utxos = make(map[consensus.Outpoint]consensus.UtxoEntry)
	}
	// Clone UTXO set for fail-atomicity (same pattern as ConnectBlockWithCoreExtProfiles
	// at line 166). A future optimization may use a delta/undo journal, but correctness
	// requires matching the sequential path's isolation semantics exactly.
	workState := consensus.InMemoryChainState{
		Utxos:            copyUtxoSet(s.Utxos),
		AlreadyGenerated: new(big.Int).SetUint64(s.AlreadyGenerated),
	}
	summary, err := consensus.ConnectBlockParallelSigVerifyWithCoreExtProfilesAndSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		&workState,
		chainID,
		coreExtProfiles,
		rotation,
		registry,
		workers,
	)
	if err != nil {
		return nil, err
	}

	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, err
	}

	// Fail-atomic: check overflow BEFORE any state mutation so that an error
	// does not leave ChainState partially updated.
	if !workState.AlreadyGenerated.IsUint64() {
		return nil, errors.New("already_generated overflow")
	}

	s.HasTip = true
	s.Height = blockHeight
	s.TipHash = blockHash
	s.AlreadyGenerated = workState.AlreadyGenerated.Uint64()
	s.Utxos = workState.Utxos

	return &ChainStateConnectSummary{
		BlockHeight:        blockHeight,
		BlockHash:          blockHash,
		SumFees:            summary.SumFees,
		AlreadyGenerated:   summary.AlreadyGenerated,
		AlreadyGeneratedN1: summary.AlreadyGeneratedN1,
		UtxoCount:          summary.UtxoCount,
		PostStateDigest:    summary.PostStateDigest,
		SigTaskCount:       summary.SigTaskCount,
		WorkerPanics:       summary.WorkerPanics,
	}, nil
}

func DevnetGenesisChainID() [32]byte {
	return devnetGenesisChainID
}

func DevnetGenesisBlockBytes() []byte {
	return append([]byte(nil), devnetGenesisBlockBytes...)
}

func DevnetGenesisBlockHash() [32]byte {
	return devnetGenesisBlockHash
}
func nextBlockContext(s *ChainState) (uint64, *[32]byte, error) {
	if s == nil {
		return 0, nil, errors.New("nil chainstate")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return nextBlockContextFromFields(s.HasTip, s.Height, s.TipHash)
}

func nextBlockContextFromFields(hasTip bool, height uint64, tipHash [32]byte) (uint64, *[32]byte, error) {
	if !hasTip {
		return 0, nil, nil
	}
	if height == math.MaxUint64 {
		return 0, nil, errors.New("height overflow")
	}
	nextHeight := height + 1
	prev := tipHash
	return nextHeight, &prev, nil
}

// copyUtxoEntry is the canonical deep-copy helper for readonly snapshot/work-copy
// contracts in node package code. Callers should build full-set or subset copies
// from this helper rather than open-coding new UTXO copy variants.
func copyUtxoEntry(entry consensus.UtxoEntry) consensus.UtxoEntry {
	return consensus.UtxoEntry{
		Value:             entry.Value,
		CovenantType:      entry.CovenantType,
		CovenantData:      append([]byte(nil), entry.CovenantData...),
		CreationHeight:    entry.CreationHeight,
		CreatedByCoinbase: entry.CreatedByCoinbase,
	}
}

func copyUtxoSet(src map[consensus.Outpoint]consensus.UtxoEntry) map[consensus.Outpoint]consensus.UtxoEntry {
	out := make(map[consensus.Outpoint]consensus.UtxoEntry, len(src))
	for k, v := range src {
		out[k] = copyUtxoEntry(v)
	}
	return out
}

func copySelectedUtxoSet(src map[consensus.Outpoint]consensus.UtxoEntry, outpoints []consensus.Outpoint) map[consensus.Outpoint]consensus.UtxoEntry {
	out := make(map[consensus.Outpoint]consensus.UtxoEntry, countExistingUniqueOutpoints(src, outpoints))
	for _, op := range outpoints {
		if _, seen := out[op]; seen {
			continue
		}
		entry, ok := src[op]
		if !ok {
			continue
		}
		out[op] = copyUtxoEntry(entry)
	}
	return out
}

func countExistingUniqueOutpoints(src map[consensus.Outpoint]consensus.UtxoEntry, outpoints []consensus.Outpoint) int {
	if len(src) == 0 || len(outpoints) == 0 {
		return 0
	}
	seen := make(map[consensus.Outpoint]struct{}, len(outpoints))
	count := 0
	for _, op := range outpoints {
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}
		if _, ok := src[op]; ok {
			count++
		}
	}
	return count
}

func stateToDisk(s *ChainState) (chainStateDisk, error) {
	if s == nil {
		return chainStateDisk{}, errors.New("nil chainstate")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	utxos := make([]utxoDiskEntry, 0, len(s.Utxos))
	for op, entry := range s.Utxos {
		utxos = append(utxos, utxoDiskEntry{
			Txid:              hex.EncodeToString(op.Txid[:]),
			Vout:              op.Vout,
			Value:             entry.Value,
			CovenantType:      entry.CovenantType,
			CovenantData:      hex.EncodeToString(entry.CovenantData),
			CreationHeight:    entry.CreationHeight,
			CreatedByCoinbase: entry.CreatedByCoinbase,
		})
	}
	sort.Slice(utxos, func(i, j int) bool {
		if utxos[i].Txid != utxos[j].Txid {
			return utxos[i].Txid < utxos[j].Txid
		}
		return utxos[i].Vout < utxos[j].Vout
	})

	return chainStateDisk{
		Version:          chainStateDiskVersion,
		HasTip:           s.HasTip,
		Height:           s.Height,
		TipHash:          hex.EncodeToString(s.TipHash[:]),
		AlreadyGenerated: s.AlreadyGenerated,
		Utxos:            utxos,
	}, nil
}

func chainStateFromDisk(disk chainStateDisk) (*ChainState, error) {
	if disk.Version != chainStateDiskVersion {
		return nil, fmt.Errorf("unsupported chainstate version: %d", disk.Version)
	}

	tipHash, err := parseHex32("tip_hash", disk.TipHash)
	if err != nil {
		return nil, err
	}
	utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(disk.Utxos))
	for _, item := range disk.Utxos {
		txid, err := parseHex32("utxo.txid", item.Txid)
		if err != nil {
			return nil, err
		}
		covData, err := parseHex("utxo.covenant_data", item.CovenantData)
		if err != nil {
			return nil, err
		}
		op := consensus.Outpoint{
			Txid: txid,
			Vout: item.Vout,
		}
		if _, exists := utxos[op]; exists {
			return nil, fmt.Errorf("duplicate utxo outpoint: %s:%d", item.Txid, item.Vout)
		}
		utxos[op] = consensus.UtxoEntry{
			Value:             item.Value,
			CovenantType:      item.CovenantType,
			CovenantData:      covData,
			CreationHeight:    item.CreationHeight,
			CreatedByCoinbase: item.CreatedByCoinbase,
		}
	}
	return &ChainState{
		HasTip:           disk.HasTip,
		Height:           disk.Height,
		TipHash:          tipHash,
		AlreadyGenerated: disk.AlreadyGenerated,
		Utxos:            utxos,
	}, nil
}

func decodeHexToBytesExact(value string, expectedLen int) []byte {
	raw := strings.TrimSpace(value)
	out, err := hex.DecodeString(raw)
	if err != nil {
		panic(fmt.Sprintf("invalid hex: %v", err))
	}
	if len(out) != expectedLen {
		panic(fmt.Sprintf("expected %d bytes, got %d", expectedLen, len(out)))
	}
	return out
}

func decodeHexToBytes32(value string) [32]byte {
	raw := decodeHexToBytesExact(value, 32)
	var out [32]byte
	copy(out[:], raw)
	return out
}

func deriveGenesisChainID(headerBytes, txBytes []byte) [32]byte {
	// Chain ID = SHA3-256("RUBIN-GENESIS-v1" || header || compact_size(tx_count) || tx_bytes)
	preimage := append([]byte{}, []byte(genesisMagicSeparator)...)
	preimage = append(preimage, headerBytes...)
	preimage = consensus.AppendCompactSize(preimage, 1) // tx_count = 1
	preimage = append(preimage, txBytes...)
	return sha3.Sum256(preimage)
}

func parseHex(name, value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed)%2 != 0 {
		return nil, fmt.Errorf("%s: odd-length hex", name)
	}
	out, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func parseHex32(name, value string) ([32]byte, error) {
	var out [32]byte
	raw, err := parseHex(name, value)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("%s: expected 32 bytes, got %d", name, len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmpPath := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmpPath, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

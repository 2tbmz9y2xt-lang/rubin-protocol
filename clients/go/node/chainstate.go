package node

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
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

// CanonicalAppliedBlock identifies one block a canonical apply committed, plus
// the complete DA-set IDs that block carries. It deliberately holds NO raw block
// bytes: a reorg summary accumulates one record per newly-canonical block, and a
// block is up to consensus.MAX_BLOCK_BYTES, so retaining bytes made summary size
// grow with reorg depth times block size. CompleteDAIDs is bounded by
// consensus.MAX_DA_BATCHES_PER_BLOCK fixed-width IDs, which is all any consumer
// needed from the bytes.
type CanonicalAppliedBlock struct {
	Hash          [32]byte
	CompleteDAIDs [][32]byte
}

type ChainStateConnectSummary struct {
	BlockHeight        uint64
	BlockHash          [32]byte
	SumFees            uint64
	AlreadyGenerated   uint64
	AlreadyGeneratedN1 uint64
	UtxoCount          uint64
	// CanonicalAppliedBlocks is populated ONLY by the SyncEngine canonical-apply
	// path, in canonical order: a direct apply reports the single connected
	// block, a reorg reports every newly-canonical branch block, and a
	// stored-but-not-switched side branch reports none. The ChainState connect
	// entry points leave it nil — connecting to an in-memory state is not by
	// itself a canonical-application event (the reorg preview and startup replay
	// both connect blocks that must never be reported).
	CanonicalAppliedBlocks []CanonicalAppliedBlock
	PostStateDigest        [32]byte
	SigTaskCount           uint64 // parallel path only; 0 for sequential
	WorkerPanics           uint64 // parallel path only; 0 for sequential
}

// CompleteDASetIDsFromParsedBlock returns the da_id of every COMPLETE DA set
// carried by an already-parsed block, in ascending byte order.
//
// This is the single implementation of block-level complete-DA-set extraction in
// the Go tree; node/p2p parses untrusted bytes and delegates here so the
// bytes-entry and parsed-entry paths cannot diverge.
//
// A set counts as complete exactly when the block carries one tx_kind=0x01
// commit for that da_id (a second commit disqualifies it), the commit's
// chunk_count is in 1..=consensus.MAX_DA_CHUNK_COUNT, and the block carries a
// tx_kind=0x02 chunk for every index 0..chunk_count-1. This mirrors the
// completeness rule consensus.ConnectBlock* already enforces; it is repeated
// here because the caller may hand over a block that has NOT been validated.
//
// Contract:
//   - Output is sorted by raw ID bytes, never by map iteration order, so it is
//     deterministic for a given block.
//   - At most consensus.MAX_DA_BATCHES_PER_BLOCK IDs are returned; a block that
//     would yield more is reported as an error rather than truncated. A block
//     that passed consensus validation cannot reach that branch.
//   - pb is read-only; no field of pb or of its transactions is mutated.
//   - A nil pb, a nil transaction, or a DA transaction missing its DA core is an
//     error or is skipped — never a panic, since callers may pass a block that
//     was assembled rather than parsed.
func CompleteDASetIDsFromParsedBlock(pb *consensus.ParsedBlock) ([][32]byte, error) {
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	sets := make(map[[32]byte]blockDASetTally)
	for _, tx := range pb.Txs {
		recordBlockDATx(sets, tx)
	}
	ids := make([][32]byte, 0, len(sets))
	for daID, set := range sets {
		if !set.complete() {
			continue
		}
		ids = append(ids, daID)
	}
	if len(ids) > consensus.MAX_DA_BATCHES_PER_BLOCK {
		return nil, fmt.Errorf("complete DA sets in block: %d exceeds MAX_DA_BATCHES_PER_BLOCK=%d", len(ids), consensus.MAX_DA_BATCHES_PER_BLOCK)
	}
	sort.Slice(ids, func(i, j int) bool {
		return bytes.Compare(ids[i][:], ids[j][:]) < 0
	})
	return ids, nil
}

func recordBlockDATx(sets map[[32]byte]blockDASetTally, tx *consensus.Tx) {
	if tx == nil {
		return
	}
	switch tx.TxKind {
	case 0x01:
		if tx.DaCommitCore == nil {
			return
		}
		daID := tx.DaCommitCore.DaID
		set := sets[daID]
		set.commitCount++
		set.chunkCount = tx.DaCommitCore.ChunkCount
		sets[daID] = set
	case 0x02:
		if tx.DaChunkCore == nil {
			return
		}
		daID := tx.DaChunkCore.DaID
		set := sets[daID]
		if set.chunks == nil {
			set.chunks = make(map[uint16]struct{})
		}
		set.chunks[tx.DaChunkCore.ChunkIndex] = struct{}{}
		sets[daID] = set
	}
}

type blockDASetTally struct {
	commitCount int
	chunkCount  uint16
	chunks      map[uint16]struct{}
}

func (s blockDASetTally) complete() bool {
	if s.commitCount != 1 || s.chunkCount == 0 || uint64(s.chunkCount) > consensus.MAX_DA_CHUNK_COUNT {
		return false
	}
	if len(s.chunks) != int(s.chunkCount) {
		return false
	}
	for i := uint16(0); i < s.chunkCount; i++ {
		if _, ok := s.chunks[i]; !ok {
			return false
		}
	}
	return true
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
		if suiteID, ok := explicitSuiteIDForUtxoEntry(entry); ok {
			if _, seenAlready := seen[suiteID]; seenAlready {
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

func explicitSuiteIDForUtxoEntry(entry consensus.UtxoEntry) (uint8, bool) {
	switch entry.CovenantType {
	case consensus.COV_TYPE_P2PK:
		if len(entry.CovenantData) != consensus.MAX_P2PK_COVENANT_DATA {
			return 0, false
		}
		return entry.CovenantData[0], true
	default:
		return 0, false
	}
}

func utxoEntryExplicitlyUsesSuite(entry consensus.UtxoEntry, suiteID uint8) bool {
	id, ok := explicitSuiteIDForUtxoEntry(entry)
	return ok && id == suiteID
}

func sortOutpointsDeterministically(outpoints []consensus.Outpoint) {
	sort.Slice(outpoints, func(i, j int) bool {
		if cmp := bytes.Compare(outpoints[i].Txid[:], outpoints[j].Txid[:]); cmp != 0 {
			return cmp < 0
		}
		return outpoints[i].Vout < outpoints[j].Vout
	})
}

// UtxoSetHash returns the deterministic SHA3-256 digest over the current UTXO
// set. It is bit-identical with the Rust node ChainState::utxo_set_hash() and
// uses the same canonical encoding as consensus.UtxoSetHash (which produces
// PostStateDigest in ConnectBlock summaries). On a nil receiver returns the
// digest of an empty UTXO map for definedness.
//
// Cost: O(n log n) over the entire UTXO set (sort by outpoint canonical key)
// plus one SHA3-256 hash + per-entry allocations for the canonical encoding.
// Intended for low-frequency inspection / parity-vector verification — do
// NOT call from hot paths or polling loops. If a caller needs incremental
// digest updates, fold the maintenance into ConnectBlock / DisconnectTip
// instead of calling this.
func (s *ChainState) UtxoSetHash() [32]byte {
	if s == nil {
		return consensus.UtxoSetHash(nil)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return consensus.UtxoSetHash(s.Utxos)
}

// StateDigest is an alias for UtxoSetHash that mirrors the Rust node
// ChainState::state_digest() surface. Today the chain state digest is exactly
// the UTXO set hash; the two names are kept in parity with Rust so that
// inspection callers can reach for either spelling.
func (s *ChainState) StateDigest() [32]byte {
	return s.UtxoSetHash()
}

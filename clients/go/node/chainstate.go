package node

import (
	"bytes"
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

type CanonicalAppliedBlock struct {
	Hash       [32]byte
	BlockBytes []byte
}

type ChainStateConnectSummary struct {
	BlockHeight            uint64
	BlockHash              [32]byte
	SumFees                uint64
	AlreadyGenerated       uint64
	AlreadyGeneratedN1     uint64
	UtxoCount              uint64
	CanonicalAppliedBlocks []CanonicalAppliedBlock
	PostStateDigest        [32]byte
	SigTaskCount           uint64 // parallel path only; 0 for sequential
	WorkerPanics           uint64 // parallel path only; 0 for sequential
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

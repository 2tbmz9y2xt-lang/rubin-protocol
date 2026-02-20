package consensus

import "math/big"

const (
	CORE_P2PK            = 0x0000
	CORE_TIMELOCK_V1     = 0x0001
	CORE_ANCHOR          = 0x0002
	CORE_HTLC_V1         = 0x0100
	CORE_VAULT_V1        = 0x0101
	CORE_HTLC_V2         = 0x0102
	CORE_DA_COMMIT       = 0x0103
	CORE_RESERVED_FUTURE = 0x00ff

	MAX_BLOCK_WEIGHT           = 4_000_000
	MAX_ANCHOR_BYTES_PER_BLOCK = 131_072
	MAX_ANCHOR_PAYLOAD_SIZE    = 65_536
	WINDOW_SIZE                = 2_016
	TARGET_BLOCK_INTERVAL      = 600
	MAX_FUTURE_DRIFT           = 7_200
	COINBASE_MATURITY          = 100
	BASE_UNITS_PER_RBN         = 100_000_000
	MAX_SUPPLY                 = 10_000_000_000_000_000
	SUBSIDY_TOTAL_MINED        = 9_900_000_000_000_000
	SUBSIDY_DURATION_BLOCKS    = 1_314_900
	VERIFY_COST_ML_DSA         = 8
	VERIFY_COST_SLH_DSA        = 64

	MAX_TX_INPUTS            = 1_024
	MAX_TX_OUTPUTS           = 1_024
	MAX_WITNESS_ITEMS        = 1_024
	MAX_WITNESS_BYTES_PER_TX = 100_000

	// DA (on-chain data availability) consensus caps (v2 wire, planning profile).
	MAX_DA_MANIFEST_BYTES_PER_TX = 65_536
	MAX_DA_CHUNK_BYTES_PER_TX    = 524_288
	MAX_DA_BYTES_PER_BLOCK       = 32_000_000
	MAX_DA_COMMITS_PER_BLOCK     = 128
	MAX_DA_CHUNK_COUNT           = 4_096

	SUITE_ID_SENTINEL     = 0x00
	SUITE_ID_ML_DSA       = 0x01
	SUITE_ID_SLH_DSA      = 0x02
	ML_DSA_PUBKEY_BYTES   = 2592
	ML_DSA_SIG_BYTES      = 4_627
	SLH_DSA_PUBKEY_BYTES  = 64
	SLH_DSA_SIG_MAX_BYTES = 49_856

	TIMELOCK_MODE_HEIGHT    = 0x00
	TIMELOCK_MODE_TIMESTAMP = 0x01
)

const (
	TX_VERSION_V2 = 2

	TX_KIND_STANDARD = 0x00
	TX_KIND_DA_COMMIT = 0x01
	TX_KIND_DA_CHUNK  = 0x02
)

const (
	TX_NONCE_ZERO            = 0
	TX_MAX_SEQUENCE          = 0x7fffffff
	TX_COINBASE_PREVOUT_VOUT = ^uint32(0)
	TX_ERR_NONCE_REPLAY      = "TX_ERR_NONCE_REPLAY"
	TX_ERR_TX_NONCE_INVALID  = "TX_ERR_TX_NONCE_INVALID"
	TX_ERR_SEQUENCE_INVALID  = "TX_ERR_SEQUENCE_INVALID"
	TX_ERR_COINBASE_IMMATURE = "TX_ERR_COINBASE_IMMATURE"
	TX_ERR_WITNESS_OVERFLOW  = "TX_ERR_WITNESS_OVERFLOW"
	TX_ERR_MISSING_UTXO      = "TX_ERR_MISSING_UTXO"
)

var MAX_TARGET = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

var maxTargetBig = new(big.Int).SetBytes(MAX_TARGET[:])

var targetBlockIntervalBig = big.NewInt(TARGET_BLOCK_INTERVAL * WINDOW_SIZE)

type BlockHeader struct {
	Version       uint32
	PrevBlockHash [32]byte
	MerkleRoot    [32]byte
	Timestamp     uint64
	Target        [32]byte
	Nonce         uint64
}

type Block struct {
	Header       BlockHeader
	Transactions []Tx
}

// BlockValidationContext captures chain and validation settings used by ApplyBlock.
// AncestorHeaders must be ordered from oldest to newest and include the parent block
// of Header as the last entry when available.
type BlockValidationContext struct {
	Height           uint64
	AncestorHeaders  []BlockHeader
	LocalTime        uint64
	LocalTimeSet     bool
	SuiteIDSLHActive bool
	HTLCV2Active     bool
}

const (
	BLOCK_ERR_PARSE                 = "BLOCK_ERR_PARSE"
	BLOCK_ERR_LINKAGE_INVALID       = "BLOCK_ERR_LINKAGE_INVALID"
	BLOCK_ERR_POW_INVALID           = "BLOCK_ERR_POW_INVALID"
	BLOCK_ERR_TARGET_INVALID        = "BLOCK_ERR_TARGET_INVALID"
	BLOCK_ERR_MERKLE_INVALID        = "BLOCK_ERR_MERKLE_INVALID"
	BLOCK_ERR_WEIGHT_EXCEEDED       = "BLOCK_ERR_WEIGHT_EXCEEDED"
	BLOCK_ERR_COINBASE_INVALID      = "BLOCK_ERR_COINBASE_INVALID"
	BLOCK_ERR_SUBSIDY_EXCEEDED      = "BLOCK_ERR_SUBSIDY_EXCEEDED"
	BLOCK_ERR_TIMESTAMP_OLD         = "BLOCK_ERR_TIMESTAMP_OLD"
	BLOCK_ERR_TIMESTAMP_FUTURE      = "BLOCK_ERR_TIMESTAMP_FUTURE"
	BLOCK_ERR_ANCHOR_BYTES_EXCEEDED = "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED"
)

type blockWeightError struct {
	code string
}

func (e blockWeightError) Error() string { return e.code }

type Tx struct {
	// Consensus wire v2: Version MUST be TX_VERSION_V2.
	Version uint32

	// tx_kind: 0x00=standard, 0x01=DA_COMMIT_TX, 0x02=DA_CHUNK_TX.
	TxKind uint8

	TxNonce  uint64
	Inputs   []TxInput
	Outputs  []TxOutput
	Locktime uint32

	// DA core fields (present iff TxKind != 0x00) and DA payload bytes (present iff TxKind != 0x00).
	DACommit *DACommitFields
	DAChunk  *DAChunkFields
	DAPayload []byte

	Witness WitnessSection
}

type DACommitFields struct {
	DAID            [32]byte
	ChunkCount      uint16
	RETLDomainID    [32]byte
	BatchNumber     uint64
	TxDataRoot      [32]byte
	StateRoot       [32]byte
	WithdrawalsRoot [32]byte
	BatchSigSuite   uint8
	BatchSig        []byte
}

type DAChunkFields struct {
	DAID       [32]byte
	ChunkIndex uint16
	ChunkHash  [32]byte
}

type TxOutPoint struct {
	TxID [32]byte
	Vout uint32
}

type TxInput struct {
	PrevTxid  [32]byte
	PrevVout  uint32
	ScriptSig []byte
	Sequence  uint32
}

type TxOutput struct {
	Value        uint64
	CovenantType uint16
	CovenantData []byte
}

type UtxoEntry struct {
	Output            TxOutput
	CreationHeight    uint64
	CreatedByCoinbase bool
}

type WitnessSection struct {
	Witnesses []WitnessItem
}

type WitnessItem struct {
	SuiteID   byte
	Pubkey    []byte
	Signature []byte
}

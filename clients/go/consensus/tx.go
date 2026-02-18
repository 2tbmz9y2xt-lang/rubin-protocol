package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"rubin.dev/node/crypto"
)

const (
	CORE_P2PK            = 0x0000
	CORE_TIMELOCK_V1     = 0x0001
	CORE_ANCHOR          = 0x0002
	CORE_HTLC_V1         = 0x0100
	CORE_VAULT_V1        = 0x0101
	CORE_HTLC_V2         = 0x0102
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

		MAX_TX_INPUTS     = 1_024
		MAX_TX_OUTPUTS    = 1_024
		MAX_WITNESS_ITEMS = 1_024
		MAX_WITNESS_BYTES_PER_TX = 100_000

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
	BLOCK_ERR_MINTING               = "BLOCK_ERR_MINTING"
)

type blockWeightError struct {
	code string
}

func (e blockWeightError) Error() string { return e.code }

type Tx struct {
	Version  uint32
	TxNonce  uint64
	Inputs   []TxInput
	Outputs  []TxOutput
	Locktime uint32
	Witness  WitnessSection
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

type cursor struct {
	b   []byte
	pos int
}

func maxIntAsUint64() uint64 {
	return uint64(^uint(0) >> 1)
}

func toIntLen(v uint64, name string) (int, error) {
	if v > maxIntAsUint64() {
		return 0, fmt.Errorf("parse: %s overflows usize", name)
	}
	// #nosec G115 -- v is bounded to int by maxIntAsUint64 above.
	return int(v), nil
}

func u32ToInt(v uint32, name string, max int) (int, error) {
	if max < 0 {
		return 0, fmt.Errorf("parse: %s invalid bound", name)
	}
	if uint64(v) > uint64(max) {
		return 0, fmt.Errorf("parse: %s does not fit int", name)
	}
	// #nosec G115 -- v is bounded to max via explicit uint32 comparison above.
	return int(v), nil
}

func newCursor(b []byte) *cursor {
	return &cursor{b: b, pos: 0}
}

func (c *cursor) remaining() int {
	if c.pos >= len(c.b) {
		return 0
	}
	return len(c.b) - c.pos
}

func (c *cursor) readExact(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("parse: truncated")
	}
	start := c.pos
	c.pos += n
	return c.b[start:c.pos], nil
}

func (c *cursor) readU8() (byte, error) {
	b, err := c.readExact(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) readU16LE() (uint16, error) {
	b, err := c.readExact(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (c *cursor) readU32LE() (uint32, error) {
	b, err := c.readExact(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (c *cursor) readU64LE() (uint64, error) {
	b, err := c.readExact(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (c *cursor) readCompactSize() (uint64, error) {
	cs, used, err := DecodeCompactSize(c.b[c.pos:])
	if err != nil {
		return 0, err
	}
	c.pos += used
	return uint64(cs), nil
}

func parseInput(cur *cursor) (TxInput, error) {
	prevTxidBytes, err := cur.readExact(32)
	if err != nil {
		return TxInput{}, err
	}
	var prevTxid [32]byte
	copy(prevTxid[:], prevTxidBytes)

	prevVout, err := cur.readU32LE()
	if err != nil {
		return TxInput{}, err
	}

	scriptSigLenU64, err := cur.readCompactSize()
	if err != nil {
		return TxInput{}, err
	}
	scriptSigLen, err := toIntLen(scriptSigLenU64, "script_sig_len")
	if err != nil {
		return TxInput{}, err
	}
	scriptSigBytes, err := cur.readExact(scriptSigLen)
	if err != nil {
		return TxInput{}, err
	}

	sequence, err := cur.readU32LE()
	if err != nil {
		return TxInput{}, err
	}

	return TxInput{
		PrevTxid:  prevTxid,
		PrevVout:  prevVout,
		ScriptSig: append([]byte(nil), scriptSigBytes...),
		Sequence:  sequence,
	}, nil
}

func parseOutput(cur *cursor) (TxOutput, error) {
	value, err := cur.readU64LE()
	if err != nil {
		return TxOutput{}, err
	}
	covenantType, err := cur.readU16LE()
	if err != nil {
		return TxOutput{}, err
	}

	covenantDataLenU64, err := cur.readCompactSize()
	if err != nil {
		return TxOutput{}, err
	}
	covenantDataLen, err := toIntLen(covenantDataLenU64, "covenant_data_len")
	if err != nil {
		return TxOutput{}, err
	}
	covenantDataBytes, err := cur.readExact(covenantDataLen)
	if err != nil {
		return TxOutput{}, err
	}

	return TxOutput{
		Value:        value,
		CovenantType: covenantType,
		CovenantData: append([]byte(nil), covenantDataBytes...),
	}, nil
}

func parseWitnessItem(cur *cursor) (WitnessItem, error) {
	suiteID, err := cur.readU8()
	if err != nil {
		return WitnessItem{}, err
	}

	pubkeyLenU64, err := cur.readCompactSize()
	if err != nil {
		return WitnessItem{}, err
	}
	pubkeyLen, err := toIntLen(pubkeyLenU64, "pubkey_len")
	if err != nil {
		return WitnessItem{}, err
	}
	pubkeyBytes, err := cur.readExact(pubkeyLen)
	if err != nil {
		return WitnessItem{}, err
	}

	sigLenU64, err := cur.readCompactSize()
	if err != nil {
		return WitnessItem{}, err
	}
	sigLen, err := toIntLen(sigLenU64, "sig_len")
	if err != nil {
		return WitnessItem{}, err
	}
	sigBytes, err := cur.readExact(sigLen)
	if err != nil {
		return WitnessItem{}, err
	}

	return WitnessItem{
		SuiteID:   suiteID,
		Pubkey:    append([]byte(nil), pubkeyBytes...),
		Signature: append([]byte(nil), sigBytes...),
	}, nil
}

func parseInputList(cur *cursor) ([]TxInput, error) {
	inputCountU64, err := cur.readCompactSize()
	if err != nil {
		return nil, err
	}
	inputCount, err := toIntLen(inputCountU64, "input_count")
	if err != nil {
		return nil, err
	}
	inputs := make([]TxInput, 0, inputCount)
	for i := 0; i < inputCount; i++ {
		inp, err := parseInput(cur)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, inp)
	}
	return inputs, nil
}

func parseOutputList(cur *cursor) ([]TxOutput, error) {
	outputCountU64, err := cur.readCompactSize()
	if err != nil {
		return nil, err
	}
	outputCount, err := toIntLen(outputCountU64, "output_count")
	if err != nil {
		return nil, err
	}
	outputs := make([]TxOutput, 0, outputCount)
	for i := 0; i < outputCount; i++ {
		out, err := parseOutput(cur)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
	}
	return outputs, nil
}

func parseWitnessList(cur *cursor) ([]WitnessItem, error) {
	witnessCountU64, err := cur.readCompactSize()
	if err != nil {
		return nil, err
	}
	witnessCount, err := toIntLen(witnessCountU64, "witness_count")
	if err != nil {
		return nil, err
	}
	witnesses := make([]WitnessItem, 0, witnessCount)
	for i := 0; i < witnessCount; i++ {
		w, err := parseWitnessItem(cur)
		if err != nil {
			return nil, err
		}
		witnesses = append(witnesses, w)
	}
	return witnesses, nil
}

func ParseTxBytes(b []byte) (*Tx, error) {
	cur := newCursor(b)

	version, err := cur.readU32LE()
	if err != nil {
		return nil, err
	}
	txNonce, err := cur.readU64LE()
	if err != nil {
		return nil, err
	}
	inputs, err := parseInputList(cur)
	if err != nil {
		return nil, err
	}
	outputs, err := parseOutputList(cur)
	if err != nil {
		return nil, err
	}

	locktime, err := cur.readU32LE()
	if err != nil {
		return nil, err
	}
	witnesses, err := parseWitnessList(cur)
	if err != nil {
		return nil, err
	}

	if cur.pos != len(b) {
		return nil, fmt.Errorf("parse: trailing bytes")
	}

	return &Tx{
		Version:  version,
		TxNonce:  txNonce,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
		Witness:  WitnessSection{Witnesses: witnesses},
	}, nil
}

func BlockHeaderBytes(header BlockHeader) []byte {
	out := make([]byte, 0, 4+32+32+8+32+8)
	var tmp4 [4]byte
	var tmp8 [8]byte

	binary.LittleEndian.PutUint32(tmp4[:], header.Version)
	out = append(out, tmp4[:]...)
	out = append(out, header.PrevBlockHash[:]...)
	out = append(out, header.MerkleRoot[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], header.Timestamp)
	out = append(out, tmp8[:]...)
	out = append(out, header.Target[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], header.Nonce)
	out = append(out, tmp8[:]...)
	return out
}

func ParseBlockHeader(cur *cursor) (BlockHeader, error) {
	version, err := cur.readU32LE()
	if err != nil {
		return BlockHeader{}, err
	}
	prev, err := cur.readExact(32)
	if err != nil {
		return BlockHeader{}, err
	}
	merkle, err := cur.readExact(32)
	if err != nil {
		return BlockHeader{}, err
	}
	timestamp, err := cur.readU64LE()
	if err != nil {
		return BlockHeader{}, err
	}
	target, err := cur.readExact(32)
	if err != nil {
		return BlockHeader{}, err
	}
	nonce, err := cur.readU64LE()
	if err != nil {
		return BlockHeader{}, err
	}
	var target32 [32]byte
	copy(target32[:], target)
	var prev32 [32]byte
	copy(prev32[:], prev)
	var merkle32 [32]byte
	copy(merkle32[:], merkle)
	return BlockHeader{
		Version:       version,
		PrevBlockHash: prev32,
		MerkleRoot:    merkle32,
		Timestamp:     timestamp,
		Target:        target32,
		Nonce:         nonce,
	}, nil
}

func ParseBlockBytes(b []byte) (Block, error) {
	cur := newCursor(b)
	header, err := ParseBlockHeader(cur)
	if err != nil {
		return Block{}, err
	}
	txCountU64, err := cur.readCompactSize()
	if err != nil {
		return Block{}, err
	}
	txCount, err := toIntLen(txCountU64, "tx_count")
	if err != nil {
		return Block{}, err
	}
	txs := make([]Tx, 0, txCount)
	for i := 0; i < txCount; i++ {
		tx, err := ParseTxBytesFromCursor(cur)
		if err != nil {
			return Block{}, err
		}
		txs = append(txs, *tx)
	}
	if cur.pos != len(b) {
		return Block{}, fmt.Errorf("BLOCK_ERR_PARSE")
	}
	return Block{
		Header:       header,
		Transactions: txs,
	}, nil
}

func ParseTxBytesFromCursor(cur *cursor) (*Tx, error) {
	version, err := cur.readU32LE()
	if err != nil {
		return nil, err
	}
	txNonce, err := cur.readU64LE()
	if err != nil {
		return nil, err
	}
	inputs, err := parseInputList(cur)
	if err != nil {
		return nil, err
	}
	outputs, err := parseOutputList(cur)
	if err != nil {
		return nil, err
	}
	locktime, err := cur.readU32LE()
	if err != nil {
		return nil, err
	}
	witnesses, err := parseWitnessList(cur)
	if err != nil {
		return nil, err
	}
	return &Tx{
		Version:  version,
		TxNonce:  txNonce,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
		Witness:  WitnessSection{Witnesses: witnesses},
	}, nil
}

func TxOutputBytes(o TxOutput) []byte {
	out := make([]byte, 0, 8+2+9+len(o.CovenantData))
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], o.Value)
	out = append(out, tmp8[:]...)
	var tmp2 [2]byte
	binary.LittleEndian.PutUint16(tmp2[:], o.CovenantType)
	out = append(out, tmp2[:]...)
	out = append(out, CompactSize(len(o.CovenantData)).Encode()...)
	out = append(out, o.CovenantData...)
	return out
}

func WitnessItemBytes(w WitnessItem) []byte {
	out := make([]byte, 0, 1+9+len(w.Pubkey)+9+len(w.Signature))
	out = append(out, w.SuiteID)
	out = append(out, CompactSize(len(w.Pubkey)).Encode()...)
	out = append(out, w.Pubkey...)
	out = append(out, CompactSize(len(w.Signature)).Encode()...)
	out = append(out, w.Signature...)
	return out
}

func WitnessBytes(w WitnessSection) []byte {
	out := make([]byte, 0, 9)
	out = append(out, CompactSize(len(w.Witnesses)).Encode()...)
	for _, item := range w.Witnesses {
		out = append(out, WitnessItemBytes(item)...)
	}
	return out
}

func TxNoWitnessBytes(tx *Tx) []byte {
	out := make([]byte, 0, 4+8)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], tx.Version)
	out = append(out, tmp4[:]...)
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], tx.TxNonce)
	out = append(out, tmp8[:]...)

	out = append(out, CompactSize(len(tx.Inputs)).Encode()...)
	for _, in := range tx.Inputs {
		out = append(out, in.PrevTxid[:]...)
		binary.LittleEndian.PutUint32(tmp4[:], in.PrevVout)
		out = append(out, tmp4[:]...)
		out = append(out, CompactSize(len(in.ScriptSig)).Encode()...)
		out = append(out, in.ScriptSig...)
		binary.LittleEndian.PutUint32(tmp4[:], in.Sequence)
		out = append(out, tmp4[:]...)
	}

	out = append(out, CompactSize(len(tx.Outputs)).Encode()...)
	for _, o := range tx.Outputs {
		out = append(out, TxOutputBytes(o)...)
	}

	binary.LittleEndian.PutUint32(tmp4[:], tx.Locktime)
	out = append(out, tmp4[:]...)
	return out
}

func TxBytes(tx *Tx) []byte {
	out := TxNoWitnessBytes(tx)
	out = append(out, WitnessBytes(tx.Witness)...)
	return out
}

func BlockBytes(block *Block) []byte {
	out := make([]byte, 0, 64)
	out = append(out, BlockHeaderBytes(block.Header)...)
	out = append(out, CompactSize(len(block.Transactions)).Encode()...)
	for _, tx := range block.Transactions {
		out = append(out, TxBytes(&tx)...)
	}
	return out
}

func TxWeight(tx *Tx) (uint64, error) {
	base := len(TxNoWitnessBytes(tx))
	witness := len(WitnessBytes(tx.Witness))
	base = base * 4
	sigCost := 0
	for i, item := range tx.Witness.Witnesses {
		if i < len(tx.Inputs) {
			switch item.SuiteID {
			case SUITE_ID_ML_DSA:
				sigCost += VERIFY_COST_ML_DSA
			case SUITE_ID_SLH_DSA:
				sigCost += VERIFY_COST_SLH_DSA
			}
		}
	}
	total, err := addUint64(uint64(base), uint64(witness))
	if err != nil {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	return addUint64(total, uint64(sigCost))
}

func blockHeaderHash(p crypto.CryptoProvider, header *BlockHeader) [32]byte {
	out := BlockHeaderBytes(*header)
	return p.SHA3_256(out)
}

func blockRewardForHeight(height uint64) uint64 {
	if height >= SUBSIDY_DURATION_BLOCKS {
		return 0
	}
	base := uint64(SUBSIDY_TOTAL_MINED / SUBSIDY_DURATION_BLOCKS)
	rem := uint64(SUBSIDY_TOTAL_MINED % SUBSIDY_DURATION_BLOCKS)
	if height < rem {
		return base + 1
	}
	return base
}

func medianPastTimestamp(headers []BlockHeader, height uint64) (uint64, error) {
	if height == 0 {
		return 0, fmt.Errorf(BLOCK_ERR_TIMESTAMP_OLD)
	}
	if len(headers) == 0 {
		return 0, fmt.Errorf(BLOCK_ERR_TIMESTAMP_OLD)
	}

	k := uint64(11)
	if height < k {
		k = height
	}
	limit := int(k)
	if len(headers) < limit {
		limit = len(headers)
	}
	timestamps := make([]uint64, limit)
	for i := 0; i < limit; i++ {
		timestamps[i] = headers[len(headers)-1-i].Timestamp
	}
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})
	return timestamps[(len(timestamps)-1)/2], nil
}

func blockExpectedTarget(headers []BlockHeader, height uint64, targetIn [32]byte) ([32]byte, error) {
	if height == 0 {
		return targetIn, nil
	}
	if len(headers) == 0 {
		return [32]byte{}, fmt.Errorf(BLOCK_ERR_TARGET_INVALID)
	}

	targetOld := new(big.Int).SetBytes(headers[len(headers)-1].Target[:])
	if int(height%WINDOW_SIZE) != 0 {
		var target [32]byte
		targetOld.FillBytes(target[:])
		return target, nil
	}

	if len(headers) < WINDOW_SIZE {
		return [32]byte{}, fmt.Errorf(BLOCK_ERR_TARGET_INVALID)
	}

	first := headers[len(headers)-WINDOW_SIZE].Timestamp
	last := headers[len(headers)-1].Timestamp
	tActual := new(big.Int)
	if last >= first {
		tActual.SetUint64(last - first)
	} else {
		tActual.SetInt64(1)
	}

	targetNew := new(big.Int).Mul(targetOld, tActual)
	targetNew.Quo(targetNew, targetBlockIntervalBig)

	minTarget := new(big.Int).Quo(targetOld, big.NewInt(4))
	if minTarget.Sign() == 0 {
		minTarget = big.NewInt(1)
	}
	maxTarget := new(big.Int).Mul(targetOld, big.NewInt(4))

	if targetNew.Cmp(minTarget) < 0 {
		targetNew = minTarget
	}
	if targetNew.Cmp(maxTarget) > 0 {
		targetNew = maxTarget
	}

	var expected [32]byte
	targetNew.FillBytes(expected[:])
	return expected, nil
}

func txSums(tx *Tx, utxo map[TxOutPoint]UtxoEntry) (uint64, uint64, error) {
	var inputSum uint64
	var outputSum uint64
	for _, input := range tx.Inputs {
		prev := TxOutPoint{
			TxID: input.PrevTxid,
			Vout: input.PrevVout,
		}
		entry, ok := utxo[prev]
		if !ok {
			return 0, 0, fmt.Errorf(TX_ERR_MISSING_UTXO)
		}
		var err error
		inputSum, err = addUint64(inputSum, entry.Output.Value)
		if err != nil {
			return 0, 0, err
		}
	}
	for _, output := range tx.Outputs {
		var err error
		outputSum, err = addUint64(outputSum, output.Value)
		if err != nil {
			return 0, 0, err
		}
	}
	return inputSum, outputSum, nil
}

func subUint64(a, b uint64) (uint64, error) {
	if b > a {
		return 0, fmt.Errorf("TX_ERR_VALUE_CONSERVATION")
	}
	return a - b, nil
}

// ApplyBlock validates all block-level consensus rules for block B and mutates utxo on success.
// On error, utxo is not modified.
func ApplyBlock(
	p crypto.CryptoProvider,
	chainID [32]byte,
	block *Block,
	utxo map[TxOutPoint]UtxoEntry,
	ctx BlockValidationContext,
) error {
	if block == nil || len(block.Transactions) == 0 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}

	if ctx.Height > 0 && len(ctx.AncestorHeaders) == 0 {
		return fmt.Errorf(BLOCK_ERR_LINKAGE_INVALID)
	}

	if ctx.Height == 0 {
		var zero [32]byte
		if block.Header.PrevBlockHash != zero {
			return fmt.Errorf(BLOCK_ERR_LINKAGE_INVALID)
		}
	} else {
		parent := ctx.AncestorHeaders[len(ctx.AncestorHeaders)-1]
		if block.Header.PrevBlockHash != blockHeaderHash(p, &parent) {
			return fmt.Errorf(BLOCK_ERR_LINKAGE_INVALID)
		}
	}

	expectedTarget, err := blockExpectedTarget(ctx.AncestorHeaders, ctx.Height, block.Header.Target)
	if err != nil {
		return err
	}
	if !bytes.Equal(block.Header.Target[:], expectedTarget[:]) {
		return fmt.Errorf(BLOCK_ERR_TARGET_INVALID)
	}

	blockHash := blockHeaderHash(p, &block.Header)
	if bytes.Compare(blockHash[:], block.Header.Target[:]) >= 0 {
		return fmt.Errorf(BLOCK_ERR_POW_INVALID)
	}

	headerTxs := make([]*Tx, len(block.Transactions))
	for i := range block.Transactions {
		headerTxs[i] = &block.Transactions[i]
	}
	merkleRoot, err := merkleRootTxIDs(p, headerTxs)
	if err != nil {
		return fmt.Errorf(BLOCK_ERR_MERKLE_INVALID)
	}
	if merkleRoot != block.Header.MerkleRoot {
		return fmt.Errorf(BLOCK_ERR_MERKLE_INVALID)
	}

	if ctx.Height > 0 {
		medianTs, err := medianPastTimestamp(ctx.AncestorHeaders, ctx.Height)
		if err != nil {
			return err
		}
		if block.Header.Timestamp <= medianTs {
			return fmt.Errorf(BLOCK_ERR_TIMESTAMP_OLD)
		}
		if ctx.LocalTimeSet && block.Header.Timestamp > ctx.LocalTime+MAX_FUTURE_DRIFT {
			return fmt.Errorf(BLOCK_ERR_TIMESTAMP_FUTURE)
		}
	}

	coinbaseCount := 0
	for i := range block.Transactions {
		if isCoinbaseTx(&block.Transactions[i], ctx.Height) {
			coinbaseCount++
			if i != 0 {
				return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
			}
		}
	}
	if coinbaseCount != 1 {
		return fmt.Errorf(BLOCK_ERR_COINBASE_INVALID)
	}

	workingUTXO := make(map[TxOutPoint]UtxoEntry, len(utxo))
	for point, entry := range utxo {
		workingUTXO[point] = entry
	}

	var totalWeight uint64
	var totalAnchorBytes uint64
	var totalFees uint64
	seenNonces := make(map[uint64]struct{}, len(block.Transactions))

	for _, tx := range block.Transactions {
		weight, err := TxWeight(&tx)
		if err != nil {
			return err
		}
		totalWeight, err = addUint64(totalWeight, weight)
		if err != nil {
			return err
		}

		isCoinbase := isCoinbaseTx(&tx, ctx.Height)
		if !isCoinbase {
			if _, exists := seenNonces[tx.TxNonce]; exists {
				return fmt.Errorf(TX_ERR_NONCE_REPLAY)
			}
			seenNonces[tx.TxNonce] = struct{}{}
		}

		// HTLC_V2 is VERSION_BITS deployment-gated; wire activation through ctx when deployments are implemented.
		if err := ApplyTx(p, chainID, &tx, workingUTXO, ctx.Height, block.Header.Timestamp, ctx.SuiteIDSLHActive, false); err != nil {
			return err
		}

		if !isCoinbase {
			inputSum, outputSum, err := txSums(&tx, workingUTXO)
			if err != nil {
				return err
			}
			fee, err := subUint64(inputSum, outputSum)
			if err != nil {
				return err
			}
			totalFees, err = addUint64(totalFees, fee)
			if err != nil {
				return err
			}
			for _, input := range tx.Inputs {
				delete(workingUTXO, TxOutPoint{TxID: input.PrevTxid, Vout: input.PrevVout})
			}
		}

			txID := TxID(p, &tx)
			for i, output := range tx.Outputs {
				if output.CovenantType == CORE_ANCHOR {
					totalAnchorBytes, err = addUint64(totalAnchorBytes, uint64(len(output.CovenantData)))
					if err != nil {
						return err
					}
					continue
				}
				workingUTXO[TxOutPoint{TxID: txID, Vout: uint32(i)}] = UtxoEntry{
					Output:            output,
					CreationHeight:    ctx.Height,
					CreatedByCoinbase: isCoinbase,
				}
			}
	}

	if totalWeight > MAX_BLOCK_WEIGHT {
		return fmt.Errorf(BLOCK_ERR_WEIGHT_EXCEEDED)
	}
	if totalAnchorBytes > MAX_ANCHOR_BYTES_PER_BLOCK {
		return fmt.Errorf(BLOCK_ERR_ANCHOR_BYTES_EXCEEDED)
	}

	var coinbaseValue uint64
	for _, output := range block.Transactions[0].Outputs {
		var err error
		coinbaseValue, err = addUint64(coinbaseValue, output.Value)
		if err != nil {
			return err
		}
	}
		maxCoinbase, err := addUint64(blockRewardForHeight(ctx.Height), totalFees)
		if err != nil {
			return err
		}
		if ctx.Height != 0 {
			if coinbaseValue > maxCoinbase {
				return fmt.Errorf(BLOCK_ERR_SUBSIDY_EXCEEDED)
			}
		}

		for prev := range utxo {
			delete(utxo, prev)
		}
	for point, entry := range workingUTXO {
		utxo[point] = entry
	}
	return nil
}

func merkleRootTxIDs(p crypto.CryptoProvider, txs []*Tx) ([32]byte, error) {
	if len(txs) == 0 {
		return [32]byte{}, fmt.Errorf("BLOCK_ERR_MERKLE_INVALID")
	}
	level := make([][32]byte, 0, len(txs))
	for _, tx := range txs {
		// Leaf domain separation (spec §5.1.1): Leaf = SHA3-256(0x00 || txid)
		txid := TxID(p, tx)
		leaf := make([]byte, 0, 1+len(txid))
		leaf = append(leaf, 0x00)
		leaf = append(leaf, txid[:]...)
		level = append(level, p.SHA3_256(leaf))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			concat := make([]byte, 0, 1+len(level[i])+len(level[i+1]))
			concat = append(concat, 0x01)
			concat = append(concat, level[i][:]...)
			concat = append(concat, level[i+1][:]...)
			next = append(next, p.SHA3_256(concat))
		}
		level = next
	}
	return level[0], nil
}

func txidFromTx(p crypto.CryptoProvider, tx *Tx) [32]byte {
	return TxID(p, tx)
}

func TxID(p crypto.CryptoProvider, tx *Tx) [32]byte {
	return p.SHA3_256(TxNoWitnessBytes(tx))
}

func addUint64(a, b uint64) (uint64, error) {
	if b > (^uint64(0) - a) {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	return a + b, nil
}

func SighashV1Digest(
	p crypto.CryptoProvider,
	chainID [32]byte,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
) ([32]byte, error) {
	inputIndexInt, err := u32ToInt(inputIndex, "input_index", len(tx.Inputs))
	if err != nil {
		return [32]byte{}, err
	}
	if uint64(inputIndex) >= uint64(len(tx.Inputs)) {
		return [32]byte{}, fmt.Errorf("sighash: input_index out of bounds")
	}

	prevouts := make([]byte, 0, len(tx.Inputs)*(32+4))
	var tmp4 [4]byte
	for _, in := range tx.Inputs {
		prevouts = append(prevouts, in.PrevTxid[:]...)
		binary.LittleEndian.PutUint32(tmp4[:], in.PrevVout)
		prevouts = append(prevouts, tmp4[:]...)
	}
	hashPrevouts := p.SHA3_256(prevouts)

	sequences := make([]byte, 0, len(tx.Inputs)*4)
	for _, in := range tx.Inputs {
		binary.LittleEndian.PutUint32(tmp4[:], in.Sequence)
		sequences = append(sequences, tmp4[:]...)
	}
	hashSequences := p.SHA3_256(sequences)

	outputsBytes := make([]byte, 0)
	for _, o := range tx.Outputs {
		outputsBytes = append(outputsBytes, TxOutputBytes(o)...)
	}
	hashOutputs := p.SHA3_256(outputsBytes)

	in := tx.Inputs[inputIndexInt]

	preimage := make([]byte, 0, 14+32+4+8+32+32+4+32+4+8+4+32+4)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)

	binary.LittleEndian.PutUint32(tmp4[:], tx.Version)
	preimage = append(preimage, tmp4[:]...)

	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], tx.TxNonce)
	preimage = append(preimage, tmp8[:]...)

	preimage = append(preimage, hashPrevouts[:]...)
	preimage = append(preimage, hashSequences[:]...)

	binary.LittleEndian.PutUint32(tmp4[:], inputIndex)
	preimage = append(preimage, tmp4[:]...)

	preimage = append(preimage, in.PrevTxid[:]...)
	binary.LittleEndian.PutUint32(tmp4[:], in.PrevVout)
	preimage = append(preimage, tmp4[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], inputValue)
	preimage = append(preimage, tmp8[:]...)
	binary.LittleEndian.PutUint32(tmp4[:], in.Sequence)
	preimage = append(preimage, tmp4[:]...)

	preimage = append(preimage, hashOutputs[:]...)

	binary.LittleEndian.PutUint32(tmp4[:], tx.Locktime)
	preimage = append(preimage, tmp4[:]...)

	return p.SHA3_256(preimage), nil
}

func parseU64LE(v []byte, start int, name string) (uint64, error) {
	if start+8 > len(v) {
		return 0, fmt.Errorf("parse: %s truncated", name)
	}
	var tmp [8]byte
	copy(tmp[:], v[start:start+8])
	return binary.LittleEndian.Uint64(tmp[:]), nil
}

func isZeroOutPoint(prevout TxOutPoint) bool {
	return prevout.TxID == ([32]byte{}) && prevout.Vout == TX_COINBASE_PREVOUT_VOUT
}

func isCoinbaseTx(tx *Tx, blockHeight uint64) bool {
	if tx == nil {
		return false
	}
	if len(tx.Inputs) != 1 {
		return false
	}
	if uint64(tx.Locktime) != blockHeight {
		return false
	}
	if tx.TxNonce != 0 {
		return false
	}
	if len(tx.Witness.Witnesses) != 0 {
		return false
	}
	txin := tx.Inputs[0]
	return isZeroOutPoint(TxOutPoint{TxID: txin.PrevTxid, Vout: txin.PrevVout}) &&
		txin.Sequence == TX_COINBASE_PREVOUT_VOUT &&
		len(txin.ScriptSig) == 0
}

func validateOutputCovenantConstraints(output TxOutput) error {
	switch output.CovenantType {
	case CORE_P2PK:
		if len(output.CovenantData) != 33 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_TIMELOCK_V1:
		if len(output.CovenantData) != 9 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_ANCHOR:
		if output.Value != 0 {
			return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
		}
		if len(output.CovenantData) == 0 || len(output.CovenantData) > MAX_ANCHOR_PAYLOAD_SIZE {
			return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
		}
	case CORE_HTLC_V1:
		if len(output.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_HTLC_V2:
		// Deployment gate checked at spend time, not output creation time.
		// Output-level constraint: same covenant_data layout as HTLC_V1.
		if len(output.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		claimKeyID := output.CovenantData[41:73]
		refundKeyID := output.CovenantData[73:105]
		if bytes.Equal(claimKeyID, refundKeyID) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_VAULT_V1:
		if len(output.CovenantData) != 73 && len(output.CovenantData) != 81 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_RESERVED_FUTURE:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	default:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	}
	return nil
}

func validateCoinbaseTxInputs(tx *Tx) error {
	if tx.TxNonce != 0 {
		return fmt.Errorf("TX_ERR_COINBASE_INVALID")
	}
	if len(tx.Inputs) != 1 {
		return fmt.Errorf("TX_ERR_COINBASE_INVALID")
	}
	in := tx.Inputs[0]
	if in.Sequence != TX_COINBASE_PREVOUT_VOUT {
		return fmt.Errorf("TX_ERR_COINBASE_INVALID")
	}
	if in.PrevTxid != ([32]byte{}) || in.PrevVout != TX_COINBASE_PREVOUT_VOUT {
		return fmt.Errorf("TX_ERR_COINBASE_INVALID")
	}
	if len(in.ScriptSig) != 0 {
		return fmt.Errorf("TX_ERR_COINBASE_INVALID")
	}
	if len(tx.Witness.Witnesses) != 0 {
		return fmt.Errorf("TX_ERR_COINBASE_INVALID")
	}
	return nil
}

func isScriptSigZeroLen(itemName string, scriptSigLen int) error {
	if scriptSigLen != 0 {
		return fmt.Errorf("parse: %s script_sig must be empty", itemName)
	}
	return nil
}

func validateHTLCScriptSigLen(scriptSigLen int) error {
	switch scriptSigLen {
	case 0, 32:
		return nil
	default:
		return fmt.Errorf("TX_ERR_PARSE")
	}
}

func ApplyTx(
	p crypto.CryptoProvider,
	chainID [32]byte,
	tx *Tx,
	utxo map[TxOutPoint]UtxoEntry,
	chainHeight uint64,
	chainTimestamp uint64,
	suiteIDSLHActive bool,
	htlcV2Active bool,
) error {
	if tx == nil {
		return fmt.Errorf("TX_ERR_PARSE")
	}

	if len(tx.Inputs) > MAX_TX_INPUTS || len(tx.Outputs) > MAX_TX_OUTPUTS {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if len(tx.Witness.Witnesses) > MAX_WITNESS_ITEMS {
		return fmt.Errorf(TX_ERR_WITNESS_OVERFLOW)
	}
	if len(WitnessBytes(tx.Witness)) > MAX_WITNESS_BYTES_PER_TX {
		return fmt.Errorf(TX_ERR_WITNESS_OVERFLOW)
	}

	if isCoinbaseTx(tx, chainHeight) {
		if err := validateCoinbaseTxInputs(tx); err != nil {
			return err
		}
		for _, output := range tx.Outputs {
			if err := validateOutputCovenantConstraints(output); err != nil {
				return err
			}
		}
		return nil
	}

	if tx.TxNonce == TX_NONCE_ZERO {
		return fmt.Errorf(TX_ERR_TX_NONCE_INVALID)
	}
	if len(tx.Inputs) != len(tx.Witness.Witnesses) {
		return fmt.Errorf("TX_ERR_PARSE")
	}

	for _, output := range tx.Outputs {
		if err := validateOutputCovenantConstraints(output); err != nil {
			return err
		}
	}

	seen := make(map[TxOutPoint]struct{}, len(tx.Inputs))
	var totalInputs uint64
	var totalOutputs uint64

	for i, input := range tx.Inputs {
		if input.Sequence == TX_COINBASE_PREVOUT_VOUT || input.Sequence > TX_MAX_SEQUENCE {
			return fmt.Errorf(TX_ERR_SEQUENCE_INVALID)
		}

		prevout := TxOutPoint{
			TxID: input.PrevTxid,
			Vout: input.PrevVout,
		}
		if isZeroOutPoint(prevout) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if _, dup := seen[prevout]; dup {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		seen[prevout] = struct{}{}

		prevEntry, ok := utxo[prevout]
		if !ok {
			return fmt.Errorf("TX_ERR_MISSING_UTXO")
		}
		if err := ValidateInputAuthorization(
			p,
			chainID,
			tx,
			uint32(i),
			prevEntry.Output.Value,
			&prevEntry.Output,
			prevEntry.CreationHeight,
			chainHeight,
			chainTimestamp,
			suiteIDSLHActive,
			htlcV2Active,
		); err != nil {
			return err
		}
		if prevEntry.CreatedByCoinbase && chainHeight < prevEntry.CreationHeight+COINBASE_MATURITY {
			return fmt.Errorf(TX_ERR_COINBASE_IMMATURE)
		}

		var sumErr error
		totalInputs, sumErr = addUint64(totalInputs, prevEntry.Output.Value)
		if sumErr != nil {
			return sumErr
		}
	}

	for _, output := range tx.Outputs {
		var sumErr error
		totalOutputs, sumErr = addUint64(totalOutputs, output.Value)
		if sumErr != nil {
			return sumErr
		}
	}
	if totalOutputs > totalInputs {
		return fmt.Errorf("TX_ERR_VALUE_CONSERVATION")
	}
	return nil
}

func checkWitnessFormat(item WitnessItem, suiteIDSLHActive bool) error {
	switch item.SuiteID {
	case SUITE_ID_SENTINEL:
		if len(item.Pubkey) != 0 || len(item.Signature) != 0 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		return nil
	case SUITE_ID_ML_DSA:
		if len(item.Pubkey) != ML_DSA_PUBKEY_BYTES || len(item.Signature) != ML_DSA_SIG_BYTES {
			return fmt.Errorf("TX_ERR_SIG_NONCANONICAL")
		}
		return nil
	case SUITE_ID_SLH_DSA:
		if !suiteIDSLHActive {
			return fmt.Errorf("TX_ERR_DEPLOYMENT_INACTIVE")
		}
		if len(item.Pubkey) != SLH_DSA_PUBKEY_BYTES || len(item.Signature) == 0 || len(item.Signature) > SLH_DSA_SIG_MAX_BYTES {
			return fmt.Errorf("TX_ERR_SIG_NONCANONICAL")
		}
		return nil
	default:
		return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
	}
}

func satisfyLock(lockMode byte, lockValue, height, timestamp uint64) error {
	switch lockMode {
	case TIMELOCK_MODE_HEIGHT:
		if height >= lockValue {
			return nil
		}
		return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
	case TIMELOCK_MODE_TIMESTAMP:
		if timestamp >= lockValue {
			return nil
		}
		return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
	default:
		return fmt.Errorf("TX_ERR_PARSE")
	}
}

func ValidateInputAuthorization(
	p crypto.CryptoProvider,
	chainID [32]byte,
	tx *Tx,
	inputIndex uint32,
	prevValue uint64,
	prevout *TxOutput,
	prevCreationHeight uint64,
	chainHeight uint64,
	chainTimestamp uint64,
	suiteIDSLHActive bool,
	htlcV2Active bool,
) error {
	if int(inputIndex) >= len(tx.Inputs) {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if int(inputIndex) >= len(tx.Witness.Witnesses) {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if prevout == nil {
		return fmt.Errorf("TX_ERR_PARSE")
	}

	inputIndexInt, err := u32ToInt(inputIndex, "input_index", len(tx.Inputs))
	if err != nil {
		return err
	}
	input := tx.Inputs[inputIndexInt]
	witness := tx.Witness.Witnesses[inputIndexInt]

	switch prevout.CovenantType {
	case CORE_P2PK:
		if err := isScriptSigZeroLen("CORE_P2PK", len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}

		if len(prevout.CovenantData) != 33 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		suiteID := prevout.CovenantData[0]
		if suiteID != witness.SuiteID {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
		actualKeyID := p.SHA3_256(witness.Pubkey)
		if expected := prevout.CovenantData[1:33]; !bytes.Equal(actualKeyID[:], expected) {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
	case CORE_TIMELOCK_V1:
		if err := isScriptSigZeroLen("CORE_TIMELOCK_V1", len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID != SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if len(prevout.CovenantData) != 9 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		lockMode := prevout.CovenantData[0]
		lockValue, err := parseU64LE(prevout.CovenantData, 1, "covenant_lock_value")
		if err != nil {
			return err
		}
		if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
			return err
		}
	case CORE_HTLC_V1:
		if err := validateHTLCScriptSigLen(len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		if len(prevout.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		lockMode := prevout.CovenantData[32]
		lockValue, err := parseU64LE(prevout.CovenantData, 33, "htlc_lock_value")
		if err != nil {
			return err
		}
		if len(input.ScriptSig) == 32 {
			expectedHash := prevout.CovenantData[:32]
			scriptHash := p.SHA3_256(input.ScriptSig)
			if !bytes.Equal(scriptHash[:], expectedHash) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			expectedClaimKeyID := prevout.CovenantData[41:73]
			actualKeyID := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID[:], expectedClaimKeyID) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
		} else {
			expectedRefundKeyID := prevout.CovenantData[73:105]
			actualKeyID := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID[:], expectedRefundKeyID) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
				return err
			}
		}
	case CORE_VAULT_V1:
		if err := isScriptSigZeroLen("CORE_VAULT_V1", len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		var ownerKeyID []byte
		var recoveryKeyID []byte
		var spendDelay uint64
		var lockMode byte
		var lockValue uint64
		switch len(prevout.CovenantData) {
		case 73:
			ownerKeyID = prevout.CovenantData[:32]
			spendDelay = 0
			lockMode = prevout.CovenantData[32]
			var err error
			lockValue, err = parseU64LE(prevout.CovenantData, 33, "vault_lock_value")
			if err != nil {
				return err
			}
			recoveryKeyID = prevout.CovenantData[41:73]
		case 81:
			ownerKeyID = prevout.CovenantData[:32]
			var err error
			spendDelay, err = parseU64LE(prevout.CovenantData, 32, "vault_spend_delay")
			if err != nil {
				return err
			}
			lockMode = prevout.CovenantData[40]
			lockValue, err = parseU64LE(prevout.CovenantData, 41, "vault_lock_value")
			if err != nil {
				return err
			}
			recoveryKeyID = prevout.CovenantData[49:81]
		default:
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if lockMode != TIMELOCK_MODE_HEIGHT && lockMode != TIMELOCK_MODE_TIMESTAMP {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if bytes.Equal(ownerKeyID, recoveryKeyID) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		actualKeyID := p.SHA3_256(witness.Pubkey)
		if !bytes.Equal(actualKeyID[:], ownerKeyID) && !bytes.Equal(actualKeyID[:], recoveryKeyID) {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
		if bytes.Equal(actualKeyID[:], ownerKeyID) && spendDelay > 0 {
			if chainHeight < prevCreationHeight+spendDelay {
				return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
			}
		}
		if bytes.Equal(actualKeyID[:], recoveryKeyID) {
			if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
				return err
			}
		}
	case CORE_HTLC_V2:
		// Deployment gate
		if !htlcV2Active {
			return fmt.Errorf("TX_ERR_DEPLOYMENT_INACTIVE")
		}
		if len(input.ScriptSig) != 0 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		if witness.SuiteID == SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		if len(prevout.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		claimKeyID2 := prevout.CovenantData[41:73]
		refundKeyID2 := prevout.CovenantData[73:105]
		if bytes.Equal(claimKeyID2, refundKeyID2) {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		hash2 := prevout.CovenantData[:32]
		lockMode2 := prevout.CovenantData[32]
		lockValue2, err := parseU64LE(prevout.CovenantData, 33, "htlc2_lock_value")
		if err != nil {
			return err
		}
		// Scan ANCHOR outputs for matching HTLC_V2 envelope
		// prefix = ASCII("RUBINv1-htlc-preimage/") — 22 bytes, total envelope = 54 bytes
		const htlcV2Prefix = "RUBINv1-htlc-preimage/"
		const htlcV2EnvelopeLen = 54
		var matchingAnchors [][]byte
		for _, out := range tx.Outputs {
			if out.CovenantType == CORE_ANCHOR &&
				len(out.CovenantData) == htlcV2EnvelopeLen &&
				string(out.CovenantData[:len(htlcV2Prefix)]) == htlcV2Prefix {
				matchingAnchors = append(matchingAnchors, out.CovenantData)
			}
		}
		switch len(matchingAnchors) {
		case 0:
			// Refund path
			actualKeyID2 := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID2[:], refundKeyID2) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			if err := satisfyLock(lockMode2, lockValue2, chainHeight, chainTimestamp); err != nil {
				return err
			}
		case 1:
			// Claim path
			preimage32 := matchingAnchors[0][len(htlcV2Prefix):]
			preimageHash := p.SHA3_256(preimage32)
			if !bytes.Equal(preimageHash[:], hash2) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			actualKeyID2 := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID2[:], claimKeyID2) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
		default:
			// Two or more matching envelopes — non-deterministic, reject
			return fmt.Errorf("TX_ERR_PARSE")
		}
	case CORE_ANCHOR:
		return fmt.Errorf("TX_ERR_MISSING_UTXO")
	case CORE_RESERVED_FUTURE:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	default:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	}

	digest, err := SighashV1Digest(p, chainID, tx, inputIndex, prevValue)
	if err != nil {
		return err
	}

	switch witness.SuiteID {
	case SUITE_ID_ML_DSA:
		if p.VerifyMLDSA87(witness.Pubkey, witness.Signature, digest) {
			return nil
		}
		return fmt.Errorf("TX_ERR_SIG_INVALID")
	case SUITE_ID_SLH_DSA:
		if p.VerifySLHDSASHAKE_256f(witness.Pubkey, witness.Signature, digest) {
			return nil
		}
		return fmt.Errorf("TX_ERR_SIG_INVALID")
	case SUITE_ID_SENTINEL:
		// Timelock-only covenants are already validated above.
		return nil
	default:
		return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
	}
}

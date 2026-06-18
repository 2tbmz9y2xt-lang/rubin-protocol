package consensus

import (
	"encoding/binary"
	"math"
)

type Tx struct {
	DaCommitCore *DaCommitCore
	DaChunkCore  *DaChunkCore
	Inputs       []TxInput
	Outputs      []TxOutput
	Witness      []WitnessItem
	DaPayload    []byte
	TxNonce      uint64
	Version      uint32
	Locktime     uint32
	TxKind       uint8
}

type TxInput struct {
	ScriptSig []byte
	PrevVout  uint32
	Sequence  uint32
	PrevTxid  [32]byte
}

type TxOutput struct {
	CovenantData []byte
	Value        uint64
	CovenantType uint16
}

type WitnessItem struct {
	Pubkey    []byte
	Signature []byte
	SuiteID   uint8
}

type DaCommitCore struct {
	BatchSig        []byte
	BatchNumber     uint64
	ChunkCount      uint16
	DaID            [32]byte
	RetlDomainID    [32]byte
	TxDataRoot      [32]byte
	StateRoot       [32]byte
	WithdrawalsRoot [32]byte
	BatchSigSuite   uint8
}

type DaChunkCore struct {
	DaID       [32]byte
	ChunkIndex uint16
	ChunkHash  [32]byte
}

func ParseTx(b []byte) (*Tx, [32]byte, [32]byte, int, error) {
	var zero [32]byte
	off := 0

	version, txKind, txNonce, err := parseTxHeader(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	inputs, err := parseTxInputs(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	outputs, err := parseTxOutputs(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	locktime, err := readU32le(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	daCommitCore, daChunkCore, err := parseTxDaCore(b, &off, txKind)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	coreEnd := off

	witness, err := parseTxWitness(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	daPayload, err := parseTxDaPayload(b, &off, txKind)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	tx := &Tx{
		Version: version, TxKind: txKind, TxNonce: txNonce,
		Inputs: inputs, Outputs: outputs, Locktime: locktime,
		DaCommitCore: daCommitCore, DaChunkCore: daChunkCore,
		Witness: witness, DaPayload: daPayload,
	}

	txid := sha3_256(b[:coreEnd])
	wtxid := sha3_256(b[:off])
	return tx, txid, wtxid, off, nil
}

func parseTxHeader(b []byte, off *int) (uint32, uint8, uint64, error) {
	version, err := readU32le(b, off)
	if err != nil {
		return 0, 0, 0, err
	}
	if version != TX_WIRE_VERSION {
		return 0, 0, 0, txerr(TX_ERR_PARSE, "unsupported tx version")
	}

	txKind, err := readU8(b, off)
	if err != nil {
		return 0, 0, 0, err
	}
	switch txKind {
	case 0x00, 0x01, 0x02:
	default:
		return 0, 0, 0, txerr(TX_ERR_PARSE, "unsupported tx_kind")
	}

	txNonce, err := readU64le(b, off)
	if err != nil {
		return 0, 0, 0, err
	}
	return version, txKind, txNonce, nil
}

func parseTxInputs(b []byte, off *int) ([]TxInput, error) {
	inCountU64, _, err := readCompactSize(b, off)
	if err != nil {
		return nil, err
	}
	if inCountU64 > MAX_TX_INPUTS {
		return nil, txerr(TX_ERR_PARSE, "input_count overflow")
	}
	inCount := int(inCountU64)

	inputs := make([]TxInput, 0, inCount)
	for i := 0; i < inCount; i++ {
		input, err := parseTxInput(b, off)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}

func parseTxInput(b []byte, off *int) (TxInput, error) {
	prevTxid, err := readHash32(b, off)
	if err != nil {
		return TxInput{}, err
	}

	prevVout, err := readU32le(b, off)
	if err != nil {
		return TxInput{}, err
	}

	scriptSigLenU64, _, err := readCompactSize(b, off)
	if err != nil {
		return TxInput{}, err
	}
	if scriptSigLenU64 > MAX_SCRIPT_SIG_BYTES {
		return TxInput{}, txerr(TX_ERR_PARSE, "script_sig_len overflow")
	}
	scriptSig, err := readBytes(b, off, int(scriptSigLenU64))
	if err != nil {
		return TxInput{}, err
	}

	sequence, err := readU32le(b, off)
	if err != nil {
		return TxInput{}, err
	}

	return TxInput{PrevTxid: prevTxid, PrevVout: prevVout, ScriptSig: scriptSig, Sequence: sequence}, nil
}

func parseTxOutputs(b []byte, off *int) ([]TxOutput, error) {
	outCountU64, _, err := readCompactSize(b, off)
	if err != nil {
		return nil, err
	}
	if outCountU64 > MAX_TX_OUTPUTS {
		return nil, txerr(TX_ERR_PARSE, "output_count overflow")
	}
	outCount := int(outCountU64)

	outputs := make([]TxOutput, 0, outCount)
	for i := 0; i < outCount; i++ {
		output, err := parseTxOutput(b, off)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}

func parseTxOutput(b []byte, off *int) (TxOutput, error) {
	value, err := readU64le(b, off)
	if err != nil {
		return TxOutput{}, err
	}

	covType, err := readU16le(b, off)
	if err != nil {
		return TxOutput{}, err
	}

	covLenU64, _, err := readCompactSize(b, off)
	if err != nil {
		return TxOutput{}, err
	}
	if covLenU64 > uint64(math.MaxInt) {
		return TxOutput{}, txerr(TX_ERR_PARSE, "covenant_data_len overflows int")
	}
	if covLenU64 > MAX_COVENANT_DATA_PER_OUTPUT {
		return TxOutput{}, txerr(TX_ERR_PARSE, "covenant_data_len exceeds MAX_COVENANT_DATA_PER_OUTPUT")
	}
	covData, err := readBytes(b, off, int(covLenU64))
	if err != nil {
		return TxOutput{}, err
	}

	return TxOutput{Value: value, CovenantType: covType, CovenantData: covData}, nil
}

func parseTxDaCore(b []byte, off *int, txKind uint8) (*DaCommitCore, *DaChunkCore, error) {
	switch txKind {
	case 0x00:
		return nil, nil, nil
	case 0x01:
		daCommitCore, err := parseTxDaCommitCore(b, off)
		return daCommitCore, nil, err
	case 0x02:
		daChunkCore, err := parseTxDaChunkCore(b, off)
		return nil, daChunkCore, err
	default:
		return nil, nil, txerr(TX_ERR_PARSE, "unsupported tx_kind")
	}
}

func parseTxDaCommitCore(b []byte, off *int) (*DaCommitCore, error) {
	daID, err := readHash32(b, off)
	if err != nil {
		return nil, err
	}

	chunkCount, err := readU16le(b, off)
	if err != nil {
		return nil, err
	}
	if invalidDaCommitChunkCount(chunkCount) {
		return nil, txerr(TX_ERR_PARSE, "chunk_count out of range for tx_kind=0x01")
	}

	retlDomainID, err := readHash32(b, off)
	if err != nil {
		return nil, err
	}
	batchNumber, err := readU64le(b, off)
	if err != nil {
		return nil, err
	}
	txDataRoot, stateRoot, withdrawalsRoot, batchSigSuite, batchSig, err := parseDaCommitTail(b, off)
	if err != nil {
		return nil, err
	}

	return &DaCommitCore{
		DaID: daID, ChunkCount: chunkCount, RetlDomainID: retlDomainID,
		BatchNumber: batchNumber, TxDataRoot: txDataRoot, StateRoot: stateRoot,
		WithdrawalsRoot: withdrawalsRoot, BatchSigSuite: batchSigSuite, BatchSig: batchSig,
	}, nil
}

func invalidDaCommitChunkCount(chunkCount uint16) bool {
	return chunkCount == 0 || uint64(chunkCount) > MAX_DA_CHUNK_COUNT
}

func parseDaCommitTail(b []byte, off *int) ([32]byte, [32]byte, [32]byte, uint8, []byte, error) {
	txDataRoot, err := readHash32(b, off)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, 0, nil, err
	}
	stateRoot, err := readHash32(b, off)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, 0, nil, err
	}
	withdrawalsRoot, err := readHash32(b, off)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, 0, nil, err
	}
	batchSigSuite, err := readU8(b, off)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, 0, nil, err
	}
	batchSigLenU64, _, err := readCompactSize(b, off)
	if err != nil {
		return [32]byte{}, [32]byte{}, [32]byte{}, 0, nil, err
	}
	if batchSigLenU64 > MAX_DA_MANIFEST_BYTES_PER_TX {
		return [32]byte{}, [32]byte{}, [32]byte{}, 0, nil, txerr(TX_ERR_PARSE, "batch_sig_len overflow")
	}
	batchSig, err := readBytes(b, off, int(batchSigLenU64))
	return txDataRoot, stateRoot, withdrawalsRoot, batchSigSuite, batchSig, err
}

func parseTxDaChunkCore(b []byte, off *int) (*DaChunkCore, error) {
	daID, err := readHash32(b, off)
	if err != nil {
		return nil, err
	}
	chunkIndex, err := readU16le(b, off)
	if err != nil {
		return nil, err
	}
	if uint64(chunkIndex) >= MAX_DA_CHUNK_COUNT {
		return nil, txerr(TX_ERR_PARSE, "chunk_index out of range for tx_kind=0x02")
	}
	chunkHash, err := readHash32(b, off)
	if err != nil {
		return nil, err
	}
	return &DaChunkCore{DaID: daID, ChunkIndex: chunkIndex, ChunkHash: chunkHash}, nil
}

func parseTxWitness(b []byte, off *int) ([]WitnessItem, error) {
	witnessCountU64, witnessCountVarintBytes, err := readCompactSize(b, off)
	if err != nil {
		return nil, err
	}
	if witnessCountU64 > MAX_WITNESS_ITEMS {
		return nil, txerr(TX_ERR_WITNESS_OVERFLOW, "witness_count overflow")
	}
	witnessCount := int(witnessCountU64)

	witnessBytes := witnessCountVarintBytes
	witness := make([]WitnessItem, 0, witnessCount)

	for i := 0; i < witnessCount; i++ {
		item, pubLen, sigLen, itemBytes, err := parseWitnessItemFields(b, off)
		if err != nil {
			return nil, err
		}
		witnessBytes += itemBytes
		if witnessBytes > MAX_WITNESS_BYTES_PER_TX {
			return nil, txerr(TX_ERR_WITNESS_OVERFLOW, "witness bytes overflow")
		}
		if err := validateWitnessItemLengths(item, pubLen, sigLen); err != nil {
			return nil, err
		}
		witness = append(witness, item)
	}
	return witness, nil
}

func parseWitnessItemFields(b []byte, off *int) (WitnessItem, int, int, int, error) {
	suiteID, err := readU8(b, off)
	if err != nil {
		return WitnessItem{}, 0, 0, 0, err
	}

	pubkey, pubLen, pubBytes, err := parseWitnessBytes(b, off, "pubkey_length overflows int")
	if err != nil {
		return WitnessItem{}, 0, 0, 0, err
	}
	sig, sigLen, sigBytes, err := parseWitnessBytes(b, off, "sig_length overflows int")
	if err != nil {
		return WitnessItem{}, 0, 0, 0, err
	}
	if suiteID != SUITE_ID_SENTINEL && sigLen == 0 {
		return WitnessItem{}, 0, 0, 0, txerr(TX_ERR_PARSE, "missing sighash_type byte")
	}

	item := WitnessItem{SuiteID: suiteID, Pubkey: pubkey, Signature: sig}
	return item, pubLen, sigLen, 1 + pubBytes + sigBytes, nil
}

func parseWitnessBytes(b []byte, off *int, overflowMsg string) ([]byte, int, int, error) {
	lenU64, varintBytes, err := readCompactSize(b, off)
	if err != nil {
		return nil, 0, 0, err
	}
	if lenU64 > uint64(math.MaxInt) {
		return nil, 0, 0, txerr(TX_ERR_PARSE, overflowMsg)
	}
	fieldLen := int(lenU64)
	field, err := readBytes(b, off, fieldLen)
	if err != nil {
		return nil, 0, 0, err
	}
	return field, fieldLen, varintBytes + fieldLen, nil
}

func validateWitnessItemLengths(item WitnessItem, pubLen int, sigLen int) error {
	switch item.SuiteID {
	case SUITE_ID_SENTINEL:
		if !isCanonicalSentinelWitnessItem(pubLen, item.Signature) {
			return txerr(TX_ERR_PARSE, "non-canonical sentinel witness item")
		}
	case SUITE_ID_ML_DSA_87:
		if pubLen != ML_DSA_87_PUBKEY_BYTES || sigLen != ML_DSA_87_SIG_BYTES+1 {
			return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA witness item lengths")
		}
	case SUITE_ID_SIMPLICITY_ENVELOPE:
		if pubLen != 0 {
			return txerr(TX_ERR_PARSE, "non-canonical Simplicity envelope witness item")
		}
		if err := validateSimplicityEnvelopeSignature(item.Signature); err != nil {
			return err
		}
	default:
		// Unknown suites are accepted at parse stage (CANONICAL §12.2 / CV-SIG-05).
		// Semantic suite authorization is enforced at the spend path.
	}
	return nil
}

type parsedSimplicityEnvelope struct {
	program []byte
	witness []byte
}

func parseSimplicityEnvelopeSignature(sig []byte) (parsedSimplicityEnvelope, error) {
	var parsed parsedSimplicityEnvelope
	if len(sig) < 2 {
		return parsed, txerr(TX_ERR_PARSE, "non-canonical Simplicity envelope witness item")
	}
	envelope, _, err := extractCryptoSigAndSighash(WitnessItem{Signature: sig})
	if err != nil {
		return parsed, err
	}
	if len(envelope) > MAX_SIMPLICITY_ENVELOPE_BYTES {
		return parsed, txerr(TX_ERR_PARSE, "Simplicity envelope too large")
	}
	off := 0

	version, err := readU8(envelope, &off)
	if err != nil {
		return parsed, err
	}
	if version != 0x01 {
		return parsed, txerr(TX_ERR_PARSE, "non-canonical Simplicity envelope witness item")
	}
	programLenU64, _, err := readCompactSize(envelope, &off)
	if err != nil {
		return parsed, err
	}
	if programLenU64 > MAX_SIMPLICITY_PROGRAM_BYTES {
		return parsed, txerr(TX_ERR_PARSE, "Simplicity program too large")
	}
	if programLenU64 > uint64(math.MaxInt) {
		return parsed, txerr(TX_ERR_PARSE, "Simplicity program_len overflows int")
	}
	program, err := readBytes(envelope, &off, int(programLenU64))
	if err != nil {
		return parsed, err
	}
	witnessLenU64, _, err := readCompactSize(envelope, &off)
	if err != nil {
		return parsed, err
	}
	if witnessLenU64 > uint64(math.MaxInt) {
		return parsed, txerr(TX_ERR_PARSE, "Simplicity witness_len overflows int")
	}
	witness, err := readBytes(envelope, &off, int(witnessLenU64))
	if err != nil {
		return parsed, err
	}
	if off != len(envelope) {
		return parsed, txerr(TX_ERR_PARSE, "non-canonical Simplicity envelope witness item")
	}
	parsed.program = program
	parsed.witness = witness
	return parsed, nil
}

func validateSimplicityEnvelopeSignature(sig []byte) error {
	_, err := parseSimplicityEnvelopeSignature(sig)
	return err
}

func isCanonicalSentinelWitnessItem(pubLen int, sig []byte) bool {
	if pubLen == 0 {
		return len(sig) == 0
	}
	if pubLen != 32 {
		return false
	}
	if len(sig) == 1 {
		return sig[0] == 0x01
	}
	if len(sig) < 3 {
		return false
	}
	if sig[0] != 0x00 {
		return false
	}
	preLen := int(binary.LittleEndian.Uint16(sig[1:3]))
	if preLen < MIN_HTLC_PREIMAGE_BYTES || preLen > MAX_HTLC_PREIMAGE_BYTES {
		return false
	}
	return len(sig) == 3+preLen
}

func parseTxDaPayload(b []byte, off *int, txKind uint8) ([]byte, error) {
	daLenU64, _, err := readCompactSize(b, off)
	if err != nil {
		return nil, err
	}
	switch txKind {
	case 0x00:
		if daLenU64 != 0 {
			return nil, txerr(TX_ERR_PARSE, "da_payload_len must be 0 for tx_kind=0x00")
		}
		return nil, nil
	case 0x01:
		return readDaPayloadBytes(b, off, daLenU64, MAX_DA_MANIFEST_BYTES_PER_TX, true, "da_payload_len out of range for tx_kind=0x01")
	case 0x02:
		return readDaPayloadBytes(b, off, daLenU64, CHUNK_BYTES, false, "da_payload_len out of range for tx_kind=0x02")
	default:
		return nil, txerr(TX_ERR_PARSE, "unsupported tx_kind")
	}
}

func readDaPayloadBytes(b []byte, off *int, daLenU64 uint64, maxLen uint64, allowEmpty bool, overflowMsg string) ([]byte, error) {
	if daLenU64 > maxLen {
		return nil, txerr(TX_ERR_PARSE, overflowMsg)
	}
	if daLenU64 == 0 {
		if !allowEmpty {
			return nil, txerr(TX_ERR_PARSE, overflowMsg)
		}
		return nil, nil
	}
	return readBytes(b, off, int(daLenU64))
}

func readHash32(b []byte, off *int) ([32]byte, error) {
	hashBytes, err := readBytes(b, off, 32)
	var hash [32]byte
	copy(hash[:], hashBytes)
	return hash, err
}

func daCoreFieldsBytes(tx *Tx) ([]byte, error) {
	if tx == nil {
		return nil, txerr(TX_ERR_PARSE, "nil tx")
	}
	switch tx.TxKind {
	case 0x00:
		return nil, nil
	case 0x01:
		if tx.DaCommitCore == nil {
			return nil, txerr(TX_ERR_PARSE, "missing da_commit_core for tx_kind=0x01")
		}
		core := tx.DaCommitCore
		out := make([]byte, 0, 32+2+32+8+32+32+32+1+9+len(core.BatchSig))
		out = append(out, core.DaID[:]...)
		out = AppendU16le(out, core.ChunkCount)
		out = append(out, core.RetlDomainID[:]...)
		out = AppendU64le(out, core.BatchNumber)
		out = append(out, core.TxDataRoot[:]...)
		out = append(out, core.StateRoot[:]...)
		out = append(out, core.WithdrawalsRoot[:]...)
		out = append(out, core.BatchSigSuite)
		out = AppendCompactSize(out, uint64(len(core.BatchSig)))
		out = append(out, core.BatchSig...)
		return out, nil
	case 0x02:
		if tx.DaChunkCore == nil {
			return nil, txerr(TX_ERR_PARSE, "missing da_chunk_core for tx_kind=0x02")
		}
		core := tx.DaChunkCore
		out := make([]byte, 0, 32+2+32)
		out = append(out, core.DaID[:]...)
		out = AppendU16le(out, core.ChunkIndex)
		out = append(out, core.ChunkHash[:]...)
		return out, nil
	default:
		return nil, txerr(TX_ERR_PARSE, "unsupported tx_kind")
	}
}

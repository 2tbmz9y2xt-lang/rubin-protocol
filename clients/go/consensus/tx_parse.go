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

	version, err := readU32le(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	txKind, err := readU8(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	switch txKind {
	case 0x00, 0x01, 0x02:
	default:
		return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "unsupported tx_kind")
	}

	txNonce, err := readU64le(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}

	inCountU64, _, err := readCompactSize(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	if inCountU64 > MAX_TX_INPUTS {
		return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "input_count overflow")
	}
	inCount := int(inCountU64)

	inputs := make([]TxInput, 0, inCount)
	for i := 0; i < inCount; i++ {
		prevTxidBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var prevTxid [32]byte
		copy(prevTxid[:], prevTxidBytes)

		prevVout, err := readU32le(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}

		scriptSigLenU64, _, err := readCompactSize(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		if scriptSigLenU64 > MAX_SCRIPT_SIG_BYTES {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "script_sig_len overflow")
		}
		scriptSigLen := int(scriptSigLenU64)
		scriptSig, err := readBytes(b, &off, scriptSigLen)
		if err != nil {
			return nil, zero, zero, 0, err
		}

		sequence, err := readU32le(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}

		inputs = append(inputs, TxInput{
			PrevTxid:  prevTxid,
			PrevVout:  prevVout,
			ScriptSig: scriptSig,
			Sequence:  sequence,
		})
	}

	outCountU64, _, err := readCompactSize(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	if outCountU64 > MAX_TX_OUTPUTS {
		return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "output_count overflow")
	}
	outCount := int(outCountU64)

	outputs := make([]TxOutput, 0, outCount)
	for i := 0; i < outCount; i++ {
		value, err := readU64le(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}

		covType, err := readU16le(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}

		covLenU64, _, err := readCompactSize(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		if covLenU64 > uint64(math.MaxInt) {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "covenant_data_len overflows int")
		}
		if covLenU64 > MAX_COVENANT_DATA_PER_OUTPUT {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "covenant_data_len exceeds MAX_COVENANT_DATA_PER_OUTPUT")
		}
		covLen := int(covLenU64)
		covData, err := readBytes(b, &off, covLen)
		if err != nil {
			return nil, zero, zero, 0, err
		}

		outputs = append(outputs, TxOutput{
			Value:        value,
			CovenantType: covType,
			CovenantData: covData,
		})
	}

	locktime, err := readU32le(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	var daCommitCore *DaCommitCore
	var daChunkCore *DaChunkCore
	switch txKind {
	case 0x01:
		daIDBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var daID [32]byte
		copy(daID[:], daIDBytes)
		chunkCount, err := readU16le(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		if chunkCount == 0 || uint64(chunkCount) > MAX_DA_CHUNK_COUNT {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "chunk_count out of range for tx_kind=0x01")
		}
		retlDomainBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var retlDomainID [32]byte
		copy(retlDomainID[:], retlDomainBytes)
		batchNumber, err := readU64le(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		txDataRootBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var txDataRoot [32]byte
		copy(txDataRoot[:], txDataRootBytes)
		stateRootBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var stateRoot [32]byte
		copy(stateRoot[:], stateRootBytes)
		withdrawalsRootBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var withdrawalsRoot [32]byte
		copy(withdrawalsRoot[:], withdrawalsRootBytes)
		batchSigSuite, err := readU8(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		batchSigLenU64, _, err := readCompactSize(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		if batchSigLenU64 > MAX_DA_MANIFEST_BYTES_PER_TX || batchSigLenU64 > uint64(math.MaxInt) {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "batch_sig_len overflow")
		}
		batchSig, err := readBytes(b, &off, int(batchSigLenU64))
		if err != nil {
			return nil, zero, zero, 0, err
		}
		daCommitCore = &DaCommitCore{
			DaID:            daID,
			ChunkCount:      chunkCount,
			RetlDomainID:    retlDomainID,
			BatchNumber:     batchNumber,
			TxDataRoot:      txDataRoot,
			StateRoot:       stateRoot,
			WithdrawalsRoot: withdrawalsRoot,
			BatchSigSuite:   batchSigSuite,
			BatchSig:        batchSig,
		}
	case 0x02:
		daIDBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var daID [32]byte
		copy(daID[:], daIDBytes)
		chunkIndex, err := readU16le(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		if uint64(chunkIndex) >= MAX_DA_CHUNK_COUNT {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "chunk_index out of range for tx_kind=0x02")
		}
		chunkHashBytes, err := readBytes(b, &off, 32)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		var chunkHash [32]byte
		copy(chunkHash[:], chunkHashBytes)
		daChunkCore = &DaChunkCore{
			DaID:       daID,
			ChunkIndex: chunkIndex,
			ChunkHash:  chunkHash,
		}
	}

	coreEnd := off

	// Witness section.
	witnessCountU64, witnessCountVarintBytes, err := readCompactSize(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	if witnessCountU64 > MAX_WITNESS_ITEMS {
		return nil, zero, zero, 0, txerr(TX_ERR_WITNESS_OVERFLOW, "witness_count overflow")
	}
	witnessCount := int(witnessCountU64)

	witnessBytes := witnessCountVarintBytes
	witness := make([]WitnessItem, 0, witnessCount)

	for i := 0; i < witnessCount; i++ {
		suiteID, err := readU8(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		witnessBytes += 1

		pubLenU64, pubLenVarintBytes, err := readCompactSize(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		witnessBytes += pubLenVarintBytes
		if pubLenU64 > uint64(math.MaxInt) {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "pubkey_length overflows int")
		}
		pubLen := int(pubLenU64)
		pubkey, err := readBytes(b, &off, pubLen)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		witnessBytes += pubLen

		sigLenU64, sigLenVarintBytes, err := readCompactSize(b, &off)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		witnessBytes += sigLenVarintBytes
		if sigLenU64 > uint64(math.MaxInt) {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "sig_length overflows int")
		}
		sigLen := int(sigLenU64)
		sig, err := readBytes(b, &off, sigLen)
		if err != nil {
			return nil, zero, zero, 0, err
		}
		witnessBytes += sigLen

		switch suiteID {
		case SUITE_ID_SENTINEL:
			ok := false
			if pubLen == 0 && sigLen == 0 {
				ok = true
			} else if pubLen == 32 {
				if sigLen == 1 {
					ok = len(sig) == 1 && sig[0] == 0x01
				} else if sigLen >= 3 {
					if len(sig) >= 3 && sig[0] == 0x00 {
						preLen := int(binary.LittleEndian.Uint16(sig[1:3]))
						ok = preLen >= 1 && preLen <= MAX_HTLC_PREIMAGE_BYTES && sigLen == 3+preLen
					}
				}
			}
			if !ok {
				return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "non-canonical sentinel witness item")
			}
		case SUITE_ID_ML_DSA_87:
			if !(pubLen == ML_DSA_87_PUBKEY_BYTES && sigLen == ML_DSA_87_SIG_BYTES) {
				return nil, zero, zero, 0, txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA witness item lengths")
			}
		case SUITE_ID_SLH_DSA_SHAKE_256F:
			if pubLen != SLH_DSA_SHAKE_256F_PUBKEY_BYTES || sigLen <= 0 || sigLen > MAX_SLH_DSA_SIG_BYTES {
				return nil, zero, zero, 0, txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical SLH-DSA witness item lengths")
			}
		default:
			return nil, zero, zero, 0, txerr(TX_ERR_SIG_ALG_INVALID, "unknown suite_id")
		}

		if witnessBytes > MAX_WITNESS_BYTES_PER_TX {
			return nil, zero, zero, 0, txerr(TX_ERR_WITNESS_OVERFLOW, "witness bytes overflow")
		}

		witness = append(witness, WitnessItem{
			SuiteID:   suiteID,
			Pubkey:    pubkey,
			Signature: sig,
		})
	}

	// DA payload.
	daLenU64, _, err := readCompactSize(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	var daPayload []byte
	switch txKind {
	case 0x00:
		if daLenU64 != 0 {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "da_payload_len must be 0 for tx_kind=0x00")
		}
	case 0x01:
		if daLenU64 > MAX_DA_MANIFEST_BYTES_PER_TX || daLenU64 > uint64(math.MaxInt) {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "da_payload_len out of range for tx_kind=0x01")
		}
		if daLenU64 != 0 {
			daPayload, err = readBytes(b, &off, int(daLenU64))
			if err != nil {
				return nil, zero, zero, 0, err
			}
		}
	case 0x02:
		if daLenU64 == 0 || daLenU64 > CHUNK_BYTES || daLenU64 > uint64(math.MaxInt) {
			return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "da_payload_len out of range for tx_kind=0x02")
		}
		daPayload, err = readBytes(b, &off, int(daLenU64))
		if err != nil {
			return nil, zero, zero, 0, err
		}
	}
	totalEnd := off

	txid := sha3_256(b[:coreEnd])
	wtxid := sha3_256(b[:totalEnd])

	tx := &Tx{
		Version:      version,
		TxKind:       txKind,
		TxNonce:      txNonce,
		Inputs:       inputs,
		Outputs:      outputs,
		Locktime:     locktime,
		DaCommitCore: daCommitCore,
		DaChunkCore:  daChunkCore,
		Witness:      witness,
		DaPayload:    daPayload,
	}

	return tx, txid, wtxid, totalEnd, nil
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
		out = appendU16le(out, core.ChunkCount)
		out = append(out, core.RetlDomainID[:]...)
		out = appendU64le(out, core.BatchNumber)
		out = append(out, core.TxDataRoot[:]...)
		out = append(out, core.StateRoot[:]...)
		out = append(out, core.WithdrawalsRoot[:]...)
		out = append(out, core.BatchSigSuite)
		out = appendCompactSize(out, uint64(len(core.BatchSig)))
		out = append(out, core.BatchSig...)
		return out, nil
	case 0x02:
		if tx.DaChunkCore == nil {
			return nil, txerr(TX_ERR_PARSE, "missing da_chunk_core for tx_kind=0x02")
		}
		core := tx.DaChunkCore
		out := make([]byte, 0, 32+2+32)
		out = append(out, core.DaID[:]...)
		out = appendU16le(out, core.ChunkIndex)
		out = append(out, core.ChunkHash[:]...)
		return out, nil
	default:
		return nil, txerr(TX_ERR_PARSE, "unsupported tx_kind")
	}
}

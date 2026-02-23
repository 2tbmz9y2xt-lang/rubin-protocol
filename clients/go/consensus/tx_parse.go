package consensus

import (
	"encoding/binary"
	"math"
)

type Tx struct {
	Version   uint32
	TxKind    uint8
	TxNonce   uint64
	Inputs    []TxInput
	Outputs   []TxOutput
	Locktime  uint32
	Witness   []WitnessItem
	DaPayload []byte
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

type WitnessItem struct {
	SuiteID   uint8
	Pubkey    []byte
	Signature []byte
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
	if txKind != 0x00 {
		return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "unsupported tx_kind (genesis)")
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
							ok = preLen <= MAX_HTLC_PREIMAGE_BYTES && sigLen == 3+preLen
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

	// DA payload (genesis tx_kind=0x00 forbids any payload bytes; the length prefix is still present).
	daLenU64, _, err := readCompactSize(b, &off)
	if err != nil {
		return nil, zero, zero, 0, err
	}
	if daLenU64 != 0 {
		return nil, zero, zero, 0, txerr(TX_ERR_PARSE, "da_payload_len must be 0 for tx_kind=0x00")
	}

	// da_payload_len=0 => no payload bytes.
	totalEnd := off

	txid := sha3_256(b[:coreEnd])
	wtxid := sha3_256(b[:totalEnd])

	tx := &Tx{
		Version:   version,
		TxKind:    txKind,
		TxNonce:   txNonce,
		Inputs:    inputs,
		Outputs:   outputs,
		Locktime:  locktime,
		Witness:   witness,
		DaPayload: nil,
	}

	return tx, txid, wtxid, totalEnd, nil
}

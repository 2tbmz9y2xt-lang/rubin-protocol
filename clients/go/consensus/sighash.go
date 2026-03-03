package consensus

func IsValidSighashType(sighashType uint8) bool {
	switch sighashType {
	case SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
		SIGHASH_ALL | SIGHASH_ANYONECANPAY,
		SIGHASH_NONE | SIGHASH_ANYONECANPAY,
		SIGHASH_SINGLE | SIGHASH_ANYONECANPAY:
		return true
	default:
		return false
	}
}

func SighashV1Digest(tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte) ([32]byte, error) {
	return SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
}

func SighashV1DigestWithType(tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, sighashType uint8) ([32]byte, error) {
	var zero [32]byte
	if tx == nil {
		return zero, txerr(TX_ERR_PARSE, "sighash: nil tx")
	}
	if int(inputIndex) < 0 || int(inputIndex) >= len(tx.Inputs) {
		return zero, txerr(TX_ERR_PARSE, "sighash: input_index out of bounds")
	}
	if !IsValidSighashType(sighashType) {
		return zero, txerr(TX_ERR_SIGHASH_TYPE_INVALID, "sighash: invalid sighash_type")
	}

	baseType := sighashType & 0x1f
	anyoneCanPay := (sighashType & SIGHASH_ANYONECANPAY) != 0

	daCoreBytes, err := daCoreFieldsBytes(tx)
	if err != nil {
		return zero, err
	}
	hashOfDaCoreFields := sha3_256(daCoreBytes)

	in := tx.Inputs[inputIndex]

	var hashPrevouts [32]byte
	var hashSequences [32]byte
	if anyoneCanPay {
		prevouts := make([]byte, 0, 32+4)
		prevouts = append(prevouts, in.PrevTxid[:]...)
		prevouts = AppendU32le(prevouts, in.PrevVout)
		hashPrevouts = sha3_256(prevouts)

		sequences := make([]byte, 0, 4)
		sequences = AppendU32le(sequences, in.Sequence)
		hashSequences = sha3_256(sequences)
	} else {
		prevouts := make([]byte, 0, len(tx.Inputs)*(32+4))
		for _, txIn := range tx.Inputs {
			prevouts = append(prevouts, txIn.PrevTxid[:]...)
			prevouts = AppendU32le(prevouts, txIn.PrevVout)
		}
		hashPrevouts = sha3_256(prevouts)

		sequences := make([]byte, 0, len(tx.Inputs)*4)
		for _, txIn := range tx.Inputs {
			sequences = AppendU32le(sequences, txIn.Sequence)
		}
		hashSequences = sha3_256(sequences)
	}

	var hashOutputs [32]byte
	switch baseType {
	case SIGHASH_ALL:
		outputsBytes := make([]byte, 0, len(tx.Outputs)*64)
		for _, o := range tx.Outputs {
			outputsBytes = AppendU64le(outputsBytes, o.Value)
			outputsBytes = AppendU16le(outputsBytes, o.CovenantType)
			outputsBytes = AppendCompactSize(outputsBytes, uint64(len(o.CovenantData)))
			outputsBytes = append(outputsBytes, o.CovenantData...)
		}
		hashOutputs = sha3_256(outputsBytes)
	case SIGHASH_NONE:
		hashOutputs = sha3_256(nil)
	case SIGHASH_SINGLE:
		if int(inputIndex) < len(tx.Outputs) {
			o := tx.Outputs[inputIndex]
			outputsBytes := make([]byte, 0, 64)
			outputsBytes = AppendU64le(outputsBytes, o.Value)
			outputsBytes = AppendU16le(outputsBytes, o.CovenantType)
			outputsBytes = AppendCompactSize(outputsBytes, uint64(len(o.CovenantData)))
			outputsBytes = append(outputsBytes, o.CovenantData...)
			hashOutputs = sha3_256(outputsBytes)
		} else {
			hashOutputs = sha3_256(nil)
		}
	default:
		return zero, txerr(TX_ERR_SIGHASH_TYPE_INVALID, "sighash: invalid base_type")
	}

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)
	preimage = AppendU32le(preimage, tx.Version)
	preimage = append(preimage, tx.TxKind)
	preimage = AppendU64le(preimage, tx.TxNonce)
	preimage = append(preimage, hashOfDaCoreFields[:]...)
	preimage = append(preimage, hashPrevouts[:]...)
	preimage = append(preimage, hashSequences[:]...)
	preimage = AppendU32le(preimage, inputIndex)
	preimage = append(preimage, in.PrevTxid[:]...)
	preimage = AppendU32le(preimage, in.PrevVout)
	preimage = AppendU64le(preimage, inputValue)
	preimage = AppendU32le(preimage, in.Sequence)
	preimage = append(preimage, hashOutputs[:]...)
	preimage = AppendU32le(preimage, tx.Locktime)
	preimage = append(preimage, sighashType)

	return sha3_256(preimage), nil
}

package consensus

func SighashV1Digest(tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte) ([32]byte, error) {
	var zero [32]byte
	if tx == nil {
		return zero, txerr(TX_ERR_PARSE, "sighash: nil tx")
	}
	if int(inputIndex) < 0 || int(inputIndex) >= len(tx.Inputs) {
		return zero, txerr(TX_ERR_PARSE, "sighash: input_index out of bounds")
	}

	hashOfDaCoreFields := sha3_256([]byte{})

	// hash_of_all_prevouts
	prevouts := make([]byte, 0, len(tx.Inputs)*(32+4))
	for _, in := range tx.Inputs {
		prevouts = append(prevouts, in.PrevTxid[:]...)
		prevouts = appendU32le(prevouts, in.PrevVout)
	}
	hashOfAllPrevouts := sha3_256(prevouts)

	// hash_of_all_sequences
	sequences := make([]byte, 0, len(tx.Inputs)*4)
	for _, in := range tx.Inputs {
		sequences = appendU32le(sequences, in.Sequence)
	}
	hashOfAllSequences := sha3_256(sequences)

	// hash_of_all_outputs
	outputsBytes := make([]byte, 0, len(tx.Outputs)*64)
	for _, o := range tx.Outputs {
		outputsBytes = appendU64le(outputsBytes, o.Value)
		outputsBytes = appendU16le(outputsBytes, o.CovenantType)
		outputsBytes = appendCompactSize(outputsBytes, uint64(len(o.CovenantData)))
		outputsBytes = append(outputsBytes, o.CovenantData...)
	}
	hashOfAllOutputs := sha3_256(outputsBytes)

	in := tx.Inputs[inputIndex]

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)
	preimage = appendU32le(preimage, tx.Version)
	preimage = append(preimage, tx.TxKind)
	preimage = appendU64le(preimage, tx.TxNonce)
	preimage = append(preimage, hashOfDaCoreFields[:]...)
	preimage = append(preimage, hashOfAllPrevouts[:]...)
	preimage = append(preimage, hashOfAllSequences[:]...)
	preimage = appendU32le(preimage, inputIndex)
	preimage = append(preimage, in.PrevTxid[:]...)
	preimage = appendU32le(preimage, in.PrevVout)
	preimage = appendU64le(preimage, inputValue)
	preimage = appendU32le(preimage, in.Sequence)
	preimage = append(preimage, hashOfAllOutputs[:]...)
	preimage = appendU32le(preimage, tx.Locktime)

	return sha3_256(preimage), nil
}

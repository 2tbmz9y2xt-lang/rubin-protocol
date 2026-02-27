package consensus

func SighashV1Digest(tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte) ([32]byte, error) {
	var zero [32]byte
	if tx == nil {
		return zero, txerr(TX_ERR_PARSE, "sighash: nil tx")
	}
	if int(inputIndex) < 0 || int(inputIndex) >= len(tx.Inputs) {
		return zero, txerr(TX_ERR_PARSE, "sighash: input_index out of bounds")
	}

	daCoreBytes, err := daCoreFieldsBytes(tx)
	if err != nil {
		return zero, err
	}
	hashOfDaCoreFields := sha3_256(daCoreBytes)

	// hash_of_all_prevouts
	prevouts := make([]byte, 0, len(tx.Inputs)*(32+4))
	for _, in := range tx.Inputs {
		prevouts = append(prevouts, in.PrevTxid[:]...)
		prevouts = AppendU32le(prevouts, in.PrevVout)
	}
	hashOfAllPrevouts := sha3_256(prevouts)

	// hash_of_all_sequences
	sequences := make([]byte, 0, len(tx.Inputs)*4)
	for _, in := range tx.Inputs {
		sequences = AppendU32le(sequences, in.Sequence)
	}
	hashOfAllSequences := sha3_256(sequences)

	// hash_of_all_outputs
	outputsBytes := make([]byte, 0, len(tx.Outputs)*64)
	for _, o := range tx.Outputs {
		outputsBytes = AppendU64le(outputsBytes, o.Value)
		outputsBytes = AppendU16le(outputsBytes, o.CovenantType)
		outputsBytes = AppendCompactSize(outputsBytes, uint64(len(o.CovenantData)))
		outputsBytes = append(outputsBytes, o.CovenantData...)
	}
	hashOfAllOutputs := sha3_256(outputsBytes)

	in := tx.Inputs[inputIndex]

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)
	preimage = AppendU32le(preimage, tx.Version)
	preimage = append(preimage, tx.TxKind)
	preimage = AppendU64le(preimage, tx.TxNonce)
	preimage = append(preimage, hashOfDaCoreFields[:]...)
	preimage = append(preimage, hashOfAllPrevouts[:]...)
	preimage = append(preimage, hashOfAllSequences[:]...)
	preimage = AppendU32le(preimage, inputIndex)
	preimage = append(preimage, in.PrevTxid[:]...)
	preimage = AppendU32le(preimage, in.PrevVout)
	preimage = AppendU64le(preimage, inputValue)
	preimage = AppendU32le(preimage, in.Sequence)
	preimage = append(preimage, hashOfAllOutputs[:]...)
	preimage = AppendU32le(preimage, tx.Locktime)

	return sha3_256(preimage), nil
}

package consensus

import "fmt"

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

package consensus

type SighashV1PrehashCache struct {
	tx                 *Tx
	hashOfDaCoreFields [32]byte
	hashAllPrevouts    [32]byte
	hashAllSequences   [32]byte
	hashAllOutputs     [32]byte
	singleOutputs      map[uint32][32]byte
}

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

func NewSighashV1PrehashCache(tx *Tx) (*SighashV1PrehashCache, error) {
	if tx == nil {
		return nil, txerr(TX_ERR_PARSE, "sighash: nil tx")
	}
	daCoreBytes, err := daCoreFieldsBytes(tx)
	if err != nil {
		return nil, err
	}
	prevouts := make([]byte, 0, len(tx.Inputs)*(32+4))
	sequences := make([]byte, 0, len(tx.Inputs)*4)
	for _, txIn := range tx.Inputs {
		prevouts = append(prevouts, txIn.PrevTxid[:]...)
		prevouts = AppendU32le(prevouts, txIn.PrevVout)
		sequences = AppendU32le(sequences, txIn.Sequence)
	}
	outputsBytes := make([]byte, 0, len(tx.Outputs)*64)
	for _, o := range tx.Outputs {
		outputsBytes = AppendU64le(outputsBytes, o.Value)
		outputsBytes = AppendU16le(outputsBytes, o.CovenantType)
		outputsBytes = AppendCompactSize(outputsBytes, uint64(len(o.CovenantData)))
		outputsBytes = append(outputsBytes, o.CovenantData...)
	}
	return &SighashV1PrehashCache{
		tx:                 tx,
		hashOfDaCoreFields: sha3_256(daCoreBytes),
		hashAllPrevouts:    sha3_256(prevouts),
		hashAllSequences:   sha3_256(sequences),
		hashAllOutputs:     sha3_256(outputsBytes),
		singleOutputs:      make(map[uint32][32]byte),
	}, nil
}

func SighashV1DigestWithType(tx *Tx, inputIndex uint32, inputValue uint64, chainID [32]byte, sighashType uint8) ([32]byte, error) {
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		return [32]byte{}, err
	}
	return SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, sighashType)
}

func SighashV1DigestWithCache(cache *SighashV1PrehashCache, inputIndex uint32, inputValue uint64, chainID [32]byte, sighashType uint8) ([32]byte, error) {
	var zero [32]byte
	if cache == nil || cache.tx == nil {
		return zero, txerr(TX_ERR_PARSE, "sighash: nil cache")
	}
	tx := cache.tx
	if int(inputIndex) < 0 || int(inputIndex) >= len(tx.Inputs) {
		return zero, txerr(TX_ERR_PARSE, "sighash: input_index out of bounds")
	}
	if !IsValidSighashType(sighashType) {
		return zero, txerr(TX_ERR_SIGHASH_TYPE_INVALID, "sighash: invalid sighash_type")
	}

	baseType := sighashType & 0x1f
	anyoneCanPay := (sighashType & SIGHASH_ANYONECANPAY) != 0

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
		hashPrevouts = cache.hashAllPrevouts
		hashSequences = cache.hashAllSequences
	}

	var hashOutputs [32]byte
	switch baseType {
	case SIGHASH_ALL:
		hashOutputs = cache.hashAllOutputs
	case SIGHASH_NONE:
		hashOutputs = sha3_256(nil)
	case SIGHASH_SINGLE:
		hashOutputs = cache.singleOutputHash(inputIndex)
	default:
		return zero, txerr(TX_ERR_SIGHASH_TYPE_INVALID, "sighash: invalid base_type")
	}

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)
	preimage = AppendU32le(preimage, tx.Version)
	preimage = append(preimage, tx.TxKind)
	preimage = AppendU64le(preimage, tx.TxNonce)
	preimage = append(preimage, cache.hashOfDaCoreFields[:]...)
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

func (c *SighashV1PrehashCache) singleOutputHash(inputIndex uint32) [32]byte {
	if c == nil || c.tx == nil {
		return sha3_256(nil)
	}
	if out, ok := c.singleOutputs[inputIndex]; ok {
		return out
	}
	var hash [32]byte
	if int(inputIndex) < len(c.tx.Outputs) {
		o := c.tx.Outputs[inputIndex]
		outputsBytes := make([]byte, 0, 64)
		outputsBytes = AppendU64le(outputsBytes, o.Value)
		outputsBytes = AppendU16le(outputsBytes, o.CovenantType)
		outputsBytes = AppendCompactSize(outputsBytes, uint64(len(o.CovenantData)))
		outputsBytes = append(outputsBytes, o.CovenantData...)
		hash = sha3_256(outputsBytes)
	} else {
		hash = sha3_256(nil)
	}
	c.singleOutputs[inputIndex] = hash
	return hash
}

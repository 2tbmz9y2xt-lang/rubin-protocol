package consensus

import (
	"encoding/binary"
	"fmt"

	"rubin.dev/node/crypto"
)

// SighashV1Digest computes the RUBIN v1 signature digest for a specific input of a transaction.
//
// It constructs a canonical preimage (starting with the ASCII prefix "RUBINv1-sighash/" followed by the provided chainID)
// that encodes the transaction version, nonce, hashed prevouts, hashed sequences, the target input (prevout, value, sequence),
// hashed outputs, and locktime, then returns the SHA3-256 digest of that preimage.
//
// An error is returned if the provided inputIndex cannot be interpreted as a valid index or is out of range for tx.Inputs.
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

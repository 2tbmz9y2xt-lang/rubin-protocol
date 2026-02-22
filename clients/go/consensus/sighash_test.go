package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSighashV1Digest_Smoke(t *testing.T) {
	var txb bytes.Buffer
	_ = binary.Write(&txb, binary.LittleEndian, uint32(1))
	txb.WriteByte(0x00) // tx_kind
	_ = binary.Write(&txb, binary.LittleEndian, uint64(0))
	txb.WriteByte(0x01) // input_count

	prevTxid := bytes.Repeat([]byte{0x11}, 32)
	txb.Write(prevTxid)
	_ = binary.Write(&txb, binary.LittleEndian, uint32(2)) // prev_vout
	txb.WriteByte(0x00)                                    // script_sig_len
	_ = binary.Write(&txb, binary.LittleEndian, uint32(3)) // sequence

	txb.WriteByte(0x00)                                    // output_count
	_ = binary.Write(&txb, binary.LittleEndian, uint32(4)) // locktime
	txb.WriteByte(0x00)                                    // witness_count
	txb.WriteByte(0x00)                                    // da_payload_len

	tx, _, _, _, err := ParseTx(txb.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	var chainID [32]byte
	chainID[31] = 0x01
	digest, err := SighashV1Digest(tx, 0, 5, chainID)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}

	hashOfDaCoreFields := sha3_256([]byte{})
	prevouts := append([]byte{}, prevTxid...)
	prevouts = appendU32le(prevouts, 2)
	hashOfAllPrevouts := sha3_256(prevouts)
	hashOfAllSequences := sha3_256(appendU32le(nil, 3))
	hashOfAllOutputs := sha3_256([]byte{})

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)
	preimage = appendU32le(preimage, 1)
	preimage = append(preimage, 0x00) // tx_kind
	preimage = appendU64le(preimage, 0)
	preimage = append(preimage, hashOfDaCoreFields[:]...)
	preimage = append(preimage, hashOfAllPrevouts[:]...)
	preimage = append(preimage, hashOfAllSequences[:]...)
	preimage = appendU32le(preimage, 0) // input_index
	preimage = append(preimage, prevTxid...)
	preimage = appendU32le(preimage, 2)
	preimage = appendU64le(preimage, 5)
	preimage = appendU32le(preimage, 3)
	preimage = append(preimage, hashOfAllOutputs[:]...)
	preimage = appendU32le(preimage, 4)

	want := sha3_256(preimage)
	if digest != want {
		t.Fatalf("digest mismatch")
	}
}

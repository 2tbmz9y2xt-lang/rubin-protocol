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
	prevouts = AppendU32le(prevouts, 2)
	hashOfAllPrevouts := sha3_256(prevouts)
	hashOfAllSequences := sha3_256(AppendU32le(nil, 3))
	hashOfAllOutputs := sha3_256([]byte{})

	preimage := make([]byte, 0, 256)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)
	preimage = AppendU32le(preimage, 1)
	preimage = append(preimage, 0x00) // tx_kind
	preimage = AppendU64le(preimage, 0)
	preimage = append(preimage, hashOfDaCoreFields[:]...)
	preimage = append(preimage, hashOfAllPrevouts[:]...)
	preimage = append(preimage, hashOfAllSequences[:]...)
	preimage = AppendU32le(preimage, 0) // input_index
	preimage = append(preimage, prevTxid...)
	preimage = AppendU32le(preimage, 2)
	preimage = AppendU64le(preimage, 5)
	preimage = AppendU32le(preimage, 3)
	preimage = append(preimage, hashOfAllOutputs[:]...)
	preimage = AppendU32le(preimage, 4)
	preimage = append(preimage, SIGHASH_ALL)

	want := sha3_256(preimage)
	if digest != want {
		t.Fatalf("digest mismatch")
	}
}

func TestSighashV1DigestWithCacheMatchesUncachedAcrossTypes(t *testing.T) {
	var prev0 [32]byte
	var prev1 [32]byte
	prev0[0] = 0x11
	prev1[0] = 0x22
	var chainID [32]byte
	chainID[0] = 0x44

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 9,
		Inputs: []TxInput{
			{PrevTxid: prev0, PrevVout: 0, Sequence: 1},
			{PrevTxid: prev1, PrevVout: 1, Sequence: 2},
		},
		Outputs: []TxOutput{
			{Value: 3, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
			{Value: 4, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
		},
		Locktime: 5,
	}
	cache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		t.Fatalf("NewSighashV1PrehashCache: %v", err)
	}

	types := []uint8{
		SIGHASH_ALL,
		SIGHASH_NONE,
		SIGHASH_SINGLE,
		SIGHASH_ALL | SIGHASH_ANYONECANPAY,
		SIGHASH_NONE | SIGHASH_ANYONECANPAY,
		SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
	}
	for _, sighashType := range types {
		for inputIndex, inputValue := range []uint64{11, 17} {
			want, err := SighashV1DigestWithType(tx, uint32(inputIndex), inputValue, chainID, sighashType)
			if err != nil {
				t.Fatalf("SighashV1DigestWithType(type=%d,input=%d): %v", sighashType, inputIndex, err)
			}
			got, err := SighashV1DigestWithCache(cache, uint32(inputIndex), inputValue, chainID, sighashType)
			if err != nil {
				t.Fatalf("SighashV1DigestWithCache(type=%d,input=%d): %v", sighashType, inputIndex, err)
			}
			if got != want {
				t.Fatalf("digest mismatch type=%d input=%d", sighashType, inputIndex)
			}
		}
	}
}

func TestSighashV1DigestWithCacheRejectsNilCache(t *testing.T) {
	if _, err := SighashV1DigestWithCache(nil, 0, 0, [32]byte{}, SIGHASH_ALL); err == nil {
		t.Fatalf("expected nil cache error")
	}
}

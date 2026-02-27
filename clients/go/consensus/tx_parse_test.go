package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

const txCoreEnd = 4 + 1 + 8 + 1 + 1 + 4

func mustTxErrCode(t *testing.T, err error) ErrorCode {
	t.Helper()
	te, ok := err.(*TxError)
	if !ok {
		t.Fatalf("expected *TxError, got %T: %v", err, err)
	}
	return te.Code
}

func minimalTxBytes() []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))
	b.WriteByte(0x00) // tx_kind
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	b.WriteByte(0x00)                                    // input_count
	b.WriteByte(0x00)                                    // output_count
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // locktime
	b.WriteByte(0x00)                                    // witness_count
	b.WriteByte(0x00)                                    // da_payload_len
	return b.Bytes()
}

func txWithWitnessSection(section []byte) []byte {
	txBytes := minimalTxBytes()
	return append(txBytes[:txCoreEnd], section...)
}

func expectParseErrCode(t *testing.T, txBytes []byte, want ErrorCode) {
	t.Helper()
	_, _, _, _, err := ParseTx(txBytes)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != want {
		t.Fatalf("code=%s, want %s", got, want)
	}
}

func TestParseTx_Minimal_TxIDWTXID(t *testing.T) {
	txBytes := minimalTxBytes()

	_, txid, wtxid, n, err := ParseTx(txBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(txBytes) {
		t.Fatalf("consumed %d bytes, want %d", n, len(txBytes))
	}

	// TxCoreBytes = everything up to and including locktime (no witness, no da_payload_len).
	wantTxid := sha3_256(txBytes[:txCoreEnd])
	if txid != wantTxid {
		t.Fatalf("txid mismatch")
	}
	wantWtxid := sha3_256(txBytes)
	if wtxid != wantWtxid {
		t.Fatalf("wtxid mismatch")
	}
}

func TestParseTx_NonMinimalCompactSize(t *testing.T) {
	txBytes := minimalTxBytes()
	// Replace input_count=0x00 with a non-minimal CompactSize encoding 0xfd 0x00 0x00.
	// Offsets: version(4) + tx_kind(1) + tx_nonce(8) = 13.
	bad := append([]byte{}, txBytes...)
	bad = append(bad[:13], append([]byte{0xfd, 0x00, 0x00}, bad[14:]...)...)

	expectParseErrCode(t, bad, TX_ERR_PARSE)
}

func TestParseTx_ScriptSigLenOverflow(t *testing.T) {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))
	b.WriteByte(0x00) // tx_kind
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	b.WriteByte(0x01) // input_count
	b.Write(make([]byte, 32))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	b.WriteByte(0x21) // script_sig_len = 33 (overflow)
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	b.WriteByte(0x00)                                    // output_count
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // locktime
	b.WriteByte(0x00)                                    // witness_count
	b.WriteByte(0x00)                                    // da_payload_len

	expectParseErrCode(t, b.Bytes(), TX_ERR_PARSE)
}

func TestParseTx_CovenantDataLenExceedsCap(t *testing.T) {
	// output_count=1; covenant_data_len set to CompactSize(65537) so we hit the wire-level cap
	// MAX_COVENANT_DATA_PER_OUTPUT=65536 (constants.go).
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))
	b.WriteByte(0x00) // tx_kind
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	b.WriteByte(0x00) // input_count

	b.WriteByte(0x01) // output_count
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))
	_ = binary.Write(&b, binary.LittleEndian, uint16(0))

	// CompactSize(65537) = 0xfe + u32le(65537).
	b.WriteByte(0xfe)
	_ = binary.Write(&b, binary.LittleEndian, uint32(65_537))

	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // locktime
	b.WriteByte(0x00)                                    // witness_count
	b.WriteByte(0x00)                                    // da_payload_len

	_, _, _, _, err := ParseTx(b.Bytes())
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseTx_WitnessCountOverflow(t *testing.T) {
	txBytes := minimalTxBytes()
	// Replace witness_count=0x00 with CompactSize(1025) = 0xfd 0x01 0x04.
	// Offset to witness_count: coreEnd (19 bytes) + current witness_count (1 byte) => 19.
	bad := append([]byte{}, txBytes...)
	bad = append(bad[:txCoreEnd], append([]byte{0xfd, 0x01, 0x04}, bad[txCoreEnd+1:]...)...)

	expectParseErrCode(t, bad, TX_ERR_WITNESS_OVERFLOW)
}

func TestParseTx_WitnessItem_Canonicalization(t *testing.T) {
	cases := []struct {
		name    string
		wantErr ErrorCode
		section func() []byte
	}{
		{
			name:    "sentinel_noncanonical",
			wantErr: TX_ERR_PARSE,
			section: func() []byte {
				var w bytes.Buffer
				w.WriteByte(0x01) // witness_count
				w.WriteByte(SUITE_ID_SENTINEL)
				w.WriteByte(0x01) // pubkey_length
				w.WriteByte(0x00) // pubkey
				w.WriteByte(0x00) // sig_length
				w.WriteByte(0x00) // da_payload_len
				return w.Bytes()
			},
		},
		{
			name:    "unknown_suite",
			wantErr: TX_ERR_SIG_ALG_INVALID,
			section: func() []byte {
				var w bytes.Buffer
				w.WriteByte(0x01) // witness_count
				w.WriteByte(0x03) // suite_id unknown
				w.WriteByte(0x00) // pubkey_length
				w.WriteByte(0x00) // sig_length
				w.WriteByte(0x00) // da_payload_len
				return w.Bytes()
			},
		},
		{
			name:    "ml_dsa_len_mismatch",
			wantErr: TX_ERR_SIG_NONCANONICAL,
			section: func() []byte {
				var w bytes.Buffer
				w.WriteByte(0x01)               // witness_count
				w.WriteByte(SUITE_ID_ML_DSA_87) // suite_id
				w.WriteByte(0xfd)               // pubkey_length = 2591 (0x0A1F) non-canonical for ML
				w.WriteByte(0x1f)
				w.WriteByte(0x0a)
				w.Write(make([]byte, 2591))
				w.WriteByte(0xfd) // sig_length = 4627
				w.WriteByte(0x13)
				w.WriteByte(0x12)
				w.Write(make([]byte, 4627))
				w.WriteByte(0x00) // da_payload_len
				return w.Bytes()
			},
		},
		{
			name:    "slh_dsa_sig_len_zero",
			wantErr: TX_ERR_SIG_NONCANONICAL,
			section: func() []byte {
				var w bytes.Buffer
				w.WriteByte(0x01)                        // witness_count
				w.WriteByte(SUITE_ID_SLH_DSA_SHAKE_256F) // suite_id
				w.WriteByte(0x40)                        // pubkey_length = 64
				w.Write(make([]byte, 64))
				w.WriteByte(0x00) // sig_length = 0 (non-canonical)
				w.WriteByte(0x00) // da_payload_len
				return w.Bytes()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectParseErrCode(t, txWithWitnessSection(tc.section()), tc.wantErr)
		})
	}
}

func TestParseTx_WitnessBytesOverflow(t *testing.T) {
	var w bytes.Buffer
	w.WriteByte(0x03) // witness_count = 3
	for i := 0; i < 3; i++ {
		w.WriteByte(SUITE_ID_SLH_DSA_SHAKE_256F)
		w.WriteByte(0x40) // pubkey_length=64
		w.Write(make([]byte, 64))
		w.WriteByte(0xfd) // sig_length=49856 (0xC2C0)
		w.WriteByte(0xc0)
		w.WriteByte(0xc2)
		w.Write(make([]byte, 49_856))
	}
	w.WriteByte(0x00) // da_payload_len

	expectParseErrCode(t, txWithWitnessSection(w.Bytes()), TX_ERR_WITNESS_OVERFLOW)
}

func TestParseTx_HTLCPathWitnessItemsCanonical(t *testing.T) {
	claimPayload := []byte{0x00} // HTLC path selector for claim
	claimPayload = appendU16le(claimPayload, 1)
	claimPayload = append(claimPayload, 0x42)

	var w bytes.Buffer
	w.WriteByte(0x02) // witness_count = 2

	// path item: suite_id=0x00, key_id=32 bytes, payload=path_selector+u16le(len)+preimage
	w.WriteByte(SUITE_ID_SENTINEL)
	w.WriteByte(0x20) // pubkey_length=32
	w.Write(make([]byte, 32))
	w.WriteByte(byte(len(claimPayload))) // sig_length = 4
	w.Write(claimPayload)

	// signature item: suite_id=0x01 with canonical ML-DSA lengths
	w.WriteByte(SUITE_ID_ML_DSA_87)
	w.WriteByte(0xfd)
	w.WriteByte(0x20)
	w.WriteByte(0x0a)
	w.Write(make([]byte, ML_DSA_87_PUBKEY_BYTES))
	w.WriteByte(0xfd)
	w.WriteByte(0x13)
	w.WriteByte(0x12)
	w.Write(make([]byte, ML_DSA_87_SIG_BYTES))

	w.WriteByte(0x00) // da_payload_len
	if _, _, _, _, err := ParseTx(txWithWitnessSection(w.Bytes())); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

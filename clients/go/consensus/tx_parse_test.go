package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

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
	coreEnd := 4 + 1 + 8 + 1 + 1 + 4
	wantTxid := sha3_256(txBytes[:coreEnd])
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

	_, _, _, _, err := ParseTx(bad)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
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
	coreEnd := 4 + 1 + 8 + 1 + 1 + 4
	bad := append([]byte{}, txBytes...)
	bad = append(bad[:coreEnd], append([]byte{0xfd, 0x01, 0x04}, bad[coreEnd+1:]...)...)

	_, _, _, _, err := ParseTx(bad)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_WITNESS_OVERFLOW {
		t.Fatalf("code=%s, want %s", got, TX_ERR_WITNESS_OVERFLOW)
	}
}

func TestParseTx_WitnessItem_Canonicalization(t *testing.T) {
	t.Run("sentinel_noncanonical", func(t *testing.T) {
		// witness_count=1, suite_id=0, pubkey_length=1, pubkey=0x00, sig_length=0
		txBytes := append([]byte{}, minimalTxBytes()...)
		coreEnd := 4 + 1 + 8 + 1 + 1 + 4
		var w bytes.Buffer
		w.WriteByte(0x01) // witness_count
		w.WriteByte(SUITE_ID_SENTINEL)
		w.WriteByte(0x01) // pubkey_length
		w.WriteByte(0x00) // pubkey
		w.WriteByte(0x00) // sig_length
		w.WriteByte(0x00) // da_payload_len
		txBytes = append(txBytes[:coreEnd], w.Bytes()...)

		_, _, _, _, err := ParseTx(txBytes)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
			t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
		}
	})

	t.Run("unknown_suite", func(t *testing.T) {
		txBytes := append([]byte{}, minimalTxBytes()...)
		coreEnd := 4 + 1 + 8 + 1 + 1 + 4
		var w bytes.Buffer
		w.WriteByte(0x01) // witness_count
		w.WriteByte(0x03) // suite_id unknown
		w.WriteByte(0x00) // pubkey_length
		w.WriteByte(0x00) // sig_length
		w.WriteByte(0x00) // da_payload_len
		txBytes = append(txBytes[:coreEnd], w.Bytes()...)

		_, _, _, _, err := ParseTx(txBytes)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
			t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
		}
	})

	t.Run("ml_dsa_len_mismatch", func(t *testing.T) {
		txBytes := append([]byte{}, minimalTxBytes()...)
		coreEnd := 4 + 1 + 8 + 1 + 1 + 4
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
		txBytes = append(txBytes[:coreEnd], w.Bytes()...)

		_, _, _, _, err := ParseTx(txBytes)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_SIG_NONCANONICAL {
			t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_NONCANONICAL)
		}
	})

	t.Run("slh_dsa_sig_len_zero", func(t *testing.T) {
		txBytes := append([]byte{}, minimalTxBytes()...)
		coreEnd := 4 + 1 + 8 + 1 + 1 + 4
		var w bytes.Buffer
		w.WriteByte(0x01)                        // witness_count
		w.WriteByte(SUITE_ID_SLH_DSA_SHAKE_256F) // suite_id
		w.WriteByte(0x40)                        // pubkey_length = 64
		w.Write(make([]byte, 64))
		w.WriteByte(0x00) // sig_length = 0 (non-canonical)
		w.WriteByte(0x00) // da_payload_len
		txBytes = append(txBytes[:coreEnd], w.Bytes()...)

		_, _, _, _, err := ParseTx(txBytes)
		if err == nil {
			t.Fatalf("expected error")
		}
		if got := mustTxErrCode(t, err); got != TX_ERR_SIG_NONCANONICAL {
			t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_NONCANONICAL)
		}
	})
}

func TestParseTx_WitnessBytesOverflow(t *testing.T) {
	txBytes := append([]byte{}, minimalTxBytes()...)
	coreEnd := 4 + 1 + 8 + 1 + 1 + 4

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
	txBytes = append(txBytes[:coreEnd], w.Bytes()...)

	_, _, _, _, err := ParseTx(txBytes)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_WITNESS_OVERFLOW {
		t.Fatalf("code=%s, want %s", got, TX_ERR_WITNESS_OVERFLOW)
	}
}

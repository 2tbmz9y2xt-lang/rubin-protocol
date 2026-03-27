package consensus

import (
	"bytes"
	"testing"
)

func minimalTxBytesForFuzz() []byte {
	// version(4) + tx_kind(1) + tx_nonce(8) + input_count(1) + output_count(1) + locktime(4) + witness_count(1) + da_payload_len(1)
	return []byte{
		0x01, 0x00, 0x00, 0x00, // version
		0x00,                                           // tx_kind
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tx_nonce
		0x00,                   // input_count
		0x00,                   // output_count
		0x00, 0x00, 0x00, 0x00, // locktime
		0x00, // witness_count
		0x00, // da_payload_len
	}
}

func minimalBlockBytesForFuzz() []byte {
	var prev [32]byte
	var target [32]byte
	for i := range target {
		target[i] = 0xff
	}
	var root [32]byte
	tx := minimalTxBytesForFuzz()

	header := make([]byte, 0, BLOCK_HEADER_BYTES)
	header = AppendU32le(header, 1) // version
	header = append(header, prev[:]...)
	header = append(header, root[:]...)
	header = AppendU64le(header, 1) // timestamp
	header = append(header, target[:]...)
	header = AppendU64le(header, 1) // nonce

	out := make([]byte, 0, len(header)+1+len(tx))
	out = append(out, header...)
	out = AppendCompactSize(out, 1) // tx_count
	out = append(out, tx...)
	return out
}

func FuzzReadCompactSize(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0xfc})
	f.Add([]byte{0xfd, 0xfd, 0x00})
	f.Add([]byte{0xfe, 0x00, 0x00, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		off := 0
		n, nbytes, err := readCompactSize(b, &off)
		if err != nil {
			return
		}
		if nbytes <= 0 || nbytes > len(b) {
			t.Fatalf("bad nbytes=%d len=%d", nbytes, len(b))
		}
		enc := AppendCompactSize(nil, n)
		if !bytes.Equal(enc, b[:nbytes]) {
			t.Fatalf("non-minimal or mismatch: got=%x want_prefix=%x", enc, b[:nbytes])
		}
	})
}

func FuzzParseTx(f *testing.F) {
	f.Add(minimalTxBytesForFuzz())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, n, err := ParseTx(b)
		if err != nil {
			return
		}
		if n != len(b) {
			t.Fatalf("consumed=%d len=%d", n, len(b))
		}
	})
}

func FuzzParseBlockBytes(f *testing.F) {
	f.Add(minimalBlockBytesForFuzz())
	f.Fuzz(func(t *testing.T, b []byte) {
		pb, err := ParseBlockBytes(b)
		if err != nil {
			return
		}
		if pb.TxCount != uint64(len(pb.Txs)) || pb.TxCount != uint64(len(pb.Txids)) || pb.TxCount != uint64(len(pb.Wtxids)) {
			t.Fatalf("inconsistent tx sizes: tx_count=%d txs=%d txids=%d wtxids=%d", pb.TxCount, len(pb.Txs), len(pb.Txids), len(pb.Wtxids))
		}
	})
}

func FuzzParseBlockHeaderBytes(f *testing.F) {
	header := minimalBlockBytesForFuzz()[:BLOCK_HEADER_BYTES]
	f.Add(header)
	f.Add(make([]byte, BLOCK_HEADER_BYTES-1))
	f.Add(append(append([]byte(nil), header...), 0x99))

	f.Fuzz(func(t *testing.T, b []byte) {
		h1, err1 := ParseBlockHeaderBytes(b)
		h2, err2 := ParseBlockHeaderBytes(b)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("ParseBlockHeaderBytes non-deterministic error presence: first=%v second=%v", err1, err2)
		}
		if err1 != nil {
			return
		}
		if len(b) < BLOCK_HEADER_BYTES {
			t.Fatalf("accepted short header length=%d", len(b))
		}
		if h1 != h2 {
			t.Fatalf("ParseBlockHeaderBytes non-deterministic output")
		}
		hPrefix, err := ParseBlockHeaderBytes(b[:BLOCK_HEADER_BYTES])
		if err != nil {
			t.Fatalf("ParseBlockHeaderBytes(prefix): %v", err)
		}
		if h1 != hPrefix {
			t.Fatalf("trailing bytes changed parsed header")
		}
	})
}

func FuzzParseStealthCovenantData(f *testing.F) {
	var keyID [32]byte
	keyID[0] = 0xAA
	keyID[31] = 0x55

	f.Add([]byte{})
	f.Add(make([]byte, MAX_STEALTH_COVENANT_DATA-1))
	f.Add(stealthCovenantDataForKeyID(keyID))

	f.Fuzz(func(t *testing.T, covData []byte) {
		got, err := ParseStealthCovenantData(covData)
		if err != nil {
			return
		}
		if len(covData) != MAX_STEALTH_COVENANT_DATA {
			t.Fatalf("accepted non-canonical stealth covenant length=%d", len(covData))
		}
		if len(got.Ciphertext) != ML_KEM_1024_CT_BYTES {
			t.Fatalf("ciphertext_len=%d, want %d", len(got.Ciphertext), ML_KEM_1024_CT_BYTES)
		}

		var expectedKeyID [32]byte
		copy(expectedKeyID[:], covData[ML_KEM_1024_CT_BYTES:])
		if got.OneTimeKeyID != expectedKeyID {
			t.Fatalf("one_time_key_id mismatch")
		}

		if len(covData) > 0 {
			clone := append([]byte(nil), covData...)
			parsed, err := ParseStealthCovenantData(clone)
			if err != nil {
				t.Fatalf("ParseStealthCovenantData second parse: %v", err)
			}
			clone[0] ^= 0xFF
			if len(parsed.Ciphertext) > 0 && parsed.Ciphertext[0] != covData[0] {
				t.Fatalf("ciphertext aliases caller input")
			}
		}
	})
}

func FuzzParseCoreExtCovenantData(f *testing.F) {
	f.Add([]byte{0x01})
	f.Add([]byte{0x34, 0x12, 0x00})
	f.Add(coreExtCovenantData(0x1234, []byte{0xAA, 0xBB, 0xCC}))
	f.Add([]byte{0x34, 0x12, 0x02, 0xAA})

	f.Fuzz(func(t *testing.T, covenantData []byte) {
		got, err := ParseCoreExtCovenantData(covenantData)
		if err != nil {
			return
		}

		canonical := coreExtCovenantData(got.ExtID, got.ExtPayload)
		if !bytes.Equal(canonical, covenantData) {
			t.Fatalf("non-canonical or non-roundtripping CORE_EXT covenant data")
		}
	})
}

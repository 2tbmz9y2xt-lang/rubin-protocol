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
	header = appendU32le(header, 1) // version
	header = append(header, prev[:]...)
	header = append(header, root[:]...)
	header = appendU64le(header, 1) // timestamp
	header = append(header, target[:]...)
	header = appendU64le(header, 1) // nonce

	out := make([]byte, 0, len(header)+1+len(tx))
	out = append(out, header...)
	out = appendCompactSize(out, 1) // tx_count
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
		enc := appendCompactSize(nil, n)
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

package consensus

import "testing"

func filled32ForParseTests(v byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = v
	}
	return out
}

func TestParseTx_UnsupportedTxKind(t *testing.T) {
	txBytes := minimalTxBytes()
	bad := append([]byte(nil), txBytes...)
	bad[4] = 0x03 // tx_kind unsupported
	expectParseErrCode(t, bad, TX_ERR_PARSE)
}

func TestParseTx_InputCountOverflow(t *testing.T) {
	b := make([]byte, 0, 32)
	b = AppendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = AppendU64le(b, 0)
	b = AppendCompactSize(b, MAX_TX_INPUTS+1)

	_, _, _, _, err := ParseTx(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseTx_OutputCountOverflow(t *testing.T) {
	b := make([]byte, 0, 32)
	b = AppendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = AppendU64le(b, 0)
	b = AppendCompactSize(b, 0) // input_count
	b = AppendCompactSize(b, MAX_TX_OUTPUTS+1)

	_, _, _, _, err := ParseTx(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseTx_CovenantDataLenOverflowsInt(t *testing.T) {
	b := make([]byte, 0, 64)
	b = AppendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = AppendU64le(b, 0)
	b = AppendCompactSize(b, 0) // input_count
	b = AppendCompactSize(b, 1) // output_count
	b = AppendU64le(b, 0)
	b = AppendU16le(b, 0)
	b = AppendCompactSize(b, ^uint64(0))

	_, _, _, _, err := ParseTx(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseTx_TxKind00RejectsNonZeroDaPayloadLen(t *testing.T) {
	txBytes := minimalTxBytes()
	bad := append([]byte(nil), txBytes...)
	bad[len(bad)-1] = 0x01 // da_payload_len = 1
	expectParseErrCode(t, bad, TX_ERR_PARSE)
}

func TestParseTx_DACommitAndChunk_MinimalOK(t *testing.T) {
	daID := filled32ForParseTests(0xa1)
	payload := []byte("abc")
	payloadCommitment := sha3_256(payload)

	commitBytes := daCommitTxBytes(1, daID, 1, payloadCommitment)
	commitTx, _, _, _, err := ParseTx(commitBytes)
	if err != nil {
		t.Fatalf("ParseTx(commit): %v", err)
	}
	if commitTx.TxKind != 0x01 || commitTx.DaCommitCore == nil {
		t.Fatalf("expected tx_kind=0x01 with da_commit_core")
	}

	chunkBytes := daChunkTxBytes(2, daID, 0, sha3_256(payload), payload)
	chunkTx, _, _, _, err := ParseTx(chunkBytes)
	if err != nil {
		t.Fatalf("ParseTx(chunk): %v", err)
	}
	if chunkTx.TxKind != 0x02 || chunkTx.DaChunkCore == nil {
		t.Fatalf("expected tx_kind=0x02 with da_chunk_core")
	}
}

func TestParseTx_DACommit_RejectsOversizeManifestPayloadLen(t *testing.T) {
	b := make([]byte, 0, 256)
	b = AppendU32le(b, 1)
	b = append(b, 0x01) // tx_kind
	b = AppendU64le(b, 0)
	b = AppendCompactSize(b, 0) // input_count
	b = AppendCompactSize(b, 0) // output_count
	b = AppendU32le(b, 0)       // locktime
	daID := filled32ForParseTests(0xa2)
	b = append(b, daID[:]...)
	b = AppendU16le(b, 1) // chunk_count
	retl := filled32ForParseTests(0xa3)
	b = append(b, retl[:]...)
	b = AppendU64le(b, 1)
	txDataRoot := filled32ForParseTests(0xa4)
	stateRoot := filled32ForParseTests(0xa5)
	withdrawalsRoot := filled32ForParseTests(0xa6)
	b = append(b, txDataRoot[:]...)
	b = append(b, stateRoot[:]...)
	b = append(b, withdrawalsRoot[:]...)
	b = append(b, 0x00)                                      // batch_sig_suite
	b = AppendCompactSize(b, 0)                              // batch_sig_len
	b = AppendCompactSize(b, 0)                              // witness_count
	b = AppendCompactSize(b, MAX_DA_MANIFEST_BYTES_PER_TX+1) // da_payload_len too large

	_, _, _, _, err := ParseTx(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseTx_DAChunk_RejectsZeroPayloadLen(t *testing.T) {
	b := make([]byte, 0, 160)
	b = AppendU32le(b, 1)
	b = append(b, 0x02) // tx_kind
	b = AppendU64le(b, 0)
	b = AppendCompactSize(b, 0) // input_count
	b = AppendCompactSize(b, 0) // output_count
	b = AppendU32le(b, 0)       // locktime
	daID := filled32ForParseTests(0xb1)
	b = append(b, daID[:]...)
	b = AppendU16le(b, 0) // chunk_index
	chunkHash := filled32ForParseTests(0xb2)
	b = append(b, chunkHash[:]...)
	b = AppendCompactSize(b, 0) // witness_count
	b = AppendCompactSize(b, 0) // da_payload_len = 0 (invalid for tx_kind=0x02)

	_, _, _, _, err := ParseTx(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseTx_WitnessPubkeyLengthOverflowsInt(t *testing.T) {
	// Trigger: pubkey_length CompactSize decodes to a value > math.MaxInt.
	section := make([]byte, 0, 16)
	section = append(section, 0x01) // witness_count
	section = append(section, SUITE_ID_SENTINEL)
	section = append(section, 0xff) // CompactSize u64
	for i := 0; i < 8; i++ {
		section = append(section, 0xff)
	}

	expectParseErrCode(t, txWithWitnessSection(section), TX_ERR_PARSE)
}

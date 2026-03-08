package consensus

import (
	"bytes"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseTx — previously uncovered branches
// ---------------------------------------------------------------------------

func TestParseTx_SentinelEmptyWitness(t *testing.T) {
	// Sentinel witness item with pubLen=0, sigLen=0 → canonical (ok = true branch).
	var w bytes.Buffer
	w.WriteByte(0x01)              // witness_count = 1
	w.WriteByte(SUITE_ID_SENTINEL) // suite_id
	w.WriteByte(0x00)              // pubkey_length = 0
	w.WriteByte(0x00)              // sig_length = 0
	w.WriteByte(0x00)              // da_payload_len

	tx, _, _, _, err := ParseTx(txWithWitnessSection(w.Bytes()))
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if len(tx.Witness) != 1 {
		t.Fatalf("want 1 witness item, got %d", len(tx.Witness))
	}
	if tx.Witness[0].SuiteID != SUITE_ID_SENTINEL {
		t.Fatalf("suite_id=%d, want SENTINEL", tx.Witness[0].SuiteID)
	}
}

func TestParseTx_MissingSighashTypeByte(t *testing.T) {
	// Non-sentinel witness item with sig_length=0 → "missing sighash_type byte"
	var w bytes.Buffer
	w.WriteByte(0x01) // witness_count = 1
	w.WriteByte(0x03) // suite_id = unknown (not sentinel)
	w.WriteByte(0x00) // pubkey_length = 0
	w.WriteByte(0x00) // sig_length = 0
	w.WriteByte(0x00) // da_payload_len

	expectParseErrCode(t, txWithWitnessSection(w.Bytes()), TX_ERR_PARSE)
}

func TestParseTx_TruncatedAtVariousOffsets(t *testing.T) {
	// Build a valid TX with inputs, outputs, and witness, then truncate at
	// various points to cover the many readU32le/readU64le/readBytes error
	// return branches in ParseTx.
	var full bytes.Buffer
	// version
	full.Write(AppendU32le(nil, 1))
	// tx_kind = 0x00
	full.WriteByte(0x00)
	// tx_nonce
	full.Write(AppendU64le(nil, 42))
	// input_count = 1
	full.WriteByte(0x01)
	// input: prev_txid (32) + prev_vout (4) + script_sig_len (1, =0) + sequence (4)
	full.Write(make([]byte, 32)) // prev_txid
	full.Write(AppendU32le(nil, 0))
	full.WriteByte(0x00)            // script_sig_len
	full.Write(AppendU32le(nil, 0)) // sequence
	// output_count = 1
	full.WriteByte(0x01)
	// output: value (8) + cov_type (2) + cov_data_len (1, =0)
	full.Write(AppendU64le(nil, 100))
	full.Write(AppendU16le(nil, COV_TYPE_P2PK))
	full.WriteByte(byte(MAX_P2PK_COVENANT_DATA))
	covData := make([]byte, MAX_P2PK_COVENANT_DATA)
	covData[0] = SUITE_ID_ML_DSA_87
	full.Write(covData)
	// locktime
	full.Write(AppendU32le(nil, 0))
	// witness_count = 0
	full.WriteByte(0x00)
	// da_payload_len = 0
	full.WriteByte(0x00)

	validBytes := full.Bytes()

	// Verify full bytes parse correctly
	if _, _, _, _, err := ParseTx(validBytes); err != nil {
		t.Fatalf("full TX should parse: %v", err)
	}

	// Truncate at many offsets — each triggers an early error return
	offsets := []int{
		0,  // no version
		3,  // partial version
		4,  // no tx_kind
		5,  // no tx_nonce
		12, // partial tx_nonce
		13, // no input count
		14, // no prev_txid
		30, // partial prev_txid
		46, // no prev_vout
		49, // partial prev_vout
		50, // no script_sig_len
		51, // no sequence
		54, // partial sequence
		55, // no output count
		56, // no output value
		63, // partial value
		64, // no cov_type
		65, // partial cov_type
		66, // no cov_data_len
		67, // no cov_data (partial)
	}

	for _, off := range offsets {
		if off > len(validBytes) {
			continue
		}
		truncated := validBytes[:off]
		_, _, _, _, err := ParseTx(truncated)
		if err == nil {
			t.Errorf("offset=%d: expected error for truncated TX", off)
		}
	}
}

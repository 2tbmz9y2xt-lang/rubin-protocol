package consensus

import "testing"

func TestParseTx_CovenantDataLenExceedsCap(t *testing.T) {
	b := make([]byte, 0, 64)
	b = appendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = appendU64le(b, 0)
	b = appendCompactSize(b, 0) // input_count

	b = appendCompactSize(b, 1) // output_count
	b = appendU64le(b, 0)
	b = appendU16le(b, 0)
	b = appendCompactSize(b, MAX_COVENANT_DATA_PER_OUTPUT+1)

	b = appendU32le(b, 0)       // locktime
	b = appendCompactSize(b, 0) // witness_count
	b = appendCompactSize(b, 0) // da_payload_len

	_, _, _, _, err := ParseTx(b)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

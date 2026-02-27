package consensus

import "testing"

func TestReadBytes_NegativeLen(t *testing.T) {
	off := 0
	_, err := readBytes([]byte{}, &off, -1)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestReadBytes_UnexpectedEOF(t *testing.T) {
	off := 0
	_, err := readBytes([]byte{0x01, 0x02}, &off, 3)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

//go:build cgo

package consensus

import "testing"

func TestVerifySig_UnsupportedSuiteReturnsError(t *testing.T) {
	var d [32]byte
	_, err := verifySig(0xff, []byte{0x01}, []byte{0x02}, d)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestOpenSSLVerifySig_EmptyInputsReturnErrors(t *testing.T) {
	var d [32]byte
	_, err := opensslVerifySigMessage("", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty alg")
	}
	_, err = opensslVerifySigMessage("ML-DSA-87", nil, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty pubkey")
	}
	_, err = opensslVerifySigMessage("ML-DSA-87", []byte{0x01}, nil, d[:])
	if err == nil {
		t.Fatalf("expected error for empty signature")
	}
	_, err = opensslVerifySigMessage("ML-DSA-87", []byte{0x01}, []byte{0x02}, nil)
	if err == nil {
		t.Fatalf("expected error for empty message")
	}

	_, err = opensslVerifySigDigestOneShot("", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty alg (oneshot)")
	}
	_, err = opensslVerifySigDigestOneShot("SLH-DSA-SHAKE-256f", nil, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty pubkey (oneshot)")
	}
	_, err = opensslVerifySigDigestOneShot("SLH-DSA-SHAKE-256f", []byte{0x01}, nil, d[:])
	if err == nil {
		t.Fatalf("expected error for empty signature (oneshot)")
	}
	_, err = opensslVerifySigDigestOneShot("SLH-DSA-SHAKE-256f", []byte{0x01}, []byte{0x02}, nil)
	if err == nil {
		t.Fatalf("expected error for empty message (oneshot)")
	}
}

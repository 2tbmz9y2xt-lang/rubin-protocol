package node

import (
	"bytes"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestDefaultMineAddressUsesMLDSASuite(t *testing.T) {
	got := defaultMineAddress()
	if len(got) != consensus.MAX_P2PK_COVENANT_DATA {
		t.Fatalf("len=%d, want %d", len(got), consensus.MAX_P2PK_COVENANT_DATA)
	}
	if got[0] != consensus.SUITE_ID_ML_DSA_87 {
		t.Fatalf("suite_id=0x%02x, want 0x%02x", got[0], consensus.SUITE_ID_ML_DSA_87)
	}
	for i, b := range got[1:] {
		if b != 0x00 {
			t.Fatalf("byte[%d]=0x%02x, want 0x00", i+1, b)
		}
	}
}

func TestNormalizeMineAddressEmptyUsesDefaultCopy(t *testing.T) {
	got, err := normalizeMineAddress(nil)
	if err != nil {
		t.Fatalf("normalizeMineAddress: %v", err)
	}
	if !bytes.Equal(got, defaultMineAddress()) {
		t.Fatalf("got=%x want=%x", got, defaultMineAddress())
	}
	got[1] = 0x99
	if bytes.Equal(got, defaultMineAddress()) {
		t.Fatalf("expected defensive copy")
	}
}

func TestNormalizeMineAddressRejectsInvalidSuiteAndLength(t *testing.T) {
	if _, err := normalizeMineAddress([]byte{0x01, 0x02}); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("expected length error, got %v", err)
	}

	raw := bytes.Repeat([]byte{0x11}, consensus.MAX_P2PK_COVENANT_DATA)
	raw[0] = 0x02
	if _, err := normalizeMineAddress(raw); err == nil || !strings.Contains(err.Error(), "unsupported suite_id") {
		t.Fatalf("expected suite error, got %v", err)
	}
}

func TestParseMineAddressTrimsPrefixAndRejectsBadHex(t *testing.T) {
	keyHex := " 0X" + strings.Repeat("ab", mineAddressKeyIDBytes) + " "
	got, err := ParseMineAddress(keyHex)
	if err != nil {
		t.Fatalf("ParseMineAddress: %v", err)
	}
	if len(got) != consensus.MAX_P2PK_COVENANT_DATA {
		t.Fatalf("len=%d, want %d", len(got), consensus.MAX_P2PK_COVENANT_DATA)
	}
	if got[0] != consensus.SUITE_ID_ML_DSA_87 {
		t.Fatalf("suite_id=0x%02x, want 0x%02x", got[0], consensus.SUITE_ID_ML_DSA_87)
	}

	if got, err := ParseMineAddress("   "); err != nil || got != nil {
		t.Fatalf("blank ParseMineAddress = (%x, %v), want (nil, nil)", got, err)
	}
	if _, err := ParseMineAddress("abc"); err == nil || !strings.Contains(err.Error(), "odd-length") {
		t.Fatalf("expected odd-length error, got %v", err)
	}
	if _, err := ParseMineAddress("zz"); err == nil || !strings.Contains(err.Error(), "invalid byte") {
		t.Fatalf("expected hex decode error, got %v", err)
	}
}

func TestParseMineAddressRejectsInvalidCanonicalEncoding(t *testing.T) {
	raw := bytes.Repeat([]byte{0x22}, consensus.MAX_P2PK_COVENANT_DATA)
	raw[0] = 0x03
	_, err := ParseMineAddress(strings.ToUpper(bytesToHex(raw)))
	if err == nil || !strings.Contains(err.Error(), "unsupported suite_id") {
		t.Fatalf("expected suite validation error, got %v", err)
	}

	short := bytes.Repeat([]byte{0x11}, mineAddressKeyIDBytes-1)
	_, err = ParseMineAddress(bytesToHex(short))
	if err == nil || !strings.Contains(err.Error(), "expected 32-byte key_id or 33-byte covenant_data") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func bytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0f]
	}
	return string(out)
}

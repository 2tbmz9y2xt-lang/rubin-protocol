package crypto

import (
	"bytes"
	"testing"
)

func TestAESKW_Roundtrip(t *testing.T) {
	kek := bytes.Repeat([]byte{0x11}, 32)
	keyIn := bytes.Repeat([]byte{0x22}, 32)
	wrapped, err := AESKeyWrapRFC3394(kek, keyIn)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := AESKeyUnwrapRFC3394(kek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, keyIn) {
		t.Fatalf("unwrap mismatch")
	}
}

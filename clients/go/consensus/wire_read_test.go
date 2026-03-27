package consensus

import "testing"

func TestReadBytes_RejectsInvalidOffsets(t *testing.T) {
	buf := []byte{0x01, 0x02, 0x03}

	for _, off := range []int{-1, len(buf) + 1, int(^uint(0) >> 1)} {
		off := off
		t.Run("off", func(t *testing.T) {
			_, err := readBytes(buf, &off, 1)
			if err == nil {
				t.Fatalf("expected error for invalid offset=%d", off)
			}
			if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
				t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
			}
		})
	}
}

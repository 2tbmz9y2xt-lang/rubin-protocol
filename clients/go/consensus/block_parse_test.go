package consensus

import "testing"

func TestParseBlockHeaderBytes_RoundtripFields(t *testing.T) {
	prev := hashWithPrefix(0x01)
	root := hashWithPrefix(0x02)
	target := filledHash(0xff)
	version := uint32(7)
	timestamp := uint64(11)
	nonce := uint64(13)

	b := make([]byte, 0, BLOCK_HEADER_BYTES)
	b = AppendU32le(b, version)
	b = append(b, prev[:]...)
	b = append(b, root[:]...)
	b = AppendU64le(b, timestamp)
	b = append(b, target[:]...)
	b = AppendU64le(b, nonce)
	if len(b) != BLOCK_HEADER_BYTES {
		t.Fatalf("header len=%d", len(b))
	}

	h, err := ParseBlockHeaderBytes(b)
	if err != nil {
		t.Fatalf("ParseBlockHeaderBytes: %v", err)
	}
	if h.Version != version || h.PrevBlockHash != prev || h.MerkleRoot != root || h.Timestamp != timestamp || h.Target != target || h.Nonce != nonce {
		t.Fatalf("parsed mismatch: %#v", h)
	}
}

func TestParseBlockHeaderBytes_TooShort(t *testing.T) {
	_, err := ParseBlockHeaderBytes(make([]byte, BLOCK_HEADER_BYTES-1))
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestParseBlockHeaderBytes_TruncationPoints(t *testing.T) {
	// Exercise each early-return error path from readU32le/readBytes/readU64le.
	cases := []struct {
		name string
		n    int
	}{
		{name: "no_version", n: 0},
		{name: "short_version", n: 3},
		{name: "short_prev", n: 4 + 31},
		{name: "short_merkle", n: 4 + 32 + 31},
		{name: "short_timestamp", n: 4 + 32 + 32 + 7},
		{name: "short_target", n: 4 + 32 + 32 + 8 + 31},
		{name: "short_nonce", n: 4 + 32 + 32 + 8 + 32 + 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseBlockHeaderBytes(make([]byte, tc.n))
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
				t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
			}
		})
	}
}

func TestBlockHash_InvalidLen(t *testing.T) {
	_, err := BlockHash(nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestBlockHash_HashMatchesSHA3(t *testing.T) {
	header := make([]byte, BLOCK_HEADER_BYTES)
	header[0] = 0x42
	h, err := BlockHash(header)
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}
	want := sha3_256(header)
	if h != want {
		t.Fatalf("hash mismatch")
	}
}

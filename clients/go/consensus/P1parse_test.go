package consensus

import (
	"bytes"
	"testing"
)

func makeParseCoinbaseTx(height uint32) Tx {
	return Tx{
		Version: 1,
		TxNonce: 0,
		Inputs: []TxInput{
			{
				PrevTxid: [32]byte{},
				PrevVout: TX_COINBASE_PREVOUT_VOUT,
				Sequence: TX_COINBASE_PREVOUT_VOUT,
			},
		},
		Outputs: []TxOutput{
			{
				Value:        0,
				CovenantType: CORE_P2PK,
				CovenantData: bytes.Repeat([]byte{0x11}, 33),
			},
		},
		Locktime: uint32(height),
		Witness:  WitnessSection{},
	}
}

func makeParseTxFixture() Tx {
	return Tx{
		Version: 1,
		TxNonce: 1,
		Inputs: []TxInput{
			{
				PrevTxid:  [32]byte{0x11},
				PrevVout:  0,
				ScriptSig: nil,
				Sequence:  9,
			},
		},
		Outputs: []TxOutput{
			{
				Value:        100,
				CovenantType: CORE_P2PK,
				CovenantData: bytes.Repeat([]byte{0xaa}, 33),
			},
		},
		Locktime: 12345,
		Witness: WitnessSection{
			Witnesses: []WitnessItem{{
				SuiteID:   SUITE_ID_ML_DSA,
				Pubkey:    bytes.Repeat([]byte{0x11}, ML_DSA_PUBKEY_BYTES),
				Signature: bytes.Repeat([]byte{0x22}, ML_DSA_SIG_BYTES),
			}},
		},
	}
}

func TestParseTxBytes(t *testing.T) {
	t.Run("valid tx (1 input + 1 output + ML-DSA witness)", func(t *testing.T) {
		tx := makeParseTxFixture()
		raw := TxBytes(&tx)
		parsed, err := ParseTxBytes(raw)
		if err != nil {
			t.Fatalf("expected parse success: %v", err)
		}
		if parsed.TxNonce != tx.TxNonce || parsed.Locktime != tx.Locktime {
			t.Fatalf("parsed tx mismatch: got %#v want %#v", parsed, tx)
		}
	})

	t.Run("trailing bytes -> parse: trailing bytes", func(t *testing.T) {
		tx := makeParseTxFixture()
		raw := append(TxBytes(&tx), 0x00)
		if _, err := ParseTxBytes(raw); err == nil || err.Error() != "parse: trailing bytes" {
			t.Fatalf("expected trailing bytes parse error, got %v", err)
		}
	})

	t.Run("truncated на каждом поле", func(t *testing.T) {
		tx := makeParseTxFixture()
		full := TxBytes(&tx)
		for i := 0; i < len(full); i++ {
			if _, err := ParseTxBytes(full[:i]); err == nil {
				t.Fatalf("expected truncation error at len=%d", i)
			}
		}
	})

	t.Run("compactsize overflow в input_count", func(t *testing.T) {
		raw := make([]byte, 0, 12+9)
		raw = append(raw, []byte{0x01, 0x00, 0x00, 0x00}...)
		raw = append(raw, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
		raw = append(raw, 0xff)
		raw = append(raw, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80)
		if _, err := ParseTxBytes(raw); err == nil {
			t.Fatal("expected compactsize overflow to fail")
		}
	})
}

func TestParseBlockBytes(t *testing.T) {
	header := BlockHeader{
		Version:       1,
		PrevBlockHash: [32]byte{},
		MerkleRoot:    [32]byte{0x11},
		Timestamp:     100,
		Target:        [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Nonce:         7,
	}

	t.Run("coinbase-only block", func(t *testing.T) {
		cb := makeParseCoinbaseTx(0)
		block := Block{Header: header, Transactions: []Tx{cb}}
		block.Header.MerkleRoot, _ = merkleRootTxIDs(applyTxStubProvider{}, []*Tx{&block.Transactions[0]})
		raw := BlockBytes(&block)
		parsed, err := ParseBlockBytes(raw)
		if err != nil {
			t.Fatalf("expected parse success: %v", err)
		}
		if len(parsed.Transactions) != 1 {
			t.Fatalf("unexpected tx count: %d", len(parsed.Transactions))
		}
	})

	t.Run("coinbase + 2 tx", func(t *testing.T) {
		cb := makeParseCoinbaseTx(0)
		spend := makeParseTxFixture()
		block := Block{Header: header, Transactions: []Tx{cb, spend}}
		block.Header.MerkleRoot, _ = merkleRootTxIDs(applyTxStubProvider{}, []*Tx{&block.Transactions[0], &block.Transactions[1]})
		raw := BlockBytes(&block)
		if _, err := ParseBlockBytes(raw); err != nil {
			t.Fatalf("expected parse success: %v", err)
		}
	})

	t.Run("trailing bytes -> BLOCK_ERR_PARSE", func(t *testing.T) {
		cb := makeParseCoinbaseTx(0)
		block := Block{Header: header, Transactions: []Tx{cb}}
		block.Header.MerkleRoot, _ = merkleRootTxIDs(applyTxStubProvider{}, []*Tx{&block.Transactions[0]})
		raw := append(BlockBytes(&block), 0x00, 0x11, 0x22)
		if _, err := ParseBlockBytes(raw); err == nil || err.Error() != "BLOCK_ERR_PARSE" {
			t.Fatalf("expected BLOCK_ERR_PARSE, got %v", err)
		}
	})
}

func TestParseBlockHeader(t *testing.T) {
	header := BlockHeader{
		Version:   4,
		Timestamp: 0x1122334455667788,
		Nonce:     0x99aabbccddeeff00,
		Target:    [32]byte{0x01, 0x02, 0x03},
	}
	copy(header.PrevBlockHash[:], bytes.Repeat([]byte{0xaa}, 32))
	copy(header.MerkleRoot[:], bytes.Repeat([]byte{0xbb}, 32))

	t.Run("correct 116-байтовый header", func(t *testing.T) {
		raw := BlockHeaderBytes(header)
		parsed, err := ParseBlockHeader(newCursor(raw))
		if err != nil {
			t.Fatalf("expected parse success: %v", err)
		}
		if parsed != header {
			t.Fatalf("header mismatch: got %#v want %#v", parsed, header)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		raw := BlockHeaderBytes(header)
		for i := 0; i < len(raw); i++ {
			if _, err := ParseBlockHeader(newCursor(raw[:i])); err == nil {
				t.Fatalf("expected truncation parse error at len=%d", i)
			}
		}
	})
}

func TestParseOutput(t *testing.T) {
	t.Run("CORE_P2PK", func(t *testing.T) {
		out := TxOutput{Value: 1, CovenantType: CORE_P2PK, CovenantData: make([]byte, 33)}
		raw := TxOutputBytes(out)
		parsed, err := parseOutput(newCursor(raw))
		if err != nil {
			t.Fatalf("parse p2pk output: %v", err)
		}
		if parsed.CovenantType != CORE_P2PK || parsed.Value != out.Value || len(parsed.CovenantData) != len(out.CovenantData) {
			t.Fatalf("unexpected output: %#v", parsed)
		}
	})

	t.Run("CORE_TIMELOCK_V1", func(t *testing.T) {
		out := TxOutput{Value: 1, CovenantType: CORE_TIMELOCK_V1, CovenantData: make([]byte, 9)}
		raw := TxOutputBytes(out)
		parsed, err := parseOutput(newCursor(raw))
		if err != nil {
			t.Fatalf("parse timelock output: %v", err)
		}
		if parsed.CovenantType != CORE_TIMELOCK_V1 || len(parsed.CovenantData) != 9 {
			t.Fatalf("unexpected output: %#v", parsed)
		}
	})

	t.Run("CORE_HTLC_V1", func(t *testing.T) {
		out := TxOutput{Value: 1, CovenantType: CORE_HTLC_V1, CovenantData: make([]byte, 105)}
		raw := TxOutputBytes(out)
		parsed, err := parseOutput(newCursor(raw))
		if err != nil {
			t.Fatalf("parse htlc_v1 output: %v", err)
		}
		if parsed.CovenantType != CORE_HTLC_V1 || len(parsed.CovenantData) != 105 {
			t.Fatalf("unexpected output: %#v", parsed)
		}
	})

	t.Run("CORE_VAULT_V1", func(t *testing.T) {
		out := TxOutput{Value: 1, CovenantType: CORE_VAULT_V1, CovenantData: make([]byte, 73)}
		raw := TxOutputBytes(out)
		parsed, err := parseOutput(newCursor(raw))
		if err != nil {
			t.Fatalf("parse vault output: %v", err)
		}
		if parsed.CovenantType != CORE_VAULT_V1 || len(parsed.CovenantData) != 73 {
			t.Fatalf("unexpected output: %#v", parsed)
		}
	})
}

func TestParseWitnessItem(t *testing.T) {
	t.Run("SENTINEL", func(t *testing.T) {
		item := WitnessItem{SuiteID: SUITE_ID_SENTINEL}
		raw := WitnessItemBytes(item)
		parsed, err := parseWitnessItem(newCursor(raw))
		if err != nil {
			t.Fatalf("parse sentinel witness: %v", err)
		}
		if parsed.SuiteID != SUITE_ID_SENTINEL || len(parsed.Pubkey) != 0 || len(parsed.Signature) != 0 {
			t.Fatalf("unexpected witness: %#v", parsed)
		}
	})

	t.Run("ML-DSA", func(t *testing.T) {
		item := WitnessItem{
			SuiteID:   SUITE_ID_ML_DSA,
			Pubkey:    bytes.Repeat([]byte{0x01}, ML_DSA_PUBKEY_BYTES),
			Signature: bytes.Repeat([]byte{0x02}, ML_DSA_SIG_BYTES),
		}
		raw := WitnessItemBytes(item)
		parsed, err := parseWitnessItem(newCursor(raw))
		if err != nil {
			t.Fatalf("parse ml-dsa witness: %v", err)
		}
		if parsed.SuiteID != SUITE_ID_ML_DSA ||
			len(parsed.Pubkey) != ML_DSA_PUBKEY_BYTES ||
			len(parsed.Signature) != ML_DSA_SIG_BYTES {
			t.Fatalf("unexpected witness: %#v", parsed)
		}
	})

	t.Run("SLH-DSA", func(t *testing.T) {
		item := WitnessItem{
			SuiteID:   SUITE_ID_SLH_DSA,
			Pubkey:    bytes.Repeat([]byte{0x03}, SLH_DSA_PUBKEY_BYTES),
			Signature: bytes.Repeat([]byte{0x04}, 128),
		}
		raw := WitnessItemBytes(item)
		parsed, err := parseWitnessItem(newCursor(raw))
		if err != nil {
			t.Fatalf("parse slh-dsa witness: %v", err)
		}
		if parsed.SuiteID != SUITE_ID_SLH_DSA || len(parsed.Pubkey) != SLH_DSA_PUBKEY_BYTES || len(parsed.Signature) != 128 {
			t.Fatalf("unexpected witness: %#v", parsed)
		}
	})

	t.Run("unknown suite", func(t *testing.T) {
		item := WitnessItem{
			SuiteID:   0x99,
			Pubkey:    []byte{1, 2, 3},
			Signature: []byte{4, 5},
		}
		raw := WitnessItemBytes(item)
		parsed, err := parseWitnessItem(newCursor(raw))
		if err != nil {
			t.Fatalf("parse unknown witness: %v", err)
		}
		if parsed.SuiteID != 0x99 || !bytes.Equal(parsed.Pubkey, item.Pubkey) || !bytes.Equal(parsed.Signature, item.Signature) {
			t.Fatalf("unexpected parsed values: %#v", parsed)
		}
	})
}

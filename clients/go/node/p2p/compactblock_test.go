package p2p

import (
	"testing"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

func TestSendCmpct_Roundtrip(t *testing.T) {
	raw, err := EncodeSendCmpctPayload(SendCmpctPayload{
		Announce:        1,
		ShortIDWTXID:    1,
		ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := DecodeSendCmpctPayload(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Announce != 1 || dec.ShortIDWTXID != 1 || dec.ProtocolVersion != 1 {
		t.Fatalf("unexpected decoded payload: %+v", *dec)
	}
}

func TestCmpctBlock_Roundtrip(t *testing.T) {
	// Minimal header; only parsing/encoding is tested here.
	h := consensus.BlockHeader{
		Version:       1,
		PrevBlockHash: [32]byte{},
		MerkleRoot:    [32]byte{},
		Timestamp:     123,
		Target:        [32]byte{},
		Nonce:         7,
	}

	tx := consensus.Tx{
		Version:  consensus.TX_VERSION_V2,
		TxKind:   consensus.TX_KIND_STANDARD,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: [32]byte{}, PrevVout: 0, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: 0, CovenantType: consensus.CORE_P2PK, CovenantData: nil}},
		Locktime: 0,
		Witness:  consensus.WitnessSection{Witnesses: nil},
	}
	txb := consensus.TxBytes(&tx)

	p := CmpctBlockPayload{
		Header:   h,
		Nonce:    42,
		TxCount:  2,
		ShortIDs: [][CompactBlockShortIDBytes]byte{{1, 2, 3, 4, 5, 6}},
		Prefilled: []PrefilledTx{
			{Index: 0, TxBytes: txb},
		},
	}

	raw, err := EncodeCmpctBlockPayload(p)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dec, err := DecodeCmpctBlockPayload(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.TxCount != p.TxCount {
		t.Fatalf("tx_count mismatch: %d != %d", dec.TxCount, p.TxCount)
	}
	if len(dec.ShortIDs) != 1 || dec.ShortIDs[0] != p.ShortIDs[0] {
		t.Fatalf("shortids mismatch")
	}
	if len(dec.Prefilled) != 1 || dec.Prefilled[0].Index != 0 {
		t.Fatalf("prefilled mismatch")
	}
	if string(dec.Prefilled[0].TxBytes) != string(txb) {
		t.Fatalf("prefilled tx bytes mismatch")
	}
}

func TestShortID_Deterministic(t *testing.T) {
	cp := crypto.DevStdCryptoProvider{}
	h := consensus.BlockHeader{
		Version:       1,
		PrevBlockHash: [32]byte{},
		MerkleRoot:    [32]byte{},
		Timestamp:     1,
		Target:        [32]byte{},
		Nonce:         2,
	}
	tx := consensus.Tx{
		Version:  consensus.TX_VERSION_V2,
		TxKind:   consensus.TX_KIND_STANDARD,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: [32]byte{}, PrevVout: 0, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: 0, CovenantType: consensus.CORE_P2PK, CovenantData: nil}},
		Locktime: 0,
		Witness:  consensus.WitnessSection{Witnesses: nil},
	}
	txb := consensus.TxBytes(&tx)

	s1, err := ShortID(cp, h, 123, txb)
	if err != nil {
		t.Fatalf("shortid: %v", err)
	}
	s2, err := ShortID(cp, h, 123, txb)
	if err != nil {
		t.Fatalf("shortid: %v", err)
	}
	if s1 != s2 {
		t.Fatalf("shortid not deterministic: %v != %v", s1, s2)
	}
}

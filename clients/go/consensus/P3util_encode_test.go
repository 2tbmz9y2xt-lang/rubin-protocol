package consensus

import (
	"bytes"
	"testing"
)

func TestSubUint64(t *testing.T) {
	t.Run("a>=b -> no error", func(t *testing.T) {
		got, err := subUint64(7, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 4 {
			t.Fatalf("expected 4, got %d", got)
		}
	})

	t.Run("b>a -> TX_ERR_VALUE_CONSERVATION", func(t *testing.T) {
		_, err := subUint64(3, 7)
		if err == nil || err.Error() != "TX_ERR_VALUE_CONSERVATION" {
			t.Fatalf("expected TX_ERR_VALUE_CONSERVATION, got %v", err)
		}
	})
}

func TestIsCoinbaseTx(t *testing.T) {
	t.Run("nil -> false", func(t *testing.T) {
		if isCoinbaseTx(nil, 0) {
			t.Fatalf("expected false for nil tx")
		}
	})

	t.Run("len(inputs)!=1 -> false", func(t *testing.T) {
		tx := &Tx{Inputs: []TxInput{}, Outputs: []TxOutput{}, Witness: WitnessSection{}, TxNonce: 0, Locktime: 1}
		if isCoinbaseTx(tx, 0) {
			t.Fatalf("expected false for input count not 1")
		}
	})

	t.Run("locktime!=height -> false", func(t *testing.T) {
		tx := &Tx{
			Inputs:   []TxInput{{PrevTxid: [32]byte{}, PrevVout: TX_COINBASE_PREVOUT_VOUT, ScriptSig: []byte{}, Sequence: TX_COINBASE_PREVOUT_VOUT}},
			Outputs:  []TxOutput{},
			TxNonce:  0,
			Locktime: 2,
			Witness:  WitnessSection{},
		}
		if isCoinbaseTx(tx, 1) {
			t.Fatalf("expected false when locktime != block height")
		}
	})

	t.Run("all conditions OK -> true", func(t *testing.T) {
		tx := &Tx{
			Inputs:   []TxInput{{PrevTxid: [32]byte{}, PrevVout: TX_COINBASE_PREVOUT_VOUT, ScriptSig: []byte{}, Sequence: TX_COINBASE_PREVOUT_VOUT}},
			Outputs:  []TxOutput{},
			TxNonce:  0,
			Locktime: 1,
			Witness:  WitnessSection{},
		}
		if !isCoinbaseTx(tx, 1) {
			t.Fatalf("expected true for coinbase tx shape")
		}
	})
}

func TestEncodingRoundTrips(t *testing.T) {
	t.Run("BlockHeaderBytes roundtrip", func(t *testing.T) {
		header := BlockHeader{
			Version:       9,
			PrevBlockHash: [32]byte{0x11},
			MerkleRoot:    [32]byte{0x22},
			Timestamp:     98765,
			Target:        [32]byte{0xaa},
			Nonce:         0x7fff,
		}
		parsed, err := ParseBlockHeader(newCursor(BlockHeaderBytes(header)))
		if err != nil {
			t.Fatalf("parse header failed: %v", err)
		}
		if parsed != header {
			t.Fatalf("block header mismatch: got %#v want %#v", parsed, header)
		}
	})

	t.Run("TxBytes roundtrip", func(t *testing.T) {
		tx := &Tx{
			Version:  2,
			TxNonce:  77,
			Inputs:   []TxInput{{PrevTxid: [32]byte{0xaa}, PrevVout: 1, ScriptSig: []byte{1, 2}, Sequence: 9}},
			Outputs:  []TxOutput{{Value: 1, CovenantType: CORE_P2PK, CovenantData: make([]byte, 33)}},
			Locktime: 10,
			Witness:  WitnessSection{Witnesses: []WitnessItem{{SuiteID: SUITE_ID_ML_DSA, Pubkey: make([]byte, ML_DSA_PUBKEY_BYTES), Signature: make([]byte, ML_DSA_SIG_BYTES)}}},
		}
		parsed, err := ParseTxBytes(TxBytes(tx))
		if err != nil {
			t.Fatalf("parse tx failed: %v", err)
		}
		if !txsEqual(parsed, tx) {
			t.Fatalf("tx mismatch: got %#v want %#v", parsed, tx)
		}
	})
}

func txsEqual(a, b *Tx) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Version != b.Version || a.TxNonce != b.TxNonce || a.Locktime != b.Locktime {
		return false
	}
	if len(a.Inputs) != len(b.Inputs) || len(a.Outputs) != len(b.Outputs) || len(a.Witness.Witnesses) != len(b.Witness.Witnesses) {
		return false
	}
	for i := range a.Inputs {
		if a.Inputs[i].PrevTxid != b.Inputs[i].PrevTxid || a.Inputs[i].PrevVout != b.Inputs[i].PrevVout ||
			a.Inputs[i].Sequence != b.Inputs[i].Sequence || !bytes.Equal(a.Inputs[i].ScriptSig, b.Inputs[i].ScriptSig) {
			return false
		}
	}
	for i := range a.Outputs {
		if a.Outputs[i].Value != b.Outputs[i].Value || a.Outputs[i].CovenantType != b.Outputs[i].CovenantType ||
			!bytes.Equal(a.Outputs[i].CovenantData, b.Outputs[i].CovenantData) {
			return false
		}
	}
	for i := range a.Witness.Witnesses {
		if a.Witness.Witnesses[i].SuiteID != b.Witness.Witnesses[i].SuiteID ||
			!bytes.Equal(a.Witness.Witnesses[i].Pubkey, b.Witness.Witnesses[i].Pubkey) ||
			!bytes.Equal(a.Witness.Witnesses[i].Signature, b.Witness.Witnesses[i].Signature) {
			return false
		}
	}
	return true
}

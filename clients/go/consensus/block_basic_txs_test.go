package consensus

import "testing"

// ---------------------------------------------------------------------------
// accumulateBlockResourceStats — error branches
// ---------------------------------------------------------------------------

func TestAccumulateBlockResourceStats_NilTxError(t *testing.T) {
	pb := &ParsedBlock{Txs: []*Tx{nil}}
	_, err := accumulateBlockResourceStats(pb)
	if err == nil {
		t.Fatalf("expected error for nil tx")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

func TestAccumulateBlockResourceStats_SumWeightOverflow(t *testing.T) {
	// Each TX has ScriptSig large enough to produce weight ≈ 2^63 + 2.
	// Two such TXs make addU64(sumWeight, w) overflow on the second iteration.
	//
	// weight = 4*(68 + L) + 1 + 1 + 0  (1 input, 0 outputs, 0 witness, 0 da)
	// We need weight > max_u64 / 2 so that weight+weight overflows.
	// L = 2305843009213693884 gives weight = 9223372036854775810 > 2^63.
	const scriptLen = 2305843009213693884

	makeTx := func() *Tx {
		return &Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  0,
			Inputs:   []TxInput{{ScriptSig: unsafeLenBytes(scriptLen)}},
			Outputs:  nil,
			Locktime: 0,
		}
	}

	pb := &ParsedBlock{Txs: []*Tx{makeTx(), makeTx()}}
	_, err := accumulateBlockResourceStats(pb)
	if err == nil {
		t.Fatalf("expected overflow error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
}

// ---------------------------------------------------------------------------
// validateBlockTxSemantics — error branches
// ---------------------------------------------------------------------------

func TestValidateBlockTxSemantics_NonceReplay(t *testing.T) {
	coinbase := &Tx{
		TxKind:  0x00,
		TxNonce: 0,
		Inputs: []TxInput{{
			PrevTxid: [32]byte{},
			PrevVout: ^uint32(0),
			Sequence: ^uint32(0),
		}},
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}

	nonCB := func(nonce uint64) *Tx {
		return &Tx{
			TxKind:  0x00,
			TxNonce: nonce,
			Inputs: []TxInput{{
				PrevTxid: [32]byte{0x01},
				PrevVout: 0,
				Sequence: 0xffffffff,
			}},
			Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		}
	}

	pb := &ParsedBlock{Txs: []*Tx{coinbase, nonCB(42), nonCB(42)}}
	err := validateBlockTxSemantics(pb, 1)
	if err == nil {
		t.Fatalf("expected TX_ERR_NONCE_REPLAY")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_NONCE_REPLAY {
		t.Fatalf("code=%s, want %s", got, TX_ERR_NONCE_REPLAY)
	}
}

func TestValidateBlockTxSemantics_CovenantError(t *testing.T) {
	coinbase := &Tx{
		TxKind:  0x00,
		TxNonce: 0,
		Inputs: []TxInput{{
			PrevTxid: [32]byte{},
			PrevVout: ^uint32(0),
			Sequence: ^uint32(0),
		}},
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}

	// P2PK with Value=0 is invalid: "CORE_P2PK value must be > 0"
	badCov := &Tx{
		TxKind:  0x00,
		TxNonce: 99,
		Inputs: []TxInput{{
			PrevTxid: [32]byte{0x02},
			PrevVout: 0,
			Sequence: 0xffffffff,
		}},
		Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}

	pb := &ParsedBlock{Txs: []*Tx{coinbase, badCov}}
	err := validateBlockTxSemantics(pb, 1)
	if err == nil {
		t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}
}

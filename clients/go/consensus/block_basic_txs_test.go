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

func TestAddBlockResourceStat_OverflowMessages(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  string
	}{
		{name: "sum_weight", msg: "sum_weight overflow"},
		{name: "sum_da", msg: "sum_da overflow"},
		{name: "sum_anchor", msg: "sum_anchor overflow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := addBlockResourceStat(^uint64(0), 1, tc.msg)
			if err == nil {
				t.Fatalf("expected overflow error")
			}
			if got := mustTxErrCode(t, err); got != TX_ERR_PARSE {
				t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
			}
			want := "TX_ERR_PARSE: " + tc.msg
			if got := err.Error(); got != want {
				t.Fatalf("err=%q, want %q", got, want)
			}
		})
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
		Outputs:  []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Locktime: 1,
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
	err := validateBlockTxSemantics(pb, 1, nil)
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
		Outputs:  []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Locktime: 1,
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
	err := validateBlockTxSemantics(pb, 1, nil)
	if err == nil {
		t.Fatalf("expected TX_ERR_COVENANT_TYPE_INVALID")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COVENANT_TYPE_INVALID)
	}

	var cmr [32]byte
	cmr[0] = 0x44
	simp := &Tx{TxKind: 0x00, TxNonce: 100, Inputs: []TxInput{{PrevTxid: [32]byte{0x03}, Sequence: 0xffffffff}}, Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData(cmr, nil)}}}
	err = validateBlockTxSemantics(&ParsedBlock{Txs: []*Tx{coinbase, simp}}, 1, nil)
	assertTxErrCode(t, err, TX_ERR_COVENANT_TYPE_INVALID)
	if err := validateBlockTxSemantics(&ParsedBlock{Txs: []*Tx{coinbase, simp}}, 1, testRotationProvider{createSuiteID: SUITE_ID_ML_DSA_87}); err != nil {
		t.Fatalf("active CORE_SIMPLICITY block tx semantics: %v", err)
	}
}

// The same-cmr CORE_SIMPLICITY output group cap applies to EVERY transaction,
// coinbase included (RUB-594): a coinbase creating >SIMPLICITY_MAX_GROUP_OUTPUTS
// same-program_cmr CORE_SIMPLICITY outputs at an active deployment height is
// rejected on the block-apply path (validateBlockTxSemantics runs the covenant
// genesis cap for tx index 0).
func TestValidateBlockTxSemantics_CoinbaseCoreSimplicityOutputGroupCap(t *testing.T) {
	var cmr [32]byte
	cmr[0] = 0x77
	rotation := testRotationProvider{createSuiteID: SUITE_ID_ML_DSA_87, simplicityActiveHeight: 1}
	coinbaseWith := func(n int) *Tx {
		outputs := make([]TxOutput, n)
		for i := range outputs {
			outputs[i] = TxOutput{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: encodeSimplicityCovenantData(cmr, nil)}
		}
		return &Tx{
			TxKind:   0x00,
			TxNonce:  0,
			Inputs:   []TxInput{{PrevTxid: [32]byte{}, PrevVout: ^uint32(0), Sequence: ^uint32(0)}},
			Outputs:  outputs,
			Locktime: 1,
		}
	}

	// Exactly the cap of same-cmr CORE_SIMPLICITY outputs in a coinbase is accepted.
	if err := validateBlockTxSemantics(&ParsedBlock{Txs: []*Tx{coinbaseWith(SIMPLICITY_MAX_GROUP_OUTPUTS)}}, 1, rotation); err != nil {
		t.Fatalf("coinbase with SIMPLICITY_MAX_GROUP_OUTPUTS same-cmr outputs must pass: %v", err)
	}
	// One over the cap is rejected on the block-apply path, coinbase included.
	err := validateBlockTxSemantics(&ParsedBlock{Txs: []*Tx{coinbaseWith(SIMPLICITY_MAX_GROUP_OUTPUTS + 1)}}, 1, rotation)
	assertTxErrCodeMsg(t, err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY same-cmr output group exceeds limit")
}

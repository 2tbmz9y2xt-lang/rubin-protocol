package consensus

import "testing"

func makeCoreSimplicityCovenantData(programCMR [32]byte, state []byte) []byte {
	out := make([]byte, 0, 32+1+len(state))
	out = append(out, programCMR[:]...)
	out = AppendCompactSize(out, uint64(len(state)))
	out = append(out, state...)
	return out
}

func TestBuildSimplicityTxContext_NoCoreSimplicityInputReturnsNil(t *testing.T) {
	tx := &Tx{
		Version:  TX_WIRE_VERSION,
		TxNonce:  1,
		Locktime: 9,
		Inputs:   []TxInput{{PrevVout: 0}},
		Outputs:  []TxOutput{{Value: 5, CovenantType: COV_TYPE_P2PK}},
	}
	resolved := []UtxoEntry{{Value: 10, CovenantType: COV_TYPE_P2PK}}

	ctx, err := BuildSimplicityTxContext(tx, resolved, 77, [32]byte{0x01})
	if err != nil {
		t.Fatalf("BuildSimplicityTxContext: %v", err)
	}
	if ctx != nil {
		t.Fatalf("expected nil context, got %#v", ctx)
	}

	if _, err := BuildSimplicityTxContext(nil, nil, 1, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected nil tx parse error, got %v", err)
	}
	tx.Inputs = append(tx.Inputs, TxInput{PrevVout: 1})
	if _, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected resolved input mismatch, got %v", err)
	}
}

func TestBuildSimplicityTxContext_BaseInputsOutputsAndSelf(t *testing.T) {
	chainID := [32]byte{0: 0x11, 31: 0xee}
	cmr := [32]byte{0: 0xaa, 31: 0xbb}
	digest := [32]byte{0: 0x42}
	state := []byte{0x01, 0x02, 0x03}
	simplicityCovenant := makeCoreSimplicityCovenantData(cmr, state)

	tx := &Tx{
		Version:  TX_WIRE_VERSION,
		TxKind:   0x02,
		TxNonce:  99,
		Locktime: 12345,
		Inputs:   []TxInput{{PrevVout: 0}, {PrevVout: 1}},
		Outputs: []TxOutput{
			{Value: ^uint64(0), CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmr, nil)},
			{Value: 1, CovenantType: COV_TYPE_P2PK},
		},
	}
	resolved := []UtxoEntry{
		{Value: ^uint64(0), CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: simplicityCovenant},
		{Value: 1, CovenantType: COV_TYPE_P2PK},
	}

	ctx, err := BuildSimplicityTxContext(tx, resolved, 700, chainID)
	if err != nil {
		t.Fatalf("BuildSimplicityTxContext: %v", err)
	}
	if ctx == nil {
		t.Fatalf("expected context")
	}
	if got := ctx.Base.ChainID; got != chainID {
		t.Fatalf("chain_id=%x want %x", got, chainID)
	}
	if ctx.Base.Height != 700 || ctx.Base.TxKind != 0x02 || ctx.Base.TxNonce != 99 || ctx.Base.Locktime != 12345 {
		t.Fatalf("base scalar fields mismatch: %+v", ctx.Base)
	}
	if ctx.Base.InputCount != 2 || ctx.Base.OutputCount != 2 {
		t.Fatalf("counts=%d/%d want 2/2", ctx.Base.InputCount, ctx.Base.OutputCount)
	}
	if got := ctx.Base.TotalIn; got != (Uint128{Lo: 0, Hi: 1}) {
		t.Fatalf("total_in=%+v want hi carry", got)
	}
	if got := ctx.Base.TotalOut; got != (Uint128{Lo: 0, Hi: 1}) {
		t.Fatalf("total_out=%+v want hi carry", got)
	}

	inputs := ctx.InputViews()
	if len(inputs) != 2 || inputs[0] != (SimplicityTxContextIOView{Value: ^uint64(0), CovenantType: COV_TYPE_CORE_SIMPLICITY}) {
		t.Fatalf("input views=%+v", inputs)
	}
	outputs := ctx.OutputViews()
	if len(outputs) != 2 || outputs[1] != (SimplicityTxContextIOView{Value: 1, CovenantType: COV_TYPE_P2PK}) {
		t.Fatalf("output views=%+v", outputs)
	}

	self, err := ctx.SelfView(0, SIGHASH_ALL, digest)
	if err != nil {
		t.Fatalf("SelfView: %v", err)
	}
	if self.InputIndex != 0 || self.SelfValue != ^uint64(0) || self.SighashType != SIGHASH_ALL {
		t.Fatalf("self scalar fields mismatch: %+v", self)
	}
	if self.SelfProgramCMR != cmr || self.Digest32 != digest {
		t.Fatalf("self cmr/digest mismatch")
	}
	if string(self.SelfState) != string(state) {
		t.Fatalf("self state=%x want %x", self.SelfState, state)
	}

	if _, err := ctx.SelfView(1, SIGHASH_ALL, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected non-CORE_SIMPLICITY self error, got %v", err)
	}
	if _, err := ctx.SelfView(2, SIGHASH_ALL, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected out-of-range self error, got %v", err)
	}
}

func TestBuildSimplicityTxContext_EmptyStateIsNonNilAndAliasingSafe(t *testing.T) {
	cmr := [32]byte{0: 0x51}
	covenantData := makeCoreSimplicityCovenantData(cmr, nil)
	tx := &Tx{Version: TX_WIRE_VERSION, Inputs: []TxInput{{PrevVout: 0}}}
	resolved := []UtxoEntry{{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: covenantData}}

	ctx, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{})
	if err != nil {
		t.Fatalf("BuildSimplicityTxContext: %v", err)
	}
	if ctx == nil {
		t.Fatalf("expected context")
	}

	covenantData[0] = 0xff
	self, err := ctx.SelfView(0, SIGHASH_ALL, [32]byte{})
	if err != nil {
		t.Fatalf("SelfView: %v", err)
	}
	if self.SelfProgramCMR != cmr {
		t.Fatalf("self program CMR aliases source covenant data")
	}
	if self.SelfState == nil {
		t.Fatalf("empty self_state must be non-nil")
	}
	if len(self.SelfState) != 0 {
		t.Fatalf("empty self_state len=%d want 0", len(self.SelfState))
	}

	self.SelfState = append(self.SelfState, 0xaa)
	selfAgain, err := ctx.SelfView(0, SIGHASH_ALL, [32]byte{})
	if err != nil {
		t.Fatalf("SelfView again: %v", err)
	}
	if len(selfAgain.SelfState) != 0 {
		t.Fatalf("self_state accessor must return a fresh copy, got %x", selfAgain.SelfState)
	}

	inputs := ctx.InputViews()
	inputs[0].Value = 99
	if got := ctx.InputViews()[0].Value; got != 1 {
		t.Fatalf("input views must return a fresh copy, got value %d", got)
	}
}

func TestBuildSimplicityTxContext_MalformedSelfCovenantFailsClosed(t *testing.T) {
	tx := &Tx{Version: TX_WIRE_VERSION, Inputs: []TxInput{{PrevVout: 0}}}
	resolved := []UtxoEntry{{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: []byte{0x01}}}

	_, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{})
	if err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected malformed CORE_SIMPLICITY covenant error, got %v", err)
	}
}

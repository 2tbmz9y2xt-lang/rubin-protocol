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
		DaChunkCore: &DaChunkCore{
			ChunkIndex: 1,
		},
		Inputs: []TxInput{{PrevVout: 0}, {PrevVout: 1}},
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
	simplicityCovenant[len(simplicityCovenant)-1] = 0xff
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

	if got, err := ctx.SelfView(1, SIGHASH_ALL, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected non-CORE_SIMPLICITY self error, got %v", err)
	} else if !isZeroSimplicitySelfView(got) {
		t.Fatalf("SelfView error must return zero view, got %+v", got)
	}
	if got, err := ctx.SelfView(2, SIGHASH_ALL, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected out-of-range self error, got %v", err)
	} else if !isZeroSimplicitySelfView(got) {
		t.Fatalf("SelfView out-of-range error must return zero view, got %+v", got)
	}
	if got, err := ctx.SameCMRView(1); err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected non-CORE_SIMPLICITY same-CMR error, got %v", err)
	} else if !isZeroSimplicitySameCMRView(got) {
		t.Fatalf("SameCMRView error must return zero view, got %+v", got)
	}
}

func TestBuildSimplicityTxContext_SameCMRViewProjection(t *testing.T) {
	cmrA := [32]byte{0: 0xa0}
	cmrB := [32]byte{0: 0xb0}
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}, {PrevVout: 1}, {PrevVout: 2}},
		Outputs: []TxOutput{
			{Value: 44, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmrA, []byte{0x04})},
			{Value: 55, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmrB, []byte{0x05})},
		},
	}
	resolved := []UtxoEntry{
		{Value: 11, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmrA, []byte{0x01})},
		{Value: 22, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmrB, []byte{0x02})},
		{Value: 33, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmrA, []byte{0x03})},
	}
	ctx, err := BuildSimplicityTxContext(tx, resolved, 7, [32]byte{})
	if err != nil {
		t.Fatalf("BuildSimplicityTxContext: %v", err)
	}

	viewA, err := ctx.SameCMRView(0)
	if err != nil {
		t.Fatalf("SameCMRView: %v", err)
	}
	if viewA.ProgramCMR != cmrA || len(viewA.Inputs) != 2 || len(viewA.Outputs) != 1 ||
		viewA.Inputs[0].Value != 11 || string(viewA.Inputs[0].State) != "\x01" ||
		viewA.Inputs[1].Value != 33 || string(viewA.Inputs[1].State) != "\x03" ||
		viewA.Outputs[0].Value != 44 || string(viewA.Outputs[0].State) != "\x04" {
		t.Fatalf("same-CMR projection mismatch: %+v", viewA)
	}
	viewA.Inputs[0].State[0] = 0xff
	viewAgain, err := ctx.SameCMRView(0)
	if err != nil {
		t.Fatalf("SameCMRView again: %v", err)
	}
	if string(viewAgain.Inputs[0].State) != "\x01" {
		t.Fatalf("same-CMR state must be copied, got %x", viewAgain.Inputs[0].State)
	}

	viewB, err := ctx.SameCMRView(1)
	if err != nil {
		t.Fatalf("SameCMRView B: %v", err)
	}
	if viewB.ProgramCMR != cmrB || len(viewB.Inputs) != 1 || len(viewB.Outputs) != 1 ||
		viewB.Inputs[0].Value != 22 || string(viewB.Inputs[0].State) != "\x02" ||
		viewB.Outputs[0].Value != 55 || string(viewB.Outputs[0].State) != "\x05" {
		t.Fatalf("foreign CMR leaked into own-CMR view: %+v", viewB)
	}
	if got, err := ctx.SameCMRView(3); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected out-of-range same-CMR error, got %v", err)
	} else if !isZeroSimplicitySameCMRView(got) {
		t.Fatalf("SameCMRView out-of-range error must return zero view, got %+v", got)
	}
}

func TestBuildSimplicityTxContext_InvalidCoreSimplicityOutputFailsClosed(t *testing.T) {
	cmr := [32]byte{0: 0xba}
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		Inputs:  []TxInput{{PrevVout: 0}},
		Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmr, nil)}},
	}
	resolved := []UtxoEntry{{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmr, nil)}}

	if _, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected invalid CORE_SIMPLICITY output error, got %v", err)
	}
}

func isZeroSimplicitySelfView(view SimplicityTxContextSelfView) bool {
	return view.InputIndex == 0 &&
		view.SelfValue == 0 &&
		view.SighashType == 0 &&
		view.SelfProgramCMR == [32]byte{} &&
		view.Digest32 == [32]byte{} &&
		len(view.SelfState) == 0
}

func isZeroSimplicitySameCMRView(view SimplicityTxContextSameCMRView) bool {
	return view.ProgramCMR == [32]byte{} &&
		len(view.Inputs) == 0 &&
		len(view.Outputs) == 0
}

func TestBuildSimplicityTxContext_SameCMRInputCap(t *testing.T) {
	cmr := [32]byte{0: 0xc0}
	tx := &Tx{Version: TX_WIRE_VERSION, Inputs: make([]TxInput, SIMPLICITY_MAX_GROUP_INPUTS+1)}
	resolved := make([]UtxoEntry, len(tx.Inputs))
	for i := range resolved {
		tx.Inputs[i] = TxInput{PrevVout: uint32(i)}
		resolved[i] = UtxoEntry{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmr, []byte{byte(i)})}
	}
	exactTx := *tx
	exactTx.Inputs = exactTx.Inputs[:SIMPLICITY_MAX_GROUP_INPUTS]
	if _, err := BuildSimplicityTxContext(&exactTx, resolved[:SIMPLICITY_MAX_GROUP_INPUTS], 1, [32]byte{}); err != nil {
		t.Fatalf("8 same-CMR inputs must pass cap: %v", err)
	}
	resolved[SIMPLICITY_MAX_GROUP_INPUTS].CovenantData = makeCoreSimplicityCovenantData([32]byte{0: 0xc1}, nil)
	if _, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{}); err != nil {
		t.Fatalf("9 split-CMR inputs must pass cap: %v", err)
	}
	resolved[SIMPLICITY_MAX_GROUP_INPUTS].CovenantData = makeCoreSimplicityCovenantData(cmr, nil)
	if _, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_COVENANT_TYPE_INVALID {
		t.Fatalf("expected same-CMR input cap error, got %v", err)
	}
}

func TestBuildSimplicityTxContext_DAView(t *testing.T) {
	cmr := [32]byte{0: 0xd0}
	daID := [32]byte{0: 0x01}
	resolved := []UtxoEntry{{Value: 1, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(cmr, nil)}}
	build := func(name string, tx *Tx) (SimplicityTxContextDAView, error) {
		t.Helper()
		tx.Version = TX_WIRE_VERSION
		tx.Inputs = []TxInput{{PrevVout: 0}}
		ctx, err := BuildSimplicityTxContext(tx, resolved, 1, [32]byte{})
		if err != nil {
			return SimplicityTxContextDAView{}, err
		}
		return ctx.daView, nil
	}

	batchSig := []byte{0xaa, 0xbb}
	commit, err := build("commit", &Tx{
		TxKind: 0x01,
		DaCommitCore: &DaCommitCore{
			DaID: daID, ChunkCount: 2, BatchNumber: 9,
			BatchSigSuite: SUITE_ID_ML_DSA_87, BatchSig: batchSig,
		},
		DaChunkCore: &DaChunkCore{ChunkIndex: 7},
	})
	if err != nil {
		t.Fatalf("commit view: %v", err)
	}
	want := SimplicityTxContextDAView{Kind: SimplicityTxContextDAViewCommit, Commit: SimplicityTxContextDACommitView{DaID: daID, ChunkCount: 2, BatchNumber: 9}}
	if commit != want {
		t.Fatalf("DA commit view mismatch: got %+v want %+v", commit, want)
	}
	batchSig[0] = 0xff
	if commit != want {
		t.Fatalf("DA commit view must exclude batch_sig and ignore stale chunk core: %+v", commit)
	}

	chunkHash := [32]byte{0: 0x03}
	for _, tc := range []struct {
		name string
		tx   *Tx
		want SimplicityTxContextDAView
	}{
		{"absent ignores stale cores", &Tx{TxKind: 0x00, DaCommitCore: &DaCommitCore{DaID: daID}, DaChunkCore: &DaChunkCore{DaID: daID, ChunkIndex: 1}}, SimplicityTxContextDAView{Kind: SimplicityTxContextDAViewAbsent}},
		{"chunk ignores stale commit", &Tx{TxKind: 0x02, DaCommitCore: &DaCommitCore{DaID: [32]byte{0: 0xff}}, DaChunkCore: &DaChunkCore{DaID: daID, ChunkIndex: 4, ChunkHash: chunkHash}}, SimplicityTxContextDAView{Kind: SimplicityTxContextDAViewChunk, Chunk: SimplicityTxContextDAChunkView{DaID: daID, ChunkIndex: 4, ChunkHash: chunkHash}}},
	} {
		got, err := build(tc.name, tc.tx)
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %+v err=%v want %+v", tc.name, got, err, tc.want)
		}
	}
	for _, tc := range []struct {
		name string
		tx   *Tx
	}{
		{"missing commit core", &Tx{TxKind: 0x01}},
		{"missing chunk core", &Tx{TxKind: 0x02}},
		{"unsupported tx kind", &Tx{TxKind: 0x03}},
		{"zero commit chunk count", &Tx{TxKind: 0x01, DaCommitCore: &DaCommitCore{ChunkCount: 0}}},
		{"too many commit chunks", &Tx{TxKind: 0x01, DaCommitCore: &DaCommitCore{ChunkCount: uint16(MAX_DA_CHUNK_COUNT + 1)}}},
		{"chunk index out of range", &Tx{TxKind: 0x02, DaChunkCore: &DaChunkCore{ChunkIndex: uint16(MAX_DA_CHUNK_COUNT)}}},
	} {
		if _, err := build(tc.name, tc.tx); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
			t.Fatalf("%s: expected DA core parse error, got %v", tc.name, err)
		}
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

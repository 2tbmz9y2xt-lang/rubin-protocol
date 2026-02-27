package consensus

import "testing"

func txBytesFromTx(t *testing.T, tx *Tx) []byte {
	t.Helper()
	if tx == nil {
		t.Fatalf("tx must not be nil")
	}

	b := make([]byte, 0, 256)
	b = appendU32le(b, tx.Version)
	b = append(b, tx.TxKind)
	b = appendU64le(b, tx.TxNonce)

	b = appendCompactSize(b, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		b = append(b, in.PrevTxid[:]...)
		b = appendU32le(b, in.PrevVout)
		b = appendCompactSize(b, uint64(len(in.ScriptSig)))
		b = append(b, in.ScriptSig...)
		b = appendU32le(b, in.Sequence)
	}

	b = appendCompactSize(b, uint64(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		b = appendU64le(b, out.Value)
		b = appendU16le(b, out.CovenantType)
		b = appendCompactSize(b, uint64(len(out.CovenantData)))
		b = append(b, out.CovenantData...)
	}

	b = appendU32le(b, tx.Locktime)

	b = appendCompactSize(b, uint64(len(tx.Witness)))
	for _, w := range tx.Witness {
		b = append(b, w.SuiteID)
		b = appendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = appendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}

	b = appendCompactSize(b, uint64(len(tx.DaPayload)))
	b = append(b, tx.DaPayload...)

	return b
}

func TestConnectBlockBasicInMemoryAtHeight_OK_ComputesFeesAndUpdatesState(t *testing.T) {
	height := uint64(1)

	prev := hashWithPrefix(0x77)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	// Spend a single P2PK UTXO: 100 -> 90 (fee=10).
	prevOut := Outpoint{Txid: prev, Vout: 0}
	spendTx := &Tx{
		Version:   1,
		TxKind:    0x00,
		TxNonce:   1,
		Inputs:    []TxInput{{PrevTxid: prev, PrevVout: 0, ScriptSig: nil, Sequence: 0}},
		Outputs:   []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime:  0,
		Witness:   nil,
		DaPayload: nil,
	}
	spendTx.Witness = []WitnessItem{signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	state := &InMemoryChainState{
		Utxos: map[Outpoint]UtxoEntry{
			prevOut: {
				Value:             100,
				CovenantType:      COV_TYPE_P2PK,
				CovenantData:      covData,
				CreationHeight:    0,
				CreatedByCoinbase: false,
			},
		},
		AlreadyGenerated: 0,
	}

	sumFees := uint64(10)
	subsidy := BlockSubsidy(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})

	// Provide minimal prev_timestamps to exercise MTP branch (k=min(11,height)=1).
	s, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, []uint64{0}, state, [32]byte{})
	if err != nil {
		t.Fatalf("ConnectBlockBasicInMemoryAtHeight: %v", err)
	}

	if s.SumFees != sumFees {
		t.Fatalf("sum_fees=%d, want %d", s.SumFees, sumFees)
	}
	if s.AlreadyGenerated != 0 {
		t.Fatalf("already_generated=%d, want 0", s.AlreadyGenerated)
	}
	if s.AlreadyGeneratedN1 != subsidy {
		t.Fatalf("already_generated_n1=%d, want %d", s.AlreadyGeneratedN1, subsidy)
	}
	// UTXO set should contain spend output + coinbase p2pk output (anchor output is not added).
	if s.UtxoCount != 2 {
		t.Fatalf("utxo_count=%d, want 2", s.UtxoCount)
	}
	if state.AlreadyGenerated != subsidy {
		t.Fatalf("state.already_generated=%d, want %d", state.AlreadyGenerated, subsidy)
	}
}

func TestConnectBlockBasicInMemoryAtHeight_NilState(t *testing.T) {
	height := uint64(0)
	prev := hashWithPrefix(0x11)
	target := filledHash(0xff)

	coinbase := coinbaseWithWitnessCommitmentAtHeight(t, height)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 3, [][]byte{coinbase})

	_, err = ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, nil, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_PARSE)
	}
}

func TestConnectBlockBasicInMemoryAtHeight_Height0_DoesNotAdvanceAlreadyGenerated(t *testing.T) {
	height := uint64(0)
	prev := hashWithPrefix(0x12)
	target := filledHash(0xff)

	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, 1)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 4, [][]byte{coinbase})

	state := &InMemoryChainState{Utxos: nil, AlreadyGenerated: 123}
	s, err := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, state, [32]byte{})
	if err != nil {
		t.Fatalf("ConnectBlockBasicInMemoryAtHeight: %v", err)
	}
	if s.SumFees != 0 {
		t.Fatalf("sum_fees=%d, want 0", s.SumFees)
	}
	if s.AlreadyGenerated != 123 || s.AlreadyGeneratedN1 != 123 || state.AlreadyGenerated != 123 {
		t.Fatalf("already_generated advanced at height=0: %#v / state=%d", s, state.AlreadyGenerated)
	}
	if s.UtxoCount != 1 {
		t.Fatalf("utxo_count=%d, want 1", s.UtxoCount)
	}
}

func TestConnectBlockBasicInMemoryAtHeight_RejectsSubsidyExceeded(t *testing.T) {
	height := uint64(1)

	prev := hashWithPrefix(0x78)
	target := filledHash(0xff)

	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	prevOut := Outpoint{Txid: prev, Vout: 0}
	spendTx := &Tx{
		Version:   1,
		TxKind:    0x00,
		TxNonce:   1,
		Inputs:    []TxInput{{PrevTxid: prev, PrevVout: 0, ScriptSig: nil, Sequence: 0}},
		Outputs:   []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime:  0,
		Witness:   nil,
		DaPayload: nil,
	}
	spendTx.Witness = []WitnessItem{signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx(spend): %v", err)
	}

	state := &InMemoryChainState{
		Utxos: map[Outpoint]UtxoEntry{
			prevOut: {
				Value:             100,
				CovenantType:      COV_TYPE_P2PK,
				CovenantData:      covData,
				CreationHeight:    0,
				CreatedByCoinbase: false,
			},
		},
		AlreadyGenerated: 0,
	}

	sumFees := uint64(10)
	subsidy := BlockSubsidy(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+sumFees+1, spendBytes)
	cbTxid := testTxID(t, coinbase)

	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, prev, root, target, 2, [][]byte{coinbase, spendBytes})

	_, err = ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, height, nil, state, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != BLOCK_ERR_SUBSIDY_EXCEEDED {
		t.Fatalf("code=%s, want %s", got, BLOCK_ERR_SUBSIDY_EXCEEDED)
	}
}

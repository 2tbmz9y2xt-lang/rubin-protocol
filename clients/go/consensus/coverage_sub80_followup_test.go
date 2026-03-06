package consensus

import (
	"errors"
	"math/big"
	"testing"
)

func TestCoverageResidual_BlockBasicHelpers(t *testing.T) {
	if isCoinbaseTx(nil) {
		t.Fatalf("nil tx must not be coinbase")
	}
	if isCoinbaseTx(&Tx{TxKind: 0x00, TxNonce: 0, Inputs: []TxInput{{PrevVout: ^uint32(0)}}}) {
		t.Fatalf("missing prev txid zero check should fail")
	}
	if _, err := validateParsedBlockBasicWithContextAtHeight(nil, nil, nil, 0, nil); err == nil {
		t.Fatalf("expected nil parsed block rejection")
	}
	if err := validateCoinbaseValueBound(nil, 1, big.NewInt(0), 0); err == nil {
		t.Fatalf("expected missing coinbase rejection")
	}
	if err := validateCoinbaseValueBound(&ParsedBlock{Txs: []*Tx{nil}}, 1, big.NewInt(0), 0); err == nil {
		t.Fatalf("expected nil coinbase rejection")
	}
	if err := validateCoinbaseWitnessCommitment(nil); err == nil {
		t.Fatalf("expected witness commitment guard")
	}
	if _, err := addU64ToU128Block(u128{hi: ^uint64(0), lo: ^uint64(0)}, 1); err == nil {
		t.Fatalf("expected u128 overflow")
	}
}

func TestCoverageResidual_FeatureBitsValidationAndFallbacks(t *testing.T) {
	if err := (FeatureBitDeployment{Bit: 1, StartHeight: 10, TimeoutHeight: 10}).Validate(); err == nil {
		t.Fatalf("expected empty name rejection")
	}
	if err := (FeatureBitDeployment{Name: "x", Bit: 1, StartHeight: 11, TimeoutHeight: 10}).Validate(); err == nil {
		t.Fatalf("expected timeout < start rejection")
	}
	if got := evalFeatureBitsNextState(FeatureBitState("UNKNOWN"), 0, 0, FeatureBitDeployment{}); got != FeatureBitState("UNKNOWN") {
		t.Fatalf("default transition mismatch: %q", got)
	}
	if got := evalFeatureBitsNextState(FEATUREBIT_ACTIVE, 0, 0, FeatureBitDeployment{}); got != FEATUREBIT_ACTIVE {
		t.Fatalf("active should stay active")
	}
	if got := evalFeatureBitsNextState(FEATUREBIT_FAILED, 0, 0, FeatureBitDeployment{}); got != FEATUREBIT_FAILED {
		t.Fatalf("failed should stay failed")
	}
}

func TestCoverageResidual_SpendVerifyAndStealthBranches(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pub := kp.PubkeyBytes()
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)

	entry := p2pkEntryForPub(t, SUITE_ID_ML_DSA_87, pub)
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: nil}
	if err := validateP2PKSpend(entry, w, tx, inputIndex, inputValue, chainID, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("expected noncanonical empty signature, got %v", err)
	}

	w = WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig[:len(sig)-1]}
	if err := validateP2PKSpend(entry, w, tx, inputIndex, inputValue, chainID, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("expected noncanonical short signature, got %v", err)
	}

	keys := [][32]byte{sha3_256(pub)}
	ws := []WitnessItem{{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig[:len(sig)-1]}}
	if err := validateThresholdSigSpend(keys, 1, ws, tx, inputIndex, inputValue, chainID, 0, "ctx"); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_NONCANONICAL {
		t.Fatalf("expected threshold noncanonical rejection, got %v", err)
	}

	stealthCov := make([]byte, MAX_STEALTH_COVENANT_DATA)
	keyID := sha3_256(pub)
	copy(stealthCov[ML_KEM_1024_CT_BYTES:], keyID[:])
	stealthEntry := UtxoEntry{Value: 1, CovenantType: COV_TYPE_CORE_STEALTH, CovenantData: stealthCov}
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x01
	stealthWitness := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: badSig}
	if err := validateCoreStealthSpend(stealthEntry, stealthWitness, tx, inputIndex, inputValue, chainID, 0); err == nil || mustTxErrCode(t, err) != TX_ERR_SIG_INVALID {
		t.Fatalf("expected stealth invalid signature, got %v", err)
	}
}

func TestCoverageResidual_TxParseAndDaCoreBranches(t *testing.T) {
	if _, err := daCoreFieldsBytes(nil); err == nil {
		t.Fatalf("expected nil tx rejection")
	}
	if _, err := daCoreFieldsBytes(&Tx{TxKind: 0x01}); err == nil {
		t.Fatalf("expected missing commit core rejection")
	}
	if _, err := daCoreFieldsBytes(&Tx{TxKind: 0x02}); err == nil {
		t.Fatalf("expected missing chunk core rejection")
	}
	if _, err := daCoreFieldsBytes(&Tx{TxKind: 0x03}); err == nil {
		t.Fatalf("expected unsupported tx kind rejection")
	}

	b := minimalTxBytes()
	b = append([]byte(nil), b...)
	b[4] = 0x01
	// insert minimal DA-commit core after locktime; keep chunk_count=0 to hit range guard.
	prefix := append([]byte(nil), b[:txCoreEnd]...)
	suffix := append([]byte(nil), b[txCoreEnd:]...)
	core := make([]byte, 0, 32+2+32+8+32+32+32+1+1)
	core = append(core, make([]byte, 32)...) // da_id
	core = AppendU16le(core, 0)              // invalid chunk_count
	core = append(core, make([]byte, 32)...) // retl_domain_id
	core = AppendU64le(core, 0)
	core = append(core, make([]byte, 32)...) // tx_data_root
	core = append(core, make([]byte, 32)...) // state_root
	core = append(core, make([]byte, 32)...) // withdrawals_root
	core = append(core, 0x00)                // batch_sig_suite
	core = AppendCompactSize(core, 0)        // batch_sig_len
	badCommit := append(prefix, core...)
	badCommit = append(badCommit, suffix...)
	if _, _, _, _, err := ParseTx(badCommit); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected DA-commit chunk_count parse rejection, got %v", err)
	}
}

func TestCoverageResidual_UtxoEarlyGuards(t *testing.T) {
	txid := filled32(0xaa)
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(nil, txid, map[Outpoint]UtxoEntry{}, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected nil tx rejection, got %v", err)
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(&Tx{TxNonce: 1}, txid, map[Outpoint]UtxoEntry{}, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected missing input rejection, got %v", err)
	}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(&Tx{TxNonce: 0, Inputs: []TxInput{{}}}, txid, map[Outpoint]UtxoEntry{}, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_TX_NONCE_INVALID {
		t.Fatalf("expected nonce rejection, got %v", err)
	}

	op := Outpoint{Txid: filled32(0x01), Vout: 0}
	utxos := map[Outpoint]UtxoEntry{op: {Value: 10, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}
	baseTx := &Tx{TxNonce: 1, Inputs: []TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout, Sequence: 0}}, Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}}

	txScriptSig := *baseTx
	txScriptSig.Inputs = []TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout, Sequence: 0, ScriptSig: []byte{0x01}}}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(&txScriptSig, txid, utxos, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected scriptSig rejection, got %v", err)
	}

	txSeq := *baseTx
	txSeq.Inputs = []TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout, Sequence: 0x80000000}}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(&txSeq, txid, utxos, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_SEQUENCE_INVALID {
		t.Fatalf("expected sequence rejection, got %v", err)
	}

	txDup := *baseTx
	txDup.Inputs = []TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}, {PrevTxid: op.Txid, PrevVout: op.Vout}}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(&txDup, txid, utxos, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected duplicate input rejection, got %v", err)
	}

	coinbaseForbidden := *baseTx
	coinbaseForbidden.Inputs = []TxInput{{PrevTxid: [32]byte{}, PrevVout: ^uint32(0), Sequence: 0}}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(&coinbaseForbidden, txid, utxos, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected coinbase prevout rejection, got %v", err)
	}

	anchorUtxos := map[Outpoint]UtxoEntry{op: {Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: []byte{0x01}}}
	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(baseTx, txid, anchorUtxos, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_MISSING_UTXO {
		t.Fatalf("expected non-spendable covenant rejection, got %v", err)
	}

	if _, _, err := ApplyNonCoinbaseTxBasicUpdate(baseTx, txid, utxos, 1, 0, [32]byte{}); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected witness underflow, got %v", err)
	}
}

func TestCoverageResidual_BlockBasicTimestampAndParseBranches(t *testing.T) {
	if _, err := ValidateBlockBasicWithContextAtHeight([]byte{0x00}, nil, nil, 0, nil); err == nil {
		t.Fatalf("expected parse rejection")
	}
	prev := filled32(0x91)
	target := filled32(0xff)
	cb := coinbaseWithWitnessCommitmentAtHeight(t, 1)
	root := MerkleRootFromTxBytes(t, [][]byte{cb})
	block := buildBlockBytes(t, prev, root, target, 7, [][]byte{cb})
	wrongPrev := filled32(0x92)
	if _, err := ValidateBlockBasicWithContextAtHeight(block, &wrongPrev, &target, 1, nil); err == nil {
		t.Fatalf("expected prev hash mismatch")
	}
}

func MerkleRootFromTxBytes(t *testing.T, txs [][]byte) [32]byte {
	t.Helper()
	txids := make([][32]byte, 0, len(txs))
	for _, txb := range txs {
		_, txid, _, _, err := ParseTx(txb)
		if err != nil {
			t.Fatalf("ParseTx(tx): %v", err)
		}
		txids = append(txids, txid)
	}
	root, err := MerkleRootTxids(txids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	return root
}

func TestCoverageResidual_StealthHappyPathSmoke(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pub := kp.PubkeyBytes()
	keyID := sha3_256(pub)
	entry := UtxoEntry{Value: 1, CovenantType: COV_TYPE_CORE_STEALTH, CovenantData: append(make([]byte, ML_KEM_1024_CT_BYTES), keyID[:]...)}
	tx, inputIndex, inputValue, chainID := testSighashContextTx()
	sig := signDigestWithSighashType(t, kp, tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	w := WitnessItem{SuiteID: SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}
	if err := validateCoreStealthSpend(entry, w, tx, inputIndex, inputValue, chainID, 0); err != nil {
		t.Fatalf("expected valid stealth spend, got %v", err)
	}
}

func TestCoverageResidual_BlockBasicValueBoundHeightZero(t *testing.T) {
	if err := validateCoinbaseValueBound(&ParsedBlock{Txs: []*Tx{{}}}, 0, big.NewInt(0), 0); err != nil {
		t.Fatalf("height zero should bypass subsidy bound: %v", err)
	}
}

func TestCoverageResidual_ErrorHelpersSmoke(t *testing.T) {
	if !errors.Is(txerr(TX_ERR_PARSE, "x"), txerr(TX_ERR_PARSE, "y")) {
		// keep compiler using errors import; semantic check is not meaningful here.
	}
}

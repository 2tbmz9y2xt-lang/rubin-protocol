package consensus

import (
	"bytes"
	"reflect"
	"slices"
	"testing"
)

func txWithOneInputOneOutput(prevTxid [32]byte, prevVout uint32, outValue uint64, outCovType uint16, outCovData []byte) []byte {
	return txWithOneInputOneOutputWithWitness(prevTxid, prevVout, outValue, outCovType, outCovData, nil)
}

func txWithOneInputOneOutputWithWitness(
	prevTxid [32]byte,
	prevVout uint32,
	outValue uint64,
	outCovType uint16,
	outCovData []byte,
	witnesses []WitnessItem,
) []byte {
	b := make([]byte, 0, 256+len(outCovData))
	b = AppendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = AppendU64le(b, 1)
	b = AppendCompactSize(b, 1) // input_count
	b = append(b, prevTxid[:]...)
	b = AppendU32le(b, prevVout)
	b = AppendCompactSize(b, 0) // script_sig_len
	b = AppendU32le(b, 0)       // sequence

	b = AppendCompactSize(b, 1) // output_count
	b = AppendU64le(b, outValue)
	b = AppendU16le(b, outCovType)
	b = AppendCompactSize(b, uint64(len(outCovData)))
	b = append(b, outCovData...)

	b = AppendU32le(b, 0) // locktime
	b = AppendCompactSize(b, uint64(len(witnesses)))
	for _, w := range witnesses {
		b = append(b, w.SuiteID)
		b = AppendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = AppendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}
	b = AppendCompactSize(b, 0)
	return b
}

func dummyWitnesses(n int) []WitnessItem {
	witnesses := make([]WitnessItem, 0, n)
	for i := 0; i < n; i++ {
		witnesses = append(witnesses, WitnessItem{
			SuiteID: SUITE_ID_SENTINEL,
		})
	}
	return witnesses
}

func validP2PKCovenantData() []byte {
	b := make([]byte, MAX_P2PK_COVENANT_DATA)
	b[0] = SUITE_ID_ML_DSA_87
	return b
}

func ownerP2PKCovenantDataForVault() []byte {
	b := validP2PKCovenantData()
	b[1] = 0x01
	return b
}

func mustParseTxForUtxo(t *testing.T, txBytes []byte) (*Tx, [32]byte) {
	t.Helper()
	tx, txid, _, _, err := ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return tx, txid
}

func unknown0105WitnessCases() []struct {
	name    string
	witness []WitnessItem
} {
	return []struct {
		name    string
		witness []WitnessItem
	}{
		{name: "none"},
		{name: "extra", witness: dummyWitnesses(2)},
		{name: "wrong_suite", witness: []WitnessItem{{SuiteID: 0x02, Pubkey: make([]byte, 2592), Signature: bytes.Repeat([]byte{0x01}, 4628)}}},
	}
}

func unknown0105InputTx(t *testing.T, witness []WitnessItem) (*Tx, [32]byte) {
	t.Helper()
	raw := txWithOneInputOneOutputWithWitness(hashWithPrefix(0xee), 0, 90, COV_TYPE_P2PK, validP2PKCovenantData(), witness)
	return mustParseTxForUtxo(t, raw)
}

func snapshotRefusalUtxos(utxos map[Outpoint]UtxoEntry) map[Outpoint]UtxoEntry {
	before := make(map[Outpoint]UtxoEntry, len(utxos))
	for op, entry := range utxos {
		entry.CovenantData = bytes.Clone(entry.CovenantData)
		before[op] = entry
	}
	return before
}

func TestApplyNonCoinbaseTxBasicUpdate_Unknown0105NoEffects(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	sibling := Outpoint{Txid: hashWithPrefix(0xef)}
	for _, tc := range unknown0105WitnessCases() {
		t.Run(tc.name, func(t *testing.T) {
			utxos := map[Outpoint]UtxoEntry{
				{Txid: hashWithPrefix(0xee)}: {Value: 100, CovenantType: 0x0105, CovenantData: make([]byte, 1600), CreationHeight: 100},
				sibling:                      {Value: 25, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes()), CreationHeight: 99},
			}
			backend := newLiveSigCacheBackend(t, true, nil)
			tx, txid := unknown0105InputTx(t, tc.witness)
			before := snapshotRefusalUtxos(utxos)
			work, summary, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(tx, txid, utxos, 200, 1, [32]byte{}, nil, nil)
			assertTxErrCode(t, err, "TX_ERR_COVENANT_TYPE_INVALID")
			if work != nil || summary != nil || backend.calls != 0 {
				t.Fatalf("refusal work=%v summary=%v backend calls=%d", work, summary, backend.calls)
			}
			if !reflect.DeepEqual(utxos, before) {
				t.Fatal("unknown input refusal changed the full caller snapshot")
			}
			// An independent retained spend still succeeds on that original snapshot.
			tx, txid = mustParseTxForUtxo(t, txWithOneInputOneOutput(sibling.Txid, 0, 20, COV_TYPE_P2PK, validP2PKCovenantData()))
			tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 25, [32]byte{}, kp)}
			work, summary, err = ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 200, 1, [32]byte{})
			if err != nil || summary == nil || summary.Fee != Uint128FromU64(5) || len(work) != 2 || backend.calls != 1 {
				t.Fatalf("subsequent retained spend summary=%+v work=%v calls=%d err=%v", summary, work, backend.calls, err)
			}
			if !reflect.DeepEqual(utxos, before) {
				t.Fatal("subsequent independent operation changed the supplied snapshot")
			}
		})
	}
}

func TestApplyNonCoinbaseTxBasic_UnassignedInputTags(t *testing.T) {
	for _, tag := range []uint16{0x0001, 0x00ff, 0x0102, 0x0107} {
		tx, txid := unknown0105InputTx(t, nil)
		utxos := map[Outpoint]UtxoEntry{{Txid: hashWithPrefix(0xee)}: {Value: 100, CovenantType: tag, CovenantData: make([]byte, 1600)}}
		before := snapshotRefusalUtxos(utxos)
		work, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 200, 1, [32]byte{})
		assertTxErrCode(t, err, "TX_ERR_COVENANT_TYPE_INVALID")
		if work != nil || summary != nil || !reflect.DeepEqual(utxos, before) {
			t.Fatalf("unassigned tag 0x%04x published work or changed caller UTXOs", tag)
		}
	}
}

func TestApplyNonCoinbaseTxBasic_Unknown0105StageOrder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		nonce  uint64
		inputs []TxInput
		want   ErrorCode
	}{
		{"nonce", 0, nil, "TX_ERR_TX_NONCE_INVALID"},
		{"input_count", 1, nil, "TX_ERR_PARSE"},
		{"output_before_missing", 1, []TxInput{{PrevTxid: hashWithPrefix(0xe1)}}, "TX_ERR_COVENANT_TYPE_INVALID"},
		{"output_before_unsupported", 1, []TxInput{{PrevTxid: hashWithPrefix(0xe2)}}, "TX_ERR_COVENANT_TYPE_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &Tx{Version: 1, TxNonce: tc.nonce, Inputs: tc.inputs, Outputs: []TxOutput{{Value: 1, CovenantType: 0x0105, CovenantData: make([]byte, 1600)}}}
			raw, err := MarshalTx(tx)
			if err != nil {
				t.Fatalf("MarshalTx: %v", err)
			}
			utxos := map[Outpoint]UtxoEntry{{Txid: hashWithPrefix(0xe2)}: {Value: 100, CovenantType: 0x0107, CovenantData: []byte{0xff}}}
			before := snapshotRefusalUtxos(utxos)
			checked, err := CheckTransaction(raw, utxos, 200, 1, [32]byte{})
			assertTxErrCode(t, err, tc.want)
			if checked != nil || !reflect.DeepEqual(utxos, before) {
				t.Fatal("rejection published a result or changed caller UTXOs")
			}
			queue := NewSigCheckQueue(1)
			work, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0xe3), utxos, 200, 1, [32]byte{}, queue, nil, nil)
			assertTxErrCode(t, err, tc.want)
			if work != nil || fee != (Uint128{}) || queue.Len() != 0 || !reflect.DeepEqual(utxos, before) {
				t.Fatal("queued stage rejection published a result or changed caller state")
			}
		})
	}
}

func TestCheckTransaction_Unknown0105KeepsParsePriority(t *testing.T) {
	valid := txWithOneInputOneOutput(hashWithPrefix(0xee), 0, 1, 0x0105, make([]byte, 1600))
	for _, tc := range []struct {
		name string
		raw  []byte
		want ErrorCode
	}{
		{"truncated", valid[:len(valid)-1], "TX_ERR_PARSE"},
		{"registered_witness_shape", txWithOneInputOneOutputWithWitness(hashWithPrefix(0xee), 0, 1, 0x0105, make([]byte, 1600), []WitnessItem{{SuiteID: 0x01, Pubkey: []byte{1}, Signature: []byte{1}}}), "TX_ERR_SIG_NONCANONICAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			utxos := map[Outpoint]UtxoEntry{{Txid: hashWithPrefix(0xee)}: {Value: 100, CovenantType: 0x0105, CovenantData: make([]byte, 1600)}}
			before := snapshotRefusalUtxos(utxos)
			checked, err := CheckTransaction(tc.raw, utxos, 200, 1, [32]byte{})
			assertTxErrCode(t, err, tc.want)
			if checked != nil || !reflect.DeepEqual(utxos, before) {
				t.Fatal("parse rejection published a result or changed caller UTXOs")
			}
		})
	}
}

func TestApplyNonCoinbaseTxBasic_Unknown0105InputOrder(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	prefix, missing, unknown := hashWithPrefix(0xe0), hashWithPrefix(0xe1), hashWithPrefix(0xee)
	for _, tc := range []struct {
		name     string
		first    [32]byte
		second   [32]byte
		extra    bool
		immature bool
		want     ErrorCode
	}{
		{"missing_first", missing, unknown, false, false, "TX_ERR_MISSING_UTXO"},
		{"unknown_first_underflow", unknown, missing, false, false, "TX_ERR_COVENANT_TYPE_INVALID"},
		{"unknown_first_extra", unknown, missing, true, false, "TX_ERR_COVENANT_TYPE_INVALID"},
		{"maturity_before_unknown", unknown, missing, false, true, "TX_ERR_COINBASE_IMMATURE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &Tx{Version: 1, TxNonce: 1, Inputs: []TxInput{{PrevTxid: prefix}, {PrevTxid: tc.first}, {PrevTxid: tc.second}}, Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}}
			tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, [32]byte{}, kp)}
			if tc.extra {
				tx.Witness = append(tx.Witness, dummyWitnesses(2)...)
			}
			raw, err := MarshalTx(tx)
			if err != nil {
				t.Fatalf("MarshalTx: %v", err)
			}
			tx, txid := mustParseTxForUtxo(t, raw)
			utxos := map[Outpoint]UtxoEntry{
				{Txid: prefix}:  {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())},
				{Txid: unknown}: {Value: 100, CovenantType: 0x0105, CovenantData: make([]byte, 1600), CreationHeight: 199, CreatedByCoinbase: tc.immature},
			}
			before := snapshotRefusalUtxos(utxos)
			work, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 200, 1, [32]byte{})
			assertTxErrCode(t, err, tc.want)
			if work != nil || summary != nil || !reflect.DeepEqual(utxos, before) {
				t.Fatal("ordered rejection published work/summary or changed caller UTXOs")
			}
			queue := NewSigCheckQueue(1)
			work, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxos, 200, 1, [32]byte{}, queue, nil, nil)
			assertTxErrCode(t, err, tc.want)
			if work != nil || fee != (Uint128{}) || queue.Len() != 0 || !reflect.DeepEqual(utxos, before) {
				t.Fatal("queued input-order rejection published work/fee or changed caller state")
			}
		})
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_P2PKOK(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0xa1

	kp := mustMLDSA87Keypair(t)
	prevCov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, kp),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: prevCov,
		},
	}

	work, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 0, 0, chainID)
	if err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdate: %v", err)
	}
	if summary == nil {
		t.Fatalf("expected summary")
	}
	if summary.Fee.Cmp(Uint128FromU64(10)) != 0 {
		t.Fatalf("fee=%d, want %d", summary.Fee, 10)
	}
	if summary.UtxoCount != 1 {
		t.Fatalf("utxo_count=%d, want %d", summary.UtxoCount, 1)
	}

	if _, ok := work[Outpoint{Txid: prev, Vout: 0}]; ok {
		t.Fatalf("expected input UTXO to be removed")
	}
	out, ok := work[Outpoint{Txid: txid, Vout: 0}]
	if !ok {
		t.Fatalf("expected output UTXO to exist")
	}
	if out.Value != 90 || out.CovenantType != COV_TYPE_P2PK || len(out.CovenantData) != MAX_P2PK_COVENANT_DATA {
		t.Fatalf("unexpected output UTXO fields")
	}
	if _, ok := utxos[Outpoint{Txid: prev, Vout: 0}]; !ok {
		t.Fatalf("input utxo mutated in original map")
	}
	if _, ok := utxos[Outpoint{Txid: txid, Vout: 0}]; ok {
		t.Fatalf("output utxo leaked into original map")
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_RejectsImmatureCoinbaseSpend(t *testing.T) {
	var prev [32]byte
	prev[0] = 0xc1

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:             100,
			CovenantType:      COV_TYPE_P2PK,
			CovenantData:      validP2PKCovenantData(),
			CreationHeight:    0,
			CreatedByCoinbase: true,
		},
	}

	_, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, COINBASE_MATURITY-1, 0, [32]byte{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COINBASE_IMMATURE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COINBASE_IMMATURE)
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_CoreSimplicitySpendRejected(t *testing.T) {
	var prev [32]byte
	prev[0] = 0x61
	txBytes := txWithOneInputOneOutputWithWitness(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData(), dummyWitnesses(SIMPLICITY_WITNESS_SLOTS))
	tx, txid := mustParseTxForUtxo(t, txBytes)
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_SIMPLICITY,
			CovenantData: encodeSimplicityCovenantData([32]byte{0x61}, nil),
		},
	}

	_, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 1, 0, [32]byte{})
	assertTxErrCodeMsg(t, err, TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment not active")
}

func TestApplyNonCoinbaseTxBasicUpdate_CoreSimplicityImmatureCoinbasePrecedesDisabledSpend(t *testing.T) {
	prev := hashWithPrefix(0x67)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prev, PrevVout: 0}},
		Outputs: []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:             100,
			CovenantType:      COV_TYPE_CORE_SIMPLICITY,
			CovenantData:      encodeSimplicityCovenantData([32]byte{0x67}, nil),
			CreationHeight:    0,
			CreatedByCoinbase: true,
		},
	}

	work, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, hashWithPrefix(0x68), utxos, COINBASE_MATURITY-1, 0, [32]byte{})
	if work != nil || summary != nil {
		t.Fatalf("expected no mutation on reject, got work=%v summary=%v", work, summary)
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COINBASE_IMMATURE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COINBASE_IMMATURE)
	}
}

func TestApplyNonCoinbaseTxBasicUpdate_CoreSimplicityPreservesInputOrderPriority(t *testing.T) {
	makeOutpoint := func(prev [32]byte) Outpoint {
		return Outpoint{Txid: prev, Vout: 0}
	}
	p2pkPrev := hashWithPrefix(0xE0)
	simpPrev := hashWithPrefix(0xE1)
	// current_simplicity_precedes_later_missing_utxo was a reject-only artifact: it relied on the
	// removed resolveInputs early-return. Under live spend, input resolution processes all inputs in
	// wire order (a missing UTXO at a later input surfaces during resolution), and the CORE_SIMPLICITY
	// activation/spend check runs afterward in validateInputSpends — so that ordering no longer holds.
	// Live first-error ordering is covered by TestSimplicityLiveGate_OrderedErrorSet.

	t.Run("earlier_p2pk_witness_underflow_precedes_later_simplicity", func(t *testing.T) {
		tx := &Tx{
			Version: TX_WIRE_VERSION,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []TxInput{
				{PrevTxid: p2pkPrev, PrevVout: 0},
				{PrevTxid: simpPrev, PrevVout: 0},
			},
			Outputs: []TxOutput{{Value: 190, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		}
		utxos := map[Outpoint]UtxoEntry{
			makeOutpoint(p2pkPrev): {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
			makeOutpoint(simpPrev): coreSimplicityAcceptEntry(100),
		}

		work, summary, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(
			tx,
			hashWithPrefix(0xE4),
			utxos,
			1,
			0,
			[32]byte{},
			nil,
			nil,
		)
		if work != nil || summary != nil {
			t.Fatalf("expected no mutation on reject, got work=%v summary=%v", work, summary)
		}
		assertTxErrCodeMsg(t, err, TX_ERR_PARSE, "witness underflow")
	})
}

func TestApplyNonCoinbaseTxBasicUpdate_NonSimplicityWitnessUnderflowPrecedesLaterValidation(t *testing.T) {
	firstPrev := hashWithPrefix(0xE7)
	laterPrev := hashWithPrefix(0xE8)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: firstPrev, PrevVout: 0},
			{PrevTxid: laterPrev, PrevVout: 0},
		},
		Outputs: []TxOutput{{Value: 190, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}
	utxos := map[Outpoint]UtxoEntry{
		{Txid: firstPrev, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
		{Txid: laterPrev, Vout: 0}: {Value: 100, CovenantType: COV_TYPE_HTLC, CovenantData: []byte{0x01}},
	}

	work, summary, err := ApplyNonCoinbaseTxBasicUpdateWithMTPAndSuiteContext(
		tx,
		hashWithPrefix(0xE9),
		utxos,
		1,
		0,
		[32]byte{},
		nil,
		nil,
	)
	if work != nil || summary != nil {
		t.Fatalf("expected no mutation on reject, got work=%v summary=%v", work, summary)
	}
	assertTxErrCodeMsg(t, err, TX_ERR_PARSE, "witness underflow")
}

func TestApplyNonCoinbaseTxBasicUpdate_RejectsImmatureCoinbaseSpend_OverflowSafe(t *testing.T) {
	// Regression: creation_height near MaxUint64 must not wrap around and
	// falsely pass the maturity check. The overflow-safe form uses
	// subtraction instead of addition.
	var prev [32]byte
	prev[0] = 0xc2

	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)

	const nearMax uint64 = ^uint64(0) - 10 // MaxUint64 - 10
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:             100,
			CovenantType:      COV_TYPE_P2PK,
			CovenantData:      validP2PKCovenantData(),
			CreationHeight:    nearMax,
			CreatedByCoinbase: true,
		},
	}

	// height = nearMax + 5: maturity gap is only 5, well below COINBASE_MATURITY.
	// With the old overflow-prone check (height < creation+MATURITY), the
	// addition would wrap and the check would incorrectly pass.
	_, _, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, nearMax+5, 0, [32]byte{})
	if err == nil {
		t.Fatalf("expected TX_ERR_COINBASE_IMMATURE for overflow-edge case")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_COINBASE_IMMATURE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_COINBASE_IMMATURE)
	}
}

func TestApplyNonCoinbaseTxBasic_InputValidationErrors(t *testing.T) {
	cases := []struct {
		utxosFn   func(prev [32]byte) map[Outpoint]UtxoEntry
		name      string
		wantError ErrorCode
		outValue  uint64
		prevByte  byte
	}{
		{
			name:     "missing_utxo",
			prevByte: 0xaa,
			outValue: 1,
			utxosFn: func(prev [32]byte) map[Outpoint]UtxoEntry {
				return map[Outpoint]UtxoEntry{}
			},
			wantError: TX_ERR_MISSING_UTXO,
		},
		{
			name:     "spend_anchor_rejected",
			prevByte: 0xab,
			outValue: 1,
			utxosFn: func(prev [32]byte) map[Outpoint]UtxoEntry {
				return map[Outpoint]UtxoEntry{
					{Txid: prev, Vout: 0}: {
						Value:        1,
						CovenantType: COV_TYPE_ANCHOR,
						CovenantData: []byte{0x01},
					},
				}
			},
			wantError: TX_ERR_MISSING_UTXO,
		},
		{
			name:     "witness_count_zero_rejected",
			prevByte: 0xb0,
			outValue: 90,
			utxosFn: func(prev [32]byte) map[Outpoint]UtxoEntry {
				return map[Outpoint]UtxoEntry{
					{Txid: prev, Vout: 0}: {
						Value:        100,
						CovenantType: COV_TYPE_P2PK,
						CovenantData: validP2PKCovenantData(),
					},
				}
			},
			wantError: TX_ERR_PARSE,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prev [32]byte
			prev[0] = tc.prevByte
			txBytes := txWithOneInputOneOutput(prev, 0, tc.outValue, COV_TYPE_P2PK, validP2PKCovenantData())
			tx, txid := mustParseTxForUtxo(t, txBytes)

			_, err := ApplyNonCoinbaseTxBasic(tx, txid, tc.utxosFn(prev), 200, 1000, [32]byte{})
			if err == nil {
				t.Fatalf("expected error")
			}
			if got := mustTxErrCode(t, err); got != tc.wantError {
				t.Fatalf("code=%s, want %s", got, tc.wantError)
			}
		})
	}
}

func TestApplyNonCoinbaseTxBasic_P2PKValueConservationCases(t *testing.T) {
	var chainID [32]byte
	cases := []struct {
		name      string
		wantErr   ErrorCode
		outValue  uint64
		wantFee   uint64
		wantUTXOs uint64
		prevByte  byte
		txidByte  byte
	}{
		{
			name:     "value_conservation_error",
			prevByte: 0xae,
			txidByte: 0x01,
			outValue: 101,
			wantErr:  TX_ERR_VALUE_CONSERVATION,
		},
		{
			name:      "ok_fee_10",
			prevByte:  0xaf,
			txidByte:  0x02,
			outValue:  90,
			wantFee:   10,
			wantUTXOs: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prev [32]byte
			prev[0] = tc.prevByte
			var txid [32]byte
			txid[0] = tc.txidByte

			kp := mustMLDSA87Keypair(t)
			covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
			tx := &Tx{
				Version:  1,
				TxKind:   0x00,
				TxNonce:  1,
				Inputs:   []TxInput{{PrevTxid: prev, PrevVout: 0}},
				Outputs:  []TxOutput{{Value: tc.outValue, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
				Locktime: 0,
			}
			tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp)}

			utxos := map[Outpoint]UtxoEntry{
				{Txid: prev, Vout: 0}: {
					Value:        100,
					CovenantType: COV_TYPE_P2PK,
					CovenantData: covData,
				},
			}
			s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error")
				}
				if got := mustTxErrCode(t, err); got != tc.wantErr {
					t.Fatalf("code=%s, want %s", got, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s.Fee.Cmp(Uint128FromU64(tc.wantFee)) != 0 {
				t.Fatalf("fee=%d, want %d", s.Fee, tc.wantFee)
			}
			if s.UtxoCount != tc.wantUTXOs {
				t.Fatalf("utxo_count=%d, want %d", s.UtxoCount, tc.wantUTXOs)
			}
		})
	}
}

func TestApplyNonCoinbaseTxBasic_VaultCannotFundFee(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xc0
	prevFee[0] = 0xc1
	txid[0] = 0xc2

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VALUE_CONSERVATION {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VALUE_CONSERVATION)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultPreservedWithOwnerFeeInput(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xd0
	prevFee[0] = 0xd1
	txid[0] = 0xd2

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee.Cmp(Uint128FromU64(10)) != 0 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultAllowsOwnerTopUp(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xd3
	prevFee[0] = 0xd4
	txid[0] = 0xd5

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 105, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee.Cmp(Uint128FromU64(5)) != 0 {
		t.Fatalf("fee=%d, want 5", s.Fee)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultWhitelistRejectsOutput(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xe0
	prevFee[0] = 0xe1
	txid[0] = 0xe2

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	whitelistedDestKP := mustMLDSA87Keypair(t)
	nonWhitelistedDestKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	whitelistedOutData := p2pkCovenantDataForPubkey(whitelistedDestKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, whitelistedOutData))

	nonWhitelistedOutData := p2pkCovenantDataForPubkey(nonWhitelistedDestKP.PubkeyBytes())

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: nonWhitelistedOutData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED)
	}
}

func TestApplyNonCoinbaseTxBasic_VaultRejectsDisallowedDestinationCovenantTypeEvenIfWhitelisted(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevFee, txid [32]byte
	prevVault[0] = 0xe4
	prevFee[0] = 0xe5
	txid[0] = 0xe6

	vaultKP := mustMLDSA87Keypair(t)
	ownerKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))
	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	destLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	anchorOutData := []byte{0x01}
	anchorH := sha3_256(OutputDescriptorBytes(COV_TYPE_ANCHOR, anchorOutData))
	whitelistA, whitelistB := sortKeys32(anchorH, destLockID)

	vaultKeyID := sha3_256(vaultKP.PubkeyBytes())
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{vaultKeyID}, [][32]byte{whitelistA, whitelistB})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevFee, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 0, CovenantType: COV_TYPE_ANCHOR, CovenantData: anchorOutData},
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		signP2PKInputWitness(t, tx, 0, 100, chainID, vaultKP),
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevFee, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	assertTxErrCodeMsg(t, err, TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED, "disallowed destination covenant_type for CORE_VAULT spend")
}

func TestApplyNonCoinbaseTxBasic_VaultRejectsFeeSponsor(t *testing.T) {
	var chainID [32]byte
	var prevVault, prevOwner, prevSponsor, txid [32]byte
	prevVault[0] = 0xf2
	prevOwner[0] = 0xf3
	prevSponsor[0] = 0xf4
	txid[0] = 0xf5

	ownerKP := mustMLDSA87Keypair(t)
	sponsorKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	ownerCovData := p2pkCovenantDataForPubkey(ownerKP.PubkeyBytes())
	ownerLockID := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, ownerCovData))

	sponsorCovData := p2pkCovenantDataForPubkey(sponsorKP.PubkeyBytes())

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())
	whitelistH := sha3_256(OutputDescriptorBytes(COV_TYPE_P2PK, destCovData))

	var dummyVaultKeyID [32]byte
	dummyVaultKeyID[0] = 0x11
	vaultCovData := encodeVaultCovenantData(ownerLockID, 1, [][32]byte{dummyVaultKeyID}, [][32]byte{whitelistH})

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{PrevTxid: prevVault, PrevVout: 0},
			{PrevTxid: prevOwner, PrevVout: 0},
			{PrevTxid: prevSponsor, PrevVout: 0},
		},
		Outputs: []TxOutput{
			{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData},
		},
	}
	tx.Witness = []WitnessItem{
		{SuiteID: SUITE_ID_SENTINEL}, // vault slot (not reached; sponsor check fails earlier)
		signP2PKInputWitness(t, tx, 1, 10, chainID, ownerKP),
		signP2PKInputWitness(t, tx, 2, 10, chainID, sponsorKP),
	}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevVault, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_VAULT,
			CovenantData: vaultCovData,
		},
		{Txid: prevOwner, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: ownerCovData,
		},
		{Txid: prevSponsor, Vout: 0}: {
			Value:        10,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: sponsorCovData,
		},
	}

	_, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN {
		t.Fatalf("code=%s, want %s", got, TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN)
	}
}

func TestApplyNonCoinbaseTxBasic_MultisigInputAccepted(t *testing.T) {
	var chainID [32]byte
	var prevMS, txid [32]byte
	prevMS[0] = 0xf0
	txid[0] = 0xf1

	msKP := mustMLDSA87Keypair(t)
	destKP := mustMLDSA87Keypair(t)

	msKeyID := sha3_256(msKP.PubkeyBytes())
	msCovData := encodeMultisigCovenantData(1, [][32]byte{msKeyID})

	destCovData := p2pkCovenantDataForPubkey(destKP.PubkeyBytes())

	tx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prevMS, PrevVout: 0}},
		Outputs:  []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: destCovData}},
		Locktime: 0,
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, msKP)}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prevMS, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_MULTISIG,
			CovenantData: msCovData,
		},
	}
	s, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, chainID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Fee.Cmp(Uint128FromU64(10)) != 0 {
		t.Fatalf("fee=%d, want 10", s.Fee)
	}
}

func TestWitnessSlotsUnknownCovenantRejected(t *testing.T) {
	for _, tag := range []uint16{0x0001, 0x00ff, 0x0102, 0x0105, 0x0107, 0x7777} {
		_, err := WitnessSlots(tag, make([]byte, 1600))
		assertTxErrCode(t, err, "TX_ERR_COVENANT_TYPE_INVALID")
	}
}

func TestWitnessSlotsKnownTypes(t *testing.T) {
	tests := []struct {
		name     string
		covType  uint16
		covData  []byte
		expected int
	}{
		{"P2PK", COV_TYPE_P2PK, nil, 1},
		{"HTLC", COV_TYPE_HTLC, nil, 2},
		{"CORE_SIMPLICITY", COV_TYPE_CORE_SIMPLICITY, nil, SIMPLICITY_WITNESS_SLOTS},
		{"MULTISIG_default", COV_TYPE_MULTISIG, []byte{0x01}, 1},
		{"MULTISIG_3", COV_TYPE_MULTISIG, []byte{0x01, 0x03}, 3},
		{"VAULT_default", COV_TYPE_VAULT, make([]byte, 32), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WitnessSlots(tt.covType, tt.covData)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expected {
				t.Fatalf("got=%d, want=%d", got, tt.expected)
			}
		})
	}
}

type section16StructuralCase struct {
	name   string
	nonce  uint64
	inputs []TxInput
	want   ErrorCode
	msg    string
}

func section16StructuralCases() []section16StructuralCase {
	coinbasePrevout := TxInput{PrevVout: ^uint32(0)}
	return []section16StructuralCase{
		{name: "nonce_before_input_count", want: TX_ERR_TX_NONCE_INVALID, msg: "tx_nonce must be >= 1 for non-coinbase"},
		{name: "input_count_only", nonce: 1, want: TX_ERR_PARSE, msg: "non-coinbase must have at least one input"},
		{name: "coinbase_prevout_before_script_sig", nonce: 1, inputs: []TxInput{{PrevVout: coinbasePrevout.PrevVout, ScriptSig: []byte{0x01}}}, want: TX_ERR_PARSE, msg: "coinbase prevout encoding forbidden in non-coinbase"},
		{name: "coinbase_prevout_before_sequence", nonce: 1, inputs: []TxInput{{PrevVout: coinbasePrevout.PrevVout, Sequence: 0x8000_0000}}, want: TX_ERR_PARSE, msg: "coinbase prevout encoding forbidden in non-coinbase"},
		{name: "later_coinbase_before_earlier_sequence", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: 0x8000_0000}, coinbasePrevout}, want: TX_ERR_PARSE, msg: "coinbase prevout encoding forbidden in non-coinbase"},
		{name: "script_sig_only", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x52), ScriptSig: []byte{0x01}}}, want: TX_ERR_PARSE, msg: "script_sig must be empty under genesis covenant set"},
		{name: "sequence_only", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x53), Sequence: 0x8000_0000}}, want: TX_ERR_SEQUENCE_INVALID, msg: "sequence exceeds 0x7fffffff"},
		{name: "coinbase_prevout_only", nonce: 1, inputs: []TxInput{coinbasePrevout}, want: TX_ERR_PARSE, msg: "coinbase prevout encoding forbidden in non-coinbase"},
		{name: "later_coinbase_before_earlier_script", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), ScriptSig: []byte{1}}, coinbasePrevout}, want: TX_ERR_PARSE, msg: "coinbase prevout encoding forbidden in non-coinbase"},
		{name: "later_script_before_earlier_sequence", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: 0x8000_0000}, {PrevTxid: hashWithPrefix(0x52), ScriptSig: []byte{1}}}, want: TX_ERR_PARSE, msg: "script_sig must be empty under genesis covenant set"},
		{name: "sequence_before_earlier_duplicate", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51)}, {PrevTxid: hashWithPrefix(0x51)}, {PrevTxid: hashWithPrefix(0x52), Sequence: 0x8000_0000}}, want: TX_ERR_SEQUENCE_INVALID, msg: "sequence exceeds 0x7fffffff"},
		{name: "nonadjacent_duplicate", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51)}, {PrevTxid: hashWithPrefix(0x51), PrevVout: 1}, {PrevTxid: hashWithPrefix(0x51)}}, want: TX_ERR_PARSE, msg: "duplicate input outpoint"},
		{name: "later_coinbase_before_missing", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51)}, coinbasePrevout}, want: TX_ERR_PARSE, msg: "coinbase prevout encoding forbidden in non-coinbase"},
		{name: "two_sequence_failures", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: 0x8000_0000}, {PrevTxid: hashWithPrefix(0x52), Sequence: 0xffffffff}}, want: TX_ERR_SEQUENCE_INVALID, msg: "sequence exceeds 0x7fffffff"},
	}
}

func section16SnapshotTx(tx *Tx) *Tx {
	if tx == nil {
		return nil
	}
	out := *tx
	out.Inputs = slices.Clone(tx.Inputs)
	for i := range out.Inputs {
		out.Inputs[i].ScriptSig = slices.Clone(tx.Inputs[i].ScriptSig)
	}
	out.Outputs = slices.Clone(tx.Outputs)
	for i := range out.Outputs {
		out.Outputs[i].CovenantData = slices.Clone(tx.Outputs[i].CovenantData)
	}
	out.Witness = slices.Clone(tx.Witness)
	for i := range out.Witness {
		out.Witness[i].Pubkey = slices.Clone(tx.Witness[i].Pubkey)
		out.Witness[i].Signature = slices.Clone(tx.Witness[i].Signature)
	}
	out.DaPayload = slices.Clone(tx.DaPayload)
	if tx.DaCommitCore != nil {
		core := *tx.DaCommitCore
		core.BatchSig = slices.Clone(tx.DaCommitCore.BatchSig)
		out.DaCommitCore = &core
	}
	if tx.DaChunkCore != nil {
		core := *tx.DaChunkCore
		out.DaChunkCore = &core
	}
	return &out
}

func TestValidateSpendTxS1A(t *testing.T) {
	cases := append(section16StructuralCases(), []section16StructuralCase{
		{name: "minimal", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), ScriptSig: []byte{}}}},
		{name: "max_valid", nonce: 0xffffffffffffffff, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: 0x7fffffff}}},
		{name: "zero_txid_only", nonce: 1, inputs: []TxInput{{PrevVout: 0}}},
		{name: "max_vout_only", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), PrevVout: 0xffffffff}}},
		{name: "equal_txid_distinct_vout", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51)}, {PrevTxid: hashWithPrefix(0x51), PrevVout: 1}}},
		{name: "full_width_vout", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51)}, {PrevTxid: hashWithPrefix(0x51), PrevVout: 0x10000}}},
		{name: "distinct_txid_equal_vout", nonce: 1, inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51)}, {PrevTxid: hashWithPrefix(0x52)}}},
		{name: "full_width_txid", nonce: 1, inputs: []TxInput{{PrevTxid: [32]byte{0: 0x51}}, {PrevTxid: [32]byte{0: 0x51, 31: 1}}}},
		{name: "empty_inputs", nonce: 1, inputs: []TxInput{}, want: TX_ERR_PARSE, msg: "non-coinbase must have at least one input"},
	}...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := section16TestTx(tc.nonce, tc.inputs)
			tx.Witness = []WitnessItem{{SuiteID: 0x7f, Pubkey: []byte{2, 3}, Signature: []byte{4, 5}}, {Pubkey: []byte{}, Signature: nil}}
			tx.DaPayload = []byte{6, 7}
			// S1A reads only its six families. Snapshot every nested owner as
			// well, including DA objects, without asking S1A to validate them.
			tx.DaCommitCore = &DaCommitCore{BatchNumber: 9, BatchSig: []byte{8, 9}, DaID: hashWithPrefix(0x61)}
			tx.DaChunkCore = &DaChunkCore{ChunkIndex: 2, ChunkHash: hashWithPrefix(0x62)}
			before := section16SnapshotTx(tx)
			for repeat := 0; repeat < 2; repeat++ {
				err := ValidateSpendTxS1A(tx)
				if tc.want == "" {
					if err != nil {
						t.Fatalf("valid S1A: %v", err)
					}
				} else {
					assertTxErrCodeMsg(t, err, tc.want, tc.msg)
				}
				if !reflect.DeepEqual(tx, before) {
					t.Fatal("caller Tx changed during S1A")
				}
			}
		})
	}
	assertTxErrCodeMsg(t, ValidateSpendTxS1A(nil), TX_ERR_PARSE, "nil tx")
	for _, tx := range []*Tx{
		{TxNonce: 1, Inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51)}}},
		{
			TxNonce: 1, Inputs: []TxInput{{PrevTxid: hashWithPrefix(0x51), ScriptSig: []byte{}}},
			Outputs: []TxOutput{{CovenantData: []byte{}}}, Witness: []WitnessItem{{Pubkey: []byte{}, Signature: []byte{}}},
			DaPayload: []byte{}, DaCommitCore: &DaCommitCore{BatchSig: []byte{}}, DaChunkCore: &DaChunkCore{},
		},
	} {
		before := section16SnapshotTx(tx)
		if err := ValidateSpendTxS1A(tx); err != nil {
			t.Fatalf("valid nil/empty S1A control: %v", err)
		}
		if !reflect.DeepEqual(tx, before) {
			t.Fatal("caller Tx changed during S1A")
		}
	}
}

func section16TestTx(nonce uint64, inputs []TxInput) *Tx {
	return &Tx{
		Version: TX_WIRE_VERSION,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs:  inputs,
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
	}
}

func section16TestUtxos() map[Outpoint]UtxoEntry {
	prev := hashWithPrefix(0x54)
	return map[Outpoint]UtxoEntry{{Txid: prev}: {Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}
}

func section16SignedControl(t *testing.T) (*Tx, map[Outpoint]UtxoEntry) {
	t.Helper()
	kp := mustMLDSA87Keypair(t)
	cov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	tx := section16TestTx(1, []TxInput{{PrevTxid: hashWithPrefix(0x61)}, {PrevTxid: hashWithPrefix(0x62)}})
	tx.Outputs = []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: cov}}
	utxos := map[Outpoint]UtxoEntry{
		{Txid: hashWithPrefix(0x61)}: {Value: 50, CovenantType: COV_TYPE_P2PK, CovenantData: slices.Clone(cov)},
		{Txid: hashWithPrefix(0x62)}: {Value: 50, CovenantType: COV_TYPE_P2PK, CovenantData: slices.Clone(cov)},
	}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 50, [32]byte{}, kp), signP2PKInputWitness(t, tx, 1, 50, [32]byte{}, kp)}
	return tx, utxos
}

func TestValidateBlockTxSemantics_Section16GlobalFamilyOrder(t *testing.T) {
	for _, tc := range section16StructuralCases()[:2] {
		t.Run(tc.name, func(t *testing.T) {
			txBytes, err := MarshalTx(section16TestTx(tc.nonce, tc.inputs))
			if err != nil {
				t.Fatalf("MarshalTx: %v", err)
			}
			coinbase := coinbaseWithWitnessCommitment(t, txBytes)
			root, err := MerkleRootTxids([][32]byte{testTxID(t, coinbase), testTxID(t, txBytes)})
			if err != nil {
				t.Fatalf("MerkleRootTxids: %v", err)
			}
			prev, target := hashWithPrefix(0x55), filledHash(0xff)
			_, err = ValidateBlockBasicAtHeight(buildBlockBytes(t, prev, root, target, 56, [][]byte{coinbase, txBytes}), &prev, &target, 0)
			assertTxErrCodeMsg(t, err, tc.want, tc.msg)
		})
	}
	t.Run("single_nonce_rejected", func(t *testing.T) {
		txBytes, err := MarshalTx(section16TestTx(0, []TxInput{{PrevTxid: hashWithPrefix(0x58)}}))
		if err != nil {
			t.Fatalf("MarshalTx: %v", err)
		}
		coinbase := coinbaseWithWitnessCommitment(t, txBytes)
		root, err := MerkleRootTxids([][32]byte{testTxID(t, coinbase), testTxID(t, txBytes)})
		if err != nil {
			t.Fatalf("MerkleRootTxids: %v", err)
		}
		prev, target := hashWithPrefix(0x55), filledHash(0xff)
		_, err = ValidateBlockBasicAtHeight(buildBlockBytes(t, prev, root, target, 56, [][]byte{coinbase, txBytes}), &prev, &target, 0)
		assertTxErrCodeMsg(t, err, TX_ERR_TX_NONCE_INVALID, "tx_nonce must be >= 1 for non-coinbase")
	})
	for _, nonce := range []uint64{7, 8} {
		tx := section16TestTx(nonce, []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: 0x80000000}, {PrevVout: 0xffffffff}})
		seen := map[uint64]struct{}{7: {}, 11: {}}
		before := map[uint64]struct{}{7: {}, 11: {}}
		assertTxErrCodeMsg(t, validateNonCoinbaseBlockTx(tx, seen), TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
		if !reflect.DeepEqual(seen, before) {
			t.Fatal("S1A rejection changed entry nonce prefix")
		}
	}
	tx := section16TestTx(7, []TxInput{{PrevTxid: hashWithPrefix(0x51)}})
	tx.Outputs = []TxOutput{{CovenantType: 0x0105}}
	assertTxErrCodeMsg(t, validateNonCoinbaseBlockTx(tx, map[uint64]struct{}{7: {}}), TX_ERR_NONCE_REPLAY, "duplicate tx_nonce in block")
}

func TestApplyNonCoinbaseTxBasic_Section16StructuralOrder(t *testing.T) {
	for _, tc := range section16StructuralCases() {
		t.Run(tc.name, func(t *testing.T) {
			utxos := section16TestUtxos()
			before := cloneUtxoSet(utxos)
			tx := section16TestTx(tc.nonce, tc.inputs)
			if tc.name == "nonce_before_input_count" {
				tx.Outputs = []TxOutput{{CovenantType: 0x0105}}
			}
			work, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, hashWithPrefix(0x56), utxos, 1, 0, [32]byte{})
			assertTxErrCodeMsg(t, err, tc.want, tc.msg)
			if work != nil || summary != nil {
				t.Fatal("S1A rejection returned candidate or summary")
			}
			if !reflect.DeepEqual(utxos, before) {
				t.Fatal("caller UTXOs changed on rejection")
			}
		})
	}
	for _, sequence := range []uint32{0x80000000, 0} {
		tx := section16TestTx(1, []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: sequence}})
		tx.Outputs = []TxOutput{{CovenantType: 0x0105}}
		_, err := ApplyNonCoinbaseTxBasic(tx, hashWithPrefix(0x56), section16TestUtxos(), 1, 0, [32]byte{})
		if sequence != 0 {
			assertTxErrCodeMsg(t, err, TX_ERR_SEQUENCE_INVALID, "sequence exceeds 0x7fffffff")
		} else {
			assertTxErrCodeMsg(t, err, TX_ERR_COVENANT_TYPE_INVALID, "unknown covenant_type")
		}
	}
	tx := section16TestTx(1, []TxInput{{PrevTxid: hashWithPrefix(0x51)}, {PrevVout: 0xffffffff}})
	utxos := map[Outpoint]UtxoEntry{{Txid: hashWithPrefix(0x51)}: {CovenantType: COV_TYPE_ANCHOR}}
	_, err := ApplyNonCoinbaseTxBasic(tx, hashWithPrefix(0x56), utxos, 1, 0, [32]byte{})
	assertTxErrCodeMsg(t, err, TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
	for _, inputs := range [][]TxInput{
		{{PrevVout: 0}},
		{{PrevTxid: hashWithPrefix(0x51), PrevVout: 0xffffffff}},
		{{PrevTxid: hashWithPrefix(0x51)}, {PrevTxid: hashWithPrefix(0x51), PrevVout: 1}},
		{{PrevTxid: [32]byte{0: 0x51}}, {PrevTxid: [32]byte{0: 0x51, 31: 1}}},
	} {
		_, err := ApplyNonCoinbaseTxBasic(section16TestTx(1, inputs), hashWithPrefix(0x56), section16TestUtxos(), 1, 0, [32]byte{})
		assertTxErrCodeMsg(t, err, TX_ERR_MISSING_UTXO, "utxo not found")
	}
}

func TestApplyNonCoinbaseTxBasic_HTLCCreationFirstErrorOrder(t *testing.T) {
	prev := hashWithPrefix(0x63)
	var hash, claimKeyID [32]byte
	hash[0], claimKeyID[0] = 0x42, 0x11
	paired := encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 1, claimKeyID, claimKeyID)
	tx := &Tx{
		Version: TX_WIRE_VERSION,
		TxNonce: 1,
		Inputs:  []TxInput{{PrevTxid: prev}},
		Outputs: []TxOutput{{Value: 0, CovenantType: COV_TYPE_HTLC, CovenantData: paired}},
	}
	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev}: {Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()},
	}
	before := cloneUtxoSet(utxos)
	work, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, hashWithPrefix(0x64), utxos, 1, 0, [32]byte{})
	if work != nil || summary != nil {
		t.Fatalf("rejection returned work=%v summary=%v", work, summary)
	}
	assertTxErrCodeMsg(t, err, TX_ERR_PARSE, "CORE_HTLC claim/refund key_id must differ")
	if !reflect.DeepEqual(utxos, before) {
		t.Fatal("caller UTXOs changed on rejection")
	}
}

func TestApplyNonCoinbaseTxBasicWorkQ_Section16StructuralOrder(t *testing.T) {
	for _, tc := range section16StructuralCases() {
		t.Run(tc.name, func(t *testing.T) {
			utxos := section16TestUtxos()
			before := cloneUtxoSet(utxos)
			queue := NewSigCheckQueue(1)
			tx := section16TestTx(tc.nonce, tc.inputs)
			if tc.name == "sequence_only" || tc.name == "nonce_before_input_count" {
				tx.Outputs = []TxOutput{{CovenantType: 0x0105}}
			}
			work, _, err := applyNonCoinbaseTxBasicWorkQ(tx, hashWithPrefix(0x57), utxos, 1, 0, [32]byte{}, queue, nil, nil)
			assertTxErrCodeMsg(t, err, tc.want, tc.msg)
			if work != nil || queue.Len() != 0 {
				t.Fatalf("rejection changed returned work or queued signatures: work=%v queue=%d", work, queue.Len())
			}
			if !reflect.DeepEqual(utxos, before) {
				t.Fatal("caller UTXOs changed on queued rejection")
			}
		})
	}
	valid, utxos := section16SignedControl(t)
	beforeUtxos := cloneUtxoSet(utxos)
	wantWork, wantSummary, err := ApplyNonCoinbaseTxBasicUpdate(valid, hashWithPrefix(0x63), utxos, 1, 0, [32]byte{})
	if err != nil || wantSummary.Fee.Cmp(Uint128FromU64(10)) != 0 {
		t.Fatalf("signed valid control: summary=%v err=%v", wantSummary, err)
	}
	for _, populated := range []bool{false, true} {
		queue := NewSigCheckQueue(1)
		if populated {
			if _, _, err := applyNonCoinbaseTxBasicWorkQ(valid, hashWithPrefix(0x63), utxos, 1, 0, [32]byte{}, queue, nil, nil); err != nil {
				t.Fatalf("populate queue: %v", err)
			}
		}
		before := slices.Clone(queue.tasks)
		for i := range before {
			before[i].pubkey = slices.Clone(before[i].pubkey)
			before[i].sig = slices.Clone(before[i].sig)
		}
		bad := section16TestTx(1, []TxInput{{PrevTxid: hashWithPrefix(0x51), Sequence: 0x80000000}, {PrevVout: 0xffffffff}})
		bad.Outputs = []TxOutput{{CovenantType: 0x0105}}
		work, summary, err := applyNonCoinbaseTxBasicUpdateWithMTPQ(bad, hashWithPrefix(0x64), utxos, 1, 0, 0, [32]byte{}, queue, nil, nil)
		assertTxErrCodeMsg(t, err, TX_ERR_PARSE, "coinbase prevout encoding forbidden in non-coinbase")
		if work != nil || summary != nil || !reflect.DeepEqual(queue.tasks, before) || !reflect.DeepEqual(utxos, beforeUtxos) {
			t.Fatal("S1A rejection changed entry queue/caller UTXOs or returned a candidate")
		}
		work, summary, err = applyNonCoinbaseTxBasicUpdateWithMTPQ(valid, hashWithPrefix(0x63), utxos, 1, 0, 0, [32]byte{}, queue, nil, nil)
		if err != nil || !reflect.DeepEqual(work, wantWork) || !reflect.DeepEqual(summary, wantSummary) {
			t.Fatalf("rejected-then-valid differs from valid alone: %v", err)
		}
		if queue.Len() != len(before)+2 || (len(before) > 0 && !reflect.DeepEqual(queue.tasks[:len(before)], before)) {
			t.Fatal("valid operation changed entry queue jobs/order")
		}
		if err := queue.Flush(); err != nil {
			t.Fatalf("retained genuine signatures: %v", err)
		}
	}
}

// TestApplyNonCoinbaseTxBasicFeeAboveU64 pins RUB-1127: a transaction fee
// above u64 is derived exactly — not narrowed, saturated, or rejected on
// width alone.
//
// Two 2^63 inputs and zero outputs give a fee of exactly 2^64, one above the
// u64 domain. Every apply path that can see this transaction must agree:
// sequential, queued-parallel, and precompute. Mirrors Rust
// `apply_non_coinbase_tx_basic_fee_above_u64_is_exact` and the shared vector
// CV-U-FEE-U128-01.
func TestApplyNonCoinbaseTxBasicFeeAboveU64(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	cov := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	const inputValue = uint64(1) << 63
	wantFee, ok := Uint128FromU64(inputValue).CheckedAdd(Uint128FromU64(inputValue))
	if !ok {
		t.Fatal("want fee overflow")
	}
	if wantFee.Cmp(Uint128FromU64(^uint64(0))) <= 0 {
		t.Fatalf("row must exceed u64: %s", wantFee.String())
	}

	prevTxids := [][32]byte{{0xe1}, {0xe2}}
	utxos := map[Outpoint]UtxoEntry{}
	inputs := make([]TxInput, 0, len(prevTxids))
	for _, prev := range prevTxids {
		utxos[Outpoint{Txid: prev, Vout: 0}] = UtxoEntry{
			Value:        inputValue,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), cov...),
		}
		inputs = append(inputs, TxInput{PrevTxid: prev, PrevVout: 0})
	}

	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  inputs,
		Outputs: nil, // burn-to-fee: the whole input sum becomes fee
	}
	witness := make([]WitnessItem, 0, len(inputs))
	for i := range inputs {
		witness = append(witness, signP2PKInputWitness(t, tx, uint32(i), inputValue, [32]byte{}, kp))
	}
	tx.Witness = witness
	txid := [32]byte{0xe3}

	summary, err := ApplyNonCoinbaseTxBasic(tx, txid, utxos, 200, 1000, [32]byte{})
	if err != nil {
		t.Fatalf("fee above u64 must be accepted on ordinary validation: %v", err)
	}
	if summary.Fee.Cmp(wantFee) != 0 {
		t.Fatalf("sequential fee=%s want=%s", summary.Fee.String(), wantFee.String())
	}

	// Queued-parallel path must derive the identical fee.
	queue := NewSigCheckQueue(2).WithRegistry(DefaultSuiteRegistry())
	_, queued, err := applyNonCoinbaseTxBasicUpdateWithMTPQ(
		tx, txid, utxos, 200, 1000, 1000, [32]byte{}, queue, nil, nil,
	)
	if err != nil {
		t.Fatalf("queued apply: %v", err)
	}
	if queued.Fee.Cmp(wantFee) != 0 {
		t.Fatalf("queued fee=%s want=%s", queued.Fee.String(), wantFee.String())
	}

	// Precompute must derive the identical fee too.
	var sumIn u128
	for range prevTxids {
		var addErr error
		if sumIn, addErr = addU64ToU128(sumIn, inputValue); addErr != nil {
			t.Fatalf("sum_in: %v", addErr)
		}
	}
	precomputed, err := computePrecomputeFee(sumIn, tx.Outputs)
	if err != nil {
		t.Fatalf("precompute fee: %v", err)
	}
	if precomputed.Cmp(wantFee) != 0 {
		t.Fatalf("precompute fee=%s want=%s", precomputed.String(), wantFee.String())
	}
}

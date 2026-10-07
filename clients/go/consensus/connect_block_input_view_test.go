package consensus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type inputViewTestView struct {
	entries map[Outpoint]UtxoEntry
	rows    map[Outpoint]logicalStateRowRead
	reads   []Outpoint
}

func (*inputViewTestView) Counters() logicalStateCounterRead { panic("unexpected counters read") }

func (v *inputViewTestView) Lookup(op Outpoint) logicalStateRowRead {
	v.reads = append(v.reads, op)
	if row, ok := v.rows[op]; ok {
		return row
	}
	if entry, ok := v.entries[op]; ok {
		return logicalStateRowRead{kind: logicalStateRowPresent, entry: entry}
	}
	return logicalStateRowRead{kind: logicalStateRowAbsent}
}

func inputViewBlock(t *testing.T, height, coinbaseValue uint64, txs ...*Tx) connectBlockBasicInMemorySuiteContext {
	t.Helper()
	encoded := make([][]byte, 0, len(txs))
	for _, tx := range txs {
		encoded = append(encoded, txBytesFromTx(t, tx))
	}
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, coinbaseValue, encoded...)
	encoded = append([][]byte{coinbase}, encoded...)
	txids := make([][32]byte, 0, len(encoded))
	for _, tx := range encoded {
		txids = append(txids, testTxID(t, tx))
	}
	root, err := MerkleRootTxids(txids)
	if err != nil {
		t.Fatal(err)
	}
	prev, target := hashWithPrefix(0xd1), filledHash(0xff)
	return connectBlockBasicInMemorySuiteContext{
		BlockBytes: buildBlockBytes(t, prev, root, target, 1, encoded),
		ExpectedPrevHash: &prev, ExpectedTarget: &target, BlockHeight: height,
	}
}

func inputViewTx(nonce uint64, ops ...Outpoint) *Tx {
	tx := &Tx{
		Version: 1, TxNonce: nonce,
		Outputs: []TxOutput{{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}},
		Witness: dummyWitnesses(len(ops)),
	}
	for _, op := range ops {
		tx.Inputs = append(tx.Inputs, TxInput{PrevTxid: op.Txid, PrevVout: op.Vout})
	}
	return tx
}

func inputViewSignedTx(t *testing.T, nonce uint64, entries map[Outpoint]UtxoEntry, kp *MLDSA87Keypair, ops ...Outpoint) *Tx {
	t.Helper()
	tx := inputViewTx(nonce, ops...)
	var total uint64
	for _, op := range ops {
		total += entries[op].Value
	}
	tx.Outputs[0].Value = total - 10
	tx.Outputs[0].CovenantData = p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	for i, op := range ops {
		tx.Witness[i] = signP2PKInputWitness(t, tx, uint32(i), entries[op].Value, [32]byte{}, kp)
	}
	return tx
}

func inputViewRowSnapshot(rows map[Outpoint]logicalStateRowRead) map[Outpoint]logicalStateRowRead {
	copy := make(map[Outpoint]logicalStateRowRead, len(rows))
	for op, row := range rows {
		row.entry = cloneUtxoEntry(row.entry)
		copy[op] = row
	}
	return copy
}

func inputViewConnect(t *testing.T, input connectBlockBasicInMemorySuiteContext, view *inputViewTestView, generated Uint128) (*connectBlockInputViewResult, error) {
	t.Helper()
	entriesBefore := copyUtxoMap(view.entries)
	rowsBefore := inputViewRowSnapshot(view.rows)
	blockBefore := append([]byte(nil), input.BlockBytes...)
	result, err := connectBlockBasicWithInputView(input, view, generated)
	if !reflect.DeepEqual(view.entries, entriesBefore) || len(view.rows) != len(rowsBefore) {
		t.Fatal("connect modified view-owned rows")
	}
	for op, row := range view.rows {
		before, ok := rowsBefore[op]
		if !ok || row.kind != before.kind || row.cause != before.cause || !reflect.DeepEqual(row.entry, before.entry) {
			t.Fatalf("connect modified view-owned row %v", op)
		}
	}
	if !bytes.Equal(input.BlockBytes, blockBefore) {
		t.Fatal("connect modified block bytes")
	}
	if err != nil && result != nil {
		t.Fatal("failed connect published a partial result")
	}
	return result, err
}

func inputViewNew(entries map[Outpoint]UtxoEntry) *inputViewTestView {
	return &inputViewTestView{entries: copyUtxoMap(entries), rows: make(map[Outpoint]logicalStateRowRead)}
}

func assertInputViewReads(t *testing.T, view *inputViewTestView, want ...Outpoint) {
	t.Helper()
	if !reflect.DeepEqual(view.reads, want) {
		t.Fatalf("reads=%v, want exactly %v", view.reads, want)
	}
}

func assertInputViewTxError(t *testing.T, err error, code, message string) {
	t.Helper()
	got, ok := err.(*TxError)
	if !ok || got.Code != ErrorCode(code) || got.Msg != message {
		t.Fatalf("error=%v, want %s: %s", err, code, message)
	}
}

func assertInputViewFailure(t *testing.T, err error, op Outpoint, txIndex, inputIndex int, kind logicalStateFailureKind, cause error, message string) {
	t.Helper()
	got, ok := err.(*blockInputViewReadError)
	if !ok {
		t.Fatalf("error type=%T, want *blockInputViewReadError", err)
	}
	if got.outpoint != op || got.txIndex != txIndex || got.inputIndex != inputIndex || got.failure.kind != kind {
		t.Fatalf("failure tuple=%#v/%#v, want %v (%d,%d) kind %d", got, got.failure, op, txIndex, inputIndex, kind)
	}
	if cause != nil && got.failure.cause != cause {
		t.Fatal("read failure replaced the original cause")
	}
	if got.Error() != message || got.failure.Error() != message {
		t.Fatalf("failure diagnostic=%q, want %q", got.Error(), message)
	}
}

func assertInputViewResult(t *testing.T, input connectBlockBasicInMemorySuiteContext, pre map[Outpoint]UtxoEntry, generated Uint128, result *connectBlockInputViewResult) {
	t.Helper()
	state := &InMemoryChainState{Utxos: copyUtxoMap(pre), AlreadyGenerated: generated.Big()}
	oracle, err := ConnectBlockBasicInMemoryAtHeightAndSuiteContext(
		input.BlockBytes, input.ExpectedPrevHash, input.ExpectedTarget, input.BlockHeight,
		input.PrevTimestamps, state, input.ChainID, input.Rotation, input.Registry,
	)
	if err != nil {
		t.Fatalf("map oracle: %v", err)
	}
	if result == nil || result.sumFees != oracle.SumFees || result.alreadyGenerated != oracle.AlreadyGenerated || result.alreadyGeneratedN1 != oracle.AlreadyGeneratedN1 {
		t.Fatalf("result counters=%#v, map=%#v", result, oracle)
	}
	pb, err := ParseBlockBytes(input.BlockBytes)
	if err != nil {
		t.Fatal(err)
	}
	var spent []blockSpentInput
	for txIndex, tx := range pb.Txs[1:] {
		for inputIndex, in := range tx.Inputs {
			op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
			if entry, ok := pre[op]; ok {
				spent = append(spent, blockSpentInput{outpoint: op, entry: entry, txIndex: txIndex + 1, inputIndex: inputIndex})
			}
		}
	}
	if !reflect.DeepEqual(result.spentInputs, spent) {
		t.Fatalf("spent rows=%#v, want map inputs %#v", result.spentInputs, spent)
	}
	created := make(map[Outpoint]UtxoEntry)
	for op, entry := range state.Utxos {
		if _, existed := pre[op]; !existed {
			created[op] = entry
		}
	}
	if !reflect.DeepEqual(result.createdUtxos, created) {
		t.Fatalf("created/unspent map=%#v, want %#v", result.createdUtxos, created)
	}
	reconstructed := copyUtxoMap(pre)
	for _, row := range result.spentInputs {
		delete(reconstructed, row.outpoint)
	}
	for op, entry := range result.createdUtxos {
		reconstructed[op] = entry
	}
	if !reflect.DeepEqual(reconstructed, state.Utxos) || UtxoSetHash(reconstructed) != oracle.PostStateDigest {
		t.Fatal("reconstructed full-entry map/digest differs from map oracle")
	}
}

func inputViewVectorInput(t *testing.T, v connectBlockTestVector) connectBlockBasicInMemorySuiteContext {
	t.Helper()
	block, err := hex.DecodeString(v.BlockHex)
	if err != nil {
		t.Fatal(err)
	}
	input := connectBlockBasicInMemorySuiteContext{BlockBytes: block, BlockHeight: v.Height, PrevTimestamps: v.PrevTimestamps}
	for _, field := range []struct {
		name, value string
		target      **[32]byte
	}{
		{"expected_prev_hash", v.ExpectedPrevHash, &input.ExpectedPrevHash},
		{"expected_target", v.ExpectedTarget, &input.ExpectedTarget},
	} {
		if field.value != "" {
			h, err := decodeHex32Field(field.name, field.value)
			if err != nil {
				t.Fatal(err)
			}
			*field.target = &h
		}
	}
	if v.ChainID != "" {
		input.ChainID, err = decodeHex32Field("chain_id", v.ChainID)
		if err != nil {
			t.Fatal(err)
		}
	}
	return input
}

func TestConnectBlockInputViewConformance(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "conformance", "fixtures", "CV-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var accepted, rejected int
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct{ Vectors []json.RawMessage }
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, rawVector := range doc.Vectors {
			var probe struct {
				Op        string `json:"op"`
				ExpectOK  bool   `json:"expect_ok"`
				ExpectErr string `json:"expect_err"`
			}
			if err := json.Unmarshal(rawVector, &probe); err != nil {
				t.Fatal(err)
			}
			if probe.Op != "connect_block_basic" {
				continue
			}
			var v connectBlockTestVector
			if err := json.Unmarshal(rawVector, &v); err != nil {
				t.Fatal(err)
			}
			t.Run(v.ID, func(t *testing.T) { inputViewCheckVector(t, v, probe.ExpectOK, probe.ExpectErr) })
			if probe.ExpectOK {
				accepted++
			} else {
				rejected++
			}
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("vacuous corpus: valid=%d invalid=%d", accepted, rejected)
	}
	t.Logf("connect_block_basic valid=%d invalid=%d", accepted, rejected)
}

func inputViewCheckVector(t *testing.T, v connectBlockTestVector, expectOK bool, expectErr string) {
	t.Helper()
	input := inputViewVectorInput(t, v)
	pre := buildUtxoMapFromVectorJSON(t, v.Utxos)
	view := inputViewNew(pre)
	result, err := inputViewConnect(t, input, view, v.AlreadyGenerated)
	if expectOK {
		if err != nil {
			t.Fatal(err)
		}
		assertInputViewResult(t, input, pre, v.AlreadyGenerated, result)
		return
	}
	state := &InMemoryChainState{Utxos: copyUtxoMap(pre), AlreadyGenerated: v.AlreadyGenerated.Big()}
	_, mapErr := ConnectBlockBasicInMemoryAtHeightAndSuiteContext(
		input.BlockBytes, input.ExpectedPrevHash, input.ExpectedTarget, input.BlockHeight,
		input.PrevTimestamps, state, input.ChainID, input.Rotation, input.Registry,
	)
	mapTxErr, mapOK := mapErr.(*TxError)
	viewTxErr, viewOK := err.(*TxError)
	if !mapOK || !viewOK || viewTxErr.Code != mapTxErr.Code || string(viewTxErr.Code) != expectErr {
		t.Fatalf("invalid corpus errors: view=%v map=%v expected=%s", err, mapErr, expectErr)
	}
	if !reflect.DeepEqual(state.Utxos, pre) || state.AlreadyGenerated.Cmp(v.AlreadyGenerated.Big()) != 0 {
		t.Fatal("map rejection changed oracle state")
	}
}

func TestConnectBlockInputViewOrderedResult(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	pre := make(map[Outpoint]UtxoEntry)
	ops := make([]Outpoint, 6)
	for i := range ops {
		ops[i] = Outpoint{Txid: hashWithPrefix(byte(0x20 + i)), Vout: uint32(i)}
		pre[ops[i]] = UtxoEntry{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes()), CreationHeight: 1}
	}
	// Leave one pre-block entry untouched to distinguish the created map from a
	// whole-set clone, and use a mature coinbase row to cover all entry fields.
	pre[Outpoint{Txid: hashWithPrefix(0xa0)}] = UtxoEntry{Value: 7, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}
	entry := pre[ops[0]]
	entry.CreatedByCoinbase, entry.CreationHeight = true, 0
	pre[ops[0]] = entry
	tx1 := inputViewSignedTx(t, 1, pre, kp, ops[0:2]...)
	tx2 := inputViewSignedTx(t, 2, pre, kp, ops[2])
	tx3 := inputViewSignedTx(t, 3, pre, kp, ops[3:6]...)
	input := inputViewBlock(t, 100, 1, tx1, tx2, tx3)
	view := inputViewNew(pre)
	result, err := inputViewConnect(t, input, view, Uint128{})
	if err != nil {
		t.Fatal(err)
	}
	assertInputViewReads(t, view, ops...)
	assertInputViewResult(t, input, pre, Uint128{}, result)
	if result.sumFees != (Uint128{Lo: 30}) || len(result.spentInputs) != 6 || len(result.createdUtxos) != 4 {
		t.Fatalf("ordered result: %#v", result)
	}
}

func TestConnectBlockInputViewEarlyErrors(t *testing.T) {
	op0, op1 := Outpoint{Txid: hashWithPrefix(0x31)}, Outpoint{Txid: hashWithPrefix(0x32)}
	entry := UtxoEntry{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}
	for _, tc := range []struct {
		name, code, message string
		change              func(*Tx, *inputViewTestView)
		reads               []Outpoint
	}{
		{"nonce_before_later_transaction", "TX_ERR_TX_NONCE_INVALID", "tx_nonce must be >= 1 for non-coinbase", func(tx *Tx, _ *inputViewTestView) { tx.TxNonce = 0 }, nil},
		{"nonce_before_same_transaction_read", "TX_ERR_TX_NONCE_INVALID", "tx_nonce must be >= 1 for non-coinbase", func(tx *Tx, v *inputViewTestView) {
			tx.TxNonce = 0
			v.rows[op0] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("same tx unavailable")}
		}, nil},
		{"absent_before_next_input", "TX_ERR_MISSING_UTXO", "utxo not found", func(_ *Tx, v *inputViewTestView) { delete(v.entries, op0) }, []Outpoint{op0}},
		{"immature_before_next_input", "TX_ERR_COINBASE_IMMATURE", "coinbase immature", func(_ *Tx, v *inputViewTestView) {
			e := v.entries[op0]
			e.CreatedByCoinbase = true
			v.entries[op0] = e
		}, []Outpoint{op0}},
		{"duplicate_before_second_read", "TX_ERR_PARSE", "duplicate input outpoint", func(tx *Tx, _ *inputViewTestView) { tx.Inputs[1] = tx.Inputs[0] }, []Outpoint{op0}},
		{"witness_underflow_before_next_input", "TX_ERR_PARSE", "witness underflow", func(tx *Tx, _ *inputViewTestView) { tx.Witness = nil }, []Outpoint{op0}},
		{"bad_merkle_before_all_reads", "BLOCK_ERR_MERKLE_INVALID", "merkle_root mismatch", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := inputViewTx(1, op0, op1)
			view := inputViewNew(map[Outpoint]UtxoEntry{op0: entry})
			view.rows[op1] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("later unavailable")}
			if tc.change != nil {
				tc.change(tx, view)
			}
			input := inputViewBlock(t, 1, 1, tx, inputViewTx(2, op1))
			if tc.name == "bad_merkle_before_all_reads" {
				input.BlockBytes[36] ^= 1
			}
			_, err := inputViewConnect(t, input, view, Uint128{})
			assertInputViewTxError(t, err, tc.code, tc.message)
			assertInputViewReads(t, view, tc.reads...)
		})
	}
}

type inputViewFailureCase struct {
	name, message string
	row           logicalStateRowRead
	kind          logicalStateFailureKind
	cause         error
}

func inputViewFailureCases(cause error) []inputViewFailureCase {
	valid := UtxoEntry{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}
	wrapped := fmt.Errorf("wrapped row: %w", cause)
	var typedNil *TxError
	return []inputViewFailureCase{
		{"unavailable_direct", "row unavailable", logicalStateRowRead{kind: logicalStateRowUnavailable, cause: cause}, 1, cause},
		{"unavailable_wrapped", "wrapped row: row unavailable", logicalStateRowRead{kind: logicalStateRowUnavailable, cause: wrapped}, 1, wrapped},
		{"unavailable_typed_nil", "<nil>", logicalStateRowRead{kind: logicalStateRowUnavailable, cause: typedNil}, 1, typedNil},
		{"store_integrity_direct", "row unavailable", logicalStateRowRead{kind: logicalStateRowStoreIntegrity, cause: cause}, 2, cause},
		{"store_integrity_wrapped", "wrapped row: row unavailable", logicalStateRowRead{kind: logicalStateRowStoreIntegrity, cause: wrapped}, 2, wrapped},
		{"store_integrity_typed_nil", "<nil>", logicalStateRowRead{kind: logicalStateRowStoreIntegrity, cause: typedNil}, 2, typedNil},
		{"local_invariant_direct", "row unavailable", logicalStateRowRead{kind: logicalStateRowLocalInvariant, cause: cause}, 3, cause},
		{"local_invariant_wrapped", "wrapped row: row unavailable", logicalStateRowRead{kind: logicalStateRowLocalInvariant, cause: wrapped}, 3, wrapped},
		{"local_invariant_typed_nil", "<nil>", logicalStateRowRead{kind: logicalStateRowLocalInvariant, cause: typedNil}, 3, typedNil},
		{"present_cause", "invalid present logical state row", logicalStateRowRead{kind: logicalStateRowPresent, entry: valid, cause: cause}, 2, nil},
		{"present_oversize", "invalid present logical state row", logicalStateRowRead{kind: logicalStateRowPresent, entry: UtxoEntry{CovenantData: make([]byte, MAX_COVENANT_DATA_PER_OUTPUT+1)}}, 2, nil},
		{"absent_cause", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, cause: cause}, 2, nil},
		{"absent_value", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{Value: 1}}, 2, nil},
		{"absent_type", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CovenantType: 1}}, 2, nil},
		{"absent_data", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CovenantData: []byte{1}}}, 2, nil},
		{"absent_height", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CreationHeight: 1}}, 2, nil},
		{"absent_coinbase", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CreatedByCoinbase: true}}, 2, nil},
		{"unknown_zero", "unknown row read kind", logicalStateRowRead{}, 3, nil},
		{"unknown_nonzero", "unknown row read kind", logicalStateRowRead{kind: 99}, 3, nil},
		{"unknown_with_bad_payload", "unknown row read kind", logicalStateRowRead{kind: 99, entry: valid, cause: cause}, 3, nil},
	}
}

func inputViewMalformedFailureCases(cause error) []inputViewFailureCase {
	var cases []inputViewFailureCase
	for _, kind := range []struct {
		name string
		read logicalStateRowReadKind
	}{
		{"unavailable", logicalStateRowUnavailable},
		{"store_integrity", logicalStateRowStoreIntegrity},
		{"local_invariant", logicalStateRowLocalInvariant},
	} {
		cases = append(cases, inputViewFailureCase{name: kind.name + "_nil_cause", message: "malformed row read", row: logicalStateRowRead{kind: kind.read}, kind: 3})
		for _, payload := range []struct {
			name  string
			entry UtxoEntry
		}{
			{"value", UtxoEntry{Value: 1}},
			{"type", UtxoEntry{CovenantType: 1}},
			{"data", UtxoEntry{CovenantData: []byte{1}}},
			{"height", UtxoEntry{CreationHeight: 1}},
			{"coinbase", UtxoEntry{CreatedByCoinbase: true}},
		} {
			cases = append(cases, inputViewFailureCase{
				name: kind.name + "_payload_" + payload.name, message: "malformed row read",
				row: logicalStateRowRead{kind: kind.read, entry: payload.entry, cause: cause}, kind: 3,
			})
		}
	}
	return cases
}

func TestConnectBlockInputViewReadFailures(t *testing.T) {
	op0, op1 := Outpoint{Txid: hashWithPrefix(0x41)}, Outpoint{Txid: hashWithPrefix(0x42)}
	cause := errors.New("row unavailable")
	cases := append(inputViewFailureCases(cause), inputViewMalformedFailureCases(cause)...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := inputViewBlock(t, 1, 1, inputViewTx(1, op0, op1), inputViewTx(2, op1))
			view := inputViewNew(nil)
			view.rows[op0] = tc.row
			view.rows[op1] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("later unavailable")}
			_, err := inputViewConnect(t, input, view, Uint128{})
			assertInputViewFailure(t, err, op0, 1, 0, tc.kind, tc.cause, tc.message)
			assertInputViewReads(t, view, op0)
		})
	}
}

func TestConnectBlockInputViewUnavailableAtTransactionTwoInputOne(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	ops := []Outpoint{{Txid: hashWithPrefix(0x51)}, {Txid: hashWithPrefix(0x52)}, {Txid: hashWithPrefix(0x53)}, {Txid: hashWithPrefix(0x54)}}
	pre := make(map[Outpoint]UtxoEntry)
	for _, op := range ops {
		pre[op] = UtxoEntry{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}
	}
	input := inputViewBlock(t, 1, 1,
		inputViewSignedTx(t, 1, pre, kp, ops[0]), inputViewTx(2, ops[1], ops[2], ops[3]), inputViewTx(3, ops[3]),
	)
	view := inputViewNew(pre)
	cause := errors.New("tx 2 input 1 unavailable")
	view.rows[ops[2]] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: cause}
	_, err := inputViewConnect(t, input, view, Uint128{})
	assertInputViewFailure(t, err, ops[2], 2, 1, 1, cause, "tx 2 input 1 unavailable")
	assertInputViewReads(t, view, ops[0], ops[1], ops[2])
}

func TestConnectBlockInputViewInheritedInputOrder(t *testing.T) {
	op0, op1 := Outpoint{Txid: hashWithPrefix(0x61)}, Outpoint{Txid: hashWithPrefix(0x62)}
	tx := inputViewTx(1, op0, op1)
	tx.Inputs[1].Sequence = 0x80000000
	input := inputViewBlock(t, 1, 1, tx)
	view := inputViewNew(map[Outpoint]UtxoEntry{op0: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}})
	cause := errors.New("first input unavailable")
	view.rows[op0] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: cause}
	_, err := inputViewConnect(t, input, view, Uint128{})
	assertInputViewFailure(t, err, op0, 1, 0, 1, cause, "first input unavailable")
	assertInputViewReads(t, view, op0)
	state := &InMemoryChainState{Utxos: copyUtxoMap(view.entries), AlreadyGenerated: new(big.Int)}
	_, err = ConnectBlockBasicInMemoryAtHeight(input.BlockBytes, input.ExpectedPrevHash, input.ExpectedTarget, 1, nil, state, [32]byte{})
	assertInputViewTxError(t, err, "TX_ERR_SEQUENCE_INVALID", "sequence exceeds 0x7fffffff")
}

func TestConnectBlockInputViewSpentTombstones(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	op := Outpoint{Txid: hashWithPrefix(0x71)}
	pre := map[Outpoint]UtxoEntry{op: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}}
	tx1 := inputViewSignedTx(t, 1, pre, kp, op)
	created := Outpoint{Txid: testTxID(t, txBytesFromTx(t, tx1))}
	createdPre := map[Outpoint]UtxoEntry{created: {Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: pre[op].CovenantData}}
	tx2 := inputViewSignedTx(t, 2, createdPre, kp, created)
	t.Run("created_output_map_hit", func(t *testing.T) {
		input := inputViewBlock(t, 1, 1, tx1, tx2)
		view := inputViewNew(pre)
		view.rows[created] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("created output must use map")}
		result, err := inputViewConnect(t, input, view, Uint128{})
		if err != nil {
			t.Fatal(err)
		}
		assertInputViewReads(t, view, op)
		assertInputViewResult(t, input, pre, Uint128{}, result)
		if len(result.spentInputs) != 1 || len(result.createdUtxos) != 2 {
			t.Fatal("in-block output was recorded or retained after spend")
		}
	})
	for _, tc := range []struct {
		name string
		txs  []*Tx
	}{
		{"store_double_spend", []*Tx{tx1, inputViewTx(2, op)}},
		{"created_double_spend", []*Tx{tx1, tx2, inputViewTx(3, created)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := inputViewBlock(t, 1, 1, tc.txs...)
			view := inputViewNew(pre)
			_, err := inputViewConnect(t, input, view, Uint128{})
			assertInputViewTxError(t, err, "TX_ERR_MISSING_UTXO", "utxo not found")
			assertInputViewReads(t, view, op)
		})
	}
}

func TestConnectBlockInputViewCoinbaseMapHit(t *testing.T) {
	// Coinbase commitments depend on the other transactions. Use the existing
	// parsed-block continuation to observe this otherwise circular same-block
	// reference at its real lookup/maturity boundary.
	op := Outpoint{Txid: hashWithPrefix(0x81)}
	coinbase := &Tx{Outputs: []TxOutput{{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}}}
	pb := &ParsedBlock{Txs: []*Tx{coinbase, inputViewTx(1, op)}, Txids: [][32]byte{op.Txid, hashWithPrefix(0x82)}}
	view := inputViewNew(nil)
	state := &blockInputViewState{view: view, height: 1, spent: make(map[Outpoint]struct{})}
	work, fees, err := applyInMemorySequentialConnect(pb, make(map[Outpoint]UtxoEntry), 1, 1, connectBlockInMemoryValidationContext{inputView: state})
	assertInputViewTxError(t, err, "TX_ERR_COINBASE_IMMATURE", "coinbase immature")
	assertInputViewReads(t, view)
	if work != nil || fees != (Uint128{}) || len(state.spentInputs) != 0 || len(state.spent) != 0 {
		t.Fatal("immature coinbase spend published state or recorded a store row")
	}
}

func TestConnectBlockInputViewSuppliedAlreadyGenerated(t *testing.T) {
	for _, generated := range []Uint128{{Lo: 4_673_004_150}, {Hi: 1, Lo: 17}, {Hi: ^uint64(0), Lo: ^uint64(0)}} {
		for _, over := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/over=%t", generated.String(), over), func(t *testing.T) {
				subsidy := BlockSubsidyBig(2, generated.Big())
				value := subsidy
				if over {
					value++
				}
				block, prev, target := buildSupplyOnlyBlock(t, 2, value)
				ambient := &InMemoryChainState{Utxos: nil, AlreadyGenerated: big.NewInt(-1)}
				input := connectBlockBasicInMemorySuiteContext{BlockBytes: block, ExpectedPrevHash: &prev, ExpectedTarget: &target, BlockHeight: 2, State: ambient}
				view := inputViewNew(nil)
				result, err := inputViewConnect(t, input, view, generated)
				assertInputViewReads(t, view)
				if ambient.Utxos != nil || ambient.AlreadyGenerated.Cmp(big.NewInt(-1)) != 0 {
					t.Fatal("view connect read or modified ambient chainstate")
				}
				if over {
					assertInputViewTxError(t, err, "BLOCK_ERR_SUBSIDY_EXCEEDED", "coinbase outputs exceed subsidy+fees bound")
				} else if generated.Hi == ^uint64(0) {
					assertInputViewTxError(t, err, "BLOCK_ERR_PARSE", "already_generated overflow")
				} else {
					if err != nil {
						t.Fatal(err)
					}
					assertInputViewResult(t, input, nil, generated, result)
				}
				state := &InMemoryChainState{Utxos: make(map[Outpoint]UtxoEntry), AlreadyGenerated: generated.Big()}
				_, mapErr := ConnectBlockBasicInMemoryAtHeight(block, &prev, &target, 2, nil, state, [32]byte{})
				if (err == nil) != (mapErr == nil) {
					t.Fatalf("supplied counter outcomes: view=%v map=%v", err, mapErr)
				}
				if err != nil && mapErr.Error() != err.Error() {
					t.Fatalf("supplied counter errors: view=%v map=%v", err, mapErr)
				}
			})
		}
	}
}

type inputViewPanicView struct{}

func (*inputViewPanicView) Counters() logicalStateCounterRead { panic("unexpected counters read") }

func (*inputViewPanicView) Lookup(Outpoint) logicalStateRowRead { panic("view lookup panic") }

func TestConnectBlockInputViewNilAndPanic(t *testing.T) {
	result, err := connectBlockBasicWithInputView(connectBlockBasicInMemorySuiteContext{BlockBytes: []byte{0}}, nil, Uint128{})
	failure, ok := err.(*logicalStateFailure)
	if !ok || failure.kind != 3 || failure.Error() != "nil logical state view" || result != nil {
		t.Fatalf("nil view preflight=%#v/%v", result, err)
	}
	op := Outpoint{Txid: hashWithPrefix(0x91)}
	input := inputViewBlock(t, 1, 1, inputViewTx(1, op))
	var typedNil *inputViewPanicView
	for _, tc := range []struct {
		name string
		view logicalStateView
	}{{"direct_panic", &inputViewPanicView{}}, {"typed_nil_panic", typedNil}} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if got := recover(); got != "view lookup panic" {
					t.Fatalf("panic=%v, want unchanged view lookup panic", got)
				}
			}()
			_, _ = connectBlockBasicWithInputView(input, tc.view, Uint128{})
		})
	}
}

func TestConnectBlockInputViewHeightZero(t *testing.T) {
	op := Outpoint{Txid: hashWithPrefix(0x92)}
	input := inputViewBlock(t, 0, 1, inputViewTx(1, op))
	view := inputViewNew(nil)
	view.rows[op] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("pre-genesis read forbidden")}
	_, err := inputViewConnect(t, input, view, Uint128{})
	assertInputViewTxError(t, err, "TX_ERR_MISSING_UTXO", "utxo not found")
	assertInputViewReads(t, view)
	state := &InMemoryChainState{Utxos: make(map[Outpoint]UtxoEntry)}
	_, err = ConnectBlockBasicInMemoryAtHeight(input.BlockBytes, input.ExpectedPrevHash, input.ExpectedTarget, 0, nil, state, [32]byte{})
	assertInputViewTxError(t, err, "TX_ERR_MISSING_UTXO", "utxo not found")
}

func TestConnectBlockInputViewRetainedRows(t *testing.T) {
	block, prev, target, pre := buildTestBlock(t, 1)
	input := connectBlockBasicInMemorySuiteContext{BlockBytes: block, ExpectedPrevHash: &prev, ExpectedTarget: &target, BlockHeight: 1}
	view := inputViewNew(pre)
	result, err := inputViewConnect(t, input, view, Uint128{})
	if err != nil {
		t.Fatal(err)
	}
	assertInputViewResult(t, input, pre, Uint128{}, result)
	row := result.spentInputs[0]
	source := view.entries[row.outpoint]
	if &row.entry.CovenantData[0] != &source.CovenantData[0] {
		t.Fatal("spent list did not retain the row exactly as returned")
	}
	beforeSpent := append([]blockSpentInput(nil), result.spentInputs...)
	for i := range beforeSpent {
		beforeSpent[i].entry = cloneUtxoEntry(beforeSpent[i].entry)
	}
	beforeCreated := copyUtxoMap(result.createdUtxos)
	other, err := inputViewConnect(t, input, view, Uint128{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.spentInputs, beforeSpent) || !reflect.DeepEqual(result.createdUtxos, beforeCreated) {
		t.Fatal("later connect changed a retained result")
	}
	if &result.spentInputs[0] == &other.spentInputs[0] {
		t.Fatal("block calls share their spent-list storage")
	}
}

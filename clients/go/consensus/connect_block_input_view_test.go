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

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
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
		raw, err := MarshalTx(tx)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, raw)
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
		PrevTimestamps: make([]uint64, min(height, 11)),
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
	result, err := inputViewQualifiedConnect(input, view, generated)
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

func inputViewQualifiedConnect(input connectBlockBasicInMemorySuiteContext, view logicalStateView, generated Uint128) (*connectBlockInputViewResult, error) {
	if input.ExpectedPrevHash == nil || input.ExpectedTarget == nil {
		return nil, ErrBlockSteps1To12Context
	}
	if _, err := ValidateBlockSteps1To12(input.BlockBytes, *input.ExpectedPrevHash, *input.ExpectedTarget, input.BlockHeight, input.PrevTimestamps); err != nil {
		return nil, err
	}
	return connectBlockBasicWithInputView(input, view, generated)
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

func assertInputViewResult(t *testing.T, input connectBlockBasicInMemorySuiteContext, pre map[Outpoint]UtxoEntry, generated Uint128, result *connectBlockInputViewResult) []blockSpentInput {
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
				// Independent CSM-SV framing: Outpoint36 + value8 + type2 +
				// CompactSize + complete data + height8 + coinbase1.
				dataLen := len(entry.CovenantData)
				prefix := 1
				if dataLen >= 65_536 {
					prefix = 5
				} else if dataLen >= 253 {
					prefix = 3
				}
				spent = append(spent, blockSpentInput{
					outpoint: op, txIndex: uint32(txIndex + 1), inputIndex: uint32(inputIndex),
					logicalEntryLength: uint32(55 + prefix + dataLen),
				})
			}
		}
	}
	observed := inputViewConsume(t, result.spentInputs)
	if !reflect.DeepEqual(observed, spent) {
		t.Fatalf("spent rows=%#v, want map inputs %#v", observed, spent)
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
	for _, row := range observed {
		delete(reconstructed, row.outpoint)
	}
	for op, entry := range result.createdUtxos {
		reconstructed[op] = entry
	}
	if !reflect.DeepEqual(reconstructed, state.Utxos) || UtxoSetHash(reconstructed) != oracle.PostStateDigest {
		t.Fatal("reconstructed full-entry map/digest differs from map oracle")
	}
	return observed
}

func inputViewConsume(t *testing.T, source *blockSpentInputSource) []blockSpentInput {
	t.Helper()
	if source == nil {
		t.Fatal("successful connect has no compact source")
	}
	var rows []blockSpentInput
	for {
		row, ok := source.next()
		if !ok {
			if row != (blockSpentInput{}) {
				t.Fatalf("terminal tuple=%#v, want zero", row)
			}
			break
		}
		rows = append(rows, row)
	}
	assertInputViewSourceReleased(t, source)
	return rows
}

func assertInputViewSourceReleased(t *testing.T, source *blockSpentInputSource) {
	t.Helper()
	if source.raw != nil || source.spent != nil || source.current != nil {
		t.Fatalf("terminal source retained an owner: %#v", source)
	}
	for i := 0; i < 2; i++ {
		row, ok := source.next()
		if ok || row != (blockSpentInput{}) || source.raw != nil || source.spent != nil || source.current != nil {
			t.Fatalf("terminal source resumed: %#v/%t/%#v", row, ok, source)
		}
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
			// Optional-context/height-zero vectors remain covered by the
			// existing public suite; they are outside this private admission.
			if v.Height == 0 || v.ExpectedPrevHash == "" || v.ExpectedTarget == "" || uint64(len(v.PrevTimestamps)) != min(v.Height, 11) {
				continue
			}
			t.Run(v.ID, func(t *testing.T) { inputViewCheckVector(t, v, probe.ExpectOK, probe.ExpectErr) })
			if probe.ExpectOK {
				accepted++
			} else {
				rejected++
			}
		}
	}
	if accepted == 0 {
		t.Fatalf("vacuous qualified corpus: valid=%d invalid=%d", accepted, rejected)
	}
	t.Logf("explicit positive-height context corpus valid=%d invalid=%d; bespoke rows cover omitted step13 failures", accepted, rejected)
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
	if !mapOK || !viewOK || viewTxErr.Code != mapTxErr.Code || viewTxErr.Msg != mapTxErr.Msg || string(viewTxErr.Code) != expectErr {
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
	rows := assertInputViewResult(t, input, pre, Uint128{}, result)
	assertInputViewReads(t, view, ops...)
	if result.sumFees != (Uint128{Lo: 30}) || len(rows) != 6 || len(result.createdUtxos) != 4 {
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
		{"present_oversize", "invalid present logical state row", logicalStateRowRead{kind: logicalStateRowPresent, entry: UtxoEntry{CovenantData: make([]byte, 65_537)}}, 2, nil},
		{"absent_cause", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, cause: cause}, 2, nil},
		{"absent_value", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{Value: 1}}, 2, nil},
		{"absent_type", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CovenantType: 1}}, 2, nil},
		{"absent_data", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CovenantData: []byte{1}}}, 2, nil},
		{"absent_height", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CreationHeight: 1}}, 2, nil},
		{"absent_coinbase", "invalid absent logical state row", logicalStateRowRead{kind: logicalStateRowAbsent, entry: UtxoEntry{CreatedByCoinbase: true}}, 2, nil},
		{"unknown_zero", "unknown row read kind", logicalStateRowRead{}, 3, nil},
		{"unknown_zero_with_bad_payload", "unknown row read kind", logicalStateRowRead{entry: valid, cause: cause}, 3, nil},
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
	var typedNil *TxError
	for _, tc := range []struct {
		name, message string
		cause         error
	}{
		{"direct", "tx 2 input 1 unavailable", cause},
		{"wrapped", "wrapped: tx 2 input 1 unavailable", fmt.Errorf("wrapped: %w", cause)},
		{"typed_nil", "<nil>", typedNil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view.reads = nil
			view.rows[ops[2]] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: tc.cause}
			_, err := inputViewConnect(t, input, view, Uint128{})
			assertInputViewFailure(t, err, ops[2], 2, 1, 1, tc.cause, tc.message)
			assertInputViewReads(t, view, ops[0], ops[1], ops[2])
		})
	}
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
		rows := assertInputViewResult(t, input, pre, Uint128{}, result)
		assertInputViewReads(t, view, op)
		if len(rows) != 1 || len(result.createdUtxos) != 2 {
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
	// A bounded Q fixture for a same-block coinbase reference is not available:
	// its txid includes the commitment of the suffix that would reference it.
	// Observe the actual private UB map-hit/maturity boundary directly instead.
	op := Outpoint{Txid: hashWithPrefix(0x81)}
	created := map[Outpoint]UtxoEntry{op: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData(), CreationHeight: 1, CreatedByCoinbase: true}}
	before := copyUtxoMap(created)
	view := inputViewNew(nil)
	state := &blockInputViewState{view: view, height: 1, txIndex: 1, spent: make(map[Outpoint]uint32)}
	work, fees, err := applyNonCoinbaseTxBasicWork(nonCoinbaseApplyWorkInput{
		tx: inputViewTx(1, op), txid: hashWithPrefix(0x82), utxoSet: created,
		height: 1, blockMTP: 1, inputView: state,
	})
	assertInputViewTxError(t, err, "TX_ERR_COINBASE_IMMATURE", "coinbase immature")
	assertInputViewReads(t, view)
	if work != nil || fees != (Uint128{}) || len(state.spent) != 0 || !reflect.DeepEqual(created, before) {
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
				input := connectBlockBasicInMemorySuiteContext{BlockBytes: block, ExpectedPrevHash: &prev, ExpectedTarget: &target, BlockHeight: 2, PrevTimestamps: []uint64{0, 0}, State: ambient}
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
			_, _ = inputViewQualifiedConnect(input, tc.view, Uint128{})
		})
	}
}

func TestConnectBlockInputViewHeightZero(t *testing.T) {
	op := Outpoint{Txid: hashWithPrefix(0x92)}
	input := inputViewBlock(t, 0, 1, inputViewTx(1, op))
	view := inputViewNew(nil)
	view.rows[op] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("pre-genesis read forbidden")}
	_, err := inputViewConnect(t, input, view, Uint128{})
	if err != ErrBlockSteps1To12Context {
		t.Fatalf("height-zero Q refusal=%v, want context refusal", err)
	}
	assertInputViewReads(t, view)
	state := &InMemoryChainState{Utxos: make(map[Outpoint]UtxoEntry)}
	_, err = ConnectBlockBasicInMemoryAtHeight(input.BlockBytes, input.ExpectedPrevHash, input.ExpectedTarget, 0, nil, state, [32]byte{})
	assertInputViewTxError(t, err, "TX_ERR_MISSING_UTXO", "utxo not found")
}

func TestConnectBlockInputViewRetainedRows(t *testing.T) {
	block, prev, target, pre := buildTestBlock(t, 1)
	input := connectBlockBasicInMemorySuiteContext{BlockBytes: block, ExpectedPrevHash: &prev, ExpectedTarget: &target, BlockHeight: 1, PrevTimestamps: []uint64{0}}
	view := inputViewNew(pre)
	result, err := inputViewConnect(t, input, view, Uint128{})
	if err != nil {
		t.Fatal(err)
	}
	rows := assertInputViewResult(t, input, pre, Uint128{}, result)
	beforeCreated := copyUtxoMap(result.createdUtxos)
	other, err := inputViewConnect(t, input, view, Uint128{})
	if err != nil {
		t.Fatal(err)
	}
	otherRows := assertInputViewResult(t, input, pre, Uint128{}, other)
	if !reflect.DeepEqual(rows, otherRows) || !reflect.DeepEqual(result.createdUtxos, beforeCreated) {
		t.Fatal("later connect changed a retained result")
	}
	if result.spentInputs == other.spentInputs {
		t.Fatal("block calls share their consuming source")
	}
	for _, row := range rows {
		entry := view.entries[row.outpoint]
		entry.CovenantData[0] ^= 1
		view.entries[row.outpoint] = entry
	}
	for i := range input.BlockBytes {
		input.BlockBytes[i] ^= 1
	}
	if !reflect.DeepEqual(result.createdUtxos, beforeCreated) || !reflect.DeepEqual(other.createdUtxos, beforeCreated) {
		t.Fatal("created result borrowed released block/view backing")
	}
}

func TestConnectBlockInputViewSourceDiscard(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	op0, op1 := Outpoint{Txid: hashWithPrefix(0xa1)}, Outpoint{Txid: hashWithPrefix(0xa2)}
	pre := map[Outpoint]UtxoEntry{
		op0: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())},
		op1: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())},
	}
	tx1 := inputViewSignedTx(t, 1, pre, kp, op0)
	created := Outpoint{Txid: testTxID(t, txBytesFromTx(t, tx1))}
	createdPre := map[Outpoint]UtxoEntry{created: {Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: pre[op0].CovenantData}}
	input := inputViewBlock(t, 1, 1, tx1, inputViewSignedTx(t, 2, createdPre, kp, created), inputViewSignedTx(t, 3, pre, kp, op1))
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial=%t", partial), func(t *testing.T) {
			view := inputViewNew(pre)
			result, err := inputViewConnect(t, input, view, Uint128{})
			if err != nil {
				t.Fatal(err)
			}
			source := result.spentInputs
			if len(source.spent) != 3 || source.spent[op0] != 89 || source.spent[op1] != 89 || source.spent[created] != 0 {
				t.Fatalf("compact domains=%v", source.spent)
			}
			if &source.raw[0] != &input.BlockBytes[0] {
				t.Fatal("source copied immutable block backing")
			}
			if partial {
				got, ok := source.next()
				want := blockSpentInput{outpoint: op0, txIndex: 1, inputIndex: 0, logicalEntryLength: 89}
				if !ok || got != want {
					t.Fatalf("first tuple=%#v/%t, want %#v", got, ok, want)
				}
				if _, retained := source.spent[op0]; retained {
					t.Fatal("emitted key was not consumed")
				}
			}
			source.discard()
			assertInputViewSourceReleased(t, source)
			source.discard()
			assertInputViewSourceReleased(t, source)
			assertInputViewReads(t, view, op0, op1)
			fresh, err := inputViewConnect(t, input, view, Uint128{})
			if err != nil {
				t.Fatal(err)
			}
			got := inputViewConsume(t, fresh.spentInputs)
			want := []blockSpentInput{
				{outpoint: op0, txIndex: 1, inputIndex: 0, logicalEntryLength: 89},
				{outpoint: op1, txIndex: 3, inputIndex: 0, logicalEntryLength: 89},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("fresh source=%#v, want %#v", got, want)
			}
			assertInputViewReads(t, view, op0, op1, op0, op1)
		})
	}
}

func TestConnectBlockInputViewCoinbaseOnlySource(t *testing.T) {
	input := inputViewBlock(t, 2, 1)
	view := inputViewNew(nil)
	result, err := inputViewConnect(t, input, view, Uint128{})
	if err != nil {
		t.Fatal(err)
	}
	rows := assertInputViewResult(t, input, nil, Uint128{}, result)
	if len(rows) != 0 || result.sumFees != (Uint128{}) || len(result.createdUtxos) != 1 {
		t.Fatalf("coinbase-only result=%#v rows=%#v", result, rows)
	}
	assertInputViewReads(t, view)
	var zero blockSpentInputSource
	assertInputViewSourceReleased(t, &zero)
}

func TestConnectBlockInputViewCompactLengthBoundaries(t *testing.T) {
	op := Outpoint{Txid: hashWithPrefix(0xb1), Vout: 7}
	for _, tc := range []struct {
		dataLength int
		logical    uint32
		serialized uint32
	}{{0, 56, 20}, {252, 308, 272}, {253, 311, 275}, {65_535, 65_593, 65_557}, {65_536, 65_596, 65_560}} {
		t.Run(fmt.Sprint(tc.dataLength), func(t *testing.T) {
			data := append([]byte(nil), bytes.Repeat([]byte{0x51}, tc.dataLength)...)
			entry := UtxoEntry{Value: 17, CovenantType: COV_TYPE_P2PK, CovenantData: data, CreationHeight: 3, CreatedByCoinbase: true}
			view := inputViewNew(map[Outpoint]UtxoEntry{op: entry})
			state := &blockInputViewState{view: view, height: 100, txIndex: 2, spent: make(map[Outpoint]uint32)}
			got, err := state.lookup(op, 1)
			if err != nil || !reflect.DeepEqual(got, entry) || state.spent[op] != tc.logical || state.spent[op]-36 != tc.serialized {
				t.Fatalf("complete read/length=%#v/%v/%v, want %#v/%d/%d", got, err, state.spent, entry, tc.logical, tc.serialized)
			}
			assertInputViewReads(t, view, op)
			// These are generic width-valid rows, not creation-valid P2PK.
			// Their complete data still reaches the existing spend-time owner.
			ctx := nonCoinbaseApplyContext{tx: inputViewTx(1, op), work: make(map[Outpoint]UtxoEntry), height: 100}
			ctx.tx.Witness[0] = WitnessItem{SuiteID: 1, Pubkey: make([]byte, 2_592), Signature: make([]byte, 4_628)}
			err = ctx.validateP2PKInput(0, got, ctx.tx.Witness)
			assertInputViewTxError(t, err, "TX_ERR_COVENANT_TYPE_INVALID", "CORE_P2PK covenant_data invalid")
			if len(got.CovenantData) != tc.dataLength || !reflect.DeepEqual(view.entries[op], entry) {
				t.Fatal("spend rejection truncated or modified complete generic source")
			}
		})
	}
}

func inputViewRewriteFirst(t *testing.T, input connectBlockBasicInMemorySuiteContext, change func(*Tx)) connectBlockBasicInMemorySuiteContext {
	t.Helper()
	pb, err := ParseBlockBytes(input.BlockBytes)
	if err != nil {
		t.Fatal(err)
	}
	change(pb.Txs[0])
	encoded := make([][]byte, 0, len(pb.Txs))
	ids := make([][32]byte, 0, len(pb.Txs))
	for _, tx := range pb.Txs {
		b := txBytesFromTx(t, tx)
		encoded = append(encoded, b)
		ids = append(ids, testTxID(t, b))
	}
	root, err := MerkleRootTxids(ids)
	if err != nil {
		t.Fatal(err)
	}
	input.BlockBytes = buildBlockBytes(t, *input.ExpectedPrevHash, root, *input.ExpectedTarget, 1, encoded)
	return input
}

func TestConnectBlockInputViewExactPlacementTerms(t *testing.T) {
	canonical := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	for _, tc := range []struct {
		name   string
		change func(*Tx)
	}{
		{"input_count_zero", func(tx *Tx) { tx.Inputs = nil }},
		{"input_count_two", func(tx *Tx) { tx.Inputs = append(tx.Inputs, tx.Inputs[0]) }},
		{"output_count_zero", func(tx *Tx) { tx.Outputs = nil }},
		{"kind_one", func(tx *Tx) { tx.TxKind = 1 }},
		{"nonzero_prevtxid", func(tx *Tx) { tx.Inputs[0].PrevTxid[31] = 1 }},
		{"ordinary_prevout", func(tx *Tx) { tx.Inputs[0].PrevVout = 0xffff_fffe }},
		{"script_sig", func(tx *Tx) { tx.Inputs[0].ScriptSig = []byte{1} }},
		{"witness", func(tx *Tx) { tx.Witness = dummyWitnesses(1) }},
		{"da_payload", func(tx *Tx) { tx.DaPayload = []byte{1} }},
		{"sequence", func(tx *Tx) { tx.Inputs[0].Sequence = 0xffff_fffe }},
		{"nonce", func(tx *Tx) { tx.TxNonce = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, _, _, _, err := ParseTx(canonical)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateInputViewPlacementTx(tx, 0); err != nil {
				t.Fatalf("canonical first rejected: %v", err)
			}
			assertInputViewTxError(t, validateInputViewPlacementTx(tx, 2), "BLOCK_ERR_COINBASE_INVALID", "coinbase-like tx is only allowed at index 0")
			tc.change(tx)
			message := "first tx must be canonical coinbase"
			if tc.name == "output_count_zero" {
				message = "coinbase must have at least one output"
			}
			assertInputViewTxError(t, validateInputViewPlacementTx(tx, 0), "BLOCK_ERR_COINBASE_INVALID", message)
			for _, ordinal := range []uint64{1, 2, 3} {
				if err := validateInputViewPlacementTx(tx, ordinal); err != nil {
					t.Fatalf("exact non-match falsely rejected at %d: %v", ordinal, err)
				}
			}
		})
	}
}

func TestConnectBlockInputViewPlacementBeforeApplication(t *testing.T) {
	op := Outpoint{Txid: hashWithPrefix(0xc1)}
	later, _, _, _, err := ParseTx(coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		ordinary     func(*Tx)
		coinbase     func(*Tx)
		unavailable  bool
	}{
		{name: "missing"},
		{name: "unavailable", unavailable: true},
		{name: "nonce", ordinary: func(tx *Tx) { tx.TxNonce = 0 }},
		{name: "locktime", coinbase: func(tx *Tx) { tx.Locktime = 2 }},
		{name: "coinbase_creation", coinbase: func(tx *Tx) { tx.Outputs[0].CovenantData = []byte{1} }},
	} {
		for _, ordinal := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/suffix%d", tc.name, ordinal), func(t *testing.T) {
				ordinary := inputViewTx(1, op)
				if tc.ordinary != nil {
					tc.ordinary(ordinary)
				}
				txs := []*Tx{ordinary, inputViewTx(2, op)}
				txs = append(txs[:ordinal-1], append([]*Tx{later}, txs[ordinal-1:]...)...)
				input := inputViewBlock(t, 1, 1, txs...)
				if tc.coinbase != nil {
					input = inputViewRewriteFirst(t, input, tc.coinbase)
				}
				view := inputViewNew(nil)
				if tc.unavailable {
					view.rows[op] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("unavailable before suffix")}
				}
				_, err := inputViewConnect(t, input, view, Uint128{})
				assertInputViewTxError(t, err, "BLOCK_ERR_COINBASE_INVALID", "coinbase-like tx is only allowed at index 0")
				assertInputViewReads(t, view)
			})
		}
	}
}

func TestConnectBlockInputViewZeroOutputSuffix(t *testing.T) {
	later, _, _, _, err := ParseTx(coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	later.Outputs = nil
	input := inputViewBlock(t, 1, 1, later)
	_, off, count, err := storedCommitmentFrame(input.BlockBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInputViewPlacement(input.BlockBytes, off, count); err != nil {
		t.Fatalf("zero-output suffix must pass exact placement: %v", err)
	}
	view := inputViewNew(nil)
	_, err = inputViewConnect(t, input, view, Uint128{})
	assertInputViewTxError(t, err, "BLOCK_ERR_COINBASE_INVALID", "coinbase-like tx is only allowed at index 0")
	assertInputViewReads(t, view)
	// This is inherited application classification, not normative non-match conformance.
	state := &InMemoryChainState{Utxos: make(map[Outpoint]UtxoEntry)}
	_, err = ConnectBlockBasicInMemoryAtHeight(input.BlockBytes, input.ExpectedPrevHash, input.ExpectedTarget, 1, input.PrevTimestamps, state, [32]byte{})
	assertInputViewTxError(t, err, "BLOCK_ERR_COINBASE_INVALID", "coinbase-like tx is only allowed at index 0")
}

func TestConnectBlockInputViewQualificationRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*connectBlockBasicInMemorySuiteContext)
		want   error
	}{
		{"height_zero", func(input *connectBlockBasicInMemorySuiteContext) { input.BlockHeight, input.PrevTimestamps = 0, nil }, ErrBlockSteps1To12Context},
		{"missing_parent", func(input *connectBlockBasicInMemorySuiteContext) { input.ExpectedPrevHash = nil }, ErrBlockSteps1To12Context},
		{"missing_target", func(input *connectBlockBasicInMemorySuiteContext) { input.ExpectedTarget = nil }, ErrBlockSteps1To12Context},
		{"zero_target", func(input *connectBlockBasicInMemorySuiteContext) { input.ExpectedTarget = &[32]byte{} }, ErrBlockSteps1To12Context},
		{"nil_timestamps", func(input *connectBlockBasicInMemorySuiteContext) { input.PrevTimestamps = nil }, ErrBlockSteps1To12Context},
		{"short_timestamps", func(input *connectBlockBasicInMemorySuiteContext) { input.PrevTimestamps = []uint64{0} }, ErrBlockSteps1To12Context},
		{"extra_timestamps", func(input *connectBlockBasicInMemorySuiteContext) { input.PrevTimestamps = []uint64{0, 0, 0} }, ErrBlockSteps1To12Context},
		{"capacity", func(input *connectBlockBasicInMemorySuiteContext) { input.BlockBytes = make([]byte, 68_000_126) }, ErrBlockSteps1To12Capacity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := inputViewBlock(t, 2, 1)
			tc.change(&input)
			view := inputViewNew(nil)
			_, err := inputViewConnect(t, input, view, Uint128{})
			if err != tc.want {
				t.Fatalf("Q refusal=%v, want unchanged %v", err, tc.want)
			}
			assertInputViewReads(t, view)
		})
	}
}

func TestConnectBlockInputViewQualificationBeforePlacement(t *testing.T) {
	op := Outpoint{Txid: hashWithPrefix(0xc2)}
	later, _, _, _, err := ParseTx(coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, code, message string
		change              func(*connectBlockBasicInMemorySuiteContext)
	}{
		{"bad_merkle", "BLOCK_ERR_MERKLE_INVALID", "merkle_root mismatch", func(input *connectBlockBasicInMemorySuiteContext) { input.BlockBytes[36] ^= 1 }},
		{"trailing_P0", "BLOCK_ERR_PARSE", "trailing bytes after tx list", func(input *connectBlockBasicInMemorySuiteContext) { input.BlockBytes = append(input.BlockBytes, 1) }},
		{"complete_P0", "TX_ERR_PARSE", "unexpected EOF (u8)", func(input *connectBlockBasicInMemorySuiteContext) { input.BlockBytes = input.BlockBytes[:len(input.BlockBytes)-1] }},
		{"parent", "BLOCK_ERR_LINKAGE_INVALID", "prev_block_hash mismatch", func(input *connectBlockBasicInMemorySuiteContext) { input.ExpectedPrevHash = &[32]byte{3} }},
		{"timestamp", "BLOCK_ERR_TIMESTAMP_OLD", "timestamp <= MTP median", func(input *connectBlockBasicInMemorySuiteContext) { input.PrevTimestamps = []uint64{1} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := inputViewBlock(t, 1, 1, inputViewTx(0, op), later)
			tc.change(&input)
			view := inputViewNew(nil)
			_, err := inputViewConnect(t, input, view, Uint128{})
			assertInputViewTxError(t, err, tc.code, tc.message)
			assertInputViewReads(t, view)
		})
	}
	t.Run("dual_merkle_weight", func(t *testing.T) {
		tx := inputViewTx(1, op)
		tx.Witness[0] = WitnessItem{SuiteID: 0x7e, Signature: make([]byte, 67_999_600)}
		input := inputViewBlock(t, 1, 1, tx, later)
		// First establish the single resource result, then add only the Merkle
		// violation so the dual case cannot fail merely on capacity or setup.
		view := inputViewNew(nil)
		_, err := inputViewConnect(t, input, view, Uint128{})
		assertInputViewTxError(t, err, "BLOCK_ERR_WEIGHT_EXCEEDED", "block weight exceeded")
		assertInputViewReads(t, view)
		input.BlockBytes[36] ^= 1
		_, err = inputViewConnect(t, input, view, Uint128{})
		assertInputViewTxError(t, err, "BLOCK_ERR_MERKLE_INVALID", "merkle_root mismatch")
		assertInputViewReads(t, view)
	})
}

func TestConnectBlockInputViewScalarCoinbaseOrdering(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	op0, op1 := Outpoint{Txid: hashWithPrefix(0xd1)}, Outpoint{Txid: hashWithPrefix(0xd2)}
	pre := map[Outpoint]UtxoEntry{op0: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}}
	tx1 := inputViewSignedTx(t, 1, pre, kp, op0)
	for _, successfulSuffix := range []bool{false, true} {
		t.Run(fmt.Sprintf("suffix_success=%t", successfulSuffix), func(t *testing.T) {
			txs := []*Tx{tx1}
			if !successfulSuffix {
				txs = append(txs, inputViewTx(0, op1), inputViewTx(2, op1))
			}
			input := inputViewBlock(t, 1, ^uint64(0), txs...)
			view := inputViewNew(pre)
			view.rows[op1] = logicalStateRowRead{kind: logicalStateRowUnavailable, cause: errors.New("later unavailable")}
			_, err := inputViewConnect(t, input, view, Uint128{})
			if successfulSuffix {
				assertInputViewTxError(t, err, "BLOCK_ERR_SUBSIDY_EXCEEDED", "coinbase outputs exceed subsidy+fees bound")
			} else {
				assertInputViewTxError(t, err, "TX_ERR_TX_NONCE_INVALID", "tx_nonce must be >= 1 for non-coinbase")
			}
			assertInputViewReads(t, view, op0)
		})
	}
	for _, generated := range []Uint128{{Lo: 4_673_004_150}, {Hi: 1, Lo: 17}} {
		input := inputViewBlock(t, 2, 1, tx1)
		input.State = &InMemoryChainState{AlreadyGenerated: big.NewInt(-1)}
		view := inputViewNew(pre)
		result, err := inputViewConnect(t, input, view, generated)
		if err != nil {
			t.Fatal(err)
		}
		assertInputViewResult(t, input, pre, generated, result)
		if result.sumFees != (Uint128{Lo: 10}) || input.State.AlreadyGenerated.Sign() != -1 {
			t.Fatalf("underclaim/fees/ambient result=%#v", result)
		}
		assertInputViewReads(t, view, op0)
	}
}

func TestConnectBlockInputViewCoinbaseStructure(t *testing.T) {
	for _, tc := range []struct {
		name, code, message string
		height              uint64
		change              func(*Tx)
	}{
		{"noncanonical_first", "BLOCK_ERR_COINBASE_INVALID", "first tx must be canonical coinbase", 1, func(tx *Tx) { tx.TxNonce = 1 }},
		{"height_range", "BLOCK_ERR_COINBASE_INVALID", "block height exceeds coinbase locktime range", 0x1_0000_0000, nil},
		{"locktime", "BLOCK_ERR_COINBASE_INVALID", "coinbase locktime must equal block height", 1, func(tx *Tx) { tx.Locktime = 2 }},
		{"creation", "TX_ERR_COVENANT_TYPE_INVALID", "invalid CORE_P2PK covenant_data length", 1, func(tx *Tx) { tx.Outputs[0].CovenantData = []byte{1} }},
		{"vault", "BLOCK_ERR_COINBASE_INVALID", "coinbase must not create CORE_VAULT outputs", 1, func(tx *Tx) { tx.Outputs[0].CovenantType = COV_TYPE_VAULT }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := inputViewBlock(t, tc.height, 1, inputViewTx(1, Outpoint{Txid: hashWithPrefix(0xd3)}))
			if tc.change != nil {
				input = inputViewRewriteFirst(t, input, tc.change)
			}
			view := inputViewNew(nil)
			_, err := inputViewConnect(t, input, view, Uint128{})
			assertInputViewTxError(t, err, tc.code, tc.message)
			assertInputViewReads(t, view)
		})
	}
}

func TestConnectBlockInputViewLegacyCoinbaseGuards(t *testing.T) {
	for _, tc := range []struct {
		name    string
		block   *ParsedBlock
		height  uint64
		fees    Uint128
		code    string
		message string
	}{
		{"missing_nil_positive", nil, 1, Uint128{}, "BLOCK_ERR_COINBASE_INVALID", "missing coinbase"},
		{"missing_nil_genesis", nil, 0, Uint128{}, "BLOCK_ERR_COINBASE_INVALID", "missing coinbase"},
		{"missing_empty_positive", &ParsedBlock{}, 1, Uint128{}, "BLOCK_ERR_COINBASE_INVALID", "missing coinbase"},
		{"missing_empty_genesis", &ParsedBlock{}, 0, Uint128{}, "BLOCK_ERR_COINBASE_INVALID", "missing coinbase"},
		{"nil_coinbase_positive", &ParsedBlock{Txs: []*Tx{nil}}, 1, Uint128{}, "BLOCK_ERR_COINBASE_INVALID", "nil coinbase"},
		{"nil_coinbase_genesis", &ParsedBlock{Txs: []*Tx{nil}}, 0, Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}, "", ""},
		{"genesis_before_bound", &ParsedBlock{Txs: []*Tx{{Outputs: []TxOutput{{Value: ^uint64(0)}}}}}, 0, Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}, "", ""},
		{"checked_subsidy_fees_overflow", &ParsedBlock{Txs: []*Tx{{}}}, 1, Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}, "BLOCK_ERR_PARSE", "u128 overflow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCoinbaseValueBound(tc.block, tc.height, big.NewInt(0), tc.fees)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("legacy genesis guard: %v", err)
				}
				return
			}
			assertInputViewTxError(t, err, tc.code, tc.message)
		})
	}
}

func TestConnectBlockInputViewQualificationDA(t *testing.T) {
	for _, hashMatches := range []bool{false, true} {
		t.Run(fmt.Sprintf("hash_match=%t", hashMatches), func(t *testing.T) {
			tx := inputViewTx(1, Outpoint{Txid: hashWithPrefix(0xd4)})
			tx.TxKind, tx.DaPayload = 2, []byte{1, 2}
			tx.DaChunkCore = &DaChunkCore{DaID: hashWithPrefix(0xd5)}
			if hashMatches {
				tx.DaChunkCore.ChunkHash = sha3_256(tx.DaPayload)
			}
			input := inputViewBlock(t, 1, 1, tx)
			view := inputViewNew(nil)
			_, err := inputViewConnect(t, input, view, Uint128{})
			if hashMatches {
				assertInputViewTxError(t, err, "BLOCK_ERR_DA_SET_INVALID", "DA chunks without DA commit")
			} else {
				assertInputViewTxError(t, err, "BLOCK_ERR_DA_CHUNK_HASH_INVALID", "chunk_hash mismatch")
			}
			assertInputViewReads(t, view)
		})
	}
}

func TestConnectBlockInputViewContextShapeGuards(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		nilTx                     bool
		inputs, resolved, outputs int
		message                   string
	}{
		{"nil", true, 0, 0, 0, "nil tx"},
		{"missing_resolved", false, 1, 0, 1, "simplicity txcontext resolved input count mismatch"},
		{"extra_resolved", false, 0, 1, 1, "simplicity txcontext resolved input count mismatch"},
		{"input_overflow", false, 1025, 1025, 1, "simplicity txcontext input_count overflow"},
		{"output_overflow", false, 1, 1, 1025, "simplicity txcontext output_count overflow"},
		{"both_overflow", false, 1025, 1025, 1025, "simplicity txcontext input_count overflow"},
		{"mismatch_before_overflow", false, 1025, 1024, 1025, "simplicity txcontext resolved input count mismatch"},
		{"max_inputs", false, 1024, 1024, 1, ""},
		{"max_outputs", false, 1, 1, 1024, ""},
		{"max_both", false, 1024, 1024, 1024, ""},
		{"empty", false, 0, 0, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &Tx{Inputs: make([]TxInput, tc.inputs), Outputs: make([]TxOutput, tc.outputs)}
			for i := range tx.Inputs {
				tx.Inputs[i] = TxInput{PrevTxid: hashWithPrefix(0xf5), PrevVout: uint32(i), Sequence: 17}
			}
			inputsBefore := append([]TxInput{}, tx.Inputs...)
			resolved, resolvedBefore := make([]UtxoEntry, tc.resolved), make([]UtxoEntry, tc.resolved)
			for i := range resolved {
				resolved[i] = UtxoEntry{Value: 19, CovenantType: COV_TYPE_P2PK, CovenantData: []byte{0x51}, CreationHeight: 7, CreatedByCoinbase: true}
				resolvedBefore[i] = resolved[i]
				resolvedBefore[i].CovenantData = append([]byte{}, resolved[i].CovenantData...)
			}
			if tc.nilTx {
				tx = nil
			}
			ctx, err := BuildSimplicityTxContext(tx, resolved, 7, [32]byte{0x42})
			if ctx != nil {
				t.Fatal("shape/no-Simplicity result published a context")
			}
			if tc.message == "" {
				if err != nil {
					t.Fatalf("width-valid no-Simplicity shape: %v", err)
				}
			} else {
				assertInputViewTxError(t, err, "TX_ERR_PARSE", tc.message)
			}
			if (tx != nil && !reflect.DeepEqual(tx.Inputs, inputsBefore)) || !reflect.DeepEqual(resolved, resolvedBefore) {
				t.Fatal("shape guard mutated its input snapshot")
			}
		})
	}
}

func inputViewMixedContext(t *testing.T, private, generic bool) (*nonCoinbaseApplyContext, *inputViewTestView) {
	t.Helper()
	kp := mustMLDSA87Keypair(t)
	ops := []Outpoint{{Txid: hashWithPrefix(0xe0)}, {Txid: hashWithPrefix(0xe1)}, {Txid: hashWithPrefix(0xe2)}}
	pre := map[Outpoint]UtxoEntry{
		ops[0]: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())},
		ops[1]: {Value: 200, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(coreSimplicityAcceptCMR, bytes.Repeat([]byte{0x21}, 512))},
		ops[2]: {Value: 300, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(coreSimplicityAcceptCMR, nil)},
	}
	if generic {
		pre[ops[0]] = UtxoEntry{Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: bytes.Repeat([]byte{0x51}, 65_536)}
	}
	tx := inputViewTx(19, ops...)
	tx.Locktime = 2
	tx.Outputs = append(tx.Outputs,
		TxOutput{Value: 2, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(coreSimplicityAcceptCMR, []byte{0x91, 0x92})},
		TxOutput{Value: 3, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(coreSimplicityAcceptCMR, nil)},
	)
	chainID := [32]byte{0x42}
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp), coreSimplicityAcceptWitness(), coreSimplicityAcceptWitness()}
	ctx := &nonCoinbaseApplyContext{tx: tx, work: cloneUtxoSet(pre), height: 7, blockMTP: 6, chainID: chainID, rotation: activeSimplicityRotation(chainID, 1)}
	view := inputViewNew(pre)
	if private {
		ctx.work = make(map[Outpoint]UtxoEntry)
		ctx.inputView = &blockInputViewState{view: view, height: 7, txIndex: 1, spent: make(map[Outpoint]uint32)}
	}
	return ctx, view
}

func TestConnectBlockInputViewFrozenDescriptorSources(t *testing.T) {
	ctx, view := inputViewMixedContext(t, true, true)
	if err := ctx.applyPreOutputPhases(); err == nil {
		t.Fatal("generic P2PK source must reject at spend time")
	} else {
		assertInputViewTxError(t, err, "TX_ERR_COVENANT_TYPE_INVALID", "CORE_P2PK covenant_data invalid")
	}
	assertInputViewReads(t, view, Outpoint{Txid: hashWithPrefix(0xe0)}, Outpoint{Txid: hashWithPrefix(0xe1)}, Outpoint{Txid: hashWithPrefix(0xe2)})
	sim := ctx.simplicityCtx
	if sim == nil {
		t.Fatal("ACTIVE eager context absent before lower-index spend rejection")
	}
	for i, resolved := range ctx.resolved {
		data := sim.inputDescriptors[i].covenantData
		if len(data) != len(resolved.entry.CovenantData) || &data[0] != &resolved.entry.CovenantData[0] || !bytes.Equal(data, resolved.entry.CovenantData) {
			t.Fatalf("input%d descriptor does not share complete frozen source", i)
		}
	}
	for i, out := range ctx.tx.Outputs {
		data := sim.outputDescriptors[i].covenantData
		if len(data) != len(out.CovenantData) || &data[0] != &out.CovenantData[0] || !bytes.Equal(data, out.CovenantData) {
			t.Fatalf("output%d descriptor does not share complete frozen source", i)
		}
	}
	inputViewAssertContextValues(t, sim)
	inputViewAssertDescriptorAccess(t, sim, ctx.resolved[0].entry.CovenantData, ctx.tx.Outputs[0].CovenantData)
	if &sim.selfSources[1].state[0] == &ctx.resolved[1].entry.CovenantData[35] || &sim.groupOutputs[coreSimplicityAcceptCMR][0].State[0] == &ctx.tx.Outputs[1].CovenantData[33] {
		t.Fatal("required prefix-stripped states borrowed descriptor backing")
	}
	// A fresh frozen context with a different scalar output value has the same
	// descriptor hash. No admitted frozen source is mutated for this control.
	otherCtx, _ := inputViewMixedContext(t, true, true)
	otherCtx.tx.Outputs[0].Value = 9
	assertInputViewTxError(t, otherCtx.applyPreOutputPhases(), "TX_ERR_COVENANT_TYPE_INVALID", "CORE_P2PK covenant_data invalid")
	var meter0, meter1 SimplicityTxContextMeter
	a, err0 := sim.OutputDescriptorHash(0, &meter0)
	b, err1 := otherCtx.simplicityCtx.OutputDescriptorHash(0, &meter1)
	if err0 != nil || err1 != nil || a != b || meter0.Cost() != meter1.Cost() || otherCtx.simplicityCtx.Base.TotalOut != (Uint128{Lo: 14}) {
		t.Fatalf("output value affected descriptor: %#v/%#v %v/%v", a, b, err0, err1)
	}
}

func inputViewAssertContextValues(t *testing.T, ctx *SimplicityTxContext) {
	t.Helper()
	want := SimplicityTxContextBase{ChainID: [32]byte{0x42}, TotalIn: Uint128{Lo: 600}, TotalOut: Uint128{Lo: 6}, Height: 7, TxNonce: 19, Locktime: 2, InputCount: 3, OutputCount: 3, TxKind: 0}
	if ctx.Base != want {
		t.Fatalf("base=%#v, want %#v", ctx.Base, want)
	}
	wantInputs := []SimplicityTxContextIOView{{Value: 100, CovenantType: 0}, {Value: 200, CovenantType: 0x0106}, {Value: 300, CovenantType: 0x0106}}
	wantOutputs := []SimplicityTxContextIOView{{Value: 1, CovenantType: 0}, {Value: 2, CovenantType: 0x0106}, {Value: 3, CovenantType: 0x0106}}
	if !reflect.DeepEqual(ctx.InputViews(), wantInputs) || !reflect.DeepEqual(ctx.OutputViews(), wantOutputs) {
		t.Fatalf("IO scalar copies=%#v/%#v", ctx.InputViews(), ctx.OutputViews())
	}
	self, err := ctx.SelfView(1, 1, [32]byte{0x61})
	wantSelf := SimplicityTxContextSelfView{SelfProgramCMR: coreSimplicityAcceptCMR, Digest32: [32]byte{0x61}, SelfState: bytes.Repeat([]byte{0x21}, 512), SelfValue: 200, InputIndex: 1, SighashType: 1}
	if err != nil || !reflect.DeepEqual(self, wantSelf) {
		t.Fatalf("self=%#v/%v, want %#v", self, err, wantSelf)
	}
	group, err := ctx.SameCMRView(2)
	wantGroup := SimplicityTxContextSameCMRView{
		ProgramCMR: coreSimplicityAcceptCMR,
		Inputs:     []SimplicityTxContextGroupEntry{{Value: 200, State: bytes.Repeat([]byte{0x21}, 512)}, {Value: 300, State: []byte{}}},
		Outputs:    []SimplicityTxContextGroupEntry{{Value: 2, State: []byte{0x91, 0x92}}, {Value: 3, State: []byte{}}},
	}
	if err != nil || !reflect.DeepEqual(group, wantGroup) {
		t.Fatalf("group/order=%#v/%v, want %#v", group, err, wantGroup)
	}
	self.SelfState[0], group.Inputs[0].State[0], group.Outputs[0].State[0] = 0, 0, 0
	inputs, outputs := ctx.InputViews(), ctx.OutputViews()
	inputs[0].Value, outputs[0].Value = 0, 0
	again, err := ctx.SameCMRView(2)
	if err != nil || !reflect.DeepEqual(again, wantGroup) || !reflect.DeepEqual(ctx.InputViews(), wantInputs) || !reflect.DeepEqual(ctx.OutputViews(), wantOutputs) {
		t.Fatal("accessor returned mutable context-owned state or scalars")
	}
	empty, err := ctx.SelfView(2, 1, [32]byte{})
	if err != nil || empty.SelfState == nil || len(empty.SelfState) != 0 || empty.SelfValue != 300 || empty.InputIndex != 2 {
		t.Fatalf("empty self state/index=%#v/%v", empty, err)
	}
}

func inputViewAssertDescriptorAccess(t *testing.T, ctx *SimplicityTxContext, inputData, outputData []byte) {
	t.Helper()
	// Literal CSM-DESC framing, independent of OutputDescriptorBytes:
	// ordinary type0 and CompactSize(65,536)=fe00000100; output data33.
	inputDescriptor := append([]byte{0, 0, 0xfe, 0, 0, 1, 0}, inputData...)
	outputDescriptor := append([]byte{0, 0, 33}, outputData...)
	var meter SimplicityTxContextMeter
	for repeat := uint64(1); repeat <= 2; repeat++ {
		got, err := ctx.InputDescriptorHash(0, &meter)
		if err != nil || !got.Present || got.Hash != sha3_256(inputDescriptor) || meter.Cost() != repeat*(64+65_543) {
			t.Fatalf("full input hash/repeat charge=%#v/%v/%d", got, err, meter.Cost())
		}
	}
	for repeat := uint64(1); repeat <= 2; repeat++ {
		got, err := ctx.OutputDescriptorHash(0, &meter)
		if err != nil || !got.Present || got.Hash != sha3_256(outputDescriptor) || meter.Cost() != 2*(64+65_543)+repeat*(64+36) {
			t.Fatalf("output hash/repeat charge=%#v/%v/%d", got, err, meter.Cost())
		}
	}
	inputState := append([]byte{6, 1, 0xfd, 0x23, 2}, coreSimplicityAcceptCMR[:]...)
	inputState = append(inputState, 0xfd, 0, 2)
	inputState = append(inputState, bytes.Repeat([]byte{0x21}, 512)...)
	emptyState := append([]byte{6, 1, 33}, coreSimplicityAcceptCMR[:]...)
	emptyState = append(emptyState, 0)
	outputState := append([]byte{6, 1, 35}, coreSimplicityAcceptCMR[:]...)
	outputState = append(outputState, 2, 0x91, 0x92)
	for _, tc := range []struct {
		name       string
		inputSide  bool
		index      uint16
		descriptor []byte
		cost       uint64
	}{
		{"input_state512", true, 1, inputState, 616},
		{"input_empty", true, 2, emptyState, 100},
		{"output_state2", false, 1, outputState, 102},
		{"output_empty", false, 2, emptyState, 100},
	} {
		for repeat := 0; repeat < 2; repeat++ {
			before := meter.Cost()
			var got SimplicityTxContextDescriptorHashResult
			var err error
			if tc.inputSide {
				got, err = ctx.InputDescriptorHash(tc.index, &meter)
			} else {
				got, err = ctx.OutputDescriptorHash(tc.index, &meter)
			}
			if err != nil || !got.Present || got.Hash != sha3_256(tc.descriptor) || meter.Cost() != before+tc.cost {
				t.Fatalf("%s repeat%d hash/cost=%#v/%v/%d", tc.name, repeat, got, err, meter.Cost())
			}
		}
	}
	before := meter.Cost()
	for _, inputSide := range []bool{true, false} {
		var got SimplicityTxContextDescriptorHashResult
		var err error
		if inputSide {
			got, err = ctx.InputDescriptorHash(3, &meter)
		} else {
			got, err = ctx.OutputDescriptorHash(3, &meter)
		}
		before++
		if err != nil || got != (SimplicityTxContextDescriptorHashResult{}) || meter.Cost() != before {
			t.Fatalf("miss/hash/cost=%#v/%v/%d, want zero/%d", got, err, meter.Cost(), before)
		}
	}
	program, err := simplicity.Decode([]byte{0xe8, 0x22, 0}, nil, simplicity.DecodeOptions{SemanticsVersion: simplicity.SemanticsVersion})
	if err != nil {
		t.Fatal(err)
	}
	var intrinsicMeter SimplicityTxContextMeter
	result, err := program.Evaluate(simplicity.EvalOptions{
		Host: testSimplicityEvalHost{ctx: ctx, meter: &intrinsicMeter}, ContextIndex: 0,
		ContextEvaluator: func(in simplicity.ContextIntrinsic, value simplicity.IntrinsicResult) bool { return in.ID == 0x0122 && value.Value.Bytes32 == sha3_256(inputDescriptor) },
	})
	if err != nil || !result.Accepted || result.Cost != 65_607 || intrinsicMeter.Cost() != 65_607 {
		t.Fatalf("private intrinsic hash/cost=%#v/%v/%d", result, err, intrinsicMeter.Cost())
	}
}

func TestConnectBlockInputViewNilInputViewContextCopies(t *testing.T) {
	ctx, view := inputViewMixedContext(t, false, false)
	if err := ctx.applyPreOutputPhases(); err != nil {
		t.Fatalf("actual nil-inputView pre-output route: %v", err)
	}
	assertInputViewReads(t, view)
	inputData := append([]byte(nil), ctx.resolved[0].entry.CovenantData...)
	outputData := append([]byte(nil), ctx.tx.Outputs[0].CovenantData...)
	wantInput := sha3_256(append([]byte{0, 0, 33}, inputData...))
	wantOutput := sha3_256(append([]byte{0, 0, 33}, outputData...))
	// This legacy route permits the caller's own post-preparation mutation.
	ctx.resolved[0].entry.CovenantData[1] ^= 1
	ctx.tx.Outputs[0].CovenantData[1] ^= 1
	var meter SimplicityTxContextMeter
	input, inputErr := ctx.simplicityCtx.InputDescriptorHash(0, &meter)
	output, outputErr := ctx.simplicityCtx.OutputDescriptorHash(0, &meter)
	if inputErr != nil || outputErr != nil || !input.Present || !output.Present || input.Hash != wantInput || output.Hash != wantOutput || meter.Cost() != 200 {
		t.Fatalf("nil-inputView copied descriptors=%#v/%#v %v/%v cost%d", input, output, inputErr, outputErr, meter.Cost())
	}
}

func TestConnectBlockInputViewActiveSimplicitySource(t *testing.T) {
	tx, _, pre := simplicityLiveTx(1, simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL))
	op := Outpoint{Txid: tx.Inputs[0].PrevTxid, Vout: tx.Inputs[0].PrevVout}
	pre[op] = UtxoEntry{Value: 100, CovenantType: COV_TYPE_CORE_SIMPLICITY, CovenantData: makeCoreSimplicityCovenantData(coreSimplicityAcceptCMR, bytes.Repeat([]byte{0x77}, 512))}
	input := inputViewBlock(t, 1, 1, tx)
	input.Rotation = activeSimplicityRotation([32]byte{}, 1)
	view := inputViewNew(pre)
	result, err := inputViewConnect(t, input, view, Uint128{})
	if err != nil {
		t.Fatal(err)
	}
	rows := assertInputViewResult(t, input, pre, Uint128{}, result)
	want := []blockSpentInput{{outpoint: op, txIndex: 1, inputIndex: 0, logicalEntryLength: 605}}
	if !reflect.DeepEqual(rows, want) || rows[0].logicalEntryLength-36 != 569 || result.sumFees != (Uint128{Lo: 99}) {
		t.Fatalf("ACTIVE creation-valid metadata=%#v, want %#v", rows, want)
	}
	assertInputViewReads(t, view, op)
}

func TestConnectBlockInputViewPrivateSimplicityGate(t *testing.T) {
	tx, _, pre := simplicityLiveTx(9, simplicityEnvelopeSignature([]byte{0x24}, nil, SIGHASH_ALL))
	op := Outpoint{Txid: hashWithPrefix(0xf1)}
	pre[op] = UtxoEntry{Value: 1, CovenantType: COV_TYPE_P2PK, CovenantData: validP2PKCovenantData()}
	tx.Inputs = append([]TxInput{{PrevTxid: op.Txid, PrevVout: op.Vout}}, tx.Inputs...)
	tx.Witness = append([]WitnessItem{{SuiteID: 1, Pubkey: make([]byte, 2_592), Signature: make([]byte, 4_628)}}, tx.Witness...)
	reads := make([]Outpoint, 0, len(tx.Inputs))
	for _, in := range tx.Inputs {
		reads = append(reads, Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout})
	}
	for _, tc := range []struct {
		name, message string
		rotation      RotationProvider
	}{
		{"active_cap", "CORE_SIMPLICITY same-cmr input group exceeds limit", activeSimplicityRotation([32]byte{}, 1)},
		{"inactive_before_cap", "CORE_SIMPLICITY deployment not active", activeSimplicityRotation([32]byte{}, 2)},
		{"no_active_before_cap", "CORE_SIMPLICITY deployment not active", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := inputViewBlock(t, 1, 1, tx)
			input.Rotation = tc.rotation
			view := inputViewNew(pre)
			_, err := inputViewConnect(t, input, view, Uint128{})
			assertInputViewTxError(t, err, "TX_ERR_COVENANT_TYPE_INVALID", tc.message)
			assertInputViewReads(t, view, reads...)
		})
	}
}

func TestConnectBlockInputViewNoSimplicityContext(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	op := Outpoint{Txid: hashWithPrefix(0xf2)}
	pre := map[Outpoint]UtxoEntry{op: {Value: 100, CovenantType: COV_TYPE_P2PK, CovenantData: p2pkCovenantDataForPubkey(kp.PubkeyBytes())}}
	view := inputViewNew(pre)
	ctx := nonCoinbaseApplyContext{
		tx: inputViewSignedTx(t, 1, pre, kp, op), work: make(map[Outpoint]UtxoEntry), height: 1,
		inputView: &blockInputViewState{view: view, height: 1, txIndex: 1, spent: make(map[Outpoint]uint32)},
	}
	if err := ctx.applyPreOutputPhases(); err != nil || ctx.simplicityCtx != nil {
		t.Fatalf("no-Simplicity pre-output context=%#v/%v", ctx.simplicityCtx, err)
	}
	assertInputViewReads(t, view, op)
}

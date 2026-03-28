package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func cloneChainStateForDisconnectFuzz(src *ChainState) *ChainState {
	if src == nil {
		return nil
	}
	utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(src.Utxos))
	for op, entry := range src.Utxos {
		utxos[op] = copyUtxoEntry(entry)
	}
	out := &ChainState{
		Utxos:            utxos,
		Height:           src.Height,
		AlreadyGenerated: src.AlreadyGenerated,
		TipHash:          src.TipHash,
		HasTip:           src.HasTip,
		Rotation:         src.Rotation,
		Registry:         src.Registry,
	}
	return out
}

func buildSignedTransferTxForDisconnectFuzz(
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	inputs []consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	toAddress []byte,
) ([]byte, error) {
	txInputs := make([]consensus.TxInput, 0, len(inputs))
	var totalIn uint64
	for _, op := range inputs {
		entry, ok := utxos[op]
		if !ok {
			return nil, errors.New("missing utxo")
		}
		totalIn += entry.Value
		txInputs = append(txInputs, consensus.TxInput{
			PrevTxid: op.Txid,
			PrevVout: op.Vout,
			Sequence: 0,
		})
	}

	change := totalIn - amount - fee
	outputs := []consensus.TxOutput{{
		Value:        amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), toAddress...),
	}}
	if change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), changeAddress...),
		})
	}

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  nonce,
		Inputs:   txInputs,
		Outputs:  outputs,
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		return nil, err
	}
	return consensus.MarshalTx(tx)
}

func buildMultiTxBlockForDisconnectFuzz(prevHash [32]byte, target [32]byte, timestamp uint64, txs ...[]byte) ([]byte, error) {
	txids := make([][32]byte, 0, len(txs))
	totalLen := consensus.BLOCK_HEADER_BYTES + 8
	for _, txBytes := range txs {
		_, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			return nil, err
		}
		txids = append(txids, txid)
		totalLen += len(txBytes)
	}
	root, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
	header = consensus.AppendU32le(header, 1)
	header = append(header, prevHash[:]...)
	header = append(header, root[:]...)
	header = consensus.AppendU64le(header, timestamp)
	header = append(header, target[:]...)
	header = consensus.AppendU64le(header, 7)

	block := make([]byte, 0, totalLen)
	block = append(block, header...)
	block = consensus.AppendCompactSize(block, uint64(len(txs)))
	for _, txBytes := range txs {
		block = append(block, txBytes...)
	}
	return block, nil
}

func coinbaseWithWitnessCommitmentForDisconnectFuzz(height uint64, value uint64, wtxids [][32]byte) ([]byte, error) {
	wroot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		return nil, err
	}
	commitment := consensus.WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: value, covenantType: consensus.COV_TYPE_P2PK, covenantData: testP2PKCovenantData(0x11)},
		{value: 0, covenantType: consensus.COV_TYPE_ANCHOR, covenantData: commitment[:]},
	}), nil
}

func mustDisconnectFuzzFixture(tb testing.TB) ([]byte, []byte, *ChainState, *ChainState) {
	tb.Helper()

	signer, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			tb.Skipf("ML-DSA backend unavailable: %v", err)
		}
		tb.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	defer signer.Close()

	keyID := sha3.Sum256(signer.PubkeyBytes())
	fromAddr, err := ParseMineAddress(hex.EncodeToString(keyID[:]))
	if err != nil {
		tb.Fatalf("ParseMineAddress: %v", err)
	}

	prevState, ops := testSpendableChainState(fromAddr, []uint64{100})
	preDisconnectState := cloneChainStateForDisconnectFuzz(prevState)
	target := consensus.POW_LIMIT
	height := prevState.Height + 1

	spendTx, err := buildSignedTransferTxForDisconnectFuzz(prevState.Utxos, []consensus.Outpoint{ops[0]}, 90, 1, 1, signer, fromAddr, fromAddr)
	if err != nil {
		tb.Fatalf("buildSignedTransferTx: %v", err)
	}
	_, _, spendWTxID, _, err := consensus.ParseTx(spendTx)
	if err != nil {
		tb.Fatalf("ParseTx(spend): %v", err)
	}

	subsidy := consensus.BlockSubsidy(height, prevState.AlreadyGenerated)
	coinbase, err := coinbaseWithWitnessCommitmentForDisconnectFuzz(height, subsidy, [][32]byte{{}, spendWTxID})
	if err != nil {
		tb.Fatalf("coinbaseWithWitnessCommitment: %v", err)
	}
	blockBytes, err := buildMultiTxBlockForDisconnectFuzz(prevState.TipHash, target, 2, coinbase, spendTx)
	if err != nil {
		tb.Fatalf("buildMultiTxBlock: %v", err)
	}

	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		tb.Fatalf("ParseBlockBytes: %v", err)
	}
	undo, err := buildBlockUndo(preDisconnectState, pb, height)
	if err != nil {
		tb.Fatalf("buildBlockUndo: %v", err)
	}
	rawUndo, err := marshalBlockUndo(undo)
	if err != nil {
		tb.Fatalf("marshalBlockUndo: %v", err)
	}

	postDisconnectState := cloneChainStateForDisconnectFuzz(preDisconnectState)
	if _, err := postDisconnectState.ConnectBlock(blockBytes, &target, nil, devnetGenesisChainID); err != nil {
		tb.Fatalf("ConnectBlock: %v", err)
	}

	return blockBytes, rawUndo, postDisconnectState, preDisconnectState
}

func FuzzDisconnectBlock(f *testing.F) {
	blockSeed, undoSeed, postStateSeed, preStateSeed := mustDisconnectFuzzFixture(f)
	f.Add(blockSeed, undoSeed)
	f.Add([]byte{0x01, 0x02}, undoSeed)

	f.Fuzz(func(t *testing.T, blockBytes []byte, rawUndo []byte) {
		if len(blockBytes) > 2<<20 || len(rawUndo) > 1<<20 {
			return
		}
		undo, err := unmarshalBlockUndo(rawUndo)
		if err != nil {
			return
		}

		st1 := cloneChainStateForDisconnectFuzz(postStateSeed)
		st2 := cloneChainStateForDisconnectFuzz(postStateSeed)
		beforeHash := consensus.UtxoSetHash(postStateSeed.Utxos)
		beforeHeight := postStateSeed.Height
		beforeTip := postStateSeed.TipHash
		beforeAlreadyGenerated := postStateSeed.AlreadyGenerated
		beforeHasTip := postStateSeed.HasTip

		summary1, err1 := st1.DisconnectBlock(blockBytes, undo)
		summary2, err2 := st2.DisconnectBlock(blockBytes, undo)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("DisconnectBlock error presence mismatch: %v vs %v", err1, err2)
		}
		if err1 != nil {
			if err1.Error() != err2.Error() {
				t.Fatalf("DisconnectBlock error text mismatch: %q vs %q", err1, err2)
			}
			if consensus.UtxoSetHash(st1.Utxos) != beforeHash || consensus.UtxoSetHash(st2.Utxos) != beforeHash {
				t.Fatalf("DisconnectBlock mutated state on error")
			}
			if st1.Height != beforeHeight || st2.Height != beforeHeight {
				t.Fatalf("DisconnectBlock changed height on error")
			}
			if st1.TipHash != beforeTip || st2.TipHash != beforeTip {
				t.Fatalf("DisconnectBlock changed tip on error")
			}
			if st1.AlreadyGenerated != beforeAlreadyGenerated || st2.AlreadyGenerated != beforeAlreadyGenerated {
				t.Fatalf("DisconnectBlock changed already_generated on error")
			}
			if st1.HasTip != beforeHasTip || st2.HasTip != beforeHasTip {
				t.Fatalf("DisconnectBlock changed has_tip on error")
			}
			return
		}

		if !reflect.DeepEqual(summary1, summary2) {
			t.Fatalf("DisconnectBlock summary mismatch: %+v vs %+v", summary1, summary2)
		}
		if consensus.UtxoSetHash(st1.Utxos) != consensus.UtxoSetHash(st2.Utxos) {
			t.Fatalf("DisconnectBlock final state digest mismatch")
		}

		if bytes.Equal(blockBytes, blockSeed) && bytes.Equal(rawUndo, undoSeed) {
			if consensus.UtxoSetHash(st1.Utxos) != consensus.UtxoSetHash(preStateSeed.Utxos) {
				t.Fatalf("valid disconnect did not restore pre-state digest")
			}
			if st1.Height != preStateSeed.Height || st1.TipHash != preStateSeed.TipHash || st1.HasTip != preStateSeed.HasTip {
				t.Fatalf("valid disconnect did not restore chainstate tip metadata")
			}
		}
	})
}

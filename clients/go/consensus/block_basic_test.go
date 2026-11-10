package consensus

import "testing"

func parseStoredCommitmentTestBlock(t *testing.T, txs ...[]byte) *ParsedBlock {
	t.Helper()
	if len(txs) == 0 {
		t.Fatal("test block needs a coinbase")
	}
	txids := make([][32]byte, 0, len(txs))
	for _, tx := range txs {
		txids = append(txids, testTxID(t, tx))
	}
	root, err := MerkleRootTxids(txids)
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block := buildBlockBytes(t, hashWithPrefix(0x51), root, filledHash(0xff), 1, txs)
	pb, err := ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes: %v", err)
	}
	return pb
}

// requireStoredCommitmentError observes the exact direct *TxError, its code, message and unspecified cause.
func requireStoredCommitmentError(t *testing.T, label string, pb *ParsedBlock, code ErrorCode, msg string) {
	t.Helper()
	initial148BlockWantError(t, "binding stored "+label, ValidateStoredBlockCommitments(pb), code, msg)
}

func TestValidateStoredBlockCommitments(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
		if err := ValidateStoredBlockCommitments(pb); err != nil {
			t.Fatalf("ValidateStoredBlockCommitments(valid): %v", err)
		}
	})

	t.Run("nil", func(t *testing.T) {
		requireStoredCommitmentError(t, "nil parsed", nil, BLOCK_ERR_PARSE, "nil parsed block")
	})

	t.Run("position-zero pins follow commitments", func(t *testing.T) {
		for _, c := range []struct {
			name   string
			mutate func(*ParsedBlock)
		}{
			{"witness pin", func(pb *ParsedBlock) { pb.Txs[0].Witness = []WitnessItem{{}} }},
			{"payload pin", func(pb *ParsedBlock) { pb.Txs[0].DaPayload = []byte{0x01} }},
		} {
			pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
			c.mutate(pb)
			requireStoredCommitmentError(t, c.name, pb, BLOCK_ERR_COINBASE_INVALID, bindingPinMsg)
			pb.Txids[0][0] ^= 0xff // The Merkle check precedes both pins in binding order.
			requireStoredCommitmentError(t, c.name+" behind merkle", pb, BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch")
		}
	})

	t.Run("absent or nil first transaction", func(t *testing.T) {
		pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
		pb.Txs[0] = nil
		requireStoredCommitmentError(t, "nil first", pb, BLOCK_ERR_COINBASE_INVALID, bindingPinMsg)
		pb.Txs = nil
		requireStoredCommitmentError(t, "absent first", pb, BLOCK_ERR_COINBASE_INVALID, bindingPinMsg)
		// Both guards precede the txid-root comparison: a wrong root does not change their refusal.
		wrong := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
		wrong.Header.MerkleRoot[0] ^= 0xff
		wrong.Txs[0] = nil
		requireStoredCommitmentError(t, "nil first before root", wrong, BLOCK_ERR_COINBASE_INVALID, bindingPinMsg)
		wrong.Txs = nil
		requireStoredCommitmentError(t, "absent first before root", wrong, BLOCK_ERR_COINBASE_INVALID, bindingPinMsg)
	})

	t.Run("txid Merkle mismatch", func(t *testing.T) {
		pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
		pb.Txids[0][0] ^= 0xff
		pb.Wtxids[0][0] ^= 0xff
		requireStoredCommitmentError(t, "txid mismatch", pb, BLOCK_ERR_MERKLE_INVALID, "merkle_root mismatch")
	})

	t.Run("witness-only mismatch", func(t *testing.T) {
		spend := txWithOneOutput(1, COV_TYPE_P2PK, validP2PKCovenantData())
		pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t, spend), spend)
		pb.Wtxids[1][0] ^= 0xff
		requireStoredCommitmentError(t, "witness-only mismatch", pb, BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg)
	})

	wroot, err := WitnessMerkleRootWtxids([][32]byte{{}})
	if err != nil {
		t.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commitment := WitnessCommitmentHash(wroot)
	t.Run("missing witness commitment", func(t *testing.T) {
		coinbase := coinbaseTxWithOutputs(0, []testOutput{{
			value: 1, covenantType: COV_TYPE_P2PK, covenantData: validP2PKCovenantData(),
		}})
		requireStoredCommitmentError(t, "missing commitment", parseStoredCommitmentTestBlock(t, coinbase), BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg)
	})
	t.Run("duplicated witness commitment", func(t *testing.T) {
		coinbase := coinbaseTxWithOutputs(0, []testOutput{
			{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commitment[:]},
			{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commitment[:]},
		})
		requireStoredCommitmentError(t, "duplicated commitment", parseStoredCommitmentTestBlock(t, coinbase), BLOCK_ERR_WITNESS_COMMITMENT, bindingWitnessMsg)
	})
}

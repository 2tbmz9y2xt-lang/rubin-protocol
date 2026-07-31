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

func requireStoredCommitmentError(t *testing.T, pb *ParsedBlock, want ErrorCode) {
	t.Helper()
	err := ValidateStoredBlockCommitments(pb)
	if err == nil {
		t.Fatal("ValidateStoredBlockCommitments unexpectedly succeeded")
	}
	if got := mustTxErrCode(t, err); got != want {
		t.Fatalf("code=%s, want %s (err=%v)", got, want, err)
	}
}

func TestValidateStoredBlockCommitments(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
		if err := ValidateStoredBlockCommitments(pb); err != nil {
			t.Fatalf("ValidateStoredBlockCommitments(valid): %v", err)
		}
	})

	t.Run("nil", func(t *testing.T) {
		requireStoredCommitmentError(t, nil, BLOCK_ERR_PARSE)
	})

	t.Run("coinbase witness or DA slot precedes commitments", func(t *testing.T) {
		for _, mutate := range []func(*ParsedBlock){
			func(pb *ParsedBlock) { pb.Txs[0].Witness = []WitnessItem{{}} },
			func(pb *ParsedBlock) { pb.Txs[0].DaPayload = []byte{0x01} },
		} {
			pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
			pb.Txids[0][0] ^= 0xff // Coinbases must reject before the later Merkle check.
			mutate(pb)
			requireStoredCommitmentError(t, pb, BLOCK_ERR_COINBASE_INVALID)
		}
	})

	t.Run("txid Merkle mismatch", func(t *testing.T) {
		pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t))
		pb.Txids[0][0] ^= 0xff
		requireStoredCommitmentError(t, pb, BLOCK_ERR_MERKLE_INVALID)
	})

	t.Run("witness-only mismatch", func(t *testing.T) {
		spend := txWithOneOutput(1, COV_TYPE_P2PK, validP2PKCovenantData())
		pb := parseStoredCommitmentTestBlock(t, coinbaseWithWitnessCommitment(t, spend), spend)
		pb.Wtxids[1][0] ^= 0xff
		requireStoredCommitmentError(t, pb, BLOCK_ERR_WITNESS_COMMITMENT)
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
		requireStoredCommitmentError(t, parseStoredCommitmentTestBlock(t, coinbase), BLOCK_ERR_WITNESS_COMMITMENT)
	})
	t.Run("duplicated witness commitment", func(t *testing.T) {
		coinbase := coinbaseTxWithOutputs(0, []testOutput{
			{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commitment[:]},
			{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commitment[:]},
		})
		requireStoredCommitmentError(t, parseStoredCommitmentTestBlock(t, coinbase), BLOCK_ERR_WITNESS_COMMITMENT)
	})
}

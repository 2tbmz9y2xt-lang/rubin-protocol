package consensus

import "testing"

func TestCoverageResidual4_StealthInvalidSighashType(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0x71

	kp := mustMLDSA87Keypair(t)
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, p2pkCovenantDataForPubkey(kp.PubkeyBytes()))
	tx, _ := mustParseTxForUtxo(t, txBytes)
	validWitness := signP2PKInputWitness(t, tx, 0, 100, chainID, kp)
	validWitness.Signature[len(validWitness.Signature)-1] = 0x7f

	entry := UtxoEntry{
		Value:        100,
		CovenantType: COV_TYPE_CORE_STEALTH,
		CovenantData: stealthCovenantDataForKeyID(sha3_256(validWitness.Pubkey)),
	}
	err := validateCoreStealthSpend(entry, validWitness, tx, 0, 100, chainID, 200)
	if err == nil {
		t.Fatalf("expected invalid sighash rejection")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIGHASH_TYPE_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIGHASH_TYPE_INVALID)
	}
}

func TestCoverageResidual4_ParseTxAdditionalBranches(t *testing.T) {
	t.Run("standard_tx_rejects_da_payload", func(t *testing.T) {
		bad := append([]byte(nil), minimalTxBytes()...)
		bad[len(bad)-1] = 0x01
		if _, _, _, _, err := ParseTx(bad); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
			t.Fatalf("expected tx_kind=0 da_payload_len rejection, got %v", err)
		}
	})

	t.Run("da_chunk_index_out_of_range", func(t *testing.T) {
		tx := make([]byte, 0, 4+1+8+1+1+4+32+2+32+1+2)
		tx = AppendU32le(tx, 1)
		tx = append(tx, 0x02)
		tx = AppendU64le(tx, 1)
		tx = AppendCompactSize(tx, 0)
		tx = AppendCompactSize(tx, 0)
		tx = AppendU32le(tx, 0)
		tx = append(tx, make([]byte, 32)...)
		tx = AppendU16le(tx, uint16(MAX_DA_CHUNK_COUNT))
		tx = append(tx, make([]byte, 32)...)
		tx = AppendCompactSize(tx, 0)
		tx = AppendCompactSize(tx, 1)
		tx = append(tx, 0x00)
		if _, _, _, _, err := ParseTx(tx); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
			t.Fatalf("expected chunk_index rejection, got %v", err)
		}
	})

	t.Run("da_chunk_requires_payload", func(t *testing.T) {
		tx := make([]byte, 0, 4+1+8+1+1+4+32+2+32+1+1)
		tx = AppendU32le(tx, 1)
		tx = append(tx, 0x02)
		tx = AppendU64le(tx, 1)
		tx = AppendCompactSize(tx, 0)
		tx = AppendCompactSize(tx, 0)
		tx = AppendU32le(tx, 0)
		tx = append(tx, make([]byte, 32)...)
		tx = AppendU16le(tx, 0)
		tx = append(tx, make([]byte, 32)...)
		tx = AppendCompactSize(tx, 0)
		tx = AppendCompactSize(tx, 0)
		if _, _, _, _, err := ParseTx(tx); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
			t.Fatalf("expected da chunk payload rejection, got %v", err)
		}
	})

	t.Run("da_commit_payload_limit", func(t *testing.T) {
		tx := make([]byte, 0, 4+1+8+1+1+4+32+2+32+8+32+32+32+1+1+1)
		tx = AppendU32le(tx, 1)
		tx = append(tx, 0x01)
		tx = AppendU64le(tx, 1)
		tx = AppendCompactSize(tx, 0)
		tx = AppendCompactSize(tx, 0)
		tx = AppendU32le(tx, 0)
		tx = append(tx, make([]byte, 32)...)
		tx = AppendU16le(tx, 1)
		tx = append(tx, make([]byte, 32)...)
		tx = AppendU64le(tx, 0)
		tx = append(tx, make([]byte, 32)...)
		tx = append(tx, make([]byte, 32)...)
		tx = append(tx, make([]byte, 32)...)
		tx = append(tx, 0x00)
		tx = AppendCompactSize(tx, 0)
		tx = AppendCompactSize(tx, 0)
		tx = append(tx, 0xfe)
		tx = AppendU32le(tx, uint32(MAX_DA_MANIFEST_BYTES_PER_TX+1))
		if _, _, _, _, err := ParseTx(tx); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
			t.Fatalf("expected da commit payload limit rejection, got %v", err)
		}
	})

	t.Run("da_commit_and_chunk_roundtrip", func(t *testing.T) {
		commitTx := &Tx{
			Version:  1,
			TxKind:   0x01,
			TxNonce:  7,
			Locktime: 9,
			DaCommitCore: &DaCommitCore{
				ChunkCount:    2,
				BatchNumber:   11,
				BatchSigSuite: 0x03,
				BatchSig:      []byte{0xaa, 0xbb},
			},
			DaPayload: []byte{0x10, 0x20},
		}
		commitBytes, err := MarshalTx(commitTx)
		if err != nil {
			t.Fatalf("MarshalTx(commit): %v", err)
		}
		parsedCommit, _, _, _, err := ParseTx(commitBytes)
		if err != nil {
			t.Fatalf("ParseTx(commit): %v", err)
		}
		if parsedCommit.DaCommitCore == nil || parsedCommit.DaCommitCore.ChunkCount != 2 {
			t.Fatalf("unexpected da commit core: %+v", parsedCommit.DaCommitCore)
		}
		if len(parsedCommit.DaPayload) != 2 {
			t.Fatalf("unexpected commit payload len: %d", len(parsedCommit.DaPayload))
		}

		chunkTx := &Tx{
			Version: 1,
			TxKind:  0x02,
			TxNonce: 8,
			DaChunkCore: &DaChunkCore{
				ChunkIndex: 1,
			},
			DaPayload: []byte{0x99},
		}
		chunkBytes, err := MarshalTx(chunkTx)
		if err != nil {
			t.Fatalf("MarshalTx(chunk): %v", err)
		}
		parsedChunk, _, _, _, err := ParseTx(chunkBytes)
		if err != nil {
			t.Fatalf("ParseTx(chunk): %v", err)
		}
		if parsedChunk.DaChunkCore == nil || parsedChunk.DaChunkCore.ChunkIndex != 1 {
			t.Fatalf("unexpected da chunk core: %+v", parsedChunk.DaChunkCore)
		}
		if len(parsedChunk.DaPayload) != 1 || parsedChunk.DaPayload[0] != 0x99 {
			t.Fatalf("unexpected chunk payload: %x", parsedChunk.DaPayload)
		}
	})
}

func TestCoverageResidual4_U128HelperBranches(t *testing.T) {
	sum, err := addU64ToU128(u128{hi: 1, lo: ^uint64(0)}, 1)
	if err != nil {
		t.Fatalf("addU64ToU128 carry: %v", err)
	}
	if sum.hi != 2 || sum.lo != 0 {
		t.Fatalf("unexpected carried sum: %+v", sum)
	}

	if got := cmpU128(u128{hi: 0, lo: 1}, u128{hi: 1, lo: 0}); got >= 0 {
		t.Fatalf("expected low-high compare to be negative, got %d", got)
	}
	if got := cmpU128(u128{hi: 2, lo: 0}, u128{hi: 1, lo: ^uint64(0)}); got <= 0 {
		t.Fatalf("expected high compare to be positive, got %d", got)
	}
	if got := cmpU128(u128{hi: 1, lo: 9}, u128{hi: 1, lo: 9}); got != 0 {
		t.Fatalf("expected equal compare, got %d", got)
	}

	diff, err := subU128(u128{hi: 1, lo: 5}, u128{hi: 1, lo: 2})
	if err != nil {
		t.Fatalf("subU128: %v", err)
	}
	if diff.hi != 0 || diff.lo != 3 {
		t.Fatalf("unexpected diff: %+v", diff)
	}

	value, err := u128ToU64(u128{lo: 9})
	if err != nil {
		t.Fatalf("u128ToU64: %v", err)
	}
	if value != 9 {
		t.Fatalf("value=%d, want 9", value)
	}

	if _, err := addU64ToU128(u128{hi: ^uint64(0), lo: ^uint64(0)}, 1); err == nil || mustTxErrCode(t, err) != TX_ERR_PARSE {
		t.Fatalf("expected addU64ToU128 overflow, got %v", err)
	}
}

func TestCoverageResidual4_ApplyNonCoinbaseTxBasicWorkStealthSpend(t *testing.T) {
	var chainID [32]byte
	var prev [32]byte
	prev[0] = 0x72

	kp := mustMLDSA87Keypair(t)
	txBytes := txWithOneInputOneOutput(prev, 0, 90, COV_TYPE_P2PK, validP2PKCovenantData())
	tx, txid := mustParseTxForUtxo(t, txBytes)
	tx.Witness = []WitnessItem{signP2PKInputWitness(t, tx, 0, 100, chainID, kp)}

	utxos := map[Outpoint]UtxoEntry{
		{Txid: prev, Vout: 0}: {
			Value:        100,
			CovenantType: COV_TYPE_CORE_STEALTH,
			CovenantData: stealthCovenantDataForKeyID(sha3_256(kp.PubkeyBytes())),
		},
	}
	work, summary, err := ApplyNonCoinbaseTxBasicUpdate(tx, txid, utxos, 200, 0, chainID)
	if err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicUpdate(stealth): %v", err)
	}
	if summary == nil || summary.Fee != 10 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(work) != 1 {
		t.Fatalf("unexpected work size: %d", len(work))
	}
}

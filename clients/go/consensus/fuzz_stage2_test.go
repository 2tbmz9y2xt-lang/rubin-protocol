package consensus

import "testing"

func FuzzValidateTxCovenantsGenesis(f *testing.F) {
	f.Add(minimalTxBytesForFuzz(), uint64(0))

	var prev [32]byte
	prev[0] = 0x42
	f.Add(txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData()), uint64(1))

	f.Fuzz(func(t *testing.T, txBytes []byte, blockHeight uint64) {
		if len(txBytes) > 1<<20 {
			return
		}
		tx, _, _, _, err := ParseTx(txBytes)
		if err != nil {
			return
		}
		_ = ValidateTxCovenantsGenesis(tx, blockHeight)
	})
}

func FuzzVerifySigDeterminism(f *testing.F) {
	kp, err := NewMLDSA87Keypair()
	if err == nil {
		defer kp.Close()

		var digest [32]byte
		digest[0] = 0x11
		digest[31] = 0xEE
		if signature, signErr := kp.SignDigest32(digest); signErr == nil {
			f.Add(uint8(SUITE_ID_ML_DSA_87), kp.PubkeyBytes(), signature, digest[:])
		}
	}

	f.Add(uint8(SUITE_ID_ML_DSA_87), []byte{0x01}, []byte{0x02}, []byte{0x03})

	f.Fuzz(func(t *testing.T, suiteID uint8, pubkey []byte, signature []byte, digest []byte) {
		if len(pubkey) > 8192 || len(signature) > 131072 || len(digest) > 1024 {
			return
		}

		var digest32 [32]byte
		copy(digest32[:], digest)

		ok1, err1 := verifySig(suiteID, pubkey, signature, digest32)
		ok2, err2 := verifySig(suiteID, pubkey, signature, digest32)

		if ok1 != ok2 {
			t.Fatalf("verifySig non-deterministic ok value: first=%v second=%v", ok1, ok2)
		}
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("verifySig non-deterministic error presence: first=%v second=%v", err1, err2)
		}
	})
}

func FuzzRetargetV1Arithmetic(f *testing.F) {
	var targetPowLimit [32]byte
	for i := range targetPowLimit {
		targetPowLimit[i] = 0xff
	}
	f.Add(targetPowLimit[:], uint64(1), uint64(WINDOW_SIZE*TARGET_BLOCK_INTERVAL))
	f.Add([]byte{0xff}, uint64(100), uint64(90))

	f.Fuzz(func(t *testing.T, targetRaw []byte, tsFirst uint64, tsLast uint64) {
		if len(targetRaw) == 0 || len(targetRaw) > 64 {
			return
		}

		var targetOld [32]byte
		copy(targetOld[:], targetRaw)

		out1, err1 := RetargetV1(targetOld, tsFirst, tsLast)
		out2, err2 := RetargetV1(targetOld, tsFirst, tsLast)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("retarget non-deterministic error presence: first=%v second=%v", err1, err2)
		}
		if err1 == nil && out1 != out2 {
			t.Fatalf("retarget non-deterministic output")
		}
	})
}

func FuzzParseTxDAKinds(f *testing.F) {
	daID := filled32(0xA1)
	payload := []byte("rubin-da-fuzz")
	payloadCommitment := sha3_256(payload)
	chunkHash := sha3_256(payload)

	f.Add(daCommitTxBytes(1, daID, 1, payloadCommitment))
	f.Add(daChunkTxBytes(2, daID, 0, chunkHash, payload))

	f.Fuzz(func(t *testing.T, txBytes []byte) {
		if len(txBytes) > (2 << 20) {
			return
		}
		_, _, _, _, _ = ParseTx(txBytes)
	})
}

func FuzzApplyNonCoinbaseTxBasic(f *testing.F) {
	var prev [32]byte
	prev[0] = 0x55
	f.Add(txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData()), uint64(100), uint64(1000), uint64(1000))

	f.Fuzz(func(t *testing.T, txBytes []byte, blockHeight uint64, blockTimestamp uint64, blockMTP uint64) {
		if len(txBytes) > (2 << 20) {
			return
		}
		tx, txid, _, _, err := ParseTx(txBytes)
		if err != nil {
			return
		}
		if tx.TxKind != 0x00 {
			return
		}

		utxoSet := make(map[Outpoint]UtxoEntry, len(tx.Inputs))
		for _, in := range tx.Inputs {
			utxoSet[Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}] = UtxoEntry{
				Value:             100,
				CovenantType:      COV_TYPE_P2PK,
				CovenantData:      validP2PKCovenantData(),
				CreationHeight:    1,
				CreatedByCoinbase: false,
			}
		}

		var chainID [32]byte
		_, _ = ApplyNonCoinbaseTxBasicWithMTP(
			tx,
			txid,
			utxoSet,
			blockHeight,
			blockTimestamp,
			blockMTP,
			chainID,
		)
	})
}

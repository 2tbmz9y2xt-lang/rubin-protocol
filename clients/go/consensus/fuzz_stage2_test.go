package consensus

import (
	"encoding/binary"
	"testing"
)

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

// Fuzz SighashV1Digest: determinism and no-panic for arbitrary parsed
// transactions.  Mirrors Rust fuzz target sighash.rs (CV-SIG).
func FuzzSighashV1Digest(f *testing.F) {
	var prev [32]byte
	prev[0] = 0x01
	txSeed := txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData())
	// Pack: txBytes || inputIndex(LE32) || inputValue(LE64) || chainID(32)
	packed := make([]byte, 0, len(txSeed)+44)
	packed = append(packed, txSeed...)
	packed = AppendU32le(packed, 0)   // inputIndex = 0
	packed = AppendU64le(packed, 100) // inputValue = 100
	var chainSeed [32]byte
	chainSeed[0] = 0xCC
	packed = append(packed, chainSeed[:]...)
	f.Add(packed)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 44+13 || len(data) > (1<<20) {
			return
		}
		txEnd := len(data) - 44
		txBytes := data[:txEnd]
		params := data[txEnd:]

		tx, _, _, _, err := ParseTx(txBytes)
		if err != nil || len(tx.Inputs) == 0 {
			return
		}

		inputIndex := binary.LittleEndian.Uint32(params[0:4]) % uint32(len(tx.Inputs))
		inputValue := binary.LittleEndian.Uint64(params[4:12])
		var chainID [32]byte
		copy(chainID[:], params[12:44])

		r1, e1 := SighashV1Digest(tx, inputIndex, inputValue, chainID)
		r2, e2 := SighashV1Digest(tx, inputIndex, inputValue, chainID)

		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("SighashV1Digest non-deterministic error: %v vs %v", e1, e2)
		}
		if e1 == nil && r1 != r2 {
			t.Fatalf("SighashV1Digest non-deterministic output")
		}
	})
}

// Fuzz ValidateBlockBasic: no-panic and determinism for arbitrary block bytes
// with optional prev_hash/target constraints.  Mirrors Rust
// validate_block_basic.rs (CV-BLOCK-BASIC).
func FuzzValidateBlockBasic(f *testing.F) {
	seed := minimalBlockBytesForFuzz()
	packed := append(seed, make([]byte, 64)...)
	f.Add(packed)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < BLOCK_HEADER_BYTES+1+64 || len(data) > (4<<20) {
			return
		}
		blockEnd := len(data) - 64
		blockBytes := data[:blockEnd]
		params := data[blockEnd:]

		// Path 1: no constraints (nil params).
		r1, e1 := ValidateBlockBasic(blockBytes, nil, nil)
		r2, e2 := ValidateBlockBasic(blockBytes, nil, nil)
		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("ValidateBlockBasic(nil,nil) non-deterministic error")
		}
		_ = r1
		_ = r2

		// Path 2: with prev_hash and target constraints.
		var prevHash [32]byte
		copy(prevHash[:], params[0:32])
		var target [32]byte
		copy(target[:], params[32:64])
		_, _ = ValidateBlockBasic(blockBytes, &prevHash, &target)
	})
}

// Fuzz PowCheck: no-panic and determinism for arbitrary 116-byte header +
// 32-byte target.  Mirrors Rust pow_check.rs (CV-POW).
func FuzzPowCheck(f *testing.F) {
	header := make([]byte, BLOCK_HEADER_BYTES)
	header[0] = 0x01
	f.Add(append(header, POW_LIMIT[:]...))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < BLOCK_HEADER_BYTES+32 {
			return
		}
		headerBytes := data[:BLOCK_HEADER_BYTES]
		var target [32]byte
		copy(target[:], data[BLOCK_HEADER_BYTES:BLOCK_HEADER_BYTES+32])

		e1 := PowCheck(headerBytes, target)
		e2 := PowCheck(headerBytes, target)

		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("PowCheck non-deterministic error: %v vs %v", e1, e2)
		}
	})
}

// Fuzz CompactShortID: determinism for arbitrary wtxid + nonces.
// Mirrors Rust compact_shortid.rs (CV-COMPACT).
func FuzzCompactShortID(f *testing.F) {
	seed := make([]byte, 48)
	seed[0] = 0xAB
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 48 {
			return
		}
		var wtxid [32]byte
		copy(wtxid[:], data[0:32])
		nonce1 := binary.LittleEndian.Uint64(data[32:40])
		nonce2 := binary.LittleEndian.Uint64(data[40:48])

		r1 := CompactShortID(wtxid, nonce1, nonce2)
		r2 := CompactShortID(wtxid, nonce1, nonce2)

		if r1 != r2 {
			t.Fatalf("CompactShortID non-deterministic: %x vs %x", r1, r2)
		}
	})
}

// Fuzz ParseHTLCCovenantData: no-panic and determinism for arbitrary bytes.
// Mirrors Rust parse_htlc.rs (CV-HTLC).
func FuzzParseHTLCCovenantData(f *testing.F) {
	claim := filled32(0x01)
	refund := filled32(0x02)
	hash := filled32(0xAA)
	f.Add(encodeHTLCCovenantData(hash, LOCK_MODE_HEIGHT, 100, claim, refund))
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		_, e1 := ParseHTLCCovenantData(data)
		_, e2 := ParseHTLCCovenantData(data)

		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("ParseHTLCCovenantData non-deterministic error")
		}
	})
}

// Fuzz ParseVaultCovenantData: no-panic and determinism for arbitrary bytes.
// Mirrors Rust parse_vault.rs (CV-VAULT).
func FuzzParseVaultCovenantData(f *testing.F) {
	// Minimal valid vault: 1-of-1, 1 whitelist entry.
	owner := filled32(0x10)
	key1 := filled32(0x20)
	wl1 := filled32(0x30)
	seed := make([]byte, 0, 100)
	seed = append(seed, owner[:]...) // owner_lock_id
	seed = append(seed, 1)           // threshold
	seed = append(seed, 1)           // key_count
	seed = append(seed, key1[:]...)  // key[0]
	seed = AppendU16le(seed, 1)      // whitelist_count
	seed = append(seed, wl1[:]...)   // whitelist[0]
	f.Add(seed)
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		_, e1 := ParseVaultCovenantData(data)
		_, e2 := ParseVaultCovenantData(data)

		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("ParseVaultCovenantData non-deterministic error")
		}
	})
}

// Fuzz ParseMultisigCovenantData: no-panic and determinism for arbitrary bytes.
// Mirrors Rust parse_multisig.rs (CV-VAULT).
func FuzzParseMultisigCovenantData(f *testing.F) {
	// Minimal valid multisig: 1-of-1.
	key1 := filled32(0x11)
	seed := make([]byte, 0, 34)
	seed = append(seed, 1)          // threshold
	seed = append(seed, 1)          // key_count
	seed = append(seed, key1[:]...) // key[0]
	f.Add(seed)
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		_, e1 := ParseMultisigCovenantData(data)
		_, e2 := ParseMultisigCovenantData(data)

		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("ParseMultisigCovenantData non-deterministic error")
		}
	})
}

// Fuzz WorkFromTarget and ChainWorkFromTargets: no-panic and determinism for
// arbitrary big-endian targets.  Mirrors Rust fork_work.rs (CV-FORK-CHOICE).
func FuzzForkWork(f *testing.F) {
	f.Add(POW_LIMIT[:])
	small := make([]byte, 32)
	small[31] = 0x01
	f.Add(small)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}
		nTargets := len(data) / 32

		var target [32]byte
		copy(target[:], data[0:32])

		r1, e1 := WorkFromTarget(target)
		r2, e2 := WorkFromTarget(target)

		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("WorkFromTarget non-deterministic error")
		}
		if e1 == nil && r1.Cmp(r2) != 0 {
			t.Fatalf("WorkFromTarget non-deterministic output")
		}

		if nTargets >= 2 && nTargets <= 256 {
			targets := make([][32]byte, nTargets)
			for i := 0; i < nTargets; i++ {
				copy(targets[i][:], data[i*32:(i+1)*32])
			}
			_, _ = ChainWorkFromTargets(targets)
		}
	})
}

// Fuzz BlockSubsidy: no-panic, determinism, and genesis-zero + tail-emission
// floor invariants.  Mirrors Rust block_subsidy.rs (CV-VALUE).
func FuzzBlockSubsidy(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(1), uint64(0))
	f.Add(uint64(1), uint64(MINEABLE_CAP))
	f.Add(uint64(100000), uint64(MINEABLE_CAP/2))

	f.Fuzz(func(t *testing.T, height uint64, alreadyGenerated uint64) {
		s1 := BlockSubsidy(height, alreadyGenerated)
		s2 := BlockSubsidy(height, alreadyGenerated)

		if s1 != s2 {
			t.Fatalf("BlockSubsidy non-deterministic: %d vs %d", s1, s2)
		}
		if height == 0 && s1 != 0 {
			t.Fatalf("BlockSubsidy(0, _) != 0: got %d", s1)
		}
		if height > 0 && s1 < TAIL_EMISSION_PER_BLOCK {
			t.Fatalf("BlockSubsidy floor violated: %d < %d", s1, TAIL_EMISSION_PER_BLOCK)
		}
	})
}

// Fuzz MerkleRootTxids: determinism and no-panic for arbitrary txid lists.
// Mirrors Rust merkle_determinism.rs (CV-MERKLE).
func FuzzMerkleRootTxids(f *testing.F) {
	f.Add([]byte{}) // empty
	seed1 := filled32(0x01)
	f.Add(seed1[:])
	seed2 := filled32(0x02)
	two := append(seed1[:], seed2[:]...)
	f.Add(two)

	f.Fuzz(func(t *testing.T, data []byte) {
		nTxids := len(data) / 32
		if nTxids == 0 {
			_, _ = MerkleRootTxids(nil)
			return
		}
		if nTxids > 4096 {
			return
		}

		txids := make([][32]byte, nTxids)
		for i := 0; i < nTxids; i++ {
			copy(txids[i][:], data[i*32:(i+1)*32])
		}

		r1, e1 := MerkleRootTxids(txids)
		r2, e2 := MerkleRootTxids(txids)

		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("MerkleRootTxids non-deterministic error")
		}
		if e1 == nil && r1 != r2 {
			t.Fatalf("MerkleRootTxids non-deterministic output: %x vs %x", r1, r2)
		}
	})
}

// Fuzz MarshalTx roundtrip: parse → marshal → parse and assert txid/wtxid
// identity.  Go-only target (Rust has no MarshalTx equivalent) (CV-PARSE).
func FuzzMarshalTxRoundtrip(f *testing.F) {
	f.Add(minimalTxBytesForFuzz())
	var prev [32]byte
	prev[0] = 0x42
	f.Add(txWithOneInputOneOutput(prev, 0, 1, COV_TYPE_P2PK, validP2PKCovenantData()))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > (1 << 20) {
			return
		}
		tx, txid1, wtxid1, n, err := ParseTx(data)
		if err != nil {
			return
		}
		if n != len(data) {
			return // only full-consume parses
		}

		marshaled, err := MarshalTx(tx)
		if err != nil {
			t.Fatalf("MarshalTx failed on valid tx: %v", err)
		}

		_, txid2, wtxid2, n2, err := ParseTx(marshaled)
		if err != nil {
			t.Fatalf("ParseTx(MarshalTx(tx)) failed: %v", err)
		}
		if n2 != len(marshaled) {
			t.Fatalf("roundtrip length mismatch: marshal=%d consumed=%d", len(marshaled), n2)
		}
		if txid1 != txid2 {
			t.Fatalf("roundtrip txid mismatch: %x vs %x", txid1, txid2)
		}
		if wtxid1 != wtxid2 {
			t.Fatalf("roundtrip wtxid mismatch: %x vs %x", wtxid1, wtxid2)
		}
	})
}

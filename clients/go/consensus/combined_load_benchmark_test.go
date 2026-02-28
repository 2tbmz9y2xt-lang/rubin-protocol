package consensus

import (
	"bytes"
	"os"
	"strconv"
	"testing"
)

const (
	defaultCombinedLoadSLHTxCount   = 8
	defaultCombinedLoadDAChunkCount = 32
	defaultCombinedLoadChunkBytes   = 65_536
	defaultCombinedLoadSLHSigBytes  = 49_856
)

func benchmarkEnvInt(tb testing.TB, key string, defaultValue int, minValue int, maxValue int) int {
	tb.Helper()
	raw := os.Getenv(key)
	if raw == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		tb.Fatalf("invalid %s=%q: %v", key, raw, err)
	}
	if parsed < minValue || parsed > maxValue {
		tb.Fatalf("%s=%d out of range [%d,%d]", key, parsed, minValue, maxValue)
	}
	return parsed
}

func benchTxWithOneInputOneOutputAndWitness(txNonce uint64, suiteID byte, pubkey []byte, signature []byte) []byte {
	outCov := validP2PKCovenantData()
	b := make([]byte, 0, 160+len(pubkey)+len(signature)+len(outCov))
	b = AppendU32le(b, 1)       // version
	b = append(b, 0x00)         // tx_kind
	b = AppendU64le(b, txNonce) // tx_nonce
	b = AppendCompactSize(b, 1)
	prevTxid := filled32(byte(txNonce))
	b = append(b, prevTxid[:]...)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 0)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 1)
	b = AppendU64le(b, 1)
	b = AppendU16le(b, COV_TYPE_P2PK)
	b = AppendCompactSize(b, uint64(len(outCov)))
	b = append(b, outCov...)
	b = AppendU32le(b, 0)
	b = AppendCompactSize(b, 1)
	b = append(b, suiteID)
	b = AppendCompactSize(b, uint64(len(pubkey)))
	b = append(b, pubkey...)
	b = AppendCompactSize(b, uint64(len(signature)))
	b = append(b, signature...)
	b = AppendCompactSize(b, 0)
	return b
}

func benchTestTxID(tb testing.TB, txBytes []byte) [32]byte {
	tb.Helper()
	_, txid, _, _, err := ParseTx(txBytes)
	if err != nil {
		tb.Fatalf("ParseTx: %v", err)
	}
	return txid
}

func benchCoinbaseWithWitnessCommitment(tb testing.TB, height uint64, nonCoinbaseTxs ...[]byte) []byte {
	tb.Helper()

	wtxids := make([][32]byte, 1, 1+len(nonCoinbaseTxs))
	for _, txb := range nonCoinbaseTxs {
		_, _, wtxid, _, err := ParseTx(txb)
		if err != nil {
			tb.Fatalf("ParseTx(non-coinbase): %v", err)
		}
		wtxids = append(wtxids, wtxid)
	}

	wroot, err := WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		tb.Fatalf("WitnessMerkleRootWtxids: %v", err)
	}
	commit := WitnessCommitmentHash(wroot)
	return coinbaseTxWithOutputs(uint32(height), []testOutput{
		{value: 0, covenantType: COV_TYPE_ANCHOR, covenantData: commit[:]},
	})
}

func benchBuildBlockBytes(tb testing.TB, txs [][]byte) ([]byte, [32]byte, [32]byte) {
	tb.Helper()
	if len(txs) == 0 {
		tb.Fatalf("txs must not be empty")
	}

	txids := make([][32]byte, 0, len(txs))
	for _, txb := range txs {
		txids = append(txids, benchTestTxID(tb, txb))
	}
	root, err := MerkleRootTxids(txids)
	if err != nil {
		tb.Fatalf("MerkleRootTxids: %v", err)
	}

	prev := filled32(0x91)
	target := filled32(0xff)

	header := make([]byte, 0, BLOCK_HEADER_BYTES)
	header = AppendU32le(header, 1) // version
	header = append(header, prev[:]...)
	header = append(header, root[:]...)
	header = AppendU64le(header, 1) // timestamp
	header = append(header, target[:]...)
	header = AppendU64le(header, 31) // nonce
	if len(header) != BLOCK_HEADER_BYTES {
		tb.Fatalf("header size=%d, want %d", len(header), BLOCK_HEADER_BYTES)
	}

	block := make([]byte, 0, len(header)+32)
	block = append(block, header...)
	block = AppendCompactSize(block, uint64(len(txs)))
	for _, tx := range txs {
		block = append(block, tx...)
	}
	return block, prev, target
}

func BenchmarkValidateBlockBasicCombinedLoad(b *testing.B) {
	slhTxCount := benchmarkEnvInt(
		b,
		"RUBIN_COMBINED_LOAD_SLH_TXS",
		defaultCombinedLoadSLHTxCount,
		1,
		64,
	)
	daChunkCount := benchmarkEnvInt(
		b,
		"RUBIN_COMBINED_LOAD_DA_CHUNKS",
		defaultCombinedLoadDAChunkCount,
		1,
		MAX_DA_CHUNK_COUNT,
	)
	chunkPayloadBytes := benchmarkEnvInt(
		b,
		"RUBIN_COMBINED_LOAD_CHUNK_BYTES",
		defaultCombinedLoadChunkBytes,
		1,
		MAX_DA_MANIFEST_BYTES_PER_TX,
	)
	slhSigBytes := benchmarkEnvInt(
		b,
		"RUBIN_COMBINED_LOAD_SLH_SIG_BYTES",
		defaultCombinedLoadSLHSigBytes,
		1,
		MAX_SLH_DSA_SIG_BYTES,
	)

	height := uint64(SLH_DSA_ACTIVATION_HEIGHT)
	slhPub := bytes.Repeat([]byte{0x42}, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	slhSig := bytes.Repeat([]byte{0x5a}, slhSigBytes)

	nonce := uint64(1)
	nonCoinbaseTxs := make([][]byte, 0, slhTxCount+1+daChunkCount)
	for i := 0; i < slhTxCount; i++ {
		nonCoinbaseTxs = append(nonCoinbaseTxs, benchTxWithOneInputOneOutputAndWitness(
			nonce,
			SUITE_ID_SLH_DSA_SHAKE_256F,
			slhPub,
			slhSig,
		))
		nonce++
	}

	daID := filled32(0xd7)
	concat := make([]byte, 0, daChunkCount*chunkPayloadBytes)
	chunkPayloads := make([][]byte, 0, daChunkCount)
	for i := 0; i < daChunkCount; i++ {
		fill := byte((i % 251) + 1)
		payload := bytes.Repeat([]byte{fill}, chunkPayloadBytes)
		chunkPayloads = append(chunkPayloads, payload)
		concat = append(concat, payload...)
	}
	payloadCommitment := sha3_256(concat)
	nonCoinbaseTxs = append(nonCoinbaseTxs, daCommitTxBytes(
		nonce,
		daID,
		uint16(daChunkCount),
		payloadCommitment,
	))
	nonce++

	for i, payload := range chunkPayloads {
		nonCoinbaseTxs = append(nonCoinbaseTxs, daChunkTxBytes(
			nonce,
			daID,
			uint16(i),
			sha3_256(payload),
			payload,
		))
		nonce++
	}

	coinbase := benchCoinbaseWithWitnessCommitment(b, height, nonCoinbaseTxs...)
	txs := make([][]byte, 0, len(nonCoinbaseTxs)+1)
	txs = append(txs, coinbase)
	txs = append(txs, nonCoinbaseTxs...)
	blockBytes, prevHash, target := benchBuildBlockBytes(b, txs)

	if _, err := ValidateBlockBasicWithContextAtHeight(
		blockBytes,
		&prevHash,
		&target,
		height,
		nil,
	); err != nil {
		b.Fatalf("combined-load block fixture invalid: %v", err)
	}

	b.Logf(
		"combined-load fixture: slh_txs=%d da_chunks=%d chunk_bytes=%d total_block_bytes=%d",
		slhTxCount,
		daChunkCount,
		chunkPayloadBytes,
		len(blockBytes),
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(blockBytes)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := ValidateBlockBasicWithContextAtHeight(
			blockBytes,
			&prevHash,
			&target,
			height,
			nil,
		); err != nil {
			b.Fatalf("iteration %d failed: %v", i, err)
		}
	}

	b.StopTimer()
	b.Logf(
		"metrics: ns/op and allocs/op emitted by go test benchmark output (N=%d, bytes=%s)",
		b.N,
		strconv.FormatInt(int64(len(blockBytes)), 10),
	)
}

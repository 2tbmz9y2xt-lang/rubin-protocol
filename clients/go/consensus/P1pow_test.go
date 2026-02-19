package consensus

import (
	"math/big"
	"testing"
)

func makePowHeader(timestamp uint64) BlockHeader {
	return BlockHeader{
		Version:   1,
		Timestamp: timestamp,
		Target:    [32]byte{0x01},
	}
}

func makeWindowHeaders(count int, step uint64) []BlockHeader {
	headers := make([]BlockHeader, 0, count)
	for i := 0; i < count; i++ {
		headers = append(headers, makePowHeader(uint64(i)*step))
	}
	return headers
}

func TestBlockRewardForHeight(t *testing.T) {
	base := uint64(SUBSIDY_TOTAL_MINED / SUBSIDY_DURATION_BLOCKS)
	rem := uint64(SUBSIDY_TOTAL_MINED % SUBSIDY_DURATION_BLOCKS)

	t.Run("height=0 -> base+1 (pre-mint remainder)", func(t *testing.T) {
		if got := blockRewardForHeight(0); got != base+1 {
			t.Fatalf("expected %d, got %d", base, got)
		}
	})

	t.Run("height<rem -> base+1", func(t *testing.T) {
		if got := blockRewardForHeight(rem - 1); got != base+1 {
			t.Fatalf("expected %d, got %d", base+1, got)
		}
	})

	t.Run("height>=SUBSIDY_DURATION_BLOCKS -> 0", func(t *testing.T) {
		if got := blockRewardForHeight(SUBSIDY_DURATION_BLOCKS); got != 0 {
			t.Fatalf("expected 0, got %d", got)
		}
	})
}

func TestMedianPastTimestamp(t *testing.T) {
	t.Run("height=0 -> BLOCK_ERR_TIMESTAMP_OLD", func(t *testing.T) {
		_, err := medianPastTimestamp([]BlockHeader{}, 0)
		if err == nil || err.Error() != BLOCK_ERR_TIMESTAMP_OLD {
			t.Fatalf("expected %s, got %v", BLOCK_ERR_TIMESTAMP_OLD, err)
		}
	})

	t.Run("headers=[] -> BLOCK_ERR_TIMESTAMP_OLD", func(t *testing.T) {
		_, err := medianPastTimestamp([]BlockHeader{}, 1)
		if err == nil || err.Error() != BLOCK_ERR_TIMESTAMP_OLD {
			t.Fatalf("expected %s, got %v", BLOCK_ERR_TIMESTAMP_OLD, err)
		}
	})

	t.Run("1 header -> its timestamp", func(t *testing.T) {
		headers := []BlockHeader{{Timestamp: 12345}}
		got, err := medianPastTimestamp(headers, 1)
		if err != nil {
			t.Fatalf("medianPastTimestamp failed: %v", err)
		}
		if got != 12345 {
			t.Fatalf("expected 12345, got %d", got)
		}
	})

	t.Run("5 headers -> median of 5", func(t *testing.T) {
		headers := []BlockHeader{
			{Timestamp: 20},
			{Timestamp: 10},
			{Timestamp: 40},
			{Timestamp: 30},
			{Timestamp: 50},
		}
		got, err := medianPastTimestamp(headers, 5)
		if err != nil {
			t.Fatalf("medianPastTimestamp failed: %v", err)
		}
		if got != 30 {
			t.Fatalf("expected median 30, got %d", got)
		}
	})

	t.Run("20 headers -> median of 11 latest", func(t *testing.T) {
		headers := makeWindowHeaders(20, 10)
		got, err := medianPastTimestamp(headers, 20)
		if err != nil {
			t.Fatalf("medianPastTimestamp failed: %v", err)
		}
		if got != 140 {
			t.Fatalf("expected median 140, got %d", got)
		}
	})
}

func TestBlockExpectedTarget(t *testing.T) {
	targetIn := [32]byte{}
	targetIn[31] = 1

	t.Run("height=0 -> target_in", func(t *testing.T) {
		got, err := blockExpectedTarget([]BlockHeader{}, 0, targetIn)
		if err != nil {
			t.Fatalf("blockExpectedTarget failed: %v", err)
		}
		if got != targetIn {
			t.Fatalf("expected target_in on height 0")
		}
	})

	t.Run("height != WINDOW_SIZE -> old target", func(t *testing.T) {
		targetIn := makeWindowHeaders(1, 0)[0].Target
		targetIn = [32]byte{0x01}
		headers := makeWindowHeaders(10, 60)
		for i := range headers {
			headers[i].Target = targetIn
		}
		got, err := blockExpectedTarget(headers, 1, targetIn)
		if err != nil {
			t.Fatalf("blockExpectedTarget failed: %v", err)
		}
		if got != targetIn {
			t.Fatalf("expected old target when not at retarget boundary")
		}
	})

	t.Run("height==WINDOW_SIZE, len<WINDOW_SIZE -> BLOCK_ERR_TARGET_INVALID", func(t *testing.T) {
		headers := makeWindowHeaders(WINDOW_SIZE-1, 60)
		for i := range headers {
			headers[i].Target = targetIn
		}
		_, err := blockExpectedTarget(headers, WINDOW_SIZE, targetIn)
		if err == nil || err.Error() != BLOCK_ERR_TARGET_INVALID {
			t.Fatalf("expected %s, got %v", BLOCK_ERR_TARGET_INVALID, err)
		}
	})

	t.Run("retarget clamp ×4", func(t *testing.T) {
		headers := makeWindowHeaders(WINDOW_SIZE, 3000)
		for i := range headers {
			headers[i].Target = targetIn
		}
		got, err := blockExpectedTarget(headers, WINDOW_SIZE, targetIn)
		if err != nil {
			t.Fatalf("blockExpectedTarget failed: %v", err)
		}
		targetOld := new(big.Int).SetBytes(headers[WINDOW_SIZE-1].Target[:])
		expectedMul := new(big.Int).Set(targetOld)
		expectedMul.Mul(expectedMul, big.NewInt(4))
		var expected [32]byte
		expectedMul.FillBytes(expected[:])
		if got != expected {
			t.Fatalf("expected 4x clamp target, got %x", got)
		}
	})

	t.Run("retarget clamp ÷4", func(t *testing.T) {
		headers := makeWindowHeaders(WINDOW_SIZE, 100)
		for i := range headers {
			headers[i].Target = targetIn
		}
		got, err := blockExpectedTarget(headers, WINDOW_SIZE, targetIn)
		if err != nil {
			t.Fatalf("blockExpectedTarget failed: %v", err)
		}
		targetOld := new(big.Int).SetBytes(headers[WINDOW_SIZE-1].Target[:])
		expectedDiv := new(big.Int).Quo(targetOld, big.NewInt(4))
		if expectedDiv.Sign() == 0 {
			expectedDiv = big.NewInt(1)
		}
		var expected [32]byte
		expectedDiv.FillBytes(expected[:])
		if got != expected {
			t.Fatalf("expected 1/4 clamp target, got %x", got)
		}
	})
}

func TestBlockHeaderHashRoundtrip(t *testing.T) {
	header := BlockHeader{
		Version:       1,
		PrevBlockHash: [32]byte{0x11},
		MerkleRoot:    [32]byte{0x22},
		Timestamp:     12345,
		Target:        [32]byte{0x99},
		Nonce:         0x1234,
	}

	encoded := BlockHeaderBytes(header)
	decoded, err := ParseBlockHeader(newCursor(encoded))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if decoded != header {
		t.Fatalf("decode mismatch: got %#v want %#v", decoded, header)
	}

	hashA, err := BlockHeaderHash(applyTxStubProvider{}, header)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	hashB, err := BlockHeaderHash(applyTxStubProvider{}, decoded)
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if hashA != hashB {
		t.Fatalf("hash mismatch: %x != %x", hashA, hashB)
	}
}

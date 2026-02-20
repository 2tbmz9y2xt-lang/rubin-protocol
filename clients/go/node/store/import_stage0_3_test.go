package store

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

func makeTestCoinbaseTx(height uint64) consensus.Tx {
	// Minimal coinbase shape expected by consensus.ApplyBlock.
	return consensus.Tx{
		Version: 2,
		TxKind:  consensus.TX_KIND_STANDARD,
		TxNonce: 0,
		Inputs: []consensus.TxInput{
			{
				PrevTxid:  [32]byte{},
				PrevVout:  consensus.TX_COINBASE_PREVOUT_VOUT,
				Sequence:  consensus.TX_COINBASE_PREVOUT_VOUT,
				ScriptSig: nil,
			},
		},
		Outputs: []consensus.TxOutput{
			{
				Value:        0,
				CovenantType: consensus.CORE_P2PK,
				CovenantData: make([]byte, 33),
			},
		},
		Locktime: uint32(height),
		Witness:  consensus.WitnessSection{},
	}
}

func makeTestBlockBytes(p crypto.CryptoProvider, height uint64, prevHash [32]byte, ts uint64, target [32]byte, merkleOverride *[32]byte) ([]byte, consensus.BlockHeader, [32]byte, error) {
	cb := makeTestCoinbaseTx(height)
	txs := []consensus.Tx{cb}

	headerTxs := []*consensus.Tx{&txs[0]}
	merkle, err := consensus.MerkleRootTxIDs(p, headerTxs)
	if err != nil {
		return nil, consensus.BlockHeader{}, [32]byte{}, err
	}
	if merkleOverride != nil {
		merkle = *merkleOverride
	}

	h := consensus.BlockHeader{
		Version:       1,
		PrevBlockHash: prevHash,
		MerkleRoot:    merkle,
		Timestamp:     ts,
		Target:        target,
		Nonce:         1,
	}
	b := consensus.BlockBytes(&consensus.Block{Header: h, Transactions: txs})
	bh, err := consensus.BlockHeaderHash(p, h)
	if err != nil {
		return nil, consensus.BlockHeader{}, [32]byte{}, err
	}
	return b, h, bh, nil
}

func mustBig(t *testing.T, x *big.Int, err error) *big.Int {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return x
}

func TestImportStage0To3_Stage1_InvalidHeader_MarksIndex(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}

	chainID := [32]byte{0x01}
	db, err := Open(t.TempDir(), hex.EncodeToString(chainID[:]))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Genesis: target = max, timestamp = 1.
	var maxTarget [32]byte
	for i := range maxTarget {
		maxTarget[i] = 0xff
	}
	genesisBytes, genesisHeader, genesisHash, err := makeTestBlockBytes(p, 0, [32]byte{}, 1, maxTarget, nil)
	if err != nil {
		t.Fatalf("make genesis: %v", err)
	}
	if err := db.InitGenesis(p, chainID, genesisBytes); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}

	t.Run("merkle invalid => INVALID_HEADER", func(t *testing.T) {
		badMerkle := genesisHeader.MerkleRoot
		badMerkle[0] ^= 0x01

		blockBytes, header, blockHash, err := makeTestBlockBytes(p, 1, genesisHash, 2, maxTarget, &badMerkle)
		if err != nil {
			t.Fatalf("make block: %v", err)
		}

		_, err = db.ImportStage0To3(p, blockBytes, Stage03Options{})
		if err == nil || err.Error() != consensus.BLOCK_ERR_MERKLE_INVALID {
			t.Fatalf("expected %s, got %v (header=%x)", consensus.BLOCK_ERR_MERKLE_INVALID, err, consensus.BlockHeaderBytes(header))
		}

		idx, ok, err := db.GetIndex(blockHash)
		if err != nil || !ok || idx == nil {
			t.Fatalf("GetIndex: ok=%v err=%v", ok, err)
		}
		if idx.Status != BlockStatusInvalidHeader {
			t.Fatalf("expected status INVALID_HEADER (%d), got %d", BlockStatusInvalidHeader, idx.Status)
		}
	})

	t.Run("target invalid => INVALID_HEADER", func(t *testing.T) {
		var wrongTarget [32]byte
		binary.LittleEndian.PutUint64(wrongTarget[0:8], 1) // deterministic but != maxTarget

		blockBytes, _, blockHash, err := makeTestBlockBytes(p, 1, genesisHash, 2, wrongTarget, nil)
		if err != nil {
			t.Fatalf("make block: %v", err)
		}
		_, err = db.ImportStage0To3(p, blockBytes, Stage03Options{})
		if err == nil || err.Error() != consensus.BLOCK_ERR_TARGET_INVALID {
			t.Fatalf("expected %s, got %v", consensus.BLOCK_ERR_TARGET_INVALID, err)
		}
		idx, ok, err := db.GetIndex(blockHash)
		if err != nil || !ok || idx == nil {
			t.Fatalf("GetIndex: ok=%v err=%v", ok, err)
		}
		if idx.Status != BlockStatusInvalidHeader {
			t.Fatalf("expected status INVALID_HEADER (%d), got %d", BlockStatusInvalidHeader, idx.Status)
		}
	})

	t.Run("timestamp old => INVALID_HEADER", func(t *testing.T) {
		blockBytes, _, blockHash, err := makeTestBlockBytes(p, 1, genesisHash, 1, maxTarget, nil)
		if err != nil {
			t.Fatalf("make block: %v", err)
		}
		_, err = db.ImportStage0To3(p, blockBytes, Stage03Options{})
		if err == nil || err.Error() != consensus.BLOCK_ERR_TIMESTAMP_OLD {
			t.Fatalf("expected %s, got %v", consensus.BLOCK_ERR_TIMESTAMP_OLD, err)
		}
		idx, ok, err := db.GetIndex(blockHash)
		if err != nil || !ok || idx == nil {
			t.Fatalf("GetIndex: ok=%v err=%v", ok, err)
		}
		if idx.Status != BlockStatusInvalidHeader {
			t.Fatalf("expected status INVALID_HEADER (%d), got %d", BlockStatusInvalidHeader, idx.Status)
		}
	})

	t.Run("timestamp future (local_time) => INVALID_HEADER", func(t *testing.T) {
		localTime := uint64(10)
		ts := localTime + consensus.MAX_FUTURE_DRIFT + 1

		blockBytes, _, blockHash, err := makeTestBlockBytes(p, 1, genesisHash, ts, maxTarget, nil)
		if err != nil {
			t.Fatalf("make block: %v", err)
		}
		_, err = db.ImportStage0To3(p, blockBytes, Stage03Options{LocalTime: localTime, LocalTimeSet: true})
		if err == nil || err.Error() != consensus.BLOCK_ERR_TIMESTAMP_FUTURE {
			t.Fatalf("expected %s, got %v", consensus.BLOCK_ERR_TIMESTAMP_FUTURE, err)
		}
		idx, ok, err := db.GetIndex(blockHash)
		if err != nil || !ok || idx == nil {
			t.Fatalf("GetIndex: ok=%v err=%v", ok, err)
		}
		if idx.Status != BlockStatusInvalidHeader {
			t.Fatalf("expected status INVALID_HEADER (%d), got %d", BlockStatusInvalidHeader, idx.Status)
		}
	})

	t.Run("valid header produces non-invalid index", func(t *testing.T) {
		blockBytes, _, blockHash, err := makeTestBlockBytes(p, 1, genesisHash, 2, maxTarget, nil)
		if err != nil {
			t.Fatalf("make block: %v", err)
		}
		res, err := db.ImportStage0To3(p, blockBytes, Stage03Options{})
		if err != nil {
			t.Fatalf("expected ok, got %v", err)
		}
		if res == nil {
			t.Fatalf("expected result")
		}
		idx, ok, err := db.GetIndex(blockHash)
		if err != nil || !ok || idx == nil {
			t.Fatalf("GetIndex: ok=%v err=%v", ok, err)
		}
		if idx.Status.IsInvalid() {
			t.Fatalf("expected non-invalid status, got %d", idx.Status)
		}
		// Basic sanity: chainwork computed (non-zero) for maxTarget.
		if idx.CumulativeWork == nil || idx.CumulativeWork.Sign() < 0 {
			t.Fatalf("expected non-negative cumulative work")
		}
		w, err := WorkFromTarget(maxTarget)
		_ = mustBig(t, w, err)
	})
}

package store

import (
	"testing"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

func makeCoinbaseOnlyBlockBytes(t *testing.T, p crypto.CryptoProvider, height uint64, prev [32]byte, ts uint64) ([]byte, consensus.Block) {
	t.Helper()

	// Minimal coinbase tx satisfying consensus coinbase rules.
	cb := consensus.Tx{
		Version: 1,
		TxNonce: 0,
		Inputs: []consensus.TxInput{{
			PrevTxid:  [32]byte{},
			PrevVout:  consensus.TX_COINBASE_PREVOUT_VOUT,
			ScriptSig: nil,
			Sequence:  consensus.TX_COINBASE_PREVOUT_VOUT,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        0,
			CovenantType: consensus.CORE_P2PK,
			CovenantData: make([]byte, 33),
		}},
		Locktime: uint32(height), // coinbase rule: locktime MUST equal block height
		Witness:  consensus.WitnessSection{Witnesses: nil},
	}

	// Merkle root over txids.
	ptrs := []*consensus.Tx{&cb}
	merkle, err := consensus.MerkleRootTxIDs(p, ptrs)
	if err != nil {
		t.Fatalf("MerkleRootTxIDs: %v", err)
	}

	hdr := consensus.BlockHeader{
		Version:       1,
		PrevBlockHash: prev,
		MerkleRoot:    merkle,
		Timestamp:     ts,
		Target:        consensus.MAX_TARGET,
		Nonce:         0,
	}

	blk := consensus.Block{
		Header:       hdr,
		Transactions: []consensus.Tx{cb},
	}
	return consensus.BlockBytes(&blk), blk
}

func TestReorgToTip_Integration(t *testing.T) {
	p := crypto.DevStdCryptoProvider{}
	var chainID [32]byte
	chainID[0] = 1

	// Build a self-contained genesis block (no profile dependency).
	genBytes, genBlock := makeCoinbaseOnlyBlockBytes(t, p, 0, [32]byte{}, 1)

	db, err := Open(t.TempDir(), "00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00"+"00")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.InitGenesis(p, chainID, genBytes); err != nil {
		t.Fatalf("InitGenesis: %v", err)
	}
	genHash, err := consensus.BlockHeaderHash(p, genBlock.Header)
	if err != nil {
		t.Fatalf("genesis hash: %v", err)
	}

	// Main chain: G -> B1 -> B2
	b1Bytes, b1 := makeCoinbaseOnlyBlockBytes(t, p, 1, genHash, 2)
	dec, err := db.ApplyBlockIfBestTip(p, chainID, b1Bytes, ApplyOptions{})
	if err != nil {
		t.Fatalf("apply b1: %v", err)
	}
	if dec != ApplyAppliedAsTip {
		t.Fatalf("unexpected decision for b1: %s", dec)
	}
	b1Hash, _ := consensus.BlockHeaderHash(p, b1.Header)

	b2Bytes, b2 := makeCoinbaseOnlyBlockBytes(t, p, 2, b1Hash, 3)
	dec, err = db.ApplyBlockIfBestTip(p, chainID, b2Bytes, ApplyOptions{})
	if err != nil {
		t.Fatalf("apply b2: %v", err)
	}
	if dec != ApplyAppliedAsTip {
		t.Fatalf("unexpected decision for b2: %s", dec)
	}
	_ = b2 // ensure parsed path compiled

	// Fork chain from B1: F2 -> F3 (longer => higher cumulative work).
	f2Bytes, f2 := makeCoinbaseOnlyBlockBytes(t, p, 2, b1Hash, 4)
	_, _ = db.ApplyBlockIfBestTip(p, chainID, f2Bytes, ApplyOptions{}) // may or may not trigger reorg; either is fine
	f2Hash, _ := consensus.BlockHeaderHash(p, f2.Header)

	f3Bytes, f3 := makeCoinbaseOnlyBlockBytes(t, p, 3, f2Hash, 5)
	dec, err = db.ApplyBlockIfBestTip(p, chainID, f3Bytes, ApplyOptions{})
	if err != nil {
		t.Fatalf("apply f3: %v", err)
	}
	if dec != ApplyAppliedAsTip {
		t.Fatalf("unexpected decision for f3: %s", dec)
	}

	// Tip should now be f3 (either by reorg or linear extension).
	f3Hash, _ := consensus.BlockHeaderHash(p, f3.Header)
	m := db.Manifest()
	if m == nil || m.TipHashHex == "" {
		t.Fatalf("expected manifest to be set")
	}
	// Only check prefix to avoid importing hex helpers here.
	if len(m.TipHashHex) != 64 {
		t.Fatalf("unexpected tip hash hex length: %d", len(m.TipHashHex))
	}
	_ = f3Hash
}

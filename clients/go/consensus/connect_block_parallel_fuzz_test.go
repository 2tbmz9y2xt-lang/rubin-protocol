package consensus

import (
	"encoding/binary"
	"math/big"
	"testing"
)

// FuzzConnectBlockParallelDeterminism (Q-PV-17) asserts that for any block bytes
// and minimal state, sequential and parallel validation either both succeed with
// the same post-state digest or both fail. Seed is preserved on failure for
// deterministic replay: go test -run=FuzzConnectBlockParallelDeterminism/seed -v
func FuzzConnectBlockParallelDeterminism(f *testing.F) {
	seed := minimalBlockBytesForFuzz()
	// Pack: block bytes + 32 prev + 32 target + 8 height + 8 ag + 1 workers
	packed := make([]byte, 0, len(seed)+32+32+8+8+1)
	packed = append(packed, seed...)
	packed = append(packed, make([]byte, 32+32+8+8+1)...)
	f.Add(packed)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < BLOCK_HEADER_BYTES+1+32+32+8+8+1 {
			return
		}
		if len(data) > 2<<20 {
			return
		}
		ctxLen := 32 + 32 + 8 + 8 + 1
		blockEnd := len(data) - ctxLen
		blockBytes := data[:blockEnd]
		ctx := data[blockEnd:]

		var prevHash [32]byte
		copy(prevHash[:], ctx[0:32])
		var target [32]byte
		copy(target[:], ctx[32:64])
		if len(ctx) < 81 {
			return
		}
		height := binary.BigEndian.Uint64(ctx[64:72])
		if height > 1<<20 {
			return
		}
		ag := binary.BigEndian.Uint64(ctx[72:80])
		workers := int(ctx[80])
		if workers > 32 {
			workers = 32
		}
		if workers <= 0 {
			workers = 1
		}

		state := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: new(big.Int).SetUint64(ag),
		}
		// Avoid overflow in subsidy math for fuzz
		if ag > 1<<60 {
			return
		}

		seqState := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: new(big.Int).Set(state.AlreadyGenerated),
		}
		parState := &InMemoryChainState{
			Utxos:            make(map[Outpoint]UtxoEntry),
			AlreadyGenerated: new(big.Int).Set(state.AlreadyGenerated),
		}

		var prev, tgt *[32]byte
		if prevHash != [32]byte{} {
			prev = &prevHash
		}
		if target != [32]byte{} {
			tgt = &target
		}

		seqSummary, seqErr := ConnectBlockBasicInMemoryAtHeight(blockBytes, prev, tgt, height, nil, seqState, [32]byte{})
		parSummary, parErr := ConnectBlockParallelSigVerify(blockBytes, prev, tgt, height, nil, parState, [32]byte{}, workers)

		if seqErr != nil && parErr != nil {
			return
		}
		if seqErr != nil || parErr != nil {
			t.Fatalf("seq/par mismatch: seqErr=%v parErr=%v", seqErr, parErr)
		}
		if seqSummary.PostStateDigest != parSummary.PostStateDigest {
			t.Fatalf("post_state_digest mismatch seq=%x par=%x", seqSummary.PostStateDigest, parSummary.PostStateDigest)
		}
	})
}

// TestConnectBlockParallelSigVerify_Race (Q-PV-17) runs parallel validation
// from multiple goroutines with cloned state to stress scheduler/reducer under
// the race detector. Run: go test -race -run TestConnectBlockParallelSigVerify_Race
func TestConnectBlockParallelSigVerify_Race(t *testing.T) {
	block, prev, target, height, state := buildBlockForRaceTest(t)
	const concurrency = 8
	done := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			st := cloneChainStateForRace(state)
			_, _ = ConnectBlockParallelSigVerify(block, &prev, &target, height, []uint64{0}, st, [32]byte{}, 2)
			done <- struct{}{}
		}()
	}
	for i := 0; i < concurrency; i++ {
		<-done
	}
}

func buildBlockForRaceTest(t *testing.T) (block []byte, prev, target [32]byte, height uint64, state *InMemoryChainState) {
	t.Helper()
	prev = hashWithPrefix(0x77)
	target = filledHash(0xff)
	height = 1
	kp := mustMLDSA87Keypair(t)
	covData := p2pkCovenantDataForPubkey(kp.PubkeyBytes())
	prevOut := Outpoint{Txid: prev, Vout: 0}
	state = &InMemoryChainState{
		Utxos: map[Outpoint]UtxoEntry{
			prevOut: {
				Value:        100,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: append([]byte(nil), covData...),
			},
		},
		AlreadyGenerated: new(big.Int),
	}
	spendTx := &Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []TxInput{{PrevTxid: prev, PrevVout: 0, Sequence: 0}},
		Outputs:  []TxOutput{{Value: 90, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
		Locktime: 0,
	}
	spendTx.Witness = []WitnessItem{signP2PKInputWitness(t, spendTx, 0, 100, [32]byte{}, kp)}
	spendBytes := txBytesFromTx(t, spendTx)
	_, spendTxid, _, _, err := ParseTx(spendBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	subsidy := BlockSubsidyBig(height, state.AlreadyGenerated)
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, subsidy+10, spendBytes)
	cbTxid := testTxID(t, coinbase)
	root, err := MerkleRootTxids([][32]byte{cbTxid, spendTxid})
	if err != nil {
		t.Fatalf("MerkleRootTxids: %v", err)
	}
	block = buildBlockBytes(t, prev, root, target, 1, [][]byte{coinbase, spendBytes})
	return block, prev, target, height, state
}

func cloneChainStateForRace(s *InMemoryChainState) *InMemoryChainState {
	utxos := make(map[Outpoint]UtxoEntry, len(s.Utxos))
	for k, v := range s.Utxos {
		utxos[k] = v
	}
	return &InMemoryChainState{
		Utxos:            utxos,
		AlreadyGenerated: new(big.Int).Set(s.AlreadyGenerated),
	}
}

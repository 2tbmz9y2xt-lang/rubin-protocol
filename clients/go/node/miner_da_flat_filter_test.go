package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestMinerFlatDAFilterPreservesExplicitNonDACandidates(t *testing.T) {
	daCommit := daCommitTxBytesForMinerPolicyTest(1, []byte("manifest"))
	daChunk := minerFlatDATestChunk(t, [32]byte{0x71}, 0, []byte("chunk"))
	nonDA := minerFlatTestNonDA(0x11)

	miner := &Miner{cfg: MinerConfig{MaxTxPerBlock: 2}}
	candidates := miner.candidateTransactions([][]byte{daCommit, daChunk, nonDA})
	selected, err := miner.selectCandidateTransactions(candidates, nil, 1, ^uint64(0))
	if err != nil {
		t.Fatalf("selectCandidateTransactions: %v", err)
	}
	if len(selected) != 1 || !bytes.Equal(selected[0].raw, nonDA) {
		t.Fatalf("selected=%d, want only trailing non-DA candidate", len(selected))
	}
}

func TestMinerMempoolCandidateEntriesSkipFlatDABeforeWindowCap(t *testing.T) {
	daCommit := daCommitTxBytesForMinerPolicyTest(1, []byte("manifest"))
	nonDA := minerFlatTestNonDA(0x12)
	entries := []*mempoolEntry{
		{raw: daCommit, size: len(daCommit)},
		{raw: nonDA, size: len(nonDA)},
		{raw: minerFlatDATestChunk(t, [32]byte{0x72}, 0, []byte("chunk")), size: 1},
	}

	selected := pickMinerCandidateEntries(entries, 1, 1<<20)
	if len(selected) != 1 || !bytes.Equal(selected[0], nonDA) {
		t.Fatalf("selected=%d, want non-DA candidate past skipped flat DA entries", len(selected))
	}
}

func TestMinerFlatDAFilterKeepsCapacityBoundedByCandidates(t *testing.T) {
	nonDA := minerFlatTestNonDA(0x13)

	selected := pickFlatCandidateRaw([][]byte{nonDA}, 1_000_000)
	if len(selected) != 1 || cap(selected) != 1 {
		t.Fatalf("explicit selected len/cap=%d/%d, want 1/1", len(selected), cap(selected))
	}

	entries := []*mempoolEntry{{raw: nonDA, size: len(nonDA)}}
	selected = pickMinerCandidateEntries(entries, 1_000_000, 1<<20)
	if len(selected) != 1 || cap(selected) != 1 {
		t.Fatalf("mempool selected len/cap=%d/%d, want 1/1", len(selected), cap(selected))
	}
}

func TestMinerFlatDAFilterSkipsDAInSelectionPath(t *testing.T) {
	miner := &Miner{cfg: DefaultMinerConfig()}
	if _, _, ok, err := miner.trySelectFlatCandidate(daCommitTxBytesForMinerPolicyTest(2, []byte("manifest")), nil, 1, 0, ^uint64(0), 0); err != nil || ok {
		t.Fatalf("DA candidate ok=%v err=%v, want skipped without error", ok, err)
	}
}

func TestMinerFlatDAFilterSkipsWeightBudgetRejects(t *testing.T) {
	nonDA := minerFlatTestNonDA(0x15)
	miner := &Miner{cfg: DefaultMinerConfig()}
	if _, _, ok, err := miner.trySelectFlatCandidate(nonDA, nil, 1, 0, 0, 0); err != nil || ok {
		t.Fatalf("zero remaining weight ok=%v err=%v, want skipped without error", ok, err)
	}
	if _, _, ok, err := miner.trySelectFlatCandidate(nonDA, nil, 1, 0, 1, 0); err != nil || ok {
		t.Fatalf("overweight candidate ok=%v err=%v, want skipped without error", ok, err)
	}
}

func TestMinerFlatDAFilterPreservesNonCanonicalInputError(t *testing.T) {
	badDACommit := append(daCommitTxBytesForMinerPolicyTest(1, []byte("manifest")), 0x00)
	miner := &Miner{cfg: MinerConfig{MaxTxPerBlock: 2}}

	candidates := miner.candidateTransactions([][]byte{badDACommit})
	if len(candidates) != 1 {
		t.Fatalf("candidate count=%d, want malformed DA-shaped input preserved", len(candidates))
	}
	if _, err := miner.selectCandidateTransactions(candidates, nil, 1, ^uint64(0)); err == nil {
		t.Fatalf("expected non-canonical miner input error")
	}
}

type minerTestCompleteDASetProvider []CompleteDASetCandidate

func (p minerTestCompleteDASetProvider) CompleteDASetCandidates(uint64) []CompleteDASetCandidate {
	return p
}
func TestMinerCompleteDASetProviderValidity(t *testing.T) {
	fixture := newMinerProviderTestFixture(t)
	daID := [32]byte{0x81}
	set := fixture.completeDASet(t, daID, []byte("chunk-0"), []byte("chunk-1"))
	nonDA := minerFlatTestNonDA(0x82)
	selected := minerProviderSelected(t, []CompleteDASetCandidate{set, set}, nil, fixture.utxos, 0, 0)
	if len(selected) != 3 {
		t.Fatalf("duplicate da_id selected=%d, want one complete DA set", len(selected))
	}
	policyOffMiner := &Miner{
		cfg: MinerConfig{
			CompleteDASetProvider:    minerTestCompleteDASetProvider{set},
			MaxTxPerBlock:            16,
			PolicyDaAnchorAntiAbuse:  false,
			PolicyMaxDaBytesPerBlock: 3,
		},
		sync: &SyncEngine{cfg: SyncConfig{ChainID: devnetGenesisChainID}},
	}
	selected, err := policyOffMiner.selectCandidateTransactions(nil, fixture.utxos, 1, ^uint64(0))
	if err != nil {
		t.Fatalf("select with DA policy disabled: %v", err)
	}
	if len(selected) != 3 {
		t.Fatalf("policy-disabled provider selected=%d, want complete DA set", len(selected))
	}
	collidingNonce := minerProviderCloneSet(set)
	collidingNonce.CommitTx = minerProviderMutateTx(t, collidingNonce.CommitTx, func(tx *consensus.Tx) { tx.TxNonce = 1 })
	selected = minerProviderSelected(t, []CompleteDASetCandidate{collidingNonce}, [][]byte{nonDA}, fixture.utxos, 0, 0)
	if len(selected) != 1 || string(selected[0].raw) != string(nonDA) {
		t.Fatalf("provider nonce collision selected=%d, want only flat tx", len(selected))
	}
	collidingInput := minerProviderCloneSet(set)
	collidingInput.CommitTx = minerProviderMutateTx(t, collidingInput.CommitTx, func(tx *consensus.Tx) { tx.Inputs[0].PrevTxid = [32]byte{0x82} })
	selected = minerProviderSelected(t, []CompleteDASetCandidate{collidingInput}, [][]byte{nonDA}, fixture.utxos, 0, 0)
	if len(selected) != 1 || string(selected[0].raw) != string(nonDA) {
		t.Fatalf("provider input collision selected=%d, want only flat tx", len(selected))
	}
	sets := make([]CompleteDASetCandidate, 0, consensus.MAX_DA_BATCHES_PER_BLOCK+1)
	for i := 0; i < consensus.MAX_DA_BATCHES_PER_BLOCK+1; i++ {
		sets = append(sets, fixture.completeDASet(t, [32]byte{byte(i + 1), 0x85}, []byte{byte(i), 0}, []byte{byte(i), 1}))
	}
	selected = minerProviderSelected(t, sets, nil, fixture.utxos, len(sets)*3+1, 0)
	if len(selected) != int(consensus.MAX_DA_BATCHES_PER_BLOCK)*3 {
		t.Fatalf("selected batches=%d, want capped provider DA batches", len(selected)/3)
	}
}
func TestMinerCompleteDASetProviderRejectsInvalidGroups(t *testing.T) {
	fixture := newMinerProviderTestFixture(t)
	base := fixture.completeDASet(t, [32]byte{0x83}, []byte("chunk-0"), []byte("chunk-1"))
	missing := minerProviderCloneSet(base)
	missing.Chunks = missing.Chunks[:1]
	duplicate := minerProviderCloneSet(base)
	duplicate.Chunks[1].Index = 0
	wrongDAID := minerProviderCloneSet(base)
	wrongDAID.Chunks[1].Tx = minerProviderMutateTx(t, wrongDAID.Chunks[1].Tx, func(tx *consensus.Tx) { tx.DaChunkCore.DaID = [32]byte{0x84} })
	badHash := minerProviderCloneSet(base)
	badHash.Chunks[0].Tx = minerProviderMutateTx(t, badHash.Chunks[0].Tx, func(tx *consensus.Tx) { tx.DaChunkCore.ChunkHash = [32]byte{0x85} })
	badCommitment := minerProviderCloneSet(base)
	badCommitment.CommitTx = minerProviderMutateTx(t, badCommitment.CommitTx, func(tx *consensus.Tx) { tx.Outputs[0].CovenantData[0] ^= 0xff })
	duplicateNonce := minerProviderCloneSet(base)
	duplicateNonce.Chunks[1].Tx = minerProviderMutateTx(t, duplicateNonce.Chunks[1].Tx, func(tx *consensus.Tx) { tx.TxNonce = mustParseTx(t, duplicateNonce.Chunks[0].Tx).TxNonce })
	duplicateInput := minerProviderCloneSet(base)
	duplicateInput.Chunks[1].Tx = minerProviderMutateTx(t, duplicateInput.Chunks[1].Tx, func(tx *consensus.Tx) { tx.Inputs[0] = mustParseTx(t, duplicateInput.Chunks[0].Tx).Inputs[0] })
	zeroNonce := minerProviderCloneSet(base)
	zeroNonce.CommitTx = minerProviderMutateTx(t, zeroNonce.CommitTx, func(tx *consensus.Tx) { tx.TxNonce = 0 })
	overBudget := minerProviderCloneSet(base)
	wrongChainSig := fixture.completeDASetWithChainID(t, [32]byte{0x88}, [32]byte{0x87}, []byte("chunk-0"), []byte("chunk-1"))
	for i, set := range []CompleteDASetCandidate{missing, duplicate, wrongDAID, badHash, badCommitment, duplicateNonce, duplicateInput, zeroNonce, overBudget, wrongChainSig} {
		maxBytes := uint64(0)
		if i == 8 {
			maxBytes = 3
		}
		if selected := minerProviderSelected(t, []CompleteDASetCandidate{set}, nil, fixture.utxos, 0, maxBytes); len(selected) != 0 {
			t.Fatalf("invalid provider selected=%d", len(selected))
		}
	}
	badRaw := minerProviderCloneSet(base)
	badRaw.CommitTx = append(badRaw.CommitTx, 0)
	if _, err := (&Miner{cfg: MinerConfig{CompleteDASetProvider: minerTestCompleteDASetProvider{badRaw}, MaxTxPerBlock: 16}}).selectCandidateTransactions(nil, nil, 1, ^uint64(0)); err == nil {
		t.Fatalf("expected malformed provider raw error")
	}
	set2 := fixture.completeDASet(t, [32]byte{0x86}, []byte("chunk-0"), []byte("chunk-1"))
	set2.CommitTx = minerProviderMutateTx(t, set2.CommitTx, func(tx *consensus.Tx) { tx.TxNonce = mustParseTx(t, base.CommitTx).TxNonce })
	if selected := minerProviderSelected(t, []CompleteDASetCandidate{base, set2}, nil, fixture.utxos, 0, 0); len(selected) != 3 {
		t.Fatalf("cross-provider nonce collision selected=%d, want first complete DA set only", len(selected))
	}
}

func minerProviderCloneSet(s CompleteDASetCandidate) CompleteDASetCandidate {
	s.CommitTx = append([]byte(nil), s.CommitTx...)
	s.Chunks = append([]CompleteDASetChunkCandidate(nil), s.Chunks...)
	for i := range s.Chunks {
		s.Chunks[i].Tx = append([]byte(nil), s.Chunks[i].Tx...)
	}
	return s
}

func minerProviderSelected(t *testing.T, sets []CompleteDASetCandidate, flat [][]byte, utxos map[consensus.Outpoint]consensus.UtxoEntry, maxTx int, maxBytes uint64) []minedCandidate {
	if maxTx == 0 {
		maxTx = 16
	}
	cfg := MinerConfig{
		CompleteDASetProvider:    minerTestCompleteDASetProvider(sets),
		MaxTxPerBlock:            maxTx,
		PolicyDaAnchorAntiAbuse:  true,
		PolicyMaxDaBytesPerBlock: maxBytes,
	}
	miner := &Miner{cfg: cfg, sync: &SyncEngine{cfg: SyncConfig{ChainID: devnetGenesisChainID}}}
	selected, err := miner.selectCandidateTransactions(flat, utxos, 1, ^uint64(0))
	if err != nil {
		t.Fatalf("select provider candidates: %v", err)
	}
	return selected
}

type minerProviderTestFixture struct {
	signer    *consensus.MLDSA87Keypair
	address   []byte
	utxos     map[consensus.Outpoint]consensus.UtxoEntry
	nextInput uint64
}

func newMinerProviderTestFixture(t *testing.T) *minerProviderTestFixture {
	signer := mustNodeMLDSA87Keypair(t)
	return &minerProviderTestFixture{
		signer:  signer,
		address: consensus.P2PKCovenantDataForPubkey(signer.PubkeyBytes()),
		utxos:   make(map[consensus.Outpoint]consensus.UtxoEntry),
	}
}

func (f *minerProviderTestFixture) completeDASet(t *testing.T, daID [32]byte, payloads ...[]byte) CompleteDASetCandidate {
	return f.completeDASetWithChainID(t, devnetGenesisChainID, daID, payloads...)
}

func (f *minerProviderTestFixture) completeDASetWithChainID(t *testing.T, chainID [32]byte, daID [32]byte, payloads ...[]byte) CompleteDASetCandidate {
	base := 2 + uint64(daID[0])*(consensus.MAX_DA_CHUNK_COUNT+2)
	hasher := sha3.New256()
	chunks := make([]CompleteDASetChunkCandidate, 0, len(payloads))
	for i, payload := range payloads {
		_, _ = hasher.Write(payload)
		raw := f.chunkTx(t, chainID, daID, base, uint16(i), payload)
		chunks = append(chunks, CompleteDASetChunkCandidate{Index: uint16(i), Tx: raw})
	}
	tx := &consensus.Tx{Version: 1, TxKind: 0x01, TxNonce: base, DaPayload: []byte{0xa1}}
	tx.Inputs = []consensus.TxInput{f.nextSignedInput()}
	tx.Outputs = []consensus.TxOutput{{CovenantType: consensus.COV_TYPE_DA_COMMIT, CovenantData: hasher.Sum(nil)}}
	tx.DaCommitCore = &consensus.DaCommitCore{DaID: daID, ChunkCount: uint16(len(payloads)), BatchNumber: 1}
	commit := f.signAndMarshal(t, chainID, tx)
	return CompleteDASetCandidate{DAID: daID, CommitTx: commit, Chunks: chunks}
}

func (f *minerProviderTestFixture) chunkTx(t *testing.T, chainID [32]byte, daID [32]byte, base uint64, index uint16, payload []byte) []byte {
	chunkHash := sha3.Sum256(payload)
	tx := &consensus.Tx{Version: 1, TxKind: 0x02, TxNonce: base + uint64(index) + 1, DaPayload: append([]byte(nil), payload...)}
	tx.Inputs = []consensus.TxInput{f.nextSignedInput()}
	tx.DaChunkCore = &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: chunkHash}
	return f.signAndMarshal(t, chainID, tx)
}

func (f *minerProviderTestFixture) nextSignedInput() consensus.TxInput {
	f.nextInput++
	var txid [32]byte
	txid[0] = 0xd7
	binary.BigEndian.PutUint64(txid[24:], f.nextInput)
	op := consensus.Outpoint{Txid: txid}
	f.utxos[op] = consensus.UtxoEntry{
		Value:             1_000_000,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      append([]byte(nil), f.address...),
		CreationHeight:    1,
		CreatedByCoinbase: false,
	}
	return consensus.TxInput{PrevTxid: op.Txid, PrevVout: op.Vout}
}

func (f *minerProviderTestFixture) signAndMarshal(t *testing.T, chainID [32]byte, tx *consensus.Tx) []byte {
	t.Helper()
	if err := consensus.SignTransaction(tx, f.utxos, chainID, f.signer); err != nil {
		t.Fatalf("SignTransaction(provider): %v", err)
	}
	return mustMarshalTxForNodeTest(t, tx)
}

func minerProviderMutateTx(t *testing.T, raw []byte, mutate func(*consensus.Tx)) []byte {
	tx := mustParseTx(t, raw)
	mutate(tx)
	return mustMarshalTxForNodeTest(t, tx)
}

func minerFlatDATestChunk(t *testing.T, daID [32]byte, index uint16, payload []byte) []byte {
	t.Helper()
	chunkHash := sha3.Sum256(payload)
	return mustMarshalTxForNodeTest(t, &consensus.Tx{
		Version:     1,
		TxKind:      0x02,
		TxNonce:     uint64(index) + 1,
		DaChunkCore: &consensus.DaChunkCore{DaID: daID, ChunkIndex: index, ChunkHash: chunkHash},
		DaPayload:   append([]byte(nil), payload...),
	})
}

func minerFlatTestNonDA(marker byte) []byte {
	return txWithOneInputOneOutput([32]byte{marker}, 0, 1, consensus.COV_TYPE_P2PK, testP2PKCovenantData(marker), nil)
}

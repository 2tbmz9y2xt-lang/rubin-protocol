package p2p

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type compactCandidateFixture struct {
	state  *node.ChainState
	signer *consensus.MLDSA87Keypair
	mp     *node.Mempool
	da     *node.DARelayState
	pool   *CanonicalMempoolTxPool
	raw    [][]byte
	ids    []node.CompactCandidateIdentity
}

func newCompactCandidateFixture(tb testing.TB, count int, reverse ...bool) compactCandidateFixture {
	tb.Helper()
	f := newCompactCandidateOwners(tb, count)
	address := consensus.P2PKCovenantDataForPubkey(f.signer.PubkeyBytes())
	for i := 0; i < count; i++ {
		var txid [32]byte
		binary.LittleEndian.PutUint64(txid[:8], uint64(i+1))
		op := consensus.Outpoint{Txid: txid}
		f.state.Utxos[op] = consensus.UtxoEntry{Value: 1_000_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: slices.Clone(address)}
		tx := &consensus.Tx{Version: 1, TxNonce: uint64(i + 1), Inputs: []consensus.TxInput{{PrevTxid: op.Txid}}, Outputs: []consensus.TxOutput{{Value: 900_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: slices.Clone(address)}}}
		if err := consensus.SignTransaction(tx, f.state.Utxos, node.DevnetGenesisChainID(), f.signer); err != nil {
			tb.Fatal(err)
		}
		raw, err := consensus.MarshalTx(tx)
		if err != nil {
			tb.Fatal(err)
		}
		_, txid, wtxid, consumed, err := consensus.ParseTx(raw)
		if err != nil || consumed != len(raw) {
			tb.Fatalf("fixture parse=(%d,%v)", consumed, err)
		}
		f.raw = append(f.raw, raw)
		f.ids = append(f.ids, node.CompactCandidateIdentity{TxID: txid, WTxID: wtxid})
	}
	for i := 0; i < count; i++ {
		at := i
		if len(reverse) != 0 && reverse[0] {
			at = count - 1 - i
		}
		if err := f.mp.AddTx(f.raw[at]); err != nil {
			tb.Fatal(err)
		}
	}
	return f
}

func newCompactCandidateOwners(tb testing.TB, count int) compactCandidateFixture {
	tb.Helper()
	signer, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(signer.Close)
	state := node.NewChainState()
	cfg := node.DefaultMempoolConfig()
	cfg.MaxTransactions, cfg.MaxBytes = count+1, 1_000_000_000
	mp, err := node.NewMempoolWithConfig(state, nil, node.DevnetGenesisChainID(), cfg)
	if err != nil {
		tb.Fatal(err)
	}
	dir := tb.TempDir()
	store, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		tb.Fatal(err)
	}
	target := consensus.POW_LIMIT
	syncCfg := node.DefaultSyncConfig(&target, node.DevnetGenesisChainID(), node.ChainStatePath(dir))
	engine, err := node.NewSyncEngine(state, store, syncCfg)
	if err != nil {
		tb.Fatal(err)
	}
	engine.SetMempool(mp)
	pool := NewCanonicalMempoolTxPool(mp)
	runtimeCfg := node.DefaultPeerRuntimeConfig("devnet", 8)
	service, err := NewService(ServiceConfig{BindAddr: "127.0.0.1:0", GenesisHash: node.DevnetGenesisBlockHash(), PeerRuntimeConfig: runtimeCfg, PeerManager: node.NewPeerManager(runtimeCfg), SyncEngine: engine, SyncConfig: syncCfg, BlockStore: store, TxPool: pool, TxMetadataFunc: mp.RelayMetadata})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		if err := service.Close(); err != nil {
			tb.Error(err)
		}
	})
	return compactCandidateFixture{mp: mp, da: service.daRelay, pool: pool, state: state, signer: signer}
}

func compactCandidateAdmitDA(tb testing.TB, f compactCandidateFixture) ([]byte, node.CompactCandidateIdentity) {
	tb.Helper()
	address := consensus.P2PKCovenantDataForPubkey(f.signer.PubkeyBytes())
	op := consensus.Outpoint{Txid: [32]byte{0xff}}
	f.state.Utxos[op] = consensus.UtxoEntry{Value: 2_000_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: slices.Clone(address)}
	payload := []byte("actual compact DA")
	tx := &consensus.Tx{Version: 1, TxKind: 2, TxNonce: 99, Inputs: []consensus.TxInput{{PrevTxid: op.Txid}}, Outputs: []consensus.TxOutput{{Value: 1_400_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: slices.Clone(address)}}, DaChunkCore: &consensus.DaChunkCore{DaID: [32]byte{0xc7}, ChunkHash: sha3.Sum256(payload)}, DaPayload: payload}
	if err := consensus.SignTransaction(tx, f.state.Utxos, node.DevnetGenesisChainID(), f.signer); err != nil {
		tb.Fatal(err)
	}
	raw, err := consensus.MarshalTx(tx)
	if err != nil {
		tb.Fatal(err)
	}
	provenance, err := node.NewPeerDAProvenance("compact", "compact")
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := f.da.AdmitDA(raw, provenance); err != nil {
		tb.Fatal(err)
	}
	_, txid, wtxid, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		tb.Fatal("admitted DA canonical identity unavailable")
	}
	return raw, node.CompactCandidateIdentity{TxID: txid, WTxID: wtxid}
}

func requireCompactCandidateZero(t *testing.T, got compactCandidateOutcome, err, want error) {
	t.Helper()
	if err != want || !reflect.DeepEqual(got.Result, compactReconstructionResult{}) {
		t.Fatalf("outcome=%+v err=%v want=%v with zero Result", got, err, want)
	}
}

func TestCompactCandidateReconstruct(t *testing.T) {
	t.Run("input_validation", compactCandidateInputCases)
	t.Run("complete_population", func(t *testing.T) {
		for _, reverse := range []bool{false, true} {
			f := newCompactCandidateFixture(t, 1001, reverse)
			prefill := minimalBlockTxnTestTxBytes(99)
			block := cmpctBlockPayload{Nonce1: 4, Nonce2: 5, Prefilled: []prefilledTxn{{Index: 0, Tx: prefill}}, ShortIDs: []compactShortID{compactShortIDForTx(t, f.raw[1000], 4, 5)}}
			got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
			if err != nil || !reflect.DeepEqual(got.Result.Transactions, [][]byte{prefill, f.raw[1000]}) || got.Result.PartialTransactions != nil || got.Result.MissingIndexes != nil || got.Result.MissingShortIDs != nil {
				t.Fatalf("complete population reverse%v outcome=%+v err=%v", reverse, got, err)
			}
			if f.mp.Len() != 1001 {
				t.Fatal("candidate changed resident population")
			}
		}
	})
	t.Run("retained_da_fills", compactCandidateRetainedFills)
	t.Run("later_read_refusal", compactCandidateLaterRefusal)
	t.Run("zero_sid_bypass", compactCandidateZeroSID)
	t.Run("immutable_bytes", func(t *testing.T) {
		f := newCompactCandidateFixture(t, 1)
		prefill := minimalBlockTxnTestTxBytes(777)
		block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: prefill}}, ShortIDs: []compactShortID{compactShortIDForTx(t, f.raw[0], 0, 0)}}
		got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		if err != nil || !reflect.DeepEqual(got.Result.Transactions, [][]byte{prefill, f.raw[0]}) || !got.D4Complete || got.DistinctCollisionCount != 0 {
			t.Fatalf("complete=%+v err=%v", got, err)
		}
		prefill[0] ^= 1
		got.Result.Transactions[1][0] ^= 1
		read := f.mp.ReadCompactStandard(f.ids[0], ^uint64(0))
		if !bytes.Equal(read.Raw, f.raw[0]) || got.Result.Transactions[0][0] == prefill[0] {
			t.Fatal("input/result/owner alias")
		}
		if err := f.mp.EvictConfirmedParsed(&consensus.ParsedBlock{Txids: [][32]byte{f.ids[0].TxID}}); err != nil {
			t.Fatal(err)
		}
		got2, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		requireCompactCandidateZero(t, got2, err, errCompactCandidateInput)
		block.Prefilled[0].Tx = minimalBlockTxnTestTxBytes(777)
		got2, err = reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		if err != nil || !reflect.DeepEqual(got2.Result.MissingIndexes, []uint64{1}) || got2.Result.PartialTransactions[1] != nil {
			t.Fatalf("next removal=%+v err=%v", got2, err)
		}
	})
	t.Run("ascending_missing", func(t *testing.T) {
		f := newCompactCandidateFixture(t, 0)
		block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: minimalBlockTxnTestTxBytes(55)}}, ShortIDs: []compactShortID{{1}, {2}, {1}}}
		got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		if err != nil || !reflect.DeepEqual(got.Result.MissingIndexes, []uint64{1, 2, 3}) || !reflect.DeepEqual(got.Result.MissingShortIDs, block.ShortIDs) || len(got.Result.PartialTransactions) != 4 || got.Result.Transactions != nil || !got.D4Complete || got.DistinctCollisionCount != 1 {
			t.Fatalf("ascending missing=%+v err=%v", got, err)
		}
	})
	t.Run("profile1_missing_boundary", compactCandidateMissingBoundary)
	t.Run("resource_arithmetic", compactCandidateArithmetic)
	t.Run("late_collision", compactCandidateCollisionCases)
	t.Run("metadata_fault", compactCandidateMetadataFault)
	t.Run("all_observers", compactCandidateObserverCases)
	t.Run("separate_snapshot_lifetime", func(t *testing.T) {
		f := newCompactCandidateFixture(t, 1)
		_, daID := compactCandidateAdmitDA(t, f)
		daIDs, ok := f.da.CompactDAIdentities(f.mp)
		if !ok || len(daIDs) != 1 || daIDs[0] != daID {
			t.Fatal("first coherent DA snapshot failed")
		}
		if err := f.da.ReleasePeerQuotaKey("compact"); err != nil {
			t.Fatal(err)
		}
		standardIDs, ok := f.mp.CompactStandardIdentities()
		if !ok || len(standardIDs) != 1 {
			t.Fatal("second coherent standard snapshot failed")
		}
		block := cmpctBlockPayload{ShortIDs: []compactShortID{compactShortID(consensus.CompactShortID(daID.WTxID, 0, 0)), compactShortID(consensus.CompactShortID(f.ids[0].WTxID, 0, 0))}}
		observed := []compactCandidateObservation{{Identity: daIDs[0], ShortID: block.ShortIDs[0], Sources: 1}, {Identity: standardIDs[0], ShortID: block.ShortIDs[1], Sources: 2}}
		catalog, err := compactCandidateScan(observed)
		if err != nil {
			t.Fatal(err)
		}
		eligible, _ := compactCandidateEligibility(block, nil, catalog)
		partial, err := compactCandidateFill(block.ShortIDs, make([][]byte, 2), eligible, catalog, f.mp, f.da, 117, 72_000_000)
		if err != nil || !reflect.DeepEqual(partial.MissingIndexes, []uint64{0}) || !bytes.Equal(partial.PartialTransactions[1], f.raw[0]) {
			t.Fatal("captured disappearance became fault or replacement fill")
		}
		got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		if err != nil || !reflect.DeepEqual(got.Result.MissingIndexes, []uint64{0}) || got.Result.PartialTransactions[0] != nil {
			t.Fatalf("independent-time next outcome=%+v err=%v", got, err)
		}
	})
	t.Run("d4_observation", compactCandidateD4)
	t.Run("canonical_sources", func(t *testing.T) {
		f := newCompactCandidateFixture(t, 0)
		block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: minimalBlockTxnTestTxBytes(3)}}, ShortIDs: []compactShortID{{1}}}
		for _, pool := range []TxPool{nil, NewMemoryTxPool(), &staticTxPool{}, (*CanonicalMempoolTxPool)(nil), &CanonicalMempoolTxPool{}} {
			got, err := reconstructCompactCandidates(block, 1, 72_000_000, pool, f.da)
			requireCompactCandidateZero(t, got, err, errCompactCandidateFault)
			if got.D4Complete || got.DistinctCollisionCount != 0 {
				t.Fatal("pre-D4 fault became measured zero")
			}
		}
		got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, nil)
		requireCompactCandidateZero(t, got, err, errCompactCandidateFault)
		other := newCompactCandidateFixture(t, 0)
		got, err = reconstructCompactCandidates(block, 1, 72_000_000, f.pool, other.da)
		requireCompactCandidateZero(t, got, err, errCompactCandidateFault)
		got, err = reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		if err != nil || !reflect.DeepEqual(got.Result.MissingIndexes, []uint64{1}) || !got.D4Complete {
			t.Fatalf("valid next=%+v err=%v", got, err)
		}
	})
}

func compactCandidateRetainedFills(t *testing.T) {
	for _, standardCount := range []int{0, 1} {
		f := newCompactCandidateFixture(t, standardCount)
		daRaw, daID := compactCandidateAdmitDA(t, f)
		for _, nonce := range [][2]uint64{{4, 5}, {7, 9}} {
			for _, partial := range []bool{false, true} {
				prefill := minimalBlockTxnTestTxBytes(777)
				block := cmpctBlockPayload{Nonce1: nonce[0], Nonce2: nonce[1], Prefilled: []prefilledTxn{{Index: 1, Tx: prefill}}, ShortIDs: []compactShortID{compactShortIDForTx(t, daRaw, nonce[0], nonce[1])}}
				want := [][]byte{daRaw, slices.Clone(prefill)}
				missingIndex := uint64(2)
				if standardCount == 1 {
					block.ShortIDs = append(block.ShortIDs, compactShortIDForTx(t, f.raw[0], nonce[0], nonce[1]))
					want, missingIndex = append(want, f.raw[0]), 3
				}
				missing := compactShortID{0xab}
				for slices.Contains(block.ShortIDs, missing) || missing == compactShortIDForTx(t, prefill, nonce[0], nonce[1]) {
					missing[0]++
				}
				if partial {
					block.ShortIDs, want = append(block.ShortIDs, missing), append(want, nil)
				}
				counts, used := f.mp.AdmissionCounts(), f.mp.BytesUsed()
				for invocation := 0; invocation < 2; invocation++ {
					got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
					expected := compactReconstructionResult{Transactions: want}
					if partial {
						expected = compactReconstructionResult{PartialTransactions: want, MissingIndexes: []uint64{missingIndex}, MissingShortIDs: []compactShortID{missing}}
					}
					if err != nil || !reflect.DeepEqual(got.Result, expected) || !got.D4Complete || got.DistinctCollisionCount != 0 || !bytes.Equal(block.Prefilled[0].Tx, want[1]) || f.mp.AdmissionCounts() != counts || f.mp.BytesUsed() != used {
						t.Fatalf("DA/mixed%d partial%v nonce%v invocation%d=%+v err=%v", standardCount, partial, nonce, invocation, got, err)
					}
					result := got.Result.Transactions
					if partial {
						result = got.Result.PartialTransactions
						got.Result.MissingIndexes[0], got.Result.MissingShortIDs[0] = 77, compactShortID{0xee}
						result[missingIndex] = []byte{0xee}
					}
					block.Prefilled[0].Tx[0] ^= 1
					if !bytes.Equal(result[1], want[1]) {
						t.Fatal("input edit reached result bytes")
					}
					result[0][0] ^= 1
					read := f.da.ReadCompactDA(daID, uint64(len(daRaw)))
					if read.Disposition != 1 || !bytes.Equal(read.Raw, daRaw) {
						t.Fatal("result edit reached real retained DA")
					}
					block.Prefilled[0].Tx = slices.Clone(want[1])
				}
			}
		}
	}
}

func compactCandidateLaterRefusal(t *testing.T) {
	f := newCompactCandidateFixture(t, 2)
	daRaw, daID := compactCandidateAdmitDA(t, f)
	daSID, standardSID := compactShortIDForTx(t, daRaw, 0, 0), compactShortIDForTx(t, f.raw[0], 0, 0)
	observed := []compactCandidateObservation{{Identity: daID, ShortID: daSID, Sources: 1}, {Identity: f.ids[0], ShortID: standardSID, Sources: 2}}
	catalog, err := compactCandidateScan(observed)
	if err != nil {
		t.Fatal(err)
	}
	eligible := map[compactShortID]int{daSID: 0, standardSID: 1}
	counts, used := f.mp.AdmissionCounts(), f.mp.BytesUsed()
	for _, fault := range []bool{true, false} {
		mp, budget, want := f.mp, uint64(72_000_000), errCompactCandidateFault
		if fault {
			mp = &node.Mempool{}
		} else {
			budget, want = 117+uint64(len(daRaw)), errCompactCandidateResource
		}
		txs := make([][]byte, 2)
		got, err := compactCandidateFill([]compactShortID{daSID, standardSID}, txs, eligible, catalog, mp, f.da, 117, budget)
		if err != want || !reflect.DeepEqual(got, compactReconstructionResult{}) || !bytes.Equal(txs[0], daRaw) {
			t.Fatalf("later refusal=(%+v,%v), first genuine fill=%x", got, err, txs[0])
		}
		next, err := compactCandidateFill([]compactShortID{daSID, standardSID}, make([][]byte, 2), eligible, catalog, f.mp, f.da, 117, 72_000_000)
		if err != nil || !reflect.DeepEqual(next, compactReconstructionResult{Transactions: [][]byte{daRaw, f.raw[0]}}) || f.mp.AdmissionCounts() != counts || f.mp.BytesUsed() != used {
			t.Fatal("stage refusal retained prefix/changed owner/contaminated next invocation")
		}
	}
	prefilled := compactCandidateLargePrefills(f.raw[1])
	for i := range prefilled {
		prefilled[i].Index = uint64(i + 2)
	}
	x, y := compactShortID{1}, compactShortID{2}
	reserved := []compactShortID{daSID, standardSID, compactShortIDForTx(t, f.raw[1], 0, 0)}
	for slices.Contains(reserved, x) {
		x[0]++
	}
	for slices.Contains(reserved, y) || x == y {
		y[0]++
	}
	block := cmpctBlockPayload{Prefilled: prefilled, ShortIDs: []compactShortID{daSID, standardSID, x, x, y, y}}
	if len(prefilled)+6 < 253 || len(prefilled)+4099 > 65535 {
		t.Fatal("fixture does not have literal three-byte CompactSize count")
	}
	baseline := uint64(119 + len(prefilled)*len(f.raw[1]))
	budget := baseline + uint64(len(daRaw))
	if budget < 72_000_000 {
		t.Fatal("fixture budget violates minimum")
	}
	for _, byteBudget := range []uint64{budget, baseline} {
		got, err := reconstructCompactCandidates(block, 1, byteBudget, f.pool, f.da)
		requireCompactCandidateZero(t, got, err, errCompactCandidateResource)
		if !got.D4Complete || got.DistinctCollisionCount != 2 || f.mp.AdmissionCounts() != counts || f.mp.BytesUsed() != used {
			t.Fatal("hydration refusal lost completed D4 or changed owner")
		}
	}
	late := block
	late.ShortIDs = []compactShortID{daSID}
	for i := 0; i < 4097; i++ {
		if i%2 == 0 {
			late.ShortIDs = append(late.ShortIDs, x)
		} else {
			late.ShortIDs = append(late.ShortIDs, y)
		}
	}
	late.ShortIDs = append(late.ShortIDs, standardSID)
	got, err := reconstructCompactCandidates(late, 1, budget, f.pool, f.da)
	requireCompactCandidateZero(t, got, err, errCompactCandidateResource)
	if !got.D4Complete || got.DistinctCollisionCount != 2 {
		t.Fatal("4097 earlier misses hid later resource error or lost D4")
	}
	lateCatalog, err := compactCandidateScan([]compactCandidateObservation{{Identity: f.ids[0], ShortID: standardSID, Sources: 2}, {Identity: daID, ShortID: daSID, Sources: 1}})
	if err != nil {
		t.Fatal(err)
	}
	late.ShortIDs[0], late.ShortIDs[len(late.ShortIDs)-1] = standardSID, daSID
	lateEligible, _ := compactCandidateEligibility(late, nil, lateCatalog)
	staged := make([][]byte, len(late.ShortIDs))
	result, err := compactCandidateFill(late.ShortIDs, staged, lateEligible, lateCatalog, f.mp, nil, 119, 72_000_000)
	if err != errCompactCandidateFault || !reflect.DeepEqual(result, compactReconstructionResult{}) || !bytes.Equal(staged[0], f.raw[0]) {
		t.Fatal("4097 stage misses hid later actual unavailable DA fault")
	}
	got, err = reconstructCompactCandidates(block, 1, 72_000_000, f.pool, nil)
	requireCompactCandidateZero(t, got, err, errCompactCandidateFault)
	if got.D4Complete || got.DistinctCollisionCount != 0 {
		t.Fatal("unavailable owner lost priority over oversized canonical baseline")
	}
	got, err = reconstructCompactCandidates(block, 1, budget+uint64(len(f.raw[0])), f.pool, f.da)
	if err != nil || !got.D4Complete || got.DistinctCollisionCount != 2 || got.Result.Transactions != nil || len(got.Result.PartialTransactions) != len(prefilled)+6 || !bytes.Equal(got.Result.PartialTransactions[0], daRaw) || !bytes.Equal(got.Result.PartialTransactions[1], f.raw[0]) || !reflect.DeepEqual(got.Result.MissingIndexes, []uint64{uint64(len(prefilled) + 2), uint64(len(prefilled) + 3), uint64(len(prefilled) + 4), uint64(len(prefilled) + 5)}) || !reflect.DeepEqual(got.Result.MissingShortIDs, []compactShortID{x, x, y, y}) {
		t.Fatalf("next exact-bound kernel=%+v err=%v", got, err)
	}
}

func compactCandidateInputCases(t *testing.T) {
	prefill := minimalBlockTxnTestTxBytes(1)
	valid := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: prefill}}}
	reject := func(t *testing.T, block cmpctBlockPayload, profile, budget uint64) {
		t.Helper()
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("input rejection panicked: %v; want errCompactCandidateInput with zero Result and no D4 observation", recovered)
			}
		}()
		got, err := reconstructCompactCandidates(block, profile, budget, nil, nil)
		requireCompactCandidateZero(t, got, err, errCompactCandidateInput)
		if got.D4Complete || got.DistinctCollisionCount != 0 {
			t.Fatal("input fault has D4 observation")
		}
		next, nextErr := reconstructCompactCandidates(valid, 1, 72_000_000, nil, nil)
		if nextErr != nil || !reflect.DeepEqual(next, compactCandidateOutcome{Result: compactReconstructionResult{Transactions: [][]byte{prefill}}}) {
			t.Fatal("input refusal changed the next independent invocation")
		}
	}
	t.Run("profile", func(t *testing.T) {
		for _, profile := range []uint64{0, 3} {
			reject(t, valid, profile, 72_000_000)
		}
		for _, profile := range []uint64{1, 2} {
			got, err := reconstructCompactCandidates(valid, profile, 72_000_000, nil, nil)
			if err != nil || len(got.Result.Transactions) != 1 {
				t.Fatal("valid profile rejected")
			}
		}
	})
	t.Run("byte_budget", func(t *testing.T) {
		for _, budget := range []uint64{0, 71_999_999} {
			reject(t, valid, 1, budget)
		}
		for _, budget := range []uint64{72_000_000, 80_000_000} {
			got, err := reconstructCompactCandidates(valid, 1, budget, nil, nil)
			if err != nil || len(got.Result.Transactions) != 1 {
				t.Fatal("valid budget rejected")
			}
		}
	})
	t.Run("count", func(t *testing.T) {
		for _, row := range []struct {
			profile, short, prefilled, want uint64
			accepted                        bool
		}{
			{1, 0, 0, 0, false},
			{2, 0, 0, 0, false},
			{1, 72_000_000, 0, 72_000_000, true},
			{1, 72_000_001, 0, 0, false},
			{2, 280_991, 0, 280_991, true},
			{2, 280_992, 0, 0, false},
			{1, ^uint64(0), 2, 0, false},
			{2, ^uint64(0), 2, 0, false},
			{1, 2, ^uint64(0), 0, false},
			{2, 2, ^uint64(0), 0, false},
			{0, 1, 0, 0, false},
			{3, 1, 0, 0, false},
		} {
			got, err := compactCandidateEntryCount(row.profile, row.short, row.prefilled)
			if got != row.want || (row.accepted && err != nil) || (!row.accepted && err != errCompactCandidateInput) {
				t.Fatalf("count%+v=(%d,%v)", row, got, err)
			}
		}
		reject(t, cmpctBlockPayload{}, 1, 72_000_000)
	})
	t.Run("prefilled_positions", func(t *testing.T) {
		reject(t, cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: prefill}, {Index: 0, Tx: prefill}}}, 1, 72_000_000)
		reject(t, cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 1, Tx: prefill}}}, 1, 72_000_000)
	})
	t.Run("profile2_order", func(t *testing.T) {
		f := newCompactCandidateFixture(t, 2)
		block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 3, Tx: prefill}, {Index: 0, Tx: prefill}}, ShortIDs: []compactShortID{compactShortIDForTx(t, f.raw[0], 0, 0), compactShortIDForTx(t, f.raw[1], 0, 0)}}
		reject(t, block, 2, 72_000_000)
		got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		if err != nil || !reflect.DeepEqual(got.Result.Transactions, [][]byte{prefill, f.raw[0], f.raw[1], prefill}) {
			t.Fatalf("profile1 order=%+v err=%v", got, err)
		}
		if _, err := encodeCmpctBlockPayload(block); err == nil {
			t.Fatal("legacy wire unexpectedly accepted decreasing prefills")
		}
		block.Prefilled[0], block.Prefilled[1] = block.Prefilled[1], block.Prefilled[0]
		got, err = reconstructCompactCandidates(block, 2, 72_000_000, f.pool, f.da)
		if err != nil || !reflect.DeepEqual(got.Result.Transactions, [][]byte{prefill, f.raw[0], f.raw[1], prefill}) || !got.D4Complete || got.DistinctCollisionCount != 0 {
			t.Fatal("profile2 increasing multi-prefill placement failed")
		}
	})
	t.Run("prefilled_canonical", func(t *testing.T) {
		nonminimal := append(slices.Clone(prefill[:13]), 0xfd, 0, 0)
		nonminimal = append(nonminimal, prefill[14:]...)
		for _, raw := range [][]byte{nil, {0}, prefill[:len(prefill)-1], append(slices.Clone(prefill), 0), nonminimal} {
			for _, profile := range []uint64{1, 2} {
				for _, badAt := range []int{0, 1} {
					for _, withSID := range []bool{false, true} {
						block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: slices.Clone(raw)}}}
						before := []prefilledTxn{{Index: 0, Tx: slices.Clone(raw)}}
						if badAt == 1 {
							block.Prefilled = []prefilledTxn{{Index: 0, Tx: slices.Clone(prefill)}, {Index: 1, Tx: slices.Clone(raw)}}
							before = []prefilledTxn{{Index: 0, Tx: slices.Clone(prefill)}, {Index: 1, Tx: slices.Clone(raw)}}
						}
						if withSID {
							block.ShortIDs = []compactShortID{{1}}
						}
						reject(t, block, profile, 72_000_000)
						if !reflect.DeepEqual(block.Prefilled, before) {
							t.Fatal("later malformed prefill changed input prefix")
						}
					}
				}
			}
		}
	})
}

func compactCandidateZeroSID(t *testing.T) {
	// Repeating canonical bytes is legal for this component's parsing projection;
	// complete-body transaction uniqueness and admission are future-owned.
	f := newCompactCandidateFixture(t, 1)
	raw := slices.Clone(f.raw[0])
	prefilled := compactCandidateLargePrefills(raw)
	count := len(prefilled)
	got, err := reconstructCompactCandidates(cmpctBlockPayload{Prefilled: prefilled}, 1, 72_000_000, nil, nil)
	if err != nil || len(got.Result.Transactions) != count || got.D4Complete || got.DistinctCollisionCount != 0 || got.Result.PartialTransactions != nil || got.Result.MissingIndexes != nil || got.Result.MissingShortIDs != nil {
		t.Fatalf("zero SID=%+v err=%v", got, err)
	}
	raw[0] ^= 1
	if got.Result.Transactions[0][0] == raw[0] || got.Result.Transactions[count-1][0] == raw[0] {
		t.Fatal("zero-SID input alias")
	}
}

func compactCandidateLargePrefills(raw []byte) []prefilledTxn {
	prefilled := make([]prefilledTxn, 72_000_000/len(raw)+1)
	for i := range prefilled {
		prefilled[i] = prefilledTxn{Index: uint64(i), Tx: raw}
	}
	return prefilled
}

func compactCandidateMissingBoundary(t *testing.T) {
	f := newCompactCandidateFixture(t, 0)
	for _, row := range []struct {
		profile  uint64
		missing  int
		fallback bool
	}{{1, 4096, false}, {1, 4097, true}, {2, 4097, false}} {
		block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: minimalBlockTxnTestTxBytes(1)}}, ShortIDs: make([]compactShortID, row.missing)}
		got, err := reconstructCompactCandidates(block, row.profile, 72_000_000, f.pool, f.da)
		if row.fallback {
			requireCompactCandidateZero(t, got, err, errCompactRelayMissingRequestTooLarge)
			if !got.D4Complete || got.DistinctCollisionCount != 1 {
				t.Fatal("count fallback lost D4")
			}
			continue
		}
		if err != nil || got.Result.Transactions != nil || len(got.Result.PartialTransactions) != row.missing+1 || len(got.Result.MissingIndexes) != row.missing {
			t.Fatalf("boundary%+v outcome=%+v err=%v", row, got, err)
		}
		for i, index := range got.Result.MissingIndexes {
			if index != uint64(i+1) || got.Result.MissingShortIDs[i] != block.ShortIDs[i] || got.Result.PartialTransactions[index] != nil {
				t.Fatal("missing vector truncated/unordered")
			}
		}
	}
	// The count refusal must discard a genuine earlier accepted fill as well.
	filled := newCompactCandidateFixture(t, 1)
	match := compactShortIDForTx(t, filled.raw[0], 0, 0)
	missing := compactShortID{1}
	if missing == match {
		missing = compactShortID{2}
	}
	block := cmpctBlockPayload{ShortIDs: append([]compactShortID{match}, slices.Repeat([]compactShortID{missing}, 4097)...)}
	got, err := reconstructCompactCandidates(block, 1, 72_000_000, filled.pool, filled.da)
	requireCompactCandidateZero(t, got, err, errCompactRelayMissingRequestTooLarge)
	if !got.D4Complete || got.DistinctCollisionCount != 1 {
		t.Fatal("accepted-fill count fallback lost D4")
	}
	block.ShortIDs = block.ShortIDs[:4097]
	got, err = reconstructCompactCandidates(block, 1, 72_000_000, filled.pool, filled.da)
	if err != nil || len(got.Result.MissingIndexes) != 4096 || !bytes.Equal(got.Result.PartialTransactions[0], filled.raw[0]) {
		t.Fatal("next legal missing count lost admitted fill")
	}
}

func compactCandidateArithmetic(t *testing.T) {
	for _, row := range []struct {
		current, extra, budget, want uint64
		accepted                     bool
	}{
		{117, 71_999_883, 72_000_000, 72_000_000, true},
		{117, 71_999_884, 72_000_000, 0, false},
		{117, 72_000_000, 72_000_000, 0, false},
		{^uint64(0), 1, ^uint64(0), 0, false},
		{1, ^uint64(0), ^uint64(0), 0, false},
		{^uint64(0) - 1, 1, ^uint64(0), ^uint64(0), true},
	} {
		got, err := compactCandidateAdd(row.current, row.extra, row.budget)
		if got != row.want || (row.accepted && err != nil) || (!row.accepted && !errors.Is(err, errCompactCandidateResource)) {
			t.Fatalf("arithmetic%+v=(%d,%v)", row, got, err)
		}
	}
	for _, row := range []struct{ total, want uint64 }{{1, 117}, {252, 117}, {253, 119}, {65535, 119}, {65536, 121}, {1 << 32, 125}} {
		got, err := compactCandidateBaseline(row.total, nil, ^uint64(0))
		if err != nil || got != row.want {
			t.Fatalf("literal116+minimalCS=%d want%d err=%v", got, row.want, err)
		}
	}
	raw := make([]byte, 71_999_883)
	if got, err := compactCandidateBaseline(1, []prefilledTxn{{Tx: raw}}, 72_000_000); err != nil || got != 72_000_000 {
		t.Fatalf("exact baseline=(%d,%v)", got, err)
	}
	if _, err := compactCandidateBaseline(1, []prefilledTxn{{Tx: make([]byte, 71_999_884)}}, 72_000_000); !errors.Is(err, errCompactCandidateResource) {
		t.Fatal("baseline+1 accepted")
	}
}

func compactCandidateCollisionCases(t *testing.T) {
	x, y := compactShortID{1}, compactShortID{2}
	a := compactCandidateObservation{Identity: node.CompactCandidateIdentity{TxID: [32]byte{1}, WTxID: [32]byte{2}}, ShortID: x, Sources: 2}
	b := compactCandidateObservation{Identity: node.CompactCandidateIdentity{TxID: [32]byte{1}, WTxID: [32]byte{3}}, ShortID: x, Sources: 1}
	for _, observed := range [][]compactCandidateObservation{{a, b}, {b, a}} {
		catalog, err := compactCandidateScan(observed)
		if err != nil || len(catalog.Observed) != 2 || catalog.Index[x] != -1 {
			t.Fatal("late/equal-txid collision lost")
		}
		block := cmpctBlockPayload{ShortIDs: []compactShortID{x, y, x}}
		eligible, count := compactCandidateEligibility(block, nil, catalog)
		if count != 1 || eligible[x] != -1 || eligible[y] != -1 {
			t.Fatalf("eligibility=%v collisions=%d", eligible, count)
		}
		// Nil actual owners prove no hydration for every ineligible position.
		result, err := compactCandidateFill(block.ShortIDs, make([][]byte, 3), eligible, catalog, nil, nil, 117, 72_000_000)
		if err != nil || !reflect.DeepEqual(result.MissingIndexes, []uint64{0, 1, 2}) {
			t.Fatal("ineligible raw was queried")
		}
	}
	duplicate := a
	duplicate.Sources = 1
	catalog, err := compactCandidateScan([]compactCandidateObservation{a, duplicate})
	if err != nil || len(catalog.Observed) != 1 || catalog.Observed[0].Sources != 3 || catalog.Index[x] != 0 {
		t.Fatal("exact pair did not retain both observers")
	}
	// Each exclusion category is independently sufficient with the other two absent.
	for _, row := range []struct {
		observed []compactCandidateObservation
		received []compactShortID
		prefills [][32]byte
	}{
		{[]compactCandidateObservation{a, b}, []compactShortID{x}, nil},
		{[]compactCandidateObservation{a}, []compactShortID{x, x}, nil},
		{[]compactCandidateObservation{{Identity: a.Identity, ShortID: compactShortID(consensus.CompactShortID(a.Identity.WTxID, 0, 0)), Sources: 2}}, []compactShortID{compactShortID(consensus.CompactShortID(a.Identity.WTxID, 0, 0))}, [][32]byte{a.Identity.WTxID}},
	} {
		catalog, err := compactCandidateScan(row.observed)
		if err != nil {
			t.Fatal(err)
		}
		block := cmpctBlockPayload{ShortIDs: row.received}
		eligible, count := compactCandidateEligibility(block, row.prefills, catalog)
		if count != 1 {
			t.Fatal("independent exclusion category lost its distinct SID")
		}
		result, err := compactCandidateFill(block.ShortIDs, make([][]byte, len(row.received)), eligible, catalog, nil, nil, 117, 72_000_000)
		if err != nil || len(result.MissingIndexes) != len(row.received) {
			t.Fatal("independent ineligible identity was hydrated")
		}
	}
	f := newCompactCandidateFixture(t, 2)
	x, y = compactShortIDForTx(t, f.raw[0], 0, 0), compactShortIDForTx(t, f.raw[1], 0, 0)
	a = compactCandidateObservation{Identity: f.ids[0], ShortID: x, Sources: 2}
	b = a
	b.Identity.WTxID[0] ^= 1
	// The matching stage takes fixed observations; only eligible real identities
	// reach the actual owner. No alternate short-id function or provider is used.
	for _, row := range []struct {
		d, p, a bool
		count   uint64
	}{{false, false, false, 0}, {false, false, true, 1}, {false, true, false, 1}, {false, true, true, 1}, {true, false, false, 1}, {true, false, true, 1}, {true, true, false, 1}, {true, true, true, 1}} {
		for _, resident := range []bool{true, false} {
			if !resident && (row.d || row.p || row.a) {
				continue
			}
			t.Run(fmt.Sprintf("D%v/P%v/A%v/resident%v", row.d, row.p, row.a, resident), func(t *testing.T) {
				prefill := minimalBlockTxnTestTxBytes(88)
				if row.p {
					prefill = f.raw[0]
				}
				prefillID := compactWTxIDForTx(t, prefill)
				observed := []compactCandidateObservation{{Identity: f.ids[1], ShortID: y, Sources: 2}}
				if resident {
					observed = append(observed, a)
				}
				if row.a {
					observed = append(observed, b)
				}
				z := compactShortID{0xe1}
				for z == x || z == y || z == compactShortID(consensus.CompactShortID(prefillID, 0, 0)) {
					z[0]++
				}
				z1, z2 := a, a
				z1.Identity.WTxID[0], z2.Identity.WTxID[0] = z1.Identity.WTxID[0]^2, z2.Identity.WTxID[0]^4
				z1.ShortID, z2.ShortID = z, z
				observed = append(observed, z1, z2)
				catalog, err := compactCandidateScan(observed)
				if err != nil {
					t.Fatal(err)
				}
				block := cmpctBlockPayload{ShortIDs: []compactShortID{x, y}, Prefilled: []prefilledTxn{{Index: 1, Tx: prefill}}}
				want := [][]byte{f.raw[0], prefill, f.raw[1]}
				var missing []uint64
				var missingSIDs []compactShortID
				if row.count == 1 || !resident {
					want[0], missing, missingSIDs = nil, []uint64{0}, []compactShortID{x}
				}
				if row.d {
					block.ShortIDs, want = append(block.ShortIDs, x), append(want, nil)
					missing, missingSIDs = append(missing, 3), append(missingSIDs, x)
				}
				eligible, count := compactCandidateEligibility(block, [][32]byte{prefillID}, catalog)
				if count != row.count || eligible[y] < 0 || (eligible[x] < 0) != (row.count == 1 || !resident) {
					t.Fatalf("collision union=%d eligibility=%v", count, eligible)
				}
				txs := make([][]byte, len(want))
				txs[1] = slices.Clone(prefill)
				got, err := compactCandidateFill(block.ShortIDs, txs, eligible, catalog, f.mp, f.da, 117+uint64(len(prefill)), 72_000_000)
				expected := compactReconstructionResult{Transactions: want}
				if missing != nil {
					expected = compactReconstructionResult{PartialTransactions: want, MissingIndexes: missing, MissingShortIDs: missingSIDs}
				}
				if err != nil || !reflect.DeepEqual(got, expected) {
					t.Fatalf("collision fill=%+v err=%v", got, err)
				}
			})
		}
	}
	b.ShortID = y
	if catalog, err := compactCandidateScan([]compactCandidateObservation{a, b}); err != nil || len(catalog.Observed) != 2 || catalog.Index[x] != 0 || catalog.Index[y] != 1 {
		t.Fatal("equal TXID with different WTXID/SID collapsed")
	}
}

func compactCandidateMetadataFault(t *testing.T) {
	first := compactCandidateObservation{Identity: node.CompactCandidateIdentity{TxID: [32]byte{1}, WTxID: [32]byte{2}}, ShortID: compactShortID{1}, Sources: 2}
	conflict := first
	conflict.Identity.TxID[0] = 3
	third := compactCandidateObservation{Identity: node.CompactCandidateIdentity{TxID: [32]byte{4}, WTxID: [32]byte{5}}, ShortID: compactShortID{2}, Sources: 1}
	for _, observed := range [][]compactCandidateObservation{{first, conflict}, {conflict, first}, {third, first, conflict}} {
		got, err := compactCandidateScan(observed)
		if err != errCompactCandidateFault || !reflect.DeepEqual(got, compactCandidateCatalog{}) {
			t.Fatal("metadata contradiction returned prefix")
		}
		if got, err := compactCandidateScan([]compactCandidateObservation{first}); err != nil || len(got.Observed) != 1 {
			t.Fatal("next independent scan failed")
		}
	}
}

func compactCandidateObserverCases(t *testing.T) {
	raw := minimalBlockTxnTestTxBytes(88)
	present := node.CompactCandidateRead{Disposition: 1, Raw: slices.Clone(raw)}
	absent := node.CompactCandidateRead{Disposition: 2}
	fault := node.CompactCandidateRead{Disposition: 3}
	over := node.CompactCandidateRead{Disposition: 4}
	for _, row := range []struct {
		name string
		read node.CompactCandidateRead
		want error
	}{
		{"ABSENT_nil", absent, nil}, {"PRESENT_fit", present, nil},
		{"PRESENT_nil", node.CompactCandidateRead{Disposition: 1}, errCompactCandidateFault},
		{"PRESENT_empty", node.CompactCandidateRead{Disposition: 1, Raw: []byte{}}, errCompactCandidateFault},
		{"PRESENT_over", node.CompactCandidateRead{Disposition: 1, Raw: append(slices.Clone(raw), 0)}, errCompactCandidateResource},
		{"FAULT", fault, errCompactCandidateFault}, {"OVER_BUDGET", over, errCompactCandidateResource},
		{"enum0", node.CompactCandidateRead{Disposition: 0}, errCompactCandidateFault},
		{"enum5", node.CompactCandidateRead{Disposition: 5}, errCompactCandidateFault},
		{"ABSENT_raw", node.CompactCandidateRead{Disposition: 2, Raw: raw}, errCompactCandidateFault},
	} {
		for _, prior := range [][]byte{nil, slices.Clone(raw)} {
			t.Run(fmt.Sprintf("%s/prior%v", row.name, prior != nil), func(t *testing.T) {
				got, err := compactCandidateCompose(prior, row.read, uint64(len(raw)))
				want := prior
				if row.want != nil {
					want = nil
				} else if row.read.Disposition == 1 && prior == nil {
					want = raw
				}
				if err != row.want || !bytes.Equal(got, want) || (want == nil && got != nil) {
					t.Fatalf("compose=(%x,%v) want(%x,%v)", got, err, want, row.want)
				}
				if err == nil && prior != nil && &got[0] != &prior[0] {
					t.Fatal("agreeing source replaced the already selected byte slice")
				}
				if next, err := compactCandidateCompose(nil, present, uint64(len(raw))); err != nil || !bytes.Equal(next, raw) {
					t.Fatal("failed invocation leaked staged fill")
				}
			})
		}
	}
	different := node.CompactCandidateRead{Disposition: 1, Raw: minimalBlockTxnTestTxBytes(89)}
	for _, row := range []struct {
		name          string
		first, second node.CompactCandidateRead
		want          error
		filled        bool
	}{
		{"A/A", absent, absent, nil, false}, {"A/P", absent, present, nil, true},
		{"P/A", present, absent, nil, true}, {"agreeing_P/P", present, node.CompactCandidateRead{Disposition: 1, Raw: slices.Clone(raw)}, nil, true},
		{"differing_P/P", present, different, errCompactCandidateFault, false},
		{"P/F", present, fault, errCompactCandidateFault, false}, {"P/O", present, over, errCompactCandidateResource, false},
		{"A/F", absent, fault, errCompactCandidateFault, false}, {"A/O", absent, over, errCompactCandidateResource, false},
		{"F/O", fault, over, errCompactCandidateFault, false}, {"O/F", over, fault, errCompactCandidateResource, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			var selected []byte
			var err error
			for _, read := range []node.CompactCandidateRead{row.first, row.second} {
				selected, err = compactCandidateCompose(selected, read, uint64(len(raw)))
				if err != nil {
					break
				}
			}
			if err != row.want || (row.filled && !bytes.Equal(selected, raw)) || (!row.filled && selected != nil) {
				t.Fatalf("ordered composition=(%x,%v), want filled%v/%v", selected, err, row.filled, row.want)
			}
			if row.name == "agreeing_P/P" && &selected[0] != &row.first.Raw[0] {
				t.Fatal("agreeing second PRESENT retained a second selection")
			}
			if next, err := compactCandidateCompose(nil, present, uint64(len(raw))); err != nil || !bytes.Equal(next, raw) {
				t.Fatal("ordered refusal contaminated next invocation")
			}
		})
	}
	f := newCompactCandidateFixture(t, 0)
	daRaw, identity := compactCandidateAdmitDA(t, f)
	observation := compactCandidateObservation{Identity: identity, Sources: 3}
	// An actual DA PRESENT precedes a real unavailable standard owner. Returning
	// on PRESENT would hide the second observer's FAULT and retain the first copy.
	got, err := compactCandidateHydrate(observation, &node.Mempool{}, f.da, uint64(len(daRaw)))
	if got != nil || err != errCompactCandidateFault {
		t.Fatal("first actual PRESENT hid later observer fault")
	}
	got, err = compactCandidateHydrate(observation, f.mp, f.da, uint64(len(daRaw)))
	if err != nil || !bytes.Equal(got, daRaw) {
		t.Fatal("actual PRESENT plus ABSENT failed next invocation")
	}
	standard := newCompactCandidateFixture(t, 1)
	sid := compactShortIDForTx(t, standard.raw[0], 0, 0)
	// Sources3 is a fixed matching-stage observation for the real consumers.
	// The empty DA owner never originally held this standard canonical pair.
	observation = compactCandidateObservation{Identity: standard.ids[0], ShortID: sid, Sources: 3}
	got, err = compactCandidateHydrate(observation, standard.mp, standard.da, uint64(len(standard.raw[0])))
	if err != nil || !bytes.Equal(got, standard.raw[0]) {
		t.Fatal("actual DA ABSENT plus standard PRESENT lost the selection")
	}
	catalog, err := compactCandidateScan([]compactCandidateObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	eligible := map[compactShortID]int{sid: 0}
	result, err := compactCandidateFill([]compactShortID{sid}, make([][]byte, 1), eligible, catalog, standard.mp, standard.da, 117, 117+uint64(len(standard.raw[0])))
	if err != nil || !reflect.DeepEqual(result, compactReconstructionResult{Transactions: [][]byte{standard.raw[0]}}) {
		t.Fatal("two actual observers charged more than one logical fill")
	}
	if err := standard.mp.EvictConfirmedParsed(&consensus.ParsedBlock{Txids: [][32]byte{standard.ids[0].TxID}}); err != nil {
		t.Fatal(err)
	}
	got, err = compactCandidateHydrate(observation, standard.mp, standard.da, 0)
	if err != nil || got != nil {
		t.Fatal("actual DA/standard ABSENT returned bytes or an error")
	}
	result, err = compactCandidateFill([]compactShortID{sid}, make([][]byte, 1), eligible, catalog, standard.mp, standard.da, 117, 117)
	if err != nil || !reflect.DeepEqual(result, compactReconstructionResult{PartialTransactions: [][]byte{nil}, MissingIndexes: []uint64{0}, MissingShortIDs: []compactShortID{sid}}) {
		t.Fatal("actual two-owner absence did not produce one ordinary miss")
	}
}

func compactCandidateD4(t *testing.T) {
	f := newCompactCandidateFixture(t, 0)
	prefill := minimalBlockTxnTestTxBytes(1)
	_, _, wtxid, _, err := consensus.ParseTx(prefill)
	if err != nil {
		t.Fatal(err)
	}
	x := compactShortID(consensus.CompactShortID(wtxid, 0, 0))
	observed := []compactCandidateObservation{{Identity: node.CompactCandidateIdentity{WTxID: [32]byte{1}}, ShortID: x, Sources: 1}, {Identity: node.CompactCandidateIdentity{WTxID: [32]byte{2}}, ShortID: x, Sources: 2}}
	catalog, err := compactCandidateScan(observed)
	if err != nil {
		t.Fatal(err)
	}
	eligible, count := compactCandidateEligibility(cmpctBlockPayload{ShortIDs: []compactShortID{x, x}}, [][32]byte{wtxid}, catalog)
	if count != 1 || eligible[x] != -1 {
		t.Fatalf("union=%d eligibility=%v want1,ineligible", count, eligible)
	}
	block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: prefill}}, ShortIDs: []compactShortID{{1}, {1}, {2}, {2}}}
	got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, nil)
	requireCompactCandidateZero(t, got, err, errCompactCandidateFault)
	if got.D4Complete || got.DistinctCollisionCount != 0 {
		t.Fatal("unknown D4 changed")
	}
	block.ShortIDs = make([]compactShortID, 4097)
	for i := range block.ShortIDs {
		if i%2 == 0 {
			block.ShortIDs[i] = compactShortID{1}
		} else {
			block.ShortIDs[i] = compactShortID{2}
		}
	}
	got, err = reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
	requireCompactCandidateZero(t, got, err, errCompactRelayMissingRequestTooLarge)
	if !got.D4Complete || got.DistinctCollisionCount != 2 {
		t.Fatalf("completed D4 fallback=%+v", got)
	}
	large := newCompactCandidateFixture(t, 1)
	resourceBlock := cmpctBlockPayload{Prefilled: compactCandidateLargePrefills(large.raw[0]), ShortIDs: []compactShortID{{1}, {1}, {2}, {2}}}
	got, err = reconstructCompactCandidates(resourceBlock, 1, 72_000_000, large.pool, large.da)
	requireCompactCandidateZero(t, got, err, errCompactCandidateResource)
	if !got.D4Complete || got.DistinctCollisionCount != 2 {
		t.Fatal("resource fallback lost completed collision union")
	}
	got, err = reconstructCompactCandidates(resourceBlock, 1, 80_000_000, large.pool, large.da)
	if err != nil || !got.D4Complete || got.DistinctCollisionCount != 2 || len(got.Result.MissingIndexes) != 4 {
		t.Fatal("higher valid B failed or changed collision/count policy")
	}
	block.ShortIDs = []compactShortID{{3}}
	got, err = reconstructCompactCandidates(block, 1, 80_000_000, f.pool, f.da)
	if err != nil || !got.D4Complete || got.DistinctCollisionCount != 0 {
		t.Fatal("genuine zero differs from unknown")
	}
}

func TestCompactCandidateDormantBoundary(t *testing.T) {
	f := newCompactCandidateFixture(t, 1)
	block := cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: minimalBlockTxnTestTxBytes(77)}}, ShortIDs: []compactShortID{compactShortIDForTx(t, f.raw[0], 0, 0)}}
	component, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
	if err != nil || len(component.Result.Transactions) != 2 {
		t.Fatal("dormant component failed")
	}
	legacy, err := reconstructCompactBlock(block, compactRelayLocalTransactionsForBlock(block, NewMemoryTxPool()))
	if err != nil || !reflect.DeepEqual(legacy.MissingIndexes, []uint64{1}) {
		t.Fatal("actual legacy Memory collector changed")
	}
}

func BenchmarkCompactReconstructW20000(b *testing.B) { benchmarkCompactCandidates(b, 20000, 4000) }
func BenchmarkCompactReconstructW1000(b *testing.B)  { benchmarkCompactCandidates(b, 1000, 1000) }

type compactBenchmarkRecord struct {
	Raw      []byte
	Outpoint consensus.Outpoint
	UTXO     consensus.UtxoEntry
}

func compactCandidateBenchmarkFixture(b *testing.B, population int) compactCandidateFixture {
	b.Helper()
	dir := os.Getenv("RUBIN_COMPACT_BENCH_FIXTURE_DIR")
	if dir == "" {
		b.Fatal("RUBIN_COMPACT_BENCH_FIXTURE_DIR must name the shared temporary dataset directory")
	}
	path := filepath.Join(dir, fmt.Sprintf("compact-%d.json", population))
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		f := newCompactCandidateFixture(b, population, true)
		records := make([]compactBenchmarkRecord, population)
		for i, raw := range f.raw {
			tx, _, _, _, err := consensus.ParseTx(raw)
			if err != nil {
				b.Fatal(err)
			}
			op := consensus.Outpoint{Txid: tx.Inputs[0].PrevTxid, Vout: tx.Inputs[0].PrevVout}
			records[i] = compactBenchmarkRecord{Raw: raw, Outpoint: op, UTXO: f.state.Utxos[op]}
		}
		data, err = json.Marshal(records)
		if err != nil {
			b.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			b.Fatal(err)
		}
		b.Logf("resident_dataset population=%d sha256=%x", population, sha256.Sum256(data))
		return f
	}
	if err != nil {
		b.Fatal(err)
	}
	var records []compactBenchmarkRecord
	if err := json.Unmarshal(data, &records); err != nil {
		b.Fatal(err)
	}
	if len(records) != population {
		b.Fatalf("resident dataset count=%d want%d", len(records), population)
	}
	f := newCompactCandidateOwners(b, population)
	for _, record := range records {
		tx, txid, wtxid, consumed, err := consensus.ParseTx(record.Raw)
		if err != nil || consumed != len(record.Raw) || len(tx.Inputs) != 1 {
			b.Fatal("noncanonical resident dataset row")
		}
		if (consensus.Outpoint{Txid: tx.Inputs[0].PrevTxid, Vout: tx.Inputs[0].PrevVout}) != record.Outpoint {
			b.Fatal("dataset UTXO association changed")
		}
		f.state.Utxos[record.Outpoint] = record.UTXO
		f.raw = append(f.raw, record.Raw)
		f.ids = append(f.ids, node.CompactCandidateIdentity{TxID: txid, WTxID: wtxid})
	}
	for i := len(f.raw) - 1; i >= 0; i-- {
		if err := f.mp.AddTx(f.raw[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.Logf("resident_dataset population=%d sha256=%x", population, sha256.Sum256(data))
	return f
}

func benchmarkCompactCandidates(b *testing.B, population, entries int) {
	f := compactCandidateBenchmarkFixture(b, population)
	block := cmpctBlockPayload{Nonce1: 4, Nonce2: 5, Prefilled: []prefilledTxn{{Index: 0, Tx: minimalBlockTxnTestTxBytes(77)}}}
	for i := 0; i < entries-1; i++ {
		block.ShortIDs = append(block.ShortIDs, compactShortID(consensus.CompactShortID(f.ids[population-1-i].WTxID, 4, 5)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := reconstructCompactCandidates(block, 1, 72_000_000, f.pool, f.da)
		if err != nil || len(got.Result.Transactions) != entries {
			b.Fatalf("candidate=%d err=%v", len(got.Result.Transactions), err)
		}
	}
}

func TestReconstructCompactBlockCompletesExactPositionsFromWTxID(t *testing.T) {
	nonce1, nonce2 := uint64(0x0102030405060708), uint64(0x1112131415161718)
	prefilledTx := minimalBlockTxnTestTxBytes(1)
	tx2 := minimalBlockTxnTestTxBytes(2)
	tx3 := minimalBlockTxnTestTxBytes(3)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, tx2, nonce1, nonce2), compactShortIDForTx(t, tx3, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{tx3, tx2})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	want := [][]byte{prefilledTx, tx2, tx3}
	if !reflect.DeepEqual(result.Transactions, want) || len(result.MissingIndexes) != 0 {
		t.Fatalf("result=%+v want txs=%v", result, want)
	}

	tx2[0] ^= 0xff
	if reflect.DeepEqual(result.Transactions[1], tx2) {
		t.Fatal("result aliases local transaction bytes")
	}
	prefilledTx[0] ^= 0xff
	if reflect.DeepEqual(result.Transactions[0], prefilledTx) {
		t.Fatal("result aliases prefilled transaction bytes")
	}
}

func TestReconstructCompactBlockReportsAbsoluteMissingIndexes(t *testing.T) {
	nonce1, nonce2 := uint64(4), uint64(5)
	tx1 := minimalBlockTxnTestTxBytes(11)
	tx2 := minimalBlockTxnTestTxBytes(12)
	tx3 := minimalBlockTxnTestTxBytes(13)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, tx1, nonce1, nonce2), compactShortIDForTx(t, tx3, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 1, Tx: tx2},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{tx3})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{0}) || result.Transactions != nil {
		t.Fatalf("missing=%v txs=%v, want absolute missing [0] and no completed block", result.MissingIndexes, result.Transactions)
	}
}

func TestReconstructCompactBlockDoesNotUseTxIDShortIDs(t *testing.T) {
	nonce1, nonce2 := uint64(6), uint64(7)
	prefilledTx := minimalBlockTxnTestTxBytes(21)
	localTx := minimalBlockTxnTestTxBytes(22)
	_, txid, _, consumed, err := consensus.ParseTx(localTx)
	if err != nil || consumed != len(localTx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortID(consensus.CompactShortID(txid, nonce1, nonce2))},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{localTx})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want missing absolute index 1 from TXID short ID mismatch", result)
	}
}

func TestReconstructCompactBlockFailsClosedOnDuplicatePayloadShortIDs(t *testing.T) {
	nonce1, nonce2 := uint64(8), uint64(9)
	prefilledTx := minimalBlockTxnTestTxBytes(31)
	localTx := minimalBlockTxnTestTxBytes(32)
	shortID := compactShortIDForTx(t, localTx, nonce1, nonce2)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{shortID, shortID},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{localTx})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1, 2}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want duplicate short IDs as bounded missing indexes", result)
	}
}

func TestReconstructCompactBlockFailsClosedOnAmbiguousLocalShortID(t *testing.T) {
	nonce1, nonce2 := uint64(8), uint64(9)
	prefilledTx := minimalBlockTxnTestTxBytes(31)
	localTx := minimalBlockTxnTestTxBytes(32)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, localTx, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{localTx, append([]byte(nil), localTx...)})
	if err != nil {
		t.Fatalf("reconstructCompactBlock duplicate local: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want ambiguous local short ID as missing index", result)
	}
}

func TestReconstructCompactBlockFailsClosedOnPrefilledShortIDCollision(t *testing.T) {
	nonce1, nonce2 := uint64(8), uint64(9)
	prefilledTx := minimalBlockTxnTestTxBytes(31)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, prefilledTx, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{prefilledTx})
	if err != nil {
		t.Fatalf("reconstructCompactBlock prefilled collision: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want prefilled short ID collision as missing index", result)
	}
}

func TestReconstructCompactBlockRejectsMalformedInputs(t *testing.T) {
	validTx := minimalBlockTxnTestTxBytes(41)
	shortID := compactShortIDForTx(t, validTx, 1, 2)
	for _, tc := range []struct {
		name    string
		payload cmpctBlockPayload
		local   [][]byte
		wantErr string
	}{
		{
			name:    "out_of_range_prefilled",
			payload: cmpctBlockPayload{ShortIDs: []compactShortID{shortID}, Prefilled: []prefilledTxn{{Index: 2, Tx: validTx}}},
			wantErr: "compact relay index out of range",
		},
		{
			name:    "duplicate_prefilled",
			payload: cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: validTx}, {Index: 0, Tx: validTx}}},
			wantErr: "compact relay index out of range",
		},
		{
			name:    "unsorted_prefilled",
			payload: cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 1, Tx: validTx}, {Index: 0, Tx: validTx}}},
			wantErr: "compact relay index out of range",
		},
		{
			name:    "noncanonical_prefilled",
			payload: cmpctBlockPayload{ShortIDs: []compactShortID{shortID}, Prefilled: []prefilledTxn{{Index: 0, Tx: append(validTx, 0x00)}}},
			wantErr: "cmpctblock prefilled transaction is non-canonical",
		},
	} {
		_, err := reconstructCompactBlock(tc.payload, tc.local)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: err=%v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestReconstructCompactBlockFailsClosedWhenMissingRequestExceedsCap(t *testing.T) {
	exact, err := reconstructCompactBlock(cmpctBlockPayload{ShortIDs: make([]compactShortID, maxCompactRelayEntries)}, nil)
	if err != nil || len(exact.MissingIndexes) != maxCompactRelayEntries {
		t.Fatalf("exact max result=%+v err=%v", exact, err)
	}
	_, err = reconstructCompactBlock(cmpctBlockPayload{
		ShortIDs: make([]compactShortID, maxCompactRelayEntries+1),
	}, nil)
	if !errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		t.Fatalf("overflow err=%v", err)
	}
	if exact.MissingIndexes[0] != 0 || exact.MissingIndexes[len(exact.MissingIndexes)-1] != maxCompactRelayEntries-1 {
		t.Fatalf("missing bounds got first=%d last=%d", exact.MissingIndexes[0], exact.MissingIndexes[len(exact.MissingIndexes)-1])
	}
}

func TestCompactFillShortIDTransactionsRejectsCumulativeOversize(t *testing.T) {
	shortID := compactShortID{0x51}
	txs := [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES), nil}
	err := compactFillShortIDTransactions(
		txs,
		2,
		[]prefilledTxn{{Index: 0, Tx: txs[0]}},
		[]compactShortID{shortID},
		map[compactShortID][]byte{shortID: {0x01}},
	)
	if err == nil || !strings.Contains(err.Error(), "blocktxn transactions exceed block size") {
		t.Fatalf("compactFillShortIDTransactions err=%v, want cumulative size failure", err)
	}
	if txs[1] != nil {
		t.Fatalf("compactFillShortIDTransactions mutated short-id tx before validation: %x", txs[1])
	}
}

func TestCompactFillShortIDTransactionsDoesNotDoubleCountPrefilledBytes(t *testing.T) {
	prefilledTx := minimalBlockTxnTestTxBytes(50)
	shortTx := minimalBlockTxnTestTxBytes(51)
	shortID := compactShortID{0x51}
	txs := [][]byte{prefilledTx, nil}
	err := compactFillShortIDTransactions(
		txs,
		2,
		[]prefilledTxn{{Index: 0, Tx: prefilledTx}},
		[]compactShortID{shortID},
		map[compactShortID][]byte{shortID: shortTx},
	)
	if err != nil {
		t.Fatalf("compactFillShortIDTransactions double-counted prefilled bytes: %v", err)
	}
	if !reflect.DeepEqual(txs[1], shortTx) {
		t.Fatalf("filled tx=%x, want %x", txs[1], shortTx)
	}
	prefilledTx[0], shortTx[0] = 0xff, 0xee
	if txs[0][0] == 0xff || txs[1][0] == 0xee {
		t.Fatal("filled txs alias source bytes")
	}
}

func TestCompactFillShortIDTransactionsRejectsInvalidCompletionShapes(t *testing.T) {
	shortID := compactShortID{0x61}
	if err := compactFillShortIDTransactions(make([][]byte, 1), 1, nil, []compactShortID{shortID}, nil); err == nil || !strings.Contains(err.Error(), "compact block transaction missing") {
		t.Fatalf("missing short-id err=%v, want missing", err)
	}
	if err := compactFillShortIDTransactions(make([][]byte, maxCompactRelayEntries+1), maxCompactRelayEntries+1, nil, make([]compactShortID, maxCompactRelayEntries+1), nil); !errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		t.Fatalf("overflow err=%v", err)
	}
	txs := make([][]byte, 2)
	err := compactFillShortIDTransactions(txs, 2, nil, []compactShortID{shortID}, map[compactShortID][]byte{shortID: minimalBlockTxnTestTxBytes(60)})
	if err == nil || !strings.Contains(err.Error(), "compact block transaction missing") {
		t.Fatalf("incomplete staged txs err=%v, want completion failure", err)
	}
}

func TestCompactFillOrCollectMissingRecomputesSizeAfterDuplicateReclassification(t *testing.T) {
	dup := compactShortID{0x01}
	later := compactShortID{0x02}
	txs := make([][]byte, 3)
	missing, _, overflow, err := compactFillOrCollectMissing(
		txs,
		3,
		nil,
		[]compactShortID{dup, later, dup},
		map[compactShortID][]byte{
			dup:   make([]byte, consensus.MAX_BLOCK_BYTES),
			later: {0x01},
		},
		nil,
	)
	if err != nil || overflow {
		t.Fatalf("compactFillOrCollectMissing duplicate reclassification err=%v overflow=%v", err, overflow)
	}
	if !reflect.DeepEqual(missing, []uint64{0, 2}) || txs[0] != nil || !reflect.DeepEqual(txs[1], []byte{0x01}) {
		t.Fatalf("missing=%v txs[0]=%v txs[1]=%v, want late duplicate missing and intervening tx retained", missing, txs[0], txs[1])
	}
}

func TestCompactLocalTxIndexUsesBoundedPerCandidateValidation(t *testing.T) {
	nonce1, nonce2 := uint64(51), uint64(52)
	validTx := minimalBlockTxnTestTxBytes(53)
	localIndex, err := compactLocalTxIndex([][]byte{validTx}, nonce1, nonce2)
	if err != nil {
		t.Fatalf("compactLocalTxIndex: %v", err)
	}
	shortID := compactShortIDForTx(t, validTx, nonce1, nonce2)
	if !reflect.DeepEqual(localIndex[shortID], validTx) {
		t.Fatalf("localIndex[%v]=%x want %x", shortID, localIndex[shortID], validTx)
	}

	localIndex, err = compactLocalTxIndex([][]byte{append(minimalBlockTxnTestTxBytes(54), 0x00), validTx}, nonce1, nonce2)
	if err != nil {
		t.Fatalf("compactLocalTxIndex with noncanonical candidate: %v", err)
	}
	if !reflect.DeepEqual(localIndex[shortID], validTx) || len(localIndex) != 1 {
		t.Fatalf("localIndex after noncanonical candidate=%+v, want only valid candidate", localIndex)
	}
}

func TestNewCompactOutstandingRequestBuildsPartialState(t *testing.T) {
	tx := minimalBlockTxnTestTxBytes(90)
	shortID := compactShortIDForTx(t, tx, 91, 92)
	blockHash := [32]byte{0x33}
	block := cmpctBlockPayload{Header: [consensus.BLOCK_HEADER_BYTES]byte{0x44}, Nonce1: 91, Nonce2: 92}
	result := compactReconstructionResult{PartialTransactions: [][]byte{nil, tx}, MissingIndexes: []uint64{0}, MissingShortIDs: []compactShortID{shortID}}
	req, err := newCompactOutstandingRequest(block, blockHash, result)
	if err != nil {
		t.Fatalf("newCompactOutstandingRequest: %v", err)
	}
	wantPayloadCap := uint32(32 + len(consensus.EncodeCompactSize(1)) + maxCompactSizeBytes + consensus.MAX_BLOCK_BYTES - len(tx))
	if req.BlockHash != blockHash || req.Header != block.Header || req.Nonce1 != block.Nonce1 || req.Nonce2 != block.Nonce2 || req.BlockTxnPayloadCap != wantPayloadCap {
		t.Fatalf("request metadata mismatch: %+v", req)
	}
	if !reflect.DeepEqual(req.MissingIndexes, []uint64{0}) || !reflect.DeepEqual(req.MissingShortIDs, []compactShortID{shortID}) || !reflect.DeepEqual(req.Transactions, [][]byte{nil, tx}) {
		t.Fatalf("request state mismatch: %+v", req)
	}
	if _, err := newCompactOutstandingRequest(block, blockHash, compactReconstructionResult{}); err == nil {
		t.Fatal("empty missing request should fail")
	}
	if _, err := newCompactOutstandingRequest(block, blockHash, compactReconstructionResult{MissingIndexes: []uint64{0}}); err == nil {
		t.Fatal("mismatched missing short-id request should fail")
	}
	if _, err := newCompactOutstandingRequest(block, blockHash, compactReconstructionResult{PartialTransactions: [][]byte{tx}, MissingIndexes: []uint64{0}, MissingShortIDs: []compactShortID{shortID}}); err == nil {
		t.Fatal("non-missing partial slot should fail")
	}
}

func TestCompactMissingRequestCapPrecedesPartialTableAllocation(t *testing.T) {
	shortIDs := make([]compactShortID, maxCompactRelayEntries+1)
	_, _, overflow, err := compactFillOrCollectMissing(nil, len(shortIDs), nil, shortIDs, nil, nil)
	if err != nil || !overflow {
		t.Fatal("missing-heavy compact block should hit request cap before partial table allocation")
	}
}

func TestCompactBlockTxnResponsePayloadCapUsesRemainingBudget(t *testing.T) {
	tx := minimalBlockTxnTestTxBytes(93)
	cap, err := compactBlockTxnResponsePayloadCap([][]byte{tx, nil}, 1)
	if err != nil {
		t.Fatalf("compactBlockTxnResponsePayloadCap: %v", err)
	}
	want := uint32(32 + len(consensus.EncodeCompactSize(1)) + maxCompactSizeBytes + consensus.MAX_BLOCK_BYTES - len(tx))
	if cap != want || cap >= compactRelayPayloadCap(messageBlockTxn) {
		t.Fatalf("cap=%d want=%d and below global cap %d", cap, want, compactRelayPayloadCap(messageBlockTxn))
	}
	wantFull := uint32(32 + len(consensus.EncodeCompactSize(maxCompactRelayEntries)) + maxCompactRelayEntries*maxCompactSizeBytes + consensus.MAX_BLOCK_BYTES)
	if full, err := compactBlockTxnResponsePayloadCap(nil, maxCompactRelayEntries); err != nil || full != wantFull || full >= compactRelayPayloadCap(messageBlockTxn) {
		t.Fatalf("full missing cap=%d err=%v want %d below global %d", full, err, wantFull, compactRelayPayloadCap(messageBlockTxn))
	}
}

func TestCompactFillResponseTransactionsValidatesExpectedShortIDs(t *testing.T) {
	blockHash := [32]byte{0x71}
	nonce1, nonce2 := uint64(71), uint64(72)
	tx1 := minimalBlockTxnTestTxBytes(73)
	tx2 := minimalBlockTxnTestTxBytes(74)
	req := compactOutstandingRequest{
		BlockHash:       blockHash,
		Transactions:    [][]byte{nil, tx2},
		MissingIndexes:  []uint64{0},
		MissingShortIDs: []compactShortID{compactShortIDForTx(t, tx1, nonce1, nonce2)},
		Nonce1:          nonce1,
		Nonce2:          nonce2,
	}
	response := blockTxnRuntimePayload{BlockHash: blockHash, Transactions: [][]byte{tx1}, WTxIDs: [][32]byte{compactWTxIDForTx(t, tx1)}}
	filled, err := compactFillResponseTransactions(req, response)
	if err != nil {
		t.Fatalf("compactFillResponseTransactions: %v", err)
	}
	tx1[0] ^= 0xff
	if filled[0][0] == tx1[0] {
		t.Fatal("filled blocktxn response aliases source bytes")
	}
	wrongShortIDResponse := blockTxnRuntimePayload{BlockHash: blockHash, Transactions: [][]byte{tx2}, WTxIDs: [][32]byte{compactWTxIDForTx(t, tx2)}}
	if _, err := compactFillResponseTransactions(req, wrongShortIDResponse); err == nil || !strings.Contains(err.Error(), "short id mismatch") {
		t.Fatalf("wrong short ID err=%v, want short id mismatch", err)
	}
	mismatchedWTxIDResponse := blockTxnRuntimePayload{BlockHash: blockHash, Transactions: [][]byte{tx2}, WTxIDs: [][32]byte{compactWTxIDForTx(t, filled[0])}}
	if _, err := compactFillResponseTransactions(req, mismatchedWTxIDResponse); err == nil || !strings.Contains(err.Error(), "wtxid mismatch") {
		t.Fatalf("mismatched response wtxid err=%v, want wtxid mismatch", err)
	}
	wrongHashResponse := response
	wrongHashResponse.BlockHash[0] ^= 0xff
	if _, err := compactFillResponseTransactions(req, wrongHashResponse); err == nil || !strings.Contains(err.Error(), "block hash mismatch") {
		t.Fatalf("wrong response block hash err=%v, want block hash mismatch", err)
	}
}

func TestCompactFillResponseTransactionsRejectsAggregateOversize(t *testing.T) {
	nonce1, nonce2 := uint64(81), uint64(82)
	wtxid := [32]byte{0x01}
	req := compactOutstandingRequest{
		Transactions:    [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES), nil},
		MissingIndexes:  []uint64{1},
		MissingShortIDs: []compactShortID{compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))},
		Nonce1:          nonce1,
		Nonce2:          nonce2,
	}
	_, err := compactFillResponseTransactions(req, blockTxnRuntimePayload{Transactions: [][]byte{{0x01}}, WTxIDs: [][32]byte{wtxid}})
	if err == nil || !strings.Contains(err.Error(), "blocktxn transactions exceed block size") {
		t.Fatalf("aggregate oversize err=%v, want block size rejection", err)
	}
}

func TestReconstructCompactBlockSkipsLocalLookupForPrefilledOnlyBlock(t *testing.T) {
	validTx := minimalBlockTxnTestTxBytes(61)
	result, err := reconstructCompactBlock(cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: validTx}}}, [][]byte{{0xff}})
	if err != nil {
		t.Fatalf("prefilled-only compact block should not index local candidates: %v", err)
	}
	if !reflect.DeepEqual(result.Transactions, [][]byte{validTx}) || result.MissingIndexes != nil {
		t.Fatalf("result=%+v, want prefilled-only reconstruction", result)
	}
}

func TestHandleBlockTxnMalformedAndLateResponses(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newPeerRuntimeTestPeer(t)
	if err := p.handleBlockTxn(nil); err == nil || !strings.Contains(err.Error(), "missing block hash") || p.snapshotState().BanScore == 0 {
		t.Fatalf("short blocktxn err=%v state=%+v", err, p.snapshotState())
	}

	p = newPeerRuntimeTestPeer(t)
	if err := p.handleBlockTxn(make([]byte, 32)); err != nil || p.snapshotState().BanScore != 0 || !strings.Contains(p.snapshotState().LastError, "ignored unexpected blocktxn") {
		t.Fatalf("unexpected blocktxn err=%v state=%+v, want diagnostic without ban", err, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	if err := p.handleBlockTxn(make([]byte, 32)); err != nil || p.snapshotState().BanScore != 0 || !strings.Contains(p.snapshotState().LastError, "ignored stale blocktxn") {
		t.Fatalf("wrong hash blocktxn err=%v state=%+v, want stale diagnostic without ban", err, p.snapshotState())
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); !ok {
		t.Fatal("stale blocktxn response cleared active outstanding request")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("stale blocktxn response sent fallback")
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	malformed := append(blockHash[:], 0xff)
	if err := p.handleBlockTxn(malformed); err == nil || p.snapshotState().BanScore == 0 {
		t.Fatalf("malformed blocktxn err=%v state=%+v", err, p.snapshotState())
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("malformed blocktxn did not clear matching outstanding request")
	}
}

func TestHandleBlockTxnStaleBodyDisconnectsWithoutBan(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	p.compact.outstanding.Transactions = [][]byte{txs[0]}
	txAlias := p.compact.outstanding.Transactions[0]
	stale := make([]byte, int(p.blockTxnPayloadCap()))
	err := p.handleBlockTxn(stale)
	requireBlockTxnStaleBodyError(t, err)
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("state=%+v, want no-ban disconnect", p.snapshotState())
	}
	if p.blockTxnPayloadCap() == 0 {
		t.Fatal("near-cap stale blocktxn lost active blocktxn payload cap")
	}
	if &txs[0][0] != &txAlias[0] {
		t.Fatal("near-cap stale blocktxn cloned outstanding transaction bytes")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("near-cap stale blocktxn sent fallback")
	}
}

func TestHandleBlockTxnMatchingPayloadCapOverflowBans(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	p.compact.outstanding.BlockTxnPayloadCap = 64
	payload := append(blockHash[:], make([]byte, 33)...)
	if err := p.handleBlockTxn(payload); err == nil || err.Error() != "blocktxn payload exceeds outstanding cap" {
		t.Fatalf("handleBlockTxn err=%v, want outstanding cap error", err)
	}
	state := p.snapshotState()
	if state.BanScore == 0 || !strings.Contains(state.LastError, "blocktxn payload exceeds outstanding cap") {
		t.Fatalf("state=%+v, want outstanding cap ban", state)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("matching payload cap overflow left outstanding request")
	}
}

func TestRunRoutesNegotiatedGetBlockTxn(t *testing.T) {
	_, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	p.markCompactBlockAnnounced(blockHash)
	payload := mustEncodeGetBlockTxnRequest(t, blockHash, []uint64{0})
	p.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageGetBlockTxn, Payload: payload})}}}

	requireNoCompactErr(t, p.run(context.Background()), "run getblocktxn")
	frame := requireCompactFrame(t, p, messageBlockTxn)
	got, err := decodeBlockTxnPayload(frame.Payload)
	requireNoCompactErr(t, err, "decode served blocktxn")
	if got.BlockHash != blockHash || len(got.Transactions) != 1 || !bytes.Equal(got.Transactions[0], txs[0]) {
		t.Fatalf("served blocktxn=%+v, want hash %x and requested tx", got, blockHash)
	}
}

func TestHandleGetBlockTxnRejectsDuplicateBeforeBlockLookup(t *testing.T) {
	p := newCompactScriptedPeer(t)
	p.service.cfg.BlockStore = nil
	payload := mustEncodeGetBlockTxnRequest(t, [32]byte{0x42}, []uint64{0, 0})

	err := p.handleGetBlockTxn(payload)
	if err == nil || !strings.Contains(err.Error(), "duplicate getblocktxn index") {
		t.Fatalf("handleGetBlockTxn duplicate err=%v, want duplicate index", err)
	}
	if p.snapshotState().BanScore == 0 {
		t.Fatal("duplicate getblocktxn did not bump ban before block lookup")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("duplicate getblocktxn sent a response")
	}
}

func TestHandleGetBlockTxnMalformedAndMissingBlock(t *testing.T) {
	p := newCompactScriptedPeer(t)
	if err := p.handleGetBlockTxn(make([]byte, 31)); err == nil || !strings.Contains(err.Error(), "getblocktxn payload missing block hash") {
		t.Fatalf("short getblocktxn err=%v, want missing block hash", err)
	}
	if p.snapshotState().BanScore == 0 {
		t.Fatal("malformed getblocktxn did not bump ban")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("malformed getblocktxn sent a response")
	}

	p = newCompactScriptedPeer(t)
	payload := mustEncodeGetBlockTxnRequest(t, [32]byte{0x99}, []uint64{0})
	p.markCompactBlockAnnounced([32]byte{0x99})
	if err := p.handleGetBlockTxn(payload); err != nil {
		t.Fatalf("missing block getblocktxn err=%v, want nil", err)
	}
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("missing block ban_score=%d, want 0", p.snapshotState().BanScore)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("missing block getblocktxn sent a response")
	}
}

func TestHandleGetBlockTxnRejectsOutOfRangeAfterBlockCount(t *testing.T) {
	_, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	p.markCompactBlockAnnounced(blockHash)
	payload := mustEncodeGetBlockTxnRequest(t, blockHash, []uint64{uint64(len(txs))})

	err := p.handleGetBlockTxn(payload)
	if err == nil || !strings.Contains(err.Error(), "getblocktxn index out of range") {
		t.Fatalf("handleGetBlockTxn out-of-range err=%v, want range error", err)
	}
	if p.snapshotState().BanScore == 0 {
		t.Fatal("out-of-range getblocktxn did not bump ban")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("out-of-range getblocktxn sent a response")
	}
}

func TestHandleGetBlockTxnRequiresCompactAnnouncement(t *testing.T) {
	_, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload := mustEncodeGetBlockTxnRequest(t, blockHash, []uint64{0})
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")

	if err := p.handleGetBlockTxn(payload); err != nil {
		t.Fatalf("unannounced getblocktxn err=%v, want nil", err)
	}
	state := p.snapshotState()
	if state.BanScore != 0 || !strings.Contains(state.LastError, "ignored unannounced getblocktxn request") {
		t.Fatalf("unannounced getblocktxn state=%+v, want no-ban diagnostic", state)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("unannounced getblocktxn sent a response")
	}

	p.markCompactBlockAnnounced(blockHash)
	requireNoCompactErr(t, p.handleGetBlockTxn(payload), "announced getblocktxn")
	frame := requireCompactFrame(t, p, messageBlockTxn)
	got, err := decodeBlockTxnPayload(frame.Payload)
	requireNoCompactErr(t, err, "decode announced blocktxn")
	if got.BlockHash != blockHash || len(got.Transactions) != 1 || !bytes.Equal(got.Transactions[0], txs[0]) {
		t.Fatalf("announced blocktxn=%+v, want hash %x and requested tx", got, blockHash)
	}

	p.conn.(*scriptedConn).Buffer.Reset()
	requireNoCompactErr(t, p.handleGetBlockTxn(payload), "consumed getblocktxn announcement")
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("consumed getblocktxn announcement allowed a repeated response")
	}
}

func TestHandleGetBlockTxnIgnoresUnannouncedBeforeBlockLookup(t *testing.T) {
	p := newCompactScriptedPeer(t)
	p.service.cfg.BlockStore = nil
	payload := mustEncodeGetBlockTxnRequest(t, [32]byte{0x42}, []uint64{0})

	if err := p.handleGetBlockTxn(payload); err != nil {
		t.Fatalf("unannounced getblocktxn with nil blockstore err=%v, want nil before lookup", err)
	}
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("unannounced getblocktxn ban_score=%d, want 0", p.snapshotState().BanScore)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("unannounced getblocktxn with nil blockstore sent a response")
	}
}

func TestCompactValidateUniqueGetBlockTxnIndexesAcceptsDistinct(t *testing.T) {
	if err := compactValidateUniqueGetBlockTxnIndexes([]uint64{2, 0, 1}); err != nil {
		t.Fatalf("compactValidateUniqueGetBlockTxnIndexes: %v", err)
	}
}

func TestCompactBlockTransactionsByIndexPreservesRequestOrder(t *testing.T) {
	txs := [][]byte{
		minimalBlockTxnTestTxBytes(301),
		minimalBlockTxnTestTxBytes(302),
		minimalBlockTxnTestTxBytes(303),
	}
	block := compactTestBlockBytesWithTxs(t, txs)

	got, err := compactBlockTransactionsByIndex(block, []uint64{2, 0, 1})
	requireNoCompactErr(t, err, "slice compact block transactions")
	want := [][]byte{txs[2], txs[0], txs[1]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered txs=%x, want %x", got, want)
	}
}

func TestCompactBlockTransactionsByIndexHandlesEmptyRequest(t *testing.T) {
	got, err := compactBlockTransactionsByIndex(node.DevnetGenesisBlockBytes(), nil)
	requireNoCompactErr(t, err, "empty getblocktxn request")
	if len(got) != 0 {
		t.Fatalf("empty request returned %d txs, want 0", len(got))
	}
}

func TestCompactBlockTransactionsByIndexRejectsRangeBeforeScanningTx(t *testing.T) {
	genesis := node.DevnetGenesisBlockBytes()
	block := append([]byte(nil), genesis[:consensus.BLOCK_HEADER_BYTES]...)
	block = consensus.AppendCompactSize(block, 1)
	block = append(block, 0xff)

	_, err := compactBlockTransactionsByIndex(block, []uint64{1})
	if err == nil || !strings.Contains(err.Error(), "getblocktxn index out of range") {
		t.Fatalf("compactBlockTransactionsByIndex err=%v, want range before tx parse", err)
	}
}

func TestCompactBlockTransactionsByIndexStopsAfterHighestRequested(t *testing.T) {
	txs := [][]byte{minimalBlockTxnTestTxBytes(501), {0xff}}
	block := compactTestBlockBytesWithRawTxTail(t, txs, nil)

	got, err := compactBlockTransactionsByIndex(block, []uint64{0})
	requireNoCompactErr(t, err, "slice early requested tx")
	if len(got) != 1 || !bytes.Equal(got[0], txs[0]) {
		t.Fatalf("early requested tx=%x, want %x", got, txs[0])
	}
}

func TestCompactBlockTransactionsByIndexRejectsMalformedStoredBlocks(t *testing.T) {
	txs := [][]byte{minimalBlockTxnTestTxBytes(401)}
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "short_header", raw: make([]byte, consensus.BLOCK_HEADER_BYTES-1), want: "stored block missing header"},
		{name: "bad_count", raw: append(make([]byte, consensus.BLOCK_HEADER_BYTES), 0xfd), want: "TX_ERR_PARSE"},
		{name: "bad_tx", raw: compactTestBlockBytesWithRawTxTail(t, [][]byte{{0xff}}, nil), want: "stored block transaction is non-canonical"},
		{name: "trailing", raw: compactTestBlockBytesWithRawTxTail(t, txs, []byte{0x00}), want: "stored block has trailing bytes after transactions"},
	} {
		_, err := compactBlockTransactionsByIndex(tc.raw, []uint64{0})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s err=%v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestHandleCmpctBlockIgnoresMalformedLocalCandidates(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	shortID := compactShortIDForTx(t, txs[0], 201, 202)
	pool := NewMemoryTxPoolWithLimit(1)
	pool.txs[[32]byte{0x42}] = &relayTxEntry{raw: append(txs[0], 0x00), fee: consensus.Uint128FromU64(1), size: len(txs[0]) + 1}
	p := newCompactScriptedPeer(t)
	p.service.cfg.TxPool = pool
	payload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Nonce1: 201, Nonce2: 202, ShortIDs: []compactShortID{shortID}})

	if err := p.handleCmpctBlock(compactFrameLease(t, p, payload)); err != nil {
		t.Fatalf("handleCmpctBlock with malformed local candidate: %v", err)
	}
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("ban_score=%d, want 0 for local candidate corruption", p.snapshotState().BanScore)
	}
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockHash != blockHash || len(snap.MissingIndexes) != 1 {
		t.Fatalf("outstanding=%+v ok=%v, want getblocktxn request for missing compact tx", snap, ok)
	}
	requireCompactFrame(t, p, messageGetBlockTxn)
}

func TestInternalHandleBlockTxnCompletesOutstandingBlock(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	valid, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")
	requireNoCompactErr(t, p.handleBlockTxn(valid), "handle blocktxn")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("outstanding request was not cleared")
	}
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestHandleCmpctBlockValidationAndFallbackEdges(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	full := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})
	missing := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, ShortIDs: []compactShortID{{0xaa}}})

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	requireNoCompactErr(t, p.handleCmpctBlock(compactFrameLease(t, p, full)), "already-have compact block")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("already-have compact block did not clear matching outstanding request")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("already-have compact block sent fallback")
	}

	tinyTarget := [32]byte{}
	tinyTarget[31] = 0x01
	powInvalidHeader := compactHeaderWithTarget(header, tinyTarget)
	p = newCompactScriptedPeer(t)
	err := p.handleCmpctBlock(compactFrameLease(t, p, mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: powInvalidHeader, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})))
	if err == nil || !strings.Contains(err.Error(), "pow invalid") || p.snapshotState().BanScore == 0 {
		t.Fatalf("pow-invalid compact header err=%v state=%+v", err, p.snapshotState())
	}

	wrongExpected := compactFilledTarget(0xee)
	p = newCompactScriptedPeer(t)
	// RUB-655: the static equality is now skipped under the stock devnet
	// predicate, so this row pins the unchanged non-stock behavior. The
	// predicate follows the ENGINE, so the engine is what must move off devnet.
	retargetPeerEngine(t, p, "regtest", node.DevnetGenesisChainID())
	p.service.cfg.SyncConfig.ExpectedTarget = &wrongExpected
	err = p.handleCmpctBlock(compactFrameLease(t, p, full))
	if err == nil || !strings.Contains(err.Error(), "target mismatch") || p.snapshotState().BanScore == 0 {
		t.Fatalf("target-mismatch compact header err=%v state=%+v", err, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 301, 302), 301, 302)
	requireNoCompactErr(t, p.handleCmpctBlock(compactFrameLease(t, p, missing)), "missing compact block with existing outstanding")
	requireCompactFrame(t, p, messageGetData)

	p = newCompactScriptedPeer(t)
	err = p.requestMissingCompactTransactions(cmpctBlockPayload{Header: header}, blockHash, compactReconstructionResult{
		PartialTransactions: [][]byte{nil},
		MissingIndexes:      []uint64{1},
		MissingShortIDs:     []compactShortID{{0x01}},
	})
	if err == nil || !strings.Contains(err.Error(), "compact relay index out of range") {
		t.Fatalf("invalid missing request err=%v, want index out of range", err)
	}
}

func TestCompactProcessErrorEdges(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, nil, true), "short-id assembly fallback")
	requireCompactFrame(t, p, messageGetData)
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("short-id assembly state=%+v, want no ban fallback", p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	if err := p.processCompactTransactions(blockHash, header, nil, false); err == nil || !strings.Contains(err.Error(), "compact block has no transactions") || p.snapshotState().BanScore == 0 {
		t.Fatalf("prefilled empty compact transactions err=%v state=%+v", err, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	if fallback, accepted, err := p.processCompactRelayedBlockWithFallback([32]byte{0x99}, node.DevnetGenesisBlockBytes(), true); !fallback || accepted || err != nil {
		t.Fatalf("mismatched expected hash fallback=%v accepted=%v err=%v", fallback, accepted, err)
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 401, 402), 401, 402)
	p.service.cfg.BlockStore = nil
	if fallback, accepted, err := p.processCompactRelayedBlockWithFallback(blockHash, node.DevnetGenesisBlockBytes(), true); fallback || accepted || err == nil {
		t.Fatalf("hasBlock error fallback=%v accepted=%v err=%v", fallback, accepted, err)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("hasBlock error did not clear matching compact outstanding request")
	}

	p = newCompactScriptedPeer(t)
	p.service.cfg.BlockStore = nil
	err := p.processCompactTransactions(blockHash, header, txs, true)
	if err == nil || !strings.Contains(err.Error(), "nil blockstore") {
		t.Fatalf("process compact transactions hasBlock err=%v, want nil blockstore", err)
	}
}

func TestRequestCompactFullBlockFallbackClearsOnlyMatchingOutstanding(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 901, 902), 901, 902)

	requireNoCompactErr(t, p.requestCompactFullBlockFallback(blockHash), "matching compact fallback")
	frame := requireCompactFrame(t, p, messageGetData)
	items, err := decodeInventoryVectors(frame.Payload)
	requireNoCompactErr(t, err, "decode matching fallback getdata")
	if len(items) != 1 || items[0].Type != MSG_BLOCK || items[0].Hash != blockHash {
		t.Fatalf("matching fallback inventory=%+v, want MSG_BLOCK %x", items, blockHash)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("matching compact fallback left outstanding request active")
	}

	activeHash := [32]byte{0x81}
	p = newCompactScriptedPeer(t)
	p.activateCompactOutstandingRequest(compactOutstandingTestRequest(activeHash))
	requireNoCompactErr(t, p.requestCompactFullBlockFallback(blockHash), "stale compact fallback")
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockHash != activeHash {
		t.Fatalf("stale compact fallback corrupted outstanding=%+v ok=%v", snap, ok)
	}
}

func TestCompactApplyErrorFallbackEdges(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	pb, parsedHash, err := parseRelayedBlock(blockBytes)
	requireNoCompactErr(t, err, "parse relayed block")
	if parsedHash != blockHash {
		t.Fatalf("parsed block hash=%x, want %x", parsedHash, blockHash)
	}

	p := newCompactScriptedPeer(t)
	fallback, accepted, err := p.compactApplyErrorFallback(pb, blockHash, blockBytes, node.ErrParentNotFound, false)
	requireNoCompactErr(t, err, "parent-not-found retain")
	if fallback || accepted || p.service.orphans.Len() != 1 {
		t.Fatalf("parent-not-found fallback=%v accepted=%v orphans=%d", fallback, accepted, p.service.orphans.Len())
	}

	p = newCompactScriptedPeer(t)
	applyErr := &consensus.TxError{Code: consensus.BLOCK_ERR_MERKLE_INVALID, Msg: "merkle mismatch"}
	fallback, accepted, err = p.compactApplyErrorFallback(pb, blockHash, blockBytes, applyErr, true)
	requireNoCompactErr(t, err, "consensus apply fallback")
	if !fallback || accepted || !strings.Contains(p.snapshotState().LastError, "merkle mismatch") {
		t.Fatalf("consensus fallback=%v accepted=%v state=%+v", fallback, accepted, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	errBoom := errors.New("local apply failure")
	fallback, accepted, err = p.compactApplyErrorFallback(pb, blockHash, blockBytes, errBoom, false)
	if fallback || accepted || !errors.Is(err, errBoom) || !strings.Contains(p.snapshotState().LastError, "local apply failure") {
		t.Fatalf("local apply fallback=%v accepted=%v err=%v state=%+v", fallback, accepted, err, p.snapshotState())
	}
}

func TestCompactBlockBytesRejectsInvalidAssembly(t *testing.T) {
	header, _, _ := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	cases := []struct {
		name string
		txs  [][]byte
		want string
	}{
		{name: "empty", txs: nil, want: "compact block has no transactions"},
		{name: "missing", txs: [][]byte{nil}, want: "compact block transaction missing"},
		{name: "empty_tx", txs: [][]byte{{}}, want: "blocktxn transaction is empty"},
		{name: "oversize_block", txs: [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES)}, want: "compact block exceeds block size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compactBlockBytes(header, tc.txs)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("compactBlockBytes err=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestCompactPrefilledParentNotFoundRetainsOrphanWithoutFallback(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	header, gotHash, txs := compactPartsFromBlockBytes(t, blockBytes)
	if gotHash != blockHash {
		t.Fatalf("block hash=%x, want %x", gotHash, blockHash)
	}

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, txs, false), "parent-not-found prefilled compact apply")
	if got := p.service.orphans.Len(); got != 1 {
		t.Fatalf("orphans.Len()=%d, want 1", got)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("parent-not-found compact apply sent full-block fallback")
	}
}

func TestCompactShortIDParentNotFoundFallsBackWithoutBlockSeen(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	header, gotHash, txs := compactPartsFromBlockBytes(t, blockBytes)
	if gotHash != blockHash {
		t.Fatalf("block hash=%x, want %x", gotHash, blockHash)
	}

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, txs, true), "parent-not-found short-id compact apply")
	requireCompactFrame(t, p, messageGetData)
	if got := p.service.orphans.Len(); got != 0 {
		t.Fatalf("orphans.Len()=%d, want 0 for short-id reconstructed bytes", got)
	}
	if p.service.blockSeen.Has(blockHash) {
		t.Fatal("short-id reconstructed orphan poisoned blockSeen")
	}
}

func TestRunRoutesNegotiatedCmpctBlock(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageCmpctBlock, Payload: payload})}}}

	requireNoCompactErr(t, p.run(context.Background()), "run cmpctblock")
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestRunRoutesOutstandingBlockTxn(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	p.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload})}}}

	requireNoCompactErr(t, p.run(context.Background()), "run blocktxn")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("outstanding request was not cleared")
	}
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestRunRoutesOutstandingBlockTxnAfterCompactModeDisabled(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 0, Version: compactRelayVersion})
	p.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload})}}}

	requireNoCompactErr(t, p.run(context.Background()), "run blocktxn after compact mode disabled")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("outstanding request was not cleared")
	}
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
	if state := p.snapshotState(); state.BanScore != 0 {
		t.Fatalf("state=%+v, want no ban for valid outstanding blocktxn after mode 0", state)
	}
}

func TestHandleBlockTxnFallsBackWithoutBanOnShortIDMismatch(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortID{0xbb}, 301, 302)
	valid, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")
	requireNoCompactErr(t, p.handleBlockTxn(valid), "mismatched blocktxn fallback")
	requireCompactFrame(t, p, messageGetData)
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("mismatched blocktxn state=%+v, want no ban", p.snapshotState())
	}
}

func TestHandleBlockTxnBansMalformedFillWithoutFallback(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 301, 302), 301, 302)
	payload, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0], txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")

	err = p.handleBlockTxn(payload)
	if err == nil || !strings.Contains(err.Error(), "transaction count mismatch") {
		t.Fatalf("malformed blocktxn fill err=%v, want transaction count mismatch", err)
	}
	state := p.snapshotState()
	if state.BanScore == 0 || !strings.Contains(state.LastError, "transaction count mismatch") {
		t.Fatalf("malformed blocktxn fill state=%+v, want ban and last error", state)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("malformed blocktxn fill sent fallback instead of returning an error")
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("malformed blocktxn fill did not clear matching outstanding request")
	}
}

func TestInternalCompactReceiveMissingAndFallbackBranches(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	missing := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, ShortIDs: []compactShortID{{0xaa}}})
	full := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})

	p := newCompactScriptedPeer(t)
	if err := p.handleCmpctBlock(compactFrameLease(t, p, nil)); err == nil || p.snapshotState().BanScore == 0 {
		t.Fatalf("malformed cmpctblock err=%v state=%+v", err, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 801, 802), 801, 802)
	p.service.cfg.BlockStore = nil
	if err := p.handleCmpctBlock(compactFrameLease(t, p, full)); err == nil || !strings.Contains(err.Error(), "nil blockstore") {
		t.Fatalf("hasBlock cmpctblock err=%v, want nil blockstore", err)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("hasBlock error did not clear matching compact outstanding request")
	}

	p = newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleCmpctBlock(compactFrameLease(t, p, missing)), "missing compact block")
	requireCompactFrame(t, p, messageGetBlockTxn)
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockHash != blockHash || snap.BlockTxnPayloadCap == 0 {
		t.Fatalf("outstanding=%+v ok=%v", snap, ok)
	}

	p = newCompactScriptedPeer(t)
	tooMany := oversizedCmpctBlockShortIDPayload(header)
	requireNoCompactErr(t, p.handleCmpctBlock(compactFrameLease(t, p, tooMany)), "missing overflow fallback")
	requireCompactFrame(t, p, messageGetData)

	p = newCompactScriptedPeer(t)
	truncatedTooMany := oversizedCmpctBlockShortIDCountPayload(header)
	if err := p.handleCmpctBlock(compactFrameLease(t, p, truncatedTooMany)); err == nil || !strings.Contains(err.Error(), "cmpctblock payload truncated short IDs") {
		t.Fatalf("truncated oversized short IDs err=%v, want malformed truncated short IDs", err)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("truncated oversized short IDs sent fallback")
	}

	p = newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleCmpctBlock(compactFrameLease(t, p, full)), "prefilled compact block")
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestCompactOversizedFallbackSkipsAlreadyStoredBlock(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 901, 902), 901, 902)
	requireNoCompactErr(t, p.handleCmpctBlock(compactFrameLease(t, p, oversizedCmpctBlockShortIDPayload(header))), "already-have oversized compact fallback")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("already-have oversized compact fallback did not clear matching outstanding request")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("already-have oversized compact fallback sent getdata")
	}
}

func TestCompactOversizedFallbackValidatesHeaderAndShape(t *testing.T) {
	header, _, _ := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	tinyTarget := [32]byte{}
	tinyTarget[31] = 0x01
	powInvalidHeader := compactHeaderWithTarget(header, tinyTarget)
	p := newCompactScriptedPeer(t)
	if err := p.handleCmpctBlock(compactFrameLease(t, p, oversizedCmpctBlockShortIDPayload(powInvalidHeader))); err == nil || !strings.Contains(err.Error(), "pow invalid") || p.snapshotState().BanScore == 0 {
		t.Fatalf("invalid oversized fallback header err=%v state=%+v", err, p.snapshotState())
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("invalid oversized compact header sent fallback")
	}
}

func TestHandleCmpctBlockValidatesHeaderBeforeBlockstore(t *testing.T) {
	header, _, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	tinyTarget := [32]byte{}
	tinyTarget[31] = 0x01
	powInvalidHeader := compactHeaderWithTarget(header, tinyTarget)
	payload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: powInvalidHeader, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})

	p := newCompactScriptedPeer(t)
	p.service.cfg.BlockStore = nil
	err := p.handleCmpctBlock(compactFrameLease(t, p, payload))
	if err == nil || !strings.Contains(err.Error(), "pow invalid") || p.snapshotState().BanScore == 0 {
		t.Fatalf("pow-invalid compact header err=%v state=%+v", err, p.snapshotState())
	}
	if !strings.Contains(p.snapshotState().LastError, "pow invalid") {
		t.Fatalf("state=%+v, want PoW failure before nil blockstore access", p.snapshotState())
	}
}

func TestHandleCmpctBlockRejectsMalformedTailBeforeHeaderValidation(t *testing.T) {
	header, _, _ := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	tinyTarget := [32]byte{}
	tinyTarget[31] = 0x01
	powInvalidHeader := compactHeaderWithTarget(header, tinyTarget)
	payload := cmpctBlockMissingPrefilledTailPayload(powInvalidHeader, maxCompactRelayEntries)

	p := newCompactScriptedPeer(t)
	err := p.handleCmpctBlock(compactFrameLease(t, p, payload))
	if err == nil || !strings.Contains(err.Error(), "cmpctblock payload truncated prefilled index") || p.snapshotState().BanScore == 0 {
		t.Fatalf("malformed compact tail err=%v state=%+v", err, p.snapshotState())
	}
	if strings.Contains(p.snapshotState().LastError, "pow invalid") {
		t.Fatalf("state=%+v, want malformed shape rejected before PoW", p.snapshotState())
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("malformed compact tail sent fallback")
	}
}

func TestHandleCmpctBlockValidatesHeaderBeforeNonCanonicalPrefilledDecode(t *testing.T) {
	header, _, _ := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	tinyTarget := [32]byte{}
	tinyTarget[31] = 0x01
	powInvalidHeader := compactHeaderWithTarget(header, tinyTarget)
	payload := cmpctBlockNonCanonicalPrefilledPayload(powInvalidHeader, append(minimalBlockTxnTestTxBytes(77), 0x00))

	p := newCompactScriptedPeer(t)
	err := p.handleCmpctBlock(compactFrameLease(t, p, payload))
	if err == nil || !strings.Contains(err.Error(), "pow invalid") || p.snapshotState().BanScore == 0 {
		t.Fatalf("non-canonical compact tail err=%v state=%+v, want header validation first", err, p.snapshotState())
	}
	if strings.Contains(p.snapshotState().LastError, "cmpctblock prefilled transaction is non-canonical") {
		t.Fatalf("state=%+v, want structural preflight without transaction parse", p.snapshotState())
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("non-canonical compact tail sent fallback")
	}
}

func TestInternalCompactApplySuccessClearsMatchingOutstanding(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 601, 602), 601, 602)
	fallback, accepted, err := p.processCompactRelayedBlockWithFallback(blockHash, node.DevnetGenesisBlockBytes(), true)
	requireNoCompactErr(t, err, "compact apply success")
	if fallback || !accepted {
		t.Fatalf("compact apply success fallback=%v accepted=%v, want accepted without fallback", fallback, accepted)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("compact apply success did not clear matching compact outstanding request")
	}
}

func TestInternalCompactApplyEarlyHaveClearsMatchingOutstanding(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 701, 702), 701, 702)
	fallback, accepted, err := p.processCompactRelayedBlockWithFallback(blockHash, node.DevnetGenesisBlockBytes(), true)
	requireNoCompactErr(t, err, "compact apply early-have")
	if fallback || accepted {
		t.Fatalf("compact apply early-have fallback=%v accepted=%v, want no accepted sync trigger", fallback, accepted)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("compact apply early-have did not clear matching compact outstanding request")
	}
}

func TestProcessCompactTransactionsAlreadyHaveSkipsSyncRequest(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	p.state.RemoteVersion.BestHeight = 1

	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, txs, true), "compact apply early-have")
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("already-have compact block requested more blocks")
	}
}

func TestProcessCompactTransactionsRejectsAcceptedBlockMissingAfterApply(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	for _, tc := range []struct {
		name            string
		fallbackOnApply bool
	}{
		{name: "short_id", fallbackOnApply: true},
		{name: "prefilled_only", fallbackOnApply: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newCompactScriptedPeer(t)
			otherStore, err := node.CreateBlockStore(node.BlockStorePath(t.TempDir()))
			requireNoCompactErr(t, err, "open alternate blockstore")
			p.service.cfg.BlockStore = otherStore

			err = p.processCompactTransactions(blockHash, header, txs, tc.fallbackOnApply)
			if err == nil || !strings.Contains(err.Error(), "compact block apply succeeded without accepting block") {
				t.Fatalf("processCompactTransactions err=%v, want explicit missing accepted block error", err)
			}
			if p.service.blockSeen.Has(blockHash) {
				t.Fatal("accepted-but-missing compact block marked blockSeen before storage verification")
			}
			if p.conn.(*scriptedConn).Buffer.Len() != 0 {
				t.Fatal("accepted-but-missing compact block path sent fallback instead of returning an error")
			}
		})
	}
}

func TestCompactPartsFromBlockBytesDecodesCompactSizeTxCountWidth(t *testing.T) {
	const txCount = 253
	genesis := node.DevnetGenesisBlockBytes()
	block := append([]byte(nil), genesis[:consensus.BLOCK_HEADER_BYTES]...)
	block = consensus.AppendCompactSize(block, txCount)
	firstTx := minimalBlockTxnTestTxBytes(1000)
	block = append(block, firstTx...)
	for i := uint64(1); i < txCount; i++ {
		block = append(block, minimalBlockTxnTestTxBytes(1000+i)...)
	}

	_, _, txs := compactPartsFromBlockBytes(t, block)
	if len(txs) != txCount {
		t.Fatalf("tx count=%d, want %d", len(txs), txCount)
	}
	if !bytes.Equal(txs[0], firstTx) {
		t.Fatalf("first tx was sliced from the wrong offset")
	}
}

func TestCompactRelayLocalTransactionsBoundsMemoryPoolSnapshot(t *testing.T) {
	pool := compactRelayTestMemoryPool(t, 4)
	if got := compactRelayLocalTransactions(pool, 2); len(got) != 2 {
		t.Fatalf("bounded snapshot len=%d, want 2", len(got))
	}
	if got := compactRelayLocalTransactions(pool, 0); got != nil {
		t.Fatalf("zero-limit snapshot=%v, want nil", got)
	}
	byteCap := len(minimalBlockTxnTestTxBytes(1))
	if got := compactRelayLocalTransactionsWithBudget(pool, 4, byteCap); len(got) != 1 {
		t.Fatalf("byte-bounded snapshot len=%d, want 1", len(got))
	}
}

func TestCompactRelayLocalCandidateCollectorCountsSkippedEntries(t *testing.T) {
	smallRaw := minimalBlockTxnTestTxBytes(90)
	smallCap := len(smallRaw)
	collector := newCompactLocalTxCandidateCollector(4, 4, smallCap)
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(smallRaw)
	if len(collector.out) != 1 || !bytes.Equal(collector.out[0], smallRaw) {
		t.Fatalf("oversized local candidates stopped bounded scan: len=%d", len(collector.out))
	}

	collector = newCompactLocalTxCandidateCollector(4, 4, smallCap)
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	continued := collector.consider(smallRaw)
	if continued || len(collector.out) != 0 {
		t.Fatalf("scan budget accepted late candidate: continue=%v len=%d", continued, len(collector.out))
	}
}

func TestCompactRelayLocalTransactionsCopiesMemoryPoolBytes(t *testing.T) {
	aliasPool := NewMemoryTxPoolWithLimit(1)
	aliasRaw := minimalBlockTxnTestTxBytes(99)
	_, aliasTxid, _, _, err := consensus.ParseTx(aliasRaw)
	if err != nil {
		t.Fatalf("ParseTx alias: %v", err)
	}
	if !aliasPool.Put(aliasTxid, aliasRaw, consensus.Uint128FromU64(1), len(aliasRaw)) {
		t.Fatal("Put alias tx rejected")
	}
	got := compactRelayLocalTransactions(aliasPool, 1)
	if len(got) != 1 || len(got[0]) == 0 {
		t.Fatalf("alias snapshot=%v", got)
	}
	got[0][0] ^= 0xff
	if stored, ok := aliasPool.Get(aliasTxid); !ok || stored[0] == got[0][0] {
		t.Fatal("bounded snapshot aliases memory pool transaction bytes")
	}
}

func TestCompactRelayLocalTransactionsUsesPurposeSpecificByteCap(t *testing.T) {
	if compactLocalTxCandidateBytesLimit >= consensus.MAX_BLOCK_BYTES {
		t.Fatalf("local candidate byte limit=%d, want below MAX_BLOCK_BYTES=%d", compactLocalTxCandidateBytesLimit, consensus.MAX_BLOCK_BYTES)
	}
	pool := NewMemoryTxPoolWithLimit(1)
	raw := make([]byte, compactLocalTxCandidateBytesLimit+1)
	if !pool.Put([32]byte{0x44}, raw, consensus.Uint128FromU64(1), len(raw)) {
		t.Fatal("Put oversized local candidate")
	}
	if got := compactRelayLocalTransactions(pool, 1); len(got) != 0 {
		t.Fatalf("default local candidate cap accepted %d oversized txs", len(got))
	}
}

func compactRelayTestMemoryPool(t *testing.T, count int) *MemoryTxPool {
	t.Helper()
	pool := NewMemoryTxPoolWithLimit(count)
	for i := 0; i < count; i++ {
		raw := minimalBlockTxnTestTxBytes(uint64(i + 1))
		_, txid, _, _, err := consensus.ParseTx(raw)
		if err != nil {
			t.Fatalf("ParseTx[%d]: %v", i, err)
		}
		if !pool.Put(txid, raw, consensus.Uint128FromU64(uint64(i+1)), len(raw)) {
			t.Fatalf("Put[%d] rejected", i)
		}
	}
	return pool
}

func TestCompactRelayLocalTransactionsForBlockSkipsPrefilledOnly(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(1)
	if !pool.Put([32]byte{0x01}, []byte{0xaa}, consensus.Uint128FromU64(1), 1) {
		t.Fatal("Put local candidate")
	}
	if got := compactRelayLocalTransactionsForBlock(cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: []byte{0xbb}}}}, pool); got != nil {
		t.Fatalf("prefilled-only compact block candidates=%v, want nil", got)
	}
	if got := compactRelayLocalTransactionsForBlock(cmpctBlockPayload{ShortIDs: []compactShortID{{0x01}}}, pool); len(got) != 1 {
		t.Fatalf("short-id compact block candidates len=%d, want 1", len(got))
	}
}

func TestCompactRelayLocalTransactionsCoversCanonicalAndUnknownPools(t *testing.T) {
	if got := compactRelayLocalTransactionsWithBudget(rejectingTxPool{}, 1, 1); got != nil {
		t.Fatalf("unknown pool candidates=%v, want nil", got)
	}
	if got := compactRelayLocalTransactionsWithBudget(NewCanonicalMempoolTxPool(nil), 1, 1); got != nil {
		t.Fatalf("nil canonical candidates=%v, want nil", got)
	}

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	mempool := wireCanonicalMempoolForP2PTest(t, h)
	tx1, _, _ := signedCanonicalP2PTxForHarness(t, h, 9001)
	if err := mempool.AddTx(tx1); err != nil {
		t.Fatalf("AddTx tx1: %v", err)
	}

	pool := NewCanonicalMempoolTxPool(mempool)
	if got := compactRelayLocalTransactionsWithBudget(pool, 1, consensus.MAX_BLOCK_BYTES); len(got) != 1 {
		t.Fatalf("limit-bounded canonical candidates len=%d, want 1", len(got))
	}
	if got := compactRelayLocalTransactionsWithBudget(pool, 2, len(tx1)-1); len(got) != 0 {
		t.Fatalf("byte-bounded canonical candidates len=%d, want 0", len(got))
	}
}

func compactShortIDForTx(t *testing.T, tx []byte, nonce1, nonce2 uint64) compactShortID {
	t.Helper()
	wtxid := compactWTxIDForTx(t, tx)
	return compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))
}

func compactWTxIDForTx(t *testing.T, tx []byte) [32]byte {
	t.Helper()
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	return wtxid
}

func mustEncodeCmpctBlockPayload(t *testing.T, in cmpctBlockPayload) []byte {
	t.Helper()
	raw, err := encodeCmpctBlockPayload(in)
	requireNoCompactErr(t, err, "encode cmpctblock")
	return raw
}

func oversizedCmpctBlockShortIDPayload(header [consensus.BLOCK_HEADER_BYTES]byte) []byte {
	raw := oversizedCmpctBlockShortIDCountPayload(header)
	raw = append(raw, make([]byte, (maxCompactRelayEntries+1)*compactShortIDBytes)...)
	return consensus.AppendCompactSize(raw, 0)
}

func oversizedCmpctBlockShortIDCountPayload(header [consensus.BLOCK_HEADER_BYTES]byte) []byte {
	raw := append([]byte(nil), header[:]...)
	raw = consensus.AppendU64le(raw, 1)
	raw = consensus.AppendU64le(raw, 2)
	return consensus.AppendCompactSize(raw, maxCompactRelayEntries+1)
}

func cmpctBlockMissingPrefilledTailPayload(header [consensus.BLOCK_HEADER_BYTES]byte, shortCount int) []byte {
	raw := append([]byte(nil), header[:]...)
	raw = consensus.AppendU64le(raw, 1)
	raw = consensus.AppendU64le(raw, 2)
	raw = consensus.AppendCompactSize(raw, uint64(shortCount))
	raw = append(raw, make([]byte, shortCount*compactShortIDBytes)...)
	return consensus.AppendCompactSize(raw, 1)
}

func cmpctBlockNonCanonicalPrefilledPayload(header [consensus.BLOCK_HEADER_BYTES]byte, tx []byte) []byte {
	raw := append([]byte(nil), header[:]...)
	raw = consensus.AppendU64le(raw, 1)
	raw = consensus.AppendU64le(raw, 2)
	raw = consensus.AppendCompactSize(raw, 0)
	raw = consensus.AppendCompactSize(raw, 1)
	raw = consensus.AppendU32le(raw, 0)
	raw = consensus.AppendCompactSize(raw, uint64(len(tx)))
	return append(raw, tx...)
}

func mustEncodeGetBlockTxnRequest(t *testing.T, blockHash [32]byte, indexes []uint64) []byte {
	t.Helper()
	raw, err := encodeGetBlockTxnPayload(getBlockTxnPayload{BlockHash: blockHash, Indexes: indexes})
	if err != nil {
		t.Fatalf("encodeGetBlockTxnPayload: %v", err)
	}
	return raw
}

func compactTestBlockBytesWithTxs(t *testing.T, txs [][]byte) []byte {
	t.Helper()
	return compactTestBlockBytesWithRawTxTail(t, txs, nil)
}

func compactTestBlockBytesWithRawTxTail(t *testing.T, txs [][]byte, tail []byte) []byte {
	t.Helper()
	genesis := node.DevnetGenesisBlockBytes()
	raw := append([]byte(nil), genesis[:consensus.BLOCK_HEADER_BYTES]...)
	raw = consensus.AppendCompactSize(raw, uint64(len(txs)))
	for _, tx := range txs {
		raw = append(raw, tx...)
	}
	return append(raw, tail...)
}

func newCompactScriptedPeer(t *testing.T) *peer {
	t.Helper()
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	return p
}

// compactFrameLease installs on p the lease the budgeted reader holds for a cmpctblock frame of
// payload, 3 bytes per payload byte, and returns payload.
func compactFrameLease(t *testing.T, p *peer, payload []byte) []byte {
	t.Helper()
	p.inboundLease = mustReserve(t, p.service.inboundBudget, 3*uint64(len(payload)))
	return payload
}

func setCompactTestOutstanding(p *peer, blockHash [32]byte, header [consensus.BLOCK_HEADER_BYTES]byte, shortID compactShortID, nonce1, nonce2 uint64) {
	p.activateCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:          blockHash,
		Header:             header,
		MissingIndexes:     []uint64{0},
		MissingShortIDs:    []compactShortID{shortID},
		Transactions:       [][]byte{nil},
		Nonce1:             nonce1,
		Nonce2:             nonce2,
		BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn),
	})
}

func compactPartsFromBlockBytes(t *testing.T, block []byte) ([consensus.BLOCK_HEADER_BYTES]byte, [32]byte, [][]byte) {
	t.Helper()
	if len(block) < consensus.BLOCK_HEADER_BYTES+1 {
		t.Fatalf("block too short: %d", len(block))
	}
	var header [consensus.BLOCK_HEADER_BYTES]byte
	copy(header[:], block[:consensus.BLOCK_HEADER_BYTES])
	blockHash, _ := consensus.BlockHash(header[:])
	txCount, countLen, err := consensus.DecodeCompactSize(block[consensus.BLOCK_HEADER_BYTES:])
	if err != nil {
		t.Fatalf("decode tx_count: %v", err)
	}
	offset := consensus.BLOCK_HEADER_BYTES + countLen
	txs := make([][]byte, 0)
	for i := uint64(0); i < txCount; i++ {
		_, _, _, consumed, err := consensus.ParseTx(block[offset:])
		if err != nil {
			t.Fatalf("parse tx[%d]: %v", i, err)
		}
		if consumed <= 0 || offset+consumed > len(block) {
			t.Fatalf("parse tx[%d] consumed invalid length %d at offset %d", i, consumed, offset)
		}
		txs = append(txs, append([]byte(nil), block[offset:offset+consumed]...))
		offset += consumed
	}
	if offset != len(block) {
		t.Fatalf("block has trailing bytes after tx list: %d", len(block)-offset)
	}
	return header, blockHash, txs
}

func requireCompactFrame(t *testing.T, p *peer, command string) message {
	t.Helper()
	conn := p.conn.(*scriptedConn)
	frame, err := readFrame(bytes.NewReader(conn.Buffer.Bytes()), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	conn.Buffer.Reset()
	if err != nil || frame.Command != command {
		t.Fatalf("compact frame=%+v err=%v want %s", frame, err, command)
	}
	return frame
}

func requireNoCompactErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

func compactHeaderWithTarget(header [consensus.BLOCK_HEADER_BYTES]byte, target [32]byte) [consensus.BLOCK_HEADER_BYTES]byte {
	const targetOffset = 4 + 32 + 32 + 8
	copy(header[targetOffset:targetOffset+32], target[:])
	return header
}

func compactFilledTarget(fill byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = fill
	}
	return out
}

// TestTargetScheduleRuntimeCompactStaticTargetGate pins both sides of the
// RUB-655 compact-relay gate: under the exact stock Phase-0 devnet predicate
// the optional static expected-target equality is skipped so the reconstructed
// block reaches the authoritative SyncEngine apply, and under any other
// configuration the pre-existing static comparison and peer disposition are
// unchanged. Parse, PoW range and PoW work are enforced either way.
func TestTargetScheduleRuntimeCompactStaticTargetGate(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	// The published genesis carries POW_LIMIT, so this configured value is
	// deliberately not the header's target.
	wrongExpected := compactFilledTarget(0xee)
	powInvalid := [32]byte{}
	powInvalid[31] = 0x01

	for _, tc := range []struct {
		name      string
		breakTerm func(*testing.T, *peer) // nil keeps the stock devnet configuration
		target    *[32]byte               // nil keeps the published genesis header target
		wantStock bool
		wantErr   string // "" means the block must reach the apply path
	}{
		{name: "stock_devnet_defers_to_apply_path", wantStock: true},
		{name: "stock_devnet_still_enforces_pow", target: &powInvalid, wantStock: true, wantErr: "pow invalid"},
		// The predicate moves with the ENGINE's identity, not this service's
		// SyncConfig copy, and NewSyncEngine normalizes what it is given.
		{name: "engine_padded_mixed_case_network_is_devnet", breakTerm: func(t *testing.T, p *peer) {
			retargetPeerEngine(t, p, " DevNet\t", node.DevnetGenesisChainID())
		}, wantStock: true},
		{name: "engine_non_devnet_network", breakTerm: func(t *testing.T, p *peer) {
			retargetPeerEngine(t, p, "regtest", node.DevnetGenesisChainID())
		}, wantErr: "target mismatch"},
		{name: "engine_foreign_chain_id", breakTerm: func(t *testing.T, p *peer) {
			retargetPeerEngine(t, p, "devnet", [32]byte{0x01})
		}, wantErr: "target mismatch"},
		// validateServiceConfig never requires ServiceConfig.SyncConfig to
		// agree with the engine, so the gate must follow the engine it hands
		// the block to. Reading the copy here would reject a header the engine
		// would have accepted — a same-process accept/reject divergence.
		{name: "service_config_disagrees_gate_follows_engine", breakTerm: func(_ *testing.T, p *peer) {
			p.service.cfg.SyncConfig.Network = "regtest"
			p.service.cfg.SyncConfig.ChainID = [32]byte{0x01}
		}, wantStock: true},
		// The configured genesis hash is deliberately NOT a predicate term:
		// the chain id already commits to the published genesis bytes, and a
		// hash term had no single realizable form across layers. Changing it
		// must not flip rule selection.
		{name: "foreign_genesis_hash_is_not_a_term", breakTerm: func(_ *testing.T, p *peer) { p.service.cfg.GenesisHash = [32]byte{0x01} }, wantStock: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newCompactScriptedPeer(t)
			p.service.cfg.SyncConfig.ExpectedTarget = &wrongExpected
			if tc.breakTerm != nil {
				tc.breakTerm(t, p)
			}
			if got := peerStockDevnetTargetSchedule(p); got != tc.wantStock {
				t.Fatalf("predicate=%v, want %v", got, tc.wantStock)
			}
			relayed := header
			if tc.target != nil {
				relayed = compactHeaderWithTarget(header, *tc.target)
			}
			err := p.handleCmpctBlock(compactFrameLease(t, p, mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{
				Header:    relayed,
				Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}},
			})))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || p.snapshotState().BanScore == 0 {
					t.Fatalf("err=%v state=%+v, want %q with a ban", err, p.snapshotState(), tc.wantErr)
				}
				return
			}
			requireNoCompactErr(t, err, tc.name)
			have, haveErr := p.service.hasBlock(blockHash)
			if p.snapshotState().BanScore != 0 || haveErr != nil || !have {
				t.Fatalf("ban=%d have=%v err=%v, want the block accepted by the apply path", p.snapshotState().BanScore, have, haveErr)
			}
		})
	}
}

// peerStockDevnetTargetSchedule reads the predicate exactly as
// validateCompactBlockHeader does: from the ENGINE the service defers to.
func peerStockDevnetTargetSchedule(p *peer) bool {
	return p.service.cfg.SyncEngine.StockDevnetTargetSchedule()
}

// retargetPeerEngine rebuilds the service's sync engine with a different
// startup identity. The gate reads the ENGINE's normalized config, so this —
// not ServiceConfig.SyncConfig — is what moves the predicate.
func retargetPeerEngine(t *testing.T, p *peer, network string, chainID [32]byte) {
	t.Helper()
	dir := t.TempDir()
	store, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	cfg := node.DefaultSyncConfig(nil, chainID, node.ChainStatePath(dir))
	cfg.Network = network
	engine, err := node.NewSyncEngine(node.NewChainState(), store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	// Keep the service's store with its engine, as production wires them.
	p.service.cfg.SyncEngine = engine
	p.service.cfg.BlockStore = store
}

func compactHeaderWithPrev(header [consensus.BLOCK_HEADER_BYTES]byte, prev [32]byte) [consensus.BLOCK_HEADER_BYTES]byte {
	const prevOffset = 4
	copy(header[prevOffset:prevOffset+32], prev[:])
	return header
}

// TestTargetScheduleRuntimeCompactOrphanRetainedNotBanned pins the disposition
// of a relayed block whose parent is not in the store: target-schedule context
// cannot be derived for an unresolved parent, so the block must be RETAINED as
// an orphan — never turned into a connection-level error and never ban-scored.
// Go reaches this through compactApplyErrorFallback -> retainRelayedOrphanIfValid;
// the row exists so the two clients are provably aligned on it.
func TestTargetScheduleRuntimeCompactOrphanRetainedNotBanned(t *testing.T) {
	header, _, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	// A non-zero, unknown parent. The published genesis carries POW_LIMIT so
	// the header still satisfies PoW and the orphan guard admits it.
	orphanHeader := compactHeaderWithPrev(header, [32]byte{0xab})
	orphanHash, err := consensus.BlockHash(orphanHeader[:])
	if err != nil {
		t.Fatalf("BlockHash: %v", err)
	}

	p := newCompactScriptedPeer(t)
	if !peerStockDevnetTargetSchedule(p) {
		t.Fatal("scripted peer is not the stock devnet configuration")
	}
	// Prefilled-only: no short ids, so the apply path does not fall back to a
	// full-block request and the orphan disposition is what gets exercised.
	err = p.handleCmpctBlock(compactFrameLease(t, p, mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{
		Header:    orphanHeader,
		Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}},
	})))
	if err != nil {
		t.Fatalf("unresolved-parent compact block returned a connection-level error: %v", err)
	}
	if score := p.snapshotState().BanScore; score != 0 {
		t.Fatalf("BanScore=%d, want 0 for an orphan", score)
	}
	if p.service.orphans.Len() != 1 {
		t.Fatalf("orphan pool len=%d, want the block retained", p.service.orphans.Len())
	}
	if have, herr := p.service.hasBlock(orphanHash); herr != nil || have {
		t.Fatalf("hasBlock=%v err=%v, want the orphan NOT applied", have, herr)
	}
}

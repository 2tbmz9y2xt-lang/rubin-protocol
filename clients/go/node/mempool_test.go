package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestMempoolAdd(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
}

func TestMempoolAcceptedEntryMetadataAndIndexes(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 300_000, 1, fromKey, fromAddress, toAddress)
	tx, txid, wtxid, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		t.Fatalf("TxWeightAndStats: %v", err)
	}

	if err := mp.addTxWithSource(txBytes, mempoolTxSourceRemote); err != nil {
		t.Fatalf("addTxWithSource: %v", err)
	}

	mp.mu.RLock()
	defer mp.mu.RUnlock()
	entry, ok := mp.txs[txid]
	if !ok {
		t.Fatalf("entry for txid %x missing", txid)
	}
	if !bytes.Equal(entry.raw, txBytes) {
		t.Fatal("entry raw bytes mismatch")
	}
	if entry.txid != txid {
		t.Fatalf("entry txid=%x, want %x", entry.txid, txid)
	}
	if entry.wtxid != wtxid {
		t.Fatalf("entry wtxid=%x, want %x", entry.wtxid, wtxid)
	}
	if entry.fee != 300_000 {
		t.Fatalf("entry fee=%d, want 300000", entry.fee)
	}
	if entry.weight != weight {
		t.Fatalf("entry weight=%d, want %d", entry.weight, weight)
	}
	if entry.size != len(txBytes) {
		t.Fatalf("entry wire bytes=%d, want %d", entry.size, len(txBytes))
	}
	if entry.admissionSeq != 1 {
		t.Fatalf("entry admission_seq=%d, want 1", entry.admissionSeq)
	}
	if entry.source != mempoolTxSourceRemote {
		t.Fatalf("entry source=%q, want %q", entry.source, mempoolTxSourceRemote)
	}
	if got, ok := mp.wtxids[wtxid]; !ok || got != txid {
		t.Fatalf("wtxid index got %x ok=%v, want txid %x", got, ok, txid)
	}
	if got, ok := mp.spenders[outpoints[0]]; !ok || got != txid {
		t.Fatalf("spender index got %x ok=%v, want txid %x", got, ok, txid)
	}
}

func TestMempoolAdmissionSourceWrappersRecordOrigin(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	cases := []struct {
		name      string
		outpoint  consensus.Outpoint
		nonce     uint64
		source    mempoolTxSource
		admitFunc func([]byte) error
	}{
		{
			name:      "local",
			outpoint:  outpoints[0],
			nonce:     1,
			source:    mempoolTxSourceLocal,
			admitFunc: mp.AddTx,
		},
		{
			name:      "remote",
			outpoint:  outpoints[1],
			nonce:     2,
			source:    mempoolTxSourceRemote,
			admitFunc: mp.AddRemoteTx,
		},
		{
			name:      "reorg",
			outpoint:  outpoints[2],
			nonce:     3,
			source:    mempoolTxSourceReorg,
			admitFunc: mp.AddReorgTx,
		},
	}

	for _, tc := range cases {
		txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{tc.outpoint}, 100_000, 300_000, tc.nonce, fromKey, fromAddress, toAddress)
		if err := tc.admitFunc(txBytes); err != nil {
			t.Fatalf("%s admit: %v", tc.name, err)
		}
		txid := txID(t, txBytes)
		mp.mu.RLock()
		entry := mp.txs[txid]
		mp.mu.RUnlock()
		if entry == nil {
			t.Fatalf("%s entry for txid %x missing", tc.name, txid)
		}
		if entry.source != tc.source {
			t.Fatalf("%s source=%q, want %q", tc.name, entry.source, tc.source)
		}
	}
}

func TestMempoolRejectsInvalidEntrySource(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	err = mp.addTxWithSource(txBytes, "sidecar")
	if err == nil || !strings.Contains(err.Error(), "invalid mempool tx source") {
		t.Fatalf("expected invalid source rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitRejected {
		t.Fatalf("expected TxAdmitRejected, got %v", txErr.Kind)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	if mp.lastAdmissionSeq != 0 {
		t.Fatalf("lastAdmissionSeq after invalid source=%d, want 0", mp.lastAdmissionSeq)
	}
}

func TestMempoolAddEntryLockedInitializesMetadataIndexes(t *testing.T) {
	op := consensus.Outpoint{Txid: [32]byte{0x01}, Vout: 2}
	entry := &mempoolEntry{
		txid:         [32]byte{0x02},
		wtxid:        [32]byte{0x03},
		inputs:       []consensus.Outpoint{op},
		fee:          5,
		weight:       5,
		size:         7,
		admissionSeq: 9,
		source:       mempoolTxSourceReorg,
	}

	mp := &Mempool{maxTxs: 10, maxBytes: 100}
	if err := mp.addEntryLocked(entry); err != nil {
		t.Fatalf("addEntryLocked: %v", err)
	}

	if mp.txs == nil || mp.wtxids == nil || mp.spenders == nil {
		t.Fatalf("indexes were not initialized: txs=%v wtxids=%v spenders=%v", mp.txs != nil, mp.wtxids != nil, mp.spenders != nil)
	}
	if got := mp.txs[entry.txid]; got != entry {
		t.Fatalf("tx index got %p, want entry %p", got, entry)
	}
	if got := mp.wtxids[entry.wtxid]; got != entry.txid {
		t.Fatalf("wtxid index got %x, want txid %x", got, entry.txid)
	}
	if got := mp.spenders[op]; got != entry.txid {
		t.Fatalf("spender index got %x, want txid %x", got, entry.txid)
	}
	if mp.lastAdmissionSeq != entry.admissionSeq {
		t.Fatalf("lastAdmissionSeq=%d, want %d", mp.lastAdmissionSeq, entry.admissionSeq)
	}
	if mp.usedBytes != entry.size {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, entry.size)
	}
}

func TestMempoolAddEntryLockedDefaultsUnsetWtxid(t *testing.T) {
	entry := &mempoolEntry{
		txid:   [32]byte{0x0a},
		fee:    1,
		weight: 1,
		size:   1,
	}

	mp := &Mempool{
		maxTxs:   1,
		maxBytes: 10,
	}
	if err := mp.addEntryLocked(entry); err != nil {
		t.Fatalf("addEntryLocked: %v", err)
	}

	if entry.wtxid != entry.txid {
		t.Fatalf("entry wtxid=%x, want txid %x", entry.wtxid, entry.txid)
	}
	if got, ok := mp.wtxids[entry.txid]; !ok || got != entry.txid {
		t.Fatalf("wtxid index got %x ok=%v, want txid %x", got, ok, entry.txid)
	}
	if got, ok := mp.wtxids[[32]byte{}]; ok {
		t.Fatalf("zero wtxid key unexpectedly indexed txid %x", got)
	}
	err := mp.addEntryLocked(&mempoolEntry{txid: [32]byte{0x0b}, fee: 1, weight: 1, size: 1})
	if err == nil || !strings.Contains(err.Error(), "mempool capacity candidate rejected by eviction ordering") {
		t.Fatalf("expected candidate-worst rejection after zero-wtxid default, got %v", err)
	}
}

func TestMempoolAddEntryLockedRejectsZeroTxidWithoutMutation(t *testing.T) {
	mp := &Mempool{}

	err := mp.addEntryLocked(&mempoolEntry{weight: 1, size: 1})
	if err == nil || !strings.Contains(err.Error(), "invalid mempool entry txid") {
		t.Fatalf("expected invalid txid rejection, got %v", err)
	}
	if mp.txs != nil || mp.wtxids != nil || mp.spenders != nil {
		t.Fatalf("indexes initialized after zero txid reject: txs=%v wtxids=%v spenders=%v", mp.txs != nil, mp.wtxids != nil, mp.spenders != nil)
	}
	if mp.usedBytes != 0 {
		t.Fatalf("usedBytes=%d, want 0 after zero txid reject", mp.usedBytes)
	}
	if mp.lastAdmissionSeq != 0 {
		t.Fatalf("lastAdmissionSeq=%d, want 0 after zero txid reject", mp.lastAdmissionSeq)
	}

	err = mp.validateNonCapacityAdmissionLocked(&mempoolEntry{weight: 1, size: 1})
	if err == nil || !strings.Contains(err.Error(), "invalid mempool entry txid") {
		t.Fatalf("expected validate invalid txid rejection, got %v", err)
	}
}

func TestMempoolEvictionComparatorTiers(t *testing.T) {
	lowerRate := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x01}, fee: 1, weight: 2, size: 1, admissionSeq: 1}}
	higherRate := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x02}, fee: 1, weight: 1, size: 1, admissionSeq: 2}}
	if !evictionPlanEntryWorse(lowerRate, higherRate) {
		t.Fatal("lower fee/weight entry was not worse")
	}

	lowerAbsoluteFee := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x03}, fee: 1, weight: 1, size: 1000, admissionSeq: 3}}
	higherAbsoluteFee := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x04}, fee: 2, weight: 2, size: 1, admissionSeq: 4}}
	if !evictionPlanEntryWorse(lowerAbsoluteFee, higherAbsoluteFee) {
		t.Fatal("lower absolute fee tie-break was not worse before admission_seq")
	}

	older := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x05}, fee: 3, weight: 3, size: 1, admissionSeq: 5}}
	newer := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x06}, fee: 3, weight: 3, size: 1, admissionSeq: 6}}
	if !evictionPlanEntryWorse(older, newer) {
		t.Fatal("older admission_seq tie-break was not worse")
	}

	candidate := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x07}, fee: 3, weight: 3, size: 1}, candidate: true}
	if !evictionPlanEntryWorse(candidate, older) {
		t.Fatal("capacity candidate did not compare as virtual admission_seq=0")
	}

	local := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x09}, fee: 3, weight: 3, size: 1, admissionSeq: 7, source: mempoolTxSourceLocal}}
	remote := mempoolEvictionPlanEntry{entry: &mempoolEntry{txid: [32]byte{0x08}, fee: 3, weight: 3, size: 1, admissionSeq: 7, source: mempoolTxSourceRemote}}
	if !evictionPlanEntryWorse(local, remote) {
		t.Fatal("source provenance unexpectedly affected eviction ordering before deterministic txid tie-break")
	}
}

func TestMempoolFeeRateComparatorUsesWeightAndDoesNotOverflow(t *testing.T) {
	if got := compareFeeRateWeightValues(^uint64(0), ^uint64(0)-1, ^uint64(0)-1, ^uint64(0)); got <= 0 {
		t.Fatalf("overflow-sensitive fee-rate compare=%d, want first greater", got)
	}
	lowWeightFeeRate := &mempoolEntry{txid: [32]byte{0x01}, fee: 10, weight: 5, size: 10_000, admissionSeq: 1}
	highWeightFeeRate := &mempoolEntry{txid: [32]byte{0x02}, fee: 10, weight: 10, size: 1, admissionSeq: 2}
	if !evictionPlanEntryWorse(mempoolEvictionPlanEntry{entry: highWeightFeeRate}, mempoolEvictionPlanEntry{entry: lowWeightFeeRate}) {
		t.Fatal("eviction comparator used wire bytes instead of weight")
	}
}

func TestMempoolAddEntryLockedRejectsInvalidSourceAndDuplicateAdmissionSeq(t *testing.T) {
	mp := &Mempool{maxTxs: 10, maxBytes: 100}
	first := &mempoolEntry{
		txid:         [32]byte{0x11},
		fee:          1,
		weight:       1,
		size:         1,
		admissionSeq: 7,
		source:       mempoolTxSourceLocal,
	}
	if err := mp.addEntryLocked(first); err != nil {
		t.Fatalf("addEntryLocked(first): %v", err)
	}
	err := mp.addEntryLocked(&mempoolEntry{
		txid:         [32]byte{0x12},
		fee:          1,
		weight:       1,
		size:         1,
		admissionSeq: 7,
		source:       mempoolTxSourceRemote,
	})
	if err == nil || !strings.Contains(err.Error(), "mempool admission sequence conflict") {
		t.Fatalf("expected admission sequence conflict, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError for admission sequence conflict, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitRejected {
		t.Fatalf("admission sequence conflict kind=%v, want %v", txErr.Kind, TxAdmitRejected)
	}
	if err := mp.addEntryLocked(&mempoolEntry{
		txid:   [32]byte{0x13},
		fee:    1,
		weight: 1,
		size:   1,
		source: "sidecar",
	}); err == nil || !strings.Contains(err.Error(), "invalid mempool tx source") {
		t.Fatalf("expected invalid source rejection, got %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1 after helper rejects", got)
	}
}

func TestDefaultMempoolLowWaterBytes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		maxBytes int
		want     int
	}{
		{name: "zero", maxBytes: 0, want: 0},
		{name: "negative", maxBytes: -1, want: 0},
		{name: "one", maxBytes: 1, want: 1},
		{name: "small", maxBytes: 9, want: 8},
		{name: "ten", maxBytes: 10, want: 9},
		{name: "remainder", maxBytes: 11, want: 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultMempoolLowWaterBytes(tc.maxBytes); got != tc.want {
				t.Fatalf("defaultMempoolLowWaterBytes(%d)=%d, want %d", tc.maxBytes, got, tc.want)
			}
		})
	}
}

func TestMempoolCapacityPlanRejectsInvalidDryRunInputs(t *testing.T) {
	validCandidate := func() *mempoolEntry {
		return &mempoolEntry{
			txid:   [32]byte{0x21},
			fee:    1,
			weight: 1,
			size:   1,
		}
	}
	for _, tc := range []struct {
		name      string
		mp        *Mempool
		candidate *mempoolEntry
		want      string
	}{
		{
			name:      "nil_candidate",
			mp:        &Mempool{maxTxs: 10, maxBytes: 100},
			candidate: nil,
			want:      "nil mempool entry",
		},
		{
			name:      "negative_max_bytes",
			mp:        &Mempool{maxTxs: 10, maxBytes: -1},
			candidate: validCandidate(),
			want:      "invalid mempool max_bytes",
		},
		{
			name:      "zero_capacity",
			mp:        &Mempool{maxTxs: 0, maxBytes: 100},
			candidate: validCandidate(),
			want:      "invalid mempool capacity limits",
		},
		{
			name: "negative_candidate_size",
			mp:   &Mempool{maxTxs: 10, maxBytes: 100},
			candidate: &mempoolEntry{
				txid:   [32]byte{0x22},
				fee:    1,
				weight: 1,
				size:   -1,
			},
			want: "invalid mempool candidate_size",
		},
		{
			name:      "negative_used_bytes",
			mp:        &Mempool{maxTxs: 10, maxBytes: 100, usedBytes: -1},
			candidate: validCandidate(),
			want:      "invalid mempool used_bytes",
		},
		{
			name: "candidate_over_max_bytes",
			mp:   &Mempool{maxTxs: 10, maxBytes: 1},
			candidate: &mempoolEntry{
				txid:   [32]byte{0x23},
				fee:    1,
				weight: 1,
				size:   2,
			},
			want: "mempool byte limit exceeded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := tc.mp.capacityEvictionPlanLocked(tc.candidate)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestMempoolCapacityPlanRejectsInvalidExistingMetadata(t *testing.T) {
	validExisting := func(txid [32]byte, seq uint64) *mempoolEntry {
		return &mempoolEntry{
			txid:         txid,
			fee:          10,
			weight:       1,
			size:         1,
			admissionSeq: seq,
			source:       mempoolTxSourceLocal,
		}
	}
	validCandidate := &mempoolEntry{
		txid:   [32]byte{0xaa},
		fee:    10,
		weight: 1,
		size:   1,
	}
	for _, tc := range []struct {
		name    string
		entries map[[32]byte]*mempoolEntry
		want    string
	}{
		{
			name:    "nil_existing",
			entries: map[[32]byte]*mempoolEntry{{0x01}: nil},
			want:    "nil mempool entry",
		},
		{
			name:    "zero_txid",
			entries: map[[32]byte]*mempoolEntry{{0x02}: {fee: 10, weight: 1, size: 1, admissionSeq: 1}},
			want:    "invalid mempool entry txid",
		},
		{
			name: "zero_size",
			entries: map[[32]byte]*mempoolEntry{
				{0x03}: {txid: [32]byte{0x03}, fee: 10, weight: 1, admissionSeq: 1},
			},
			want: "invalid mempool entry size",
		},
		{
			name: "zero_weight",
			entries: map[[32]byte]*mempoolEntry{
				{0x04}: {txid: [32]byte{0x04}, fee: 10, size: 1, admissionSeq: 1},
			},
			want: "invalid mempool entry weight",
		},
		{
			name: "zero_admission_seq",
			entries: map[[32]byte]*mempoolEntry{
				{0x05}: {txid: [32]byte{0x05}, fee: 10, weight: 1, size: 1},
			},
			want: "invalid mempool entry admission_seq",
		},
		{
			name: "duplicate_admission_seq",
			entries: map[[32]byte]*mempoolEntry{
				{0x06}: validExisting([32]byte{0x06}, 1),
				{0x07}: validExisting([32]byte{0x07}, 1),
			},
			want: "duplicate mempool entry admission_seq",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mp := &Mempool{
				maxTxs:    1,
				maxBytes:  100,
				usedBytes: len(tc.entries),
				txs:       tc.entries,
			}
			_, _, err := mp.capacityEvictionPlanLocked(validCandidate)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
		})
	}
}

func TestMempoolEntryFloorRateUsesSatisfiableFloor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fee    uint64
		weight uint64
		want   uint64
	}{
		{name: "C1_non_div_even_3_over_2", fee: 3, weight: 2, want: 1},
		{name: "C2_non_div_odd_5_over_3", fee: 5, weight: 3, want: 1},
		{name: "C3_non_div_big_7_over_4", fee: 7, weight: 4, want: 1},
		{name: "C4_divisible_4_over_2", fee: 4, weight: 2, want: 2},
		{name: "C5_divisible_9_over_3", fee: 9, weight: 3, want: 3},
		{name: "C6_fee_equals_weight", fee: 1, weight: 1, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := &mempoolEntry{
				txid:   [32]byte{0x71},
				fee:    tc.fee,
				weight: tc.weight,
				size:   1,
			}

			floor, ok := entryFloorRate(entry)
			if !ok {
				t.Fatal("entryFloorRate returned !ok for valid entry")
			}
			if floor != tc.want {
				t.Fatalf("entryFloorRate=%d, want %d for fee=%d weight=%d", floor, tc.want, tc.fee, tc.weight)
			}
			if feeRateBelowFloor(entry.fee, entry.weight, floor) {
				t.Fatalf("entry is below its satisfiable floor: fee=%d weight=%d floor=%d", entry.fee, entry.weight, floor)
			}
			if !feeRateBelowFloor(entry.fee, entry.weight, floor+DefaultMempoolMinFeeRate) {
				t.Fatalf("entry unexpectedly satisfies raised floor: fee=%d weight=%d floor=%d", entry.fee, entry.weight, floor+DefaultMempoolMinFeeRate)
			}
		})
	}
	if floor, ok := entryFloorRate(&mempoolEntry{txid: [32]byte{0x72}, fee: 3}); ok || floor != 0 {
		t.Fatalf("zero-weight entryFloorRate=(%d,%v), want (0,false)", floor, ok)
	}
}

func TestMempoolRaiseMinFeeRateUsesHighestSatisfiableEvictedFloor(t *testing.T) {
	mp := &Mempool{maxTxs: 10, maxBytes: 100, currentMinFeeRate: DefaultMempoolMinFeeRate}
	mp.raiseMinFeeRateAfterEvictionLocked([]*mempoolEntry{
		{txid: [32]byte{0x81}, fee: 3, weight: 2, size: 1},
		{txid: [32]byte{0x82}, fee: 10, weight: 2, size: 1},
		{txid: [32]byte{0x83}, fee: 7, weight: 4, size: 1},
	})

	wantFloor := uint64(5) + DefaultMempoolMinFeeRate
	if got := mp.currentMinFeeRate; got != wantFloor {
		t.Fatalf("currentMinFeeRate=%d, want %d after mixed non-divisible/divisible eviction", got, wantFloor)
	}
	if err := mp.validateFeeFloorLocked(&mempoolEntry{txid: [32]byte{0x84}, fee: 12, weight: 2, size: 1}); err != nil {
		t.Fatalf("candidate at raised floor was rejected: %v", err)
	}
	for _, entry := range []*mempoolEntry{
		{txid: [32]byte{0x85}, fee: 10, weight: 2, size: 1},
		{txid: [32]byte{0x86}, fee: 8, weight: 2, size: 1},
	} {
		if err := mp.validateFeeFloorLocked(entry); err == nil || !strings.Contains(err.Error(), "mempool fee below rolling minimum") {
			t.Fatalf("candidate below raised floor was not rejected as below-floor: fee=%d weight=%d err=%v", entry.fee, entry.weight, err)
		}
	}
}

func TestMempoolRaiseMinFeeRateUsesHighestNonDivisibleEvictedFloor(t *testing.T) {
	mp := &Mempool{maxTxs: 10, maxBytes: 100, currentMinFeeRate: DefaultMempoolMinFeeRate}
	mp.raiseMinFeeRateAfterEvictionLocked([]*mempoolEntry{
		{txid: [32]byte{0xa1}, fee: 3, weight: 2, size: 1},
		{txid: [32]byte{0xa2}, fee: 7, weight: 4, size: 1},
	})

	wantFloor := uint64(1) + DefaultMempoolMinFeeRate
	if got := mp.currentMinFeeRate; got != wantFloor {
		t.Fatalf("currentMinFeeRate=%d, want %d after all-non-divisible eviction", got, wantFloor)
	}
	if err := mp.validateFeeFloorLocked(&mempoolEntry{txid: [32]byte{0xa3}, fee: 4, weight: 2, size: 1}); err != nil {
		t.Fatalf("candidate at non-divisible raised floor was rejected: %v", err)
	}
}

func TestMempoolRaiseMinFeeRatePreservesDivisibleEvictedFloor(t *testing.T) {
	mp := &Mempool{maxTxs: 10, maxBytes: 100, currentMinFeeRate: DefaultMempoolMinFeeRate}
	mp.raiseMinFeeRateAfterEvictionLocked([]*mempoolEntry{
		{txid: [32]byte{0x91}, fee: 4, weight: 2, size: 1},
	})

	wantFloor := uint64(2) + DefaultMempoolMinFeeRate
	if got := mp.currentMinFeeRate; got != wantFloor {
		t.Fatalf("currentMinFeeRate=%d, want %d after divisible eviction", got, wantFloor)
	}
	if err := mp.validateFeeFloorLocked(&mempoolEntry{txid: [32]byte{0x92}, fee: 6, weight: 2, size: 1}); err != nil {
		t.Fatalf("candidate at divisible raised floor was rejected: %v", err)
	}
	if err := mp.validateFeeFloorLocked(&mempoolEntry{txid: [32]byte{0x93}, fee: 4, weight: 2, size: 1}); err == nil || !strings.Contains(err.Error(), "mempool fee below rolling minimum") {
		t.Fatalf("candidate below divisible raised floor was not rejected as below-floor: %v", err)
	}
}

func TestMempoolSortAndEvictionUseWeightFeeRate(t *testing.T) {
	feeSizeWinner := &mempoolEntry{txid: [32]byte{0xb1}, fee: 4, weight: 4, size: 1}
	feeWeightWinner := &mempoolEntry{txid: [32]byte{0xb2}, fee: 2, weight: 1, size: 1}

	entries := []*mempoolEntry{feeSizeWinner, feeWeightWinner}
	sortMempoolEntries(entries)
	if entries[0] != feeWeightWinner {
		t.Fatalf("sortMempoolEntries picked txid %x first, want fee/weight winner %x", entries[0].txid, feeWeightWinner.txid)
	}

	if !evictionPlanEntryWorse(
		mempoolEvictionPlanEntry{entry: feeSizeWinner},
		mempoolEvictionPlanEntry{entry: feeWeightWinner},
	) {
		t.Fatal("eviction priority did not mark lower fee/weight entry as worse")
	}
}

func TestMempoolAddEntryLockedCapacityPlanRejectsWithoutMutation(t *testing.T) {
	badResidentID := [32]byte{0x30}
	mp := &Mempool{
		maxTxs:    1,
		maxBytes:  100,
		usedBytes: 1,
		txs: map[[32]byte]*mempoolEntry{
			badResidentID: {
				txid:         badResidentID,
				fee:          10,
				size:         1,
				admissionSeq: 1,
			},
		},
	}
	err := mp.addEntryLocked(&mempoolEntry{
		txid:   [32]byte{0x31},
		fee:    10,
		weight: 1,
		size:   1,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid mempool entry weight") {
		t.Fatalf("expected capacity plan metadata rejection, got %v", err)
	}
	if len(mp.txs) != 1 || mp.txs[badResidentID] == nil || mp.wtxids != nil || mp.spenders != nil || mp.lastAdmissionSeq != 0 || mp.currentMinFeeRate != 0 || mp.usedBytes != 1 {
		t.Fatalf("capacity-plan error mutated mempool: len=%d wtxids=%v spenders=%v seq=%d floor=%d used=%d", len(mp.txs), mp.wtxids != nil, mp.spenders != nil, mp.lastAdmissionSeq, mp.currentMinFeeRate, mp.usedBytes)
	}
}

func TestMempoolAddEntryLockedCandidateWorstRejectsWithoutMutation(t *testing.T) {
	mp := &Mempool{maxTxs: 1, maxBytes: 100}
	resident := &mempoolEntry{
		txid:   [32]byte{0x41},
		fee:    100,
		weight: 1,
		size:   1,
	}
	if err := mp.addEntryLocked(resident); err != nil {
		t.Fatalf("addEntryLocked(resident): %v", err)
	}
	before, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot before direct candidate-worst: %v", err)
	}
	err = mp.addEntryLocked(&mempoolEntry{
		txid:   [32]byte{0x42},
		fee:    1,
		weight: 1,
		size:   1,
	})
	if err == nil || !strings.Contains(err.Error(), "mempool capacity candidate rejected by eviction ordering") {
		t.Fatalf("expected direct candidate-worst rejection, got %v", err)
	}
	after, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot after direct candidate-worst: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("direct candidate-worst mutated mempool: before=%+v after=%+v", before, after)
	}
}

func TestMempoolRejectsZeroWeightMetadata(t *testing.T) {
	mp := &Mempool{maxTxs: 10, maxBytes: 100}
	err := mp.validateNonCapacityAdmissionLocked(&mempoolEntry{
		txid: [32]byte{0x21},
		fee:  1,
		size: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid mempool entry weight") {
		t.Fatalf("expected zero weight rejection, got %v", err)
	}
}

func TestMempoolEntryIndexesRemovedWithEntry(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 300_000, 1, fromKey, fromAddress, toAddress)
	_, txid, wtxid, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	mp.mu.Lock()
	mp.removeTxLocked(txid)
	if _, ok := mp.txs[txid]; ok {
		t.Fatalf("removed txid %x still present", txid)
	}
	if _, ok := mp.wtxids[wtxid]; ok {
		t.Fatalf("removed wtxid %x still indexed", wtxid)
	}
	if _, ok := mp.spenders[outpoints[0]]; ok {
		t.Fatalf("removed spender %x:%d still indexed", outpoints[0].Txid, outpoints[0].Vout)
	}
	mp.mu.Unlock()
}

func TestMempoolAdmissionSeqOnlyAcceptedTxs(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx([]byte{0xde, 0xad}); err == nil {
		t.Fatal("malformed tx unexpectedly accepted")
	}
	if mp.lastAdmissionSeq != 0 {
		t.Fatalf("lastAdmissionSeq after malformed=%d, want 0", mp.lastAdmissionSeq)
	}

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 100_000, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if got := mp.txs[txID(t, tx1)].admissionSeq; got != 1 {
		t.Fatalf("tx1 admission_seq=%d, want 1", got)
	}
	if err := mp.AddTx(tx1); err == nil {
		t.Fatal("duplicate tx unexpectedly accepted")
	}
	if mp.lastAdmissionSeq != 1 {
		t.Fatalf("lastAdmissionSeq after duplicate=%d, want 1", mp.lastAdmissionSeq)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2): %v", err)
	}
	if got := mp.txs[txID(t, tx2)].admissionSeq; got != 2 {
		t.Fatalf("tx2 admission_seq=%d, want 2", got)
	}
}

func TestMempoolAdmissionSeqDoesNotWrap(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	mp.lastAdmissionSeq = ^uint64(0)

	err = mp.AddTx(txBytes)
	if err == nil || !strings.Contains(err.Error(), "mempool admission sequence exhausted") {
		t.Fatalf("expected sequence exhaustion rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("expected TxAdmitUnavailable, got %v", txErr.Kind)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	if mp.lastAdmissionSeq != ^uint64(0) {
		t.Fatalf("lastAdmissionSeq mutated to %d", mp.lastAdmissionSeq)
	}
}

func TestMempoolRejectsDuplicateWtxidIndexWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	tx1ID := txID(t, tx1)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 100_000, 2, fromKey, fromAddress, toAddress)
	_, tx2ID, tx2Wtxid, _, err := consensus.ParseTx(tx2)
	if err != nil {
		t.Fatalf("ParseTx(tx2): %v", err)
	}

	mp.mu.Lock()
	mp.wtxids[tx2Wtxid] = tx1ID
	usedBytes := mp.usedBytes
	lastAdmissionSeq := mp.lastAdmissionSeq
	mp.mu.Unlock()

	err = mp.AddTx(tx2)
	if err == nil || !strings.Contains(err.Error(), "mempool wtxid conflict") {
		t.Fatalf("expected wtxid conflict rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitConflict {
		t.Fatalf("expected TxAdmitConflict, got %v", txErr.Kind)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1 after wtxid conflict", got)
	}
	if mp.Contains(tx2ID) {
		t.Fatalf("wtxid conflict admitted tx2 %x", tx2ID)
	}
	if mp.usedBytes != usedBytes {
		t.Fatalf("usedBytes=%d, want %d after wtxid conflict", mp.usedBytes, usedBytes)
	}
	if mp.lastAdmissionSeq != lastAdmissionSeq {
		t.Fatalf("lastAdmissionSeq=%d, want %d after wtxid conflict", mp.lastAdmissionSeq, lastAdmissionSeq)
	}
	if got := mp.wtxids[tx2Wtxid]; got != tx1ID {
		t.Fatalf("wtxid index overwritten with %x, want existing %x", got, tx1ID)
	}
}

func TestMempoolAddTxWaitsForChainStateWriter(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)

	st.admissionMu.Lock()
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- mp.AddTx(txBytes)
	}()
	<-started

	select {
	case err := <-done:
		t.Fatalf("AddTx returned while chainstate writer lock held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	st.admissionMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AddTx after writer unlock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddTx remained blocked after chainstate writer unlock")
	}
}

func TestMempoolAddTxRejectsWhenWriterInvalidatesSnapshotBeforeAdmission(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)

	st.admissionMu.Lock()
	st.mu.Lock()
	delete(st.Utxos, outpoints[0])
	st.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- mp.AddTx(txBytes)
	}()

	select {
	case err := <-done:
		t.Fatalf("AddTx returned while writer gate held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	st.admissionMu.Unlock()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), string(consensus.TX_ERR_MISSING_UTXO)) {
			t.Fatalf("expected missing utxo after writer mutation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddTx remained blocked after writer gate unlock")
	}

	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func TestMempoolAddTxWaitsForPolicyWriterBeforeSnapshot(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedAnchorOutputTx(t, st.Utxos, outpoints[0], 0, 1, 1, fromKey, toAddress)

	mp.mu.Lock()
	mp.policy.PolicyRejectNonCoinbaseAnchorOutputs = true

	done := make(chan error, 1)
	go func() {
		done <- mp.AddTx(txBytes)
	}()

	select {
	case err := <-done:
		t.Fatalf("AddTx returned while policy writer lock held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	mp.mu.Unlock()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
			t.Fatalf("expected policy rejection after writer unlock, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddTx remained blocked after policy writer unlock")
	}

	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func TestMempoolRelayMetadata(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 300_000, 5, fromKey, fromAddress, toAddress)
	meta, err := mp.RelayMetadata(txBytes)
	if err != nil {
		t.Fatalf("RelayMetadata: %v", err)
	}
	if meta.Fee != 300_000 {
		t.Fatalf("fee=%d, want 300000", meta.Fee)
	}
	if meta.Size != len(txBytes) {
		t.Fatalf("size=%d, want %d", meta.Size, len(txBytes))
	}
}

func TestMempoolRelayMetadataTrailingBytes(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 300_000, 5, fromKey, fromAddress, toAddress)
	txBytes = append(txBytes, 0x00)
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "trailing bytes after canonical tx") {
		t.Fatalf("expected trailing-bytes rejection, got %v", err)
	}
}

func TestMempoolRelayMetadataNil(t *testing.T) {
	var mp *Mempool
	if _, err := mp.RelayMetadata([]byte{0x01}); err == nil {
		t.Fatal("nil mempool should reject RelayMetadata")
	}
}

func TestMempoolPolicyRejectsNonCoinbaseAnchorOutputs(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectNonCoinbaseAnchorOutputs: true,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedAnchorOutputTx(t, st.Utxos, outpoints[0], 0, 1, 1, fromKey, toAddress)
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
		t.Fatalf("expected non-coinbase anchor policy rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "non-coinbase CORE_ANCHOR") {
		t.Fatalf("expected relay metadata anchor policy rejection, got %v", err)
	}
}

func TestMempoolPolicyRejectsLowFeeDaCommit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 99, 1, 1, fromKey, toAddress, []byte("0123456789"))
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "DA fee below policy minimum") {
		t.Fatalf("expected DA surcharge rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "DA fee below policy minimum") {
		t.Fatalf("expected relay metadata DA surcharge rejection, got %v", err)
	}
}

func TestMempoolPolicyAllowsSufficientFeeDaCommit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 100_000, 900_000, 1, fromKey, toAddress, []byte("0123456789"))
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("expected DA tx admission, got %v", err)
	}
}

func TestMempoolPolicySnapshot_DoesNotMutateForDaPolicy(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyDaSurchargePerByte: 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 80, 10, 1, fromKey, toAddress, []byte("0123456789"))
	nextHeight, _, err := nextBlockContext(st)
	if err != nil {
		t.Fatalf("nextBlockContext: %v", err)
	}
	blockMTP, err := mp.nextBlockMTP(nextHeight)
	if err != nil {
		t.Fatalf("nextBlockMTP: %v", err)
	}
	checked, err := consensus.CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		copyUtxoSet(st.Utxos),
		nextHeight,
		blockMTP,
		devnetGenesisChainID,
		mp.policy.CoreExtProfiles,
		mp.policy.RotationProvider,
		mp.policy.SuiteRegistry,
	)
	if err != nil {
		t.Fatalf("CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext: %v", err)
	}
	policyUtxos, err := policyInputSnapshot(checked.Tx, st.Utxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot: %v", err)
	}
	before, err := policyInputSnapshot(checked.Tx, policyUtxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot(before): %v", err)
	}

	if err := mp.applyPolicyAgainstState(checked, nextHeight, policyUtxos, mp.policySnapshot()); err != nil {
		t.Fatalf("applyPolicyAgainstState: %v", err)
	}
	if !reflect.DeepEqual(policyUtxos, before) {
		t.Fatalf("policy path mutated DA snapshot")
	}
}

func TestMempoolPolicyRejectsCoreExtOutputPreActivation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 90, 1, 1, fromKey, fromAddress, 7)
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT output pre-ACTIVE ext_id=7") {
		t.Fatalf("expected CORE_EXT output rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT output pre-ACTIVE ext_id=7") {
		t.Fatalf("expected relay CORE_EXT output rejection, got %v", err)
	}
}

func TestMempoolPolicyRejectsCoreExtSpendPreActivation(t *testing.T) {
	toKey := mustNodeMLDSA87Keypair(t)
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	var prev [32]byte
	prev[0] = 0x55
	st := NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x11
	st.Utxos[consensus.Outpoint{Txid: prev, Vout: 0}] = consensus.UtxoEntry{
		Value:        100,
		CovenantType: consensus.COV_TYPE_CORE_EXT,
		CovenantData: coreExtCovenantDataForNodeTest(7, nil),
	}

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildCoreExtSpendTx(t, prev, 99, 1, 1, toAddress)
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT spend pre-ACTIVE ext_id=7") {
		t.Fatalf("expected CORE_EXT spend rejection, got %v", err)
	}
	if _, err := mp.RelayMetadata(txBytes); err == nil || !strings.Contains(err.Error(), "CORE_EXT spend pre-ACTIVE ext_id=7") {
		t.Fatalf("expected relay CORE_EXT spend rejection, got %v", err)
	}
}

func TestMempoolPolicyAllowsCoreExtWhenProfileActive(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
		CoreExtProfiles:                  testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 100_000, 100_000, 1, fromKey, fromAddress, 7)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("expected CORE_EXT tx admission, got %v", err)
	}
	meta, err := mp.RelayMetadata(txBytes)
	if err != nil {
		t.Fatalf("expected relay metadata success, got %v", err)
	}
	if meta.Fee != 100_000 {
		t.Fatalf("relay fee=%d, want 100000", meta.Fee)
	}
}

func TestMempoolPolicySnapshot_DoesNotMutateForCoreExtPolicy(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyRejectCoreExtPreActivation: true,
		CoreExtProfiles:                  testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txBytes := mustBuildSignedCoreExtOutputTx(t, st.Utxos, outpoints[0], 90, 1, 1, fromKey, fromAddress, 7)
	nextHeight, _, err := nextBlockContext(st)
	if err != nil {
		t.Fatalf("nextBlockContext: %v", err)
	}
	blockMTP, err := mp.nextBlockMTP(nextHeight)
	if err != nil {
		t.Fatalf("nextBlockMTP: %v", err)
	}
	checked, err := consensus.CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext(
		txBytes,
		copyUtxoSet(st.Utxos),
		nextHeight,
		blockMTP,
		devnetGenesisChainID,
		mp.policy.CoreExtProfiles,
		mp.policy.RotationProvider,
		mp.policy.SuiteRegistry,
	)
	if err != nil {
		t.Fatalf("CheckTransactionWithOwnedUtxoSetAndCoreExtProfilesAndSuiteContext: %v", err)
	}
	policyUtxos, err := policyInputSnapshot(checked.Tx, st.Utxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot: %v", err)
	}
	before, err := policyInputSnapshot(checked.Tx, policyUtxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot(before): %v", err)
	}

	if err := mp.applyPolicyAgainstState(checked, nextHeight, policyUtxos, mp.policySnapshot()); err != nil {
		t.Fatalf("applyPolicyAgainstState: %v", err)
	}
	if !reflect.DeepEqual(policyUtxos, before) {
		t.Fatalf("policy path mutated CORE_EXT snapshot")
	}
}

func TestMempoolPolicyRejectsOversizedCoreExtPayload(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyMaxExtPayloadBytes: 32,
		CoreExtProfiles:          testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	// Build tx with oversized payload (49 bytes > 32 limit)
	entry := st.Utxos[outpoints[0]]
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []consensus.TxInput{{
			PrevTxid: outpoints[0].Txid,
			PrevVout: outpoints[0].Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: 90, CovenantType: consensus.COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantDataForNodeTest(7, make([]byte, 49))},
			{Value: entry.Value - 91, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), fromAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, st.Utxos, devnetGenesisChainID, fromKey); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	if err := mp.AddTx(txBytes); err == nil || !strings.Contains(err.Error(), "exceeds policy limit") {
		t.Fatalf("expected oversized payload rejection, got %v", err)
	}
}

func TestMempoolPolicyAllowsCoreExtPayloadUnderLimit(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		PolicyMaxExtPayloadBytes: 48,
		CoreExtProfiles:          testCoreExtProfiles{activeByExtID: map[uint16]bool{7: true}},
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	// Build tx with payload under limit (32 bytes <= 48 limit)
	entry := st.Utxos[outpoints[0]]
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []consensus.TxInput{{
			PrevTxid: outpoints[0].Txid,
			PrevVout: outpoints[0].Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: 100_000, CovenantType: consensus.COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantDataForNodeTest(7, make([]byte, 32))},
			{Value: entry.Value - 200_000, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), fromAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, st.Utxos, devnetGenesisChainID, fromKey); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("expected admission, got %v", err)
	}
}

func TestMempoolPolicyRejectsNilCheckedTransaction(t *testing.T) {
	mp := &Mempool{}
	if err := mp.applyPolicyAgainstState(nil, 0, nil, MempoolConfig{}); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
		t.Fatalf("expected nil checked transaction rejection, got %v", err)
	}
	if err := mp.applyPolicyAgainstState(&consensus.CheckedTransaction{}, 0, nil, MempoolConfig{}); err == nil || !strings.Contains(err.Error(), "nil checked transaction") {
		t.Fatalf("expected nil checked tx rejection, got %v", err)
	}
}

func TestMempoolPolicyPropagatesDaFeeComputationErrors(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100})
	txBytes := mustBuildSignedDaCommitTx(t, st.Utxos, outpoints[0], 80, 10, 1, fromKey, toAddress, []byte("0123456789"))
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx(da): %v", err)
	}

	mp := &Mempool{
		chainState: &ChainState{},
		policy: MempoolConfig{
			PolicyDaSurchargePerByte: 1,
		},
	}
	if err := mp.applyPolicyAgainstState(&consensus.CheckedTransaction{Tx: tx}, 101, nil, mp.policySnapshot()); err == nil || !strings.Contains(err.Error(), "nil utxo set") {
		t.Fatalf("expected DA fee computation error, got %v", err)
	}
}

func TestPolicyInputSnapshotCopiesOnlySpentInputs(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 2_000_000})

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	snapshot, err := policyInputSnapshot(tx, st.Utxos)
	if err != nil {
		t.Fatalf("policyInputSnapshot: %v", err)
	}
	if len(snapshot) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(snapshot))
	}
	if _, ok := snapshot[outpoints[0]]; !ok {
		t.Fatalf("snapshot missing spent input")
	}
	if _, ok := snapshot[outpoints[1]]; ok {
		t.Fatalf("snapshot unexpectedly copied unrelated utxo")
	}

	entry := snapshot[outpoints[0]]
	entry.CovenantData[0] ^= 0xff
	snapshot[outpoints[0]] = entry
	if reflect.DeepEqual(snapshot[outpoints[0]].CovenantData, st.Utxos[outpoints[0]].CovenantData) {
		t.Fatal("mutating snapshot covenant data leaked into original utxo set")
	}
}

func TestChainStateAdmissionSnapshotForInputsCopiesOnlyRequestedEntries(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{100, 200})
	var missingTxid [32]byte
	missingTxid[0] = 0xee

	snapshot := st.admissionSnapshotForInputs([]consensus.Outpoint{
		outpoints[0],
		outpoints[0],
		{Txid: missingTxid, Vout: 9},
	})
	if snapshot == nil {
		t.Fatal("admissionSnapshotForInputs returned nil")
	}
	if len(snapshot.utxos) != 1 {
		t.Fatalf("snapshot len=%d, want 1", len(snapshot.utxos))
	}
	if _, ok := snapshot.utxos[outpoints[0]]; !ok {
		t.Fatal("snapshot missing requested input")
	}
	if _, ok := snapshot.utxos[outpoints[1]]; ok {
		t.Fatal("snapshot unexpectedly copied unrelated utxo")
	}

	entry := snapshot.utxos[outpoints[0]]
	entry.CovenantData[0] ^= 0xff
	snapshot.utxos[outpoints[0]] = entry
	if reflect.DeepEqual(snapshot.utxos[outpoints[0]].CovenantData, st.Utxos[outpoints[0]].CovenantData) {
		t.Fatal("mutating input snapshot leaked into original utxo set")
	}
}

func TestPolicyInputSnapshotRejectsMissingInput(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	delete(st.Utxos, outpoints[0])

	_, err = policyInputSnapshot(tx, st.Utxos)
	if err == nil || !strings.Contains(err.Error(), string(consensus.TX_ERR_MISSING_UTXO)) {
		t.Fatalf("expected missing utxo rejection, got %v", err)
	}
}

func TestMempoolDoubleSpend(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	tx1ID := txID(t, tx1)
	if got, ok := mp.spenders[outpoints[0]]; !ok || got != tx1ID {
		t.Fatalf("spender index got %x ok=%v, want tx1 %x", got, ok, tx1ID)
	}
	seqAfterTx1 := mp.lastAdmissionSeq
	if err := mp.AddTx(tx2); err == nil {
		t.Fatalf("expected double-spend rejection")
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	if mp.Contains(txID(t, tx2)) {
		t.Fatalf("conflicting tx entered mempool")
	}
	if got, ok := mp.spenders[outpoints[0]]; !ok || got != tx1ID {
		t.Fatalf("spender index after conflict got %x ok=%v, want tx1 %x", got, ok, tx1ID)
	}
	if mp.lastAdmissionSeq != seqAfterTx1 {
		t.Fatalf("lastAdmissionSeq after conflict=%d, want %d", mp.lastAdmissionSeq, seqAfterTx1)
	}
}

func TestMempoolFullEvictsWorstByFeeWeight(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	txBest := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 100_000, 300_000, 3, fromKey, fromAddress, toAddress)

	if err := mp.AddTx(txLow); err != nil {
		t.Fatalf("AddTx(low): %v", err)
	}
	if err := mp.AddTx(txHigh); err != nil {
		t.Fatalf("AddTx(high): %v", err)
	}
	if err := mp.AddTx(txBest); err != nil {
		t.Fatalf("AddTx(best): %v", err)
	}
	if got := mp.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}
	if mp.Contains(txID(t, txLow)) {
		t.Fatal("lowest fee/weight tx remained after count-pressure eviction")
	}
	if !mp.Contains(txID(t, txHigh)) || !mp.Contains(txID(t, txBest)) {
		t.Fatal("capacity eviction removed a survivor with better fee/weight")
	}
	if got := mp.lastAdmissionSeq; got != 3 {
		t.Fatalf("lastAdmissionSeq=%d, want 3", got)
	}
	if got := mp.txs[txID(t, txBest)].admissionSeq; got != 3 {
		t.Fatalf("best admission_seq=%d, want 3", got)
	}
	if mp.currentMinFeeRate <= DefaultMempoolMinFeeRate {
		t.Fatalf("currentMinFeeRate=%d, want above base floor after actual eviction", mp.currentMinFeeRate)
	}

	selected := mp.SelectTransactions(3, 1<<20)
	if len(selected) != 2 {
		t.Fatalf("selected=%d, want 2", len(selected))
	}
	got := []string{txIDHex(t, selected[0]), txIDHex(t, selected[1])}
	wantBest := txIDHex(t, txBest)
	wantHigh := txIDHex(t, txHigh)
	if got[0] != wantBest || got[1] != wantHigh {
		t.Fatalf("selected=%v, want [%s %s]", got, wantBest, wantHigh)
	}
}

func TestMempoolCandidateWorstRejectsWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 100_000, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(tx1) + len(tx2) - 1,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	before, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot before candidate-worst: %v", err)
	}
	usedBytes := mp.usedBytes
	if err := mp.AddTx(tx2); err == nil || !strings.Contains(err.Error(), "mempool capacity candidate rejected by eviction ordering") {
		t.Fatalf("expected candidate-worst rejection, got %v", err)
	}
	after, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot after candidate-worst: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("mempool snapshot mutated after candidate-worst reject: before=%+v after=%+v", before, after)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	if mp.usedBytes != usedBytes {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, usedBytes)
	}
	if mp.Contains(txID(t, tx2)) {
		t.Fatalf("rejected byte-cap tx entered mempool")
	}
}

func TestMempoolCapacityRejectsBelowRollingFloorWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	txBelowFloor := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 1, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	before, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot before below-floor: %v", err)
	}
	err = mp.AddTx(txBelowFloor)
	if err == nil || !strings.Contains(err.Error(), "mempool fee below rolling minimum") {
		t.Fatalf("expected below-floor rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) || txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("below-floor err=%v, want TxAdmitUnavailable", err)
	}
	after, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot after below-floor: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("below-floor capacity reject mutated mempool: before=%+v after=%+v", before, after)
	}
	if mp.Contains(txID(t, txBelowFloor)) {
		t.Fatal("below-floor capacity candidate entered mempool")
	}
}

func TestMempoolRollingFloorRejectsBelowCapacityWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	txBelowFloor := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 1, 1, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.currentMinFeeRate = 8
	before, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot before below-capacity below-floor: %v", err)
	}
	err = mp.AddTx(txBelowFloor)
	if err == nil || !strings.Contains(err.Error(), "mempool fee below rolling minimum") {
		t.Fatalf("expected below-capacity below-floor rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) || txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("below-capacity floor err=%v, want TxAdmitUnavailable", err)
	}
	after, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot after below-capacity below-floor: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("below-capacity floor reject mutated mempool: before=%+v after=%+v", before, after)
	}
	if mp.usedBytes != 0 || mp.lastAdmissionSeq != 0 || mp.currentMinFeeRate != 8 {
		t.Fatalf("below-capacity floor reject state usedBytes=%d seq=%d floor=%d", mp.usedBytes, mp.lastAdmissionSeq, mp.currentMinFeeRate)
	}
}

func TestMempoolAddEntryLockedRejectsBelowFloor(t *testing.T) {
	mp := &Mempool{maxTxs: 10, maxBytes: 100, currentMinFeeRate: 8}
	err := mp.addEntryLocked(&mempoolEntry{
		txid:   [32]byte{0x51},
		fee:    7,
		weight: 1,
		size:   1,
	})
	if err == nil || !strings.Contains(err.Error(), "mempool fee below rolling minimum") {
		t.Fatalf("expected addEntryLocked below-floor rejection, got %v", err)
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) || txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("addEntryLocked floor err=%v, want TxAdmitUnavailable", err)
	}
	if len(mp.txs) != 0 || mp.usedBytes != 0 || mp.lastAdmissionSeq != 0 || mp.currentMinFeeRate != 8 {
		t.Fatalf("addEntryLocked floor reject mutated mempool: len=%d used=%d seq=%d floor=%d", len(mp.txs), mp.usedBytes, mp.lastAdmissionSeq, mp.currentMinFeeRate)
	}
}

func TestMempoolRollingFloorAcceptsExactFloorBelowCapacity(t *testing.T) {
	const floor = uint64(8)
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	probe := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 1, 1, fromKey, fromAddress, toAddress)
	parsed, _, _, _, err := consensus.ParseTx(probe)
	if err != nil {
		t.Fatalf("ParseTx(probe): %v", err)
	}
	weight, _, _, err := consensus.TxWeightAndStats(parsed)
	if err != nil {
		t.Fatalf("TxWeightAndStats(probe): %v", err)
	}
	exactFee := weight * floor
	txExactFloor := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, exactFee, 1, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.currentMinFeeRate = floor
	if err := mp.AddTx(txExactFloor); err != nil {
		t.Fatalf("AddTx(exact floor): %v", err)
	}
	entry := mp.txs[txID(t, txExactFloor)]
	if entry == nil {
		t.Fatal("exact-floor tx missing from mempool")
	}
	if feeRateBelowFloor(entry.fee, entry.weight, floor) {
		t.Fatalf("accepted exact-floor entry still below floor: fee=%d weight=%d floor=%d", entry.fee, entry.weight, floor)
	}
}

func TestMempoolByteCapEvictsToLowWater(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000, 1_000_000})

	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	txMid := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 100_000, 300_000, 3, fromKey, fromAddress, toAddress)
	txBest := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[3]}, 100_000, 400_000, 4, fromKey, fromAddress, toAddress)
	maxBytes := len(txLow) + len(txMid) + len(txHigh)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        maxBytes,
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	for _, item := range []struct {
		name string
		raw  []byte
	}{
		{name: "low", raw: txLow},
		{name: "mid", raw: txMid},
		{name: "high", raw: txHigh},
	} {
		if err := mp.AddTx(item.raw); err != nil {
			t.Fatalf("AddTx(%s): %v", item.name, err)
		}
	}
	if err := mp.AddTx(txBest); err != nil {
		t.Fatalf("AddTx(best): %v", err)
	}
	if got, wantMax := mp.usedBytes, mp.effectiveLowWaterBytesLocked(); got > wantMax {
		t.Fatalf("usedBytes=%d, want <= lowWater %d after byte-pressure eviction", got, wantMax)
	}
	if mp.Contains(txID(t, txLow)) || mp.Contains(txID(t, txMid)) {
		t.Fatal("byte-pressure low-water trim kept lower-priority evicted entries")
	}
	if !mp.Contains(txID(t, txHigh)) || !mp.Contains(txID(t, txBest)) {
		t.Fatal("byte-pressure low-water trim removed expected survivors")
	}
}

func TestMempoolSmallByteCapKeepsFittingCandidateAfterLowWaterTrim(t *testing.T) {
	for _, tc := range []struct {
		name     string
		maxBytes int
	}{
		{name: "one", maxBytes: 1},
		{name: "two", maxBytes: 2},
		{name: "five", maxBytes: 5},
		{name: "nine", maxBytes: 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			residentID := [32]byte{byte(0x60 + tc.maxBytes)}
			candidateID := [32]byte{byte(0x70 + tc.maxBytes)}
			mp := &Mempool{maxTxs: 10, maxBytes: tc.maxBytes}
			resident := &mempoolEntry{txid: residentID, fee: 1, weight: 1, size: tc.maxBytes}
			if err := mp.addEntryLocked(resident); err != nil {
				t.Fatalf("addEntryLocked(resident): %v", err)
			}

			candidate := &mempoolEntry{txid: candidateID, fee: 10, weight: 1, size: 1}
			if err := mp.addEntryLocked(candidate); err != nil {
				t.Fatalf("addEntryLocked(candidate): %v", err)
			}
			if got := mp.Len(); got != 1 {
				t.Fatalf("mempool len=%d, want 1 after small-cap low-water trim", got)
			}
			if got := mp.usedBytes; got != 1 {
				t.Fatalf("usedBytes=%d, want 1 after small-cap low-water trim", got)
			}
			if !mp.Contains(candidate.txid) {
				t.Fatal("candidate fitting the hard byte cap was not admitted")
			}
			if mp.Contains(resident.txid) {
				t.Fatal("small-cap low-water trim kept lower-priority resident")
			}
		})
	}
}

func TestMempoolBytePressureAdmitsCandidateLargerThanLowWaterWhenFitsHardCap(t *testing.T) {
	residentID := [32]byte{0x80}
	candidateID := [32]byte{0x81}
	mp := &Mempool{maxTxs: 10, maxBytes: 100}
	resident := &mempoolEntry{txid: residentID, fee: 1, weight: 1, size: 95}
	if err := mp.addEntryLocked(resident); err != nil {
		t.Fatalf("addEntryLocked(resident): %v", err)
	}
	if got, want := mp.effectiveLowWaterBytesLocked(), 90; got != want {
		t.Fatalf("lowWater=%d, want %d", got, want)
	}

	candidate := &mempoolEntry{txid: candidateID, fee: 100, weight: 1, size: 95}
	if err := mp.addEntryLocked(candidate); err != nil {
		t.Fatalf("addEntryLocked(candidate): %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1 after byte-pressure replacement", got)
	}
	if got := mp.usedBytes; got != 95 {
		t.Fatalf("usedBytes=%d, want candidate hard-cap size 95", got)
	}
	if !mp.Contains(candidateID) {
		t.Fatal("candidate fitting maxBytes was not admitted")
	}
	if mp.Contains(residentID) {
		t.Fatal("byte-pressure replacement kept lower-priority resident")
	}
}

func TestMempoolDuplicateRejectsBeforeEviction(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	tx := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx(tx); err != nil {
		t.Fatalf("AddTx(tx): %v", err)
	}
	before, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot before duplicate: %v", err)
	}
	if err := mp.AddTx(tx); err == nil || !strings.Contains(err.Error(), "tx already in mempool") {
		t.Fatalf("expected duplicate rejection before eviction, got %v", err)
	}
	after, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot after duplicate: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("duplicate path mutated mempool: before=%+v after=%+v", before, after)
	}
}

func TestMempoolConflictRejectsBeforeEvictionUnderPressure(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	tx := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	conflictingHigherFee := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 1, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx(tx); err != nil {
		t.Fatalf("AddTx(tx): %v", err)
	}
	before, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot before conflict: %v", err)
	}
	if err := mp.AddTx(conflictingHigherFee); err == nil || !strings.Contains(err.Error(), "mempool double-spend conflict") {
		t.Fatalf("expected conflict rejection before eviction, got %v", err)
	}
	after, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshot after conflict: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("conflict path mutated mempool: before=%+v after=%+v", before, after)
	}
	if !mp.Contains(txID(t, tx)) || mp.Contains(txID(t, conflictingHigherFee)) {
		t.Fatal("conflict path replaced resident transaction")
	}
}

func TestMempoolRollingMinFeeDecaysOnlyOnConnectedBlockLowWater(t *testing.T) {
	st := NewChainState()
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxBytes: 1000})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.currentMinFeeRate = 8
	mp.usedBytes = mp.effectiveLowWaterBytesLocked() - 1
	if err := mp.RemoveConflictingParsed(&consensus.ParsedBlock{}); err != nil {
		t.Fatalf("RemoveConflictingParsed: %v", err)
	}
	if got := mp.currentMinFeeRate; got != 8 {
		t.Fatalf("RemoveConflictingParsed decayed floor to %d, want 8", got)
	}
	if err := mp.EvictConfirmedParsed(&consensus.ParsedBlock{}); err != nil {
		t.Fatalf("EvictConfirmedParsed: %v", err)
	}
	if got := mp.currentMinFeeRate; got != 4 {
		t.Fatalf("connected block low-water decay=%d, want 4", got)
	}
	mp.currentMinFeeRate = 8
	mp.usedBytes = mp.effectiveLowWaterBytesLocked()
	if err := mp.EvictConfirmedParsed(&consensus.ParsedBlock{}); err != nil {
		t.Fatalf("EvictConfirmedParsed at low-water boundary: %v", err)
	}
	if got := mp.currentMinFeeRate; got != 8 {
		t.Fatalf("boundary usedBytes decayed floor to %d, want 8", got)
	}
	mp.currentMinFeeRate = DefaultMempoolMinFeeRate
	mp.usedBytes = 0
	if err := mp.EvictConfirmedParsed(&consensus.ParsedBlock{}); err != nil {
		t.Fatalf("EvictConfirmedParsed at base floor: %v", err)
	}
	if got := mp.currentMinFeeRate; got != DefaultMempoolMinFeeRate {
		t.Fatalf("base floor decayed to %d, want %d", got, DefaultMempoolMinFeeRate)
	}
}

func TestMempoolConnectedBlockDecaySeesConfirmedAndConflictingRemovals(t *testing.T) {
	spentByBlock := consensus.Outpoint{Txid: [32]byte{0xc1}, Vout: 2}
	confirmedID := [32]byte{0xa1}
	conflictingID := [32]byte{0xb1}
	mp := &Mempool{maxTxs: 10, maxBytes: 100, currentMinFeeRate: 8}
	confirmed := &mempoolEntry{
		txid:         confirmedID,
		wtxid:        confirmedID,
		fee:          8,
		weight:       1,
		size:         5,
		admissionSeq: 1,
		source:       mempoolTxSourceLocal,
	}
	conflicting := &mempoolEntry{
		txid:         conflictingID,
		wtxid:        conflictingID,
		inputs:       []consensus.Outpoint{spentByBlock},
		fee:          8,
		weight:       1,
		size:         90,
		admissionSeq: 2,
		source:       mempoolTxSourceLocal,
	}
	if err := mp.addEntryLocked(confirmed); err != nil {
		t.Fatalf("add confirmed entry: %v", err)
	}
	if err := mp.addEntryLocked(conflicting); err != nil {
		t.Fatalf("add conflicting entry: %v", err)
	}
	if got := mp.usedBytes; got != 95 {
		t.Fatalf("usedBytes before connected block=%d, want 95", got)
	}

	block := &consensus.ParsedBlock{
		Txids: [][32]byte{[32]byte{0x01}, confirmedID},
		Txs: []*consensus.Tx{
			{},
			{Inputs: []consensus.TxInput{{PrevTxid: spentByBlock.Txid, PrevVout: spentByBlock.Vout}}},
		},
	}
	if err := mp.applyConnectedBlockParsed(block); err != nil {
		t.Fatalf("applyConnectedBlockParsed: %v", err)
	}
	if mp.Contains(confirmedID) {
		t.Fatal("connected block left confirmed tx in mempool")
	}
	if mp.Contains(conflictingID) {
		t.Fatal("connected block left conflicting tx in mempool")
	}
	if got := mp.usedBytes; got != 0 {
		t.Fatalf("usedBytes after connected block=%d, want 0", got)
	}
	if got := mp.currentMinFeeRate; got != 4 {
		t.Fatalf("currentMinFeeRate after confirmed+conflict removals=%d, want 4", got)
	}
}

func TestMempoolAddReorgTxUsesRollingFloor(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	mp.currentMinFeeRate = 8
	txBelowFloor := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 1, 1, fromKey, fromAddress, toAddress)

	err = mp.AddReorgTx(txBelowFloor)
	var admitErr *TxAdmitError
	if !errors.As(err, &admitErr) || admitErr.Kind != TxAdmitUnavailable {
		t.Fatalf("AddReorgTx below rolling floor error=%T %v, want TxAdmitUnavailable", err, err)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len after reorg floor reject=%d, want 0", got)
	}
	if mp.lastAdmissionSeq != 0 {
		t.Fatalf("lastAdmissionSeq after reorg floor reject=%d, want 0", mp.lastAdmissionSeq)
	}
	if got := mp.currentMinFeeRate; got != 8 {
		t.Fatalf("currentMinFeeRate after reorg floor reject=%d, want 8", got)
	}
}

func TestMempoolByteCapAllowsExactBoundary(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2) at exact byte cap: %v", err)
	}
	if got := mp.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}
	if mp.usedBytes != len(tx1)+len(tx2) {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, len(tx1)+len(tx2))
	}
}

func TestMempoolAdmissionRejectsDoNotMutateByteAccounting(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 10})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	txDoubleSpend := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 300_000, 2, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	wantBytes := mp.usedBytes
	wantLen := mp.Len()

	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{name: "duplicate", raw: tx1},
		{name: "double_spend", raw: txDoubleSpend},
		{name: "malformed", raw: []byte{0xde, 0xad}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := mp.AddTx(tc.raw); err == nil {
				t.Fatalf("expected rejection")
			}
			if got := mp.Len(); got != wantLen {
				t.Fatalf("mempool len=%d, want %d", got, wantLen)
			}
			if mp.usedBytes != wantBytes {
				t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, wantBytes)
			}
		})
	}
}

func TestRestoreMempoolSnapshotRecomputesByteAccounting(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2): %v", err)
	}
	if err := restoreMempoolSnapshot(mp, snapshot); err != nil {
		t.Fatalf("restoreMempoolSnapshot: %v", err)
	}
	if got := mp.Len(); got != 1 {
		t.Fatalf("mempool len=%d, want 1", got)
	}
	tx1ID := txID(t, tx1)
	_, _, tx1WTxID, _, err := consensus.ParseTx(tx1)
	if err != nil {
		t.Fatalf("ParseTx(tx1): %v", err)
	}
	restored := mp.txs[tx1ID]
	if restored == nil {
		t.Fatalf("restored entry for tx1 missing")
	}
	if restored.wtxid != tx1WTxID {
		t.Fatalf("restored wtxid=%x, want %x", restored.wtxid, tx1WTxID)
	}
	if restored.admissionSeq != 1 {
		t.Fatalf("restored admission_seq=%d, want 1", restored.admissionSeq)
	}
	if restored.source != mempoolTxSourceLocal {
		t.Fatalf("restored source=%q, want %q", restored.source, mempoolTxSourceLocal)
	}
	if mp.lastAdmissionSeq != restored.admissionSeq {
		t.Fatalf("lastAdmissionSeq after restore=%d, want %d", mp.lastAdmissionSeq, restored.admissionSeq)
	}
	if mp.usedBytes != len(tx1) {
		t.Fatalf("usedBytes=%d, want %d", mp.usedBytes, len(tx1))
	}
	if mp.Contains(txID(t, tx2)) {
		t.Fatalf("restored mempool still contains tx2")
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2) after restore: %v", err)
	}
	if mp.usedBytes != len(tx1)+len(tx2) {
		t.Fatalf("usedBytes=%d, want %d after post-restore AddTx", mp.usedBytes, len(tx1)+len(tx2))
	}
}

func TestRestoreMempoolSnapshotPreservesAdmissionSeqHighWatermark(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 100_000, 2, fromKey, fromAddress, toAddress)
	tx3 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 100_000, 100_000, 3, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(tx1); err != nil {
		t.Fatalf("AddTx(tx1): %v", err)
	}
	if err := mp.AddTx(tx2); err != nil {
		t.Fatalf("AddTx(tx2): %v", err)
	}
	mp.currentMinFeeRate = 7
	tx2ID := txID(t, tx2)
	mp.mu.Lock()
	mp.removeTxLocked(tx2ID)
	if mp.lastAdmissionSeq != 2 {
		t.Fatalf("lastAdmissionSeq after removing tx2=%d, want 2", mp.lastAdmissionSeq)
	}
	mp.mu.Unlock()

	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	if snapshot.lastAdmissionSeq != 2 {
		t.Fatalf("snapshot lastAdmissionSeq=%d, want 2", snapshot.lastAdmissionSeq)
	}
	if snapshot.currentMinFeeRate != 7 {
		t.Fatalf("snapshot currentMinFeeRate=%d, want 7", snapshot.currentMinFeeRate)
	}
	mp.currentMinFeeRate = 3
	if err := restoreMempoolSnapshot(mp, snapshot); err != nil {
		t.Fatalf("restoreMempoolSnapshot: %v", err)
	}
	if mp.lastAdmissionSeq != 2 {
		t.Fatalf("lastAdmissionSeq after restore=%d, want 2", mp.lastAdmissionSeq)
	}
	if mp.currentMinFeeRate != 7 {
		t.Fatalf("currentMinFeeRate after restore=%d, want 7", mp.currentMinFeeRate)
	}
	if err := mp.AddTx(tx3); err != nil {
		t.Fatalf("AddTx(tx3): %v", err)
	}
	tx3ID := txID(t, tx3)
	if got := mp.txs[tx3ID].admissionSeq; got != 3 {
		t.Fatalf("tx3 admissionSeq=%d, want 3", got)
	}
}

func TestSnapshotMempoolNormalizesRollingFloor(t *testing.T) {
	mp := &Mempool{}
	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	if snapshot.currentMinFeeRate != DefaultMempoolMinFeeRate {
		t.Fatalf("snapshot currentMinFeeRate=%d, want %d", snapshot.currentMinFeeRate, DefaultMempoolMinFeeRate)
	}
}

func TestRestoreMempoolSnapshotRejectsInvalidEntriesWithoutMutation(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	txSecond := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	txSecondID := txID(t, txSecond)
	mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 10,
		MaxBytes:        len(txBytes) + len(txSecond),
	})
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	snapshot, err := snapshotMempool(mp)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}
	wantTxID := txID(t, txBytes)
	wantBytes := mp.usedBytes
	txDoubleSpend := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 300_000, 2, fromKey, fromAddress, toAddress)
	doubleSpendID := txID(t, txDoubleSpend)
	snapshotEntry := func(txRaw []byte, id [32]byte, inputs []consensus.Outpoint) mempoolEntry {
		parsed, _, wtxid, _, err := consensus.ParseTx(txRaw)
		if err != nil {
			t.Fatalf("ParseTx(snapshotEntry): %v", err)
		}
		weight, _, _, err := consensus.TxWeightAndStats(parsed)
		if err != nil {
			t.Fatalf("TxWeightAndStats(snapshotEntry): %v", err)
		}
		return mempoolEntry{
			raw:          append([]byte(nil), txRaw...),
			txid:         id,
			wtxid:        wtxid,
			inputs:       append([]consensus.Outpoint(nil), inputs...),
			size:         len(txRaw),
			weight:       weight,
			admissionSeq: 99,
			source:       mempoolTxSourceLocal,
		}
	}
	cloneSnapshotForTest := func(base mempoolSnapshot) mempoolSnapshot {
		entries := make([]mempoolEntry, 0, len(base.entries))
		for i := range base.entries {
			entries = append(entries, cloneMempoolEntry(&base.entries[i]))
		}
		return mempoolSnapshot{entries: entries, lastAdmissionSeq: base.lastAdmissionSeq, currentMinFeeRate: base.currentMinFeeRate}
	}
	withEditedFirst := func(edit func(*mempoolEntry)) func(mempoolSnapshot) mempoolSnapshot {
		return func(base mempoolSnapshot) mempoolSnapshot {
			bad := cloneSnapshotForTest(base)
			edit(&bad.entries[0])
			return bad
		}
	}

	for _, tc := range []struct {
		name      string
		configure func(*Mempool)
		mutate    func(mempoolSnapshot) mempoolSnapshot
		want      string
	}{
		{
			name:   "zero_size",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.size = 0 }),
			want:   "invalid mempool snapshot entry size",
		},
		{
			name:   "zero_weight",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.weight = 0 }),
			want:   "invalid mempool snapshot entry weight",
		},
		{
			name:   "weight_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.weight++ }),
			want:   "mempool snapshot entry weight mismatch",
		},
		{
			name:   "size_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.size = len(entry.raw) + 1 }),
			want:   "mempool snapshot entry size mismatch",
		},
		{
			name:   "malformed_raw",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.raw, entry.size = []byte{0xde, 0xad}, 2 }),
			want:   "invalid mempool snapshot entry raw",
		},
		{
			name: "trailing_bytes",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.raw = append(entry.raw, 0)
				entry.size = len(entry.raw)
			}),
			want: "mempool snapshot entry has trailing bytes",
		},
		{
			name: "txid_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.txid[0] ^= 0x01
			}),
			want: "mempool snapshot entry txid mismatch",
		},
		{
			name: "wtxid_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.wtxid[0] ^= 0x01
			}),
			want: "mempool snapshot entry wtxid mismatch",
		},
		{
			name:   "zero_admission_seq",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.admissionSeq = 0 }),
			want:   "invalid mempool snapshot entry admission_seq",
		},
		{
			name:   "invalid_source",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.source = "sidecar" }),
			want:   "invalid mempool snapshot entry source",
		},
		{
			name:   "input_count_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) { entry.inputs = nil }),
			want:   "mempool snapshot entry input count mismatch",
		},
		{
			name: "input_mismatch",
			mutate: withEditedFirst(func(entry *mempoolEntry) {
				entry.inputs[0].Vout++
			}),
			want: "mempool snapshot entry input mismatch",
		},
		{
			name: "duplicate_txid",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, bad.entries[0])
				return bad
			},
			want: "duplicate mempool snapshot txid",
		},
		{
			name: "duplicate_admission_seq",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				duplicate := snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]})
				duplicate.admissionSeq = bad.entries[0].admissionSeq
				bad.entries = append(bad.entries, duplicate)
				return bad
			},
			want: "duplicate mempool snapshot admission_seq",
		},
		{
			name: "duplicate_wtxid",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				duplicate := snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]})
				duplicate.wtxid = bad.entries[0].wtxid
				bad.entries = append(bad.entries, duplicate)
				return bad
			},
			want: "duplicate mempool snapshot wtxid",
		},
		{
			name: "admission_high_watermark_below_entry_max",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.lastAdmissionSeq = bad.entries[0].admissionSeq - 1
				return bad
			},
			want: "mempool snapshot admission high-watermark below restored max",
		},
		{
			name: "duplicate_spender",
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, snapshotEntry(txDoubleSpend, doubleSpendID, []consensus.Outpoint{outpoints[0]}))
				return bad
			},
			want: "duplicate mempool snapshot spender",
		},
		{
			name: "aggregate_count_over_cap",
			configure: func(m *Mempool) {
				m.maxTxs = 1
			},
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]}))
				return bad
			},
			want: "mempool snapshot exceeds transaction cap",
		},
		{
			name: "aggregate_bytes_over_cap",
			configure: func(m *Mempool) {
				m.maxBytes = len(txBytes) + len(txSecond) - 1
			},
			mutate: func(base mempoolSnapshot) mempoolSnapshot {
				bad := cloneSnapshotForTest(base)
				bad.entries = append(bad.entries, snapshotEntry(txSecond, txSecondID, []consensus.Outpoint{outpoints[1]}))
				return bad
			},
			want: "mempool snapshot exceeds byte cap",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mp.maxTxs = 10
			mp.maxBytes = len(txBytes) + len(txSecond)
			if tc.configure != nil {
				tc.configure(mp)
			}
			bad := tc.mutate(snapshot)
			if err := restoreMempoolSnapshot(mp, bad); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q rejection, got %v", tc.want, err)
			}
			if got := mp.Len(); got != 1 {
				t.Fatalf("mempool len=%d, want 1 after rejected restore", got)
			}
			if !mp.Contains(wantTxID) {
				t.Fatalf("rejected restore removed existing tx %x", wantTxID)
			}
			if mp.usedBytes != wantBytes {
				t.Fatalf("usedBytes=%d, want %d after rejected restore", mp.usedBytes, wantBytes)
			}
		})
	}
}

func TestRestoreMempoolSnapshotAllowsExactCapacityBoundary(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})

	tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
	tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
	source, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 2,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new source mempool: %v", err)
	}
	if err := source.AddTx(tx1); err != nil {
		t.Fatalf("source AddTx(tx1): %v", err)
	}
	if err := source.AddTx(tx2); err != nil {
		t.Fatalf("source AddTx(tx2): %v", err)
	}
	snapshot, err := snapshotMempool(source)
	if err != nil {
		t.Fatalf("snapshotMempool: %v", err)
	}

	target, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{
		MaxTransactions: 2,
		MaxBytes:        len(tx1) + len(tx2),
	})
	if err != nil {
		t.Fatalf("new target mempool: %v", err)
	}
	if err := restoreMempoolSnapshot(target, snapshot); err != nil {
		t.Fatalf("restoreMempoolSnapshot exact boundary: %v", err)
	}
	if got := target.Len(); got != 2 {
		t.Fatalf("mempool len=%d, want 2", got)
	}
	if target.usedBytes != len(tx1)+len(tx2) {
		t.Fatalf("usedBytes=%d, want %d", target.usedBytes, len(tx1)+len(tx2))
	}
}

func TestMempoolAddTxHeightOverflow(t *testing.T) {
	st := &ChainState{HasTip: true, Height: ^uint64(0)} // MaxUint64
	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	err = mp.AddTx([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for height overflow")
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("expected TxAdmitUnavailable, got %v", txErr.Kind)
	}
}

func TestMempoolAddTxBlockMTPError(t *testing.T) {
	// Empty blockStore + non-zero height → prevTimestampsFromStore fails.
	dir := t.TempDir()
	store := mustOpenBlockStore(t, BlockStorePath(dir))
	st := &ChainState{HasTip: true, Height: 50}
	mp, err := NewMempool(st, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	err = mp.AddTx([]byte{0x01})
	if err == nil {
		t.Fatal("expected error for missing block timestamps")
	}
	var txErr *TxAdmitError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TxAdmitError, got %T: %v", err, err)
	}
	if txErr.Kind != TxAdmitUnavailable {
		t.Fatalf("expected TxAdmitUnavailable, got %v", txErr.Kind)
	}
}

func TestMempoolEviction(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	block := buildSingleTxBlock(t, [32]byte{}, consensus.POW_LIMIT, 1, txBytes)
	if err := mp.EvictConfirmed(block); err != nil {
		t.Fatalf("EvictConfirmed: %v", err)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
	if got := mp.usedBytes; got != 0 {
		t.Fatalf("usedBytes=%d, want 0", got)
	}
}

func TestMempoolSelectByFee(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txLow := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	txHigh := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 300_000, 2, fromKey, fromAddress, toAddress)
	txMid := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[2]}, 100_000, 200_000, 3, fromKey, fromAddress, toAddress)
	for _, txBytes := range [][]byte{txLow, txHigh, txMid} {
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("AddTx: %v", err)
		}
	}

	selected := mp.SelectTransactions(2, 1<<20)
	if len(selected) != 2 {
		t.Fatalf("selected=%d, want 2", len(selected))
	}
	if got, want := txIDHex(t, selected[0]), txIDHex(t, txHigh); got != want {
		t.Fatalf("selected[0]=%s, want %s", got, want)
	}
	if got, want := txIDHex(t, selected[1]), txIDHex(t, txMid); got != want {
		t.Fatalf("selected[1]=%s, want %s", got, want)
	}
}

func TestMinerMineOneSelectsFromMempool(t *testing.T) {
	dir := t.TempDir()
	store := mustOpenBlockStore(t, BlockStorePath(dir))

	var tipHash [32]byte
	for height := uint64(0); height <= 100; height++ {
		hash, _ := mustPutBlock(t, store, height, byte(height), height+1, []byte{byte(height)})
		if height == 100 {
			tipHash = hash
		}
	}

	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})
	st.HasTip = true
	st.Height = 100
	st.TipHash = tipHash

	syncEngine, err := NewSyncEngine(st, store, DefaultSyncConfig(nil, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}
	mp, err := NewMempool(st, store, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	syncEngine.SetMempool(mp)

	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}

	cfg := DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 124 }
	miner, err := NewMiner(st, store, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}
	mined, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("MineOne: %v", err)
	}
	if mined.TxCount != 2 {
		t.Fatalf("tx_count=%d, want 2", mined.TxCount)
	}
	if got := mp.Len(); got != 0 {
		t.Fatalf("mempool len=%d, want 0", got)
	}
}

func mustNodeMLDSA87Keypair(t *testing.T) *consensus.MLDSA87Keypair {
	t.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			t.Skipf("ML-DSA backend unavailable: %v", err)
		}
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func testSpendableChainState(fromAddress []byte, values []uint64) (*ChainState, []consensus.Outpoint) {
	st := NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x11
	outpoints := make([]consensus.Outpoint, 0, len(values))
	for i, value := range values {
		var txid [32]byte
		txid[0] = byte(i + 1)
		txid[31] = byte(i + 9)
		op := consensus.Outpoint{Txid: txid, Vout: uint32(i)}
		st.Utxos[op] = consensus.UtxoEntry{
			Value:             value,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      append([]byte(nil), fromAddress...),
			CreationHeight:    1,
			CreatedByCoinbase: true,
		}
		outpoints = append(outpoints, op)
	}
	return st, outpoints
}

func mustBuildSignedTransferTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	inputs []consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	toAddress []byte,
) []byte {
	t.Helper()
	txInputs := make([]consensus.TxInput, 0, len(inputs))
	var totalIn uint64
	for _, op := range inputs {
		entry, ok := utxos[op]
		if !ok {
			t.Fatalf("missing utxo for %x:%d", op.Txid, op.Vout)
		}
		totalIn += entry.Value
		txInputs = append(txInputs, consensus.TxInput{
			PrevTxid: op.Txid,
			PrevVout: op.Vout,
			Sequence: 0,
		})
	}
	change := totalIn - amount - fee
	outputs := []consensus.TxOutput{{
		Value:        amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), toAddress...),
	}}
	if change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), changeAddress...),
		})
	}

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  nonce,
		Inputs:   txInputs,
		Outputs:  outputs,
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return txBytes
}

func mustBuildSignedAnchorOutputTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	anchorValue uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
) []byte {
	t.Helper()
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	var anchorData [32]byte
	anchorData[0] = 0x42
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: anchorValue, CovenantType: consensus.COV_TYPE_ANCHOR, CovenantData: anchorData[:]},
			{Value: entry.Value - anchorValue - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), changeAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(anchor): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(anchor): %v", err)
	}
	return txBytes
}

func mustBuildSignedDaCommitTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	toAddress []byte,
	manifest []byte,
) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x01,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        amount,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), toAddress...),
		}},
		Locktime:  0,
		DaPayload: append([]byte(nil), manifest...),
		DaCommitCore: &consensus.DaCommitCore{
			ChunkCount:  1,
			BatchNumber: 1,
		},
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(da): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(da): %v", err)
	}
	return txBytes
}

func mustBuildSignedCoreExtOutputTx(
	t *testing.T,
	utxos map[consensus.Outpoint]consensus.UtxoEntry,
	input consensus.Outpoint,
	amount uint64,
	fee uint64,
	nonce uint64,
	signer *consensus.MLDSA87Keypair,
	changeAddress []byte,
	extID uint16,
) []byte {
	t.Helper()
	entry, ok := utxos[input]
	if !ok {
		t.Fatalf("missing utxo for %x:%d", input.Txid, input.Vout)
	}
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: input.Txid,
			PrevVout: input.Vout,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{
			{Value: amount, CovenantType: consensus.COV_TYPE_CORE_EXT, CovenantData: coreExtCovenantDataForNodeTest(extID, nil)},
			{Value: entry.Value - amount - fee, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: append([]byte(nil), changeAddress...)},
		},
		Locktime: 0,
	}
	if err := consensus.SignTransaction(tx, utxos, devnetGenesisChainID, signer); err != nil {
		t.Fatalf("SignTransaction(core_ext output): %v", err)
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(core_ext output): %v", err)
	}
	return txBytes
}

func mustBuildCoreExtSpendTx(
	t *testing.T,
	prev [32]byte,
	amount uint64,
	fee uint64,
	nonce uint64,
	toAddress []byte,
) []byte {
	t.Helper()
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: nonce,
		Inputs: []consensus.TxInput{{
			PrevTxid: prev,
			PrevVout: 0,
			Sequence: 0,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        amount,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), toAddress...),
		}},
		Locktime: 0,
		Witness:  []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_SENTINEL}},
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx(core_ext spend): %v", err)
	}
	if gotFee := uint64(100) - amount; gotFee != fee {
		t.Fatalf("fee mismatch: implied=%d declared=%d", gotFee, fee)
	}
	return txBytes
}

func txIDHex(t *testing.T, txBytes []byte) string {
	t.Helper()
	txid := txID(t, txBytes)
	return fmt.Sprintf("%x", txid[:])
}

func txID(t *testing.T, txBytes []byte) [32]byte {
	t.Helper()
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	return txid
}

func TestTxAdmitErrorKinds(t *testing.T) {
	assertKind := func(t *testing.T, err error, wantKind TxAdmitErrorKind) {
		t.Helper()
		var txErr *TxAdmitError
		if !errors.As(err, &txErr) {
			t.Fatalf("expected *TxAdmitError, got %T: %v", err, err)
		}
		if txErr.Kind != wantKind {
			t.Fatalf("kind=%q, want %q (msg=%q)", txErr.Kind, wantKind, txErr.Message)
		}
	}

	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	t.Run("nil mempool", func(t *testing.T) {
		var mp *Mempool
		err := mp.AddTx([]byte{0x00})
		assertKind(t, err, TxAdmitUnavailable)
	})

	t.Run("duplicate tx conflict", func(t *testing.T) {
		st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})
		mp, err := NewMempool(st, nil, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		tx := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(tx); err != nil {
			t.Fatalf("first AddTx: %v", err)
		}
		err = mp.AddTx(tx)
		assertKind(t, err, TxAdmitConflict)
	})

	t.Run("double spend conflict", func(t *testing.T) {
		st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})
		mp, err := NewMempool(st, nil, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
		tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(tx1); err != nil {
			t.Fatalf("first AddTx: %v", err)
		}
		err = mp.AddTx(tx2)
		assertKind(t, err, TxAdmitConflict)
	})

	t.Run("mempool full unavailable", func(t *testing.T) {
		st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000})
		mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 1, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		tx1 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 200_000, 1, fromKey, fromAddress, toAddress)
		tx2 := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[1]}, 100_000, 200_000, 2, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(tx1); err != nil {
			t.Fatalf("first AddTx: %v", err)
		}
		err = mp.AddTx(tx2)
		assertKind(t, err, TxAdmitUnavailable)
	})

	t.Run("rolling floor unavailable", func(t *testing.T) {
		st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})
		mp, err := NewMempoolWithConfig(st, nil, devnetGenesisChainID, MempoolConfig{MaxTransactions: 10, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		mp.currentMinFeeRate = 8
		tx := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 1, 1, fromKey, fromAddress, toAddress)
		err = mp.AddTx(tx)
		assertKind(t, err, TxAdmitUnavailable)
	})

	t.Run("invalid tx rejected", func(t *testing.T) {
		st, _ := testSpendableChainState(fromAddress, []uint64{1_000_000})
		mp, err := NewMempool(st, nil, devnetGenesisChainID)
		if err != nil {
			t.Fatalf("new mempool: %v", err)
		}
		// Garbage bytes that fail consensus.CheckTransaction → rejected.
		err = mp.AddTx([]byte{0xDE, 0xAD})
		assertKind(t, err, TxAdmitRejected)
	})
}

func TestTxAdmitErrorMessage(t *testing.T) {
	err := &TxAdmitError{Kind: TxAdmitConflict, Message: "tx already in mempool"}
	if err.Error() != "tx already in mempool" {
		t.Fatalf("Error()=%q, want %q", err.Error(), "tx already in mempool")
	}
}

func TestMempoolAllTxIDsReturnsEveryEntry(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}

	want := make(map[[32]byte]struct{})
	for i := 0; i < 3; i++ {
		txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[i]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("AddTx[%d]: %v", i, err)
		}
		_, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			t.Fatalf("ParseTx[%d]: %v", i, err)
		}
		want[txid] = struct{}{}
	}

	got := mp.AllTxIDs()
	if len(got) != 3 {
		t.Fatalf("AllTxIDs len=%d, want 3", len(got))
	}
	for _, id := range got {
		if _, ok := want[id]; !ok {
			t.Fatalf("AllTxIDs returned unexpected txid %x", id)
		}
	}
}

func TestMempoolAllTxIDsSortedDeterministic(t *testing.T) {
	// Verify that sorting AllTxIDs produces deterministic lexicographic order;
	// handlers sort the IDs before presenting them.
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000, 1_000_000, 1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	var ids [][32]byte
	for i := 0; i < 3; i++ {
		txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[i]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
		if err := mp.AddTx(txBytes); err != nil {
			t.Fatalf("AddTx[%d]: %v", i, err)
		}
		_, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			t.Fatalf("ParseTx[%d]: %v", i, err)
		}
		ids = append(ids, txid)
	}
	got := mp.AllTxIDs()
	if len(got) != 3 {
		t.Fatalf("AllTxIDs len=%d, want 3", len(got))
	}
	// Replicate handler sort: lexicographic on hex-encoded txid.
	sort.Slice(got, func(i, j int) bool {
		return hex.EncodeToString(got[i][:]) < hex.EncodeToString(got[j][:])
	})
	sort.Slice(ids, func(i, j int) bool {
		return hex.EncodeToString(ids[i][:]) < hex.EncodeToString(ids[j][:])
	})
	for i := range ids {
		if got[i] != ids[i] {
			t.Fatalf("sorted[%d]: got %x, want %x", i, got[i], ids[i])
		}
	}
}

func TestMempoolAllTxIDsEmpty(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, _ := testSpendableChainState(fromAddress, []uint64{100})
	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if got := mp.AllTxIDs(); len(got) != 0 {
		t.Fatalf("AllTxIDs on empty mempool returned %d entries, want 0", len(got))
	}
}

func TestMempoolAllTxIDsNilReceiver(t *testing.T) {
	var mp *Mempool
	if got := mp.AllTxIDs(); got != nil {
		t.Fatalf("AllTxIDs on nil receiver=%v, want nil", got)
	}
}

func TestMempoolTxByIDReturnsRawAndDefensiveCopy(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	got, ok := mp.TxByID(txid)
	if !ok {
		t.Fatalf("TxByID ok=false, want true")
	}
	if !bytes.Equal(got, txBytes) {
		t.Fatalf("TxByID raw mismatch")
	}

	// Defensive-copy invariant: mutate the returned slice and verify the
	// mempool entry remains intact via a second TxByID call.
	got[0] ^= 0xff
	got2, ok2 := mp.TxByID(txid)
	if !ok2 {
		t.Fatalf("TxByID second call ok=false")
	}
	if !bytes.Equal(got2, txBytes) {
		t.Fatalf("mempool entry mutated by caller — defensive copy broken")
	}
}

func TestMempoolTxByIDMissing(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	st, _ := testSpendableChainState(fromAddress, []uint64{100})
	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	var unknown [32]byte
	raw, ok := mp.TxByID(unknown)
	if ok || raw != nil {
		t.Fatalf("TxByID on unknown txid returned raw=%v ok=%v, want nil,false", raw, ok)
	}
}

func TestMempoolTxByIDNilReceiver(t *testing.T) {
	var mp *Mempool
	var id [32]byte
	raw, ok := mp.TxByID(id)
	if ok || raw != nil {
		t.Fatalf("TxByID on nil receiver returned raw=%v ok=%v, want nil,false", raw, ok)
	}
}

func TestMempoolContainsReflectsAdmission(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	_, txid, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}

	if mp.Contains(txid) {
		t.Fatalf("Contains before admit=true, want false")
	}
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	if !mp.Contains(txid) {
		t.Fatalf("Contains after admit=false, want true")
	}
	var other [32]byte
	if mp.Contains(other) {
		t.Fatalf("Contains for unrelated txid=true, want false")
	}
}

func TestMempoolContainsNilReceiver(t *testing.T) {
	var mp *Mempool
	var id [32]byte
	if mp.Contains(id) {
		t.Fatalf("Contains on nil receiver=true, want false")
	}
}

// TestMempoolBytesUsedTracksUsedBytes pins the BytesUsed gauge: empty
// mempool reports 0; after a successful AddTx BytesUsed reflects the
// raw transaction byte size accounted in the existing usedBytes field.
// This is the metric scrape source for rubin_node_mempool_bytes.
func TestMempoolBytesUsedTracksUsedBytes(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if got := mp.BytesUsed(); got != 0 {
		t.Fatalf("BytesUsed empty=%d, want 0", got)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	if got := mp.BytesUsed(); got != len(txBytes) {
		t.Fatalf("BytesUsed=%d, want %d (raw tx size)", got, len(txBytes))
	}
}

// TestMempoolBytesUsedNilReceiver pins the nil-safety contract used by
// the /metrics rendering path: a nil mempool reports 0 bytes without
// panicking, so the scrape rendering can call BytesUsed unconditionally.
func TestMempoolBytesUsedNilReceiver(t *testing.T) {
	var mp *Mempool
	if got := mp.BytesUsed(); got != 0 {
		t.Fatalf("BytesUsed nil receiver=%d, want 0", got)
	}
}

// TestMempoolAdmissionCountsAcceptedBumpsExactlyOnce pins that a happy
// AddTx call increments only the Accepted bucket of the admission
// counters and leaves the other three buckets at zero.
func TestMempoolAdmissionCountsAcceptedBumpsExactlyOnce(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	if got := mp.AdmissionCounts(); got != (MempoolAdmissionCounts{}) {
		t.Fatalf("AdmissionCounts pre-AddTx=%+v, want zero", got)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("AddTx: %v", err)
	}
	got := mp.AdmissionCounts()
	if got.Accepted != 1 || got.Conflict != 0 || got.Rejected != 0 || got.Unavailable != 0 {
		t.Fatalf("AdmissionCounts after accepted AddTx=%+v, want only Accepted=1", got)
	}
}

// TestMempoolAdmissionCountsConflictBumpsExactlyOnce pins that a
// duplicate-txid AddTx call routes to the Conflict bucket. The first
// AddTx accepts; the second AddTx with the same bytes hits the
// validateAdmissionLocked duplicate-spender path which returns
// txAdmitConflict.
func TestMempoolAdmissionCountsConflictBumpsExactlyOnce(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	if err := mp.AddTx(txBytes); err != nil {
		t.Fatalf("first AddTx: %v", err)
	}
	dupErr := mp.AddTx(txBytes)
	if dupErr == nil {
		t.Fatalf("duplicate AddTx unexpectedly accepted")
	}
	var admitErr *TxAdmitError
	if !errors.As(dupErr, &admitErr) || admitErr.Kind != TxAdmitConflict {
		t.Fatalf("duplicate AddTx err=%v (kind=%v), want TxAdmitConflict", dupErr, func() any {
			if admitErr != nil {
				return admitErr.Kind
			}
			return "<nil>"
		}())
	}
	got := mp.AdmissionCounts()
	if got.Accepted != 1 {
		t.Fatalf("AdmissionCounts.Accepted=%d, want 1 (first AddTx)", got.Accepted)
	}
	if got.Conflict != 1 || got.Rejected != 0 || got.Unavailable != 0 {
		t.Fatalf("AdmissionCounts after duplicate=%+v, want Conflict=1", got)
	}
}

// TestMempoolAdmissionCountsRejectedBumpsExactlyOnce pins that an
// AddTx call rejected by the parse-time path (here: trailing bytes
// after canonical tx) routes to the Rejected bucket via the
// txAdmitRejected helper inside checkTransactionWithSnapshot.
func TestMempoolAdmissionCountsRejectedBumpsExactlyOnce(t *testing.T) {
	fromKey := mustNodeMLDSA87Keypair(t)
	toKey := mustNodeMLDSA87Keypair(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())
	st, outpoints := testSpendableChainState(fromAddress, []uint64{1_000_000})

	mp, err := NewMempool(st, nil, devnetGenesisChainID)
	if err != nil {
		t.Fatalf("new mempool: %v", err)
	}
	txBytes := mustBuildSignedTransferTx(t, st.Utxos, []consensus.Outpoint{outpoints[0]}, 100_000, 100_000, 1, fromKey, fromAddress, toAddress)
	// Append a trailing byte to force the "trailing bytes after canonical
	// tx" reject path inside checkTransactionWithSnapshot.
	bad := append([]byte{}, txBytes...)
	bad = append(bad, 0x00)
	addErr := mp.AddTx(bad)
	if addErr == nil {
		t.Fatalf("malformed AddTx unexpectedly accepted")
	}
	var admitErr *TxAdmitError
	if !errors.As(addErr, &admitErr) || admitErr.Kind != TxAdmitRejected {
		t.Fatalf("malformed AddTx err=%v, want TxAdmitRejected", addErr)
	}
	got := mp.AdmissionCounts()
	if got.Rejected != 1 || got.Accepted != 0 || got.Conflict != 0 || got.Unavailable != 0 {
		t.Fatalf("AdmissionCounts after malformed=%+v, want Rejected=1", got)
	}
}

// TestMempoolAdmissionCountsUnavailableBumpsExactlyOnce pins that an
// AddTx call hitting the nil-chainstate guard routes to the
// Unavailable bucket. nil-chainstate is the explicit unavailable
// branch documented in AddTx.
func TestMempoolAdmissionCountsUnavailableBumpsExactlyOnce(t *testing.T) {
	mp := &Mempool{} // chainState nil — exercises txAdmitUnavailable("nil chainstate")
	addErr := mp.AddTx([]byte{0x00})
	if addErr == nil {
		t.Fatalf("AddTx on nil-chainstate mempool unexpectedly accepted")
	}
	var admitErr *TxAdmitError
	if !errors.As(addErr, &admitErr) || admitErr.Kind != TxAdmitUnavailable {
		t.Fatalf("AddTx err=%v, want TxAdmitUnavailable", addErr)
	}
	got := mp.AdmissionCounts()
	if got.Unavailable != 1 || got.Accepted != 0 || got.Conflict != 0 || got.Rejected != 0 {
		t.Fatalf("AdmissionCounts after unavailable=%+v, want Unavailable=1", got)
	}
}

// TestMempoolAdmissionCountsNilReceiver pins the nil-safety contract
// used by /metrics rendering: a nil mempool returns the zero-value
// MempoolAdmissionCounts struct without panicking.
func TestMempoolAdmissionCountsNilReceiver(t *testing.T) {
	var mp *Mempool
	if got := mp.AdmissionCounts(); got != (MempoolAdmissionCounts{}) {
		t.Fatalf("AdmissionCounts nil receiver=%+v, want zero struct", got)
	}
}

package node

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestLoadChainState_InvalidFileName(t *testing.T) {
	// readFileFromDir rejects "." and ".." and LoadChainState should surface the error.
	st, err := LoadChainState(filepath.Join(t.TempDir(), "."))
	if err == nil {
		t.Fatalf("expected error")
	}
	if st != nil {
		t.Fatalf("state should be nil on read error")
	}
}

func TestLoadChainState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chainstate.json")
	// RUB-1134: planted INSIDE a valid frame so the row still reaches the INNER
	// chainStateDisk decode rather than the legacy verdict (owned by
	// TestLoadChainStateRejectsIntegrityFailures).
	raw, err := marshalStoreEnvelope(storeEnvelopeChainState, []byte("{\n"))
	if err != nil {
		t.Fatalf("wrap chainstate: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadChainState(path); err == nil {
		t.Fatalf("expected error")
	} else if errors.Is(err, ErrStoreIntegrity) {
		t.Fatalf("row must fail on the inner decode class, got %v", err)
	}
}

func TestChainStateSave_NilReceiver(t *testing.T) {
	var st *ChainState
	if err := st.Save(filepath.Join(t.TempDir(), "x.json")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestNextBlockContext_Errors(t *testing.T) {
	if _, _, err := nextBlockContext(nil); err == nil {
		t.Fatalf("expected error")
	}
	if _, _, err := nextBlockContext(&ChainState{HasTip: true, Height: ^uint64(0)}); err == nil {
		t.Fatalf("expected height overflow error")
	}
}

func TestStateToDisk_NilReceiver(t *testing.T) {
	if _, err := stateToDisk(nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestCopySelectedUtxoSetCopiesRequestedEntries(t *testing.T) {
	t.Parallel()

	var txidA, txidB [32]byte
	txidA[0] = 0xaa
	txidB[0] = 0xbb
	opA := consensus.Outpoint{Txid: txidA, Vout: 1}
	opB := consensus.Outpoint{Txid: txidB, Vout: 2}
	src := map[consensus.Outpoint]consensus.UtxoEntry{
		opA: {
			Value:             11,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      []byte{0x01, 0x02},
			CreationHeight:    7,
			CreatedByCoinbase: true,
		},
		opB: {
			Value:             22,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      []byte{0x03, 0x04},
			CreationHeight:    8,
			CreatedByCoinbase: false,
		},
	}

	out := copySelectedUtxoSet(src, []consensus.Outpoint{opA, opA, {Txid: [32]byte{0xcc}, Vout: 9}})
	if len(out) != 1 {
		t.Fatalf("len(out)=%d, want 1", len(out))
	}
	if _, ok := out[opA]; !ok {
		t.Fatal("copied set missing requested outpoint")
	}
	if _, ok := out[opB]; ok {
		t.Fatal("copied set unexpectedly contains unrelated outpoint")
	}

	entry := out[opA]
	entry.CovenantData[0] ^= 0xff
	out[opA] = entry
	if src[opA].CovenantData[0] == out[opA].CovenantData[0] {
		t.Fatal("copySelectedUtxoSet aliased covenant data")
	}
}

func TestCountExistingUniqueOutpointsSkipsMissingAndDuplicates(t *testing.T) {
	t.Parallel()

	var txidA, txidB [32]byte
	txidA[0] = 0xaa
	txidB[0] = 0xbb
	opA := consensus.Outpoint{Txid: txidA, Vout: 1}
	opB := consensus.Outpoint{Txid: txidB, Vout: 2}

	src := map[consensus.Outpoint]consensus.UtxoEntry{
		opA: {Value: 11, CovenantType: consensus.COV_TYPE_P2PK},
	}

	count := countExistingUniqueOutpoints(src, []consensus.Outpoint{opA, opA, opB})
	if count != 1 {
		t.Fatalf("countExistingUniqueOutpoints=%d, want 1", count)
	}
}

func TestStateToDisk_SortsByVoutWhenSameTxid(t *testing.T) {
	txid := mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	st := &ChainState{
		HasTip:           true,
		Height:           1,
		TipHash:          txid,
		AlreadyGenerated: 0,
		Utxos: map[consensus.Outpoint]consensus.UtxoEntry{
			{Txid: txid, Vout: 2}: {Value: 1, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: []byte{0x01}},
			{Txid: txid, Vout: 1}: {Value: 2, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: []byte{0x02}},
		},
	}
	disk, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk: %v", err)
	}
	if len(disk.Utxos) != 2 {
		t.Fatalf("utxos=%d, want 2", len(disk.Utxos))
	}
	if disk.Utxos[0].Txid != disk.Utxos[1].Txid {
		t.Fatalf("expected same txid in both entries")
	}
	if disk.Utxos[0].Vout != 1 || disk.Utxos[1].Vout != 2 {
		t.Fatalf("vout order=%d,%d; want 1,2", disk.Utxos[0].Vout, disk.Utxos[1].Vout)
	}
}

func TestChainStateFromDisk_Errors(t *testing.T) {
	zeros64 := strings.Repeat("00", 32)

	t.Run("version_mismatch", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{Version: chainStateDiskVersion + 1})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("bad_tip_hash", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{Version: chainStateDiskVersion, TipHash: "zz"})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("bad_utxo_txid", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{
			Version: chainStateDiskVersion,
			TipHash: zeros64,
			Utxos: []utxoDiskEntry{
				{Txid: "zz", Vout: 0, CovenantData: ""},
			},
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("bad_utxo_covenant_data", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{
			Version: chainStateDiskVersion,
			TipHash: zeros64,
			Utxos: []utxoDiskEntry{
				{Txid: zeros64, Vout: 0, CovenantData: "abc"},
			},
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("duplicate_outpoint", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{
			Version: chainStateDiskVersion,
			TipHash: zeros64,
			Utxos: []utxoDiskEntry{
				{Txid: zeros64, Vout: 1, CovenantData: ""},
				{Txid: zeros64, Vout: 1, CovenantData: ""},
			},
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestParseHex_Errors(t *testing.T) {
	if _, err := parseHex("x", "a"); err == nil {
		t.Fatalf("expected odd-length error")
	}
	if _, err := parseHex("x", "zz"); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestParseHex32_Errors(t *testing.T) {
	if _, err := parseHex32("x", ""); err == nil {
		t.Fatalf("expected length mismatch error")
	}
}

func TestWriteFileAtomic_Errors(t *testing.T) {
	t.Run("write_fails_missing_dir", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nope", "x.json")
		if err := writeFileAtomic(path, []byte("x"), 0o600); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("rename_fails_target_is_dir", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeFileAtomic(dir, []byte("x"), 0o600); err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestDevnetGenesisBlockBytes_NonEmpty(t *testing.T) {
	raw := DevnetGenesisBlockBytes()
	if len(raw) == 0 {
		t.Fatal("DevnetGenesisBlockBytes returned empty slice")
	}
	// Defensive copy: mutating returned slice must not affect source.
	raw[0] = 0xFF
	raw2 := DevnetGenesisBlockBytes()
	if raw2[0] == 0xFF {
		t.Fatal("DevnetGenesisBlockBytes must return a defensive copy")
	}
}

func TestDevnetGenesisBlockHash_NonZero(t *testing.T) {
	hash := DevnetGenesisBlockHash()
	var zero [32]byte
	if hash == zero {
		t.Fatal("DevnetGenesisBlockHash returned all zeros")
	}
}

func TestChainStateConnectBlock_NilReceiver(t *testing.T) {
	var st *ChainState
	if _, err := st.ConnectBlock(nil, nil, nil, [32]byte{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestChainStateConnectBlock_NilUtxoMapInitialized(t *testing.T) {
	target := consensus.POW_LIMIT
	st := &ChainState{HasTip: true, Height: 0, Utxos: nil}
	st.TipHash = mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111")

	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block := buildSingleTxBlock(t, st.TipHash, target, 2, coinbase)

	if _, err := st.ConnectBlock(block, &target, nil, devnetGenesisChainID); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	if st.Utxos == nil {
		t.Fatalf("utxo map should be initialized")
	}
}

func TestChainStateConnectSupplyOverflowPreservesNonzeroState(t *testing.T) {
	const height = uint64(5_771_107)
	target := consensus.POW_LIMIT

	for _, parallel := range []bool{false, true} {
		path := "sequential"
		if parallel {
			path = "parallel"
		}
		t.Run(path, func(t *testing.T) {
			tip := mustHash32Hex(t, "1212121212121212121212121212121212121212121212121212121212121212")
			originalUtxos := map[consensus.Outpoint]consensus.UtxoEntry{
				{Txid: mustHash32Hex(t, "3434343434343434343434343434343434343434343434343434343434343434"), Vout: 2}: {
					Value:             17,
					CovenantType:      consensus.COV_TYPE_P2PK,
					CovenantData:      testP2PKCovenantData(0x34),
					CreationHeight:    11,
					CreatedByCoinbase: false,
				},
			}
			st := &ChainState{
				HasTip:           true,
				Height:           height - 1,
				TipHash:          tip,
				AlreadyGenerated: ^uint64(0),
				Utxos:            originalUtxos,
			}
			before, err := stateToDisk(st)
			if err != nil {
				t.Fatalf("stateToDisk(before): %v", err)
			}
			coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, consensus.TAIL_EMISSION_PER_BLOCK)
			block := buildSingleTxBlock(t, tip, target, height, coinbase)

			var summary *ChainStateConnectSummary
			if parallel {
				summary, err = st.ConnectBlockParallelSigs(block, &target, nil, devnetGenesisChainID, 2)
			} else {
				summary, err = st.ConnectBlock(block, &target, nil, devnetGenesisChainID)
			}
			if err == nil || summary != nil || !strings.Contains(err.Error(), "already_generated overflow") {
				t.Fatalf("summary=%#v err=%v, want durable supply overflow", summary, err)
			}
			after, diskErr := stateToDisk(st)
			if diskErr != nil {
				t.Fatalf("stateToDisk(after): %v", diskErr)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("durable state changed on supply overflow")
			}
			probe := consensus.Outpoint{Txid: [32]byte{0x56}, Vout: 3}
			originalUtxos[probe] = consensus.UtxoEntry{Value: 18}
			if _, ok := st.Utxos[probe]; !ok {
				t.Fatal("durable UTXO map was replaced on supply overflow")
			}
		})
	}
}

func TestApplyConnectedBlockConvertsAllSupplyValuesBeforeMutation(t *testing.T) {
	overU64 := new(big.Int).Lsh(big.NewInt(1), 64)
	wide := consensus.Uint128{Hi: 1}

	for _, tc := range []struct {
		name       string
		workSupply *big.Int
		before     consensus.Uint128
		after      consensus.Uint128
	}{
		{name: "work_state", workSupply: overU64, before: consensus.Uint128FromU64(9), after: consensus.Uint128FromU64(10)},
		{name: "summary_before", workSupply: big.NewInt(10), before: wide, after: consensus.Uint128FromU64(10)},
		{name: "summary_after", workSupply: big.NewInt(10), before: consensus.Uint128FromU64(9), after: wide},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tip := [32]byte{0x71}
			originalUtxos := map[consensus.Outpoint]consensus.UtxoEntry{
				{Txid: [32]byte{0x72}, Vout: 1}: {Value: 21, CovenantData: []byte{0xaa}},
			}
			st := &ChainState{HasTip: true, Height: 7, TipHash: tip, AlreadyGenerated: 9, Utxos: originalUtxos}
			beforeState, err := stateToDisk(st)
			if err != nil {
				t.Fatalf("stateToDisk(before): %v", err)
			}
			work := &consensus.InMemoryChainState{
				AlreadyGenerated: new(big.Int).Set(tc.workSupply),
				Utxos: map[consensus.Outpoint]consensus.UtxoEntry{
					{Txid: [32]byte{0x73}, Vout: 2}: {Value: 22},
				},
			}
			result := &consensus.ConnectBlockBasicSummary{
				AlreadyGenerated:   tc.before,
				AlreadyGeneratedN1: tc.after,
				UtxoCount:          1,
			}

			out, err := st.applyConnectedBlockLocked(8, [32]byte{0x74}, work, result)
			if err == nil || out != nil || !strings.Contains(err.Error(), "already_generated overflow") {
				t.Fatalf("out=%#v err=%v, want supply overflow", out, err)
			}
			afterState, diskErr := stateToDisk(st)
			if diskErr != nil {
				t.Fatalf("stateToDisk(after): %v", diskErr)
			}
			if !reflect.DeepEqual(beforeState, afterState) {
				t.Fatal("durable state changed before all supply conversions completed")
			}
			probe := consensus.Outpoint{Txid: [32]byte{0x75}, Vout: 3}
			originalUtxos[probe] = consensus.UtxoEntry{Value: 23}
			if _, ok := st.Utxos[probe]; !ok {
				t.Fatal("durable UTXO map was replaced before all supply conversions completed")
			}
		})
	}
}

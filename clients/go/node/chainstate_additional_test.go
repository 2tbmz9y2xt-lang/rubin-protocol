package node

import (
	"os"
	"path/filepath"
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
	if err := os.WriteFile(path, []byte("{\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := LoadChainState(path)
	if err == nil {
		t.Fatalf("expected error")
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

func TestChainStateConnectBlock_NilReceiver(t *testing.T) {
	var st *ChainState
	if _, err := st.ConnectBlock(nil, nil, nil, [32]byte{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestChainStateConnectBlock_NilUtxoMapInitialized(t *testing.T) {
	target := consensus.POW_LIMIT
	var chainID [32]byte

	st := &ChainState{Utxos: nil}
	prev := mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111")
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, 1)
	block := buildSingleTxBlock(t, prev, target, 1, coinbase)

	if _, err := st.ConnectBlock(block, &target, nil, chainID); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	if st.Utxos == nil {
		t.Fatalf("utxo map should be initialized")
	}
}

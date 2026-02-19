package store

import (
	"math/big"
	"testing"

	"rubin.dev/node/consensus"
)

func TestDB_PutGetUTXOAndLoadSet(t *testing.T) {
	datadir := t.TempDir()
	chainIDHex := "00" + "11" + "22" + "33" + "44" + "55" + "66" + "77" + "88" + "99" + "aa" + "bb" + "cc" + "dd" + "ee" + "ff" + "00" + "11" + "22" + "33" + "44" + "55" + "66" + "77" + "88" + "99" + "aa" + "bb" + "cc" + "dd" + "ee" + "ff"
	// 64 hex chars required; ensure exact length.
	if len(chainIDHex) != 64 {
		t.Fatalf("bad chainIDHex length: %d", len(chainIDHex))
	}

	db, err := Open(datadir, chainIDHex)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_ = db.ChainDir()
	_ = db.Manifest()

	var txid [32]byte
	txid[0] = 1
	point := consensus.TxOutPoint{TxID: txid, Vout: 2}
	entry := consensus.UtxoEntry{
		Output: consensus.TxOutput{
			Value:        7,
			CovenantType: 0x9999,
			CovenantData: []byte{0x01, 0x02},
		},
		CreationHeight:    3,
		CreatedByCoinbase: true,
	}
	if err := db.PutUTXO(point, entry); err != nil {
		t.Fatalf("PutUTXO: %v", err)
	}
	got, ok, err := db.GetUTXO(point)
	if err != nil || !ok {
		t.Fatalf("GetUTXO: ok=%v err=%v", ok, err)
	}
	if got.Output.Value != entry.Output.Value || got.CreationHeight != entry.CreationHeight || got.CreatedByCoinbase != entry.CreatedByCoinbase {
		t.Fatalf("got mismatch: %+v want %+v", got, entry)
	}

	utxo, err := db.LoadUTXOSet()
	if err != nil {
		t.Fatalf("LoadUTXOSet: %v", err)
	}
	if len(utxo) != 1 {
		t.Fatalf("expected 1 utxo, got %d", len(utxo))
	}

	if err := db.DeleteUTXO(point); err != nil {
		t.Fatalf("DeleteUTXO: %v", err)
	}
	_, ok, err = db.GetUTXO(point)
	if err != nil {
		t.Fatalf("GetUTXO after delete: %v", err)
	}
	if ok {
		t.Fatalf("expected utxo to be deleted")
	}

	undo := UndoRecord{
		Spent:   []UndoSpent{},
		Created: []consensus.TxOutPoint{},
	}
	var bh [32]byte
	bh[0] = 9
	if err := db.PutUndo(bh, undo); err != nil {
		t.Fatalf("PutUndo: %v", err)
	}
	_, ok, err = db.GetUndo(bh)
	if err != nil || !ok {
		t.Fatalf("GetUndo: ok=%v err=%v", ok, err)
	}
}

func TestDB_IndexEncodeDecode(t *testing.T) {
	var prev [32]byte
	prev[0] = 1
	e := BlockIndexEntry{
		Height:         5,
		PrevHash:       prev,
		CumulativeWork: big.NewInt(12345),
		Status:         BlockStatusValid,
	}
	b, err := encodeIndexEntry(e)
	if err != nil {
		t.Fatalf("encodeIndexEntry: %v", err)
	}
	dec, err := decodeIndexEntry(b)
	if err != nil {
		t.Fatalf("decodeIndexEntry: %v", err)
	}
	if dec.Height != e.Height || dec.Status != e.Status || dec.CumulativeWork.Cmp(e.CumulativeWork) != 0 {
		t.Fatalf("decoded mismatch: %+v vs %+v", dec, e)
	}
	if _, err := decodeIndexEntry(b[:10]); err == nil {
		t.Fatalf("expected truncated error")
	}
}

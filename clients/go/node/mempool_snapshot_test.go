package node

import "testing"

func TestMempoolTxIDsLimitBoundsSnapshot(t *testing.T) {
	mp := &Mempool{txs: map[[32]byte]*mempoolEntry{
		{0x01}: {},
		{0x02}: {},
		{0x03}: {},
	}}
	if got := mp.TxIDsLimit(2); len(got) != 2 {
		t.Fatalf("TxIDsLimit len=%d, want 2", len(got))
	}
	if got := mp.TxIDsLimit(0); got != nil {
		t.Fatalf("TxIDsLimit(0)=%v, want nil", got)
	}
	if got := mp.AllTxIDs(); len(got) != 3 {
		t.Fatalf("AllTxIDs len=%d, want 3", len(got))
	}
}

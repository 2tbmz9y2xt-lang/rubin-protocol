package node

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type testSimplicityRotation struct{ activeAt uint64 }

func (r testSimplicityRotation) NativeCreateSuites(uint64) *consensus.NativeSuiteSet {
	return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87)
}
func (r testSimplicityRotation) NativeSpendSuites(uint64) *consensus.NativeSuiteSet {
	return consensus.NewNativeSuiteSet(consensus.SUITE_ID_ML_DSA_87)
}
func (r testSimplicityRotation) SimplicityActiveAtHeight(height uint64) (bool, error) {
	return height >= r.activeAt, nil
}

func simplicityCovenantDataForNodeTest(programCMR [32]byte, state []byte) []byte {
	out := append([]byte(nil), programCMR[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(state)))
	out = append(out, state...)
	return out
}

func txWithOneInputOneOutput(prevTxid [32]byte, prevVout uint32, outValue uint64, outCovType uint16, outCovData []byte, witnesses []consensus.WitnessItem) []byte {
	b := make([]byte, 0, 256+len(outCovData))
	b = consensus.AppendU32le(b, 1)
	b = append(b, 0x00) // tx_kind
	b = consensus.AppendU64le(b, 1)
	b = consensus.AppendCompactSize(b, 1)
	b = append(b, prevTxid[:]...)
	b = consensus.AppendU32le(b, prevVout)
	b = consensus.AppendCompactSize(b, 0)
	b = consensus.AppendU32le(b, 0)
	b = consensus.AppendCompactSize(b, 1)
	b = consensus.AppendU64le(b, outValue)
	b = consensus.AppendU16le(b, outCovType)
	b = consensus.AppendCompactSize(b, uint64(len(outCovData)))
	b = append(b, outCovData...)
	b = consensus.AppendU32le(b, 0)
	b = consensus.AppendCompactSize(b, uint64(len(witnesses)))
	for _, w := range witnesses {
		b = append(b, w.SuiteID)
		b = consensus.AppendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = consensus.AppendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}
	b = consensus.AppendCompactSize(b, 0)
	return b
}

func mustParseTx(t *testing.T, raw []byte) *consensus.Tx {
	t.Helper()
	tx, _, _, consumed, err := consensus.ParseTx(raw)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(raw) {
		t.Fatalf("consumed=%d len=%d", consumed, len(raw))
	}
	return tx
}

func mustMarshalTxForNodeTest(t *testing.T, tx *consensus.Tx) []byte {
	t.Helper()
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return txBytes
}

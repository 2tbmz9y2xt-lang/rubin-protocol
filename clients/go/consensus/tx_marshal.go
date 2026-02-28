package consensus

import "fmt"

// MarshalTx serialises a Tx into its canonical wire-format bytes.
// The output is the exact inverse of ParseTx (roundtrip property).
func MarshalTx(tx *Tx) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("nil tx")
	}

	var b []byte

	// Header: version(4) | tx_kind(1) | tx_nonce(8)
	b = AppendU32le(b, tx.Version)
	b = append(b, tx.TxKind)
	b = AppendU64le(b, tx.TxNonce)

	// Inputs
	b = AppendCompactSize(b, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		b = append(b, in.PrevTxid[:]...)
		b = AppendU32le(b, in.PrevVout)
		b = AppendCompactSize(b, uint64(len(in.ScriptSig)))
		b = append(b, in.ScriptSig...)
		b = AppendU32le(b, in.Sequence)
	}

	// Outputs
	b = AppendCompactSize(b, uint64(len(tx.Outputs)))
	for _, o := range tx.Outputs {
		b = AppendU64le(b, o.Value)
		b = AppendU16le(b, o.CovenantType)
		b = AppendCompactSize(b, uint64(len(o.CovenantData)))
		b = append(b, o.CovenantData...)
	}

	// Locktime
	b = AppendU32le(b, tx.Locktime)

	// Witness
	b = AppendCompactSize(b, uint64(len(tx.Witness)))
	for _, w := range tx.Witness {
		b = append(b, w.SuiteID)
		b = AppendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = AppendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}

	// DA payload
	b = AppendCompactSize(b, uint64(len(tx.DaPayload)))
	b = append(b, tx.DaPayload...)

	return b, nil
}

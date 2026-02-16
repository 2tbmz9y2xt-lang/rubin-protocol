package consensus

import (
	"encoding/binary"
	"fmt"

	"rubin.dev/node/crypto"
)

type Tx struct {
	Version  uint32
	TxNonce  uint64
	Inputs   []TxInput
	Outputs  []TxOutput
	Locktime uint32
	Witness  WitnessSection
}

type TxInput struct {
	PrevTxid  [32]byte
	PrevVout  uint32
	ScriptSig []byte
	Sequence  uint32
}

type TxOutput struct {
	Value        uint64
	CovenantType uint16
	CovenantData []byte
}

type WitnessSection struct {
	Witnesses []WitnessItem
}

type WitnessItem struct {
	SuiteID   byte
	Pubkey    []byte
	Signature []byte
}

type cursor struct {
	b   []byte
	pos int
}

func maxIntAsUint64() uint64 {
	return uint64(^uint(0) >> 1)
}

func toIntLen(v uint64, name string) (int, error) {
	if v > maxIntAsUint64() {
		return 0, fmt.Errorf("parse: %s overflows usize", name)
	}
	// #nosec G115 -- v is bounded to int by maxIntAsUint64 above.
	return int(v), nil
}

func u32ToInt(v uint32, name string, max int) (int, error) {
	if max < 0 {
		return 0, fmt.Errorf("parse: %s invalid bound", name)
	}
	if uint64(v) > uint64(max) {
		return 0, fmt.Errorf("parse: %s does not fit int", name)
	}
	// #nosec G115 -- v is bounded to max via explicit uint32 comparison above.
	return int(v), nil
}

func newCursor(b []byte) *cursor {
	return &cursor{b: b, pos: 0}
}

func (c *cursor) remaining() int {
	if c.pos >= len(c.b) {
		return 0
	}
	return len(c.b) - c.pos
}

func (c *cursor) readExact(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("parse: truncated")
	}
	start := c.pos
	c.pos += n
	return c.b[start:c.pos], nil
}

func (c *cursor) readU8() (byte, error) {
	b, err := c.readExact(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) readU16LE() (uint16, error) {
	b, err := c.readExact(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (c *cursor) readU32LE() (uint32, error) {
	b, err := c.readExact(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (c *cursor) readU64LE() (uint64, error) {
	b, err := c.readExact(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (c *cursor) readCompactSize() (uint64, error) {
	cs, used, err := DecodeCompactSize(c.b[c.pos:])
	if err != nil {
		return 0, err
	}
	c.pos += used
	return uint64(cs), nil
}

func ParseTxBytes(b []byte) (*Tx, error) {
	cur := newCursor(b)

	version, err := cur.readU32LE()
	if err != nil {
		return nil, err
	}
	txNonce, err := cur.readU64LE()
	if err != nil {
		return nil, err
	}

	inputCountU64, err := cur.readCompactSize()
	if err != nil {
		return nil, err
	}
	inputCount, err := toIntLen(inputCountU64, "input_count")
	if err != nil {
		return nil, err
	}
	inputs := make([]TxInput, 0, inputCount)
	for i := 0; i < inputCount; i++ {
		prevTxidBytes, err := cur.readExact(32)
		if err != nil {
			return nil, err
		}
		var prevTxid [32]byte
		copy(prevTxid[:], prevTxidBytes)

		prevVout, err := cur.readU32LE()
		if err != nil {
			return nil, err
		}

		scriptSigLenU64, err := cur.readCompactSize()
		if err != nil {
			return nil, err
		}
		scriptSigLen, err := toIntLen(scriptSigLenU64, "script_sig_len")
		if err != nil {
			return nil, err
		}
		scriptSigBytes, err := cur.readExact(scriptSigLen)
		if err != nil {
			return nil, err
		}

		sequence, err := cur.readU32LE()
		if err != nil {
			return nil, err
		}

		inputs = append(inputs, TxInput{
			PrevTxid:  prevTxid,
			PrevVout:  prevVout,
			ScriptSig: append([]byte(nil), scriptSigBytes...),
			Sequence:  sequence,
		})
	}

	outputCountU64, err := cur.readCompactSize()
	if err != nil {
		return nil, err
	}
	outputCount, err := toIntLen(outputCountU64, "output_count")
	if err != nil {
		return nil, err
	}
	outputs := make([]TxOutput, 0, outputCount)
	for i := 0; i < outputCount; i++ {
		value, err := cur.readU64LE()
		if err != nil {
			return nil, err
		}
		covenantType, err := cur.readU16LE()
		if err != nil {
			return nil, err
		}
		covenantDataLenU64, err := cur.readCompactSize()
		if err != nil {
			return nil, err
		}
		covenantDataLen, err := toIntLen(covenantDataLenU64, "covenant_data_len")
		if err != nil {
			return nil, err
		}
		covenantDataBytes, err := cur.readExact(covenantDataLen)
		if err != nil {
			return nil, err
		}

		outputs = append(outputs, TxOutput{
			Value:        value,
			CovenantType: covenantType,
			CovenantData: append([]byte(nil), covenantDataBytes...),
		})
	}

	locktime, err := cur.readU32LE()
	if err != nil {
		return nil, err
	}

	witnessCountU64, err := cur.readCompactSize()
	if err != nil {
		return nil, err
	}
	witnessCount, err := toIntLen(witnessCountU64, "witness_count")
	if err != nil {
		return nil, err
	}
	witnesses := make([]WitnessItem, 0, witnessCount)
	for i := 0; i < witnessCount; i++ {
		suiteID, err := cur.readU8()
		if err != nil {
			return nil, err
		}
		pubkeyLenU64, err := cur.readCompactSize()
		if err != nil {
			return nil, err
		}
		pubkeyLen, err := toIntLen(pubkeyLenU64, "pubkey_len")
		if err != nil {
			return nil, err
		}
		pubkeyBytes, err := cur.readExact(pubkeyLen)
		if err != nil {
			return nil, err
		}

		sigLenU64, err := cur.readCompactSize()
		if err != nil {
			return nil, err
		}
		sigLen, err := toIntLen(sigLenU64, "sig_len")
		if err != nil {
			return nil, err
		}
		sigBytes, err := cur.readExact(sigLen)
		if err != nil {
			return nil, err
		}

		witnesses = append(witnesses, WitnessItem{
			SuiteID:   suiteID,
			Pubkey:    append([]byte(nil), pubkeyBytes...),
			Signature: append([]byte(nil), sigBytes...),
		})
	}

	if cur.pos != len(b) {
		return nil, fmt.Errorf("parse: trailing bytes")
	}

	return &Tx{
		Version:  version,
		TxNonce:  txNonce,
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: locktime,
		Witness:  WitnessSection{Witnesses: witnesses},
	}, nil
}

func TxOutputBytes(o TxOutput) []byte {
	out := make([]byte, 0, 8+2+9+len(o.CovenantData))
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], o.Value)
	out = append(out, tmp8[:]...)
	var tmp2 [2]byte
	binary.LittleEndian.PutUint16(tmp2[:], o.CovenantType)
	out = append(out, tmp2[:]...)
	out = append(out, CompactSize(len(o.CovenantData)).Encode()...)
	out = append(out, o.CovenantData...)
	return out
}

func WitnessItemBytes(w WitnessItem) []byte {
	out := make([]byte, 0, 1+9+len(w.Pubkey)+9+len(w.Signature))
	out = append(out, w.SuiteID)
	out = append(out, CompactSize(len(w.Pubkey)).Encode()...)
	out = append(out, w.Pubkey...)
	out = append(out, CompactSize(len(w.Signature)).Encode()...)
	out = append(out, w.Signature...)
	return out
}

func WitnessBytes(w WitnessSection) []byte {
	out := make([]byte, 0, 9)
	out = append(out, CompactSize(len(w.Witnesses)).Encode()...)
	for _, item := range w.Witnesses {
		out = append(out, WitnessItemBytes(item)...)
	}
	return out
}

func TxNoWitnessBytes(tx *Tx) []byte {
	out := make([]byte, 0, 4+8)
	var tmp4 [4]byte
	binary.LittleEndian.PutUint32(tmp4[:], tx.Version)
	out = append(out, tmp4[:]...)
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], tx.TxNonce)
	out = append(out, tmp8[:]...)

	out = append(out, CompactSize(len(tx.Inputs)).Encode()...)
	for _, in := range tx.Inputs {
		out = append(out, in.PrevTxid[:]...)
		binary.LittleEndian.PutUint32(tmp4[:], in.PrevVout)
		out = append(out, tmp4[:]...)
		out = append(out, CompactSize(len(in.ScriptSig)).Encode()...)
		out = append(out, in.ScriptSig...)
		binary.LittleEndian.PutUint32(tmp4[:], in.Sequence)
		out = append(out, tmp4[:]...)
	}

	out = append(out, CompactSize(len(tx.Outputs)).Encode()...)
	for _, o := range tx.Outputs {
		out = append(out, TxOutputBytes(o)...)
	}

	binary.LittleEndian.PutUint32(tmp4[:], tx.Locktime)
	out = append(out, tmp4[:]...)
	return out
}

func TxBytes(tx *Tx) []byte {
	out := TxNoWitnessBytes(tx)
	out = append(out, WitnessBytes(tx.Witness)...)
	return out
}

func TxID(p crypto.CryptoProvider, tx *Tx) [32]byte {
	return p.SHA3_256(TxNoWitnessBytes(tx))
}

func SighashV1Digest(
	p crypto.CryptoProvider,
	chainID [32]byte,
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
) ([32]byte, error) {
	inputIndexInt, err := u32ToInt(inputIndex, "input_index", len(tx.Inputs))
	if err != nil {
		return [32]byte{}, err
	}
	if uint64(inputIndex) >= uint64(len(tx.Inputs)) {
		return [32]byte{}, fmt.Errorf("sighash: input_index out of bounds")
	}

	prevouts := make([]byte, 0, len(tx.Inputs)*(32+4))
	var tmp4 [4]byte
	for _, in := range tx.Inputs {
		prevouts = append(prevouts, in.PrevTxid[:]...)
		binary.LittleEndian.PutUint32(tmp4[:], in.PrevVout)
		prevouts = append(prevouts, tmp4[:]...)
	}
	hashPrevouts := p.SHA3_256(prevouts)

	sequences := make([]byte, 0, len(tx.Inputs)*4)
	for _, in := range tx.Inputs {
		binary.LittleEndian.PutUint32(tmp4[:], in.Sequence)
		sequences = append(sequences, tmp4[:]...)
	}
	hashSequences := p.SHA3_256(sequences)

	outputsBytes := make([]byte, 0)
	for _, o := range tx.Outputs {
		outputsBytes = append(outputsBytes, TxOutputBytes(o)...)
	}
	hashOutputs := p.SHA3_256(outputsBytes)

	in := tx.Inputs[inputIndexInt]

	preimage := make([]byte, 0, 14+32+4+8+32+32+4+32+4+8+4+32+4)
	preimage = append(preimage, []byte("RUBINv1-sighash/")...)
	preimage = append(preimage, chainID[:]...)

	binary.LittleEndian.PutUint32(tmp4[:], tx.Version)
	preimage = append(preimage, tmp4[:]...)

	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], tx.TxNonce)
	preimage = append(preimage, tmp8[:]...)

	preimage = append(preimage, hashPrevouts[:]...)
	preimage = append(preimage, hashSequences[:]...)

	binary.LittleEndian.PutUint32(tmp4[:], inputIndex)
	preimage = append(preimage, tmp4[:]...)

	preimage = append(preimage, in.PrevTxid[:]...)
	binary.LittleEndian.PutUint32(tmp4[:], in.PrevVout)
	preimage = append(preimage, tmp4[:]...)
	binary.LittleEndian.PutUint64(tmp8[:], inputValue)
	preimage = append(preimage, tmp8[:]...)
	binary.LittleEndian.PutUint32(tmp4[:], in.Sequence)
	preimage = append(preimage, tmp4[:]...)

	preimage = append(preimage, hashOutputs[:]...)

	binary.LittleEndian.PutUint32(tmp4[:], tx.Locktime)
	preimage = append(preimage, tmp4[:]...)

	return p.SHA3_256(preimage), nil
}

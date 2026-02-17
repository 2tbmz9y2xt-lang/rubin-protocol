package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"rubin.dev/node/crypto"
)

const (
	CORE_P2PK            = 0x0000
	CORE_TIMELOCK_V1     = 0x0001
	CORE_ANCHOR          = 0x0002
	CORE_HTLC_V1         = 0x0100
	CORE_VAULT_V1        = 0x0101
	CORE_RESERVED_FUTURE = 0x00ff

	SUITE_ID_SENTINEL     = 0x00
	SUITE_ID_ML_DSA       = 0x01
	SUITE_ID_SLH_DSA      = 0x02
	ML_DSA_PUBKEY_BYTES   = 2592
	ML_DSA_SIG_BYTES      = 4_627
	SLH_DSA_PUBKEY_BYTES  = 64
	SLH_DSA_SIG_MAX_BYTES = 49_856

	TIMELOCK_MODE_HEIGHT    = 0x00
	TIMELOCK_MODE_TIMESTAMP = 0x01
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

func parseInput(cur *cursor) (TxInput, error) {
	prevTxidBytes, err := cur.readExact(32)
	if err != nil {
		return TxInput{}, err
	}
	var prevTxid [32]byte
	copy(prevTxid[:], prevTxidBytes)

	prevVout, err := cur.readU32LE()
	if err != nil {
		return TxInput{}, err
	}

	scriptSigLenU64, err := cur.readCompactSize()
	if err != nil {
		return TxInput{}, err
	}
	scriptSigLen, err := toIntLen(scriptSigLenU64, "script_sig_len")
	if err != nil {
		return TxInput{}, err
	}
	scriptSigBytes, err := cur.readExact(scriptSigLen)
	if err != nil {
		return TxInput{}, err
	}

	sequence, err := cur.readU32LE()
	if err != nil {
		return TxInput{}, err
	}

	return TxInput{
		PrevTxid:  prevTxid,
		PrevVout:  prevVout,
		ScriptSig: append([]byte(nil), scriptSigBytes...),
		Sequence:  sequence,
	}, nil
}

func parseOutput(cur *cursor) (TxOutput, error) {
	value, err := cur.readU64LE()
	if err != nil {
		return TxOutput{}, err
	}
	covenantType, err := cur.readU16LE()
	if err != nil {
		return TxOutput{}, err
	}

	covenantDataLenU64, err := cur.readCompactSize()
	if err != nil {
		return TxOutput{}, err
	}
	covenantDataLen, err := toIntLen(covenantDataLenU64, "covenant_data_len")
	if err != nil {
		return TxOutput{}, err
	}
	covenantDataBytes, err := cur.readExact(covenantDataLen)
	if err != nil {
		return TxOutput{}, err
	}

	return TxOutput{
		Value:        value,
		CovenantType: covenantType,
		CovenantData: append([]byte(nil), covenantDataBytes...),
	}, nil
}

func parseWitnessItem(cur *cursor) (WitnessItem, error) {
	suiteID, err := cur.readU8()
	if err != nil {
		return WitnessItem{}, err
	}

	pubkeyLenU64, err := cur.readCompactSize()
	if err != nil {
		return WitnessItem{}, err
	}
	pubkeyLen, err := toIntLen(pubkeyLenU64, "pubkey_len")
	if err != nil {
		return WitnessItem{}, err
	}
	pubkeyBytes, err := cur.readExact(pubkeyLen)
	if err != nil {
		return WitnessItem{}, err
	}

	sigLenU64, err := cur.readCompactSize()
	if err != nil {
		return WitnessItem{}, err
	}
	sigLen, err := toIntLen(sigLenU64, "sig_len")
	if err != nil {
		return WitnessItem{}, err
	}
	sigBytes, err := cur.readExact(sigLen)
	if err != nil {
		return WitnessItem{}, err
	}

	return WitnessItem{
		SuiteID:   suiteID,
		Pubkey:    append([]byte(nil), pubkeyBytes...),
		Signature: append([]byte(nil), sigBytes...),
	}, nil
}

func parseInputList(cur *cursor) ([]TxInput, error) {
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
		inp, err := parseInput(cur)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, inp)
	}
	return inputs, nil
}

func parseOutputList(cur *cursor) ([]TxOutput, error) {
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
		out, err := parseOutput(cur)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, out)
	}
	return outputs, nil
}

func parseWitnessList(cur *cursor) ([]WitnessItem, error) {
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
		w, err := parseWitnessItem(cur)
		if err != nil {
			return nil, err
		}
		witnesses = append(witnesses, w)
	}
	return witnesses, nil
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
	inputs, err := parseInputList(cur)
	if err != nil {
		return nil, err
	}
	outputs, err := parseOutputList(cur)
	if err != nil {
		return nil, err
	}

	locktime, err := cur.readU32LE()
	if err != nil {
		return nil, err
	}
	witnesses, err := parseWitnessList(cur)
	if err != nil {
		return nil, err
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

func parseU64LE(v []byte, start int, name string) (uint64, error) {
	if start+8 > len(v) {
		return 0, fmt.Errorf("parse: %s truncated", name)
	}
	var tmp [8]byte
	copy(tmp[:], v[start:start+8])
	return binary.LittleEndian.Uint64(tmp[:]), nil
}

func isScriptSigZeroLen(itemName string, scriptSigLen int) error {
	if scriptSigLen != 0 {
		return fmt.Errorf("parse: %s script_sig must be empty", itemName)
	}
	return nil
}

func validateHTLCScriptSigLen(scriptSigLen int) error {
	switch scriptSigLen {
	case 0, 32:
		return nil
	default:
		return fmt.Errorf("TX_ERR_PARSE")
	}
}

func checkWitnessFormat(item WitnessItem, suiteIDSLHActive bool) error {
	switch item.SuiteID {
	case SUITE_ID_SENTINEL:
		if len(item.Pubkey) != 0 || len(item.Signature) != 0 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		return nil
	case SUITE_ID_ML_DSA:
		if len(item.Pubkey) != ML_DSA_PUBKEY_BYTES || len(item.Signature) != ML_DSA_SIG_BYTES {
			return fmt.Errorf("TX_ERR_SIG_NONCANONICAL")
		}
		return nil
	case SUITE_ID_SLH_DSA:
		if !suiteIDSLHActive {
			return fmt.Errorf("TX_ERR_DEPLOYMENT_INACTIVE")
		}
		if len(item.Pubkey) != SLH_DSA_PUBKEY_BYTES || len(item.Signature) == 0 || len(item.Signature) > SLH_DSA_SIG_MAX_BYTES {
			return fmt.Errorf("TX_ERR_SIG_NONCANONICAL")
		}
		return nil
	default:
		return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
	}
}

func satisfyLock(lockMode byte, lockValue, height, timestamp uint64) error {
	switch lockMode {
	case TIMELOCK_MODE_HEIGHT:
		if height >= lockValue {
			return nil
		}
		return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
	case TIMELOCK_MODE_TIMESTAMP:
		if timestamp >= lockValue {
			return nil
		}
		return fmt.Errorf("TX_ERR_TIMELOCK_NOT_MET")
	default:
		return fmt.Errorf("TX_ERR_PARSE")
	}
}

func ValidateInputAuthorization(
	p crypto.CryptoProvider,
	chainID [32]byte,
	tx *Tx,
	inputIndex uint32,
	prevValue uint64,
	prevout *TxOutput,
	chainHeight uint64,
	chainTimestamp uint64,
	suiteIDSLHActive bool,
) error {
	if int(inputIndex) >= len(tx.Inputs) {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if int(inputIndex) >= len(tx.Witness.Witnesses) {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	if prevout == nil {
		return fmt.Errorf("TX_ERR_PARSE")
	}

	inputIndexInt, err := u32ToInt(inputIndex, "input_index", len(tx.Inputs))
	if err != nil {
		return err
	}
	input := tx.Inputs[inputIndexInt]
	witness := tx.Witness.Witnesses[inputIndexInt]

	switch prevout.CovenantType {
	case CORE_P2PK:
		if err := isScriptSigZeroLen("CORE_P2PK", len(input.ScriptSig)); err != nil {
			return err
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}

		if len(prevout.CovenantData) != 33 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		suiteID := prevout.CovenantData[0]
		if suiteID != witness.SuiteID {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
		actualKeyID := p.SHA3_256(witness.Pubkey)
		if expected := prevout.CovenantData[1:33]; !bytes.Equal(actualKeyID[:], expected) {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
	case CORE_TIMELOCK_V1:
		if err := isScriptSigZeroLen("CORE_TIMELOCK_V1", len(input.ScriptSig)); err != nil {
			return err
		}
		if witness.SuiteID != SUITE_ID_SENTINEL {
			return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
		}
		if len(prevout.CovenantData) != 9 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		lockMode := prevout.CovenantData[0]
		lockValue, err := parseU64LE(prevout.CovenantData, 1, "covenant_lock_value")
		if err != nil {
			return err
		}
		if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
			return err
		}
	case CORE_HTLC_V1:
		if err := validateHTLCScriptSigLen(len(input.ScriptSig)); err != nil {
			return err
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		if len(prevout.CovenantData) != 105 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		lockMode := prevout.CovenantData[32]
		lockValue, err := parseU64LE(prevout.CovenantData, 33, "htlc_lock_value")
		if err != nil {
			return err
		}
		if len(input.ScriptSig) == 32 {
			expectedHash := prevout.CovenantData[:32]
			scriptHash := p.SHA3_256(input.ScriptSig)
			if !bytes.Equal(scriptHash[:], expectedHash) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			expectedClaimKeyID := prevout.CovenantData[41:73]
			actualKeyID := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID[:], expectedClaimKeyID) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
		} else {
			expectedRefundKeyID := prevout.CovenantData[73:105]
			actualKeyID := p.SHA3_256(witness.Pubkey)
			if !bytes.Equal(actualKeyID[:], expectedRefundKeyID) {
				return fmt.Errorf("TX_ERR_SIG_INVALID")
			}
			if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
				return err
			}
		}
	case CORE_VAULT_V1:
		if err := isScriptSigZeroLen("CORE_VAULT_V1", len(input.ScriptSig)); err != nil {
			return err
		}
		if err := checkWitnessFormat(witness, suiteIDSLHActive); err != nil {
			return err
		}
		if len(prevout.CovenantData) != 73 {
			return fmt.Errorf("TX_ERR_PARSE")
		}
		lockMode := prevout.CovenantData[32]
		lockValue, err := parseU64LE(prevout.CovenantData, 33, "vault_lock_value")
		if err != nil {
			return err
		}
		ownerKeyID := prevout.CovenantData[:32]
		recoveryKeyID := prevout.CovenantData[41:73]
		actualKeyID := p.SHA3_256(witness.Pubkey)
		if !bytes.Equal(actualKeyID[:], ownerKeyID) && !bytes.Equal(actualKeyID[:], recoveryKeyID) {
			return fmt.Errorf("TX_ERR_SIG_INVALID")
		}
		if bytes.Equal(actualKeyID[:], recoveryKeyID) {
			if err := satisfyLock(lockMode, lockValue, chainHeight, chainTimestamp); err != nil {
				return err
			}
		}
	case CORE_ANCHOR:
		return fmt.Errorf("TX_ERR_MISSING_UTXO")
	case CORE_RESERVED_FUTURE:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	default:
		return fmt.Errorf("TX_ERR_COVENANT_TYPE_INVALID")
	}

		digest, err := SighashV1Digest(p, chainID, tx, inputIndex, prevValue)
	if err != nil {
		return err
	}

	switch witness.SuiteID {
	case SUITE_ID_ML_DSA:
		if p.VerifyMLDSA87(witness.Pubkey, witness.Signature, digest) {
			return nil
		}
		return fmt.Errorf("TX_ERR_SIG_INVALID")
	case SUITE_ID_SLH_DSA:
		if p.VerifySLHDSASHAKE_256f(witness.Pubkey, witness.Signature, digest) {
			return nil
		}
		return fmt.Errorf("TX_ERR_SIG_INVALID")
	case SUITE_ID_SENTINEL:
		// Timelock-only covenants are already validated above.
		return nil
	default:
		return fmt.Errorf("TX_ERR_SIG_ALG_INVALID")
	}
}

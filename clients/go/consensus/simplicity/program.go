// Package simplicity implements the standalone RUB-482 Program Encoding v1
// library and RUB-485 evaluation/metering library for the closed RUB-561
// artifact subset.
//
// Consensus dispatch remains reject-only until the staged Go dispatch, Rust
// parity, and shared conformance slices land.
package simplicity

import (
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

const (
	SemanticsVersion uint32 = 1
	MaxProgramBytes         = 16_384
	MaxExecCost      uint64 = 400_000
	StepCost         uint64 = 1

	CostModelSemanticsVersion    uint32 = 2
	JetsRegistrySemanticsVersion uint32 = 2
	IntrinsicReadCost            uint64 = 1
	IntrinsicMissCost            uint64 = 1
	DescriptorHashBaseCost       uint64 = 64
	DescriptorHashByteCost       uint64 = 1
	MaxFrameBytes                uint64 = 65_536
	MaxLiveMemoryBytes           uint64 = 1_048_576
)

type ErrorCode string

const (
	ErrDecode          ErrorCode = "TX_ERR_SIMPLICITY_DECODE"
	ErrProgramTooLarge ErrorCode = "TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE"
	ErrCMRMismatch     ErrorCode = "TX_ERR_SIMPLICITY_CMR_MISMATCH"
	ErrJetDisallowed   ErrorCode = "TX_ERR_SIMPLICITY_JET_DISALLOWED"
	ErrBudgetExceeded  ErrorCode = "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED"
	ErrRejected        ErrorCode = "TX_ERR_SIMPLICITY_REJECTED"
)

type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	return string(e.Code)
}

type DecodeOptions struct {
	SemanticsVersion   uint32
	CovenantProgramCMR *[32]byte
}

type Program struct {
	CMR            [32]byte
	Jet            *Jet
	NeedsWitness   bool
	maxWitnessLen  int
	witnesses      map[witnessKey]struct{}
	intrinsics     []ContextIntrinsic
	evalSteps      uint64
	decoded        bool
	hasJet         bool
	disallowedJet  bool
	jetKey         jetKey
	frameBitWidths []uint64
}

type Jet struct {
	ID             uint16
	SubOp          uint8
	Name           string
	SelectorBitLen int
	SelectorPadded []byte
	CMR            [32]byte
}

type EvalOptions struct {
	JetEvaluator func(Jet) (EvalResult, error)
	Host         EvalHost
}

type EvalResult struct {
	Accepted bool
	Cost     uint64
}

func Decode(program, witness []byte, opts DecodeOptions) (Program, error) {
	if len(program) > MaxProgramBytes {
		return Program{}, &Error{Code: ErrProgramTooLarge}
	}
	decoded, err := decodeProgram(program)
	if err != nil {
		return Program{}, err
	}
	if opts.CovenantProgramCMR != nil && decoded.CMR != *opts.CovenantProgramCMR {
		return Program{}, &Error{Code: ErrCMRMismatch}
	}
	if len(witness) > decoded.maxWitnessLen {
		return Program{}, &Error{Code: ErrDecode}
	}
	if _, ok := decoded.witnesses[witnessKey{version: opts.SemanticsVersion, bytes: string(witness)}]; !ok {
		return Program{}, &Error{Code: ErrDecode}
	}
	decoded.decoded = true
	decoded.frameBitWidths = append([]uint64(nil), decoded.frameBitWidths...)
	if decoded.Jet != nil {
		jet := copyJet(*decoded.Jet)
		decoded.Jet = &jet
		decoded.hasJet = true
		decoded.jetKey = jetKey{id: jet.ID, subOp: jet.SubOp}
	}
	return decoded, nil
}

func LookupJet(id uint16, subOp uint8) (Jet, bool) {
	row, ok := jetRows[jetKey{id: id, subOp: subOp}]
	return copyJet(row), ok
}

func requireJet(id uint16, subOp uint8) (Jet, error) {
	jet, ok := LookupJet(id, subOp)
	if !ok {
		return Jet{}, &Error{Code: ErrJetDisallowed}
	}
	return jet, nil
}

func (p Program) Evaluate(opts EvalOptions) (EvalResult, error) {
	if !p.decoded {
		return EvalResult{}, &Error{Code: ErrDecode}
	}
	if err := p.checkRunnable(); err != nil {
		return EvalResult{}, err
	}

	switch {
	case p.hasJet:
		return p.evaluateJet(opts)
	case len(p.intrinsics) > 0:
		return p.evaluateIntrinsics(opts)
	default:
		return p.evaluateStepProgram(opts)
	}
}

func (p Program) checkRunnable() error {
	if p.disallowedJet {
		return &Error{Code: ErrJetDisallowed}
	}
	if p.hasJet {
		if _, ok := jetRows[p.jetKey]; !ok {
			return &Error{Code: ErrDecode}
		}
		return checkMemoryBounds(p.frameBitWidths)
	}
	if len(p.intrinsics) == 0 && p.evalSteps == 0 {
		return &Error{Code: ErrDecode}
	}
	return checkMemoryBounds(p.frameBitWidths)
}

func (p Program) evaluateJet(opts EvalOptions) (EvalResult, error) {
	if opts.JetEvaluator == nil {
		return EvalResult{}, &Error{Code: ErrJetDisallowed}
	}
	jet, ok := LookupJet(p.jetKey.id, p.jetKey.subOp)
	if !ok {
		return EvalResult{}, &Error{Code: ErrDecode}
	}
	if opts.Host != nil && opts.Host.Cost() >= MaxExecCost {
		return EvalResult{Accepted: true, Cost: MaxExecCost}, &Error{Code: ErrBudgetExceeded}
	}
	result, err := opts.JetEvaluator(jet)
	if err != nil {
		return EvalResult{}, err
	}
	if opts.Host != nil {
		return evaluateJetWithHost(result, opts.Host)
	}
	return evaluateJetWithLocalMeter(result)
}

func evaluateSteps(steps uint64) (EvalResult, error) {
	if StepCost == 0 {
		return EvalResult{Accepted: true}, nil
	}
	maxSteps := MaxExecCost / StepCost
	if steps > maxSteps {
		return EvalResult{Accepted: true, Cost: MaxExecCost}, &Error{Code: ErrBudgetExceeded}
	}
	return EvalResult{Accepted: true, Cost: steps * StepCost}, nil
}

func RubinJetCMR(identityHash [32]byte, jetWeight uint64) [32]byte {
	state := [8]uint32{0x9532ee28, 0xcdca69de, 0xc8a0a218, 0xb79be362, 0xf740ceaf, 0x647f15b3, 0x8aed9168, 0x163f921b}
	var block [64]uint32
	block[6] = uint32(jetWeight >> 32)
	block[7] = uint32(jetWeight)
	block[8] = binary.BigEndian.Uint32(identityHash[0:4])
	block[9] = binary.BigEndian.Uint32(identityHash[4:8])
	block[10] = binary.BigEndian.Uint32(identityHash[8:12])
	block[11] = binary.BigEndian.Uint32(identityHash[12:16])
	block[12] = binary.BigEndian.Uint32(identityHash[16:20])
	block[13] = binary.BigEndian.Uint32(identityHash[20:24])
	block[14] = binary.BigEndian.Uint32(identityHash[24:28])
	block[15] = binary.BigEndian.Uint32(identityHash[28:32])
	sha256Compress(&state, block)
	var out [32]byte
	binary.BigEndian.PutUint32(out[0:4], state[0])
	binary.BigEndian.PutUint32(out[4:8], state[1])
	binary.BigEndian.PutUint32(out[8:12], state[2])
	binary.BigEndian.PutUint32(out[12:16], state[3])
	binary.BigEndian.PutUint32(out[16:20], state[4])
	binary.BigEndian.PutUint32(out[20:24], state[5])
	binary.BigEndian.PutUint32(out[24:28], state[6])
	binary.BigEndian.PutUint32(out[28:32], state[7])
	return out
}

func CostModelHash() [32]byte {
	return sha3.Sum256(costModelBytes())
}

// JetsRegistryHash returns the hash of the ordered Go jet registry table.
func JetsRegistryHash() [32]byte {
	return jetsRegistryHashValue
}

func decodeProgram(program []byte) (Program, error) {
	entry, ok := programs[string(program)]
	if !ok {
		return Program{}, &Error{Code: ErrDecode}
	}
	if entry.err != "" {
		return Program{}, &Error{Code: entry.err}
	}
	return entry.program, nil
}

func copyJet(row Jet) Jet {
	row.SelectorPadded = append([]byte(nil), row.SelectorPadded...)
	return row
}

// hex32 decodes checked-in 32-byte hex constants and panics during invariant
// setup if a committed constant is malformed.
func hex32(s string) [32]byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid embedded bytes32 hex: " + err.Error())
	}
	if len(raw) != 32 {
		panic("invalid embedded bytes32")
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

type jetKey struct {
	id    uint16
	subOp uint8
}

type jetRegistryRow struct {
	jet       Jet
	signature string
}

type costFormulaID uint8

const (
	costConstant costFormulaID = iota
	costBasePlusLen
	costOnePlusCeilLen32
)

type costModelRow struct {
	jet     jetKey
	formula costFormulaID
	param   uint64
}

type witnessKey struct {
	version uint32
	bytes   string
}

var jetRegistryRows = []jetRegistryRow{
	{jet: Jet{ID: 0x0001, SubOp: 0x00, Name: "sha3_256", SelectorBitLen: 2, SelectorPadded: []byte{0x00}, CMR: hex32("3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637")}, signature: "bytes -> bytes32"},
	{jet: Jet{ID: 0x0002, SubOp: 0x00, Name: "mldsa87_verify", SelectorBitLen: 4, SelectorPadded: []byte{0x80}, CMR: hex32("f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941")}, signature: "(pubkey:bytes, sig:bytes, digest32:bytes32) -> bool"},
	{jet: Jet{ID: 0x0010, SubOp: 0x00, Name: "u64_checked_add", SelectorBitLen: 12, SelectorPadded: []byte{0xe0, 0x00}, CMR: hex32("4911cf2b5d37ccc5407c0d4e0686f0c6871c0b18c33ebc2dd28ec905cbec90ee")}, signature: "(u64, u64) -> Either<unit, u64>"},
	{jet: Jet{ID: 0x0010, SubOp: 0x01, Name: "u64_checked_sub", SelectorBitLen: 14, SelectorPadded: []byte{0xe0, 0x10}, CMR: hex32("9c2b594d0673d2f416e0bb216f15d35a55a75c2237d030493ec3ae72652f2146")}, signature: "(u64, u64) -> Either<unit, u64>"},
	{jet: Jet{ID: 0x0010, SubOp: 0x02, Name: "u64_checked_mul", SelectorBitLen: 14, SelectorPadded: []byte{0xe0, 0x14}, CMR: hex32("cf668e8e6a8bd1e9bcceebef182e063d1facd1665664170b6ae163456e739fa7")}, signature: "(u64, u64) -> Either<unit, u64>"},
	{jet: Jet{ID: 0x0010, SubOp: 0x03, Name: "u64_cmp", SelectorBitLen: 17, SelectorPadded: []byte{0xe0, 0x18, 0x00}, CMR: hex32("50a228b34771cac098612f13ccf74949a8a0d8856b29440502fe8b45dd699c07")}, signature: "(u64, u64) -> ordering"},
	{jet: Jet{ID: 0x0011, SubOp: 0x00, Name: "u128_checked_add", SelectorBitLen: 12, SelectorPadded: []byte{0xe0, 0x20}, CMR: hex32("9d4674805162aca15086e994aa03fb6d2093665316449f9cc97e5288daf14dd9")}, signature: "(u128, u128) -> Either<unit, u128>"},
	{jet: Jet{ID: 0x0011, SubOp: 0x01, Name: "u128_checked_sub", SelectorBitLen: 14, SelectorPadded: []byte{0xe0, 0x30}, CMR: hex32("0d8bc8c7815edb3c220fd212f4c7b6986f50e8a427d6200b74f83a85c1792f75")}, signature: "(u128, u128) -> Either<unit, u128>"},
	{jet: Jet{ID: 0x0011, SubOp: 0x03, Name: "u128_cmp", SelectorBitLen: 17, SelectorPadded: []byte{0xe0, 0x38, 0x00}, CMR: hex32("c90a66af21fc7ced71a9141082a47dbb0db878c25f432af25f382ccb055f4add")}, signature: "(u128, u128) -> ordering"},
	{jet: Jet{ID: 0x0020, SubOp: 0x00, Name: "bytes_eq", SelectorBitLen: 13, SelectorPadded: []byte{0xe2, 0x00}, CMR: hex32("33f82e38417283760f1d9deba367aeaa0feb4c703b69aa37dc8c2aefe7c32d4a")}, signature: "(bytes, bytes) -> bool"},
	{jet: Jet{ID: 0x0020, SubOp: 0x01, Name: "bytes_cmp", SelectorBitLen: 15, SelectorPadded: []byte{0xe2, 0x08}, CMR: hex32("bd237f53ad86be9b3c8bd3dcb2a36642782c07885d5afc44903b5dc6d017960a")}, signature: "(bytes, bytes) -> ordering"},
	{jet: Jet{ID: 0x0021, SubOp: 0x00, Name: "bytes_slice", SelectorBitLen: 13, SelectorPadded: []byte{0xe2, 0x10}, CMR: hex32("9c28e72f9da964de2c90d92c5c772211537ed2e07d20f6790c988284a87c0ce2")}, signature: "(src:bytes, start:u64, len:u64) -> Either<unit, bytes>"},
}

var jetRows = jetRowsFromRegistryRows(jetRegistryRows)

var jetsRegistryHashValue = sha3.Sum256(jetsRegistryBytes(jetRegistryRows))

type programEntry struct {
	program Program
	err     ErrorCode
}

type meter struct {
	cost uint64
}

// ChargeCost applies the shared Simplicity execution budget cap.
func ChargeCost(current, cost uint64) (uint64, error) {
	if current > MaxExecCost || cost > MaxExecCost-current {
		return MaxExecCost, &Error{Code: ErrBudgetExceeded}
	}
	return current + cost, nil
}

// DescriptorHashAccessCost returns the in-range descriptor_hash access cost.
func DescriptorHashAccessCost(descriptorLen uint64) (uint64, error) {
	if DescriptorHashByteCost != 0 && descriptorLen > (^uint64(0)-DescriptorHashBaseCost)/DescriptorHashByteCost {
		return MaxExecCost, &Error{Code: ErrBudgetExceeded}
	}
	return ChargeCost(0, DescriptorHashBaseCost+DescriptorHashByteCost*descriptorLen)
}

func (m *meter) charge(cost uint64) error {
	next, err := ChargeCost(m.cost, cost)
	m.cost = next
	return err
}

func checkMemoryBounds(frameBitWidths []uint64) error {
	var live uint64
	for _, bits := range frameBitWidths {
		frame := frameBytes(bits)
		if frame > MaxFrameBytes || live > MaxLiveMemoryBytes-frame {
			return &Error{Code: ErrBudgetExceeded}
		}
		live += frame
	}
	return nil
}

func frameBytes(bitWidth uint64) uint64 {
	bytes := bitWidth / 8
	if bitWidth%8 != 0 {
		bytes++
	}
	return bytes
}

func costModelBytes() []byte {
	out := []byte("RUBIN-SIMPLICITY-COST-v1")
	out = binary.LittleEndian.AppendUint32(out, CostModelSemanticsVersion)
	for _, v := range []uint64{StepCost, IntrinsicReadCost, IntrinsicMissCost, DescriptorHashBaseCost, DescriptorHashByteCost, MaxFrameBytes, MaxLiveMemoryBytes} {
		out = binary.LittleEndian.AppendUint64(out, v)
	}
	out = append(out, costModelRowCountByte(costModelRows))
	for _, row := range costModelRows {
		out = binary.LittleEndian.AppendUint16(out, row.jet.id)
		out = append(out, row.jet.subOp, byte(row.formula))
		out = binary.LittleEndian.AppendUint64(out, row.param)
	}
	return out
}

func jetsRegistryBytes(rows []jetRegistryRow) []byte {
	if err := validateJetLookupRows(rows); err != nil {
		panic(err)
	}
	out := []byte("RUBIN-SIMPLICITY-JETS-v1")
	out = binary.LittleEndian.AppendUint32(out, JetsRegistrySemanticsVersion)
	out = appendOneByteCompactSize(out, len(rows))
	for _, row := range rows {
		out = binary.LittleEndian.AppendUint16(out, row.jet.ID)
		out = append(out, row.jet.SubOp)
		out = appendOneByteCompactSize(out, len(row.jet.Name))
		out = append(out, row.jet.Name...)
		out = appendOneByteCompactSize(out, len(row.signature))
		out = append(out, row.signature...)
	}
	return out
}

func appendOneByteCompactSize(out []byte, n int) []byte {
	if n >= 253 {
		panic("jet registry CompactSize value exceeds one-byte encoding")
	}
	return append(out, byte(n))
}

func validateJetLookupRows(rows []jetRegistryRow) error {
	var prev jetKey
	for i, row := range rows {
		key := jetKey{id: row.jet.ID, subOp: row.jet.SubOp}
		if i > 0 && (prev.id > key.id || (prev.id == key.id && prev.subOp >= key.subOp)) {
			return fmt.Errorf("jet registry rows not strictly sorted at %d", i)
		}
		prev = key
	}
	return nil
}

func jetRowsFromRegistryRows(rows []jetRegistryRow) map[jetKey]Jet {
	if err := validateJetLookupRows(rows); err != nil {
		panic(err)
	}
	out := make(map[jetKey]Jet, len(rows))
	for _, row := range rows {
		out[jetKey{id: row.jet.ID, subOp: row.jet.SubOp}] = copyJet(row.jet)
	}
	return out
}

func costModelRowCountByte(rows []costModelRow) byte {
	if len(rows) >= 253 {
		panic("cost model row count exceeds one-byte CompactSize encoding")
	}
	return byte(len(rows))
}

var (
	noWitness            = map[witnessKey]struct{}{{version: SemanticsVersion, bytes: ""}: {}}
	boolWitness          = map[witnessKey]struct{}{{version: SemanticsVersion, bytes: string([]byte{0x00})}: {}, {version: SemanticsVersion, bytes: string([]byte{0x80})}: {}}
	sha3JetRow           = jetRows[jetKey{id: 0x0001, subOp: 0x00}]
	mldsa87JetRow        = jetRows[jetKey{id: 0x0002, subOp: 0x00}]
	unitFrames           = []uint64{0, 0}
	boolFrames           = []uint64{1, 1}
	contextChainIDFrames = []uint64{0, 256}
	sha3Frames           = []uint64{512, 256}
	mldsa87Frames        = []uint64{(2_592 + 4_627 + 32) * 8, 1}
	costModelRows        = []costModelRow{
		{jet: jetKey{id: 0x0001, subOp: 0x00}, formula: costBasePlusLen, param: sha3256JetBaseCost},
		{jet: jetKey{id: 0x0002, subOp: 0x00}, formula: costConstant, param: mldsa87VerifyJetCost},
		{jet: jetKey{id: 0x0010, subOp: 0x00}, formula: costConstant, param: 1},
		{jet: jetKey{id: 0x0010, subOp: 0x01}, formula: costConstant, param: 1},
		{jet: jetKey{id: 0x0010, subOp: 0x02}, formula: costConstant, param: 1},
		{jet: jetKey{id: 0x0010, subOp: 0x03}, formula: costConstant, param: 1},
		{jet: jetKey{id: 0x0011, subOp: 0x00}, formula: costConstant, param: 1},
		{jet: jetKey{id: 0x0011, subOp: 0x01}, formula: costConstant, param: 1},
		{jet: jetKey{id: 0x0011, subOp: 0x03}, formula: costConstant, param: 1},
		{jet: jetKey{id: 0x0020, subOp: 0x00}, formula: costOnePlusCeilLen32},
		{jet: jetKey{id: 0x0020, subOp: 0x01}, formula: costOnePlusCeilLen32},
		{jet: jetKey{id: 0x0021, subOp: 0x00}, formula: costOnePlusCeilLen32},
	}
	programs = map[string]programEntry{
		string([]byte{0x24}):                         {program: Program{CMR: hex32("c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7"), witnesses: noWitness, evalSteps: 1, frameBitWidths: unitFrames}},
		string([]byte{0xc1, 0x22, 0x0f, 0x01, 0x00}): {program: Program{CMR: hex32("afeae8c18903b9e0aae2c125f31f7b8e09de916e461f221936b633d587c1b434"), witnesses: noWitness, evalSteps: 4, frameBitWidths: unitFrames}},
		string([]byte{0x89, 0x00}):                   {program: Program{CMR: hex32("d296a48e538af38908242ab30244036fdb66e9056d5f812a5b328fae2b6a2726"), witnesses: noWitness, evalSteps: 2, frameBitWidths: unitFrames}},
		string([]byte{0xc1, 0xd2, 0x10, 0x14}):       {program: Program{CMR: hex32("d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83"), NeedsWitness: true, maxWitnessLen: 1, witnesses: boolWitness, evalSteps: 4, frameBitWidths: boolFrames}},
		string([]byte{0xe8, 0x00, 0x00}):             {program: Program{CMR: hex32("39f9eaabbe10dc4e46b4b099604762181b70921da4d17ccb76fd585e1370a66a"), witnesses: noWitness, intrinsics: []ContextIntrinsic{contextChainIDRow}, frameBitWidths: contextChainIDFrames}},
		string([]byte{0x60}):                         {program: Program{CMR: sha3JetRow.CMR, Jet: &sha3JetRow, witnesses: noWitness, frameBitWidths: sha3Frames}},
		string([]byte{0x70}):                         {program: Program{CMR: mldsa87JetRow.CMR, Jet: &mldsa87JetRow, witnesses: noWitness, frameBitWidths: mldsa87Frames}},
		string([]byte{0xe8, 0x60, 0x00}):             {err: ErrDecode},
		string([]byte{0xf0, 0x00, 0x10, 0x00}):       {err: ErrDecode},
		string([]byte{0xe8, 0x00, 0x80}):             {err: ErrDecode},
		string([]byte{0xe3, 0x00}):                   {err: ErrJetDisallowed},
		string([]byte{0x7c, 0x06, 0x80}):             {err: ErrJetDisallowed},
	}
)

func sha256Compress(state *[8]uint32, block [64]uint32) {
	for i := 16; i < 64; i++ {
		s0 := bits.RotateLeft32(block[i-15], -7) ^ bits.RotateLeft32(block[i-15], -18) ^ (block[i-15] >> 3)
		s1 := bits.RotateLeft32(block[i-2], -17) ^ bits.RotateLeft32(block[i-2], -19) ^ (block[i-2] >> 10)
		block[i] = block[i-16] + s0 + block[i-7] + s1
	}
	a, b, c, d := state[0], state[1], state[2], state[3]
	e, f, g, h := state[4], state[5], state[6], state[7]
	for i := 0; i < 64; i++ {
		s1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
		ch := (e & f) ^ (^e & g)
		t1 := h + s1 + ch + sha256K[i] + block[i]
		s0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := s0 + maj
		h, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
	state[4] += e
	state[5] += f
	state[6] += g
	state[7] += h
}

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

package consensus

import (
	"encoding/binary"
	"reflect"
)

const (
	htlcSpendArgsBasic     = 5
	htlcSpendArgsWithCache = 6
	htlcSpendArgsAtHeight  = 8
)

type HTLCCovenant struct {
	Hash        [32]byte
	LockMode    uint8
	LockValue   uint64
	ClaimKeyID  [32]byte
	RefundKeyID [32]byte
}

// HTLCSpendContext carries the transaction, height, cache, and registry state
// required to validate a CORE_HTLC spend.
type HTLCSpendContext struct {
	Tx          *Tx
	InputIndex  uint32
	InputValue  uint64
	ChainID     [32]byte
	BlockHeight uint64
	BlockMTP    uint64
	Cache       *SighashV1PrehashCache
	Rotation    RotationProvider
	Registry    *SuiteRegistry
}

func ParseHTLCCovenantData(covData []byte) (*HTLCCovenant, error) {
	if len(covData) != MAX_HTLC_COVENANT_DATA {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_HTLC covenant_data length mismatch")
	}

	var c HTLCCovenant
	copy(c.Hash[:], covData[0:32])
	c.LockMode = covData[32]
	c.LockValue = binary.LittleEndian.Uint64(covData[33:41])
	copy(c.ClaimKeyID[:], covData[41:73])
	copy(c.RefundKeyID[:], covData[73:105])

	if c.LockMode != LOCK_MODE_HEIGHT && c.LockMode != LOCK_MODE_TIMESTAMP {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_HTLC lock_mode invalid")
	}
	if c.LockValue == 0 {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_HTLC lock_value must be > 0")
	}
	if c.ClaimKeyID == c.RefundKeyID {
		return nil, txerr(TX_ERR_PARSE, "CORE_HTLC claim/refund key_id must differ")
	}

	return &c, nil
}

func ValidateHTLCSpend(
	entry UtxoEntry,
	pathItem WitnessItem,
	sigItem WitnessItem,
	tx *Tx,
	args ...any,
) error {
	ctx, err := htlcSpendContextFromArgs(tx, args, htlcSpendArgsBasic)
	if err != nil {
		return err
	}
	ctx.Cache = nil
	return validateHTLCSpendWithContext(entry, pathItem, sigItem, ctx)
}

func ValidateHTLCSpendWithCache(
	entry UtxoEntry,
	pathItem WitnessItem,
	sigItem WitnessItem,
	tx *Tx,
	args ...any,
) error {
	ctx, err := htlcSpendContextFromArgs(tx, args, htlcSpendArgsWithCache)
	if err != nil {
		return err
	}
	return validateHTLCSpendWithContext(entry, pathItem, sigItem, ctx)
}

func ValidateHTLCSpendAtHeight(
	entry UtxoEntry,
	pathItem WitnessItem,
	sigItem WitnessItem,
	tx *Tx,
	args ...any,
) error {
	ctx, err := htlcSpendContextFromArgs(tx, args, htlcSpendArgsAtHeight)
	if err != nil {
		return err
	}
	return validateHTLCSpendWithContext(entry, pathItem, sigItem, ctx)
}

func htlcSpendContextFromArgs(tx *Tx, args []any, argCount int) (HTLCSpendContext, error) {
	if len(args) != argCount {
		return HTLCSpendContext{}, htlcSpendArgError()
	}
	ctx, err := htlcSpendBaseContextFromArgs(tx, args)
	if err != nil {
		return HTLCSpendContext{}, err
	}
	if argCount >= htlcSpendArgsWithCache {
		ctx.Cache, err = htlcSpendCacheArg(args[5])
		if err != nil {
			return HTLCSpendContext{}, err
		}
	}
	if argCount >= htlcSpendArgsAtHeight {
		ctx.Rotation, err = htlcSpendRotationArg(args[6])
		if err != nil {
			return HTLCSpendContext{}, err
		}
		ctx.Registry, err = htlcSpendRegistryArg(args[7])
		if err != nil {
			return HTLCSpendContext{}, err
		}
	}
	return ctx, nil
}

func htlcSpendBaseContextFromArgs(tx *Tx, args []any) (HTLCSpendContext, error) {
	inputIndex, err := htlcUint32Arg(args[0])
	if err != nil {
		return HTLCSpendContext{}, err
	}
	inputValue, err := htlcUint64Arg(args[1])
	if err != nil {
		return HTLCSpendContext{}, err
	}
	chainID, ok := args[2].([32]byte)
	if !ok {
		return HTLCSpendContext{}, htlcSpendArgError()
	}
	blockHeight, err := htlcUint64Arg(args[3])
	if err != nil {
		return HTLCSpendContext{}, err
	}
	blockMTP, err := htlcUint64Arg(args[4])
	if err != nil {
		return HTLCSpendContext{}, err
	}
	return HTLCSpendContext{
		Tx:          tx,
		InputIndex:  inputIndex,
		InputValue:  inputValue,
		ChainID:     chainID,
		BlockHeight: blockHeight,
		BlockMTP:    blockMTP,
	}, nil
}

func htlcUint32Arg(arg any) (uint32, error) {
	value, err := htlcUint64Arg(arg)
	if err != nil {
		return 0, err
	}
	if value > 1<<32-1 {
		return 0, htlcSpendArgError()
	}
	return uint32(value), nil
}

func htlcUint64Arg(arg any) (uint64, error) {
	if arg == nil {
		return 0, htlcSpendArgError()
	}
	value := reflect.ValueOf(arg)
	switch value.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if value.Int() < 0 {
			return 0, htlcSpendArgError()
		}
		return uint64(value.Int()), nil
	default:
		return 0, htlcSpendArgError()
	}
}

func htlcSpendCacheArg(arg any) (*SighashV1PrehashCache, error) {
	if isNilHTLCSpendArg(arg) {
		return nil, nil
	}
	cache, ok := arg.(*SighashV1PrehashCache)
	if !ok {
		return nil, htlcSpendArgError()
	}
	return cache, nil
}

func htlcSpendRotationArg(arg any) (RotationProvider, error) {
	if isNilHTLCSpendArg(arg) {
		return nil, nil
	}
	rotation, ok := arg.(RotationProvider)
	if !ok {
		return nil, htlcSpendArgError()
	}
	return rotation, nil
}

func htlcSpendRegistryArg(arg any) (*SuiteRegistry, error) {
	if isNilHTLCSpendArg(arg) {
		return nil, nil
	}
	registry, ok := arg.(*SuiteRegistry)
	if !ok {
		return nil, htlcSpendArgError()
	}
	return registry, nil
}

func isNilHTLCSpendArg(arg any) bool {
	if arg == nil {
		return true
	}
	value := reflect.ValueOf(arg)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func htlcSpendArgError() error {
	return txerr(TX_ERR_PARSE, "CORE_HTLC validation arguments invalid")
}

func validateHTLCSpendWithContext(entry UtxoEntry, pathItem WitnessItem, sigItem WitnessItem, ctx HTLCSpendContext) error {
	ctx = ctx.withDefaults()

	c, err := ParseHTLCCovenantData(entry.CovenantData)
	if err != nil {
		return err
	}

	expectedKeyID, err := validateHTLCSpendPath(c, pathItem, ctx)
	if err != nil {
		return err
	}
	return validateHTLCSignature(sigItem, expectedKeyID, ctx)
}

func (ctx HTLCSpendContext) withDefaults() HTLCSpendContext {
	if ctx.Rotation == nil {
		ctx.Rotation = DefaultRotationProvider{}
	}
	if ctx.Registry == nil {
		ctx.Registry = DefaultSuiteRegistry()
	}
	return ctx
}

func validateHTLCSpendPath(c *HTLCCovenant, pathItem WitnessItem, ctx HTLCSpendContext) ([32]byte, error) {
	if pathItem.SuiteID != SUITE_ID_SENTINEL {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC selector suite_id invalid")
	}
	if len(pathItem.Pubkey) != 32 {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC selector key_id length invalid")
	}
	pathSig := pathItem.Signature
	if len(pathSig) < 1 {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC selector payload too short")
	}

	switch pathSig[0] {
	case 0x00:
		return validateHTLCClaimPath(c, pathItem, pathSig)
	case 0x01:
		return validateHTLCRefundPath(c, pathItem, pathSig, ctx)
	default:
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC unknown spend path")
	}
}

func validateHTLCClaimPath(c *HTLCCovenant, pathItem WitnessItem, pathSig []byte) ([32]byte, error) {
	var pathKeyID [32]byte
	copy(pathKeyID[:], pathItem.Pubkey)
	if pathKeyID != c.ClaimKeyID {
		return [32]byte{}, txerr(TX_ERR_SIG_INVALID, "CORE_HTLC claim key_id mismatch")
	}
	if len(pathSig) < 3 {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC claim payload too short")
	}
	preLen := int(binary.LittleEndian.Uint16(pathSig[1:3]))
	if preLen < MIN_HTLC_PREIMAGE_BYTES {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC preimage_len must be >= 16")
	}
	if preLen > MAX_HTLC_PREIMAGE_BYTES {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC preimage length overflow")
	}
	if len(pathSig) != 3+preLen {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC claim payload length mismatch")
	}
	if sha3_256(pathSig[3:]) != c.Hash {
		return [32]byte{}, txerr(TX_ERR_SIG_INVALID, "CORE_HTLC claim preimage hash mismatch")
	}
	return c.ClaimKeyID, nil
}

func validateHTLCRefundPath(c *HTLCCovenant, pathItem WitnessItem, pathSig []byte, ctx HTLCSpendContext) ([32]byte, error) {
	if len(pathSig) != 1 {
		return [32]byte{}, txerr(TX_ERR_PARSE, "CORE_HTLC refund payload length mismatch")
	}
	var pathKeyID [32]byte
	copy(pathKeyID[:], pathItem.Pubkey)
	if pathKeyID != c.RefundKeyID {
		return [32]byte{}, txerr(TX_ERR_SIG_INVALID, "CORE_HTLC refund key_id mismatch")
	}
	if c.LockMode == LOCK_MODE_HEIGHT {
		if ctx.BlockHeight < c.LockValue {
			return [32]byte{}, txerr(TX_ERR_TIMELOCK_NOT_MET, "CORE_HTLC height lock not met")
		}
	} else if ctx.BlockMTP < c.LockValue {
		return [32]byte{}, txerr(TX_ERR_TIMELOCK_NOT_MET, "CORE_HTLC timestamp lock not met")
	}
	return c.RefundKeyID, nil
}

func validateHTLCSignature(sigItem WitnessItem, expectedKeyID [32]byte, ctx HTLCSpendContext) error {
	if err := validateHTLCSignatureShape(sigItem, ctx); err != nil {
		return err
	}
	return verifyHTLCSignatureBinding(sigItem, expectedKeyID, ctx)
}

func validateHTLCSignatureShape(sigItem WitnessItem, ctx HTLCSpendContext) error {
	nativeSpend := ctx.Rotation.NativeSpendSuites(ctx.BlockHeight)
	if !nativeSpend.Contains(sigItem.SuiteID) {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_HTLC suite not in native spend set")
	}

	params, ok := ctx.Registry.Lookup(sigItem.SuiteID)
	if !ok {
		return txerr(TX_ERR_SIG_ALG_INVALID, "CORE_HTLC suite not registered")
	}
	if len(sigItem.Pubkey) != params.PubkeyLen {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
	}
	if len(sigItem.Signature) != params.SigLen+1 {
		return txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical witness item lengths")
	}
	return nil
}

func verifyHTLCSignatureBinding(sigItem WitnessItem, expectedKeyID [32]byte, ctx HTLCSpendContext) error {
	if sha3_256(sigItem.Pubkey) != expectedKeyID {
		return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC signature key binding mismatch")
	}

	cryptoSig, digest, err := extractSigAndDigestWithCache(sigItem, ctx.Tx, ctx.InputIndex, ctx.InputValue, ctx.ChainID, ctx.Cache)
	if err != nil {
		return err
	}
	ok, err := verifySigWithRegistry(sigItem.SuiteID, sigItem.Pubkey, cryptoSig, digest, ctx.Registry)
	if err != nil {
		return err
	}
	if !ok {
		return txerr(TX_ERR_SIG_INVALID, "CORE_HTLC signature invalid")
	}
	return nil
}

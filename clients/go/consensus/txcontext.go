package consensus

import (
	"fmt"
	"sort"
)

const TXCONTEXT_MAX_CONTINUING_OUTPUTS = 2

// Uint128 is the public TXCTX-facing representation of a consensus u128 value.
// The numeric value is Hi*2^64 + Lo.
type Uint128 struct {
	Lo uint64
	Hi uint64
}

// TxContextBase is the immutable transaction-level context shared by all
// txcontext-enabled CORE_EXT inputs in a transaction.
type TxContextBase struct {
	TotalIn  Uint128
	TotalOut Uint128
	Height   uint64
}

// TxOutputView is the normalized view of a continuing CORE_EXT output.
type TxOutputView struct {
	Value      uint64
	ExtPayload []byte
}

// ExtIDCacheEntry is one step-2 CORE_EXT output cache record for txcontext.
// Entries are keyed by ext_id and preserve vout order within each bucket.
type ExtIDCacheEntry struct {
	ExtID      uint16
	VoutIndex  uint32
	ExtPayload []byte
	Value      uint64
}

// TxContextContinuing is the immutable ext_id-local continuing output bundle.
// Only indices [0, ContinuingOutputCount) are valid.
type TxContextContinuing struct {
	ContinuingOutputCount uint8
	ContinuingOutputs     [TXCONTEXT_MAX_CONTINUING_OUTPUTS]TxOutputView
}

// TxContextBundle is the full txcontext package for one transaction.
type TxContextBundle struct {
	Base             *TxContextBase
	ContinuingByExt  map[uint16]*TxContextContinuing
	continuingExtIDs []uint16
}

func (b *TxContextBundle) Continuing(extID uint16) (*TxContextContinuing, bool) {
	if b == nil || len(b.ContinuingByExt) == 0 {
		return nil, false
	}
	v, ok := b.ContinuingByExt[extID]
	return v, ok
}

// OrderedExtIDs returns the deterministic ext_id traversal order for
// ContinuingByExt.
func (b *TxContextBundle) OrderedExtIDs() []uint16 {
	if b == nil || len(b.continuingExtIDs) == 0 {
		return nil
	}
	return append([]uint16(nil), b.continuingExtIDs...)
}

func uint128FromInternal(v u128) Uint128 {
	return Uint128{
		Lo: v.lo,
		Hi: v.hi,
	}
}

func uint128ToInternal(v Uint128) u128 {
	return u128{
		lo: v.Lo,
		hi: v.Hi,
	}
}

// CheckValueConservationTxWide applies the canonical tx-wide value
// conservation rules against the immutable txcontext totals. The vault floor
// input is ignored unless the transaction actually spends at least one
// CORE_VAULT input.
func CheckValueConservationTxWide(
	base *TxContextBase,
	hasVaultInputs bool,
	vaultInputSum Uint128,
) *TxError {
	if base == nil {
		return &TxError{Code: TX_ERR_PARSE, Msg: "txcontext base missing"}
	}

	totalIn := uint128ToInternal(base.TotalIn)
	totalOut := uint128ToInternal(base.TotalOut)
	if cmpU128(totalOut, totalIn) > 0 {
		return &TxError{Code: TX_ERR_VALUE_CONSERVATION, Msg: "sum_out exceeds sum_in"}
	}

	if hasVaultInputs {
		vaultFloor := uint128ToInternal(vaultInputSum)
		if cmpU128(totalOut, vaultFloor) < 0 {
			return &TxError{Code: TX_ERR_VALUE_CONSERVATION, Msg: "CORE_VAULT value must not fund miner fee"}
		}
	}

	return nil
}

func cloneTxContextPayload(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// BuildTxContextOutputExtIDCache builds the step-2 structural CORE_EXT output
// cache used by BuildTxContext. Buckets preserve transaction vout order.
func BuildTxContextOutputExtIDCache(tx *Tx) (map[uint16][]ExtIDCacheEntry, error) {
	if tx == nil {
		return nil, txerr(TX_ERR_PARSE, "nil tx")
	}
	cache := make(map[uint16][]ExtIDCacheEntry)
	for voutIndex, out := range tx.Outputs {
		if out.CovenantType != COV_TYPE_CORE_EXT {
			continue
		}
		cd, err := ParseCoreExtCovenantData(out.CovenantData)
		if err != nil {
			return nil, err
		}
		cache[cd.ExtID] = append(cache[cd.ExtID], ExtIDCacheEntry{
			ExtID:      cd.ExtID,
			VoutIndex:  uint32(voutIndex),
			ExtPayload: cloneTxContextPayload(cd.ExtPayload),
			Value:      out.Value,
		})
	}
	return cache, nil
}

func collectTxContextExtIDs(
	resolvedInputs []UtxoEntry,
	blockHeight uint64,
	coreExtProfiles CoreExtProfileProvider,
) ([]uint16, error) {
	if coreExtProfiles == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile provider missing")
	}

	wanted := make(map[uint16]struct{})
	for _, entry := range resolvedInputs {
		if entry.CovenantType != COV_TYPE_CORE_EXT {
			continue
		}
		cd, err := ParseCoreExtCovenantData(entry.CovenantData)
		if err != nil {
			return nil, err
		}
		profile, ok, err := coreExtProfiles.LookupCoreExtProfile(cd.ExtID, blockHeight)
		if err != nil {
			return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile lookup failure")
		}
		if !ok || !profile.Active || !profile.TxContextEnabled {
			continue
		}
		wanted[cd.ExtID] = struct{}{}
	}

	extIDs := make([]uint16, 0, len(wanted))
	for extID := range wanted {
		extIDs = append(extIDs, extID)
	}
	sort.Slice(extIDs, func(i, j int) bool { return extIDs[i] < extIDs[j] })
	return extIDs, nil
}

func sumTxContextInputValues(resolvedInputs []UtxoEntry, initial u128) (u128, error) {
	total := initial
	for _, entry := range resolvedInputs {
		var err error
		total, err = addU64ToU128(total, entry.Value)
		if err != nil {
			return u128{}, err
		}
	}
	return total, nil
}

func sumTxContextOutputValues(outputs []TxOutput, initial u128) (u128, error) {
	total := initial
	for _, out := range outputs {
		var err error
		total, err = addU64ToU128(total, out.Value)
		if err != nil {
			return u128{}, err
		}
	}
	return total, nil
}

// BuildTxContext constructs the immutable txcontext bundle for a transaction.
// It returns nil when the transaction has no CORE_EXT input whose ACTIVE profile
// enables txcontext at the supplied height.
func BuildTxContext(
	tx *Tx,
	resolvedInputs []UtxoEntry,
	outputExtIDCache map[uint16][]ExtIDCacheEntry,
	blockHeight uint64,
	coreExtProfiles CoreExtProfileProvider,
) (*TxContextBundle, error) {
	if tx == nil {
		return nil, txerr(TX_ERR_PARSE, "nil tx")
	}
	if len(tx.Inputs) != len(resolvedInputs) {
		return nil, txerr(TX_ERR_PARSE, "txcontext resolved input count mismatch")
	}
	extIDs, err := collectTxContextExtIDs(resolvedInputs, blockHeight, coreExtProfiles)
	if err != nil {
		return nil, err
	}
	if len(extIDs) == 0 {
		return nil, nil
	}
	if outputExtIDCache == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "txcontext output cache missing")
	}

	totalIn, err := sumTxContextInputValues(resolvedInputs, u128{})
	if err != nil {
		return nil, err
	}
	totalOut, err := sumTxContextOutputValues(tx.Outputs, u128{})
	if err != nil {
		return nil, err
	}

	bundle := &TxContextBundle{
		Base: &TxContextBase{
			TotalIn:  uint128FromInternal(totalIn),
			TotalOut: uint128FromInternal(totalOut),
			Height:   blockHeight,
		},
		ContinuingByExt:  make(map[uint16]*TxContextContinuing, len(extIDs)),
		continuingExtIDs: append([]uint16(nil), extIDs...),
	}

	for _, extID := range extIDs {
		continuing := &TxContextContinuing{}
		for _, entry := range outputExtIDCache[extID] {
			if int(continuing.ContinuingOutputCount) >= TXCONTEXT_MAX_CONTINUING_OUTPUTS {
				return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, fmt.Sprintf("too many continuing outputs for ext_id=%d", extID))
			}
			idx := int(continuing.ContinuingOutputCount)
			continuing.ContinuingOutputs[idx] = TxOutputView{
				Value:      entry.Value,
				ExtPayload: cloneTxContextPayload(entry.ExtPayload),
			}
			continuing.ContinuingOutputCount++
		}
		bundle.ContinuingByExt[extID] = continuing
	}

	return bundle, nil
}

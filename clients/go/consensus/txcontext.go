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
	blockHeight uint64,
	coreExtProfiles CoreExtProfileProvider,
) (*TxContextBundle, error) {
	if tx == nil {
		return nil, txerr(TX_ERR_PARSE, "nil tx")
	}
	if len(tx.Inputs) != len(resolvedInputs) {
		return nil, txerr(TX_ERR_PARSE, "txcontext resolved input count mismatch")
	}
	if coreExtProfiles == nil {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_EXT profile provider missing")
	}

	totalIn, err := sumTxContextInputValues(resolvedInputs, u128{})
	if err != nil {
		return nil, err
	}
	totalOut, err := sumTxContextOutputValues(tx.Outputs, u128{})
	if err != nil {
		return nil, err
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
	if len(wanted) == 0 {
		return nil, nil
	}

	extIDs := make([]uint16, 0, len(wanted))
	for extID := range wanted {
		extIDs = append(extIDs, extID)
	}
	sort.Slice(extIDs, func(i, j int) bool { return extIDs[i] < extIDs[j] })

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
		bundle.ContinuingByExt[extID] = &TxContextContinuing{}
	}

	for _, out := range tx.Outputs {
		if out.CovenantType != COV_TYPE_CORE_EXT {
			continue
		}
		cd, err := ParseCoreExtCovenantData(out.CovenantData)
		if err != nil {
			return nil, err
		}
		continuing, ok := bundle.ContinuingByExt[cd.ExtID]
		if !ok {
			continue
		}
		if int(continuing.ContinuingOutputCount) >= TXCONTEXT_MAX_CONTINUING_OUTPUTS {
			return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, fmt.Sprintf("too many continuing outputs for ext_id=%d", cd.ExtID))
		}
		idx := int(continuing.ContinuingOutputCount)
		continuing.ContinuingOutputs[idx] = TxOutputView{
			Value:      out.Value,
			ExtPayload: cloneBytes(cd.ExtPayload),
		}
		continuing.ContinuingOutputCount++
	}

	return bundle, nil
}

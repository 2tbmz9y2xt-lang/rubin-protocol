package p2p

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const defaultMaxTxPoolSize = 1000

// TxPool is the narrow relay-side transaction store contract.
//
// Put's fee is the authoritative admitted fee as an exact u128 scalar,
// carried unnarrowed from consensus through node.RelayTxMetadata. An
// implementation MUST NOT narrow it to u64, and MUST order by exact
// fee-rate cross-multiplication rather than a truncated or floating-point
// rate.
type TxPool interface {
	Get(txid [32]byte) ([]byte, bool)
	Has(txid [32]byte) bool
	Put(txid [32]byte, raw []byte, fee consensus.Uint128, size int) bool
}

// CanonicalMempoolTxPool adapts the node mempool to the P2P relay TxPool
// interface without introducing a second relay-owned transaction store.
type CanonicalMempoolTxPool struct {
	mempool *node.Mempool
}

// NewCanonicalMempoolTxPool returns a TxPool backed by the canonical node
// mempool used by RPC submission and miner candidate selection.
func NewCanonicalMempoolTxPool(mempool *node.Mempool) *CanonicalMempoolTxPool {
	return &CanonicalMempoolTxPool{mempool: mempool}
}

// PendingOutpointOwner returns the pointer-identical pending-outpoint owner of
// the adapted canonical mempool, so a relay-side consumer binds to the same
// single authority instead of starting a second one. Nil-safe on a nil adapter
// or a nil adapted mempool.
//
// Deliberately NOT part of the generic TxPool interface: the interface stays
// the narrow relay contract, and only this concrete adapter exposes the owner.
func (p *CanonicalMempoolTxPool) PendingOutpointOwner() *node.PendingOutpointOwner {
	if p == nil {
		return nil
	}
	return p.mempool.PendingOutpointOwner()
}

func (p *CanonicalMempoolTxPool) Get(txid [32]byte) ([]byte, bool) {
	if p == nil || p.mempool == nil {
		return nil, false
	}
	return p.mempool.TxByID(txid)
}

func (p *CanonicalMempoolTxPool) Has(txid [32]byte) bool {
	if p == nil || p.mempool == nil {
		return false
	}
	return p.mempool.Contains(txid)
}

// RetainedTxByID forwards the adapted mempool's atomic retained snapshot —
// indexed txid, admission-time wtxid, and the owner's single defensive copy of
// the exact retained bytes — with the owner's meaning unchanged: no identity
// recompute, no second payload copy, no added classification, and a bool that
// stays primary-index presence only, so a present nil row still reports found and
// remains distinguishable from absence. A nil adapter or a nil adapted mempool
// returns the zero snapshot and false.
//
// Deliberately NOT part of the generic TxPool interface: the interface stays the
// narrow relay contract, and only this concrete adapter exposes retained metadata.
func (p *CanonicalMempoolTxPool) RetainedTxByID(txid [32]byte) (node.RetainedTxSnapshot, bool) {
	if p == nil || p.mempool == nil {
		return node.RetainedTxSnapshot{}, false
	}
	return p.mempool.RetainedTxByID(txid)
}

// AddRemoteTxForRelay admits a peer transaction through the canonical mempool
// and returns the producer's result UNCHANGED: the same disposition, the
// producer's own TxID and WTxID, the same admission-context evidence, and the
// same error. The adapter classifies nothing itself.
//
// It first validates its OWN identity contract — the announced txid must be the
// txid of the supplied canonical bytes. A mismatch is an adapter contract
// violation, reported INTERNAL, and the mempool is never called. Bytes that do
// not parse carry no identity to mismatch, so they are handed to the producer,
// which owns the parse classification.
//
// A nil adapter returns RelayAdmissionUnavailable without reaching a mempool. A
// nil-backed adapter is NOT special-cased here: the nil *node.Mempool receiver
// already publishes the legacy "nil mempool" TxAdmitUnavailable result itself.
//
// Both adapter-local exits carry a *node.TxAdmitError, exactly like every result
// the producer returns, so a consumer's errors.As over the Err field always
// resolves.
//
// Deliberately NOT part of the generic TxPool interface: the interface stays the
// narrow relay contract and only this concrete adapter exposes relay dispositions.
func (p *CanonicalMempoolTxPool) AddRemoteTxForRelay(txid [32]byte, raw []byte, expected *node.PendingOutpointAdmissionContext) node.RelayAdmissionResult {
	if p == nil {
		return node.RelayAdmissionResult{
			Disposition: node.RelayAdmissionUnavailable,
			Err:         &node.TxAdmitError{Kind: node.TxAdmitUnavailable, Message: "nil canonical mempool tx pool"},
		}
	}
	if rawTxid, rawWTxID, ok := canonicalRelayIdentity(raw); ok && rawTxid != txid {
		return node.RelayAdmissionResult{
			Disposition: node.RelayAdmissionInternal,
			// The bytes parsed CANONICALLY to reach this branch, so BOTH identities
			// are known and both are published: the result doc states TxID and
			// WTxID are zero only when the candidate never parsed canonically.
			TxID:  rawTxid,
			WTxID: rawWTxID,
			// An impossible-invariant admission failure keeps the producer's own
			// compatibility kind for this class: TxAdmitRejected.
			Err: &node.TxAdmitError{Kind: node.TxAdmitRejected, Message: fmt.Sprintf("relay adapter identity mismatch: announced %x, canonical %x", txid, rawTxid)},
		}
	}
	return p.mempool.AddRemoteTxForRelay(raw, expected)
}

// canonicalRelayIdentity returns BOTH identities of canonically encoded tx
// bytes. It applies exactly the canonical-parse test canonicalTxID applies —
// consensus.ParseTx plus the full-consumption check — and differs from it only
// by also yielding the wtxid the same parse already produced.
func canonicalRelayIdentity(raw []byte) (txid [32]byte, wtxid [32]byte, ok bool) {
	_, parsedTxid, parsedWTxID, consumed, err := consensus.ParseTx(raw)
	if err != nil || consumed != len(raw) {
		return [32]byte{}, [32]byte{}, false
	}
	return parsedTxid, parsedWTxID, true
}

func (p *CanonicalMempoolTxPool) Put(txid [32]byte, raw []byte, _ consensus.Uint128, _ int) bool {
	if p == nil || p.mempool == nil {
		return false
	}
	rawTxid, err := canonicalTxID(raw)
	if err != nil || rawTxid != txid {
		return false
	}
	return p.mempool.AddRemoteTx(raw) == nil
}

type MemoryTxPool struct {
	mu      sync.RWMutex
	txs     map[[32]byte]*relayTxEntry
	maxSize int
}

type relayTxEntry struct {
	raw  []byte
	fee  consensus.Uint128
	size int
}

func NewMemoryTxPool() *MemoryTxPool {
	return NewMemoryTxPoolWithLimit(defaultMaxTxPoolSize)
}

func NewMemoryTxPoolWithLimit(maxSize int) *MemoryTxPool {
	if maxSize <= 0 {
		maxSize = defaultMaxTxPoolSize
	}
	return &MemoryTxPool{
		txs:     make(map[[32]byte]*relayTxEntry),
		maxSize: maxSize,
	}
}

func (p *MemoryTxPool) Put(txid [32]byte, raw []byte, fee consensus.Uint128, size int) bool {
	if p == nil {
		return false
	}
	if size <= 0 {
		size = len(raw)
	}
	if size <= 0 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.txs[txid]; exists {
		return false
	}
	if len(p.txs) >= p.maxSize {
		worstTxid, worstEntry, ok := p.findWorstLocked()
		if !ok || compareRelayPriority(fee, size, txid, worstEntry.fee, worstEntry.size, worstTxid) <= 0 {
			return false
		}
		delete(p.txs, worstTxid)
	}
	p.txs[txid] = &relayTxEntry{
		raw:  append([]byte(nil), raw...),
		fee:  fee,
		size: size,
	}
	return true
}

func (p *MemoryTxPool) Len() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.txs)
}

func (p *MemoryTxPool) Remove(txid [32]byte) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.txs, txid)
}

func (p *MemoryTxPool) Get(txid [32]byte) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.txs[txid]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), entry.raw...), true
}

func (p *MemoryTxPool) Has(txid [32]byte) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.txs[txid]
	return ok
}

func (p *MemoryTxPool) findWorstLocked() ([32]byte, *relayTxEntry, bool) {
	var worstTxid [32]byte
	var worstEntry *relayTxEntry
	first := true
	for txid, entry := range p.txs {
		if first || compareRelayPriority(entry.fee, entry.size, txid, worstEntry.fee, worstEntry.size, worstTxid) < 0 {
			worstTxid = txid
			worstEntry = entry
			first = false
		}
	}
	return worstTxid, worstEntry, !first
}

func compareRelayPriority(aFee consensus.Uint128, aSize int, aTxid [32]byte, bFee consensus.Uint128, bSize int, bTxid [32]byte) int {
	if cmp := compareRelayFeeRate(aFee, aSize, bFee, bSize); cmp != 0 {
		return cmp
	}
	if cmp := aFee.Cmp(bFee); cmp != 0 {
		return cmp
	}
	switch cmp := bytes.Compare(aTxid[:], bTxid[:]); {
	case cmp < 0:
		return 1
	case cmp > 0:
		return -1
	default:
		return 0
	}
}

// compareRelayFeeRate compares aFee/aSize against bFee/bSize by exact
// cross-multiplication over all 192 product bits of a u128 fee by a u64
// size. No division, truncation, or floating point.
//
// consensus.CompareFeeRate performs the cross-multiplication itself, so the
// sizes are passed straight through with their own fees: swapping them here
// would cross twice and compare fee*size products instead of rates.
func compareRelayFeeRate(aFee consensus.Uint128, aSize int, bFee consensus.Uint128, bSize int) int {
	if aSize <= 0 || bSize <= 0 {
		return 0
	}
	return consensus.CompareFeeRate(aFee, uint64(aSize), bFee, uint64(bSize))
}

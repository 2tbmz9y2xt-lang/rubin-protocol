package p2p

import (
	"bytes"
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
func compareRelayFeeRate(aFee consensus.Uint128, aSize int, bFee consensus.Uint128, bSize int) int {
	if aSize <= 0 || bSize <= 0 {
		return 0
	}
	return consensus.CompareFeeRate(aFee, uint64(bSize), bFee, uint64(aSize))
}

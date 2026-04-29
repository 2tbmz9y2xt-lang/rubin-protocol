package p2p

import (
	"bytes"
	"math/bits"
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

const defaultMaxTxPoolSize = 1000

type TxPool interface {
	Get(txid [32]byte) ([]byte, bool)
	Has(txid [32]byte) bool
	Put(txid [32]byte, raw []byte, fee uint64, size int) bool
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

func (p *CanonicalMempoolTxPool) Put(txid [32]byte, raw []byte, _ uint64, _ int) bool {
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
	fee  uint64
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

func (p *MemoryTxPool) Put(txid [32]byte, raw []byte, fee uint64, size int) bool {
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

func compareRelayPriority(aFee uint64, aSize int, aTxid [32]byte, bFee uint64, bSize int, bTxid [32]byte) int {
	if cmp := compareRelayFeeRate(aFee, aSize, bFee, bSize); cmp != 0 {
		return cmp
	}
	if aFee != bFee {
		if aFee > bFee {
			return 1
		}
		return -1
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

func compareRelayFeeRate(aFee uint64, aSize int, bFee uint64, bSize int) int {
	if aSize <= 0 || bSize <= 0 {
		return 0
	}
	ahi, alo := bits.Mul64(aFee, uint64(bSize))
	bhi, blo := bits.Mul64(bFee, uint64(aSize))
	if ahi != bhi {
		if ahi > bhi {
			return 1
		}
		return -1
	}
	if alo != blo {
		if alo > blo {
			return 1
		}
		return -1
	}
	return 0
}

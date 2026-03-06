package p2p

import "sync"

const defaultMaxTxPoolSize = 1000

type TxPool interface {
	Get(txid [32]byte) ([]byte, bool)
	Has(txid [32]byte) bool
	Put(txid [32]byte, raw []byte) bool
}

type MemoryTxPool struct {
	mu      sync.RWMutex
	txs     map[[32]byte][]byte
	maxSize int
}

func NewMemoryTxPool() *MemoryTxPool {
	return NewMemoryTxPoolWithLimit(defaultMaxTxPoolSize)
}

func NewMemoryTxPoolWithLimit(maxSize int) *MemoryTxPool {
	if maxSize <= 0 {
		maxSize = defaultMaxTxPoolSize
	}
	return &MemoryTxPool{
		txs:     make(map[[32]byte][]byte),
		maxSize: maxSize,
	}
}

func (p *MemoryTxPool) Put(txid [32]byte, raw []byte) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.txs[txid]; exists {
		return false
	}
	if len(p.txs) >= p.maxSize {
		return false
	}
	p.txs[txid] = append([]byte(nil), raw...)
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
	raw, ok := p.txs[txid]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), raw...), true
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

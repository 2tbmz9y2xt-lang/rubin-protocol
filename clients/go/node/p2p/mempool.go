package p2p

import "sync"

type TxPool interface {
	Get(txid [32]byte) ([]byte, bool)
	Has(txid [32]byte) bool
	Put(txid [32]byte, raw []byte) bool
}

type MemoryTxPool struct {
	mu  sync.RWMutex
	txs map[[32]byte][]byte
}

func NewMemoryTxPool() *MemoryTxPool {
	return &MemoryTxPool{
		txs: make(map[[32]byte][]byte),
	}
}

func (p *MemoryTxPool) Put(txid [32]byte, raw []byte) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.txs[txid]
	p.txs[txid] = append([]byte(nil), raw...)
	return !exists
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

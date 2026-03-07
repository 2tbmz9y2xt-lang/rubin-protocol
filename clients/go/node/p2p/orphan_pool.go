package p2p

import "sync"

type orphanEntry struct {
	blockHash  [32]byte
	parentHash [32]byte
	blockBytes []byte
}

type orphanMeta struct {
	parentHash [32]byte
}

type orphanPool struct {
	mu     sync.Mutex
	limit  int
	pool   map[[32]byte][]orphanEntry
	byHash map[[32]byte]orphanMeta
	fifo   [][32]byte
}

func newOrphanPool(limit int) *orphanPool {
	if limit <= 0 {
		limit = 500
	}
	return &orphanPool{
		limit:  limit,
		pool:   make(map[[32]byte][]orphanEntry),
		byHash: make(map[[32]byte]orphanMeta),
	}
}

func (o *orphanPool) Add(blockHash, parentHash [32]byte, blockBytes []byte) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.byHash[blockHash]; exists {
		return false
	}
	entry := orphanEntry{
		blockHash:  blockHash,
		parentHash: parentHash,
		blockBytes: append([]byte(nil), blockBytes...),
	}
	o.pool[parentHash] = append(o.pool[parentHash], entry)
	o.byHash[blockHash] = orphanMeta{parentHash: parentHash}
	o.fifo = append(o.fifo, blockHash)
	for len(o.byHash) > o.limit {
		o.evictOldest()
	}
	return true
}

func (o *orphanPool) TakeChildren(parentHash [32]byte) []orphanEntry {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	children := append([]orphanEntry(nil), o.pool[parentHash]...)
	delete(o.pool, parentHash)
	for _, child := range children {
		delete(o.byHash, child.blockHash)
	}
	return children
}

func (o *orphanPool) Len() int {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.byHash)
}

func (o *orphanPool) evictOldest() {
	for len(o.fifo) > 0 {
		oldest := o.fifo[0]
		o.fifo = o.fifo[1:]
		meta, exists := o.byHash[oldest]
		if !exists {
			continue
		}
		delete(o.byHash, oldest)
		children := o.pool[meta.parentHash]
		for index, child := range children {
			if child.blockHash != oldest {
				continue
			}
			children = append(children[:index], children[index+1:]...)
			break
		}
		if len(children) == 0 {
			delete(o.pool, meta.parentHash)
		} else {
			o.pool[meta.parentHash] = children
		}
		return
	}
}

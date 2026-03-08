package p2p

import "sync"

const defaultOrphanByteLimit = 64 << 20

type orphanEntry struct {
	blockHash  [32]byte
	parentHash [32]byte
	blockBytes []byte
}

type orphanMeta struct {
	parentHash [32]byte
	size       int
}

type orphanPool struct {
	mu         sync.Mutex
	limit      int
	byteLimit  int
	totalBytes int
	pool       map[[32]byte][]orphanEntry
	byHash     map[[32]byte]orphanMeta
	fifo       [][32]byte
}

func newOrphanPool(limit int) *orphanPool {
	if limit <= 0 {
		limit = 500
	}
	return &orphanPool{
		limit:     limit,
		byteLimit: defaultOrphanByteLimit,
		pool:      make(map[[32]byte][]orphanEntry),
		byHash:    make(map[[32]byte]orphanMeta),
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
	if o.byteLimit > 0 && len(blockBytes) > o.byteLimit {
		return false
	}
	entry := orphanEntry{
		blockHash:  blockHash,
		parentHash: parentHash,
		blockBytes: append([]byte(nil), blockBytes...),
	}
	o.pool[parentHash] = append(o.pool[parentHash], entry)
	o.byHash[blockHash] = orphanMeta{parentHash: parentHash, size: len(entry.blockBytes)}
	o.fifo = append(o.fifo, blockHash)
	o.totalBytes += len(entry.blockBytes)
	for len(o.byHash) > o.limit || (o.byteLimit > 0 && o.totalBytes > o.byteLimit) {
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
	removed := make(map[[32]byte]struct{}, len(children))
	for _, child := range children {
		if meta, ok := o.byHash[child.blockHash]; ok {
			o.totalBytes -= meta.size
			delete(o.byHash, child.blockHash)
		}
		removed[child.blockHash] = struct{}{}
	}
	if len(removed) > 0 {
		o.pruneFIFO(removed)
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
		o.totalBytes -= meta.size
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

func (o *orphanPool) pruneFIFO(removed map[[32]byte]struct{}) {
	if len(o.fifo) == 0 || len(removed) == 0 {
		return
	}
	filtered := o.fifo[:0]
	for _, blockHash := range o.fifo {
		if _, drop := removed[blockHash]; drop {
			continue
		}
		filtered = append(filtered, blockHash)
	}
	o.fifo = filtered
}

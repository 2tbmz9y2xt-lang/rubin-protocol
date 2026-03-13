package p2p

import (
	"net"
	"net/netip"
	"sync"
)

const defaultOrphanByteLimit = 64 << 20

// defaultPerPeerOrphanLimit caps how many orphans a single peer may inject
// before further submissions are silently dropped.  This prevents a single
// attacker from monopolising the global pool.
const defaultPerPeerOrphanLimit = 50

type orphanEntry struct {
	blockHash  [32]byte
	parentHash [32]byte
	blockBytes []byte
	fromPeer   string // peer address that relayed this orphan
}

type orphanMeta struct {
	parentHash [32]byte
	size       int
	fromPeer   string
}

type orphanPool struct {
	mu            sync.Mutex
	limit         int
	perPeerLimit  int
	byteLimit     int
	totalBytes    int
	pool          map[[32]byte][]orphanEntry
	byHash        map[[32]byte]orphanMeta
	fifo          [][32]byte
	peerOrphanCnt map[string]int // per-peer orphan count
}

func newOrphanPool(limit int) *orphanPool {
	if limit <= 0 {
		limit = 500
	}
	return &orphanPool{
		limit:         limit,
		perPeerLimit:  defaultPerPeerOrphanLimit,
		byteLimit:     defaultOrphanByteLimit,
		pool:          make(map[[32]byte][]orphanEntry),
		byHash:        make(map[[32]byte]orphanMeta),
		peerOrphanCnt: make(map[string]int),
	}
}

func (o *orphanPool) Add(blockHash, parentHash [32]byte, blockBytes []byte, fromPeer string) (bool, [][32]byte) {
	if o == nil {
		return false, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.byHash[blockHash]; exists {
		return false, nil
	}
	if o.byteLimit > 0 && len(blockBytes) > o.byteLimit {
		return false, nil
	}
	// Per-peer quota keyed by normalised IP (not ip:port) so that
	// reconnecting with a new source port does not bypass the quota.
	quotaKey := peerQuotaKey(fromPeer)
	if o.perPeerLimit > 0 && quotaKey != "" && o.peerOrphanCnt[quotaKey] >= o.perPeerLimit {
		return false, nil
	}
	entry := orphanEntry{
		blockHash:  blockHash,
		parentHash: parentHash,
		blockBytes: append([]byte(nil), blockBytes...),
		fromPeer:   quotaKey,
	}
	o.pool[parentHash] = append(o.pool[parentHash], entry)
	o.byHash[blockHash] = orphanMeta{parentHash: parentHash, size: len(entry.blockBytes), fromPeer: quotaKey}
	o.fifo = append(o.fifo, blockHash)
	o.totalBytes += len(entry.blockBytes)
	if quotaKey != "" {
		o.peerOrphanCnt[quotaKey]++
	}
	evicted := make([][32]byte, 0, 1)
	for len(o.byHash) > o.limit || (o.byteLimit > 0 && o.totalBytes > o.byteLimit) {
		if dropped, ok := o.evictOldest(); ok {
			evicted = append(evicted, dropped)
		}
	}
	return true, evicted
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
			if meta.fromPeer != "" {
				o.peerOrphanCnt[meta.fromPeer]--
				if o.peerOrphanCnt[meta.fromPeer] <= 0 {
					delete(o.peerOrphanCnt, meta.fromPeer)
				}
			}
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

func (o *orphanPool) evictOldest() ([32]byte, bool) {
	for len(o.fifo) > 0 {
		oldest := o.fifo[0]
		o.fifo = o.fifo[1:]
		meta, exists := o.byHash[oldest]
		if !exists {
			continue
		}
		delete(o.byHash, oldest)
		o.totalBytes -= meta.size
		if meta.fromPeer != "" {
			o.peerOrphanCnt[meta.fromPeer]--
			if o.peerOrphanCnt[meta.fromPeer] <= 0 {
				delete(o.peerOrphanCnt, meta.fromPeer)
			}
		}
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
		return oldest, true
	}
	return [32]byte{}, false
}

// peerQuotaKey normalises a peer address to its IP so that the orphan
// per-peer quota cannot be trivially bypassed by reconnecting (which
// changes the source port, hence the ip:port string).
func peerQuotaKey(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // already bare IP or unparseable
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.WithZone("").String()
	}
	return host
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

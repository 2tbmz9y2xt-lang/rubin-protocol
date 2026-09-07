package node

import (
	"sync"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const daRejectCacheCapacity = 50_000

// daRejectCache suppresses only exact remote DA candidate rejections under one
// stable admission context. It is volatile owner state, not retained DA state.
type daRejectCache struct {
	mu      sync.Mutex
	context PendingOutpointAdmissionContext
	adopted bool
	entries map[[32]byte]struct{}
	fifo    [][32]byte
	next    int
}

func daRejectCacheEligible(policy MempoolConfig) bool {
	if !nativeSuiteRelayContextTrusted(policy) {
		return false
	}
	_, dynamic := policy.RotationProvider.(consensus.SimplicityDeploymentProvider)
	return !dynamic
}

func (c *daRejectCache) validateCandidate(
	m *Mempool,
	owned []byte,
	tx *consensus.Tx,
	txid [32]byte,
	wtxid [32]byte,
	snapshot *chainStateAdmissionSnapshot,
	policy MempoolConfig,
	context PendingOutpointAdmissionContext,
) (*consensus.CheckedTransaction, []consensus.Outpoint, error) {
	if c == nil || !daRejectCacheEligible(policy) {
		return m.checkParsedTransactionWithSnapshot(owned, tx, txid, wtxid, snapshot, policy)
	}
	if c.contains(context, wtxid) {
		return nil, nil, selectRelayDisposition(txAdmitUnavailable("DA repeated stable rejection suppressed"), RelayAdmissionUnavailable)
	}
	checked, inputs, err := m.checkParsedTransactionWithSnapshot(owned, tx, txid, wtxid, snapshot, policy)
	if daRejectCacheInsertable(err) {
		c.insert(context, wtxid)
	}
	return checked, inputs, err
}

func daRejectCacheInsertable(err error) bool {
	return err != nil && relayDispositionOf(err) == RelayAdmissionStableTerminalReject
}

func (c *daRejectCache) contains(context PendingOutpointAdmissionContext, wtxid [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconcileLocked(context)
	_, ok := c.entries[wtxid]
	return ok
}

func (c *daRejectCache) insert(context PendingOutpointAdmissionContext, wtxid [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reconcileLocked(context)
	if _, ok := c.entries[wtxid]; ok {
		return
	}
	if c.entries == nil {
		c.entries = make(map[[32]byte]struct{}, daRejectCacheCapacity)
		c.fifo = make([][32]byte, 0, daRejectCacheCapacity)
	}
	if len(c.fifo) < daRejectCacheCapacity {
		c.fifo = append(c.fifo, wtxid)
	} else {
		delete(c.entries, c.fifo[c.next])
		c.fifo[c.next] = wtxid
		c.next = (c.next + 1) % daRejectCacheCapacity
	}
	c.entries[wtxid] = struct{}{}
}

func (c *daRejectCache) reconcileLocked(context PendingOutpointAdmissionContext) {
	if c.adopted && c.context == context {
		return
	}
	c.context = context
	c.adopted = true
	c.entries = nil
	c.fifo = nil
	c.next = 0
}

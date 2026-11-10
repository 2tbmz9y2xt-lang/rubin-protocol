package p2p

import (
	"errors"
	"fmt"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// ScheduleLocalDAPrefetch registers one local post-admission effect and uses
// the existing peerless scheduler path, which considers every eligible peer.
func (s *Service) ScheduleLocalDAPrefetch(daID [32]byte) error {
	if s == nil {
		return errors.New("nil service")
	}
	if !s.acquireWork() {
		return errServiceClosed
	}
	defer s.releaseWork()
	s.scheduleDAPrefetch(nil, daID)
	return nil
}

func (s *Service) scheduleDAPrefetch(trigger *peer, daID [32]byte) {
	if !s.canScheduleDAPrefetch() {
		return
	}
	peersByKey, keys := s.daPrefetchPeers(trigger)
	plans, diagnostic := s.daRelay.PlanPrefetch(daID, keys, s.cfg.Now())
	reportDAPrefetchDiagnostic(peersByKey, keys, diagnostic)
	for _, plan := range plans {
		s.sendDAPrefetchPlan(peersByKey, plan)
	}
}

func (s *Service) canScheduleDAPrefetch() bool {
	return s != nil && s.daRelay != nil
}

// daPrefetchPeers lists every eligible prefetch peer by quota key and moves the
// trigger connection's key to the front when it still holds its preference,
// binding that key's representative in the returned map to the trigger connection
// so the preferred plan is sent through the session whose score earned it. A nil
// trigger is a peerless call with no preference. The local tip height the
// preference reads is captured once, only for a trigger and before peersMu, so no
// chain lock is taken under a peer lock.
func (s *Service) daPrefetchPeers(trigger *peer) (map[string]*peer, []string) {
	var height uint64
	if trigger != nil {
		height = s.cfg.SyncEngine.LocalTipHeight()
	}
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	peers, keys := s.allDAPrefetchPeersLocked()
	if trigger == nil {
		return peers, keys
	}
	return peers, preferDAPrefetchPeer(keys, s.preferredDAPrefetchPeerKeyLocked(trigger, height, peers))
}

// preferredDAPrefetchPeerKeyLocked reads the trigger connection itself, never the
// connection Service.peers holds under its logical address, which may be a newer
// one on another socket. It returns the trigger's daQuotaIdentity when the trigger
// is non-nil, accepts prefetch, still meets the preference minimum after its
// quality score drifts to height, and that key is nonempty and present in
// peersByKey (a connection replaced under its logical address may be unlisted, and
// then keeps no preference); otherwise "" without touching the map. A low score
// only removes the front-of-list preference: the key stays eligible and the peer
// stays usable in the ordinary fallback order. On success the only map effect is
// peersByKey[key] = trigger, so the preferred key's ephemeral representative is
// that exact session, not the last same-host session allDAPrefetchPeersLocked
// visited.
func (s *Service) preferredDAPrefetchPeerKeyLocked(trigger *peer, height uint64, peersByKey map[string]*peer) string {
	if !acceptsDAPrefetch(trigger) || !trigger.qualityPreferred(height) {
		return ""
	}
	key := trigger.daQuotaIdentity
	if _, ok := peersByKey[key]; key == "" || !ok {
		return ""
	}
	peersByKey[key] = trigger
	return key
}

func (s *Service) allDAPrefetchPeersLocked() (map[string]*peer, []string) {
	peers := map[string]*peer{}
	for _, current := range s.peers {
		if !acceptsDAPrefetch(current) {
			continue
		}
		if key := current.daQuotaIdentity; key != "" {
			peers[key] = current
		}
	}
	keys := make([]string, 0, len(peers))
	for key := range peers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return peers, keys
}

func preferDAPrefetchPeer(keys []string, preferred string) []string {
	if preferred == "" || len(keys) < 2 {
		return keys
	}
	ordered := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == preferred {
			ordered = append(ordered, key)
			break
		}
	}
	if len(ordered) == 0 {
		return keys
	}
	for _, key := range keys {
		if key != preferred {
			ordered = append(ordered, key)
		}
	}
	return ordered
}

func acceptsDAPrefetch(current *peer) bool {
	return current != nil && current.acceptsCompactBlocks()
}

func reportDAPrefetchDiagnostic(peersByKey map[string]*peer, keys []string, diagnostic string) {
	if diagnostic == "" || len(keys) == 0 {
		return
	}
	peersByKey[keys[0]].setLastError(diagnostic)
}

func (s *Service) sendDAPrefetchPlan(peersByKey map[string]*peer, plan node.DARelayPrefetchPlan) {
	current := peersByKey[plan.PeerKey]
	if current == nil {
		s.daRelay.ReleasePrefetchPlan(plan)
		return
	}
	payload, err := encodeDAPrefetchPlanPayload(plan)
	if err == nil {
		err = current.send(messageGetDAChunk, payload)
	}
	if err != nil {
		current.setLastError(fmt.Sprintf("da prefetch send failed: %v", err))
		s.daRelay.ReleasePrefetchPlan(plan)
	}
}

func encodeDAPrefetchPlanPayload(plan node.DARelayPrefetchPlan) ([]byte, error) {
	return encodeGetDAChunkPayload(getDAChunkPayload{Version: daChunkRequestVersion, DAID: plan.DAID, Indexes: plan.Indexes})
}

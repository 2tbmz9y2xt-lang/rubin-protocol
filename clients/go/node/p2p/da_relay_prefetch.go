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
	s.scheduleDAPrefetch("", daID)
	return nil
}

func (s *Service) scheduleDAPrefetch(peerAddr string, daID [32]byte) {
	if !s.canScheduleDAPrefetch() {
		return
	}
	peersByKey, keys := s.daPrefetchPeers(peerAddr)
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
// trigger peer's key to the front when it still holds its preference, binding
// that key's representative in the returned map to the trigger connection so
// the preferred plan is sent through the session whose score earned it. The
// local tip height the preference reads is captured once, only when a trigger
// is named and before peersMu, so no chain lock is taken under a peer lock.
func (s *Service) daPrefetchPeers(peerAddr string) (map[string]*peer, []string) {
	var height uint64
	if peerAddr != "" {
		height = s.cfg.SyncEngine.LocalTipHeight()
	}
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	peers, keys := s.allDAPrefetchPeersLocked()
	if peerAddr == "" {
		return peers, keys
	}
	return peers, preferDAPrefetchPeer(keys, s.preferredDAPrefetchPeerKeyLocked(peerAddr, height, peers))
}

// preferredDAPrefetchPeerKeyLocked returns the trigger's quota key when the peer is
// present, accepts prefetch, still meets the preference minimum after its quality
// score drifts to height, and that key is nonempty and present in peersByKey (the
// contract's fail-closed bound; the production caller's trigger is always listed by
// allDAPrefetchPeersLocked in the same call, so both arms are defensive); otherwise
// "" without touching the map. A low score only removes the front-of-list
// preference: the key stays eligible and the peer stays usable in the ordinary
// fallback order. On success the only map effect is peersByKey[key] = the trigger
// pointer, so the preferred key's ephemeral representative is that exact session,
// not the last same-host session allDAPrefetchPeersLocked visited.
func (s *Service) preferredDAPrefetchPeerKeyLocked(peerAddr string, height uint64, peersByKey map[string]*peer) string {
	current := s.peers[peerAddr]
	if !acceptsDAPrefetch(current) || !current.qualityPreferred(height) {
		return ""
	}
	key := peerQuotaKey(current.addr())
	if _, ok := peersByKey[key]; key == "" || !ok {
		return ""
	}
	peersByKey[key] = current
	return key
}

func (s *Service) allDAPrefetchPeersLocked() (map[string]*peer, []string) {
	peers := map[string]*peer{}
	for _, current := range s.peers {
		if !acceptsDAPrefetch(current) {
			continue
		}
		if key := peerQuotaKey(current.addr()); key != "" {
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

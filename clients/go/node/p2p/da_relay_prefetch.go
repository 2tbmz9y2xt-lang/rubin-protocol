package p2p

import (
	"fmt"
	"sort"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	daPrefetchPerPeerBytesPerSecond uint64 = 4_000_000
	daPrefetchGlobalBytesPerSecond  uint64 = 32_000_000
	daPrefetchMaxConcurrentSets            = 8
	daPrefetchRequestTTL                   = time.Second
)

type daRelayPrefetchState struct {
	indexes map[[32]byte]map[uint16]string
	expires map[[32]byte]time.Time
}
type daRelayPrefetchPlan struct {
	daID    [32]byte
	peerKey string
	indexes []uint16
}

func (s *Service) scheduleDAPrefetch(peerAddr string, record daRelaySetRecord) {
	if !s.canScheduleDAPrefetch() {
		return
	}
	peersByKey, keys := s.daPrefetchPeers(peerAddr)
	plans, diagnostic := s.daRelay.planDAPrefetch(record, keys, s.cfg.Now())
	reportDAPrefetchDiagnostic(peersByKey, keys, diagnostic)
	for _, plan := range plans {
		s.sendDAPrefetchPlan(peersByKey, plan)
	}
}

func (s *Service) canScheduleDAPrefetch() bool {
	if s == nil {
		return false
	}
	return s.daRelay != nil
}

func (s *Service) daPrefetchPeers(peerAddr string) (map[string]*peer, []string) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	if peerAddr != "" {
		peers, keys, ok := s.preferredDAPrefetchPeerLocked(peerAddr)
		if ok {
			return peers, keys
		}
	}
	return s.allDAPrefetchPeersLocked()
}

func (s *Service) preferredDAPrefetchPeerLocked(peerAddr string) (map[string]*peer, []string, bool) {
	current := s.peers[peerAddr]
	if !acceptsDAPrefetch(current) {
		return nil, nil, false
	}
	key := peerQuotaKey(current.addr())
	if key == "" {
		return nil, nil, false
	}
	return map[string]*peer{key: current}, []string{key}, true
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

func acceptsDAPrefetch(current *peer) bool {
	if current == nil {
		return false
	}
	return current.acceptsCompactBlocks()
}

func reportDAPrefetchDiagnostic(peersByKey map[string]*peer, keys []string, diagnostic string) {
	if diagnostic == "" || len(keys) == 0 {
		return
	}
	peersByKey[keys[0]].setLastError(diagnostic)
}

func (s *Service) sendDAPrefetchPlan(peersByKey map[string]*peer, plan daRelayPrefetchPlan) {
	current := peersByKey[plan.peerKey]
	if current == nil {
		s.daRelay.releaseDAPrefetchPlan(plan)
		return
	}
	payload, err := encodeDAPrefetchPlanPayload(plan)
	if err == nil {
		err = current.send(messageGetDAChunk, payload)
	}
	if err != nil {
		current.setLastError(fmt.Sprintf("da prefetch send failed: %v", err))
		s.daRelay.releaseDAPrefetchPlan(plan)
	}
}

func encodeDAPrefetchPlanPayload(plan daRelayPrefetchPlan) ([]byte, error) {
	return encodeGetDAChunkPayload(getDAChunkPayload{Version: daChunkRequestVersion, DAID: plan.daID, Indexes: plan.indexes})
}

func (s *daRelayState) planDAPrefetch(record daRelaySetRecord, peerKeys []string, now time.Time) ([]daRelayPrefetchPlan, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefetch.ensureMaps()
	s.prefetch.releaseExpired(now)
	missing := record.missingChunkIndexes()
	if len(missing) == 0 {
		s.prefetch.releaseSet(record.daID)
		return nil, ""
	}
	if len(peerKeys) == 0 {
		return nil, ""
	}
	set, diagnostic := s.prefetch.planSet(record.daID)
	if diagnostic != "" {
		return nil, diagnostic
	}
	plansByPeer, diagnostic := s.prefetch.reserveMissing(record.daID, missing, peerKeys, set, now)
	return buildDAPrefetchPlans(record.daID, peerKeys, plansByPeer), diagnostic
}

func (p *daRelayPrefetchState) ensureMaps() {
	if p.indexes == nil {
		p.indexes = map[[32]byte]map[uint16]string{}
		p.expires = map[[32]byte]time.Time{}
	}
}

func (p *daRelayPrefetchState) releaseExpired(now time.Time) {
	for daID, expiresAt := range p.expires {
		if !expiresAt.IsZero() && !now.Before(expiresAt) {
			p.releaseSet(daID)
		}
	}
}

func (p *daRelayPrefetchState) planSet(daID [32]byte) (map[uint16]string, string) {
	set := p.indexes[daID]
	if set != nil {
		return set, ""
	}
	if len(p.indexes) >= daPrefetchMaxConcurrentSets {
		return nil, "da prefetch global set cap exceeded"
	}
	return map[uint16]string{}, ""
}

func (p *daRelayPrefetchState) reserveMissing(daID [32]byte, missing []uint16, peerKeys []string, set map[uint16]string, now time.Time) (map[string][]uint16, string) {
	globalBytes, peerBytes := p.bytesInFlight()
	plansByPeer := map[string][]uint16{}
	peerIndex := 0
	for _, chunkIndex := range missing {
		if _, inFlight := set[chunkIndex]; inFlight {
			continue
		}
		peerKey, ok, reason := nextDAPrefetchPeer(peerKeys, peerBytes, globalBytes, &peerIndex)
		if !ok {
			p.expirePlanned(daID, plansByPeer, now)
			return plansByPeer, reason
		}
		p.indexes[daID] = set
		set[chunkIndex] = peerKey
		globalBytes += consensus.CHUNK_BYTES
		peerBytes[peerKey] += consensus.CHUNK_BYTES
		plansByPeer[peerKey] = append(plansByPeer[peerKey], chunkIndex)
	}
	p.expirePlanned(daID, plansByPeer, now)
	return plansByPeer, ""
}

func (p *daRelayPrefetchState) expirePlanned(daID [32]byte, plansByPeer map[string][]uint16, now time.Time) {
	if len(plansByPeer) != 0 {
		p.expires[daID] = now.Add(daPrefetchRequestTTL)
	}
}

func nextDAPrefetchPeer(peerKeys []string, peerBytes map[string]uint64, globalBytes uint64, peerIndex *int) (string, bool, string) {
	if len(peerKeys) == 0 {
		return "", false, ""
	}
	if globalBytes+consensus.CHUNK_BYTES > daPrefetchGlobalBytesPerSecond {
		return "", false, "da prefetch global byte cap exceeded"
	}
	for checked := 0; checked < len(peerKeys); checked++ {
		idx := (*peerIndex + checked) % len(peerKeys)
		key := peerKeys[idx]
		if peerBytes[key]+consensus.CHUNK_BYTES <= daPrefetchPerPeerBytesPerSecond {
			*peerIndex = idx + 1
			return key, true, ""
		}
	}
	return "", false, "da prefetch per-peer byte cap exceeded"
}

func buildDAPrefetchPlans(daID [32]byte, peerKeys []string, plansByPeer map[string][]uint16) []daRelayPrefetchPlan {
	plans := make([]daRelayPrefetchPlan, 0, len(plansByPeer))
	for _, peerKey := range peerKeys {
		if indexes := plansByPeer[peerKey]; len(indexes) != 0 {
			plans = append(plans, daRelayPrefetchPlan{daID: daID, peerKey: peerKey, indexes: indexes})
		}
	}
	return plans
}

func (s *daRelayState) releaseDAPrefetchPlan(plan daRelayPrefetchPlan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.prefetch.indexes[plan.daID]
	for _, index := range plan.indexes {
		if set[index] == plan.peerKey {
			delete(set, index)
		}
	}
	if len(set) == 0 {
		s.prefetch.releaseSet(plan.daID)
	}
}

func (p *daRelayPrefetchState) releaseSet(daID [32]byte) {
	delete(p.indexes, daID)
	delete(p.expires, daID)
}

func (p *daRelayPrefetchState) bytesInFlight() (uint64, map[string]uint64) {
	peerBytes := map[string]uint64{}
	var globalBytes uint64
	for _, indexes := range p.indexes {
		for _, peerKey := range indexes {
			globalBytes += consensus.CHUNK_BYTES
			peerBytes[peerKey] += consensus.CHUNK_BYTES
		}
	}
	return globalBytes, peerBytes
}

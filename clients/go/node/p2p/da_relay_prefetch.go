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
	if s == nil || s.daRelay == nil {
		return
	}
	peersByKey, keys := s.daPrefetchPeers(peerAddr)
	plans, diagnostic := s.daRelay.planDAPrefetch(record, keys, s.cfg.Now())
	if diagnostic != "" && len(keys) != 0 {
		peersByKey[keys[0]].setLastError(diagnostic)
	}
	for _, plan := range plans {
		current := peersByKey[plan.peerKey]
		if current == nil {
			s.daRelay.releaseDAPrefetchPlan(plan)
			continue
		}
		payload, err := encodeGetDAChunkPayload(getDAChunkPayload{Version: daChunkRequestVersion, DAID: plan.daID, Indexes: plan.indexes})
		if err == nil {
			err = current.send(messageGetDAChunk, payload)
		}
		if err != nil {
			current.setLastError(fmt.Sprintf("da prefetch send failed: %v", err))
			s.daRelay.releaseDAPrefetchPlan(plan)
		}
	}
}

func (s *Service) daPrefetchPeers(peerAddr string) (map[string]*peer, []string) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()
	peers := map[string]*peer{}
	if peerAddr != "" {
		if current := s.peers[peerAddr]; current != nil && current.acceptsCompactBlocks() {
			if key := peerQuotaKey(current.addr()); key != "" {
				return map[string]*peer{key: current}, []string{key}
			}
		}
	}
	for _, current := range s.peers {
		if current == nil || !current.acceptsCompactBlocks() {
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

func (s *daRelayState) planDAPrefetch(record daRelaySetRecord, peerKeys []string, now time.Time) ([]daRelayPrefetchPlan, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prefetch.indexes == nil {
		s.prefetch.indexes = map[[32]byte]map[uint16]string{}
		s.prefetch.expires = map[[32]byte]time.Time{}
	}
	for daID, expiresAt := range s.prefetch.expires {
		if !expiresAt.IsZero() && !now.Before(expiresAt) {
			s.prefetch.releaseSet(daID)
		}
	}
	missing := record.missingChunkIndexes()
	if len(missing) == 0 {
		s.prefetch.releaseSet(record.daID)
		return nil, ""
	}
	if len(peerKeys) == 0 {
		return nil, ""
	}
	set := s.prefetch.indexes[record.daID]
	if set == nil {
		if len(s.prefetch.indexes) >= daPrefetchMaxConcurrentSets {
			return nil, "da prefetch global set cap exceeded"
		}
		set = map[uint16]string{}
	}
	globalBytes, peerBytes := s.prefetch.bytesInFlight()
	plansByPeer := map[string][]uint16{}
	peerIndex := 0
	for _, chunkIndex := range missing {
		if _, inFlight := set[chunkIndex]; inFlight {
			continue
		}
		peerKey, ok, reason := nextDAPrefetchPeer(peerKeys, peerBytes, globalBytes, &peerIndex)
		if !ok {
			if len(plansByPeer) != 0 {
				s.prefetch.expires[record.daID] = now.Add(daPrefetchRequestTTL)
			}
			return buildDAPrefetchPlans(record.daID, peerKeys, plansByPeer), reason
		}
		if s.prefetch.indexes[record.daID] == nil {
			s.prefetch.indexes[record.daID] = set
		}
		set[chunkIndex] = peerKey
		globalBytes += consensus.CHUNK_BYTES
		peerBytes[peerKey] += consensus.CHUNK_BYTES
		plansByPeer[peerKey] = append(plansByPeer[peerKey], chunkIndex)
	}
	if len(plansByPeer) != 0 {
		s.prefetch.expires[record.daID] = now.Add(daPrefetchRequestTTL)
	}
	return buildDAPrefetchPlans(record.daID, peerKeys, plansByPeer), ""
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

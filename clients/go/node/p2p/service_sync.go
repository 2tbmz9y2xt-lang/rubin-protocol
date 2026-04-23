package p2p

import (
	"errors"
	"os"
)

// maxBestHeightDelta bounds how far above the local tip a peer's claimed
// best_height is allowed to influence sync decisions, mirroring the Rust
// client's MAX_BEST_HEIGHT_DELTA in clients/rust/crates/rubin-node/src/p2p_runtime.rs.
// Without this clamp a malicious or misconfigured peer reporting an absurdly
// high best_height could force unnecessary sync behavior downstream.
const maxBestHeightDelta uint64 = 100_000

// clampRemoteBestHeight returns the peer's claimed best_height bounded by
// localHeight + maxBestHeightDelta. Uses saturating addition so a localHeight
// near uint64 max does not wrap and silently accept arbitrary remote claims.
func clampRemoteBestHeight(localHeight, remote uint64) uint64 {
	upper := localHeight + maxBestHeightDelta
	if upper < localHeight {
		upper = ^uint64(0)
	}
	if remote > upper {
		return upper
	}
	return remote
}

func (s *Service) requestBlocksIfBehind(p *peer) error {
	localHeight, hasTip, err := s.tipHeight()
	if err != nil {
		return err
	}
	remoteBest := clampRemoteBestHeight(localHeight, p.snapshotState().RemoteVersion.BestHeight)
	if hasTip && localHeight >= remoteBest {
		return nil
	}
	payload, err := s.getBlocksRequestPayload()
	if err != nil {
		return err
	}
	return p.send(messageGetBlk, payload)
}

func (s *Service) getBlocksRequestPayload() ([]byte, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	locators, err := s.cfg.BlockStore.LocatorHashes(s.cfg.LocatorLimit)
	if err != nil {
		return nil, err
	}
	return encodeGetBlocksPayload(GetBlocksPayload{
		LocatorHashes: locators,
	})
}

func (s *Service) tipHeight() (uint64, bool, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	height, _, ok, err := s.cfg.BlockStore.Tip()
	return height, ok, err
}

func (s *Service) hasBlock(blockHash [32]byte) (bool, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	_, err := s.cfg.BlockStore.GetHeaderByHash(blockHash)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

package node

import (
	"errors"
	"fmt"
)

func (bs *BlockStore) FindCanonicalHeight(blockHash [32]byte) (uint64, bool, error) {
	if bs == nil {
		return 0, false, errors.New("nil blockstore")
	}
	return findCanonicalHeightWithRetry(bs, blockHash)
}

// findCanonicalHeightWithRetry runs the scan-validate-cache loop.
func findCanonicalHeightWithRetry(bs *BlockStore, blockHash [32]byte) (uint64, bool, error) {
	for {
		height, found, staleCache, err := bs.scanCanonicalHeight(blockHash)
		if err != nil {
			return 0, false, err
		}
		if !found {
			if staleCache {
				bs.dropCanonicalHeightCache(blockHash)
			}
			return 0, false, nil
		}
		current, err := bs.cacheCanonicalHeightIfCurrent(blockHash, height, staleCache)
		if err != nil {
			return 0, false, err
		}
		if current {
			return height, true, nil
		}
	}
}

func (bs *BlockStore) scanCanonicalHeight(blockHash [32]byte) (uint64, bool, bool, error) {
	bs.stateMu.RLock()
	defer bs.stateMu.RUnlock()

	if cachedHeight, ok := bs.canonicalHeightByHash[blockHash]; ok {
		if cachedHeight < uint64(len(bs.index.Canonical)) {
			hash, err := bs.canonicalHashAtLocked(cachedHeight)
			if err != nil {
				return 0, false, false, err
			}
			if hash == blockHash {
				return cachedHeight, true, false, nil
			}
		}
		return bs.scanCanonicalHeightFromIndexLocked(blockHash, true)
	}
	return bs.scanCanonicalHeightFromIndexLocked(blockHash, false)
}

func (bs *BlockStore) scanCanonicalHeightFromIndexLocked(blockHash [32]byte, staleCache bool) (uint64, bool, bool, error) {
	for idx := len(bs.index.Canonical); idx > 0; idx-- {
		height := uint64(idx - 1) // #nosec G115 -- idx > 0 in this loop, so idx-1 is non-negative.
		hash, err := bs.canonicalHashAtLocked(height)
		if err != nil {
			return 0, false, false, err
		}
		if hash == blockHash {
			return height, true, staleCache, nil
		}
	}
	return 0, false, staleCache, nil
}

func (bs *BlockStore) canonicalHashAtLocked(height uint64) ([32]byte, error) {
	return parseHex32(fmt.Sprintf("canonical[%d]", height), bs.index.Canonical[height])
}

func (bs *BlockStore) cacheCanonicalHeightIfCurrent(blockHash [32]byte, height uint64, staleCache bool) (bool, error) {
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()

	if height < uint64(len(bs.index.Canonical)) {
		hash, err := bs.canonicalHashAtLocked(height)
		if err != nil {
			return false, err
		}
		if hash == blockHash {
			bs.canonicalHeightByHash[blockHash] = height
			return true, nil
		}
	}
	if staleCache {
		delete(bs.canonicalHeightByHash, blockHash)
	}
	return false, nil
}

func (bs *BlockStore) dropCanonicalHeightCache(blockHash [32]byte) {
	bs.stateMu.Lock()
	defer bs.stateMu.Unlock()
	delete(bs.canonicalHeightByHash, blockHash)
}

func (bs *BlockStore) LocatorHashes(limit int) ([][32]byte, error) {
	limit, tipHeight, ok, err := bs.locatorStart(limit)
	if err != nil || !ok {
		return nil, err
	}
	return buildLocatorHashes(bs, limit, tipHeight)
}

func buildLocatorHashes(bs *BlockStore, limit int, tipHeight uint64) ([][32]byte, error) {
	out := make([][32]byte, 0, limit)
	step := uint64(1)
	for {
		var exists bool
		var err error
		out, exists, err = bs.appendCanonicalHashAt(out, tipHeight)
		if err != nil {
			return nil, err
		}
		if !exists || locatorHashComplete(len(out), limit, tipHeight) {
			break
		}
		tipHeight, step = previousLocatorHeight(tipHeight, step, len(out))
	}
	return out, nil
}

func (bs *BlockStore) locatorStart(limit int) (int, uint64, bool, error) {
	if bs == nil {
		return 0, 0, false, errors.New("nil blockstore")
	}
	if limit <= 0 {
		limit = 32
	}
	tipHeight, _, ok, err := bs.Tip()
	return limit, tipHeight, ok, err
}

func (bs *BlockStore) appendCanonicalHashAt(out [][32]byte, height uint64) ([][32]byte, bool, error) {
	hash, exists, err := bs.CanonicalHash(height)
	if err != nil || !exists {
		return out, exists, err
	}
	return append(out, hash), true, nil
}

func locatorHashComplete(appended int, limit int, height uint64) bool {
	return appended >= limit || height == 0
}

func previousLocatorHeight(height uint64, step uint64, appended int) (uint64, uint64) {
	if appended >= 10 {
		step *= 2
	}
	if height <= step {
		return 0, step
	}
	return height - step, step
}

func (bs *BlockStore) HashesAfterLocators(locatorHashes [][32]byte, stopHash [32]byte, limit uint64) ([][32]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	if limit == 0 {
		limit = 128
	}
	tipHeight, _, ok, err := bs.Tip()
	if err != nil || !ok {
		return nil, err
	}
	return computeHashesAfterLocators(bs, locatorHashes, stopHash, tipHeight, limit)
}

func computeHashesAfterLocators(bs *BlockStore, locatorHashes [][32]byte, stopHash [32]byte, tipHeight uint64, limit uint64) ([][32]byte, error) {
	startHeight, err := bs.firstHeightAfterLocators(locatorHashes)
	if err != nil {
		return nil, err
	}
	return bs.canonicalHashesInRange(startHeight, tipHeight, stopHash, limit)
}

func (bs *BlockStore) firstHeightAfterLocators(locatorHashes [][32]byte) (uint64, error) {
	for _, locator := range locatorHashes {
		height, found, err := bs.FindCanonicalHeight(locator)
		if err != nil {
			return 0, err
		}
		if found {
			return height + 1, nil
		}
	}
	return 0, nil
}

func (bs *BlockStore) canonicalHashesInRange(startHeight uint64, tipHeight uint64, stopHash [32]byte, limit uint64) ([][32]byte, error) {
	var zero [32]byte
	out := make([][32]byte, 0, limit)
	for height := startHeight; height <= tipHeight && uint64(len(out)) < limit; height++ {
		hash, exists, err := bs.CanonicalHash(height)
		if err != nil {
			return nil, err
		}
		if !exists {
			break
		}
		out = append(out, hash)
		if stopHash != zero && hash == stopHash {
			break
		}
	}
	return out, nil
}

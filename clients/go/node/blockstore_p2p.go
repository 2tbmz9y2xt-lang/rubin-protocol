package node

import (
	"errors"
	"fmt"
)

func (bs *BlockStore) FindCanonicalHeight(blockHash [32]byte) (uint64, bool, error) {
	if bs == nil {
		return 0, false, errors.New("nil blockstore")
	}

	for {
		var (
			found      bool
			height     uint64
			staleCache bool
		)

		bs.stateMu.RLock()
		if cachedHeight, ok := bs.canonicalHeightByHash[blockHash]; ok {
			if cachedHeight < uint64(len(bs.index.Canonical)) {
				hash, err := parseHex32(fmt.Sprintf("canonical[%d]", cachedHeight), bs.index.Canonical[cachedHeight])
				if err != nil {
					bs.stateMu.RUnlock()
					return 0, false, err
				}
				if hash == blockHash {
					bs.stateMu.RUnlock()
					return cachedHeight, true, nil
				}
			}
			staleCache = true
		}
		for idx := len(bs.index.Canonical); idx > 0; idx-- {
			currentHeight := uint64(idx - 1)
			hash, err := parseHex32(fmt.Sprintf("canonical[%d]", currentHeight), bs.index.Canonical[currentHeight])
			if err != nil {
				bs.stateMu.RUnlock()
				return 0, false, err
			}
			if hash == blockHash {
				found = true
				height = currentHeight
				break
			}
		}
		bs.stateMu.RUnlock()

		if !found {
			if staleCache {
				bs.stateMu.Lock()
				delete(bs.canonicalHeightByHash, blockHash)
				bs.stateMu.Unlock()
			}
			return 0, false, nil
		}

		bs.stateMu.Lock()
		if height < uint64(len(bs.index.Canonical)) {
			hash, err := parseHex32(fmt.Sprintf("canonical[%d]", height), bs.index.Canonical[height])
			if err != nil {
				bs.stateMu.Unlock()
				return 0, false, err
			}
			if hash == blockHash {
				bs.canonicalHeightByHash[blockHash] = height
				bs.stateMu.Unlock()
				return height, true, nil
			}
		}
		if staleCache {
			delete(bs.canonicalHeightByHash, blockHash)
		}
		bs.stateMu.Unlock()
	}
}

func (bs *BlockStore) LocatorHashes(limit int) ([][32]byte, error) {
	if bs == nil {
		return nil, errors.New("nil blockstore")
	}
	if limit <= 0 {
		limit = 32
	}
	tipHeight, _, ok, err := bs.Tip()
	if err != nil || !ok {
		return nil, err
	}

	out := make([][32]byte, 0, limit)
	step := uint64(1)
	appended := 0
	for {
		hash, exists, err := bs.CanonicalHash(tipHeight)
		if err != nil {
			return nil, err
		}
		if !exists {
			break
		}
		out = append(out, hash)
		appended++
		if appended >= limit || tipHeight == 0 {
			break
		}
		if appended >= 10 {
			step *= 2
		}
		if tipHeight <= step {
			tipHeight = 0
			continue
		}
		tipHeight -= step
	}
	return out, nil
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

	startHeight := uint64(0)
	for _, locator := range locatorHashes {
		height, found, err := bs.FindCanonicalHeight(locator)
		if err != nil {
			return nil, err
		}
		if found {
			startHeight = height + 1
			break
		}
	}

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

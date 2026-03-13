package node

import (
	"encoding/hex"
	"errors"
)

func (bs *BlockStore) FindCanonicalHeight(blockHash [32]byte) (uint64, bool, error) {
	if bs == nil {
		return 0, false, errors.New("nil blockstore")
	}
	blockHashHex := hex.EncodeToString(blockHash[:])
	bs.stateMu.RLock()
	if height, ok := bs.canonicalHeightByHash[blockHash]; ok {
		if height < uint64(len(bs.index.Canonical)) && bs.index.Canonical[height] == blockHashHex {
			bs.stateMu.RUnlock()
			return height, true, nil
		}
		bs.stateMu.RUnlock()
		bs.stateMu.Lock()
		delete(bs.canonicalHeightByHash, blockHash)
		bs.stateMu.Unlock()
	} else {
		bs.stateMu.RUnlock()
	}

	bs.stateMu.RLock()
	canonical := append([]string(nil), bs.index.Canonical...)
	bs.stateMu.RUnlock()
	if len(canonical) == 0 {
		return 0, false, nil
	}

	for height := len(canonical); height > 0; height-- {
		currentHeight := uint64(height - 1)
		if canonical[currentHeight] == blockHashHex {
			bs.stateMu.Lock()
			if bs.canonicalHeightByHash != nil && currentHeight < uint64(len(bs.index.Canonical)) && bs.index.Canonical[currentHeight] == blockHashHex {
				bs.canonicalHeightByHash[blockHash] = currentHeight
			}
			bs.stateMu.Unlock()
			return currentHeight, true, nil
		}
	}
	return 0, false, nil
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

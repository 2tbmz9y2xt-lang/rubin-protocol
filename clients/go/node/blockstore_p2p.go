package node

import "errors"

func (bs *BlockStore) FindCanonicalHeight(blockHash [32]byte) (uint64, bool, error) {
	if bs == nil {
		return 0, false, errors.New("nil blockstore")
	}
	if height, ok := bs.canonicalHeightByHash[blockHash]; ok {
		hash, exists, err := bs.CanonicalHash(height)
		if err != nil {
			return 0, false, err
		}
		if exists && hash == blockHash {
			return height, true, nil
		}
		bs.rebuildCanonicalHeightIndex()
		if height, ok := bs.canonicalHeightByHash[blockHash]; ok {
			hash, exists, err := bs.CanonicalHash(height)
			if err != nil {
				return 0, false, err
			}
			if exists && hash == blockHash {
				return height, true, nil
			}
		}
	}
	tipHeight, _, ok, err := bs.Tip()
	if err != nil || !ok {
		return 0, false, err
	}
	for height := tipHeight + 1; height > 0; height-- {
		currentHeight := height - 1
		hash, exists, err := bs.CanonicalHash(currentHeight)
		if err != nil {
			return 0, false, err
		}
		if exists && hash == blockHash {
			if bs.canonicalHeightByHash != nil {
				bs.canonicalHeightByHash[blockHash] = currentHeight
			}
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

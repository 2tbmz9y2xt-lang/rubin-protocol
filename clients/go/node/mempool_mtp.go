package node

func (m *Mempool) nextBlockMTP(nextHeight uint64) (uint64, error) {
	if m == nil || m.blockStore == nil || nextHeight == 0 {
		return 0, nil
	}
	prevTimestamps, err := prevTimestampsFromStore(m.blockStore, nextHeight)
	if err != nil {
		return 0, err
	}
	if len(prevTimestamps) == 0 {
		return 0, nil
	}
	return mtpMedian(nextHeight, prevTimestamps), nil
}

package consensus

func MerkleRootTxids(txids [][32]byte) ([32]byte, error) {
	var zero [32]byte
	if len(txids) == 0 {
		return zero, txerr(TX_ERR_PARSE, "merkle: empty tx list")
	}

	level := make([][32]byte, 0, len(txids))
	var leafPreimage [1 + 32]byte
	leafPreimage[0] = 0x00
	for _, txid := range txids {
		copy(leafPreimage[1:], txid[:])
		level = append(level, sha3_256(leafPreimage[:]))
	}

	var nodePreimage [1 + 32 + 32]byte
	nodePreimage[0] = 0x01
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); {
			if i == len(level)-1 {
				// Odd promotion rule: carry forward unchanged.
				next = append(next, level[i])
				i++
				continue
			}
			copy(nodePreimage[1:33], level[i][:])
			copy(nodePreimage[33:], level[i+1][:])
			next = append(next, sha3_256(nodePreimage[:]))
			i += 2
		}
		level = next
	}

	return level[0], nil
}

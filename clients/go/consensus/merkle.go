package consensus

const witnessCommitmentPrefix = "RUBIN-WITNESS/"

func MerkleRootTxids(txids [][32]byte) ([32]byte, error) {
	return merkleRootTagged(txids, 0x00, 0x01)
}

func WitnessMerkleRootWtxids(wtxids [][32]byte) ([32]byte, error) {
	var zero [32]byte
	if len(wtxids) == 0 {
		return zero, txerr(TX_ERR_PARSE, "merkle: empty wtxid list")
	}
	ids := make([][32]byte, len(wtxids))
	copy(ids, wtxids)
	// Break self-reference: coinbase witness commitment tree uses a zero id for index 0.
	ids[0] = [32]byte{}
	return merkleRootTagged(ids, 0x02, 0x03)
}

func WitnessCommitmentHash(witnessRoot [32]byte) [32]byte {
	buf := make([]byte, 0, len(witnessCommitmentPrefix)+32)
	buf = append(buf, witnessCommitmentPrefix...)
	buf = append(buf, witnessRoot[:]...)
	return sha3_256(buf)
}

func merkleRootTagged(ids [][32]byte, leafTag byte, nodeTag byte) ([32]byte, error) {
	var zero [32]byte
	if len(ids) == 0 {
		return zero, txerr(TX_ERR_PARSE, "merkle: empty id list")
	}

	level := make([][32]byte, 0, len(ids))
	var leafPreimage [1 + 32]byte
	leafPreimage[0] = leafTag
	for _, id := range ids {
		copy(leafPreimage[1:], id[:])
		level = append(level, sha3_256(leafPreimage[:]))
	}

	var nodePreimage [1 + 32 + 32]byte
	nodePreimage[0] = nodeTag
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

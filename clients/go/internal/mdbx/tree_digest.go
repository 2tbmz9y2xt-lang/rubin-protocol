package mdbx

import (
	"crypto/sha3"
	"encoding/binary"
)

// CSM 2.6 domains (RUBIN_CONSENSUS_STATE_MACHINE.md section 2.6).
const (
	treeEmptyDomainV1  = "RUBIN_UTXO_TREE_V1\x00"
	treeLeafDomainV1   = "RUBIN_UTXO_TREE_V1\x01"
	treeBranchDomainV1 = "RUBIN_UTXO_TREE_V1\x02"
)

func treeEmptyDigestV1() [32]byte { return sha3.Sum256([]byte(treeEmptyDomainV1)) }

// treeLeafDigestV1 hashes D_LEAF || S(op, e) where op is the routing key's
// outpoint and value is the stored utxo-v1 value. Precondition: value is in
// the DecodeUTXOValue domain; it is neither copied nor re-checked.
func treeLeafDigestV1(routingKey [36]byte, value []byte) [32]byte {
	var head [55]byte
	copy(head[:19], treeLeafDomainV1)
	copy(head[19:51], routingKey[:32])
	binary.LittleEndian.PutUint32(head[51:], binary.BigEndian.Uint32(routingKey[32:]))
	var h sha3.SHA3
	h.Write(head[:])
	h.Write(value)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// treeBranchDigestV1 hashes D_BRANCH || u16be(depth) || prefix || zero || one.
// Precondition: id.Kind == TreeNodeBranchV1 and validTreeNodeID(id).
func treeBranchDigestV1(id TreeNodeIDV1, zero, one [32]byte) [32]byte {
	var preimage [121]byte
	copy(preimage[:19], treeBranchDomainV1)
	binary.BigEndian.PutUint16(preimage[19:21], id.Depth)
	copy(preimage[21:57], id.Prefix[:])
	copy(preimage[57:89], zero[:])
	copy(preimage[89:], one[:])
	return sha3.Sum256(preimage[:])
}

package consensus

import (
	"crypto/sha3"
	"encoding/binary"
	"sort"
)

const (
	canonicalUTXOEmptyDomain  = "RUBIN_UTXO_TREE_V1\x00"
	canonicalUTXOLeafDomain   = "RUBIN_UTXO_TREE_V1\x01"
	canonicalUTXOBranchDomain = "RUBIN_UTXO_TREE_V1\x02"
)

// canonicalUTXORoot implements CSM section 2.6 over a complete admitted map.
// The caller owns membership, field admission and exclusion of concurrent
// mutation. This synchronous derivation neither changes nor retains its input.
func canonicalUTXORoot(utxos map[Outpoint]UtxoEntry) [32]byte {
	if len(utxos) == 0 {
		return sha3.Sum256([]byte(canonicalUTXOEmptyDomain))
	}
	ordered := make([]Outpoint, 0, len(utxos))
	for op := range utxos {
		ordered = append(ordered, op)
	}
	sort.Slice(ordered, func(i, j int) bool { return logicalOutpointLess(ordered[i], ordered[j]) })
	return canonicalUTXORootRange(utxos, ordered)
}

// ordered is a nonempty contiguous range in routing-key order. Its endpoints
// determine the first differing absolute bit; both resulting ranges are nonempty.
func canonicalUTXORootRange(utxos map[Outpoint]UtxoEntry, ordered []Outpoint) [32]byte {
	if len(ordered) == 1 {
		h := sha3.New256()
		_, _ = h.Write([]byte(canonicalUTXOLeafDomain))
		_, _ = h.Write(logicalStateEntryBytes(ordered[0], utxos[ordered[0]]))
		var root [32]byte
		h.Sum(root[:0])
		return root
	}
	first := canonicalUTXORoutingKey(ordered[0])
	last := canonicalUTXORoutingKey(ordered[len(ordered)-1])
	d := uint16(0)
	for first[d/8] == last[d/8] {
		d += 8
	}
	difference := first[d/8] ^ last[d/8]
	for difference&0x80 == 0 {
		d++
		difference <<= 1
	}
	mask := byte(0x80 >> uint(d%8))
	split := sort.Search(len(ordered), func(i int) bool {
		key := canonicalUTXORoutingKey(ordered[i])
		return key[d/8]&mask != first[d/8]&mask
	})
	left := canonicalUTXORootRange(utxos, ordered[:split])
	right := canonicalUTXORootRange(utxos, ordered[split:])
	var preimage [121]byte
	copy(preimage[:19], canonicalUTXOBranchDomain)
	binary.BigEndian.PutUint16(preimage[19:21], d)
	q, r := d/8, d%8
	copy(preimage[21:21+q], first[:q])
	if r != 0 {
		preimage[21+q] = first[q] & (0xff << (8 - r))
	}
	copy(preimage[57:89], left[:])
	copy(preimage[89:], right[:])
	return sha3.Sum256(preimage[:])
}

func canonicalUTXORoutingKey(op Outpoint) [36]byte {
	var key [36]byte
	copy(key[:32], op.Txid[:])
	binary.BigEndian.PutUint32(key[32:], op.Vout)
	return key
}

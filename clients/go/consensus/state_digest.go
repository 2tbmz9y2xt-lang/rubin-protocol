package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"sort"
)

var utxoSetHashDST = []byte("RUBINv1-utxo-set-hash/")

// enablePostStateDigest gates expensive full-UTXO post-state hashing.
//
// The digest is only used for diagnostics/parity tooling and is disabled by
// default in production block-connection paths to avoid per-block O(N) work.
var enablePostStateDigest = false

func maybeUtxoSetHash(utxos map[Outpoint]UtxoEntry) [32]byte {
	if !enablePostStateDigest {
		return [32]byte{}
	}
	return UtxoSetHash(utxos)
}

// UtxoSetHash computes a deterministic SHA3-256 digest over the full UTXO set.
//
// This is intended for parity checks (sequential vs parallel pipelines) and MUST
// be stable across platforms and map iteration order. The encoding matches the
// Rust node implementation (`rubin-node`).
func UtxoSetHash(utxos map[Outpoint]UtxoEntry) [32]byte {
	type item struct {
		key   [36]byte // txid (32) || vout_le (4)
		entry UtxoEntry
	}

	items := make([]item, 0, len(utxos))
	for op, e := range utxos {
		var k [36]byte
		copy(k[:32], op.Txid[:])
		binary.LittleEndian.PutUint32(k[32:], op.Vout)
		items = append(items, item{key: k, entry: e})
	}

	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].key[:], items[j].key[:]) < 0
	})

	// dst || count_u64_le || items...
	buf := make([]byte, 0, len(utxoSetHashDST)+8+len(items)*64)
	buf = append(buf, utxoSetHashDST...)
	var tmp8 [8]byte
	binary.LittleEndian.PutUint64(tmp8[:], uint64(len(items)))
	buf = append(buf, tmp8[:]...)

	for _, it := range items {
		e := it.entry
		buf = append(buf, it.key[:]...)

		binary.LittleEndian.PutUint64(tmp8[:], e.Value)
		buf = append(buf, tmp8[:]...)

		var tmp2 [2]byte
		binary.LittleEndian.PutUint16(tmp2[:], e.CovenantType)
		buf = append(buf, tmp2[:]...)

		buf = AppendCompactSize(buf, uint64(len(e.CovenantData)))
		buf = append(buf, e.CovenantData...)

		binary.LittleEndian.PutUint64(tmp8[:], e.CreationHeight)
		buf = append(buf, tmp8[:]...)

		if e.CreatedByCoinbase {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}
	}

	return sha3.Sum256(buf)
}

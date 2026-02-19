package consensus

import (
	"bytes"
	"encoding/binary"
	"sort"

	"rubin.dev/node/crypto"
)

const utxoSetHashDST = "RUBINv1-utxo-set-hash/"

type utxoSetHashItem struct {
	key   [36]byte
	entry UtxoEntry
}

func outpointKeyBytes(p TxOutPoint) [36]byte {
	var out [36]byte
	copy(out[0:32], p.TxID[:])
	binary.LittleEndian.PutUint32(out[32:36], p.Vout)
	return out
}

// UtxoSetHash computes the Phase 1 canonical `utxo_set_hash` used for cross-client chainstate comparability.
// See operational/RUBIN_CHAINSTATE_SNAPSHOT_HASH_v1.1.md.
func UtxoSetHash(p crypto.CryptoProvider, utxo map[TxOutPoint]UtxoEntry) ([32]byte, error) {
	items := make([]utxoSetHashItem, 0, len(utxo))
	for point, entry := range utxo {
		items = append(items, utxoSetHashItem{
			key:   outpointKeyBytes(point),
			entry: entry,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].key[:], items[j].key[:]) < 0
	})

	// NOTE: This allocates a full message buffer for hashing. Phase 1 conformance workloads are small.
	buf := make([]byte, 0, 64+len(items)*64)
	buf = append(buf, []byte(utxoSetHashDST)...)
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], uint64(len(items)))
	buf = append(buf, n[:]...)

	var u64b [8]byte
	var u16b [2]byte
	for _, it := range items {
		buf = append(buf, it.key[:]...)
		binary.LittleEndian.PutUint64(u64b[:], it.entry.Output.Value)
		buf = append(buf, u64b[:]...)
		binary.LittleEndian.PutUint16(u16b[:], it.entry.Output.CovenantType)
		buf = append(buf, u16b[:]...)
		buf = append(buf, CompactSize(len(it.entry.Output.CovenantData)).Encode()...)
		buf = append(buf, it.entry.Output.CovenantData...)
		binary.LittleEndian.PutUint64(u64b[:], it.entry.CreationHeight)
		buf = append(buf, u64b[:]...)
		if it.entry.CreatedByCoinbase {
			buf = append(buf, 0x01)
		} else {
			buf = append(buf, 0x00)
		}
	}

	return p.SHA3_256(buf)
}

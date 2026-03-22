package consensus

// UtxoSnapshot is a read-only, immutable view of the UTXO set at a specific
// point in time (typically block-start). It enables safe concurrent lookups
// from parallel validation workers without synchronization, because no
// mutation is allowed after creation.
//
// The snapshot captures the entire UTXO map at creation time via a shallow
// copy. This is safe because UtxoEntry values contain only value types and a
// CovenantData []byte which is never mutated after insertion.
//
// Sharding: UtxoSnapshot provides a deterministic shard function based on
// the outpoint's txid bytes. This enables future work-partitioning across
// workers without hash-map contention.
type UtxoSnapshot struct {
	utxos map[Outpoint]UtxoEntry
	count int
}

// NewUtxoSnapshot creates a read-only snapshot from the given UTXO set.
// The input map is shallow-copied; callers may safely continue mutating
// the original map after this call.
func NewUtxoSnapshot(utxos map[Outpoint]UtxoEntry) *UtxoSnapshot {
	if utxos == nil {
		return &UtxoSnapshot{
			utxos: make(map[Outpoint]UtxoEntry),
			count: 0,
		}
	}
	snap := make(map[Outpoint]UtxoEntry, len(utxos))
	for k, v := range utxos {
		snap[k] = v
	}
	return &UtxoSnapshot{
		utxos: snap,
		count: len(snap),
	}
}

// Get looks up an outpoint in the snapshot. Returns the entry and true if
// found, or a zero UtxoEntry and false otherwise. This method is safe for
// concurrent use from multiple goroutines.
func (s *UtxoSnapshot) Get(op Outpoint) (UtxoEntry, bool) {
	e, ok := s.utxos[op]
	return e, ok
}

// Contains returns true if the outpoint exists in the snapshot.
// This method is safe for concurrent use.
func (s *UtxoSnapshot) Contains(op Outpoint) bool {
	_, ok := s.utxos[op]
	return ok
}

// Count returns the number of UTXOs in the snapshot.
func (s *UtxoSnapshot) Count() int {
	return s.count
}

// Shard returns a deterministic shard index for the given outpoint.
// The shard is computed from the first bytes of the txid, ensuring
// uniform distribution for power-of-two shard counts.
//
// If numShards <= 0, returns 0.
// If numShards is 1, returns 0.
func Shard(op Outpoint, numShards int) int {
	if numShards <= 1 {
		return 0
	}
	// Use first 4 bytes of txid as a uint32 for distribution.
	// This is deterministic and provides good uniformity for typical
	// txid distributions (SHA3-256 hashes).
	h := uint32(op.Txid[0])<<24 | uint32(op.Txid[1])<<16 |
		uint32(op.Txid[2])<<8 | uint32(op.Txid[3])
	return int(h % uint32(numShards)) // #nosec G115 -- numShards <= 1 is rejected above; shard index remains bounded by numShards.
}

// ResolveInputs looks up all input outpoints for a transaction and returns
// the corresponding UtxoEntry slice. Returns an error if any input is not
// found in the snapshot (missing UTXO).
//
// This is the primary entry point for parallel validation workers to resolve
// transaction inputs against the block-start UTXO state.
func (s *UtxoSnapshot) ResolveInputs(tx *Tx) ([]UtxoEntry, error) {
	entries := make([]UtxoEntry, len(tx.Inputs))
	for i, inp := range tx.Inputs {
		op := Outpoint{Txid: inp.PrevTxid, Vout: inp.PrevVout}
		e, ok := s.utxos[op]
		if !ok {
			return nil, txerr(TX_ERR_MISSING_UTXO, "input references missing UTXO")
		}
		entries[i] = e
	}
	return entries, nil
}

// ForEach iterates over all UTXOs in the snapshot, calling fn for each.
// The iteration order is non-deterministic (Go map iteration).
// This is intended for diagnostic and testing purposes only.
func (s *UtxoSnapshot) ForEach(fn func(op Outpoint, entry UtxoEntry)) {
	for k, v := range s.utxos {
		fn(k, v)
	}
}

package policycontrol

import "bytes"

// PutRow stages an insert or payload replacement of the (kind, key) row, stamped
// with the committing sequence. An unknown kind or over-ceiling key or payload
// refuses before effects; an identical payload stages nothing; Commit checks bounds.
func (tx *Tx) PutRow(kind RowKind, key, payload []byte) error {
	if kind < KindOriginalRejection || kind > KindWorkingReservation || len(key) > MaxKeyBytes || len(payload) > MaxPayloadBytes {
		return refused("journal row outside its domain or ceilings")
	}
	id := rowID(kind, key)
	delete(tx.dels, id)
	if old, ok := tx.base.rows[id]; ok && bytes.Equal(old.Payload, payload) {
		delete(tx.puts, id)
	} else {
		tx.puts[id] = Row{Kind: kind, Key: clone(key), Payload: clone(payload)}
	}
	return nil
}

// DeleteRow stages removal of a reservation or working-reservation row; an
// absent row stages nothing. Lasting slots and contexts are never removed,
// reused, evicted or reset.
func (tx *Tx) DeleteRow(kind RowKind, key []byte) error {
	if kind != KindReservation && kind != KindWorkingReservation {
		return refused("lasting slots and contexts are never removed")
	}
	id := rowID(kind, key)
	if delete(tx.puts, id); tx.base.rows[id].Kind != 0 {
		tx.dels[id] = struct{}{}
	}
	return nil
}

// Membership returns the complete committed membership in (kind, key) order,
// each row with its committing sequence, or ErrClosed after Close or ErrBusy during a crossing or
// while an attempt is UNKNOWN; never a partial or empty substitute, and never inferred from the receipt.
func (s *Store) Membership() ([]Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readableLocked(); err != nil {
		return nil, err
	}
	out := make([]Row, 0, len(s.st.rows))
	for _, id := range sortedRowIDs(s.st.rows) {
		r := s.st.rows[id]
		r.Key, r.Payload = clone(r.Key), clone(r.Payload)
		out = append(out, r)
	}
	return out, nil
}

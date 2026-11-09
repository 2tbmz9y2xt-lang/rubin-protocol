package policycontrol

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// boundedState seeds slots counted rows (a mix of the five counted kinds, including RECOVERY_CORE_IMPOSSIBLE) and contexts context rows at sequence 40.
func boundedState(slots, contexts int) *state {
	st := ownerlessState(testIdentity(1), 40)
	counted := []RowKind{KindOriginalRejection, KindRecoveryCoreImpossible, KindCorrectiveAcceptance, KindAudit, KindDisposition}
	for i := 0; i < slots; i++ {
		k := counted[i%len(counted)]
		key := []byte(fmt.Sprintf("s%08d", i))
		st.rows[rowID(k, key)] = Row{Kind: k, Key: key, Sequence: 1 + uint64(i%40), Payload: []byte("p")}
	}
	for i := 0; i < contexts; i++ {
		key := []byte(fmt.Sprintf("c%05d", i))
		st.rows[rowID(KindContext, key)] = Row{Kind: KindContext, Key: key, Sequence: 40}
	}
	return st
}

func rowCommit(t *testing.T, s *Store, stageFn func(tx *Tx) error) (Result, error) {
	t.Helper()
	tx := mustBegin(t, s)
	tx.AdmitOwner(OwnerOrdinaryRecovery, []byte("producer"))
	tx.Operation(ClassCapture, 3)
	if err := stageFn(tx); err != nil {
		r, _ := tx.Abort()
		return r, err
	}
	return tx.Commit()
}

func putFn(kind RowKind, key string) func(tx *Tx) error {
	return func(tx *Tx) error { return tx.PutRow(kind, []byte(key), []byte("payload")) }
}

func counts(t *testing.T, s *Store) (slots, contexts, reservations, working int) {
	t.Helper()
	rows, err := s.Membership()
	must(t, err)
	m := map[string]Row{}
	for _, r := range rows {
		m[rowID(r.Kind, r.Key)] = r
	}
	n := countRows(m)
	return n[0], n[1], n[2], n[3]
}

// A16: exactly 65,536 slots and 1,024 contexts commit; one more refuses before effects; reservation and working rows count in neither bound; a second working row refuses; lasting rows are never removed.
func TestJournalBounds(t *testing.T) {
	dir, s := seedStore(t, boundedState(MaxLastingSlots-1, MaxContexts-1))
	mustCommit2 := func(fn func(tx *Tx) error, seq uint64) {
		t.Helper()
		r, err := rowCommit(t, s, fn)
		if wantResult(t, r, NEW, seq); err != nil {
			t.Fatal(err)
		}
	}
	mustCommit2(func(tx *Tx) error {
		if err := tx.PutRow(KindAudit, []byte("last-slot"), nil); err != nil {
			return err
		}
		return tx.PutRow(KindContext, []byte("last-context"), nil)
	}, 41)
	if sl, cx, _, _ := counts(t, s); sl != MaxLastingSlots || cx != MaxContexts {
		t.Fatalf("counts %d/%d", sl, cx)
	}
	full := fileBytes(t, dir)
	for name, fn := range map[string]func(tx *Tx) error{
		"slot 65,537":      putFn(KindDisposition, "over"),
		"context 1,025":    putFn(KindContext, "over"),
		"remove a slot":    func(tx *Tx) error { return tx.DeleteRow(KindAudit, []byte("last-slot")) },
		"remove a context": func(tx *Tx) error { return tx.DeleteRow(KindContext, []byte("last-context")) },
		"over-ceiling key": func(tx *Tx) error { return tx.PutRow(KindReservation, make([]byte, MaxKeyBytes+1), nil) },
		"over-ceiling payload": func(tx *Tx) error {
			return tx.PutRow(KindReservation, []byte("r"), make([]byte, MaxPayloadBytes+1))
		},
		"unknown kind": putFn(9, "x"),
	} {
		r, err := rowCommit(t, s, fn)
		if wantResult(t, r, OLD, 41); !errors.Is(err, ErrRefused) || !bytes.Equal(fileBytes(t, dir), full) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	mustCommit2(func(tx *Tx) error {
		if err := tx.PutRow(KindReservation, make([]byte, MaxKeyBytes), make([]byte, MaxPayloadBytes)); err != nil {
			return err
		}
		return tx.PutRow(KindWorkingReservation, []byte("w"), []byte("RESERVED"))
	}, 42)
	if sl, cx, rs, wk := counts(t, s); sl != MaxLastingSlots || cx != MaxContexts || rs != 1 || wk != 1 {
		t.Fatalf("counts %d/%d/%d/%d", sl, cx, rs, wk)
	}
	if r, err := rowCommit(t, s, putFn(KindWorkingReservation, "w2")); r.Truth != OLD || !errors.Is(err, ErrRefused) {
		t.Fatalf("second working reservation: %v", err)
	}
	mustCommit2(putFn(KindWorkingReservation, "w"), 43)
	mustCommit2(func(tx *Tx) error { return tx.DeleteRow(KindWorkingReservation, []byte("w")) }, 44)
	mustCommit2(putFn(KindWorkingReservation, "w2"), 45)
	mustCommit2(putFn(KindAudit, "last-slot"), 46)
	if sl, _, _, wk := counts(t, s); sl != MaxLastingSlots || wk != 1 {
		t.Fatalf("payload update changed counts: %d/%d", sl, wk)
	}
}

// A21: a RECOVERY_CORE_IMPOSSIBLE row commits as a member of the closed kind domain with its committing sequence and counts one lasting slot.
func TestRecoveryCoreImpossibleRow(t *testing.T) {
	dir, s := seedStore(t, boundedState(MaxLastingSlots-1, 0))
	r, err := rowCommit(t, s, putFn(KindRecoveryCoreImpossible, "core"))
	if wantResult(t, r, NEW, 41); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.Membership()
	found := false
	for _, row := range rows {
		if row.Kind == KindRecoveryCoreImpossible && string(row.Key) == "core" {
			found = row.Sequence == 41 && string(row.Payload) == "payload"
		}
	}
	if sl, _, _, _ := counts(t, s); !found || sl != MaxLastingSlots {
		t.Fatalf("core row found=%v slots=%d", found, sl)
	}
	full := fileBytes(t, dir)
	if r, err := rowCommit(t, s, putFn(KindRecoveryCoreImpossible, "core2")); r.Truth != OLD || !errors.Is(err, ErrRefused) || !bytes.Equal(fileBytes(t, dir), full) {
		t.Fatalf("core row at bound: %v", err)
	}
}

// A17, X12: membership is the complete committed set read from rows, not the receipt; a malformed row is an integrity error, never a partial list.
func TestStrictMembership(t *testing.T) {
	id := testIdentity(1)
	dir, s := seedStore(t, ownerlessState(id, 40))
	mustCommit(t, batchTx(t, s, 0, 3, "b"), NEW, 41)
	mustCommit(t, controlTx(t, s, "z"), NEW, 42)
	rows, err := s.Membership()
	if err != nil || len(rows) != 4 || rows[0].Sequence != 41 || rows[3].Sequence != 42 || mustView(t, s).Receipt.Cursors != nil {
		t.Fatalf("membership %v err %v", rows, err)
	}
	rows[0].Key[0] = 'X'
	if again, _ := s.Membership(); again[0].Key[0] != 'b' {
		t.Fatal("membership exposed committed bytes")
	}
	must(t, s.Close())
	good, _ := decode(fileBytes(t, dir))
	for name, tamper := range map[string]func(st *state){
		"unknown kind":    func(st *state) { st.rows["\x0Bk"] = Row{Kind: 11, Key: []byte("k"), Sequence: 41} },
		"row seq above P": func(st *state) { st.rows["\x06z"] = Row{Kind: KindAudit, Key: []byte("z"), Sequence: 43} },
	} {
		st := *good
		st.rows = map[string]Row{}
		for k, v := range good.rows {
			st.rows[k] = v
		}
		tamper(&st)
		must(t, os.WriteFile(filepath.Join(dir, controlFile), encode(&st), 0o600))
		if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: open %v", name, err)
		}
	}
	img := encode(good)
	for name, bad := range map[string][]byte{"missing field": img[:len(img)-1], "extra field": append(bytes.Clone(img), 0)} {
		must(t, os.WriteFile(filepath.Join(dir, controlFile), bad, 0o600))
		if s, err := Open(dir, id); s != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s: open %v", name, err)
		}
	}
}

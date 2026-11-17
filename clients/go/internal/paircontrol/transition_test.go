package paircontrol

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReplacementDurability(t *testing.T) {
	for _, mode := range []uint8{1, 2} {
		for _, lag := range []uint8{1, 2, 3} {
			t.Run(string(rune('0'+mode))+string(rune('0'+lag)), func(t *testing.T) {
				v, i := selected(), replacement()
				i.Origin, i.LAG = mode, lag
				if lag == 2 {
					r := reference()
					i.LAGSourceRef = &r
				}
				if lag == 3 {
					r := reference()
					i.Source, i.AssuranceRef = 2, &r
				}
				s, dir := existing(t, v)
				r, err := s.PersistIntentV1(context.Background(), 17, i, nil)
				require(t, err)
				if r != (ResultV1{2, 18, false}) {
					t.Fatalf("persist result %+v", r)
				}
				v.Sequence, v.Intent = 18, &i
				wantBytes := fixtureBytes(v)
				if !bytes.Equal(diskBytes(t, dir), wantBytes) {
					t.Fatal("persist changed original source/mode/OLD/D/comparand/assurance")
				}
				i.SourceRef.Opaque[0] ^= 1
				i.ComparandRef.Opaque[0] ^= 1
				observed, err := s.ObserveV1()
				require(t, err)
				if !bytes.Equal(fixtureBytes(observed), wantBytes) || !bytes.Equal(diskBytes(t, dir), wantBytes) {
					t.Fatal("stored operator input aliases caller backing")
				}
				i.SourceRef.Opaque[0] ^= 1
				i.ComparandRef.Opaque[0] ^= 1
				require(t, s.CloseV1())
				s, err = OpenV1(dir, identity())
				require(t, err)
				wantRecord(t, s, v)
				r, err = s.PersistIntentV1(context.Background(), 18, i, nil)
				require(t, err)
				if r != (ResultV1{1, 18, false}) || !bytes.Equal(wantBytes, diskBytes(t, dir)) {
					t.Fatal("identical intent wrote/incremented")
				}
				different := replacement()
				different.ID[1] = 1
				r, err = s.PersistIntentV1(context.Background(), 18, different, nil)
				wantLocal(t, r, err, "persist_intent", "refused", ResultV1{1, 18, false})
				wantRecord(t, s, v)
				got, err := s.ObserveV1()
				require(t, err)
				got.Intent.SourceRef.Opaque[0] ^= 1
				got.Intent.ComparandRef.Opaque[0] ^= 1
				got.Intent.Destination.Location = "other"
				got.Intent.Old.AuthoritySequence++
				if got.Intent.AssuranceRef != nil {
					got.Intent.AssuranceRef.Opaque[0] ^= 1
				}
				if got.Intent.LAGSourceRef != nil {
					got.Intent.LAGSourceRef.Opaque[0] ^= 1
				}
				wantRecord(t, s, v)
				require(t, s.CloseV1())
			})
		}
	}
}

func TestRetirementGapAndRetainedRefusal(t *testing.T) {
	for _, mode := range []uint8{1, 2} {
		v, i := selected(), replacement()
		i.Origin = mode
		s, dir := existing(t, v)
		r, err := s.PersistIntentV1(context.Background(), 17, i, nil)
		require(t, err)
		if r != (ResultV1{2, 18, false}) {
			t.Fatal("intent was not persisted")
		}
		v.Sequence, v.Intent = 18, &i
		r, err = s.RetireV1(context.Background(), 18, i.ID, reference(), nil)
		if mode == 2 {
			wantLocal(t, r, err, "retire", "refused", ResultV1{1, 18, false})
			wantRecord(t, s, v)
			require(t, s.CloseV1())
			continue
		}
		require(t, err)
		if r != (ResultV1{2, 19, false}) {
			t.Fatal("retirement result")
		}
		v.Sequence, v.Selector, v.Selected = 19, 3, nil
		v.Retired = &RetirementV1{originalPair(), 1, reference()}
		require(t, s.CloseV1())
		s, err = OpenV1(dir, identity())
		require(t, err)
		wantRecord(t, s, v)
		if _, err := os.Stat(filepath.Join(dir, "D17")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("control retirement created a destination")
		}
		r, err = s.RetireV1(context.Background(), 19, i.ID, reference(), nil)
		require(t, err)
		if r != (ResultV1{1, 19, false}) {
			t.Fatal("same retirement was not no-op OLD")
		}
		changed := reference()
		changed.Opaque = []byte("other-result")
		r, err = s.RetireV1(context.Background(), 19, i.ID, changed, nil)
		wantLocal(t, r, err, "retire", "refused", ResultV1{1, 19, false})
		wantRecord(t, s, v)
		require(t, s.CloseV1())
	}
}

func TestPositiveDamagePreservesExistingOwner(t *testing.T) {
	for _, origin := range []uint8{0, 1, 2, 3} {
		v, i := selected(), replacement()
		p, h1 := h1Policy(t)
		if origin == 3 {
			i = h1
		} else if origin != 0 {
			i.Origin = origin
		}
		if origin != 0 {
			v.Intent = &i
		}
		s, dir := existing(t, v)
		beforeP, err := p.View()
		require(t, err)
		wrong := originalPair()
		wrong.Database.DatabaseID[1] = 1
		r, err := s.RecordDamageV1(context.Background(), 17, wrong, reference())
		wantLocal(t, r, err, "damage", "stale", ResultV1{1, 17, false})
		wantRecord(t, s, v)
		r, err = s.RecordDamageV1(context.Background(), 16, originalPair(), reference())
		wantLocal(t, r, err, "damage", "stale", ResultV1{1, 17, false})
		r, err = s.RecordDamageV1(context.Background(), 17, originalPair(), reference())
		require(t, err)
		if r != (ResultV1{2, 18, false}) {
			t.Fatal("damage raw control result")
		}
		v.Sequence, v.Selector, v.Selected = 18, 3, nil
		v.Retired = &RetirementV1{originalPair(), 3, reference()}
		require(t, s.CloseV1())
		s, err = OpenV1(dir, identity())
		require(t, err)
		wantRecord(t, s, v)
		r, err = s.RecordDamageV1(context.Background(), 18, originalPair(), reference())
		require(t, err)
		if r != (ResultV1{1, 18, false}) {
			t.Fatal("same positive disposition not idempotent")
		}
		afterP, err := p.View()
		require(t, err)
		if !reflect.DeepEqual(beforeP, afterP) {
			t.Fatal("damage changed independent P incident/attempt/latch/owner")
		}
		if _, err := os.Stat(filepath.Join(dir, "D17")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("positive projection created D")
		}
		require(t, s.CloseV1())
	}
}

func TestAdmissionPriorityAndExhaustion(t *testing.T) {
	v := selected()
	s, dir := existing(t, v)
	before := diskBytes(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bad := replacement()
	bad.Origin = 4
	s.mu.Lock()
	r, err := s.PersistIntentV1(ctx, 17, bad, nil)
	wantLocal(t, r, err, "persist_intent", "refused", ResultV1{})
	r, err = s.PersistIntentV1(context.Background(), 17, replacement(), nil)
	wantLocal(t, r, err, "persist_intent", "busy", ResultV1{})
	s.mu.Unlock()
	r, err = s.PersistIntentV1(ctx, 17, replacement(), nil)
	e := wantLocal(t, r, err, "persist_intent", "precommit", ResultV1{})
	if !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation identity lost")
	}
	var nilContext context.Context
	r, err = s.PersistIntentV1(nilContext, 17, replacement(), nil)
	wantLocal(t, r, err, "persist_intent", "refused", ResultV1{})
	r, err = s.PersistIntentV1(context.Background(), 16, replacement(), nil)
	wantLocal(t, r, err, "persist_intent", "stale", ResultV1{1, 17, false})
	if !bytes.Equal(before, diskBytes(t, dir)) {
		t.Fatal("admission refusal changed durable preimage")
	}
	r, err = s.PersistIntentV1(context.Background(), 17, replacement(), nil)
	require(t, err)
	if r != (ResultV1{2, 18, false}) {
		t.Fatal("fresh legal operation after refusals was not admitted")
	}
	v.Sequence = math.MaxUint64
	s2, _ := existing(t, v)
	o2 := installFaults(t, s2)
	r, err = s2.PersistIntentV1(context.Background(), math.MaxUint64, replacement(), nil)
	e = wantLocal(t, r, err, "persist_intent", "refused", ResultV1{1, math.MaxUint64, true})
	if e.Cause == nil {
		t.Fatal("sequence exhaustion lost local-invariant diagnostic")
	}
	if _, err := os.Stat(filepath.Join(s2.dir, "outer-control.scratch")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("overflow acquired scratch")
	}
	checkBlockedNext(t, s2, o2, e, r, v, v)
	require(t, s2.CloseV1())
	fresh, err := OpenV1(s2.dir, identity())
	require(t, err)
	wantRecord(t, fresh, v)
	require(t, fresh.CloseV1())
}

func TestEveryMutatorEntryGuard(t *testing.T) {
	p, _ := h1Policy(t)
	for _, operation := range []string{"persist_intent", "retire", "damage", "end_h1"} {
		call := func(s *Store, ctx context.Context, seq uint64, malformed bool) (ResultV1, error) {
			i, old, ref := replacement(), originalPair(), reference()
			id := i.ID
			if malformed {
				i.Origin, old.CurrentGeneration, ref.OwnerID, id = 4, 0, [32]byte{}, [32]byte{}
			}
			switch operation {
			case "persist_intent":
				return s.PersistIntentV1(ctx, seq, i, nil)
			case "retire":
				return s.RetireV1(ctx, seq, id, ref, nil)
			case "damage":
				return s.RecordDamageV1(ctx, seq, old, ref)
			default:
				return s.EndH1V1(ctx, seq, id, p)
			}
		}
		for _, state := range []string{"busy", "closed", "cancelled", "nil_context", "stale", "unresolved"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				s, dir := existing(t, selected())
				ctx, expected := context.Background(), uint64(17)
				code, want := "busy", ResultV1{}
				if state == "busy" {
					s.mu.Lock()
					defer s.mu.Unlock()
				}
				if state == "closed" {
					require(t, s.CloseV1())
					code = "closed"
				}
				if state == "cancelled" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
					code = "precommit"
				}
				if state == "nil_context" {
					ctx, code = nil, "refused"
				}
				if state == "stale" {
					expected, code, want = 16, "stale", ResultV1{1, 17, false}
				}
				if state == "unresolved" {
					installFaults(t, s, faultAt{"sync:dir", 2, errors.New("durability"), false})
					_, err := s.PersistIntentV1(ctx, 17, replacement(), nil)
					if err == nil {
						t.Fatal("actual poisoned crossing was not reached")
					}
					code, want = "unresolved", ResultV1{3, 0, true}
				}
				before := diskBytes(t, dir)
				r, err := call(s, ctx, expected, true)
				wantLocal(t, r, err, operation, "refused", ResultV1{})
				r, err = call(s, ctx, expected, false)
				e := wantLocal(t, r, err, operation, code, want)
				if state == "cancelled" && !errors.Is(e, context.Canceled) {
					t.Fatal("entry cancellation Cause was replaced")
				}
				if !bytes.Equal(before, diskBytes(t, dir)) {
					t.Fatal("entry guard mutated durable bytes")
				}
			})
		}
	}
}

func TestIndependentStaticPayloadPriority(t *testing.T) {
	p, h1 := h1Policy(t)
	for _, kind := range []string{"persist_shape", "persist_extra_p", "persist_missing_p", "retire_id", "retire_ref", "damage_old", "damage_ref", "end_id", "end_p"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := existing(t, selected())
			before := diskBytes(t, dir)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			i, ref, old := replacement(), reference(), originalPair()
			var r ResultV1
			var err error
			s.mu.Lock()
			switch kind {
			case "persist_shape":
				i.ID = [32]byte{}
				r, err = s.PersistIntentV1(ctx, 17, i, nil)
			case "persist_extra_p":
				r, err = s.PersistIntentV1(ctx, 17, i, p)
			case "persist_missing_p":
				r, err = s.PersistIntentV1(ctx, 17, h1, nil)
			case "retire_id":
				r, err = s.RetireV1(ctx, 17, [32]byte{}, ref, nil)
			case "retire_ref":
				ref.OwnerID = [32]byte{}
				r, err = s.RetireV1(ctx, 17, i.ID, ref, nil)
			case "damage_old":
				old.CurrentGeneration = 0
				r, err = s.RecordDamageV1(ctx, 17, old, ref)
			case "damage_ref":
				ref.Opaque = nil
				r, err = s.RecordDamageV1(ctx, 17, old, ref)
			case "end_id":
				r, err = s.EndH1V1(ctx, 17, [32]byte{}, p)
			case "end_p":
				r, err = s.EndH1V1(ctx, 17, i.ID, nil)
			}
			s.mu.Unlock()
			var e *ErrorV1
			if r != (ResultV1{}) || !errors.As(err, &e) || e.Code != "refused" || errors.Is(err, context.Canceled) {
				t.Fatal("one-field static refusal lost precedence over cancellation/held owner")
			}
			if !bytes.Equal(before, diskBytes(t, dir)) {
				t.Fatal("static refusal changed owned bytes")
			}
		})
	}
}

func TestCompleteOriginalPairCAS(t *testing.T) {
	for _, field := range []string{"form", "location", "database_id", "current", "lag", "authority"} {
		t.Run(field, func(t *testing.T) {
			s, dir := existing(t, selected())
			i := replacement()
			switch field {
			case "form":
				i.Old.Database.Form, i.Old.Database.Location = 2, "old"
			case "location":
				i.Old.Database.Location = "/other-old"
			case "database_id":
				i.Old.Database.DatabaseID[1] = 1
			case "current":
				i.Old.CurrentGeneration++
			case "lag":
				i.Old.LagGeneration++
			case "authority":
				i.Old.AuthoritySequence++
			}
			before := diskBytes(t, dir)
			r, err := s.PersistIntentV1(context.Background(), 17, i, nil)
			wantLocal(t, r, err, "persist_intent", "stale", ResultV1{1, 17, false})
			if !bytes.Equal(before, diskBytes(t, dir)) {
				t.Fatal("complete OLD mismatch changed aggregate")
			}
			r, err = s.PersistIntentV1(context.Background(), 17, replacement(), nil)
			require(t, err)
			if r != (ResultV1{2, 18, false}) {
				t.Fatal("requalified exact OLD was refused")
			}
		})
	}
}


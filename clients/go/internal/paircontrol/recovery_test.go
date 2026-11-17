package paircontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

func policyChange(t *testing.T, p *policycontrol.Store, owner policycontrol.Owner, edit func(*policycontrol.Tx) error) {
	t.Helper()
	tx, err := p.Begin()
	require(t, err)
	if owner.Epoch == 0 {
		tx.Ownerless()
	} else {
		tx.RetainOwner(owner)
	}
	tx.Operation(policycontrol.ClassControl, 1)
	require(t, edit(tx))
	r, err := tx.Commit()
	require(t, err)
	if r.Truth != 2 {
		t.Fatal("actual P transaction was not NEW")
	}
}

func h1Policy(t *testing.T) (*policycontrol.Store, IntentV1) {
	t.Helper()
	return h1PolicyAt(t, directory(t))
}

func h1PolicyAt(t *testing.T, dir string) (*policycontrol.Store, IntentV1) {
	t.Helper()
	id, i := identity(), h1Value()
	p, err := policycontrol.Create(dir, id.Identity, policycontrol.NewInstallationProof{Identity: id.Identity})
	require(t, err)
	t.Cleanup(func() { require(t, p.Close()) })
	policyChange(t, p, policycontrol.Owner{}, func(tx *policycontrol.Tx) error {
		_, err := tx.ObserveIncident(i.H1Binding.Diagnosis)
		return err
	})
	tx, err := p.Begin()
	require(t, err)
	tx.AdmitOwner(policycontrol.OwnerH1, i.ID[:])
	tx.Operation(policycontrol.ClassControl, 1)
	require(t, tx.ConsumeIntent(i.H1Binding.Admission))
	r, err := tx.Commit()
	require(t, err)
	seq, known := r.Sequence()
	if r.Truth != 2 || !known || seq != 2 {
		t.Fatal("actual original H1 admission epoch is not2")
	}
	v, err := p.View()
	require(t, err)
	if v.Sequence != 2 || !v.HasAttempt || v.Incident == nil || !v.Incident.Attempted || v.Incident.State != 2 {
		t.Fatal("actual P INTENT qualification differs")
	}
	i.H1Binding.ObservedPSequence = v.Sequence
	return p, i
}

func originalOwner(i IntentV1) policycontrol.Owner {
	return policycontrol.Owner{Kind: policycontrol.OwnerH1, Epoch: i.H1Binding.OwnerEpoch, Intent: append([]byte(nil), i.ID[:]...)}
}

func TestH1AdmissionAndDetachedBinding(t *testing.T) {
	p, i := h1Policy(t)
	v := selected()
	s, _ := existing(t, v)
	r, err := s.PersistIntentV1(context.Background(), 17, i, p)
	require(t, err)
	if r != (ResultV1{2, 18, false}) {
		t.Fatal("H1 actual admission did not write NEW")
	}
	v.Sequence, v.Intent = 18, &i
	want := fixtureBytes(v)
	i.H1Binding.Diagnosis.Error[0] ^= 1
	i.H1Binding.Diagnosis.Source[0] ^= 1
	i.H1Binding.Diagnosis.Trigger[0] ^= 1
	i.H1Binding.Admission.Old[0] ^= 1
	i.H1Binding.Admission.Destination[0] ^= 1
	i.H1Binding.Admission.Ownership[0] ^= 1
	i.SourceRef.Opaque[0] ^= 1
	got, err := s.ObserveV1()
	require(t, err)
	if !bytes.Equal(fixtureBytes(got), want) {
		t.Fatal("stored nested input backing aliases the original caller")
	}
	got.Intent.H1Binding.Admission.Ownership[0] ^= 1
	got.Intent.H1Binding.Diagnosis.Error[0] ^= 1
	again, err := s.ObserveV1()
	require(t, err)
	if !bytes.Equal(fixtureBytes(again), want) {
		t.Fatal("returned nested P binding aliases the owner")
	}
	policyChange(t, p, originalOwner(i), func(tx *policycontrol.Tx) error { return tx.AutoBlock() })
	r, err = s.EndH1V1(context.Background(), 18, i.ID, p)
	require(t, err)
	if r != (ResultV1{2, 19, false}) {
		t.Fatal("mutated caller/returned backing changed next historical-owner operation")
	}
}

func TestH1RefusesUnqualifiedCurrentP(t *testing.T) {
	for _, kind := range []string{"held_tx", "closed", "identity", "ownership", "diagnosis_height", "diagnosis_hash", "diagnosis_error", "diagnosis_source", "diagnosis_trigger", "old_location", "old_id", "destination", "destination_id", "observed_sequence", "extra_operator_p"} {
		t.Run(kind, func(t *testing.T) {
			p, i := h1Policy(t)
			s, dir := existing(t, selected())
			before := diskBytes(t, dir)
			var target error
			switch kind {
			case "held_tx":
				tx, err := p.Begin()
				require(t, err)
				defer func() {
					_, err := tx.Abort()
					require(t, err)
				}()
				target = policycontrol.ErrBusy
			case "closed":
				require(t, p.Close())
				target = policycontrol.ErrClosed
			case "identity":
				v := selected()
				v.Identity.ChainID[1] = 1
				s, dir = existing(t, v)
				before = diskBytes(t, dir)
			case "ownership":
				i.H1Binding.OwnerEpoch = 1
				i.H1Binding.Admission.Ownership[7] = 1
			case "diagnosis_height":
				i.H1Binding.Diagnosis.Height++
			case "diagnosis_hash":
				i.H1Binding.Diagnosis.Hash[1] = 1
			case "diagnosis_error":
				i.H1Binding.Diagnosis.Error[0] ^= 1
			case "diagnosis_source":
				i.H1Binding.Diagnosis.Source[0] ^= 1
			case "diagnosis_trigger":
				i.H1Binding.Diagnosis.Trigger[0] ^= 1
			case "destination":
				i.Destination.Location = "D18"
				i.H1Binding.Admission.Destination = leafBytes(i.Destination)
			case "destination_id":
				i.Destination.DatabaseID[1] = 1
				i.H1Binding.Admission.Destination = leafBytes(i.Destination)
			case "old_location", "old_id":
				v := selected()
				if kind == "old_location" {
					i.Old.Database.Location = "/another-old"
				} else {
					i.Old.Database.DatabaseID[1] = 1
				}
				i.H1Binding.Admission.Old = leafBytes(i.Old.Database)
				v.Selected = i.Old
				s, dir = existing(t, v)
				before = diskBytes(t, dir)
			case "observed_sequence":
				i.H1Binding.ObservedPSequence = 3
			case "extra_operator_p":
				i = replacement()
			}
			r, err := s.PersistIntentV1(context.Background(), 17, i, p)
			var e *ErrorV1
			if !errors.As(err, &e) || e.Operation != "persist_intent" || e.Code != "refused" {
				t.Fatalf("H1 current-P refusal tuple: %+v %v", r, err)
			}
			want := ResultV1{1, 17, false}
			if kind == "extra_operator_p" {
				want = ResultV1{}
			}
			if r != want || target != nil && !errors.Is(e.Cause, target) || !bytes.Equal(before, diskBytes(t, dir)) {
				t.Fatal("P refusal changed outer truth/cause/preimage")
			}
		})
	}
}

func terminalPolicy(t *testing.T, p *policycontrol.Store, i IntentV1, kind string) {
	t.Helper()
	if kind == "live" || kind == "rollback" {
		return
	}
	if kind == "live_advanced" {
		p.RequestLatch()
		g := &policycontrol.Guard{}
		_, err := p.PersistLatch(policycontrol.LatchProof{PredicateTrue: true, Basis: g.Qualify()})
		require(t, err)
		return
	}
	policyChange(t, p, originalOwner(i), func(tx *policycontrol.Tx) error {
		if kind == "success" || kind == "observed_later" || kind == "nil_not_later" {
			return tx.RemoveOnSuccess()
		}
		return tx.AutoBlock()
	})
	if kind == "observed_later" {
		d := h1Value().H1Binding.Diagnosis
		d.Hash[1] = 1
		policyChange(t, p, policycontrol.Owner{}, func(tx *policycontrol.Tx) error {
			_, err := tx.ObserveIncident(d)
			return err
		})
	}
	if !strings.HasPrefix(kind, "manual_") {
		return
	}
	a := h1Value().H1Binding.Admission
	d := replacement().Destination
	d.DatabaseID[1], d.Location = 1, "D18"
	a.Destination = leafBytes(d)
	newID := [32]byte{0x45}
	if kind == "manual_same_id" {
		newID = i.ID
	}
	a.Ownership = append([]byte{0, 0, 0, 0, 0, 0, 0, 4}, newID[:]...)
	switch kind {
	case "manual_same_epoch":
		a.Ownership[7] = 2
	case "manual_short_owner":
		a.Ownership = a.Ownership[:39]
	case "manual_future_epoch":
		a.Ownership[7] = 5
	case "manual_bad_old":
		a.Old = []byte{1}
	case "manual_bad_destination":
		a.Destination = []byte{2}
	case "manual_absolute_destination":
		d.Form, d.Location = 1, "/db/D18"
		a.Destination = leafBytes(d)
	}
	tx, err := p.Begin()
	require(t, err)
	tx.AdmitOwner(policycontrol.OwnerH1, newID[:])
	tx.Operation(policycontrol.ClassControl, 1)
	require(t, tx.ConsumeIntent(a))
	pr, err := tx.Commit()
	require(t, err)
	if pr.Truth != 2 {
		t.Fatal("new manual owner was not admitted")
	}
	view, err := p.View()
	require(t, err)
	if view.Sequence != 4 || view.Receipt.Owner.Kind != policycontrol.OwnerH1 || view.Receipt.Owner.Epoch != 4 || !bytes.Equal(view.Receipt.Owner.Intent, newID[:]) {
		t.Fatal("actual new owner/epoch differs from the independently supplied manual witness")
	}
	if kind == "manual_same_d" {
		owner := policycontrol.Owner{Kind: policycontrol.OwnerH1, Epoch: 4, Intent: newID[:]}
		policyChange(t, p, owner, func(tx *policycontrol.Tx) error { return tx.RemoveOnSuccess() })
		diagnosis := i.H1Binding.Diagnosis
		diagnosis.Hash[1] = 2
		policyChange(t, p, policycontrol.Owner{}, func(tx *policycontrol.Tx) error {
			_, err := tx.ObserveIncident(diagnosis)
			return err
		})
		tx, err := p.Begin()
		require(t, err)
		newID = [32]byte{0x46}
		a = h1Value().H1Binding.Admission
		a.Ownership = append([]byte{0, 0, 0, 0, 0, 0, 0, 7}, newID[:]...)
		tx.AdmitOwner(policycontrol.OwnerH1, newID[:])
		tx.Operation(policycontrol.ClassControl, 1)
		require(t, tx.ConsumeIntent(a))
		pr, err := tx.Commit()
		require(t, err)
		if seq, known := pr.Sequence(); pr.Truth != 2 || !known || seq != 7 {
			t.Fatal("new incident did not lawfully admit original D under fresh owner7")
		}
		view, err := p.View()
		require(t, err)
		if view.Receipt.Owner.Kind != policycontrol.OwnerH1 || view.Receipt.Owner.Epoch != 7 || !bytes.Equal(view.Receipt.Owner.Intent, newID[:]) {
			t.Fatal("new incident owner is not the actual independently supplied owner7")
		}
	}
	if kind == "manual_blocked" {
		owner := policycontrol.Owner{Kind: policycontrol.OwnerH1, Epoch: 4, Intent: newID[:]}
		policyChange(t, p, owner, func(tx *policycontrol.Tx) error { return tx.AutoBlock() })
	}
}

func TestTerminalH1Bookkeeping(t *testing.T) {
	for _, kind := range []string{"live", "live_advanced", "blocked", "success", "observed_later", "manual_later", "manual_blocked", "manual_same_epoch", "manual_same_id", "manual_same_d", "manual_short_owner", "manual_future_epoch", "manual_bad_old", "manual_bad_destination", "manual_absolute_destination", "blocked_changed_diagnosis", "rollback", "nil_not_later", "stale_outer", "precommit", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			p, i := h1Policy(t)
			v := selected()
			s, dir := existing(t, v)
			r, err := s.PersistIntentV1(context.Background(), 17, i, p)
			require(t, err)
			if r != (ResultV1{2, 18, false}) {
				t.Fatal("H1 setup intent not NEW")
			}
			r, err = s.RetireV1(context.Background(), 18, i.ID, reference(), p)
			require(t, err)
			if r != (ResultV1{2, 19, false}) {
				t.Fatal("H1 no-selection retirement not NEW")
			}
			v.Sequence, v.Selector, v.Selected, v.Intent = 19, 3, nil, &i
			v.Retired = &RetirementV1{originalPair(), 2, reference()}
			terminalPolicy(t, p, i, kind)
			if kind == "rollback" || kind == "nil_not_later" || kind == "blocked_changed_diagnosis" {
				require(t, s.CloseV1())
				if kind == "blocked_changed_diagnosis" {
					v.Intent.H1Binding.Diagnosis.Error[0] ^= 1
				} else {
					v.Intent.H1Binding.ObservedPSequence = 3
				}
				writeFixture(t, dir, fixtureBytes(v))
				s, err = OpenV1(dir, identity())
				require(t, err)
			}
			beforeP, err := p.View()
			require(t, err)
			before := diskBytes(t, dir)
			o := installFaults(t, s)
			expected := uint64(19)
			if kind == "stale_outer" {
				expected = 18
			}
			if kind == "precommit" {
				installFaults(t, s, faultAt{"write:outer-control.scratch", 1, errors.New("write"), false})
			}
			if kind == "unknown" {
				installFaults(t, s, faultAt{"sync:dir", 2, errors.New("dirsync"), false})
			}
			r, err = s.EndH1V1(context.Background(), expected, i.ID, p)
			switch kind {
			case "live", "live_advanced":
				wantLocal(t, r, err, "end_h1", "refused", ResultV1{1, 19, false})
			case "rollback", "nil_not_later", "blocked_changed_diagnosis", "manual_same_epoch", "manual_same_id", "manual_same_d", "manual_short_owner", "manual_future_epoch", "manual_bad_old", "manual_bad_destination", "manual_absolute_destination":
				wantLocal(t, r, err, "end_h1", "integrity", ResultV1{1, 19, false})
				if len(o.events) != 0 {
					t.Fatal("terminal qualification rejection acquired outer OS effects")
				}
			case "stale_outer":
				wantLocal(t, r, err, "end_h1", "stale", ResultV1{1, 19, false})
			case "precommit":
				wantLocal(t, r, err, "end_h1", "precommit", ResultV1{1, 19, false})
			case "unknown":
				wantLocal(t, r, err, "end_h1", "unresolved", ResultV1{3, 0, true})
			default:
				require(t, err)
				if r != (ResultV1{2, 20, false}) {
					t.Fatal("terminal bookkeeping result")
				}
				v.Sequence, v.Intent = 20, nil
			}
			afterP, err := p.View()
			require(t, err)
			if !reflect.DeepEqual(beforeP, afterP) {
				t.Fatal("EndH1 overwrote current P/new owner")
			}
			if kind != "unknown" {
				if r.Truth == 1 && !bytes.Equal(before, diskBytes(t, dir)) {
					t.Fatal("OLD changed complete bookkeeping")
				}
				wantRecord(t, s, v)
			}
			require(t, s.CloseV1())
			s, err = OpenV1(dir, identity())
			if kind == "unknown" {
				wantNilStore(t, s, err, "open", "unresolved")
				return
			}
			require(t, err)
			wantRecord(t, s, v)
			if _, err := os.Stat(filepath.Join(dir, "D17")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("historical D recreated")
			}
			require(t, s.CloseV1())
		})
	}
}

func TestLostAcknowledgementRecovery(t *testing.T) {
	for _, kind := range []string{"new", "old", "neither", "neither_identity", "neither_selected", "neither_source", "neither_comparand", "neither_destination", "malformed", "missing", "unreadable", "close_error"} {
		t.Run(kind, func(t *testing.T) {
			s, dir := existing(t, selected())
			old := diskBytes(t, dir)
			ack := errors.New("acknowledgement lost")
			recorder := installFaults(t, s, faultAt{"ack", 1, ack, false})
			r, err := s.PersistIntentV1(context.Background(), 17, replacement(), nil)
			original := wantLocal(t, r, err, "persist_intent", "unresolved", ResultV1{3, 0, true})
			if !errors.Is(original, ack) {
				t.Fatal("ack cause lost")
			}
			// These deliberate readback perturbations exercise classification;
			// they do not posit a lawful second writer under the live flock.
			switch kind {
			case "old":
				writeFixture(t, dir, old)
			case "neither":
				v := selected()
				v.Sequence = 99
				writeFixture(t, dir, fixtureBytes(v))
			case "neither_identity", "neither_selected", "neither_source", "neither_comparand", "neither_destination":
				v, i := selected(), replacement()
				v.Sequence, v.Intent = 18, &i
				switch kind {
				case "neither_identity":
					v.Identity.ChainID[1] = 1
				case "neither_selected":
					v.Selected.AuthoritySequence++
					i.Old.AuthoritySequence++
				case "neither_source":
					i.SourceRef.Opaque[0] ^= 1
				case "neither_comparand":
					i.ComparandRef.OwnerID[1] = 1
				case "neither_destination":
					i.Destination.DatabaseID[1] = 1
				}
				writeFixture(t, dir, fixtureBytes(v))
			case "malformed":
				writeFixture(t, dir, []byte{1})
			case "missing":
				require(t, os.Remove(filepath.Join(dir, "outer-control")))
			case "unreadable":
				recorder.add(faultAt{"open:outer-control", 1, os.ErrPermission, false})
			case "close_error":
				recorder.add(faultAt{"close:outer-control", 1, errors.New("read-close"), false})
			}
			recorder.resetCounts()
			r, err = s.RecoverV1()
			truth, seq, code := TruthV1(3), uint64(0), "unresolved"
			switch kind {
			case "new":
				truth, seq, code = 2, 18, "postcommit_new"
			case "old":
				truth, seq, code = 1, 17, "postcommit_old"
			case "malformed":
				code = "integrity"
			case "missing":
				code = "missing"
			case "unreadable", "close_error":
				code = "unreadable"
			}
			e := wantLocal(t, r, err, "recover", code, ResultV1{truth, seq, true})
			if !errors.Is(e, ack) {
				t.Fatal("Recover dropped original acknowledgement")
			}
			if recorder.count("open:outer-control") != 1 {
				t.Fatal("Recover did not take exactly one image")
			}
			for _, event := range recorder.events {
				if event == "rename" || event == "link" || event == "remove:outer-control.pending" {
					t.Fatal("Recover repaired durable state")
				}
			}
			n := len(recorder.events)
			r2, e2 := s.RecoverV1()
			wantLocal(t, r2, e2, "recover", "unresolved", r)
			if len(recorder.events) != n {
				t.Fatal("terminal/poisoned Recover performed more I/O")
			}
			r2, e2 = s.RecordDamageV1(context.Background(), seq, originalPair(), reference())
			wantLocal(t, r2, e2, "damage", "unresolved", r)
			if len(recorder.events) != n {
				t.Fatal("blocked mutator performed effects")
			}
			require(t, s.CloseV1())
		})
	}
}

type outerNilError struct{}

func (*outerNilError) Error() string { return "typed nil filesystem cause" }

func TestEnteredPCallbackRetainsOuterDisposition(t *testing.T) {
	var typedNil *outerNilError
	for _, cause := range []error{policycontrol.ErrBusy, fmt.Errorf("filesystem: %w", policycontrol.ErrUnresolved), typedNil} {
		for _, event := range []string{"sync:outer-control.scratch", "remove:outer-control.pending", "ack"} {
			t.Run(event+fmt.Sprintf("/%T", cause), func(t *testing.T) {
				p, i := h1Policy(t)
				s, _ := existing(t, selected())
				o := installFaults(t, s, faultAt{event, 1, cause, false})
				r, err := s.PersistIntentV1(context.Background(), 17, i, p)
				want, code := ResultV1{1, 17, false}, "precommit"
				if event == "remove:outer-control.pending" {
					want, code = ResultV1{2, 18, true}, "postcommit_new"
				}
				if event == "ack" {
					want, code = ResultV1{3, 0, true}, "unresolved"
				}
				e := wantLocal(t, r, err, "persist_intent", code, want)
				wantCauses(t, e, cause)
				wantConsumed(t, o)
				if o.count("open:outer-control.pending") != 1 {
					t.Fatal("actual callback was not entered")
				}
				tx, err := p.Begin()
				require(t, err)
				_, err = tx.Abort()
				require(t, err)
			})
		}
	}
}

func TestRegularBoundedReadAndGrowth(t *testing.T) {
	for _, kind := range []string{"fifo", "zero", "growth", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			dir := directory(t)
			path := filepath.Join(dir, "outer-control")
			holder := &Store{dir: dir}
			o := installFaults(t, holder)
			if kind == "fifo" {
				require(t, syscall.Mkfifo(path, 0o600))
			} else {
				b := fixtureBytes(selected())
				if kind == "zero" {
					b = nil
				}
				writeFixture(t, dir, b)
			}
			if kind == "growth" || kind == "truncated" {
				original := holder.ops.sync
				holder.ops.sync = func(f *os.File) error {
					err := original(f)
					if err == nil && f.Name() == path {
						b := fixtureBytes(selected())
						if kind == "growth" {
							b = append(b, 0)
						} else {
							b = b[:len(b)-1]
						}
						writeFixture(t, dir, b)
					}
					return err
				}
			}
			s, err := startV1(dir, identity(), nil, holder.ops)
			code := "integrity"
			if kind == "truncated" || kind == "fifo" {
				code = "unreadable"
			}
			wantNilStore(t, s, err, "open", code)
			wantConsumed(t, o)
			if o.releases != 1 || o.count("ack") != 0 {
				t.Fatal("failed read retained owner or acknowledged transition")
			}
		})
	}
}

func TestOriginalObservationSurvivesUnrelatedPAdvances(t *testing.T) {
	p, i := h1Policy(t)
	advance := func(key string) {
		policyChange(t, p, policycontrol.Owner{}, func(tx *policycontrol.Tx) error {
			return tx.PutRow(policycontrol.KindAudit, []byte(key), []byte("unrelated"))
		})
	}
	advance("before")
	view, err := p.View()
	require(t, err)
	if view.Sequence != 3 || view.ControlSequence != 2 || view.Receipt.Owner.Kind != 1 || view.Receipt.Owner.Epoch != 3 {
		t.Fatal("fixture did not produce distinct actual admission and current receipt owners")
	}
	i.H1Binding.ObservedPSequence = view.Sequence
	s, dir := existing(t, selected())
	r, err := s.PersistIntentV1(context.Background(), 17, i, p)
	require(t, err)
	if r != (ResultV1{2, 18, false}) {
		t.Fatal("valid epoch below original protected observation was refused")
	}
	advance("after")
	r, err = s.RetireV1(context.Background(), 18, i.ID, reference(), p)
	require(t, err)
	if r != (ResultV1{2, 19, false}) {
		t.Fatal("unrelated latest owner displaced original admission")
	}
	v := selected()
	v.Sequence, v.Selector, v.Selected, v.Intent = 19, 3, nil, &i
	v.Retired = &RetirementV1{originalPair(), 2, reference()}
	wantRecord(t, s, v)
	require(t, s.CloseV1())
	s, err = OpenV1(dir, identity())
	require(t, err)
	wantRecord(t, s, v)
	policyChange(t, p, originalOwner(i), func(tx *policycontrol.Tx) error { return tx.AutoBlock() })
	r, err = s.EndH1V1(context.Background(), 19, i.ID, p)
	require(t, err)
	v.Sequence, v.Intent = 20, nil
	wantRecord(t, s, v)
	require(t, s.CloseV1())
}

func TestNewOuterH1OwnerRejectsHistoricalEnd(t *testing.T) {
	p, i := h1Policy(t)
	s, _ := existing(t, selected())
	_, err := s.PersistIntentV1(context.Background(), 17, i, p)
	require(t, err)
	terminalPolicy(t, p, i, "manual_later")
	_, err = s.EndH1V1(context.Background(), 18, i.ID, p)
	require(t, err)
	newIntent := h1Value()
	newIntent.ID = [32]byte{0x45}
	newIntent.Destination.Location, newIntent.Destination.DatabaseID[1] = "D18", 1
	h := newIntent.H1Binding
	h.OwnerEpoch, h.ObservedPSequence, h.OwnerIntent = 4, 4, newIntent.ID
	h.Admission.Destination = leafBytes(newIntent.Destination)
	h.Admission.Ownership = append([]byte{0, 0, 0, 0, 0, 0, 0, 4}, newIntent.ID[:]...)
	r, err := s.PersistIntentV1(context.Background(), 19, newIntent, p)
	require(t, err)
	if r != (ResultV1{2, 20, false}) {
		t.Fatal("separately admitted new outer owner was not persisted")
	}
	v := selected()
	v.Sequence, v.Intent = 20, &newIntent
	for _, expected := range []uint64{18, 20} {
		before := diskBytes(t, s.dir)
		r, err := s.EndH1V1(context.Background(), expected, i.ID, p)
		wantLocal(t, r, err, "end_h1", "stale", ResultV1{1, 20, false})
		if !bytes.Equal(before, diskBytes(t, s.dir)) {
			t.Fatal("historical cleanup overwrote newer outer owner")
		}
		wantRecord(t, s, v)
	}
}

func TestRecoveryRetainsActualPhysicalWriter(t *testing.T) {
	s, dir := existing(t, selected())
	o := installFaults(t, s, faultAt{"ack", 1, errors.New("ack"), false})
	r, err := s.PersistIntentV1(context.Background(), 17, replacement(), nil)
	wantLocal(t, r, err, "persist_intent", "unresolved", ResultV1{3, 0, true})
	o.block, o.entered, o.resume = "open:outer-control", make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	var recovered ResultV1
	var recoveryError error
	go func() {
		defer close(done)
		recovered, recoveryError = s.RecoverV1()
	}()
	defer func() {
		close(o.resume)
		await(t, done)
		wantLocal(t, recovered, recoveryError, "recover", "postcommit_new", ResultV1{2, 18, true})
	}()
	await(t, o.entered)
	fresh, err := OpenV1(dir, identity())
	if fresh != nil {
		require(t, fresh.CloseV1())
		t.Fatal("recovery released actual inode writer before protected read")
	}
	wantNilStore(t, fresh, err, "open", "busy")
}


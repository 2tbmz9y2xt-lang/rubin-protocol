package node

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// Logical-step scalar evidence only: these fixtures do not prove canonical
// retained bytes, signed admission, fee provenance, or live completion.
func capacitySet(id byte, size, payload, fee, sequence uint64) daCompleteCapacitySet {
	return daCompleteCapacitySet{[32]byte{id}, consensus.Uint128{Lo: fee}, size, payload, sequence}
}

func capacityInput(residents ...daCompleteCapacitySet) daCompleteCapacityInput {
	in := daCompleteCapacityInput{byteCap: 536870912, candidate: capacitySet(255, 1, 0, 1000000000, 0), residents: residents}
	for _, r := range residents {
		in.completeBytes += r.totalBytes
		in.completePayload += r.payloadBytes
		in.completeCount++
	}
	return in
}

func capacityRun(t *testing.T, in daCompleteCapacityInput) (daCompleteCapacityPlan, error) {
	t.Helper()
	before := in
	if in.residents != nil {
		before.residents = append([]daCompleteCapacitySet{}, in.residents...)
	}
	plan, err := planDACompleteCapacity(in)
	if !reflect.DeepEqual(in, before) {
		t.Fatal("input changed")
	}
	return plan, err
}

func capacityWant(t *testing.T, in daCompleteCapacityInput, ids [][32]byte, shared, count, payload uint64, message string) {
	t.Helper()
	got, err := capacityRun(t, in)
	want := daCompleteCapacityPlan{true, ids, shared, count, payload}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: got=%+v err=%v want=%+v", message, got, err, want)
	}
}

func TestDACompleteCapacityPlanStagedCredit(t *testing.T) {
	for _, credit := range []uint64{0, 7, 20} {
		in := capacityInput(capacitySet(1, 30, 3, 0, 1))
		in.stagedBytes, in.priorCredit = 20, credit
		in.candidate = capacitySet(255, 11, 2, 100, 0)
		want := map[uint64]uint64{0: 61, 7: 54, 20: 41}[credit]
		capacityWant(t, in, nil, want, 2, 5, "shared byte projection")
	}
	in := capacityInput(capacitySet(1, 30, 3, 0, 1), capacitySet(2, 50, 5, 0, 2))
	in.stagedBytes, in.priorCredit = 536870800, 7
	in.candidate = capacitySet(255, 60, 6, 100, 0)
	capacityWant(t, in, [][32]byte{{1}}, 536870903, 2, 11, "shared byte projection")
}

func capacityCountInput(count int) daCompleteCapacityInput {
	residents := make([]daCompleteCapacitySet, count)
	for i := range residents {
		residents[i] = capacitySet(0, 1, 0, 0, uint64(i+1))
		binary.BigEndian.PutUint64(residents[i].id[24:], uint64(i+1))
	}
	return capacityInput(residents...)
}

func TestDACompleteCapacityPlanThreeBounds(t *testing.T) {
	t.Run("pressure", func(t *testing.T) {
		in := capacityCountInput(65536)
		var first [32]byte
		first[31] = 1
		capacityWant(t, in, [][32]byte{first}, 65536, 65536, 0, "all three bounds")
		in = capacityInput(capacitySet(1, 96000000, 96000000, 0, 1))
		in.candidate = capacitySet(255, 10, 1, 100, 0)
		capacityWant(t, in, [][32]byte{{1}}, 10, 1, 1, "all three bounds")
		in = capacityInput(capacitySet(1, 100, 0, 0, 1), capacitySet(2, 96000000, 96000000, 0, 2))
		in.stagedBytes = 440870812
		in.candidate = capacitySet(255, 50, 1, 100, 0)
		capacityWant(t, in, [][32]byte{{1}, {2}}, 440870862, 1, 1, "all three bounds")
	})
	t.Run("inclusive", func(t *testing.T) {
		var in daCompleteCapacityInput
		for _, cap := range []uint64{536870912, 4294967295} {
			in = capacityInput()
			in.byteCap, in.candidate.totalBytes = cap, cap
			capacityWant(t, in, nil, cap, 1, 0, "inclusive capacity boundary")
			in = capacityInput(capacitySet(1, 1, 0, 0, 1))
			in.byteCap, in.stagedBytes = cap, cap-1
			capacityWant(t, in, [][32]byte{{1}}, cap, 1, 0, "inclusive capacity boundary")
		}
		in = capacityCountInput(65535)
		capacityWant(t, in, nil, 65536, 65536, 0, "inclusive capacity boundary")
		in = capacityInput(capacitySet(1, 95999999, 95999999, 0, 1))
		in.candidate.payloadBytes = 1
		capacityWant(t, in, nil, 96000000, 2, 96000000, "inclusive capacity boundary")
	})
}

func TestDACompleteCapacityPlanCandidateEquality(t *testing.T) {
	for _, sequence := range []uint64{0, 1, ^uint64(0)} {
		for _, id := range []byte{0, 255} {
			in := capacityInput(capacitySet(1, 2, 0, 2, 2))
			in.stagedBytes = 536870908
			in.candidate = capacitySet(id, 4, 0, 4, sequence)
			got, err := capacityRun(t, in)
			if err != nil || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
				t.Fatalf("equal candidate was accepted: %+v %v", got, err)
			}
		}
	}
	in := capacityInput(capacitySet(1, 1, 0, 0, 1))
	in.stagedBytes, in.candidate.fee = 536870911, consensus.Uint128{}
	got, err := capacityRun(t, in)
	if err != nil || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
		t.Fatal("equal candidate was accepted")
	}
	in.stagedBytes = 0
	capacityWant(t, in, nil, 2, 2, 0, "zero fee no pressure")
}

func TestDACompleteCapacityPlanWideProducts(t *testing.T) {
	a, b := capacitySet(1, 100000000, 0, 0, 2), capacitySet(2, 100000000, 0, 1, 1)
	a.fee = consensus.Uint128{Hi: 1 << 63}
	b.fee = consensus.Uint128{Hi: (1 << 63) - 1, Lo: ^uint64(0)}
	for _, residents := range [][]daCompleteCapacitySet{{a, b}, {b, a}} {
		in := capacityInput(residents...)
		in.stagedBytes = 300000000
		in.candidate = capacitySet(255, 100000000, 0, 0, 0)
		in.candidate.fee = consensus.Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}
		capacityWant(t, in, [][32]byte{{2}}, 500000000, 2, 0, "wide ratio victim order")
	}
	in := capacityInput(a)
	in.stagedBytes = 400000000
	in.candidate = capacitySet(255, 100000000, 0, 1, 0)
	got, err := capacityRun(t, in)
	if err != nil || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
		t.Fatalf("wide ratio victim order: %+v %v", got, err)
	}
}

func TestDACompleteCapacityPlanResidentOrder(t *testing.T) {
	a, b, c := capacitySet(1, 2, 0, 2, 2), capacitySet(1, 2, 0, 2, 2), capacitySet(2, 2, 0, 2, 1)
	a.id[31], b.id[31] = 255, 1
	for _, residents := range [][]daCompleteCapacitySet{{a, b, c}, {c, b, a}, {b, a, c}} {
		in := capacityInput(residents...)
		in.stagedBytes, in.candidate.totalBytes = 536870906, 6
		capacityWant(t, in, [][32]byte{c.id, b.id, a.id}, 536870912, 1, 0, "resident total order")
	}
}

func TestDACompleteCapacityPlanVictimPrefix(t *testing.T) {
	in := capacityCountInput(130)
	in.stagedBytes, in.candidate.totalBytes = 536870782, 129
	want := make([][32]byte, 129)
	for i := range want {
		binary.BigEndian.PutUint64(want[i][24:], uint64(i+1))
	}
	capacityWant(t, in, want, 536870912, 2, 0, "complete minimal victim prefix")
	in = capacityInput(capacitySet(1, 10, 0, 0, 1), capacitySet(2, 10, 0, 0, 2))
	in.stagedBytes, in.candidate.totalBytes = 536870892, 5
	capacityWant(t, in, [][32]byte{{1}}, 536870907, 2, 0, "complete minimal victim prefix")
}

func TestDACompleteCapacityPlanRefusalPurity(t *testing.T) {
	for _, fee := range []uint64{0, 1, 100} {
		in := capacityInput(capacitySet(1, 10, 0, 0, 1), capacitySet(2, 10, 0, fee, 2))
		in.stagedBytes = 536870892
		in.candidate = capacitySet(255, 21, 0, 1, 0)
		for range 2 {
			got, err := capacityRun(t, in)
			if err != nil || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
				t.Fatalf("refusal carries victims: %+v %v", got, err)
			}
		}
	}
	in := capacityInput()
	in.stagedBytes = 536870912
	got, err := capacityRun(t, in)
	if err != nil || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
		t.Fatal("refusal carries victims")
	}
}

func TestDACompleteCapacityPlanIndividualBound(t *testing.T) {
	for _, size := range []uint64{536870913, ^uint64(0)} {
		in := capacityInput()
		in.stagedBytes, in.candidate.totalBytes = 1, size
		got, err := capacityRun(t, in)
		if err != nil || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
			t.Fatalf("individual byte bound before projection: %+v %v", got, err)
		}
	}
}

func TestDACompleteCapacityPlanInputOwnership(t *testing.T) {
	in := capacityInput(capacitySet(2, 10, 0, 0, 2), capacitySet(1, 10, 0, 0, 1))
	in.stagedBytes = 536870892
	got, err := capacityRun(t, in)
	if err != nil || !got.accepted || len(got.victims) != 1 {
		t.Fatalf("ownership setup: %+v %v", got, err)
	}
	got.victims[0][0] = 77
	capacityWant(t, in, [][32]byte{{1}}, 536870903, 2, 0, "input changed")
}

func TestDACompleteCapacityPlanInvalidSnapshot(t *testing.T) {
	for _, row := range []struct {
		name   string
		shape  bool
		change func(*daCompleteCapacityInput)
	}{
		{"cap below", false, func(in *daCompleteCapacityInput) { in.byteCap = 536870911 }},
		{"cap above", false, func(in *daCompleteCapacityInput) { in.byteCap = 4294967296 }},
		{"candidate zero bytes", false, func(in *daCompleteCapacityInput) { in.candidate.totalBytes = 0 }},
		{"candidate payload", true, func(in *daCompleteCapacityInput) { in.candidate.payloadBytes = 2 }},
		{"resident zero bytes", false, func(in *daCompleteCapacityInput) {
			in.residents[0].totalBytes, in.residents[0].payloadBytes = 0, 0
			in.completeBytes, in.completePayload = 20, 2
		}},
		{"resident payload", true, func(in *daCompleteCapacityInput) {
			in.residents[0].payloadBytes, in.completePayload = 11, 13
		}},
		{"resident sequence", false, func(in *daCompleteCapacityInput) { in.residents[0].receivedSequence = 0 }},
		{"duplicate ID", false, func(in *daCompleteCapacityInput) { in.residents[0].id = in.residents[1].id }},
		{"candidate in residents", false, func(in *daCompleteCapacityInput) { in.candidate.id = in.residents[0].id }},
		{"prior credit", false, func(in *daCompleteCapacityInput) { in.priorCredit = 1 }},
		{"shared bound", true, func(in *daCompleteCapacityInput) { in.stagedBytes = 536870883 }},
		{"count bound", true, func(in *daCompleteCapacityInput) { *in = capacityCountInput(65537) }},
		{"count length", true, func(in *daCompleteCapacityInput) { in.completeCount = 1 }},
		{"payload bound", true, func(in *daCompleteCapacityInput) {
			in.residents[0].totalBytes, in.residents[0].payloadBytes = 96000000, 96000000
			in.completeBytes, in.completePayload = 96000020, 96000002
		}},
		{"byte sum", false, func(in *daCompleteCapacityInput) { in.completeBytes = 31 }},
		{"payload sum", false, func(in *daCompleteCapacityInput) { in.completePayload = 4 }},
		{"empty byte totals", false, func(in *daCompleteCapacityInput) {
			*in = capacityInput()
			in.completeBytes = 1
		}},
		{"empty payload totals", false, func(in *daCompleteCapacityInput) {
			*in = capacityInput()
			in.completePayload = 1
		}},
		{"empty count totals", true, func(in *daCompleteCapacityInput) {
			*in = capacityInput()
			in.completeCount = 1
		}},
		{"shared sum overflow", true, func(in *daCompleteCapacityInput) { in.stagedBytes = ^uint64(0) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			in := capacityInput(capacitySet(1, 10, 1, 0, 1), capacitySet(2, 20, 2, 0, 2))
			row.change(&in)
			got, err := capacityRun(t, in)
			message := "exact scalar integrity refusal"
			if row.shape {
				message = "invalid scalar shape or pre-state repaired"
			}
			if !errors.Is(err, errDARelayImageIncompatible) || reflect.TypeOf(err) != reflect.TypeOf(errDARelayImageIncompatible) || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
				t.Fatalf("%s: %+v %v", message, got, err)
			}
		})
	}
	in := capacityInput(capacitySet(1, 10, 1, 0, 1), capacitySet(2, 20, 2, 0, 2))
	in.candidate.totalBytes = ^uint64(0)
	in.residents[1].receivedSequence = 0
	got, err := capacityRun(t, in)
	if !errors.Is(err, errDARelayImageIncompatible) || reflect.TypeOf(err) != reflect.TypeOf(errDARelayImageIncompatible) || !reflect.DeepEqual(got, daCompleteCapacityPlan{}) {
		t.Fatalf("resident integrity before individual capacity: %+v %v", got, err)
	}
}

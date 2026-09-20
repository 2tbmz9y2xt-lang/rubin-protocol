package node

import (
	"bytes"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// These scalar descriptors require canonical provenance from the future snapshot
// owner. This dormant decision does not validate retained bodies or publish state.
type daCompleteCapacitySet struct {
	id               [32]byte
	fee              consensus.Uint128
	totalBytes       uint64
	payloadBytes     uint64
	receivedSequence uint64
}

type daCompleteCapacityInput struct {
	byteCap         uint64
	stagedBytes     uint64
	priorCredit     uint64
	completeBytes   uint64
	completeCount   uint64
	completePayload uint64
	candidate       daCompleteCapacitySet
	residents       []daCompleteCapacitySet
}

type daCompleteCapacityPlan struct {
	accepted      bool
	victims       [][32]byte
	sharedBytes   uint64
	completeCount uint64
	payloadBytes  uint64
}

func planDACompleteCapacity(in daCompleteCapacityInput) (daCompleteCapacityPlan, error) {
	if err := validateDACompleteCapacity(in); err != nil {
		return daCompleteCapacityPlan{}, err
	}
	if in.candidate.totalBytes > in.byteCap {
		return daCompleteCapacityPlan{}, nil
	}
	plan, err := projectDACompleteCapacity(in)
	if err != nil {
		return daCompleteCapacityPlan{}, err
	}
	if plan.fits(in.byteCap) {
		plan.accepted = true
		return plan, nil
	}
	return selectDACompleteVictims(in, plan)
}

func validateDACompleteCapacity(in daCompleteCapacityInput) error {
	if in.byteCap < 536870912 || in.byteCap > 4294967295 {
		return errDARelayImageIncompatible
	}
	if in.candidate.totalBytes == 0 || in.candidate.payloadBytes > in.candidate.totalBytes {
		return errDARelayImageIncompatible
	}
	if in.priorCredit > in.stagedBytes {
		return errDARelayImageIncompatible
	}
	if err := validateDACompleteTotals(in); err != nil {
		return err
	}
	return validateDACompleteResidents(in)
}

func validateDACompleteTotals(in daCompleteCapacityInput) error {
	if in.completeCount > 65536 || in.completeCount != uint64(len(in.residents)) {
		return errDARelayImageIncompatible
	}
	if in.completePayload > 96000000 {
		return errDARelayImageIncompatible
	}
	shared, err := checkedAddUint64(in.stagedBytes, in.completeBytes)
	if err != nil || shared > in.byteCap {
		return errDARelayImageIncompatible
	}
	return nil
}

func validateDACompleteResidents(in daCompleteCapacityInput) error {
	seen := make(map[[32]byte]bool, len(in.residents))
	for _, resident := range in.residents {
		if err := validateDACompleteResident(resident, in.byteCap); err != nil {
			return err
		}
		if seen[resident.id] || resident.id == in.candidate.id {
			return errDARelayImageIncompatible
		}
		seen[resident.id] = true
	}
	return validateDACompleteSums(in)
}

func validateDACompleteSums(in daCompleteCapacityInput) error {
	var total, payload uint64
	for _, resident := range in.residents {
		var err error
		total, err = checkedAddUint64(total, resident.totalBytes)
		if err != nil {
			return errDARelayImageIncompatible
		}
		payload, err = checkedAddUint64(payload, resident.payloadBytes)
		if err != nil {
			return errDARelayImageIncompatible
		}
	}
	if total != in.completeBytes || payload != in.completePayload {
		return errDARelayImageIncompatible
	}
	return nil
}

func validateDACompleteResident(resident daCompleteCapacitySet, byteCap uint64) error {
	if resident.totalBytes == 0 || resident.totalBytes > byteCap {
		return errDARelayImageIncompatible
	}
	if resident.payloadBytes > resident.totalBytes || resident.receivedSequence == 0 {
		return errDARelayImageIncompatible
	}
	return nil
}

func projectDACompleteCapacity(in daCompleteCapacityInput) (daCompleteCapacityPlan, error) {
	var plan daCompleteCapacityPlan
	var err error
	plan.sharedBytes, err = checkedApplyUint64Delta(in.stagedBytes, in.priorCredit, in.candidate.totalBytes)
	if err != nil {
		return daCompleteCapacityPlan{}, err
	}
	plan.sharedBytes, err = checkedAddUint64(plan.sharedBytes, in.completeBytes)
	if err != nil {
		return daCompleteCapacityPlan{}, err
	}
	plan.completeCount, err = checkedAddUint64(in.completeCount, 1)
	if err != nil {
		return daCompleteCapacityPlan{}, err
	}
	plan.payloadBytes, err = checkedAddUint64(in.completePayload, in.candidate.payloadBytes)
	if err != nil {
		return daCompleteCapacityPlan{}, err
	}
	return plan, nil
}

func (plan daCompleteCapacityPlan) fits(byteCap uint64) bool {
	return plan.sharedBytes <= byteCap && plan.completeCount <= 65536 && plan.payloadBytes <= 96000000
}

func daCompleteResidentLess(a, b daCompleteCapacitySet) bool {
	if cmp := consensus.CompareFeeRate(a.fee, a.totalBytes, b.fee, b.totalBytes); cmp != 0 {
		return cmp < 0
	}
	if a.receivedSequence != b.receivedSequence {
		return a.receivedSequence < b.receivedSequence
	}
	return bytes.Compare(a.id[:], b.id[:]) < 0
}

func selectDACompleteVictims(in daCompleteCapacityInput, plan daCompleteCapacityPlan) (daCompleteCapacityPlan, error) {
	residents := append([]daCompleteCapacitySet(nil), in.residents...)
	sort.Slice(residents, func(i, j int) bool {
		return daCompleteResidentLess(residents[i], residents[j])
	})
	for _, resident := range residents {
		if consensus.CompareFeeRate(in.candidate.fee, in.candidate.totalBytes, resident.fee, resident.totalBytes) <= 0 {
			return daCompleteCapacityPlan{}, nil
		}
		if err := plan.removeResident(resident); err != nil {
			return daCompleteCapacityPlan{}, err
		}
		plan.victims = append(plan.victims, resident.id)
		if plan.fits(in.byteCap) {
			plan.accepted = true
			return plan, nil
		}
	}
	return daCompleteCapacityPlan{}, nil
}

func (plan *daCompleteCapacityPlan) removeResident(resident daCompleteCapacitySet) error {
	var err error
	plan.sharedBytes, err = checkedApplyUint64Delta(plan.sharedBytes, resident.totalBytes, 0)
	if err != nil {
		return err
	}
	plan.completeCount, err = checkedApplyUint64Delta(plan.completeCount, 1, 0)
	if err != nil {
		return err
	}
	plan.payloadBytes, err = checkedApplyUint64Delta(plan.payloadBytes, resident.payloadBytes, 0)
	return err
}

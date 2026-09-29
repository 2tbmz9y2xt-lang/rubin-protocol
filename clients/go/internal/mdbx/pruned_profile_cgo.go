//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"encoding/binary"
	"errors"
)

// PrunedProfileOutcome preserves the Update tuple and exposes only this invocation's
// clean decision or complete, independently owned equality-new authority.
type PrunedProfileOutcome struct {
	Decision  string
	Authority *StorageAuthorityV1
	Truth     CommitTruth
	Stage     UpdateStage
	Err       error
}

// SelectPrunedProfileV1 atomically selects PRUNED at a qualified unchanged tip.
// It is dormant; it neither deletes artifacts nor implements operator dispatch.
func (s *Store) SelectPrunedProfileV1(confirmed bool, expectedTip *AuthorityPointV1, reservations *OperationReservationOwner) PrunedProfileOutcome {
	out := PrunedProfileOutcome{Truth: CommitTruthOld, Stage: UpdateStagePrewrite}
	if s == nil {
		out.Err = adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
		return out
	}
	sentinel := errors.New("pruned profile decision")
	var decision string
	var planned *StorageAuthorityV1
	// Logical envelope: ChainValue104 + suffix120 + key16 + consulted clone16
	// + generation prefix8 + two work40 values80. Control metadata is outside R.
	out.Err = reservations.WithReservation(344, func() error {
		var tip *AuthorityPointV1
		if expectedTip != nil {
			copied := *expectedTip
			tip = &copied
		}
		var err error
		out.Truth, out.Stage, err = s.Update(func(reader *Reader) (Batch, error) {
			value, _, readErr := reader.Get(SchemaV2DBIs()[0], []byte{2})
			if readErr != nil {
				return Batch{}, readErr
			}
			a, decodeErr := DecodeStorageAuthorityV1(value)
			if decodeErr != nil {
				return Batch{}, bootstrapFailure(reader, integrityError(operationGet, "invalid pruned profile authority", decodeErr))
			}
			batch, planErr := prunedProfileBatch(reader, &a, confirmed, tip, &decision, sentinel)
			if planErr == nil {
				planned = &a
			}
			return batch, planErr
		})
		return err
	})
	return prunedProfileOutcome(out, planned, decision, sentinel)
}

func prunedProfileBatch(reader *Reader, a *StorageAuthorityV1, confirmed bool, tip *AuthorityPointV1, decision *string, sentinel error) (Batch, error) {
	switch {
	case a.Lifecycle != StorageLifecycleStableV1:
		*decision = "RECOVERY_REQUIRED"
		return Batch{}, sentinel
	case a.ActiveProfile == StorageProfilePrunedV1:
		*decision = "PROFILE_NOOP"
		return Batch{}, sentinel
	case a.Phase == StoragePhasePruneGCV1:
		*decision = "LOCAL_BUSY"
		return Batch{}, sentinel
	case !confirmed:
		*decision = "PROFILE_CONFIRMATION_REQUIRED"
		return Batch{}, sentinel
	}
	key, err := prunedProfileTip(reader, a.ActiveGenerationID, tip, sentinel)
	if err != nil {
		*decision = "STALE_LOCAL_PLAN"
		return Batch{}, err
	}
	encoded, err := prunedProfileReplacement(reader, a, tip)
	if err != nil {
		return Batch{}, err
	}
	batch := Batch{Mutations: []Mutation{{DBI: SchemaV2DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded}}}
	if key != nil {
		batch.Consulted = []ConsultedRow{{DBI: SchemaV2DBIs()[2], Key: key}}
	}
	return batch, nil
}

func prunedProfileTip(reader *Reader, generation uint64, tip *AuthorityPointV1, stale error) ([]byte, error) {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], generation)
	var key []byte
	// Membership and work are checked before hash comparison and suffix exhaustion.
	qualify := func() error {
		if tip.Height > 0xffffffff {
			return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "invalid pruned profile tip", nil)
		}
		var err error
		key, err = HeightKey(generation, tip.Height)
		if err != nil {
			return err
		}
		value, present, err := reader.Get(SchemaV2DBIs()[2], key)
		if err != nil {
			return err
		}
		if !present {
			return stale
		}
		if !validWork([40]byte(value[64:104])) {
			return bootstrapFailure(reader, integrityError(operationGet, "invalid pruned profile tip work", nil))
		}
		if [32]byte(value[:32]) != tip.BlockHash {
			return stale
		}
		return nil
	}
	if tip != nil {
		if err := qualify(); err != nil {
			return nil, err
		}
	}
	page, err := reader.PrefixPage(SchemaV2DBIs()[2], prefix[:], key, 1, 120)
	if err != nil {
		return nil, err
	}
	if len(page.Rows) != 0 || page.Stop != PrefixPageExhausted {
		return nil, stale
	}
	return key, nil
}

func prunedProfileReplacement(reader *Reader, a *StorageAuthorityV1, tip *AuthorityPointV1) ([]byte, error) {
	height := uint64(0)
	if tip != nil {
		height = tip.Height
	}
	if a.U != laggedPromise(height, 1440) {
		return nil, bootstrapFailure(reader, integrityError(operationGet, "pruned profile promises disagree with tip", nil))
	}
	a.ActiveProfile, a.B = StorageProfilePrunedV1, laggedPromise(height, 15120)
	if a.B > 0 {
		a.Phase = StoragePhasePruneGCV1
		a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: CleanupSpanBlocksV1, GenerationID: a.ActiveGenerationID, FirstHeight: 0, LastHeight: a.B - 1, NextHeight: 0}}}
	}
	if err := ValidateStorageAuthorityV1(*a); err != nil {
		return nil, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid pruned profile replacement", err)
	}
	if _, fits := authoritySize(*a); !fits {
		return nil, updateBoundError()
	}
	encoded, err := a.Encode()
	if err != nil {
		return nil, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid pruned profile replacement", err)
	}
	return encoded, nil
}

func prunedProfileOutcome(out PrunedProfileOutcome, planned *StorageAuthorityV1, decision string, sentinel error) PrunedProfileOutcome {
	if out.Err == sentinel && out.Truth == CommitTruthOld && out.Stage == UpdateStagePrewrite { //nolint:errorlint // Only the complete invocation-local sentinel excludes cleanup errors.
		out.Decision, out.Err = decision, nil
		return out
	}
	if out.Truth == CommitTruthNew && out.Stage == UpdateStageCommitMayHaveCrossed {
		out.Authority = planned
	}
	return out
}

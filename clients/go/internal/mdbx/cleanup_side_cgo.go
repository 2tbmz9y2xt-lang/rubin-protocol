//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"slices"
)

// CleanupSideV1 drains exactly one height of the first committed SIDE span.
// The synchronous full-lane grant covers planning, commit, readback and cleanup.
func (s *Store) CleanupSideV1(reservations *OperationReservationOwner) (CommitTruth, UpdateStage, error) {
	if s == nil {
		return CommitTruthOld, UpdateStagePrewrite, adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	truth, stage := CommitTruthOld, UpdateStagePrewrite
	noWork := errors.New("cleanup SIDE has no selected work")
	err := reservations.WithReservation(MaxOperationDataBytes, func() error {
		var updateErr error
		truth, stage, updateErr = s.Update(func(reader *Reader) (Batch, error) {
			return cleanupSideBatch(reader, noWork)
		})
		return updateErr
	})
	if truth == CommitTruthOld && stage == UpdateStagePrewrite {
		switch err {
		case noWork:
			err = nil
		}
	}
	return truth, stage, err
}

func cleanupSideBatch(reader *Reader, noWork error) (Batch, error) {
	a, err := cleanupSideAuthority(reader)
	if err != nil {
		return Batch{}, err
	}
	if !all(a.Phase == StoragePhasePruneGCV1, a.DetachedSuffix == nil) {
		return Batch{}, noWork
	}
	span := a.Cleanup.Spans[0]
	if span.Kind != CleanupSpanSideV1 {
		return Batch{}, noWork
	}
	link, err := reader.ReadRequiredSideLink(span.GenerationID, span.NextHeight)
	if err != nil {
		return Batch{}, err
	}
	hash := [32]byte(link[:32])
	owner, err := reader.CanonicalOwnerV1(a.ActiveGenerationID, hash)
	if err != nil {
		return Batch{}, err
	}
	required := all(owner.Owned, owner.Height >= a.B)
	keep := required
	consulted := owner.Rows
	if !keep {
		keep, consulted, err = cleanupSideMembership(reader, a.SelectedSide, hash, consulted)
		if err != nil {
			return Batch{}, err
		}
	}
	return cleanupSideFinish(reader, &a, span, hash, required, keep, consulted)
}

func cleanupSideAuthority(reader *Reader) (StorageAuthorityV1, error) {
	a, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return StorageAuthorityV1{}, err
	}
	return a, cleanupSidePromises(reader, a)
}

// Exact committed promises are checked even on a route that has no SIDE work.
func cleanupSidePromises(reader *Reader, a StorageAuthorityV1) error {
	cleanup := a.Cleanup
	if a.Ordinary != nil {
		cleanup = a.Ordinary.CarriedCleanup
	}
	if cleanup == nil {
		return nil
	}
	for _, span := range cleanup.Spans {
		if !cleanupSidePromise(a, span) {
			return cleanupBUEvidence(reader, "invalid storage authority")
		}
	}
	return nil
}

func cleanupSidePromise(a StorageAuthorityV1, span CleanupSpanV1) bool {
	switch span.Kind {
	case CleanupSpanBlocksV1:
		return span.LastHeight+1 == a.B
	case CleanupSpanUndoV1:
		return span.LastHeight+1 == a.U
	default:
		return true
	}
}

// Membership requires all eligible identities, including links after a match.
// Body health is not evidence of optional membership.
func cleanupSideMembership(reader *Reader, selected *SelectedSideV1, hash [32]byte, consulted []ConsultedRow) (bool, []ConsultedRow, error) {
	if selected == nil {
		return false, consulted, nil
	}
	keep := false
	first := selected.TipHeight - uint64(selected.RowCount) + 1
	for height := first; height <= selected.TipHeight; height++ {
		link, err := reader.ReadRequiredSideLink(selected.GenerationID, height)
		if err != nil {
			return false, nil, err
		}
		key, _ := HeightKey(selected.GenerationID, height)
		consulted = append(consulted, ConsultedRow{DBI: SchemaV2DBIs()[6], Key: key})
		keep = anyTrue(keep, bytes.Equal(link[:32], hash[:]))
	}
	return keep, consulted, nil
}

func cleanupSideFinish(reader *Reader, a *StorageAuthorityV1, span CleanupSpanV1, hash [32]byte, required, keep bool, consulted []ConsultedRow) (Batch, error) {
	dbis := SchemaV2DBIs()
	body, err := reader.GetOptionalSide(dbis[4], hash[:])
	if err != nil {
		return Batch{}, err
	}
	if required {
		if !all(body.Present, !body.InvalidWidth) {
			return Batch{}, cleanupBUEvidence(reader, "invalid cleanup owed artifact")
		}
		if sha3.Sum256(body.Value[:116]) != hash {
			return Batch{}, cleanupBUEvidence(reader, "invalid cleanup owed artifact")
		}
	}
	encoded, err := cleanupBUAdvance(reader, a, span)
	if err != nil {
		return Batch{}, err
	}
	mutations := []Mutation{{DBI: dbis[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded}}
	if all(body.Present, !keep) {
		mutations = append(mutations, Mutation{DBI: dbis[4], Key: hash[:], BeforePresent: true, AfterKind: AfterAbsent})
	}
	key, _ := HeightKey(span.GenerationID, span.NextHeight)
	mutations = append(mutations, Mutation{DBI: dbis[6], Key: key, BeforePresent: true, AfterKind: AfterAbsent})
	slices.SortFunc(consulted, func(x, y ConsultedRow) int {
		if x.DBI.Rank != y.DBI.Rank {
			return int(x.DBI.Rank) - int(y.DBI.Rank)
		}
		return bytes.Compare(x.Key, y.Key)
	})
	return Batch{Mutations: mutations, Consulted: consulted, LargeConsulted: []LargeImageSelectorV1{{Kind: LargeImageBlockBodyV1, Hash: hash}}}, nil
}

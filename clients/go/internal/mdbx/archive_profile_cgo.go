//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"encoding/binary"
	"errors"
)

// ArchiveProfileOutcome forwards the Update tuple and invocation-local payload.
type ArchiveProfileOutcome = PrunedProfileOutcome

const archiveProfileReservationBytes = 512

// SelectArchiveProfileV1 selects ARCHIVE at PRE_GENESIS or H0 without changing
// canonical data, promises, generation identities or cleanup progress.
func (s *Store) SelectArchiveProfileV1(reservations *OperationReservationOwner) ArchiveProfileOutcome {
	out := ArchiveProfileOutcome{Truth: CommitTruthOld, Stage: UpdateStagePrewrite}
	if s == nil {
		out.Err = adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
		return out
	}
	sentinel := errors.New("archive profile decision")
	var decision string
	var planned *StorageAuthorityV1
	// The 498-byte charged envelope fits 512; authority/control metadata is outside R.
	out.Err = reservations.WithReservation(archiveProfileReservationBytes, func() error {
		var err error
		out.Truth, out.Stage, err = s.Update(func(reader *Reader) (Batch, error) {
			batch, authority, planErr := archiveProfileBatch(reader, &decision, sentinel)
			planned = authority
			return batch, planErr
		})
		return err
	})
	return archiveProfileOutcome(out, planned, decision, sentinel)
}

// archiveProfileBatch borrows only this Update's Reader. It neither acquires a
// grant nor starts another transaction, allowing later same-reader composition.
func archiveProfileBatch(reader *Reader, decision *string, sentinel error) (Batch, *StorageAuthorityV1, error) {
	a, err := reader.ReadStorageAuthorityV1()
	if err != nil {
		return Batch{}, nil, err
	}
	switch {
	case a.Lifecycle != StorageLifecycleStableV1:
		*decision = "RECOVERY_REQUIRED"
		return Batch{}, nil, sentinel
	case a.ActiveProfile == StorageProfileArchiveV1:
		*decision = "PROFILE_NOOP"
		return Batch{}, nil, sentinel
	}
	identity, err := archiveProfileIdentity(reader, a.ActiveGenerationID)
	if err != nil {
		return Batch{}, nil, err
	}
	if a.Phase == StoragePhasePruneGCV1 && identity != 1 {
		*decision = "LOCAL_BUSY"
		return Batch{}, nil, sentinel
	}
	if identity == 2 {
		return Batch{}, nil, adapterError(operationUpdate, EngineStateMismatch, codeProblem, "archive above genesis is owned by the selected-side and replay-entry leaves", nil)
	}
	return archiveProfileReplacement(reader, a)
}

// Identity is PRE_GENESIS=0, H0=1 or H>0=2. PrefixPage validates both observed
// rows before the first row's height/work checks; the third row is unobserved.
func archiveProfileIdentity(reader *Reader, generation uint64) (uint8, error) {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], generation)
	page, err := reader.PrefixPage(SchemaV2DBIs()[2], prefix[:], nil, 1, 120)
	if err != nil {
		return 0, err
	}
	if len(page.Rows) == 0 {
		return 0, nil
	}
	if binary.BigEndian.Uint64(page.Rows[0].Key[8:]) != 0 {
		return 0, bootstrapFailure(reader, integrityError(operationGet, "archive canonical index does not start at genesis", nil))
	}
	if !validWork([40]byte(page.Rows[0].Value[64:104])) {
		return 0, bootstrapFailure(reader, integrityError(operationGet, "invalid archive profile genesis work", nil))
	}
	if page.Stop == PrefixPageExhausted {
		return 1, nil
	}
	return 2, nil
}

func archiveProfileReplacement(reader *Reader, a StorageAuthorityV1) (Batch, *StorageAuthorityV1, error) {
	if a.B != 0 || a.U != 0 {
		return Batch{}, nil, bootstrapFailure(reader, integrityError(operationGet, "archive profile promises disagree with tip", nil))
	}
	a.ActiveProfile = StorageProfileArchiveV1
	if err := ValidateStorageAuthorityV1(a); err != nil {
		return Batch{}, nil, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid archive profile replacement", err)
	}
	if _, fits := authoritySize(a); !fits {
		return Batch{}, nil, updateBoundError()
	}
	encoded, err := a.Encode()
	if err != nil {
		return Batch{}, nil, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid archive profile replacement", err)
	}
	g0, _ := HeightKey(a.ActiveGenerationID, 0) // Validated generation and literal heights.
	g1, _ := HeightKey(a.ActiveGenerationID, 1)
	batch := Batch{
		Mutations: []Mutation{{DBI: SchemaV2DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded}},
		Consulted: []ConsultedRow{{DBI: SchemaV2DBIs()[2], Key: g0}, {DBI: SchemaV2DBIs()[2], Key: g1}},
	}
	return batch, &a, nil
}

func archiveProfileOutcome(out ArchiveProfileOutcome, planned *StorageAuthorityV1, decision string, sentinel error) ArchiveProfileOutcome {
	if out.Err == sentinel && out.Truth == CommitTruthOld && out.Stage == UpdateStagePrewrite { //nolint:errorlint // Exact sentinel alone excludes wrappers and cleanup causes.
		out.Decision, out.Err = decision, nil
		return out
	}
	if out.Truth == CommitTruthNew && out.Stage == UpdateStageCommitMayHaveCrossed {
		out.Authority = planned
	}
	return out
}

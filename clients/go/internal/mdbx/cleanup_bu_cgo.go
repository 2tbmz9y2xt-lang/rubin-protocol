//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"slices"
)

// CleanupBUV1 removes one committed active-canonical BLOCKS or UNDO height.
// The full lane stays reserved through Update's native commit and cleanup.
func (s *Store) CleanupBUV1(reservations *OperationReservationOwner) (CommitTruth, UpdateStage, error) {
	if s == nil {
		return CommitTruthOld, UpdateStagePrewrite, adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	truth, stage := CommitTruthOld, UpdateStagePrewrite
	noWork := errors.New("cleanup B/U has no selected work")
	err := reservations.WithReservation(MaxOperationDataBytes, func() error {
		var updateErr error
		truth, stage, updateErr = s.Update(func(reader *Reader) (Batch, error) {
			return cleanupBUBatch(reader, noWork)
		})
		return updateErr
	})
	if err == noWork && truth == CommitTruthOld && stage == UpdateStagePrewrite { //nolint:errorlint // Complete identity excludes joined cleanup errors.
		err = nil
	}
	return truth, stage, err
}

func cleanupBUBatch(reader *Reader, noWork error) (Batch, error) {
	a, err := cleanupBUAuthority(reader)
	if err != nil {
		return Batch{}, err
	}
	span, err := cleanupBUSelect(reader, a, noWork)
	if err != nil {
		return Batch{}, err
	}
	hash, consulted, err := cleanupBUCanonical(reader, a.ActiveGenerationID, span.NextHeight)
	if err != nil {
		return Batch{}, err
	}
	var deletes []Mutation
	if span.Kind == CleanupSpanBlocksV1 {
		deletes, err = cleanupBUBlocks(reader, hash)
	} else {
		deletes, err = cleanupBUUndo(reader, hash, span.NextHeight)
	}
	if err != nil {
		return Batch{}, err
	}
	encoded, err := cleanupBUAdvance(reader, &a, span)
	if err != nil {
		return Batch{}, err
	}
	dbis := SchemaV1DBIs()
	mutations := make([]Mutation, 0, 1+len(deletes))
	mutations = append(mutations, Mutation{DBI: dbis[0], Key: []byte{2}, BeforePresent: true, AfterKind: AfterLiteral, Literal: encoded})
	mutations = append(mutations, deletes...)
	return Batch{Mutations: mutations, Consulted: consulted, Reverse: span.Kind == CleanupSpanUndoV1}, nil
}

func cleanupBUAuthority(reader *Reader) (StorageAuthorityV1, error) {
	value, present, err := reader.Get(SchemaV1DBIs()[0], []byte{2})
	if err != nil {
		return StorageAuthorityV1{}, err
	}
	a, err := DecodeStorageAuthorityV1(value)
	if !present || err != nil {
		return StorageAuthorityV1{}, bootstrapFailure(reader, integrityError(operationGet, "invalid cleanup authority", err))
	}
	return a, nil
}

func cleanupBUSelect(reader *Reader, a StorageAuthorityV1, noWork error) (CleanupSpanV1, error) {
	if a.Phase != StoragePhasePruneGCV1 || a.DetachedSuffix != nil || a.Cleanup == nil {
		return CleanupSpanV1{}, noWork
	}
	span := a.Cleanup.Spans[0]
	if span.Kind != CleanupSpanBlocksV1 && span.Kind != CleanupSpanUndoV1 {
		return CleanupSpanV1{}, noWork
	}
	if err := cleanupBUPromise(reader, a, span); err != nil {
		return CleanupSpanV1{}, err
	}
	return span, nil
}

func cleanupBUPromise(reader *Reader, a StorageAuthorityV1, span CleanupSpanV1) error {
	bound := a.B
	if span.Kind == CleanupSpanUndoV1 {
		bound = a.U
	}
	if span.GenerationID != a.ActiveGenerationID || span.NextHeight >= bound || span.LastHeight >= bound || span.NextHeight > maxAuthorityHeight {
		return bootstrapFailure(reader, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "cleanup promises disagree with authority", nil))
	}
	return nil
}

func cleanupBUAdvance(reader *Reader, a *StorageAuthorityV1, span CleanupSpanV1) ([]byte, error) {
	// Copy the span list before changing its cursor; Decode owns no caller bytes.
	a.Cleanup.Spans = slices.Clone(a.Cleanup.Spans)
	if span.NextHeight == span.LastHeight {
		a.Cleanup.Spans = a.Cleanup.Spans[1:]
		if len(a.Cleanup.Spans) == 0 {
			a.Cleanup = nil
			a.Phase = StoragePhaseNoneV1
		}
	} else {
		a.Cleanup.Spans[0].NextHeight++
	}
	if ValidateStorageAuthorityV1(*a) != nil {
		return nil, bootstrapFailure(reader, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid cleanup replacement", nil))
	}
	if _, fits := authoritySize(*a); !fits {
		return nil, updateBoundError()
	}
	encoded, err := a.Encode()
	if err != nil {
		return nil, bootstrapFailure(reader, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid cleanup replacement", err))
	}
	return encoded, nil
}

// The exact current and predecessor index rows plus the required header are
// unchanged observations for Store.Update's strict possible-crossed readback.
func cleanupBUCanonical(reader *Reader, generation, height uint64) ([32]byte, []ConsultedRow, error) {
	dbis := SchemaV1DBIs()
	key, value, err := cleanupBUIndex(reader, generation, height)
	if err != nil {
		return [32]byte{}, nil, err
	}
	var hash, parent [32]byte
	copy(hash[:], value[:32])
	copy(parent[:], value[32:64])
	consulted := []ConsultedRow{{DBI: dbis[2], Key: key}}
	if height > 0 {
		previous, previousErr := cleanupBUPrevious(reader, generation, height, parent, value[64:104])
		if previousErr != nil {
			return [32]byte{}, nil, previousErr
		}
		consulted = append([]ConsultedRow{previous}, consulted...)
	}
	if err := cleanupBUHeader(reader, hash, parent, height); err != nil {
		return [32]byte{}, nil, err
	}
	consulted = append(consulted, ConsultedRow{DBI: dbis[3], Key: hash[:]})
	return hash, consulted, nil
}

func cleanupBUIndex(reader *Reader, generation, height uint64) ([]byte, []byte, error) {
	key, err := HeightKey(generation, height)
	if err != nil {
		return nil, nil, cleanupBUEvidence(reader, "invalid cleanup canonical evidence")
	}
	value, present, err := reader.Get(SchemaV1DBIs()[2], key)
	if err != nil {
		return nil, nil, err
	}
	if !present || len(value) != 104 || !validWork([40]byte(value[64:104])) {
		return nil, nil, cleanupBUEvidence(reader, "invalid cleanup canonical evidence")
	}
	return key, value, nil
}

func cleanupBUPrevious(reader *Reader, generation, height uint64, parent [32]byte, work []byte) (ConsultedRow, error) {
	key, _ := HeightKey(generation, height-1)
	previous, found, err := reader.Get(SchemaV1DBIs()[2], key)
	if err != nil {
		return ConsultedRow{}, err
	}
	if !found || len(previous) != 104 || !validWork([40]byte(previous[64:104])) || !bytes.Equal(previous[:32], parent[:]) || bytes.Compare(previous[64:104], work) >= 0 {
		return ConsultedRow{}, cleanupBUEvidence(reader, "invalid cleanup canonical evidence")
	}
	return ConsultedRow{DBI: SchemaV1DBIs()[2], Key: key}, nil
}

func cleanupBUHeader(reader *Reader, hash, parent [32]byte, height uint64) error {
	header, found, err := reader.Get(SchemaV1DBIs()[3], hash[:])
	if err != nil {
		return err
	}
	if !found || len(header) != 116 || sha3.Sum256(header) != hash || !bytes.Equal(header[4:36], parent[:]) || height == 0 && parent != ([32]byte{}) {
		return cleanupBUEvidence(reader, "invalid cleanup canonical evidence")
	}
	return nil
}

func cleanupBUBlocks(reader *Reader, hash [32]byte) ([]Mutation, error) {
	value, present, err := reader.Get(SchemaV1DBIs()[4], hash[:])
	if err != nil {
		return nil, err
	}
	if !present || ValidateRow(SchemaV1DBIs()[4], hash[:], value) != nil {
		return nil, cleanupBUEvidence(reader, "invalid cleanup owed artifact")
	}
	return []Mutation{{DBI: SchemaV1DBIs()[4], Key: hash[:], BeforePresent: true, AfterKind: AfterAbsent}}, nil
}

func cleanupBUUndo(reader *Reader, hash [32]byte, height uint64) ([]Mutation, error) {
	manifest, txCount, spentCount, err := cleanupBUManifest(reader, hash, height)
	if err != nil {
		return nil, err
	}
	return cleanupBUUndoEntries(reader, hash, manifest, txCount, spentCount)
}

func cleanupBUManifest(reader *Reader, hash [32]byte, height uint64) ([]byte, uint32, uint32, error) {
	dbi := SchemaV1DBIs()[5]
	manifest := UndoManifestKey(hash)
	value, present, err := reader.Get(dbi, manifest)
	if err != nil {
		return nil, 0, 0, err
	}
	if !present || ValidateRow(dbi, manifest, value) != nil || binary.BigEndian.Uint64(value[1:9]) != height {
		return nil, 0, 0, cleanupBUEvidence(reader, "invalid cleanup owed artifact")
	}
	txCount := binary.BigEndian.Uint32(value[25:29])
	spentCount := binary.BigEndian.Uint32(value[29:33])
	if spentCount > uint32(maxUpdateInputs) || txCount > uint32(maxUpdateOutputs) || (spentCount > 0 && txCount == 0) {
		return nil, 0, 0, cleanupBUEvidence(reader, "invalid cleanup owed artifact")
	}
	return manifest, txCount, spentCount, nil
}

func cleanupBUUndoEntries(reader *Reader, hash [32]byte, manifest []byte, txCount, spentCount uint32) ([]Mutation, error) {
	dbi := SchemaV1DBIs()[5]
	deletes := make([]Mutation, 0, 1+int(spentCount))
	deletes = append(deletes, Mutation{DBI: dbi, Key: manifest, BeforePresent: true, AfterKind: AfterAbsent})
	outpoints := make([][36]byte, 0, int(spentCount))
	var after []byte
	for {
		page, pageErr := reader.PrefixPage(dbi, hash[:], after, 64, 4_200_000)
		if pageErr != nil {
			return nil, pageErr
		}
		rows := page.Rows
		if after == nil {
			if len(rows) == 0 || !bytes.Equal(rows[0].Key, manifest) {
				return nil, cleanupBUEvidence(reader, "invalid cleanup owed artifact")
			}
			rows = rows[1:]
		}
		if err := cleanupBUPageRows(reader, dbi, rows, txCount, spentCount, &deletes, &outpoints); err != nil {
			return nil, err
		}
		if page.Stop == PrefixPageExhausted {
			break
		}
		if len(page.Rows) == 0 || page.Stop != PrefixPageRowLimit && page.Stop != PrefixPageByteLimit {
			return nil, cleanupBUEvidence(reader, "invalid cleanup owed artifact")
		}
		after = page.Rows[len(page.Rows)-1].Key
	}
	if err := cleanupBUDistinct(reader, outpoints, spentCount); err != nil {
		return nil, err
	}
	return deletes, nil
}

func cleanupBUPageRows(reader *Reader, dbi DBI, rows []PrefixRow, txCount, spentCount uint32, deletes *[]Mutation, outpoints *[][36]byte) error {
	for _, row := range rows {
		if len(row.Key) != 77 || row.Key[32] != 1 || ValidateRow(dbi, row.Key, row.Value) != nil || binary.BigEndian.Uint32(row.Key[33:37]) >= txCount || len(*outpoints) >= int(spentCount) {
			return cleanupBUEvidence(reader, "invalid cleanup owed artifact")
		}
		var outpoint [36]byte
		copy(outpoint[:], row.Key[41:77])
		*outpoints = append(*outpoints, outpoint)
		*deletes = append(*deletes, Mutation{DBI: dbi, Key: row.Key, BeforePresent: true, AfterKind: AfterAbsent})
	}
	return nil
}

func cleanupBUDistinct(reader *Reader, outpoints [][36]byte, expected uint32) error {
	if len(outpoints) != int(expected) {
		return cleanupBUEvidence(reader, "invalid cleanup owed artifact")
	}
	slices.SortFunc(outpoints, func(a, b [36]byte) int { return bytes.Compare(a[:], b[:]) })
	for i := 1; i < len(outpoints); i++ {
		if outpoints[i-1] == outpoints[i] {
			return cleanupBUEvidence(reader, "invalid cleanup owed artifact")
		}
	}
	return nil
}

func cleanupBUEvidence(reader *Reader, diagnostic string) error {
	return bootstrapFailure(reader, integrityError(operationGet, diagnostic, nil))
}

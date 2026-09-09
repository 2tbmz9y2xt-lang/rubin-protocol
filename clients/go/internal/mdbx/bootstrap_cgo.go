//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

// bootstrapOperationBytes is the maximum-live logical buffer envelope of one
// BootstrapStorageV1 call. Producer originals are 68 bytes (40 authority, 16 counter,
// 1+9 mutation keys and the two 1-byte metadata keys the reads and the consulted rows
// share); Reader.Get copies the 4+48 required metadata bytes; Update clones 66 mutation
// and 2 consulted bytes when it takes the plan. The inherited per-row validation scratch
// holds at most 40 bytes and every scan finishes before the clone phase, so its peak of
// 160 stays below this maximum instead of adding to it. Rederive this before changing any
// copy route, buffer size or lifetime.
const bootstrapOperationBytes uint64 = 188

// BootstrapStorageV1 initializes an exact-empty SchemaV1 store into its first authority
// image and that generation's zero logical counter, in one Store.Update transaction. It
// is dormant: no production caller selects it, and it decides nothing about targets,
// genesis, replay entry or startup classification.
//
// Static input is decided before any Store or reservation work: a nil receiver, then a
// profile outside {StorageProfilePrunedV1, StorageProfileArchiveV1}, each returning a
// direct EngineInvalidInput refusal with CommitTruthOld. bootstrapOperationBytes are then
// charged to reservations for the whole operation and released before every return,
// panic and Goexit; a refused charge returns the owner's own error and never reaches
// Store.Update. Once Update runs, its (CommitTruth, error) pair is forwarded unchanged:
// no class, code, operation, cause or truth is rewritten.
//
// A store whose seven entry counts are not the exact-empty census is refused with
// EngineStateMismatch: nothing is reset and no image is classified as corrupt, and after a
// successful OLD abort the Store stays open, reusable and byte-identical; a cleanup failure
// keeps its own existing lifecycle instead. A store that passes that census while a required
// metadata row is absent, of a width Reader.Get itself refuses, undecodable or disagreeing
// with this Store's config is refused with EngineIntegrity instead, and like a native
// inspection failure or a Reader.Get failure it travels the existing infrastructure path, so
// the Store ends terminal and no partial initial image exists. The caller supplies an
// already-open Store and one long-lived shared reservation owner; no Reader, Inspection,
// buffer or token escapes this call.
func (s *Store) BootstrapStorageV1(profile StorageProfileV1, reservations *OperationReservationOwner) (CommitTruth, error) {
	if s == nil {
		return CommitTruthOld, adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "nil Store", nil)
	}
	if !validProfile(profile) {
		return CommitTruthOld, adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "invalid bootstrap profile", nil)
	}
	truth := CommitTruthOld
	err := reservations.WithReservation(bootstrapOperationBytes, func() error {
		var updateErr error
		truth, updateErr = s.Update(func(reader *Reader) (Batch, error) { return bootstrapBatch(s, reader, profile) })
		return updateErr
	})
	return truth, err
}

// bootstrapBatch is the whole Update callback. It observes every DBI through the caller's
// own OLD transaction, refuses anything but the exact-empty image before reading or
// allocating anything else, revalidates the two required metadata rows it binds as
// consulted, and returns the fixed two-row initial plan. The first count mismatch returns
// immediately and there is no second census. Update holds Store.operations from OLD
// snapshot creation through write/readback and cleanup. The Store's lifetime directory
// advisory lock excludes other cooperating Rubin writers, so the census cannot change
// before this fixed two-row plan is applied.
func bootstrapBatch(s *Store, reader *Reader, profile StorageProfileV1) (Batch, error) {
	inspection, err := bootstrapInspect(s, reader)
	if err != nil {
		return Batch{}, err
	}
	for rank, want := range [7]uint64{2, 0, 0, 0, 0, 0, 0} {
		if inspection.DBIs[rank].Entries != want {
			return Batch{}, adapterError(operationUpdate, EngineStateMismatch, codeProblem, "bootstrap requires exact-empty store", nil)
		}
	}
	versionKey, configKey := []byte{0x00}, []byte{0x01}
	if metadataErr := bootstrapMetadata(s, reader, versionKey, configKey); metadataErr != nil {
		return Batch{}, metadataErr
	}
	authority, err := bootstrapAuthority(reader, profile)
	if err != nil {
		return Batch{}, err
	}
	meta := SchemaV1DBIs()[0]
	return Batch{
		Mutations: []Mutation{
			{DBI: meta, Key: []byte{0x02}, AfterKind: AfterLiteral, Literal: authority},
			// MetaKey(0x10, 1) for the generation this call creates, written out because that
			// constructor's only refusal is image ID zero, which a literal 1 cannot reach.
			{DBI: meta, Key: []byte{0x10, 0, 0, 0, 0, 0, 0, 0, 1}, AfterKind: AfterLiteral, Literal: LogicalCounterValue(0, 0)},
		},
		Consulted: []ConsultedRow{{DBI: meta, Key: versionKey}, {DBI: meta, Key: configKey}},
	}, nil
}

// bootstrapInspect returns the seven transaction-bound DBI entry counts of the Update's
// own OLD snapshot, copying no native value bytes. A native or geometry failure is this
// Reader's infrastructure provenance: it is recorded unchanged under the lock this
// function already holds and returned as the same object, so readPrimary forwards that
// object instead of joining an equal-valued copy. The unlock is deferred so a panic or
// Goexit cannot strand the Reader lock, and no Reader.Get may run inside this scope
// because getMu is not reentrant.
func bootstrapInspect(s *Store, reader *Reader) (Inspection, error) {
	reader.getMu.Lock()
	defer reader.getMu.Unlock()
	inspection, err := s.inspectReadLocked(reader.txn)
	if err != nil {
		reader.failure = err
		reader.active.Store(false)
	}
	return inspection, err
}

// bootstrapMetadata revalidates the two required metadata rows this bootstrap binds as
// consulted, reusing the caller's key slices. An existing Reader.Get error is returned
// unchanged and already carries its recorded Reader state; an absent row, an undecodable
// value or a stored geometry differing from the one this Store was opened with becomes
// the fixed integrity refusal naming that row, recorded as infrastructure. Row 00 is
// decided first and short-circuits, because a failed Get disarms the Reader.
func bootstrapMetadata(s *Store, reader *Reader, versionKey, configKey []byte) error {
	meta := SchemaV1DBIs()[0]
	value, _, err := reader.Get(meta, versionKey)
	if err != nil {
		return err
	}
	if !bootstrapVersionRow(value) {
		return bootstrapFailure(reader, integrityError(operationGet, "invalid bootstrap metadata 00", nil))
	}
	value, _, err = reader.Get(meta, configKey)
	if err != nil {
		return err
	}
	if !bootstrapConfigRow(value, s.config) {
		return bootstrapFailure(reader, integrityError(operationGet, "invalid bootstrap metadata 01", nil))
	}
	return nil
}

// bootstrapVersionRow reports whether the required SchemaV1 version row carries exactly the
// version this build writes. An absent row reaches this decode as a nil value, whose width
// the decode already refuses, so presence carries no decision of its own.
func bootstrapVersionRow(value []byte) bool {
	return DecodeSchemaVersionValue(value) == nil
}

// bootstrapConfigRow reports whether the required ConfigV1 row decodes and equals caller,
// the persisted geometry comparison Open already performs; an absent row is the nil value
// that decode refuses for its width. Effective current geometry is not this comparison and
// cannot substitute for it.
func bootstrapConfigRow(value []byte, caller ConfigV1) bool {
	stored, err := DecodeConfigV1(value)
	return err == nil && validateStoredConfig(stored, caller) == nil
}

// bootstrapAuthority encodes the fixed initial authority for profile: version 1, B and U
// zero, active generation 1, next generation 2, no phase, stable lifecycle and every
// optional descriptor absent. Encode refuses only a struct failing its own validation,
// which no admitted profile can produce here; that residue is wrapped once with the
// encoder error as its cause, recorded as infrastructure, and never ignored.
func bootstrapAuthority(reader *Reader, profile StorageProfileV1) ([]byte, error) {
	encoded, err := StorageAuthorityV1{
		Version: StorageAuthorityVersionV1, ActiveProfile: profile, B: 0, U: 0,
		ActiveGenerationID: 1, NextGenerationID: 2,
		Phase: StoragePhaseNoneV1, Lifecycle: StorageLifecycleStableV1,
	}.Encode()
	if err != nil {
		return nil, bootstrapFailure(reader, adapterError(operationUpdate, EngineLocalInvariant, codeProblem, "invalid bootstrap authority", err))
	}
	return encoded, nil
}

// bootstrapFailure records err as this Reader's infrastructure failure and returns the
// same object. It mutates no Store field, consumes nothing, aborts nothing and changes no
// error; recording the identical object is what lets readPrimary forward it verbatim.
func bootstrapFailure(reader *Reader, err error) error {
	reader.getMu.Lock()
	defer reader.getMu.Unlock()
	reader.failure = err
	reader.active.Store(false)
	return err
}

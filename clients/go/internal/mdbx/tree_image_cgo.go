//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

// TreeImagePublicationV1 is the result of the UpdateImageV1 planner, run once with a Reader that expires when the planner exits. One ORIGINAL
// OLD abort then takes the first primary of: the planner error joined before a failure the Reader recorded (the failure alone for a nil or
// identical error); "invalid Update Batch" (InvalidInput/update/EINVAL, no Cause) if a field is not admitted or the account ceiling is not
// LaneMaxBytes; a meta key 0x02 read error for update, of its get, of the exact-empty census if absent, or Integrity "invalid tree native
// representation" caused by the DecodeTreeAuthorityV1 error if present; "invalid Update Batch". A clean abort returns the primary, or
// consumes the Store with it if the Reader recorded a failure or the primary is the key 0x02 read error; a THREAD_MISMATCH abort error with
// the primary as Cause is returned and poisons the Store as its terminal; another failed abort consumes the Store with the primary joined
// before the abort error. A panic or Goexit resumes after the abort instead, with the recorded failure, if any, as primary.
type TreeImagePublicationV1 struct {
	// Tag is admitted from 1 through 4.
	Tag uint8
	// Authority is admitted when DecodeTreeAuthorityV1 accepts it.
	Authority []byte
	// RecordLimit is admitted when positive.
	RecordLimit uint64
	// Replay is admitted when non-nil; UpdateImageV1 does not call it.
	Replay func(*Reader, func(TreeImageRecordV1) error) error
}

// TreeImageRecordV1 is the record type of TreeImagePublicationV1.Replay.
type TreeImageRecordV1 struct {
	Kind      uint8
	Rows      [4]Mutation
	Consulted ConsultedRow
}

// UpdateImageV1 writes no native row; returns have UpdateStagePrewrite, index -1 and, unless stated, CommitTruthOld. First match, where
// errors quoted here have no Cause: "nil Store", "nil UpdateImageV1 callback" for a nil planner, "nil operation account", or "closed
// operation account" for a zero or closed account (InvalidInput/update/EINVAL) before the serving mark; Concurrency/update/-30778 "store
// operation in progress" if another operation holds the Store; state refusals with the Store's retained truth if valid: "invalid Store state"
// or "invalid Store resource shape" (LocalInvariant/update/-30779), the cached terminal, or "Store is closed" (InvalidInput/update/EINVAL)
// for a closed Store with none; StateMismatch/update/-30779 "typed tree operation requires tree store" for a format other than 3; an ORIGINAL
// OLD begin error for update, consuming the Store; then TreeImagePublicationV1 applies. Consuming closes the Store, or blocks it on a busy
// close, and returns its new terminal: the error joined before any close and lock-release errors, or as Cause of the busy close error.
func (s *Store) UpdateImageV1(account *OperationAccount, planner func(*Reader) (TreeImagePublicationV1, error)) (CommitTruth, UpdateStage, int, error) {
	return s.treeEntryGateV1(account, planner == nil, "nil UpdateImageV1 callback", func() (CommitTruth, UpdateStage, int, treeUnwindV1, error) {
		return s.treeOriginalOldV1(func(e *treePublicEntryV1) (CommitTruth, UpdateStage, int, treeUnwindV1, error) {
			return e.publicationV1(account, planner)
		})
	})
}

// publicationV1 runs planner through treeCallbackV1 with a preserve function that keeps no canonical
// tip. When treeCallbackV1 returns an error or a panic unwind, publicationV1 returns that result; after a
// planner Goexit, treeCallbackV1 aborts ORIGINAL OLD and the Goexit continues, so publicationV1 does not
// return. Otherwise it aborts ORIGINAL OLD once through abortReadLocked with the publicationRefusalV1
// error as the primary and its flag as infrastructure.
func (e *treePublicEntryV1) publicationV1(account *OperationAccount, planner func(*Reader) (TreeImagePublicationV1, error)) (CommitTruth, UpdateStage, int, treeUnwindV1, error) {
	publication, unwind, err := treeCallbackV1(e, planner, func(TreeImagePublicationV1) bool { return false })
	if err != nil || unwind.kind != 0 {
		return CommitTruthOld, UpdateStagePrewrite, -1, unwind, err
	}
	infrastructure, refusal := e.publicationRefusalV1(account, publication)
	return CommitTruthOld, UpdateStagePrewrite, -1, treeUnwindV1{}, e.store.abortReadLocked(e.old, refusal, infrastructure)
}

// publicationRefusalV1 returns false and "invalid Update Batch" when publicationDescriptorV1
// refuses, true and the treeAuthorityRead error when that read of ORIGINAL OLD with
// operationUpdate fails, and false and "invalid Update Batch" otherwise.
func (e *treePublicEntryV1) publicationRefusalV1(account *OperationAccount, publication TreeImagePublicationV1) (bool, error) {
	if !publicationDescriptorV1(account, publication) {
		return false, updateInvalidBatch()
	}
	s := e.store
	if _, _, err := treeAuthorityRead(e.old, s.dbis, s.config, s.databaseID, operationUpdate); err != nil {
		return true, err
	}
	return false, updateInvalidBatch()
}

// publicationDescriptorV1 reports whether Tag is 1 through 4, Replay is non-nil, RecordLimit is
// positive, the account ceiling is LaneMaxBytes and DecodeTreeAuthorityV1 accepts Authority. It
// reads no Store and charges no account.
func publicationDescriptorV1(account *OperationAccount, publication TreeImagePublicationV1) bool {
	if publication.Tag < 1 || publication.Tag > 4 || publication.Replay == nil || publication.RecordLimit == 0 || account.shared.ceiling != LaneMaxBytes {
		return false
	}
	_, err := DecodeTreeAuthorityV1(publication.Authority)
	return err == nil
}

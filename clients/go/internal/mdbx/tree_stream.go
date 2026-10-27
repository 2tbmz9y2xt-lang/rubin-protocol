package mdbx

// TreePositionV1 identifies the writer or strict readback replay of one source.
type TreePositionV1 uint8

const (
	TreeWriterV1   TreePositionV1 = 1
	TreeReadbackV1 TreePositionV1 = 2
)

// TreeOutpointV1 identifies an output without carrying its value bytes.
type TreeOutpointV1 struct {
	Txid [32]byte
	Vout uint32
}

// TreeEventKindV1 is the closed SPEND/CREATE record domain.
type TreeEventKindV1 uint8

const (
	TreeEventSpendV1  TreeEventKindV1 = 1
	TreeEventCreateV1 TreeEventKindV1 = 2
)

// TreeBlockV1 declares one block's complete forward event stream.
type TreeBlockV1 struct {
	EventCount uint32
	TxCount    uint32
	Generated  [16]byte
}

// TreeSourceCoverageV1 binds an already qualified complete immutable source.
// BodyKind 1 borrows the same complete body backing as the expected-absent Pair
// literal; BodyKind 2 uses the protected stored body and requires CurrentBody nil.
// All primitives are covered or all omit Coverage. Qualification of the body,
// header, hashes, work and Generated belongs to the caller, through cleanup.
type TreeSourceCoverageV1 struct {
	DatabaseID  [32]byte
	Generation  uint64
	Block       [32]byte
	Height      uint64
	HeaderBytes uint16
	BodyKind    uint8
	BlockMeta   TreeBlockV1
	CurrentBody []byte
}

// TreeObservationKindV1 describes a bounded artifact detection, not eligibility
// for recovery, a protocol result, or permission to retry the Store.
type TreeObservationKindV1 uint8

const (
	TreeObservationAbsentV1           TreeObservationKindV1 = 1
	TreeObservationMalformedV1        TreeObservationKindV1 = 2
	TreeObservationIdentityMismatchV1 TreeObservationKindV1 = 3
	TreeObservationDigestMismatchV1   TreeObservationKindV1 = 4
)

// TreeObservationV1 is copied diagnostic context at the actual detection site.
// A node needs both original flags; outer owners separately qualify roles and
// progress. Native IO and unlocalized/source contradictions carry no observation.
type TreeObservationV1 struct {
	DatabaseID                       [32]byte
	Generation                       uint64
	Block                            [32]byte
	Height                           uint64
	Key                              [46]byte
	Primitive                        int
	Rank, KeyLength                  uint8
	Position                         TreePositionV1
	Kind                             TreeObservationKindV1
	OriginalImage, OriginalReference bool
}

// TreeEventV1 is copied by value; CREATE points into the block's output frame.
type TreeEventV1 struct {
	Kind        TreeEventKindV1
	Outpoint    TreeOutpointV1
	TxIndex     uint32
	InputIndex  uint32
	FrameOffset uint64
	FrameLength uint32
}

// TreeUndoEffectV1 specifies the composer's already-qualified own-family effect.
// WriteOrReuse writes the forward undo family or reuses its identical image;
// Transient creates no retained undo family; Compare compares it unchanged;
// CompareDelete compares then deletes it. SourceRetain reads an inverse source
// family and retains it; SourceDelete reads and deletes that inverse source.
type TreeUndoEffectV1 uint8

const (
	UndoWriteOrReuseV1  TreeUndoEffectV1 = 1
	UndoTransientV1     TreeUndoEffectV1 = 2
	UndoCompareV1       TreeUndoEffectV1 = 3
	UndoCompareDeleteV1 TreeUndoEffectV1 = 4
	UndoSourceRetainV1  TreeUndoEffectV1 = 5
	UndoSourceDeleteV1  TreeUndoEffectV1 = 6
)

// TreeDirectionV1 is a closed direction; zero is invalid.
type TreeDirectionV1 uint8

const (
	TreeForwardV1 TreeDirectionV1 = 1
	TreeInverseV1 TreeDirectionV1 = 2
)

// TreePrimitiveKindV1 fixes tree integration before reservation. Kinds 1-6
// require forward direction, kinds 7-9 inverse; only LAG kinds follow CURRENT.
type TreePrimitiveKindV1 uint8

const (
	TreeKindDirectApplyV1  TreePrimitiveKindV1 = 1
	TreeKindConnectV1      TreePrimitiveKindV1 = 2
	TreeKindReplayNextV1   TreePrimitiveKindV1 = 3
	TreeKindFirstGenesisV1 TreePrimitiveKindV1 = 4
	TreeKindRestoreOldV1   TreePrimitiveKindV1 = 5
	TreeKindLagForwardV1   TreePrimitiveKindV1 = 6
	TreeKindDisconnectV1   TreePrimitiveKindV1 = 7
	TreeKindRollbackNewV1  TreePrimitiveKindV1 = 8
	TreeKindLagReverseV1   TreePrimitiveKindV1 = 9
)

// TreeDeltaSinkV1 accepts exactly one BEGIN followed by every forward event in
// original body order. A malformed stream records its first "invalid tree delta"
// refusal. BEGIN requires nonzero TxCount; at height zero it requires TxCount 1,
// zero Generated, and no SPEND. Records are copied by value. WindowV1 is lent
// only during the source call; neither records, window nor sink may be retained.
// After the call, and on nil or zero-value sinks, methods refuse with "tree delta
// sink is not active" without changing the recorded failure; WindowV1 is nil.
type TreeDeltaSinkV1 struct{ recorder *treeRecorderV1 }

// TreeRoleDeltaV1 is one generation role of a TreeDeltaReportV1. Present is
// false only for an absent LAG role, and then every other field is zero.
// Generation is the role's generation id. BytesBefore/CountBefore are the
// 0x10||g counter values in ORIGINAL OLD; BytesAfter/CountAfter are that
// counter in the image the attempt commits (36+len(value) bytes per entry).
// IndexAdded/IndexRemoved count owned rank-2 Pair targets keyed under the
// generation from the caller-declared Pair presence: IndexAdded those with
// BeforePresent false and a literal After, IndexRemoved those with BeforePresent
// true and an absent After. Present-to-present replacements and rank-7 rows are
// not counted. The counts are exact for every committed operation: a false
// BeforePresent declaration is refused only at flush, after Proof has returned,
// so that operation never commits.
type TreeRoleDeltaV1 struct {
	Present                  bool
	Generation               uint64
	BytesBefore, CountBefore uint64
	BytesAfter, CountAfter   uint64
	IndexAdded, IndexRemoved uint64
}

// TreeUndoFamilyEffectV1 is the physical effect one primitive applies to the
// undo-v1 family of its Block: none, written, kept or deleted. A Transient
// primitive is always none, even when ORIGINAL holds a family under its Block.
type TreeUndoFamilyEffectV1 uint8

const (
	TreeUndoFamilyNoneV1    TreeUndoFamilyEffectV1 = 0
	TreeUndoFamilyWrittenV1 TreeUndoFamilyEffectV1 = 1
	TreeUndoFamilyKeptV1    TreeUndoFamilyEffectV1 = 2
	TreeUndoFamilyDeletedV1 TreeUndoFamilyEffectV1 = 3
)

// TreeUndoChargeV1 is one primitive's undo-family record. Entries and Bytes
// (36+len(value) per entry) describe the family written, kept or deleted: the
// entries before a forward primitive, after an inverse one. Both are zero for
// TreeUndoFamilyNoneV1. Records are per primitive, in primitive order; applied in
// that order, Written adds Bytes, Deleted removes Bytes, Kept and None change
// nothing. A Block named twice is not deduplicated.
type TreeUndoChargeV1 struct {
	Effect         TreeUndoFamilyEffectV1
	Entries, Bytes uint64
}

// TreeDeltaReportV1 states the storage-image difference between ORIGINAL OLD
// and the image one covered UpdateTreeV1 attempt commits. Current describes
// Primitives[0].Generation, Lag the single generation of Primitives[1:], and
// Undo has one record per primitive. It holds no Reader, row bytes or reference
// into the write image; the engine owns its backing and it is valid only during
// the Proof call.
type TreeDeltaReportV1 struct {
	Current, Lag TreeRoleDeltaV1
	Undo         []TreeUndoChargeV1
}

// TreeHeaderSlotV1 names one optional headers-v1 row of a covered operation:
// Hash is the row key and Header its 148-byte literal.
type TreeHeaderSlotV1 struct {
	Hash   [32]byte
	Header [148]byte
}

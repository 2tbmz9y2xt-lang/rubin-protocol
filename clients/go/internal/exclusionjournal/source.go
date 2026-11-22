// Package exclusionjournal retains independently durable original evidence bytes.
package exclusionjournal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"slices"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

var (
	ErrIntegrityV1   = errors.New("source: integrity")
	ErrUnavailableV1 = errors.New("source: unavailable")
	ErrCapacityV1    = errors.New("source: capacity")
	ErrIdentityV1    = errors.New("source: identity")
	ErrBusyV1        = errors.New("source: busy")
)

type (
	CaptureClassV1 uint8
	PartKindV1     uint8
)

const (
	RejectionV1 CaptureClassV1 = iota + 1
	AcceptanceV1
	RecoveryCoreImpossibleV1
)

const (
	BoundBodyV1 PartKindV1 = iota + 1
	ObservedResultV1
	HistoricalContextV1
	OriginalAssuranceV1
	ParentPathV1
	AcceptedPrefixV1
	AcquiredBlockBytesV1
	ExpectedHeaderPathV1
	AcquisitionPositionV1
)

// SourcePartSpecV1 fixes a part kind and its exact admitted byte length.
type SourcePartSpecV1 struct {
	Kind   PartKindV1
	Length uint64
}

// SourceManifestV1 fixes original identity and ordered parts (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
type SourceManifestV1 struct {
	Identity, AcquiredDigest [32]byte
	Class                    CaptureClassV1
	Parts                    []SourcePartSpecV1
}

// SourceLimitsV1 bounds retained backing and operations (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
type SourceLimitsV1 struct {
	Bytes, Files, Scans, RAM, Headers, Descriptors, Overhead uint64
}

// SourceOwnerV1 binds source operations to one actual Store instance and its protected directory.
type SourceOwnerV1 struct {
	sourceBinding
	store         *policycontrol.Store
	info          os.FileInfo
	self          *SourceOwnerV1
	limits        SourceLimitsV1
	busy          atomic.Bool
	ops           sourceFS
	debt          sourceDebt
	pendingStage  sourceDebt
	observedStage string
	stage         *policycontrol.SourceStagePinV1
	release       *sourceRelease
	live          map[string]*sourceIncarnation
}

type sourceBinding struct {
	dir    string
	id     policycontrol.Identity
	parent filelock.IdentityV1
}

// PreparedSourceV1 identifies qualified backing (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.4).
type PreparedSourceV1 struct {
	manifest    SourceManifestV1
	name        string
	incarnation *sourceIncarnation
}

type sourceIncarnation struct {
	file              filelock.IdentityV1
	size              uint64
	footer            [sha256.Size]byte
	issued, uncertain bool
}

const (
	sourceDirectory = "source-captures-v1"
	scratchBytes    = 64 * 1024
	bundleHeader    = 4 + 97 + 32 + 32 + 1 + 1
)

// NewSourceOwnerV1 reserves its workspace on account before claiming the Store's source directory and accounting for retained files.
func NewSourceOwnerV1(store *policycontrol.Store, expected policycontrol.Identity, limits SourceLimitsV1, account *mdbx.OperationAccount) (*SourceOwnerV1, error) {
	b, err := store.BorrowSourceAuthorityV1()
	if err != nil {
		return nil, err
	}
	defer b.ReleaseV1()
	dir, id, parent, err := b.BindingV1()
	if err != nil || id != expected {
		return nil, ErrIdentityV1
	}
	if !limits.valid() || account == nil {
		return nil, ErrCapacityV1
	}
	o := &SourceOwnerV1{store: store, sourceBinding: sourceBinding{dir, id, parent}, limits: limits, ops: realSourceFS, live: make(map[string]*sourceIncarnation)}
	o.self = o
	err = account.WithReservation(limits.WorkingBytesV1(), func() error {
		return b.WithSourceOwnerClaimV1(func(stage *policycontrol.SourceStagePinV1) error {
			o.stage = stage
			return o.openSourceRoot()
		})
	})
	if any(err) == any(policycontrol.ErrBusy) {
		return nil, ErrBusyV1
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (l SourceLimitsV1) valid() bool {
	bounds := []uint64{l.Bytes, l.Files, l.Scans, l.RAM, l.Headers, l.Descriptors, l.Overhead}
	working := l.WorkingBytesV1()
	available := min(l.RAM, uint64(math.MaxInt))
	return slices.Min(bounds) != 0 && slices.Max(bounds) < math.MaxInt64 && l.Scans <= uint64(math.MaxInt-scratchBytes-4096)/512 &&
		l.Descriptors >= 4 && l.Files < l.Scans && working <= available && l.retainedRAM() <= available-working
}

// WorkingBytesV1 bounds copy scratch, window digests, directory metadata and operation state.
func (l SourceLimitsV1) WorkingBytesV1() uint64 {
	return scratchBytes + 4096 + l.Scans*512 + sha256.Size*(l.Bytes/scratchBytes+6)
}

func (l SourceLimitsV1) retainedRAM() uint64 { return 1024 + l.Files*(136+sha256.Size) }

func (o *SourceOwnerV1) operation(account *mdbx.OperationAccount, use func() error) error {
	if o == nil || o.self != o {
		return ErrIdentityV1
	}
	b, err := o.store.BorrowSourceAuthorityV1()
	if err != nil {
		return err
	}
	defer b.ReleaseV1()
	dir, id, parent, err := b.BindingV1()
	if err != nil || (sourceBinding{dir, id, parent}) != o.sourceBinding {
		return ErrIdentityV1
	}
	if !o.busy.CompareAndSwap(false, true) {
		return ErrBusyV1
	}
	defer o.busy.Store(false)
	if account == nil {
		return ErrCapacityV1
	}
	return account.WithReservation(o.limits.WorkingBytesV1(), use)
}

var (
	boundSourceMinimums   = []SourcePartSpecV1{{BoundBodyV1, 1}, {ObservedResultV1, 1}, {HistoricalContextV1, 1}, {OriginalAssuranceV1, 1}, {ParentPathV1, 1}, {AcceptedPrefixV1, 0}}
	sourceMinimumsByClass = map[CaptureClassV1][]SourcePartSpecV1{
		RejectionV1:              boundSourceMinimums,
		AcceptanceV1:             boundSourceMinimums,
		RecoveryCoreImpossibleV1: {{AcquiredBlockBytesV1, 1}, {ExpectedHeaderPathV1, 1}, {HistoricalContextV1, 1}, {OriginalAssuranceV1, 1}, {AcquisitionPositionV1, 1}},
	}
)

// SizeV1 validates the closed manifest and returns its exact encoded length before allocation, or ErrIntegrityV1.
func (m SourceManifestV1) SizeV1() (uint64, error) {
	minimums := sourceMinimumsByClass[m.Class]
	if minimums == nil || len(m.Parts) != len(minimums) || m.Identity == [32]byte{} ||
		(m.Class == RecoveryCoreImpossibleV1) != (m.AcquiredDigest != [32]byte{}) {
		return 0, ErrIntegrityV1
	}
	total := uint64(bundleHeader + sha256.Size + 9*len(minimums))
	for i, p := range m.Parts {
		if !p.fits(minimums[i], math.MaxInt64-total) {
			return 0, ErrIntegrityV1
		}
		total += p.Length
	}
	return total, nil
}

func (p SourcePartSpecV1) fits(minimum SourcePartSpecV1, remaining uint64) bool {
	return p.Kind == minimum.Kind && p.Length >= minimum.Length && p.Length <= remaining
}

func (m SourceManifestV1) header(id policycontrol.Identity) []byte {
	b := make([]byte, 0, bundleHeader+9*len(m.Parts))
	b = append(b, 'S', 'C', 'V', 1)
	b = append(b, id.InstallationID[:]...)
	b = append(b, id.ChainID[:]...)
	b = append(b, id.GenesisHash[:]...)
	b = append(b, byte(id.Profile))
	b = append(b, m.Identity[:]...)
	b = append(b, m.AcquiredDigest[:]...)
	b = append(b, byte(m.Class), byte(len(m.Parts)&math.MaxUint8))
	for _, part := range m.Parts {
		b = append(b, byte(part.Kind))
		b = binary.LittleEndian.AppendUint64(b, part.Length)
	}
	return b
}

func (m SourceManifestV1) name(id policycontrol.Identity) string {
	digest := sha256.Sum256(m.header(id)[:bundleHeader])
	return hex.EncodeToString(digest[:])
}

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

// SourceManifestV1 fixes original identity, class, acquired-byte digest and ordered census.
type SourceManifestV1 struct {
	Identity, AcquiredDigest [32]byte
	Class                    CaptureClassV1
	Parts                    []SourcePartSpecV1
}

// SourceLimitsV1 are positive finite ceilings over the shared retained-source census and each operation.
type SourceLimitsV1 struct {
	Bytes, Files, Scans, RAM, Headers, Descriptors, Overhead uint64
}

// SourceOwnerV1 binds source operations to one actual Store instance and its protected directory. Each operation holds
// a Store source borrow and returns its refusal; a copied owner, a changed binding or a source directory not of mode
// 0700 returns ErrIdentityV1, a nil account ErrCapacityV1, an overlapping operation ErrBusyV1 and an account refusal is
// returned unchanged. The census of retained files refuses a misnamed or non-regular entry, an unexpected release record
// or a counted file that changed length or vanished with ErrIntegrityV1, a counted file of another inode with
// ErrIdentityV1, a second staging identity with ErrBusyV1 and entries or bytes over the limits with ErrCapacityV1.
type SourceOwnerV1 struct {
	store   *policycontrol.Store
	dir     string
	id      policycontrol.Identity
	info    os.FileInfo
	parent  filelock.IdentityV1
	self    *SourceOwnerV1
	limits  SourceLimitsV1
	busy    atomic.Bool
	ops     sourceFS
	debt    *sourceDebt
	release *sourceRelease
	live    map[string]*sourceIncarnation
}

// PreparedSourceV1 identifies qualified durable backing for a source incarnation.
type PreparedSourceV1 struct {
	manifest    SourceManifestV1
	name        string
	incarnation *sourceIncarnation
}

type sourceIncarnation struct {
	file   filelock.IdentityV1
	size   uint64
	footer [sha256.Size]byte
}

const (
	sourceDirectory = "source-captures-v1"
	scratchBytes    = 64 * 1024
	bundleHeader    = 4 + 97 + 32 + 32 + 1 + 1
)

// NewSourceOwnerV1 claims the Store's protected source directory and accounts for retained files. A binding other than
// expected or a source directory not of mode 0700 returns ErrIdentityV1, invalid limits or a nil account ErrCapacityV1
// and a second owner on the same open Store ErrBusyV1; a borrow refusal returns unchanged and a failed construction
// leaves the claim retryable.
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
	o := &SourceOwnerV1{store: store, dir: dir, id: id, parent: parent, limits: limits, ops: realSourceFS, live: make(map[string]*sourceIncarnation)}
	o.self = o
	err = b.WithSourceOwnerClaimV1(func() error {
		return account.WithReservation(limits.WorkingBytesV1(), o.openSourceRoot)
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
	if slices.Min(bounds) == 0 || slices.Max(bounds) >= math.MaxInt64 {
		return false
	}
	return l.Scans <= uint64(math.MaxInt-scratchBytes-4096)/512 &&
		l.Descriptors >= 4 && l.Files < l.Scans && l.RAM >= l.WorkingBytesV1()+l.retainedRAM()
}

// WorkingBytesV1 bounds copy scratch, directory metadata and constant operation/borrow state.
func (l SourceLimitsV1) WorkingBytesV1() uint64 { return scratchBytes + 4096 + l.Scans*512 }

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
	if !o.matchesBinding(b) {
		return ErrIdentityV1
	}
	if account == nil {
		return ErrCapacityV1
	}
	if !o.busy.CompareAndSwap(false, true) {
		return ErrBusyV1
	}
	defer o.busy.Store(false)
	return account.WithReservation(o.limits.WorkingBytesV1(), use)
}

func (o *SourceOwnerV1) matchesBinding(b *policycontrol.SourceAuthorityBorrowV1) bool {
	dir, id, parent, err := b.BindingV1()
	return err == nil && id == o.id && dir == o.dir && parent == o.parent
}

type sourcePartRule struct {
	kind    PartKindV1
	minimum uint64
}

var (
	boundSourceParts   = []sourcePartRule{{BoundBodyV1, 1}, {ObservedResultV1, 1}, {HistoricalContextV1, 1}, {OriginalAssuranceV1, 1}, {ParentPathV1, 1}, {AcceptedPrefixV1, 0}}
	sourcePartsByClass = map[CaptureClassV1][]sourcePartRule{
		RejectionV1:              boundSourceParts,
		AcceptanceV1:             boundSourceParts,
		RecoveryCoreImpossibleV1: {{AcquiredBlockBytesV1, 1}, {ExpectedHeaderPathV1, 1}, {HistoricalContextV1, 1}, {OriginalAssuranceV1, 1}, {AcquisitionPositionV1, 1}},
	}
)

// SizeV1 validates the closed manifest and returns its exact encoded length before allocation, or ErrIntegrityV1.
func (m SourceManifestV1) SizeV1() (uint64, error) {
	rules := sourcePartsByClass[m.Class]
	if rules == nil || len(m.Parts) != len(rules) || m.Identity == [32]byte{} ||
		(m.Class == RecoveryCoreImpossibleV1) != (m.AcquiredDigest != [32]byte{}) {
		return 0, ErrIntegrityV1
	}
	total := uint64(bundleHeader + sha256.Size + 9*len(rules))
	for i, p := range m.Parts {
		if !p.fits(rules[i], math.MaxInt64-total) {
			return 0, ErrIntegrityV1
		}
		total += p.Length
	}
	return total, nil
}

func (p SourcePartSpecV1) fits(rule sourcePartRule, remaining uint64) bool {
	return p.Kind == rule.kind && p.Length >= rule.minimum && p.Length <= remaining
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

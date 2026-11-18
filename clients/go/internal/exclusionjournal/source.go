// Package exclusionjournal retains independently durable original evidence bytes.
package exclusionjournal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
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

// SourceOwnerV1 binds source operations to one actual Store instance and its protected directory.
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
	owner       *SourceOwnerV1
	manifest    SourceManifestV1
	name        string
	incarnation *sourceIncarnation
}

type sourceIncarnation struct{ file filelock.IdentityV1 }

const (
	sourceDirectory = "source-captures-v1"
	scratchBytes    = 64 * 1024
	bundleHeader    = 4 + 97 + 32 + 32 + 1 + 1
)

// NewSourceOwnerV1 claims the Store's protected source directory and accounts for retained files.
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
	o := &SourceOwnerV1{store: store, dir: dir, id: id, parent: parent, limits: limits, ops: realSourceFS}
	o.self = o
	err = b.WithSourceOwnerClaimV1(func() error {
		return account.WithReservation(limits.WorkingBytesV1(), o.openSourceRoot)
	})
	if err == policycontrol.ErrBusy {
		return nil, ErrBusyV1
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (l SourceLimitsV1) valid() bool {
	for _, n := range []uint64{l.Bytes, l.Files, l.Scans, l.RAM, l.Headers, l.Descriptors, l.Overhead} {
		if n == 0 || n >= math.MaxInt64 {
			return false
		}
	}
	if l.Scans > uint64(math.MaxInt-scratchBytes-4096)/512 {
		return false
	}
	return l.Descriptors >= 4 && l.Files < l.Scans && l.RAM >= l.WorkingBytesV1()+l.retainedRAM()
}

// WorkingBytesV1 bounds copy scratch, directory metadata and constant operation/borrow state.
func (l SourceLimitsV1) WorkingBytesV1() uint64 { return scratchBytes + 4096 + l.Scans*512 }

func (l SourceLimitsV1) retainedRAM() uint64 { return 1024 + l.Files*128 }

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
	if err != nil || id != o.id || dir != o.dir || parent != o.parent {
		return ErrIdentityV1
	}
	if account == nil || !o.limits.valid() {
		return ErrCapacityV1
	}
	if !o.busy.CompareAndSwap(false, true) {
		return ErrBusyV1
	}
	defer o.busy.Store(false)
	return account.WithReservation(o.limits.WorkingBytesV1(), use)
}

func (m SourceManifestV1) kinds() []PartKindV1 {
	switch m.Class {
	case RejectionV1, AcceptanceV1:
		return []PartKindV1{BoundBodyV1, ObservedResultV1, HistoricalContextV1, OriginalAssuranceV1, ParentPathV1, AcceptedPrefixV1}
	case RecoveryCoreImpossibleV1:
		return []PartKindV1{AcquiredBlockBytesV1, ExpectedHeaderPathV1, HistoricalContextV1, OriginalAssuranceV1, AcquisitionPositionV1}
	}
	return nil
}

// SizeV1 validates the closed manifest and returns its exact encoded length before allocation.
func (m SourceManifestV1) SizeV1() (uint64, error) {
	kinds := m.kinds()
	if kinds == nil || len(m.Parts) != len(kinds) || m.Identity == [32]byte{} {
		return 0, ErrIntegrityV1
	}
	if (m.Class == RecoveryCoreImpossibleV1) != (m.AcquiredDigest != [32]byte{}) {
		return 0, ErrIntegrityV1
	}
	total := uint64(bundleHeader + 32)
	for i, p := range m.Parts {
		if !p.fits(kinds[i], total) {
			return 0, ErrIntegrityV1
		}
		total += 9 + p.Length
	}
	return total, nil
}

func (p SourcePartSpecV1) fits(kind PartKindV1, total uint64) bool {
	if p.Kind != kind || (p.Length == 0 && p.Kind != AcceptedPrefixV1) {
		return false
	}
	return total <= math.MaxInt64-9 && p.Length <= math.MaxInt64-total-9
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
	b = append(b, byte(m.Class), byte(len(m.Parts)))
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

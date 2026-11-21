package policycontrol

import (
	"fmt"
	"math"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/filelock"
)

// SourceAuthorityBorrowV1 excludes Close and keeps the Store's directory lock alive until release.
type SourceAuthorityBorrowV1 struct {
	state *sourceAuthorityStateV1
}

type sourceAuthorityStateV1 struct {
	store *Store
	live  bool
}

// SourceStagePinV1 holds the source owner's staging file under the Store lifetime.
type SourceStagePinV1 struct {
	File *os.File
}

// Clear closes the retained file. The source owner accesses the pin under a Store borrow.
func (p *SourceStagePinV1) Clear() {
	_ = p.File.Close()
	p.File = nil
}

// BorrowSourceAuthorityV1 admits a source lifetime without holding a transaction or mutex.
func (s *Store) BorrowSourceAuthorityV1() (*SourceAuthorityBorrowV1, error) {
	if s == nil || s.self != s {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed, s.st == nil, s.lock == nil:
		return nil, ErrClosed
	case s.pending != nil:
		return nil, fmt.Errorf("%w: %w", ErrBusy, ErrUnresolved)
	case s.tx != nil, s.crossing, s.sourceBorrows == math.MaxUint64:
		return nil, ErrBusy
	}
	s.sourceBorrows++
	return &SourceAuthorityBorrowV1{state: &sourceAuthorityStateV1{store: s, live: true}}, nil
}

// BindingV1 returns the immutable installation and held directory identity while the borrow is live.
func (b *SourceAuthorityBorrowV1) BindingV1() (string, Identity, filelock.IdentityV1, error) {
	if b == nil || b.state == nil {
		return "", Identity{}, filelock.IdentityV1{}, ErrClosed
	}
	s := b.state.store
	s.mu.Lock()
	if !b.state.live {
		s.mu.Unlock()
		return "", Identity{}, filelock.IdentityV1{}, ErrClosed
	}
	dir, id, expected := s.dir, s.st.id, s.directory
	s.mu.Unlock()
	current, err := os.Lstat(dir)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !b.state.live {
		return "", Identity{}, filelock.IdentityV1{}, ErrClosed
	}
	if err != nil || !current.IsDir() || expected != filelock.FileIdentityV1(current) {
		return "", Identity{}, filelock.IdentityV1{}, ErrRefused
	}
	return dir, id, expected, nil
}

// WithSourceOwnerClaimV1 reserves the Store's sole source construction until success or unwinding.
func (b *SourceAuthorityBorrowV1) WithSourceOwnerClaimV1(use func(*SourceStagePinV1) error) (err error) {
	if b == nil || b.state == nil || use == nil {
		return ErrClosed
	}
	s := b.state.store
	s.mu.Lock()
	switch {
	case !b.state.live:
		s.mu.Unlock()
		return ErrClosed
	case s.sourceStage != nil, s.sourceBorrows == math.MaxUint64:
		s.mu.Unlock()
		return ErrBusy
	}
	stage := new(SourceStagePinV1)
	s.sourceStage = stage
	s.sourceBorrows++
	s.mu.Unlock()
	success := false
	defer func() {
		s.mu.Lock()
		if !success {
			stage.Clear()
			s.sourceStage = nil
		}
		s.sourceBorrows--
		s.mu.Unlock()
	}()
	err = use(stage)
	success = err == nil
	return err
}

// ReleaseV1 ends this borrow once without changing control state or releasing the lock.
func (b *SourceAuthorityBorrowV1) ReleaseV1() {
	if b == nil || b.state == nil {
		return
	}
	s := b.state.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.state.live {
		b.state.live = false
		s.sourceBorrows--
	}
}

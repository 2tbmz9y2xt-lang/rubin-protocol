package policycontrol

import (
	"fmt"
	"math"
	"os"
)

// SourceAuthorityBorrowV1 keeps the Store and its directory lock alive until release.
// It grants no sequence qualification and excludes only Close.
type SourceAuthorityBorrowV1 struct {
	state *sourceAuthorityStateV1
}

type sourceAuthorityStateV1 struct {
	store *Store
	live  bool
}

// BorrowSourceAuthorityV1 admits one source lifetime without holding a transaction or mutex.
// Closed admission precedes UNKNOWN, held transaction/crossing and counter exhaustion.
func (s *Store) BorrowSourceAuthorityV1() (*SourceAuthorityBorrowV1, error) {
	if s == nil {
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

// BindingV1 returns the immutable directory and identity while this borrow is live.
func (b *SourceAuthorityBorrowV1) BindingV1() (string, Identity, error) {
	if b == nil || b.state == nil || b.state.store == nil {
		return "", Identity{}, ErrClosed
	}
	s := b.state.store
	s.mu.Lock()
	if !b.state.live {
		s.mu.Unlock()
		return "", Identity{}, ErrClosed
	}
	dir, id, expected := s.sourceDir, s.st.id, s.sourceInfo
	s.mu.Unlock()
	current, err := os.Lstat(dir)
	if err != nil || !os.SameFile(expected, current) {
		return "", Identity{}, ErrRefused
	}
	return dir, id, nil
}

// ReleaseV1 ends this borrow once without changing control state or releasing the lock.
func (b *SourceAuthorityBorrowV1) ReleaseV1() {
	if b == nil || b.state == nil || b.state.store == nil {
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

package node

import "sync"

// admissionMutex is the canonical-state admission fence. Terminal publication
// keeps its write lock held and wakes readers so they can refuse instead of
// waiting for a restart.
type admissionMutex struct {
	sync.RWMutex
	waitMu   sync.Mutex
	wait     *sync.Cond
	terminal bool
}

// RLockUnlessTerminal waits through ordinary write contention and returns
// false only after terminal publication. A true result owns one read lock.
func (m *admissionMutex) RLockUnlessTerminal() bool {
	m.waitMu.Lock()
	defer m.waitMu.Unlock()
	for !m.terminal {
		if m.TryRLock() {
			return true
		}
		if m.wait == nil {
			m.wait = sync.NewCond(&m.waitMu)
		}
		m.wait.Wait()
	}
	return false
}

// Unlock releases an ordinary writer and wakes readers registered on the
// domain predicate without leaving a check-to-wait gap.
func (m *admissionMutex) Unlock() {
	m.waitMu.Lock()
	m.RWMutex.Unlock()
	if m.wait != nil {
		m.wait.Broadcast()
	}
	m.waitMu.Unlock()
}

// notifyTerminal publishes the monotone terminal predicate. The writer lock
// remains held; this method only wakes current and refuses future readers.
func (m *admissionMutex) notifyTerminal() {
	m.waitMu.Lock()
	m.terminal = true
	if m.wait != nil {
		m.wait.Broadcast()
	}
	m.waitMu.Unlock()
}

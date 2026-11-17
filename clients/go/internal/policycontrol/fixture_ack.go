//go:build rubin_mdbx_fixture

package policycontrol

// FixtureOpenLoseNextCommitAckV1 opens existing P with one private serialized
// acknowledgement loss. Read, no-work and refused operations do not consume it.
// The exact nonnil cause interface is retained, including typed-nil values.
func FixtureOpenLoseNextCommitAckV1(dir string, id Identity, cause error) (*Store, error) {
	if cause == nil {
		return nil, ErrRefused
	}
	h := productionHooks
	consumed := false
	h.fault = func(at stage) error {
		if at != stageAck || consumed {
			return nil
		}
		consumed = true
		return cause
	}
	return start(dir, id, nil, h)
}

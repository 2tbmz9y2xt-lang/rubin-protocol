//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// TestInitial148CompleteBlockFixtureAdmission runs the composer against the
// native tree store inside an existing TreeOperation account: a rejection
// inside UpdateTreeV1's builder must return no operation, so no write occurs.
func TestInitial148CompleteBlockFixtureAdmission(t *testing.T) {
	w := btNew(t)
	in := icbInputV1()
	want := icbStepsErrorV1(t, in)
	icbWithAccountV1(t, w, func(account *mdbx.OperationAccount) {
		out, err := withInitial148CompleteBlockV1(account, in, func(validate func(*mdbx.Reader) (*initial148CompleteBlockResultV1, error)) error {
			return w.s.View(func(reader *mdbx.Reader) error {
				result, verr := validate(reader)
				logicalMDBXAssert(t, result == nil, "rejected candidate delivered a result")
				return verr
			})
		})
		logicalMDBXAssert(t, out.attempted && err != nil && err.Error() == want.Error() && !out.required.derived && !out.required.hasObservation, "fixture rejection: %+v / %v", out, err)
	})
}

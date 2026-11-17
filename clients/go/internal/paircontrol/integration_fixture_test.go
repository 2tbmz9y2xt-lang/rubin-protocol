//go:build rubin_mdbx_fixture

package paircontrol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

type fixtureNilError struct{}

func (*fixtureNilError) Error() string { return "typed nil acknowledgement" }

func TestActualPTerminalUnknownJoin(t *testing.T) {
	var typedNil *fixtureNilError
	direct := errors.New("terminal acknowledgement")
	for _, ending := range []string{"blocked", "success"} {
		for _, cause := range []error{direct, fmt.Errorf("transport: %w", direct), typedNil} {
			t.Run(ending+fmt.Sprintf("/%T", cause), func(t *testing.T) {
				dir := directory(t)
				p, i := h1PolicyAt(t, dir)
				s, _ := existing(t, selected())
				_, err := s.PersistIntentV1(context.Background(), 17, i, p)
				require(t, err)
				_, err = s.RetireV1(context.Background(), 18, i.ID, reference(), p)
				require(t, err)
				nilStore, err := policycontrol.FixtureOpenLoseNextCommitAckV1(dir, identity().Identity, nil)
				if nilStore != nil || !errors.Is(err, policycontrol.ErrRefused) {
					t.Fatal("nil cause did not refuse before held physical lock")
				}
				nilStore, err = policycontrol.FixtureOpenLoseNextCommitAckV1(dir, identity().Identity, cause)
				if nilStore != nil || !errors.Is(err, policycontrol.ErrBusy) {
					t.Fatal("fixture bypassed Open lock")
				}
				require(t, p.Close())
				p, err = policycontrol.FixtureOpenLoseNextCommitAckV1(dir, identity().Identity, cause)
				require(t, err)
				t.Cleanup(func() { require(t, p.Close()) })
				_, err = p.View()
				require(t, err)
				tx, err := p.Begin()
				require(t, err)
				if err = tx.ConsumeIntent(policycontrol.Admission{}); !errors.Is(err, policycontrol.ErrRefused) {
					t.Fatal("invalid edit accepted")
				}
				noWork, err := tx.Commit()
				require(t, err)
				if noWork.Truth != 1 {
					t.Fatal("no-work crossing consumed acknowledgement")
				}
				tx, err = p.Begin()
				require(t, err)
				tx.RetainOwner(originalOwner(i))
				tx.Operation(policycontrol.ClassControl, 1)
				if ending == "blocked" {
					err = tx.AutoBlock()
				} else {
					err = tx.RemoveOnSuccess()
				}
				require(t, err)
				terminal, commitError := tx.Commit()
				if terminal.Truth != 3 || !errors.Is(commitError, cause) || !errors.Is(commitError, policycontrol.ErrUnresolved) {
					t.Fatal("actual first terminal Commit lost UNKNOWN/original cause")
				}
				before := diskBytes(t, s.dir)
				o := installFaults(t, s)
				r, err := s.EndH1V1(context.Background(), 19, i.ID, p)
				e := wantLocal(t, r, err, "end_h1", "refused", ResultV1{1, 19, false})
				if !errors.Is(e.Cause, policycontrol.ErrBusy) || !errors.Is(e.Cause, policycontrol.ErrUnresolved) || errors.Is(e.Cause, cause) {
					t.Fatal("EndH1 did not preserve the reached pending-P refusal")
				}
				if len(o.events) != 0 || !bytes.Equal(before, diskBytes(t, s.dir)) {
					t.Fatal("pending P admitted outer effects")
				}
				if _, err := p.View(); !errors.Is(err, policycontrol.ErrUnresolved) {
					t.Fatal("UNKNOWN P returned a view")
				}
				pr, err := p.Recover()
				require(t, err)
				if pr.Truth != 2 {
					t.Fatal("actual P Recover did not establish NEW")
				}
				r, err = s.EndH1V1(context.Background(), 19, i.ID, p)
				require(t, err)
				if r != (ResultV1{2, 20, false}) {
					t.Fatal("qualified terminal bookkeeping did not advance")
				}
				v := selected()
				v.Sequence, v.Selector, v.Selected = 20, 3, nil
				v.Retired = &RetirementV1{originalPair(), 2, reference()}
				wantRecord(t, s, v)
				policyChange(t, p, policycontrol.Owner{}, func(tx *policycontrol.Tx) error {
					return tx.PutRow(policycontrol.KindAudit, []byte("next"), []byte("normal acknowledgement"))
				})
				require(t, p.Close())
				p, err = policycontrol.Open(dir, identity().Identity)
				require(t, err)
				policyChange(t, p, policycontrol.Owner{}, func(tx *policycontrol.Tx) error {
					return tx.PutRow(policycontrol.KindAudit, []byte("reopen"), []byte("no injection"))
				})
			})
		}
	}
}

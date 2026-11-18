//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

type journalReplaySourcePartsV1 struct {
	BoundBody, ObservedResult, HistoricalContext  []byte
	OriginalAssurance, ParentPath, AcceptedPrefix []byte
}

// withJournalReplaySourceExportV1 exports already-owned immutable views under the caller's live account.
func withJournalReplaySourceExportV1(account *mdbx.OperationAccount, manifest exclusionjournal.SourceManifestV1, parts journalReplaySourcePartsV1, visit func(exclusionjournal.SourcePartV1) error) error {
	views := [][]byte{parts.BoundBody, parts.ObservedResult, parts.HistoricalContext, parts.OriginalAssurance, parts.ParentPath, parts.AcceptedPrefix}
	if err := exclusionjournal.CheckSourceBytesV1(manifest, views); err != nil {
		return err
	}
	backing, err := exclusionjournal.SourceBackingBytesV1(views)
	if err != nil {
		return err
	}
	return account.WithReservation(backing+64*1024+1024, func() error {
		return exclusionjournal.ExportSourceBytesV1(manifest, views, visit)
	})
}

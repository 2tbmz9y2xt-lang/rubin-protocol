//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/exclusionjournal"
)

// withJournalReplaySourceExportV1 exports the original replay views under one backing reservation.
func withJournalReplaySourceExportV1(manifest exclusionjournal.SourceManifestV1, origins []exclusionjournal.SourceOriginV1, views []exclusionjournal.SourceViewV1) (exclusionjournal.SourceExporterV1, error) {
	if _, err := manifest.SizeV1(); err != nil {
		return nil, err
	}
	lengthsMatch := slices.EqualFunc(manifest.Parts, views, func(spec exclusionjournal.SourcePartSpecV1, view exclusionjournal.SourceViewV1) bool {
		return spec.Length == view.Length
	})
	if manifest.Class == exclusionjournal.RecoveryCoreImpossibleV1 || !lengthsMatch || len(origins) > 9 {
		return nil, exclusionjournal.ErrIntegrityV1
	}
	for _, origin := range origins {
		if origin.PlannedBytes != 0 {
			return nil, exclusionjournal.ErrIntegrityV1
		}
	}
	parts, origins, views := slices.Clone(manifest.Parts), slices.Clone(origins), slices.Clone(views)
	return func(op *exclusionjournal.SourceOperationV1, visit func(exclusionjournal.SourcePartV1) error) error {
		return op.WithBackingV1(origins, views, func() error {
			return journalReplayPartsV1(parts, origins, views, visit)
		})
	}, nil
}

// journalReplayPartsV1 stops at the first visitor failure and keeps the original part order.
func journalReplayPartsV1(parts []exclusionjournal.SourcePartSpecV1, origins []exclusionjournal.SourceOriginV1, views []exclusionjournal.SourceViewV1, visit func(exclusionjournal.SourcePartV1) error) error {
	for i, spec := range parts {
		view := views[i]
		var bytes []byte
		if view.Origin >= 0 {
			bytes = origins[view.Origin].Bytes[view.Offset : view.Offset+view.Length]
		}
		part := exclusionjournal.SourcePartV1{Kind: spec.Kind, Length: spec.Length, ReadAt: func(dst []byte, offset int64) (int, error) {
			return copy(dst, bytes[offset:]), nil
		}}
		if err := visit(part); err != nil {
			return err
		}
	}
	return nil
}

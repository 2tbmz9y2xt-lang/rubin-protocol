//go:build !darwin && !linux

package node

import (
	"errors"
	"os"
)

var errNoncanonicalReconstructionUnsupported = errors.New("noncanonical reconstruction is unsupported on this host")

func requireNoncanonicalReconstructionHost() error { return errNoncanonicalReconstructionUnsupported }

func openNoncanonicalArtifactFile(string) (*os.File, error) {
	return nil, errNoncanonicalReconstructionUnsupported
}

func openNoncanonicalDirectory(string) (*os.File, error) {
	return nil, errNoncanonicalReconstructionUnsupported
}

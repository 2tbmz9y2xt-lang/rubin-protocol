package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// ChainDir returns the on-disk directory for a given chain under datadir.
//
// Phase 1 storage model (operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md):
//   datadir/chains/<chain_id_hex>/
func ChainDir(datadir string, chainIDHex string) string {
	return filepath.Join(datadir, "chains", chainIDHex)
}

func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	return nil
}


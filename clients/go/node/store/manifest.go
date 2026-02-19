package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const SchemaVersionV1 uint32 = 1

type Manifest struct {
	SchemaVersion uint32 `json:"schema_version"`
	ChainIDHex    string `json:"chain_id_hex"`

	TipHashHex           string `json:"tip_hash"`
	TipHeight            uint64 `json:"tip_height"`
	TipCumulativeWorkDec string `json:"tip_cumulative_work"`

	LastAppliedBlockHashHex string `json:"last_applied_block_hash"`
	LastAppliedHeight       uint64 `json:"last_applied_height"`
}

func manifestPath(chainDir string) string {
	return filepath.Join(chainDir, "MANIFEST.json")
}

func readManifest(chainDir string) (*Manifest, error) {
	b, err := os.ReadFile(manifestPath(chainDir))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest json: %w", err)
	}
	return &m, nil
}

// writeManifestAtomic writes MANIFEST.json as a crash-safe commit point:
// write temp -> fsync temp -> rename -> fsync dir.
func writeManifestAtomic(chainDir string, m *Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest: nil")
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("manifest json: %w", err)
	}
	b = append(b, '\n')

	final := manifestPath(chainDir)
	tmp := final + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- tmp path is derived from operator-controlled datadir; G302 addressed by 0o600.
	if err != nil {
		return fmt.Errorf("manifest open tmp: %w", err)
	}
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("manifest write tmp: %w", werr)
	}
	if serr != nil {
		return fmt.Errorf("manifest fsync tmp: %w", serr)
	}
	if cerr != nil {
		return fmt.Errorf("manifest close tmp: %w", cerr)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("manifest rename: %w", err)
	}

	// Fsync the directory so rename is durable.
	d, err := os.Open(chainDir) // #nosec G304 -- chainDir is derived from operator-controlled datadir, not user input.
	if err != nil {
		return fmt.Errorf("manifest fsync dir open: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("manifest fsync dir: %w", err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("manifest fsync dir close: %w", err)
	}
	return nil
}

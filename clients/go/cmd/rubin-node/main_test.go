package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node/p2p"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func assertPathMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode %s = %04o, want %04o", path, got, want)
	}
}

type legacyExposureReportJSON struct {
	ReportVersion         uint64  `json:"report_version"`
	MeasurementScope      string  `json:"measurement_scope"`
	Network               string  `json:"network"`
	DataDir               string  `json:"data_dir"`
	ChainstateHeight      uint64  `json:"chainstate_height"`
	ChainstateHasTip      bool    `json:"chainstate_has_tip"`
	IndexedSuiteIDs       []uint8 `json:"indexed_suite_ids"`
	WatchedLegacySuiteIDs []uint8 `json:"watched_legacy_suite_ids"`
	LegacyExposureTotal   uint64  `json:"legacy_exposure_total"`
	SunsetReadiness       string  `json:"sunset_readiness"`
	WarningHook           string  `json:"warning_hook"`
	GraceHook             string  `json:"grace_hook"`
	IncludeOutpoints      bool    `json:"include_outpoints"`
	LegacySuiteReports    []struct {
		SuiteID           uint8    `json:"suite_id"`
		UtxoExposureCount uint64   `json:"utxo_exposure_count"`
		OutpointCount     uint64   `json:"outpoint_count"`
		Outpoints         []string `json:"outpoints"`
	} `json:"legacy_suite_reports"`
}

type legacyExposureHookVectorJSON struct {
	Name                string `json:"name"`
	HasChainstateTip    bool   `json:"has_chainstate_tip"`
	LegacyExposureTotal uint64 `json:"legacy_exposure_total"`
	SunsetReadiness     string `json:"sunset_readiness"`
	WarningHook         string `json:"warning_hook"`
	GraceHook           string `json:"grace_hook"`
}

type legacyExposureHookVectorsJSON struct {
	ContractVersion uint64                         `json:"contract_version"`
	FixtureKind     string                         `json:"fixture_kind"`
	Cases           []legacyExposureHookVectorJSON `json:"cases"`
}

func legacyExposureContractRepoPath(parts ...string) string {
	segments := append([]string{"..", "..", "..", ".."}, parts...)
	return filepath.Join(segments...)
}

func canonicalLegacyExposureHookVectors() []legacyExposureHookVectorJSON {
	return []legacyExposureHookVectorJSON{
		{
			Name:                "no_chainstate_tip_zero_total",
			HasChainstateTip:    false,
			LegacyExposureTotal: 0,
			SunsetReadiness:     "invalid_no_chainstate_tip",
			WarningHook:         "none",
			GraceHook:           "not_applicable_no_chainstate_tip",
		},
		{
			Name:                "no_chainstate_tip_nonzero_total",
			HasChainstateTip:    false,
			LegacyExposureTotal: 5,
			SunsetReadiness:     "invalid_no_chainstate_tip",
			WarningHook:         "none",
			GraceHook:           "not_applicable_no_chainstate_tip",
		},
		{
			Name:                "tipped_chain_zero_exposure",
			HasChainstateTip:    true,
			LegacyExposureTotal: 0,
			SunsetReadiness:     "ready_for_operator_defined_grace_window",
			WarningHook:         "none",
			GraceHook:           "start_operator_defined_grace_window",
		},
		{
			Name:                "tipped_chain_nonzero_exposure",
			HasChainstateTip:    true,
			LegacyExposureTotal: 3,
			SunsetReadiness:     "not_ready_legacy_exposure_present",
			WarningHook:         "legacy_exposure_present_notify_operator_and_council",
			GraceHook:           "not_applicable_legacy_exposure_present",
		},
	}
}

func TestMustTipReturnsExitCode2OnError(t *testing.T) {
	var errOut bytes.Buffer
	_, _, _, code := mustTip(0, [32]byte{}, false, errors.New("boom"), &errOut)
	if code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
	if errOut.Len() == 0 {
		t.Fatalf("expected stderr output")
	}
}

func TestRunReturnsTipExitCodeWhenMustTipNonZero(t *testing.T) {
	prev := mustTipFn
	mustTipFn = func(uint64, [32]byte, bool, error, io.Writer) (uint64, [32]byte, bool, int) {
		return 0, [32]byte{}, false, 2
	}
	t.Cleanup(func() { mustTipFn = prev })

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestMultiStringFlagSetAppends(t *testing.T) {
	var m multiStringFlag
	if err := m.Set("a"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := m.Set("b"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := m.String(); got != "a,b" {
		t.Fatalf("string=%q, want %q", got, "a,b")
	}
}

func TestLegacyExposureHooksNoTipReturnsInvalidState(t *testing.T) {
	readiness, warning, grace := legacyExposureHooks(false, 0)
	if readiness != "invalid_no_chainstate_tip" {
		t.Fatalf("sunset_readiness=%q, want invalid_no_chainstate_tip", readiness)
	}
	if warning != "none" {
		t.Fatalf("warning_hook=%q, want none", warning)
	}
	if grace != "not_applicable_no_chainstate_tip" {
		t.Fatalf("grace_hook=%q, want not_applicable_no_chainstate_tip", grace)
	}
}

func TestLegacyExposureHooksNoTipWithNonZeroTotalReturnsInvalidState(t *testing.T) {
	readiness, warning, grace := legacyExposureHooks(false, 5)
	if readiness != "invalid_no_chainstate_tip" {
		t.Fatalf("sunset_readiness=%q, want invalid_no_chainstate_tip", readiness)
	}
	if warning != "none" {
		t.Fatalf("warning_hook=%q, want none", warning)
	}
	if grace != "not_applicable_no_chainstate_tip" {
		t.Fatalf("grace_hook=%q, want not_applicable_no_chainstate_tip", grace)
	}
}

func TestLegacyExposureHooksWithTipZeroTotalReturnsGraceWindow(t *testing.T) {
	readiness, warning, grace := legacyExposureHooks(true, 0)
	if readiness != "ready_for_operator_defined_grace_window" {
		t.Fatalf("sunset_readiness=%q, want ready_for_operator_defined_grace_window", readiness)
	}
	if warning != "none" {
		t.Fatalf("warning_hook=%q, want none", warning)
	}
	if grace != "start_operator_defined_grace_window" {
		t.Fatalf("grace_hook=%q, want start_operator_defined_grace_window", grace)
	}
}

func TestLegacyExposureHooksWithTipNonZeroTotalReturnsNotReady(t *testing.T) {
	readiness, warning, grace := legacyExposureHooks(true, 3)
	if readiness != "not_ready_legacy_exposure_present" {
		t.Fatalf("sunset_readiness=%q, want not_ready_legacy_exposure_present", readiness)
	}
	if warning != "legacy_exposure_present_notify_operator_and_council" {
		t.Fatalf("warning_hook=%q, want legacy_exposure_present_notify_operator_and_council", warning)
	}
	if grace != "not_applicable_legacy_exposure_present" {
		t.Fatalf("grace_hook=%q, want not_applicable_legacy_exposure_present", grace)
	}
}

func TestLegacyExposureHookVectorsFixtureParity(t *testing.T) {
	raw, err := os.ReadFile(legacyExposureContractRepoPath("conformance", "fixtures", "protocol", "legacy_exposure_hook_vectors.json"))
	if err != nil {
		t.Fatalf("ReadFile(hook vectors): %v", err)
	}
	var doc legacyExposureHookVectorsJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("json.Unmarshal(hook vectors): %v", err)
	}
	if doc.ContractVersion != legacyExposureReportVersion {
		t.Fatalf("contract_version=%d, want %d", doc.ContractVersion, legacyExposureReportVersion)
	}
	if doc.FixtureKind != "legacy_exposure_hook_vectors" {
		t.Fatalf("fixture_kind=%q, want legacy_exposure_hook_vectors", doc.FixtureKind)
	}
	expected := canonicalLegacyExposureHookVectors()
	if !reflect.DeepEqual(doc.Cases, expected) {
		t.Fatalf("hook vectors=%+v, want %+v", doc.Cases, expected)
	}
	for _, c := range doc.Cases {
		t.Run(c.Name, func(t *testing.T) {
			r, w, g := legacyExposureHooks(c.HasChainstateTip, c.LegacyExposureTotal)
			if r != c.SunsetReadiness {
				t.Fatalf("sunset_readiness=%q, want %q", r, c.SunsetReadiness)
			}
			if w != c.WarningHook {
				t.Fatalf("warning_hook=%q, want %q", w, c.WarningHook)
			}
			if g != c.GraceHook {
				t.Fatalf("grace_hook=%q, want %q", g, c.GraceHook)
			}
		})
	}
}

func TestLegacyExposureExampleFixtureMatchesFrozenContract(t *testing.T) {
	raw, err := os.ReadFile(legacyExposureContractRepoPath("conformance", "fixtures", "protocol", "legacy_exposure_report_v1_example.json"))
	if err != nil {
		t.Fatalf("ReadFile(example fixture): %v", err)
	}
	var report legacyExposureReportJSON
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("json.Unmarshal(example fixture): %v", err)
	}
	if report.ReportVersion != legacyExposureReportVersion {
		t.Fatalf("report_version=%d, want %d", report.ReportVersion, legacyExposureReportVersion)
	}
	if report.MeasurementScope != "explicit_suite_id_utxos" {
		t.Fatalf("measurement_scope=%q", report.MeasurementScope)
	}
	if report.Network != "devnet" {
		t.Fatalf("network=%q, want devnet", report.Network)
	}
	if !report.ChainstateHasTip {
		t.Fatalf("expected chainstate_has_tip=true")
	}
	if report.LegacyExposureTotal != 3 {
		t.Fatalf("legacy_exposure_total=%d, want 3", report.LegacyExposureTotal)
	}
	if report.IncludeOutpoints {
		t.Fatalf("expected include_outpoints=false")
	}
	if !reflect.DeepEqual(report.IndexedSuiteIDs, []uint8{consensus.SUITE_ID_ML_DSA_87, 0x42}) {
		t.Fatalf("indexed_suite_ids=%v", report.IndexedSuiteIDs)
	}
	if !reflect.DeepEqual(report.WatchedLegacySuiteIDs, []uint8{consensus.SUITE_ID_ML_DSA_87, 0x42}) {
		t.Fatalf("watched_legacy_suite_ids=%v", report.WatchedLegacySuiteIDs)
	}
	if len(report.LegacySuiteReports) != 2 {
		t.Fatalf("legacy_suite_reports=%d, want 2", len(report.LegacySuiteReports))
	}
	readiness, warning, grace := legacyExposureHooks(report.ChainstateHasTip, report.LegacyExposureTotal)
	if report.SunsetReadiness != readiness {
		t.Fatalf("sunset_readiness=%q, want %q", report.SunsetReadiness, readiness)
	}
	if report.WarningHook != warning {
		t.Fatalf("warning_hook=%q, want %q", report.WarningHook, warning)
	}
	if report.GraceHook != grace {
		t.Fatalf("grace_hook=%q, want %q", report.GraceHook, grace)
	}
}

// seedBlockStore initializes a store the way an operator would with
// --create-store, for tests whose subject is a later startup step.
func seedBlockStore(t *testing.T, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir datadir: %v", err)
	}
	if _, err := node.CreateBlockStore(node.BlockStorePath(dataDir)); err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
}

func TestRunDryRunOK(t *testing.T) {
	dir := t.TempDir()
	seedBlockStore(t, dir)
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--dry-run", "--datadir", dir, "--log-level", "INFO"},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if out.Len() == 0 {
		t.Fatalf("expected stdout output")
	}
	// RUB-1071: --dry-run reports, it does not initialize.
	if _, err := os.Stat(node.ChainStatePath(dir)); !os.IsNotExist(err) {
		t.Fatalf("dry-run must not create a chainstate file: stat err=%v", err)
	}
}

func symlinkTraversalDataDir(t *testing.T) (raw string, cleaned string, escaped string) {
	t.Helper()
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	sep := string(filepath.Separator)
	raw = link + sep + ".." + sep + "chain"
	cleaned = filepath.Clean(raw)
	escaped = filepath.Join(outside, "chain")
	if cleaned == escaped {
		t.Fatalf("invalid fixture: cleaned path equals symlink-resolved escape path %q", cleaned)
	}
	return raw, cleaned, escaped
}

func runNormalizesDataDirBeforeChainStateAndBlockStorePathDerivation(t *testing.T) {
	raw, cleaned, _ := symlinkTraversalDataDir(t)
	seedBlockStore(t, cleaned)
	// Height 7 is the chainstate-path probe: --dry-run no longer writes a
	// snapshot (RUB-1071), so the derivation is proved by reading this one
	// back out of the report instead of by stat-ing a file the run created.
	if err := testLegacyExposureTippedChainState().Save(node.ChainStatePath(cleaned)); err != nil {
		t.Fatalf("seed chainstate: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", raw}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}

	var printed node.Config
	if err := json.NewDecoder(strings.NewReader(out.String())).Decode(&printed); err != nil {
		t.Fatalf("decode printed config: %v\nstdout=%q", err, out.String())
	}
	if printed.DataDir != cleaned {
		t.Fatalf("printed data_dir=%q, want normalized %q", printed.DataDir, cleaned)
	}
	if !strings.Contains(out.String(), "chainstate: has_tip=true height=7") {
		t.Fatalf("chainstate must be read from the normalized datadir, stdout=%q", out.String())
	}
	if info, err := os.Stat(node.BlockStorePath(cleaned)); err != nil {
		t.Fatalf("expected blockstore under normalized datadir: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("blockstore path is not a directory: %s", node.BlockStorePath(cleaned))
	}
}

func TestOperatorPathOwnerInventory(t *testing.T) {
	owners := []struct {
		surface, ownership, cleanCall string
		goOwner                       func(*testing.T)
	}{
		{"--datadir", "shared", "cfg.DataDir = node.NormalizeDataDir(cfg.DataDir)", runNormalizesDataDirBeforeChainStateAndBlockStorePathDerivation},
		{"--genesis-file", "shared", "node.ReadConfigFile(filepath.Clean(path))", runGenesisFileUsesLexicallyNormalizedPath},
		{"--featurebits-deployments", "go-only", "node.ReadConfigFile(filepath.Clean(deploymentsPath))", runFeatureBitsDeploymentsUsesLexicallyNormalizedPath},
	}
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range owners {
		if got := bytes.Count(source, []byte(owner.cleanCall)); got != 1 {
			t.Fatalf("%s clean call count=%d, want 1", owner.surface, got)
		}
		t.Run(owner.ownership+":"+owner.surface, owner.goOwner)
	}
}

func runGenesisFileUsesLexicallyNormalizedPath(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("symlink-plus-parent fixture is Unix-only")
	}
	dir := t.TempDir()
	seedBlockStore(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "other", "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	lexicalID, kernelID := strings.Repeat("11", 32), strings.Repeat("22", 32)
	pack := func(id string) []byte {
		return []byte(fmt.Sprintf(`{"chain_id_hex":%q,"genesis_hash_hex":%q}`, id, strings.Repeat("33", 32)))
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "genesis-pack.json"), pack(lexicalID), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other", "genesis-pack.json"), pack(kernelID), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "other", "real"), filepath.Join(dir, "sub", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	sep := string(filepath.Separator)
	raw := filepath.Join(dir, "sub", "link") + sep + ".." + sep + "genesis-pack.json"
	var out, errOut bytes.Buffer
	code := run([]string{"--network", "testnet", "--dry-run", "--datadir", dir, "--genesis-file", raw}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(out.String(), lexicalID) || strings.Contains(out.String(), kernelID) {
		t.Fatalf("run did not select lexical genesis identity: %q", out.String())
	}
}

func runFeatureBitsDeploymentsUsesLexicallyNormalizedPath(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("symlink-plus-parent fixture is Unix-only")
	}
	dir := preparedDatadir(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "other", "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	deployment := func(name string) []byte {
		return []byte(fmt.Sprintf(`[{"name":%q,"bit":1,"start_height":0,"timeout_height":1000}]`, name))
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "deployments.json"), deployment("lexical-owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "other", "deployments.json"), deployment("kernel-owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "other", "real"), filepath.Join(root, "sub", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	sep := string(filepath.Separator)
	raw := filepath.Join(root, "sub", "link") + sep + ".." + sep + "deployments.json"
	var out, errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir, "--featurebits-deployments", raw}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "lexical-owner") || strings.Contains(out.String(), "kernel-owner") {
		t.Fatalf("run did not select lexical deployment content: %q", out.String())
	}
}

// TestRunRejectsInvalidFeatureBitsDeploymentsBeforeStorage proves the
// RUB-876 guard fires BEFORE any filesystem or service side effect:
// datadir creation, chainstate load/save, blockstore open/create,
// reconcile, and service construction. Pre-hoist, the file was parsed
// only inside the telemetry print AFTER blockstore open + reconcile +
// Save (and silently ignored whenever the store had no tip, as on a
// fresh --create-store run), so the clean-datadir, snapshot, stdout,
// and exit-code assertions all turn red without the hoisted guard.
func TestRunRejectsInvalidFeatureBitsDeploymentsBeforeStorage(t *testing.T) {
	const wantGuardStderr = "invalid featurebits deployments: "
	forbiddenStderr := []string{
		"datadir create failed",
		"chainstate load failed",
		"chainstate reconcile failed",
		"chainstate save failed",
		"blockstore open failed",
		"blockstore create failed",
		"featurebits telemetry failed",
	}
	const invalidRow = `[{"name":"x","bit":1,"start_height":10,"timeout_height":9}]`

	writeDeployments := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "deployments.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write deployments: %v", err)
		}
		return path
	}

	runInvalid := func(t *testing.T, args []string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 {
			t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
		}
		if !strings.Contains(errOut.String(), wantGuardStderr) {
			t.Fatalf("stderr missing featurebits guard error: %q", errOut.String())
		}
		for _, marker := range forbiddenStderr {
			if strings.Contains(errOut.String(), marker) {
				t.Fatalf("storage path reached despite invalid featurebits deployments (%q): %q", marker, errOut.String())
			}
		}
		if out.String() != "" {
			t.Fatalf("expected empty stdout, got %q", out.String())
		}
		return errOut.String()
	}

	t.Run("hostile_inputs_clean_datadir_create_store", func(t *testing.T) {
		for _, tc := range []struct {
			name, content, wantErr string
			missing                bool
		}{
			{name: "missing_file", missing: true},
			{name: "malformed_json", content: "{"},
			{name: "wrong_shape_object", content: `{"name":"x"}`},
			{name: "bit_out_of_range", content: `[{"name":"x","bit":32,"start_height":0,"timeout_height":10}]`, wantErr: "bit out of range"},
			{name: "empty_name", content: `[{"name":"","bit":1,"start_height":0,"timeout_height":10}]`, wantErr: "name required"},
			{name: "timeout_before_start", content: invalidRow, wantErr: "timeout_height < start_height"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "missing.json")
				if !tc.missing {
					path = writeDeployments(t, tc.content)
				}
				datadir := filepath.Join(t.TempDir(), "data")
				stderr := runInvalid(t, []string{
					"--datadir", datadir, "--create-store", "--mine-blocks", "1", "--mine-exit",
					"--featurebits-deployments", path,
				})
				if tc.wantErr != "" && !strings.Contains(stderr, tc.wantErr) {
					t.Fatalf("stderr missing %q: %q", tc.wantErr, stderr)
				}
				if _, err := os.Stat(datadir); !os.IsNotExist(err) {
					t.Fatalf("datadir must not be created on invalid featurebits deployments: stat err=%v", err)
				}
			})
		}
	})

	for _, leg := range []struct {
		name      string
		extraArgs []string
	}{
		{name: "normal_preexisting_datadir"},
		{name: "dry_run_preexisting_datadir", extraArgs: []string{"--dry-run"}},
		// Pre-hoist the scan returned 0 without ever reading the
		// deployments file; this rejection is a disclosed RUB-876 change.
		{name: "legacy_exposure_scan_preexisting_datadir", extraArgs: []string{"--legacy-exposure-scan", "--legacy-suite-id", "1"}},
	} {
		t.Run(leg.name, func(t *testing.T) {
			datadir := preparedDatadir(t)
			before := datadirSnapshot(t, datadir)
			args := append([]string{"--datadir", datadir, "--featurebits-deployments", writeDeployments(t, invalidRow)}, leg.extraArgs...)
			runInvalid(t, args)
			assertNoFilesystemWrite(t, before, datadirSnapshot(t, datadir))
		})
	}
}

// TestRunRejectsInvalidMineAddressBeforeStorage proves the RUB-1135 guard
// fires BEFORE any filesystem or service side effect: datadir creation,
// chainstate load/save, blockstore open/create, reconcile, and service
// construction — on mining and non-mining startups alike. Pre-fix the early
// check only length-checked the decoded hex, so an unsupported-suite_id value
// was caught at the late --mine-blocks site AFTER the whole storage lifecycle
// (exit 2 on a mutated datadir) and, on the RPC path, not at all: it printed
// "rpc: live mining disabled (invalid --mine-address)" and kept running. The
// service stubs turn a regression into a failed assertion instead of a node
// that starts and blocks on its lifecycle ctx.
func TestRunRejectsInvalidMineAddressBeforeStorage(t *testing.T) {
	const wantGuardStderr = "invalid config: mine_address: "
	forbiddenStderr := []string{
		"datadir create failed",
		"chainstate load failed",
		"chainstate reconcile failed",
		"chainstate save failed",
		"blockstore open failed",
		"blockstore create failed",
		"invalid mine-address",
		"rpc: live mining disabled",
	}
	keyID := strings.Repeat("11", 32)

	forbidServiceStart := func(t *testing.T) {
		t.Helper()
		prevSync, prevMempool, prevP2P, prevMiner := newSyncEngineFn, newMempoolFn, newP2PServiceFn, newMinerFn
		newSyncEngineFn = func(*node.ChainState, *node.BlockStore, node.SyncConfig) (*node.SyncEngine, error) {
			t.Error("sync engine constructed despite a rejected --mine-address")
			return nil, errors.New("forbidden by test")
		}
		newMempoolFn = func(*node.ChainState, *node.BlockStore, [32]byte, node.MempoolConfig) (*node.Mempool, error) {
			t.Error("mempool constructed despite a rejected --mine-address")
			return nil, errors.New("forbidden by test")
		}
		newP2PServiceFn = func(p2p.ServiceConfig) (*p2p.Service, error) {
			t.Error("p2p service constructed despite a rejected --mine-address")
			return nil, errors.New("forbidden by test")
		}
		newMinerFn = func(*node.ChainState, *node.BlockStore, *node.SyncEngine, node.MinerConfig) (*node.Miner, error) {
			t.Error("miner constructed despite a rejected --mine-address")
			return nil, errors.New("forbidden by test")
		}
		t.Cleanup(func() {
			newSyncEngineFn, newMempoolFn, newP2PServiceFn, newMinerFn = prevSync, prevMempool, prevP2P, prevMiner
		})
	}

	runInvalid := func(t *testing.T, args []string) {
		t.Helper()
		forbidServiceStart(t)
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 {
			t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
		}
		if !strings.Contains(errOut.String(), wantGuardStderr) {
			t.Fatalf("stderr missing mine-address guard error: %q", errOut.String())
		}
		for _, marker := range forbiddenStderr {
			if strings.Contains(errOut.String(), marker) {
				t.Fatalf("late path reached despite a rejected --mine-address (%q): %q", marker, errOut.String())
			}
		}
		if out.String() != "" {
			t.Fatalf("expected empty stdout, got %q", out.String())
		}
	}

	t.Run("hostile_values_clean_datadir_create_store", func(t *testing.T) {
		for _, tc := range []struct{ name, value string }{
			{name: "unsupported_suite_00", value: "00" + keyID},
			{name: "unsupported_suite_02", value: "02" + keyID},
			{name: "unsupported_suite_ff", value: "ff" + keyID},
			{name: "prefixed_unsupported_suite_ff", value: "0Xff" + keyID},
			{name: "padded_unsupported_suite_ff", value: "  ff" + keyID + "  "},
			{name: "odd_length_hex", value: "abc"},
			{name: "non_hex", value: "0xzz"},
			{name: "short_31_bytes", value: strings.Repeat("11", 31)},
			{name: "long_34_bytes", value: strings.Repeat("11", 34)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				datadir := filepath.Join(t.TempDir(), "data")
				runInvalid(t, []string{
					"--datadir", datadir, "--create-store", "--mine-blocks", "1", "--mine-exit",
					"--mine-address", tc.value,
				})
				if _, err := os.Stat(datadir); !os.IsNotExist(err) {
					t.Fatalf("datadir must not be created on a rejected --mine-address: stat err=%v", err)
				}
			})
		}
	})

	for _, leg := range []struct {
		name      string
		extraArgs []string
	}{
		{name: "non_mining_startup"},
		{name: "mining_startup", extraArgs: []string{"--mine-blocks", "1", "--mine-exit"}},
		{name: "dry_run", extraArgs: []string{"--dry-run"}},
		{name: "rpc_bind_live_mining", extraArgs: []string{"--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"}},
		{name: "legacy_exposure_scan", extraArgs: []string{"--legacy-exposure-scan", "--legacy-suite-id", "1"}},
	} {
		t.Run(leg.name, func(t *testing.T) {
			datadir := preparedDatadir(t)
			before := datadirSnapshot(t, datadir)
			args := append([]string{"--datadir", datadir, "--mine-address", "ff" + keyID}, leg.extraArgs...)
			runInvalid(t, args)
			assertNoFilesystemWrite(t, before, datadirSnapshot(t, datadir))
		})
	}

	// Mixed-violation row: mine_address is validated inside node.ValidateConfig,
	// which runs ahead of the pv-mode guard, so its message wins.
	t.Run("invalid_mine_address_wins_over_invalid_pv_mode", func(t *testing.T) {
		datadir := filepath.Join(t.TempDir(), "data")
		runInvalid(t, []string{
			"--datadir", datadir, "--mine-address", "ff" + keyID, "--pv-mode", "nope",
		})
		if _, err := os.Stat(datadir); !os.IsNotExist(err) {
			t.Fatalf("datadir must not be created: stat err=%v", err)
		}
	})
}

// TestRunPassesParsedMineAddressToMiner pins the accepted side of RUB-1135:
// a 0X-prefixed, whitespace-padded key_id — which ParseMineAddress accepts and
// the pre-fix config check refused outright — reaches the offline-mining miner
// as the exact suite_id||key_id bytes the parser produces.
func TestRunPassesParsedMineAddressToMiner(t *testing.T) {
	prev := newMinerFn
	var captured node.MinerConfig
	newMinerFn = func(_ *node.ChainState, _ *node.BlockStore, _ *node.SyncEngine, cfg node.MinerConfig) (*node.Miner, error) {
		captured = cfg
		return nil, errors.New("capture-only miner")
	}
	t.Cleanup(func() { newMinerFn = prev })

	datadir := filepath.Join(t.TempDir(), "data")
	var out, errOut bytes.Buffer
	code := run([]string{
		"--create-store", "--datadir", datadir, "--mine-blocks", "1", "--mine-exit",
		"--mine-address", "  0X" + strings.Repeat("11", 32) + "  ",
	}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2 from the capture-only miner, got %d (stderr=%q)", code, errOut.String())
	}
	want := append([]byte{consensus.SUITE_ID_ML_DSA_87}, bytes.Repeat([]byte{0x11}, 32)...)
	if !bytes.Equal(captured.MineAddress, want) {
		t.Fatalf("miner cfg.MineAddress=%x, want %x", captured.MineAddress, want)
	}
}

// TestRunEmptyMineAddressFlagLeavesMinerDefault pins the unset/empty flag as
// unchanged: no address is produced and the miner keeps its built-in default.
func TestRunEmptyMineAddressFlagLeavesMinerDefault(t *testing.T) {
	prev := newMinerFn
	var captured node.MinerConfig
	newMinerFn = func(_ *node.ChainState, _ *node.BlockStore, _ *node.SyncEngine, cfg node.MinerConfig) (*node.Miner, error) {
		captured = cfg
		return nil, errors.New("capture-only miner")
	}
	t.Cleanup(func() { newMinerFn = prev })

	datadir := filepath.Join(t.TempDir(), "data")
	var out, errOut bytes.Buffer
	if code := run([]string{
		"--create-store", "--datadir", datadir, "--mine-blocks", "1", "--mine-exit", "--mine-address", "  ",
	}, &out, &errOut); code != 2 {
		t.Fatalf("expected exit code 2 from the capture-only miner, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Equal(captured.MineAddress, node.DefaultMinerConfig().MineAddress) {
		t.Fatalf("miner cfg.MineAddress=%x, want the default %x", captured.MineAddress, node.DefaultMinerConfig().MineAddress)
	}
}

// TestRunEmptyFeatureBitsDeploymentsFlagSkipsValidation pins the flag's
// pre-existing contract that an explicitly empty --featurebits-deployments
// behaves exactly like an unset flag: no file read, no validation, no
// telemetry line. preparedDatadir has a mined tip, so a non-empty valid
// file WOULD print a "featurebits:" line here — the absence assertion
// discriminates on the flag, not on the missing tip.
func TestRunEmptyFeatureBitsDeploymentsFlagSkipsValidation(t *testing.T) {
	datadir := preparedDatadir(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"--dry-run", "--datadir", datadir, "--featurebits-deployments", ""}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d (stderr=%q)", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("empty flag must not write to stderr: %q", errOut.String())
	}
	if strings.Contains(out.String(), "featurebits:") {
		t.Fatalf("empty flag must not emit telemetry: %q", out.String())
	}
}

func TestRunCreatesPrivatePersistencePaths(t *testing.T) {
	datadir := filepath.Join(t.TempDir(), "data")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--create-store", "--datadir", datadir, "--mine-blocks", "1", "--mine-exit"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}

	assertPathMode(t, datadir, 0o700)
	assertPathMode(t, node.ChainStatePath(datadir), 0o600)
	blockstore := node.BlockStorePath(datadir)
	assertPathMode(t, blockstore, 0o700)
	assertPathMode(t, filepath.Join(blockstore, "blocks"), 0o700)
	assertPathMode(t, filepath.Join(blockstore, "headers"), 0o700)
	assertPathMode(t, filepath.Join(blockstore, "undo"), 0o700)

	var reopenOut bytes.Buffer
	var reopenErr bytes.Buffer
	reopenCode := run([]string{"--dry-run", "--datadir", datadir}, &reopenOut, &reopenErr)
	if reopenCode != 0 {
		t.Fatalf("reopen dry-run exit code %d (stderr=%q)", reopenCode, reopenErr.String())
	}
}

func testLegacyExposureP2PKCovenantData(suiteID uint8) []byte {
	cov := make([]byte, consensus.MAX_P2PK_COVENANT_DATA)
	cov[0] = suiteID
	return cov
}

func testLegacyExposureTippedChainState() *node.ChainState {
	state := node.NewChainState()
	state.HasTip = true
	state.Height = 7
	state.TipHash = [32]byte{0x42}
	return state
}

func TestRunLegacyExposureScanEmitsDeterministicJSON(t *testing.T) {
	dir := t.TempDir()
	state := node.NewChainState()
	state.HasTip = true
	state.Height = 42
	first := consensus.Outpoint{Txid: [32]byte{0x01}, Vout: 0}
	second := consensus.Outpoint{Txid: [32]byte{0x02}, Vout: 1}
	third := consensus.Outpoint{Txid: [32]byte{0x03}, Vout: 2}
	state.Utxos[first] = consensus.UtxoEntry{
		Value:             10,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testLegacyExposureP2PKCovenantData(consensus.SUITE_ID_ML_DSA_87),
		CreationHeight:    2,
		CreatedByCoinbase: false,
	}
	state.Utxos[second] = consensus.UtxoEntry{
		Value:             11,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testLegacyExposureP2PKCovenantData(0x42),
		CreationHeight:    3,
		CreatedByCoinbase: false,
	}
	state.Utxos[third] = consensus.UtxoEntry{
		Value:             12,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testLegacyExposureP2PKCovenantData(0x42),
		CreationHeight:    4,
		CreatedByCoinbase: false,
	}
	if err := state.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save(chainstate): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", dir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "0x42",
			"--legacy-suite-id", "1",
			"--legacy-suite-id", "0x42",
		},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}

	var report legacyExposureReportJSON
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal(raw): %v", err)
	}
	if report.ReportVersion != legacyExposureReportVersion {
		t.Fatalf("report_version=%d, want %d", report.ReportVersion, legacyExposureReportVersion)
	}
	if report.MeasurementScope != "explicit_suite_id_utxos" {
		t.Fatalf("measurement_scope=%q", report.MeasurementScope)
	}
	if report.Network != "devnet" {
		t.Fatalf("network=%q, want devnet", report.Network)
	}
	if !reflect.DeepEqual(report.WatchedLegacySuiteIDs, []uint8{consensus.SUITE_ID_ML_DSA_87, 0x42}) {
		t.Fatalf("watched ids=%v", report.WatchedLegacySuiteIDs)
	}
	if !reflect.DeepEqual(report.IndexedSuiteIDs, []uint8{consensus.SUITE_ID_ML_DSA_87, 0x42}) {
		t.Fatalf("indexed ids=%v", report.IndexedSuiteIDs)
	}
	indexedRaw, ok := raw["indexed_suite_ids"].([]any)
	if !ok {
		t.Fatalf("indexed_suite_ids encoded as %T, want JSON array", raw["indexed_suite_ids"])
	}
	if len(indexedRaw) != 2 || indexedRaw[0] != float64(consensus.SUITE_ID_ML_DSA_87) || indexedRaw[1] != float64(0x42) {
		t.Fatalf("indexed_suite_ids raw=%v", indexedRaw)
	}
	watchedRaw, ok := raw["watched_legacy_suite_ids"].([]any)
	if !ok {
		t.Fatalf("watched_legacy_suite_ids encoded as %T, want JSON array", raw["watched_legacy_suite_ids"])
	}
	if len(watchedRaw) != 2 || watchedRaw[0] != float64(consensus.SUITE_ID_ML_DSA_87) || watchedRaw[1] != float64(0x42) {
		t.Fatalf("watched_legacy_suite_ids raw=%v", watchedRaw)
	}
	if report.LegacyExposureTotal != 3 {
		t.Fatalf("legacy exposure total=%d, want 3", report.LegacyExposureTotal)
	}
	if report.SunsetReadiness != "not_ready_legacy_exposure_present" {
		t.Fatalf("sunset readiness=%q", report.SunsetReadiness)
	}
	if report.WarningHook != "legacy_exposure_present_notify_operator_and_council" {
		t.Fatalf("warning hook=%q", report.WarningHook)
	}
	if report.GraceHook != "not_applicable_legacy_exposure_present" {
		t.Fatalf("grace hook=%q", report.GraceHook)
	}
	if len(report.LegacySuiteReports) != 2 {
		t.Fatalf("legacy suite reports=%d, want 2", len(report.LegacySuiteReports))
	}
	if report.LegacySuiteReports[0].SuiteID != consensus.SUITE_ID_ML_DSA_87 || report.LegacySuiteReports[0].UtxoExposureCount != 1 {
		t.Fatalf("suite report[0]=%+v", report.LegacySuiteReports[0])
	}
	if report.LegacySuiteReports[1].SuiteID != 0x42 || report.LegacySuiteReports[1].UtxoExposureCount != 2 {
		t.Fatalf("suite report[1]=%+v", report.LegacySuiteReports[1])
	}
}

func TestRunLegacyExposureScanIncludesOutpoints(t *testing.T) {
	dir := t.TempDir()
	state := testLegacyExposureTippedChainState()
	first := consensus.Outpoint{Txid: [32]byte{0x02}, Vout: 1}
	second := consensus.Outpoint{Txid: [32]byte{0x01}, Vout: 0}
	state.Utxos[first] = consensus.UtxoEntry{
		Value:             11,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testLegacyExposureP2PKCovenantData(0x42),
		CreationHeight:    3,
		CreatedByCoinbase: false,
	}
	state.Utxos[second] = consensus.UtxoEntry{
		Value:             12,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      testLegacyExposureP2PKCovenantData(0x42),
		CreationHeight:    4,
		CreatedByCoinbase: false,
	}
	if err := state.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save(chainstate): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", dir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "66",
			"--legacy-exposure-include-outpoints",
		},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}

	var report legacyExposureReportJSON
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if !report.IncludeOutpoints {
		t.Fatalf("expected include_outpoints=true")
	}
	if len(report.LegacySuiteReports) != 1 {
		t.Fatalf("legacy suite reports=%d, want 1", len(report.LegacySuiteReports))
	}
	if report.LegacyExposureTotal != 2 {
		t.Fatalf("legacy exposure total=%d, want 2", report.LegacyExposureTotal)
	}
	if report.LegacySuiteReports[0].UtxoExposureCount != 2 {
		t.Fatalf("utxo_exposure_count=%d, want 2", report.LegacySuiteReports[0].UtxoExposureCount)
	}
	if report.LegacySuiteReports[0].OutpointCount != 2 {
		t.Fatalf("outpoint_count=%d, want 2", report.LegacySuiteReports[0].OutpointCount)
	}
	want := []string{
		"0100000000000000000000000000000000000000000000000000000000000000:0",
		"0200000000000000000000000000000000000000000000000000000000000000:1",
	}
	if !reflect.DeepEqual(report.LegacySuiteReports[0].Outpoints, want) {
		t.Fatalf("outpoints=%v, want %v", report.LegacySuiteReports[0].Outpoints, want)
	}
}

func TestRunLegacyExposureScanEmitsEmptyOutpointsWhenDetailModeHasNoMatches(t *testing.T) {
	dir := t.TempDir()
	if err := testLegacyExposureTippedChainState().Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save(chainstate): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", dir,
			"--network", "mainnet",
			"--legacy-exposure-scan",
			"--legacy-suite-id", "1",
			"--legacy-exposure-include-outpoints",
		},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}

	var report legacyExposureReportJSON
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(report.LegacySuiteReports) != 1 {
		t.Fatalf("legacy suite reports=%d, want 1", len(report.LegacySuiteReports))
	}
	if report.LegacyExposureTotal != 0 {
		t.Fatalf("legacy exposure total=%d, want 0", report.LegacyExposureTotal)
	}
	if report.LegacySuiteReports[0].UtxoExposureCount != 0 {
		t.Fatalf("utxo_exposure_count=%d, want 0", report.LegacySuiteReports[0].UtxoExposureCount)
	}
	if report.LegacySuiteReports[0].OutpointCount != 0 {
		t.Fatalf("outpoint_count=%d, want 0", report.LegacySuiteReports[0].OutpointCount)
	}
	if report.LegacySuiteReports[0].Outpoints == nil {
		t.Fatalf("expected outpoints field to be present as [] in detail mode")
	}
	if len(report.LegacySuiteReports[0].Outpoints) != 0 {
		t.Fatalf("outpoints=%v, want []", report.LegacySuiteReports[0].Outpoints)
	}
}

func TestRunLegacyExposureScanRejectsMissingSuiteIDs(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", dir, "--legacy-exposure-scan"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "requires at least one --legacy-suite-id") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestRunLegacyExposureScanRequiresExistingChainstateWithTip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", dir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "1",
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "legacy exposure scan requires an existing chainstate file with a tip") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestRunLegacyExposureScanRequiresChainstateTip(t *testing.T) {
	dir := t.TempDir()
	if err := node.NewChainState().Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save(chainstate): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", dir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "1",
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "legacy exposure scan requires a chainstate with a tip") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestLoadLegacyExposureScanChainStateIncludesPathOnStatFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}
	path := filepath.Join(blocker, "chainstate.json")

	_, err := loadLegacyExposureScanChainState(path)
	if err == nil {
		t.Fatal("expected stat failure")
	}
	if !strings.Contains(err.Error(), "legacy exposure scan chainstate stat failed for "+path) {
		t.Fatalf("err=%q", err)
	}
}

func TestLoadLegacyExposureScanChainStateIncludesPathOnLoadFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chainstate.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(chainstate): %v", err)
	}

	_, err := loadLegacyExposureScanChainState(path)
	if err == nil {
		t.Fatal("expected load failure")
	}
	if !strings.Contains(err.Error(), "chainstate load failed for "+path) {
		t.Fatalf("err=%q", err)
	}
}

func TestRunLegacyExposureScanRejectsInvalidSuiteID(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", blocker,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "0x100",
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "invalid legacy suite_id") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestRunLegacyExposureScanValidatesSuiteIDsBeforeDataDirCreate(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", blocker, "--legacy-exposure-scan"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "requires at least one --legacy-suite-id") {
		t.Fatalf("stderr=%q", errOut.String())
	}
	if strings.Contains(errOut.String(), "datadir create failed") {
		t.Fatalf("suite-id validation ran too late: %q", errOut.String())
	}
}

func TestRunLegacyExposureScanDoesNotRequireGenesisFileForNamedNetwork(t *testing.T) {
	dir := t.TempDir()
	state := testLegacyExposureTippedChainState()
	if err := state.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save(chainstate): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", dir,
			"--network", "mainnet",
			"--legacy-exposure-scan",
			"--legacy-suite-id", "1",
		},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}

	var report legacyExposureReportJSON
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if report.Network != "mainnet" {
		t.Fatalf("network=%q, want mainnet", report.Network)
	}
	if report.LegacyExposureTotal != 0 {
		t.Fatalf("legacy exposure total=%d, want 0", report.LegacyExposureTotal)
	}
}

func TestRunRejectsLegacyExposureFlagsWithoutScanMode(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", blocker,
			"--legacy-suite-id", "1",
			"--legacy-exposure-include-outpoints",
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "legacy exposure flags require --legacy-exposure-scan") {
		t.Fatalf("stderr=%q", errOut.String())
	}
	if strings.Contains(errOut.String(), "datadir create failed") {
		t.Fatalf("scanner-only flags should fail before datadir create: %q", errOut.String())
	}
}

func TestRunRejectsNonDevnetWithoutGenesisFileBeforeDataDirCreate(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--network", "mainnet", "--datadir", blocker}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "requires a genesis file (--genesis-file)") {
		t.Fatalf("stderr=%q", errOut.String())
	}
	if strings.Contains(errOut.String(), "datadir create failed") {
		t.Fatalf("genesis validation should run before datadir create: %q", errOut.String())
	}
}

func TestRunRejectsInvalidGenesisFileBeforeDataDirCreate(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}
	genesisPath := filepath.Join(dir, "invalid-genesis.json")
	if err := os.WriteFile(genesisPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile(genesis): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--network", "mainnet",
			"--datadir", blocker,
			"--genesis-file", genesisPath,
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(errOut.String(), "invalid genesis file:") {
		t.Fatalf("stderr=%q", errOut.String())
	}
	if strings.Contains(errOut.String(), "datadir create failed") {
		t.Fatalf("invalid genesis should fail before datadir create: %q", errOut.String())
	}
}

// writeGenesisPackForTest serializes a minimal devnet genesis pack to a
// temp file. Both chain_id and genesis_hash are mandatory to exercise
// the boot-time identity guards: parseGenesisConfigFull rejects missing
// hash via parseGenesisHash, so a wrong-hash test still needs a valid
// 32-byte hex value (just one that disagrees with canonical).
func writeGenesisPackForTest(t *testing.T, dir string, chainID, genesisHash [32]byte) string {
	t.Helper()
	pack := map[string]string{
		"chain_id_hex":     hex.EncodeToString(chainID[:]),
		"genesis_hash_hex": hex.EncodeToString(genesisHash[:]),
	}
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("json.Marshal(genesis pack): %v", err)
	}
	path := filepath.Join(dir, "genesis-pack.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

// TestRunRejectsDevnetWrongChainIDBeforeDataDirCreate proves the
// boot-time devnet identity guard fires BEFORE os.MkdirAll(cfg.DataDir).
// The blocker-file at --datadir would force os.MkdirAll to fail with
// "datadir create failed" if the guard skipped or ran after MkdirAll;
// the asymmetric assertion (stderr contains the guard error AND does
// NOT contain "datadir create failed") is what proves the ordering, not
// just rejection. Reverting the guard to its old post-MkdirAll position
// turns this test red.
func TestRunRejectsDevnetWrongChainIDBeforeDataDirCreate(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}
	wrongChainID := node.DevnetGenesisChainID()
	wrongChainID[0] ^= 0x01
	genesisPath := writeGenesisPackForTest(t, dir, wrongChainID, node.DevnetGenesisBlockHash())

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--network", "devnet",
			"--datadir", blocker,
			"--genesis-file", genesisPath,
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "devnet genesis identity guard failed") {
		t.Fatalf("stderr missing guard prefix: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "genesis chain_id mismatch") {
		t.Fatalf("stderr missing chain_id mismatch class: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "datadir create failed") {
		t.Fatalf("devnet identity guard must reject before datadir create: %q", errOut.String())
	}
}

// TestRunRejectsDevnetWrongHashBeforeDataDirCreate is the genesis_hash
// counterpart of TestRunRejectsDevnetWrongChainIDBeforeDataDirCreate.
// chain_id stays canonical so the helper passes the chain_id arm and
// reaches the hash arm, locking in that both arms run pre-MkdirAll.
func TestRunRejectsDevnetWrongHashBeforeDataDirCreate(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}
	wrongHash := node.DevnetGenesisBlockHash()
	wrongHash[0] ^= 0x01
	genesisPath := writeGenesisPackForTest(t, dir, node.DevnetGenesisChainID(), wrongHash)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--network", "devnet",
			"--datadir", blocker,
			"--genesis-file", genesisPath,
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "devnet genesis identity guard failed") {
		t.Fatalf("stderr missing guard prefix: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "genesis_hash mismatch") {
		t.Fatalf("stderr missing genesis_hash mismatch class: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "datadir create failed") {
		t.Fatalf("devnet identity guard must reject before datadir create: %q", errOut.String())
	}
}

// TestRunRejectsMainnetMisconfigBeforeDataDirCreate covers the third
// boot-time guard arm: ValidateMainnetGenesisGuard rejects a mainnet
// runtime that did not wire ExpectedTarget. The CLI does not expose an
// expected-target flag yet, so any --network mainnet invocation
// currently fails the guard with "mainnet requires explicit
// expected_target". The asymmetric assertion proves the guard runs
// pre-MkdirAll: if the guard moved back below MkdirAll, the blocker
// file would force a "datadir create failed" stderr line.
func TestRunRejectsMainnetMisconfigBeforeDataDirCreate(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}
	// Valid genesis-pack shape — chain_id / genesis_hash are devnet
	// canonical, which is fine on mainnet because the devnet identity
	// guard is gated on cfg.Network == "devnet" and skips here.
	genesisPath := writeGenesisPackForTest(t, dir, node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash())

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{
			"--network", "mainnet",
			"--datadir", blocker,
			"--genesis-file", genesisPath,
		},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "mainnet genesis guard failed") {
		t.Fatalf("stderr missing mainnet guard prefix: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "mainnet requires explicit expected_target") {
		t.Fatalf("stderr missing expected_target class: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "datadir create failed") {
		t.Fatalf("mainnet guard must reject before datadir create: %q", errOut.String())
	}
}

// TestRunRejectsInvalidPVModeBeforeStorage proves the RUB-665 pv-mode
// guard fires BEFORE any filesystem or service side effect: datadir
// creation, chainstate load/save, blockstore open, reconcile, service
// construction, and the legacy-exposure-scan chainstate read. Invalid
// legs use otherwise-valid config, so the only guards ahead of the
// pv-mode guard are pure parse/normalize steps (flag parse,
// ValidateConfig, NormalizeDataDir, CanonicalNetworkName) — the test
// cannot pass through an unrelated early rejection. The asymmetric
// assertions (guard stderr present, storage stderr absent, filesystem
// untouched, service sentinels silent) prove ordering, not just
// rejection: on the old ordering pv-mode was parsed only inside
// NewSyncEngine after MkdirAll+LoadChainState+reconcile+Save (normal
// path) and silently ignored on the scan path (exit 0), so the clean
// datadir, snapshot, and scan legs all turn red without the guard.
func TestRunRejectsInvalidPVModeBeforeStorage(t *testing.T) {
	const invalidMode = "nope"
	const wantGuardStderr = `invalid pv-mode: invalid parallel_validation_mode: "nope" (want off|shadow|on)`
	storageStderr := []string{
		"datadir create failed",
		"chainstate load failed",
		"chainstate reconcile failed",
		"chainstate save failed",
		"blockstore open failed",
	}

	forbidServiceStart := func(t *testing.T) {
		t.Helper()
		prevSync, prevMempool, prevP2P, prevMiner := newSyncEngineFn, newMempoolFn, newP2PServiceFn, newMinerFn
		newSyncEngineFn = func(st *node.ChainState, store *node.BlockStore, cfg node.SyncConfig) (*node.SyncEngine, error) {
			t.Error("newSyncEngineFn called despite invalid pv-mode")
			return prevSync(st, store, cfg)
		}
		newMempoolFn = func(st *node.ChainState, store *node.BlockStore, chainID [32]byte, cfg node.MempoolConfig) (*node.Mempool, error) {
			t.Error("newMempoolFn called despite invalid pv-mode")
			return prevMempool(st, store, chainID, cfg)
		}
		newP2PServiceFn = func(cfg p2p.ServiceConfig) (*p2p.Service, error) {
			t.Error("newP2PServiceFn called despite invalid pv-mode")
			return prevP2P(cfg)
		}
		newMinerFn = func(st *node.ChainState, store *node.BlockStore, engine *node.SyncEngine, cfg node.MinerConfig) (*node.Miner, error) {
			t.Error("newMinerFn called despite invalid pv-mode")
			return prevMiner(st, store, engine, cfg)
		}
		t.Cleanup(func() {
			newSyncEngineFn, newMempoolFn, newP2PServiceFn, newMinerFn = prevSync, prevMempool, prevP2P, prevMiner
		})
	}

	snapshotDir := func(t *testing.T, root string) map[string]string {
		t.Helper()
		snap := make(map[string]string)
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				snap[path] = "<dir>"
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			snap[path] = string(raw)
			return nil
		}); err != nil {
			t.Fatalf("snapshot %s: %v", root, err)
		}
		return snap
	}

	runInvalid := func(t *testing.T, args []string) (stdout, stderr string) {
		t.Helper()
		forbidServiceStart(t)
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		if code != 2 {
			t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
		}
		if !strings.Contains(errOut.String(), wantGuardStderr) {
			t.Fatalf("stderr missing pv-mode guard error: %q", errOut.String())
		}
		for _, marker := range storageStderr {
			if strings.Contains(errOut.String(), marker) {
				t.Fatalf("storage path reached despite invalid pv-mode (%q): %q", marker, errOut.String())
			}
		}
		return out.String(), errOut.String()
	}

	for _, leg := range []struct {
		name      string
		extraArgs []string
	}{
		{name: "normal_clean_datadir"},
		{name: "dry_run_clean_datadir", extraArgs: []string{"--dry-run"}},
	} {
		t.Run(leg.name, func(t *testing.T) {
			datadir := filepath.Join(t.TempDir(), "data")
			args := append([]string{"--datadir", datadir, "--pv-mode", invalidMode}, leg.extraArgs...)
			stdout, _ := runInvalid(t, args)
			if stdout != "" {
				t.Fatalf("expected empty stdout, got %q", stdout)
			}
			if _, err := os.Stat(datadir); !os.IsNotExist(err) {
				t.Fatalf("datadir must not be created on invalid pv-mode: stat err=%v", err)
			}
		})
	}

	t.Run("preexisting_datadir_byte_identical", func(t *testing.T) {
		datadir := filepath.Join(t.TempDir(), "data")
		seedBlockStore(t, datadir)
		var out, errOut bytes.Buffer
		if code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut); code != 0 {
			t.Fatalf("seed dry-run exit code %d (stderr=%q)", code, errOut.String())
		}
		before := snapshotDir(t, datadir)
		stdout, _ := runInvalid(t, []string{"--datadir", datadir, "--pv-mode", invalidMode})
		if stdout != "" {
			t.Fatalf("expected empty stdout, got %q", stdout)
		}
		if after := snapshotDir(t, datadir); !reflect.DeepEqual(before, after) {
			t.Fatalf("pre-existing datadir mutated on invalid pv-mode:\nbefore=%v\nafter=%v", before, after)
		}
	})

	t.Run("legacy_exposure_scan_tipped_chainstate", func(t *testing.T) {
		datadir := t.TempDir()
		if err := testLegacyExposureTippedChainState().Save(node.ChainStatePath(datadir)); err != nil {
			t.Fatalf("Save(chainstate): %v", err)
		}
		before := snapshotDir(t, datadir)
		stdout, stderr := runInvalid(t, []string{
			"--datadir", datadir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "1",
			"--pv-mode", invalidMode,
		})
		if stdout != "" {
			t.Fatalf("scan must not emit a report on invalid pv-mode, stdout=%q", stdout)
		}
		if strings.Contains(stderr, "legacy exposure") {
			t.Fatalf("scan path reached despite invalid pv-mode: %q", stderr)
		}
		if after := snapshotDir(t, datadir); !reflect.DeepEqual(before, after) {
			t.Fatalf("datadir mutated on invalid pv-mode scan leg")
		}
	})

	t.Run("legacy_exposure_scan_missing_chainstate", func(t *testing.T) {
		datadir := filepath.Join(t.TempDir(), "missing")
		stdout, stderr := runInvalid(t, []string{
			"--datadir", datadir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "1",
			"--pv-mode", invalidMode,
		})
		if stdout != "" {
			t.Fatalf("expected empty stdout, got %q", stdout)
		}
		if strings.Contains(stderr, "legacy exposure") {
			t.Fatalf("scan chainstate precondition ran before pv-mode guard: %q", stderr)
		}
		if _, err := os.Stat(datadir); !os.IsNotExist(err) {
			t.Fatalf("datadir must not be created: stat err=%v", err)
		}
	})

	// This leg pins the branch-entry ordering: the pv-mode guard must reject before the legacy-exposure-scan branch runs its own config normalization.
	t.Run("invalid_pv_mode_with_malformed_suite_id_scan", func(t *testing.T) {
		datadir := filepath.Join(t.TempDir(), "missing")
		stdout, stderr := runInvalid(t, []string{
			"--datadir", datadir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "999",
			"--pv-mode", invalidMode,
		})
		if stdout != "" {
			t.Fatalf("expected empty stdout, got %q", stdout)
		}
		if strings.Contains(stderr, "legacy exposure scan config failed") {
			t.Fatalf("scan branch config normalization ran before pv-mode guard: %q", stderr)
		}
		if _, err := os.Stat(datadir); !os.IsNotExist(err) {
			t.Fatalf("datadir must not be created: stat err=%v", err)
		}
	})

	t.Run("valid_modes_preserved", func(t *testing.T) {
		for _, mode := range []string{"off", "shadow", "on", "", "OFF", " on "} {
			datadir := filepath.Join(t.TempDir(), "data")
			seedBlockStore(t, datadir)
			var out, errOut bytes.Buffer
			code := run([]string{"--dry-run", "--datadir", datadir, "--pv-mode", mode}, &out, &errOut)
			if code != 0 {
				t.Fatalf("valid pv-mode %q exit code %d (stderr=%q)", mode, code, errOut.String())
			}
			// The report reaches the storage path (it renders the
			// blockstore banner). It replaces a chainstate-file stat,
			// which RUB-1071 made a dry-run write rather than evidence.
			if !strings.Contains(out.String(), "blockstore: empty") {
				t.Fatalf("valid pv-mode %q: storage path not reached, stdout=%q", mode, out.String())
			}
		}
	})
}

func TestRunLegacyExposureScanPropagatesEncodeFailure(t *testing.T) {
	dir := t.TempDir()
	if err := testLegacyExposureTippedChainState().Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save(chainstate): %v", err)
	}

	var errOut bytes.Buffer
	code := run(
		[]string{
			"--datadir", dir,
			"--legacy-exposure-scan",
			"--legacy-suite-id", "1",
		},
		failWriter{},
		&errOut,
	)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "legacy exposure encode failed") {
		t.Fatalf("stderr=%q", errOut.String())
	}
}

func TestSaturatingAddUint64(t *testing.T) {
	if got := saturatingAddUint64(5, 7); got != 12 {
		t.Fatalf("saturatingAddUint64(5, 7)=%d, want 12", got)
	}
	if got := saturatingAddUint64(math.MaxUint64-1, 2); got != math.MaxUint64 {
		t.Fatalf("saturatingAddUint64(max-1, 2)=%d, want %d", got, uint64(math.MaxUint64))
	}
}

// stopAfterChainStateSave fails the sync-engine constructor, the first step
// past the reconcile+save pair. Ordinary startup otherwise runs services
// until signaled, so rows whose subject is the reconcile or the save need a
// deterministic terminator; reaching it also pins both steps as pre-service.
// RUB-1071 moved these rows off --dry-run, which no longer runs either step.
func stopAfterChainStateSave(t *testing.T) {
	t.Helper()
	prev := newSyncEngineFn
	newSyncEngineFn = func(*node.ChainState, *node.BlockStore, node.SyncConfig) (*node.SyncEngine, error) {
		return nil, errors.New("stop after reconcile+save")
	}
	t.Cleanup(func() { newSyncEngineFn = prev })
}

func TestRunStartupReconcilesChainStateFromBlockStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	store, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	state := node.NewChainState()
	engine, err := node.NewSyncEngine(state, store, node.DefaultSyncConfig(&target, node.DevnetGenesisChainID(), chainStatePath))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	if err := node.NewChainState().Save(chainStatePath); err != nil {
		t.Fatalf("Save(stale chainstate): %v", err)
	}
	stopAfterChainStateSave(t)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("run code=%d, want 2 (stderr=%q)", code, errOut.String())
	}

	loaded, err := node.LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 0 || loaded.TipHash != node.DevnetGenesisBlockHash() {
		t.Fatalf("unexpected reconciled chainstate: has_tip=%v height=%d tip=%x", loaded.HasTip, loaded.Height, loaded.TipHash)
	}
}

func TestParseGenesisChainIDEmptyDefaultsToDevnet(t *testing.T) {
	got, err := parseGenesisChainID("")
	if err != nil {
		t.Fatalf("parseGenesisChainID: %v", err)
	}
	if got != node.DevnetGenesisChainID() {
		t.Fatalf("chain_id=%x, want %x", got, node.DevnetGenesisChainID())
	}
}

func TestParseGenesisConfigEmptyDefaultsToDevnet(t *testing.T) {
	chainID, genesisHash, err := parseGenesisConfig("")
	if err != nil {
		t.Fatalf("parseGenesisConfig: %v", err)
	}
	if chainID != node.DevnetGenesisChainID() {
		t.Fatalf("chain_id=%x, want %x", chainID, node.DevnetGenesisChainID())
	}
	if genesisHash != node.DevnetGenesisBlockHash() {
		t.Fatalf("genesis_hash=%x, want %x", genesisHash, node.DevnetGenesisBlockHash())
	}
}

func TestParseGenesisConfigReadsGenesisHashFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(path, []byte(`{"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103","genesis_hash_hex":"0x8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff"}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	chainID, genesisHash, err := parseGenesisConfig(path)
	if err != nil {
		t.Fatalf("parseGenesisConfig: %v", err)
	}
	if chainID != node.DevnetGenesisChainID() {
		t.Fatalf("chain_id=%x, want %x", chainID, node.DevnetGenesisChainID())
	}
	if genesisHash != node.DevnetGenesisBlockHash() {
		t.Fatalf("genesis_hash=%x, want %x", genesisHash, node.DevnetGenesisBlockHash())
	}
}

func TestParseGenesisConfigReadsGenesisBlockHashFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(path, []byte(`{"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103","genesis_block_hash_hex":"0x8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff"}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	_, genesisHash, err := parseGenesisConfig(path)
	if err != nil {
		t.Fatalf("parseGenesisConfig: %v", err)
	}
	if genesisHash != node.DevnetGenesisBlockHash() {
		t.Fatalf("genesis_hash=%x, want %x", genesisHash, node.DevnetGenesisBlockHash())
	}
}

func TestParseGenesisConfigDerivesHashFromHeaderFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	headerHex := hex.EncodeToString(node.DevnetGenesisBlockBytes()[:consensus.BLOCK_HEADER_BYTES])
	if err := os.WriteFile(path, []byte(`{"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103","genesis_header_bytes_hex":"`+headerHex+`"}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	_, genesisHash, err := parseGenesisConfig(path)
	if err != nil {
		t.Fatalf("parseGenesisConfig: %v", err)
	}
	if genesisHash != node.DevnetGenesisBlockHash() {
		t.Fatalf("genesis_hash=%x, want %x", genesisHash, node.DevnetGenesisBlockHash())
	}
}

func TestParseGenesisConfigRejectsMissingGenesisHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(path, []byte(`{"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103"}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	if _, _, err := parseGenesisConfig(path); err == nil || err.Error() != "genesis hash missing" {
		t.Fatalf("expected genesis hash missing error, got %v", err)
	}
}

func TestParseGenesisConfigFullReadFileError(t *testing.T) {
	_, err := parseGenesisConfigFull(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil {
		t.Fatalf("expected read error")
	}
}

func TestParseGenesisConfigFullRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(path, []byte(`{"chain_id_hex"`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	if _, err := parseGenesisConfigFull(path); err == nil {
		t.Fatalf("expected json error")
	}
}

func TestParseGenesisConfigFullRejectsInvalidChainID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	genesisHashBytes := node.DevnetGenesisBlockHash()
	genesisHash := hex.EncodeToString(genesisHashBytes[:])
	if err := os.WriteFile(path, []byte(`{"chain_id_hex":"zz","genesis_hash_hex":"0x`+genesisHash+`"}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	if _, err := parseGenesisConfigFull(path); err == nil {
		t.Fatalf("expected chain_id parse error")
	}
}

func TestParseGenesisConfigFullRejectsRemovedCoreExtFields(t *testing.T) {
	dir := t.TempDir()
	chainIDBytes := node.DevnetGenesisChainID()
	genesisHashBytes := node.DevnetGenesisBlockHash()
	chainID := hex.EncodeToString(chainIDBytes[:])
	genesisHash := hex.EncodeToString(genesisHashBytes[:])

	for _, tc := range []struct {
		name  string
		field string
		value string
	}{
		{name: "profiles", field: "core_ext_profiles", value: `[]`},
		{name: "profile_set_anchor", field: "core_ext_profile_set_anchor_hex", value: `"00"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			payload := `{"chain_id_hex":"0x` + chainID + `","genesis_hash_hex":"0x` + genesisHash + `","` + tc.field + `":` + tc.value + `}`
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatalf("write genesis file: %v", err)
			}

			if _, err := parseGenesisConfigFull(path); err == nil || !strings.Contains(err.Error(), `unsupported genesis field "`+tc.field+`"`) {
				t.Fatalf("expected removed field rejection for %s, got %v", tc.field, err)
			}
		})
	}
}

func TestParseGenesisHashRejectsInvalidHeaderBytes(t *testing.T) {
	if _, err := parseGenesisHash(genesisPack{GenesisHeaderBytesHex: "zz"}); err == nil {
		t.Fatalf("expected invalid hex error")
	}
	if _, err := parseGenesisHash(genesisPack{GenesisHeaderBytesHex: "00"}); err == nil {
		t.Fatalf("expected invalid header length error")
	}
}

func TestRunDryRunUsesDevnetGenesisChainIDByDefault(t *testing.T) {
	prev := newSyncEngineFn
	var gotCfg node.SyncConfig
	newSyncEngineFn = func(st *node.ChainState, store *node.BlockStore, cfg node.SyncConfig) (*node.SyncEngine, error) {
		gotCfg = cfg
		return node.NewSyncEngine(st, store, cfg)
	}
	t.Cleanup(func() { newSyncEngineFn = prev })

	dir := t.TempDir()
	seedBlockStore(t, dir)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	want := node.DevnetGenesisChainID()
	if gotCfg.ChainID != want {
		t.Fatalf("sync chain_id=%x, want %x", gotCfg.ChainID, want)
	}
	if !bytes.Contains(out.Bytes(), []byte(hex.EncodeToString(want[:]))) {
		t.Fatalf("expected effective config to print devnet chain_id, got %q", out.String())
	}
}

func TestRunPassesMempoolLimitsToMempoolAndPrintsConfig(t *testing.T) {
	prev := newMempoolFn
	var captured node.MempoolConfig
	newMempoolFn = func(st *node.ChainState, store *node.BlockStore, chainID [32]byte, cfg node.MempoolConfig) (*node.Mempool, error) {
		captured = cfg
		return node.NewMempoolWithConfig(st, store, chainID, cfg)
	}
	t.Cleanup(func() { newMempoolFn = prev })

	dir := t.TempDir()
	seedBlockStore(t, dir)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir, "--mempool-max-txs", "7", "--mempool-max-bytes", "4096"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if captured.MaxTransactions != 7 {
		t.Fatalf("mempool MaxTransactions=%d, want 7", captured.MaxTransactions)
	}
	if captured.MaxBytes != 4096 {
		t.Fatalf("mempool MaxBytes=%d, want 4096", captured.MaxBytes)
	}
	if !strings.Contains(out.String(), `"mempool_max_txs": 7`) {
		t.Fatalf("printed config missing mempool_max_txs: %q", out.String())
	}
	if !strings.Contains(out.String(), `"mempool_max_bytes": 4096`) {
		t.Fatalf("printed config missing mempool_max_bytes: %q", out.String())
	}
}

func TestRunWiresP2PToCanonicalMempool(t *testing.T) {
	prev := newP2PServiceFn
	var captured p2p.ServiceConfig
	newP2PServiceFn = func(cfg p2p.ServiceConfig) (*p2p.Service, error) {
		captured = cfg
		return nil, errors.New("capture p2p config")
	}
	t.Cleanup(func() { newP2PServiceFn = prev })

	dir := t.TempDir()
	seedBlockStore(t, dir)
	var errOut bytes.Buffer
	code := run([]string{"--datadir", dir, "--bind", "127.0.0.1:0", "--rpc-bind", ""}, io.Discard, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2 from captured p2p init, got %d (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "capture p2p config") {
		t.Fatalf("stderr=%q, want capture error", errOut.String())
	}
	if _, ok := captured.TxPool.(*p2p.CanonicalMempoolTxPool); !ok {
		t.Fatalf("p2p TxPool type=%T, want *p2p.CanonicalMempoolTxPool", captured.TxPool)
	}
	if captured.TxMetadataFunc == nil {
		t.Fatal("expected p2p TxMetadataFunc")
	}
	meta, err := captured.TxMetadataFunc([]byte{0xFF})
	if err != nil {
		t.Fatalf("canonical p2p TxMetadataFunc should be lightweight, got %v", err)
	}
	if meta.Size != 1 {
		t.Fatalf("canonical p2p metadata size=%d, want 1", meta.Size)
	}
}

func TestApplySuiteContextToSyncConfig(t *testing.T) {
	syncCfg := node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), "")
	registry := consensus.DefaultSuiteRegistry()
	rotation := consensus.DescriptorRotationProvider{
		Descriptor: consensus.CryptoRotationDescriptor{
			Name:         "rotation-test",
			OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
			NewSuiteID:   0x02,
			CreateHeight: 100,
			SpendHeight:  120,
		},
	}

	applySuiteContextToSyncConfig(&syncCfg, rotation, registry)

	if syncCfg.RotationProvider == nil {
		t.Fatalf("expected sync config rotation provider to be propagated")
	}
	if syncCfg.SuiteRegistry == nil {
		t.Fatalf("expected sync config suite registry to be propagated")
	}
}

func TestApplySuiteContextToSyncConfig_NilConfig(t *testing.T) {
	registry := consensus.DefaultSuiteRegistry()
	rotation := consensus.DescriptorRotationProvider{
		Descriptor: consensus.CryptoRotationDescriptor{
			Name:         "rotation-test",
			OldSuiteID:   consensus.SUITE_ID_ML_DSA_87,
			NewSuiteID:   0x02,
			CreateHeight: 100,
			SpendHeight:  120,
		},
	}

	applySuiteContextToSyncConfig(nil, rotation, registry)
}

func TestRunDryRunShowsTipWhenBlockstoreHasTip(t *testing.T) {
	dir := t.TempDir()

	blockStore, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	chainState := node.NewChainState()
	syncCfg := node.DefaultSyncConfig(nil, node.DevnetGenesisChainID(), node.ChainStatePath(dir))
	engine, err := node.NewSyncEngine(chainState, blockStore, syncCfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("blockstore: tip_height=")) {
		t.Fatalf("expected tip output, got %q", out.String())
	}
}

// unreplayableStoreDataDir commits a canonical entry whose block payload is
// not a parseable block, so the reconcile's replay fails.
func unreplayableStoreDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	blockStore, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	parsed, err := consensus.ParseBlockBytes(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	if err := blockStore.CommitCanonicalBlock(0, node.DevnetGenesisBlockHash(), parsed.HeaderBytes, []byte{0x00}, &node.BlockUndo{}); err != nil {
		t.Fatalf("CommitCanonicalBlock: %v", err)
	}
	return dir
}

func TestRunStartupFailsWhenChainstateReconcileFails(t *testing.T) {
	dir := unreplayableStoreDataDir(t)
	stopAfterChainStateSave(t)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("chainstate reconcile failed")) {
		t.Fatalf("expected reconcile failure in stderr, got %q", errOut.String())
	}
}

// TestRunGenesisAnchorRefusesForeignDatadir drives the RUB-1134 genesis anchor
// through run(): the node-package anchor test calls the BlockStore method
// directly, so deleting this call site would leave every other suite green.
// Row 0 here is a foreign chain's genesis, so a mutating startup must exit 2 on
// the anchor message BEFORE the reconcile adopts anything and without touching
// the datadir; --dry-run adopts nothing and therefore still exits 0.
func TestRunGenesisAnchorRefusesForeignDatadir(t *testing.T) {
	dir := t.TempDir()
	store, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	// A COHERENT foreign row 0: header, block bytes and index row agree, so the
	// stored-identity checks all pass and only the anchor can refuse it.
	block := append([]byte(nil), node.DevnetGenesisBlockBytes()...)
	block[consensus.BLOCK_HEADER_BYTES-1] ^= 0x01 // another chain's genesis
	header := block[:consensus.BLOCK_HEADER_BYTES]
	foreign, err := consensus.BlockHash(header)
	if err != nil {
		t.Fatalf("BlockHash(foreign genesis): %v", err)
	}
	if foreign == node.DevnetGenesisBlockHash() {
		t.Fatalf("fixture is not foreign")
	}
	if err := store.CommitCanonicalBlock(0, foreign, header, block, &node.BlockUndo{}); err != nil {
		t.Fatalf("CommitCanonicalBlock: %v", err)
	}
	// Scoped to the blockstore subtree, where all canonical state lives: a
	// mutating startup legitimately creates its datadir-root lock files
	// (.rubin.lock, .rubin-atomic-write.lock) before the anchor runs, and those
	// are infrastructure, not state. The marker bytes cover the CONTENT axis
	// the snapshot does not.
	storeRoot := node.BlockStorePath(dir)
	marker := filepath.Join(storeRoot, "index.json")
	before := datadirSnapshot(t, storeRoot)
	markerBefore, err := os.ReadFile(marker) // #nosec G304 -- test-local path.
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}

	// --mine-blocks/--mine-exit only bound the run: the anchor rejects long
	// before the miner starts. Measured with the anchor call site deleted, a
	// plain `--datadir` startup ACCEPTS this datadir and serves forever (the
	// contract's "a coherent foreign datadir boots silently today"), so the
	// bounded form keeps the regression signal fast and loud.
	var out, errOut bytes.Buffer
	if code := run([]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit"}, &out, &errOut); code != 2 {
		t.Fatalf("run code=%d, want 2 (stderr=%q)", code, errOut.String())
	}
	const want = "canonical index genesis anchor failed: STORE_INTEGRITY: canonical index genesis mismatch"
	if !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr=%q, want %q", errOut.String(), want)
	}
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, storeRoot))
	if markerAfter, err := os.ReadFile(marker); err != nil || !bytes.Equal(markerAfter, markerBefore) {
		t.Fatalf("the refused startup rewrote the canonical index: %q (%v)", markerAfter, err)
	}
	if _, err := os.Lstat(node.ChainStatePath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused startup wrote a chainstate: %v", err)
	}

	out.Reset()
	errOut.Reset()
	if code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("dry-run code=%d, want 0 (stderr=%q)", code, errOut.String())
	}
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, storeRoot))
}

// A datadir the reconcile cannot replay is exactly when an operator reaches
// for --dry-run. It must not inherit the startup rejection above: --dry-run
// never runs the reconcile, so it reports the store as found and exits 0.
func TestRunDryRunReportsUnreplayableStoreWithoutFailing(t *testing.T) {
	dir := unreplayableStoreDataDir(t)
	before := datadirSnapshot(t, dir)

	report := dryRunReport(t, dir)
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
	if !strings.Contains(report, "blockstore: tip_height=0 ") {
		t.Fatalf("report must show the canonical tip as found on disk, stdout=%q", report)
	}
}

func TestRunInvalidConfigMaxPeers(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--dry-run", "--datadir", dir, "--max-peers", "0"},
		&out,
		&errOut,
	)
	if code == 0 {
		t.Fatalf("expected non-zero exit code")
	}
}

func TestRunInvalidConfigMempoolLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "txs", args: []string{"--mempool-max-txs", "0"}, want: "mempool_max_txs"},
		{name: "bytes", args: []string{"--mempool-max-bytes", "0"}, want: "mempool_max_bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var out bytes.Buffer
			var errOut bytes.Buffer
			args := append([]string{"--dry-run", "--datadir", dir}, tc.args...)
			code := run(args, &out, &errOut)
			if code != 2 {
				t.Fatalf("code=%d, want 2", code)
			}
			if !strings.Contains(errOut.String(), "invalid config") || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("stderr=%q, want %s validation error", errOut.String(), tc.want)
			}
		})
	}
}

func TestRunMineBlocksExitOK(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--create-store", "--datadir", dir, "--mine-blocks", "1", "--mine-exit"},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("mined:")) {
		t.Fatalf("expected mined output, got %q", out.String())
	}
}

func TestRunMineBlocksResetsDirtyChainStateWhenBlockstoreEmpty(t *testing.T) {
	dir := t.TempDir()
	seedBlockStore(t, dir)
	chainState := node.NewChainState()
	chainState.HasTip = true
	chainState.Height = math.MaxUint64
	chainState.AlreadyGenerated = 123
	var phantomTxid [32]byte
	phantomTxid[0] = 0xaa
	chainState.Utxos[consensus.Outpoint{Txid: phantomTxid, Vout: 1}] = consensus.UtxoEntry{Value: 7}
	if err := chainState.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("save chainstate: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit"},
		&out,
		&errOut,
	)
	if code != 0 {
		t.Fatalf("expected exit code 0 after fail-closed reset, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("mined:")) {
		t.Fatalf("expected mined output after dirty chainstate reset, got %q", out.String())
	}
}

func TestRunMineBlocksFailsWhenMinerInitFails(t *testing.T) {
	prev := newMinerFn
	newMinerFn = func(*node.ChainState, *node.BlockStore, *node.SyncEngine, node.MinerConfig) (*node.Miner, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { newMinerFn = prev })

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

// offlineMinerSentinelFloor is a distinctive rolling-floor value injected
// into the mempool BEFORE the offline-mining miner is constructed in
// TestRunMineBlocksPassesMineAddressToMiner. Picked far above
// DefaultMempoolMinFeeRate=1 and not equal to any other floor value the
// mempool might compute organically (DefaultMempoolMaxBytes, etc.) so
// `captured.CurrentMempoolMinFeeRateFn() == offlineMinerSentinelFloor`
// is a deterministic proof of liveness — a constant closure returning
// any other value would fail the check.
const offlineMinerSentinelFloor uint64 = 0xCAFEF00DDEAD

func TestRunMineBlocksPassesMineAddressToMiner(t *testing.T) {
	prevMiner := newMinerFn
	prevMempool := newMempoolFn
	var captured node.MinerConfig
	newMinerFn = func(_ *node.ChainState, _ *node.BlockStore, _ *node.SyncEngine, cfg node.MinerConfig) (*node.Miner, error) {
		captured = cfg
		return nil, errors.New("boom")
	}
	newMempoolFn = func(st *node.ChainState, store *node.BlockStore, chainID [32]byte, cfg node.MempoolConfig) (*node.Mempool, error) {
		mp, err := node.NewMempoolWithConfig(st, store, chainID, cfg)
		if err != nil {
			return nil, err
		}
		mp.SetCurrentMinFeeRateForTest(offlineMinerSentinelFloor)
		return mp, nil
	}
	t.Cleanup(func() {
		newMinerFn = prevMiner
		newMempoolFn = prevMempool
	})

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{"--create-store", "--datadir", dir, "--mine-blocks", "1", "--mine-exit", "--mine-address", strings.Repeat("11", 32)},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if len(captured.MineAddress) != consensus.MAX_P2PK_COVENANT_DATA {
		t.Fatalf("mine address len=%d, want %d", len(captured.MineAddress), consensus.MAX_P2PK_COVENANT_DATA)
	}
	if captured.MineAddress[0] != consensus.SUITE_ID_ML_DSA_87 {
		t.Fatalf("mine address suite=%d, want %d", captured.MineAddress[0], consensus.SUITE_ID_ML_DSA_87)
	}
	// Pin T-D production wiring at the offline-mining miner instantiation
	// site (cmd/rubin-node/main.go around the `if *mineBlocks > 0` block).
	// The miner template MUST receive a non-nil CurrentMempoolMinFeeRateFn
	// so relay_fee_floor reads the rolling local floor exposed by the live
	// mempool, not the static baseline. A future edit that drops this
	// wiring would let the miner template admit DA candidates the mempool
	// admit path would reject.
	//
	// The captured non-nil + >= DefaultMempoolMinFeeRate sanity check is
	// not enough on its own — a constant closure that returns
	// DefaultMempoolMinFeeRate would pass it while reintroducing the
	// original T-D bug. Only the second assertion below proves liveness:
	// a distinctive sentinel was injected into the mempool's rolling
	// floor BEFORE the miner was constructed, and the captured closure
	// MUST observe that exact value.
	if captured.CurrentMempoolMinFeeRateFn == nil {
		t.Fatal("offline-mining miner cfg missing CurrentMempoolMinFeeRateFn; T-D production wiring regressed")
	}
	if got := captured.CurrentMempoolMinFeeRateFn(); got != offlineMinerSentinelFloor {
		t.Fatalf("offline-mining provider returned %d, want sentinel %d; closure is not bound to the live mempool snapshot", got, offlineMinerSentinelFloor)
	}
	if captured.CompleteDASetProvider != nil {
		t.Fatal("offline-mining miner cfg should not receive a DA complete-set provider without a p2p service")
	}
}

func TestRunMainnetFailsWithoutGenesisFileBeforeExplicitTargetCheck(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir, "--network", "mainnet"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !bytes.Contains(errOut.Bytes(), []byte("requires a genesis file (--genesis-file)")) {
		t.Fatalf("unexpected stderr: %q", errOut.String())
	}
}

func TestRunMainnetFailsBeforeReconcilingChainState(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	store, err := node.CreateBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	target := consensus.POW_LIMIT
	state := node.NewChainState()
	engine, err := node.NewSyncEngine(state, store, node.DefaultSyncConfig(&target, node.DevnetGenesisChainID(), chainStatePath))
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	if _, err := engine.ApplyBlock(node.DevnetGenesisBlockBytes(), nil); err != nil {
		t.Fatalf("ApplyBlock(genesis): %v", err)
	}
	if err := node.NewChainState().Save(chainStatePath); err != nil {
		t.Fatalf("Save(stale chainstate): %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir, "--network", "mainnet"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("requires a genesis file (--genesis-file)")) {
		t.Fatalf("unexpected stderr: %q", errOut.String())
	}

	loaded, err := node.LoadChainState(chainStatePath)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	if loaded.HasTip || loaded.Height != 0 || loaded.TipHash != ([32]byte{}) || len(loaded.Utxos) != 0 {
		t.Fatalf("mainnet guard should prevent reconcile mutation: has_tip=%v height=%d tip=%x utxos=%d", loaded.HasTip, loaded.Height, loaded.TipHash, len(loaded.Utxos))
	}
}

func TestRunDryRunEmitsRPCBindAddrWhenPresent(t *testing.T) {
	dir := t.TempDir()
	seedBlockStore(t, dir)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir, "--rpc-bind", "127.0.0.1:19112"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(`"rpc_bind_addr": "127.0.0.1:19112"`)) {
		t.Fatalf("expected rpc_bind_addr in config, got %q", out.String())
	}
}

func TestRunFailsWhenSyncEngineInitFails(t *testing.T) {
	prev := newSyncEngineFn
	newSyncEngineFn = func(*node.ChainState, *node.BlockStore, node.SyncConfig) (*node.SyncEngine, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { newSyncEngineFn = prev })

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunParseErrorUnknownFlag(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--dry-run", "--datadir", dir, "--unknown-flag"},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunDatadirCreateFailsWhenDatadirIsFile(t *testing.T) {
	tmp := t.TempDir()
	datadir := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(datadir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunChainstateLoadFailsWhenChainstatePathIsDir(t *testing.T) {
	datadir := t.TempDir()
	chainstatePath := node.ChainStatePath(datadir)
	if err := os.MkdirAll(chainstatePath, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

// Rows that provoke a write failure by chmod'ing the datadir read-only —
// TestRunChainstateSaveFailsWhenDatadirNotWritable,
// TestRunStartupFailsWhenChainstateSaveFails and
// TestRunDryRunReportsOnAReadOnlyDatadir — live in main_unix_test.go behind
// a `//go:build unix` tag: they must skip as root, and os.Geteuid() is
// Unix-only (Copilot review feedback on PR #1218).

func TestRunFailsWhenBlockStoreOpenFails(t *testing.T) {
	datadir := t.TempDir()
	blockStorePath := node.BlockStorePath(datadir)
	if err := os.WriteFile(blockStorePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunPrintConfigFailsWhenStdoutFails(t *testing.T) {
	datadir := t.TempDir()
	seedBlockStore(t, datadir)
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, failWriter{}, &errOut)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestNowUnixU64ReturnsZeroWhenUnixTimeNonPositive(t *testing.T) {
	prev := nowUnix
	nowUnix = func() int64 { return 0 }
	t.Cleanup(func() { nowUnix = prev })

	if got := nowUnixU64(); got != 0 {
		t.Fatalf("nowUnixU64=%d, want 0", got)
	}
}

func TestMainExitCodeIs0OnDryRun(t *testing.T) {
	if os.Getenv("RUBIN_NODE_CHILD") == "1" {
		datadir := t.TempDir()
		seedBlockStore(t, datadir)
		os.Args = []string{"rubin-node", "--dry-run", "--datadir", datadir}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainExitCodeIs0OnDryRun")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_CHILD=1")
	err := cmd.Run()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stderr=%s)", ee.ExitCode(), string(ee.Stderr))
		}
		t.Fatalf("unexpected error: %v", err)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type runningBannerCapture struct {
	lockedBuffer
	pending  []byte
	observed bool
	ready    chan struct{}
}

func newRunningBannerCapture() *runningBannerCapture {
	return &runningBannerCapture{ready: make(chan struct{}, 1)}
}

func (c *runningBannerCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.buf.Write(p)
	c.pending = append(c.pending, p...)
	for {
		newline := bytes.IndexByte(c.pending, '\n')
		if newline < 0 {
			break
		}
		line := c.pending[:newline]
		c.pending = c.pending[newline+1:]
		if !c.observed && string(line) == "rubin-node skeleton running" {
			c.observed = true
			c.ready <- struct{}{}
		}
	}
	return n, err
}

func (c *runningBannerCapture) Observed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observed
}

func runChildAfterRunningBanner(t *testing.T, cmd *exec.Cmd) (string, string, error) {
	t.Helper()

	stdout := newRunningBannerCapture()
	stderr := new(lockedBuffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v (stdout=%q stderr=%q)", err, stdout.String(), stderr.String())
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()

	terminateAndReap := func(reason string) {
		killErr := cmd.Process.Kill()
		waitErr := <-waitDone
		t.Fatalf("%s (kill=%v wait=%v banner=%t stdout=%q stderr=%q)", reason, killErr, waitErr, stdout.Observed(), stdout.String(), stderr.String())
	}

	select {
	case <-stdout.ready:
		if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
			killErr := cmd.Process.Kill()
			waitErr := <-waitDone
			if waitErr != nil {
				return stdout.String(), stderr.String(), waitErr
			}
			t.Fatalf("Signal(SIGINT): %v (kill=%v wait=%v banner=%t stdout=%q stderr=%q)", err, killErr, waitErr, stdout.Observed(), stdout.String(), stderr.String())
		}
	case waitErr := <-waitDone:
		if waitErr != nil {
			return stdout.String(), stderr.String(), waitErr
		}
		if stdout.Observed() {
			return stdout.String(), stderr.String(), errors.New("child exited after running banner before parent sent SIGINT")
		}
		return stdout.String(), stderr.String(), errors.New("child exited before running banner")
	case <-timer.C:
		select {
		case waitErr := <-waitDone:
			if waitErr != nil {
				return stdout.String(), stderr.String(), waitErr
			}
			return stdout.String(), stderr.String(), errors.New("child exited before parent completed ready-then-SIGINT contract")
		default:
		}
		terminateAndReap("timeout waiting for running banner")
	}

	select {
	case waitErr := <-waitDone:
		return stdout.String(), stderr.String(), waitErr
	case <-timer.C:
		terminateAndReap("timeout waiting for child exit after SIGINT")
	}
	panic("unreachable")
}

func TestRunNonDryRunExitsOnSignal(t *testing.T) {
	if os.Getenv("RUBIN_NODE_SIGNAL_CHILD") == "1" {
		dir := t.TempDir()
		code := run([]string{"--create-store", "--datadir", dir, "--bind", "127.0.0.1:0"}, os.Stdout, os.Stderr)
		os.Exit(code)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunNonDryRunExitsOnSignal")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_SIGNAL_CHILD=1")
	stdout, stderr, err := runChildAfterRunningBanner(t, cmd)
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stdout=%s stderr=%s)", ee.ExitCode(), stdout, stderr)
		}
		t.Fatalf("unexpected error: %v (stdout=%s stderr=%s)", err, stdout, stderr)
	}
}

func TestRunFailsWhenRPCBindPortUnavailable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{"--create-store", "--datadir", dir, "--bind", "127.0.0.1:0", "--rpc-bind", listener.Addr().String()},
		&out,
		&errOut,
	)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("rpc start failed")) {
		t.Fatalf("expected rpc start failure, got stderr=%q", errOut.String())
	}
	if bytes.Contains(out.Bytes(), []byte("rubin-node skeleton running")) {
		t.Fatalf("unexpected running banner in stdout=%q", out.String())
	}
}

func TestRunNonDryRunWithRPCBindExitsOnSignal(t *testing.T) {
	if os.Getenv("RUBIN_NODE_SIGNAL_RPC_CHILD") == "1" {
		dir := t.TempDir()
		code := run(
			[]string{"--create-store", "--datadir", dir, "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"},
			os.Stdout,
			os.Stderr,
		)
		os.Exit(code)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunNonDryRunWithRPCBindExitsOnSignal")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_SIGNAL_RPC_CHILD=1")
	stdout, stderr, err := runChildAfterRunningBanner(t, cmd)
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stdout=%s stderr=%s)", ee.ExitCode(), stdout, stderr)
		}
		t.Fatalf("unexpected error: %v (stdout=%s stderr=%s)", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "rpc: listening=") {
		t.Fatalf("stdout=%q, want rpc listening line", stdout)
	}
	if !strings.Contains(stdout, "rubin-node skeleton running") {
		t.Fatalf("stdout=%q, want running banner", stdout)
	}
	if !strings.Contains(stdout, "rubin-node skeleton stopped") {
		t.Fatalf("stdout=%q, want stopped banner", stdout)
	}
}

// TestRunRPCBindReadyEndpointReportsLifecycle proves the operator-visible
// readiness contract end-to-end: in a real `run()` subprocess with
// --rpc-bind set, the parent observes (a) the rpc:listening= banner, (b)
// the "rubin-node skeleton running" banner — used as a barrier confirming
// TryMarkReadyOnStartup has fired — (c) GET /ready returns 200 with body
// {"ready":true} while the node is live, (d) on SIGINT the child exits 0
// after printing the "stopped" banner. Reverting either the TryMarkReadyOnStartup
// call or the MarkShutdown-before-drain ordering turns this red.
//
// Coverage rationale: handler-level unit tests in http_rpc_test.go pin the
// 200/503 mapping deterministically. This test pins the cmd/rubin-node
// wiring — that the flag is actually toggled by the boot sequence and not
// just exposed as a method nobody calls.
func TestRunRPCBindReadyEndpointReportsLifecycle(t *testing.T) {
	if os.Getenv("RUBIN_NODE_READY_LIFECYCLE_CHILD") == "1" {
		dir := t.TempDir()
		code := run(
			[]string{"--create-store", "--datadir", dir, "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"},
			os.Stdout,
			os.Stderr,
		)
		os.Exit(code)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunRPCBindReadyEndpointReportsLifecycle")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_READY_LIFECYCLE_CHILD=1")
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
	})

	rpcAddrCh := make(chan string, 1)
	runningCh := make(chan struct{})
	stoppedCh := make(chan struct{})
	var stdoutMu sync.Mutex
	var stdoutBuf bytes.Buffer
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stdoutPipe)
		runningClosed := false
		stoppedClosed := false
		for scanner.Scan() {
			line := scanner.Text()
			stdoutMu.Lock()
			stdoutBuf.WriteString(line)
			stdoutBuf.WriteByte('\n')
			stdoutMu.Unlock()
			if strings.HasPrefix(line, "rpc: listening=") {
				select {
				case rpcAddrCh <- strings.TrimPrefix(line, "rpc: listening="):
				default:
				}
			}
			if !runningClosed && strings.Contains(line, "rubin-node skeleton running") {
				close(runningCh)
				runningClosed = true
			}
			if !stoppedClosed && strings.Contains(line, "rubin-node skeleton stopped") {
				close(stoppedCh)
				stoppedClosed = true
			}
		}
	}()

	var rpcAddr string
	select {
	case rpcAddr = <-rpcAddrCh:
	case <-time.After(20 * time.Second):
		stdoutMu.Lock()
		dump := stdoutBuf.String()
		stdoutMu.Unlock()
		t.Fatalf("timeout waiting for rpc:listening= banner; stdout so far=%q", dump)
	}

	// Wait for the "running" banner so TryMarkReadyOnStartup is guaranteed to
	// have fired before we hit /ready. The banner is printed immediately
	// after rpcServer.TryMarkReadyOnStartup in cmd/rubin-node/main.go.
	select {
	case <-runningCh:
	case <-time.After(20 * time.Second):
		stdoutMu.Lock()
		dump := stdoutBuf.String()
		stdoutMu.Unlock()
		t.Fatalf("timeout waiting for running banner; stdout so far=%q", dump)
	}

	// Bounded HTTP timeout prevents the integration test from blocking on a
	// wedged child until the outer `go test` deadline fires. 10 s is ample
	// for a localhost devnet /ready response (typically <1 ms) and short
	// enough to surface child hangs as a clean test failure.
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get("http://" + rpcAddr + "/ready")
	if err != nil {
		t.Fatalf("http.Get /ready: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/ready status=%d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"ready":true`) {
		t.Fatalf("/ready body=%q, want ready:true", body)
	}

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("Signal(SIGINT): %v", err)
	}
	if err := cmd.Wait(); err != nil {
		ee := new(exec.ExitError)
		if errors.As(err, &ee) {
			t.Fatalf("child exit=%d, want 0", ee.ExitCode())
		}
		t.Fatalf("Wait: %v", err)
	}
	<-scanDone
	select {
	case <-stoppedCh:
	default:
		stdoutMu.Lock()
		dump := stdoutBuf.String()
		stdoutMu.Unlock()
		t.Fatalf("missing stopped banner after clean exit; stdout=%q", dump)
	}

	// Runtime evidence audit: the production main.go entrypoint MUST
	// emit the audit banners in a specific stdout order — "rpc:
	// ready=true" before "rubin-node skeleton running" (boot-time
	// TryMarkReadyOnStartup executed at the all-subsystems-up
	// boundary), and "rpc: ready=false" between "skeleton running"
	// and "skeleton stopped" (shutdown-time MarkShutdown executed
	// after <-ctx.Done() and before the deferred drain). What this
	// audit pins is the BANNER ORDERING through main.go's run() —
	// not the gate behavior itself (the gate's locked
	// observeShutdownLocked already stamps Shutdown when shutdownCtx
	// is canceled, even if MarkShutdown is never called). A
	// regression that drops the boot-time banner emit, the shutdown-
	// time banner emit, or that reorders them relative to the
	// running/stopped banners turns the index assertions below red.
	// This is the deterministic alternative to a post-SIGINT HTTP
	// poll, which cannot observe stable /ready state because
	// http.Server.Shutdown immediately closes new accepts.
	stdoutMu.Lock()
	full := stdoutBuf.String()
	stdoutMu.Unlock()
	readyTrueIdx := strings.Index(full, "rpc: ready=true")
	if readyTrueIdx < 0 {
		t.Fatalf("missing 'rpc: ready=true' boot-time runtime evidence; stdout=%q", full)
	}
	runningIdx := strings.Index(full, "rubin-node skeleton running")
	if runningIdx < 0 || readyTrueIdx > runningIdx {
		t.Fatalf("expected 'rpc: ready=true' before 'skeleton running'; stdout=%q", full)
	}
	readyFalseIdx := strings.Index(full, "rpc: ready=false")
	if readyFalseIdx < 0 {
		t.Fatalf("missing 'rpc: ready=false' shutdown-time runtime evidence; stdout=%q", full)
	}
	stoppedIdx := strings.Index(full, "rubin-node skeleton stopped")
	if stoppedIdx < 0 || readyFalseIdx > stoppedIdx {
		t.Fatalf("expected 'rpc: ready=false' before 'skeleton stopped'; stdout=%q", full)
	}
	if readyFalseIdx <= runningIdx {
		t.Fatalf("expected 'rpc: ready=false' AFTER 'skeleton running'; stdout=%q", full)
	}
}

// TestRunDevnetWithRPCBindInvalidMineAddressExitsBeforeStartup replaces the
// pre-RUB-1135 pin that this exact input started the devnet RPC node and only
// logged "rpc: live mining disabled (invalid --mine-address)". Silently
// degrading mining on operator input the startup check should have refused is
// the behavior this issue retires: the value now exits 2 on an untouched
// filesystem, so the child-process/SIGINT dance the old pin needed is gone.
func TestRunDevnetWithRPCBindInvalidMineAddressExitsBeforeStartup(t *testing.T) {
	datadir := filepath.Join(t.TempDir(), "data")
	var out, errOut bytes.Buffer
	code := run([]string{
		"--create-store",
		"--datadir", datadir,
		"--bind", "127.0.0.1:0",
		"--rpc-bind", "127.0.0.1:0",
		"--mine-address", "00" + strings.Repeat("00", 32),
	}, &out, &errOut)
	if code != 2 {
		t.Fatalf("exit code=%d, want 2 (stdout=%q stderr=%q)", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "invalid config: mine_address: unsupported suite_id 0x00") {
		t.Fatalf("stderr=%q, want the startup mine_address rejection", errOut.String())
	}
	if strings.Contains(errOut.String(), "rpc: live mining disabled") {
		t.Fatalf("stderr=%q, want no silent live-mining degradation", errOut.String())
	}
	if _, err := os.Stat(datadir); !os.IsNotExist(err) {
		t.Fatalf("datadir must not be created on a rejected --mine-address: stat err=%v", err)
	}
}

// TestRunDevnetWithRPCBindLiveMinerHasCurrentMempoolMinFeeRateFn pins the
// T-D production wiring at the live RPC mining miner instantiation site
// (cmd/rubin-node/main.go inside the `if cfg.Network == "devnet" && ... &&
// rpcBindHostIsLoopback(...)` block). The captured MinerConfig MUST carry
// a non-nil CurrentMempoolMinFeeRateFn that returns the live mempool
// rolling local floor, otherwise the miner template silently falls back
// to the static baseline and a DA candidate paying above
// DefaultMempoolMinFeeRate=1 but below the live floor would be admitted
// by the miner even when the mempool admit path would reject it.
//
// The check runs in a child process because the live mining branch only
// executes when the full devnet RPC path constructs the miner; we
// override newMinerFn to assert the cfg invariant, then SIGINT the child
// to unblock its lifecycle ctx and let it exit cleanly.
func TestRunDevnetWithRPCBindLiveMinerHasCurrentMempoolMinFeeRateFn(t *testing.T) {
	if os.Getenv("RUBIN_NODE_TEST_LIVE_MINER_FN_CHILD") == "1" {
		// Sentinel rolling-floor value injected into the mempool BEFORE
		// the live miner is constructed. The non-nil + >= baseline check
		// alone would silently accept a constant closure returning
		// DefaultMempoolMinFeeRate; the sentinel proves liveness — only
		// a closure actually bound to the live mempool snapshot returns
		// this exact value.
		const liveMinerSentinelFloor uint64 = 0xDEADBEEFCAFE
		prevMiner := newMinerFn
		prevMempool := newMempoolFn
		newMempoolFn = func(st *node.ChainState, store *node.BlockStore, chainID [32]byte, cfg node.MempoolConfig) (*node.Mempool, error) {
			mp, err := node.NewMempoolWithConfig(st, store, chainID, cfg)
			if err != nil {
				return nil, err
			}
			mp.SetCurrentMinFeeRateForTest(liveMinerSentinelFloor)
			return mp, nil
		}
		newMinerFn = func(_ *node.ChainState, _ *node.BlockStore, _ *node.SyncEngine, cfg node.MinerConfig) (*node.Miner, error) {
			if cfg.CurrentMempoolMinFeeRateFn == nil {
				_, _ = fmt.Fprintln(os.Stderr, "T-D regression: live miner cfg.CurrentMempoolMinFeeRateFn=nil")
				os.Exit(33)
			}
			if got := cfg.CurrentMempoolMinFeeRateFn(); got != liveMinerSentinelFloor {
				_, _ = fmt.Fprintf(os.Stderr, "T-D regression: provider returned %d, want sentinel %d (closure not bound to live mempool snapshot)\n", got, liveMinerSentinelFloor)
				os.Exit(35)
			}
			if cfg.CompleteDASetProvider == nil {
				_, _ = fmt.Fprintln(os.Stderr, "DA provider regression: live miner cfg.CompleteDASetProvider=nil")
				os.Exit(36)
			}
			// RUB-1135: the live-mining site consumes the single
			// startup parse of --mine-address. The flag below is
			// 0x-prefixed — a value the pre-fix config check refused
			// before startup — so this row also pins that the accepted
			// domain is exactly ParseMineAddress's.
			wantAddr := append([]byte{consensus.SUITE_ID_ML_DSA_87}, bytes.Repeat([]byte{0x11}, 32)...)
			if !bytes.Equal(cfg.MineAddress, wantAddr) {
				_, _ = fmt.Fprintf(os.Stderr, "RUB-1135 regression: live miner cfg.MineAddress=%x, want %x\n", cfg.MineAddress, wantAddr)
				os.Exit(37)
			}
			return nil, errors.New("test deliberate miner init abort to unblock SIGINT")
		}
		dir := t.TempDir()
		code := run(
			[]string{
				"--create-store",
				"--datadir", dir,
				"--bind", "127.0.0.1:0",
				"--rpc-bind", "127.0.0.1:0",
				"--mine-address", "0x" + strings.Repeat("11", 32),
			},
			os.Stdout,
			os.Stderr,
		)
		newMinerFn = prevMiner
		newMempoolFn = prevMempool
		os.Exit(code)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunDevnetWithRPCBindLiveMinerHasCurrentMempoolMinFeeRateFn")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_TEST_LIVE_MINER_FN_CHILD=1")
	stdout, stderr, err := runChildAfterRunningBanner(t, cmd)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 33 {
			t.Fatalf("T-D regression: live miner cfg.CurrentMempoolMinFeeRateFn is nil; production wiring missing in main.go around `liveMiner, err = newMinerFn(...)` (stdout=%s stderr=%s)", stdout, stderr)
		}
		if errors.As(err, &ee) && ee.ExitCode() == 35 {
			t.Fatalf("T-D regression: live miner CurrentMempoolMinFeeRateFn does not observe the live mempool snapshot (sentinel mismatch); the closure may be a static fallback that bypasses the rolling rolling-floor source (stdout=%s stderr=%s)", stdout, stderr)
		}
		if errors.As(err, &ee) && ee.ExitCode() == 36 {
			t.Fatalf("DA provider regression: live miner cfg.CompleteDASetProvider is nil; production wiring missing in main.go around `liveMiner, err = newMinerFn(...)` (stdout=%s stderr=%s)", stdout, stderr)
		}
		if errors.As(err, &ee) && ee.ExitCode() == 37 {
			t.Fatalf("RUB-1135 regression: the live-mining site did not receive the startup-parsed --mine-address bytes (stdout=%s stderr=%s)", stdout, stderr)
		}
		t.Fatalf("unexpected child error: %v (stdout=%s stderr=%s)", err, stdout, stderr)
	}
	if !strings.Contains(stderr, "rpc: live mining disabled:") {
		t.Fatalf("stderr=%q, want 'rpc: live mining disabled:' (deliberate abort marker)", stderr)
	}
}

func TestRunDevnetWithRPCBindLiveMinerInitErrorLogsStderr(t *testing.T) {
	if os.Getenv("RUBIN_NODE_TEST_LIVE_MINER_INIT_ERR_CHILD") == "1" {
		prev := newMinerFn
		newMinerFn = func(*node.ChainState, *node.BlockStore, *node.SyncEngine, node.MinerConfig) (*node.Miner, error) {
			return nil, errors.New("test miner init failed")
		}
		dir := t.TempDir()
		code := run(
			[]string{
				"--create-store",
				"--datadir", dir,
				"--bind", "127.0.0.1:0",
				"--rpc-bind", "127.0.0.1:0",
				"--mine-address", strings.Repeat("11", 32),
			},
			os.Stdout,
			os.Stderr,
		)
		newMinerFn = prev
		os.Exit(code)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunDevnetWithRPCBindLiveMinerInitErrorLogsStderr")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_TEST_LIVE_MINER_INIT_ERR_CHILD=1")
	stdout, stderr, err := runChildAfterRunningBanner(t, cmd)
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stdout=%s stderr=%s)", ee.ExitCode(), stdout, stderr)
		}
		t.Fatalf("unexpected error: %v (stdout=%s stderr=%s)", err, stdout, stderr)
	}
	s := stderr
	if !strings.Contains(s, "rpc: live mining disabled:") || !strings.Contains(s, "test miner init failed") {
		t.Fatalf("stderr=%q, want live mining disabled + test miner init failed", s)
	}
}

// TestMaybeFlipReadyOnStartup_NoopAfterMarkShutdown pins the gate
// contract on the production helper: when MarkShutdown has already
// stamped Shutdown, the helper's TryMarkReadyOnStartup MUST fail and
// IsReady MUST remain false. The audit banner reads the post-call
// IsReady (which itself observes shutdownCtx under the gate's lock),
// so it observes "false". Reverting the in-lock observe-then-decide
// path to a state-only Load turns this red.
func TestMaybeFlipReadyOnStartup_NoopAfterMarkShutdown(t *testing.T) {
	state := &devnetRPCState{gate: newReadinessGate(context.TODO())}
	server := &runningDevnetRPCServer{state: state}
	server.MarkShutdown()

	var buf bytes.Buffer
	maybeFlipReadyOnStartup(server, &buf)

	if state.IsReady() {
		t.Fatalf("expected IsReady=false after MarkShutdown, got true")
	}
	if got := buf.String(); !strings.Contains(got, "rpc: ready=false") {
		t.Fatalf("expected audit banner 'rpc: ready=false' after MarkShutdown, got %q", got)
	}
}

// TestMaybeFlipReadyOnStartup_NoopOnPreCanceledShutdownCtx is the
// production-helper regression. It constructs the state via
// newDevnetRPCStateWithLifecycle — the SAME canonical wiring helper
// cmd/rubin-node main.go uses — with a pre-canceled lifecycle ctx,
// then runs maybeFlipReadyOnStartup. The audit banner MUST read
// "false" because the gate's locked observeShutdownLocked sees ctx
// canceled and stamps Shutdown atomically with the state read.
//
// What this test protects (and what it does NOT):
//
//   - Protects: any change to newDevnetRPCStateWithLifecycle that
//     drops the internal state.SetShutdownCtx call OR any change to
//     readinessGate.observeShutdownLocked that no longer stamps
//     Shutdown on canceled ctx. Either turns this red.
//   - Does NOT protect: a future cmd/rubin-node main.go refactor
//     that stops calling newDevnetRPCStateWithLifecycle and inlines
//     a bare newDevnetRPCState constructor without SetShutdownCtx.
//     That kind of bypass requires either a deterministic end-to-end
//     run() test (timing-flaky to trigger pre-startup) or a Class-C
//     lifecycle/control-plane owner (out of scope for #1303). The
//     canonical-helper pattern is the agreed Class-B contract: as
//     long as main.go calls newDevnetRPCStateWithLifecycle the gate
//     is wired correctly; bypassing the canonical helper is a
//     deliberate refactor that must be caught by code review.
func TestMaybeFlipReadyOnStartup_NoopOnPreCanceledShutdownCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Use the canonical production-wiring helper — exactly the same
	// helper cmd/rubin-node main.go calls.
	state := newDevnetRPCStateWithLifecycle(nil, nil, nil, nil, nil, nil, io.Discard, nil, ctx)
	server := &runningDevnetRPCServer{state: state}

	var buf bytes.Buffer
	maybeFlipReadyOnStartup(server, &buf)

	if state.IsReady() {
		t.Fatalf("expected IsReady=false after newDevnetRPCStateWithLifecycle(canceledCtx), got true")
	}
	if got := buf.String(); !strings.Contains(got, "rpc: ready=false") {
		t.Fatalf("expected audit banner 'rpc: ready=false' on pre-canceled ctx, got %q", got)
	}
}

// TestMaybeFlipReadyOnStartup_FlipsOnFreshStateLiveCtx pins the happy
// path: with a fresh gate and a live shutdownCtx, the helper's
// TryMarkReadyOnStartup wins the locked transition and the audit
// banner reads "true". Reverting the transition or removing the
// banner print turns this red.
func TestMaybeFlipReadyOnStartup_FlipsOnFreshStateLiveCtx(t *testing.T) {
	state := &devnetRPCState{gate: newReadinessGate(context.Background())}
	server := &runningDevnetRPCServer{state: state}

	var buf bytes.Buffer
	maybeFlipReadyOnStartup(server, &buf)

	if !state.IsReady() {
		t.Fatalf("expected IsReady=true on fresh state with live ctx, got false")
	}
	if got := buf.String(); !strings.Contains(got, "rpc: ready=true") {
		t.Fatalf("expected audit banner 'rpc: ready=true', got %q", got)
	}
}

// TestMaybeFlipReadyOnStartup_NilServerNoOp pins the --rpc-bind="" path:
// with a nil rpcServer the helper returns early without touching state
// or stdout, so cmd/rubin-node main.go can call it unconditionally.
func TestMaybeFlipReadyOnStartup_NilServerNoOp(t *testing.T) {
	var buf bytes.Buffer
	maybeFlipReadyOnStartup(nil, &buf)
	if got := buf.String(); got != "" {
		t.Fatalf("expected no output for nil server, got %q", got)
	}
}

func runCLI(args ...string) (int, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, errOut.String()
}

// create_open_state_machine rule 2 + parity row 4: --create-store is
// incompatible with the read-only modes and rejects before any filesystem
// access. Rust mirror: `create_store_rejects_flag_combinations_before_any_storage_access`.
func TestRunCreateStoreRejectsFlagCombinationsBeforeStorage(t *testing.T) {
	for _, extra := range [][]string{
		{"--dry-run"},
		{"--legacy-exposure-scan", "--legacy-suite-id", "1"},
	} {
		dir := filepath.Join(t.TempDir(), "data")
		code, stderr := runCLI(append([]string{"--datadir", dir, "--create-store"}, extra...)...)
		if code != 2 {
			t.Fatalf("%v: exit %d, want 2", extra, code)
		}
		if want := "--create-store cannot be combined with --dry-run or --legacy-exposure-scan"; !strings.Contains(stderr, want) {
			t.Fatalf("%v: stderr = %q, want %q", extra, stderr, want)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("%v: no filesystem entry may be created: %v", extra, err)
		}
	}
}

// Parity rows 1-3 + rejected cases: create commits the tree, refuses an existing
// root (whose error wins over chainstate), refuses an existing chainstate
// without touching the root. Rust mirror:
// `create_store_creates_tree_and_rejects_existing_root_or_chainstate`.
func TestRunCreateStoreCreatesTreeAndRejectsExisting(t *testing.T) {
	create := func(dir string) []string {
		return []string{"--datadir", dir, "--create-store", "--mine-blocks", "1", "--mine-exit"}
	}
	dir := filepath.Join(t.TempDir(), "data")
	if code, stderr := runCLI(create(dir)...); code != 0 {
		t.Fatalf("create exit %d (stderr=%q)", code, stderr)
	}
	root := node.BlockStorePath(dir)
	for _, sub := range []string{"blocks", "headers", "undo"} {
		if info, err := os.Stat(filepath.Join(root, sub)); err != nil || !info.IsDir() {
			t.Fatalf("%s: %v %v", sub, info, err)
		}
	}
	markerBefore, err := os.ReadFile(filepath.Join(root, "index.json")) // #nosec G304 -- test-local path.
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}

	code, stderr := runCLI(create(dir)...)
	if code != 2 || !strings.Contains(stderr, "blockstore root already exists") {
		t.Fatalf("re-create: exit %d stderr %q", code, stderr)
	}
	markerAfter, err := os.ReadFile(filepath.Join(root, "index.json")) // #nosec G304 -- test-local path.
	if err != nil || string(markerAfter) != string(markerBefore) {
		t.Fatalf("existing store must be untouched: %v %v", markerAfter, err)
	}

	csDir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(csDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(node.ChainStatePath(csDir), []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed chainstate: %v", err)
	}
	code, stderr = runCLI(create(csDir)...)
	if code != 2 || !strings.Contains(stderr, "chainstate already exists") {
		t.Fatalf("chainstate present: exit %d stderr %q", code, stderr)
	}
	if _, err := os.Stat(node.BlockStorePath(csDir)); !os.IsNotExist(err) {
		t.Fatalf("root must not be created: %v", err)
	}

	both := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(node.BlockStorePath(both), 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.WriteFile(node.ChainStatePath(both), []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed chainstate: %v", err)
	}
	if code, stderr := runCLI(create(both)...); code != 2 || !strings.Contains(stderr, "blockstore root already exists") {
		t.Fatalf("both present: exit %d stderr %q (root error must win)", code, stderr)
	}

	// hostile: a DANGLING symlink at either path is present (lstat), not absent.
	for _, target := range []string{"blockstore root", "chainstate"} {
		dir := filepath.Join(t.TempDir(), "data")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		link := node.BlockStorePath(dir)
		if target == "chainstate" {
			link = node.ChainStatePath(dir)
		}
		if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if code, stderr := runCLI(create(dir)...); code != 2 || !strings.Contains(stderr, target+" already exists") {
			t.Fatalf("dangling %s symlink: exit %d stderr %q", target, code, stderr)
		}
	}
}

// Parity rows 5-9: ordinary startup strictly opens. Rust mirror:
// `open_existing_startup_never_synthesizes_a_store`.
func TestRunOpenExistingStartupDoesNotSynthesizeStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	code, stderr := runCLI("--datadir", dir, "--dry-run")
	if code != 2 || !strings.Contains(stderr, "blockstore open failed") {
		t.Fatalf("missing store: exit %d stderr %q", code, stderr)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("ordinary startup must not create the datadir: %v", err)
	}

	code, stderr = runCLI("--datadir", dir, "--legacy-exposure-scan", "--legacy-suite-id", "1")
	if code != 2 || !strings.Contains(stderr, "legacy exposure scan requires an existing chainstate") {
		t.Fatalf("legacy scan: exit %d stderr %q", code, stderr)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("legacy scan must not create a store: %v", err)
	}

	if code, stderr := runCLI("--datadir", dir, "--create-store", "--mine-blocks", "1", "--mine-exit"); code != 0 {
		t.Fatalf("create exit %d (stderr=%q)", code, stderr)
	}
	if code, stderr := runCLI("--datadir", dir, "--dry-run"); code != 0 {
		t.Fatalf("reopen exit %d (stderr=%q)", code, stderr)
	}
}

type datadirEntry struct {
	path string
	info os.FileInfo
}

// datadirSnapshot lists every entry under root in WalkDir's lexical order.
// os.FileInfo carries the device+inode identity that os.SameFile compares:
// chainState.Save writes a temp file and renames it over the target, so the
// replacement has identical content, identical size and (at filesystem mtime
// granularity) an identical timestamp — only the inode changes.
func datadirSnapshot(t *testing.T, root string) []datadirEntry {
	t.Helper()
	var snap []datadirEntry
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		snap = append(snap, datadirEntry{path: path, info: info})
		return nil
	}); err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return snap
}

func datadirPaths(snap []datadirEntry) []string {
	out := make([]string, len(snap))
	for i, e := range snap {
		out[i] = e.path
	}
	return out
}

// assertNoFilesystemWrite compares five axes under root: path, identity
// (device+inode), size, mtime and mode. A directory mtime bump is a write
// too — it is how a temp file the run created and then removed still shows
// up. Two axes it deliberately does NOT cover: CONTENT, so an in-place
// rewrite preserving inode, size and mtime would pass (the snapshotDir
// closure in TestRunRejectsInvalidPVModeBeforeStorage is the content-
// comparing counterpart), and anything OUTSIDE root, since it walks only the
// datadir. Do not read a pass here as "the process wrote nothing anywhere".
func assertNoFilesystemWrite(t *testing.T, before, after []datadirEntry) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("listing changed:\nbefore=%v\nafter=%v", datadirPaths(before), datadirPaths(after))
	}
	for i, b := range before {
		a := after[i]
		switch {
		case b.path != a.path:
			t.Fatalf("entry %d: %s became %s", i, b.path, a.path)
		case !os.SameFile(b.info, a.info):
			t.Fatalf("%s was replaced by a new inode (temp-and-rename)", b.path)
		case b.info.Size() != a.info.Size():
			t.Fatalf("%s size %d -> %d", b.path, b.info.Size(), a.info.Size())
		case !b.info.ModTime().Equal(a.info.ModTime()):
			t.Fatalf("%s mtime %v -> %v", b.path, b.info.ModTime(), a.info.ModTime())
		case b.info.Mode() != a.info.Mode():
			t.Fatalf("%s mode %v -> %v", b.path, b.info.Mode(), a.info.Mode())
		}
	}
}

// preparedDatadir is the datadir an operator holds after a real startup: a
// created blockstore with a mined canonical block at height 1 and the
// chainstate snapshot that startup persisted.
func preparedDatadir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if code, stderr := runCLI("--datadir", dir, "--create-store", "--mine-blocks", "1", "--mine-exit"); code != 0 {
		t.Fatalf("prepare datadir: exit %d (stderr=%q)", code, stderr)
	}
	return dir
}

// dryRunReport runs --dry-run against dir and returns the report. A
// successful read-only inspection has nothing to say on stderr, so any
// stderr output fails the row even when the exit code is 0.
func dryRunReport(t *testing.T, dir string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut); code != 0 {
		t.Fatalf("dry-run exit %d (stderr=%q)", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("dry-run wrote to stderr: %q", errOut.String())
	}
	return out.String()
}

// TestRunDryRunWritesNothing pins RUB-1071: --dry-run is read-only. Three
// runs, not one — the pre-fix code re-saved chainstate.json on every
// invocation, and measured on this datadir the three replacements shared one
// size and one mtime while burning three consecutive inodes.
func TestRunDryRunWritesNothing(t *testing.T) {
	dir := preparedDatadir(t)
	before := datadirSnapshot(t, dir)
	for i := 0; i < 3; i++ {
		if report := dryRunReport(t, dir); !strings.Contains(report, "p2p: peer_slots=") {
			t.Fatalf("run %d: truncated report %q", i, report)
		}
	}
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
}

func TestRunMutatingStartupReclaimsFixedScratchBeforeChainStateLoad(t *testing.T) {
	dir := t.TempDir()
	storeRoot := node.BlockStorePath(dir)
	if _, err := node.CreateBlockStore(storeRoot); err != nil {
		t.Fatalf("CreateBlockStore: %v", err)
	}
	parents := []string{
		dir,
		storeRoot,
		filepath.Join(storeRoot, "blocks"),
		filepath.Join(storeRoot, "headers"),
		filepath.Join(storeRoot, "undo"),
	}
	for _, parent := range parents {
		if err := os.WriteFile(filepath.Join(parent, ".rubin-atomic-write.tmp"), []byte("crash residue"), 0o600); err != nil {
			t.Fatalf("seed scratch in %s: %v", parent, err)
		}
	}
	if err := os.WriteFile(node.ChainStatePath(dir), []byte("{"), 0o600); err != nil {
		t.Fatalf("seed malformed chainstate: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := run([]string{"--datadir", dir}, &out, &errOut); code != 2 {
		t.Fatalf("run code=%d, want 2 (stderr=%q)", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "chainstate load failed") {
		t.Fatalf("startup did not reach chainstate load after reclaim: %q", errOut.String())
	}
	for _, parent := range parents {
		if _, err := os.Lstat(filepath.Join(parent, ".rubin-atomic-write.tmp")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("scratch remained in %s: %v", parent, err)
		}
	}
}

func TestRunReadOnlyModesLeaveFixedScratchAndLockUntouched(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(string) []string
	}{
		{name: "dry_run", args: func(dir string) []string { return []string{"--dry-run", "--datadir", dir} }},
		{name: "legacy_exposure_scan", args: func(dir string) []string {
			return []string{"--legacy-exposure-scan", "--legacy-suite-id", "1", "--datadir", dir}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := preparedDatadir(t)
			storeRoot := node.BlockStorePath(dir)
			parents := []string{
				dir,
				storeRoot,
				filepath.Join(storeRoot, "blocks"),
				filepath.Join(storeRoot, "headers"),
				filepath.Join(storeRoot, "undo"),
			}
			for _, parent := range parents {
				if err := os.Remove(filepath.Join(parent, ".rubin-atomic-write.lock")); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("remove setup lock in %s: %v", parent, err)
				}
				if err := os.WriteFile(filepath.Join(parent, ".rubin-atomic-write.tmp"), []byte(parent), 0o600); err != nil {
					t.Fatalf("seed scratch in %s: %v", parent, err)
				}
			}
			before := datadirSnapshot(t, dir)
			var out, errOut bytes.Buffer
			if code := run(tc.args(dir), &out, &errOut); code != 0 {
				t.Fatalf("read-only run code=%d (stderr=%q)", code, errOut.String())
			}
			assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
			for _, parent := range parents {
				if _, err := os.Lstat(filepath.Join(parent, ".rubin-atomic-write.lock")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("read-only run opened or created a reserved lock in %s: %v", parent, err)
				}
				if _, err := os.Lstat(filepath.Join(parent, ".rubin-atomic-write.tmp")); err != nil {
					t.Fatalf("read-only run removed scratch in %s: %v", parent, err)
				}
			}
		})
	}
}

func TestRunFailsClosedWhenFixedScratchIsDirectoryBeforeChainStateLoad(t *testing.T) {
	for _, tc := range []struct {
		name        string
		createStore bool
	}{
		{name: "existing_store"},
		{name: "fresh_store", createStore: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if !tc.createStore {
				if _, err := node.CreateBlockStore(node.BlockStorePath(dir)); err != nil {
					t.Fatalf("CreateBlockStore: %v", err)
				}
			}
			scratch := filepath.Join(dir, ".rubin-atomic-write.tmp")
			if err := os.Mkdir(scratch, 0o700); err != nil {
				t.Fatalf("mkdir scratch: %v", err)
			}
			args := []string{"--datadir", dir}
			if tc.createStore {
				args = append(args, "--create-store")
			}
			var out bytes.Buffer
			var errOut bytes.Buffer
			if code := run(args, &out, &errOut); code != 2 {
				t.Fatalf("run code=%d, want 2 (stderr=%q)", code, errOut.String())
			}
			wantPrefix := "atomic scratch reclaim failed: " + dir + ":"
			if !strings.Contains(errOut.String(), wantPrefix) {
				t.Fatalf("stderr=%q, want prefix %q", errOut.String(), wantPrefix)
			}
			info, err := os.Stat(scratch)
			if err != nil || !info.IsDir() {
				t.Fatalf("scratch directory changed: info=%v err=%v", info, err)
			}
			if _, err := os.Lstat(node.ChainStatePath(dir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("reclaim failure reached chainstate load or write: %v", err)
			}
		})
	}
}

// TestRunDryRunReportsStaleChainStateWithoutRepairing pins the shape that
// makes the reconcile want to mutate: a snapshot reset to genesis while the
// blockstore still holds canonical blocks. --dry-run must print the
// disagreement and leave it on disk for the operator to decide about.
func TestRunDryRunReportsStaleChainStateWithoutRepairing(t *testing.T) {
	dir := preparedDatadir(t)
	if err := node.NewChainState().Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("write stale chainstate: %v", err)
	}
	before := datadirSnapshot(t, dir)

	report := dryRunReport(t, dir)
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))

	if !strings.Contains(report, "chainstate: has_tip=false height=0") {
		t.Fatalf("report must show the stale on-disk chainstate, stdout=%q", report)
	}
	if !strings.Contains(report, "blockstore: tip_height=1 ") {
		t.Fatalf("report must show the real blockstore tip, stdout=%q", report)
	}
}

// TestRunDryRunDoesNotTruncateCanonicalIndex covers the reconcile's other
// durable write, and the destructive one: an incomplete canonical suffix
// (here a tip whose undo record is gone) makes it drop the tip from the
// index. --dry-run must surface that datadir intact, tip included, so the
// operator decides whether to lose the block.
func TestRunDryRunDoesNotTruncateCanonicalIndex(t *testing.T) {
	dir := preparedDatadir(t)
	store, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	tipHeight, tipHash, ok, err := store.Tip()
	if err != nil || !ok || tipHeight != 1 {
		t.Fatalf("fixture tip: height=%d ok=%v err=%v", tipHeight, ok, err)
	}
	undo := filepath.Join(node.BlockStorePath(dir), "undo", hex.EncodeToString(tipHash[:])+".json")
	if err := os.Remove(undo); err != nil {
		t.Fatalf("remove tip undo record: %v", err)
	}
	before := datadirSnapshot(t, dir)

	report := dryRunReport(t, dir)
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
	if !strings.Contains(report, "blockstore: tip_height=1 ") {
		t.Fatalf("report must still show the untruncated tip, stdout=%q", report)
	}
}

// TestRunDryRunLeavesALiveNodeDatadirAlone: inspecting a datadir a node is
// currently serving is the normal reason to reach for this mode. Pre-fix it
// meant a second process rewriting the running node's chainstate snapshot
// underneath it.
func TestRunDryRunLeavesALiveNodeDatadirAlone(t *testing.T) {
	if dir := os.Getenv("RUBIN_NODE_LIVE_DATADIR"); dir != "" {
		os.Exit(run([]string{"--create-store", "--datadir", dir, "--bind", "127.0.0.1:0"}, os.Stdout, os.Stderr))
	}
	dir := filepath.Join(t.TempDir(), "data")
	// The context owns the child's lifetime: it kills the node on expiry, so
	// the Kill below is a backstop rather than the only path out.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestRunDryRunLeavesALiveNodeDatadirAlone")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_LIVE_DATADIR="+dir)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	// Banner, not a sleep: the node has opened its store and started its
	// services by the time it prints this, so the snapshot below is of a
	// datadir genuinely in use.
	running := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		closed := false
		for scanner.Scan() {
			if !closed && strings.Contains(scanner.Text(), "rubin-node skeleton running") {
				close(running)
				closed = true
			}
		}
	}()
	select {
	case <-running:
	case <-ctx.Done():
		t.Fatalf("timeout waiting for the live node to start: %v", ctx.Err())
	}

	before := datadirSnapshot(t, dir)
	dryRunReport(t, dir)
	assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
}

// TestRunDryRunWritesNothingWithEveryLegalFlag: read-only is a property of
// the mode, not of the bare invocation. --mine-blocks is the load-bearing
// row — dry-run returns before the miner, so that success-gated side effect
// must not fire.
func TestRunDryRunWritesNothingWithEveryLegalFlag(t *testing.T) {
	deployments := filepath.Join(t.TempDir(), "deployments.json")
	if err := os.WriteFile(deployments, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write deployments: %v", err)
	}
	for _, extra := range [][]string{
		{"--log-level", "debug"},
		{"--bind", "127.0.0.1:0"},
		{"--rpc-bind", "127.0.0.1:0"},
		{"--max-peers", "1"},
		{"--peer", "127.0.0.1:19111"},
		{"--peers", "127.0.0.1:19111,127.0.0.1:19112"},
		{"--mempool-max-txs", "7", "--mempool-max-bytes", "4096"},
		{"--mine-address", strings.Repeat("ab", 32)},
		{"--mine-blocks", "5", "--mine-exit"},
		{"--pv-mode", "shadow", "--pv-shadow-max", "1"},
		{"--pv-mode", "on"},
		{"--featurebits-deployments", deployments},
	} {
		t.Run(strings.Join(extra, "_"), func(t *testing.T) {
			dir := preparedDatadir(t)
			before := datadirSnapshot(t, dir)
			var out, errOut bytes.Buffer
			args := append([]string{"--dry-run", "--datadir", dir}, extra...)
			if code := run(args, &out, &errOut); code != 0 {
				t.Fatalf("exit %d (stderr=%q)", code, errOut.String())
			}
			assertNoFilesystemWrite(t, before, datadirSnapshot(t, dir))
			if strings.Contains(out.String(), "mined:") {
				t.Fatalf("dry-run must not mine, stdout=%q", out.String())
			}
		})
	}
}

// TestRunDryRunKeepsChainStateInode is the check a size/mtime comparison
// cannot make. A hardlink pins the original inode; if the run renames a temp
// file over chainstate.json the path and the link stop being the same file,
// which on a real datadir is how an operator's backup link silently detaches.
func TestRunDryRunKeepsChainStateInode(t *testing.T) {
	dir := preparedDatadir(t)
	chainStatePath := node.ChainStatePath(dir)
	link := filepath.Join(filepath.Dir(dir), "chainstate.hardlink")
	if err := os.Link(chainStatePath, link); err != nil {
		t.Skipf("hardlink unavailable: %v", err)
	}
	before, err := os.Stat(chainStatePath)
	if err != nil {
		t.Fatalf("stat chainstate: %v", err)
	}

	dryRunReport(t, dir)

	after, err := os.Stat(chainStatePath)
	if err != nil {
		t.Fatalf("stat chainstate after run: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatalf("chainstate.json was replaced by a new inode")
	}
	linked, err := os.Stat(link)
	if err != nil {
		t.Fatalf("stat hardlink: %v", err)
	}
	if !os.SameFile(linked, after) {
		t.Fatalf("hardlink detached: the chainstate was rewritten under a new inode")
	}
}

// configBoundTestFile writes a config file padded with trailing JSON
// whitespace to exactly size bytes (1<<24 pins node's configFileMaxBytes via
// TestReadFileConfigBoundPinsDerivedValue).
func configBoundTestFile(t *testing.T, dir, name, payload string, size int) string {
	t.Helper()
	if len(payload) > size {
		t.Fatalf("payload longer than target size")
	}
	content := append([]byte(payload), bytes.Repeat([]byte{' '}, size-len(payload))...)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestReadFileConfigBoundDeploymentsSite pins RUB-1062 rider A at the
// featurebits-deployments call site: an at-bound file loads exactly as
// before, one byte over is refused with the typed size error.
func TestReadFileConfigBoundDeploymentsSite(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	at := configBoundTestFile(t, dir, "at.json", "[]", 1<<24)
	ds, err := loadFeatureBitDeployments(at)
	if err != nil {
		t.Fatalf("at-bound deployments must load: %v", err)
	}
	if err := printFeatureBitsTelemetryRows(&out, nil, 0, ds); err != nil {
		t.Fatalf("at-bound deployments must print: %v", err)
	}
	over := configBoundTestFile(t, dir, "over.json", "[]", 1<<24+1)
	if _, err := loadFeatureBitDeployments(over); err == nil || !strings.Contains(err.Error(), "exceeds size bound") {
		t.Fatalf("over-bound deployments must be refused with the typed size error, got %v", err)
	}
}

// TestReadFileConfigBoundGenesisSite pins RUB-1062 rider A at the
// genesis-pack call site: an at-bound file parses exactly as before, one
// byte over is refused with the typed size error.
func TestReadFileConfigBoundGenesisSite(t *testing.T) {
	dir := t.TempDir()
	chainID := strings.Repeat("ab", 32)
	pack := `{"chain_id_hex":"` + chainID + `","genesis_hash_hex":"` + strings.Repeat("cd", 32) + `"}`
	at := configBoundTestFile(t, dir, "at.json", pack, 1<<24)
	cfg, err := parseGenesisConfigFull(at)
	if err != nil {
		t.Fatalf("at-bound genesis pack must parse: %v", err)
	}
	if fmt.Sprintf("%x", cfg.ChainID[:]) != chainID {
		t.Fatalf("at-bound genesis pack parsed wrong chain id: %x", cfg.ChainID[:])
	}
	over := configBoundTestFile(t, dir, "over.json", pack, 1<<24+1)
	if _, err := parseGenesisConfigFull(over); err == nil || !strings.Contains(err.Error(), "exceeds size bound") {
		t.Fatalf("over-bound genesis pack must be refused with the typed size error, got %v", err)
	}
}

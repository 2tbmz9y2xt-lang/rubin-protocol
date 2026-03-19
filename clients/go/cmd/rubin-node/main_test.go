package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

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

func TestRunDryRunOK(t *testing.T) {
	dir := t.TempDir()
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
	// Basic sanity: should have created chainstate file.
	if _, err := os.Stat(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("expected chainstate file to exist: %v", err)
	}
}

func TestRunDryRunReconcilesChainStateFromBlockStore(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	store, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
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
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 0 {
		t.Fatalf("run dry-run code=%d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "chainstate: has_tip=true height=0") {
		t.Fatalf("stdout missing reconciled chainstate tip: %q", out.String())
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

func TestParseGenesisConfigFullBuildsCoreExtProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103",
		"genesis_hash_hex":"0x8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[1,3],"binding":"verify_sig_ext_accept"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	cfg, err := parseGenesisConfigFull(path)
	if err != nil {
		t.Fatalf("parseGenesisConfigFull: %v", err)
	}
	if cfg.CoreExtProfiles == nil {
		t.Fatalf("expected core_ext provider")
	}
	if _, ok, err := cfg.CoreExtProfiles.LookupCoreExtProfile(7, 11); err != nil {
		t.Fatalf("lookup pre-activation: %v", err)
	} else if ok {
		t.Fatalf("profile must be inactive before activation height")
	}
	profile, ok, err := cfg.CoreExtProfiles.LookupCoreExtProfile(7, 12)
	if err != nil {
		t.Fatalf("lookup active: %v", err)
	}
	if !ok || !profile.Active {
		t.Fatalf("expected active profile at activation height")
	}
	if profile.VerifySigExtFn == nil {
		t.Fatalf("expected verify_sig_ext binding")
	}
	if _, has := profile.AllowedSuites[1]; !has {
		t.Fatalf("missing allowed suite 1")
	}
	if _, has := profile.AllowedSuites[3]; !has {
		t.Fatalf("missing allowed suite 3")
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

func TestParseGenesisConfigFullRejectsEmptyCoreExtAllowedSuites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103",
		"genesis_hash_hex":"0x8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[],"binding":"native_verify_sig"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	if _, err := parseGenesisConfigFull(path); err == nil {
		t.Fatalf("expected empty allowed suites error")
	}
}

func TestParseGenesisConfigFullRejectsInvalidCoreExtBinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	chainIDBytes := node.DevnetGenesisChainID()
	genesisHashBytes := node.DevnetGenesisBlockHash()
	chainID := hex.EncodeToString(chainIDBytes[:])
	genesisHash := hex.EncodeToString(genesisHashBytes[:])
	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x`+chainID+`",
		"genesis_hash_hex":"0x`+genesisHash+`",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"binding":"unsupported"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	if _, err := parseGenesisConfigFull(path); err == nil || !strings.Contains(err.Error(), "unsupported core_ext binding") {
		t.Fatalf("expected unsupported binding error, got %v", err)
	}
}

func TestParseGenesisConfigFullRejectsCoreExtProfileSetAnchorMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	chainIDBytes := node.DevnetGenesisChainID()
	genesisHashBytes := node.DevnetGenesisBlockHash()
	deployments := []consensus.CoreExtDeploymentProfile{{
		ExtID:             7,
		ActivationHeight:  12,
		AllowedSuites:     map[uint8]struct{}{3: {}},
		VerifySigExtFn:    func(_ uint16, _ uint8, _ []byte, _ []byte, _ [32]byte, _ []byte) (bool, error) { return true, nil },
		BindingDescriptor: []byte{0xa1},
		ExtPayloadSchema:  []byte{0xb2},
	}}
	anchor, err := consensus.CoreExtProfileSetAnchorV1(chainIDBytes, deployments)
	if err != nil {
		t.Fatalf("CoreExtProfileSetAnchorV1: %v", err)
	}
	anchor[0] ^= 0xff
	chainID := hex.EncodeToString(chainIDBytes[:])
	genesisHash := hex.EncodeToString(genesisHashBytes[:])
	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x`+chainID+`",
		"genesis_hash_hex":"0x`+genesisHash+`",
		"core_ext_profile_set_anchor_hex":"0x`+hex.EncodeToString(anchor[:])+`",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[3],"binding":"verify_sig_ext_accept","binding_descriptor_hex":"a1","ext_payload_schema_hex":"b2"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}
	if _, err := parseGenesisConfigFull(path); err == nil || !strings.Contains(err.Error(), "core_ext profile set anchor mismatch") {
		t.Fatalf("expected set anchor mismatch error, got %v", err)
	}
}

func TestParseGenesisConfigFullRejectsOversizedCoreExtHexFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	chainIDBytes := node.DevnetGenesisChainID()
	genesisHashBytes := node.DevnetGenesisBlockHash()
	chainID := hex.EncodeToString(chainIDBytes[:])
	genesisHash := hex.EncodeToString(genesisHashBytes[:])
	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x`+chainID+`",
		"genesis_hash_hex":"0x`+genesisHash+`",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[3],"binding":"verify_sig_ext_accept","binding_descriptor_hex":"`+strings.Repeat("aa", maxCoreExtHexFieldBytes+1)+`","ext_payload_schema_hex":"b2"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}
	if _, err := parseGenesisConfigFull(path); err == nil || !strings.Contains(err.Error(), "bad binding_descriptor_hex") {
		t.Fatalf("expected oversized descriptor rejection, got %v", err)
	}
}

func TestParseGenesisConfigFullRejectsInvalidCoreExtHexFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	chainIDBytes := node.DevnetGenesisChainID()
	genesisHashBytes := node.DevnetGenesisBlockHash()
	chainID := hex.EncodeToString(chainIDBytes[:])
	genesisHash := hex.EncodeToString(genesisHashBytes[:])

	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x`+chainID+`",
		"genesis_hash_hex":"0x`+genesisHash+`",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[3],"binding":"verify_sig_ext_accept","binding_descriptor_hex":"zz","ext_payload_schema_hex":"b2"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}
	if _, err := parseGenesisConfigFull(path); err == nil || !strings.Contains(err.Error(), "bad binding_descriptor_hex") {
		t.Fatalf("expected invalid descriptor rejection, got %v", err)
	}

	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x`+chainID+`",
		"genesis_hash_hex":"0x`+genesisHash+`",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[3],"binding":"verify_sig_ext_accept","binding_descriptor_hex":"a1","ext_payload_schema_hex":"zz"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}
	if _, err := parseGenesisConfigFull(path); err == nil || !strings.Contains(err.Error(), "bad ext_payload_schema_hex") {
		t.Fatalf("expected invalid payload schema rejection, got %v", err)
	}
}

func TestParseGenesisConfigFullRejectsInvalidCoreExtProfileSetAnchorHex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	chainIDBytes := node.DevnetGenesisChainID()
	genesisHashBytes := node.DevnetGenesisBlockHash()
	chainID := hex.EncodeToString(chainIDBytes[:])
	genesisHash := hex.EncodeToString(genesisHashBytes[:])
	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x`+chainID+`",
		"genesis_hash_hex":"0x`+genesisHash+`",
		"core_ext_profile_set_anchor_hex":"zz",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[3],"binding":"verify_sig_ext_accept","binding_descriptor_hex":"a1","ext_payload_schema_hex":"b2"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}
	if _, err := parseGenesisConfigFull(path); err == nil {
		t.Fatalf("expected invalid set anchor rejection")
	}
}

func TestParseGenesisConfigFullRejectsInvalidCoreExtAnchorProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "genesis.json")
	chainIDBytes := node.DevnetGenesisChainID()
	genesisHashBytes := node.DevnetGenesisBlockHash()
	chainID := hex.EncodeToString(chainIDBytes[:])
	genesisHash := hex.EncodeToString(genesisHashBytes[:])
	if err := os.WriteFile(path, []byte(`{
		"chain_id_hex":"0x`+chainID+`",
		"genesis_hash_hex":"0x`+genesisHash+`",
		"core_ext_profile_set_anchor_hex":"0x`+strings.Repeat("00", 32)+`",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[],"binding":"native_verify_sig","ext_payload_schema_hex":"b2"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}
	if _, err := parseGenesisConfigFull(path); err == nil || !strings.Contains(err.Error(), "must have non-empty allowed suites") {
		t.Fatalf("expected invalid profile rejection during anchor check, got %v", err)
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

func TestParseCoreExtBindingVariants(t *testing.T) {
	tests := []struct {
		name    string
		binding string
		wantNil bool
		wantOK  bool
		wantErr bool
	}{
		{name: "empty", binding: "", wantNil: true},
		{name: "native", binding: "native_verify_sig", wantNil: true},
		{name: "accept", binding: "verify_sig_ext_accept", wantOK: true},
		{name: "reject", binding: "verify_sig_ext_reject"},
		{name: "error", binding: "verify_sig_ext_error", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, err := parseCoreExtBinding(tt.binding)
			if err != nil {
				t.Fatalf("parseCoreExtBinding(%q): %v", tt.binding, err)
			}
			if tt.wantNil {
				if fn != nil {
					t.Fatalf("expected nil verifier for %q", tt.binding)
				}
				return
			}
			if fn == nil {
				t.Fatalf("expected verifier for %q", tt.binding)
			}
			ok, callErr := fn(7, 1, nil, nil, [32]byte{}, nil)
			if ok != tt.wantOK {
				t.Fatalf("verify result=%v, want %v", ok, tt.wantOK)
			}
			if tt.wantErr {
				if callErr == nil {
					t.Fatalf("expected verifier error for %q", tt.binding)
				}
				return
			}
			if callErr != nil {
				t.Fatalf("unexpected verifier error for %q: %v", tt.binding, callErr)
			}
		})
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

func TestRunPassesGenesisCoreExtProfilesToMempool(t *testing.T) {
	prev := newMempoolFn
	var captured node.MempoolConfig
	newMempoolFn = func(st *node.ChainState, store *node.BlockStore, chainID [32]byte, cfg node.MempoolConfig) (*node.Mempool, error) {
		captured = cfg
		return node.NewMempoolWithConfig(st, store, chainID, cfg)
	}
	t.Cleanup(func() { newMempoolFn = prev })

	dir := t.TempDir()
	genesisPath := filepath.Join(dir, "genesis.json")
	if err := os.WriteFile(genesisPath, []byte(`{
		"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103",
		"genesis_hash_hex":"0x8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff",
		"core_ext_profiles":[{"ext_id":7,"activation_height":12,"allowed_suite_ids":[1],"binding":"verify_sig_ext_accept"}]
	}`), 0o600); err != nil {
		t.Fatalf("write genesis file: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir, "--genesis-file", genesisPath}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, errOut.String())
	}
	if !captured.PolicyRejectCoreExtPreActivation {
		t.Fatalf("expected CORE_EXT mempool policy enabled by default")
	}
	if captured.CoreExtProfiles == nil {
		t.Fatalf("expected mempool core_ext profiles")
	}
	profile, ok, err := captured.CoreExtProfiles.LookupCoreExtProfile(7, 12)
	if err != nil {
		t.Fatalf("LookupCoreExtProfile: %v", err)
	}
	if !ok || !profile.Active {
		t.Fatalf("expected active core_ext profile at activation height")
	}
}

func TestRunDryRunShowsTipWhenBlockstoreHasTip(t *testing.T) {
	dir := t.TempDir()

	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
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

func TestRunDryRunFailsWhenChainstateReconcileFails(t *testing.T) {
	dir := t.TempDir()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
	}
	parsed, err := consensus.ParseBlockBytes(node.DevnetGenesisBlockBytes())
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	header := parsed.HeaderBytes
	hash := node.DevnetGenesisBlockHash()
	if err := blockStore.CommitCanonicalBlock(0, hash, header, []byte{0x00}, &node.BlockUndo{}); err != nil {
		t.Fatalf("CommitCanonicalBlock: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("chainstate reconcile failed")) {
		t.Fatalf("expected reconcile failure in stderr, got %q", errOut.String())
	}
}

func TestRunDryRunFailsWhenChainstateSaveFails(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	store, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
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

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod(readonly datadir): %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", code, errOut.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("chainstate save failed")) {
		t.Fatalf("expected chainstate save failure in stderr, got %q", errOut.String())
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

func TestRunMineBlocksExitOK(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := run(
		[]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit"},
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

func TestRunMineBlocksPassesMineAddressToMiner(t *testing.T) {
	prev := newMinerFn
	var captured node.MinerConfig
	newMinerFn = func(_ *node.ChainState, _ *node.BlockStore, _ *node.SyncEngine, cfg node.MinerConfig) (*node.Miner, error) {
		captured = cfg
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { newMinerFn = prev })

	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run(
		[]string{"--datadir", dir, "--mine-blocks", "1", "--mine-exit", "--mine-address", strings.Repeat("11", 32)},
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
}

func TestRunMainnetFailsWithoutExplicitTarget(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", dir, "--network", "mainnet"}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !bytes.Contains(errOut.Bytes(), []byte("mainnet requires explicit expected_target")) {
		t.Fatalf("unexpected stderr: %q", errOut.String())
	}
}

func TestRunMainnetFailsBeforeReconcilingChainState(t *testing.T) {
	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)
	store, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("OpenBlockStore: %v", err)
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
	if !bytes.Contains(errOut.Bytes(), []byte("mainnet requires explicit expected_target")) {
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

func TestRunChainstateSaveFailsWhenDatadirNotWritable(t *testing.T) {
	datadir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(datadir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(datadir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(datadir, 0o700) })

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := run([]string{"--dry-run", "--datadir", datadir}, &out, &errOut)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

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

func TestRunNonDryRunExitsOnSignal(t *testing.T) {
	if os.Getenv("RUBIN_NODE_SIGNAL_CHILD") == "1" {
		dir := t.TempDir()
		go func() {
			time.Sleep(200 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()
		code := run([]string{"--datadir", dir, "--bind", "127.0.0.1:0"}, os.Stdout, os.Stderr)
		os.Exit(code)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunNonDryRunExitsOnSignal")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_SIGNAL_CHILD=1")
	err := cmd.Run()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stderr=%s)", ee.ExitCode(), string(ee.Stderr))
		}
		t.Fatalf("unexpected error: %v", err)
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
		[]string{"--datadir", dir, "--bind", "127.0.0.1:0", "--rpc-bind", listener.Addr().String()},
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
		go func() {
			time.Sleep(200 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(syscall.SIGINT)
		}()
		code := run(
			[]string{"--datadir", dir, "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"},
			os.Stdout,
			os.Stderr,
		)
		os.Exit(code)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunNonDryRunWithRPCBindExitsOnSignal")
	cmd.Env = append(os.Environ(), "RUBIN_NODE_SIGNAL_RPC_CHILD=1")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if ok {
			t.Fatalf("exit code=%d, want 0 (stderr=%s)", ee.ExitCode(), stderr.String())
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "rpc: listening=") {
		t.Fatalf("stdout=%q, want rpc listening line", stdout.String())
	}
	if !strings.Contains(stdout.String(), "rubin-node skeleton running") {
		t.Fatalf("stdout=%q, want running banner", stdout.String())
	}
	if !strings.Contains(stdout.String(), "rubin-node skeleton stopped") {
		t.Fatalf("stdout=%q, want stopped banner", stdout.String())
	}
}

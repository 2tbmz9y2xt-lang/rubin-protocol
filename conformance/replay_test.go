package conformance_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/conformance/devnetcv"
)

func TestDevnetFixturesReplay(t *testing.T) {
	t.Helper()

	repoRoot := repoRootFromTestFile(t)

	first, err := devnetcv.Generate()
	if err != nil {
		t.Fatalf("Generate(first): %v", err)
	}
	second, err := devnetcv.Generate()
	if err != nil {
		t.Fatalf("Generate(second): %v", err)
	}

	expected := map[string]any{
		devnetcv.GateDevnetGenesis:      first.Genesis,
		devnetcv.GateDevnetSubsidy:      first.Subsidy,
		devnetcv.GateDevnetChain:        first.Chain,
		devnetcv.GateDevnetMaturity:     first.Maturity,
		devnetcv.GateDevnetSighashChain: first.SighashChain,
	}
	expected2 := map[string]any{
		devnetcv.GateDevnetGenesis:      second.Genesis,
		devnetcv.GateDevnetSubsidy:      second.Subsidy,
		devnetcv.GateDevnetChain:        second.Chain,
		devnetcv.GateDevnetMaturity:     second.Maturity,
		devnetcv.GateDevnetSighashChain: second.SighashChain,
	}

	for _, gate := range devnetcv.GateOrder() {
		firstBytes, err := devnetcv.MarshalFixtureForTest(expected[gate])
		if err != nil {
			t.Fatalf("%s marshal(first): %v", gate, err)
		}
		secondBytes, err := devnetcv.MarshalFixtureForTest(expected2[gate])
		if err != nil {
			t.Fatalf("%s marshal(second): %v", gate, err)
		}
		if !bytes.Equal(firstBytes, secondBytes) {
			t.Fatalf("%s generation is not deterministic", gate)
		}

		path := filepath.Join(repoRoot, "conformance", "fixtures", gate+".json")
		onDisk, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s read fixture: %v", gate, err)
		}
		if !bytes.Equal(onDisk, firstBytes) {
			t.Fatalf("%s fixture drift: regenerate with conformance/cmd/gen-devnet-fixtures", gate)
		}
	}
}

func repoRootFromTestFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

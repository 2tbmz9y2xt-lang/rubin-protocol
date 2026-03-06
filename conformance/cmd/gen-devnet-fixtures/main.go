package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/conformance/devnetcv"
)

func main() {
	repoRootFlag := flag.String("repo-root", "", "repository root (defaults to parent of current conformance module)")
	flag.Parse()

	repoRoot, err := resolveRepoRoot(*repoRootFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve repo root: %v\n", err)
		os.Exit(1)
	}
	if err := devnetcv.WriteFixtures(repoRoot); err != nil {
		fmt.Fprintf(os.Stderr, "write devnet fixtures: %v\n", err)
		os.Exit(1)
	}
}

func resolveRepoRoot(flagValue string) (string, error) {
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(wd, ".."))
}

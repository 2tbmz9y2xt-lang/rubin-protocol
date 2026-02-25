# Conformance (Go reference, Rust parity)

This directory contains machine-executable conformance fixtures and a runner that checks:

1) **Go as reference**: the Go client (`clients/go`) is the reference implementation for parity.
2) **Rust parity**: the Rust client (`clients/rust`) MUST match Go behavior for every executable gate.
3) **Spec compliance**: fixtures encode expected behavior derived from the normative spec; Go is also checked
   against fixture expectations to prevent “both clients drift together”.

Normative authority remains `spec/RUBIN_L1_CANONICAL.md` (consensus validity) and
`spec/RUBIN_COMPACT_BLOCKS.md` (normative P2P). This folder is a testing harness.

## Run

macOS/Homebrew note (operational):

```bash
export PATH=/opt/homebrew/bin:$PATH
```

Run full bundle:

```bash
python3 conformance/runner/run_cv_bundle.py
```

List gates:

```bash
python3 conformance/runner/run_cv_bundle.py --list-gates
```

Run a single gate:

```bash
python3 conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT
```

## Coverage matrix

`conformance/MATRIX.md` is a generated coverage overview (gates/vectors/ops; local-only vs executable).

Regenerate:

```bash
python3 tools/gen_conformance_matrix.py
```

Check (CI):

```bash
python3 tools/gen_conformance_matrix.py --check
```

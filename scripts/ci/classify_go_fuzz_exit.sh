#!/usr/bin/env bash
# Classify a non-zero `go test -fuzz` exit as either the benign upstream
# fuzztime-expiry shutdown race (exit 0) or defect evidence (exit 1).
#
# Benign signature (verified in go1.26.5, src/internal/fuzz/fuzz.go:129): the
# fuzz coordinator can observe the fuzztime deadline via the parent done
# channel before its own context reports it, so the suppression guard
# `err == fuzzCtx.Err()` misses and a bare "context deadline exceeded" fails
# the run even though the full fuzz budget was spent and no defect was found.
#
# Usage:
#   classify_go_fuzz_exit.sh <target> <fuzztime_seconds> <log_file> \
#       <corpus_before_list> <corpus_dir>
#
# <corpus_before_list> is a file holding the sorted `find <corpus_dir> -type f`
# output taken before the run (may be empty); <corpus_dir> may not exist.
#
# Exit codes: 0 = benign shutdown race (PASS-with-warning),
#             1 = not benign (FAIL), 2 = usage/malformed-argument error.
set -euo pipefail

fail_usage() {
  echo "FAIL: $*" >&2
  exit 2
}

if (($# != 5)); then
  fail_usage "expected 5 arguments: <target> <fuzztime_seconds> <log_file> <corpus_before_list> <corpus_dir>"
fi

target="$1"
fuzz_seconds="$2"
log_file="$3"
corpus_before_list="$4"
corpus_dir="$5"

# Target feeds a grep pattern below; restricting it to a Go identifier keeps
# hostile input out of the regex.
[[ "${target}" =~ ^[A-Za-z0-9_]+$ ]] || fail_usage "target must be a Go identifier: ${target}"
[[ "${fuzz_seconds}" =~ ^[0-9]+$ ]] || fail_usage "fuzztime_seconds must match ^[0-9]+\$: ${fuzz_seconds}"
[[ -f "${log_file}" && -r "${log_file}" ]] || fail_usage "log file not readable: ${log_file}"
[[ -f "${corpus_before_list}" && -r "${corpus_before_list}" ]] || fail_usage "corpus before-list not readable: ${corpus_before_list}"

not_benign() {
  echo "NOT_BENIGN ${target}: $*" >&2
  exit 1
}

# Conjunct 1: exactly one FAIL block, whose failure text is exactly the bare
# "context deadline exceeded" line. Any other failure text (panic, assertion,
# hang diagnostics) or a second FAIL block is defect evidence, not the race.
fail_regex="^--- FAIL: ${target} \(([0-9]+(\.[0-9]+)?)s\)\$"
fail_count="$(grep -Ec -- "${fail_regex}" "${log_file}" || true)"
if [[ "${fail_count}" -ne 1 ]]; then
  not_benign "expected exactly one benign-shaped FAIL line, found ${fail_count}"
fi
fail_line_no="$(grep -En -- "${fail_regex}" "${log_file}" | cut -d: -f1)"
fail_line="$(sed -n "${fail_line_no}p" "${log_file}")"
next_line="$(sed -n "$((fail_line_no + 1))p" "${log_file}")"
if [[ "${next_line}" != "    context deadline exceeded" ]]; then
  not_benign "failure text after the FAIL line is not the bare deadline"
fi

# Conjunct 2: the run must have consumed at least the full fuzztime budget.
# A deadline below budget means something else cancelled the run early and the
# fuzz coverage was NOT delivered — that is red, not the shutdown race.
duration="${fail_line#*"("}"
duration="${duration%"s)"}"
if ! awk -v d="${duration}" -v budget="${fuzz_seconds}" 'BEGIN { exit !(d + 0 >= budget + 0) }'; then
  not_benign "deadline hit at ${duration}s, below the ${fuzz_seconds}s budget"
fi

# Conjunct 3: no crash/instability marker anywhere in the log. Each marker is
# a distinct defect-evidence channel: a written failing input (reproducible
# crash), a hung/terminated worker (abnormal termination), a worker
# communication error, or an internal fuzz-engine failure.
for marker in \
  "Failing input written" \
  "fuzzing process hung or terminated" \
  "communicating with fuzzing process" \
  "internal failure"; do
  if grep -Fq -- "${marker}" "${log_file}"; then
    not_benign "defect-evidence marker present: ${marker}"
  fi
done

# Conjunct 4: no new file under the target's corpus dir. `go test` writes any
# discovered crasher into testdata/fuzz/<Target>/ before exiting, so an
# unchanged sorted file list proves no crash input was recorded.
corpus_after="$(mktemp)"
trap 'rm -f "${corpus_after}"' EXIT
if [[ -d "${corpus_dir}" ]]; then
  find "${corpus_dir}" -type f | sort > "${corpus_after}"
fi
if ! diff -q -- "${corpus_before_list}" "${corpus_after}" >/dev/null; then
  not_benign "corpus file list changed under ${corpus_dir}"
fi

echo "BENIGN_FUZZTIME_SHUTDOWN_RACE ${target}: full ${fuzz_seconds}s budget spent, no defect evidence"
exit 0

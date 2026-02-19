#!/usr/bin/env bash
# resolve-pr-threads.sh — resolve all unresolved CodeRabbit/review threads on a PR
# Usage: scripts/resolve-pr-threads.sh <pr_number> [owner/repo]
#
# Requires: gh CLI authenticated

set -euo pipefail

PR="${1:-}"
REPO="${2:-$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null)}"

if [ -z "$PR" ] || [ -z "$REPO" ]; then
  echo "usage: $0 <pr_number> [owner/repo]" >&2
  exit 1
fi

echo "Resolving unresolved review threads on $REPO#$PR..."

THREADS=$(gh api graphql -f query="
{
  repository(owner: \"${REPO%/*}\", name: \"${REPO#*/}\") {
    pullRequest(number: $PR) {
      reviewThreads(first: 50) {
        nodes { id isResolved }
      }
    }
  }
}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
nodes = d['data']['repository']['pullRequest']['reviewThreads']['nodes']
for n in nodes:
    if not n['isResolved']:
        print(n['id'])
")

if [ -z "$THREADS" ]; then
  echo "No unresolved threads found."
  exit 0
fi

COUNT=0
while IFS= read -r thread_id; do
  RESULT=$(gh api graphql -f query="
  mutation {
    resolveReviewThread(input: { threadId: \"$thread_id\" }) {
      thread { id isResolved }
    }
  }" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['resolveReviewThread']['thread']['isResolved'])")
  echo "  resolved $thread_id → $RESULT"
  COUNT=$((COUNT + 1))
done <<< "$THREADS"

echo "Done: $COUNT thread(s) resolved."

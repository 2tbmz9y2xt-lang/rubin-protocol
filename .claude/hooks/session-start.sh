#!/bin/bash
set -euo pipefail

# Only run in remote Claude Code sessions
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi


cat >&2 <<'BOOT'
=== NEON MEMORY BOOT CHECK REQUIRED ===

Session started. Run the following Neon checks via MCP tools BEFORE doing any work:

1. WORKING CONTEXT: Run SQL on project patient-dew-75096386:
   SELECT agent, key, value, updated_at FROM agent_memory.working_context ORDER BY updated_at DESC;

2. OPEN SESSIONS (unfinished work): Run SQL:
   SELECT id, agent, started_at, summary FROM agent_memory.agent_sessions WHERE ended_at IS NULL ORDER BY started_at DESC LIMIT 10;

3. UNRESOLVED CONFLICTS: Run SQL:
   SELECT * FROM agent_memory.conflicts WHERE resolved = false ORDER BY created_at DESC LIMIT 10;

4. MEMORY STATS: Run SQL:
   SELECT * FROM agent_memory.stats ORDER BY last_activity DESC LIMIT 10;

5. RECENT DECISIONS (24h): Run SQL:
   SELECT id, source, content, created_at FROM agent_memory.memories WHERE type = 'decision' AND created_at > NOW() - INTERVAL '24 hours' ORDER BY created_at DESC LIMIT 5;

Present a concise summary of the hot context and any unfinished work to the user.

=== END BOOT CHECK ===
BOOT

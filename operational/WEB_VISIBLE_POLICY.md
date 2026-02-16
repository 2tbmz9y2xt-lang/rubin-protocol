# web-visible policy (operator-facing)

Keyword: `web-visible`

Purpose: mark repository artifacts that are safe to publish on the public GitHub repo without leaking internal-only or sensitive operational details.

## Rules

1. Any file or workflow intended for public visibility MUST be marked `web-visible`.
2. Files that contain secrets, private network topology, allowlists, or pre-genesis private coordination MUST NOT be marked `web-visible`.
3. `INBOX.md`, `inbox/`, and other local process artifacts MUST remain local-only and MUST NOT be committed.


# PRD-21253 · Code review

## Round 1 · 2026-11-02 · reviewed dev/PRD-21253 @ 2b1a163 (base main @ 0e5f2ba)

Verdict: changes requested

### Findings

1. [must-fix] `src/mailprotector_mcp/` (whole tree; no file implements this) — the tech design's own "Observability" section (`docs/tickets/PRD-21253.md:211`) commits to "structured (JSON) logs per request: tool name, redacted arg summary, Mailprotector path + status code, latency, error `code` if any (SOP §6)", and `vendor-mcp-development-sop.md:278-284` (§6) requires exactly this (structured log + request-id, tool name, redacted args, API path/status, latency, error code) as a non-optional delivery item (SOP §14 Checklist, "日志与敏感信息" section, not marked "应当"/should like §2's design-quality section is). `grep -rn "import logging\|logger\|logging\." src/` returns no hits anywhere in the repo — there is no logger, no request-id, no per-call log line of any kind; `__main__.py:1-19` runs bare `uvicorn.run(app, ...)` with uvicorn's default access log only (method/path/status, no tool name, no redacted args, no latency breakdown, no error `code`). This is a tech-design-required change that was not done (`legs/review.md` R3 "范围" row), and unlike the one other known gap in this ticket (the Chinese-language `[已假设]`/`[不阻塞]` tags, honestly flagged in Self-test at `docs/tickets/PRD-21253.md:314`), this gap is not mentioned anywhere in Self-test/Handoff — an unrecorded known issue is treated as a BLOCKER, not a WARN, per `references/REVIEW.md` §3. Fix: add a structured logger (stdlib `logging` with a JSON formatter, or equivalent) invoked from `runtime.call_api` (the single choke point every tool already funnels through, `src/mailprotector_mcp/runtime.py:41-59`) so one change covers all 20 tools; log tool name, a redacted arg summary, the Mailprotector path, the resulting status/error code, and latency — never the auth token or raw response body.

### Fixes            ← to be filled in by the dev leg on the next round

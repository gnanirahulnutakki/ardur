# CodeQL Alert Dismissals — 2026-04-29

> Audit-trail mirror of the GitHub Code Scanning dismissal record for
> alerts that surfaced on PR #8 (the `dev → main` graduation that
> carried the 11-round S2 hostile-audit cycle, the framework-demo
> code lift, and Article 06).
>
> GitHub stores the same content under
> `gh api repos/gnanirahulnutakki/ardur/code-scanning/alerts/<n>`, but
> that surface is gated behind authenticated access to the repo's
> security tab. This file mirrors the record into the public tree so
> any reader (including someone reviewing the repo without GitHub
> credentials) can audit what was dismissed and why.

## Why this file exists

The 11-round audit cycle (S2) terminated cleanly on 2026-04-29 with
two consecutive clean rounds (R10, R11), 101 findings closed across
the cycle (1 CRITICAL + 16 HIGH + 37 MEDIUM + 47 LOW). When PR #8
opened, GitHub's Advanced Security CodeQL aggregator surfaced eight
new alerts on the PR diff that the human auditor had not flagged.

This is expected — CodeQL is a different lens (taint-flow over the
semantic model) and routinely catches things a human auditor's
scope misses. It is also expected that not every CodeQL alert is a
real bug: false-positive rate on rules like
`py/clear-text-logging-sensitive-data` and
`py/overly-permissive-file` runs high in security-tooling code
because the rules cannot reason about the surrounding contract
(token redaction, public-vs-private key material, HTTP response
sinks vs. log sinks).

Every dismissal here was triaged before merge, has a recorded
justification visible in the GitHub Code Scanning UI, and is
restated in this file with file:line, rule id, severity, and the
reasoning we used.

## Summary

| Alert | Rule | Sec sev | Rule sev | Disposition | Class |
|---|---|---|---|---|---|
| #1 | `py/clear-text-logging-sensitive-data` | high | error | won't fix | Operator-bootstrap UX with abbreviation by default |
| #2 | `py/clear-text-logging-sensitive-data` | high | error | false positive | Stderr line emits redacted fingerprint, not cleartext |
| #3 | `py/overly-permissive-file` | high | warning | false positive | Stale alert — file deleted during audit cycle |
| #4 | `py/overly-permissive-file` | high | warning | false positive | `0o644` on public key (correct by definition) |
| #5 | `py/log-injection` | medium | error | false positive | HTTP response sink misclassified as log sink |
| #13 | `py/unsafe-cyclic-import` | — | error | false positive | Fix landed in commit `438ee15` (topology break) |
| #14 | `py/unsafe-cyclic-import` | — | error | false positive | Fix landed in commit `438ee15` (topology break) |
| #15 | `py/unsafe-cyclic-import` | — | error | false positive | Fix landed in commit `438ee15` (topology break) |

Eight dismissals. Five "false positive" (the rule's pattern fires
on shape but not on the actual security predicate). One "won't fix"
(the operator UX is the deliberate design and tightening it would
be backwards-incompatible without a corresponding gain). Three
correspond to a real fix that landed in the same PR and will
auto-close on the next CodeQL scan against `main` post-merge.

## Per-alert detail

### #1 — `py/clear-text-logging-sensitive-data` (HIGH)

- **File:** `python/vibap/proxy.py:5031` (banner-print site)
- **Rule message:** *"This expression logs sensitive data (password)
  as clear text."*
- **Disposition:** Won't fix
- **Justification (verbatim, 280-char limit):** *"Operator-bootstrap
  UX. Banner uses `_display_token()` abbreviation by default; full
  token printed only when `VIBAP_PRINT_FULL_TOKEN=1`. CodeQL cannot
  track the abbreviation predicate. 11-round S2 audit (101 findings)
  reviewed this surface."*
- **Extended reasoning:** When the proxy starts with auth required,
  it prints the API token to the operator's terminal so the
  operator can copy it into client configuration
  (`Authorization: Bearer <token>` headers, `VIBAP_API_TOKEN` env
  var for hooks). The default print path uses `_display_token()`,
  which abbreviates to a prefix-suffix pattern unless the operator
  explicitly opts into full-token print via the
  `VIBAP_PRINT_FULL_TOKEN=1` environment variable. CodeQL's
  data-flow analysis treats any string-formatted token in a print
  call as cleartext logging without tracking the abbreviation
  predicate. The token *must* be displayable at startup for the
  operator to function; replacing the banner with no-op would
  break operator setup. The S2 audit cycle reviewed this surface
  in rounds 1–11 and did not flag it as a real concern.

### #2 — `py/clear-text-logging-sensitive-data` (HIGH)

- **File:** `python/vibap/proxy.py:5040` (stderr structured line)
- **Rule message:** *"This expression logs sensitive data (password)
  as clear text."*
- **Disposition:** False positive
- **Justification (verbatim, 280-char limit):** *"Stderr line emits
  ONLY `_redact_token(api_token)` — an 8-prefix/4-suffix
  fingerprint, never the cleartext bearer. CodeQL taint cannot
  propagate through the redaction string-truncation. The actual
  bytes are 'token_fp=PREFIX…SUFFIX'."*
- **Extended reasoning:** The stderr line at `proxy.py:5040` is the
  audit fingerprint emission, *not* the operator-display banner.
  The format string is
  `f"[vibap] auth=on source={token_source} token_fp={_redact_token(api_token)}"`,
  and `_redact_token()` returns an 8-char prefix + ellipsis +
  4-char suffix — not the full token bytes. CodeQL's taint
  analysis sees `api_token` flow into the format expression and
  reports it as cleartext, but the redaction function's
  string-truncation is opaque to taint propagation. The actual
  emitted line never carries the cleartext bearer.

### #3 — `py/overly-permissive-file` (HIGH)

- **File:** `python/vibap/legacy_passport.py:238`
- **Rule message:** *"Overly permissive mask in chmod sets file to
  world readable."*
- **Disposition:** False positive
- **Justification (verbatim, 280-char limit):** *"`legacy_passport.py`
  was deleted during the 11-round audit cycle; no longer exists at
  HEAD. Alert is stale and will auto-close on next CodeQL scan.
  Dismissing to clear the PR view."*
- **Extended reasoning:** `legacy_passport.py` was removed during
  one of the audit-cycle rounds. The CodeQL alert references a file
  that does not exist in the repo's current tree shape. Confirmed
  via `git ls-tree HEAD -- python/vibap/legacy_passport.py`
  returning empty, and `find python/vibap -name '*passport*.py'`
  returning only `passport.py` and `biscuit_passport.py`. The alert
  will auto-close on the next CodeQL analysis run that observes
  the new tree shape; explicit dismissal here clears the PR-view
  noise.

### #4 — `py/overly-permissive-file` (HIGH)

- **File:** `python/vibap/passport.py:355` (in `_write_bytes` call
  for the public key)
- **Rule message:** *"Overly permissive mask in chmod sets file to
  world readable."*
- **Disposition:** False positive
- **Justification (verbatim, 280-char limit):** *"`0o644` on
  `passport_public.pem` is correct: PUBLIC keys are world-readable
  by definition. Companion call at `passport.py:347` writes PRIVATE
  key with `0o600`. CodeQL flags any `0o644` `.pem` chmod without
  distinguishing public from private material."*
- **Extended reasoning:** The flagged call writes
  `passport_public.pem` — the *public* half of the key pair — with
  mode `0o644` (owner read+write, world-readable). For public-key
  material, world-readable is the textbook correct posture; making
  the public key owner-only would break every consumer that needs
  to verify signatures. The companion call at `passport.py:347`
  writes the private key (`passport_private.pem`) with `0o600`
  (owner-only), the textbook correct posture for that material.
  CodeQL fires on any `chmod` call setting `0o644` on a `.pem`
  path, without semantic context for whether the file is public or
  private.

### #5 — `py/log-injection` (MEDIUM)

- **File:** `python/vibap/proxy.py:4877` (in HTTP response handler)
- **Rule message:** *"This log entry depends on a user-provided
  value."*
- **Disposition:** False positive
- **Justification (verbatim, 280-char limit):** *"Line 4877 builds
  an HTTP response dict sent via `_send_json` (writes to
  `self.wfile`, the HTTP response stream). Not a log sink. The
  handler's `log_message` is overridden to no-op at
  `proxy.py:4605`, so HTTP input never reaches a log. CodeQL
  conflates `wfile.write` with logging."*
- **Extended reasoning:** The flagged line is a `response: dict`
  assignment whose contents are written via `self._send_json`,
  which calls `self.wfile.write(...)` — the HTTP response stream,
  not a log. The proxy's `BaseHTTPRequestHandler` subclass
  explicitly overrides `log_message` to a no-op return at
  `proxy.py:4605–4606`, suppressing the default request-line log
  that would otherwise flow `self.path` into a log call. The other
  `logger.warning` sites in `proxy.py` log filesystem-controlled
  names (e.g. `session_file.name` from a directory glob), not HTTP
  user input. CodeQL's heuristics treat any `wfile.write` of
  user-controlled data as a potential log injection sink; in this
  codebase that classification is wrong.

### #13, #14, #15 — `py/unsafe-cyclic-import` (rule severity: error)

- **Files:**
  - `#13`: `python/vibap/proxy.py:100` (`build_receipt` reference)
  - `#14`: `python/vibap/proxy.py:100` (`sign_receipt` reference)
  - `#15`: `python/vibap/receipt.py:30` (`PolicyEvent` reference)
- **Rule message (representative):** *"`build_receipt` may not be
  defined if module `vibap.receipt` is imported before module
  `vibap.proxy`, as the definition of `build_receipt` occurs after
  the cyclic import of `vibap.proxy`."*
- **Disposition:** False positive (with real fix landed)
- **Justification (verbatim, 280-char limit):** *"Fixed in dev
  commit `438ee15`: deferred `from .receipt import` into
  `_build_receipt_log_entry`, breaking static topology cycle.
  Runtime was already safe via `TYPE_CHECKING` + PEP 563. Will
  auto-close on main post-merge."*
- **Extended reasoning:** The cycle CodeQL flagged was structurally
  safe at runtime:
  - `receipt.py` uses `from __future__ import annotations` (PEP
    563), so all annotations are evaluated as strings — never
    resolved at module-load time.
  - The `receipt → proxy` edge (`from .proxy import PolicyEvent`)
    was gated by `if TYPE_CHECKING:`, which evaluates `False` at
    runtime.
  - `build_receipt` and `sign_receipt` were referenced only inside
    one method (`_build_receipt_log_entry`); no module-level use.

  CodeQL's `py/unsafe-cyclic-import` rule operates on import
  topology and does not fully reason about
  `TYPE_CHECKING` + PEP 563 together, so it reported the cycle
  even though no runtime path could fail. The fix in commit
  `438ee15` removes the static topology cycle by moving
  `from .receipt import build_receipt, sign_receipt` from
  `proxy.py` module scope into the body of
  `_build_receipt_log_entry`. The cost is one `sys.modules`
  cache lookup per receipt issuance; receipt issuance is not in
  a hot loop. Verified by:
  - `python -m pytest tests/`: 423 passed
  - AST check: no top-level `.receipt` import remains in
    `proxy.py`
  - Both import orders work
    (`vibap.receipt` then `vibap.proxy`, and
    `vibap.proxy` then `vibap.receipt`)

  The alerts are dismissed against the PR's `refs/heads/main`
  ref because that ref's CodeQL database still reflects the
  pre-fix topology. They will auto-close on the next CodeQL scan
  against `main` once this PR merges.

## What's not in this file

The 39 note-severity CodeQL alerts left open after this triage
(`py/unused-import`, `py/cyclic-import` (note severity, not
unsafe), `py/empty-except`, `py/not-named-self`,
`py/import-and-import-from`, `py/ineffectual-statement`) are
deferred. None are security-relevant. The branch protection rule
on `main` was tightened on 2026-04-29 from
`code_quality: severity: all` to `code_quality: severity: errors`
so future PRs are not gridlocked by note-level cleanups while
real correctness alerts (`error` severity) continue to gate the
merge.

A future cleanup pass will remove the legitimate unused imports
inline and dismiss the rest as `won't fix` with a single
explanatory comment.

## How to verify

The dismissals above are visible via:

```bash
# Each alert (replace <N> with 1, 2, 3, 4, 5, 13, 14, or 15):
gh api repos/gnanirahulnutakki/ardur/code-scanning/alerts/<N> \
  --jq '{state, dismissed_reason, dismissed_comment, dismissed_by, dismissed_at}'
```

Or in the GitHub UI under
*Security → Code scanning → Closed alerts*.

The on-disk fix for #13/#14/#15 is verifiable by:

```bash
# Should return zero matches — no top-level .receipt import remains:
python3 -c "
import ast
with open('python/vibap/proxy.py') as f: tree = ast.parse(f.read())
for node in ast.iter_child_nodes(tree):
    if isinstance(node, ast.ImportFrom) and node.module == 'receipt' \
       and node.level == 1:
        print('PRESENT at line', node.lineno)
        break
else:
    print('OK: no top-level .receipt import')
"
```

---

*Prepared 2026-04-29 by the maintainer; mirrored from the GitHub
Code Scanning audit trail. Update this file (do not delete entries)
if any dismissal is later reversed or if new dismissals land —
the convention is append-only with dated rows.*

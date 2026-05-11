# Ardur Phase 2 Daemon Preflight + Protocol Scaffold

Date: 2026-05-10
Status: PASS for Slice 2 read-only preflight inspection and local socket contract scaffold. This slice does not install, start, bind, listen, expose a service, pin BPF maps, or mutate privileged paths.

## Scope implemented

Added `go/pkg/kernelcapture/daemon_preflight.go` and tests:

- `InspectDaemonCustodyPreflight` inspects the future root-owned daemon config/state/runtime/socket/bpffs boundary through an injected read-only filesystem/stat interface.
- Findings are machine-readable: check name, path category, expected mode/owner, observed mode/owner when available, verdict, resolved path, symlink flag, and remediation text.
- Tests cover safe root-owned defaults, missing paths, symlink paths, symlink-aware realpath escape, wrong mode, wrong owner, non-permission mode bits, file-vs-directory mismatch, non-socket socket paths, and repository-controlled privileged paths.
- Tests use a fake filesystem and do not depend on host `/etc`, `/var`, `/run`, or `/sys/fs/bpf`.

Added `go/pkg/kernelcapture/daemon_protocol.go` and tests:

- The future launch-wrapper-to-daemon contract is newline-delimited deterministic JSON.
- Requests are defined for `health`, `register_session`, `end_session`, and `session_status`.
- `register_session` accepts unprivileged session/mission/trace identity and observed root PID, PID namespace id, cgroup id, requested event classes, and bounded TTL.
- Validation rejects unknown protocol versions, unknown event classes, missing session ids, duplicate event classes, unbounded TTLs, unknown raw fields, trailing non-JSON data, and raw client-supplied privileged path fields such as bpffs/socket/config paths. The privileged-field guard is recursive and case-insensitive by design; clients should not place daemon-owned filesystem authority anywhere in request metadata.
- No socket server, bind, listen, peer credential check, or daemon process exists in this slice.

Updated `go/pkg/kernelcapture/linux_ebpf_smoke_linux.go` sequencing:

- Positive cgroup-filter smoke now validates and inserts allowlist entries before enabling the filter.
- Negative cgroup-filter smoke enables filtering only after inserting a non-matching allowlist entry, keeping the explicit invariant that filtering is not enabled with an empty allowlist.

## Works now

Ardur now has:

- a read-only daemon custody preflight inspector for root-owned config/state/runtime/socket/bpffs expectations;
- structured diagnostics for mode, owner, type, missing path, symlink, realpath boundary, non-permission mode bits, and repository-control failures;
- fail-closed treatment of setuid, setgid, and sticky bits so special mode inheritance is investigated before any future privileged daemon trusts the path;
- a deterministic local JSON protocol contract for future launch-wrapper clients;
- validation that cgroup filtering must not be enabled before non-zero allowlist entries exist.

## Not claimed

- production daemon readiness
- daemon installation or startup
- socket server, listener, bind, or exposed service
- peer credential enforcement over Unix sockets
- bpffs map pinning or privileged filesystem mutation
- daemon-created per-session cgroups
- universal CLI capture
- file/network/privilege side-effect capture

## Verification

Commands run from this worktree:

```bash
./scripts/conductor-bootstrap.sh
cd go && GOCACHE=/tmp/ardur-go-build-cache go test ./pkg/kernelcapture -count=1
cd go && GOCACHE=/tmp/ardur-go-build-cache go test -race ./pkg/kernelcapture -count=1
cd go && GOCACHE=/tmp/ardur-go-build-cache GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test
python3 site/scripts/sync_source_docs.py --check
python3 site/scripts/validate_claims.py
git diff --check
./scripts/check-local.sh --quick --python <python-with-pyyaml>
gitleaks detect --source . --no-git --redact
```

All Go, source-mirror, claim, diff, quick hygiene, and gitleaks gates passed locally. The quick hygiene command used an existing Python environment with PyYAML available so tracked YAML parsing was exercised instead of skipped.

A local Hugo binary was not available in this environment, so rendered-site build/link/provenance validation remains the GitHub `hugo-site` post-push gate for this slice.

## Residual risk

This is still a contract and inspection slice. The future daemon must add the Unix socket server, peer credential verification, daemon-owned cgroup creation or adoption policy, map-pinning ownership checks, and degraded/unknown receipt behavior when preflight fails or the daemon is unavailable.

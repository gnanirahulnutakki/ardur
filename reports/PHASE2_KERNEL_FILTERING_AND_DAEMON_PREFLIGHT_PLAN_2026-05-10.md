# Ardur Phase 2 Technical Plan — Kernel Filtering + Daemon Preflight

Date: 2026-05-10
Status: planned; no daemon install/start and no public-release claim.
Base: `origin/dev` at `71e3a60` (`feat(kernelcapture): add daemon custody scaffold`).
Owner-facing objective: move the current Linux eBPF proof from userspace-filtered smoke evidence toward a defensible daemon-owned capture boundary, without overclaiming production readiness.

## Current technical baseline

The current `kernelcapture` package already has:

- metadata-only `sched/sched_process_exec` + `sched/sched_process_exit` eBPF tracepoint producers.
- generated/embedded eBPF object committed to the Go package.
- ringbuf decoding for event type, monotonic timestamp, PID, PPID, TID, PID namespace id, cgroup id, `comm`, and exit code.
- a userspace correlator that projects process lifecycle events into honest synthetic kernel-effect receipts.
- a live, gated privileged Linux smoke runner: `scripts/run-phase2-ebpf-smoke.sh`.
- a local-only daemon custody scaffold: `BuildDaemonCustodyPlan`, including root-owned config/state/runtime/socket/bpffs defaults and mode/path validation.

The current limitation is important: session scoping is still userspace filtering after ringbuf emission. It proves event capture and correlation, but it does not yet prove daemon-owned kernel filtering or per-session capture boundaries.

## Decision

The next technical focus is **kernel-enforced cgroup/session filtering plus daemon preflight**, not file/network capture yet.

Reasoning:

1. File/network event classes would multiply data volume and claim surface before the capture boundary is trustworthy.
2. Universal CLI coverage depends on a daemon/wrapper contract; kernel filtering is the smallest concrete step toward that contract.
3. A preflight inspector is the safe bridge from the current dry-run custody scaffold to future privileged IO. It can be implemented and tested without creating directories, pinning maps, starting daemons, or touching `/etc`, `/var`, `/run`, or `/sys/fs/bpf`.

## Claim boundary for this plan

Allowed after all gates pass:

> Ardur has a local Linux eBPF process-lifecycle proof that can optionally filter ringbuf emission by daemon-populated cgroup allowlist state, plus a no-mutation daemon preflight inspector for the future root-owned config/state/runtime/socket/bpffs boundary.

Not allowed after this plan:

- production daemon readiness.
- daemon installation/startup.
- universal CLI capture.
- file/network/privilege side-effect capture.
- unprivileged/no-install eBPF support.
- macOS/Windows kernel capture.
- claim that every subprocess is captured outside the gated Linux proof environment.

## Implementation sequence

### Slice 1 — Kernel cgroup allowlist map, disabled by default

Goal: add a kernel-side filter gate before ringbuf reservation while preserving the existing unfiltered smoke path.

Files expected to change:

- `go/pkg/kernelcapture/process_exec.bpf.c`
- generated eBPF object/source under `go/pkg/kernelcapture/`
- `go/pkg/kernelcapture/linux_ebpf_smoke_linux.go`
- `go/pkg/kernelcapture/linux_ebpf_smoke_linux_test.go`
- package README/report updates after verification

Design:

- Add a small filter-control map, likely a one-entry `BPF_MAP_TYPE_ARRAY` keyed by `uint32(0)`:
  - value `0`: filter disabled; current behavior, emit events for all observed processes.
  - value `1`: filter enabled; emit only if current cgroup id is present in the allowlist map.
- Add an `allowed_cgroups` hash map:
  - key: `uint64` cgroup id from `bpf_get_current_cgroup_id()`.
  - value: small marker byte or struct; no payload or secrets.
  - bounded `max_entries`, initially conservative (for example 1024).
- In both exec and exit tracepoint handlers:
  - compute current cgroup id once.
  - if filter disabled, keep current behavior.
  - if filter enabled and cgroup id is absent, return before ringbuf reserve/submit.
  - include the same cgroup id in emitted metadata when allowed.
- Expose loader helpers in Go to enable/disable filtering and update/delete allowed cgroups.
- Keep the default smoke and unit tests unfiltered so macOS/offline checks remain stable.

Acceptance tests:

1. Existing offline package tests pass:
   - `cd go && go test ./pkg/kernelcapture -count=1`
   - `cd go && go test -race ./pkg/kernelcapture -count=1`
2. Linux arm64 compile gate passes:
   - `cd go && GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test`
3. Existing live smoke still passes through `scripts/run-phase2-ebpf-smoke.sh`.
4. New gated live smoke proves positive filter behavior:
   - enable filter.
   - insert the current test-runner cgroup id into `allowed_cgroups`.
   - run a deterministic child command.
   - observe exec+exit samples from that cgroup.
5. New gated live smoke proves negative filter behavior:
   - enable filter with no matching cgroup or an impossible cgroup.
   - run deterministic child command.
   - assert target exec+exit samples are not emitted before timeout.
6. The smoke report must explicitly say this proves cgroup allowlist map filtering, not per-session cgroup creation or production daemon custody.

Important caveat:

The local Podman smoke may run the test process and child commands in a shared container cgroup. That is enough to prove kernel map filtering, but not enough to prove user-facing per-command isolation. Per-session cgroup creation belongs to a later wrapper/daemon integration slice.

### Slice 2 — No-mutation daemon preflight inspector

Goal: add a realpath/ownership/mode inspection layer that can be used before any future privileged daemon install/start work.

Files expected to change:

- `go/pkg/kernelcapture/daemon_preflight.go`
- `go/pkg/kernelcapture/daemon_preflight_test.go`
- possibly `go/pkg/kernelcapture/daemon_custody.go` only for shared types/helpers
- docs/report updates after verification

Design:

- Add `InspectDaemonCustodyPreflight(cfg DaemonCustodyConfig, opts ...) (DaemonPreflightReport, error)`.
- It must perform inspection only; no mkdir, chmod, chown, bind, socket listen, map pinning, service install, or daemon start.
- It should distinguish:
  - missing path.
  - present path.
  - symlink path.
  - non-directory where directory expected.
  - non-socket where socket expected.
  - wrong owner/group.
  - wrong mode.
  - path escaping configured boundary after symlink-aware realpath evaluation.
  - repo-controlled path when repository-root validation context is provided.
- It should return structured machine-readable findings:
  - check name.
  - path category: config, state dir, runtime dir, socket, bpffs dir, bpffs map.
  - expected mode/owner.
  - observed mode/owner when available.
  - verdict: pass, warn, fail, missing.
  - remediation text that does not run automatically.
- Use an injected filesystem/stat interface for unit tests so tests do not depend on host `/etc`, `/var`, `/run`, or `/sys/fs/bpf`.
- Keep the existing dry-run `BuildDaemonCustodyPlan` path intact.

Acceptance tests:

1. Table-driven unit tests cover:
   - safe root-owned defaults.
   - missing paths reported without mutation.
   - symlink escape rejection.
   - wrong mode rejection.
   - wrong owner rejection.
   - file-vs-directory mismatch.
   - repository-root path rejection with validation context.
2. `go test -race ./pkg/kernelcapture -count=1` passes.
3. Documentation states preflight is inspection-only and not daemon startup.
4. No test writes to privileged system paths.

### Slice 3 — Local socket protocol draft, no server yet

Goal: define the future launch-wrapper-to-daemon contract as types/tests before implementing a daemon.

Files expected to change:

- `go/pkg/kernelcapture/daemon_protocol.go`
- `go/pkg/kernelcapture/daemon_protocol_test.go`
- docs/report updates after verification

Design:

- Use a newline-delimited JSON or length-prefixed JSON protocol over Unix domain sockets. Pick one format and specify it explicitly.
- Define request/response structs for:
  - `health`.
  - `register_session`.
  - `end_session`.
  - possibly `session_status`.
- `register_session` request should include only unprivileged session intent and observed process identity:
  - protocol version.
  - session id / mission id / trace id.
  - root pid or pidfd-backed identity when available.
  - pid namespace id when available.
  - cgroup id when available.
  - allowed event classes requested, initially `process_lifecycle` only.
  - deadline/ttl.
- The client must not be allowed to supply privileged paths such as bpffs map paths, config paths, or socket paths. Those stay daemon-owned.
- Future Linux daemon implementation must verify peer credentials via platform-appropriate Unix socket credentials before accepting mutating requests. This slice only defines the contract and tests validation.

Acceptance tests:

1. Valid `health`, `register_session`, and `end_session` messages encode/decode deterministically.
2. Unknown protocol version rejects.
3. Unknown event class rejects.
4. Missing session id rejects.
5. Client-supplied privileged path fields are impossible by type design or rejected if present in raw JSON.
6. TTL/deadline bounds reject nonsensical or unbounded sessions.

### Slice 4 — Wrapper/daemon integration design checkpoint

Goal: after slices 1-3, choose the smallest runnable integration path for `ardur run -- COMMAND ...`.

Do not implement this until slices 1-3 have landed and been reviewed.

Expected decision points:

- Whether the first integration creates a dedicated cgroup per `ardur run` invocation, or only registers the existing wrapper cgroup as a transition step.
- Whether Linux support lives initially in Go-only helper binaries or is invoked from the existing Python `ardur` CLI.
- Whether the daemon should be one root-owned process or a split unprivileged client + privileged helper.
- How receipt chains should represent kernel-capture degraded/unknown states when the daemon is absent, down, or rejected by preflight.

Approval boundary:

Creating persistent services, installing unit files, modifying system cgroup layout, or starting a long-lived privileged daemon requires explicit owner approval. Those are not part of this plan's implementation phase.

## Test and verification matrix

Run these before any completion claim:

```bash
./scripts/conductor-bootstrap.sh
cd go && go test ./pkg/kernelcapture -count=1
cd go && go test -race ./pkg/kernelcapture -count=1
cd go && GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test
./scripts/run-phase2-ebpf-smoke.sh
python3 site/scripts/sync_source_docs.py --check
./scripts/check-local.sh --quick
git diff --check
```

If the live eBPF smoke fails due to local environment/capability drift, preserve the code and report the exact failure as environment evidence. Do not fake kernel-filter evidence with replay events.

## First Codex implementation task

Title: `Phase 2: add gated cgroup allowlist filtering to kernelcapture eBPF smoke`

Task spec:

- Work from a clean worktree based on `origin/dev` after this plan lands.
- Implement Slice 1 only.
- Keep filter disabled by default so the current smoke remains unchanged.
- Add positive and negative gated live smoke tests behind `ARDUR_RUN_EBPF_SMOKE=1`.
- Regenerate eBPF artifacts only through the repo's documented Linux dev image/toolchain.
- Update reports/README with precise claim boundaries.
- Run the full verification matrix applicable to Slice 1.
- Stop before daemon preflight, socket server, file/network capture, public release, or any system service changes.

## Residual risks to watch

- eBPF verifier constraints may reject more complex map/filter logic; keep the C helper minimal.
- Negative smoke tests can become flaky if the test environment emits unrelated allowed-cgroup events; scope assertions to the deterministic child PID/comm and keep timeout tight.
- Cgroup id alone proves map filtering, not per-command isolation in a shared container. Documentation must keep this boundary explicit.
- Generated eBPF artifacts must stay reproducible enough for review; record the exact generation command/toolchain in the report.
- Preflight tests must not depend on the host filesystem or root privileges.

## Planned stopping point for the next implementation cycle

The next cycle is complete when Slice 1 is implemented, verified, reviewed, documented, and landed to `dev` with a report that makes the cgroup-filter claim exactly and narrowly.

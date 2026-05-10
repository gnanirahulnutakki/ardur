# Ardur Phase 2 eBPF MVP Plan — 2026-05-10

Status: active local implementation plan.
Owner-facing objective: deliver a narrow, evidence-backed Linux eBPF MVP without drifting into production-daemon, universal-CLI, file/network, or public-release claims.

## Starting evidence

- Phase 1 tool-boundary MVP is already verified in candidate form; Phase 2 is now explicitly prioritized by Rahul.
- Host is macOS/Darwin, so native eBPF cannot run on the host.
- Local Linux target exists through `podman-machine-default`:
  - Fedora CoreOS, linux/arm64
  - kernel `6.19.7-200.fc43.aarch64`
  - BTF present at `/sys/kernel/btf/vmlinux`
  - bpffs mounted at `/sys/fs/bpf`
  - unprivileged BPF disabled (`2`), so the live smoke must be privileged inside the local Podman VM/container.
- Local eBPF dev image is built:
  - tag `ardur-ebpf-dev:fedora43`
  - Go 1.25.9 linux/arm64
  - clang/LLVM 21.1.8
  - bpftool 7.6.0 / libbpf 1.6

## Chosen MVP slice

Implement the smallest live-kernel path that proves the Phase 2 architecture direction:

1. Add a Go `kernelcapture` package from the existing local proof harness if it is not already in the clean worktree.
2. Add a Linux-only eBPF process-exec producer with paired process-exit evidence:
   - tracepoints: `sched/sched_process_exec` and `sched/sched_process_exit`.
   - map: ringbuf emitting the existing fixed process exec+exit metadata layout.
   - fields: event type, monotonic timestamp, PID, PPID, TID, PID namespace id, cgroup id, comm, and `exit_code` on exit events.
3. Add a Linux-only loader/smoke path:
   - loads the compiled eBPF object with `github.com/cilium/ebpf`.
   - attaches tracepoint locally.
   - starts ringbuf reader.
   - runs a deterministic child command.
   - confirms scoped exec and exit events for the target process/session boundary.
   - passes the samples through the existing decoder/correlator projection.
4. Add an explicit gated test or command:
   - normal `go test ./pkg/kernelcapture` remains unprivileged/offline and passes on macOS.
   - live kernel smoke runs only when `ARDUR_RUN_EBPF_SMOKE=1` and on Linux with privileges.
5. Add docs and reports that keep claims narrow.

## Non-goals for this MVP

- No daemon install, launchd/systemd service, persistent root process, or package installer.
- No public GitHub push/PR/issue/release.
- No macOS ESF or Windows ETW implementation.
- No file open/write/unlink or network connect capture yet.
- No raw argv/env/path capture.
- No production signing-key custody or broad append-chain integration.
- No claim that all subprocesses or all CLI side effects are captured.

## Acceptance criteria

### Required before claiming MVP complete

1. Clean local worktree from `origin/dev` contains the Phase 2 MVP code and docs.
2. `./scripts/conductor-bootstrap.sh` succeeds in the worktree.
3. Host/offline checks pass:
   - `cd go && go test ./pkg/kernelcapture -count=1`
   - `cd go && go test -race ./pkg/kernelcapture -count=1`
   - `cd go && GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test`
4. Linux privileged smoke passes inside the local Podman VM/container:
   - `ARDUR_RUN_EBPF_SMOKE=1 go test ./pkg/kernelcapture -run TestLinuxEBPFSmoke -count=1`
   - or an equivalent repo-local smoke script/command with persisted output.
5. The smoke output includes:
   - kernel, distro/container, BTF, privilege/capability evidence.
   - attached tracepoint names.
   - event observed count.
   - no ringbuf loss reported in normal smoke.
   - a synthetic kernel-effect projection with honest `coverage_status`, `correlation_method`, and `verdict`.
6. Final report exists under `reports/` with exact commands, pass/fail, limitations, and next tasks.
7. No secret-pattern hits in new/changed files.

### Allowed MVP claim if all required gates pass

“Ardur has a local Linux eBPF process-exec MVP with paired process-exit evidence: in a privileged Podman Linux VM/container it can load `sched_process_exec`/`sched_process_exit` tracepoint producers, read scoped ringbuf exec+exit metadata events, and project them into honest synthetic kernel-effect evidence.”

### Disallowed claims after this MVP

- “Full eBPF capability.”
- “Production-ready Linux daemon.”
- “Universal tool-agnostic CLI coverage.”
- “File/network/privilege side effects are captured.”
- “No-privilege or no-install eBPF support.”

## Drift guards

- If the live eBPF smoke blocks, keep implementing offline/codegen/testable pieces; do not rewrite Phase 2 into only docs.
- If a privilege/kernel limitation appears, report it as an MVP blocker and keep the code gated rather than faking evidence.
- If cilium/bpf2go codegen gets too costly, fallback to a simple generated object path only if it still loads and emits real ringbuf samples.
- Preserve the existing Phase 1 claim boundary. Phase 2 work must not contaminate Phase 1 readiness claims.

## Worktree plan

Create/use:

`phase2-ebpf-mvp-2026-05-10 worktree`

Local branch:

`phase2-ebpf-mvp-2026-05-10`

Diff base:

`origin/dev`

The existing dirty proof harness worktree remains preserved as source evidence:

`ebpf-correlation-proof worktree`

## Continuous 5-hour operator loop

After the initial MVP implementation path is started, run a local background watchdog/loop for at least five hours that:

1. records checkpoints under `logs/phase2-ebpf-loop/` or `reports/`.
2. repeats safe targeted checks after each code change.
3. records blockers with exact command output.
4. does not push, publish, expose services, or delete user data.
5. stops only for completion, a real red-line boundary, or a blocker that cannot be resolved locally.

## Next implementation order

1. Create clean worktree from `origin/dev`.
2. Copy/reconcile the existing `kernelcapture` proof harness into that worktree.
3. Add eBPF C program + bpf2go/generated object workflow.
4. Add Linux-only smoke test/loader.
5. Run host Go tests and Linux privileged smoke.
6. Patch docs/report/checkpoints.
7. Start/continue autonomous background loop to harden, test, and report for five hours.

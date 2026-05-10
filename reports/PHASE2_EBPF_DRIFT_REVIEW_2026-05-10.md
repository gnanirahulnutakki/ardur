# Ardur Phase 2 eBPF MVP Drift Review — 2026-05-10

Owner: Hermes
Reviewer: Codex worker, supervised by Hermes
Scope: local-only adversarial status/drift review of `/Users/gnutakki/.hermes/workspace/projects/ardur/worktrees/phase2-ebpf-mvp-2026-05-10`.

## Verdict

ON TRACK for Rahul's narrow Phase 2 MVP presentation.

No significant drift or looping detected. The implementation remains tightly scoped to the intended MVP: local Linux privileged `sched_process_exec` capture with paired `sched_process_exit` lifecycle evidence, ringbuf transport, Go decode/correlation, and honest synthetic kernel-effect evidence. It does not drift into production daemonization, cross-platform claims, file/network capture, public release, or universal CLI coverage.

## Evidence checked

The reviewer inspected:

- worktree status and diff
- `go/pkg/kernelcapture/*`
- `reports/PHASE2_EBPF_MVP_VERIFICATION_2026-05-10.md`
- `reports/phase2-ebpf-smoke-output-rootful.txt`
- `reports/phase2-ebpf-smoke-output.txt`

The reviewer re-ran safe local checks:

```bash
cd go && go test ./pkg/kernelcapture -count=1
cd go && go test -race ./pkg/kernelcapture -count=1
cd go && GOOS=linux GOARCH=arm64 go test ./pkg/kernelcapture -c -o /tmp/kernelcapture-linux-arm64.test
./scripts/check-local.sh --quick
```

All passed during the review.

Hermes then added the missing packaging pieces identified by the review:

- copied `reports/PHASE2_EBPF_MVP_PLAN_2026-05-10.md` into this worktree.
- copied `reports/PHASE2_EBPF_TOOL_INVENTORY_2026-05-10.md` into this worktree.
- copied `tooling/phase2-ebpf/Containerfile` into this worktree.
- added repeatable smoke runner `scripts/run-phase2-ebpf-smoke.sh`.
- re-ran the live rootful smoke through the script; it passed.

## Findings

### Blocker

None.

### High

None.

### Medium

Resolved during follow-up:

1. Plan/inventory/tooling artifacts were outside the clean Phase 2 worktree.
   - Fixed by copying them into `reports/` and `tooling/phase2-ebpf/` inside the worktree.

2. Handoff durability was weak because the smoke command was only documented as an expanded manual command.
   - Fixed by adding and executing `scripts/run-phase2-ebpf-smoke.sh`.

3. Verification/report language lagged the exec+exit smoke update and still described a single exec tracepoint/sample.
   - Fixed by tightening README, plan, inventory, verification, and drift-review wording to `sched_process_exec` + paired `sched_process_exit` metadata evidence without expanding into broader side-effect claims.

Still open:

1. Files remain local/uncommitted in the worktree.
   - This is acceptable for local MVP presentation, but should be snapshotted in a local commit before any longer handoff/review cycle.
   - No public push/PR should happen without Rahul's explicit approval.

### Low

1. The MVP is Linux/privileged-environment dependent by design; this is documented and honest.
2. The rootless privileged Podman failure is useful negative evidence and should stay in the report.

## Claim boundary

Allowed:

Ardur has a local Linux eBPF process-exec MVP with paired process-exit evidence: in a privileged Podman Linux VM/container it can load `sched_process_exec`/`sched_process_exit` tracepoint producers, read scoped ringbuf exec+exit metadata events, and project them into honest synthetic kernel-effect evidence.

Not allowed:

- production daemon readiness
- universal CLI capture
- file/network/privilege side-effect capture
- macOS/Windows kernel capture
- unprivileged/no-install eBPF support
- public release readiness

## Final status

Presentation readiness: PASS for the narrow local Phase 2 eBPF MVP.

Next non-public step: keep the 5-hour autonomous loop focused on regression checks, packaging, and local snapshot readiness only. Do not expand scope into daemon, network/file capture, or public release work unless Rahul explicitly reprioritizes.

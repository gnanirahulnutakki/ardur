# Execution Receipt Kernel-effect Extension v0.1 (proposed)

> **Public-import note.** This document was authored against the private research repo's `docs/spec/` layout. In the public ardur tree, migrated specs live under `docs/specs/`. Any `docs/spec/...` path reference in the body refers to the original private layout; the public-tree mapping is in [`docs/specs/README.md`](./README.md).

## 1. Scope

This document defines a **proposed extension** to the v0.1 Execution Receipt
(ER) claim set for kernel-observed effects.

The extension is designed for future Linux eBPF, macOS Endpoint Security, and
Windows ETW/WFP capture backends. It records observed kernel effects and their
causal links back to a tool-call receipt.

This is a docs/spec/schema proposal only. It does not claim production kernel
capture is implemented today.

This document uses the key words **MUST**, **MUST NOT**, **SHOULD**,
**SHOULD NOT**, and **MAY** as described in BCP 14 (RFC 2119 / RFC 8174).

## 2. Why this extension exists

Base ER v0.1 receipts prove what Ardur observed at the tool boundary. They do
not yet carry first-class claims for subprocess trees, file syscalls, network
connectivity, or privilege-changing operations observed below that boundary.

Kernel-effect receipts close that gap by adding:

- explicit causal provenance (`caused_by_receipt_id`)
- correlation quality metadata (`correlation_method`,
  `correlation_confidence`)
- visibility-health metadata (`coverage_status`, `capture_loss`)

## 3. Non-goals

This extension does not:

- claim complete host visibility
- claim provider-side model visibility
- change default policy posture to blocking
- imply production readiness of any privileged daemon

Ambiguous attribution and degraded telemetry MUST be represented as evidence
limitations, not converted into confident compliance claims.

## 4. Extension integration model

`execution-receipt-v0.1.schema.json` is strict (`additionalProperties: false`).
So this extension is published as an overlay schema:

- Base schema: `execution-receipt-v0.1.schema.json`
- Extension overlay schema:
  `execution-receipt-kernel-effect-extension-v0.1.schema.json`

Receivers that do not opt into the extension continue to reject these extra
claims (expected and fail-closed). Implementations that opt in MUST merge base
ER properties with extension properties and evaluate both rule sets.

## 5. Required extension claims

When a receipt has `event_class = "kernel_effect"`, these extension claims are
required:

| Claim | Type | Meaning |
|---|---|---|
| `event_class` | const | MUST be `kernel_effect`. |
| `capture_backend` | enum | `linux_ebpf`, `macos_esf`, `windows_etw`, or `unknown`. |
| `platform` | enum | `linux`, `macos`, `windows`, or `unknown`. |
| `kernel_event_type` | string | Normalized event family (`execve`, `openat`, `connect`, `setuid`, ...). |
| `coverage_status` | enum | `complete`, `degraded`, `dropped`, or `unknown`. |
| `correlation_method` | enum | How causal attribution was computed. |
| `correlation_confidence` | enum | `high`, `medium`, `low`, or `ambiguous`. |
| `caused_by_receipt_id` | string | ER `receipt_id` of the triggering tool-call receipt. |

## 6. Honesty constraints (load-bearing)

Kernel-effect extension claims MUST obey:

1. If `correlation_method = "ambiguous"`, or `correlation_confidence` is
   `low` or `ambiguous`, `verdict` MUST be `insufficient_evidence`.
2. If `coverage_status` is `degraded`, `dropped`, or `unknown`, `verdict` MUST
   be `insufficient_evidence`.
3. If `capture_loss.ringbuf_dropped > 0` or
   `capture_loss.daemon_queue_dropped > 0`, `coverage_status` MUST be
   `degraded` or `dropped`, and `verdict` MUST be `insufficient_evidence`
   unless a future version defines a narrow, machine-testable exception.
4. Whenever any rule above forces `insufficient_evidence`,
   `public_denial_reason` MUST be `insufficient_evidence` and
   `internal_denial_code` MUST be present.

These rules prevent ambiguous or partial telemetry from appearing as confident
compliance.

## 7. Recommended optional claims

These optional extension claims improve replay and analysis quality:

- `capture_backend_version`
- `observed_at_monotonic_ns`
- `observed_at_wall_time`
- `pid`, `tid`, `ppid`, `cgroup_id`
- `kernel_target` (file/socket/process/privilege metadata)
- `kernel_args_digest`
- `caused_by_receipt_hash`
- `coverage_gaps`
- `capture_loss`

Raw sensitive values SHOULD be minimized. Paths, argv-like data, and network
targets MAY be redacted or digest-only where needed for privacy.

## 8. Example extension fragment

```json
{
  "event_class": "kernel_effect",
  "capture_backend": "linux_ebpf",
  "platform": "linux",
  "kernel_event_type": "connect",
  "coverage_status": "complete",
  "correlation_method": "pid_ancestry",
  "correlation_confidence": "high",
  "caused_by_receipt_id": "er:task-00000001",
  "kernel_target": {
    "type": "socket",
    "socket_family": "AF_INET",
    "remote_addr": "203.0.113.8",
    "remote_port": 443
  }
}
```

## 9. Rollout expectations

This proposal enables unprivileged schema and golden-fixture tests now, before
privileged capture code exists.

Future implementation work (outside this spec proposal) is expected to:

- wire kernel backends into a daemon capture path
- emit extension claims in signed ERs
- add conformance vectors for ambiguous/degraded telemetry cases
- preserve explicit limitation language in public docs and status pages

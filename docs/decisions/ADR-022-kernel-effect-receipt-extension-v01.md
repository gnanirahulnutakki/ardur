# ADR-022: Kernel-effect Execution Receipt extension v0.1 (proposed)

Date: 2026-05-07

## Status

Proposed. Docs/spec/schema proposal only; no privileged capture implementation in this ADR.

## Context

Ardur v0.1 receipts are issued at the tool-call boundary. This proves what the
adapter observed at that boundary, but it does not yet provide first-class,
kernel-observed evidence for subprocess trees, filesystem syscalls, socket
activity, or privilege-changing operations caused by a tool call.

A 2026-05-07 kernel-capture design report produced in the operator workspace
recommends a daemon-first capture model where kernel effects become signed
receipts in the same chain as tool-call receipts. To do that honestly, receipt
claims must carry:

- causal links from kernel effect -> triggering tool-call receipt;
- correlation quality metadata when attribution is ambiguous; and
- explicit coverage-gap signals when telemetry was dropped or unavailable.

Existing `execution-receipt-v0.1.schema.json` is intentionally strict
(`additionalProperties: false`) and cannot carry proposed kernel-effect claims
without a versioned extension.

## Decision

Add a **proposed extension schema and spec** for kernel-effect receipts without
changing runtime behavior yet.

1. Add `docs/specs/execution-receipt-kernel-effect-extension-v0.1.md` as the
   normative proposal for kernel-effect claims.
2. Add `docs/specs/execution-receipt-kernel-effect-extension-v0.1.schema.json`
   as a proposal schema that extends the base ER claim set with kernel-effect
   fields.
3. Require kernel-effect receipts to model uncertainty explicitly:
   - `coverage_status` and `correlation_confidence` are mandatory extension
     claims when `event_class = "kernel_effect"`;
   - ambiguous attribution (`correlation_method = "ambiguous"`), low/ambiguous
     confidence, degraded/dropped/unknown coverage, or nonzero capture-loss
     counters MUST force `insufficient_evidence`;
   - when capture-loss counters are nonzero, `coverage_status` MUST be
     `degraded` or `dropped`;
   - those insufficient-evidence cases MUST carry
     `public_denial_reason = "insufficient_evidence"` and
     `internal_denial_code`.
4. Keep this work docs/spec/schema-only for now: no eBPF hooks, daemon hot-path,
   entitlement enrollment, or production readiness claims.

## Consequences

- We get a concrete, testable target for Linux v0.5 kernel-capture work while
  preserving the current v0.1 runtime behavior.
- The proposed schema can be validated with unprivileged golden fixtures before
  any privileged capture code exists.
- The extension enforces honesty boundaries in the schema itself: ambiguous
  attribution cannot be surfaced as `compliant`.
- Because the base runtime schema remains unchanged, current verifiers still
  reject these extension claims unless explicitly updated.

## Out of scope

- eBPF/ESF/ETW capture implementation.
- Daemon signing-key storage and key-rotation mechanics.
- Default blocking behavior changes (observation remains default posture).
- Public marketing claims about production kernel capture readiness.

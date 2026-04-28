# Mission Governance Protocol — v0alpha1

This directory defines the **VIBAP Mission Governance Protocol**, a structured schema set for declaring, observing, and adjudicating AI agent behavior at runtime.

The protocol enables a governance reconciler to compare an agent's *observed* actions against its *declared* mission permissions and produce compliance decisions with specific findings.

## Schemas

| File | Description |
|------|-------------|
| `declaration.schema.json` | **MissionDeclaration** — the permission set granted to an agent: allowed actions, tools, resources, side effects, and delegation constraints. |
| `event.schema.json` | **ObservedEvent** — a single action performed by an agent, including action class, tool, target, side effects, and observability metadata. |
| `finding.schema.json` | **Finding** — a specific observation from reconciliation: violation code, severity, affected event, and human-readable explanation. |
| `decision.schema.json` | **Decision** — the governance verdict after evaluating events against a declaration: compliance state, findings, and recommended containment action. |
| `session.schema.json` | **SessionState** — the full governance context: declaration, event stream, latest decision, and lifecycle phase. |

All schemas use [JSON Schema draft/2020-12](https://json-schema.org/draft/2020-12/schema).

## Examples

The `examples/` directory contains realistic, schema-valid documents:

| File | Schema | Scenario |
|------|--------|----------|
| `declaration-code-review.json` | declaration | Code review agent with read/write/search permissions |
| `declaration-data-analysis.json` | declaration | Data analysis agent with query/summarize/send permissions |
| `event-compliant-read.json` | event | Fully compliant file read with full visibility |
| `event-violation-exfiltration.json` | event | Exfiltration attempt — external send of raw records |
| `event-partial-visibility.json` | event | Credential file access with partial visibility |
| `decision-compliant.json` | decision | Clean pass — no findings, no action needed |
| `decision-violation.json` | decision | Multiple findings including exfiltration, recommended alert |
| `decision-unknown.json` | decision | Insufficient visibility to determine compliance |
| `session-active.json` | session | Full active session with declaration, 3 events, and decision |

## Validation

A purpose-built validator is provided at `cmd/specvalidate/`. It requires no external dependencies.

```bash
# From the VIBAP directory:

# Validate all examples against their matching schemas
go run ./cmd/specvalidate --all

# Validate a specific document against a schema
go run ./cmd/specvalidate \
  --schema spec/mission-governance/v0alpha1/event.schema.json \
  spec/mission-governance/v0alpha1/examples/event-compliant-read.json

# Run the test suite
go test ./cmd/specvalidate/...
```

## Relationship to Other Components

### Benchmark Schemas (`benchmark/schema/`)

The benchmark schemas (`scenario.schema.json`, `event.schema.json`) define the wire format for benchmark test scenarios and their synthetic events. This governance protocol generalizes those concepts for runtime use:

- The benchmark `declaration` object (embedded in scenarios) maps to `declaration.schema.json` here, with additional fields for session binding and metadata.
- The benchmark `event.schema.json` maps to `event.schema.json` here, minus the `expected_label` field (which is benchmark-specific ground truth) and `notes`.
- Enum values for `action_class`, `side_effect_class`, and `visibility` are identical across both.

### Go Types (`pkg/governance/types.go`)

The Go types in `pkg/governance/` are the canonical runtime implementation. These JSON Schemas describe the same structures for interoperability and external tooling:

| Go Type | JSON Schema |
|---------|-------------|
| `MissionDeclaration` | `declaration.schema.json` |
| `ObservedEvent` | `event.schema.json` |
| `Finding` | `finding.schema.json` |
| `Decision` | `decision.schema.json` |
| `SessionState` | `session.schema.json` |

Field names, enum values, and constraints are aligned between the Go types and JSON Schemas. The Go `Validate()` methods enforce the same invariants described in the schemas.

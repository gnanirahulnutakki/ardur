# Public Import Plan

This plan converts the private source tree into the public Ardur repo without
turning Ardur into a monorepo dump.

## Goals

- make Ardur a code-bearing public product repo
- keep the public root simple: docs, Python, Go, deploy, examples, workflows
- preserve `VIBAP`, `MCEP`, SPIFFE, Biscuit, AAT, EAT, and related protocol
  names where they describe real technical artifacts
- remove obsolete product codenames from public-facing copy, examples, media,
  paths, and capability IDs
- keep every public claim tied to exported code, verifier output, proof media,
  or an explicit limitation

## Target Layout

```text
ardur/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── docs/
├── python/
├── go/
├── deploy/
│   └── k8s/
│       └── spire/
├── examples/
└── .github/
    └── workflows/
```

## Source Mapping

| Source area | Ardur target | Mode | Notes |
|---|---|---|---|
| `vibap-prototype/vibap/` | `python/vibap/` | copy then rename public commands | Core Python runtime, CLI, receipts, passports, policy, proof tooling. |
| `vibap-prototype/verification/` | `python/verification/` | copy | Verifier and proof-bundle support. |
| `vibap-prototype/tests/` | `python/tests/` | curated copy | Keep tests that back public claims; defer corpus-heavy research tests. |
| `vibap-prototype/examples/` | `examples/missions/` | curated copy | Mission examples for quickstart. |
| selected demos | `examples/` | curated copy | SDK agents, live governance, hardening foundation, and delegation examples. |
| selected integrations | `python/integrations/` | curated copy | Include only framework surfaces claimed in docs. |
| `VIBAP/pkg/credential/` | `go/pkg/credential/` | copy | Credential issuance and verification. |
| `VIBAP/pkg/governance/` | `go/pkg/governance/` | copy | Core Go governance engine. |
| `VIBAP/pkg/policy/` | `go/pkg/policy/` | copy | Policy evaluation surface. |
| `VIBAP/pkg/spiffe/` | `go/pkg/spiffe/` | copy | SPIFFE/SPIRE identity path. |
| selected `VIBAP/pkg/*` | `go/pkg/*` | curated copy | Provenance, issuer, AAT, trust, transparency, API if referenced by retained code. |
| selected `VIBAP/cmd/*` | `go/cmd/*` | curated copy | CLI, operator, webhook, and live benchmark only if public docs use them. |
| `VIBAP/spec/mission-governance/v0alpha1/` | `go/spec/mission-governance/v0alpha1/` or `docs/spec/` | copy | Public schema and protocol-root material. |
| selected `VIBAP/benchmark/*` | `go/benchmark/*` | curated copy | Minimal reproducible scenario packs only. |
| `k8s/spire/` | `deploy/k8s/spire/` | copy | Deployment-oriented identity design surface. |
| source docs | `docs/` | rewrite | Use substance, not private session framing. |

## Exclude By Default

- local runtime state such as `.vibap/`
- private keys, tokens, generated receipts, and local evidence bundles unless
  intentionally reviewed as public fixtures
- session logs, inboxes, branch coordination notes, and AI-team runbooks
- machine-local paths and private workspace assumptions
- generated reports, build artifacts, caches, raw benchmark archives, and
  historical trace dumps
- side-program material unless it directly strengthens Ardur's public
  runtime-governance story

## Import Order

1. **Phase 0 shell**
   Keep the current intent, status, roadmap, media, and security docs accurate.

2. **Public-safe metadata**
   Add root `.gitignore`, packaging metadata, and public-safe workflows before
   importing large code surfaces.

3. **Python runtime and verifier**
   Import `python/vibap`, verifier tooling, selected tests, and a minimal local
   quickstart. Success means a new user can install the Python surface and run
   at least one proof-backed command.

4. **Examples**
   Import only curated examples that support the README story. Success means the
   examples run without private paths, private secrets, or hidden local state.

5. **Go runtime and protocol schemas**
   Import selected `VIBAP` Go packages, schemas, and module metadata. Success
   means `go/` is a coherent module, not a partial subtree.

6. **Deployment material**
   Import SPIRE/Kubernetes material with maturity labels and security notes.
   Success means deployment docs are honest about privileges, blast radius, and
   what has or has not been tested on a real cluster.

7. **Docs and article spine**
   Build public docs around quickstart, proof, framework integration, security,
   limitations, deployment, and protocol roots.

8. **CI and release gates**
   Add public-safe checks for Python, Go, docs, proof smoke, secret scanning, and
   forbidden internal-language scans.

## Release Discipline

- `dev` is the integration branch.
- `main` is release-only.
- Promote `dev` to `main` only after repeated local verification and passing CI.
- Any claim added to `main` must map to a command, artifact, verifier report, or
  limitation note.

## Verification Checklist

- no obsolete product codename strings in public files
- no machine-local paths
- no private session or coordination references
- no secrets or generated private keys
- README links all resolve
- Python quickstart passes
- proof smoke passes
- Go module sanity check passes for retained Go surface
- Kubernetes material passes schema checks or is explicitly marked design-only
- public workflows do not require private secrets

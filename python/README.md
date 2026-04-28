# Ardur — Python Reference Implementation

This directory holds the public Python reference implementation of Ardur's runtime governance + evidence layer. The package name on PyPI (eventual) is `ardur`; the internal Python module name is `vibap` — that's a deliberate technical-lineage choice (VIBAP is the original protocol research name, not a product codename).

## Quickstart (no API keys required)

```bash
# from the ardur repo root
cd python
pip install -e .

# Issue a passport for a mission
ardur issue \
  --agent-id alice \
  --mission "summarize sales from sales/q1.csv into reports/" \
  --allowed-tools read_file,write_report \
  --resource-scope 'sales/*,reports/*'

# Verify a passport
ardur verify <token-from-issue-output>
```

That sequence exercises key generation, mission compilation, passport issuance (signed with ES256), and passport verification — entirely local, no LLM access required.

## What's here

```
python/
├── vibap/                  # Core runtime package
│   ├── attestation.py      # Per-session attestation issuance + verify
│   ├── backends/           # Policy-engine adapters (Cedar, native, forbid-rules)
│   ├── biscuit_passport.py # Biscuit AAT/DG implementation
│   ├── cli.py              # ardur CLI entrypoint
│   ├── mission.py          # Mission Declaration parsing + cache
│   ├── passport.py         # Passport issuance + verify
│   ├── policy_backend.py   # PolicyBackend protocol
│   ├── proxy.py            # Governance proxy + session lifecycle
│   ├── receipt.py          # Execution Receipt issuance + verify
│   └── ...
└── tests/                  # Curated test set (~23 files)
```

## What's NOT here yet

- **Live LLM tests** (semantic-judge, behavioral-fingerprint lanes) — require API keys; default test runs use stub LLMs. Live runs require explicit env vars (`ARDUR_SEMANTIC_JUDGE=anthropic` + `ANTHROPIC_API_KEY`).
- **Corpus-heavy benchmark tests** (AgentDojo, InjectAgent, R-Judge, STAC, telemetry-ablation) — these stay in the private research repo. The cleaner subset that backs public claims is what's curated here.

## Status

Phase 1 of the lift wave — file-level migration with end-to-end Wolverine/Radiantic → Ardur rename pass applied. Protocol-identifier rename is **clean break** (per `docs/specs/README.md` "Protocol identifier rename" section): no backward-compat dual-type for v0.1 receipts/passports/attestations.

Docker images (`rahulnutakki/ardur-demo:lang`, `:autogen`) and re-recorded asciinema casts are pending — those need interactive maintainer hands-on (Docker Hub creds + asciinema record). See `/Users/nutakki/.claude/plans/ardur-phase1-artifacts/phase1-execution-handoff.md` for the hand-off brief.

## License

MIT — see [LICENSE](../LICENSE).

# Article 12 Attestation Export Example

This directory contains a minimal manifest example for
[`docs/specs/eu-ai-act-attestation-export-v0.1.md`](../../docs/specs/eu-ai-act-attestation-export-v0.1.md).

The example is schema-valid fixture data. It is not a cryptographically complete
bundle: the referenced JWS, trust anchor, and receipt files are not included.

Run the packaged verifier from the repo root:

```bash
PYTHONPATH=python python3 -m vibap.cli article12-verify \
  --manifest examples/article12-attestation-export/minimal-export.json
```

Expected result: `incomplete_evidence`. The manifest schema and manifest digest
checks pass; the referenced trust-anchor, manifest JWS, and receipt files are
intentionally absent.

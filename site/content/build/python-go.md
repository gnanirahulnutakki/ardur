---
title: "Python And Go Runtime Surfaces"
description: "Curated runtime imports are public; dedicated Python and Go CI run on every push and pull request."
weight: 41
maturity: ["public-now"]
claim_types: ["runtime-boundary"]
surfaces: ["python", "go"]
frameworks: ["framework-agnostic"]
evidence_levels: ["code-and-doc"]
---

{{< claim "mission-boundary" >}}

The Python and Go directories are public runtime surfaces. Dedicated Python
(3.10 + 3.13) and Go test jobs run on every push and pull request via
`.github/workflows/tests.yml`, alongside CodeQL, link-check, secret-scan,
format validation, and the Hugo site build.

Sources: {{< repo-link "python/README.md" >}}, {{< repo-link "go/README.md" >}}, and {{< repo-link ".github/workflows/tests.yml" "tests workflow" >}}.

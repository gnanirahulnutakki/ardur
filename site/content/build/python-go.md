---
title: "Python And Go Runtime Surfaces"
description: "Curated runtime imports are present, with dedicated CI still in progress."
weight: 41
maturity: ["public-now", "in-progress"]
claim_types: ["runtime-boundary"]
surfaces: ["python", "go"]
frameworks: ["framework-agnostic"]
evidence_levels: ["code-and-doc"]
---

{{< claim "mission-boundary" >}}

The Python and Go directories are public runtime surfaces. The status page still
keeps the dedicated Python and Go CI workflows in the in-progress bucket until
those gates land and pass.

Sources: {{< repo-link "python/README.md" >}} and {{< repo-link "go/README.md" >}}.

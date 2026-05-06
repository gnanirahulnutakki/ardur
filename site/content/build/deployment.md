---
title: "Deployment"
description: "Deployment material exists, with security and maturity boundaries kept visible."
weight: 43
maturity: ["in-progress"]
claim_types: ["deployment"]
surfaces: ["deploy"]
frameworks: ["kubernetes", "spire"]
evidence_levels: ["doc-and-manifest", "limitation-backed"]
---

{{< claim "deployment-boundary" >}}

Deployment pages should keep least privilege, metrics exposure, identity
configuration, and blast radius visible before anyone treats the manifests as a
production recipe.

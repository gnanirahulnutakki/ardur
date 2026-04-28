# Deploy

Deployment material for running Ardur on Kubernetes. Two parallel concerns live here:

- **`k8s/spire/`** — production-shaped SPIRE deployment that gives every workload a SPIFFE identity Ardur can bind credentials to. SPIRE Server as a 3-replica StatefulSet, SPIRE Agent as a DaemonSet, the SPIFFE CSI driver for workload delivery. Sample `ClusterSPIFFEID` registrations for the framework integrations.
- **`deploy/helm/ardur/`** — Helm chart that deploys the Ardur runtime itself (proxy, governance engine, admission webhook, CRD operator) into a cluster that already has SPIRE.

The two are deliberately independent. A team that's already standardised on a different SPIFFE deployment path can use Ardur's chart against their own SPIRE; a team that's exploring Ardur for the first time can bring up SPIRE from `k8s/spire/` and the Ardur runtime from `helm/ardur/` in sequence.

## Maturity bar

Both pieces are at the "production-shaped" bar: they reflect a reviewed design but they have not been deployed end-to-end against a real cluster from this repository's exact YAML. ADR-015 documents the design choices (3-replica StatefulSet, CSI vs Workload-API socket, `k8s_psat` node attestation, `k8sbundle` trust-bundle rotation). Until a real-cluster smoke test is published, treat these manifests as a starting point you customise rather than a one-command install.

## Out of scope right now

- Cert-manager / Vault / cloud KMS integration for the upstream CA — disk-based upstream authority is the documented baseline.
- PostgreSQL provisioning for the SPIRE shared datastore — bring your own.
- PodDisruptionBudgets / NetworkPolicies / External Secrets — opinionated production hardening that depends on cluster context.

The Helm chart's `values.yaml` calls out the assumptions and the surfaces a deployer needs to override.

# ADR-015: Production-grade SPIRE deployment design for Kubernetes

- Status: Proposed
- Date: 2026-04-19
- Decision owners: Ardur runtime deployment

## Context

Ardur's architecture overview references SPIFFE/SPIRE v1.14.2, but the
repo-side demo bring-up is still framed as Docker Compose. That is good enough
for a local demo, but it is not good enough for reviewer scrutiny once the
architecture claims Kubernetes-native deployment targets.

This ADR defines a production-shaped Kubernetes deployment for SPIRE without
claiming that the repository has already deployed it to a real cluster.

## Decision

### 1. Run SPIRE Server as a 3-replica StatefulSet

We will run SPIRE Server as a `StatefulSet`, not a `Deployment`.

Rationale:

- Each server replica benefits from stable DNS identity
  (`spire-server-0`, `spire-server-1`, `spire-server-2`) for debugging,
  bootstrap flows, and deterministic operational playbooks.
- High availability in SPIRE depends on a shared datastore, but each server
  instance still maintains its own CA state. Stateful pods plus per-pod PVCs
  are a cleaner fit for that operational model than fungible Deployment pods.
- Persistent local storage is useful for disk-backed key material and runtime
  state across restarts.

Consequence:

- The manifests intentionally use PostgreSQL for the shared datastore instead
  of PVC-backed SQLite. Three replicas with independent SQLite files would not
  be honest HA. The PVCs remain, but they back local key material and runtime
  state rather than the shared datastore itself.

### 2. Prefer the SPIFFE CSI driver for workload delivery

We will use the SPIFFE CSI driver as the default workload delivery path and
keep direct Workload API socket access as an escape hatch.

Rationale:

- CSI gives pod-scoped, lifecycle-bound X.509 material without forcing every
  application team to implement Workload API client logic.
- The CSI driver keeps private key handling on-node and reduces the chance that
  application code accidentally over-exposes the Workload API socket.
- It better matches the “production-grade” expectation for Kubernetes
  workloads than ad hoc hostPath mounts into application pods.

Trade-off:

- CSI adds another node-level daemon and another moving part to debug.
- Workloads that need JWT-SVID fetches or custom rotation behavior may still
  want direct Workload API integration.

### 3. Use `k8s_psat` for node attestation and `k8s` plus `unix` for workload attestation

The server and agent will use `k8s_psat` for node attestation. Agents will use
the `k8s` and `unix` workload attestors.

Rationale:

- `k8s_psat` is the native node attestor for Kubernetes service-account-token
  based attestation and is the upstream-supported pattern for in-cluster SPIRE
  deployments.
- `k8s` attestation gives Kubernetes-native selectors that map cleanly to pod,
  service account, image, and container identity.
- `unix` remains enabled so non-Kubernetes local process selectors are still
  available if needed for sidecars or host-local helper processes.

### 4. Trust bundle rotation flows through `k8sbundle` and the Workload API

Trust bundle rotation works as follows:

1. SPIRE Server rotates or renews its intermediate CA from the disk-based
   upstream authority.
1. The server updates bundle state in the shared datastore.
1. The `k8sbundle` notifier updates the `spire-bundle` ConfigMap in
   `spire-system`.
1. SPIRE Agents observe the updated bundle and keep serving the current bundle
   over the Workload API.
1. CSI-mounted workloads and direct Workload API clients consume the renewed
   bundle and SVID material without requiring pod recreation.

Rationale:

- This keeps the bundle publication path Kubernetes-native and visible to
  operators.
- The disk upstream authority supports seamless reload from disk on CSR
  requests, which gives a credible CA rotation story without requiring a server
  restart.

### 5. Map registration entries to Ardur workloads by framework label and container identity

The sample workload registrations target three framework families:

- LangChain
- LangGraph
- AutoGen

The sample `ClusterSPIFFEID` objects match them through:

- `podSelector` labels such as `framework=langchain`
- `app.kubernetes.io/name` labels naming the pod role
- `workloadSelectorTemplates` that pin the expected container name

Rationale:

- Pod labels are easy for platform teams to standardize.
- Container-name selectors make the mapping reviewer-friendly: the registration
  story explicitly answers “which container got which SPIFFE ID?”
- The controller manager automatically adds pod UID and agent parent selectors,
  so the samples remain specific to a single pod instance even though the YAML
  is written at a higher level.

Important caveat:

- The repo slice used for this lane does not include the actual Kubernetes demo
  workload manifests, so these registrations are illustrative naming contracts,
  not claims about already-checked-in workload YAML.

### 6. Pin SPIRE to v1.14.2

We will pin both server and agent images to `ghcr.io/spiffe/spire-*:1.14.2`.

Rationale:

- Ardur's architecture description already names SPIFFE/SPIRE v1.14.2 as the
  identity layer version.
- Keeping the Kubernetes design on the same SPIRE version avoids a “paper says
  one thing, manifests say another” review trap.
- The SPIFFE site currently publishes the install guidance for SPIRE v1.14.2,
  so this pin still aligns with current upstream documentation.

### 7. Use disk-based upstream authority and disk key management on the server

The server uses:

- `UpstreamAuthority "disk"`
- `KeyManager "disk"`

Rationale:

- The disk upstream authority gives a concrete rotation story for intermediate
  CA renewal from mounted Secret material.
- Disk key management preserves server signing state across pod restart.
- This is a better fit for a design-level “production-grade” deployment than an
  in-memory-only server CA.

Trade-off:

- Mounted CA key material becomes sensitive cluster state and must be delivered
  through a real secret-management workflow before production rollout.

## Known trade-offs and non-goals

This lane deliberately does not do the following:

- It does not deploy to a real cluster.
- It does not provision PostgreSQL.
- It does not include cert-manager, Vault, or cloud KMS integration for the CA.
- It does not ship PodDisruptionBudgets, NetworkPolicies, or External Secrets.
- It does not decide whether the final production registration path is
  controller-managed `ClusterSPIFFEID` objects or imperative
  `spire-server entry create` automation.
- It does not claim that the current demo workloads already carry the labels and
  service accounts used by the sample registrations.

The design is therefore “production-shaped” rather than “production-complete.”

## Security implications

- The blast radius of a misconfigured upstream CA Secret is high because it can
  affect the entire trust domain. Treat `spire-upstream-ca` as highly sensitive.
- The PostgreSQL connection string Secret must use least privilege and TLS.
- The SPIFFE CSI driver runs privileged on each node because it participates in
  kubelet mount plumbing. That is expected, but it raises the bar for node
  hardening and image provenance verification.

## Cost and operability notes

- The StatefulSet plus CSI DaemonSet increase baseline cluster cost compared to
  a single Compose node, but that is the cost of reviewer-credible HA.
- PostgreSQL performance is likely to be the first bottleneck at scale, so the
  datastore must be sized and monitored as a first-class dependency.
- If you expose `spire-server-bootstrap` as a cloud load balancer, remember the
  recurring per-hour and data-processing charges.

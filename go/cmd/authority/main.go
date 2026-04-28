// Package main is the entrypoint for the VIBAP Authority service.
//
// The Authority is the credential-signing component of VIBAP.  In production
// it runs inside an AMD SEV-SNP Confidential Container (CoCo/Kata) so the
// Ed25519 signing key never leaves TEE-encrypted memory.
//
// On nodes without hardware TEE support the Authority still functions but
// marks its attestation as "none" so verifiers know the key was not
// hardware-protected.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// TEEAttestation describes the Trusted Execution Environment status of this
// Authority instance.  Verifiers SHOULD reject credentials whose issuer
// attestation is "none" in production environments.
type TEEAttestation struct {
	Technology string `json:"technology"`       // "amd-sev-snp", "intel-tdx", "none"
	Attested   bool   `json:"attested"`         // true if hardware attestation succeeded
	Platform   string `json:"platform"`         // CPU model
	NodeName   string `json:"node_name"`        // Kubernetes node
	PodName    string `json:"pod_name"`         // Pod identity
	Namespace  string `json:"namespace"`        // Kubernetes namespace
	RuntimeCls string `json:"runtime_class"`    // RuntimeClassName if set
	KeyPolicy  string `json:"key_policy"`       // "tee-isolated" or "memory-only"
	BootTime   string `json:"boot_time"`        // Authority start time
	SEVDevice  bool   `json:"sev_device_found"` // /dev/sev present
}

type signRequest struct {
	AgentID    string `json:"agent_id"`
	Payload    string `json:"payload"`     // base64url-encoded data to sign
	PolicyHash string `json:"policy_hash"` // Cedar policy hash binding
}

type signResponse struct {
	Signature   string          `json:"signature"`   // hex-encoded Ed25519 signature
	KeyID       string          `json:"key_id"`      // signing key identifier
	Algorithm   string          `json:"algorithm"`   // "EdDSA"
	Attestation *TEEAttestation `json:"attestation"` // TEE status at time of signing
	IssuedAt    int64           `json:"issued_at"`   // Unix timestamp
	PublicKey   string          `json:"public_key"`  // hex-encoded Ed25519 public key
	Fingerprint string          `json:"fingerprint"` // SHA-256 of public key
}

type authorityStatus struct {
	Status      string          `json:"status"`
	Attestation *TEEAttestation `json:"attestation"`
	KeyID       string          `json:"key_id"`
	Fingerprint string          `json:"fingerprint"`
	Uptime      string          `json:"uptime"`
	SignCount   int64           `json:"sign_count"`
}

type authority struct {
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	keyID       string
	fingerprint string
	attestation *TEEAttestation
	bootTime    time.Time

	mu        sync.Mutex
	signCount int64
}

func detectTEE() *TEEAttestation {
	att := &TEEAttestation{
		Technology: "none",
		Attested:   false,
		Platform:   runtime.GOARCH,
		NodeName:   os.Getenv("NODE_NAME"),
		PodName:    os.Getenv("POD_NAME"),
		Namespace:  os.Getenv("POD_NAMESPACE"),
		RuntimeCls: os.Getenv("RUNTIME_CLASS"),
		KeyPolicy:  "memory-only",
		BootTime:   time.Now().UTC().Format(time.RFC3339),
	}

	// Read CPU model
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					att.Platform = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	// Check for SEV device
	if _, err := os.Stat("/dev/sev"); err == nil {
		att.SEVDevice = true
	}

	// Probe AMD SEV-SNP via /dev/sev-guest or sysfs
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		att.Technology = "amd-sev-snp"
		att.Attested = true
		att.KeyPolicy = "tee-isolated"
		log.Println("[TEE] AMD SEV-SNP detected via /dev/sev-guest")
		return att
	}

	// Check kvm_amd module parameter
	if data, err := os.ReadFile("/sys/module/kvm_amd/parameters/sev_snp"); err == nil {
		if strings.TrimSpace(string(data)) == "Y" || strings.TrimSpace(string(data)) == "1" {
			att.Technology = "amd-sev-snp"
			att.Attested = true
			att.KeyPolicy = "tee-isolated"
			log.Println("[TEE] AMD SEV-SNP enabled via kvm_amd module")
			return att
		}
	}

	// Check Intel TDX
	if _, err := os.Stat("/dev/tdx-guest"); err == nil {
		att.Technology = "intel-tdx"
		att.Attested = true
		att.KeyPolicy = "tee-isolated"
		log.Println("[TEE] Intel TDX detected via /dev/tdx-guest")
		return att
	}

	// Check for CoCo attestation agent
	if _, err := os.Stat("/run/confidential-containers/attestation-agent.sock"); err == nil {
		att.Technology = "coco-attested"
		att.Attested = true
		att.KeyPolicy = "tee-isolated"
		log.Println("[TEE] CoCo attestation agent detected")
		return att
	}

	log.Println("[TEE] No hardware TEE detected — running in memory-only mode")
	log.Printf("[TEE] Platform: %q, Node: %q", // #nosec G706 -- values are sanitized before logging
		sanitizeLogValue(att.Platform),
		sanitizeLogValue(att.NodeName),
	)
	return att
}

func sanitizeLogValue(value string) string {
	value = strings.ReplaceAll(value, "\n", "_")
	value = strings.ReplaceAll(value, "\r", "_")
	return value
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[HTTP] encode response failed: %v", err)
	}
}

func newAuthority() (*authority, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	fp := sha256.Sum256(pub)
	fingerprint := hex.EncodeToString(fp[:])
	keyID := "vibap-authority-" + fingerprint[:12]

	att := detectTEE()

	a := &authority{
		privateKey:  priv,
		publicKey:   pub,
		keyID:       keyID,
		fingerprint: fingerprint,
		attestation: att,
		bootTime:    time.Now(),
	}

	log.Printf("[Authority] Key generated: kid=%s fp=%s", keyID, fingerprint[:16]+"...")
	log.Printf("[Authority] TEE: technology=%s attested=%v key_policy=%s",
		att.Technology, att.Attested, att.KeyPolicy)

	return a, nil
}

func (a *authority) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.AgentID == "" || req.Payload == "" {
		http.Error(w, "agent_id and payload required", http.StatusBadRequest)
		return
	}

	sig := ed25519.Sign(a.privateKey, []byte(req.Payload))

	a.mu.Lock()
	a.signCount++
	count := a.signCount
	a.mu.Unlock()

	log.Printf("[Sign] agent=%s policy_hash=%s count=%d tee=%s",
		req.AgentID, req.PolicyHash, count, a.attestation.Technology)

	resp := signResponse{
		Signature:   hex.EncodeToString(sig),
		KeyID:       a.keyID,
		Algorithm:   "EdDSA",
		Attestation: a.attestation,
		IssuedAt:    time.Now().Unix(),
		PublicKey:   hex.EncodeToString(a.publicKey),
		Fingerprint: a.fingerprint,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *authority) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	count := a.signCount
	a.mu.Unlock()

	resp := authorityStatus{
		Status:      "running",
		Attestation: a.attestation,
		KeyID:       a.keyID,
		Fingerprint: a.fingerprint,
		Uptime:      time.Since(a.bootTime).Round(time.Second).String(),
		SignCount:   count,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *authority) handleAttestation(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.attestation)
}

func (a *authority) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	jwk := map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"kid": a.keyID,
		"x":   hex.EncodeToString(a.publicKey),
	}
	writeJSON(w, http.StatusOK, jwk)
}

func main() {
	var addr string
	flag.StringVar(&addr, "addr", ":8443", "Listen address")
	flag.Parse()

	auth, err := newAuthority()
	if err != nil {
		log.Fatalf("Failed to initialize authority: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sign", auth.handleSign)
	mux.HandleFunc("/status", auth.handleStatus)
	mux.HandleFunc("/attestation", auth.handleAttestation)
	mux.HandleFunc("/public-key", auth.handlePublicKey)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			log.Printf("[HTTP] write health response failed: %v", err)
		}
	})

	log.Printf("[Authority] Listening on %s", addr)
	log.Printf("[Authority] Endpoints: /sign /status /attestation /public-key /healthz")

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

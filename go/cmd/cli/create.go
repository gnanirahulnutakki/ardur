package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gnanirahulnutakki/ardur/go/pkg/credential"
)

func runCreate(args []string) {
	fs := flag.NewFlagSet("vibap credential create", flag.ExitOnError)

	// Key and output flags
	keyFile := fs.String("key-file", "", "Path to issuer signing key (JWK JSON)")
	output := fs.String("output", "", "Output file path (default: stdout)")
	demo := fs.Bool("demo", false, "Use demo values for all layers")
	ttl := fs.Duration("ttl", credential.DefaultTTL, "Credential time-to-live (e.g., 1h, 30m)")

	// Standard claims
	issuer := fs.String("issuer", "", "Issuer URI (VIBAP Authority)")
	subject := fs.String("subject", "", "Subject (agent SPIFFE ID)")

	// Layer 1: Identity
	spiffeID := fs.String("spiffe-id", "", "Agent SPIFFE ID (Layer 1)")
	ownerID := fs.String("owner-id", "", "Deployer SPIFFE ID (Layer 1)")
	a2aCardRef := fs.String("a2a-card-ref", "", "A2A Agent Card URL (Layer 1, optional)")

	// Layer 3: Intent
	agentChecksum := fs.String("agent-checksum", "", "SHA-256 of agent config (Layer 3)")
	policyEngine := fs.String("policy-engine", "cedar", "Policy engine: cedar or rego (Layer 3)")
	policyHash := fs.String("policy-hash", "", "SHA-256 of compiled policy (Layer 3)")
	permittedActions := fs.String("permitted-actions", "", "Comma-separated permitted actions (Layer 3)")

	// Layer 5: Trust
	staticScore := fs.Float64("static-score", 0, "Static capability score 0.0-1.0 (Layer 5)")
	historicalRep := fs.Float64("historical-rep", 0, "Historical reputation 0.0-1.0 (Layer 5)")
	compositeScore := fs.Float64("composite-score", 0, "Composite trust score 0-100 (Layer 5)")

	// Layer 2: Provenance (optional)
	imageDigest := fs.String("image-digest", "", "Container image digest (Layer 2, optional)")

	// Selective disclosure
	sdLayers := fs.String("sd-layers", "", "Comma-separated layers for selective disclosure (provenance,baseline)")

	_ = fs.Parse(args) // ExitOnError handles parse errors

	// Track which flags were explicitly set (vs zero-value defaults)
	explicitFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })

	// Require key file
	if *keyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --key-file is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Load signing key
	key, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}
	if key.PrivateKey == nil {
		fmt.Fprintln(os.Stderr, "Error: key file does not contain a private key (needed for signing)")
		os.Exit(1)
	}

	// Apply demo defaults (only for flags NOT explicitly set by the user)
	if *demo {
		applyDemoDefaults(explicitFlags, issuer, subject, spiffeID, ownerID, agentChecksum, policyHash, imageDigest, staticScore, historicalRep, compositeScore)
	}

	// Validate required fields
	if *issuer == "" || *subject == "" {
		fmt.Fprintln(os.Stderr, "Error: --issuer and --subject are required (or use --demo)")
		os.Exit(1)
	}

	// Build credential
	b := credential.NewBuilder(*issuer, *subject).
		WithTTL(*ttl).
		WithIdentity(*spiffeID, *ownerID, *a2aCardRef).
		WithIntent(*agentChecksum, *policyEngine, *policyHash, parseCSV(*permittedActions)).
		WithTrust(*staticScore, *historicalRep, *compositeScore, "", "")

	// Optional: Layer 2
	if *imageDigest != "" {
		b = b.WithProvenance(*imageDigest, "", "", "", "")
	}

	// Optional: Selective disclosure
	if *sdLayers != "" {
		layers := parseCSV(*sdLayers)
		b = b.WithSelectiveDisclosure(layers...)
	}

	cred, err := b.Build(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error building credential: %v\n", err)
		os.Exit(1)
	}

	// Encode to SD-JWT-VC format
	encoded, err := credential.Encode(cred, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding credential: %v\n", err)
		os.Exit(1)
	}

	// Output
	if *output != "" {
		if err := os.WriteFile(*output, []byte(encoded+"\n"), 0600); err != nil { // #nosec G306
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Credential written to %s (expires %s)\n", *output, time.Now().Add(*ttl).UTC().Format(time.RFC3339))
	} else {
		fmt.Print(encoded)
	}
}

// applyDemoDefaults fills in realistic demo values for flags that were
// not explicitly set by the user. Uses fs.Visit tracking to distinguish
// "user set --static-score=0" from "user didn't set --static-score".
func applyDemoDefaults(explicit map[string]bool, issuer, subject, spiffeID, ownerID, agentChecksum, policyHash, imageDigest *string, staticScore, historicalRep, compositeScore *float64) {
	if !explicit["issuer"] {
		*issuer = "https://vibap.ardur.dev/authority"
	}
	if !explicit["subject"] {
		*subject = "spiffe://ardur.dev/ns/default/sa/demo-agent/instance/demo-001"
	}
	if !explicit["spiffe-id"] {
		*spiffeID = "spiffe://ardur.dev/ns/default/sa/demo-agent/instance/demo-001"
	}
	if !explicit["owner-id"] {
		*ownerID = "spiffe://ardur.dev/ns/default/sa/demo-deployer"
	}
	if !explicit["agent-checksum"] {
		*agentChecksum = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	if !explicit["policy-hash"] {
		*policyHash = "sha256:abc123def456789012345678901234567890123456789012345678901234abcd"
	}
	if !explicit["image-digest"] {
		*imageDigest = "sha256:deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
	}
	if !explicit["static-score"] {
		*staticScore = 0.3
	}
	if !explicit["historical-rep"] {
		*historicalRep = 0.85
	}
	if !explicit["composite-score"] {
		*compositeScore = 82.0
	}
}

// parseCSV splits a comma-separated string into a trimmed string slice.
// Returns nil for empty input.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

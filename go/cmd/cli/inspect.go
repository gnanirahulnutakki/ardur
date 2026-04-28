package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gnanirahulnutakki/ardur/go/pkg/credential"
)

func runInspect(args []string) {
	fs := flag.NewFlagSet("vibap credential inspect", flag.ExitOnError)

	input := fs.String("input", "", "Path to credential file (default: stdin)")
	jsonOutput := fs.Bool("json", false, "Output full claims as JSON")

	_ = fs.Parse(args) // ExitOnError handles parse errors

	// Read credential
	raw, err := readCredentialInput(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading credential: %v\n", err)
		os.Exit(1)
	}

	// Decode (no signature verification)
	cred, err := credential.Decode(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding credential: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		printJSON(cred)
		return
	}

	printHumanReadable(cred)
}

func printJSON(cred *credential.VIBAPCredential) {
	// Build a combined view with header and claims
	view := struct {
		Header      credential.Header `json:"header"`
		Claims      credential.Claims `json:"claims"`
		Disclosures []disclosureView  `json:"disclosures,omitempty"`
		KeyBinding  *kbView           `json:"key_binding,omitempty"`
	}{
		Header: cred.Header,
		Claims: cred.Claims,
	}

	for _, d := range cred.Disclosures {
		view.Disclosures = append(view.Disclosures, disclosureView{
			ClaimName: d.ClaimName,
			Value:     d.Value,
			Hash:      d.Hash,
		})
	}

	if cred.KeyBinding != nil {
		view.KeyBinding = &kbView{
			Nonce:    cred.KeyBinding.Claims.Nonce,
			Audience: cred.KeyBinding.Claims.Audience,
			IssuedAt: cred.KeyBinding.Claims.IssuedAt,
			SDHash:   cred.KeyBinding.Claims.SDHash,
		}
	}

	data, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

type disclosureView struct {
	ClaimName string `json:"claim_name"`
	Value     any    `json:"value"`
	Hash      string `json:"hash"`
}

type kbView struct {
	Nonce    string `json:"nonce"`
	Audience string `json:"audience"`
	IssuedAt int64  `json:"issued_at"`
	SDHash   string `json:"sd_hash"`
}

func printHumanReadable(cred *credential.VIBAPCredential) {
	fmt.Println("=== VIBAP Credential ===")
	fmt.Println()

	// Header
	fmt.Println("Header:")
	fmt.Printf("  Algorithm: %s\n", cred.Header.Algorithm)
	fmt.Printf("  Type:      %s\n", cred.Header.Type)
	if cred.Header.KeyID != "" {
		fmt.Printf("  Key ID:    %s\n", cred.Header.KeyID)
	}
	fmt.Println()

	// Standard claims
	fmt.Println("Standard Claims:")
	fmt.Printf("  Issuer:    %s\n", cred.Claims.Issuer)
	fmt.Printf("  Subject:   %s\n", cred.Claims.Subject)
	fmt.Printf("  VCT:       %s\n", cred.Claims.VerifiableCredentialType)
	fmt.Printf("  Issued At: %s\n", time.Unix(cred.Claims.IssuedAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("  Expires:   %s\n", time.Unix(cred.Claims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	if cred.Claims.NotBefore > 0 {
		fmt.Printf("  Not Before: %s\n", time.Unix(cred.Claims.NotBefore, 0).UTC().Format(time.RFC3339))
	}
	fmt.Println()

	// Layer 1: Identity
	if cred.Claims.Identity != nil {
		fmt.Println("Layer 1 — Identity (always disclosed):")
		fmt.Printf("  SPIFFE ID:    %s\n", cred.Claims.Identity.SPIFFEID)
		fmt.Printf("  Owner ID:     %s\n", cred.Claims.Identity.OwnerID)
		if cred.Claims.Identity.A2ACardRef != "" {
			fmt.Printf("  A2A Card Ref: %s\n", cred.Claims.Identity.A2ACardRef)
		}
		fmt.Println()
	}

	// Layer 2: Provenance
	if cred.Claims.Provenance != nil {
		fmt.Println("Layer 2 — Provenance (inline):")
		fmt.Printf("  Image Digest: %s\n", cred.Claims.Provenance.ImageDigest)
		if cred.Claims.Provenance.SLSAProvenanceRef != "" {
			fmt.Printf("  SLSA Ref:     %s\n", cred.Claims.Provenance.SLSAProvenanceRef)
		}
		if cred.Claims.Provenance.ModelHash != "" {
			fmt.Printf("  Model Hash:   %s\n", cred.Claims.Provenance.ModelHash)
		}
		fmt.Println()
	}

	// Layer 3: Intent
	if cred.Claims.Intent != nil {
		fmt.Println("Layer 3 — Intent Binding (always disclosed):")
		fmt.Printf("  Agent Checksum: %s\n", cred.Claims.Intent.AgentChecksum)
		fmt.Printf("  Policy Engine:  %s\n", cred.Claims.Intent.PolicyEngine)
		fmt.Printf("  Policy Hash:    %s\n", cred.Claims.Intent.PolicyHash)
		if len(cred.Claims.Intent.PermittedActions) > 0 {
			fmt.Printf("  Actions:        %v\n", cred.Claims.Intent.PermittedActions)
		}
		fmt.Println()
	}

	// Layer 4: Baseline
	if cred.Claims.Baseline != nil {
		fmt.Println("Layer 4 — Behavioral Baseline (inline):")
		fmt.Printf("  Profile Hash:  %s\n", cred.Claims.Baseline.ApplicationProfileHash)
		fmt.Printf("  Max Delegation: %d\n", cred.Claims.Baseline.MaxDelegationDepth)
		if len(cred.Claims.Baseline.ExpectedEndpoints) > 0 {
			fmt.Printf("  Endpoints:     %v\n", cred.Claims.Baseline.ExpectedEndpoints)
		}
		fmt.Println()
	}

	// Layer 5: Trust
	if cred.Claims.Trust != nil {
		fmt.Println("Layer 5 — Trust Score (always disclosed):")
		fmt.Printf("  Static Score:    %.2f\n", cred.Claims.Trust.StaticCapabilityScore)
		fmt.Printf("  Historical Rep:  %.2f\n", cred.Claims.Trust.HistoricalReputation)
		fmt.Printf("  Composite Score: %.0f\n", cred.Claims.Trust.CompositeScore)
		fmt.Printf("  Auth Tier:       %s\n", cred.Claims.Trust.AuthorizationTier)
		fmt.Println()
	}

	// Disclosures
	if len(cred.Disclosures) > 0 {
		fmt.Printf("Selective Disclosures: %d\n", len(cred.Disclosures))
		for i, d := range cred.Disclosures {
			hashPreview := d.Hash
			if len(hashPreview) > 16 {
				hashPreview = hashPreview[:16] + "..."
			}
			fmt.Printf("  [%d] %s (hash: %s)\n", i, d.ClaimName, hashPreview)
		}
		fmt.Println()
	}

	// Key Binding
	if cred.KeyBinding != nil {
		fmt.Println("Key Binding JWT: present")
		fmt.Printf("  Audience: %s\n", cred.KeyBinding.Claims.Audience)
		fmt.Printf("  Nonce:    %s\n", cred.KeyBinding.Claims.Nonce)
		fmt.Println()
	}

	// Status
	if cred.Claims.Status != nil {
		fmt.Println("Status Reference:")
		fmt.Printf("  URI:   %s\n", cred.Claims.Status.StatusList.URI)
		fmt.Printf("  Index: %d\n", cred.Claims.Status.StatusList.Index)
		fmt.Println()
	}

	// Confirmation
	if cred.Claims.Confirmation != nil && cred.Claims.Confirmation.JWK != nil {
		fmt.Println("Holder Key Binding:")
		fmt.Printf("  Key Type: %s/%s\n", cred.Claims.Confirmation.JWK.KeyType, cred.Claims.Confirmation.JWK.Curve)
		if cred.Claims.Confirmation.JWK.KeyID != "" {
			fmt.Printf("  Key ID:   %s\n", cred.Claims.Confirmation.JWK.KeyID)
		}
	}
}

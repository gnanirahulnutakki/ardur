package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gnanirahulnutakki/ardur/go/pkg/credential"
)

func runVerify(args []string) {
	fs := flag.NewFlagSet("vibap credential verify", flag.ExitOnError)

	keyFile := fs.String("key-file", "", "Path to issuer public key (JWK JSON)")
	input := fs.String("input", "", "Path to credential file (default: stdin)")
	audience := fs.String("audience", "", "Expected audience for KB-JWT verification")
	nonce := fs.String("nonce", "", "Expected nonce for KB-JWT verification")
	skipStatus := fs.Bool("skip-status", false, "Skip Token Status List verification")

	_ = fs.Parse(args) // ExitOnError handles parse errors

	// Require key file
	if *keyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --key-file is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Load issuer public key
	key, err := loadSigningKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading key: %v\n", err)
		os.Exit(1)
	}

	// Read credential
	raw, err := readCredentialInput(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading credential: %v\n", err)
		os.Exit(1)
	}

	// Build verification options
	opts := &credential.VerifyOptions{
		SkipStatusCheck:  *skipStatus,
		ExpectedAudience: *audience,
		ExpectedNonce:    *nonce,
	}

	// Verify
	result, err := credential.Verify(raw, key.PublicKey, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Verification error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	if result.Valid {
		fmt.Println("VALID")
	} else {
		fmt.Println("INVALID")
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, e := range result.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	// Print summary if credential was decoded
	if result.Credential != nil {
		c := result.Credential
		fmt.Printf("\nCredential Summary:\n")
		fmt.Printf("  Issuer:  %s\n", c.Claims.Issuer)
		fmt.Printf("  Subject: %s\n", c.Claims.Subject)
		fmt.Printf("  VCT:     %s\n", c.Claims.VerifiableCredentialType)
		if c.Claims.Trust != nil {
			fmt.Printf("  Trust:   %.0f (%s)\n", c.Claims.Trust.CompositeScore, c.Claims.Trust.AuthorizationTier)
		}
		fmt.Printf("  Disclosures: %d\n", len(c.Disclosures))
		if c.KeyBinding != nil {
			fmt.Printf("  Key Binding: present\n")
		}
	}

	if !result.Valid {
		os.Exit(1)
	}
}

// readCredentialInput reads an SD-JWT-VC string from a file or stdin.
func readCredentialInput(path string) (string, error) {
	var data []byte
	var err error

	if path == "" || path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path) // #nosec G304 -- CLI reads user-specified files
	}
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

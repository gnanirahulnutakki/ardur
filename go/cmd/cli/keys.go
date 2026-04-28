package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gnanirahulnutakki/ardur/go/pkg/credential"
)

// KeyFile is the JSON format for persisting Ed25519 keypairs.
// Both keys are base64url-encoded (no padding) for JWK compatibility.
type KeyFile struct {
	KeyType string `json:"kty"`           // "OKP"
	Curve   string `json:"crv"`           // "Ed25519"
	X       string `json:"x"`             // Public key (base64url)
	D       string `json:"d,omitempty"`   // Private key seed (base64url, omitted in public-only files)
	KeyID   string `json:"kid,omitempty"` // Optional key identifier
	KeyUse  string `json:"use,omitempty"` // "sig"
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("vibap keygen", flag.ExitOnError)
	output := fs.String("output", "", "Output file path (default: stdout)")
	keyID := fs.String("kid", "", "Key identifier (default: auto-generated)")
	_ = fs.Parse(args) // ExitOnError handles parse errors

	// Generate Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	// Auto-generate key ID if not provided
	kid := *keyID
	if kid == "" {
		kid = fmt.Sprintf("vibap-key-%s", base64.RawURLEncoding.EncodeToString(pub[:8]))
	}

	kf := KeyFile{
		KeyType: "OKP",
		Curve:   "Ed25519",
		X:       base64.RawURLEncoding.EncodeToString(pub),
		D:       base64.RawURLEncoding.EncodeToString(priv.Seed()),
		KeyID:   kid,
		KeyUse:  "sig",
	}

	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling key: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, append(data, '\n'), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Keypair written to %s (key ID: %s)\n", *output, kid)
	} else {
		fmt.Println(string(data))
	}
}

// loadSigningKey reads a JWK key file and returns a credential.SigningKey.
func loadSigningKey(path string) (*credential.SigningKey, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- CLI reads user-specified files
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parsing key file: %w", err)
	}

	if kf.KeyType != "OKP" || kf.Curve != "Ed25519" {
		return nil, fmt.Errorf("unsupported key type: kty=%s, crv=%s (expected OKP/Ed25519)", kf.KeyType, kf.Curve)
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(kf.X)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(pubBytes))
	}

	sk := &credential.SigningKey{
		PublicKey: ed25519.PublicKey(pubBytes),
		KeyID:     kf.KeyID,
	}

	// Private key is optional (verify-only key files won't have it)
	if kf.D != "" {
		seedBytes, err := base64.RawURLEncoding.DecodeString(kf.D)
		if err != nil {
			return nil, fmt.Errorf("decoding private key: %w", err)
		}
		if len(seedBytes) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid private key seed size: got %d, want %d", len(seedBytes), ed25519.SeedSize)
		}
		sk.PrivateKey = ed25519.NewKeyFromSeed(seedBytes)
	}

	return sk, nil
}

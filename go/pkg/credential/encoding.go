package credential

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Encode serializes a VIBAPCredential into the SD-JWT-VC tilde-separated format:
//
//	<Issuer-Signed JWT>~<Disclosure 1>~...~<Disclosure N>~
//
// The trailing tilde indicates no Key Binding JWT is appended.
// Use EncodeWithKeyBinding to include a KB-JWT.
func Encode(cred *VIBAPCredential, key *SigningKey) (string, error) {
	if cred == nil {
		return "", fmt.Errorf("credential is nil")
	}
	if key == nil {
		return "", fmt.Errorf("signing key is required")
	}

	// Serialize and sign the issuer JWT
	issuerJWT, err := signJWT(cred.Header, cred.Claims, key.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("signing issuer JWT: %w", err)
	}

	// Build tilde-separated format
	var parts []string
	parts = append(parts, issuerJWT)
	for _, d := range cred.Disclosures {
		parts = append(parts, d.Encoded)
	}

	// Trailing tilde (no KB-JWT)
	return strings.Join(parts, "~") + "~", nil
}

// EncodeWithKeyBinding serializes a VIBAPCredential with a Key Binding JWT.
// The holderKey proves the presenter possesses the credential.
//
// Format: <Issuer JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>
func EncodeWithKeyBinding(cred *VIBAPCredential, issuerKey *SigningKey, holderPrivateKey ed25519.PrivateKey, nonce, audience string) (string, error) {
	if cred == nil {
		return "", fmt.Errorf("credential is nil")
	}

	// First encode without KB-JWT
	withoutKB, err := Encode(cred, issuerKey)
	if err != nil {
		return "", err
	}

	// Remove trailing tilde to get the SD-JWT part
	sdJWTPart := strings.TrimSuffix(withoutKB, "~")

	// Compute sd_hash: SHA-256 of the SD-JWT (without KB-JWT)
	sdHash := sha256.Sum256([]byte(sdJWTPart))
	sdHashB64 := base64.RawURLEncoding.EncodeToString(sdHash[:])

	// Create KB-JWT
	kbHeader := KeyBindingHeader{
		Algorithm: "EdDSA",
		Type:      MediaTypeKBJWT,
	}
	kbClaims := KeyBindingClaims{
		Nonce:    nonce,
		Audience: audience,
		IssuedAt: time.Now().Unix(),
		SDHash:   sdHashB64,
	}

	kbJWT, err := signJWT(kbHeader, kbClaims, holderPrivateKey)
	if err != nil {
		return "", fmt.Errorf("signing key binding JWT: %w", err)
	}

	// Append KB-JWT after the last tilde
	return sdJWTPart + "~" + kbJWT, nil
}

// Decode parses an SD-JWT-VC string into its components.
// It does NOT verify signatures — use Verify for that.
func Decode(raw string) (*VIBAPCredential, error) {
	if raw == "" {
		return nil, fmt.Errorf("empty credential string")
	}

	// Split on tilde separator
	parts := strings.Split(raw, "~")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SD-JWT format: expected at least 2 tilde-separated parts, got %d", len(parts))
	}

	// First part is the issuer JWT
	issuerJWT := parts[0]

	// Parse issuer JWT header and claims (without verifying signature)
	header, claims, err := parseJWT(issuerJWT)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer JWT: %w", err)
	}

	// Validate media type
	if header.Type != MediaTypeDCSDJWT && header.Type != "vc+sd-jwt" {
		return nil, fmt.Errorf("unexpected JWT type %q, expected %q", header.Type, MediaTypeDCSDJWT)
	}

	// Parse disclosures (middle parts, excluding empty trailing parts and KB-JWT)
	var disclosures []Disclosure
	var keyBinding *KeyBindingJWT

	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if part == "" {
			continue // Skip empty parts (trailing tilde)
		}

		// Check if this is a KB-JWT (last non-empty part with "kb+jwt" typ)
		if i == len(parts)-1 {
			kbHeader, _, kbErr := parseJWTHeader(part)
			if kbErr == nil && kbHeader.Type == MediaTypeKBJWT {
				kb, err := parseKeyBindingJWT(part)
				if err != nil {
					return nil, fmt.Errorf("parsing key binding JWT: %w", err)
				}
				keyBinding = kb
				continue
			}
		}

		// Parse as disclosure
		d, err := decodeDisclosure(part)
		if err != nil {
			return nil, fmt.Errorf("parsing disclosure %d: %w", i, err)
		}
		disclosures = append(disclosures, d)
	}

	return &VIBAPCredential{
		Header:      header,
		Claims:      claims,
		Disclosures: disclosures,
		KeyBinding:  keyBinding,
		Raw:         raw,
	}, nil
}

// signJWT creates a JWS Compact Serialization (header.payload.signature)
// using Ed25519 (EdDSA algorithm).
func signJWT(header any, payload any, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key size: got %d, want %d", len(key), ed25519.PrivateKeySize)
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign header.payload
	signingInput := headerB64 + "." + payloadB64
	signature := ed25519.Sign(key, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// parseJWT extracts the header and claims from a JWS Compact Serialization
// without verifying the signature.
func parseJWT(token string) (Header, Claims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return Header{}, Claims{}, fmt.Errorf("invalid JWT format: expected 3 dot-separated parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, Claims{}, fmt.Errorf("decoding header: %w", err)
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Header{}, Claims{}, fmt.Errorf("unmarshaling header: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Header{}, Claims{}, fmt.Errorf("decoding payload: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return Header{}, Claims{}, fmt.Errorf("unmarshaling claims: %w", err)
	}

	return header, claims, nil
}

// parseJWTHeader extracts only the header from a JWT.
func parseJWTHeader(token string) (Header, string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return Header{}, "", fmt.Errorf("invalid JWT format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Header{}, "", fmt.Errorf("decoding header: %w", err)
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Header{}, "", fmt.Errorf("unmarshaling header: %w", err)
	}

	return header, parts[0], nil
}

// parseKeyBindingJWT parses a Key Binding JWT string.
func parseKeyBindingJWT(token string) (*KeyBindingJWT, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid KB-JWT format")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding KB header: %w", err)
	}

	var header KeyBindingHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unmarshaling KB header: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding KB payload: %w", err)
	}

	var claims KeyBindingClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshaling KB claims: %w", err)
	}

	return &KeyBindingJWT{
		Header: header,
		Claims: claims,
		Raw:    token,
	}, nil
}

// decodeDisclosure decodes a base64url-encoded disclosure string
// into a Disclosure struct. Recomputes the SHA-256 hash.
func decodeDisclosure(encoded string) (Disclosure, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Disclosure{}, fmt.Errorf("base64url decoding: %w", err)
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(decoded, &arr); err != nil {
		return Disclosure{}, fmt.Errorf("JSON unmarshal: %w", err)
	}

	if len(arr) != 3 {
		return Disclosure{}, fmt.Errorf("disclosure array must have 3 elements, got %d", len(arr))
	}

	var salt, claimName string
	if err := json.Unmarshal(arr[0], &salt); err != nil {
		return Disclosure{}, fmt.Errorf("unmarshaling salt: %w", err)
	}
	if err := json.Unmarshal(arr[1], &claimName); err != nil {
		return Disclosure{}, fmt.Errorf("unmarshaling claim name: %w", err)
	}

	var value any
	if err := json.Unmarshal(arr[2], &value); err != nil {
		return Disclosure{}, fmt.Errorf("unmarshaling value: %w", err)
	}

	// Recompute hash
	hash := sha256.Sum256([]byte(encoded))
	hashStr := base64.RawURLEncoding.EncodeToString(hash[:])

	return Disclosure{
		Salt:      salt,
		ClaimName: claimName,
		Value:     value,
		Encoded:   encoded,
		Hash:      hashStr,
	}, nil
}

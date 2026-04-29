package credential

import (
	"bytes"
	"compress/flate"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// StatusListToken represents a decoded Token Status List JWT.
// Per draft-ietf-oauth-status-list-18, the status list is a
// DEFLATE-compressed bitstring where each entry uses a fixed
// number of bits (2 for VIBAP: valid, invalid, suspended).
type StatusListToken struct {
	Header StatusListHeader `json:"header"`
	Claims StatusListClaims `json:"claims"`
	Bits   []byte           // Decompressed bitstring
}

// StatusListHeader is the JWT header for a Token Status List.
type StatusListHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"` // "statuslist+jwt"
	KeyID     string `json:"kid,omitempty"`
}

// StatusListClaims contains the claims of a Token Status List JWT.
type StatusListClaims struct {
	Issuer     string            `json:"iss"`
	Subject    string            `json:"sub"`
	IssuedAt   int64             `json:"iat"`
	ExpiresAt  int64             `json:"exp,omitempty"`
	StatusList StatusListPayload `json:"status_list"`
}

// StatusListPayload contains the compressed bitstring and metadata.
type StatusListPayload struct {
	// BitsPerStatus is the number of bits per credential entry. VIBAP uses 2.
	BitsPerStatus int `json:"bits"`
	// List is the base64url-encoded DEFLATE-compressed bitstring.
	List string `json:"lst"`
}

// MediaTypeStatusListJWT is the media type for Token Status List JWTs.
const MediaTypeStatusListJWT = "statuslist+jwt"

// StatusClient fetches and caches Token Status List tokens.
// It is safe for concurrent use.
type StatusClient struct {
	httpClient *http.Client
	cache      map[string]*cachedStatusList
	mu         sync.RWMutex
}

// cachedStatusList holds a parsed status list with its expiry.
type cachedStatusList struct {
	token     *StatusListToken
	fetchedAt time.Time
	maxAge    time.Duration
}

// NewStatusClient creates a new StatusClient with the given HTTP client.
// If httpClient is nil, a default client with 10-second timeout is used.
func NewStatusClient(httpClient *http.Client) *StatusClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &StatusClient{
		httpClient: httpClient,
		cache:      make(map[string]*cachedStatusList),
	}
}

// CheckStatus verifies the revocation status of a credential.
// It fetches the Token Status List from the URI in the credential's
// status claim, decompresses it, and extracts the 2-bit value at
// the credential's index.
func (c *StatusClient) CheckStatus(cred *VIBAPCredential, issuerPubKey ed25519.PublicKey) (StatusValue, error) {
	if cred.Claims.Status == nil {
		return StatusInvalid, fmt.Errorf("credential has no status claim")
	}

	ref := cred.Claims.Status.StatusList
	if ref.URI == "" {
		return StatusInvalid, fmt.Errorf("status list URI is empty")
	}
	if ref.Index < 0 {
		return StatusInvalid, fmt.Errorf("status list index must be non-negative, got %d", ref.Index)
	}

	if !strings.HasPrefix(ref.URI, "https://") {
		return StatusInvalid, fmt.Errorf("status list URI must use HTTPS scheme, got %q", ref.URI)
	}

	// Fetch or get cached status list
	sl, err := c.getStatusList(ref.URI, issuerPubKey)
	if err != nil {
		return StatusInvalid, fmt.Errorf("fetching status list: %w", err)
	}

	// Extract status value
	return extractStatus(sl.Bits, ref.Index, sl.Claims.StatusList.BitsPerStatus)
}

// getStatusList fetches a Token Status List, using cache when available.
func (c *StatusClient) getStatusList(uri string, issuerPubKey ed25519.PublicKey) (*StatusListToken, error) {
	// Check cache first
	c.mu.RLock()
	cached, ok := c.cache[uri]
	c.mu.RUnlock()

	if ok && time.Since(cached.fetchedAt) < cached.maxAge {
		return cached.token, nil
	}

	// Fetch fresh status list
	token, err := c.fetchStatusList(uri, issuerPubKey)
	if err != nil {
		return nil, err
	}

	// Cache with 5-minute default TTL
	c.mu.Lock()
	c.cache[uri] = &cachedStatusList{
		token:     token,
		fetchedAt: time.Now(),
		maxAge:    5 * time.Minute,
	}
	c.mu.Unlock()

	return token, nil
}

// fetchStatusList fetches and verifies a Token Status List JWT from the given URI.
func (c *StatusClient) fetchStatusList(uri string, issuerPubKey ed25519.PublicKey) (*StatusListToken, error) {
	resp, err := c.httpClient.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", uri, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP GET %s: status %d", uri, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return ParseStatusListToken(string(body), issuerPubKey)
}

// ParseStatusListToken parses and verifies a Token Status List JWT string.
// It verifies the Ed25519 signature, decodes the header and claims,
// and decompresses the DEFLATE-compressed bitstring.
func ParseStatusListToken(raw string, issuerPubKey ed25519.PublicKey) (*StatusListToken, error) {
	raw = strings.TrimSpace(raw)

	// Verify JWT signature
	if err := verifyJWTSignature(raw, issuerPubKey); err != nil {
		return nil, fmt.Errorf("status list JWT signature: %w", err)
	}

	// Parse JWT parts
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}
	var header StatusListHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("unmarshaling header: %w", err)
	}

	// Verify type
	if header.Type != MediaTypeStatusListJWT {
		return nil, fmt.Errorf("unexpected status list JWT type %q, expected %q", header.Type, MediaTypeStatusListJWT)
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	var claims StatusListClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshaling claims: %w", err)
	}

	// Validate bits per status
	if claims.StatusList.BitsPerStatus != 1 && claims.StatusList.BitsPerStatus != 2 &&
		claims.StatusList.BitsPerStatus != 4 && claims.StatusList.BitsPerStatus != 8 {
		return nil, fmt.Errorf("invalid bits_per_status %d, must be 1, 2, 4, or 8", claims.StatusList.BitsPerStatus)
	}

	// Validate temporal freshness
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("status list JWT expired at %s",
			time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	// Round 5 hardening (FIX-R5-H4, 2026-04-28): bound iat into the
	// future. The status list is the revocation backbone — a brief
	// compromise of the status authority + a status list with iat far
	// in the future would permanently assert "all credentials valid"
	// from the verifier's perspective until cache TTL turns over.
	// Mirrors the SD-JWT-VC verifier's skewSec (30s) for clock drift.
	const statusListIatSkewSec int64 = 30
	if claims.IssuedAt > 0 && claims.IssuedAt > time.Now().Unix()+statusListIatSkewSec {
		return nil, fmt.Errorf(
			"status list iat lies more than %ds in the future "+
				"(iat=%d, now=%d) — refusing to accept",
			statusListIatSkewSec, claims.IssuedAt, time.Now().Unix())
	}

	// Decompress the status list
	bits, err := decompressStatusList(claims.StatusList.List)
	if err != nil {
		return nil, fmt.Errorf("decompressing status list: %w", err)
	}

	return &StatusListToken{
		Header: header,
		Claims: claims,
		Bits:   bits,
	}, nil
}

// decompressStatusList decodes and DEFLATE-decompresses a status list bitstring.
func decompressStatusList(encoded string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64url decoding: %w", err)
	}

	reader := flate.NewReader(bytes.NewReader(compressed))
	defer func() {
		_ = reader.Close()
	}()

	decompressed, err := io.ReadAll(io.LimitReader(reader, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("DEFLATE decompression: %w", err)
	}

	return decompressed, nil
}

// extractStatus extracts the status value for a credential at the given index.
// For 2-bit status (VIBAP default), each byte holds 4 credential statuses.
//
// Bit layout for 2-bit status (index 0 is in the least significant bits):
//
//	byte[0]: [idx3][idx2][idx1][idx0]
//	byte[1]: [idx7][idx6][idx5][idx4]
//	...
func extractStatus(bits []byte, index, bitsPerStatus int) (StatusValue, error) {
	if bitsPerStatus <= 0 || bitsPerStatus > 8 {
		return 0, fmt.Errorf("invalid bits per status: %d", bitsPerStatus)
	}

	entriesPerByte := 8 / bitsPerStatus
	byteIndex := index / entriesPerByte
	bitOffset := (index % entriesPerByte) * bitsPerStatus

	if byteIndex >= len(bits) {
		return 0, fmt.Errorf("index %d out of range (status list has %d bytes, %d entries)",
			index, len(bits), len(bits)*entriesPerByte)
	}

	// Create mask for the number of bits
	mask := byte((1 << bitsPerStatus) - 1)

	// Extract the value at the bit offset
	value := (bits[byteIndex] >> bitOffset) & mask

	return StatusValue(value), nil
}

// CompressStatusList creates a DEFLATE-compressed, base64url-encoded status list
// from a slice of status values. This is used by issuers to create status list tokens.
func CompressStatusList(statuses []StatusValue, bitsPerStatus int) (string, error) {
	if bitsPerStatus != 1 && bitsPerStatus != 2 && bitsPerStatus != 4 && bitsPerStatus != 8 {
		return "", fmt.Errorf("invalid bits_per_status %d, must be 1, 2, 4, or 8", bitsPerStatus)
	}

	entriesPerByte := 8 / bitsPerStatus
	numBytes := (len(statuses) + entriesPerByte - 1) / entriesPerByte
	bits := make([]byte, numBytes)

	mask := byte((1 << bitsPerStatus) - 1)

	for i, status := range statuses {
		if byte(status) > mask {
			return "", fmt.Errorf("status value %d at index %d exceeds %d-bit range", status, i, bitsPerStatus)
		}
		byteIndex := i / entriesPerByte
		bitOffset := (i % entriesPerByte) * bitsPerStatus
		bits[byteIndex] |= byte(status) << bitOffset
	}

	// DEFLATE compress
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("creating DEFLATE writer: %w", err)
	}
	if _, err := writer.Write(bits); err != nil {
		return "", fmt.Errorf("DEFLATE compression: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("closing DEFLATE writer: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// InvalidateCache removes a specific URI from the status list cache.
func (c *StatusClient) InvalidateCache(uri string) {
	c.mu.Lock()
	delete(c.cache, uri)
	c.mu.Unlock()
}

// InvalidateAllCache clears the entire status list cache.
func (c *StatusClient) InvalidateAllCache() {
	c.mu.Lock()
	c.cache = make(map[string]*cachedStatusList)
	c.mu.Unlock()
}

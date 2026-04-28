package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractStatus2Bit(t *testing.T) {
	// Create a byte with known 2-bit values:
	// byte[0] = 0b_11_10_01_00 = idx0=00(valid), idx1=01(invalid), idx2=10(suspended), idx3=11(unknown)
	bits := []byte{0b_11_10_01_00}

	tests := []struct {
		index    int
		expected StatusValue
	}{
		{0, StatusValid},
		{1, StatusInvalid},
		{2, StatusSuspended},
		{3, StatusValue(0x03)},
	}

	for _, tt := range tests {
		got, err := extractStatus(bits, tt.index, 2)
		if err != nil {
			t.Errorf("extractStatus(bits, %d, 2) error: %v", tt.index, err)
			continue
		}
		if got != tt.expected {
			t.Errorf("extractStatus(bits, %d, 2) = %d, want %d", tt.index, got, tt.expected)
		}
	}
}

func TestExtractStatus1Bit(t *testing.T) {
	// byte[0] = 0b10101010 = idx0=0, idx1=1, idx2=0, idx3=1, idx4=0, idx5=1, idx6=0, idx7=1
	bits := []byte{0b10101010}

	tests := []struct {
		index    int
		expected StatusValue
	}{
		{0, StatusValue(0)},
		{1, StatusValue(1)},
		{2, StatusValue(0)},
		{3, StatusValue(1)},
		{7, StatusValue(1)},
	}

	for _, tt := range tests {
		got, err := extractStatus(bits, tt.index, 1)
		if err != nil {
			t.Errorf("extractStatus(bits, %d, 1) error: %v", tt.index, err)
			continue
		}
		if got != tt.expected {
			t.Errorf("extractStatus(bits, %d, 1) = %d, want %d", tt.index, got, tt.expected)
		}
	}
}

func TestExtractStatusMultiByte(t *testing.T) {
	// Two bytes with 2-bit status:
	// byte[0] = 0b_00_00_01_00 = idx0=valid, idx1=invalid, idx2=valid, idx3=valid
	// byte[1] = 0b_00_10_00_01 = idx4=invalid, idx5=valid, idx6=suspended, idx7=valid
	bits := []byte{0b_00_00_01_00, 0b_00_10_00_01}

	tests := []struct {
		index    int
		expected StatusValue
	}{
		{0, StatusValid},     // byte 0, offset 0
		{1, StatusInvalid},   // byte 0, offset 2
		{4, StatusInvalid},   // byte 1, offset 0
		{6, StatusSuspended}, // byte 1, offset 4
	}

	for _, tt := range tests {
		got, err := extractStatus(bits, tt.index, 2)
		if err != nil {
			t.Errorf("extractStatus(bits, %d, 2) error: %v", tt.index, err)
			continue
		}
		if got != tt.expected {
			t.Errorf("extractStatus(bits, %d, 2) = %d (%s), want %d (%s)",
				tt.index, got, got, tt.expected, tt.expected)
		}
	}
}

func TestExtractStatusOutOfRange(t *testing.T) {
	bits := []byte{0x00}
	_, err := extractStatus(bits, 10, 2) // Only 4 entries in 1 byte
	if err == nil {
		t.Error("expected out of range error")
	}
}

func TestCompressDecompressRoundtrip(t *testing.T) {
	// Create a status list with known values
	statuses := []StatusValue{
		StatusValid,     // 0
		StatusInvalid,   // 1
		StatusSuspended, // 2
		StatusValid,     // 3
		StatusValid,     // 4
		StatusInvalid,   // 5
		StatusValid,     // 6
		StatusSuspended, // 7
	}

	compressed, err := CompressStatusList(statuses, 2)
	if err != nil {
		t.Fatalf("CompressStatusList() error: %v", err)
	}

	// Decompress
	decompressed, err := decompressStatusList(compressed)
	if err != nil {
		t.Fatalf("decompressStatusList() error: %v", err)
	}

	// Verify all values
	for i, expected := range statuses {
		got, err := extractStatus(decompressed, i, 2)
		if err != nil {
			t.Errorf("extractStatus(decompressed, %d, 2) error: %v", i, err)
			continue
		}
		if got != expected {
			t.Errorf("index %d: got %d (%s), want %d (%s)", i, got, got, expected, expected)
		}
	}
}

func TestCompressStatusListLarge(t *testing.T) {
	// Create a large status list (1000 entries)
	statuses := make([]StatusValue, 1000)
	for i := range statuses {
		statuses[i] = StatusValue(i % 3) // Cycle through valid, invalid, suspended
	}

	compressed, err := CompressStatusList(statuses, 2)
	if err != nil {
		t.Fatalf("CompressStatusList() error: %v", err)
	}

	// Verify compression actually compresses (output should be smaller than raw)
	rawSize := len(statuses) / 4 // 4 entries per byte at 2-bit
	if len(compressed) >= rawSize*2 {
		t.Logf("warning: compressed size (%d) not much smaller than raw (%d bytes)", len(compressed), rawSize)
	}

	// Decompress and verify
	decompressed, err := decompressStatusList(compressed)
	if err != nil {
		t.Fatalf("decompressStatusList() error: %v", err)
	}

	for i, expected := range statuses {
		got, err := extractStatus(decompressed, i, 2)
		if err != nil {
			t.Errorf("index %d: extractStatus error: %v", i, err)
			break
		}
		if got != expected {
			t.Errorf("index %d: got %d, want %d", i, got, expected)
			break
		}
	}
}

func TestCompressStatusListErrors(t *testing.T) {
	// Invalid bits per status
	_, err := CompressStatusList([]StatusValue{StatusValid}, 3)
	if err == nil {
		t.Error("expected error for invalid bits_per_status=3")
	}

	// Value exceeds range
	_, err = CompressStatusList([]StatusValue{StatusValue(4)}, 2) // Max 2-bit = 3
	if err == nil {
		t.Error("expected error for value 4 in 2-bit status")
	}
}

func TestStatusClientNewDefault(t *testing.T) {
	client := NewStatusClient(nil)
	if client == nil {
		t.Fatal("NewStatusClient returned nil")
	}
	if client.httpClient == nil {
		t.Error("httpClient is nil")
	}
	if client.cache == nil {
		t.Error("cache is nil")
	}
}

// createTestStatusListJWT builds a signed Token Status List JWT for testing.
func createTestStatusListJWT(t *testing.T, statuses []StatusValue, bitsPerStatus int, key ed25519.PrivateKey) string {
	t.Helper()

	compressed, err := CompressStatusList(statuses, bitsPerStatus)
	if err != nil {
		t.Fatalf("CompressStatusList: %v", err)
	}

	header := StatusListHeader{
		Algorithm: "EdDSA",
		Type:      MediaTypeStatusListJWT,
		KeyID:     "test-status-key",
	}
	claims := StatusListClaims{
		Issuer:   "https://vibap.example.com",
		Subject:  "https://vibap.example.com/status/1",
		IssuedAt: 1709683200,
		StatusList: StatusListPayload{
			BitsPerStatus: bitsPerStatus,
			List:          compressed,
		},
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := ed25519.Sign(key, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + sigB64
}

func TestParseStatusListToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	statuses := []StatusValue{
		StatusValid, StatusInvalid, StatusSuspended, StatusValid,
		StatusValid, StatusInvalid, StatusValid, StatusValid,
	}

	jwt := createTestStatusListJWT(t, statuses, 2, priv)

	token, err := ParseStatusListToken(jwt, pub)
	if err != nil {
		t.Fatalf("ParseStatusListToken error: %v", err)
	}

	if token.Header.Type != MediaTypeStatusListJWT {
		t.Errorf("header type = %q, want %q", token.Header.Type, MediaTypeStatusListJWT)
	}
	if token.Claims.StatusList.BitsPerStatus != 2 {
		t.Errorf("bits_per_status = %d, want 2", token.Claims.StatusList.BitsPerStatus)
	}

	// Verify we can extract correct status values from the parsed token
	for i, expected := range statuses {
		got, err := extractStatus(token.Bits, i, 2)
		if err != nil {
			t.Errorf("extractStatus(%d): %v", i, err)
			continue
		}
		if got != expected {
			t.Errorf("index %d: got %s, want %s", i, got, expected)
		}
	}
}

func TestParseStatusListTokenWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	jwt := createTestStatusListJWT(t, []StatusValue{StatusValid}, 2, priv)

	_, err := ParseStatusListToken(jwt, wrongPub)
	if err == nil {
		t.Fatal("expected signature verification error")
	}
}

func TestParseStatusListTokenInvalidType(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Craft a JWT with wrong type
	header := StatusListHeader{Algorithm: "EdDSA", Type: "wrong+type"}
	claims := StatusListClaims{
		Issuer: "test", Subject: "test", IssuedAt: 1,
		StatusList: StatusListPayload{BitsPerStatus: 2, List: ""},
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	hB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	cB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	input := hB64 + "." + cB64
	sig := ed25519.Sign(priv, []byte(input))
	jwt := input + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, err := ParseStatusListToken(jwt, pub)
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestCheckStatusViaHTTP(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	statuses := []StatusValue{StatusValid, StatusInvalid, StatusSuspended, StatusValid}
	jwt := createTestStatusListJWT(t, statuses, 2, priv)

	// Serve the status list JWT from a TLS test server (HTTPS required)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(jwt))
	}))
	defer server.Close()

	client := NewStatusClient(server.Client())

	// Build a credential with a status reference pointing to our test server
	issuerKey := &SigningKey{PrivateKey: priv, PublicKey: pub, KeyID: "test"}
	cred, err := NewBuilder("https://vibap.example.com", "spiffe://test/agent").
		WithIdentity("spiffe://test/agent", "spiffe://test/owner", "").
		WithIntent("sha256:checksum", "cedar", "sha256:policy", nil).
		WithTrust(0.5, 0.5, 50, "", "").
		WithStatus(server.URL+"/status/1", 1).
		Build(issuerKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	status, err := client.CheckStatus(cred, pub)
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}
	if status != StatusInvalid {
		t.Errorf("status = %s, want INVALID (index 1)", status)
	}

	// Check again — should use cache
	status2, err := client.CheckStatus(cred, pub)
	if err != nil {
		t.Fatalf("CheckStatus (cached): %v", err)
	}
	if status2 != StatusInvalid {
		t.Errorf("cached status = %s, want INVALID", status2)
	}
}

func TestCheckStatusNoStatusClaim(t *testing.T) {
	client := NewStatusClient(nil)
	cred := &VIBAPCredential{Claims: Claims{}}
	_, err := client.CheckStatus(cred, nil)
	if err == nil {
		t.Error("expected error for missing status claim")
	}
}

func TestCheckStatusHTTPError(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewStatusClient(server.Client())
	cred := &VIBAPCredential{
		Claims: Claims{
			Status: &StatusReference{
				StatusList: StatusListRef{URI: server.URL + "/status/1", Index: 0},
			},
		},
	}

	_, err := client.CheckStatus(cred, pub)
	if err == nil {
		t.Error("expected error for HTTP 500")
	}
}

func TestStatusClientCacheInvalidation(t *testing.T) {
	client := NewStatusClient(nil)

	// Manually add cache entry
	client.mu.Lock()
	client.cache["https://example.com/status/1"] = &cachedStatusList{}
	client.mu.Unlock()

	// Invalidate specific
	client.InvalidateCache("https://example.com/status/1")
	client.mu.RLock()
	_, ok := client.cache["https://example.com/status/1"]
	client.mu.RUnlock()
	if ok {
		t.Error("cache entry should have been invalidated")
	}

	// Add entries back and invalidate all
	client.mu.Lock()
	client.cache["a"] = &cachedStatusList{}
	client.cache["b"] = &cachedStatusList{}
	client.mu.Unlock()

	client.InvalidateAllCache()
	client.mu.RLock()
	if len(client.cache) != 0 {
		t.Errorf("expected empty cache, got %d entries", len(client.cache))
	}
	client.mu.RUnlock()
}

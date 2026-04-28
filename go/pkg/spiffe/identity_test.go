package spiffe

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidateSPIFFEID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		wantTD   string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "valid agent SPIFFE ID",
			id:       "spiffe://ardur.dev/agent/weather-bot/instance-abc123",
			wantTD:   "ardur.dev",
			wantPath: "/agent/weather-bot/instance-abc123",
		},
		{
			name:     "valid owner SPIFFE ID",
			id:       "spiffe://ardur.dev/user/deployer-42",
			wantTD:   "ardur.dev",
			wantPath: "/user/deployer-42",
		},
		{
			name:     "trust domain only",
			id:       "spiffe://example.org",
			wantTD:   "example.org",
			wantPath: "/",
		},
		{
			name:     "root path",
			id:       "spiffe://example.org/",
			wantTD:   "example.org",
			wantPath: "/",
		},
		{
			name:    "empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			id:      "https://vibap.ardur.dev/agent/test",
			wantErr: true,
		},
		{
			name:    "no trust domain",
			id:      "spiffe:///agent/test",
			wantErr: true,
		},
		{
			name:    "with query string",
			id:      "spiffe://example.org/agent?foo=bar",
			wantErr: true,
		},
		{
			name:    "with fragment",
			id:      "spiffe://example.org/agent#section",
			wantErr: true,
		},
		{
			name:    "with port",
			id:      "spiffe://example.org:8080/agent",
			wantErr: true,
		},
		{
			name:    "with userinfo",
			id:      "spiffe://user@example.org/agent",
			wantErr: true,
		},
		{
			name:    "double slashes in path",
			id:      "spiffe://example.org//agent//test",
			wantErr: true,
		},
		{
			name:    "exceeds 2048 byte limit",
			id:      "spiffe://example.org/" + strings.Repeat("a", 2048),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td, path, err := ValidateSPIFFEID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSPIFFEID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if td != tt.wantTD {
				t.Errorf("ValidateSPIFFEID(%q) trustDomain = %q, want %q", tt.id, td, tt.wantTD)
			}
			if path != tt.wantPath {
				t.Errorf("ValidateSPIFFEID(%q) path = %q, want %q", tt.id, path, tt.wantPath)
			}
		})
	}
}

func TestMockIdentityProvider_FetchIdentity(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID:    "spiffe://ardur.dev/agent/test/instance-001",
		OwnerID:     "spiffe://ardur.dev/user/deployer",
		TrustDomain: "ardur.dev",
	})
	defer mock.Close()

	ctx := context.Background()
	identity, err := mock.FetchIdentity(ctx)
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}

	if identity.SPIFFEID != "spiffe://ardur.dev/agent/test/instance-001" {
		t.Errorf("SPIFFEID = %q, want %q", identity.SPIFFEID, "spiffe://ardur.dev/agent/test/instance-001")
	}
	if identity.OwnerID != "spiffe://ardur.dev/user/deployer" {
		t.Errorf("OwnerID = %q, want %q", identity.OwnerID, "spiffe://ardur.dev/user/deployer")
	}
	if identity.TrustDomain != "ardur.dev" {
		t.Errorf("TrustDomain = %q, want %q", identity.TrustDomain, "ardur.dev")
	}
}

func TestMockIdentityProvider_FetchAfterClose(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{})
	mock.Close()

	_, err := mock.FetchIdentity(context.Background())
	if err == nil {
		t.Fatal("FetchIdentity() after Close() should return error")
	}
}

func TestMockIdentityProvider_WatchRotation(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID: "spiffe://ardur.dev/agent/v1",
	})
	defer mock.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var received *AgentIdentity
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		_ = mock.WatchRotation(ctx, func(newIdentity *AgentIdentity) {
			received = newIdentity
			wg.Done()
			cancel()
		})
	}()

	time.Sleep(50 * time.Millisecond)

	mock.SimulateRotation(&AgentIdentity{
		SPIFFEID:    "spiffe://ardur.dev/agent/v2",
		TrustDomain: "ardur.dev",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	wg.Wait()

	if received == nil {
		t.Fatal("callback was never invoked")
	}
	if received.SPIFFEID != "spiffe://ardur.dev/agent/v2" {
		t.Errorf("rotated SPIFFEID = %q, want v2", received.SPIFFEID)
	}
}

func TestMockIdentityProvider_DefaultValues(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{})
	defer mock.Close()

	identity, err := mock.FetchIdentity(context.Background())
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}

	if identity.TrustDomain != "ardur.dev" {
		t.Errorf("default TrustDomain = %q, want vibap.ardur.dev", identity.TrustDomain)
	}
	if identity.SPIFFEID == "" {
		t.Error("default SPIFFEID should not be empty")
	}
	if identity.ExpiresAt.IsZero() {
		t.Error("default ExpiresAt should not be zero")
	}
}

func TestValidateSPIFFEID_PortInTrustDomain(t *testing.T) {
	// Port in trust domain is invalid per SPIFFE spec
	_, _, err := ValidateSPIFFEID("spiffe://domain:8080/path")
	if err == nil {
		t.Fatal("ValidateSPIFFEID should fail for trust domain with port")
	}
	if !strings.Contains(err.Error(), "must not contain port") {
		t.Errorf("error = %v, want message about port", err)
	}
}

func TestValidateSPIFFEID_Userinfo(t *testing.T) {
	// Userinfo is invalid per SPIFFE spec
	_, _, err := ValidateSPIFFEID("spiffe://user@domain/path")
	if err == nil {
		t.Fatal("ValidateSPIFFEID should fail for SPIFFE ID with userinfo")
	}
	if !strings.Contains(err.Error(), "userinfo") {
		t.Errorf("error = %v, want message about userinfo", err)
	}
}

func TestMockIdentityProvider_SimulateRotationThenFetchIdentity(t *testing.T) {
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID: "spiffe://ardur.dev/agent/v1",
	})
	defer mock.Close()

	// Initial FetchIdentity returns v1
	ctx := context.Background()
	id1, err := mock.FetchIdentity(ctx)
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}
	if id1.SPIFFEID != "spiffe://ardur.dev/agent/v1" {
		t.Errorf("initial SPIFFEID = %q, want v1", id1.SPIFFEID)
	}

	// Simulate rotation to v2
	newID := &AgentIdentity{
		SPIFFEID:    "spiffe://ardur.dev/agent/v2",
		TrustDomain: "ardur.dev",
		ExpiresAt:   time.Now().Add(2 * time.Hour),
	}
	mock.SimulateRotation(newID)

	// FetchIdentity now returns v2
	id2, err := mock.FetchIdentity(ctx)
	if err != nil {
		t.Fatalf("FetchIdentity() after rotation error = %v", err)
	}
	if id2.SPIFFEID != "spiffe://ardur.dev/agent/v2" {
		t.Errorf("after rotation SPIFFEID = %q, want v2", id2.SPIFFEID)
	}
	if id2.ExpiresAt != newID.ExpiresAt {
		t.Errorf("ExpiresAt = %v, want %v", id2.ExpiresAt, newID.ExpiresAt)
	}
}

func TestMockIdentityProvider_CustomExpiresAtAndA2ACardRef(t *testing.T) {
	expiresAt := time.Now().Add(30 * time.Minute)
	a2aRef := "https://agentgateway.example.com/cards/weather-bot"
	mock := NewMockIdentityProvider(MockIdentityProviderOptions{
		SPIFFEID:    "spiffe://ardur.dev/agent/custom",
		TrustDomain: "ardur.dev",
		ExpiresAt:   expiresAt,
		A2ACardRef:  a2aRef,
	})
	defer mock.Close()

	identity, err := mock.FetchIdentity(context.Background())
	if err != nil {
		t.Fatalf("FetchIdentity() error = %v", err)
	}
	if !identity.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", identity.ExpiresAt, expiresAt)
	}
	if identity.A2ACardRef != a2aRef {
		t.Errorf("A2ACardRef = %q, want %q", identity.A2ACardRef, a2aRef)
	}
}

// compile-time check that SPIREClient implements IdentityProvider
var _ IdentityProvider = (*SPIREClient)(nil)

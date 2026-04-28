package provenance

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockProvenanceVerifier implements ProvenanceVerifier for testing.
// Returns preconfigured results for image verification.
type MockProvenanceVerifier struct {
	mu     sync.RWMutex
	closed bool

	// VerifyResult is the result returned by VerifyImage and VerifyBundle.
	VerifyResult *ImageProvenance

	// VerifyError is the error returned by VerifyImage and VerifyBundle.
	// If set, VerifyResult is ignored.
	VerifyError error

	// CallCount tracks how many times Verify was called.
	CallCount int
}

// NewMockProvenanceVerifier creates a mock verifier with a default success result.
func NewMockProvenanceVerifier() *MockProvenanceVerifier {
	return &MockProvenanceVerifier{
		VerifyResult: &ImageProvenance{
			ImageDigest:       "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			SLSAProvenanceRef: "https://slsa.dev/provenance/v1",
			BuildPipeline:     "https://github.com/org/repo/actions/runs/12345",
			SBOMRef:           "",
			RekorVerified:     true,
			TSAVerified:       true,
			SignedAt:          time.Now().Add(-1 * time.Hour),
			SignerIdentity:    "deployer@example.com",
			SignerIssuer:      "https://accounts.google.com",
		},
	}
}

// VerifyImage returns the preconfigured result or error.
func (m *MockProvenanceVerifier) VerifyImage(_ context.Context, _ string, _ VerifyOptions) (*ImageProvenance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("mock verifier is closed")
	}
	m.CallCount++

	if m.VerifyError != nil {
		return nil, m.VerifyError
	}

	result := *m.VerifyResult
	return &result, nil
}

// VerifyBundle returns the preconfigured result or error.
func (m *MockProvenanceVerifier) VerifyBundle(_ context.Context, _ string, _ string, _ VerifyOptions) (*ImageProvenance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, fmt.Errorf("mock verifier is closed")
	}
	m.CallCount++

	if m.VerifyError != nil {
		return nil, m.VerifyError
	}

	result := *m.VerifyResult
	return &result, nil
}

// Close marks the mock verifier as closed.
func (m *MockProvenanceVerifier) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

var _ ProvenanceVerifier = (*MockProvenanceVerifier)(nil)

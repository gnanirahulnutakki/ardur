package profiling

import (
	"context"
	"fmt"
	"sync"
)

// MockProfileProvider implements ProfileProvider for testing.
// Pre-loaded profiles are returned by GetProfile; comparison uses DiffProfiles.
type MockProfileProvider struct {
	mu       sync.Mutex
	closed   bool
	profiles map[string]*ApplicationProfile // key: "namespace/pod/container"
	getErr   error
	getCount int
}

// NewMockProfileProvider creates a mock profile provider.
func NewMockProfileProvider() *MockProfileProvider {
	return &MockProfileProvider{
		profiles: make(map[string]*ApplicationProfile),
	}
}

var _ ProfileProvider = (*MockProfileProvider)(nil)

// AddProfile registers a profile that GetProfile will return.
func (m *MockProfileProvider) AddProfile(profile *ApplicationProfile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s/%s", profile.Namespace, profile.Name, profile.Container)
	m.profiles[key] = profile
}

// SetGetError configures an error returned by GetProfile.
func (m *MockProfileProvider) SetGetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getErr = err
}

// GetCount returns the number of GetProfile calls.
func (m *MockProfileProvider) GetCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCount
}

func (m *MockProfileProvider) GetProfile(_ context.Context, namespace, podName, container string) (*ApplicationProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCount++

	if m.closed {
		return nil, ErrProviderClosed
	}
	if m.getErr != nil {
		return nil, m.getErr
	}

	key := fmt.Sprintf("%s/%s/%s", namespace, podName, container)
	profile, ok := m.profiles[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProfileNotFound, key)
	}
	return profile, nil
}

func (m *MockProfileProvider) CompareProfiles(baseline, current *ApplicationProfile) (*ProfileDiff, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrProviderClosed
	}
	return DiffProfiles(baseline, current), nil
}

func (m *MockProfileProvider) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

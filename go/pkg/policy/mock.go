package policy

import (
	"context"
	"sync"
	"time"
)

// MockPolicyEngine implements PolicyEngine for testing.
// Configurable decision, errors, and call tracking.
type MockPolicyEngine struct {
	mu           sync.Mutex
	closed       bool
	decision     Decision
	compileErr   error
	evalErr      error
	evalReasons  []string
	compileCount int
	evalCount    int
	entities     []Entity
	lastRequest  *AuthzRequest
	name         string
}

// MockPolicyEngineOption configures a MockPolicyEngine.
type MockPolicyEngineOption func(*MockPolicyEngine)

// WithMockDecision sets the decision returned by Evaluate.
func WithMockDecision(d Decision) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.decision = d }
}

// WithMockCompileError sets the error returned by Compile.
func WithMockCompileError(err error) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.compileErr = err }
}

// WithMockEvalError sets the error returned by Evaluate.
func WithMockEvalError(err error) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.evalErr = err }
}

// WithMockEngineName sets the engine name.
func WithMockEngineName(name string) MockPolicyEngineOption {
	return func(m *MockPolicyEngine) { m.name = name }
}

// NewMockPolicyEngine creates a new mock policy engine.
func NewMockPolicyEngine(opts ...MockPolicyEngineOption) *MockPolicyEngine {
	m := &MockPolicyEngine{
		decision: DecisionAllow,
		name:     "mock",
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

var _ PolicyEngine = (*MockPolicyEngine)(nil)

func (m *MockPolicyEngine) Compile(_ context.Context, policyText string) (*CompiledPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.compileCount++

	if m.closed {
		return nil, ErrEngineClosed
	}
	if m.compileErr != nil {
		return nil, m.compileErr
	}

	hash := ComputePolicyHash(policyText)
	return &CompiledPolicy{
		PolicyText:  policyText,
		Hash:        hash,
		PolicyCount: 1,
		PolicyIDs:   []string{"mock-policy-0"},
	}, nil
}

func (m *MockPolicyEngine) Evaluate(_ context.Context, _ *CompiledPolicy, _ []Entity, request AuthzRequest) (*AuthzResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evalCount++
	m.lastRequest = &request

	if m.closed {
		return nil, ErrEngineClosed
	}
	if m.evalErr != nil {
		return nil, m.evalErr
	}

	return &AuthzResult{
		Decision: m.decision,
		Reasons:  m.evalReasons,
		EvalTime: 100 * time.Microsecond,
	}, nil
}

func (m *MockPolicyEngine) SetEntities(entities []Entity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrEngineClosed
	}
	m.entities = entities
	return nil
}

func (m *MockPolicyEngine) EngineName() string { return m.name }

func (m *MockPolicyEngine) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// SetDecision changes the mock decision (thread-safe).
func (m *MockPolicyEngine) SetDecision(d Decision) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decision = d
}

// CompileCount returns the number of Compile calls.
func (m *MockPolicyEngine) CompileCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.compileCount
}

// EvalCount returns the number of Evaluate calls.
func (m *MockPolicyEngine) EvalCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.evalCount
}

// LastRequest returns the last AuthzRequest passed to Evaluate.
func (m *MockPolicyEngine) LastRequest() *AuthzRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRequest
}

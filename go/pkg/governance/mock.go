package governance

import (
	"context"
	"sync"
)

// MockReconciler implements Reconciler for testing. Returns a preconfigured
// decision or error.
type MockReconciler struct {
	mu       sync.Mutex
	decision *Decision
	err      error
	calls    int
}

func NewMockReconciler() *MockReconciler {
	return &MockReconciler{}
}

var _ Reconciler = (*MockReconciler)(nil)

func (m *MockReconciler) SetDecision(d *Decision) { m.mu.Lock(); m.decision = d; m.mu.Unlock() }
func (m *MockReconciler) SetError(err error)      { m.mu.Lock(); m.err = err; m.mu.Unlock() }
func (m *MockReconciler) Calls() int              { m.mu.Lock(); defer m.mu.Unlock(); return m.calls }

func (m *MockReconciler) Reconcile(_ context.Context, decl *MissionDeclaration, events []ObservedEvent) (*Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	if m.decision != nil {
		return m.decision, nil
	}
	return &Decision{
		SessionID:         decl.SessionID,
		State:             DecisionUnknown,
		RecommendedAction: ActionNone,
		EventsProcessed:   len(events),
	}, nil
}

// MockActionSink implements ActionSink for testing.
type MockActionSink struct {
	mu      sync.Mutex
	actions []executedAction
	err     error
}

type executedAction struct {
	SessionID string
	Action    ContainmentAction
	Decision  *Decision
}

func NewMockActionSink() *MockActionSink {
	return &MockActionSink{}
}

var _ ActionSink = (*MockActionSink)(nil)

func (m *MockActionSink) SetError(err error) { m.mu.Lock(); m.err = err; m.mu.Unlock() }

func (m *MockActionSink) Execute(_ context.Context, sessionID string, action ContainmentAction, decision *Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.actions = append(m.actions, executedAction{
		SessionID: sessionID,
		Action:    action,
		Decision:  decision,
	})
	return nil
}

func (m *MockActionSink) Actions() []executedAction {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]executedAction(nil), m.actions...)
}

// MockDeclarationValidator implements DeclarationValidator for testing.
type MockDeclarationValidator struct {
	mu  sync.Mutex
	err error
}

func NewMockDeclarationValidator() *MockDeclarationValidator {
	return &MockDeclarationValidator{}
}

var _ DeclarationValidator = (*MockDeclarationValidator)(nil)

func (m *MockDeclarationValidator) SetError(err error) { m.mu.Lock(); m.err = err; m.mu.Unlock() }

func (m *MockDeclarationValidator) Validate(_ context.Context, _ *MissionDeclaration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// MockEventNormalizer implements EventNormalizer for testing.
type MockEventNormalizer struct {
	mu  sync.Mutex
	err error
}

func NewMockEventNormalizer() *MockEventNormalizer {
	return &MockEventNormalizer{}
}

var _ EventNormalizer = (*MockEventNormalizer)(nil)

func (m *MockEventNormalizer) SetError(err error) { m.mu.Lock(); m.err = err; m.mu.Unlock() }

func (m *MockEventNormalizer) Normalize(_ context.Context, event *ObservedEvent) (*ObservedEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	cp := *event
	return &cp, nil
}

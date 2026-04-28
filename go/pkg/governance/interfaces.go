package governance

import "context"

// Reconciler compares a declaration against observed events and produces a Decision.
type Reconciler interface {
	// Reconcile evaluates all events in a session against its declaration.
	// Returns DecisionUnknown when visibility is insufficient.
	Reconcile(ctx context.Context, declaration *MissionDeclaration, events []ObservedEvent) (*Decision, error)
}

// DeclarationValidator checks whether a MissionDeclaration is well-formed
// and internally consistent before it enters the governance pipeline.
type DeclarationValidator interface {
	Validate(ctx context.Context, declaration *MissionDeclaration) error
}

// EventNormalizer transforms raw observed events into a canonical form
// suitable for reconciliation. Implementations may enrich fields,
// resolve resource families, or filter noise.
type EventNormalizer interface {
	Normalize(ctx context.Context, event *ObservedEvent) (*ObservedEvent, error)
}

// SessionStore persists governance session state. Implementations range
// from in-memory (dev/test) to database-backed (production).
type SessionStore interface {
	// Create initializes a new session. Returns ErrDuplicateSession if the ID exists.
	Create(ctx context.Context, session *SessionState) error

	// Get retrieves a session by ID. Returns ErrSessionNotFound if missing.
	Get(ctx context.Context, sessionID string) (*SessionState, error)

	// Update replaces the session state. Returns ErrSessionNotFound if missing.
	Update(ctx context.Context, session *SessionState) error

	// List returns all sessions, optionally filtered by phase.
	List(ctx context.Context, phase *SessionPhase) ([]*SessionState, error)

	// Delete removes a session. Returns ErrSessionNotFound if missing.
	Delete(ctx context.Context, sessionID string) error
}

// ActionSink receives containment recommendations and acts on them.
// In test/benchmark mode this is a no-op logger. In production it may
// trigger Kubernetes label changes, Cilium policy updates, or alerts.
type ActionSink interface {
	Execute(ctx context.Context, sessionID string, action ContainmentAction, decision *Decision) error
}

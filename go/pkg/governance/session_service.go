package governance

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

type SessionService struct {
	store      SessionStore
	reconciler Reconciler
	sink       ActionSink
	logger     *slog.Logger
}

func NewSessionService(store SessionStore, reconciler Reconciler, sink ActionSink) *SessionService {
	return &SessionService{
		store:      store,
		reconciler: reconciler,
		sink:       sink,
		logger:     slog.Default(),
	}
}

func (s *SessionService) CreateSession(ctx context.Context, decl *MissionDeclaration) (*SessionState, error) {
	if decl == nil {
		return nil, fmt.Errorf("%w: nil declaration", ErrInvalidDeclaration)
	}
	if err := decl.Validate(); err != nil {
		return nil, err
	}

	if decl.CreatedAt.IsZero() {
		decl.CreatedAt = time.Now().UTC()
	}

	session := &SessionState{
		ID:          decl.SessionID,
		Phase:       PhaseInitialized,
		Declaration: decl,
		Events:      []ObservedEvent{},
	}

	if err := s.store.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	s.logger.InfoContext(ctx, "session created",
		slog.String("session_id", session.ID),
		slog.String("declaration_id", decl.ID),
	)

	return s.store.Get(ctx, session.ID)
}

func (s *SessionService) IngestEvent(ctx context.Context, event *ObservedEvent) (*Decision, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: nil event", ErrInvalidEvent)
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}

	session, err := s.store.Get(ctx, event.SessionID)
	if err != nil {
		return nil, err
	}

	if session.Phase == PhaseClosed {
		return nil, fmt.Errorf("%w: %s", ErrSessionClosed, session.ID)
	}

	if session.Phase == PhaseInitialized {
		session.Phase = PhaseActive
	}

	session.Events = append(session.Events, *event)

	decision, err := s.reconciler.Reconcile(ctx, session.Declaration, session.Events)
	if err != nil {
		return nil, fmt.Errorf("reconciliation failed for session %s: %w", session.ID, err)
	}

	session.LatestDecision = decision

	if err := s.store.Update(ctx, session); err != nil {
		return nil, fmt.Errorf("updating session %s: %w", session.ID, err)
	}

	s.logger.InfoContext(ctx, "event ingested",
		slog.String("session_id", session.ID),
		slog.String("event_id", event.EventID),
		slog.String("decision_state", string(decision.State)),
		slog.String("recommended_action", string(decision.RecommendedAction)),
	)

	if decision.State == DecisionViolation && decision.RecommendedAction != ActionNone {
		if sinkErr := s.sink.Execute(ctx, session.ID, decision.RecommendedAction, decision); sinkErr != nil {
			s.logger.ErrorContext(ctx, "action sink execution failed",
				slog.String("session_id", session.ID),
				slog.String("action", string(decision.RecommendedAction)),
				slog.String("error", sinkErr.Error()),
			)
		}
	}

	return decision, nil
}

func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*SessionState, error) {
	return s.store.Get(ctx, sessionID)
}

func (s *SessionService) GetDecision(ctx context.Context, sessionID string) (*Decision, error) {
	session, err := s.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.LatestDecision == nil {
		return nil, fmt.Errorf("%w: no decision yet for session %s", ErrSessionNotFound, sessionID)
	}
	return session.LatestDecision, nil
}

func (s *SessionService) ListSessions(ctx context.Context, phase *SessionPhase) ([]*SessionState, error) {
	return s.store.List(ctx, phase)
}

func (s *SessionService) CloseSession(ctx context.Context, sessionID string) (*SessionState, error) {
	session, err := s.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.Phase == PhaseClosed {
		return nil, fmt.Errorf("%w: %s", ErrSessionClosed, sessionID)
	}

	session.Phase = PhaseClosed
	if err := s.store.Update(ctx, session); err != nil {
		return nil, fmt.Errorf("closing session %s: %w", sessionID, err)
	}

	s.logger.InfoContext(ctx, "session closed", slog.String("session_id", sessionID))

	return s.store.Get(ctx, sessionID)
}

// IsSessionNotFound returns true when the error wraps ErrSessionNotFound.
func IsSessionNotFound(err error) bool {
	return errors.Is(err, ErrSessionNotFound)
}

// IsInvalidDeclaration returns true when the error wraps ErrInvalidDeclaration.
func IsInvalidDeclaration(err error) bool {
	return errors.Is(err, ErrInvalidDeclaration)
}

// IsInvalidEvent returns true when the error wraps ErrInvalidEvent.
func IsInvalidEvent(err error) bool {
	return errors.Is(err, ErrInvalidEvent)
}

// IsSessionClosed returns true when the error wraps ErrSessionClosed.
func IsSessionClosed(err error) bool {
	return errors.Is(err, ErrSessionClosed)
}

// LoggingActionSink logs containment actions via slog.
type LoggingActionSink struct {
	logger *slog.Logger
}

func NewLoggingActionSink() *LoggingActionSink {
	return &LoggingActionSink{logger: slog.Default()}
}

var _ ActionSink = (*LoggingActionSink)(nil)

func (l *LoggingActionSink) Execute(_ context.Context, sessionID string, action ContainmentAction, decision *Decision) error {
	l.logger.Warn("containment action triggered",
		slog.String("session_id", sessionID),
		slog.String("action", string(action)),
		slog.String("state", string(decision.State)),
		slog.Int("findings", len(decision.Findings)),
	)
	return nil
}

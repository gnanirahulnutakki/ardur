package governance

import (
	"context"
	"testing"
	"time"
)

func validDeclaration(sessionID string) *MissionDeclaration {
	return &MissionDeclaration{
		ID:             "decl-" + sessionID,
		SessionID:      sessionID,
		AllowedActions: []string{"read", "write"},
		AllowedTools:   []string{"tool-a", "tool-b"},
		CreatedAt:      time.Now().UTC(),
	}
}

func validEvent(sessionID, eventID string) *ObservedEvent {
	return &ObservedEvent{
		EventID:         eventID,
		SessionID:       sessionID,
		Timestamp:       time.Now().UTC(),
		Actor:           "agent-1",
		ActionClass:     "read",
		ToolName:        "tool-a",
		Target:          "/data/file.txt",
		Summary:         "read a file",
		SideEffectClass: "none",
		Visibility:      "full",
	}
}

func newTestService() (*SessionService, *MemoryStore, *MockActionSink) {
	store := NewMemoryStore()
	engine := NewEngine()
	sink := NewMockActionSink()
	svc := NewSessionService(store, engine, sink)
	return svc, store, sink
}

func TestCreateSession(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	decl := validDeclaration("sess-1")
	session, err := svc.CreateSession(ctx, decl)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if session.ID != "sess-1" {
		t.Errorf("session.ID = %q, want %q", session.ID, "sess-1")
	}
	if session.Phase != PhaseInitialized {
		t.Errorf("session.Phase = %q, want %q", session.Phase, PhaseInitialized)
	}
	if session.Declaration == nil {
		t.Fatal("session.Declaration is nil")
	}
	if session.Declaration.ID != "decl-sess-1" {
		t.Errorf("declaration.ID = %q, want %q", session.Declaration.ID, "decl-sess-1")
	}
}

func TestCreateSessionInvalidDeclaration(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.CreateSession(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil declaration")
	}

	bad := &MissionDeclaration{ID: "", SessionID: "x"}
	_, err = svc.CreateSession(ctx, bad)
	if !IsInvalidDeclaration(err) {
		t.Errorf("expected ErrInvalidDeclaration, got %v", err)
	}
}

func TestCreateSessionDuplicate(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	decl := validDeclaration("sess-dup")
	if _, err := svc.CreateSession(ctx, decl); err != nil {
		t.Fatalf("first CreateSession() error = %v", err)
	}

	_, err := svc.CreateSession(ctx, decl)
	if err == nil {
		t.Fatal("expected error for duplicate session")
	}
}

func TestIngestEventTriggersReconciliation(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	decl := validDeclaration("sess-2")
	if _, err := svc.CreateSession(ctx, decl); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	event := validEvent("sess-2", "evt-1")
	decision, err := svc.IngestEvent(ctx, event)
	if err != nil {
		t.Fatalf("IngestEvent() error = %v", err)
	}

	if decision.State != DecisionCompliant {
		t.Errorf("decision.State = %q, want %q", decision.State, DecisionCompliant)
	}
	if decision.EventsProcessed != 1 {
		t.Errorf("decision.EventsProcessed = %d, want 1", decision.EventsProcessed)
	}

	session, _ := svc.GetSession(ctx, "sess-2")
	if session.Phase != PhaseActive {
		t.Errorf("session.Phase = %q, want %q after first event", session.Phase, PhaseActive)
	}
}

func TestIngestEventViolationTriggersActionSink(t *testing.T) {
	svc, _, sink := newTestService()
	ctx := context.Background()

	decl := validDeclaration("sess-v")
	if _, err := svc.CreateSession(ctx, decl); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	event := validEvent("sess-v", "evt-bad")
	event.ToolName = "unauthorized-tool"

	decision, err := svc.IngestEvent(ctx, event)
	if err != nil {
		t.Fatalf("IngestEvent() error = %v", err)
	}

	if decision.State != DecisionViolation {
		t.Errorf("decision.State = %q, want %q", decision.State, DecisionViolation)
	}

	actions := sink.Actions()
	if len(actions) != 1 {
		t.Fatalf("expected 1 action sink execution, got %d", len(actions))
	}
	if actions[0].SessionID != "sess-v" {
		t.Errorf("action session = %q, want %q", actions[0].SessionID, "sess-v")
	}
}

func TestIngestEventMissingSession(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	event := validEvent("nonexistent", "evt-1")
	_, err := svc.IngestEvent(ctx, event)
	if !IsSessionNotFound(err) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestIngestEventInvalidEvent(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.IngestEvent(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil event")
	}

	bad := &ObservedEvent{EventID: "", SessionID: "x"}
	_, err = svc.IngestEvent(ctx, bad)
	if !IsInvalidEvent(err) {
		t.Errorf("expected ErrInvalidEvent, got %v", err)
	}
}

func TestIngestEventOnClosedSession(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	decl := validDeclaration("sess-closed")
	if _, err := svc.CreateSession(ctx, decl); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if _, err := svc.CloseSession(ctx, "sess-closed"); err != nil {
		t.Fatalf("CloseSession() error = %v", err)
	}

	event := validEvent("sess-closed", "evt-1")
	_, err := svc.IngestEvent(ctx, event)
	if !IsSessionClosed(err) {
		t.Errorf("expected ErrSessionClosed, got %v", err)
	}
}

func TestGetDecision(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	decl := validDeclaration("sess-d")
	if _, err := svc.CreateSession(ctx, decl); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	_, err := svc.GetDecision(ctx, "sess-d")
	if err == nil {
		t.Fatal("expected error when no decision exists yet")
	}

	event := validEvent("sess-d", "evt-1")
	if _, err := svc.IngestEvent(ctx, event); err != nil {
		t.Fatalf("IngestEvent() error = %v", err)
	}

	decision, err := svc.GetDecision(ctx, "sess-d")
	if err != nil {
		t.Fatalf("GetDecision() error = %v", err)
	}
	if decision.SessionID != "sess-d" {
		t.Errorf("decision.SessionID = %q, want %q", decision.SessionID, "sess-d")
	}
}

func TestGetDecisionNotFound(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.GetDecision(ctx, "nope")
	if !IsSessionNotFound(err) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestListSessions(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	for _, id := range []string{"s1", "s2", "s3"} {
		decl := validDeclaration(id)
		if _, err := svc.CreateSession(ctx, decl); err != nil {
			t.Fatalf("CreateSession(%s) error = %v", id, err)
		}
	}

	event := validEvent("s1", "evt-1")
	if _, err := svc.IngestEvent(ctx, event); err != nil {
		t.Fatalf("IngestEvent() error = %v", err)
	}

	all, err := svc.ListSessions(ctx, nil)
	if err != nil {
		t.Fatalf("ListSessions(nil) error = %v", err)
	}
	if len(all) != 3 {
		t.Errorf("len(all) = %d, want 3", len(all))
	}

	active := PhaseActive
	activeList, err := svc.ListSessions(ctx, &active)
	if err != nil {
		t.Fatalf("ListSessions(active) error = %v", err)
	}
	if len(activeList) != 1 {
		t.Errorf("len(activeList) = %d, want 1", len(activeList))
	}
}

func TestCloseSession(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	decl := validDeclaration("sess-c")
	if _, err := svc.CreateSession(ctx, decl); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	session, err := svc.CloseSession(ctx, "sess-c")
	if err != nil {
		t.Fatalf("CloseSession() error = %v", err)
	}
	if session.Phase != PhaseClosed {
		t.Errorf("session.Phase = %q, want %q", session.Phase, PhaseClosed)
	}

	_, err = svc.CloseSession(ctx, "sess-c")
	if !IsSessionClosed(err) {
		t.Errorf("expected ErrSessionClosed on double close, got %v", err)
	}
}

func TestCloseSessionNotFound(t *testing.T) {
	svc, _, _ := newTestService()
	ctx := context.Background()

	_, err := svc.CloseSession(ctx, "nope")
	if !IsSessionNotFound(err) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

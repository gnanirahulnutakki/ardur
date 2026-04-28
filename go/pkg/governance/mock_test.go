package governance

import (
	"context"
	"errors"
	"testing"
)

func TestMockReconcilerDefault(t *testing.T) {
	t.Parallel()
	m := NewMockReconciler()
	decl := &MissionDeclaration{SessionID: "s-1"}
	events := []ObservedEvent{{}, {}}

	d, err := m.Reconcile(context.Background(), decl, events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.State != DecisionUnknown {
		t.Fatalf("expected unknown default, got %s", d.State)
	}
	if d.EventsProcessed != 2 {
		t.Fatalf("expected 2 events, got %d", d.EventsProcessed)
	}
	if m.Calls() != 1 {
		t.Fatalf("expected 1 call, got %d", m.Calls())
	}
}

func TestMockReconcilerConfigured(t *testing.T) {
	t.Parallel()
	m := NewMockReconciler()
	m.SetDecision(&Decision{State: DecisionCompliant})

	d, err := m.Reconcile(context.Background(), &MissionDeclaration{SessionID: "s-1"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.State != DecisionCompliant {
		t.Fatalf("expected compliant, got %s", d.State)
	}
}

func TestMockReconcilerError(t *testing.T) {
	t.Parallel()
	m := NewMockReconciler()
	m.SetError(errors.New("test error"))

	_, err := m.Reconcile(context.Background(), &MissionDeclaration{SessionID: "s-1"}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMockActionSink(t *testing.T) {
	t.Parallel()
	sink := NewMockActionSink()
	decision := &Decision{State: DecisionViolation}

	err := sink.Execute(context.Background(), "s-1", ActionAlert, decision)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	actions := sink.Actions()
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].SessionID != "s-1" {
		t.Fatalf("expected s-1, got %s", actions[0].SessionID)
	}
	if actions[0].Action != ActionAlert {
		t.Fatalf("expected alert, got %s", actions[0].Action)
	}
}

func TestMockActionSinkError(t *testing.T) {
	t.Parallel()
	sink := NewMockActionSink()
	sink.SetError(errors.New("sink failed"))

	err := sink.Execute(context.Background(), "s-1", ActionAlert, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMockDeclarationValidator(t *testing.T) {
	t.Parallel()
	v := NewMockDeclarationValidator()
	if err := v.Validate(context.Background(), &MissionDeclaration{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	v.SetError(errors.New("invalid"))
	if err := v.Validate(context.Background(), &MissionDeclaration{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestMockEventNormalizer(t *testing.T) {
	t.Parallel()
	n := NewMockEventNormalizer()
	event := &ObservedEvent{EventID: "e-1"}
	result, err := n.Normalize(context.Background(), event)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.EventID != "e-1" {
		t.Fatalf("expected e-1, got %s", result.EventID)
	}

	n.SetError(errors.New("normalize failed"))
	_, err = n.Normalize(context.Background(), event)
	if err == nil {
		t.Fatal("expected error")
	}
}

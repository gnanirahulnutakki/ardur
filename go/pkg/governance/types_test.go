package governance

import (
	"errors"
	"testing"
	"time"
)

func TestMissionDeclarationValidate(t *testing.T) {
	t.Parallel()
	valid := MissionDeclaration{
		ID:             "d-1",
		SessionID:      "s-1",
		AllowedActions: []string{"read"},
		AllowedTools:   []string{"file_reader"},
		CreatedAt:      time.Now(),
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*MissionDeclaration)
	}{
		{"missing id", func(d *MissionDeclaration) { d.ID = "" }},
		{"missing session_id", func(d *MissionDeclaration) { d.SessionID = "" }},
		{"missing allowed_actions", func(d *MissionDeclaration) { d.AllowedActions = nil }},
		{"missing allowed_tools", func(d *MissionDeclaration) { d.AllowedTools = nil }},
		{"negative delegation max_depth", func(d *MissionDeclaration) {
			d.DelegationPolicy = &DelegationPolicy{MaxDepth: -1}
		}},
		{"negative delegation total", func(d *MissionDeclaration) {
			d.DelegationPolicy = &DelegationPolicy{MaxTotalDelegations: -1}
		}},
		{"negative delegation sibling", func(d *MissionDeclaration) {
			d.DelegationPolicy = &DelegationPolicy{MaxSiblingDelegations: -1}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := valid
			d.DelegationPolicy = nil
			tt.mutate(&d)
			if err := d.Validate(); err == nil {
				t.Fatal("expected error")
			} else if !errors.Is(err, ErrInvalidDeclaration) {
				t.Fatalf("expected ErrInvalidDeclaration, got %v", err)
			}
		})
	}
}

func TestObservedEventValidate(t *testing.T) {
	t.Parallel()
	valid := ObservedEvent{
		EventID:         "e-1",
		SessionID:       "s-1",
		Timestamp:       time.Now(),
		Actor:           "agent",
		ActionClass:     "read",
		ToolName:        "file_reader",
		Target:          "doc.txt",
		Summary:         "read a file",
		SideEffectClass: "none",
		Visibility:      "full",
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ObservedEvent)
	}{
		{"missing event_id", func(e *ObservedEvent) { e.EventID = "" }},
		{"missing session_id", func(e *ObservedEvent) { e.SessionID = "" }},
		{"missing timestamp", func(e *ObservedEvent) { e.Timestamp = time.Time{} }},
		{"missing actor", func(e *ObservedEvent) { e.Actor = "" }},
		{"missing action_class", func(e *ObservedEvent) { e.ActionClass = "" }},
		{"missing tool_name", func(e *ObservedEvent) { e.ToolName = "" }},
		{"missing target", func(e *ObservedEvent) { e.Target = "" }},
		{"missing summary", func(e *ObservedEvent) { e.Summary = "" }},
		{"missing side_effect_class", func(e *ObservedEvent) { e.SideEffectClass = "" }},
		{"missing visibility", func(e *ObservedEvent) { e.Visibility = "" }},
		{"confidence_hint out of range", func(e *ObservedEvent) { e.ConfidenceHint = 1.5 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := valid
			tt.mutate(&e)
			if err := e.Validate(); err == nil {
				t.Fatal("expected error")
			} else if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("expected ErrInvalidEvent, got %v", err)
			}
		})
	}
}

func TestDecisionStateConstants(t *testing.T) {
	t.Parallel()
	states := []DecisionState{DecisionCompliant, DecisionViolation, DecisionUnknown, DecisionPending}
	seen := make(map[DecisionState]bool)
	for _, s := range states {
		if seen[s] {
			t.Fatalf("duplicate state: %s", s)
		}
		seen[s] = true
	}
}

func TestContainmentActionConstants(t *testing.T) {
	t.Parallel()
	actions := []ContainmentAction{ActionNone, ActionLog, ActionAlert, ActionThrottle, ActionQuarantine, ActionTerminate}
	seen := make(map[ContainmentAction]bool)
	for _, a := range actions {
		if seen[a] {
			t.Fatalf("duplicate action: %s", a)
		}
		seen[a] = true
	}
}

func TestSessionPhaseConstants(t *testing.T) {
	t.Parallel()
	phases := []SessionPhase{PhaseInitialized, PhaseActive, PhaseClosed}
	seen := make(map[SessionPhase]bool)
	for _, p := range phases {
		if seen[p] {
			t.Fatalf("duplicate phase: %s", p)
		}
		seen[p] = true
	}
}

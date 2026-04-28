package governance

import (
	"testing"
	"time"
)

func TestAdaptDeclaration(t *testing.T) {
	t.Parallel()
	bd := BenchmarkDeclaration{
		AllowedActions:          []string{"read", "write"},
		AllowedTools:            []string{"reader", "writer"},
		AllowedResources:        []string{"doc.txt"},
		AllowedResourceFamilies: []string{"documents"},
		AllowedSideEffects:      []string{"write_notes"},
		DelegationPolicy: &DelegationPolicy{
			MaxDepth:              2,
			MaxTotalDelegations:   5,
			MaxSiblingDelegations: 3,
		},
	}

	decl := AdaptDeclaration("sess-001", bd)

	if decl.ID != "bench-sess-001" {
		t.Fatalf("expected id bench-sess-001, got %s", decl.ID)
	}
	if decl.SessionID != "sess-001" {
		t.Fatalf("expected session sess-001, got %s", decl.SessionID)
	}
	if len(decl.AllowedActions) != 2 {
		t.Fatalf("expected 2 allowed actions, got %d", len(decl.AllowedActions))
	}
	if decl.DelegationPolicy == nil {
		t.Fatal("expected delegation policy")
	}
	if decl.DelegationPolicy.MaxDepth != 2 {
		t.Fatalf("expected max depth 2, got %d", decl.DelegationPolicy.MaxDepth)
	}
	if err := decl.Validate(); err != nil {
		t.Fatalf("adapted declaration should be valid: %v", err)
	}
}

func TestAdaptDeclarationNilDelegation(t *testing.T) {
	t.Parallel()
	bd := BenchmarkDeclaration{
		AllowedActions: []string{"read"},
		AllowedTools:   []string{"reader"},
	}

	decl := AdaptDeclaration("sess-002", bd)
	if decl.DelegationPolicy != nil {
		t.Fatal("expected nil delegation policy")
	}
}

func TestAdaptDeclarationLegacyDelegation(t *testing.T) {
	t.Parallel()
	bd := BenchmarkDeclaration{
		AllowedActions: []string{"read", "delegate"},
		AllowedTools:   []string{"reader", "delegator"},
		Delegation:     "single-hop",
	}

	decl := AdaptDeclaration("sess-legacy", bd)
	if decl.DelegationPolicy == nil {
		t.Fatal("expected legacy delegation policy to be expanded")
	}
	if decl.DelegationPolicy.MaxDepth != 1 || decl.DelegationPolicy.MaxTotalDelegations != 1 || decl.DelegationPolicy.MaxSiblingDelegations != 1 {
		t.Fatalf("unexpected legacy delegation expansion: %+v", *decl.DelegationPolicy)
	}
}

func TestAdaptEvent(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	be := BenchmarkEvent{
		EventID:         "evt-001",
		Timestamp:       now.Format(time.RFC3339),
		SessionID:       "sess-001",
		Actor:           "agent",
		ActionClass:     "read",
		ToolName:        "file_reader",
		Target:          "doc.txt",
		ResourceFamily:  "documents",
		ContentClass:    "text",
		Summary:         "read the doc",
		SideEffectClass: "none",
		Visibility:      "full",
		DelegationFrom:  "agent",
		DelegationTo:    "sub-agent",
		ConfidenceHint:  0.9,
	}

	event, err := AdaptEvent(be)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.EventID != "evt-001" {
		t.Fatalf("expected evt-001, got %s", event.EventID)
	}
	if event.SessionID != "sess-001" {
		t.Fatalf("expected sess-001, got %s", event.SessionID)
	}
	if !event.Timestamp.Equal(now) {
		t.Fatalf("expected %v, got %v", now, event.Timestamp)
	}
	if event.DelegationTo != "sub-agent" {
		t.Fatalf("expected sub-agent, got %s", event.DelegationTo)
	}
}

func TestAdaptEventBadTimestamp(t *testing.T) {
	t.Parallel()
	be := BenchmarkEvent{
		EventID:   "evt-bad",
		Timestamp: "not-a-timestamp",
		SessionID: "sess-001",
	}
	_, err := AdaptEvent(be)
	if err == nil {
		t.Fatal("expected error for bad timestamp")
	}
}

func TestAdaptDecisionToOutcome(t *testing.T) {
	t.Parallel()
	tests := []struct {
		state    DecisionState
		expected string
	}{
		{DecisionCompliant, "compliant"},
		{DecisionViolation, "violation"},
		{DecisionUnknown, "unknown"},
		{DecisionPending, "unknown"},
		{DecisionState("garbage"), "unknown"},
	}
	for _, tt := range tests {
		got := AdaptDecisionToOutcome(tt.state)
		if got != tt.expected {
			t.Errorf("AdaptDecisionToOutcome(%s) = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

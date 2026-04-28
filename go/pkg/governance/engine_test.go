package governance

import (
	"context"
	"testing"
	"time"
)

func baseDeclaration() *MissionDeclaration {
	return &MissionDeclaration{
		ID:                 "d-test",
		SessionID:          "s-test",
		AllowedActions:     []string{"read", "write"},
		AllowedTools:       []string{"file_reader", "file_writer"},
		AllowedResources:   []string{"doc.txt", "report.csv"},
		AllowedSideEffects: []string{"write", "modify"},
		CreatedAt:          time.Now(),
	}
}

func compliantEvent(id string) ObservedEvent {
	return ObservedEvent{
		EventID:         id,
		SessionID:       "s-test",
		Timestamp:       time.Now(),
		Actor:           "agent",
		ActionClass:     "read",
		ToolName:        "file_reader",
		Target:          "doc.txt",
		Summary:         "reading a file",
		SideEffectClass: "none",
		Visibility:      "full",
	}
}

func TestEngineCompliantSession(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	events := []ObservedEvent{compliantEvent("e-1"), compliantEvent("e-2")}

	decision, err := engine.Reconcile(context.Background(), decl, events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionCompliant {
		t.Fatalf("expected compliant, got %s", decision.State)
	}
	if decision.EventsProcessed != 2 {
		t.Fatalf("expected 2 events processed, got %d", decision.EventsProcessed)
	}
	if len(decision.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(decision.Findings))
	}
	if decision.RecommendedAction != ActionNone {
		t.Fatalf("expected action none, got %s", decision.RecommendedAction)
	}
}

func TestEngineNilDeclaration(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decision, err := engine.Reconcile(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionPending {
		t.Fatalf("expected pending, got %s", decision.State)
	}
}

func TestEngineToolViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	event := compliantEvent("e-bad-tool")
	event.ToolName = "secret_exfiltrator"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "tool_out_of_scope")
	if decision.RecommendedAction != ActionAlert {
		t.Fatalf("expected alert action, got %s", decision.RecommendedAction)
	}
}

func TestEngineActionViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	event := compliantEvent("e-bad-action")
	event.ActionClass = "delegate"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "action_out_of_scope")
}

func TestEngineResourceViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	event := compliantEvent("e-bad-resource")
	event.Target = "secrets.yaml"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "resource_out_of_scope")
}

func TestEngineResourceFamilyMissing(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedResourceFamilies = []string{"documents"}
	event := compliantEvent("e-no-family")

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "resource_family_missing")
}

func TestEngineResourceFamilyViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedResourceFamilies = []string{"documents"}
	event := compliantEvent("e-bad-family")
	event.ResourceFamily = "credentials"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "resource_family_out_of_scope")
}

func TestEngineSideEffectViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedSideEffects = nil
	event := compliantEvent("e-bad-side-effect")
	event.SideEffectClass = "external_send"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "side_effect_out_of_scope")
}

func TestEngineSideEffectAllowed(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedSideEffects = []string{"send_summary"}
	event := compliantEvent("e-send")
	event.SideEffectClass = "external_send"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionCompliant {
		t.Fatalf("expected compliant, got %s (findings: %v)", decision.State, decision.Findings)
	}
}

func TestEngineSummarySemanticsViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedSideEffects = []string{"one_summary_note"}

	event := compliantEvent("e-summary-drift")
	event.ActionClass = "write"
	event.ToolName = "file_writer"
	event.SideEffectClass = "internal_write"
	event.ContentClass = "raw_records"
	event.Summary = "write raw dataset records to a note file"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "summary_semantics_out_of_scope")
}

func TestEngineSummarySemanticsAllowed(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedSideEffects = []string{"one_summary_note"}

	event := compliantEvent("e-summary-ok")
	event.ActionClass = "write"
	event.ToolName = "file_writer"
	event.SideEffectClass = "internal_write"
	event.ContentClass = "summary_note"
	event.Summary = "write a concise summary note"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionCompliant {
		t.Fatalf("expected compliant, got %s (findings: %v)", decision.State, decision.Findings)
	}
}

func TestEnginePartialVisibility(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	event := compliantEvent("e-partial")
	event.Visibility = "partial"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionUnknown {
		t.Fatalf("expected unknown, got %s", decision.State)
	}
	assertFindingCode(t, decision, "visibility_insufficient")
}

func TestEngineDelegationDepthViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedActions = []string{"read", "delegate"}
	decl.AllowedTools = []string{"file_reader", "delegator"}
	decl.DelegationPolicy = &DelegationPolicy{MaxDepth: 1, MaxTotalDelegations: 10, MaxSiblingDelegations: 10}

	events := []ObservedEvent{
		{
			EventID: "e-d1", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "agent", ActionClass: "delegate", ToolName: "delegator",
			Target: "sub-agent-1", Summary: "delegating", SideEffectClass: "none",
			Visibility: "full", DelegationFrom: "agent", DelegationTo: "sub-agent-1",
		},
		{
			EventID: "e-d2", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "sub-agent-1", ActionClass: "delegate", ToolName: "delegator",
			Target: "sub-agent-2", Summary: "re-delegating", SideEffectClass: "none",
			Visibility: "full", DelegationFrom: "sub-agent-1", DelegationTo: "sub-agent-2",
		},
	}

	decision, err := engine.Reconcile(context.Background(), decl, events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "delegation_depth_exceeded")
}

func TestEngineDelegationTotalViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedActions = []string{"read", "delegate"}
	decl.AllowedTools = []string{"file_reader", "delegator"}
	decl.DelegationPolicy = &DelegationPolicy{MaxDepth: 10, MaxTotalDelegations: 1, MaxSiblingDelegations: 10}

	events := []ObservedEvent{
		{
			EventID: "e-d1", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "agent", ActionClass: "delegate", ToolName: "delegator",
			Target: "sub-1", Summary: "d1", SideEffectClass: "none",
			Visibility: "full", DelegationFrom: "agent", DelegationTo: "sub-1",
		},
		{
			EventID: "e-d2", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "agent", ActionClass: "delegate", ToolName: "delegator",
			Target: "sub-2", Summary: "d2", SideEffectClass: "none",
			Visibility: "full", DelegationFrom: "agent", DelegationTo: "sub-2",
		},
	}

	decision, err := engine.Reconcile(context.Background(), decl, events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "delegation_total_exceeded")
}

func TestEngineMultipleViolations(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	event := ObservedEvent{
		EventID: "e-multi", SessionID: "s-test", Timestamp: time.Now(),
		Actor: "agent", ActionClass: "delegate", ToolName: "evil_tool",
		Target: "secrets.yaml", Summary: "exfiltrating", SideEffectClass: "external_send",
		Visibility: "full",
	}

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	if len(decision.Findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d", len(decision.Findings))
	}
}

func TestEngineEmptyEvents(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()

	decision, err := engine.Reconcile(context.Background(), decl, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionCompliant {
		t.Fatalf("expected compliant for empty events, got %s", decision.State)
	}
	if decision.EventsProcessed != 0 {
		t.Fatalf("expected 0 events, got %d", decision.EventsProcessed)
	}
}

func TestEngineSideEffectNoneAlwaysAllowed(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedSideEffects = nil
	event := compliantEvent("e-none-se")
	event.SideEffectClass = "none"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionCompliant {
		t.Fatalf("expected compliant, got %s", decision.State)
	}
}

func TestEngineStateChangeSideEffect(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedSideEffects = []string{"state_update"}
	event := compliantEvent("e-state")
	event.SideEffectClass = "state_change"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionCompliant {
		t.Fatalf("expected compliant for allowed state_change, got %s", decision.State)
	}
}

func TestEngineSendBudgetViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedActions = []string{"send"}
	decl.AllowedTools = []string{"mailer"}
	decl.AllowedSideEffects = []string{"single_send"}

	events := []ObservedEvent{
		{
			EventID: "e-send-1", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "agent", ActionClass: "send", ToolName: "mailer",
			Target: "dest-1", Summary: "send first message", SideEffectClass: "external_send",
			Visibility: "full", ContentClass: "summary",
		},
		{
			EventID: "e-send-2", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "agent", ActionClass: "send", ToolName: "mailer",
			Target: "dest-2", Summary: "send second message", SideEffectClass: "external_send",
			Visibility: "full", ContentClass: "summary",
		},
	}

	decision, err := engine.Reconcile(context.Background(), decl, events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "send_budget_exceeded")
}

func TestEngineStateChangeBudgetViolation(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedActions = []string{"write"}
	decl.AllowedTools = []string{"file_writer"}
	decl.AllowedSideEffects = []string{"single_state"}

	events := []ObservedEvent{
		{
			EventID: "e-state-1", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "agent", ActionClass: "write", ToolName: "file_writer",
			Target: "doc.txt", Summary: "first state change", SideEffectClass: "state_change",
			Visibility: "full",
		},
		{
			EventID: "e-state-2", SessionID: "s-test", Timestamp: time.Now(),
			Actor: "agent", ActionClass: "write", ToolName: "file_writer",
			Target: "report.csv", Summary: "second state change", SideEffectClass: "state_change",
			Visibility: "full",
		},
	}

	decision, err := engine.Reconcile(context.Background(), decl, events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionViolation {
		t.Fatalf("expected violation, got %s", decision.State)
	}
	assertFindingCode(t, decision, "state_change_budget_exceeded")
}

func TestEngineNoResourceConstraints(t *testing.T) {
	t.Parallel()
	engine := NewEngine()
	decl := baseDeclaration()
	decl.AllowedResources = nil
	event := compliantEvent("e-any-target")
	event.Target = "anything_at_all.txt"

	decision, err := engine.Reconcile(context.Background(), decl, []ObservedEvent{event})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.State != DecisionCompliant {
		t.Fatalf("expected compliant with no resource constraints, got %s", decision.State)
	}
}

func assertFindingCode(t *testing.T, decision *Decision, code string) {
	t.Helper()
	for _, f := range decision.Findings {
		if f.Code == code {
			return
		}
	}
	t.Fatalf("expected finding with code %q, got %v", code, decision.Findings)
}

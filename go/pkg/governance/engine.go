package governance

import (
	"context"
	"strings"
	"time"
)

// Engine is the default Reconciler implementation. It applies conservative
// rule-based checks: tool scope, action scope, resource scope, side-effect
// scope, and delegation policy. When visibility is insufficient it returns
// DecisionUnknown rather than guessing.
type Engine struct{}

// NewEngine creates a governance reconciliation engine.
func NewEngine() *Engine {
	return &Engine{}
}

var _ Reconciler = (*Engine)(nil)

func (e *Engine) Reconcile(_ context.Context, decl *MissionDeclaration, events []ObservedEvent) (*Decision, error) {
	if decl == nil {
		return &Decision{
			State:              DecisionPending,
			RecommendedAction:  ActionNone,
			ReconciliationTime: time.Now().UTC(),
		}, nil
	}

	decision := &Decision{
		SessionID:          decl.SessionID,
		State:              DecisionCompliant,
		RecommendedAction:  ActionNone,
		ReconciliationTime: time.Now().UTC(),
	}
	externalSendCount := 0
	stateChangeCount := 0
	var delegationEvents []ObservedEvent

	for _, event := range events {
		decision.EventsProcessed++

		if visibilityInsufficient(event.Visibility) {
			decision.State = DecisionUnknown
			decision.Findings = append(decision.Findings, Finding{
				Code:    "visibility_insufficient",
				EventID: event.EventID,
				Field:   "visibility",
				Message: "event visibility is insufficient for reconciliation",
			})
			continue
		}

		if !containsFold(decl.AllowedTools, event.ToolName) {
			markViolation(decision, Finding{
				Code:      "tool_out_of_scope",
				EventID:   event.EventID,
				Field:     "tool_name",
				Message:   "tool is not allowed by the declaration",
				Violation: "tool_scope_violation",
			})
		}

		if !containsFold(decl.AllowedActions, event.ActionClass) {
			markViolation(decision, Finding{
				Code:      "action_out_of_scope",
				EventID:   event.EventID,
				Field:     "action_class",
				Message:   "action is not allowed by the declaration",
				Violation: "action_scope_violation",
			})
		}

		if len(decl.AllowedResources) > 0 && !containsFold(decl.AllowedResources, event.Target) {
			markViolation(decision, Finding{
				Code:      "resource_out_of_scope",
				EventID:   event.EventID,
				Field:     "target",
				Message:   "target is outside the declared resource scope",
				Violation: "resource_scope_violation",
			})
		}

		if len(decl.AllowedResourceFamilies) > 0 {
			if strings.TrimSpace(event.ResourceFamily) == "" {
				markViolation(decision, Finding{
					Code:      "resource_family_missing",
					EventID:   event.EventID,
					Field:     "resource_family",
					Message:   "typed resource family is required by the declaration",
					Violation: "resource_scope_violation",
				})
			} else if !containsFold(decl.AllowedResourceFamilies, event.ResourceFamily) {
				markViolation(decision, Finding{
					Code:      "resource_family_out_of_scope",
					EventID:   event.EventID,
					Field:     "resource_family",
					Message:   "resource family is outside the declared scope",
					Violation: "resource_scope_violation",
				})
			}
		}

		if !sideEffectAllowed(decl.AllowedSideEffects, event) {
			markViolation(decision, Finding{
				Code:      "side_effect_out_of_scope",
				EventID:   event.EventID,
				Field:     "side_effect_class",
				Message:   "side effect is incompatible with the declared mission",
				Violation: "side_effect_scope_violation",
			})
		}

		if !summarySemanticsAllowed(decl.AllowedSideEffects, event) {
			markViolation(decision, Finding{
				Code:      "summary_semantics_out_of_scope",
				EventID:   event.EventID,
				Field:     "summary",
				Message:   "observed content semantics exceed the declared output scope",
				Violation: "content_scope_violation",
			})
		}

		if strings.EqualFold(event.SideEffectClass, "external_send") {
			externalSendCount++
		}
		if strings.EqualFold(event.SideEffectClass, "state_change") {
			stateChangeCount++
		}
		if strings.EqualFold(event.ActionClass, "delegate") {
			delegationEvents = append(delegationEvents, event)
		}
	}

	if exceedsDeclaredSendBudget(decl.AllowedSideEffects, externalSendCount) {
		markViolation(decision, Finding{
			Code:      "send_budget_exceeded",
			Field:     "side_effect_class",
			Message:   "observed number of external sends exceeds the declared mission budget",
			Violation: "cumulative_side_effect_violation",
		})
	}

	if exceedsDeclaredStateChangeBudget(decl.AllowedSideEffects, stateChangeCount) {
		markViolation(decision, Finding{
			Code:      "state_change_budget_exceeded",
			Field:     "side_effect_class",
			Message:   "observed number of state changes exceeds the declared mission budget",
			Violation: "cumulative_side_effect_violation",
		})
	}

	delegationFindings := delegationPolicyFindings(decl, delegationEvents)
	for _, f := range delegationFindings {
		markViolation(decision, f)
	}

	if decision.State == DecisionViolation {
		decision.RecommendedAction = ActionAlert
	}

	return decision, nil
}

func markViolation(d *Decision, f Finding) {
	d.State = DecisionViolation
	d.Findings = append(d.Findings, f)
}

func visibilityInsufficient(visibility string) bool {
	return !strings.EqualFold(strings.TrimSpace(visibility), "full")
}

func containsFold(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

func sideEffectAllowed(allowed []string, event ObservedEvent) bool {
	if strings.EqualFold(event.SideEffectClass, "none") {
		return true
	}
	if len(allowed) == 0 {
		return false
	}
	joined := strings.ToLower(strings.Join(allowed, " "))
	switch strings.ToLower(event.SideEffectClass) {
	case "internal_write":
		return strings.Contains(joined, "write") || strings.Contains(joined, "modify") || strings.Contains(joined, "note")
	case "external_send":
		return strings.Contains(joined, "send")
	case "state_change":
		return strings.Contains(joined, "state") || strings.Contains(joined, "update") || strings.Contains(joined, "modify")
	default:
		return false
	}
}

func summarySemanticsAllowed(allowed []string, event ObservedEvent) bool {
	sideEffect := strings.ToLower(event.SideEffectClass)
	if sideEffect != "external_send" && sideEffect != "internal_write" {
		return true
	}
	if len(allowed) == 0 {
		return false
	}

	joined := strings.ToLower(strings.Join(allowed, " "))
	summary := strings.ToLower(event.Summary)
	contentClass := strings.ToLower(strings.TrimSpace(event.ContentClass))

	if strings.Contains(joined, "summary_only") ||
		strings.Contains(joined, "summary only") ||
		strings.Contains(joined, "one_summary_note") {
		if contentClass != "" {
			switch contentClass {
			case "summary", "summary_note":
				return true
			case "raw_records", "credential_material", "dataset_dump":
				return false
			default:
				return false
			}
		}
		if !strings.Contains(summary, "summary") && !strings.Contains(summary, "note") {
			return false
		}
		for _, bad := range []string{"raw", "record", "full dataset", "credential", "dump"} {
			if strings.Contains(summary, bad) {
				return false
			}
		}
	}

	return true
}

func exceedsDeclaredSendBudget(allowed []string, externalSendCount int) bool {
	if externalSendCount <= 1 {
		return false
	}
	joined := strings.ToLower(strings.Join(allowed, " "))
	return strings.Contains(joined, "single_send") ||
		strings.Contains(joined, "one_summary") ||
		strings.Contains(joined, "summary_only")
}

func exceedsDeclaredStateChangeBudget(allowed []string, stateChangeCount int) bool {
	if stateChangeCount <= 1 {
		return false
	}
	joined := strings.ToLower(strings.Join(allowed, " "))
	return strings.Contains(joined, "single_state") ||
		strings.Contains(joined, "one_state") ||
		strings.Contains(joined, "single_update")
}

func delegationPolicyFindings(decl *MissionDeclaration, events []ObservedEvent) []Finding {
	policy := decl.DelegationPolicy
	if policy == nil {
		return nil
	}

	actorDepth := map[string]int{"agent": 0}
	siblingCounts := make(map[string]int)
	totalDelegations := 0

	var findings []Finding
	depthViolated := false
	totalViolated := false
	siblingViolated := false

	for _, event := range events {
		if !strings.EqualFold(event.ActionClass, "delegate") {
			continue
		}
		totalDelegations++

		from := normalizedActor(event.DelegationFrom)
		to := normalizedActor(event.DelegationTo)
		fromDepth, ok := actorDepth[from]
		if !ok {
			fromDepth = 1
		}
		currentDepth := fromDepth + 1
		if to != "" {
			actorDepth[to] = currentDepth
		}
		siblingCounts[from]++

		if policy.MaxDepth >= 0 && currentDepth > policy.MaxDepth && !depthViolated {
			findings = append(findings, Finding{
				Code:      "delegation_depth_exceeded",
				EventID:   event.EventID,
				Field:     "delegation_policy.max_depth",
				Message:   "observed delegation depth exceeds the declared policy",
				Violation: "delegation_scope_violation",
			})
			depthViolated = true
		}

		if policy.MaxTotalDelegations >= 0 && totalDelegations > policy.MaxTotalDelegations && !totalViolated {
			findings = append(findings, Finding{
				Code:      "delegation_total_exceeded",
				EventID:   event.EventID,
				Field:     "delegation_policy.max_total_delegations",
				Message:   "observed total delegation count exceeds the declared policy",
				Violation: "delegation_scope_violation",
			})
			totalViolated = true
		}

		if policy.MaxSiblingDelegations >= 0 && siblingCounts[from] > policy.MaxSiblingDelegations && !siblingViolated {
			findings = append(findings, Finding{
				Code:      "delegation_sibling_exceeded",
				EventID:   event.EventID,
				Field:     "delegation_policy.max_sibling_delegations",
				Message:   "observed sibling fan-out exceeds the declared delegation policy",
				Violation: "delegation_scope_violation",
			})
			siblingViolated = true
		}
	}

	return findings
}

func normalizedActor(value string) string {
	n := strings.ToLower(strings.TrimSpace(value))
	if n == "" {
		return "agent"
	}
	return n
}

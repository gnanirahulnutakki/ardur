// Package governance provides runtime mission-bound governance types and
// interfaces for reconciling declared agent intent against observed behavior.
//
// This package is the canonical home for declared-vs-observed logic that was
// previously embedded only in the benchmark evaluators. It is designed to be
// used by the benchmark (via adapters), the governor service, and the
// Kubernetes operator.
package governance

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors.
var (
	ErrSessionNotFound    = errors.New("governance: session not found")
	ErrSessionClosed      = errors.New("governance: session already closed")
	ErrInvalidDeclaration = errors.New("governance: invalid declaration")
	ErrInvalidEvent       = errors.New("governance: invalid observed event")
	ErrStoreClosed        = errors.New("governance: store closed")
	ErrDuplicateSession   = errors.New("governance: duplicate session ID")
	ErrReconcilerNotReady = errors.New("governance: reconciler not ready")
)

// DecisionState represents the governance verdict for a session or event.
type DecisionState string

const (
	DecisionCompliant DecisionState = "compliant"
	DecisionViolation DecisionState = "violation"
	DecisionUnknown   DecisionState = "unknown"
	DecisionPending   DecisionState = "pending"
)

// ContainmentAction describes what the governance layer recommends.
type ContainmentAction string

const (
	ActionNone       ContainmentAction = "none"
	ActionLog        ContainmentAction = "log"
	ActionAlert      ContainmentAction = "alert"
	ActionThrottle   ContainmentAction = "throttle"
	ActionQuarantine ContainmentAction = "quarantine"
	ActionTerminate  ContainmentAction = "terminate"
)

// SessionPhase tracks the lifecycle of a governance session.
type SessionPhase string

const (
	PhaseInitialized SessionPhase = "initialized"
	PhaseActive      SessionPhase = "active"
	PhaseClosed      SessionPhase = "closed"
)

// MissionDeclaration captures what an agent is permitted to do.
// This is the governance-layer equivalent of a benchmark Declaration,
// generalized for runtime use.
type MissionDeclaration struct {
	ID                      string            `json:"id"`
	SessionID               string            `json:"session_id"`
	AllowedActions          []string          `json:"allowed_actions"`
	AllowedTools            []string          `json:"allowed_tools"`
	AllowedResources        []string          `json:"allowed_resources,omitempty"`
	AllowedResourceFamilies []string          `json:"allowed_resource_families,omitempty"`
	AllowedSideEffects      []string          `json:"allowed_side_effects,omitempty"`
	DelegationPolicy        *DelegationPolicy `json:"delegation_policy,omitempty"`
	Metadata                map[string]string `json:"metadata,omitempty"`
	CreatedAt               time.Time         `json:"created_at"`
}

// DelegationPolicy constrains agent-to-agent delegation chains.
type DelegationPolicy struct {
	MaxDepth              int `json:"max_depth"`
	MaxTotalDelegations   int `json:"max_total_delegations"`
	MaxSiblingDelegations int `json:"max_sibling_delegations"`
}

// Validate checks that a MissionDeclaration has all required fields.
func (d *MissionDeclaration) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidDeclaration)
	}
	if strings.TrimSpace(d.SessionID) == "" {
		return fmt.Errorf("%w: missing session_id", ErrInvalidDeclaration)
	}
	if len(d.AllowedActions) == 0 {
		return fmt.Errorf("%w: missing allowed_actions", ErrInvalidDeclaration)
	}
	if len(d.AllowedTools) == 0 {
		return fmt.Errorf("%w: missing allowed_tools", ErrInvalidDeclaration)
	}
	if d.DelegationPolicy != nil {
		if d.DelegationPolicy.MaxDepth < 0 || d.DelegationPolicy.MaxTotalDelegations < 0 || d.DelegationPolicy.MaxSiblingDelegations < 0 {
			return fmt.Errorf("%w: negative delegation policy limits", ErrInvalidDeclaration)
		}
	}
	return nil
}

// ObservedEvent is a single runtime observation from an agent session.
type ObservedEvent struct {
	EventID         string    `json:"event_id"`
	SessionID       string    `json:"session_id"`
	Timestamp       time.Time `json:"timestamp"`
	Actor           string    `json:"actor"`
	ActionClass     string    `json:"action_class"`
	ToolName        string    `json:"tool_name"`
	Target          string    `json:"target"`
	ResourceFamily  string    `json:"resource_family,omitempty"`
	ContentClass    string    `json:"content_class,omitempty"`
	Summary         string    `json:"summary"`
	SideEffectClass string    `json:"side_effect_class"`
	Visibility      string    `json:"visibility"`
	ParentEventID   string    `json:"parent_event_id,omitempty"`
	DelegationFrom  string    `json:"delegation_from,omitempty"`
	DelegationTo    string    `json:"delegation_to,omitempty"`
	ConfidenceHint  float64   `json:"confidence_hint,omitempty"`
}

// Validate checks that an ObservedEvent has all required fields.
func (e *ObservedEvent) Validate() error {
	if strings.TrimSpace(e.EventID) == "" {
		return fmt.Errorf("%w: missing event_id", ErrInvalidEvent)
	}
	if strings.TrimSpace(e.SessionID) == "" {
		return fmt.Errorf("%w: missing session_id for %s", ErrInvalidEvent, e.EventID)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("%w: missing timestamp for %s", ErrInvalidEvent, e.EventID)
	}
	for _, field := range []struct {
		name, value string
	}{
		{"actor", e.Actor},
		{"action_class", e.ActionClass},
		{"tool_name", e.ToolName},
		{"target", e.Target},
		{"summary", e.Summary},
		{"side_effect_class", e.SideEffectClass},
		{"visibility", e.Visibility},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%w: missing %s for %s", ErrInvalidEvent, field.name, e.EventID)
		}
	}
	if e.ConfidenceHint < 0 || e.ConfidenceHint > 1 {
		return fmt.Errorf("%w: confidence_hint out of range for %s", ErrInvalidEvent, e.EventID)
	}
	return nil
}

// Finding records a specific observation from reconciliation.
type Finding struct {
	Code      string `json:"code"`
	EventID   string `json:"event_id,omitempty"`
	Field     string `json:"field,omitempty"`
	Message   string `json:"message"`
	Violation string `json:"violation,omitempty"`
	Severity  string `json:"severity,omitempty"`
}

// Decision is the governance verdict for a session after reconciliation.
type Decision struct {
	SessionID          string            `json:"session_id"`
	State              DecisionState     `json:"state"`
	Findings           []Finding         `json:"findings,omitempty"`
	RecommendedAction  ContainmentAction `json:"recommended_action"`
	EventsProcessed    int               `json:"events_processed"`
	ReconciliationTime time.Time         `json:"reconciliation_time"`
}

// SessionState holds the full governance state for an agent session.
type SessionState struct {
	ID             string              `json:"id"`
	Phase          SessionPhase        `json:"phase"`
	Declaration    *MissionDeclaration `json:"declaration,omitempty"`
	Events         []ObservedEvent     `json:"events"`
	LatestDecision *Decision           `json:"latest_decision,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

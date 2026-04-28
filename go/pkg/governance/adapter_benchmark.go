package governance

import (
	"fmt"
	"strings"
	"time"
)

// BenchmarkDeclaration is a minimal subset of the benchmark's Declaration
// type used for adaptation. We do not import the benchmark package to avoid
// a circular dependency; callers construct this from benchmark.Declaration.
type BenchmarkDeclaration struct {
	AllowedActions          []string
	AllowedTools            []string
	AllowedResources        []string
	AllowedResourceFamilies []string
	AllowedSideEffects      []string
	DelegationPolicy        *DelegationPolicy
	Delegation              string
}

// BenchmarkEvent is a minimal subset of the benchmark's Event type.
type BenchmarkEvent struct {
	EventID         string
	Timestamp       string
	SessionID       string
	Actor           string
	ActionClass     string
	ToolName        string
	Target          string
	ResourceFamily  string
	ContentClass    string
	Summary         string
	SideEffectClass string
	Visibility      string
	ParentEventID   string
	DelegationFrom  string
	DelegationTo    string
	ConfidenceHint  float64
}

// AdaptDeclaration converts a benchmark declaration into a governance
// MissionDeclaration. The session ID is required.
func AdaptDeclaration(sessionID string, bd BenchmarkDeclaration) *MissionDeclaration {
	decl := &MissionDeclaration{
		ID:                      fmt.Sprintf("bench-%s", sessionID),
		SessionID:               sessionID,
		AllowedActions:          bd.AllowedActions,
		AllowedTools:            bd.AllowedTools,
		AllowedResources:        bd.AllowedResources,
		AllowedResourceFamilies: bd.AllowedResourceFamilies,
		AllowedSideEffects:      bd.AllowedSideEffects,
		CreatedAt:               time.Now().UTC(),
	}
	if bd.DelegationPolicy != nil {
		decl.DelegationPolicy = &DelegationPolicy{
			MaxDepth:              bd.DelegationPolicy.MaxDepth,
			MaxTotalDelegations:   bd.DelegationPolicy.MaxTotalDelegations,
			MaxSiblingDelegations: bd.DelegationPolicy.MaxSiblingDelegations,
		}
	} else if policy := legacyDelegationPolicy(bd.Delegation); policy != nil {
		decl.DelegationPolicy = policy
	}
	return decl
}

// AdaptEvent converts a benchmark event into a governance ObservedEvent.
func AdaptEvent(be BenchmarkEvent) (*ObservedEvent, error) {
	ts, err := time.Parse(time.RFC3339, be.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("parsing timestamp for %s: %w", be.EventID, err)
	}
	return &ObservedEvent{
		EventID:         be.EventID,
		SessionID:       be.SessionID,
		Timestamp:       ts,
		Actor:           be.Actor,
		ActionClass:     be.ActionClass,
		ToolName:        be.ToolName,
		Target:          be.Target,
		ResourceFamily:  be.ResourceFamily,
		ContentClass:    be.ContentClass,
		Summary:         be.Summary,
		SideEffectClass: be.SideEffectClass,
		Visibility:      be.Visibility,
		ParentEventID:   be.ParentEventID,
		DelegationFrom:  be.DelegationFrom,
		DelegationTo:    be.DelegationTo,
		ConfidenceHint:  be.ConfidenceHint,
	}, nil
}

// AdaptDecisionToOutcome maps a governance DecisionState to a benchmark-style
// outcome string for compatibility with existing reporting.
func AdaptDecisionToOutcome(state DecisionState) string {
	switch state {
	case DecisionCompliant:
		return "compliant"
	case DecisionViolation:
		return "violation"
	default:
		return "unknown"
	}
}

func legacyDelegationPolicy(value string) *DelegationPolicy {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "none":
		return &DelegationPolicy{
			MaxDepth:              0,
			MaxTotalDelegations:   0,
			MaxSiblingDelegations: 0,
		}
	case "single-hop", "single_hop", "singlehop":
		return &DelegationPolicy{
			MaxDepth:              1,
			MaxTotalDelegations:   1,
			MaxSiblingDelegations: 1,
		}
	case "fanout":
		return &DelegationPolicy{
			MaxDepth:              1,
			MaxTotalDelegations:   -1,
			MaxSiblingDelegations: -1,
		}
	default:
		return nil
	}
}

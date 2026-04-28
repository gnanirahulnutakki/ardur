package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/gnanirahulnutakki/ardur/go/pkg/policy"
)

type benchmarkEvent struct {
	EventID         string         `json:"event_id"`
	ToolName        string         `json:"tool_name"`
	Target          string         `json:"target"`
	Arguments       map[string]any `json:"arguments"`
	SideEffectClass string         `json:"side_effect_class"`
}

type benchmarkRequest struct {
	TraceID        string           `json:"trace_id"`
	Mode           string           `json:"mode"`
	AllowedTools   []string         `json:"allowed_tools"`
	ForbiddenTools []string         `json:"forbidden_tools"`
	ResourceScope  []string         `json:"resource_scope"`
	MaxToolCalls   int              `json:"max_tool_calls"`
	Events         []benchmarkEvent `json:"events"`
}

type benchmarkBatch struct {
	Requests []benchmarkRequest `json:"requests"`
}

type benchmarkResult struct {
	TraceID         string   `json:"trace_id"`
	Verdict         string   `json:"verdict"`
	Findings        []string `json:"findings"`
	FindingsCount   int      `json:"findings_count"`
	EventsEvaluated int      `json:"events_evaluated"`
}

type benchmarkOutput struct {
	Results []benchmarkResult `json:"results"`
}

func main() {
	var batch benchmarkBatch
	if err := json.NewDecoder(os.Stdin).Decode(&batch); err != nil {
		fail(err)
	}

	results := make([]benchmarkResult, 0, len(batch.Requests))
	for _, request := range batch.Requests {
		results = append(results, evaluateTrace(request))
	}

	if err := json.NewEncoder(os.Stdout).Encode(benchmarkOutput{Results: results}); err != nil {
		fail(err)
	}
}

func fail(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "cedar-benchmark-wrapper: %v\n", err)
	os.Exit(1)
}

func evaluateTrace(request benchmarkRequest) benchmarkResult {
	result := benchmarkResult{
		TraceID:  request.TraceID,
		Verdict:  "compliant",
		Findings: make([]string, 0),
	}
	if strings.TrimSpace(request.TraceID) == "" {
		result.Verdict = "unknown"
		result.Findings = append(result.Findings, "missing trace_id")
		result.FindingsCount = len(result.Findings)
		return result
	}

	engine := policy.NewCedarEngine()
	defer engine.Close()

	policyText := buildPolicy(request)
	compiled, err := engine.Compile(context.Background(), policyText)
	if err != nil {
		result.Verdict = "unknown"
		result.Findings = append(result.Findings, fmt.Sprintf("cedar_compile_error: %v", err))
		result.FindingsCount = len(result.Findings)
		return result
	}

	toolCalls := 0
	for _, event := range request.Events {
		result.EventsEvaluated++
		inScope := resourceInScope(request.ResourceScope, event.Target, event.Arguments)
		resourceID := event.Target
		if strings.TrimSpace(resourceID) == "" {
			resourceID = event.ToolName
		}
		entities := []policy.Entity{
			{
				UID: policy.EntityRef{Type: "VIBAP::Agent", ID: request.TraceID},
			},
			{
				UID: policy.EntityRef{Type: "Action", ID: event.ToolName},
			},
			{
				UID: policy.EntityRef{Type: "VIBAP::Resource", ID: resourceID},
				Attributes: map[string]any{
					"in_scope": inScope,
				},
			},
		}
		authResult, err := engine.Evaluate(
			context.Background(),
			compiled,
			entities,
			policy.AuthzRequest{
				Principal: policy.EntityRef{Type: "VIBAP::Agent", ID: request.TraceID},
				Action:    policy.EntityRef{Type: "Action", ID: event.ToolName},
				Resource:  policy.EntityRef{Type: "VIBAP::Resource", ID: resourceID},
			},
		)
		if err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("%s: cedar_eval_error: %v", event.EventID, err))
			continue
		}
		if authResult.Decision != policy.DecisionAllow {
			result.Findings = append(result.Findings, fmt.Sprintf("%s: denied by cedar", event.EventID))
		}

		if request.Mode == "stateful" {
			toolCalls++
			if request.MaxToolCalls > 0 && toolCalls > request.MaxToolCalls {
				result.Findings = append(
					result.Findings,
					fmt.Sprintf("%s: tool call budget exceeded: %d > %d", event.EventID, toolCalls, request.MaxToolCalls),
				)
			}
		}
	}

	if len(result.Findings) > 0 {
		result.Verdict = "violation"
	}
	result.FindingsCount = len(result.Findings)
	return result
}

func buildPolicy(request benchmarkRequest) string {
	var b strings.Builder
	for _, toolName := range request.AllowedTools {
		if strings.TrimSpace(toolName) == "" {
			continue
		}
		fmt.Fprintf(
			&b,
			"permit(\n  principal == VIBAP::Agent::%s,\n  action == Action::%s,\n  resource\n)",
			quoteCedar(request.TraceID),
			quoteCedar(toolName),
		)
		if request.Mode != "real" && len(request.ResourceScope) > 0 {
			b.WriteString(" when {\n  resource.in_scope == true\n}")
		}
		b.WriteString(";\n\n")
	}
	for _, toolName := range request.ForbiddenTools {
		if strings.TrimSpace(toolName) == "" {
			continue
		}
		fmt.Fprintf(
			&b,
			"forbid(\n  principal,\n  action == Action::%s,\n  resource\n);\n\n",
			quoteCedar(toolName),
		)
	}
	if b.Len() == 0 {
		b.WriteString("forbid(principal, action, resource);\n")
	}
	return b.String()
}

func quoteCedar(value string) string {
	return strconv.Quote(value)
}

func resourceInScope(patterns []string, target string, arguments map[string]any) bool {
	if len(patterns) == 0 {
		return true
	}
	candidates := make([]string, 0, 16)
	if strings.TrimSpace(target) != "" {
		candidates = append(candidates, strings.TrimSpace(target))
	}
	candidates = append(candidates, collectStrings(arguments)...)
	for _, candidate := range candidates {
		for _, patternValue := range patterns {
			if matchesPattern(candidate, patternValue) {
				return true
			}
		}
	}
	return false
}

func collectStrings(value any) []string {
	out := make([]string, 0, 16)
	seen := map[string]struct{}{}
	var visit func(node any, depth int)
	visit = func(node any, depth int) {
		if depth > 8 || len(out) >= 64 {
			return
		}
		switch typed := node.(type) {
		case string:
			text := strings.TrimSpace(typed)
			if text == "" {
				return
			}
			if _, ok := seen[text]; ok {
				return
			}
			seen[text] = struct{}{}
			out = append(out, text)
		case []any:
			for _, item := range typed {
				visit(item, depth+1)
			}
		case []string:
			for _, item := range typed {
				visit(item, depth+1)
			}
		case map[string]any:
			for _, item := range typed {
				visit(item, depth+1)
			}
		}
	}
	visit(value, 0)
	return out
}

func matchesPattern(candidate string, patternValue string) bool {
	if candidate == patternValue {
		return true
	}
	ok, err := path.Match(patternValue, candidate)
	if err == nil && ok {
		return true
	}
	return false
}

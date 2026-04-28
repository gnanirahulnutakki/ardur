package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidScenarioPasses(t *testing.T) {
	data := []byte(`{
		"id": "T1",
		"title": "Test scenario",
		"task": {"narrative": "Test narrative"},
		"declarations": {"strong": {"allowed_actions": ["read"], "allowed_tools": ["tool1"]}},
		"environment": {"available_tools": ["tool1"]},
		"ground_truth": {"label": "compliant"},
		"baseline_expectations": {},
		"metrics_focus": ["misuse_recall"]
	}`)
	errs := validateScenario("test.json", data, false)
	if len(errs) > 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

func TestValidStrictEventPasses(t *testing.T) {
	data := []byte(`{
		"event_id": "T1-1",
		"timestamp": "2026-03-10T10:00:00Z",
		"session_id": "sess1",
		"actor": "agent",
		"action_class": "read",
		"tool_name": "tool1",
		"target": "resource1",
		"summary": "read resource",
		"side_effect_class": "none",
		"visibility": "full",
		"expected_label": "compliant",
		"confidence_hint": 0.9
	}`)
	errs := validateEvent("test.jsonl", 1, data, true)
	if len(errs) > 0 {
		t.Fatalf("expected no errors, got: %v", errs)
	}
}

func TestMissingFieldsCaught(t *testing.T) {
	t.Run("scenario_missing_id", func(t *testing.T) {
		data := []byte(`{
			"title": "No ID",
			"task": {"narrative": "n"},
			"declarations": {"strong": {"allowed_actions": ["read"], "allowed_tools": ["t"]}},
			"environment": {"available_tools": ["t"]},
			"ground_truth": {"label": "compliant"},
			"metrics_focus": ["x"]
		}`)
		errs := validateScenario("test.json", data, false)
		if !containsSubstring(errs, "missing required field: id") {
			t.Fatalf("expected missing id error, got: %v", errs)
		}
	})

	t.Run("scenario_missing_multiple", func(t *testing.T) {
		data := []byte(`{"title": "Bare minimum"}`)
		errs := validateScenario("test.json", data, false)
		wantFields := []string{"id", "task.narrative", "declarations.strong.allowed_actions",
			"declarations.strong.allowed_tools", "environment.available_tools",
			"ground_truth.label", "baseline_expectations", "metrics_focus"}
		for _, f := range wantFields {
			if !containsSubstring(errs, f) {
				t.Errorf("expected error mentioning %q, got: %v", f, errs)
			}
		}
	})

	t.Run("event_missing_event_id", func(t *testing.T) {
		data := []byte(`{
			"timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "read", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "full", "expected_label": "compliant"
		}`)
		errs := validateEvent("test.jsonl", 1, data, false)
		if !containsSubstring(errs, "event_id") {
			t.Fatalf("expected missing event_id error, got: %v", errs)
		}
	})
}

func TestInvalidEnumsCaught(t *testing.T) {
	t.Run("invalid_action_class", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "hack", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "full", "expected_label": "compliant"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "invalid action_class") {
			t.Fatalf("expected invalid action_class error, got: %v", errs)
		}
	})

	t.Run("invalid_side_effect_class", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "read", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "nuclear",
			"visibility": "full", "expected_label": "compliant"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "invalid side_effect_class") {
			t.Fatalf("expected invalid side_effect_class error, got: %v", errs)
		}
	})

	t.Run("invalid_visibility", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "read", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "invisible", "expected_label": "compliant"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "invalid visibility") {
			t.Fatalf("expected invalid visibility error, got: %v", errs)
		}
	})

	t.Run("invalid_expected_label", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "read", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "full", "expected_label": "maybe"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "invalid expected_label") {
			t.Fatalf("expected invalid expected_label error, got: %v", errs)
		}
	})

	t.Run("invalid_ground_truth_label", func(t *testing.T) {
		data := []byte(`{
			"id": "T1", "title": "T",
			"task": {"narrative": "n"},
			"declarations": {"strong": {"allowed_actions": ["read"], "allowed_tools": ["t"]}},
			"environment": {"available_tools": ["t"]},
			"ground_truth": {"label": "maybe_bad"},
			"baseline_expectations": {},
			"metrics_focus": ["x"]
		}`)
		errs := validateScenario("test.json", data, false)
		if !containsSubstring(errs, "invalid ground_truth.label") {
			t.Fatalf("expected invalid ground_truth.label error, got: %v", errs)
		}
	})

	t.Run("bad_timestamp", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "not-a-date",
			"session_id": "s", "actor": "a",
			"action_class": "read", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "full", "expected_label": "compliant"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "invalid RFC3339 timestamp") {
			t.Fatalf("expected timestamp error, got: %v", errs)
		}
	})

	t.Run("confidence_out_of_range", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "read", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "full", "expected_label": "compliant",
			"confidence_hint": 1.5
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "confidence_hint out of range") {
			t.Fatalf("expected confidence range error, got: %v", errs)
		}
	})

	t.Run("delegate_missing_linkage", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "delegate", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "full", "expected_label": "compliant"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "delegation_from") {
			t.Fatalf("expected delegation linkage error, got: %v", errs)
		}
	})

	t.Run("partial_delegate_missing_linkage_allowed", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "delegate", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "none",
			"visibility": "partial", "expected_label": "unknown"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if containsSubstring(errs, "delegation_from") {
			t.Fatalf("did not expect linkage error for partial delegate, got: %v", errs)
		}
	})

	t.Run("full_write_missing_content_class", func(t *testing.T) {
		data := []byte(`{
			"event_id": "E1", "timestamp": "2026-03-10T10:00:00Z",
			"session_id": "s", "actor": "a",
			"action_class": "write", "tool_name": "t",
			"target": "r", "summary": "s",
			"side_effect_class": "internal_write",
			"visibility": "full", "expected_label": "compliant"
		}`)
		errs := validateEvent("test.jsonl", 1, data, true)
		if !containsSubstring(errs, "missing content_class") {
			t.Fatalf("expected content_class error, got: %v", errs)
		}
	})
}

func TestStrictScenarioValidationCatchesTypedDeclarationErrors(t *testing.T) {
	data := []byte(`{
		"id": "A99",
		"title": "Delegate without policy",
		"task": {"narrative": "n"},
		"declarations": {
			"strong": {
				"allowed_actions": ["delegate"],
				"allowed_tools": ["delegator"]
			}
		},
		"environment": {"available_tools": ["delegator"]},
		"ground_truth": {"label": "delegation_violation"},
		"baseline_expectations": {},
		"metrics_focus": ["x"]
	}`)
	errs := validateScenario("test.json", data, true)
	if !containsSubstring(errs, "missing delegation_policy") {
		t.Fatalf("expected strict validation to catch missing delegation_policy, got: %v", errs)
	}
}

func TestStrictEventValidationRejectsUnknownFields(t *testing.T) {
	data := []byte(`{
		"event_id": "E1",
		"timestamp": "2026-03-10T10:00:00Z",
		"session_id": "s",
		"actor": "a",
		"action_class": "read",
		"tool_name": "t",
		"target": "r",
		"summary": "s",
		"side_effect_class": "none",
		"visibility": "full",
		"expected_label": "compliant",
		"extra": true
	}`)
	errs := validateEvent("test.jsonl", 1, data, true)
	if !containsSubstring(errs, "strict schema decode failed") {
		t.Fatalf("expected strict validation to reject unknown fields, got: %v", errs)
	}
}

func TestRunOnPackV03(t *testing.T) {
	packDir := filepath.Join("..", "..", "benchmark", "scenarios", "pack-v0.3")
	if _, err := os.Stat(packDir); os.IsNotExist(err) {
		t.Skipf("pack-v0.3 not found at %s", packDir)
	}
	errs := run(packDir, true)
	if len(errs) > 0 {
		for _, e := range errs {
			t.Error(e)
		}
		t.Fatalf("pack-v0.3 strict validation failed with %d errors", len(errs))
	}
}

func containsSubstring(items []string, substr string) bool {
	for _, item := range items {
		if strings.Contains(item, substr) {
			return true
		}
	}
	return false
}

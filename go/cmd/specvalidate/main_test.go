package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func specDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "spec", "mission-governance", "v0alpha1"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("cannot locate spec/mission-governance/v0alpha1 directory")
	return ""
}

func loadTestSchema(t *testing.T, name string) *Schema {
	t.Helper()
	dir := specDir(t)
	s, err := loadSchema(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("loading schema %s: %v", name, err)
	}
	return s
}

func loadTestDoc(t *testing.T, name string) interface{} {
	t.Helper()
	dir := specDir(t)
	doc, err := loadDocument(filepath.Join(dir, "examples", name))
	if err != nil {
		t.Fatalf("loading document %s: %v", name, err)
	}
	return doc
}

func validatorFor(t *testing.T, schemaName string) *Validator {
	t.Helper()
	dir := specDir(t)
	s := loadTestSchema(t, schemaName)
	return NewValidator(s, dir)
}

func TestDeclarationExamplesValid(t *testing.T) {
	v := validatorFor(t, "declaration.schema.json")
	for _, name := range []string{
		"declaration-code-review.json",
		"declaration-data-analysis.json",
	} {
		t.Run(name, func(t *testing.T) {
			doc := loadTestDoc(t, name)
			errs := v.Validate(doc)
			if len(errs) > 0 {
				for _, e := range errs {
					t.Errorf("  %s", e)
				}
			}
		})
	}
}

func TestEventExamplesValid(t *testing.T) {
	v := validatorFor(t, "event.schema.json")
	for _, name := range []string{
		"event-compliant-read.json",
		"event-violation-exfiltration.json",
		"event-partial-visibility.json",
	} {
		t.Run(name, func(t *testing.T) {
			doc := loadTestDoc(t, name)
			errs := v.Validate(doc)
			if len(errs) > 0 {
				for _, e := range errs {
					t.Errorf("  %s", e)
				}
			}
		})
	}
}

func TestDecisionExamplesValid(t *testing.T) {
	v := validatorFor(t, "decision.schema.json")
	for _, name := range []string{
		"decision-compliant.json",
		"decision-violation.json",
		"decision-unknown.json",
	} {
		t.Run(name, func(t *testing.T) {
			doc := loadTestDoc(t, name)
			errs := v.Validate(doc)
			if len(errs) > 0 {
				for _, e := range errs {
					t.Errorf("  %s", e)
				}
			}
		})
	}
}

func TestSessionExampleValid(t *testing.T) {
	v := validatorFor(t, "session.schema.json")
	doc := loadTestDoc(t, "session-active.json")
	errs := v.Validate(doc)
	if len(errs) > 0 {
		for _, e := range errs {
			t.Errorf("  %s", e)
		}
	}
}

func parseJSON(t *testing.T, s string) interface{} {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("parseJSON: %v", err)
	}
	return v
}

func TestDeclarationMissingRequired(t *testing.T) {
	v := validatorFor(t, "declaration.schema.json")
	doc := parseJSON(t, `{"id": "x"}`)
	errs := v.Validate(doc)
	if len(errs) == 0 {
		t.Fatal("expected validation errors for missing required fields")
	}

	missing := map[string]bool{
		"session_id":      false,
		"allowed_actions": false,
		"allowed_tools":   false,
		"created_at":      false,
	}
	for _, e := range errs {
		for field := range missing {
			if strings.Contains(e.Path, field) && strings.Contains(e.Message, "required") {
				missing[field] = true
			}
		}
	}
	for field, found := range missing {
		if !found {
			t.Errorf("expected missing-required error for %s", field)
		}
	}
}

func TestEventInvalidEnum(t *testing.T) {
	v := validatorFor(t, "event.schema.json")
	doc := parseJSON(t, `{
		"event_id": "e1",
		"session_id": "s1",
		"timestamp": "2026-03-10T09:00:00Z",
		"actor": "agent:test",
		"action_class": "INVALID_ACTION",
		"tool_name": "some_tool",
		"target": "some_target",
		"summary": "test summary",
		"side_effect_class": "none",
		"visibility": "full"
	}`)
	errs := v.Validate(doc)
	if len(errs) == 0 {
		t.Fatal("expected validation error for invalid action_class enum")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "action_class") && strings.Contains(e.Message, "enum") {
			found = true
		}
	}
	if !found {
		t.Error("expected enum violation for action_class")
	}
}

func TestEventInvalidSideEffectEnum(t *testing.T) {
	v := validatorFor(t, "event.schema.json")
	doc := parseJSON(t, `{
		"event_id": "e1",
		"session_id": "s1",
		"timestamp": "2026-03-10T09:00:00Z",
		"actor": "agent:test",
		"action_class": "read",
		"tool_name": "some_tool",
		"target": "some_target",
		"summary": "test",
		"side_effect_class": "explode",
		"visibility": "full"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "side_effect_class") && strings.Contains(e.Message, "enum") {
			found = true
		}
	}
	if !found {
		t.Error("expected enum violation for side_effect_class")
	}
}

func TestDecisionInvalidState(t *testing.T) {
	v := validatorFor(t, "decision.schema.json")
	doc := parseJSON(t, `{
		"session_id": "s1",
		"state": "maybe",
		"recommended_action": "none",
		"events_processed": 0,
		"reconciliation_time": "2026-03-10T09:00:00Z"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "state") && strings.Contains(e.Message, "enum") {
			found = true
		}
	}
	if !found {
		t.Error("expected enum violation for decision state")
	}
}

func TestFindingInvalidCodePattern(t *testing.T) {
	dir := specDir(t)
	s := loadTestSchema(t, "finding.schema.json")
	v := NewValidator(s, dir)
	doc := parseJSON(t, `{
		"code": "lowercase-invalid",
		"message": "this has a bad code"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "code") && strings.Contains(e.Message, "pattern") {
			found = true
		}
	}
	if !found {
		t.Error("expected pattern violation for finding code")
	}
}

func TestSessionInvalidPhase(t *testing.T) {
	v := validatorFor(t, "session.schema.json")
	doc := parseJSON(t, `{
		"id": "s1",
		"phase": "exploding",
		"created_at": "2026-03-10T09:00:00Z",
		"updated_at": "2026-03-10T09:00:00Z"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "phase") && strings.Contains(e.Message, "enum") {
			found = true
		}
	}
	if !found {
		t.Error("expected enum violation for session phase")
	}
}

func TestEventConfidenceOutOfRange(t *testing.T) {
	v := validatorFor(t, "event.schema.json")
	doc := parseJSON(t, `{
		"event_id": "e1",
		"session_id": "s1",
		"timestamp": "2026-03-10T09:00:00Z",
		"actor": "agent:test",
		"action_class": "read",
		"tool_name": "some_tool",
		"target": "some_target",
		"summary": "test",
		"side_effect_class": "none",
		"visibility": "full",
		"confidence_hint": 1.5
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "confidence_hint") && strings.Contains(e.Message, "greater than maximum") {
			found = true
		}
	}
	if !found {
		t.Error("expected maximum violation for confidence_hint > 1.0")
	}
}

func TestDeclarationNegativeDelegation(t *testing.T) {
	v := validatorFor(t, "declaration.schema.json")
	doc := parseJSON(t, `{
		"id": "d1",
		"session_id": "s1",
		"allowed_actions": ["read"],
		"allowed_tools": ["read_file"],
		"delegation_policy": {
			"max_depth": -1
		},
		"created_at": "2026-03-10T09:00:00Z"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "max_depth") && strings.Contains(e.Message, "less than minimum") {
			found = true
		}
	}
	if !found {
		t.Error("expected minimum violation for negative max_depth")
	}
}

func TestDeclarationEmptyID(t *testing.T) {
	v := validatorFor(t, "declaration.schema.json")
	doc := parseJSON(t, `{
		"id": "",
		"session_id": "s1",
		"allowed_actions": ["read"],
		"allowed_tools": ["read_file"],
		"created_at": "2026-03-10T09:00:00Z"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "id") && strings.Contains(e.Message, "minLength") || strings.Contains(e.Message, "less than minimum") {
			found = true
		}
	}
	if !found {
		t.Error("expected minLength violation for empty id")
	}
}

func TestDeclarationInvalidDatetime(t *testing.T) {
	v := validatorFor(t, "declaration.schema.json")
	doc := parseJSON(t, `{
		"id": "d1",
		"session_id": "s1",
		"allowed_actions": ["read"],
		"allowed_tools": ["read_file"],
		"created_at": "not-a-date"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "created_at") && strings.Contains(e.Message, "date-time") {
			found = true
		}
	}
	if !found {
		t.Error("expected date-time format violation for created_at")
	}
}

func TestDeclarationEmptyActionsArray(t *testing.T) {
	v := validatorFor(t, "declaration.schema.json")
	doc := parseJSON(t, `{
		"id": "d1",
		"session_id": "s1",
		"allowed_actions": [],
		"allowed_tools": ["read_file"],
		"created_at": "2026-03-10T09:00:00Z"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "allowed_actions") && strings.Contains(e.Message, "minimum") {
			found = true
		}
	}
	if !found {
		t.Error("expected minItems violation for empty allowed_actions")
	}
}

func TestDecisionFindingsRefValidation(t *testing.T) {
	v := validatorFor(t, "decision.schema.json")
	doc := parseJSON(t, `{
		"session_id": "s1",
		"state": "violation",
		"findings": [
			{
				"code": "bad code",
				"message": "test"
			}
		],
		"recommended_action": "alert",
		"events_processed": 1,
		"reconciliation_time": "2026-03-10T09:00:00Z"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "pattern") {
			found = true
		}
	}
	if !found {
		t.Error("expected pattern violation for finding code within decision findings array")
	}
}

func TestAllMode(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	vibapDir := filepath.Join(origDir, "..", "..")
	if err := os.Chdir(vibapDir); err != nil {
		t.Fatalf("chdir to VIBAP root: %v", err)
	}
	defer os.Chdir(origDir)

	code := runAll()
	if code != 0 {
		t.Fatalf("runAll() returned exit code %d, expected 0", code)
	}
}

func TestFindingSeverityEnum(t *testing.T) {
	dir := specDir(t)
	s := loadTestSchema(t, "finding.schema.json")
	v := NewValidator(s, dir)
	doc := parseJSON(t, `{
		"code": "TEST_CODE",
		"message": "test message",
		"severity": "extreme"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "severity") && strings.Contains(e.Message, "enum") {
			found = true
		}
	}
	if !found {
		t.Error("expected enum violation for invalid severity value")
	}
}

func TestEventWrongTypeForTimestamp(t *testing.T) {
	v := validatorFor(t, "event.schema.json")
	doc := parseJSON(t, `{
		"event_id": "e1",
		"session_id": "s1",
		"timestamp": 12345,
		"actor": "agent:test",
		"action_class": "read",
		"tool_name": "some_tool",
		"target": "some_target",
		"summary": "test",
		"side_effect_class": "none",
		"visibility": "full"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "timestamp") && strings.Contains(e.Message, "expected string") {
			found = true
		}
	}
	if !found {
		t.Error("expected type violation for numeric timestamp")
	}
}

func TestDecisionNegativeEventsProcessed(t *testing.T) {
	v := validatorFor(t, "decision.schema.json")
	doc := parseJSON(t, `{
		"session_id": "s1",
		"state": "compliant",
		"recommended_action": "none",
		"events_processed": -1,
		"reconciliation_time": "2026-03-10T09:00:00Z"
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "events_processed") && strings.Contains(e.Message, "less than minimum") {
			found = true
		}
	}
	if !found {
		t.Error("expected minimum violation for negative events_processed")
	}
}

func TestAdditionalPropertiesFalseRejected(t *testing.T) {
	v := validatorFor(t, "declaration.schema.json")
	doc := parseJSON(t, `{
		"id": "d1",
		"session_id": "s1",
		"allowed_actions": ["read"],
		"allowed_tools": ["reader"],
		"created_at": "2026-03-10T09:00:00Z",
		"unexpected_field": true
	}`)
	errs := v.Validate(doc)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Path, "unexpected_field") && strings.Contains(e.Message, "not allowed") {
			found = true
		}
	}
	if !found {
		t.Error("expected additionalProperties=false to reject unexpected_field")
	}
}

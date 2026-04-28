// Command benchcheck validates benchmark scenario and trace files for the
// VIBAP behavioral governance benchmark corpus.
//
// Usage:
//
//	benchcheck [--strict] [--pack PACKNAME] DIR
//
// Without --pack the tool scans DIR recursively. With --pack it scans
// DIR/PACKNAME only. Errors are reported as file:line: description.
// Exit 0 if clean, 1 if errors, 2 on usage error.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	benchmarkpkg "github.com/gnanirahulnutakki/ardur/go/benchmark"
)

var groundTruthLabels = map[string]bool{
	"compliant":               true,
	"undeclared_resource_use": true,
	"scope_expansion":         true,
	"exfiltration":            true,
	"delegation_violation":    true,
	"unknown":                 true,
}

var actionClasses = map[string]bool{
	"search": true, "read": true, "write": true, "query": true,
	"delegate": true, "send": true, "summarize": true, "observe": true,
}

var sideEffectClasses = map[string]bool{
	"none": true, "internal_write": true, "external_send": true, "state_change": true,
}

var visibilities = map[string]bool{
	"full": true, "partial": true, "missing": true,
}

var expectedLabels = map[string]bool{
	"compliant": true, "suspicious": true, "violation": true, "unknown": true,
}

var scenarioIDPattern = regexp.MustCompile(`^[A-Z][0-9]+$`)

type scenario struct {
	ID                   string          `json:"id"`
	Title                string          `json:"title"`
	Task                 taskSpec        `json:"task"`
	Declarations         declarations    `json:"declarations"`
	Environment          environment     `json:"environment"`
	GroundTruth          groundTruth     `json:"ground_truth"`
	BaselineExpectations json.RawMessage `json:"baseline_expectations"`
	MetricsFocus         []string        `json:"metrics_focus"`
}

type taskSpec struct {
	Narrative string `json:"narrative"`
}

type declarations struct {
	Strong declaration  `json:"strong"`
	Weak   *declaration `json:"weak,omitempty"`
}

type declaration struct {
	AllowedActions []string `json:"allowed_actions"`
	AllowedTools   []string `json:"allowed_tools"`
}

type environment struct {
	AvailableTools []string `json:"available_tools"`
}

type groundTruth struct {
	Label string `json:"label"`
}

type event struct {
	EventID         string   `json:"event_id"`
	Timestamp       string   `json:"timestamp"`
	SessionID       string   `json:"session_id"`
	Actor           string   `json:"actor"`
	ActionClass     string   `json:"action_class"`
	ToolName        string   `json:"tool_name"`
	Target          string   `json:"target"`
	Summary         string   `json:"summary"`
	SideEffectClass string   `json:"side_effect_class"`
	Visibility      string   `json:"visibility"`
	ExpectedLabel   string   `json:"expected_label"`
	ContentClass    string   `json:"content_class"`
	ConfidenceHint  *float64 `json:"confidence_hint"`
	DelegationFrom  string   `json:"delegation_from"`
	DelegationTo    string   `json:"delegation_to"`
}

func validateScenario(path string, data []byte, strict bool) []string {
	var s scenario
	if err := json.Unmarshal(data, &s); err != nil {
		return []string{fmt.Sprintf("%s:1: invalid JSON: %v", path, err)}
	}

	var errs []string
	add := func(msg string) { errs = append(errs, fmt.Sprintf("%s:1: %s", path, msg)) }

	if strings.TrimSpace(s.ID) == "" {
		add("missing required field: id")
	}
	if strings.TrimSpace(s.Title) == "" {
		add("missing required field: title")
	}
	if strings.TrimSpace(s.Task.Narrative) == "" {
		add("missing required field: task.narrative")
	}
	if len(s.Declarations.Strong.AllowedActions) == 0 {
		add("missing required field: declarations.strong.allowed_actions")
	}
	if len(s.Declarations.Strong.AllowedTools) == 0 {
		add("missing required field: declarations.strong.allowed_tools")
	}
	if len(s.Environment.AvailableTools) == 0 {
		add("missing required field: environment.available_tools")
	}
	if strings.TrimSpace(s.GroundTruth.Label) == "" {
		add("missing required field: ground_truth.label")
	}
	if len(s.BaselineExpectations) == 0 {
		add("missing required field: baseline_expectations")
	}
	if len(s.MetricsFocus) == 0 {
		add("missing required field: metrics_focus")
	}
	if s.GroundTruth.Label != "" && !groundTruthLabels[s.GroundTruth.Label] {
		add(fmt.Sprintf("invalid ground_truth.label enum value: %q", s.GroundTruth.Label))
	}

	if !strict {
		return errs
	}

	if s.ID != "" && !scenarioIDPattern.MatchString(s.ID) {
		add(fmt.Sprintf("invalid id pattern: %q", s.ID))
	}

	strictData := stripTopLevelJSONKeys(data, "$schema")
	var canonical benchmarkpkg.Scenario
	if err := decodeStrictJSON(strictData, &canonical); err != nil {
		add(fmt.Sprintf("strict schema decode failed: %v", err))
		return errs
	}
	if err := canonical.Validate(); err != nil {
		add(err.Error())
	}

	return errs
}

func validateEvent(path string, lineNo int, data []byte, strict bool) []string {
	var e event
	if err := json.Unmarshal(data, &e); err != nil {
		return []string{fmt.Sprintf("%s:%d: invalid JSON: %v", path, lineNo, err)}
	}

	var errs []string
	add := func(msg string) { errs = append(errs, fmt.Sprintf("%s:%d: %s", path, lineNo, msg)) }

	requiredStr := map[string]string{
		"event_id":          e.EventID,
		"timestamp":         e.Timestamp,
		"session_id":        e.SessionID,
		"actor":             e.Actor,
		"action_class":      e.ActionClass,
		"tool_name":         e.ToolName,
		"target":            e.Target,
		"summary":           e.Summary,
		"side_effect_class": e.SideEffectClass,
		"visibility":        e.Visibility,
		"expected_label":    e.ExpectedLabel,
	}
	for field, value := range requiredStr {
		if strings.TrimSpace(value) == "" {
			add(fmt.Sprintf("missing required field: %s", field))
		}
	}

	if !strict {
		return errs
	}

	var canonical benchmarkpkg.Event
	if err := decodeStrictJSON(data, &canonical); err != nil {
		add(fmt.Sprintf("strict schema decode failed: %v", err))
		return errs
	}
	if err := canonical.Validate(); err != nil {
		add(err.Error())
	}

	if e.ActionClass != "" && !actionClasses[e.ActionClass] {
		add(fmt.Sprintf("invalid action_class enum value: %q", e.ActionClass))
	}
	if e.SideEffectClass != "" && !sideEffectClasses[e.SideEffectClass] {
		add(fmt.Sprintf("invalid side_effect_class enum value: %q", e.SideEffectClass))
	}
	if e.Visibility != "" && !visibilities[e.Visibility] {
		add(fmt.Sprintf("invalid visibility enum value: %q", e.Visibility))
	}
	if e.ExpectedLabel != "" && !expectedLabels[e.ExpectedLabel] {
		add(fmt.Sprintf("invalid expected_label enum value: %q", e.ExpectedLabel))
	}
	if e.Timestamp != "" {
		if _, err := time.Parse(time.RFC3339, e.Timestamp); err != nil {
			add(fmt.Sprintf("invalid RFC3339 timestamp: %q", e.Timestamp))
		}
	}
	if e.ConfidenceHint != nil && (*e.ConfidenceHint < 0 || *e.ConfidenceHint > 1) {
		add(fmt.Sprintf("confidence_hint out of range [0,1]: %v", *e.ConfidenceHint))
	}
	if strings.EqualFold(e.ActionClass, "delegate") && strings.EqualFold(e.Visibility, "full") {
		if strings.TrimSpace(e.DelegationFrom) == "" || strings.TrimSpace(e.DelegationTo) == "" {
			add("delegate event missing delegation_from and/or delegation_to")
		}
	}
	if strings.EqualFold(e.Visibility, "full") {
		sec := strings.ToLower(e.SideEffectClass)
		if (sec == "external_send" || sec == "internal_write") && strings.TrimSpace(e.ContentClass) == "" {
			add("full-visibility write/send event missing content_class")
		}
	}

	return errs
}

func run(dir string, strict bool) []string {
	var allErrs []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			allErrs = append(allErrs, fmt.Sprintf("%s:0: %v", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}

		name := d.Name()
		if strings.HasSuffix(name, ".json") && !strings.Contains(name, ".schema.") {
			data, readErr := os.ReadFile(filepath.Clean(path))
			if readErr != nil {
				allErrs = append(allErrs, fmt.Sprintf("%s:0: %v", path, readErr))
				return nil
			}
			allErrs = append(allErrs, validateScenario(path, data, strict)...)
		}

		if strings.HasSuffix(name, ".jsonl") {
			f, openErr := os.Open(filepath.Clean(path))
			if openErr != nil {
				allErrs = append(allErrs, fmt.Sprintf("%s:0: %v", path, openErr))
				return nil
			}
			scanner := bufio.NewScanner(f)
			lineNo := 0
			for scanner.Scan() {
				lineNo++
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				allErrs = append(allErrs, validateEvent(path, lineNo, []byte(line), strict)...)
			}
			if scanErr := scanner.Err(); scanErr != nil {
				allErrs = append(allErrs, fmt.Sprintf("%s:0: scan error: %v", path, scanErr))
			}
			_ = f.Close()
		}
		return nil
	})
	if err != nil {
		allErrs = append(allErrs, fmt.Sprintf("%s:0: walk error: %v", dir, err))
	}
	return allErrs
}

func decodeStrictJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing JSON content")
	}
	return nil
}

func stripTopLevelJSONKeys(data []byte, keys ...string) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return data
	}
	for _, key := range keys {
		delete(obj, key)
	}
	normalized, err := json.Marshal(obj)
	if err != nil {
		return data
	}
	return normalized
}

func main() {
	strict := flag.Bool("strict", false, "enable strict enum and format validation")
	pack := flag.String("pack", "", "limit to a specific pack directory name")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: benchcheck [--strict] [--pack PACKNAME] DIR\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	dir := args[0]
	if *pack != "" {
		dir = filepath.Join(dir, *pack)
	}

	errs := run(dir, *strict)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, e)
		}
		os.Exit(1)
	}
}

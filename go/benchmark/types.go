package benchmark

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scenario is the public scenario shape accepted by benchcheck. It is intentionally
// small; corpus-specific benchmark fixtures stay outside the public repo.
type Scenario struct {
	ID           string       `json:"id"`
	Title        string       `json:"title"`
	Task         Task         `json:"task"`
	Declarations Declarations `json:"declarations"`
	Environment  Environment  `json:"environment"`
	GroundTruth  GroundTruth  `json:"ground_truth"`
	MetricsFocus []string     `json:"metrics_focus"`
}

type Task struct {
	Narrative string `json:"narrative"`
}

type Declarations struct {
	Strong Declaration  `json:"strong"`
	Weak   *Declaration `json:"weak,omitempty"`
}

type Declaration struct {
	AllowedActions   []string           `json:"allowed_actions"`
	AllowedTools     []string           `json:"allowed_tools"`
	DelegationPolicy *DelegationPolicy  `json:"delegation_policy,omitempty"`
	ResourceScope    []string           `json:"resource_scope,omitempty"`
	SideEffects      []string           `json:"side_effects,omitempty"`
	Budgets          map[string]float64 `json:"budgets,omitempty"`
}

type DelegationPolicy struct {
	Allowed  bool `json:"allowed"`
	MaxDepth int  `json:"max_depth,omitempty"`
	MaxWidth int  `json:"max_width,omitempty"`
}

type Environment struct {
	AvailableTools []string `json:"available_tools"`
}

type GroundTruth struct {
	Label string `json:"label"`
}

// Event is the public trace event shape accepted by benchcheck.
type Event struct {
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
	ContentClass    string   `json:"content_class,omitempty"`
	ConfidenceHint  *float64 `json:"confidence_hint,omitempty"`
	DelegationFrom  string   `json:"delegation_from,omitempty"`
	DelegationTo    string   `json:"delegation_to,omitempty"`
	ParentEventID   string   `json:"parent_event_id,omitempty"`
}

func (s Scenario) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("missing id")
	}
	if strings.TrimSpace(s.Title) == "" {
		return errors.New("missing title")
	}
	if strings.TrimSpace(s.Task.Narrative) == "" {
		return errors.New("missing task.narrative")
	}
	if len(s.Declarations.Strong.AllowedActions) == 0 {
		return errors.New("missing declarations.strong.allowed_actions")
	}
	if len(s.Declarations.Strong.AllowedTools) == 0 {
		return errors.New("missing declarations.strong.allowed_tools")
	}
	if declarationAllows(s.Declarations.Strong.AllowedActions, "delegate") && s.Declarations.Strong.DelegationPolicy == nil {
		return errors.New("missing delegation_policy for delegate action")
	}
	if len(s.Environment.AvailableTools) == 0 {
		return errors.New("missing environment.available_tools")
	}
	if strings.TrimSpace(s.GroundTruth.Label) == "" {
		return errors.New("missing ground_truth.label")
	}
	if len(s.MetricsFocus) == 0 {
		return errors.New("missing metrics_focus")
	}
	return nil
}

func (e Event) Validate() error {
	required := map[string]string{
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
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing %s", field)
		}
	}
	if _, err := time.Parse(time.RFC3339, e.Timestamp); err != nil {
		return fmt.Errorf("invalid RFC3339 timestamp: %w", err)
	}
	if e.ConfidenceHint != nil && (*e.ConfidenceHint < 0 || *e.ConfidenceHint > 1) {
		return errors.New("confidence_hint out of range")
	}
	if e.ActionClass == "delegate" && e.Visibility == "full" {
		if strings.TrimSpace(e.DelegationFrom) == "" || strings.TrimSpace(e.DelegationTo) == "" {
			return errors.New("missing delegation_from or delegation_to for full-visibility delegate event")
		}
	}
	if e.ActionClass == "write" && e.Visibility == "full" && e.SideEffectClass != "none" && strings.TrimSpace(e.ContentClass) == "" {
		return errors.New("missing content_class for full-visibility write event")
	}
	return nil
}

func declarationAllows(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}

type Report struct {
	PackDir              string `json:"pack_dir"`
	ScenarioCount        int    `json:"scenario_count"`
	TraceCount           int    `json:"trace_count"`
	AuthorizationHit     int    `json:"authorization_correct"`
	PolicyHit            int    `json:"policy_correct"`
	ReconcileHit         int    `json:"reconciliation_correct"`
	UncheckedEventMode   bool   `json:"unchecked_event_mode,omitempty"`
	NoPublicCorpusNotice string `json:"no_public_corpus_notice,omitempty"`
}

func RunPack(packDir string) (*Report, error) {
	return runPack(packDir, false)
}

func RunPackUncheckedEvents(packDir string) (*Report, error) {
	return runPack(packDir, true)
}

func runPack(packDir string, uncheckedEvents bool) (*Report, error) {
	info, err := os.Stat(packDir)
	if err != nil {
		return nil, fmt.Errorf("stat benchmark pack: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("benchmark pack is not a directory: %s", packDir)
	}
	report := &Report{
		PackDir:              packDir,
		UncheckedEventMode:   uncheckedEvents,
		NoPublicCorpusNotice: "public benchmark corpus is not bundled in this repository",
	}
	if err := filepath.WalkDir(packDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".scenario.json"):
			report.ScenarioCount++
		case strings.HasSuffix(path, ".events.jsonl"):
			report.TraceCount++
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return report, nil
}

func WriteReport(report *Report, outDir string) error {
	if report == nil {
		return errors.New("nil report")
	}
	if err := os.MkdirAll(outDir, 0750); err != nil {
		return err
	}
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "results.json"), jsonData, 0600); err != nil {
		return err
	}
	csvFile, err := os.Create(filepath.Join(outDir, "summary.csv"))
	if err != nil {
		return err
	}
	defer csvFile.Close()
	w := csv.NewWriter(csvFile)
	if err := w.Write([]string{"pack_dir", "scenarios", "traces", "authorization_correct", "policy_correct", "reconciliation_correct"}); err != nil {
		return err
	}
	if err := w.Write([]string{
		report.PackDir,
		fmt.Sprint(report.ScenarioCount),
		fmt.Sprint(report.TraceCount),
		fmt.Sprint(report.AuthorizationHit),
		fmt.Sprint(report.PolicyHit),
		fmt.Sprint(report.ReconcileHit),
	}); err != nil {
		return err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	summary := fmt.Sprintf("# Benchmark Summary\n\nPack: `%s`\n\nScenarios: %d\n\nTraces: %d\n\n%s\n",
		report.PackDir,
		report.ScenarioCount,
		report.TraceCount,
		report.NoPublicCorpusNotice,
	)
	return os.WriteFile(filepath.Join(outDir, "summary.md"), []byte(summary), 0600)
}

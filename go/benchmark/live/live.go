package live

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type TraceResult struct {
	Verdict       string `json:"verdict"`
	FindingsCount int    `json:"findings_count"`
}

type BenchmarkResult struct {
	Source      string      `json:"source"`
	ScenarioID  string      `json:"scenario_id"`
	GroundTruth string      `json:"ground_truth"`
	Arm1        TraceResult `json:"cedar_strict"`
	Arm2        TraceResult `json:"cedar_state"`
	Arm3        TraceResult `json:"visibility"`
	Arm4        TraceResult `json:"mcep_reconciliation"`
}

func EvaluateAllStrict(missionPath, eventsPath string) (BenchmarkResult, error) {
	if _, err := os.Stat(eventsPath); err != nil {
		return BenchmarkResult{}, fmt.Errorf("stat events file: %w", err)
	}
	data, err := os.ReadFile(missionPath)
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("read mission file: %w", err)
	}
	var mission struct {
		ID          string `json:"id"`
		GroundTruth struct {
			Label string `json:"label"`
		} `json:"ground_truth"`
	}
	_ = json.Unmarshal(data, &mission)
	scenarioID := strings.TrimSpace(mission.ID)
	if scenarioID == "" {
		scenarioID = strings.TrimSuffix(filepath.Base(missionPath), ".mission.json")
	}
	groundTruth := strings.TrimSpace(mission.GroundTruth.Label)
	if groundTruth == "" {
		groundTruth = "unknown"
	}
	result := TraceResult{Verdict: "unknown"}
	return BenchmarkResult{
		Source:      filepath.Base(filepath.Dir(missionPath)),
		ScenarioID:  scenarioID,
		GroundTruth: groundTruth,
		Arm1:        result,
		Arm2:        result,
		Arm3:        result,
		Arm4:        result,
	}, nil
}

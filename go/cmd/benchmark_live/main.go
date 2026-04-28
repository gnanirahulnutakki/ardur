package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gnanirahulnutakki/ardur/go/benchmark/live"
)

func main() {
	var tracesDirs multiFlag
	flag.Var(&tracesDirs, "traces-dir", "Directory containing .mission.json + .events.jsonl pairs; repeat or comma-separate for multiple sources")
	outputFile := flag.String("output", "results.json", "Output file for detailed results")
	flag.Parse()

	if len(tracesDirs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: benchmark_live --traces-dir /path/to/traces")
		os.Exit(1)
	}

	var results []live.BenchmarkResult

	fmt.Printf("%-22s %-32s %-12s %-14s %-14s %-14s %-14s\n", "Source", "Scenario", "GroundTruth", "Cedar-Strict", "Cedar-State", "Visibility", "MCEP-Recon")
	fmt.Println(strings.Repeat("-", 128))

	for _, tracesDir := range tracesDirs {
		dirResults, err := evaluateDir(tracesDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, result := range dirResults {
			results = append(results, result)
			fmt.Printf("%-22s %-32s %-12s %-14s %-14s %-14s %-14s\n",
				result.Source,
				result.ScenarioID,
				result.GroundTruth,
				fmtVerdict(result.Arm1),
				fmtVerdict(result.Arm2),
				fmtVerdict(result.Arm3),
				fmtVerdict(result.Arm4),
			)
		}
	}

	fmt.Println(strings.Repeat("-", 128))
	fmt.Printf("Total scenarios: %d\n", len(results))
	printCoverageSummary(results)
	printSplitCoverageSummary(results)

	// Write detailed results
	out, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling results: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outputFile, out, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outputFile, err)
		os.Exit(1)
	}
	fmt.Printf("Results written to %s\n", *outputFile)
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			*m = append(*m, trimmed)
		}
	}
	return nil
}

func evaluateDir(tracesDir string) ([]live.BenchmarkResult, error) {
	missions, err := filepath.Glob(filepath.Join(tracesDir, "*.mission.json"))
	if err != nil {
		return nil, fmt.Errorf("error scanning traces dir %s: %w", tracesDir, err)
	}
	sort.Strings(missions)
	if len(missions) == 0 {
		return nil, fmt.Errorf("no .mission.json files found in %s", tracesDir)
	}

	results := make([]live.BenchmarkResult, 0, len(missions))
	for _, missionPath := range missions {
		base := strings.TrimSuffix(filepath.Base(missionPath), ".mission.json")
		eventsPath := filepath.Join(tracesDir, base+".events.jsonl")
		if _, err := os.Stat(eventsPath); os.IsNotExist(err) {
			continue
		}
		result, err := live.EvaluateAllStrict(missionPath, eventsPath)
		if err != nil {
			return nil, fmt.Errorf("error evaluating %s: %w", missionPath, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func printCoverageSummary(results []live.BenchmarkResult) {
	arms := []struct {
		label string
		pick  func(live.BenchmarkResult) live.TraceResult
	}{
		{"Cedar-Strict", func(r live.BenchmarkResult) live.TraceResult { return r.Arm1 }},
		{"Cedar-State", func(r live.BenchmarkResult) live.TraceResult { return r.Arm2 }},
		{"Visibility", func(r live.BenchmarkResult) live.TraceResult { return r.Arm3 }},
		{"MCEP-Recon", func(r live.BenchmarkResult) live.TraceResult { return r.Arm4 }},
	}
	fmt.Printf("%-14s %-12s %-14s %-12s %-12s\n", "Arm", "TriStateAcc", "Prec@Covered", "Coverage", "Abstention")
	for _, arm := range arms {
		summary := summarizeArm(results, arm.pick)
		if summary.total == 0 {
			fmt.Printf("%-14s %-12s %-14s %-12s %-12s\n", arm.label, "n/a", "n/a", "n/a", "n/a")
			continue
		}
		fmt.Printf("%-14s %-12.3f %-14s %-12.3f %-12.3f\n",
			arm.label,
			float64(summary.triStateCorrect)/float64(summary.total),
			formatCoveredPrecision(summary),
			float64(summary.covered)/float64(summary.total),
			float64(summary.abstained)/float64(summary.total),
		)
	}
}

func printSplitCoverageSummary(results []live.BenchmarkResult) {
	bySource := make(map[string][]live.BenchmarkResult)
	for _, result := range results {
		source := strings.TrimSpace(result.Source)
		if source == "" {
			source = "unknown"
		}
		bySource[source] = append(bySource[source], result)
	}
	sources := make([]string, 0, len(bySource))
	for source := range bySource {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		fmt.Printf("\nSource split: %s (n=%d)\n", source, len(bySource[source]))
		printCoverageSummaryWithCI(bySource[source])
	}
}

func printCoverageSummaryWithCI(results []live.BenchmarkResult) {
	arms := []struct {
		label string
		pick  func(live.BenchmarkResult) live.TraceResult
	}{
		{"Cedar-Strict", func(r live.BenchmarkResult) live.TraceResult { return r.Arm1 }},
		{"Cedar-State", func(r live.BenchmarkResult) live.TraceResult { return r.Arm2 }},
		{"Visibility", func(r live.BenchmarkResult) live.TraceResult { return r.Arm3 }},
		{"MCEP-Recon", func(r live.BenchmarkResult) live.TraceResult { return r.Arm4 }},
	}
	fmt.Printf("%-14s %-12s %-18s %-14s %-12s %-12s\n", "Arm", "TriStateAcc", "TriState95CI", "Prec@Covered", "Coverage", "Abstention")
	for _, arm := range arms {
		summary := summarizeArm(results, arm.pick)
		if summary.total == 0 {
			fmt.Printf("%-14s %-12s %-18s %-14s %-12s %-12s\n", arm.label, "n/a", "n/a", "n/a", "n/a", "n/a")
			continue
		}
		triStateAccuracy := float64(summary.triStateCorrect) / float64(summary.total)
		lo, hi := wilson95(summary.triStateCorrect, summary.total)
		fmt.Printf("%-14s %-12.3f [%.3f, %.3f]     %-14s %-12.3f %-12.3f\n",
			arm.label,
			triStateAccuracy,
			lo,
			hi,
			formatCoveredPrecision(summary),
			float64(summary.covered)/float64(summary.total),
			float64(summary.abstained)/float64(summary.total),
		)
	}
}

type armSummary struct {
	total           int
	triStateCorrect int
	covered         int
	coveredCorrect  int
	abstained       int
}

func summarizeArm(results []live.BenchmarkResult, pick func(live.BenchmarkResult) live.TraceResult) armSummary {
	summary := armSummary{total: len(results)}
	for _, result := range results {
		verdict := strings.ToLower(strings.TrimSpace(pick(result).Verdict))
		if verdict == "" {
			verdict = "unknown"
		}
		groundTruth := strings.ToLower(strings.TrimSpace(result.GroundTruth))
		if verdict == "unknown" {
			summary.abstained++
		} else {
			summary.covered++
			if verdict == groundTruth {
				summary.coveredCorrect++
			}
		}
		if verdict == groundTruth {
			summary.triStateCorrect++
		}
	}
	return summary
}

func formatCoveredPrecision(summary armSummary) string {
	if summary.covered == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", float64(summary.coveredCorrect)/float64(summary.covered))
}

func wilson95(successes, total int) (float64, float64) {
	if total == 0 {
		return 0, 0
	}
	z := 1.96
	n := float64(total)
	p := float64(successes) / n
	denom := 1 + z*z/n
	center := (p + z*z/(2*n)) / denom
	margin := z * math.Sqrt((p*(1-p)+z*z/(4*n))/n) / denom
	return math.Max(0, center-margin), math.Min(1, center+margin)
}

func fmtVerdict(r live.TraceResult) string {
	if r.FindingsCount > 0 {
		return fmt.Sprintf("%s(%d)", r.Verdict, r.FindingsCount)
	}
	return r.Verdict
}

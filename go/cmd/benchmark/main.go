package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"

	"github.com/gnanirahulnutakki/ardur/go/benchmark"
)

func main() {
	packDir := flag.String("pack", filepath.Join("benchmark", "scenarios", "pack-v0.1"), "path to benchmark scenario pack")
	outDir := flag.String("out", filepath.Join("benchmark", "results", "pack-v0.1"), "directory for generated report artifacts")
	flag.Parse()

	report, err := benchmark.RunPack(*packDir)
	if err != nil {
		log.Fatalf("run benchmark pack: %v", err)
	}
	if err := benchmark.WriteReport(report, *outDir); err != nil {
		log.Fatalf("write benchmark report: %v", err)
	}

	fmt.Printf("pack=%s scenarios=%d traces=%d authorization_correct=%d policy_correct=%d reconciliation_correct=%d\n",
		report.PackDir, report.ScenarioCount, report.TraceCount, report.AuthorizationHit, report.PolicyHit, report.ReconcileHit)
	fmt.Printf("wrote %s, %s, and %s\n",
		filepath.Join(*outDir, "results.json"),
		filepath.Join(*outDir, "summary.csv"),
		filepath.Join(*outDir, "summary.md"),
	)
}

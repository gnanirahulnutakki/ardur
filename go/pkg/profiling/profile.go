// Package profiling provides behavioral baseline profiling for VIBAP Layer 4.
//
// It defines a ProfileProvider interface that abstracts over Kubescape's
// ApplicationProfile CRD (spdx.softwarecomposition.kubescape.io/v1beta1).
// The profiling system captures expected syscalls, network endpoints, file
// access patterns, and exec calls for each agent container, then freezes this
// as a baseline. At credential issuance time, the baseline is hashed into
// Layer 4 (application_profile_hash) of the VIBAP credential.
//
// Runtime enforcement is handled by Tetragon TracingPolicies (deployed
// separately), which kill processes that deviate from the baseline.
package profiling

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Sentinel errors for the profiling package.
var (
	ErrProfileNotFound = errors.New("application profile not found")
	ErrProfileNotReady = errors.New("application profile not ready")
	ErrProviderClosed  = errors.New("profile provider is closed")
)

// ApplicationProfile represents the behavioral baseline of an agent container.
// This is VIBAP's abstraction over Kubescape's ApplicationProfile CRD.
// Fields map to Kubescape's per-container profiling data.
type ApplicationProfile struct {
	// Name is the profile identifier (typically <pod-name>-<container-name>).
	Name string `json:"name"`

	// Namespace is the Kubernetes namespace of the profiled pod.
	Namespace string `json:"namespace"`

	// Container is the container name within the pod.
	Container string `json:"container"`

	// Syscalls is the set of system calls observed during profiling.
	Syscalls []string `json:"syscalls"`

	// Endpoints is the set of network endpoints the container communicates with.
	// Format: "protocol://host:port" or "dns:port".
	Endpoints []string `json:"endpoints"`

	// Execs is the set of executable paths invoked by the container.
	Execs []ExecCall `json:"execs"`

	// FileAccesses is the set of file paths opened during profiling.
	FileAccesses []FileAccess `json:"file_accesses"`

	// Capabilities is the set of Linux capabilities used.
	Capabilities []string `json:"capabilities,omitempty"`

	// ProfiledAt is when the profile was generated.
	ProfiledAt time.Time `json:"profiled_at"`

	// Status indicates profile readiness: "ready", "profiling", "error".
	Status string `json:"status"`
}

// ExecCall represents an observed process execution.
type ExecCall struct {
	Path string   `json:"path"`
	Args []string `json:"args,omitempty"`
}

// FileAccess represents an observed file access.
type FileAccess struct {
	Path  string   `json:"path"`
	Flags []string `json:"flags,omitempty"`
}

// ProfileDiff represents the differences between a current behavior profile
// and a frozen baseline. Non-empty diff fields indicate potential violations.
type ProfileDiff struct {
	// NewSyscalls are syscalls in current but not in baseline.
	NewSyscalls []string `json:"new_syscalls,omitempty"`

	// NewEndpoints are endpoints in current but not in baseline.
	NewEndpoints []string `json:"new_endpoints,omitempty"`

	// NewExecs are executables in current but not in baseline.
	NewExecs []ExecCall `json:"new_execs,omitempty"`

	// NewFileAccesses are file paths in current but not in baseline.
	NewFileAccesses []FileAccess `json:"new_file_accesses,omitempty"`

	// HasDrift indicates whether any new behavior was detected.
	HasDrift bool `json:"has_drift"`

	// DriftSummary is a human-readable description of the drift.
	DriftSummary string `json:"drift_summary,omitempty"`
}

// ProfileProvider abstracts the behavioral profiling backend for VIBAP.
// The primary implementation reads Kubescape ApplicationProfile CRDs;
// the interface enables mock providers and alternative profiling systems.
type ProfileProvider interface {
	// GetProfile retrieves the ApplicationProfile for a container.
	GetProfile(ctx context.Context, namespace, podName, container string) (*ApplicationProfile, error)

	// CompareProfiles diffs two profiles, returning new behaviors in current
	// that are not in the baseline.
	CompareProfiles(baseline, current *ApplicationProfile) (*ProfileDiff, error)

	// Close releases resources held by the provider.
	Close() error
}

// ComputeProfileHash computes a deterministic SHA-256 hash of an ApplicationProfile.
// The hash covers syscalls, endpoints, execs, and file accesses (sorted).
// This becomes the application_profile_hash in Layer 4 of the VIBAP credential.
func ComputeProfileHash(profile *ApplicationProfile) (string, error) {
	if profile == nil {
		return "", fmt.Errorf("profile is nil")
	}

	// Build a deterministic representation (all fields sorted)
	sortedExecs := make([]ExecCall, len(profile.Execs))
	copy(sortedExecs, profile.Execs)
	sort.Slice(sortedExecs, func(i, j int) bool {
		return sortedExecs[i].Path < sortedExecs[j].Path
	})

	sortedFiles := make([]FileAccess, len(profile.FileAccesses))
	copy(sortedFiles, profile.FileAccesses)
	sort.Slice(sortedFiles, func(i, j int) bool {
		return sortedFiles[i].Path < sortedFiles[j].Path
	})

	canonical := struct {
		Syscalls     []string     `json:"syscalls"`
		Endpoints    []string     `json:"endpoints"`
		Execs        []ExecCall   `json:"execs"`
		FileAccesses []FileAccess `json:"file_accesses"`
	}{
		Syscalls:     sortedCopy(profile.Syscalls),
		Endpoints:    sortedCopy(profile.Endpoints),
		Execs:        sortedExecs,
		FileAccesses: sortedFiles,
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshaling profile for hash: %w", err)
	}

	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// DiffProfiles computes the behavioral diff between a baseline and current profile.
// This is a standalone function usable without a ProfileProvider.
// Returns nil diff with HasDrift=false if either profile is nil.
func DiffProfiles(baseline, current *ApplicationProfile) *ProfileDiff {
	if baseline == nil || current == nil {
		return &ProfileDiff{}
	}
	diff := &ProfileDiff{}

	baselineSyscalls := toSet(baseline.Syscalls)
	for _, s := range current.Syscalls {
		if !baselineSyscalls[s] {
			diff.NewSyscalls = append(diff.NewSyscalls, s)
		}
	}

	baselineEndpoints := toSet(baseline.Endpoints)
	for _, ep := range current.Endpoints {
		if !baselineEndpoints[ep] {
			diff.NewEndpoints = append(diff.NewEndpoints, ep)
		}
	}

	baselineExecs := make(map[string]bool)
	for _, e := range baseline.Execs {
		baselineExecs[e.Path] = true
	}
	for _, e := range current.Execs {
		if !baselineExecs[e.Path] {
			diff.NewExecs = append(diff.NewExecs, e)
		}
	}

	baselineFiles := make(map[string]bool)
	for _, f := range baseline.FileAccesses {
		baselineFiles[f.Path] = true
	}
	for _, f := range current.FileAccesses {
		if !baselineFiles[f.Path] {
			diff.NewFileAccesses = append(diff.NewFileAccesses, f)
		}
	}

	diff.HasDrift = len(diff.NewSyscalls) > 0 || len(diff.NewEndpoints) > 0 ||
		len(diff.NewExecs) > 0 || len(diff.NewFileAccesses) > 0

	if diff.HasDrift {
		diff.DriftSummary = fmt.Sprintf(
			"drift detected: %d new syscalls, %d new endpoints, %d new execs, %d new file accesses",
			len(diff.NewSyscalls), len(diff.NewEndpoints),
			len(diff.NewExecs), len(diff.NewFileAccesses),
		)
	}

	return diff
}

func sortedCopy(s []string) []string {
	if s == nil {
		return []string{}
	}
	c := make([]string, len(s))
	copy(c, s)
	sort.Strings(c)
	return c
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

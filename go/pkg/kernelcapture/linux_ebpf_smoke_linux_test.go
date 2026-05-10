//go:build linux

package kernelcapture

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLinuxEBPFExecSmoke(t *testing.T) {
	if os.Getenv("ARDUR_RUN_EBPF_SMOKE") != "1" {
		t.Skip("set ARDUR_RUN_EBPF_SMOKE=1 to run privileged Linux eBPF smoke")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := RunLinuxEBPFExecSmoke(ctx, LinuxEBPFExecSmokeOptions{
		SessionID: "phase2-ebpf-smoke-test",
		Command:   "/usr/bin/true",
		Timeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunLinuxEBPFExecSmoke failed: %v", err)
	}
	if result.Platform != "linux" {
		t.Fatalf("platform = %q, want linux", result.Platform)
	}
	if result.AttachedTracepoint != linuxEBPFExecTracepoint {
		t.Fatalf("tracepoint = %q, want %q", result.AttachedTracepoint, linuxEBPFExecTracepoint)
	}
	if !result.BTFAvailable {
		t.Fatal("expected /sys/kernel/btf/vmlinux to be readable")
	}
	if result.ObservedEvents < 1 {
		t.Fatalf("observed events = %d, want >= 1", result.ObservedEvents)
	}
	if result.Event.Type != ProcessEventExec {
		t.Fatalf("event type = %q, want exec", result.Event.Type)
	}
	if result.Event.PID == 0 || result.Event.CgroupID == 0 || result.Event.ObservedMonotonicNS == 0 {
		t.Fatalf("incomplete event metadata: pid=%d cgroup=%d monotonic=%d", result.Event.PID, result.Event.CgroupID, result.Event.ObservedMonotonicNS)
	}
	if result.Receipt.KernelEventType != "execve" {
		t.Fatalf("kernel event type = %q, want execve", result.Receipt.KernelEventType)
	}
	if result.Receipt.CorrelationConfidence != "high" {
		t.Fatalf("correlation confidence = %q, want high; receipt=%+v event=%+v", result.Receipt.CorrelationConfidence, result.Receipt, result.Event)
	}
	if result.Receipt.Verdict != "compliant" {
		t.Fatalf("verdict = %q, want compliant; receipt=%+v", result.Receipt.Verdict, result.Receipt)
	}

	t.Logf("kernel=%s btf=%t tracepoint=%s command=%v observed_events=%d event_pid=%d ppid=%d tid=%d pid_ns=%d cgroup=%d comm=%q coverage=%s correlation=%s/%s verdict=%s",
		result.KernelRelease,
		result.BTFAvailable,
		result.AttachedTracepoint,
		result.Command,
		result.ObservedEvents,
		result.Event.PID,
		result.Event.PPID,
		result.Event.TID,
		result.Event.PIDNamespaceID,
		result.Event.CgroupID,
		result.Event.Comm,
		result.Receipt.CoverageStatus,
		result.Receipt.CorrelationMethod,
		result.Receipt.CorrelationConfidence,
		result.Receipt.Verdict,
	)
}

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
	if len(result.AttachedTracepoints) != 2 {
		t.Fatalf("attached tracepoints = %v, want exec+exit", result.AttachedTracepoints)
	}
	if result.AttachedTracepoints[0] != linuxEBPFExecTracepoint || result.AttachedTracepoints[1] != linuxEBPFExitTracepoint {
		t.Fatalf("attached tracepoints = %v, want [%q %q]", result.AttachedTracepoints, linuxEBPFExecTracepoint, linuxEBPFExitTracepoint)
	}
	if !result.BTFAvailable {
		t.Fatal("expected /sys/kernel/btf/vmlinux to be readable")
	}
	if result.ObservedEvents < 2 {
		t.Fatalf("observed events = %d, want >= 2", result.ObservedEvents)
	}
	if result.Event.Type != ProcessEventExec {
		t.Fatalf("event type = %q, want exec", result.Event.Type)
	}
	if result.Event.PID == 0 || result.Event.CgroupID == 0 || result.Event.ObservedMonotonicNS == 0 {
		t.Fatalf("incomplete event metadata: pid=%d cgroup=%d monotonic=%d", result.Event.PID, result.Event.CgroupID, result.Event.ObservedMonotonicNS)
	}
	if result.ExecEvent.Type != ProcessEventExec {
		t.Fatalf("exec event type = %q, want exec", result.ExecEvent.Type)
	}
	if result.ExitEvent.Type != ProcessEventExit {
		t.Fatalf("exit event type = %q, want exit", result.ExitEvent.Type)
	}
	if result.ExecEvent.PID == 0 || result.ExecEvent.CgroupID == 0 || result.ExecEvent.ObservedMonotonicNS == 0 {
		t.Fatalf("incomplete exec event metadata: pid=%d cgroup=%d monotonic=%d", result.ExecEvent.PID, result.ExecEvent.CgroupID, result.ExecEvent.ObservedMonotonicNS)
	}
	if result.ExitEvent.PID == 0 || result.ExitEvent.CgroupID == 0 || result.ExitEvent.ObservedMonotonicNS == 0 {
		t.Fatalf("incomplete exit event metadata: pid=%d cgroup=%d monotonic=%d", result.ExitEvent.PID, result.ExitEvent.CgroupID, result.ExitEvent.ObservedMonotonicNS)
	}
	if result.ExecEvent.PID != result.ExitEvent.PID {
		t.Fatalf("expected same process pid for exec/exit, got exec=%d exit=%d", result.ExecEvent.PID, result.ExitEvent.PID)
	}
	if result.ExitEvent.ExitCode != 0 {
		t.Fatalf("exit_code = %d, want 0 for /usr/bin/true", result.ExitEvent.ExitCode)
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
	if len(result.Receipts) != 2 {
		t.Fatalf("receipts len = %d, want 2", len(result.Receipts))
	}
	if result.Receipts[0].KernelEventType != "execve" || result.Receipts[1].KernelEventType != "exit" {
		t.Fatalf("kernel event types = [%q %q], want [execve exit]", result.Receipts[0].KernelEventType, result.Receipts[1].KernelEventType)
	}
	if result.Receipts[0].CorrelationConfidence != "high" || result.Receipts[1].CorrelationConfidence != "high" {
		t.Fatalf("unexpected correlation confidence values: [%q %q]", result.Receipts[0].CorrelationConfidence, result.Receipts[1].CorrelationConfidence)
	}
	if result.Receipts[0].Verdict != "compliant" || result.Receipts[1].Verdict != "compliant" {
		t.Fatalf("unexpected verdict values: [%q %q]", result.Receipts[0].Verdict, result.Receipts[1].Verdict)
	}

	t.Logf("kernel=%s btf=%t tracepoints=%v command=%v observed_events=%d exec_pid=%d exec_ppid=%d exec_tid=%d exec_pid_ns=%d exec_cgroup=%d exec_comm=%q exit_pid=%d exit_ppid=%d exit_tid=%d exit_pid_ns=%d exit_cgroup=%d exit_comm=%q exit_code=%d exec_coverage=%s exec_correlation=%s/%s exec_verdict=%s exit_coverage=%s exit_correlation=%s/%s exit_verdict=%s",
		result.KernelRelease,
		result.BTFAvailable,
		result.AttachedTracepoints,
		result.Command,
		result.ObservedEvents,
		result.ExecEvent.PID,
		result.ExecEvent.PPID,
		result.ExecEvent.TID,
		result.ExecEvent.PIDNamespaceID,
		result.ExecEvent.CgroupID,
		result.ExecEvent.Comm,
		result.ExitEvent.PID,
		result.ExitEvent.PPID,
		result.ExitEvent.TID,
		result.ExitEvent.PIDNamespaceID,
		result.ExitEvent.CgroupID,
		result.ExitEvent.Comm,
		result.ExitEvent.ExitCode,
		result.Receipts[0].CoverageStatus,
		result.Receipts[0].CorrelationMethod,
		result.Receipts[0].CorrelationConfidence,
		result.Receipts[0].Verdict,
		result.Receipts[1].CoverageStatus,
		result.Receipts[1].CorrelationMethod,
		result.Receipts[1].CorrelationConfidence,
		result.Receipts[1].Verdict,
	)
}

//go:build linux

package kernelcapture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const linuxEBPFExecTracepoint = "sched/sched_process_exec"

// LinuxEBPFExecSmokeOptions configures the narrow Phase 2 eBPF MVP smoke.
type LinuxEBPFExecSmokeOptions struct {
	SessionID string
	Command   string
	Args      []string
	Timeout   time.Duration
}

// LinuxEBPFExecSmokeResult is intentionally small and metadata-only. It is a
// local proof artifact, not a production daemon receipt.
type LinuxEBPFExecSmokeResult struct {
	Platform           string
	KernelRelease      string
	BTFAvailable       bool
	AttachedTracepoint string
	Command            []string
	ObservedEvents     int
	Event              ProcessEvent
	Receipt            SyntheticKernelReceipt
}

// RunLinuxEBPFExecSmoke loads the generated process-exec eBPF producer, attaches
// a tracepoint, runs one deterministic command, reads its ringbuf sample, and
// projects the sample through the existing correlation/receipt logic.
//
// This function requires a Linux host/container with privileges sufficient to
// load eBPF programs. It does not install a daemon, persist maps, expose a
// service, or collect argv/env/path/network payloads.
func RunLinuxEBPFExecSmoke(ctx context.Context, opts LinuxEBPFExecSmokeOptions) (*LinuxEBPFExecSmokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.SessionID == "" {
		opts.SessionID = "phase2-ebpf-smoke"
	}
	if opts.Command == "" {
		opts.Command = "/usr/bin/true"
	}

	kernelRelease, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	btfAvailable := fileReadable("/sys/kernel/btf/vmlinux")

	// Best effort only: rootless Podman containers can have enough effective caps to
	// load a small smoke object while still denying rlimit changes. The object uses
	// a deliberately tiny ringbuf for the MVP smoke; if the active limit is still
	// too low, object loading below returns the authoritative failure.
	_ = rlimit.RemoveMemlock()

	var objs processExecObjects
	if err := loadProcessExecObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load process-exec eBPF objects: %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleSchedProcessExec, nil)
	if err != nil {
		return nil, fmt.Errorf("attach %s tracepoint: %w", linuxEBPFExecTracepoint, err)
	}
	defer tp.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, fmt.Errorf("open eBPF ringbuf reader: %w", err)
	}
	source := &RingbufProcessSource{reader: &linuxRingbufReader{reader: reader}, closeFn: reader.Close}
	defer source.Close()

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	spanStart := time.Now().UTC().Add(-250 * time.Millisecond)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start smoke command %q: %w", opts.Command, err)
	}
	targetPID := uint32(cmd.Process.Pid)

	readCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	evt, ok, readErr := source.Next(readCtx, SessionScope{PIDs: map[uint32]struct{}{targetPID: {}}})
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("read eBPF ringbuf event for pid %d: %w", targetPID, readErr)
	}
	if !ok {
		return nil, fmt.Errorf("no scoped eBPF exec event observed for pid %d", targetPID)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("smoke command %q failed after event capture: %w", opts.Command, waitErr)
	}

	eventWall := time.Now().UTC()
	evt.EventID = fmt.Sprintf("kernel-exec:%d:%d", evt.PID, evt.ObservedMonotonicNS)
	evt.SessionID = opts.SessionID
	evt.ObservedAt = eventWall

	correlator := NewCorrelator(CorrelatorOptions{
		Platform:       "linux",
		CaptureBackend: "linux_ebpf",
	})
	correlator.RegisterReceipt(ToolReceipt{
		ReceiptID:      fmt.Sprintf("tool:phase2-smoke:%d", evt.PID),
		SessionID:      opts.SessionID,
		PID:            evt.PID,
		PIDNamespaceID: evt.PIDNamespaceID,
		CgroupID:       evt.CgroupID,
		SpanStart:      spanStart,
		SpanEnd:        eventWall.Add(250 * time.Millisecond),
		ObservedAt:     spanStart,
	})
	receipt := correlator.Correlate(evt, EventContext{})

	command := append([]string{opts.Command}, opts.Args...)
	return &LinuxEBPFExecSmokeResult{
		Platform:           "linux",
		KernelRelease:      strings.TrimSpace(string(kernelRelease)),
		BTFAvailable:       btfAvailable,
		AttachedTracepoint: linuxEBPFExecTracepoint,
		Command:            command,
		ObservedEvents:     1,
		Event:              evt,
		Receipt:            receipt,
	}, nil
}

func fileReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	return errors.Is(f.Close(), nil)
}

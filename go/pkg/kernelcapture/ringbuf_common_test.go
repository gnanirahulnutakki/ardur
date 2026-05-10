package kernelcapture

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

type scriptedRingbufRead struct {
	sample []byte
	err    error
}

type scriptedRingbufReader struct {
	reads     []scriptedRingbufRead
	next      int
	deadlines []time.Time
}

func (r *scriptedRingbufReader) SetDeadline(deadline time.Time) {
	r.deadlines = append(r.deadlines, deadline)
}

func (r *scriptedRingbufReader) ReadSample() ([]byte, error) {
	if r.next >= len(r.reads) {
		return nil, io.EOF
	}
	current := r.reads[r.next]
	r.next++
	return current.sample, current.err
}

func TestNextRingbufProcessEventContextCanceledWithoutDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &scriptedRingbufReader{reads: []scriptedRingbufRead{{err: os.ErrDeadlineExceeded}}}

	_, _, err := nextRingbufProcessEvent(ctx, reader, SessionScope{}, time.Millisecond)
	var typed *RingbufNextError
	if !errors.As(err, &typed) {
		t.Fatalf("expected RingbufNextError, got %T (%v)", err, err)
	}
	if typed.Kind != RingbufErrorContextCanceled {
		t.Fatalf("kind = %q, want %q", typed.Kind, RingbufErrorContextCanceled)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestNextRingbufProcessEventDeadlineExceeded(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	reader := &scriptedRingbufReader{reads: []scriptedRingbufRead{{err: os.ErrDeadlineExceeded}}}

	_, _, err := nextRingbufProcessEvent(ctx, reader, SessionScope{}, time.Millisecond)
	var typed *RingbufNextError
	if !errors.As(err, &typed) {
		t.Fatalf("expected RingbufNextError, got %T (%v)", err, err)
	}
	if typed.Kind != RingbufErrorDeadlineExceeded {
		t.Fatalf("kind = %q, want %q", typed.Kind, RingbufErrorDeadlineExceeded)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestNextRingbufProcessEventMalformedRecordAndGapPropagation(t *testing.T) {
	t.Parallel()

	reader := &scriptedRingbufReader{reads: []scriptedRingbufRead{{sample: []byte{1, 2, 3}}}}
	_, _, err := nextRingbufProcessEvent(context.Background(), reader, SessionScope{}, time.Millisecond)
	var typed *RingbufNextError
	if !errors.As(err, &typed) {
		t.Fatalf("expected RingbufNextError, got %T (%v)", err, err)
	}
	if typed.Kind != RingbufErrorMalformedRecord {
		t.Fatalf("kind = %q, want %q", typed.Kind, RingbufErrorMalformedRecord)
	}
	if !errors.Is(err, ErrRingbufRecordTooSmall) {
		t.Fatalf("expected ErrRingbufRecordTooSmall, got %v", err)
	}

	loss := RingbufCaptureLoss(err)
	if loss.RingbufDropped != 1 || loss.DaemonQueueDropped != 0 {
		t.Fatalf("unexpected loss mapping: %+v", loss)
	}

	eventCtx := EventContext{}
	if !ApplyRingbufCaptureLoss(&eventCtx, err) {
		t.Fatalf("expected ApplyRingbufCaptureLoss to apply increment")
	}
	if eventCtx.CaptureLoss.RingbufDropped != 1 {
		t.Fatalf("ringbuf_dropped = %d, want 1", eventCtx.CaptureLoss.RingbufDropped)
	}
}

func TestApplyRingbufCaptureLossNoopOnNonLossError(t *testing.T) {
	t.Parallel()

	eventCtx := EventContext{}
	err := &RingbufNextError{Kind: RingbufErrorDeadlineExceeded, Err: context.DeadlineExceeded}
	if ApplyRingbufCaptureLoss(&eventCtx, err) {
		t.Fatalf("expected no loss increment for deadline exceeded")
	}
	if eventCtx.CaptureLoss.RingbufDropped != 0 || eventCtx.CaptureLoss.DaemonQueueDropped != 0 {
		t.Fatalf("expected zero loss counters, got %+v", eventCtx.CaptureLoss)
	}
}

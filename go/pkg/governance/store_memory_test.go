package governance

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	session := &SessionState{
		ID:    "s-1",
		Phase: PhaseInitialized,
		Declaration: &MissionDeclaration{
			ID:             "d-1",
			SessionID:      "s-1",
			AllowedActions: []string{"read"},
			AllowedTools:   []string{"reader"},
		},
	}

	if err := store.Create(ctx, session); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.Get(ctx, "s-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != "s-1" {
		t.Fatalf("expected s-1, got %s", got.ID)
	}
	if got.Phase != PhaseInitialized {
		t.Fatalf("expected initialized, got %s", got.Phase)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("expected non-zero created_at")
	}

	got.Phase = PhaseActive
	if err := store.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, _ := store.Get(ctx, "s-1")
	if updated.Phase != PhaseActive {
		t.Fatalf("expected active, got %s", updated.Phase)
	}

	if err := store.Delete(ctx, "s-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = store.Get(ctx, "s-1")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestMemoryStoreDuplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	session := &SessionState{ID: "dup-1"}
	if err := store.Create(ctx, session); err != nil {
		t.Fatalf("first create: %v", err)
	}
	err := store.Create(ctx, session)
	if !errors.Is(err, ErrDuplicateSession) {
		t.Fatalf("expected ErrDuplicateSession, got %v", err)
	}
}

func TestMemoryStoreNotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("get: expected ErrSessionNotFound, got %v", err)
	}

	err = store.Update(ctx, &SessionState{ID: "nonexistent"})
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("update: expected ErrSessionNotFound, got %v", err)
	}

	err = store.Delete(ctx, "nonexistent")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("delete: expected ErrSessionNotFound, got %v", err)
	}
}

func TestMemoryStoreListAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	_ = store.Create(ctx, &SessionState{ID: "s-1", Phase: PhaseActive})
	_ = store.Create(ctx, &SessionState{ID: "s-2", Phase: PhaseClosed})
	_ = store.Create(ctx, &SessionState{ID: "s-3", Phase: PhaseActive})

	all, err := store.List(ctx, nil)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3, got %d", len(all))
	}
}

func TestMemoryStoreListFiltered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	_ = store.Create(ctx, &SessionState{ID: "s-1", Phase: PhaseActive})
	_ = store.Create(ctx, &SessionState{ID: "s-2", Phase: PhaseClosed})
	_ = store.Create(ctx, &SessionState{ID: "s-3", Phase: PhaseActive})

	active := PhaseActive
	filtered, err := store.List(ctx, &active)
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(filtered))
	}
}

func TestMemoryStoreClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	store.Close()

	err := store.Create(ctx, &SessionState{ID: "s-1"})
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("create on closed: expected ErrStoreClosed, got %v", err)
	}

	_, err = store.Get(ctx, "s-1")
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("get on closed: expected ErrStoreClosed, got %v", err)
	}

	err = store.Update(ctx, &SessionState{ID: "s-1"})
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("update on closed: expected ErrStoreClosed, got %v", err)
	}

	_, err = store.List(ctx, nil)
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("list on closed: expected ErrStoreClosed, got %v", err)
	}

	err = store.Delete(ctx, "s-1")
	if !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("delete on closed: expected ErrStoreClosed, got %v", err)
	}
}

func TestMemoryStoreDefaultPhase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	if err := store.Create(ctx, &SessionState{ID: "s-nophase"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, _ := store.Get(ctx, "s-nophase")
	if got.Phase != PhaseInitialized {
		t.Fatalf("expected default phase initialized, got %s", got.Phase)
	}
}

func TestMemoryStoreIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	original := &SessionState{
		ID:    "s-iso",
		Phase: PhaseInitialized,
		Declaration: &MissionDeclaration{
			ID:             "d-iso",
			SessionID:      "s-iso",
			AllowedActions: []string{"read"},
			AllowedTools:   []string{"reader"},
		},
		Events: []ObservedEvent{
			{EventID: "e-1", SessionID: "s-iso", Timestamp: time.Now(), Actor: "a", ActionClass: "read", ToolName: "t", Target: "x", Summary: "s", SideEffectClass: "none", Visibility: "full"},
		},
	}
	_ = store.Create(ctx, original)

	got, _ := store.Get(ctx, "s-iso")
	got.Phase = PhaseClosed
	retrieved, _ := store.Get(ctx, "s-iso")
	if retrieved.Phase != PhaseInitialized {
		t.Fatal("store returned a reference instead of a copy (phase)")
	}

	got2, _ := store.Get(ctx, "s-iso")
	got2.Events = append(got2.Events, ObservedEvent{EventID: "e-injected"})
	retrieved2, _ := store.Get(ctx, "s-iso")
	if len(retrieved2.Events) != 1 {
		t.Fatalf("slice isolation broken: expected 1 event, got %d", len(retrieved2.Events))
	}

	got3, _ := store.Get(ctx, "s-iso")
	got3.Declaration.AllowedActions = append(got3.Declaration.AllowedActions, "hack")
	retrieved3, _ := store.Get(ctx, "s-iso")
	if len(retrieved3.Declaration.AllowedActions) != 1 {
		t.Fatalf("declaration isolation broken: expected 1 action, got %d", len(retrieved3.Declaration.AllowedActions))
	}
}

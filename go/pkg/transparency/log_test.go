package transparency

import (
	"context"
	"errors"
	"testing"
)

func TestNewLogEntry(t *testing.T) {
	t.Run("valid entry", func(t *testing.T) {
		entry, err := NewLogEntry(EntryCredentialIssued, "agent-1", map[string]any{
			"credential_hash": "abc123",
			"ttl_seconds":     3600,
		})
		if err != nil {
			t.Fatalf("NewLogEntry: %v", err)
		}
		if entry.Hash == "" {
			t.Error("hash is empty")
		}
		if entry.AgentID != "agent-1" {
			t.Errorf("agent_id = %s, want agent-1", entry.AgentID)
		}
		if entry.Type != EntryCredentialIssued {
			t.Errorf("type = %s, want credential_issued", entry.Type)
		}
		if len(entry.Hash) != 64 {
			t.Errorf("hash length = %d, want 64", len(entry.Hash))
		}
	})

	t.Run("empty agent ID", func(t *testing.T) {
		_, err := NewLogEntry(EntryCredentialIssued, "", nil)
		if err == nil {
			t.Error("expected error for empty agent ID")
		}
		if !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("err = %v, want ErrInvalidEntry", err)
		}
	})

	t.Run("deterministic hash", func(t *testing.T) {
		e1, _ := NewLogEntry(EntryScoreChanged, "agent-1", map[string]any{"score": 85.0})
		h1 := e1.Hash
		// Hash is based on content + timestamp, so two calls will differ
		// but ComputeEntryHash of the same entry should be stable
		h2, _ := ComputeEntryHash(e1)
		if h1 != h2 {
			t.Errorf("hash not stable: %s vs %s", h1, h2)
		}
	})

	t.Run("nil entry hash", func(t *testing.T) {
		_, err := ComputeEntryHash(nil)
		if err == nil {
			t.Error("expected error for nil entry")
		}
	})
}

func TestInMemoryLog_AppendAndGet(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()
	ctx := context.Background()

	entry, _ := NewLogEntry(EntryCredentialIssued, "agent-1", map[string]any{"hash": "abc"})

	idx, err := log.Append(ctx, entry)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if idx != 0 {
		t.Errorf("first index = %d, want 0", idx)
	}

	got, err := log.Get(ctx, 0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AgentID != "agent-1" {
		t.Errorf("agent_id = %s, want agent-1", got.AgentID)
	}
	if got.Index != 0 {
		t.Errorf("index = %d, want 0", got.Index)
	}
}

func TestInMemoryLog_MultipleEntries(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		entry, _ := NewLogEntry(EntryScoreChanged, "agent-1", map[string]any{"iteration": i})
		idx, err := log.Append(ctx, entry)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if idx != uint64(i) {
			t.Errorf("index = %d, want %d", idx, i)
		}
	}

	if log.Size() != 10 {
		t.Errorf("size = %d, want 10", log.Size())
	}
}

func TestInMemoryLog_GetOutOfRange(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()

	_, err := log.Get(context.Background(), 0)
	if !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("err = %v, want ErrEntryNotFound", err)
	}
}

func TestInMemoryLog_Checkpoint(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()
	ctx := context.Background()

	// Empty log checkpoint
	cp, err := log.GetCheckpoint(ctx)
	if err != nil {
		t.Fatalf("GetCheckpoint (empty): %v", err)
	}
	if cp.TreeSize != 0 {
		t.Errorf("empty tree size = %d, want 0", cp.TreeSize)
	}
	if cp.RootHash == "" {
		t.Error("root hash should not be empty")
	}

	entry, _ := NewLogEntry(EntryCredentialIssued, "agent-1", map[string]any{"x": "y"})
	log.Append(ctx, entry)

	cp2, _ := log.GetCheckpoint(ctx)
	if cp2.TreeSize != 1 {
		t.Errorf("tree size = %d, want 1", cp2.TreeSize)
	}
	if cp2.RootHash == cp.RootHash {
		t.Error("root hash should change after append")
	}
}

func TestInMemoryLog_InclusionProof(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()
	ctx := context.Background()

	var entries []*LogEntry
	for i := 0; i < 8; i++ {
		entry, _ := NewLogEntry(EntryCredentialIssued, "agent-1", map[string]any{"idx": i})
		log.Append(ctx, entry)
		entries = append(entries, entry)
	}

	cp, _ := log.GetCheckpoint(ctx)

	// Get inclusion proof for entry 3
	proof, err := log.GetInclusionProof(ctx, 3, cp.TreeSize)
	if err != nil {
		t.Fatalf("GetInclusionProof: %v", err)
	}
	if proof.LeafIndex != 3 {
		t.Errorf("leaf index = %d, want 3", proof.LeafIndex)
	}
	if proof.TreeSize != 8 {
		t.Errorf("tree size = %d, want 8", proof.TreeSize)
	}
	if len(proof.Hashes) == 0 {
		t.Error("proof should have hashes")
	}

	// Verify the inclusion proof
	valid := VerifyInclusion(entries[3].Hash, 3, 8, proof, cp.RootHash)
	if !valid {
		t.Error("inclusion proof should be valid")
	}
}

func TestInMemoryLog_InclusionProofNonPowerOf2(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()
	ctx := context.Background()

	var entries []*LogEntry
	for i := 0; i < 3; i++ {
		entry, _ := NewLogEntry(EntryCredentialIssued, "agent-1", map[string]any{"idx": i})
		log.Append(ctx, entry)
		entries = append(entries, entry)
	}

	cp, _ := log.GetCheckpoint(ctx)
	if cp.TreeSize != 3 {
		t.Fatalf("tree size = %d, want 3", cp.TreeSize)
	}

	for idx := uint64(0); idx < 3; idx++ {
		proof, err := log.GetInclusionProof(ctx, idx, cp.TreeSize)
		if err != nil {
			t.Fatalf("GetInclusionProof(%d): %v", idx, err)
		}
		if len(proof.Hashes) == 0 {
			t.Errorf("index %d: proof should have hashes", idx)
		}
		valid := VerifyInclusion(entries[idx].Hash, idx, cp.TreeSize, proof, cp.RootHash)
		if !valid {
			t.Errorf("index %d: inclusion proof should be valid (proof hashes: %d)", idx, len(proof.Hashes))
		}
	}
}

func TestInMemoryLog_InclusionProofInvalidIndex(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()
	ctx := context.Background()

	entry, _ := NewLogEntry(EntryCredentialIssued, "agent-1", nil)
	log.Append(ctx, entry)

	_, err := log.GetInclusionProof(ctx, 5, 1)
	if !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("err = %v, want ErrEntryNotFound", err)
	}
}

func TestVerifyInclusion_InvalidInputs(t *testing.T) {
	if VerifyInclusion("", 0, 0, nil, "") {
		t.Error("nil proof should fail")
	}
	if VerifyInclusion("invalidhex", 0, 1, &InclusionProof{}, "") {
		t.Error("invalid hex should fail")
	}
}

func TestInMemoryLog_AppendNil(t *testing.T) {
	log := NewInMemoryLog()
	defer log.Close()

	_, err := log.Append(context.Background(), nil)
	if !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("err = %v, want ErrInvalidEntry", err)
	}
}

func TestInMemoryLog_Closed(t *testing.T) {
	log := NewInMemoryLog()
	log.Close()
	ctx := context.Background()

	entry, _ := NewLogEntry(EntryCredentialIssued, "agent-1", nil)
	if _, err := log.Append(ctx, entry); !errors.Is(err, ErrLogClosed) {
		t.Errorf("Append: %v, want ErrLogClosed", err)
	}
	if _, err := log.Get(ctx, 0); !errors.Is(err, ErrLogClosed) {
		t.Errorf("Get: %v, want ErrLogClosed", err)
	}
	if _, err := log.GetCheckpoint(ctx); !errors.Is(err, ErrLogClosed) {
		t.Errorf("GetCheckpoint: %v, want ErrLogClosed", err)
	}
	if _, err := log.GetInclusionProof(ctx, 0, 0); !errors.Is(err, ErrLogClosed) {
		t.Errorf("GetInclusionProof: %v, want ErrLogClosed", err)
	}
}

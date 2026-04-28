// Package transparency provides an append-only transparency log for VIBAP.
//
// All credential issuance events and trust score changes are logged to a
// verifiable append-only log, enabling auditors to detect unauthorized
// credential issuance or score manipulation. The log produces Merkle
// tree inclusion proofs that clients can independently verify.
//
// The primary implementation targets Trillian Tessera (v1.0.2), which
// provides an in-process Go library supporting POSIX, GCS, S3, and MySQL
// backends. The interface abstraction allows alternative backends (e.g.,
// a simple file-based log for development).
package transparency

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

// Sentinel errors for the transparency package.
var (
	ErrLogClosed     = errors.New("transparency log is closed")
	ErrEntryNotFound = errors.New("log entry not found")
	ErrInvalidEntry  = errors.New("invalid log entry")
	ErrProofInvalid  = errors.New("inclusion proof invalid")
)

// EntryType categorizes log entries.
type EntryType string

const (
	EntryCredentialIssued  EntryType = "credential_issued"  // #nosec G101 -- transparency log event label, not a secret
	EntryCredentialRevoked EntryType = "credential_revoked" // #nosec G101 -- transparency log event label, not a secret
	EntryScoreChanged      EntryType = "score_changed"
	EntryTierChanged       EntryType = "tier_changed"
	EntryPolicyViolation   EntryType = "policy_violation"
)

// LogEntry represents a single event in the transparency log.
type LogEntry struct {
	// Index is the entry's position in the log (set after appending).
	Index uint64 `json:"index"`

	// Type categorizes the event.
	Type EntryType `json:"type"`

	// AgentID identifies the agent this event relates to.
	AgentID string `json:"agent_id"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Data contains event-specific payload (credential hash, score values, etc.).
	Data map[string]any `json:"data"`

	// Hash is the SHA-256 of the serialized entry (set after creation).
	Hash string `json:"hash"`
}

// Checkpoint represents a signed log checkpoint (tree head).
type Checkpoint struct {
	TreeSize  uint64    `json:"tree_size"`
	RootHash  string    `json:"root_hash"`
	Timestamp time.Time `json:"timestamp"`
}

// InclusionProof proves that an entry exists in the log at a given tree size.
type InclusionProof struct {
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	Hashes    []string `json:"hashes"`
}

// TransparencyLog provides append-only logging with verifiable proofs.
type TransparencyLog interface {
	// Append adds an entry to the log and returns its index.
	Append(ctx context.Context, entry *LogEntry) (uint64, error)

	// Get retrieves an entry by index.
	Get(ctx context.Context, index uint64) (*LogEntry, error)

	// GetCheckpoint returns the current log checkpoint (tree head).
	GetCheckpoint(ctx context.Context) (*Checkpoint, error)

	// GetInclusionProof returns a proof that an entry exists in the log.
	GetInclusionProof(ctx context.Context, index, treeSize uint64) (*InclusionProof, error)

	// Close releases resources.
	Close() error
}

// ComputeEntryHash computes a deterministic SHA-256 hash of a log entry's content.
// Uses sorted keys for map[string]any to ensure determinism regardless of Go map iteration order.
func ComputeEntryHash(entry *LogEntry) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("%w: nil entry", ErrInvalidEntry)
	}

	dataBytes, err := marshalSortedJSON(entry.Data)
	if err != nil {
		return "", fmt.Errorf("marshaling entry data: %w", err)
	}

	canonical := struct {
		Type      EntryType       `json:"type"`
		AgentID   string          `json:"agent_id"`
		Timestamp time.Time       `json:"timestamp"`
		Data      json.RawMessage `json:"data"`
	}{
		Type:      entry.Type,
		AgentID:   entry.AgentID,
		Timestamp: entry.Timestamp,
		Data:      dataBytes,
	}

	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshaling entry: %w", err)
	}

	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// marshalSortedJSON serializes a map with sorted keys for deterministic output.
func marshalSortedJSON(m map[string]any) ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	sorted := make([]struct {
		K string `json:"k"`
		V any    `json:"v"`
	}, len(keys))
	for i, k := range keys {
		sorted[i].K = k
		sorted[i].V = m[k]
	}
	return json.Marshal(sorted)
}

// NewLogEntry creates a log entry with a computed hash.
func NewLogEntry(entryType EntryType, agentID string, data map[string]any) (*LogEntry, error) {
	if agentID == "" {
		return nil, fmt.Errorf("%w: empty agent ID", ErrInvalidEntry)
	}

	entry := &LogEntry{
		Type:      entryType,
		AgentID:   agentID,
		Timestamp: time.Now(),
		Data:      data,
	}

	hash, err := ComputeEntryHash(entry)
	if err != nil {
		return nil, err
	}
	entry.Hash = hash
	return entry, nil
}

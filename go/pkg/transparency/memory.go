package transparency

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// InMemoryLog implements TransparencyLog with an in-memory append-only list.
// Provides a simplified Merkle tree for inclusion proofs.
// Suitable for development and testing; use Tessera for production.
type InMemoryLog struct {
	mu      sync.RWMutex
	closed  bool
	entries []*LogEntry
	hashes  [][]byte // leaf hashes for Merkle tree
}

// NewInMemoryLog creates a new in-memory transparency log.
func NewInMemoryLog() *InMemoryLog {
	return &InMemoryLog{
		entries: make([]*LogEntry, 0),
		hashes:  make([][]byte, 0),
	}
}

var _ TransparencyLog = (*InMemoryLog)(nil)

// Append adds an entry to the log.
func (l *InMemoryLog) Append(_ context.Context, entry *LogEntry) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, ErrLogClosed
	}
	if entry == nil {
		return 0, fmt.Errorf("%w: nil entry", ErrInvalidEntry)
	}

	if entry.Hash == "" {
		hash, err := ComputeEntryHash(entry)
		if err != nil {
			return 0, err
		}
		entry.Hash = hash
	}

	index := uint64(len(l.entries))
	entry.Index = index
	l.entries = append(l.entries, entry)

	hashBytes, err := hex.DecodeString(entry.Hash)
	if err != nil {
		return 0, fmt.Errorf("decoding entry hash: %w", err)
	}
	l.hashes = append(l.hashes, hashLeaf(hashBytes))

	return index, nil
}

// Get retrieves an entry by index.
func (l *InMemoryLog) Get(_ context.Context, index uint64) (*LogEntry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrLogClosed
	}
	if index >= uint64(len(l.entries)) {
		return nil, fmt.Errorf("%w: index %d >= size %d", ErrEntryNotFound, index, len(l.entries))
	}
	entry := *l.entries[index]
	if entry.Data != nil {
		dataCopy := make(map[string]any, len(entry.Data))
		for k, v := range entry.Data {
			dataCopy[k] = v
		}
		entry.Data = dataCopy
	}
	return &entry, nil
}

// GetCheckpoint returns the current tree head.
func (l *InMemoryLog) GetCheckpoint(_ context.Context) (*Checkpoint, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrLogClosed
	}

	rootHash := l.computeRootHash()

	return &Checkpoint{
		TreeSize:  uint64(len(l.entries)),
		RootHash:  hex.EncodeToString(rootHash),
		Timestamp: time.Now(),
	}, nil
}

// GetInclusionProof returns a Merkle inclusion proof for an entry.
func (l *InMemoryLog) GetInclusionProof(_ context.Context, index, treeSize uint64) (*InclusionProof, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrLogClosed
	}

	logSize := uint64(len(l.entries))
	if treeSize > logSize {
		treeSize = logSize
	}
	if index >= treeSize {
		return nil, fmt.Errorf("%w: index %d >= tree size %d", ErrEntryNotFound, index, treeSize)
	}

	proof := computeMerkleProof(l.hashes[:treeSize], index)
	proofHex := make([]string, len(proof))
	for i, h := range proof {
		proofHex[i] = hex.EncodeToString(h)
	}

	return &InclusionProof{
		LeafIndex: index,
		TreeSize:  treeSize,
		Hashes:    proofHex,
	}, nil
}

// Close releases resources.
func (l *InMemoryLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

// Size returns the number of entries in the log.
func (l *InMemoryLog) Size() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return uint64(len(l.entries))
}

// computeRootHash computes the Merkle tree root hash.
func (l *InMemoryLog) computeRootHash() []byte {
	if len(l.hashes) == 0 {
		return sha256.New().Sum(nil)
	}
	return merkleRoot(l.hashes)
}

// merkleRoot computes the root of a Merkle tree from leaf hashes.
func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		h := sha256.New()
		return h.Sum(nil)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	current := make([][]byte, len(leaves))
	copy(current, leaves)

	for len(current) > 1 {
		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, hashPair(current[i], current[i+1]))
			} else {
				next = append(next, current[i])
			}
		}
		current = next
	}
	return current[0]
}

// hashLeaf computes SHA-256(0x00 || data) for Merkle tree leaf nodes.
// Domain separation per RFC 6962 Section 2.1.
func hashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// hashPair computes SHA-256(0x01 || left || right) for Merkle tree internal nodes.
// Domain separation per RFC 6962 Section 2.1 prevents second-preimage attacks.
func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// computeMerkleProof computes the inclusion proof path for a leaf at the given index.
// At each level, if idx is even and has a right sibling, that sibling is added to the
// proof. If idx is odd, the left sibling is added. When an odd node is promoted
// (no sibling), no proof element is emitted for that level.
func computeMerkleProof(leaves [][]byte, index uint64) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	if index >= uint64(len(leaves)) {
		return nil
	}

	var proof [][]byte
	current := make([][]byte, len(leaves))
	copy(current, leaves)
	idx := int(index) // #nosec G115 -- guarded above by len(leaves) bound check

	for len(current) > 1 {
		if idx%2 == 0 {
			sibling := idx + 1
			if sibling < len(current) {
				proof = append(proof, current[sibling])
			}
		} else {
			proof = append(proof, current[idx-1])
		}

		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, hashPair(current[i], current[i+1]))
			} else {
				next = append(next, current[i])
			}
		}
		idx /= 2
		current = next
	}
	return proof
}

// VerifyInclusion verifies that a leaf hash is included in the tree
// using the provided Merkle proof. The leafHash is the raw entry hash;
// domain separation (RFC 6962) is applied internally.
// Tracks level size (n) to correctly skip levels where a node was promoted
// without a sibling in non-power-of-2 trees.
func VerifyInclusion(leafHash string, index, treeSize uint64, proof *InclusionProof, rootHash string) bool {
	if proof == nil {
		return false
	}

	leafBytes, err := hex.DecodeString(leafHash)
	if err != nil {
		return false
	}

	current := hashLeaf(leafBytes)
	idx := index
	n := treeSize
	proofIdx := 0

	for n > 1 {
		if idx%2 == 1 {
			if proofIdx >= len(proof.Hashes) {
				return false
			}
			hashBytes, err := hex.DecodeString(proof.Hashes[proofIdx])
			if err != nil {
				return false
			}
			current = hashPair(hashBytes, current)
			proofIdx++
		} else if idx+1 < n {
			if proofIdx >= len(proof.Hashes) {
				return false
			}
			hashBytes, err := hex.DecodeString(proof.Hashes[proofIdx])
			if err != nil {
				return false
			}
			current = hashPair(current, hashBytes)
			proofIdx++
		}
		// else: promoted (even index, no sibling) — no proof element consumed
		idx /= 2
		n = (n + 1) / 2
	}

	if proofIdx != len(proof.Hashes) {
		return false
	}
	return hex.EncodeToString(current) == rootHash
}

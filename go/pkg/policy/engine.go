// Package policy provides Cedar policy engine integration for VIBAP Layer 3 (Intent Binding).
//
// It defines a PolicyEngine interface abstraction over the Cedar authorization
// engine, enabling testability and future support for alternative engines (e.g., OPA/Rego).
// The primary implementation uses cedar-go v1.5.x for policy parsing and evaluation.
//
// VIBAP uses Cedar policies to bind agent intent: what an agent is permitted to do
// is cryptographically committed into the credential via policy_hash. At runtime,
// the policy is evaluated against each agent action to enforce the declared intent.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors for the policy package.
var (
	ErrPolicyParse    = errors.New("policy parse error")
	ErrEvaluation     = errors.New("policy evaluation error")
	ErrDenied         = errors.New("action denied by policy")
	ErrEngineClosed   = errors.New("policy engine is closed")
	ErrInvalidRequest = errors.New("invalid authorization request")
)

// Decision represents the outcome of a policy evaluation.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// AuthzRequest represents a Cedar authorization request.
// Maps to Cedar's (principal, action, resource, context) tuple.
type AuthzRequest struct {
	// Principal is the entity requesting access (e.g., "VIBAP::Agent::weather-bot")
	Principal EntityRef

	// Action being requested (e.g., "Action::read_database")
	Action EntityRef

	// Resource being accessed (e.g., "VIBAP::Resource::weather-api")
	Resource EntityRef

	// Context contains additional request attributes (timestamps, IP, etc.)
	Context map[string]any
}

// EntityRef identifies a Cedar entity by type and ID.
type EntityRef struct {
	Type string // Cedar entity type (e.g., "VIBAP::Agent")
	ID   string // Entity identifier (e.g., "weather-bot")
}

func (e EntityRef) String() string {
	return fmt.Sprintf("%s::\"%s\"", e.Type, e.ID)
}

// AuthzResult contains the detailed outcome of a policy evaluation.
type AuthzResult struct {
	Decision Decision
	Reasons  []string // PolicyIDs that contributed to the decision
	Errors   []string // Evaluation errors (non-fatal)
	EvalTime time.Duration
}

// CompiledPolicy represents a parsed and compiled set of Cedar policies
// ready for evaluation. It includes the canonical text and hash for
// credential binding.
type CompiledPolicy struct {
	// PolicyText is the canonical Cedar text (sorted, deterministic).
	PolicyText string

	// Hash is the SHA-256 of the canonical policy text.
	Hash string

	// PolicyCount is the number of individual policies in the set.
	PolicyCount int

	// PolicyIDs are the identifiers of each policy in the set.
	PolicyIDs []string
}

// Entity represents a Cedar entity with its type, ID, attributes, and parents.
type Entity struct {
	UID        EntityRef
	Parents    []EntityRef
	Attributes map[string]any
}

// PolicyEngine abstracts the policy evaluation engine for VIBAP.
// The primary implementation uses Cedar; the interface enables
// alternative engines (OPA/Rego) and mock implementations.
type PolicyEngine interface {
	// Compile parses Cedar policy text and returns a compiled policy.
	// The compiled policy includes a deterministic hash for credential binding.
	Compile(ctx context.Context, policyText string) (*CompiledPolicy, error)

	// Evaluate runs an authorization request against a compiled policy.
	// Returns the decision (allow/deny) with diagnostic information.
	Evaluate(ctx context.Context, policy *CompiledPolicy, entities []Entity, request AuthzRequest) (*AuthzResult, error)

	// SetEntities loads a set of entities into the engine for evaluation.
	// This is useful for batch evaluation against the same entity store.
	SetEntities(entities []Entity) error

	// EngineName returns the name of the policy engine (e.g., "cedar", "rego").
	EngineName() string

	// Close releases resources held by the engine.
	Close() error
}

// ComputePolicyHash computes the SHA-256 hash of policy text.
// The text is normalized (trimmed, consistent line endings) before hashing.
func ComputePolicyHash(policyText string) string {
	normalized := strings.TrimSpace(policyText)
	normalized = strings.ReplaceAll(normalized, "\r\n", "\n")
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// ComputeAgentChecksum computes the SHA-256 checksum of the agent's
// system prompt, tool manifest, and derived policy. This is the
// agent_checksum field in Layer 3 of a VIBAP credential.
//
// Uses length-prefixed encoding to prevent collisions: each component
// is preceded by its byte length as an 8-byte big-endian uint64.
func ComputeAgentChecksum(systemPrompt, toolManifest, policyText string) string {
	h := sha256.New()
	for _, s := range []string{
		strings.TrimSpace(systemPrompt),
		strings.TrimSpace(toolManifest),
		strings.TrimSpace(policyText),
	} {
		lenBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBuf, uint64(len(s)))
		h.Write(lenBuf)
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ValidatePolicyEngine checks that a policy engine name is supported.
func ValidatePolicyEngine(name string) error {
	switch name {
	case "cedar", "rego":
		return nil
	default:
		return fmt.Errorf("unsupported policy engine %q: must be 'cedar' or 'rego'", name)
	}
}

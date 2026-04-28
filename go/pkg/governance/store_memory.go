package governance

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryStore is a thread-safe in-memory SessionStore for dev and test use.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState
	closed   bool
}

// NewMemoryStore creates an in-memory session store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*SessionState),
	}
}

var _ SessionStore = (*MemoryStore)(nil)

func (s *MemoryStore) Create(_ context.Context, session *SessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if _, exists := s.sessions[session.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateSession, session.ID)
	}
	now := time.Now().UTC()
	session.CreatedAt = now
	session.UpdatedAt = now
	if session.Phase == "" {
		session.Phase = PhaseInitialized
	}
	s.sessions[session.ID] = deepCopySession(session)
	return nil
}

func (s *MemoryStore) Get(_ context.Context, sessionID string) (*SessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSessionNotFound, sessionID)
	}
	return deepCopySession(session), nil
}

func (s *MemoryStore) Update(_ context.Context, session *SessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if _, ok := s.sessions[session.ID]; !ok {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, session.ID)
	}
	session.UpdatedAt = time.Now().UTC()
	s.sessions[session.ID] = deepCopySession(session)
	return nil
}

func (s *MemoryStore) List(_ context.Context, phase *SessionPhase) ([]*SessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	result := make([]*SessionState, 0, len(s.sessions))
	for _, session := range s.sessions {
		if phase != nil && session.Phase != *phase {
			continue
		}
		result = append(result, deepCopySession(session))
	}
	return result, nil
}

func deepCopySession(src *SessionState) *SessionState {
	cp := *src
	if src.Declaration != nil {
		declCopy := *src.Declaration
		declCopy.AllowedActions = copyStrings(src.Declaration.AllowedActions)
		declCopy.AllowedTools = copyStrings(src.Declaration.AllowedTools)
		declCopy.AllowedResources = copyStrings(src.Declaration.AllowedResources)
		declCopy.AllowedResourceFamilies = copyStrings(src.Declaration.AllowedResourceFamilies)
		declCopy.AllowedSideEffects = copyStrings(src.Declaration.AllowedSideEffects)
		if src.Declaration.DelegationPolicy != nil {
			dpCopy := *src.Declaration.DelegationPolicy
			declCopy.DelegationPolicy = &dpCopy
		}
		if src.Declaration.Metadata != nil {
			declCopy.Metadata = make(map[string]string, len(src.Declaration.Metadata))
			for k, v := range src.Declaration.Metadata {
				declCopy.Metadata[k] = v
			}
		}
		cp.Declaration = &declCopy
	}
	if len(src.Events) > 0 {
		cp.Events = make([]ObservedEvent, len(src.Events))
		copy(cp.Events, src.Events)
	}
	if src.LatestDecision != nil {
		decCopy := *src.LatestDecision
		if len(src.LatestDecision.Findings) > 0 {
			decCopy.Findings = make([]Finding, len(src.LatestDecision.Findings))
			copy(decCopy.Findings, src.LatestDecision.Findings)
		}
		cp.LatestDecision = &decCopy
	}
	return &cp
}

func copyStrings(src []string) []string {
	if src == nil {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

func (s *MemoryStore) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if _, ok := s.sessions[sessionID]; !ok {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, sessionID)
	}
	delete(s.sessions, sessionID)
	return nil
}

// Close marks the store as closed; subsequent operations return ErrStoreClosed.
func (s *MemoryStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

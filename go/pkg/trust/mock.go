package trust

import (
	"context"
	"fmt"
	"sync"
)

// MockAggregator implements ScoreAggregator for testing.
type MockAggregator struct {
	mu          sync.Mutex
	closed      bool
	scores      map[string]*TrustScore
	ingestErr   error
	ingestCount int
	signals     []TelemetrySignal
}

// NewMockAggregator creates a mock trust score aggregator.
func NewMockAggregator() *MockAggregator {
	return &MockAggregator{
		scores: make(map[string]*TrustScore),
	}
}

var _ ScoreAggregator = (*MockAggregator)(nil)

// SetScore pre-loads a score for testing.
func (m *MockAggregator) SetScore(score *TrustScore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scores[score.AgentID] = score
}

// SetIngestError configures an error returned by IngestSignal.
func (m *MockAggregator) SetIngestError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ingestErr = err
}

// IngestCount returns the number of IngestSignal calls.
func (m *MockAggregator) IngestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ingestCount
}

// Signals returns all ingested signals.
func (m *MockAggregator) Signals() []TelemetrySignal {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]TelemetrySignal(nil), m.signals...)
}

func (m *MockAggregator) RegisterAgent(_ context.Context, agentID string, staticCapability, historicalReputation float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrAggregatorClosed
	}
	m.scores[agentID] = &TrustScore{
		AgentID:              agentID,
		StaticCapability:     staticCapability,
		HistoricalReputation: historicalReputation,
		RuntimeCompliance:    1.0,
		CompositeScore:       100.0,
		AuthorizationTier:    TierFull,
	}
	return nil
}

func (m *MockAggregator) IngestSignal(_ context.Context, signal TelemetrySignal) (*TrustScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ingestCount++
	m.signals = append(m.signals, signal)

	if m.closed {
		return nil, ErrAggregatorClosed
	}
	if m.ingestErr != nil {
		return nil, m.ingestErr
	}

	score, ok := m.scores[signal.AgentID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAgentNotFound, signal.AgentID)
	}
	return score, nil
}

func (m *MockAggregator) GetScore(_ context.Context, agentID string) (*TrustScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrAggregatorClosed
	}
	score, ok := m.scores[agentID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAgentNotFound, agentID)
	}
	return score, nil
}

func (m *MockAggregator) ListScores(_ context.Context) ([]*TrustScore, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrAggregatorClosed
	}
	scores := make([]*TrustScore, 0, len(m.scores))
	for _, s := range m.scores {
		scores = append(scores, s)
	}
	return scores, nil
}

func (m *MockAggregator) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// Package health tracks runtime subsystem health and readiness.
package health

import (
	"sync"
	"time"
)

// State represents one runtime subsystem state.
type State string

const (
	StateStarting State = "starting"
	StateHealthy  State = "healthy"
	StateDegraded State = "degraded"
	StateFailed   State = "failed"
	StateStopped  State = "stopped"
)

// Snapshot is an immutable status view.
type Snapshot struct {
	StartedAt   time.Time `json:"started_at"`
	SourceState State     `json:"source_state"`
	StoreState  State     `json:"store_state"`
	SourceError string    `json:"source_error,omitempty"`
	StoreError  string    `json:"store_error,omitempty"`
	LastEventAt time.Time `json:"last_event_at,omitempty"`
	ActiveFlows int64     `json:"active_flows"`
}

// Ready reports whether the runtime can provide fresh audit data.
func (s Snapshot) Ready() bool {
	return s.SourceState == StateHealthy && s.StoreState == StateHealthy
}

// Status is a concurrency-safe runtime status tracker.
type Status struct {
	mu sync.RWMutex

	snapshot Snapshot
}

// New creates a status tracker.
func New() *Status {
	return &Status{
		snapshot: Snapshot{
			StartedAt:   time.Now().UTC(),
			SourceState: StateStarting,
			StoreState:  StateStarting,
		},
	}
}

// SetSource updates source health.
func (s *Status) SetSource(state State, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot.SourceState = state
	if err == nil {
		s.snapshot.SourceError = ""
	} else {
		s.snapshot.SourceError = err.Error()
	}
}

// SetStore updates storage health.
func (s *Status) SetStore(state State, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot.StoreState = state
	if err == nil {
		s.snapshot.StoreError = ""
	} else {
		s.snapshot.StoreError = err.Error()
	}
}

// EventObserved records the most recent event time.
func (s *Status) EventObserved(at time.Time, activeFlows int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot.LastEventAt = at.UTC()
	s.snapshot.ActiveFlows = activeFlows
}

// ActiveFlows updates the current open Flow count.
func (s *Status) ActiveFlows(count int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot.ActiveFlows = count
}

// Snapshot returns a consistent status view.
func (s *Status) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.snapshot
}

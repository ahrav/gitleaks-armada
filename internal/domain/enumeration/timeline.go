package enumeration

import (
	"encoding/json"
	"time"
)

// Timeline is a value object that tracks temporal aspects of both Session and Batch entities.
// It provides methods to track start time, completion time, and last update time while
// maintaining consistency through a TimeProvider interface.
type Timeline struct {
	startedAt    time.Time
	completedAt  time.Time
	lastUpdate   time.Time
	timeProvider TimeProvider
}

// NewTimeline creates a new Timeline instance with the provided TimeProvider.
// It initializes both startedAt and lastUpdate to the current time.
func NewTimeline(timeProvider TimeProvider) *Timeline {
	now := timeProvider.Now()
	return &Timeline{
		startedAt:    now,
		lastUpdate:   now,
		timeProvider: timeProvider,
	}
}

// ReconstructTimeline creates a Timeline instance from persisted timestamp data.
func ReconstructTimeline(
	startedAt time.Time,
	completedAt time.Time,
	lastUpdate time.Time,
) *Timeline {
	return &Timeline{
		startedAt:    startedAt,
		completedAt:  completedAt,
		lastUpdate:   lastUpdate,
		timeProvider: &realTimeProvider{}, // Use default provider for reconstructed timelines
	}
}

// Getters
func (t *Timeline) StartedAt() time.Time   { return t.startedAt }
func (t *Timeline) CompletedAt() time.Time { return t.completedAt }
func (t *Timeline) LastUpdate() time.Time  { return t.lastUpdate }

// MarshalJSON serializes Timeline to JSON
func (t *Timeline) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		StartedAt   time.Time `json:"started_at"`
		CompletedAt time.Time `json:"completed_at"`
		LastUpdate  time.Time `json:"last_update"`
	}{
		StartedAt:   t.startedAt,
		CompletedAt: t.completedAt,
		LastUpdate:  t.lastUpdate,
	})
}

// UnmarshalJSON deserializes JSON into Timeline
func (t *Timeline) UnmarshalJSON(data []byte) error {
	aux := &struct {
		StartedAt   time.Time `json:"started_at"`
		CompletedAt time.Time `json:"completed_at"`
		LastUpdate  time.Time `json:"last_update"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	t.startedAt = aux.StartedAt
	t.completedAt = aux.CompletedAt
	t.lastUpdate = aux.LastUpdate
	t.timeProvider = &realTimeProvider{} // Use default provider when reconstructing

	return nil
}

// MarkCompleted records the completion time and updates the last update timestamp.
func (t *Timeline) MarkCompleted() {
	t.completedAt = t.timeProvider.Now()
	t.UpdateLastUpdate()
}

// UpdateLastUpdate sets the lastUpdate field to the current time.
func (t *Timeline) UpdateLastUpdate() { t.lastUpdate = t.timeProvider.Now() }

// Since calculates the duration since the provided time.
func (t *Timeline) Since(tm time.Time) time.Duration { return t.timeProvider.Now().Sub(tm) }

// IsCompleted returns whether the timeline has been marked as completed.
func (t *Timeline) IsCompleted() bool { return !t.completedAt.IsZero() }

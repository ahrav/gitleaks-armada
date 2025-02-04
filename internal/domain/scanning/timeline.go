package scanning

import "time"

// TimeProvider is an interface that provides a Now method to get the current time.
type TimeProvider interface {
	Now() time.Time
}

// Real implementation for production.
type realTimeProvider struct{}

func (r *realTimeProvider) Now() time.Time { return time.Now() }

// Timeline tracks temporal aspects of scan jobs.
type Timeline struct {
	startedAt    time.Time
	completedAt  time.Time
	lastUpdate   time.Time
	timeProvider TimeProvider
}

// NewTimeline creates a new Timeline instance.
func NewTimeline(timeProvider TimeProvider) *Timeline {
	return &Timeline{
		lastUpdate:   timeProvider.Now(),
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
		timeProvider: new(realTimeProvider),
	}
}

// StartedAt returns the time the scan job started.
func (t *Timeline) StartedAt() time.Time { return t.startedAt }

// CompletedAt returns the time the scan job completed.
func (t *Timeline) CompletedAt() time.Time { return t.completedAt }

// LastUpdate returns the time the scan job was last updated.
func (t *Timeline) LastUpdate() time.Time { return t.lastUpdate }

// MarkStarted records the start time.
func (t *Timeline) MarkStarted() {
	t.startedAt = t.timeProvider.Now()
	t.UpdateLastUpdate()
}

// MarkCompleted records completion time.
func (t *Timeline) MarkCompleted() {
	t.completedAt = t.timeProvider.Now()
	t.UpdateLastUpdate()
}

// UpdateLastUpdate updates the last update timestamp.
func (t *Timeline) UpdateLastUpdate() { t.lastUpdate = t.timeProvider.Now() }

// IsCompleted checks if the timeline has been marked as completed.
func (t *Timeline) IsCompleted() bool { return !t.completedAt.IsZero() }

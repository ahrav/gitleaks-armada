package enumeration

import (
	"encoding/json"
	"time"
)

// Progress tracks metrics about an enumeration session's execution. It provides
// visibility into the session's timeline and processing status to enable monitoring
// and reporting of long-running enumerations.
type Progress struct {
	// Timeline
	startedAt  time.Time
	lastUpdate time.Time

	// Metrics
	itemsFound     int
	itemsProcessed int

	// Batch tracking
	batches       []BatchProgress
	failedBatches int
	totalBatches  int
}

// ReconstructProgress creates a Progress instance from persisted data.
func ReconstructProgress(
	startedAt time.Time,
	lastUpdate time.Time,
	itemsFound int,
	itemsProcessed int,
	failedBatches int,
	totalBatches int,
	batches []BatchProgress,
) *Progress {
	return &Progress{
		startedAt:      startedAt,
		lastUpdate:     lastUpdate,
		itemsFound:     itemsFound,
		itemsProcessed: itemsProcessed,
		failedBatches:  failedBatches,
		totalBatches:   totalBatches,
		batches:        batches,
	}
}

// Getters for Progress
func (p *Progress) StartedAt() time.Time     { return p.startedAt }
func (p *Progress) LastUpdate() time.Time    { return p.lastUpdate }
func (p *Progress) ItemsFound() int          { return p.itemsFound }
func (p *Progress) ItemsProcessed() int      { return p.itemsProcessed }
func (p *Progress) FailedBatches() int       { return p.failedBatches }
func (p *Progress) TotalBatches() int        { return p.totalBatches }
func (p *Progress) Batches() []BatchProgress { return p.batches }

// MarshalJSON serializes the Progress object into a JSON byte array.
func (p *Progress) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		StartedAt      time.Time       `json:"started_at"`
		LastUpdate     time.Time       `json:"last_update"`
		ItemsFound     int             `json:"items_found"`
		ItemsProcessed int             `json:"items_processed"`
		Batches        []BatchProgress `json:"batches,omitempty"`
		FailedBatches  int             `json:"failed_batches"`
		TotalBatches   int             `json:"total_batches"`
	}{
		StartedAt:      p.startedAt,
		LastUpdate:     p.lastUpdate,
		ItemsFound:     p.itemsFound,
		ItemsProcessed: p.itemsProcessed,
		Batches:        p.batches,
		FailedBatches:  p.failedBatches,
		TotalBatches:   p.totalBatches,
	})
}

// UnmarshalJSON deserializes JSON data into a Progress object.
func (p *Progress) UnmarshalJSON(data []byte) error {
	aux := &struct {
		StartedAt      time.Time       `json:"started_at"`
		LastUpdate     time.Time       `json:"last_update"`
		ItemsFound     int             `json:"items_found"`
		ItemsProcessed int             `json:"items_processed"`
		Batches        []BatchProgress `json:"batches,omitempty"`
		FailedBatches  int             `json:"failed_batches"`
		TotalBatches   int             `json:"total_batches"`
	}{
		StartedAt:      p.startedAt,
		LastUpdate:     p.lastUpdate,
		ItemsFound:     p.itemsFound,
		ItemsProcessed: p.itemsProcessed,
		Batches:        p.batches,
		FailedBatches:  p.failedBatches,
		TotalBatches:   p.totalBatches,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.startedAt = aux.StartedAt
	p.lastUpdate = aux.LastUpdate
	p.itemsFound = aux.ItemsFound
	p.itemsProcessed = aux.ItemsProcessed
	p.batches = aux.Batches
	p.failedBatches = aux.FailedBatches
	p.totalBatches = aux.TotalBatches

	return nil
}

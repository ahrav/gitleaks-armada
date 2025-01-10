package enumeration

import "encoding/json"

// SessionMetrics is a value object that tracks aggregate statistics for an enumeration session.
// It provides encapsulated methods for updating metrics to maintain invariants and prevent
// direct manipulation of internal counts.
type SessionMetrics struct {
	totalBatches   int
	failedBatches  int
	itemsFound     int
	itemsProcessed int
}

// NewSessionMetrics creates a new SessionMetrics instance with zeroed counters.
func NewSessionMetrics() *SessionMetrics { return new(SessionMetrics) }

// ReconstructSessionMetrics creates a SessionMetrics instance from persisted data.
func ReconstructSessionMetrics(
	totalBatches int,
	failedBatches int,
	itemsFound int,
	itemsProcessed int,
) *SessionMetrics {
	return &SessionMetrics{
		totalBatches:   totalBatches,
		failedBatches:  failedBatches,
		itemsFound:     itemsFound,
		itemsProcessed: itemsProcessed,
	}
}

// Getters for metrics values
func (m *SessionMetrics) TotalBatches() int   { return m.totalBatches }
func (m *SessionMetrics) FailedBatches() int  { return m.failedBatches }
func (m *SessionMetrics) ItemsProcessed() int { return m.itemsProcessed }
func (m *SessionMetrics) ItemsFound() int     { return m.itemsFound }

// MarshalJSON serializes SessionMetrics to JSON using a public struct
func (m *SessionMetrics) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		TotalBatches   int `json:"total_batches"`
		FailedBatches  int `json:"failed_batches"`
		ItemsFound     int `json:"items_found"`
		ItemsProcessed int `json:"items_processed"`
	}{
		TotalBatches:   m.totalBatches,
		FailedBatches:  m.failedBatches,
		ItemsFound:     m.itemsFound,
		ItemsProcessed: m.itemsProcessed,
	})
}

// UnmarshalJSON deserializes JSON into SessionMetrics
func (m *SessionMetrics) UnmarshalJSON(data []byte) error {
	aux := &struct {
		TotalBatches   int `json:"total_batches"`
		FailedBatches  int `json:"failed_batches"`
		ItemsFound     int `json:"items_found"`
		ItemsProcessed int `json:"items_processed"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	m.totalBatches = aux.TotalBatches
	m.failedBatches = aux.FailedBatches
	m.itemsFound = aux.ItemsFound
	m.itemsProcessed = aux.ItemsProcessed

	return nil
}

// IncrementTotalBatches increases the total batch count by one.
func (m *SessionMetrics) IncrementTotalBatches() { m.totalBatches++ }

// IncrementFailedBatches increases the failed batch count by one.
func (m *SessionMetrics) IncrementFailedBatches() { m.failedBatches++ }

// IncrementItemsFound increases the items found count by one.
func (m *SessionMetrics) IncrementItemsFound() { m.itemsFound++ }

// AddProcessedItems adds the specified number of processed items to the total.
// Returns an error if attempting to add a negative number.
func (m *SessionMetrics) AddProcessedItems(count int) error {
	if count < 0 {
		return newInvalidItemCountError()
	}
	m.itemsProcessed += count
	return nil
}

// HasFailedBatches returns true if any batches have failed.
func (m *SessionMetrics) HasFailedBatches() bool { return m.failedBatches > 0 }

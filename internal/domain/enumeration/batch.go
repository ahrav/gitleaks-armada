package enumeration

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// BatchStatus represents the lifecycle state of an enumeration batch as a value object.
// It enables tracking of batch-level outcomes to support partial failure handling
// and resumable processing.
type BatchStatus string

const (
	// BatchStatusSucceeded indicates the batch completed processing all items successfully.
	BatchStatusSucceeded BatchStatus = "SUCCEEDED"
	// BatchStatusFailed indicates the batch encountered an unrecoverable error.
	BatchStatusFailed BatchStatus = "FAILED"
	// BatchStatusPartial indicates the batch completed with some items failing.
	BatchStatusPartial BatchStatus = "PARTIALLY_COMPLETED"
	// BatchStatusInProgress indicates the batch is actively being processed.
	BatchStatusInProgress BatchStatus = "IN_PROGRESS"
)

// BatchOption defines functional options for configuring a new Batch.
type BatchOption func(*Batch)

// WithTimeProvider sets a custom time provider for the batch.
func WithTimeProvider(tp TimeProvider) BatchOption {
	return func(b *Batch) { b.timeline = NewTimeline(tp) }
}

// Batch is an entity that represents a batch of targets to be enumerated.
// It coordinates the timeline, metrics, and checkpoint data for a specific batch of work.
type Batch struct {
	batchID    string
	sessionID  string // Back-reference to aggregate
	status     BatchStatus
	timeline   *Timeline
	metrics    *BatchMetrics
	checkpoint *Checkpoint
}

// NewBatch creates a new Batch instance to track the execution of an enumeration batch.
// It initializes the batch with a unique ID and creates its timeline and metrics value objects.
func NewBatch(sessionID string, expectedItems int, checkpoint *Checkpoint, opts ...BatchOption) *Batch {
	batch := &Batch{
		batchID:    uuid.New().String(),
		sessionID:  sessionID,
		status:     BatchStatusInProgress,
		timeline:   NewTimeline(new(realTimeProvider)),
		metrics:    NewBatchMetrics(expectedItems),
		checkpoint: checkpoint,
	}

	for _, opt := range opts {
		opt(batch)
	}

	return batch
}

// ReconstructBatch creates a Batch instance from persisted data.
func ReconstructBatch(
	batchID string,
	sessionID string,
	status BatchStatus,
	timeline *Timeline,
	metrics *BatchMetrics,
	checkpoint *Checkpoint,
) *Batch {
	return &Batch{
		batchID:    batchID,
		sessionID:  sessionID,
		status:     status,
		timeline:   timeline,
		metrics:    metrics,
		checkpoint: checkpoint,
	}
}

// Getters
func (b *Batch) BatchID() string         { return b.batchID }
func (b *Batch) SessionID() string       { return b.sessionID }
func (b *Batch) Status() BatchStatus     { return b.status }
func (b *Batch) Timeline() *Timeline     { return b.timeline }
func (b *Batch) Metrics() *BatchMetrics  { return b.metrics }
func (b *Batch) Checkpoint() *Checkpoint { return b.checkpoint }

// MarshalJSON serializes the Batch object into a JSON byte array.
func (b *Batch) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		BatchID    string        `json:"batch_id"`
		SessionID  string        `json:"session_id"`
		Status     BatchStatus   `json:"status"`
		Timeline   *Timeline     `json:"timeline"`
		Metrics    *BatchMetrics `json:"metrics"`
		Checkpoint *Checkpoint   `json:"checkpoint"`
	}{
		BatchID:    b.batchID,
		SessionID:  b.sessionID,
		Status:     b.status,
		Timeline:   b.timeline,
		Metrics:    b.metrics,
		Checkpoint: b.checkpoint,
	})
}

// UnmarshalJSON deserializes JSON data into a Batch object.
func (b *Batch) UnmarshalJSON(data []byte) error {
	aux := &struct {
		BatchID    string        `json:"batch_id"`
		SessionID  string        `json:"session_id"`
		Status     BatchStatus   `json:"status"`
		Timeline   *Timeline     `json:"timeline"`
		Metrics    *BatchMetrics `json:"metrics"`
		Checkpoint *Checkpoint   `json:"checkpoint"`
	}{}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	b.batchID = aux.BatchID
	b.sessionID = aux.SessionID
	b.status = aux.Status
	b.timeline = aux.Timeline
	b.metrics = aux.Metrics
	b.checkpoint = aux.Checkpoint

	return nil
}

// MarkSuccessful transitions the batch to successful state and updates its metrics.
func (b *Batch) MarkSuccessful(itemsProcessed int) error {
	if b.status != BatchStatusInProgress {
		return fmt.Errorf("cannot mark successful: invalid state transition from %s",
			b.status)
	}

	if err := b.metrics.MarkSuccessful(itemsProcessed); err != nil {
		return err
	}

	b.status = BatchStatusSucceeded
	b.timeline.MarkCompleted()
	return nil
}

// MarkFailed transitions the batch to failed state and records the error.
func (b *Batch) MarkFailed(err error) error {
	if b.status != BatchStatusInProgress {
		return fmt.Errorf("cannot mark failed: invalid state transition from %s", b.status)
	}

	b.metrics.MarkFailed(err)
	b.status = BatchStatusFailed
	b.timeline.MarkCompleted()
	return nil
}

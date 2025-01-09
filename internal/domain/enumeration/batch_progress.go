package enumeration

import (
	"encoding/json"
	"time"

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

	// BatchStatusPending indicates the batch is prepared but not yet processed.
	BatchStatusPending BatchStatus = "PENDING"
)

// BatchProgress is a value object that captures the execution details and outcomes
// of a single enumeration batch. It provides granular visibility into batch-level
// processing to support monitoring and failure analysis.
type BatchProgress struct {
	// batchID uniquely identifies this batch within the enumeration.
	batchID string
	// status reflects the batch's processing outcome.
	status BatchStatus
	// startedAt records when batch processing began.
	startedAt time.Time
	// completedAt records when batch processing finished.
	completedAt time.Time
	// itemsProcessed tracks the number of successfully handled items.
	itemsProcessed int
	// errorDetails captures failure information when status is failed or partial.
	errorDetails string
	// checkpoint stores the checkpoint of the enumeration at the time of the batch.
	checkpoint *Checkpoint
}

// NewSuccessfulBatchProgress creates a BatchProgress record for a successfully completed batch.
// It captures the number of items processed and the state of the enumeration at the time of the batch.
// This enables accurate progress monitoring and resumable processing of large datasets.
func NewSuccessfulBatchProgress(itemCount int, checkpoint *Checkpoint) BatchProgress {
	return BatchProgress{
		batchID:        uuid.New().String(),
		status:         BatchStatusSucceeded,
		startedAt:      time.Now(),
		completedAt:    time.Now(),
		itemsProcessed: itemCount,
		checkpoint:     checkpoint,
	}
}

// NewFailedBatchProgress creates a BatchProgress record for a failed batch execution.
// It preserves the error details and state of the enumeration at the time of the batch.
// This enables failure analysis and recovery.
func NewFailedBatchProgress(err error, checkpoint *Checkpoint) BatchProgress {
	return BatchProgress{
		batchID:      uuid.New().String(),
		status:       BatchStatusFailed,
		startedAt:    time.Now(),
		completedAt:  time.Now(),
		errorDetails: err.Error(),
		checkpoint:   checkpoint,
	}
}

// NewPendingBatchProgress creates a BatchProgress record for a batch that is prepared
// but not yet processed. This enables tracking of batch preparation before task publishing.
func NewPendingBatchProgress(expectedItems int, checkpoint *Checkpoint) BatchProgress {
	return BatchProgress{
		batchID:        uuid.New().String(),
		status:         BatchStatusPending,
		startedAt:      time.Now(),
		completedAt:    time.Time{}, // Zero time since not completed
		itemsProcessed: 0,           // No items processed yet
		checkpoint:     checkpoint,
	}
}

// ReconstructBatchProgress creates a BatchProgress instance from persisted data
func ReconstructBatchProgress(
	batchID string,
	status BatchStatus,
	startedAt time.Time,
	completedAt time.Time,
	itemsProcessed int,
	errorDetails string,
	checkpoint *Checkpoint,
) BatchProgress {
	return BatchProgress{
		batchID:        batchID,
		status:         status,
		startedAt:      startedAt,
		completedAt:    completedAt,
		itemsProcessed: itemsProcessed,
		errorDetails:   errorDetails,
		checkpoint:     checkpoint,
	}
}

// Getters for BatchProgress.
func (bp BatchProgress) BatchID() string         { return bp.batchID }
func (bp BatchProgress) Status() BatchStatus     { return bp.status }
func (bp BatchProgress) ItemsProcessed() int     { return bp.itemsProcessed }
func (bp BatchProgress) Checkpoint() *Checkpoint { return bp.checkpoint }
func (bp BatchProgress) ErrorDetails() string    { return bp.errorDetails }
func (bp BatchProgress) StartedAt() time.Time    { return bp.startedAt }
func (bp BatchProgress) CompletedAt() time.Time  { return bp.completedAt }

// MarshalJSON serializes the BatchProgress object into a JSON byte array.
func (bp *BatchProgress) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		BatchID        string      `json:"batch_id"`
		Status         BatchStatus `json:"status"`
		StartedAt      time.Time   `json:"started_at"`
		CompletedAt    time.Time   `json:"completed_at"`
		ItemsProcessed int         `json:"items_processed"`
		ErrorDetails   string      `json:"error_details,omitempty"`
		Checkpoint     *Checkpoint `json:"checkpoint"`
	}{
		BatchID:        bp.batchID,
		Status:         bp.status,
		StartedAt:      bp.startedAt,
		CompletedAt:    bp.completedAt,
		ItemsProcessed: bp.itemsProcessed,
		ErrorDetails:   bp.errorDetails,
		Checkpoint:     bp.checkpoint,
	})
}

// UnmarshalJSON deserializes JSON data into a BatchProgress object.
func (bp *BatchProgress) UnmarshalJSON(data []byte) error {
	aux := &struct {
		BatchID        string      `json:"batch_id"`
		Status         BatchStatus `json:"status"`
		StartedAt      time.Time   `json:"started_at"`
		CompletedAt    time.Time   `json:"completed_at"`
		ItemsProcessed int         `json:"items_processed"`
		ErrorDetails   string      `json:"error_details,omitempty"`
		Checkpoint     *Checkpoint `json:"checkpoint"`
	}{
		BatchID:        bp.batchID,
		Status:         bp.status,
		StartedAt:      bp.startedAt,
		CompletedAt:    bp.completedAt,
		ItemsProcessed: bp.itemsProcessed,
		ErrorDetails:   bp.errorDetails,
		Checkpoint:     bp.checkpoint,
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	bp.batchID = aux.BatchID
	bp.status = aux.Status
	bp.startedAt = aux.StartedAt
	bp.completedAt = aux.CompletedAt
	bp.itemsProcessed = aux.ItemsProcessed
	bp.errorDetails = aux.ErrorDetails
	bp.checkpoint = aux.Checkpoint

	return nil
}

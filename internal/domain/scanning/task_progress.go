package scanning

import (
	"encoding/json"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Progress represents a point-in-time status update from a scanner. It provides
// detailed metrics about the current scanning progress without maintaining task state.
type Progress struct {
	taskID          uuid.UUID
	jobID           uuid.UUID
	sequenceNum     int64
	timestamp       time.Time
	itemsProcessed  int64
	errorCount      int32
	message         string
	progressDetails json.RawMessage
	checkpoint      *Checkpoint
}

// NewProgress creates a new Progress instance for tracking scan progress.
// It establishes initial state for resuming interrupted scans.
func NewProgress(
	taskID uuid.UUID,
	jobID uuid.UUID,
	sequenceNum int64,
	timestamp time.Time,
	itemsProcessed int64,
	errorCount int32,
	message string,
	progressDetails json.RawMessage,
	checkpoint *Checkpoint,
) Progress {
	return Progress{
		taskID:          taskID,
		jobID:           jobID,
		sequenceNum:     sequenceNum,
		timestamp:       timestamp,
		itemsProcessed:  itemsProcessed,
		errorCount:      errorCount,
		message:         message,
		progressDetails: progressDetails,
		checkpoint:      checkpoint,
	}
}

// ReconstructProgress creates a Progress instance from persisted data.
// This should only be used by repositories when reconstructing from storage.
func ReconstructProgress(
	taskID uuid.UUID,
	jobID uuid.UUID,
	sequenceNum int64,
	timestamp time.Time,
	itemsProcessed int64,
	errorCount int32,
	message string,
	progressDetails json.RawMessage,
	checkpoint *Checkpoint,
) Progress {
	return Progress{
		taskID:          taskID,
		jobID:           jobID,
		sequenceNum:     sequenceNum,
		timestamp:       timestamp,
		itemsProcessed:  itemsProcessed,
		errorCount:      errorCount,
		message:         message,
		progressDetails: progressDetails,
		checkpoint:      checkpoint,
	}
}

// TaskID returns the unique identifier for this scan task.
func (p Progress) TaskID() uuid.UUID { return p.taskID }

// JobID returns the unique identifier for the job containing this task.
func (p Progress) JobID() uuid.UUID { return p.jobID }

// SequenceNum returns the sequence number of this progress update.
func (p Progress) SequenceNum() int64 { return p.sequenceNum }

// Timestamp returns the time the progress update was created.
func (p Progress) Timestamp() time.Time { return p.timestamp }

// ItemsProcessed returns the total number of items scanned by this task.
func (p Progress) ItemsProcessed() int64 { return p.itemsProcessed }

// ErrorCount returns the number of errors encountered by this task.
func (p Progress) ErrorCount() int32                { return p.errorCount }
func (p Progress) Message() string                  { return p.message }
func (p Progress) ProgressDetails() json.RawMessage { return p.progressDetails }
func (p Progress) Checkpoint() *Checkpoint          { return p.checkpoint }

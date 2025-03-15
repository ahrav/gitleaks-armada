package scanning

import (
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// ResumeTaskInfo contains the minimal information needed to resume a paused task.
// This is a lightweight alternative to the full Task struct, optimized for the resumption process.
type ResumeTaskInfo struct {
	taskID      uuid.UUID
	jobID       uuid.UUID
	sourceType  shared.SourceType
	resourceURI string
	sequenceNum int64
	checkpoint  *Checkpoint
}

// NewResumeTaskInfo creates a new ResumeTaskInfo with the given parameters.
func NewResumeTaskInfo(
	taskID uuid.UUID,
	jobID uuid.UUID,
	sourceType shared.SourceType,
	resourceURI string,
	sequenceNum int64,
	checkpoint *Checkpoint,
) ResumeTaskInfo {
	return ResumeTaskInfo{
		taskID:      taskID,
		jobID:       jobID,
		sourceType:  sourceType,
		resourceURI: resourceURI,
		sequenceNum: sequenceNum,
		checkpoint:  checkpoint,
	}
}

// TaskID returns the task's unique identifier.
func (i ResumeTaskInfo) TaskID() uuid.UUID { return i.taskID }

// JobID returns the associated job's unique identifier.
func (i ResumeTaskInfo) JobID() uuid.UUID { return i.jobID }

// SourceType returns the type of source being scanned.
func (i ResumeTaskInfo) SourceType() shared.SourceType { return i.sourceType }

// ResourceURI returns the identifier of the resource being scanned.
func (i ResumeTaskInfo) ResourceURI() string { return i.resourceURI }

// SequenceNum returns the last processed sequence number.
func (i ResumeTaskInfo) SequenceNum() int64 { return i.sequenceNum }

// Checkpoint returns the resumption state stored from the last scan.
func (i ResumeTaskInfo) Checkpoint() *Checkpoint { return i.checkpoint }

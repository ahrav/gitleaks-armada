package scanning

import (
	"encoding/json"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// JobControlCommand encapsulates all information needed to control a job's lifecycle.
type JobControlCommand struct {
	JobID       uuid.UUID
	RequestedBy string
}

// NewJobControlCommand creates a new JobControlCommand.
func NewJobControlCommand(jobID uuid.UUID, requestedBy string) JobControlCommand {
	return JobControlCommand{JobID: jobID, RequestedBy: requestedBy}
}

// CreateJobCommand encapsulates all information needed to create a new scanning job.
// It follows the command pattern to express the intent of the operation while
// maintaining proper domain responsibility boundaries.
type CreateJobCommand struct {
	JobID      uuid.UUID       // Unique identifier for the job
	SourceType string          // Type of source being scanned (e.g., "github")
	Config     json.RawMessage // Authentication and configuration details
}

// NewCreateJobCommand creates a new CreateJobCommand.
func NewCreateJobCommand(jobID uuid.UUID, sourceType string, config json.RawMessage) CreateJobCommand {
	return CreateJobCommand{JobID: jobID, SourceType: sourceType, Config: config}
}

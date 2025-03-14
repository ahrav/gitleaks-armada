package scanning

import (
	"encoding/json"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// ScheduleJobCommand encapsulates all information needed to schedule a new scanning job.
// It extends the job control pattern to include target information required for scheduling.
type ScheduleJobCommand struct {
	JobID       uuid.UUID // Unique identifier for the job
	RequestedBy string    // User or system that requested the job
	Targets     []Target  // Targets to be scanned in this job
}

// NewScheduleJobCommand creates a new ScheduleJobCommand.
func NewScheduleJobCommand(jobID uuid.UUID, requestedBy string, targets []Target) ScheduleJobCommand {
	return ScheduleJobCommand{
		JobID:       jobID,
		RequestedBy: requestedBy,
		Targets:     targets,
	}
}

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

// AssociateEnumeratedTargetsCommand encapsulates all information needed to associate
// enumerated targets with a job and update the job's task count.
type AssociateEnumeratedTargetsCommand struct {
	JobID     uuid.UUID   // The job to associate targets with
	TargetIDs []uuid.UUID // The targets to associate with the job
}

// NewAssociateEnumeratedTargetsCommand creates a new AssociateEnumeratedTargetsCommand.
func NewAssociateEnumeratedTargetsCommand(jobID uuid.UUID, targetIDs []uuid.UUID) AssociateEnumeratedTargetsCommand {
	return AssociateEnumeratedTargetsCommand{JobID: jobID, TargetIDs: targetIDs}
}

// StartTaskCommand encapsulates all information needed to start a task.
type StartTaskCommand struct {
	ScannerID   uuid.UUID // The scanner to start the task on
	TaskID      uuid.UUID // The task to start
	ResourceURI string    // The resource to scan
}

// NewStartTaskCommand creates a new StartTaskCommand.
func NewStartTaskCommand(taskID uuid.UUID, scannerID uuid.UUID, resourceURI string) StartTaskCommand {
	return StartTaskCommand{TaskID: taskID, ScannerID: scannerID, ResourceURI: resourceURI}
}

// PauseTaskCommand encapsulates all information needed to pause a task and store its
// final progress checkpoint.
type PauseTaskCommand struct {
	TaskID      uuid.UUID // The task to pause
	Progress    Progress  // The final progress checkpoint
	RequestedBy string    // Who requested the pause
}

// NewPauseTaskCommand creates a new PauseTaskCommand.
func NewPauseTaskCommand(taskID uuid.UUID, progress Progress, requestedBy string) PauseTaskCommand {
	return PauseTaskCommand{TaskID: taskID, Progress: progress, RequestedBy: requestedBy}
}

// CreateScannerGroupCommand encapsulates all information needed to create a new scanner group.
type CreateScannerGroupCommand struct {
	Name        string // Human-readable name for the scanner group
	Description string // Optional description of the scanner group
}

// NewCreateScannerGroupCommand creates a new CreateScannerGroupCommand.
func NewCreateScannerGroupCommand(name, description string) CreateScannerGroupCommand {
	return CreateScannerGroupCommand{Name: name, Description: description}
}

// CreateScannerCommand encapsulates all information needed to register a new scanner.
type CreateScannerCommand struct {
	ScannerID uuid.UUID      // The unique identifier for the scanner
	GroupName string         // The group this scanner belongs to
	Name      string         // Human-readable name for the scanner
	Version   string         // Software version of the scanner
	Metadata  map[string]any // Additional metadata about the scanner
}

// NewCreateScannerCommand creates a new CreateScannerCommand.
func NewCreateScannerCommand(
	scannerID uuid.UUID,
	groupName string,
	name string,
	version string,
	metadata map[string]any,
) CreateScannerCommand {
	return CreateScannerCommand{
		ScannerID: scannerID,
		GroupName: groupName,
		Name:      name,
		Version:   version,
		Metadata:  metadata,
	}
}

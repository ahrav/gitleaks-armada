package scanning

import (
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// JobDetail represents a comprehensive view of a scan job, including its current state,
// metrics, and associated metadata. It is designed to provide all the information
// needed by API consumers to understand a job's progress and characteristics.
type JobDetail struct {
	// Core job identifiers.
	ID uuid.UUID
	// Name       string
	Status     JobStatus
	SourceType string
	// Metadata   map[string]string

	// Timing information.
	StartTime time.Time
	EndTime   *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time

	// Task progress metrics.
	Metrics *JobDetailMetrics
}

// JobDetailMetrics provides detailed information about task counts and progress.
// This is a value object specifically designed for API responses.
type JobDetailMetrics struct {
	TotalTasks      int
	PendingTasks    int
	InProgressTasks int
	CompletedTasks  int
	FailedTasks     int
	StaleTasks      int
	CancelledTasks  int
	PausedTasks     int

	// Derived progress indicators
	CompletionPercentage float64
}

// NewJobDetailFromJob creates a JobDetail from a Job and its metrics.
// This factory method ensures consistent construction and property mapping.
func NewJobDetailFromJob(job *Job, metrics *JobMetrics) *JobDetail {
	// Extract optional end time if present
	var endTimePtr *time.Time
	if endTime, hasEndTime := job.EndTime(); hasEndTime {
		endTimePtr = &endTime
	}

	// Calculate completion percentage.
	var completionPercentage float64
	if metrics.TotalTasks() > 0 {
		completionPercentage = float64(metrics.CompletedTasks()) / float64(metrics.TotalTasks()) * 100.0
	}

	return &JobDetail{
		ID:         job.JobID(),
		Status:     job.Status(),
		SourceType: job.SourceType(),
		StartTime:  job.StartTime(),
		EndTime:    endTimePtr,
		CreatedAt:  job.GetTimeline().StartedAt(),
		UpdatedAt:  job.GetTimeline().LastUpdate(),
		Metrics: &JobDetailMetrics{
			TotalTasks:           metrics.TotalTasks(),
			PendingTasks:         metrics.PendingTasks(),
			InProgressTasks:      metrics.InProgressTasks(),
			CompletedTasks:       metrics.CompletedTasks(),
			FailedTasks:          metrics.FailedTasks(),
			StaleTasks:           metrics.StaleTasks(),
			CancelledTasks:       metrics.CancelledTasks(),
			PausedTasks:          metrics.PausedTasks(),
			CompletionPercentage: completionPercentage,
		},
	}
}

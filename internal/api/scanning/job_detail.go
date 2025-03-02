package scanning

import (
	"encoding/json"
	"net/http"
	"time"

	scanDomain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
)

// JobDetail represents the API response for a scan job's details.
// It contains all the information needed to understand a job's progress and characteristics.
type JobDetail struct {
	// Core job identifiers.
	ID         string            `json:"id"`
	// Name       string            `json:"name,omitempty"`
	Status     string            `json:"status"`
	SourceType string            `json:"source_type"`
	// Metadata   map[string]string `json:"metadata,omitempty"`

	// Timing information.
	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`

	// Task progress metrics.
	TotalTasks           int     `json:"total_tasks"`
	PendingTasks         int     `json:"pending_tasks"`
	InProgressTasks      int     `json:"in_progress_tasks"`
	CompletedTasks       int     `json:"completed_tasks"`
	FailedTasks          int     `json:"failed_tasks"`
	StaleTasks           int     `json:"stale_tasks"`
	CancelledTasks       int     `json:"cancelled_tasks"`
	PausedTasks          int     `json:"paused_tasks"`
	CompletionPercentage float64 `json:"completion_percentage"`
}

// FromDomain creates an API JobDetail from a domain JobDetail.
// This mapper function ensures proper translation between domain model and API representation.
func FromDomain(domainJob *scanDomain.JobDetail) JobDetail {
	return JobDetail{
		ID:                   domainJob.ID.String(),
		// Name:                 domainJob.Name,
		Status:               domainJob.Status.String(),
		SourceType:           domainJob.SourceType,
		// Metadata:             domainJob.Metadata,
		StartTime:            domainJob.StartTime,
		EndTime:              domainJob.EndTime,
		CreatedAt:            domainJob.CreatedAt,
		UpdatedAt:            domainJob.UpdatedAt,
		TotalTasks:           domainJob.Metrics.TotalTasks,
		PendingTasks:         domainJob.Metrics.PendingTasks,
		InProgressTasks:      domainJob.Metrics.InProgressTasks,
		CompletedTasks:       domainJob.Metrics.CompletedTasks,
		FailedTasks:          domainJob.Metrics.FailedTasks,
		StaleTasks:           domainJob.Metrics.StaleTasks,
		CancelledTasks:       domainJob.Metrics.CancelledTasks,
		PausedTasks:          domainJob.Metrics.PausedTasks,
		CompletionPercentage: domainJob.Metrics.CompletionPercentage,
	}
}

// Encode implements the web.Encoder interface to serialize the job detail to JSON.
func (jd JobDetail) Encode() ([]byte, string, error) {
	data, err := json.Marshal(jd)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the web.HTTPStatusSetter interface to set the HTTP status code.
func (jd JobDetail) HTTPStatus() int {
	return http.StatusOK // 200 OK
}

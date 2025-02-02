package scanning

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
)

const (
	JobMetricsEntityType events.EntityType = "job_metrics"
)

// JobMetricsPosition represents a position in the job metrics stream.
// It is used to identify the position of a job in the job metrics stream.
type JobMetricsPosition struct {
	JobID     uuid.UUID
	Partition int32
	Offset    int64
}

// NewJobMetricsPosition creates a new JobMetricsPosition.
func NewJobMetricsPosition(jobID uuid.UUID, partition int32, offset int64) JobMetricsPosition {
	return JobMetricsPosition{JobID: jobID, Partition: partition, Offset: offset}
}

// EntityType returns the type of entity this position is for.
func (p JobMetricsPosition) EntityType() events.EntityType { return JobMetricsEntityType }

// EntityID returns a unique identifier for the position.
func (p JobMetricsPosition) EntityID() string { return fmt.Sprintf("%d:%d", p.Partition, p.Offset) }

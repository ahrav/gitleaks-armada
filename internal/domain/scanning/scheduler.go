package scanning

import (
	"context"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// JobScheduler coordinates the creation and orchestration of new jobs within the scanning
// domain. It ensures consistent job setup while allowing other parts of the system to
// react to newly scheduled work.
type JobScheduler interface {
	// Schedule creates a new job with the provided jobID and targets, then publishes
	// domain events to notify external services that the job was scheduled.
	Schedule(ctx context.Context, jobID uuid.UUID, targets []Target) error

	// Pause initiates the pausing of a job by transitioning it to the PAUSING state
	// and publishing a JobPausingEvent. The actual pause operation is handled asynchronously
	// by the job coordinator.
	Pause(ctx context.Context, jobID uuid.UUID, requestedBy string) error

	// Cancel initiates the cancellation of a job by transitioning it to the CANCELLING state
	// and publishing a JobCancelledEvent. The actual cancellation is handled asynchronously
	// by the JobMetricsTracker.
	Cancel(ctx context.Context, jobID uuid.UUID, requestedBy string) error
}

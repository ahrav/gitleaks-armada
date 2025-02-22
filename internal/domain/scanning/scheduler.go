package scanning

import (
	"context"

	"github.com/google/uuid"
)

type JobScheduler interface {
	Schedule(ctx context.Context, jobID uuid.UUID, targets []Target) error
}

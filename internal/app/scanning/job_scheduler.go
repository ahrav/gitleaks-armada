package scanning

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

var _ domain.JobScheduler = (*jobScheduler)(nil)

// jobScheduler coordinates the creation and orchestration of new jobs within the scanning
// domain. By delegating persistence to a JobTaskService and notifying external
// subscribers through domain events, it ensures consistent job setup while allowing
// other parts of the system to react to newly scheduled work.
type jobScheduler struct {
	controllerID string

	jobTaskService domain.JobTaskService
	publisher      events.DomainEventPublisher

	logger *logger.Logger
	tracer trace.Tracer
}

// NewJobScheduler returns a jobScheduler with the necessary dependencies for creating
// new jobs and distributing notifications about them.
func NewJobScheduler(
	controllerID string,
	jobTaskService domain.JobTaskService,
	publisher events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
) *jobScheduler {
	logger = logger.With("component", "job_scheduler")
	return &jobScheduler{
		controllerID:   controllerID,
		jobTaskService: jobTaskService,
		publisher:      publisher,
		logger:         logger,
		tracer:         tracer,
	}
}

// Schedule creates a new job with the provided jobID and targets, then publishes
// domain events to notify external services that the job was scheduled. This method
// can be extended to enforce additional domain rules or trigger further setup steps.
func (s *jobScheduler) Schedule(ctx context.Context, jobID uuid.UUID, targets []domain.Target) error {
	ctx, span := s.tracer.Start(ctx, "job_scheduler.schedule",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.Int("target_count", len(targets)),
		),
	)
	defer span.End()

	if err := s.jobTaskService.CreateJobFromID(ctx, jobID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return fmt.Errorf("failed to create job: %w", err)
	}
	span.AddEvent("job_created")
	span.SetStatus(codes.Ok, "job created successfully")

	for _, target := range targets {
		span.SetAttributes(
			attribute.String("target_name", target.Name()),
			attribute.String("target_source_type", target.SourceType().String()),
		)

		// Publish JobScheduledEvent with target information.
		// The target information is required by downstream consumers of the JobScheduledEvent
		// to link scan targets to a single scan job.
		evt := domain.NewJobScheduledEvent(jobID, target)
		if err := s.publisher.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to publish job scheduled event")
			return fmt.Errorf("failed to publish job scheduled event: %w", err)
		}
		span.AddEvent("job_scheduled_event_published")
		span.SetStatus(codes.Ok, "job scheduled event published successfully")
	}
	span.AddEvent("all_job_scheduled_events_published")
	span.SetStatus(codes.Ok, "all job scheduled events published successfully")

	return nil
}

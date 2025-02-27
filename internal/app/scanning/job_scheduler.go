package scanning

import (
	"context"
	"fmt"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
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

	jobTaskService     domain.JobTaskService
	publisher          events.DomainEventPublisher
	broadcastPublisher events.DomainEventPublisher // For broadcasting events to all scanners

	logger *logger.Logger
	tracer trace.Tracer
}

// NewJobScheduler returns a jobScheduler with the necessary dependencies for creating
// new jobs and distributing notifications about them.
func NewJobScheduler(
	controllerID string,
	jobTaskService domain.JobTaskService,
	publisher events.DomainEventPublisher,
	broadcastPublisher events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
) *jobScheduler {
	logger = logger.With("component", "job_scheduler")
	return &jobScheduler{
		controllerID:       controllerID,
		jobTaskService:     jobTaskService,
		publisher:          publisher,
		broadcastPublisher: broadcastPublisher,
		logger:             logger,
		tracer:             tracer,
	}
}

// Schedule creates a new job with the provided jobID and targets, then publishes
// domain events to notify external services that the job was scheduled. This method
// can be extended to enforce additional domain rules or trigger further setup steps.
func (s *jobScheduler) Schedule(ctx context.Context, jobID uuid.UUID, targets []domain.Target) error {
	logger := s.logger.With("operation", "schedule", "job_id", jobID)
	ctx, span := s.tracer.Start(ctx, "job_scheduler.schedule",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.Int("target_count", len(targets)),
		),
	)
	defer span.End()
	logger.Debug(ctx, "Scheduling job")

	if err := s.jobTaskService.CreateJobFromID(ctx, jobID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return fmt.Errorf("failed to create job (job_id: %s): %w", jobID, err)
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
		// TODO: Retry? Should we maybe move on to the next target if this fails?
		evt := domain.NewJobScheduledEvent(jobID, target)
		if err := s.publisher.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to publish job scheduled event")
			return fmt.Errorf("failed to publish job scheduled event (job_id: %s): %w", jobID, err)
		}
		span.AddEvent("job_scheduled_event_published")
		span.SetStatus(codes.Ok, "job scheduled event published successfully")
	}
	logger.Debug(ctx, "All job scheduled events published successfully")
	span.AddEvent("all_job_scheduled_events_published")
	span.SetStatus(codes.Ok, "all job scheduled events published successfully")

	return nil
}

// Pause initiates the pausing of a job by transitioning it to the PAUSED state
// and publishing a JobPausedEvent. The actual pause operation is handled asynchronously
// by the job coordinator.
func (s *jobScheduler) Pause(ctx context.Context, jobID uuid.UUID, requestedBy string) error {
	logger := s.logger.With("operation", "pause_job", "job_id", jobID)
	ctx, span := s.tracer.Start(ctx, "job_scheduler.pause_job",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()
	logger.Debug(ctx, "Pausing job")

	if err := s.jobTaskService.UpdateJobStatus(ctx, jobID, domain.JobStatusPausing); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status to paused")
		return fmt.Errorf("failed to update job status to paused (job_id: %s): %w", jobID, err)
	}
	span.AddEvent("job_status_updated_to_paused")

	evt := domain.NewJobPausedEvent(jobID.String(), requestedBy, "User requested pause")
	if err := s.broadcastPublisher.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish job paused event")
		return fmt.Errorf("failed to publish job paused event (job_id: %s): %w", jobID, err)
	}
	span.AddEvent("job_paused_event_published")
	span.SetStatus(codes.Ok, "job pause initiated successfully")

	return nil
}

// Cancel initiates the cancellation of a job by transitioning it to the CANCELLING state
// and publishing a JobCancelledEvent. The actual cancellation is handled asynchronously
// by the JobMetricsTracker.
func (s *jobScheduler) Cancel(ctx context.Context, jobID uuid.UUID, requestedBy string) error {
	logger := s.logger.With("operation", "cancel_job", "job_id", jobID)
	ctx, span := s.tracer.Start(ctx, "job_scheduler.cancel_job",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()
	logger.Debug(ctx, "Cancelling job")

	if err := s.jobTaskService.UpdateJobStatus(ctx, jobID, domain.JobStatusCancelling); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status to cancelling")
		return fmt.Errorf("failed to update job status to cancelling (job_id: %s): %w", jobID, err)
	}
	span.AddEvent("job_status_updated_to_cancelling")

	evt := domain.NewJobCancelledEvent(jobID.String(), requestedBy, "User requested cancellation")
	if err := s.broadcastPublisher.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish job cancelled event")
		return fmt.Errorf("failed to publish job cancelled event (job_id: %s): %w", jobID, err)
	}
	span.AddEvent("job_cancelled_event_published")
	span.SetStatus(codes.Ok, "job cancellation initiated successfully")

	return nil
}

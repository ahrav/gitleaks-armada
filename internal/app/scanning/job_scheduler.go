package scanning

import (
	"context"
	"encoding/json"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
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

	if len(targets) == 0 {
		span.AddEvent("no_targets_provided")
		span.SetStatus(codes.Error, "no targets provided")
		return fmt.Errorf("no targets provided")
	}

	config, err := marshalConfig(ctx, targets[0])
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to marshal target & auth config")
		return fmt.Errorf("failed to marshal target & auth config: %w", err)
	}

	// All the targets have the same source type, so we can use the first one.
	cmd := domain.NewCreateJobCommand(jobID, targets[0].SourceType().String(), config)

	if err := s.jobTaskService.CreateJob(ctx, cmd); err != nil {
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

// marshalConfig serializes the target & auth config for storage in the job.
func marshalConfig(ctx context.Context, target domain.Target) (json.RawMessage, error) {
	span := trace.SpanFromContext(ctx)
	completeConfig := struct {
		domain.Target
		Auth domain.Auth `json:"auth,omitempty"`
	}{Target: target}
	completeConfig.Auth = *target.Auth()

	data, err := json.Marshal(completeConfig)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal target & auth config: %w", err)
	}
	span.AddEvent("target_auth_config_marshalled")

	return data, nil
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

// Resume initiates the resumption of a job by transitioning it from PAUSED
// to RUNNING and publishing TaskResumeEvents for each paused task.
func (s *jobScheduler) Resume(ctx context.Context, jobID uuid.UUID, requestedBy string) error {
	logger := s.logger.With("operation", "resume_job", "job_id", jobID)
	ctx, span := s.tracer.Start(ctx, "job_scheduler.resume_job",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()
	logger.Debug(ctx, "Resuming job")

	var jobConfigInfo *domain.JobConfigInfo
	var auth domain.Auth
	var tasks []domain.ResumeTaskInfo

	// Concurrently retrieve job config info and tasks to resume
	// since they are independent of each other.
	// Bail out early if any of the operations fail.
	// TODO: Looks to make this a little more robust/ alert the user if
	// any of the operations fail.
	g, ctx := errgroup.WithContext(ctx)

	// Start job config retrieval.
	g.Go(func() error {
		var err error
		jobConfigInfo, err = s.jobTaskService.GetJobConfigInfo(ctx, jobID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to get job config info")
			return fmt.Errorf("failed to get job config information: %w", err)
		}

		span.AddEvent("job_config_info_retrieved", trace.WithAttributes(
			attribute.String("source_type", string(jobConfigInfo.SourceType())),
		))

		auth, err = domain.UnmarshalConfigAuth(jobConfigInfo.Config())
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to extract auth from job config")
			return fmt.Errorf("failed to extract auth from job config: %w", err)
		}

		span.AddEvent("auth_extracted_from_job_config", trace.WithAttributes(
			attribute.String("auth_type", string(auth.Type())),
		))

		return nil
	})

	// Start tasks retrieval.
	g.Go(func() error {
		var err error
		tasks, err = s.jobTaskService.GetTasksToResume(ctx, jobID)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to get tasks to resume")
			return fmt.Errorf("failed to get tasks to resume (job_id: %s): %w", jobID, err)
		}

		span.AddEvent("tasks_to_resume_retrieved", trace.WithAttributes(
			attribute.Int("task_count", len(tasks)),
		))

		return nil
	})

	if err := g.Wait(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to retrieve job config info and tasks to resume")
		return err // Error is already logged and recorded in span
	}

	// Publish resume events for each task.
	// TODO:  Maybe bulk publish these?
	for _, task := range tasks {
		resumeEvent := domain.NewTaskResumeEvent(
			jobID,
			task.TaskID(),
			task.SourceType(),
			task.ResourceURI(),
			int(task.SequenceNum()),
			task.Checkpoint(),
			auth,
		)

		if err := s.publisher.PublishDomainEvent(
			ctx, resumeEvent, events.WithKey(task.TaskID().String()),
		); err != nil {
			span.RecordError(err)
			// TODO: We need to figure out what to do if this fails.
			// Retry? Inform client? etc.
			logger.Error(ctx, "Failed to publish task resume event",
				"task_id", task.TaskID(),
				"error", err,
			)
			continue
		}

		span.AddEvent("task_resume_event_published", trace.WithAttributes(
			attribute.String("task_id", task.TaskID().String()),
		))
	}

	span.AddEvent("job_resumption_initiated")
	span.SetStatus(codes.Ok, "job resumption initiated successfully")

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

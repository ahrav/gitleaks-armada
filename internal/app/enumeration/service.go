package enumeration

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// enumMetrics tracks and records various metrics during the enumeration process.
// It provides methods to monitor performance, track progress, and measure errors
// during target processing and job creation.
type enumMetrics interface {
	// TrackEnumeration wraps an enumeration operation and tracks its execution
	TrackEnumeration(ctx context.Context, f func() error) error

	// IncTargetsProcessed increments the count of processed targets
	IncTargetsProcessed(ctx context.Context)

	// ObserveTargetProcessingTime records the duration taken to process a target
	ObserveTargetProcessingTime(ctx context.Context, duration time.Duration)

	// IncEnumerationStarted increments the count of started enumerations
	IncEnumerationStarted(ctx context.Context)

	// IncEnumerationCompleted increments the count of successfully completed enumerations
	IncEnumerationCompleted(ctx context.Context)

	// IncEnumerationErrors increments the count of enumeration failures
	IncEnumerationErrors(ctx context.Context)

	// ObserveEnumerationBatchSize records the size of target batches
	ObserveEnumerationBatchSize(ctx context.Context, size int)

	// ObserveTargetsPerJob records the number of targets discovered per job
	ObserveTargetsPerJob(ctx context.Context, count int)

	// IncJobsCreated increments the count of total jobs created
	IncJobsCreated(ctx context.Context)
}

var _ enumeration.Service = (*EnumService)(nil)

// EnumService coordinates the enumeration of targets by managing scan jobs,
// publishing events, and tracking metrics. It serves as the primary orchestrator
// for discovering and processing scan targets.
type EnumService struct {
	jobCoordinator  scanning.ScanJobCoordinator
	enumCoordinator Coordinator
	eventPublisher  events.DomainEventPublisher

	logger  *logger.Logger
	metrics enumMetrics
	tracer  trace.Tracer
}

// NewEnumService creates a new enumeration service with the required dependencies
// for coordinating scans, publishing events, and monitoring metrics.
func NewEnumService(
	scanningCoordinator scanning.ScanJobCoordinator,
	enumCoordinator Coordinator,
	eventPublisher events.DomainEventPublisher,
	logger *logger.Logger,
	metrics enumMetrics,
	tracer trace.Tracer,
) *EnumService {
	return &EnumService{
		jobCoordinator:  scanningCoordinator,
		enumCoordinator: enumCoordinator,
		eventPublisher:  eventPublisher,
		tracer:          tracer,
		logger:          logger,
		metrics:         metrics,
	}
}

// StartEnumeration initiates the enumeration process for a set of targets defined
// in the configuration. It creates scan jobs, processes targets concurrently, and
// handles the publishing of task events. The method ensures proper error handling
// and metric tracking throughout the enumeration lifecycle.
func (es *EnumService) StartEnumeration(ctx context.Context, cfg *config.Config) error {
	logger := es.logger.With("operation", "start_enumeration", "target_count", len(cfg.Targets))
	ctx, span := es.tracer.Start(ctx, "enum_service.start_enumeration",
		trace.WithAttributes(
			attribute.String("target_count", fmt.Sprintf("%d", len(cfg.Targets))),
		))
	defer span.End()
	es.metrics.IncEnumerationStarted(ctx)

	logger.Info(ctx, "Starting fresh enumerations")
	for _, target := range cfg.Targets {
		err := func() error {
			startTime := time.Now()
			targetCtx, targetSpan := es.tracer.Start(ctx, "enum_service.process_target",
				trace.WithAttributes(
					attribute.String("target_name", target.Name),
					attribute.String("target_type", string(target.SourceType)),
				))
			defer targetSpan.End()
			targetSpan.AddEvent("processing_target")

			job, err := es.jobCoordinator.CreateJob(targetCtx)
			if err != nil {
				// TODO: Revist this we can make this more resilient to allow for failures.
				es.metrics.IncEnumerationErrors(targetCtx)
				targetSpan.RecordError(err)
				return fmt.Errorf("failed to create job for target %s: %w", target.Name, err)
			}
			es.metrics.IncJobsCreated(targetCtx)

			// TODO: Maybe handle this in 2 goroutines?
			enumChannels := es.enumCoordinator.EnumerateTarget(targetCtx, target, cfg.Auth)

			done := false
			for !done {
				select {
				case <-targetCtx.Done():
					targetSpan.AddEvent("target_context_cancelled")
					done = true

				case scanTargetIDs, ok := <-enumChannels.ScanTargetCh:
					scanTargetIDCtx, scanTargetIDSpan := es.tracer.Start(targetCtx, "enum_service.handle_scan_target_ids")
					if !ok {
						scanTargetIDSpan.AddEvent("scan_target_ids_channel_closed")
						scanTargetIDSpan.SetStatus(codes.Ok, "scan target ids channel closed")
						enumChannels.ScanTargetCh = nil // channel closed
						continue
					}
					if err := es.jobCoordinator.LinkTargets(scanTargetIDCtx, job.JobID(), scanTargetIDs); err != nil {
						scanTargetIDSpan.RecordError(err)
						scanTargetIDSpan.SetStatus(codes.Error, "failed to associate scan targets")
						logger.Error(scanTargetIDCtx, "Failed to associate scan targets", "error", err)
					}

				case task, ok := <-enumChannels.TaskCh:
					if !ok {
						enumChannels.TaskCh = nil
						continue
					}

					taskCtx, taskSpan := es.tracer.Start(targetCtx, "enum_service.handle_task_created",
						trace.WithAttributes(
							attribute.String("task_id", task.ID.String()),
							attribute.String("job_id", job.JobID().String()),
						))

					if err := es.eventPublisher.PublishDomainEvent(
						taskCtx,
						enumeration.NewTaskCreatedEvent(job.JobID(), task),
						events.WithKey(task.ID.String()),
					); err != nil {
						taskSpan.RecordError(err)
						taskSpan.SetStatus(codes.Error, "failed to publish task event")
						logger.Error(taskCtx, "Failed to publish task event", "error", err)
					} else {
						taskSpan.AddEvent("task_event_published")
						taskSpan.SetStatus(codes.Ok, "task event published")
					}
					taskSpan.End()

				case err, ok := <-enumChannels.ErrCh:
					errCtx, errSpan := es.tracer.Start(targetCtx, "enum_service.handle_enumeration_error")
					if ok && err != nil {
						// We got an error from enumerator.
						es.metrics.IncEnumerationErrors(errCtx)
						errSpan.RecordError(err)
						errSpan.SetStatus(codes.Error, "enumeration error")
						logger.Error(errCtx, "Enumeration error", "error", err)
						done = true
					} else {
						enumChannels.ErrCh = nil
						errSpan.AddEvent("enumeration_error_channel_closed")
						errSpan.SetStatus(codes.Ok, "enumeration error channel closed")
					}
					errSpan.End()

				default:
					if enumChannels.ScanTargetCh == nil && enumChannels.TaskCh == nil && enumChannels.ErrCh == nil {
						done = true
					}
				}
			}

			duration := time.Since(startTime)
			es.metrics.ObserveTargetProcessingTime(targetCtx, duration)
			targetSpan.AddEvent("target_enumeration_completed", trace.WithAttributes(
				attribute.String("duration", duration.String()),
			))
			logger.Info(targetCtx, "Target enumeration completed", "duration", duration.String())
			targetSpan.SetStatus(codes.Ok, "target enumeration completed")
			targetSpan.End()

			return nil
		}()
		if err != nil {
			span.RecordError(err)
			return err
		}
	}

	span.AddEvent("fresh_enumeration_completed")
	return nil
}

// ResumeEnumeration implements logic to resume enumeration sessions.
// func (es *EnumService) ResumeEnumeration(ctx context.Context, states []*domain.SessionState) error {
// 	ctx, span := es.tracer.Start(ctx, "enum_service.resume_enumeration")
// 	defer span.End()

// 	es.logger.Info(ctx, "Resuming enumerations", "state_count", len(states))
// 	for _, state := range states {
// 		span.AddEvent("resuming_state", trace.WithAttributes(
// 			attribute.String("session_id", state.SessionID().String()),
// 		))
// 		// Re-create a scan job or use the existing job.
// 		if _, err := es.scanningCoordinator.CreateJob(ctx); err != nil {
// 			span.RecordError(err)
// 			es.logger.Error(ctx, "Failed to create job for state", "session", state.SessionID())
// 			return fmt.Errorf("failed to create job for state %s: %w", state.SessionID(), err)
// 		}
// 		span.AddEvent("state_enumeration_resumed", trace.WithAttributes(
// 			attribute.String("session_id", state.SessionID().String()),
// 		))
// 	}
// 	span.AddEvent("resume_enumeration_completed")
// 	return nil
// }

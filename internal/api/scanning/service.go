// Package scanning provides API services for scan operations.
package scanning

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/commands"
	"github.com/ahrav/gitleaks-armada/internal/app/commands/scanning"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	scanDomain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Service coordinates scan operations from the API layer.
type Service struct {
	cmdHandler commands.Handler
	eventBus   events.DomainEventPublisher

	// Read-only repository for querying scan jobs.
	scanJobQueryRepo scanDomain.ScanJobQueryRepository

	log    *logger.Logger
	tracer trace.Tracer
}

// NewService creates a new scan coordination service.
func NewService(
	cmdHandler commands.Handler,
	eventBus events.DomainEventPublisher,
	scanJobQueryRepo scanDomain.ScanJobQueryRepository,
	log *logger.Logger,
	tracer trace.Tracer,
) *Service {
	return &Service{
		cmdHandler:       cmdHandler,
		eventBus:         eventBus,
		scanJobQueryRepo: scanJobQueryRepo,
		log:              log.With("component", "scanning_service"),
		tracer:           tracer,
	}
}

// Target represents a single target for scanning.
type Target struct {
	// Common fields.
	Type       string
	SourceAuth *SourceAuth
	Metadata   map[string]string

	// GitHub-specific fields.
	Organization string
	Repositories []string
	// TODO: Add repository regex pattern.
	RepositoryPattern string

	// S3-specific fields.
	Bucket string
	Prefix string
	Region string

	// URL-specific fields.
	URLs          []string
	ArchiveFormat string
	RateLimit     float64
	Headers       map[string]string
}

// SourceAuth contains authentication information for a source.
type SourceAuth struct {
	Type        string
	Credentials map[string]any
}

// StartScan initiates scanning for the provided targets.
func (s *Service) StartScan(ctx context.Context, name string, targets []Target, metadata map[string]string, requestedBy string) ([]JobInfo, error) {
	ctx, span := s.tracer.Start(ctx, "scanning_service.start_scan",
		trace.WithAttributes(
			attribute.String("name", name),
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()

	var jobs []JobInfo

	// Create a separate job for each target.
	for _, t := range targets {
		jobID := uuid.New()
		tspan := trace.SpanFromContext(ctx)
		tspan.SetAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("target_type", t.Type),
		)

		tgt := s.buildTargetConfig(t)
		maps.Copy(tgt.Metadata, metadata)

		scanCfg := &config.Config{Targets: []config.TargetSpec{tgt}}
		cmd := scanning.NewStartScanCommand(jobID, scanCfg, requestedBy)
		if err := s.cmdHandler.Handle(ctx, cmd); err != nil {
			tspan.RecordError(err)
			tspan.SetStatus(codes.Error, "failed to handle scan command")
			return nil, fmt.Errorf("failed to handle scan command: %w", err)
		}
		tspan.AddEvent("scan_command_handled")
		tspan.SetStatus(codes.Ok, "scan command handled successfully")

		jobs = append(jobs, JobInfo{
			ID:         jobID.String(),
			Status:     scanDomain.JobStatusQueued.String(),
			TargetType: t.Type,
		})
	}
	span.AddEvent("scan_jobs_creation_started", trace.WithAttributes(
		attribute.Int("job_count", len(jobs)),
	))
	span.SetStatus(codes.Ok, "scan jobs creation started")

	return jobs, nil
}

// PauseJob pauses a running scan job.
func (s *Service) PauseJob(ctx context.Context, jobIDStr, requestedBy string) error {
	ctx, span := s.tracer.Start(ctx, "scanning_service.pause_job",
		trace.WithAttributes(
			attribute.String("job_id", jobIDStr),
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid job ID")
		return fmt.Errorf("invalid job ID: %w", err)
	}

	// Create and publish the JobPausingEvent.
	evt := scanDomain.NewJobPausingEvent(jobID.String(), requestedBy)
	if err := s.eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish pause event")
		return fmt.Errorf("failed to publish pause event: %w", err)
	}
	span.AddEvent("job_pausing_event_published")
	span.SetStatus(codes.Ok, "job pausing event published")

	return nil
}

// BulkPauseJobs pauses multiple running scan jobs.
func (s *Service) BulkPauseJobs(ctx context.Context, jobIDs []string, requestedBy string) ([]JobInfo, []error) {
	ctx, span := s.tracer.Start(ctx, "scanning_service.bulk_pause_jobs",
		trace.WithAttributes(
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()

	var jobs []JobInfo
	var errs []error

	for _, jobIDStr := range jobIDs {
		jspan := trace.SpanFromContext(ctx)
		jspan.SetAttributes(
			attribute.String("job_id", jobIDStr),
		)

		if err := s.PauseJob(ctx, jobIDStr, requestedBy); err != nil {
			jspan.RecordError(err)
			jspan.SetStatus(codes.Error, "failed to pause job")
			errs = append(errs, fmt.Errorf("job %s: %w", jobIDStr, err))
			continue
		}
		jspan.AddEvent("job_paused")
		jspan.SetStatus(codes.Ok, "job paused successfully")

		jobs = append(jobs, JobInfo{ID: jobIDStr, Status: scanDomain.JobStatusPausing.String()})
	}
	span.AddEvent("bulk_pause_jobs_completed", trace.WithAttributes(
		attribute.Int("job_count", len(jobs)),
	))
	span.SetStatus(codes.Ok, "bulk pause jobs completed")

	return jobs, errs
}

// ResumeJob resumes a paused scan job.
func (s *Service) ResumeJob(ctx context.Context, jobIDStr, requestedBy string) error {
	ctx, span := s.tracer.Start(ctx, "scanning_service.resume_job",
		trace.WithAttributes(
			attribute.String("job_id", jobIDStr),
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid job ID")
		return fmt.Errorf("invalid job ID: %w", err)
	}

	// Create and publish the JobResumingEvent.
	evt := scanDomain.NewJobResumingEvent(jobID.String(), requestedBy)
	if err := s.eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish resume event")
		return fmt.Errorf("failed to publish resume event: %w", err)
	}
	span.AddEvent("job_resuming_event_published")
	span.SetStatus(codes.Ok, "job resuming event published")

	return nil
}

// BulkResumeJobs resumes multiple paused scan jobs.
func (s *Service) BulkResumeJobs(ctx context.Context, jobIDs []string, requestedBy string) ([]JobInfo, []error) {
	ctx, span := s.tracer.Start(ctx, "scanning_service.bulk_resume_jobs",
		trace.WithAttributes(
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()

	var jobs []JobInfo
	var errs []error

	for _, jobIDStr := range jobIDs {
		jspan := trace.SpanFromContext(ctx)
		jspan.SetAttributes(
			attribute.String("job_id", jobIDStr),
		)

		if err := s.ResumeJob(ctx, jobIDStr, requestedBy); err != nil {
			jspan.RecordError(err)
			jspan.SetStatus(codes.Error, "failed to resume job")
			errs = append(errs, fmt.Errorf("job %s: %w", jobIDStr, err))
			continue
		}
		jspan.AddEvent("job_resumed")
		jspan.SetStatus(codes.Ok, "job resumed successfully")

		jobs = append(jobs, JobInfo{ID: jobIDStr, Status: scanDomain.JobStatusRunning.String()})
	}
	span.AddEvent("bulk_resume_jobs_completed", trace.WithAttributes(
		attribute.Int("job_count", len(jobs)),
	))
	span.SetStatus(codes.Ok, "bulk resume jobs completed")

	return jobs, errs
}

// CancelJob cancels a scan job.
func (s *Service) CancelJob(ctx context.Context, jobIDStr, reason string) error {
	ctx, span := s.tracer.Start(ctx, "scanning_service.cancel_job",
		trace.WithAttributes(
			attribute.String("job_id", jobIDStr),
			attribute.String("reason", reason),
		),
	)
	defer span.End()

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid job ID")
		return fmt.Errorf("invalid job ID format: %w", err)
	}

	// Create and publish the event to cancel the job.
	evt := scanDomain.NewJobCancellingEvent(jobIDStr, reason)
	err = s.eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String()))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to publish cancellation event")
		return fmt.Errorf("failed to publish cancellation event: %w", err)
	}
	span.AddEvent("job_cancelling_event_published")
	span.SetStatus(codes.Ok, "job cancelling event published")

	return nil
}

// BulkCancelJobs cancels multiple scan jobs.
func (s *Service) BulkCancelJobs(ctx context.Context, jobIDs []string, reason string) []JobInfo {
	ctx, span := s.tracer.Start(ctx, "scanning_service.bulk_cancel_jobs",
		trace.WithAttributes(
			attribute.String("reason", reason),
		),
	)
	defer span.End()

	var responses []JobInfo

	for _, jobIDStr := range jobIDs {
		jspan := trace.SpanFromContext(ctx)
		jspan.SetAttributes(
			attribute.String("job_id", jobIDStr),
		)

		err := s.CancelJob(ctx, jobIDStr, reason)
		if err != nil {
			jspan.RecordError(err)
			jspan.SetStatus(codes.Error, "failed to cancel job")
			responses = append(responses, JobInfo{ID: jobIDStr, Status: "ERROR"})
			continue
		}
		jspan.AddEvent("job_cancelled")
		jspan.SetStatus(codes.Ok, "job cancelled successfully")

		responses = append(responses, JobInfo{
			ID:     jobIDStr,
			Status: scanDomain.JobStatusCancelling.String(),
		})
	}
	span.AddEvent("bulk_cancel_jobs_completed", trace.WithAttributes(
		attribute.Int("job_count", len(responses)),
	))
	span.SetStatus(codes.Ok, "bulk cancel jobs completed")

	return responses
}

// buildTargetConfig converts a Target into a config.TargetSpec.
func (s *Service) buildTargetConfig(tr Target) config.TargetSpec {
	target := config.TargetSpec{
		Name:       tr.Type,
		SourceType: shared.ParseSourceType(tr.Type),
		Metadata:   tr.Metadata,
	}

	// Initialize metadata map if nil
	if target.Metadata == nil {
		target.Metadata = make(map[string]string)
	}

	// Set source authentication if provided
	if tr.SourceAuth != nil {
		target.SourceAuth = &config.AuthConfig{
			Type:        tr.SourceAuth.Type,
			Credentials: tr.SourceAuth.Credentials,
		}
	}

	// Switch over the target type
	switch shared.ParseSourceType(tr.Type) {
	case shared.SourceTypeGitHub:
		// Map GitHub-specific information.
		target.GitHub = &config.GitHubTarget{
			Org:      tr.Organization,
			RepoList: tr.Repositories,
			// TODO: Support repository regex pattern.
			// RepositoryPattern: tr.RepositoryPattern,
		}
	case shared.SourceTypeURL:
		// Map URL-specific information
		target.URL = &config.URLTarget{
			URLs:          tr.URLs,
			ArchiveFormat: config.ArchiveFormat(tr.ArchiveFormat),
			RateLimit:     tr.RateLimit,
			Headers:       tr.Headers,
		}

		if tr.ArchiveFormat != "" {
			target.Metadata["archive_format"] = tr.ArchiveFormat
		}
		if tr.RateLimit > 0 {
			target.Metadata["rate_limit"] = fmt.Sprintf("%f", tr.RateLimit)
		}
		for key, value := range tr.Headers {
			target.Metadata["header_"+key] = value
		}
	case shared.SourceTypeS3:
		// Map S3-specific information.
		target.S3 = &config.S3Target{
			Bucket: tr.Bucket,
			Prefix: tr.Prefix,
			Region: tr.Region,
		}
	}

	return target
}

// GetJob retrieves detailed information about a scan job.
// It returns job metadata, status, progress metrics, and timing information.
func (s *Service) GetJob(ctx context.Context, jobIDStr string) (*JobDetail, error) {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid job ID format: %w", err)
	}

	jobDetail, err := s.scanJobQueryRepo.GetJobByID(ctx, jobID)
	if err != nil {
		if errors.Is(err, scanDomain.ErrJobNotFound) {
			return nil, fmt.Errorf("job not found: %s", jobIDStr)
		}
		return nil, fmt.Errorf("failed to retrieve job details: %w", err)
	}

	apiJobDetail := FromDomain(jobDetail)
	return &apiJobDetail, nil
}

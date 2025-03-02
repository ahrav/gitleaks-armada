// Package scanning provides API services for scan operations.
package scanning

import (
	"context"
	"errors"
	"fmt"
	"maps"

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
	log        *logger.Logger
	cmdHandler commands.Handler
	eventBus   events.DomainEventPublisher

	// Read-only repository for querying scan jobs.
	scanJobQueryRepo scanDomain.ScanJobQueryRepository
}

// NewService creates a new scan coordination service.
func NewService(
	log *logger.Logger,
	cmdHandler commands.Handler,
	eventBus events.DomainEventPublisher,
	scanJobQueryRepo scanDomain.ScanJobQueryRepository,
) *Service {
	return &Service{
		log:              log,
		cmdHandler:       cmdHandler,
		eventBus:         eventBus,
		scanJobQueryRepo: scanJobQueryRepo,
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
	var jobs []JobInfo

	// Create a separate job for each target.
	for _, t := range targets {
		jobID := uuid.New()

		tgt := s.buildTargetConfig(t)
		maps.Copy(tgt.Metadata, metadata)

		scanCfg := &config.Config{Targets: []config.TargetSpec{tgt}}
		cmd := scanning.NewStartScanCommand(jobID, scanCfg, requestedBy)
		if err := s.cmdHandler.Handle(ctx, cmd); err != nil {
			return nil, fmt.Errorf("failed to handle scan command: %w", err)
		}

		jobs = append(jobs, JobInfo{
			ID:         jobID.String(),
			Status:     scanDomain.JobStatusQueued.String(),
			TargetType: t.Type,
		})
	}

	return jobs, nil
}

// PauseJob pauses a running scan job.
func (s *Service) PauseJob(ctx context.Context, jobIDStr, requestedBy string) error {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return fmt.Errorf("invalid job ID: %w", err)
	}

	// Create and publish the JobPausingEvent.
	evt := scanDomain.NewJobPausingEvent(jobID.String(), requestedBy)
	if err := s.eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		return fmt.Errorf("failed to publish pause event: %w", err)
	}

	return nil
}

// BulkPauseJobs pauses multiple running scan jobs.
func (s *Service) BulkPauseJobs(ctx context.Context, jobIDs []string, requestedBy string) ([]JobInfo, []error) {
	var jobs []JobInfo
	var errs []error

	for _, jobIDStr := range jobIDs {
		if err := s.PauseJob(ctx, jobIDStr, requestedBy); err != nil {
			errs = append(errs, fmt.Errorf("job %s: %w", jobIDStr, err))
			continue
		}

		jobs = append(jobs, JobInfo{ID: jobIDStr, Status: scanDomain.JobStatusPausing.String()})
	}

	return jobs, errs
}

// ResumeJob resumes a paused scan job.
func (s *Service) ResumeJob(ctx context.Context, jobIDStr, requestedBy string) error {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return fmt.Errorf("invalid job ID: %w", err)
	}

	// Create and publish the JobResumingEvent.
	evt := scanDomain.NewJobResumingEvent(jobID.String(), requestedBy)
	if err := s.eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		return fmt.Errorf("failed to publish resume event: %w", err)
	}

	return nil
}

// BulkResumeJobs resumes multiple paused scan jobs.
func (s *Service) BulkResumeJobs(ctx context.Context, jobIDs []string, requestedBy string) ([]JobInfo, []error) {
	var jobs []JobInfo
	var errs []error

	for _, jobIDStr := range jobIDs {
		if err := s.ResumeJob(ctx, jobIDStr, requestedBy); err != nil {
			errs = append(errs, fmt.Errorf("job %s: %w", jobIDStr, err))
			continue
		}

		jobs = append(jobs, JobInfo{ID: jobIDStr, Status: scanDomain.JobStatusRunning.String()})
	}

	return jobs, errs
}

// CancelJob cancels a scan job.
func (s *Service) CancelJob(ctx context.Context, jobIDStr, reason string) error {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return fmt.Errorf("invalid job ID format: %w", err)
	}

	// Create and publish the event to cancel the job.
	evt := scanDomain.NewJobCancellingEvent(jobIDStr, reason)
	err = s.eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String()))
	if err != nil {
		return fmt.Errorf("failed to publish cancellation event: %w", err)
	}

	return nil
}

// BulkCancelJobs cancels multiple scan jobs.
func (s *Service) BulkCancelJobs(ctx context.Context, jobIDs []string, reason string) []JobInfo {
	var responses []JobInfo

	for _, jobIDStr := range jobIDs {
		err := s.CancelJob(ctx, jobIDStr, reason)
		if err != nil {
			s.log.Warn(ctx, "Failed to cancel job", "job_id", jobIDStr, "error", err)
			responses = append(responses, JobInfo{ID: jobIDStr, Status: "ERROR"})
			continue
		}

		responses = append(responses, JobInfo{
			ID:     jobIDStr,
			Status: scanDomain.JobStatusCancelling.String(),
		})
	}

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

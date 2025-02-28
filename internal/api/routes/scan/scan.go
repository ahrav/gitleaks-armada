package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"maps"

	"github.com/ahrav/gitleaks-armada/internal/api/errs"
	"github.com/ahrav/gitleaks-armada/internal/app/commands"
	"github.com/ahrav/gitleaks-armada/internal/app/commands/scanning"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	scanDomain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	"github.com/ahrav/gitleaks-armada/pkg/web"
)

// Config contains the dependencies needed by the scan handlers.
type Config struct {
	Log        *logger.Logger
	CmdHandler commands.Handler
	EventBus   events.DomainEventPublisher
}

// Routes binds all the scan endpoints.
func Routes(app *web.App, cfg Config) {
	app.HandlerFunc(http.MethodPost, "", "/v1/scan", start(cfg))
	// TODO: Handle users pausing multiple times. (error, ignore, etc...)
	app.HandlerFunc(http.MethodPost, "", "/v1/scan/{id}/pause", pause(cfg))
	app.HandlerFunc(http.MethodPost, "", "/v1/scan/bulk/pause", bulkPause(cfg))
	app.HandlerFunc(http.MethodPost, "", "/v1/scan/{id}/resume", resume(cfg))
	app.HandlerFunc(http.MethodPost, "", "/v1/scan/bulk/resume", bulkResume(cfg))
	app.HandlerFunc(http.MethodPost, "", "/v1/scan/{id}/cancel", cancel(cfg))
	app.HandlerFunc(http.MethodPost, "", "/v1/scan/bulk/cancel", bulkCancel(cfg))
	// app.HandlerFunc(http.MethodGet, "", "/v1/scan/:id", status(cfg))
}

// TODO: Add sanitization, etc...

// startRequest represents the payload for starting a scan with multiple targets.
type startRequest struct {
	Name     string            `json:"name,omitempty"` // Optional, user-friendly name.
	Targets  []targetRequest   `json:"targets" validate:"required,dive"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// targetRequest represents a single target for scanning.
type targetRequest struct {
	// Common fields.
	Type       string      `json:"type" validate:"required,oneof=github s3 url"`
	SourceAuth *sourceAuth `json:"source_auth,omitempty"`
	// TODO: Look to potentially limit size of metadata.
	Metadata map[string]string `json:"metadata,omitempty"`

	// GitHub-specific fields.
	Organization string   `json:"organization,omitempty"`
	Repositories []string `json:"repositories,omitempty"`
	// TODO: Add repository regex pattern.
	RepositoryPattern string `json:"repository_pattern,omitempty"`

	// S3-specific fields.
	Bucket string `json:"bucket,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Region string `json:"region,omitempty"`

	// URL-specific fields.
	URLs          []string          `json:"urls,omitempty"`
	ArchiveFormat string            `json:"archive_format,omitempty" validate:"omitempty,oneof=none gzip tar.gz zip warc.gz auto"`
	RateLimit     float64           `json:"rate_limit,omitempty" validate:"omitempty,min=0"`
	Headers       map[string]string `json:"headers,omitempty"`
	// TODO: Add retry config.
}

// sourceAuth remains unchanged.
type sourceAuth struct {
	Type        string         `json:"type" validate:"required,oneof=none basic token oauth aws"`
	Credentials map[string]any `json:"credentials"`
}

// startResponse represents the response for starting a scan.
type startResponse struct {
	Jobs []JobInfo `json:"jobs"` // List of created jobs
}

// JobInfo contains information about a created job.
type JobInfo struct {
	ID         string `json:"id"`          // The job ID
	Status     string `json:"status"`      // Current status
	TargetType string `json:"target_type"` // Type of target for this job
}

// Encode implements the web.Encoder interface.
func (sr startResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(sr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (sr startResponse) HTTPStatus() int { return http.StatusAccepted } // 202

// TODO: Add tests, I keep breaking this shit..... :(
func start(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		var req startRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if err := errs.Check(req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		var jobs []JobInfo
		// Create a separate job for each target.
		for _, t := range req.Targets {
			jobID := uuid.New()

			tgt := buildTargetConfig(t)
			maps.Copy(tgt.Metadata, req.Metadata)

			scanCfg := &config.Config{Targets: []config.TargetSpec{tgt}}
			cmd := scanning.NewStartScanCommand(jobID, scanCfg, "system") // TODO: Use JWT user instead of "system" if available.
			if err := cfg.CmdHandler.Handle(ctx, cmd); err != nil {
				return errs.New(errs.Internal, err)
			}

			jobs = append(jobs, JobInfo{
				ID:         jobID.String(),
				Status:     scanDomain.JobStatusQueued.String(),
				TargetType: t.Type,
			})
		}

		return startResponse{Jobs: jobs}
	}
}

// buildTargetConfig converts a targetRequest into a config.TargetSpec.
func buildTargetConfig(tr targetRequest) config.TargetSpec {
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

// pauseRequest represents the payload for pausing a scan.
type pauseRequest struct {
	Reason string `json:"reason,omitempty"`
}

// pauseResponse represents the response for pausing a scan.
type pauseResponse struct {
	ID     string `json:"id"`     // The job ID
	Status string `json:"status"` // Current status
}

// Encode implements the web.Encoder interface.
func (pr pauseResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(pr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (pr pauseResponse) HTTPStatus() int { return http.StatusAccepted } // 202

// pause handles the request to pause a scan job.
func pause(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		jobIDStr := web.Param(r, "id")

		var req pauseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			return errs.New(errs.InvalidArgument, err)
		}

		response, err := pauseJob(ctx, jobIDStr, cfg.EventBus)
		if err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		return response
	}
}

// bulkPauseRequest represents the payload for pausing multiple scans.
type bulkPauseRequest struct {
	JobIDs []string `json:"job_ids" validate:"required,dive,uuid4"`
	Reason string   `json:"reason,omitempty"`
}

// bulkPauseResponse represents the response for pausing multiple scans.
type bulkPauseResponse struct {
	Jobs []pauseResponse `json:"jobs"`
}

// Encode implements the web.Encoder interface.
func (bpr bulkPauseResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(bpr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (bpr bulkPauseResponse) HTTPStatus() int { return http.StatusAccepted } // 202

const maxBulkJobCount = 500

// bulkPause handles the request to pause multiple scan jobs.
func bulkPause(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		var req bulkPauseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if err := errs.Check(req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if len(req.JobIDs) > maxBulkJobCount {
			return errs.New(errs.InvalidArgument, fmt.Errorf("too many job IDs: maximum allowed is %d", maxBulkJobCount))
		}

		var responses []pauseResponse
		var processingErrors []error

		for _, jobIDStr := range req.JobIDs {
			response, err := pauseJob(ctx, jobIDStr, cfg.EventBus)
			if err != nil {
				processingErrors = append(processingErrors, fmt.Errorf("job %s: %w", jobIDStr, err))
				continue
			}
			responses = append(responses, response)
		}

		// If there were any errors but we still have some successful responses,
		// log the errors but still return the successful responses.
		if len(processingErrors) > 0 && len(responses) > 0 {
			// Log errors but continue with partial success
			errMsg := fmt.Sprintf("Failed to pause %d out of %d jobs",
				len(processingErrors), len(req.JobIDs))
			cfg.Log.Error(ctx, errMsg, "errors", processingErrors)
		} else if len(processingErrors) > 0 {
			// If all jobs failed, return an error
			return errs.New(errs.InvalidArgument, fmt.Errorf("failed to pause any jobs: %v", processingErrors))
		}

		return bulkPauseResponse{Jobs: responses}
	}
}

// pauseJob handles the logic for pausing a single job and returns its response.
// This is a helper function used by both single and bulk pause endpoints.
func pauseJob(ctx context.Context, jobIDStr string, eventBus events.DomainEventPublisher) (pauseResponse, error) {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return pauseResponse{}, fmt.Errorf("invalid job ID: %w", err)
	}

	// Create and publish the JobPausingEvent.
	evt := scanDomain.NewJobPausingEvent(jobID.String(), "system") // TODO: Use JWT user instead of "system" if available.
	if err := eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		return pauseResponse{}, fmt.Errorf("failed to publish pause event: %w", err)
	}

	return pauseResponse{ID: jobID.String(), Status: scanDomain.JobStatusPausing.String()}, nil
}

// resumeRequest represents the payload for resuming a scan.
type resumeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// resumeResponse represents the response for resuming a scan.
type resumeResponse struct {
	ID     string `json:"id"`     // The job ID
	Status string `json:"status"` // Current status
}

// Encode implements the web.Encoder interface.
func (rr resumeResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(rr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (rr resumeResponse) HTTPStatus() int { return http.StatusAccepted } // 202

// resume handles the request to resume a scan job.
func resume(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		jobIDStr := web.Param(r, "id")

		var req resumeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			return errs.New(errs.InvalidArgument, err)
		}

		response, err := resumeJob(ctx, jobIDStr, cfg.EventBus)
		if err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		return response
	}
}

// bulkResumeRequest represents the payload for resuming multiple scans.
type bulkResumeRequest struct {
	JobIDs []string `json:"job_ids" validate:"required,dive,uuid4"`
	Reason string   `json:"reason,omitempty"`
}

// bulkResumeResponse represents the response for resuming multiple scans.
type bulkResumeResponse struct {
	Jobs []resumeResponse `json:"jobs"`
}

// Encode implements the web.Encoder interface.
func (bpr bulkResumeResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(bpr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (bpr bulkResumeResponse) HTTPStatus() int { return http.StatusAccepted } // 202

// bulkResume handles the request to resume multiple scan jobs.
func bulkResume(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		var req bulkResumeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if err := errs.Check(req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if len(req.JobIDs) > maxBulkJobCount {
			return errs.New(errs.InvalidArgument, fmt.Errorf("too many job IDs: maximum allowed is %d", maxBulkJobCount))
		}

		var responses []resumeResponse
		var processingErrors []error

		for _, jobIDStr := range req.JobIDs {
			response, err := resumeJob(ctx, jobIDStr, cfg.EventBus)
			if err != nil {
				processingErrors = append(processingErrors, fmt.Errorf("job %s: %w", jobIDStr, err))
				continue
			}
			responses = append(responses, response)
		}

		// If there were any errors but we still have some successful responses,
		// log the errors but still return the successful responses.
		if len(processingErrors) > 0 && len(responses) > 0 {
			// Log errors but continue with partial success.
			errMsg := fmt.Sprintf("Failed to resume %d out of %d jobs",
				len(processingErrors), len(req.JobIDs))
			cfg.Log.Error(ctx, errMsg, "errors", processingErrors)
		} else if len(processingErrors) > 0 {
			// If all jobs failed, return an error.
			return errs.New(errs.InvalidArgument, fmt.Errorf("failed to resume any jobs: %v", processingErrors))
		}

		return bulkResumeResponse{Jobs: responses}
	}
}

// resumeJob handles the logic for resuming a single job and returns its response.
// This is a helper function used by both single and bulk resume endpoints.
func resumeJob(ctx context.Context, jobIDStr string, eventBus events.DomainEventPublisher) (resumeResponse, error) {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return resumeResponse{}, fmt.Errorf("invalid job ID: %w", err)
	}

	// Create and publish the JobResumingEvent.
	evt := scanDomain.NewJobResumingEvent(jobID.String(), "system") // TODO: Use JWT user instead of "system" if available.
	if err := eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
		return resumeResponse{}, fmt.Errorf("failed to publish resume event: %w", err)
	}

	return resumeResponse{ID: jobID.String(), Status: scanDomain.JobStatusRunning.String()}, nil
}

// cancelRequest represents the payload for cancelling a scan.
type cancelRequest struct {
	Reason string `json:"reason,omitempty"`
}

// cancelResponse represents the response for cancelling a scan.
type cancelResponse struct {
	ID     string `json:"id"`     // The job ID
	Status string `json:"status"` // Current status
}

// Encode implements the web.Encoder interface.
func (cr cancelResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(cr)
	if err != nil {
		return nil, "", err
	}

	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (cr cancelResponse) HTTPStatus() int { return http.StatusAccepted } // 202

// cancel handles the request to cancel a scan job.
func cancel(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		jobIDStr := web.Param(r, "id")

		var req cancelRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			return errs.New(errs.InvalidArgument, err)
		}

		response, err := cancelJob(ctx, jobIDStr, cfg.EventBus)
		if err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		return response
	}
}

// bulkCancelRequest represents the payload for cancelling multiple scans.
type bulkCancelRequest struct {
	JobIDs []string `json:"job_ids" validate:"required,dive,uuid4"`
	Reason string   `json:"reason,omitempty"`
}

// bulkCancelResponse represents the response for cancelling multiple scans.
type bulkCancelResponse struct {
	Jobs []cancelResponse `json:"jobs"`
}

// Encode implements the web.Encoder interface.
func (bcr bulkCancelResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(bcr)
	if err != nil {
		return nil, "", err
	}

	return data, "application/json", nil
}

// HTTPStatus implements the httpStatus interface to set the response status code.
func (bcr bulkCancelResponse) HTTPStatus() int { return http.StatusAccepted } // 202

// bulkCancel handles the request to cancel multiple scan jobs.
func bulkCancel(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		var req bulkCancelRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if err := errs.Check(req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if len(req.JobIDs) > maxBulkJobCount {
			return errs.New(errs.InvalidArgument, fmt.Errorf("too many job IDs: maximum allowed is %d", maxBulkJobCount))
		}

		var responses []cancelResponse
		for _, jobIDStr := range req.JobIDs {
			response, err := cancelJob(ctx, jobIDStr, cfg.EventBus)
			if err != nil {
				cfg.Log.Warn(ctx, "Failed to cancel job", "job_id", jobIDStr, "error", err)
				responses = append(responses, cancelResponse{
					ID:     jobIDStr,
					Status: "ERROR", // Provide an error status
				})
				continue
			}
			responses = append(responses, response)
		}

		return bulkCancelResponse{Jobs: responses}
	}
}

// cancelJob handles the logic of cancelling a single job and returns a response.
func cancelJob(ctx context.Context, jobIDStr string, eventBus events.DomainEventPublisher) (cancelResponse, error) {
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return cancelResponse{}, fmt.Errorf("invalid job ID format: %w", err)
	}

	// Create and publish the event to cancel the job.
	evt := scanDomain.NewJobCancellingEvent(jobIDStr, "User requested cancellation")
	err = eventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String()))
	if err != nil {
		return cancelResponse{}, fmt.Errorf("failed to publish cancellation event: %w", err)
	}

	return cancelResponse{
		ID:     jobIDStr,
		Status: scanDomain.JobStatusCancelling.String(),
	}, nil
}

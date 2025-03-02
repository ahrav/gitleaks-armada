package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ahrav/gitleaks-armada/internal/api/errs"
	scanDomain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/web"
)

// Config contains the dependencies needed by the scan handlers.
type Config struct {
	Log         *logger.Logger
	ScanService *Service
}

// Routes binds all the scan endpoints.
func Routes(app *web.App, cfg Config) {
	const version = "v1"

	app.HandlerFunc(http.MethodPost, version, "/scan", start(cfg))
	// TODO: Handle users pausing multiple times. (error, ignore, etc...)
	app.HandlerFunc(http.MethodPost, version, "/scan/{id}/pause", pause(cfg))
	app.HandlerFunc(http.MethodPost, version, "/scan/bulk/pause", bulkPause(cfg))
	app.HandlerFunc(http.MethodPost, version, "/scan/{id}/resume", resume(cfg))
	app.HandlerFunc(http.MethodPost, version, "/scan/bulk/resume", bulkResume(cfg))
	app.HandlerFunc(http.MethodPost, version, "/scan/{id}/cancel", cancel(cfg))
	app.HandlerFunc(http.MethodPost, version, "/scan/bulk/cancel", bulkCancel(cfg))
	// app.HandlerFunc(http.MethodGet, "", "/v1/scan/:id", status(cfg))
	app.HandlerFunc(http.MethodGet, version, "/scan/{id}", getJob(cfg))
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

// start handles the request to start a scan.
func start(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		var req startRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if err := errs.Check(req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		targets := make([]Target, 0, len(req.Targets))
		for _, t := range req.Targets {
			targets = append(targets, convertToServiceTarget(t))
		}

		jobs, err := cfg.ScanService.StartScan(ctx, req.Name, targets, req.Metadata, "system") // TODO: Use JWT user instead of "system"
		if err != nil {
			return errs.New(errs.Internal, err)
		}

		return startResponse{Jobs: jobs}
	}
}

// convertToServiceTarget converts an API target request to a service Target.
func convertToServiceTarget(t targetRequest) Target {
	var auth *SourceAuth
	if t.SourceAuth != nil {
		auth = &SourceAuth{
			Type:        t.SourceAuth.Type,
			Credentials: t.SourceAuth.Credentials,
		}
	}

	return Target{
		Type:              t.Type,
		SourceAuth:        auth,
		Metadata:          t.Metadata,
		Organization:      t.Organization,
		Repositories:      t.Repositories,
		RepositoryPattern: t.RepositoryPattern,
		Bucket:            t.Bucket,
		Prefix:            t.Prefix,
		Region:            t.Region,
		URLs:              t.URLs,
		ArchiveFormat:     t.ArchiveFormat,
		RateLimit:         t.RateLimit,
		Headers:           t.Headers,
	}
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

		if err := cfg.ScanService.PauseJob(ctx, jobIDStr, "system"); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		return pauseResponse{ID: jobIDStr, Status: scanDomain.JobStatusPausing.String()}
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

		jobs, processingErrors := cfg.ScanService.BulkPauseJobs(ctx, req.JobIDs, "system")

		// If there were any errors but we still have some successful responses,
		// log the errors but still return the successful responses.
		if len(processingErrors) > 0 && len(jobs) > 0 {
			// Log errors but continue with partial success
			errMsg := fmt.Sprintf("Failed to pause %d out of %d jobs",
				len(processingErrors), len(req.JobIDs))
			cfg.Log.Error(ctx, errMsg, "errors", processingErrors)
		} else if len(processingErrors) > 0 {
			// If all jobs failed, return an error.
			return errs.New(errs.InvalidArgument, fmt.Errorf("failed to pause any jobs: %v", processingErrors))
		}

		var responses []pauseResponse
		for _, job := range jobs {
			responses = append(responses, pauseResponse{
				ID:     job.ID,
				Status: job.Status,
			})
		}

		return bulkPauseResponse{Jobs: responses}
	}
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

		if err := cfg.ScanService.ResumeJob(ctx, jobIDStr, "system"); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		return resumeResponse{ID: jobIDStr, Status: scanDomain.JobStatusRunning.String()}
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

		jobs, processingErrors := cfg.ScanService.BulkResumeJobs(ctx, req.JobIDs, "system")

		// If there were any errors but we still have some successful responses,
		// log the errors but still return the successful responses.
		if len(processingErrors) > 0 && len(jobs) > 0 {
			// Log errors but continue with partial success.
			errMsg := fmt.Sprintf("Failed to resume %d out of %d jobs",
				len(processingErrors), len(req.JobIDs))
			cfg.Log.Error(ctx, errMsg, "errors", processingErrors)
		} else if len(processingErrors) > 0 {
			// If all jobs failed, return an error.
			return errs.New(errs.InvalidArgument, fmt.Errorf("failed to resume any jobs: %v", processingErrors))
		}

		var responses []resumeResponse
		for _, job := range jobs {
			responses = append(responses, resumeResponse{ID: job.ID, Status: job.Status})
		}

		return bulkResumeResponse{Jobs: responses}
	}
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

		// Call service to cancel job
		if err := cfg.ScanService.CancelJob(ctx, jobIDStr, req.Reason); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		return cancelResponse{ID: jobIDStr, Status: scanDomain.JobStatusCancelling.String()}
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

		responses := cfg.ScanService.BulkCancelJobs(ctx, req.JobIDs, req.Reason)

		var cancelResponses []cancelResponse
		for _, job := range responses {
			cancelResponses = append(cancelResponses, cancelResponse{ID: job.ID, Status: job.Status})
		}

		return bulkCancelResponse{Jobs: cancelResponses}
	}
}

// getJob handles the request to get job details by ID.
func getJob(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		jobID := web.Param(r, "id")

		jobDetail, err := cfg.ScanService.GetJob(ctx, jobID)
		if err != nil {
			if errors.Is(err, scanDomain.ErrJobNotFound) {
				return errs.New(errs.NotFound, fmt.Errorf("job not found: %s", jobID))
			}
			return errs.New(errs.Internal, fmt.Errorf("failed to retrieve job details: %w", err))
		}

		return jobDetail
	}
}

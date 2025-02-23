package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/api/errs"
	"github.com/ahrav/gitleaks-armada/internal/app/commands"
	"github.com/ahrav/gitleaks-armada/internal/app/commands/scanning"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	scanDomain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
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
	// TODO: Think through how we want to handle pausing a scan multiple times. (error, ignore, etc...)
	app.HandlerFunc(http.MethodPost, "", "/v1/scan/{id}/pause", pause(cfg))
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
			for k, v := range req.Metadata {
				tgt.Metadata[k] = v
			}

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
		jobID, err := uuid.Parse(web.Param(r, "id"))
		if err != nil {
			return errs.New(errs.InvalidArgument, fmt.Errorf("invalid job ID: %w", err))
		}

		var req pauseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			return errs.New(errs.InvalidArgument, err)
		}

		// Create and publish the JobPausingEvent
		evt := scanDomain.NewJobPausingEvent(jobID.String(), "system") // TODO: Use JWT user instead of "system" if available.
		if err := cfg.EventBus.PublishDomainEvent(ctx, evt, events.WithKey(jobID.String())); err != nil {
			return errs.New(errs.Internal, fmt.Errorf("failed to publish pause event: %w", err))
		}

		return pauseResponse{
			ID:     jobID.String(),
			Status: scanDomain.JobStatusPausing.String(),
		}
	}
}

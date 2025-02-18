package scan

import (
	"context"
	"encoding/json"
	"net/http"

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
	ID     string `json:"id"`     // The job ID
	Status string `json:"status"` // Current status (e.g., "queued")
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

		// Build a list of target configurations from the API request
		// and merge global metadata from the request if needed.
		var targets []config.TargetSpec
		for _, t := range req.Targets {
			tgt := buildTargetConfig(t)
			tgt.Metadata = req.Metadata
			targets = append(targets, tgt)
		}

		// Create scan configuration with multiple targets.
		scanCfg := &config.Config{Targets: targets}
		job := scanDomain.NewJob()
		cmd := scanning.NewStartScanCommand(job.JobID(), scanCfg, "system") // TODO: Use JWT user instead of "system" if available.
		if err := cfg.CmdHandler.Handle(ctx, cmd); err != nil {
			return errs.New(errs.Internal, err)
		}

		return startResponse{
			ID:     job.JobID().String(),
			Status: job.Status().String(),
		}
	}
}

// buildTargetConfig converts a targetRequest into a config.TargetSpec.
func buildTargetConfig(tr targetRequest) config.TargetSpec {
	target := config.TargetSpec{
		Name:       tr.Type,
		SourceType: shared.ParseSourceType(tr.Type),
		Metadata:   tr.Metadata,
	}

	// Set source authentication if provided.
	if tr.SourceAuth != nil {
		target.SourceAuth = &config.AuthConfig{
			Type:        tr.SourceAuth.Type,
			Credentials: tr.SourceAuth.Credentials,
		}
	}

	// Switch over the target type.
	switch shared.ParseSourceType(tr.Type) {
	case shared.SourceTypeGitHub:
		// Map GitHub-specific information.
		target.GitHub = &config.GitHubTarget{
			RepoList: tr.Repositories,
			// TODO: Support repository regex pattern.
			// RepositoryPattern: tr.RepositoryPattern,
		}
	case shared.SourceTypeURL:
		// Map URL-specific information.
		target.URL = &config.URLTarget{
			URLs:          tr.URLs,
			ArchiveFormat: config.ArchiveFormat(tr.ArchiveFormat),
			RateLimit:     tr.RateLimit,
			Headers:       tr.Headers,
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

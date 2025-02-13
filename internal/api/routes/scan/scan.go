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
	app.HandlerFunc(http.MethodGet, "", "/v1/scan/:id", status(cfg))
}

// startRequest represents the request payload for starting a scan.
type startRequest struct {
	Name       string `json:"name" validate:"required"`
	SourceType string `json:"source_type" validate:"required,oneof=github s3 url"`

	// Authentication (optional)
	AuthType   string         `json:"auth_type,omitempty"`
	AuthConfig map[string]any `json:"auth_config,omitempty"`

	// Source-specific configurations
	URLs          []string          `json:"urls,omitempty"`
	ArchiveFormat string            `json:"archive_format,omitempty"`
	RateLimit     float64           `json:"rate_limit,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`

	// GitHub-specific fields
	Organization string   `json:"organization,omitempty"`
	Repositories []string `json:"repositories,omitempty"`

	// S3-specific fields
	Bucket string `json:"bucket,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Region string `json:"region,omitempty"`

	// Common options
	RetryConfig *config.RetryConfig `json:"retry,omitempty"`
	Metadata    map[string]string   `json:"metadata,omitempty"`
}

// startResponse represents the response for starting a scan.
type startResponse struct {
	Message string `json:"message"`
}

// Encode implements the web.Encoder interface.
func (sr startResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(sr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// statusResponse represents the response for scan status.
type statusResponse struct {
	Status string `json:"status"`
}

// Encode implements the web.Encoder interface.
func (sr statusResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(sr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

func start(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		var req startRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		if err := errs.Check(req); err != nil {
			return errs.New(errs.InvalidArgument, err)
		}

		// Transform API request to internal config structure.
		target := config.TargetSpec{
			Name:       req.Name,
			SourceType: config.SourceType(req.SourceType),
		}

		switch req.SourceType {
		case "url":
			target.URL = &config.URLTarget{
				URLs:          req.URLs,
				ArchiveFormat: config.ArchiveFormat(req.ArchiveFormat),
				RateLimit:     req.RateLimit,
				Headers:       req.Headers,
				RetryConfig:   req.RetryConfig,
				Metadata:      req.Metadata,
			}
		case "github":
			target.GitHub = &config.GitHubTarget{
				Org:      req.Organization,
				RepoList: req.Repositories,
				Metadata: req.Metadata,
			}
			// TODO: Add support for other source types.
		}

		var auth config.AuthConfig
		if req.AuthType != "" {
			auth = config.AuthConfig{
				Type:   req.AuthType,
				Config: req.AuthConfig,
			}
		}

		// TODO: Get user information from JWT claims once implemented.
		requestedBy := "system" // Placeholder until JWT implementation.

		cmd := scanning.NewStartScan(req.Name, config.SourceType(req.SourceType), auth, target, requestedBy)

		if err := cfg.CmdHandler.Handle(ctx, cmd); err != nil {
			return errs.New(errs.Internal, err)
		}

		return startResponse{
			Message: "scan started",
		}
	}
}

func status(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		return statusResponse{
			Status: "in_progress", // Placeholder
		}
	}
}

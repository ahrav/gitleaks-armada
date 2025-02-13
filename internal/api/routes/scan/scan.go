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
	Name        string            `json:"name" validate:"required"`
	SourceType  config.SourceType `json:"source_type" validate:"required"`
	Target      config.TargetSpec `json:"target" validate:"required"`
	Auth        config.AuthConfig `json:"auth"`
	RequestedBy string            `json:"requested_by"`
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

		cmd := scanning.NewStartScan(req.Name, req.SourceType, req.Auth, req.Target, req.RequestedBy)

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

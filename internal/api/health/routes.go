package health

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/web"
)

// Config contains all the mandatory systems required by handlers.
type Config struct {
	Build string
	Log   *logger.Logger
}

// Routes binds all the health check endpoints.
func Routes(app *web.App, cfg Config) {
	const version = "v1"

	app.HandlerFuncNoMid(http.MethodGet, version, "/liveness", liveness(cfg))
	app.HandlerFuncNoMid(http.MethodGet, version, "/readiness", readiness(cfg))
}

// healthResponse represents the response for health check.
type healthResponse struct {
	Status string `json:"status"`
	Build  string `json:"build"`
}

// Encode implements the web.Encoder interface.
func (hr healthResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(hr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

func liveness(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		return healthResponse{
			Status: "ok",
			Build:  cfg.Build,
		}
	}
}

// readyResponse represents the response for readiness check.
type readyResponse struct {
	Status string `json:"status"`
}

// Encode implements the web.Encoder interface.
func (rr readyResponse) Encode() ([]byte, string, error) {
	data, err := json.Marshal(rr)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json", nil
}

// TODO: This is lame and doesn't really do anything.
// Update this to ping the DB to confirm readiness.
func readiness(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		return readyResponse{
			Status: "ready",
		}
	}
}

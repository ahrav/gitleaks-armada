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
	app.HandlerFunc(http.MethodGet, "", "/v1/health", check(cfg))
	app.HandlerFunc(http.MethodGet, "", "/v1/readiness", readiness(cfg))
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

func check(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		return healthResponse{
			Status: "ok",
			Build:  cfg.Build,
		}
	}
}

func readiness(cfg Config) web.HandlerFunc {
	return func(ctx context.Context, r *http.Request) web.Encoder {
		return readyResponse{
			Status: "ready",
		}
	}
}

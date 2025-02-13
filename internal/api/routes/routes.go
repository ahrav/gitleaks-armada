package routes

import (
	"github.com/ahrav/gitleaks-armada/internal/api/mux"
	"github.com/ahrav/gitleaks-armada/internal/api/routes/health"
	"github.com/ahrav/gitleaks-armada/internal/api/routes/scan"
	"github.com/ahrav/gitleaks-armada/pkg/web"
)

// Routes constructs an add value which provides the implementation of
// RouteAdder for specifying what routes to bind to this instance.
func Routes() add {
	return add{}
}

type add struct{}

// Add implements the RouteAdder interface.
func (add) Add(app *web.App, cfg mux.Config) {
	// Health check routes
	health.Routes(app, health.Config{
		Build: cfg.Build,
		Log:   cfg.Log,
	})

	// Scan routes
	scan.Routes(app, scan.Config{
		Log:        cfg.Log,
		EventBus:   cfg.EventBus,
		CmdHandler: cfg.CmdHandler,
	})
}

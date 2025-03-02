package routes

import (
	"github.com/ahrav/gitleaks-armada/internal/api/mux"
	"github.com/ahrav/gitleaks-armada/internal/api/routes/health"
	"github.com/ahrav/gitleaks-armada/internal/api/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/web"
)

// Routes constructs an add value which provides the implementation of
// RouteAdder for specifying what routes to bind to this instance.
func Routes() add { return add{} }

// add is a type that implements the RouteAdder interface.
type add struct{}

// Add implements the RouteAdder interface by registering all application routes.
// It creates domain-specific configurations from the centralized Config.
func (add) Add(app *web.App, cfg mux.Config) {
	// Health check routes.
	health.Routes(app, health.Config{Build: cfg.Build, Log: cfg.Log})

	scanService := scanning.NewService(cfg.Log, cfg.CmdHandler, cfg.EventBus, cfg.JobStore)
	// Scan routes.
	scanning.Routes(app, scanning.Config{
		Log:         cfg.Log,
		ScanService: scanService,
	})
}

package routes

import (
	"github.com/ahrav/gitleaks-armada/internal/api/health"
	"github.com/ahrav/gitleaks-armada/internal/api/mux"
	"github.com/ahrav/gitleaks-armada/internal/api/scanning"
	scanningStore "github.com/ahrav/gitleaks-armada/internal/infra/storage/scanning/postgres"
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

	scanJobRepo := scanningStore.NewJobStore(cfg.DB, cfg.Tracer)
	scanService := scanning.NewService(cfg.Log, cfg.CmdHandler, cfg.EventBus, scanJobRepo)
	// Scan routes.
	scanning.Routes(app, scanning.Config{
		Log:         cfg.Log,
		ScanService: scanService,
	})

	// Scanner routes.
	scannerService := scanning.NewScannerService(cfg.Log, cfg.ScannerService)
	scanning.ScannerRoutes(app, scanning.ScannerConfig{
		Log:            cfg.Log,
		ScannerService: scannerService,
	})
}

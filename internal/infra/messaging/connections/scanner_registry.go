package connections

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GatewayMetrics interface defines metrics collected by the gateway service.
type GatewayMetrics interface {
	// Connection metrics.
	IncConnectedScanners(ctx context.Context)
	DecConnectedScanners(ctx context.Context)
	SetConnectedScanners(ctx context.Context, count int)
}

// ScannerRegistry manages the collection of connected scanners.
// It provides thread-safe operations for registering, accessing, and removing scanners.
//
// The registry maintains a mapping between scanner IDs and their connection state,
// enabling efficient lookup and management of scanner connections. It includes metrics
// tracking to monitor the number of active connections.
//
// All operations are thread-safe, using read-write locks to balance concurrent
// access with write protection. This allows for efficient reads when accessing
// scanner information while ensuring consistent state during modifications.
type ScannerRegistry struct {
	mu       sync.RWMutex
	scanners map[string]*ScannerConnection
	metrics  GatewayMetrics
}

// NewScannerRegistry creates a new scanner registry.
func NewScannerRegistry(metrics GatewayMetrics) *ScannerRegistry {
	return &ScannerRegistry{scanners: make(map[string]*ScannerConnection), metrics: metrics}
}

// Register adds a scanner connection to the registry.
// If a scanner with the same ID already exists, it will be replaced.
// This call always succeeds.
func (r *ScannerRegistry) Register(ctx context.Context, scannerID string, conn *ScannerConnection) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("scanner_id", scannerID))
	span.AddEvent("registering_scanner")

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.scanners[scannerID]; exists {
		span.AddEvent("scanner_already_registered")
	}

	r.scanners[scannerID] = conn
	span.AddEvent("scanner_registered")

	r.metrics.IncConnectedScanners(ctx)
	r.metrics.SetConnectedScanners(ctx, len(r.scanners))
}

// Unregister removes a scanner connection from the registry.
// Returns true if the scanner was found and removed, false otherwise.
func (r *ScannerRegistry) Unregister(ctx context.Context, scannerID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.String("scanner_id", scannerID))
	span.AddEvent("unregistering_scanner")

	if _, exists := r.scanners[scannerID]; !exists {
		span.AddEvent("scanner_not_found")
		return false
	}

	delete(r.scanners, scannerID)
	span.AddEvent("scanner_unregistered")

	r.metrics.DecConnectedScanners(ctx)
	r.metrics.SetConnectedScanners(ctx, len(r.scanners))

	return true
}

// Get retrieves a scanner connection by ID.
// Returns the connection and true if found, nil and false otherwise.
func (r *ScannerRegistry) Get(scannerID string) (*ScannerConnection, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	conn, exists := r.scanners[scannerID]
	return conn, exists
}

// Count returns the number of registered scanners.
func (r *ScannerRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.scanners)
}

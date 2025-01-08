// Package common provides shared utilities for the system.
package common

import (
	"log"
	"net/http"
	"sync/atomic"
)

// HealthServer implements health check endpoints for Kubernetes probes.
// It provides both readiness and liveness check endpoints that help
// Kubernetes determine the service's availability status.
type HealthServer struct {
	ready  *atomic.Bool // Indicates if the service is ready to receive traffic
	server *http.Server
}

// NewHealthServer creates and starts a new health check server on port 8080.
// The ready parameter controls the readiness probe response - when false,
// the readiness endpoint will return 503 Service Unavailable.
func NewHealthServer(ready *atomic.Bool) *HealthServer {
	mux := http.NewServeMux()
	server := &http.Server{Addr: ":8080", Handler: mux}
	hs := &HealthServer{
		ready:  ready,
		server: server,
	}

	mux.HandleFunc("/v1/readiness", hs.readinessHandler)
	mux.HandleFunc("/v1/health", hs.healthHandler)

	// Start server in background goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health server error: %v", err)
		}
	}()

	return hs
}

// readinessHandler responds to readiness probe requests based on the ready flag.
// Returns 503 if not ready, 200 if ready.
func (h *HealthServer) readinessHandler(w http.ResponseWriter, r *http.Request) {
	if !h.ready.Load() {
		http.Error(w, "Not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// healthHandler responds to liveness probe requests.
// Always returns 200 OK as long as the server is running.
func (h *HealthServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Server returns the underlying http.Server instance.
// This allows the caller to properly shut down the server when needed.
func (h *HealthServer) Server() *http.Server { return h.server }

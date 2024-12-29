package common

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RunMetricsServer starts the metrics HTTP server.
func RunMetricsServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(addr, mux)
}

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/commands"
	"github.com/ahrav/gitleaks-armada/internal/app/commands/scanning"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
)

type Server struct {
	cfg        *config.Config
	logger     *logger.Logger
	router     *http.ServeMux
	cmdHandler commands.Handler
	tracer     trace.Tracer
	eventBus   events.DomainEventPublisher
}

func NewServer(cfg *config.Config, log *logger.Logger, tracer trace.Tracer, eventBus events.DomainEventPublisher) (*Server, error) {
	cmdHandler := scanning.NewCommandHandler(log, tracer, eventBus)

	mux := http.NewServeMux()

	s := &Server{
		cfg:        cfg,
		logger:     log,
		router:     mux,
		cmdHandler: cmdHandler,
		tracer:     tracer,
		eventBus:   eventBus,
	}

	wrappedMux := applyMiddleware(mux,
		withRequestID,
		withRealIP,
		withTracing(tracer),
		withLogging(log),
		withRecoverer,
	)

	s.router = wrappedMux
	s.routes()
	return s, nil
}

type middleware func(http.Handler) http.Handler

func applyMiddleware(h http.Handler, middlewares ...middleware) *http.ServeMux {
	wrappedMux := http.NewServeMux()

	for _, m := range middlewares {
		h = m(h)
	}

	return wrappedMux
}

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		ctx := context.WithValue(r.Context(), "request_id", requestID)
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			r.RemoteAddr = realIP
		}
		next.ServeHTTP(w, r)
	})
}

func withTracing(tracer trace.Tracer) middleware {
	return func(next http.Handler) http.Handler {
		return otel.Middleware(tracer)(next)
	}
}

func withLogging(log *logger.Logger) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rw, r)

			log.Info(r.Context(), "http request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"duration", time.Since(start),
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

func withRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Printf("panic recovered: %v\n", err)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// responseWriter is a custom ResponseWriter that captures the status code
type responseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code before writing it
func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (s *Server) routes() {
	s.router.HandleFunc("/v1/health", s.handleHealth)
	s.router.HandleFunc("/v1/readiness", s.handleReadiness)
	s.router.HandleFunc("/v1/scans", s.handleStartScan)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string            `json:"name"`
		SourceType  config.SourceType `json:"source_type"`
		Target      config.TargetSpec `json:"target"`
		Auth        config.AuthConfig `json:"auth"`
		RequestedBy string            `json:"requested_by"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error(r.Context(), "failed to decode request", "error", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	cmd := scanning.NewStartScan(
		req.Name,
		req.SourceType,
		req.Auth,
		req.Target,
		req.RequestedBy,
	)

	if err := s.cmdHandler.Handle(r.Context(), cmd); err != nil {
		s.logger.Error(r.Context(), "failed to handle command", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", s.cfg.API.Host, s.cfg.API.Port),
		Handler: s.router,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			s.logger.Error(shutdownCtx, "failed to shutdown server", "error", err)
		}
	}()

	s.logger.Info(ctx, "starting server",
		"addr", server.Addr,
		"service", "api-gateway",
	)

	return server.ListenAndServe()
}

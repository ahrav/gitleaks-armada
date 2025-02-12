package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	router     *chi.Mux
	cmdHandler commands.Handler
	tracer     trace.Tracer
	eventBus   events.DomainEventPublisher
}

func NewServer(cfg *config.Config, log *logger.Logger, tracer trace.Tracer, eventBus events.DomainEventPublisher) (*Server, error) {
	cmdHandler := scanning.NewCommandHandler(log, tracer, eventBus)

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(otel.Middleware(tracer))
	r.Use(loggerMiddleware(log))
	r.Use(middleware.Recoverer)

	s := &Server{
		cfg:        cfg,
		logger:     log,
		router:     r,
		cmdHandler: cmdHandler,
		tracer:     tracer,
		eventBus:   eventBus,
	}

	s.routes()
	return s, nil
}

func loggerMiddleware(log *logger.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				ctx := r.Context()
				log.Info(ctx, "Request completed",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"duration", time.Since(start),
					"trace_id", otel.GetTraceID(ctx),
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

func (s *Server) routes() {
	s.router.Route("/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/readiness", s.handleReadiness)

		// Scan endpoints
		r.Post("/scans", s.handleStartScan)
		// Other endpoints as needed
	})
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

package scanning

import (
	"context"
	"maps"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/timeutil"
)

// ScannerHeartbeatManager handles periodic heartbeat signals for a scanner.
// It monitors scanner health and reports metrics to the system, ensuring
// the orchestrator knows which scanners are available and functional.
type ScannerHeartbeatManager struct {
	scannerID string

	scannerMetrics map[string]float64 // Custom metrics specific to this scanner instance
	eventPublisher events.DomainEventPublisher
	interval       time.Duration
	timeProvider   timeutil.Provider

	logger *logger.Logger
	tracer trace.Tracer
}

// NewScannerHeartbeatManager creates a new heartbeat manager for monitoring scanner health.
// It configures the manager with required dependencies and initializes internal state.
func NewScannerHeartbeatManager(
	scannerID string,
	eventPublisher events.DomainEventPublisher,
	logger *logger.Logger,
	tracer trace.Tracer,
) *ScannerHeartbeatManager {
	return &ScannerHeartbeatManager{
		scannerID:      scannerID,
		eventPublisher: eventPublisher,
		interval:       10 * time.Second, // Default interval, could be made configurable
		logger:         logger.With("component", "scanner_heartbeat"),
		tracer:         tracer,
		scannerMetrics: make(map[string]float64),
		timeProvider:   timeutil.Default(),
	}
}

// Start begins sending periodic heartbeats until context is cancelled.
// It sends an initial heartbeat immediately and then continues at the configured interval.
// Heartbeats include system metrics and custom scanner metrics to provide health status.
func (s *ScannerHeartbeatManager) Start(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "scanner_heartbeat.start")
	s.logger.Info(ctx, "Starting scanner heartbeat manager", "scanner_id", s.scannerID)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Send initial heartbeat immediately rather than waiting for first tick.
	if err := s.sendHeartbeat(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	span.End()

	for {
		ctx, span := s.tracer.Start(ctx, "scanner_heartbeat.send")
		select {
		case <-ticker.C:
			if err := s.sendHeartbeat(ctx); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				s.logger.Error(ctx, "Failed to send heartbeat", "error", err)
			}
			span.AddEvent("heartbeat_sent")
			span.End()
		case <-ctx.Done():
			span.SetStatus(codes.Error, ctx.Err().Error())
			span.RecordError(ctx.Err())
			s.logger.Info(ctx, "Stopping scanner heartbeat manager", "scanner_id", s.scannerID)
			span.End()
			return ctx.Err()
		}
	}
}

// UpdateMetrics allows updating scanner-specific metrics that will be included in heartbeats.
// These metrics supplement the standard system metrics to provide additional insights
// into scanner performance and status.
func (s *ScannerHeartbeatManager) UpdateMetrics(key string, value float64) {
	s.scannerMetrics[key] = value
}

// sendHeartbeat publishes a heartbeat event with current system and custom metrics.
func (s *ScannerHeartbeatManager) sendHeartbeat(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "scanner_heartbeat.send",
		trace.WithAttributes(
			attribute.String("scanner_id", s.scannerID),
		))
	defer span.End()

	metrics := map[string]float64{
		"memory_usage":   getMemoryUsage(),
		"cpu_usage":      getCPUUsage(),
		"active_tasks":   getActiveTasks(),
		"queue_depth":    getQueueDepth(),
		"uptime_seconds": getUptimeSeconds(),
	}

	// Merge in any custom metrics provided by the scanner.
	maps.Copy(metrics, s.scannerMetrics)

	event := scanning.NewScannerHeartbeatEvent(
		s.scannerID,
		scanning.ScannerStatusOnline,
		metrics,
	)

	err := s.eventPublisher.PublishDomainEvent(ctx, event,
		events.WithKey(s.scannerID))
	if err != nil {
		span.RecordError(err)
		return err
	}

	s.logger.Debug(ctx, "Scanner heartbeat sent", "scanner_id", s.scannerID, "timestamp", s.timeProvider.Now())
	return nil
}

// Helper functions to collect system metrics
func getMemoryUsage() float64 {
	// Implement memory usage collection
	return 0.0
}

func getCPUUsage() float64 {
	// Implement CPU usage collection
	return 0.0
}

func getActiveTasks() float64 {
	// Get number of active tasks
	return 0.0
}

func getQueueDepth() float64 {
	// Get current queue depth
	return 0.0
}

func getUptimeSeconds() float64 {
	// Get scanner uptime
	return 0.0
}

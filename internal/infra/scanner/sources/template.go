package sources

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/scanning"
	"github.com/ahrav/gitleaks-armada/internal/app/scanning/dtos"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// TemplateOptions holds configuration for a scanning operation, including
// the name of the top-level trace span, any desired span attributes,
// and the heartbeat interval.
type TemplateOptions struct {
	OperationName       string
	OperationAttributes []attribute.KeyValue
	HeartbeatInterval   time.Duration
}

// ScanTemplate provides a reusable way to run streaming scans with channels,
// heartbeats, metrics, and top-level tracing. Centralizing concurrency here
// helps each scanner remain focused on its core scanning logic.
type ScanTemplate struct {
	tracer  trace.Tracer
	logger  *logger.Logger
	metrics scanning.SourceScanMetrics
}

// NewScanTemplate constructs a ScanTemplate with shared dependencies.
// By injecting tracer, logger, and metrics here, each scan can use them
// consistently while avoiding duplication of setup.
func NewScanTemplate(
	tracer trace.Tracer,
	logger *logger.Logger,
	metrics scanning.SourceScanMetrics,
) *ScanTemplate {
	return &ScanTemplate{
		tracer:  tracer,
		logger:  logger,
		metrics: metrics,
	}
}

// ScanStreaming sets up the channels, manages context cancellation, and
// runs a scanner-specific function. It emits heartbeats regularly and
// observes total scan duration for metrics.
//
// This function returns three channels:
//   - heartbeatChan: signals the scanner is still active
//   - findingsChan:  conveys discovered items
//   - errChan:       carries any errors encountered during scanning
//
// The scanFn callback supplies the specialized scanning steps (e.g., clone a repo or fetch a URL).
func (st *ScanTemplate) ScanStreaming(
	ctx context.Context,
	task *dtos.ScanRequest,
	opts TemplateOptions,
	reporter scanning.ProgressReporter,
	scanFn func(ctx context.Context, task *dtos.ScanRequest, findingsChan chan<- scanning.Finding, reporter scanning.ProgressReporter) error,
) (<-chan struct{}, <-chan scanning.Finding, <-chan error) {
	heartbeatChan := make(chan struct{}, 1)
	findingsChan := make(chan scanning.Finding, 1)
	errChan := make(chan error, 1)

	go func() {
		defer close(heartbeatChan)
		defer close(findingsChan)
		defer close(errChan)

		ctx, span := st.tracer.Start(
			ctx,
			opts.OperationName,
			trace.WithAttributes(opts.OperationAttributes...),
		)
		startTime := time.Now()
		defer func() {
			span.End() // Ensure the top-level span always closes
			st.metrics.ObserveScanDuration(ctx, shared.SourceType(task.SourceType), time.Since(startTime))
		}()

		scanComplete := make(chan error, 1)
		go func() {
			defer close(scanComplete)
			scanComplete <- scanFn(ctx, task, findingsChan, reporter)
		}()

		ticker := time.NewTicker(opts.HeartbeatInterval)
		defer ticker.Stop()

		// Send a heartbeat as soon as we start the scan.
		heartbeatChan <- struct{}{}

		for {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			case <-ticker.C:
				// Non-blocking send to avoid a backlog if the consumer is slow.
				select {
				case heartbeatChan <- struct{}{}:
				default:
				}
			case err := <-scanComplete:
				if err != nil {
					errChan <- err
				}
				return
			}
		}
	}()

	return heartbeatChan, findingsChan, errChan
}

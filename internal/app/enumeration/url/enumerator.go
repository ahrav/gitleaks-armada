package url

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	enumeration "github.com/ahrav/gitleaks-armada/internal/app/enumeration/shared"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

var _ enumeration.TargetEnumerator = new(Enumerator)

// Enumerator enumerates a list of URLs from config or some external source.
// It supports configuration-based URL lists and maintains proper error handling
// and observability.
type Enumerator struct {
	controllerID string

	urlConfig *domain.URLTargetSpec

	logger *logger.Logger
	tracer trace.Tracer
}

// NewEnumerator constructs a new enumerator for URL-based enumeration with
// configured logging and tracing.
func NewEnumerator(
	controllerID string,
	urlConfig *domain.URLTargetSpec,
	logger *logger.Logger,
	tracer trace.Tracer,
) *Enumerator {
	return &Enumerator{
		controllerID: controllerID,
		urlConfig:    urlConfig,
		logger:       logger.With("component", "url_enumerator"),
		tracer:       tracer,
	}
}

// Enumerate streams target information for each URL in urlConfig.URLs via batchCh.
// It validates input configuration and creates appropriate metadata for each URL target.
func (e *Enumerator) Enumerate(
	ctx context.Context,
	startCursor *string,
	batchCh chan<- enumeration.EnumerateBatch,
) error {
	logger := e.logger.With(
		"operation", "enumerate",
		"url_count", len(e.urlConfig.URLs),
	)
	ctx, span := e.tracer.Start(ctx, "url_enumerator.enumerate",
		trace.WithAttributes(
			attribute.String("controller_id", e.controllerID),
			attribute.Int("url_count", len(e.urlConfig.URLs)),
			attribute.String("archive_format", string(e.urlConfig.ArchiveFormat)),
			attribute.Float64("rate_limit", e.urlConfig.RateLimit),
		),
	)
	defer span.End()

	if err := e.validateConfig(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid configuration")
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	targets, err := e.createTargets(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create targets")
		return fmt.Errorf("target creation failed: %w", err)
	}

	batchCh <- enumeration.EnumerateBatch{
		Targets:    targets,
		NextCursor: "", // No pagination for URL enumeration
	}

	span.AddEvent("targets_sent", trace.WithAttributes(
		attribute.Int("target_count", len(targets)),
	))
	logger.Info(ctx, "URL targets enumerated successfully",
		"target_count", len(targets),
	)

	span.SetStatus(codes.Ok, "URL targets enumerated successfully")
	return nil
}

func (e *Enumerator) validateConfig() error {
	if len(e.urlConfig.URLs) == 0 {
		return fmt.Errorf("no URLs provided in configuration")
	}

	for i, url := range e.urlConfig.URLs {
		if url == "" {
			return fmt.Errorf("empty URL found at index %d", i)
		}
	}

	return nil
}

// createTargets generates target information for each configured URL.
func (e *Enumerator) createTargets(ctx context.Context) ([]*enumeration.TargetInfo, error) {
	logger := e.logger.With("operation", "create_targets")
	ctx, span := e.tracer.Start(ctx, "url_enumerator.create_targets",
		trace.WithAttributes(
			attribute.String("controller_id", e.controllerID),
			attribute.Int("url_count", len(e.urlConfig.URLs)),
		),
	)
	defer span.End()

	targets := make([]*enumeration.TargetInfo, 0, len(e.urlConfig.URLs))
	for _, url := range e.urlConfig.URLs {
		meta := buildTargetMetadata(e.urlConfig)
		targets = append(targets, &enumeration.TargetInfo{
			TargetType:  shared.TargetTypeURL,
			ResourceURI: url,
			Metadata:    meta,
		})
	}

	span.AddEvent("targets_created", trace.WithAttributes(
		attribute.Int("target_count", len(targets)),
	))
	logger.Debug(ctx, "Created URL targets",
		"target_count", len(targets),
	)

	return targets, nil
}

// buildTargetMetadata creates metadata for a URL target including archive format,
// rate limits, and other configuration parameters.
func buildTargetMetadata(cfg *domain.URLTargetSpec) map[string]string {
	meta := make(map[string]string)

	if cfg.ArchiveFormat != "" {
		meta["archive_format"] = string(cfg.ArchiveFormat)
	}

	if cfg.RateLimit > 0 {
		meta["rate_limit"] = fmt.Sprintf("%f", cfg.RateLimit)
	}

	// Add headers if configured.
	for key, value := range cfg.Headers {
		meta["header_"+key] = value
	}

	return meta
}

package url

import (
	"context"
	"fmt"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	enumeration "github.com/ahrav/gitleaks-armada/internal/app/enumeration/shared"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// Enumerator enumerates a list of URLs from config or some external source.
type Enumerator struct {
	urlConfig *config.URLTarget
	tracer    trace.Tracer
}

// NewEnumerator constructs a new enumerator for URL-based enumeration.
func NewEnumerator(urlConfig *config.URLTarget, tracer trace.Tracer) *Enumerator {
	return &Enumerator{
		urlConfig: urlConfig,
		tracer:    tracer,
	}
}

// Enumerate streams target information for each URL in urlConfig.URLs via batchCh.
func (e *Enumerator) Enumerate(
	ctx context.Context,
	startCursor *string,
	batchCh chan<- enumeration.EnumerateBatch,
) error {
	_, span := e.tracer.Start(ctx, "url_enumerator.enumeration.enumerate",
		trace.WithAttributes(
			attribute.String("url_count", strconv.Itoa(len(e.urlConfig.URLs))),
		))
	defer span.End()

	targets := make([]*enumeration.TargetInfo, 0, len(e.urlConfig.URLs))

	for _, u := range e.urlConfig.URLs {
		// Construct metadata with archive format, headers, etc., if relevant.
		meta := make(map[string]string)
		if e.urlConfig.ArchiveFormat != "" {
			meta["archive_format"] = string(e.urlConfig.ArchiveFormat)
		}
		if e.urlConfig.RateLimit > 0 {
			meta["rate_limit"] = fmt.Sprintf("%f", e.urlConfig.RateLimit)
		}
		// TODO: Flatten headers, etc. into metadata as needed

		targets = append(targets, &enumeration.TargetInfo{
			TargetType:  shared.TargetTypeURL,
			ResourceURI: u,
			Metadata:    meta,
		})
	}
	span.AddEvent("targets_created")

	batchCh <- enumeration.EnumerateBatch{
		Targets:    targets,
		NextCursor: "", // No further pagination
	}
	span.AddEvent("targets_sent")

	return nil
}

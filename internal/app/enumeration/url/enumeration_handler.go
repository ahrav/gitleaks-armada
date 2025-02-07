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

// Ensure urlPersistence satisfies ResourcePersister
var _ enumeration.ResourcePersister = (*urlPersistence)(nil)

// urlPersistence implements ResourcePersister for URL-based targets.
// It coordinates domain-level creation and updates of URLTarget aggregates.
type urlPersistence struct {
	controllerID string

	urlRepo domain.URLRepository

	logger *logger.Logger
	tracer trace.Tracer
}

// NewURLPersistence constructs a new urlPersistence instance.
func NewURLPersistence(
	controllerID string,
	urlRepo domain.URLRepository,
	logger *logger.Logger,
	tracer trace.Tracer,
) *urlPersistence {
	logger = logger.With("component", "url_persistence_handler")
	return &urlPersistence{
		controllerID: controllerID,
		urlRepo:      urlRepo,
		logger:       logger,
		tracer:       tracer,
	}
}

// Persist creates or updates a URLTarget based on the provided ResourceEntry.
// It enforces idempotency by checking for an existing URLTarget (by URL) before creating
// a new one. For an existing target, it updates the URL or metadata if needed.
func (p *urlPersistence) Persist(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (enumeration.ResourceUpsertResult, error) {
	logger := p.logger.With(
		"operation", "persist",
		"resource_url", item.URL,
		"resource_name", item.Name,
	)
	ctx, span := p.tracer.Start(ctx, "url_persistence.persist",
		trace.WithAttributes(
			attribute.String("controller_id", p.controllerID),
			attribute.String("resource_name", item.Name),
			attribute.String("resource_url", item.URL),
		))
	defer span.End()

	if item.URL == "" {
		err := fmt.Errorf("empty URL provided")
		span.SetStatus(codes.Error, "empty URL provided")
		span.RecordError(err)
		return enumeration.EmptyResourceUpsertResult, err
	}

	existing, err := p.urlRepo.GetByURL(ctx, item.URL)
	if err != nil {
		span.SetStatus(codes.Error, "failed to get URLTarget by URL")
		return enumeration.EmptyResourceUpsertResult, fmt.Errorf("failed to query URL target: %w", err)
	}

	var urlTarget *domain.URLTarget
	if existing != nil {
		span.AddEvent("existing_url_target_found", trace.WithAttributes(
			attribute.Int64("url_target_id", existing.ID()),
		))
		logger.Debug(ctx, "Found existing URL target",
			"url_target_id", existing.ID(),
		)
		urlTarget, err = p.updateExistingURLTarget(ctx, existing, item)
	} else {
		span.AddEvent("creating_new_url_target")
		logger.Debug(ctx, "Creating new URL target")
		urlTarget, err = p.createNewURLTarget(ctx, item)
	}

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist URL target")
		return enumeration.EmptyResourceUpsertResult, fmt.Errorf("failed to persist URL target: %w", err)
	}

	result := enumeration.ResourceUpsertResult{
		ResourceID: urlTarget.ID(),
		TargetType: shared.TargetTypeURL,
		Name:       item.Name,
		Metadata:   urlTarget.Metadata(),
	}
	span.SetAttributes(
		attribute.Int64("resource_id", urlTarget.ID()),
		attribute.String("target_type", string(shared.TargetTypeURL)),
	)
	span.SetStatus(codes.Ok, "URL target persisted successfully")

	logger.Info(ctx, "URL target persisted successfully",
		"url_target_id", urlTarget.ID(),
		"target_type", shared.TargetTypeURL,
	)

	return result, nil
}

// updateExistingURLTarget modifies the existing domain entity with new data from ResourceEntry.
// For instance, you might update the URL itself if changed. If your logic allows updating
// metadata, you can also do that here.
func (p *urlPersistence) updateExistingURLTarget(
	ctx context.Context,
	existing *domain.URLTarget,
	item enumeration.ResourceEntry,
) (*domain.URLTarget, error) {
	logger := p.logger.With(
		"operation", "update_existing",
		"url_target_id", existing.ID(),
	)
	ctx, span := p.tracer.Start(ctx, "url_persistence.update_existing_url_target",
		trace.WithAttributes(
			attribute.String("controller_id", p.controllerID),
			attribute.Int64("url_target_id", existing.ID()),
			attribute.String("resource_name", item.Name),
			attribute.String("new_url", item.URL),
		),
	)
	defer span.End()

	// If item.URL is different from existing.URL(), update it
	// In many systems, you might consider the URL to be immutable, but let's assume you allow changes:
	if item.URL != "" && item.URL != existing.URL() {
		if err := existing.UpdateURL(item.URL); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to update URL")
			return nil, err
		}
		span.AddEvent("URL target updated",
			trace.WithAttributes(
				attribute.String("old_url", existing.URL()),
				attribute.String("new_url", item.URL),
			))
	}

	// TODO: handle updates to metadata

	if err := p.urlRepo.Update(ctx, existing); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update URL")
		return nil, fmt.Errorf("failed to update URL target (old_url: %s, new_url: %s): %w", existing.URL(), item.URL, err)
	}

	span.AddEvent("url_updated", trace.WithAttributes(
		attribute.String("old_url", existing.URL()),
		attribute.String("new_url", item.URL),
	))
	logger.Info(ctx, "URL updated successfully",
		"old_url", existing.URL(),
		"new_url", item.URL,
	)

	return existing, nil
}

// createNewURLTarget instantiates a new URLTarget domain object and persists it.
func (p *urlPersistence) createNewURLTarget(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (*domain.URLTarget, error) {
	logger := p.logger.With(
		"operation", "create_new_url_target",
		"url", item.URL,
	)
	ctx, span := p.tracer.Start(ctx, "url_persistence.create_new_url_target",
		trace.WithAttributes(
			attribute.String("controller_id", p.controllerID),
			attribute.String("resource_name", item.Name),
			attribute.String("resource_url", item.URL),
		),
	)
	defer span.End()

	meta := item.Metadata
	span.SetAttributes(
		attribute.Int64("metadata_count", int64(len(meta))),
	)

	newURLTarget, err := domain.NewURLTarget(item.URL, meta)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create domain object")
		return nil, fmt.Errorf("failed to create URL target (url: %s, metadata: %v): %w", item.URL, meta, err)
	}

	id, err := p.urlRepo.Create(ctx, newURLTarget)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to insert URL target")
		return nil, fmt.Errorf("failed to insert new URL target (url: %s, metadata: %v): %w", item.URL, meta, err)
	}
	newURLTarget.SetID(id)

	span.SetAttributes(attribute.Int64("url_target_id", id))
	span.SetStatus(codes.Ok, "URL target created successfully")

	logger.Info(ctx, "New URL target created successfully",
		"url_target_id", id,
	)

	return newURLTarget, nil
}

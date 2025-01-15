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
)

// Ensure urlPersistence satisfies ResourcePersister
var _ enumeration.ResourcePersister = (*urlPersistence)(nil)

// urlPersistence implements ResourcePersister for URL-based targets.
// It coordinates domain-level creation and updates of URLTarget aggregates.
type urlPersistence struct {
	urlRepo domain.URLRepository

	tracer trace.Tracer
}

// NewURLPersistence constructs a new urlPersistence instance.
func NewURLPersistence(
	urlRepo domain.URLRepository,
	tracer trace.Tracer,
) *urlPersistence {
	return &urlPersistence{
		urlRepo: urlRepo,
		tracer:  tracer,
	}
}

// Persist creates or updates a URLTarget based on the provided ResourceEntry.
// It enforces idempotency by checking for an existing URLTarget (by URL) before creating
// a new one. For an existing target, it updates the URL or metadata if needed.
func (p *urlPersistence) Persist(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (enumeration.ResourceUpsertResult, error) {
	ctx, span := p.tracer.Start(ctx, "url_persistence.persist",
		trace.WithAttributes(
			attribute.String("resource_name", item.Name),
			attribute.String("resource_url", item.URL),
		))
	defer span.End()

	existing, err := p.urlRepo.GetByURL(ctx, item.URL)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get URLTarget by URL")
		return enumeration.EmptyResourceUpsertResult, err
	}

	var urlTarget *domain.URLTarget
	if existing != nil {
		span.AddEvent("Found existing URL target",
			trace.WithAttributes(attribute.Int64("url_target_id", existing.ID())))
		urlTarget, err = p.updateExistingURLTarget(ctx, existing, item)
	} else {
		span.AddEvent("Creating new URL target")
		urlTarget, err = p.createNewURLTarget(ctx, item)
	}

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist URL target")
		return enumeration.EmptyResourceUpsertResult, err
	}

	result := enumeration.ResourceUpsertResult{
		ResourceID: urlTarget.ID(),
		TargetType: shared.TargetTypeURL,
		Name:       item.Name,
		Metadata:   urlTarget.Metadata(),
	}
	span.SetStatus(codes.Ok, "URL target persisted successfully")
	span.AddEvent("URL target persisted successfully",
		trace.WithAttributes(attribute.Int64("url_target_id", urlTarget.ID())))

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
	span := trace.SpanFromContext(ctx)

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
		span.SetStatus(codes.Error, "failed to update URL target in repo")
		return nil, fmt.Errorf("failed to update URL target: %w", err)
	}
	span.AddEvent("URL target updated successfully")
	return existing, nil
}

// createNewURLTarget instantiates a new URLTarget domain object and persists it.
func (p *urlPersistence) createNewURLTarget(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (*domain.URLTarget, error) {
	ctx, span := p.tracer.Start(ctx, "url_persistence.create_new_url_target")
	defer span.End()

	meta := item.Metadata

	newURLTarget, err := domain.NewURLTarget(item.URL, meta)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create domain object")
		return nil, fmt.Errorf("failed to create domain object: %w", err)
	}

	id, err := p.urlRepo.Create(ctx, newURLTarget)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to insert URL target")
		return nil, fmt.Errorf("failed to insert new URL target: %w", err)
	}
	newURLTarget.SetID(id)

	span.AddEvent("New URL target created",
		trace.WithAttributes(attribute.Int64("url_target_id", newURLTarget.ID())))
	return newURLTarget, nil
}

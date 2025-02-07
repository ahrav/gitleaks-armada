package github

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

var _ enumeration.ResourcePersister = (*repoPersistence)(nil)

// repoPersistence implements ResourcePersister for GitHub repositories.
// It handles the persistence logic for creating and updating GitHub repositories
// while maintaining domain invariants and generating scan targets.
type repoPersistence struct {
	controllerID string
	githubRepo   domain.GithubRepository
	logger       *logger.Logger
	tracer       trace.Tracer
}

// NewRepoPersistence creates a new repoPersistence instance.
func NewRepoPersistence(
	controllerID string,
	githubRepo domain.GithubRepository,
	logger *logger.Logger,
	tracer trace.Tracer,
) *repoPersistence {
	logger = logger.With("component", "github_repo_persistence")
	return &repoPersistence{
		controllerID: controllerID,
		githubRepo:   githubRepo,
		logger:       logger,
		tracer:       tracer,
	}
}

// Persist creates or updates a GitHub repository based on the provided ResourceEntry.
func (p *repoPersistence) Persist(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (enumeration.ResourceUpsertResult, error) {
	logger := p.logger.With(
		"operation", "persist",
		"resource_url", item.URL,
		"resource_name", item.Name,
	)
	ctx, span := p.tracer.Start(ctx, "github_repo_persistence.persist",
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

	existing, err := p.githubRepo.GetByURL(ctx, item.URL)
	if err != nil {
		span.SetStatus(codes.Error, "failed to get repo by URL")
		return enumeration.EmptyResourceUpsertResult, fmt.Errorf("failed to query GitHub repo: %w", err)
	}

	var repo *domain.GitHubRepo
	if existing != nil {
		span.AddEvent("existing_repository_found", trace.WithAttributes(
			attribute.Int64("repo_id", existing.ID()),
		))
		logger.Debug(ctx, "Found existing GitHub repository",
			"repo_id", existing.ID(),
		)
		repo, err = p.updateExistingRepo(ctx, existing, item)
	} else {
		span.AddEvent("creating_new_repository")
		logger.Debug(ctx, "Creating new GitHub repository")
		repo, err = p.createNewRepo(ctx, item)
	}

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist GitHub repository")
		return enumeration.EmptyResourceUpsertResult, fmt.Errorf("failed to persist GitHub repository: %w", err)
	}

	result := enumeration.ResourceUpsertResult{
		ResourceID: repo.ID(),
		TargetType: shared.TargetTypeGitHubRepo,
		Name:       repo.Name(),
		Metadata:   repo.Metadata(),
	}
	span.SetAttributes(
		attribute.Int64("resource_id", repo.ID()),
		attribute.String("target_type", string(shared.TargetTypeGitHubRepo)),
	)
	span.SetStatus(codes.Ok, "GitHub repository persisted successfully")

	logger.Info(ctx, "GitHub repository persisted successfully",
		"repo_id", repo.ID(),
		"target_type", shared.TargetTypeGitHubRepo,
	)

	return result, nil
}

func (p *repoPersistence) updateExistingRepo(
	ctx context.Context,
	existing *domain.GitHubRepo,
	item enumeration.ResourceEntry,
) (*domain.GitHubRepo, error) {
	logger := p.logger.With(
		"operation", "update_existing",
		"repo_id", existing.ID(),
	)
	ctx, span := p.tracer.Start(ctx, "github_repo_persistence.update_existing_repo",
		trace.WithAttributes(
			attribute.String("controller_id", p.controllerID),
			attribute.Int64("repo_id", existing.ID()),
			attribute.String("resource_name", item.Name),
			attribute.String("current_name", existing.Name()),
		),
	)
	defer span.End()

	if item.Name != "" && item.Name != existing.Name() {
		if err := existing.Rename(item.Name); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to rename repository")
			return nil, fmt.Errorf("failed to rename repository: %w", err)
		}
		span.AddEvent("repository_renamed", trace.WithAttributes(
			attribute.String("old_name", existing.Name()),
			attribute.String("new_name", item.Name),
		))
	}

	if err := p.githubRepo.Update(ctx, existing); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update repository")
		return nil, fmt.Errorf("failed to update GitHub repository (id: %d): %w", existing.ID(), err)
	}

	span.AddEvent("repository_updated", trace.WithAttributes(
		attribute.String("name", existing.Name()),
	))
	logger.Info(ctx, "GitHub repository updated successfully",
		"repo_id", existing.ID(),
		"name", existing.Name(),
	)

	return existing, nil
}

func (p *repoPersistence) createNewRepo(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (*domain.GitHubRepo, error) {
	logger := p.logger.With(
		"operation", "create_new_repo",
		"url", item.URL,
	)
	ctx, span := p.tracer.Start(ctx, "github_repo_persistence.create_new_repo",
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

	newRepo, err := domain.NewGitHubRepo(item.Name, item.URL, meta)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create domain object")
		return nil, fmt.Errorf("failed to create GitHub repository (url: %s): %w", item.URL, err)
	}

	id, err := p.githubRepo.Create(ctx, newRepo)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to insert repository")
		return nil, fmt.Errorf("failed to insert new GitHub repository (url: %s): %w", item.URL, err)
	}
	newRepo.SetID(id)

	span.SetAttributes(attribute.Int64("repo_id", id))
	span.SetStatus(codes.Ok, "GitHub repository created successfully")

	logger.Info(ctx, "New GitHub repository created successfully",
		"repo_id", id,
		"name", newRepo.Name(),
	)

	return newRepo, nil
}

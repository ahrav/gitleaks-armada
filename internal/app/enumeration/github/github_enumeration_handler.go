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

var _ enumeration.ResourcePersister = (*gitHubRepoPersistence)(nil)

// gitHubRepoPersistence implements resourcePersister for GitHub repositories.
// It handles the persistence logic for creating and updating GitHub repositories
// while maintaining domain invariants and generating scan targets.
type gitHubRepoPersistence struct {
	githubRepo domain.GithubRepository

	logger *logger.Logger
	tracer trace.Tracer
}

// NewGitHubRepoPersistence creates a new gitHubRepoPersistence instance.
func NewGitHubRepoPersistence(githubRepo domain.GithubRepository, logger *logger.Logger, tracer trace.Tracer) *gitHubRepoPersistence {
	return &gitHubRepoPersistence{githubRepo: githubRepo, logger: logger, tracer: tracer}
}

// Persist creates or updates a GitHub repository based on the provided ResourceEntry.
// It maintains idempotency by checking for existing repositories by URL before creating
// new ones. For existing repos, it will update the name if changed while preserving
// other attributes. Returns a ResourceUpsertResult containing the persisted entity's
// details or an error if persistence fails.
func (p *gitHubRepoPersistence) Persist(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (enumeration.ResourceUpsertResult, error) {
	ctx, span := p.tracer.Start(ctx, "github_repo_persistence.persist",
		trace.WithAttributes(
			attribute.String("resource_name", item.Name),
			attribute.String("resource_url", item.URL),
		))
	defer span.End()

	existing, err := p.githubRepo.GetByURL(ctx, item.URL)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get repo by URL")
		return enumeration.EmptyResourceUpsertResult, err
	}

	var repo *domain.GitHubRepo
	if existing != nil {
		span.AddEvent("Found existing repository", trace.WithAttributes(
			attribute.Int64("repo_id", existing.ID()),
		))
		repo, err = p.updateExistingRepo(ctx, existing, item)
	} else {
		span.AddEvent("Creating new repository")
		repo, err = p.createNewRepo(ctx, item)
	}
	if err != nil {
		return enumeration.EmptyResourceUpsertResult, err
	}

	result := enumeration.ResourceUpsertResult{
		ResourceID: repo.ID(),
		TargetType: shared.TargetTypeGitHubRepo,
		Name:       repo.Name(),
		Metadata:   repo.Metadata(),
	}
	span.SetStatus(codes.Ok, "Repository persisted successfully")
	return result, nil
}

func (p *gitHubRepoPersistence) updateExistingRepo(
	ctx context.Context,
	existing *domain.GitHubRepo,
	item enumeration.ResourceEntry,
) (*domain.GitHubRepo, error) {
	span := trace.SpanFromContext(ctx)

	if item.Name != "" && item.Name != existing.Name() {
		if err := existing.Rename(item.Name); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to rename repo")
			return nil, err
		}
		span.AddEvent("Repository renamed", trace.WithAttributes(
			attribute.String("old_name", existing.Name()),
			attribute.String("new_name", item.Name),
		))

		if err := p.githubRepo.Update(ctx, existing); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to update repo")
			return nil, fmt.Errorf("failed to update GitHub repo: %w", err)
		}
		span.AddEvent("Repository updated successfully")
	}
	return existing, nil
}

func (p *gitHubRepoPersistence) createNewRepo(
	ctx context.Context,
	item enumeration.ResourceEntry,
) (*domain.GitHubRepo, error) {
	span := trace.SpanFromContext(ctx)

	newRepo, err := domain.NewGitHubRepo(item.Name, item.URL, item.Metadata)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create domain object")
		return nil, fmt.Errorf("failed to create domain object: %w", err)
	}

	if _, err := p.githubRepo.Create(ctx, newRepo); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to insert repo")
		return nil, fmt.Errorf("failed to insert new GitHub repo: %w", err)
	}
	span.AddEvent("New repository created", trace.WithAttributes(
		attribute.Int64("repo_id", newRepo.ID()),
	))

	return newRepo, nil
}

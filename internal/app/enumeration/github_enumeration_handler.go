package enumeration

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// gitHubRepoPersistence implements resourcePersister for GitHub repositories.
// It handles the persistence logic for creating and updating GitHub repositories
// while maintaining domain invariants and generating scan targets.
type gitHubRepoPersistence struct {
	githubRepo enumeration.GithubRepository

	logger *logger.Logger
	tracer trace.Tracer
}

// NewGitHubRepoPersistence creates a new gitHubRepoPersistence instance.
func NewGitHubRepoPersistence(githubRepo enumeration.GithubRepository, logger *logger.Logger, tracer trace.Tracer) *gitHubRepoPersistence {
	return &gitHubRepoPersistence{githubRepo: githubRepo, logger: logger, tracer: tracer}
}

// persist creates or updates a GitHub repository based on the provided ResourceEntry.
// It maintains idempotency by checking for existing repositories by URL before creating
// new ones. For existing repos, it will update the name if changed while preserving
// other attributes. Returns a ResourceUpsertResult containing the persisted entity's
// details or an error if persistence fails.
func (p *gitHubRepoPersistence) persist(
	ctx context.Context,
	item ResourceEntry,
) (ResourceUpsertResult, error) {
	existing, err := p.githubRepo.GetByURL(ctx, item.URL)
	if err != nil {
		return EmptyResourceUpsertResult, err
	}

	var repo *enumeration.GitHubRepo
	if existing != nil {
		// Update flow: Only rename if name has changed to avoid unnecessary updates
		repo = existing
		if item.Name != "" && item.Name != repo.Name() {
			if renameErr := repo.Rename(item.Name); renameErr != nil {
				return EmptyResourceUpsertResult, renameErr
			}

			if err := p.githubRepo.Update(ctx, repo); err != nil {
				return EmptyResourceUpsertResult, fmt.Errorf("failed to update GitHub repo: %w", err)
			}
		}
	} else {
		// Create flow: Construct and persist new repository
		newRepo, err := enumeration.NewGitHubRepo(item.Name, item.URL, item.Metadata)
		if err != nil {
			return EmptyResourceUpsertResult, fmt.Errorf("failed to create domain object: %w", err)
		}
		if _, err := p.githubRepo.Create(ctx, newRepo); err != nil {
			return EmptyResourceUpsertResult, fmt.Errorf("failed to insert new GitHub repo: %w", err)
		}
		repo = newRepo
	}

	return ResourceUpsertResult{
		ResourceID: repo.ID(),
		TargetType: shared.TargetTypeGitHubRepo,
		Name:       repo.Name(),
		Metadata:   repo.Metadata(),
	}, nil
}

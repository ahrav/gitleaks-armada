package enumeration

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// GitHubAPI defines the interface for interacting with GitHub's API.
type GitHubAPI interface {
	// ListRepositories returns a list of repositories for an organization
	// along with pagination information.
	ListRepositories(ctx context.Context, org string, cursor *string) (*githubGraphQLResponse, error)
}

// TargetEnumerator provides application-level target enumeration capabilities.
// It differs from the domain interface by operating on batches and managing cursors
// directly to support efficient streaming of large datasets.
type TargetEnumerator interface {
	// Enumerate walks through a data source and streams batches of scan tasks.
	// It accepts a cursor to support resumable operations and sends batches through
	// the provided channel. Each batch includes both tasks and checkpoint data.
	Enumerate(
		ctx context.Context,
		startCursor *string,
		batchCh chan<- EnumerateBatch,
	) error
}

// TargetInfo represents a scannable target with its associated metadata.
// It provides the minimal information needed to create a scan task while
// keeping the enumeration layer decoupled from domain specifics.
type TargetInfo struct {
	// TargetType identifies the type of target being scanned (e.g., "github_repo").
	TargetType shared.TargetType

	// ResourceURI is the unique location identifier for the target.
	ResourceURI string

	// Metadata contains additional context needed for scanning the target.
	Metadata map[string]string
}

// EnumerateBatch groups related scan tasks with their checkpoint data.
// This enables atomic processing of task batches while maintaining
// resumability through checkpoint tracking.
type EnumerateBatch struct {
	Targets    []*TargetInfo
	NextCursor string
}

var _ TargetEnumerator = new(GitHubEnumerator)

// GitHubEnumerator handles enumerating repositories from a GitHub organization.
// It supports pagination and checkpoint-based resumption to handle large organizations
// efficiently and reliably.
type GitHubEnumerator struct {
	ghConfig *config.GitHubTarget

	ghClient GitHubAPI
	tracer   trace.Tracer
}

// NewGitHubEnumerator creates a new GitHubEnumerator with the provided HTTP client,
// credentials and state storage.
func NewGitHubEnumerator(
	client GitHubAPI,
	ghConfig *config.GitHubTarget,
	tracer trace.Tracer,
) *GitHubEnumerator {
	return &GitHubEnumerator{
		ghClient: client,
		ghConfig: ghConfig,
		tracer:   tracer,
	}
}

// Enumerate fetches all repositories from a GitHub organization and creates scan tasks.
// It uses GraphQL for efficient pagination and maintains checkpoints for resumability.
// The method streams batches of tasks through the provided channel and updates progress
// in the enumeration state storage.
func (e *GitHubEnumerator) Enumerate(ctx context.Context, startCursor *string, batchCh chan<- EnumerateBatch) error {
	ctx, span := e.tracer.Start(ctx, "github_enumerator.enumeration.enumerate",
		trace.WithAttributes(
			attribute.String("org", e.ghConfig.Org),
			attribute.Int("repo_list_count", len(e.ghConfig.RepoList)),
		))
	defer span.End()

	if e.ghConfig.Org == "" && len(e.ghConfig.RepoList) < 1 {
		span.RecordError(fmt.Errorf("must provide either an org or a repo_list"))
		return fmt.Errorf("must provide either an org or a repo_list")
	}

	// If we have a repo list, process it directly.
	// TODO: Batch this too.
	if len(e.ghConfig.RepoList) > 0 {
		targets := make([]*TargetInfo, 0, len(e.ghConfig.RepoList))
		for _, repoURL := range e.ghConfig.RepoList {
			targets = append(targets, &TargetInfo{
				TargetType:  shared.TargetTypeGitHubRepo,
				ResourceURI: repoURL,
				Metadata:    e.ghConfig.Metadata,
			})
		}
		batchCh <- EnumerateBatch{Targets: targets}
		return nil
	}

	// Resume from last known position if checkpoint exists.
	var endCursor = startCursor

	for {
		// Create child span for API calls
		apiCtx, apiSpan := e.tracer.Start(ctx, "github_enumerator.enumeration.list_repositories")
		respData, err := e.ghClient.ListRepositories(apiCtx, e.ghConfig.Org, endCursor)
		if err != nil {
			apiSpan.RecordError(err)
			apiSpan.End()
			return fmt.Errorf("failed to list repositories: %w", err)
		}
		apiSpan.End()

		_, taskSpan := e.tracer.Start(ctx, "github_enumerator.enumeration.create_tasks")
		targets := make([]*TargetInfo, 0, len(respData.Data.Organization.Repositories.Nodes))
		for _, node := range respData.Data.Organization.Repositories.Nodes {
			targets = append(targets, &TargetInfo{
				TargetType:  shared.TargetTypeGitHubRepo,
				ResourceURI: buildGithubResourceURI(e.ghConfig.Org, node.Name),
				Metadata:    e.ghConfig.Metadata,
			})
		}
		taskSpan.End()

		pageInfo := respData.Data.Organization.Repositories.PageInfo
		newCursor := pageInfo.EndCursor

		batchCh <- EnumerateBatch{
			Targets:    targets,
			NextCursor: newCursor,
		}

		if !pageInfo.HasNextPage {
			break
		}
		endCursor = &newCursor
	}

	return nil
}

// buildGithubResourceURI creates a standardized URI for GitHub repositories.
// The URI format follows the standard HTTPS clone URL pattern used by GitHub.
func buildGithubResourceURI(org, repoName string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", org, repoName)
}

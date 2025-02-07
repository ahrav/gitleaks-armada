package github

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	enumeration "github.com/ahrav/gitleaks-armada/internal/app/enumeration/shared"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// API defines the interface for interacting with GitHub's API.
type API interface {
	// ListRepositories returns a list of repositories for an organization
	// along with pagination information.
	ListRepositories(ctx context.Context, org string, cursor *string) (*repositoryResponse, error)
}

var _ enumeration.TargetEnumerator = new(Enumerator)

// Enumerator handles enumerating repositories from a GitHub organization.
// It supports pagination and checkpoint-based resumption to handle large organizations
// efficiently and reliably.
type Enumerator struct {
	controllerID string

	ghConfig *config.GitHubTarget
	ghClient API

	logger *logger.Logger
	tracer trace.Tracer
}

// NewEnumerator creates a new GitHubEnumerator with the provided configuration
// and dependencies.
func NewEnumerator(
	controllerID string,
	client API,
	ghConfig *config.GitHubTarget,
	logger *logger.Logger,
	tracer trace.Tracer,
) *Enumerator {
	return &Enumerator{
		controllerID: controllerID,
		ghClient:     client,
		ghConfig:     ghConfig,
		logger:       logger.With("component", "github_enumerator"),
		tracer:       tracer,
	}
}

// Enumerate fetches all repositories from a GitHub organization and creates scan tasks.
// It uses GraphQL for efficient pagination and maintains checkpoints for resumability.
// The method streams batches of tasks through the provided channel and updates progress
// in the enumeration state storage.
func (e *Enumerator) Enumerate(ctx context.Context, startCursor *string, batchCh chan<- enumeration.EnumerateBatch) error {
	ctx, span := e.tracer.Start(ctx, "github_enumerator.enumerate",
		trace.WithAttributes(
			attribute.String("controller_id", e.controllerID),
			attribute.String("org", e.ghConfig.Org),
			attribute.Int("repo_list_count", len(e.ghConfig.RepoList)),
		),
	)
	defer span.End()

	if err := e.validateConfig(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid configuration")
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Process explicit repo list if provided.
	if len(e.ghConfig.RepoList) > 0 {
		return e.processRepoList(ctx, batchCh)
	}

	return e.processOrgRepos(ctx, startCursor, batchCh)
}

// validateConfig ensures the enumerator has valid configuration
func (e *Enumerator) validateConfig() error {
	if e.ghConfig.Org == "" && len(e.ghConfig.RepoList) < 1 {
		return fmt.Errorf("must provide either an org or a repo_list")
	}
	return nil
}

// processRepoList handles enumeration for explicitly provided repository list
func (e *Enumerator) processRepoList(ctx context.Context, batchCh chan<- enumeration.EnumerateBatch) error {
	logger := e.logger.With("operation", "process_repo_list")
	ctx, span := e.tracer.Start(ctx, "github_enumerator.process_repo_list",
		trace.WithAttributes(
			attribute.String("controller_id", e.controllerID),
			attribute.String("org", e.ghConfig.Org),
			attribute.Int("repo_list_count", len(e.ghConfig.RepoList)),
		),
	)
	defer span.End()

	targets := make([]*enumeration.TargetInfo, 0, len(e.ghConfig.RepoList))
	for _, repoURL := range e.ghConfig.RepoList {
		targets = append(targets, &enumeration.TargetInfo{
			TargetType:  shared.TargetTypeGitHubRepo,
			ResourceURI: repoURL,
			Metadata:    e.ghConfig.Metadata,
		})
	}

	span.AddEvent("repo_list_processed", trace.WithAttributes(
		attribute.Int("target_count", len(targets)),
	))
	logger.Info(ctx, "Processed repository list",
		"target_count", len(targets),
	)

	batchCh <- enumeration.EnumerateBatch{Targets: targets}
	return nil
}

// processOrgRepos handles enumeration for GitHub organization repositories
func (e *Enumerator) processOrgRepos(ctx context.Context, startCursor *string, batchCh chan<- enumeration.EnumerateBatch) error {
	logger := e.logger.With(
		"operation", "process_org_repos",
		"org", e.ghConfig.Org,
	)
	ctx, span := e.tracer.Start(ctx, "github_enumerator.process_org_repos",
		trace.WithAttributes(
			attribute.String("controller_id", e.controllerID),
			attribute.String("org", e.ghConfig.Org),
		),
	)
	defer span.End()

	var endCursor = startCursor
	for {
		respData, err := e.fetchRepositoryBatch(ctx, endCursor)
		if err != nil {
			return err
		}

		targets, err := e.createTargetsFromResponse(ctx, respData)
		if err != nil {
			return err
		}

		pageInfo := respData.Data.Organization.Repositories.PageInfo
		newCursor := pageInfo.EndCursor

		batchCh <- enumeration.EnumerateBatch{
			Targets:    targets,
			NextCursor: newCursor,
		}

		logger.Debug(ctx, "Processed repository batch",
			"batch_size", len(targets),
			"has_next_page", pageInfo.HasNextPage,
		)

		if !pageInfo.HasNextPage {
			break
		}
		endCursor = &newCursor
	}

	span.SetStatus(codes.Ok, "organization repositories processed successfully")
	return nil
}

// fetchRepositoryBatch retrieves a single page of repositories from GitHub API
func (e *Enumerator) fetchRepositoryBatch(ctx context.Context, cursor *string) (*repositoryResponse, error) {
	ctx, span := e.tracer.Start(ctx, "github_enumerator.fetch_repository_batch",
		trace.WithAttributes(
			attribute.String("controller_id", e.controllerID),
			attribute.String("org", e.ghConfig.Org),
		),
	)
	defer span.End()

	respData, err := e.ghClient.ListRepositories(ctx, e.ghConfig.Org, cursor)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to list repositories")
		return nil, fmt.Errorf("failed to list repositories for org %s: %w", e.ghConfig.Org, err)
	}

	span.AddEvent("repositories_fetched", trace.WithAttributes(
		attribute.Int("count", len(respData.Data.Organization.Repositories.Nodes)),
	))

	return respData, nil
}

// createTargetsFromResponse converts API response to enumeration targets
func (e *Enumerator) createTargetsFromResponse(ctx context.Context, respData *repositoryResponse) ([]*enumeration.TargetInfo, error) {
	_, span := e.tracer.Start(ctx, "github_enumerator.create_targets_from_response",
		trace.WithAttributes(
			attribute.String("controller_id", e.controllerID),
			attribute.String("org", e.ghConfig.Org),
		),
	)
	defer span.End()

	targets := make([]*enumeration.TargetInfo, 0, len(respData.Data.Organization.Repositories.Nodes))
	for _, node := range respData.Data.Organization.Repositories.Nodes {
		targets = append(targets, &enumeration.TargetInfo{
			TargetType:  shared.TargetTypeGitHubRepo,
			ResourceURI: buildGithubResourceURI(e.ghConfig.Org, node.Name),
			Metadata:    e.ghConfig.Metadata,
		})
	}

	span.AddEvent("targets_created", trace.WithAttributes(
		attribute.Int("count", len(targets)),
	))

	return targets, nil
}

// buildGithubResourceURI creates a standardized URI for GitHub repositories.
// The URI format follows the standard HTTPS clone URL pattern used by GitHub.
func buildGithubResourceURI(org, repoName string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", org, repoName)
}

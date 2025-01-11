package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

// defaultDBAttributes defines standard OpenTelemetry attributes for PostgreSQL operations.
var defaultDBAttributes = []attribute.KeyValue{
	attribute.String("db.system", "postgresql"),
}

// Ensure githubRepositoryStore satisfies scanning.GithubRepository (compile-time check).
var _ scanning.GithubRepository = (*githubRepositoryStore)(nil)

// githubRepositoryStore implements scanning.GithubRepository using PostgreSQL.
// It provides persistence for GitHub repository aggregates while maintaining
// domain invariants and includes OpenTelemetry instrumentation.
type githubRepositoryStore struct {
	q      *db.Queries
	tracer trace.Tracer
}

// NewGithubRepositoryStore creates a PostgreSQL-backed implementation of scanning.GithubRepository.
// It uses sqlc-generated queries to ensure type-safe database operations.
func NewGithubRepositoryStore(pool *pgxpool.Pool, tracer trace.Tracer) *githubRepositoryStore {
	return &githubRepositoryStore{
		q:      db.New(pool),
		tracer: tracer,
	}
}

// Create persists a new GitHubRepo aggregate to PostgreSQL and returns its assigned ID.
// If the insert fails, it returns a wrapped error preserving the root cause.
func (s *githubRepositoryStore) Create(ctx context.Context, repo *scanning.GitHubRepo) (int64, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("method", "Create"),
		attribute.String("repo_name", repo.Name()),
		attribute.String("repo_url", repo.URL()),
	)

	var id int64
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.githubrepo.create", dbAttrs, func(ctx context.Context) error {
		metadata, err := json.Marshal(repo.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		insertParams := db.CreateGitHubRepoParams{
			Name:      repo.Name(),
			Url:       repo.URL(),
			IsActive:  repo.IsActive(),
			Metadata:  metadata,
			CreatedAt: pgtype.Timestamptz{Time: repo.CreatedAt(), Valid: true},
			UpdatedAt: pgtype.Timestamptz{Time: repo.UpdatedAt(), Valid: true},
		}

		id, err = s.q.CreateGitHubRepo(ctx, insertParams)
		if err != nil {
			return fmt.Errorf("githubRepositoryStore.Create: insert error: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("githubRepositoryStore.Create: %w", err)
	}

	return id, nil
}

// Update modifies an existing GitHubRepo in PostgreSQL.
// It expects the repo has already passed domain validation.
// Returns an error if the update fails or metadata serialization fails.
func (s *githubRepositoryStore) Update(ctx context.Context, repo *scanning.GitHubRepo) error {
	dbAttrs := []attribute.KeyValue{
		attribute.String("method", "Update"),
		attribute.Int64("repo_id", repo.ID()),
		attribute.String("repo_url", repo.URL()),
		attribute.String("repo_name", repo.Name()),
	}
	dbAttrs = append(dbAttrs, defaultDBAttributes...)

	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.githubrepo.update", dbAttrs, func(ctx context.Context) error {
		metadata, err := json.Marshal(repo.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		updateParams := db.UpdateGitHubRepoParams{
			ID:        repo.ID(),
			Name:      repo.Name(),
			Url:       repo.URL(),
			IsActive:  repo.IsActive(),
			Metadata:  metadata,
			UpdatedAt: pgtype.Timestamptz{Time: repo.UpdatedAt(), Valid: true},
		}

		var rowsAff int64
		rowsAff, err = s.q.UpdateGitHubRepo(ctx, updateParams)
		if err != nil {
			return fmt.Errorf("githubRepositoryStore.Update: update error: %w", err)
		}
		if rowsAff == 0 {
			return fmt.Errorf("githubRepositoryStore.Update: no rows affected")
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("githubRepositoryStore.Update: %w", err)
	}

	return nil
}

// GetByID retrieves a GitHubRepo by its primary key from PostgreSQL.
// Returns (nil, nil) if no matching record exists, allowing callers to
// distinguish between missing records and errors.
func (s *githubRepositoryStore) GetByID(ctx context.Context, id int64) (*scanning.GitHubRepo, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("method", "GetByID"),
		attribute.Int64("repo_id", id),
	)

	var repo *scanning.GitHubRepo
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.githubrepo.get_by_id", dbAttrs, func(ctx context.Context) error {
		dbRepo, err := s.q.GetGitHubRepoByID(ctx, id)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // No matching record found
			}
			return fmt.Errorf("select error: %w", err)
		}

		var metadata map[string]any
		if err := json.Unmarshal(dbRepo.Metadata, &metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		// TODO: Fix ReconstructTimeline so we don't have to pass in a zero time.
		repo = scanning.ReconstructGitHubRepo(
			dbRepo.ID,
			dbRepo.Name,
			dbRepo.Url,
			dbRepo.IsActive,
			metadata,
			scanning.ReconstructTimeline(dbRepo.CreatedAt.Time, dbRepo.UpdatedAt.Time, time.Time{}),
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("githubRepositoryStore.GetByID: %w", err)
	}
	return repo, nil
}

// GetByURL retrieves a GitHubRepo by its unique URL from PostgreSQL.
// Returns (nil, nil) if no matching record exists, allowing callers to
// distinguish between missing records and errors.
func (s *githubRepositoryStore) GetByURL(ctx context.Context, url string) (*scanning.GitHubRepo, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("method", "GetByURL"),
		attribute.String("repo_url", url),
	)

	var repo *scanning.GitHubRepo
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.githubrepo.get_by_url", dbAttrs, func(ctx context.Context) error {
		dbRepo, err := s.q.GetGitHubRepoByURL(ctx, url)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("select error: %w", err)
		}

		var metadata map[string]any
		if err := json.Unmarshal(dbRepo.Metadata, &metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		repo = scanning.ReconstructGitHubRepo(
			dbRepo.ID,
			dbRepo.Name,
			dbRepo.Url,
			dbRepo.IsActive,
			metadata,
			scanning.ReconstructTimeline(dbRepo.CreatedAt.Time, dbRepo.UpdatedAt.Time, time.Time{}),
		)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("githubRepositoryStore.GetByURL: %w", err)
	}
	return repo, nil
}

// List retrieves a paginated slice of GitHubRepo aggregates from PostgreSQL.
// Results are ordered by creation time (descending) and limited by the provided
// limit and offset parameters to support efficient pagination through large result sets.
func (s *githubRepositoryStore) List(ctx context.Context, limit, offset int32) ([]*scanning.GitHubRepo, error) {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("method", "List"),
		attribute.Int64("limit", int64(limit)),
		attribute.Int64("offset", int64(offset)),
	)

	var repos []*scanning.GitHubRepo
	err := storage.ExecuteAndTrace(ctx, s.tracer, "postgres.githubrepo.list", dbAttrs, func(ctx context.Context) error {
		dbRows, err := s.q.ListGitHubRepos(ctx, db.ListGitHubReposParams{
			Limit:  limit,
			Offset: offset,
		})
		if err != nil {
			return fmt.Errorf("list error: %w", err)
		}

		tmp := make([]*scanning.GitHubRepo, 0, len(dbRows))
		for _, row := range dbRows {
			var metadata map[string]any
			if err := json.Unmarshal(row.Metadata, &metadata); err != nil {
				return fmt.Errorf("failed to unmarshal metadata: %w", err)
			}

			repo := scanning.ReconstructGitHubRepo(
				row.ID,
				row.Name,
				row.Url,
				row.IsActive,
				metadata,
				scanning.ReconstructTimeline(row.CreatedAt.Time, row.UpdatedAt.Time, time.Time{}),
			)
			tmp = append(tmp, repo)
		}
		repos = tmp
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("githubRepositoryStore.List: %w", err)
	}

	return repos, nil
}

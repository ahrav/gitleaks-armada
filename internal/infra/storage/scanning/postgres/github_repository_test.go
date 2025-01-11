package postgres

import (
	"context"
	"testing"
	"time"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

func setupGitHubRepoTest(t *testing.T) (context.Context, *githubRepositoryStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	store := NewGithubRepositoryStore(db, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, store, cleanup
}

func createTestRepo(name string) *scanning.GitHubRepo {
	return scanning.ReconstructGitHubRepo(
		0, // ID will be assigned by database
		name,
		"https://github.com/org/"+name+".git",
		true,
		map[string]any{
			"language": "Go",
			"stars":    100,
		},
		scanning.ReconstructTimeline(time.Now(), time.Now(), time.Time{}),
	)
}

func TestGitHubRepositoryStore_CreateAndGetByID(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupGitHubRepoTest(t)
	defer cleanup()

	repo := createTestRepo("test-repo")
	expectedStars := float64(100)

	id, err := store.Create(ctx, repo)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0))

	loaded, err := store.GetByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, repo.Name(), loaded.Name())
	assert.Equal(t, repo.URL(), loaded.URL())
	assert.Equal(t, repo.IsActive(), loaded.IsActive())
	assert.Equal(t, repo.Metadata()["language"], loaded.Metadata()["language"])

	stars, ok := loaded.Metadata()["stars"].(float64)
	assert.True(t, ok, "stars should be float64")
	assert.Equal(t, expectedStars, stars)
}

func TestGitHubRepositoryStore_GetByURL(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupGitHubRepoTest(t)
	defer cleanup()

	repo := createTestRepo("test-repo")

	id, err := store.Create(ctx, repo)
	require.NoError(t, err)

	loaded, err := store.GetByURL(ctx, repo.URL())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, id, loaded.ID())
	assert.Equal(t, repo.Name(), loaded.Name())
	assert.Equal(t, repo.URL(), loaded.URL())
}

func TestGitHubRepositoryStore_Update(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupGitHubRepoTest(t)
	defer cleanup()

	repo := createTestRepo("test-repo")

	id, err := store.Create(ctx, repo)
	require.NoError(t, err)

	// Modify to test the update.
	loaded, err := store.GetByID(ctx, id)
	require.NoError(t, err)

	loaded.Deactivate()

	err = store.Update(ctx, loaded)
	require.NoError(t, err)

	updated, err := store.GetByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, updated)

	assert.False(t, updated.IsActive())
}

func TestGitHubRepositoryStore_List(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupGitHubRepoTest(t)
	defer cleanup()

	repos := []*scanning.GitHubRepo{
		createTestRepo("repo-1"),
		createTestRepo("repo-2"),
		createTestRepo("repo-3"),
	}

	for _, repo := range repos {
		_, err := store.Create(ctx, repo)
		require.NoError(t, err)
	}

	tests := []struct {
		name     string
		limit    int32
		offset   int32
		expected int
	}{
		{
			name:     "fetch all",
			limit:    10,
			offset:   0,
			expected: 3,
		},
		{
			name:     "fetch with limit",
			limit:    2,
			offset:   0,
			expected: 2,
		},
		{
			name:     "fetch with offset",
			limit:    10,
			offset:   1,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listed, err := store.List(ctx, tt.limit, tt.offset)
			require.NoError(t, err)
			assert.Len(t, listed, tt.expected)
		})
	}
}

func TestGitHubRepositoryStore_GetNonExistent(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupGitHubRepoTest(t)
	defer cleanup()

	repo, err := store.GetByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, repo)

	repo, err = store.GetByURL(ctx, "https://github.com/org/non-existent.git")
	require.NoError(t, err)
	assert.Nil(t, repo)
}

func TestGitHubRepositoryStore_CreateDuplicate(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupGitHubRepoTest(t)
	defer cleanup()

	repo := createTestRepo("test-repo")

	_, err := store.Create(ctx, repo)
	require.NoError(t, err)

	// Attempt to create duplicate.
	_, err = store.Create(ctx, repo)
	require.Error(t, err)
}

func TestGitHubRepositoryStore_UpdateNonExistent(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupGitHubRepoTest(t)
	defer cleanup()

	repo := createTestRepo("test-repo")

	// Set a non-existent ID.
	nonExistentRepo := scanning.ReconstructGitHubRepo(
		99999,
		repo.Name(),
		repo.URL(),
		repo.IsActive(),
		repo.Metadata(),
		scanning.ReconstructTimeline(time.Now(), time.Now(), time.Time{}),
	)

	err := store.Update(ctx, nonExistentRepo)
	require.Error(t, err)
}

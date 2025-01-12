package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

type mockTimeProvider struct{ current time.Time }

func (m *mockTimeProvider) Now() time.Time { return m.current }

func (m *mockTimeProvider) Advance(d time.Duration) { m.current = m.current.Add(d) }

func setupScanTargetTest(t *testing.T) (context.Context, *scanTargetRepository, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	repo := NewScanTargetRepository(db, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, repo, cleanup
}

func createTestScanTarget(name string) *enumeration.ScanTarget {
	return enumeration.ReconstructScanTarget(
		0, // ID will be assigned by database
		name,
		"github_repositories",
		123,
		nil, // no last scan time initially
		map[string]any{
			"owner": "test-org",
			"repo":  name,
		},
		enumeration.NewTimeline(&mockTimeProvider{current: time.Now()}),
	)
}

func TestScanTargetRepository_CreateAndGetByID(t *testing.T) {
	t.Parallel()

	ctx, repo, cleanup := setupScanTargetTest(t)
	defer cleanup()

	target := createTestScanTarget("test-repo")

	id, err := repo.Create(ctx, target)
	require.NoError(t, err)

	// Get by ID should work
	loaded, err := repo.GetByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, target.Name(), loaded.Name())
	assert.Equal(t, target.TargetType(), loaded.TargetType())
	assert.Equal(t, target.TargetID(), loaded.TargetID())
	assert.Equal(t, target.Metadata()["owner"], loaded.Metadata()["owner"])
	assert.Equal(t, target.Metadata()["repo"], loaded.Metadata()["repo"])
	assert.Nil(t, loaded.LastScanTime())
}

func TestScanTargetRepository_Find(t *testing.T) {
	t.Parallel()

	ctx, repo, cleanup := setupScanTargetTest(t)
	defer cleanup()

	target := createTestScanTarget("test-repo")

	_, err := repo.Create(ctx, target)
	require.NoError(t, err)

	found, err := repo.Find(ctx, target.TargetType(), target.TargetID())
	require.NoError(t, err)
	require.NotNil(t, found)

	assert.Equal(t, target.Name(), found.Name())
	assert.Equal(t, target.TargetType(), found.TargetType())
	assert.Equal(t, target.TargetID(), found.TargetID())
}

func TestScanTargetRepository_Update(t *testing.T) {
	t.Parallel()

	ctx, repo, cleanup := setupScanTargetTest(t)
	defer cleanup()

	target := createTestScanTarget("test-repo")

	id, err := repo.Create(ctx, target)
	require.NoError(t, err)

	// Update last scan time.
	scanTime := time.Now().UTC()
	loaded, err := repo.GetByID(ctx, id)
	require.NoError(t, err)

	loaded.UpdateLastScanTime(scanTime)

	err = repo.Update(ctx, loaded)
	require.NoError(t, err)

	// Verify updates.
	updated, err := repo.GetByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, updated)

	assert.Equal(t, scanTime.Unix(), updated.LastScanTime().Unix())
}

func TestScanTargetRepository_List(t *testing.T) {
	t.Parallel()

	ctx, repo, cleanup := setupScanTargetTest(t)
	defer cleanup()

	targets := []*enumeration.ScanTarget{
		createTestScanTarget("repo-1"),
		createTestScanTarget("repo-2"),
		createTestScanTarget("repo-3"),
	}

	for _, target := range targets {
		_, err := repo.Create(ctx, target)
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
			listed, err := repo.List(ctx, tt.limit, tt.offset)
			require.NoError(t, err)
			assert.Len(t, listed, tt.expected)
		})
	}
}

func TestScanTargetRepository_GetNonExistent(t *testing.T) {
	t.Parallel()

	ctx, repo, cleanup := setupScanTargetTest(t)
	defer cleanup()

	target, err := repo.GetByID(ctx, 99999)
	require.NoError(t, err)
	assert.Nil(t, target)

	target, err = repo.Find(ctx, "github_repositories", 99999)
	require.NoError(t, err)
	assert.Nil(t, target)
}

func TestScanTargetRepository_UpdateNonExistent(t *testing.T) {
	t.Parallel()

	ctx, repo, cleanup := setupScanTargetTest(t)
	defer cleanup()

	target := createTestScanTarget("test-repo")
	// Set a non-existent ID
	nonExistentTarget := enumeration.ReconstructScanTarget(
		99999,
		target.Name(),
		target.TargetType(),
		target.TargetID(),
		nil,
		target.Metadata(),
		enumeration.ReconstructTimeline(time.Now(), time.Now(), time.Time{}),
	)

	err := repo.Update(ctx, nonExistentTarget)
	require.Error(t, err)
}

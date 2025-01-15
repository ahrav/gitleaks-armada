package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

// setupURLTargetTest spins up a test Postgres container, creates a urlTargetStore,
// and returns the store along with a cleanup function to destroy the container.
func setupURLTargetTest(t *testing.T) (context.Context, *urlTargetStore, func()) {
	t.Helper()

	dbPool, cleanup := storage.SetupTestContainer(t)

	store := NewURLTargetStore(dbPool, storage.NoOpTracer())

	ctx := context.Background()
	return ctx, store, cleanup
}

// createTestURLTarget is a helper that either uses your domain constructor or the reconstruction method.
func createTestURLTarget(url string) *enumeration.URLTarget {
	target, err := enumeration.NewURLTarget(url, map[string]any{
		"archive_format": "tar.gz",
		"some_key":       "some_value",
	})
	require.NoErrorf(nil, err, "expected no error creating test URL target")

	return target
}

func TestURLTargetStore_CreateAndGetByURL(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupURLTargetTest(t)
	defer cleanup()

	original := createTestURLTarget("https://example.com/data1.zip")
	id, err := store.Create(ctx, original)
	require.NoError(t, err)
	assert.Greater(t, id, int64(0), "expected a valid DB-generated ID")

	loaded, err := store.GetByURL(ctx, original.URL())
	require.NoError(t, err)
	require.NotNil(t, loaded, "expected a record for this URL")

	assert.Equal(t, id, loaded.ID())
	assert.Equal(t, original.URL(), loaded.URL())

	assert.Equal(t, "tar.gz", loaded.Metadata()["archive_format"])
	assert.Equal(t, "some_value", loaded.Metadata()["some_key"])
}

func TestURLTargetStore_GetByURL_NonExistent(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupURLTargetTest(t)
	defer cleanup()

	loaded, err := store.GetByURL(ctx, "https://non-existent.com/data.zip")
	require.NoError(t, err, "should not fail on non-existent URL")
	assert.Nil(t, loaded, "expected nil for non-existent URL")
}

func TestURLTargetStore_Update(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupURLTargetTest(t)
	defer cleanup()

	original := createTestURLTarget("https://example.com/data2.zip")
	id, err := store.Create(ctx, original)
	require.NoError(t, err)

	loaded, err := store.GetByURL(ctx, original.URL())
	require.NoError(t, err)
	require.NotNil(t, loaded, "expected to find record")

	newURL := "https://example.com/data2-updated.zip"
	err = loaded.UpdateURL(newURL)
	require.NoError(t, err, "expected a valid new URL")

	err = store.Update(ctx, loaded)
	require.NoError(t, err)

	updated, err := store.GetByURL(ctx, newURL)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equal(t, newURL, updated.URL())
	assert.Equal(t, id, updated.ID())
}

func TestURLTargetStore_UpdateNonExistent(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupURLTargetTest(t)
	defer cleanup()

	nonExistent := enumeration.ReconstructURLTarget(
		99999,
		"https://no-where.com/resource.zip",
		map[string]any{"archive_format": "zip"},
		nil,
	)

	err := store.Update(ctx, nonExistent)
	require.Error(t, err, "expected error updating non-existent record")
}

func TestURLTargetStore_CreateDuplicate(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupURLTargetTest(t)
	defer cleanup()

	original := createTestURLTarget("https://example.com/duplicate.zip")

	_, err := store.Create(ctx, original)
	require.NoError(t, err, "first create should succeed")

	_, err = store.Create(ctx, original)
	require.Error(t, err, "expected constraint error for duplicate URL insertion")
}

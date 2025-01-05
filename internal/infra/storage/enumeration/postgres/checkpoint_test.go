package postgres

import (
	"context"
	"testing"
	"time"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

func setupCheckpointTest(t *testing.T) (context.Context, *checkpointStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	store := NewCheckpointStore(db, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, store, cleanup
}

func TestPGCheckpointStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	checkpoint := enumeration.NewTemporaryCheckpoint("test-target", map[string]any{
		"cursor": "abc123",
		"page":   42,
	})

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, checkpoint.TargetID(), loaded.TargetID())
	assert.Equal(t, checkpoint.Data()["cursor"], loaded.Data()["cursor"])
	assert.Equal(t, float64(42), loaded.Data()["page"])
	assert.False(t, loaded.UpdatedAt().IsZero(), "UpdatedAt should be set")
}

func TestPGCheckpointStorage_LoadNonExistent(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	loaded, err := store.Load(ctx, "non-existent")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestPGCheckpointStorage_Delete(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	checkpoint := enumeration.NewTemporaryCheckpoint("test-target", map[string]any{
		"cursor": "abc123",
	})

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	err = store.Delete(ctx, checkpoint.TargetID())
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID())
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestPGCheckpointStorage_DeleteNonExistent(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	err := store.Delete(ctx, "non-existent")
	require.NoError(t, err)
}

func TestPGCheckpointStorage_Update(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	checkpoint := enumeration.NewTemporaryCheckpoint("test-target", map[string]any{
		"cursor": "abc123",
	})

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID())
	require.NoError(t, err)
	require.NotNil(t, loaded)
	firstSaveTime := loaded.UpdatedAt()

	time.Sleep(10 * time.Millisecond)

	checkpoint.Data()["cursor"] = "def456"
	err = store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded2, err := store.Load(ctx, checkpoint.TargetID())
	require.NoError(t, err)
	require.NotNil(t, loaded2)

	assert.Equal(t, "def456", loaded2.Data()["cursor"])
	assert.True(t, loaded2.UpdatedAt().After(firstSaveTime),
		"UpdatedAt should be later than first save")
}

func TestPGCheckpointStorage_ConcurrentOperations(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			checkpoint := enumeration.NewTemporaryCheckpoint("concurrent-target", map[string]any{
				"value": id,
			})

			err := store.Save(ctx, checkpoint)
			require.NoError(t, err)

			_, err = store.Load(ctx, checkpoint.TargetID())
			require.NoError(t, err)

			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	loaded, err := store.Load(ctx, "concurrent-target")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.NotNil(t, loaded.Data()["value"])
}

func TestPGCheckpointStorage_Mutability(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	original := enumeration.NewTemporaryCheckpoint("test-target", map[string]any{
		"cursor": "abc123",
		"nested": map[string]any{
			"key": "value",
		},
	})

	err := store.Save(ctx, original)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, original.TargetID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.Data()["cursor"] = "modified"
	if nestedMap, ok := loaded.Data()["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.Load(ctx, original.TargetID())
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, "abc123", reloaded.Data()["cursor"], "Top-level value should not be modified")
	if nestedMap, ok := reloaded.Data()["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested value should not be modified")
	}
}

func TestPGCheckpointStorage_LoadByID(t *testing.T) {
	t.Parallel()

	ctx, store, cleanup := setupCheckpointTest(t)
	defer cleanup()

	checkpoint := enumeration.NewTemporaryCheckpoint("test-target", map[string]any{
		"cursor": "abc123",
		"nested": map[string]any{
			"key": "value",
		},
	})

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	// Get the checkpoint by target ID first to get its database ID.
	saved, err := store.Load(ctx, checkpoint.TargetID())
	require.NoError(t, err)
	require.NotNil(t, saved)

	loaded, err := store.LoadByID(ctx, saved.ID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, saved.ID(), loaded.ID())
	assert.Equal(t, checkpoint.TargetID(), loaded.TargetID())
	assert.Equal(t, checkpoint.Data()["cursor"], loaded.Data()["cursor"])
	if nestedMap, ok := loaded.Data()["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"])
	}

	// Test non-existent ID.
	nonExistent, err := store.LoadByID(ctx, 999)
	require.NoError(t, err)
	assert.Nil(t, nonExistent)

	loaded.Data()["cursor"] = "modified"
	if nestedMap, ok := loaded.Data()["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.LoadByID(ctx, saved.ID())
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, "abc123", reloaded.Data()["cursor"], "Top-level value should not be modified")
	if nestedMap, ok := reloaded.Data()["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested value should not be modified")
	}
}

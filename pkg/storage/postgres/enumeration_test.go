package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

func createTestCheckpoint(t *testing.T, ctx context.Context, store *CheckpointStorage, targetID string, data map[string]any) *storage.Checkpoint {
	checkpoint := &storage.Checkpoint{
		TargetID: targetID,
		Data:     data,
	}
	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	saved, err := store.Load(ctx, targetID)
	require.NoError(t, err)
	return saved
}

func TestPGEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	checkpointStore := NewCheckpointStorage(db)
	store := NewEnumerationStateStorage(db, checkpointStore)
	ctx := context.Background()

	checkpoint := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})

	state := &storage.EnumerationState{
		SessionID:      "test-session",
		SourceType:     "github",
		Config:         json.RawMessage(`{"org": "test-org"}`),
		LastCheckpoint: checkpoint,
		Status:         storage.StatusInitialized,
	}

	err := store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, state.SessionID, loaded.SessionID)
	assert.Equal(t, state.SourceType, loaded.SourceType)
	assert.Equal(t, state.Config, loaded.Config)
	assert.Equal(t, state.Status, loaded.Status)
	assert.False(t, loaded.LastUpdated.IsZero(), "LastUpdated should be set")

	// Verify checkpoint was saved and linked correctly
	assert.NotNil(t, loaded.LastCheckpoint)
	assert.Equal(t, state.LastCheckpoint.TargetID, loaded.LastCheckpoint.TargetID)
	assert.Equal(t, state.LastCheckpoint.Data["cursor"], loaded.LastCheckpoint.Data["cursor"])
}

func TestPGEnumerationStateStorage_LoadEmpty(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	checkpointStore := NewCheckpointStorage(db)
	store := NewEnumerationStateStorage(db, checkpointStore)
	ctx := context.Background()

	loaded, err := store.Load(ctx)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestPGEnumerationStateStorage_Update(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	checkpointStore := NewCheckpointStorage(db)
	store := NewEnumerationStateStorage(db, checkpointStore)
	ctx := context.Background()

	checkpoint := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})

	initialState := &storage.EnumerationState{
		SessionID:      "test-session",
		SourceType:     "github",
		Config:         json.RawMessage(`{}`),
		LastCheckpoint: checkpoint,
		Status:         storage.StatusInitialized,
	}

	err := store.Save(ctx, initialState)
	require.NoError(t, err)

	firstState, err := store.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, firstState)
	firstSaveTime := firstState.LastUpdated

	initialState.Status = storage.StatusInProgress
	err = store.Save(ctx, initialState)
	require.NoError(t, err)

	loaded, err := store.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, storage.StatusInProgress, loaded.Status)
	assert.True(t, loaded.LastUpdated.After(firstSaveTime),
		"LastUpdated should be later than first save")
}

func TestPGEnumerationStateStorage_Mutability(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	checkpointStore := NewCheckpointStorage(db)
	store := NewEnumerationStateStorage(db, checkpointStore)
	ctx := context.Background()

	checkpoint := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
		"nested": map[string]any{
			"key": "value",
		},
	})

	original := &storage.EnumerationState{
		SessionID:      "test-session",
		SourceType:     "github",
		Config:         json.RawMessage(`{}`),
		LastCheckpoint: checkpoint,
		Status:         storage.StatusInitialized,
	}

	err := store.Save(ctx, original)
	require.NoError(t, err)

	loaded, err := store.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.Status = storage.StatusCompleted
	loaded.LastCheckpoint.Data["cursor"] = "modified"
	if nestedMap, ok := loaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, storage.StatusInitialized, reloaded.Status, "Status should not be modified")
	assert.Equal(t, "abc123", reloaded.LastCheckpoint.Data["cursor"], "Checkpoint cursor should not be modified")
	if nestedMap, ok := reloaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested checkpoint value should not be modified")
	}
}

func TestPGEnumerationStateStorage_ConcurrentOperations(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	checkpointStore := NewCheckpointStorage(db)
	store := NewEnumerationStateStorage(db, checkpointStore)
	ctx := context.Background()
	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			checkpoint := createTestCheckpoint(t, ctx, checkpointStore, fmt.Sprintf("test-target-%d", id), map[string]any{
				"value": id,
			})

			state := &storage.EnumerationState{
				SessionID:      "concurrent-session",
				SourceType:     "github",
				Config:         json.RawMessage(`{}`),
				LastCheckpoint: checkpoint,
				Status:         storage.StatusInProgress,
			}

			err := store.Save(ctx, state)
			require.NoError(t, err)

			_, err = store.Load(ctx)
			require.NoError(t, err)

			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	loaded, err := store.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "concurrent-session", loaded.SessionID)
	assert.Equal(t, storage.StatusInProgress, loaded.Status)
}

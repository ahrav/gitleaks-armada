package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/storage"
)

func createTestCheckpoint(t *testing.T, ctx context.Context, store *checkpointStore, targetID string, data map[string]any) *enumeration.Checkpoint {
	t.Helper()
	checkpoint := &enumeration.Checkpoint{
		TargetID: targetID,
		Data:     data,
	}
	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	saved, err := store.Load(ctx, targetID)
	require.NoError(t, err)
	return saved
}

func setupEnumerationTest(t *testing.T) (context.Context, *enumerationStateStore, *checkpointStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	checkpointStore := NewCheckpointStore(db, storage.NoOpTracer())
	store := NewEnumerationStateStore(db, checkpointStore, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, store, checkpointStore, cleanup
}

func TestPGEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()

	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	checkpoint := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})

	state := &enumeration.EnumerationState{
		SessionID:      "test-session",
		SourceType:     "github",
		Config:         json.RawMessage(`{"org": "test-org"}`),
		LastCheckpoint: checkpoint,
		Status:         enumeration.StatusInitialized,
	}

	err := store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID)
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

	ctx, store, _, cleanup := setupEnumerationTest(t)
	defer cleanup()

	loaded, err := store.Load(ctx, "non-existent-session")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestPGEnumerationStateStorage_Update(t *testing.T) {
	t.Parallel()

	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	checkpoint := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})

	initialState := &enumeration.EnumerationState{
		SessionID:      "test-session",
		SourceType:     "github",
		Config:         json.RawMessage(`{}`),
		LastCheckpoint: checkpoint,
		Status:         enumeration.StatusInitialized,
	}

	err := store.Save(ctx, initialState)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, initialState.SessionID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, enumeration.StatusInitialized, loaded.Status)
	assert.True(t, loaded.LastUpdated.After(initialState.LastUpdated),
		"LastUpdated should be later than initial save")
}

func TestPGEnumerationStateStorage_Mutability(t *testing.T) {
	t.Parallel()

	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	checkpoint := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
		"nested": map[string]any{
			"key": "value",
		},
	})

	original := &enumeration.EnumerationState{
		SessionID:      "test-session",
		SourceType:     "github",
		Config:         json.RawMessage(`{}`),
		LastCheckpoint: checkpoint,
		Status:         enumeration.StatusInitialized,
	}

	err := store.Save(ctx, original)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, original.SessionID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.Status = enumeration.StatusCompleted
	loaded.LastCheckpoint.Data["cursor"] = "modified"
	if nestedMap, ok := loaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.Load(ctx, original.SessionID)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, enumeration.StatusInitialized, reloaded.Status, "Status should not be modified")
	assert.Equal(t, "abc123", reloaded.LastCheckpoint.Data["cursor"], "Checkpoint cursor should not be modified")
	if nestedMap, ok := reloaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested checkpoint value should not be modified")
	}
}

func TestPGEnumerationStateStorage_ConcurrentOperations(t *testing.T) {
	t.Parallel()

	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			checkpoint := createTestCheckpoint(t, ctx, checkpointStore, fmt.Sprintf("test-target-%d", id), map[string]any{
				"value": id,
			})

			state := &enumeration.EnumerationState{
				SessionID:      "concurrent-session",
				SourceType:     "github",
				Config:         json.RawMessage(`{}`),
				LastCheckpoint: checkpoint,
				Status:         enumeration.StatusInProgress,
			}

			err := store.Save(ctx, state)
			require.NoError(t, err)

			_, err = store.Load(ctx, state.SessionID)
			require.NoError(t, err)

			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	loaded, err := store.Load(ctx, "concurrent-session")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "concurrent-session", loaded.SessionID)
	assert.Equal(t, enumeration.StatusInProgress, loaded.Status)
}

func TestPGEnumerationStateStorage_GetActiveStates(t *testing.T) {
	t.Parallel()

	ctx, store, _, cleanup := setupEnumerationTest(t)
	defer cleanup()

	// Create states with different statuses.
	states := []*enumeration.EnumerationState{
		{
			SessionID:  "session-1",
			SourceType: "github",
			Status:     enumeration.StatusInitialized,
			Config:     json.RawMessage(`{}`),
		},
		{
			SessionID:  "session-2",
			SourceType: "github",
			Status:     enumeration.StatusInProgress,
			Config:     json.RawMessage(`{}`),
		},
		{
			SessionID:  "session-3",
			SourceType: "github",
			Status:     enumeration.StatusCompleted,
			Config:     json.RawMessage(`{}`),
		},
	}

	for _, s := range states {
		err := store.Save(ctx, s)
		require.NoError(t, err)
	}

	active, err := store.GetActiveStates(ctx)
	require.NoError(t, err)
	require.Len(t, active, 2, "Should have 2 active states")

	for _, s := range active {
		assert.Contains(t, []enumeration.EnumerationStatus{
			enumeration.StatusInitialized,
			enumeration.StatusInProgress,
		}, s.Status)
	}
}

func TestPGEnumerationStateStorage_List(t *testing.T) {
	t.Parallel()

	ctx, store, _, cleanup := setupEnumerationTest(t)
	defer cleanup()

	states := []*enumeration.EnumerationState{
		{
			SessionID:  "session-1",
			SourceType: "github",
			Status:     enumeration.StatusCompleted,
			Config:     json.RawMessage(`{}`),
		},
		{
			SessionID:  "session-2",
			SourceType: "github",
			Status:     enumeration.StatusInProgress,
			Config:     json.RawMessage(`{}`),
		},
		{
			SessionID:  "session-3",
			SourceType: "github",
			Status:     enumeration.StatusInitialized,
			Config:     json.RawMessage(`{}`),
		},
	}

	for _, s := range states {
		err := store.Save(ctx, s)
		require.NoError(t, err)
	}

	listed, err := store.List(ctx, 2)
	require.NoError(t, err)
	require.Len(t, listed, 2, "Should respect the limit")

	assert.Equal(t, "session-3", listed[0].SessionID)
	assert.Equal(t, "session-2", listed[1].SessionID)
}

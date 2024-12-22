package memory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

func TestInMemoryEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	store := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	state := &storage.EnumerationState{
		SessionID:  "test-session",
		SourceType: "github",
		Config:     json.RawMessage(`{"org": "test-org"}`),
		LastCheckpoint: &storage.Checkpoint{
			TargetID: "test-target",
			Data: map[string]any{
				"cursor": "abc123",
			},
		},
		Status: storage.StatusInitialized,
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
}

func TestInMemoryEnumerationStateStorage_LoadEmpty(t *testing.T) {
	store := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	loaded, err := store.Load(ctx)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestInMemoryEnumerationStateStorage_Update(t *testing.T) {
	store := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	initialState := &storage.EnumerationState{
		SessionID:  "test-session",
		SourceType: "github",
		Status:     storage.StatusInitialized,
	}

	err := store.Save(ctx, initialState)
	require.NoError(t, err)
	firstSaveTime := initialState.LastUpdated

	// Wait a moment to ensure different timestamp.
	time.Sleep(time.Millisecond)

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

func TestInMemoryEnumerationStateStorage_Mutability(t *testing.T) {
	store := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	original := &storage.EnumerationState{
		SessionID:  "test-session",
		SourceType: "github",
		LastCheckpoint: &storage.Checkpoint{
			TargetID: "test-target",
			Data: map[string]any{
				"cursor": "abc123",
				"nested": map[string]any{
					"key": "value",
				},
			},
		},
		Status: storage.StatusInitialized,
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

	// Load again and verify original wasn't modified.
	reloaded, err := store.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, storage.StatusInitialized, reloaded.Status, "Status should not be modified")
	assert.Equal(t, "abc123", reloaded.LastCheckpoint.Data["cursor"], "Checkpoint cursor should not be modified")
	if nestedMap, ok := reloaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested checkpoint value should not be modified")
	}
}

func TestInMemoryEnumerationStateStorage_ConcurrentOperations(t *testing.T) {
	store := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()
	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			state := &storage.EnumerationState{
				SessionID:  "concurrent-session",
				SourceType: "github",
				LastCheckpoint: &storage.Checkpoint{
					TargetID: "test-target",
					Data: map[string]any{
						"value": id,
					},
				},
				Status: storage.StatusInProgress,
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

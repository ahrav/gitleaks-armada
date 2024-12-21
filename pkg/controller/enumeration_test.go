package controller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	storage := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	state := &EnumerationState{
		SessionID:  "test-session",
		SourceType: "github",
		Config:     json.RawMessage(`{"org": "test-org"}`),
		LastCheckpoint: &Checkpoint{
			TargetID: "test-target",
			Data: map[string]any{
				"cursor": "abc123",
			},
		},
		Status: StatusInitialized,
	}

	err := storage.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := storage.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, state.SessionID, loaded.SessionID)
	assert.Equal(t, state.SourceType, loaded.SourceType)
	assert.Equal(t, state.Config, loaded.Config)
	assert.Equal(t, state.Status, loaded.Status)
	assert.False(t, loaded.LastUpdated.IsZero(), "LastUpdated should be set")
}

func TestInMemoryEnumerationStateStorage_LoadEmpty(t *testing.T) {
	storage := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	loaded, err := storage.Load(ctx)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestInMemoryEnumerationStateStorage_Update(t *testing.T) {
	storage := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	initialState := &EnumerationState{
		SessionID:  "test-session",
		SourceType: "github",
		Status:     StatusInitialized,
	}

	err := storage.Save(ctx, initialState)
	require.NoError(t, err)
	firstSaveTime := initialState.LastUpdated

	// Wait a moment to ensure different timestamp.
	time.Sleep(time.Millisecond)

	initialState.Status = StatusInProgress
	err = storage.Save(ctx, initialState)
	require.NoError(t, err)

	loaded, err := storage.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, StatusInProgress, loaded.Status)
	assert.True(t, loaded.LastUpdated.After(firstSaveTime),
		"LastUpdated should be later than first save")
}

func TestInMemoryEnumerationStateStorage_Mutability(t *testing.T) {
	storage := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()

	original := &EnumerationState{
		SessionID:  "test-session",
		SourceType: "github",
		LastCheckpoint: &Checkpoint{
			TargetID: "test-target",
			Data: map[string]any{
				"cursor": "abc123",
				"nested": map[string]any{
					"key": "value",
				},
			},
		},
		Status: StatusInitialized,
	}

	err := storage.Save(ctx, original)
	require.NoError(t, err)

	loaded, err := storage.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.Status = StatusCompleted
	loaded.LastCheckpoint.Data["cursor"] = "modified"
	if nestedMap, ok := loaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	// Load again and verify original wasn't modified.
	reloaded, err := storage.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, StatusInitialized, reloaded.Status, "Status should not be modified")
	assert.Equal(t, "abc123", reloaded.LastCheckpoint.Data["cursor"], "Checkpoint cursor should not be modified")
	if nestedMap, ok := reloaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested checkpoint value should not be modified")
	}
}

func TestInMemoryEnumerationStateStorage_ConcurrentOperations(t *testing.T) {
	storage := NewInMemoryEnumerationStateStorage()
	ctx := context.Background()
	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			state := &EnumerationState{
				SessionID:  "concurrent-session",
				SourceType: "github",
				LastCheckpoint: &Checkpoint{
					TargetID: "test-target",
					Data: map[string]any{
						"value": id,
					},
				},
				Status: StatusInProgress,
			}

			err := storage.Save(ctx, state)
			require.NoError(t, err)

			_, err = storage.Load(ctx)
			require.NoError(t, err)

			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	loaded, err := storage.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "concurrent-session", loaded.SessionID)
	assert.Equal(t, StatusInProgress, loaded.Status)
}

package memory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

func TestInMemoryEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	store := NewEnumerationStateStorage(NewCheckpointStorage())
	ctx := context.Background()

	state := &enumeration.State{
		SessionID:  "test-session",
		SourceType: "github",
		Config:     json.RawMessage(`{"org": "test-org"}`),
		LastCheckpoint: &enumeration.Checkpoint{
			ID:       1,
			TargetID: "test-target",
			Data: map[string]any{
				"cursor": "abc123",
			},
		},
		Status: enumeration.StatusInitialized,
	}
	state.LastUpdated = time.Now()

	err := store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, state.SessionID, loaded.SessionID)
	assert.Equal(t, state.SourceType, loaded.SourceType)
	assert.Equal(t, state.Config, loaded.Config)
	assert.Equal(t, state.Status, loaded.Status)
	assert.Equal(t, state.LastCheckpoint.ID, loaded.LastCheckpoint.ID)
	assert.Equal(t, state.LastCheckpoint.TargetID, loaded.LastCheckpoint.TargetID)
	assert.Equal(t, state.LastCheckpoint.Data["cursor"], loaded.LastCheckpoint.Data["cursor"])
	assert.False(t, loaded.LastUpdated.IsZero(), "LastUpdated should be set")
}

func TestInMemoryEnumerationStateStorage_GetActiveStates(t *testing.T) {
	store := NewEnumerationStateStorage(NewCheckpointStorage())
	ctx := context.Background()

	state := &enumeration.State{
		SessionID:  "test-session",
		SourceType: "github",
		Status:     enumeration.StatusInProgress,
	}

	err := store.Save(ctx, state)
	require.NoError(t, err)

	states, err := store.GetActiveStates(ctx)
	require.NoError(t, err)
	require.Len(t, states, 1)

	assert.Equal(t, state.SessionID, states[0].SessionID)
	assert.Equal(t, state.Status, states[0].Status)

	// Test with completed state
	state.Status = enumeration.StatusCompleted
	err = store.Save(ctx, state)
	require.NoError(t, err)

	states, err = store.GetActiveStates(ctx)
	require.NoError(t, err)
	require.Empty(t, states)
}

func TestInMemoryEnumerationStateStorage_List(t *testing.T) {
	store := NewEnumerationStateStorage(NewCheckpointStorage())
	ctx := context.Background()

	state := &enumeration.State{
		SessionID:  "test-session",
		SourceType: "github",
		Status:     enumeration.StatusCompleted,
	}

	err := store.Save(ctx, state)
	require.NoError(t, err)

	states, err := store.List(ctx, 10)
	require.NoError(t, err)
	require.Len(t, states, 1)

	assert.Equal(t, state.SessionID, states[0].SessionID)
	assert.Equal(t, state.Status, states[0].Status)
}

func TestInMemoryEnumerationStateStorage_LoadEmpty(t *testing.T) {
	store := NewEnumerationStateStorage(NewCheckpointStorage())
	ctx := context.Background()

	loaded, err := store.Load(ctx, "test-session")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestInMemoryEnumerationStateStorage_Update(t *testing.T) {
	store := NewEnumerationStateStorage(NewCheckpointStorage())
	ctx := context.Background()

	initialState := &enumeration.State{
		SessionID:  "test-session",
		SourceType: "github",
	}
	initialState.UpdateStatus(enumeration.StatusInitialized)

	err := store.Save(ctx, initialState)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, initialState.SessionID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify initial state
	assert.Equal(t, enumeration.StatusInitialized, loaded.Status)
	assert.False(t, loaded.LastUpdated.IsZero())

	// Update state
	initialState.UpdateStatus(enumeration.StatusInProgress)
	err = store.Save(ctx, initialState)
	require.NoError(t, err)

	loaded2, err := store.Load(ctx, initialState.SessionID)
	require.NoError(t, err)
	require.NotNil(t, loaded2)

	// Verify updated state
	assert.Equal(t, enumeration.StatusInProgress, loaded2.Status)
	assert.NotEqual(t, loaded.LastUpdated, loaded2.LastUpdated,
		"LastUpdated should be different after update")
}

func TestInMemoryEnumerationStateStorage_Mutability(t *testing.T) {
	store := NewEnumerationStateStorage(NewCheckpointStorage())
	ctx := context.Background()

	original := &enumeration.State{
		SessionID:  "test-session",
		SourceType: "github",
		LastCheckpoint: &enumeration.Checkpoint{
			TargetID: "test-target",
			Data: map[string]any{
				"cursor": "abc123",
				"nested": map[string]any{
					"key": "value",
				},
			},
		},
		Status: enumeration.StatusInitialized,
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

	// Load again and verify original wasn't modified.
	reloaded, err := store.Load(ctx, original.SessionID)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, enumeration.StatusInitialized, reloaded.Status, "Status should not be modified")
	assert.Equal(t, "abc123", reloaded.LastCheckpoint.Data["cursor"], "Checkpoint cursor should not be modified")
	if nestedMap, ok := reloaded.LastCheckpoint.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested checkpoint value should not be modified")
	}
}

func TestInMemoryEnumerationStateStorage_ConcurrentOperations(t *testing.T) {
	store := NewEnumerationStateStorage(NewCheckpointStorage())
	ctx := context.Background()
	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			state := &enumeration.State{
				SessionID:  "concurrent-session",
				SourceType: "github",
				LastCheckpoint: &enumeration.Checkpoint{
					TargetID: "test-target",
					Data: map[string]any{
						"value": id,
					},
				},
				Status: enumeration.StatusInProgress,
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

package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

func TestInMemoryCheckpointStorage_SaveAndLoad(t *testing.T) {
	store := NewInMemoryCheckpointStorage()
	ctx := context.Background()

	checkpoint := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
			"page":   42,
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, checkpoint.TargetID, loaded.TargetID)
	assert.Equal(t, checkpoint.Data["cursor"], loaded.Data["cursor"])
	assert.Equal(t, checkpoint.Data["page"], loaded.Data["page"])
	assert.False(t, loaded.UpdatedAt.IsZero(), "UpdatedAt should be set")
}

func TestInMemoryCheckpointStorage_LoadNonExistent(t *testing.T) {
	storage := NewInMemoryCheckpointStorage()
	ctx := context.Background()

	loaded, err := storage.Load(ctx, "non-existent")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestInMemoryCheckpointStorage_Delete(t *testing.T) {
	store := NewInMemoryCheckpointStorage()
	ctx := context.Background()

	checkpoint := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	err = store.Delete(ctx, checkpoint.TargetID)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestInMemoryCheckpointStorage_DeleteNonExistent(t *testing.T) {
	store := NewInMemoryCheckpointStorage()
	ctx := context.Background()

	err := store.Delete(ctx, "non-existent")
	require.NoError(t, err)
}

func TestInMemoryCheckpointStorage_Update(t *testing.T) {
	store := NewInMemoryCheckpointStorage()
	ctx := context.Background()

	// Initial checkpoint.
	checkpoint := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)
	firstSaveTime := checkpoint.UpdatedAt

	// Wait a moment to ensure different timestamp.
	time.Sleep(time.Millisecond)

	checkpoint.Data["cursor"] = "def456"
	err = store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "def456", loaded.Data["cursor"])
	assert.True(t, loaded.UpdatedAt.After(firstSaveTime),
		"UpdatedAt should be later than first save")
}

func TestInMemoryCheckpointStorage_ConcurrentOperations(t *testing.T) {
	store := NewInMemoryCheckpointStorage()
	ctx := context.Background()
	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			checkpoint := &storage.Checkpoint{
				TargetID: "concurrent-target",
				Data: map[string]any{
					"value": id,
				},
			}

			err := store.Save(ctx, checkpoint)
			require.NoError(t, err)

			_, err = store.Load(ctx, checkpoint.TargetID)
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
	assert.NotNil(t, loaded.Data["value"])
}

func TestInMemoryCheckpointStorage_Mutability(t *testing.T) {
	store := NewInMemoryCheckpointStorage()
	ctx := context.Background()

	original := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
			"nested": map[string]any{
				"key": "value",
			},
		},
	}

	err := store.Save(ctx, original)
	require.NoError(t, err)

	// Load checkpoint
	loaded, err := store.Load(ctx, original.TargetID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.Data["cursor"] = "modified"
	if nestedMap, ok := loaded.Data["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	// Load again and verify original wasn't modified.
	reloaded, err := store.Load(ctx, original.TargetID)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, "abc123", reloaded.Data["cursor"], "Top-level value should not be modified")
	if nestedMap, ok := reloaded.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested value should not be modified")
	}
}

func TestInMemoryCheckpointStorage_LoadByID(t *testing.T) {
	store := NewInMemoryCheckpointStorage()
	ctx := context.Background()

	// Create and save a checkpoint.
	checkpoint := &storage.Checkpoint{
		ID:       123,
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
			"nested": map[string]any{
				"key": "value",
			},
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded, err := store.LoadByID(ctx, 123)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, checkpoint.ID, loaded.ID)
	assert.Equal(t, checkpoint.TargetID, loaded.TargetID)
	assert.Equal(t, checkpoint.Data["cursor"], loaded.Data["cursor"])
	if nestedMap, ok := loaded.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"])
	}

	nonExistent, err := store.LoadByID(ctx, 999)
	require.NoError(t, err)
	assert.Nil(t, nonExistent)

	loaded.Data["cursor"] = "modified"
	if nestedMap, ok := loaded.Data["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.LoadByID(ctx, 123)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, "abc123", reloaded.Data["cursor"], "Top-level value should not be modified")
	if nestedMap, ok := reloaded.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested value should not be modified")
	}
}

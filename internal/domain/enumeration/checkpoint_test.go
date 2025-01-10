package enumeration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestNewCheckpoint verifies that a checkpoint with a given ID is properly created.
func TestNewCheckpoint(t *testing.T) {
	cp := NewCheckpoint(123, uuid.New(), map[string]any{"foo": "bar"})
	require.Equal(t, int64(123), cp.ID())
	require.Equal(t, uuid.New(), cp.TargetID())
	require.Equal(t, "bar", cp.Data()["foo"])
	require.False(t, cp.IsTemporary(), "Checkpoint with ID != 0 should not be temporary")
}

// TestNewTemporaryCheckpoint verifies that a checkpoint without ID is considered temporary.
func TestNewTemporaryCheckpoint(t *testing.T) {
	cp := NewTemporaryCheckpoint(uuid.New(), map[string]any{"hello": "world"})
	require.Equal(t, int64(0), cp.ID())
	require.Equal(t, uuid.New(), cp.TargetID())
	require.True(t, cp.IsTemporary(), "Checkpoint with ID == 0 should be temporary")
}

// TestCheckpointSetID ensures that setting the ID on a temporary checkpoint works,
// but panics if the checkpoint is already persisted.
func TestCheckpointSetID(t *testing.T) {
	t.Run("Sets ID on temporary checkpoint", func(t *testing.T) {
		cp := NewTemporaryCheckpoint(uuid.New(), nil)
		require.True(t, cp.IsTemporary())
		cp.SetID(999)
		require.False(t, cp.IsTemporary())
		require.Equal(t, int64(999), cp.ID())
	})

	t.Run("Panics if checkpoint already has an ID", func(t *testing.T) {
		cp := NewCheckpoint(123, uuid.New(), nil)
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic but did not get one")
			}
		}()
		cp.SetID(456) // should panic
	})
}

// TestCheckpointJSONMarshaling verifies MarshalJSON and UnmarshalJSON round-trip.
func TestCheckpointJSONMarshaling(t *testing.T) {
	original := NewCheckpoint(10, uuid.New(), map[string]any{"key": "value"})
	originalBytes, err := json.Marshal(original)
	require.NoError(t, err)

	var cp Checkpoint
	require.NoError(t, json.Unmarshal(originalBytes, &cp))

	require.Equal(t, int64(10), cp.ID())
	require.Equal(t, uuid.New(), cp.TargetID())
	require.Equal(t, "value", cp.Data()["key"])
	require.WithinDuration(t, time.Now(), cp.UpdatedAt(), 2*time.Second)
}

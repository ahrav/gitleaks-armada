package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

func createTestCheckpoint(t *testing.T, ctx context.Context, store *checkpointStore, targetID string, data map[string]any) *enumeration.Checkpoint {
	t.Helper()
	checkpoint := enumeration.NewTemporaryCheckpoint(targetID, data)
	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	saved, err := store.Load(ctx, targetID)
	require.NoError(t, err)
	return saved
}

func setupEnumerationTest(t *testing.T) (context.Context, *enumerationSessionStateStore, *checkpointStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	checkpointStore := NewCheckpointStore(db, storage.NoOpTracer())
	store := NewEnumerationSessionStateStore(db, checkpointStore, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, store, checkpointStore, cleanup
}

func setupTestState(t *testing.T, ctx context.Context, checkpointStore *checkpointStore, targetID string) *enumeration.SessionState {
	t.Helper()
	// mockTime := &mockTimeProvider{current: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	state := enumeration.NewState(
		"github",
		json.RawMessage(`{"org": "test-org"}`),
		// enumeration.WithSessionTimeProvider(mockTime),
	)

	err := state.MarkInProgress()
	require.NoError(t, err)

	if targetID != "" {
		cp := createTestCheckpoint(t, ctx, checkpointStore, targetID, map[string]any{
			"cursor": "abc123",
			"nested": map[string]any{
				"key": "value",
			},
		})

		batch := enumeration.NewBatch(
			state.SessionID(),
			5,
			cp,
			// enumeration.WithTimeProvider(mockTime),
		)
		require.NoError(t, batch.MarkSuccessful(5))
		require.NoError(t, state.ProcessCompletedBatch(batch))
	}
	return state
}

func TestPGEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()
	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	state := setupTestState(t, ctx, checkpointStore, "test-target")

	cp := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})
	batch := enumeration.NewBatch(
		state.SessionID(),
		5,
		cp,
	)
	require.NoError(t, batch.MarkSuccessful(5))
	require.NoError(t, state.ProcessCompletedBatch(batch))

	err := store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, loaded, "Loaded session should not be nil")

	// Verify core state.
	assert.Equal(t, state.SessionID(), loaded.SessionID())
	assert.Equal(t, state.SourceType(), loaded.SourceType())
	assert.Equal(t, state.Config(), loaded.Config())
	assert.Equal(t, state.Status(), loaded.Status())

	// Verify timeline.
	require.NotNil(t, loaded.Timeline(), "Timeline should not be nil")
	assert.True(t, loaded.Timeline().StartedAt().Equal(state.Timeline().StartedAt()))
	assert.True(t, loaded.Timeline().LastUpdate().Equal(state.Timeline().LastUpdate()))

	// Verify metrics.
	require.NotNil(t, loaded.Metrics(), "Metrics should not be nil")
	assert.Equal(t, state.Metrics().TotalBatches(), loaded.Metrics().TotalBatches())
	assert.Equal(t, state.Metrics().FailedBatches(), loaded.Metrics().FailedBatches())
	assert.Equal(t, state.Metrics().ItemsProcessed(), loaded.Metrics().ItemsProcessed())
	assert.Equal(t, state.Metrics().ItemsFound(), loaded.Metrics().ItemsFound())

	// Verify checkpoint
	require.NotNil(t, loaded.LastCheckpoint(), "Loaded session should have a checkpoint")
	assert.Equal(t, "test-target", loaded.LastCheckpoint().TargetID())
	assert.Equal(t, "abc123", loaded.LastCheckpoint().Data()["cursor"])
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

	state := setupTestState(t, ctx, checkpointStore, "test-target")
	initialLastUpdate := state.Timeline().LastUpdate()

	err := store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Make a state change.
	err = loaded.MarkCompleted()
	require.NoError(t, err)

	// Save the updated state
	err = store.Save(ctx, loaded)
	require.NoError(t, err)

	// Load again and verify.
	reloaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, enumeration.StatusCompleted, reloaded.Status())
	assert.True(t, reloaded.Timeline().LastUpdate().After(initialLastUpdate),
		"LastUpdate should be later after making changes and saving again")
}

func TestPGEnumerationStateStorage_Mutability(t *testing.T) {
	t.Parallel()

	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	state := setupTestState(t, ctx, checkpointStore, "test-target")

	err := store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// loaded.Status = enumeration.StatusCompleted
	loaded.LastCheckpoint().Data()["cursor"] = "modified"
	if nestedMap, ok := loaded.LastCheckpoint().Data()["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, enumeration.StatusInProgress, reloaded.Status(), "Status should not be modified")
	assert.Equal(t, "abc123", reloaded.LastCheckpoint().Data()["cursor"], "Checkpoint cursor should not be modified")
	if nestedMap, ok := reloaded.LastCheckpoint().Data()["nested"].(map[string]any); ok {
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
			state := setupTestState(t, ctx, checkpointStore, fmt.Sprintf("test-target-%d", id))

			err := store.Save(ctx, state)
			require.NoError(t, err)

			_, err = store.Load(ctx, state.SessionID())
			require.NoError(t, err)

			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

func TestPGEnumerationStateStorage_GetActiveStates(t *testing.T) {
	t.Parallel()

	ctx, store, _, cleanup := setupEnumerationTest(t)
	defer cleanup()

	// Create states with different statuses
	states := make([]*enumeration.SessionState, 3)
	for i := range states {
		state := enumeration.NewState("github", json.RawMessage(`{}`))
		states[i] = state

		switch i {
		case 1:
			err := state.MarkInProgress()
			require.NoError(t, err)
		case 2:
			err := state.MarkInProgress()
			require.NoError(t, err)
			err = state.MarkCompleted()
			require.NoError(t, err)
		}

		err := store.Save(ctx, state)
		require.NoError(t, err)
	}

	active, err := store.GetActiveStates(ctx)
	require.NoError(t, err)
	require.Len(t, active, 2, "Should have 2 active states")

	for _, s := range active {
		assert.Contains(t, []enumeration.Status{
			enumeration.StatusInitialized,
			enumeration.StatusInProgress,
		}, s.Status())
	}
}

func TestPGEnumerationStateStorage_List(t *testing.T) {
	t.Parallel()

	ctx, store, _, cleanup := setupEnumerationTest(t)
	defer cleanup()

	// Create states with different statuses
	states := make([]*enumeration.SessionState, 3)
	for i := range states {
		state := enumeration.NewState("github", json.RawMessage(`{}`))
		states[i] = state

		switch i {
		case 0:
			err := state.MarkInProgress()
			require.NoError(t, err)
			err = state.MarkCompleted()
			require.NoError(t, err)
		case 1:
			err := state.MarkInProgress()
			require.NoError(t, err)
		}

		err := store.Save(ctx, state)
		require.NoError(t, err)
	}

	listed, err := store.List(ctx, 2)
	require.NoError(t, err)
	require.Len(t, listed, 2, "Should respect the limit")

	assert.Equal(t, states[2].SessionID(), listed[0].SessionID())
	assert.Equal(t, states[1].SessionID(), listed[1].SessionID())
}

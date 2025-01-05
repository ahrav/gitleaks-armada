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

func setupTestState(t *testing.T, ctx context.Context, checkpointStore *checkpointStore, targetID string) (*enumeration.SessionState, enumeration.LifecycleService) {
	t.Helper()
	domainSvc := enumeration.NewLifecycleService()
	state := enumeration.NewState("github", json.RawMessage(`{"org": "test-org"}`))

	err := domainSvc.MarkInProgress(state)
	require.NoError(t, err)

	if targetID != "" {
		cp := createTestCheckpoint(t, ctx, checkpointStore, targetID, map[string]any{
			"cursor": "abc123",
			"nested": map[string]any{
				"key": "value",
			},
		})

		batchProgress := enumeration.NewSuccessfulBatchProgress(5, cp)
		err = domainSvc.RecordBatchProgress(state, batchProgress)
		require.NoError(t, err)
	}

	return state, domainSvc
}

func TestPGEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()

	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	domainSvc := enumeration.NewLifecycleService()

	state := enumeration.NewState("github", json.RawMessage(`{"org": "test-org"}`))

	err := domainSvc.MarkInProgress(state)
	require.NoError(t, err)

	cp := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})

	batchProgress := enumeration.NewSuccessfulBatchProgress(5, cp)

	err = domainSvc.RecordBatchProgress(state, batchProgress)
	require.NoError(t, err)

	err = store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, loaded, "Loaded session should not be nil")

	assert.Equal(t, state.SessionID(), loaded.SessionID())
	assert.Equal(t, state.SourceType(), loaded.SourceType())
	assert.Equal(t, state.Config(), loaded.Config())
	assert.Equal(t, state.Status(), loaded.Status())
	assert.False(t, loaded.LastUpdated().IsZero(), "LastUpdated should be set")

	//  Verify checkpoint was saved and linked correctly.
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

	state, _ := setupTestState(t, ctx, checkpointStore, "test-target")

	err := store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, enumeration.StatusInProgress, loaded.Status())
	assert.True(t, loaded.LastUpdated().After(state.LastUpdated()),
		"LastUpdated should be later than initial save")
}

func TestPGEnumerationStateStorage_Mutability(t *testing.T) {
	t.Parallel()

	ctx, store, checkpointStore, cleanup := setupEnumerationTest(t)
	defer cleanup()

	state, _ := setupTestState(t, ctx, checkpointStore, "test-target")

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
			state, _ := setupTestState(t, ctx, checkpointStore, fmt.Sprintf("test-target-%d", id))

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

	domainSvc := enumeration.NewLifecycleService()

	// Create states with different statuses
	states := make([]*enumeration.SessionState, 3)
	for i := range states {
		state := enumeration.NewState("github", json.RawMessage(`{}`))
		states[i] = state

		switch i {
		case 1:
			err := domainSvc.MarkInProgress(state)
			require.NoError(t, err)
		case 2:
			err := domainSvc.MarkInProgress(state)
			require.NoError(t, err)
			err = domainSvc.MarkCompleted(state)
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

	domainSvc := enumeration.NewLifecycleService()

	// Create states with different statuses
	states := make([]*enumeration.SessionState, 3)
	for i := range states {
		state := enumeration.NewState("github", json.RawMessage(`{}`))
		states[i] = state

		switch i {
		case 0:
			err := domainSvc.MarkInProgress(state)
			require.NoError(t, err)
			err = domainSvc.MarkCompleted(state)
			require.NoError(t, err)
		case 1:
			err := domainSvc.MarkInProgress(state)
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

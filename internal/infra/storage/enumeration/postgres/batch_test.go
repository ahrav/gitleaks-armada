package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

func setupTestSession(t *testing.T, ctx context.Context, store *enumerationSessionStateStore) *enumeration.SessionState {
	t.Helper()
	state := enumeration.NewState(
		"github",
		json.RawMessage(`{"org": "test-org"}`),
	)
	err := store.Save(ctx, state)
	require.NoError(t, err)
	return state
}

func setupBatchTest(t *testing.T) (context.Context, *batchStore, *checkpointStore, *enumerationSessionStateStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	checkpointStore := NewCheckpointStore(db, storage.NoOpTracer())
	batchStore := NewBatchStore(db, checkpointStore, storage.NoOpTracer())
	sessionStore := NewEnumerationSessionStateStore(db, checkpointStore, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, batchStore, checkpointStore, sessionStore, cleanup
}

func createTestBatch(t *testing.T, sessionID string, checkpoint *enumeration.Checkpoint) *enumeration.Batch {
	t.Helper()
	return enumeration.NewBatch(sessionID, 5, checkpoint)
}

func TestBatchStore_SaveAndFindByID(t *testing.T) {
	t.Parallel()
	ctx, store, checkpointStore, sessionStore, cleanup := setupBatchTest(t)
	defer cleanup()

	// First create a session
	session := setupTestSession(t, ctx, sessionStore)

	cp := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})
	batch := createTestBatch(t, session.SessionID(), cp)

	err := store.Save(ctx, batch)
	require.NoError(t, err)

	found, err := store.FindByID(ctx, batch.BatchID())
	require.NoError(t, err)
	require.NotNil(t, found)

	// Verify batch properties.
	assert.Equal(t, batch.BatchID(), found.BatchID())
	assert.Equal(t, batch.SessionID(), found.SessionID())
	assert.Equal(t, batch.Status(), found.Status())
	assert.Equal(t, batch.Metrics().ExpectedItems(), found.Metrics().ExpectedItems())

	// Verify checkpoint.
	require.NotNil(t, found.Checkpoint())
	assert.Equal(t, cp.TargetID(), found.Checkpoint().TargetID())
	assert.Equal(t, cp.Data()["cursor"], found.Checkpoint().Data()["cursor"])
}

func TestBatchStore_FindBySessionID(t *testing.T) {
	t.Parallel()
	ctx, store, checkpointStore, sessionStore, cleanup := setupBatchTest(t)
	defer cleanup()

	// First create a session
	session := setupTestSession(t, ctx, sessionStore)
	sessionID := session.SessionID()

	// Create multiple batches for the same session
	batches := make([]*enumeration.Batch, 3)
	for i := range batches {
		cp := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
			"cursor": "abc123",
		})
		batch := createTestBatch(t, sessionID, cp)
		require.NoError(t, batch.MarkSuccessful(5))

		err := store.Save(ctx, batch)
		require.NoError(t, err)

		batches[i] = batch
	}

	// Test FindBySessionID
	found, err := store.FindBySessionID(ctx, sessionID)
	require.NoError(t, err)
	assert.Len(t, found, 3)

	// Test FindLastBySessionID
	last, err := store.FindLastBySessionID(ctx, sessionID)
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, batches[2].BatchID(), last.BatchID())
}

func TestBatchStore_UpdateExisting(t *testing.T) {
	t.Parallel()
	ctx, store, checkpointStore, sessionStore, cleanup := setupBatchTest(t)
	defer cleanup()

	session := setupTestSession(t, ctx, sessionStore)

	cp := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
		"cursor": "abc123",
	})
	batch := createTestBatch(t, session.SessionID(), cp)

	err := store.Save(ctx, batch)
	require.NoError(t, err)

	require.NoError(t, batch.MarkSuccessful(5))
	err = store.Save(ctx, batch)
	require.NoError(t, err)

	// Verify updates.
	found, err := store.FindByID(ctx, batch.BatchID())
	require.NoError(t, err)
	assert.Equal(t, enumeration.BatchStatusSucceeded, found.Status())
	assert.Equal(t, 5, found.Metrics().ItemsProcessed())
}

func TestBatchStore_NonExistentBatch(t *testing.T) {
	t.Parallel()
	ctx, store, _, _, cleanup := setupBatchTest(t)
	defer cleanup()

	found, err := store.FindByID(ctx, "non-existent-batch")
	require.Error(t, err)
	assert.Nil(t, found)

	batches, err := store.FindBySessionID(ctx, "non-existent-session")
	require.NoError(t, err)
	assert.Empty(t, batches)

	last, err := store.FindLastBySessionID(ctx, "non-existent-session")
	require.NoError(t, err)
	assert.Nil(t, last)
}

func TestBatchStore_ConcurrentOperations(t *testing.T) {
	t.Parallel()
	ctx, store, checkpointStore, sessionStore, cleanup := setupBatchTest(t)
	defer cleanup()

	session := setupTestSession(t, ctx, sessionStore)
	sessionID := session.SessionID()

	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			cp := createTestCheckpoint(t, ctx, checkpointStore, "test-target", map[string]any{
				"cursor": "abc123",
			})
			batch := createTestBatch(t, sessionID, cp)

			err := store.Save(ctx, batch)
			require.NoError(t, err)

			_, err = store.FindByID(ctx, batch.BatchID())
			require.NoError(t, err)

			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

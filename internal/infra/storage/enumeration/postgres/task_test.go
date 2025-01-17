package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

func setupTaskTest(t *testing.T) (context.Context, *taskStore, *enumerationSessionStateStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	store := NewTaskStore(db, storage.NoOpTracer())
	sessionStore := NewEnumerationSessionStateStore(db, NewCheckpointStore(db, storage.NoOpTracer()), storage.NoOpTracer())
	ctx := context.Background()

	return ctx, store, sessionStore, cleanup
}

func createTestTask(t *testing.T, ctx context.Context, sessionStore *enumerationSessionStateStore) *enumeration.Task {
	t.Helper()

	// First create and save a session state
	state := enumeration.NewState("github", json.RawMessage(`{"org": "test-org"}`))
	err := state.MarkInProgress() // Mark the state as in_progress before saving
	require.NoError(t, err)

	err = sessionStore.Save(ctx, state)
	require.NoError(t, err)

	metadata := map[string]string{
		"org":      "test-org",
		"repo":     "test-repo",
		"branch":   "main",
		"commit":   "abc123",
		"filename": "test.txt",
	}

	credentials := enumeration.NewGitHubCredentials("test-token")
	task := enumeration.NewTask(
		shared.SourceTypeGitHub,
		state.SessionID(),
		"https://github.com/test-org/test-repo",
		metadata,
		credentials,
	)
	return task
}

func TestPGTaskStorage_SaveAndGet(t *testing.T) {
	t.Parallel()

	ctx, store, sessionStore, cleanup := setupTaskTest(t)
	defer cleanup()

	task := createTestTask(t, ctx, sessionStore)

	err := store.Save(ctx, task)
	require.NoError(t, err)

	loaded, err := store.GetByID(ctx, task.ID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, task.ID, loaded.ID)
	assert.Equal(t, task.SourceType, loaded.SourceType)
	assert.Equal(t, task.SessionID(), loaded.SessionID())
	assert.Equal(t, task.ResourceURI(), loaded.ResourceURI())
	assert.Equal(t, task.Metadata(), loaded.Metadata())
}

func TestPGTaskStorage_GetNonExistent(t *testing.T) {
	t.Parallel()

	ctx, store, _, cleanup := setupTaskTest(t)
	defer cleanup()

	loaded, err := store.GetByID(ctx, uuid.New())
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestPGTaskStorage_SaveDuplicate(t *testing.T) {
	t.Parallel()

	ctx, store, sessionStore, cleanup := setupTaskTest(t)
	defer cleanup()

	task := createTestTask(t, ctx, sessionStore)

	// First save should succeed.
	err := store.Save(ctx, task)
	require.NoError(t, err)

	// Second save of the same task should fail.
	err = store.Save(ctx, task)
	require.Error(t, err)
}

func TestPGTaskStorage_ConcurrentOperations(t *testing.T) {
	t.Parallel()

	ctx, store, sessionStore, cleanup := setupTaskTest(t)
	defer cleanup()

	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func() {
			task := createTestTask(t, ctx, sessionStore)

			err := store.Save(ctx, task)
			require.NoError(t, err)

			_, err = store.GetByID(ctx, task.ID)
			require.NoError(t, err)

			done <- true
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

func TestPGTaskStorage_MetadataHandling(t *testing.T) {
	t.Parallel()

	ctx, store, sessionStore, cleanup := setupTaskTest(t)
	defer cleanup()

	state := enumeration.NewState("github", json.RawMessage(`{"org": "test-org"}`))
	err := sessionStore.Save(ctx, state)
	require.NoError(t, err)

	// Create a task with complex metadata.
	metadata := map[string]string{
		"empty":     "",
		"special":   "!@#$%^&*()",
		"unicode":   "测试",
		"multiline": "line1\nline2\nline3",
	}

	task := enumeration.NewTask(
		shared.SourceTypeGitHub,
		state.SessionID(),
		"https://github.com/test-org/test-repo",
		metadata,
		enumeration.NewGitHubCredentials("test-token"),
	)

	// Save and reload.
	err = store.Save(ctx, task)
	require.NoError(t, err)

	loaded, err := store.GetByID(ctx, task.ID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify metadata was preserved exactly.
	assert.Equal(t, metadata, loaded.Metadata())
}

package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
)

func setupEnumerationTest(t *testing.T) (context.Context, *EnumerationStateStorage) {
	t.Helper()
	ctx := context.Background()
	store := NewEnumerationStateStorage(nil) // No checkpoint store needed
	return ctx, store
}

func TestMemoryEnumerationStateStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()

	ctx, store := setupEnumerationTest(t)
	domainSvc := enumeration.NewLifecycleService()

	state := enumeration.NewState("github", json.RawMessage(`{"org": "test-org"}`))
	err := domainSvc.MarkInProgress(state)
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
}

func TestMemoryEnumerationStateStorage_LoadEmpty(t *testing.T) {
	t.Parallel()

	ctx, store := setupEnumerationTest(t)

	loaded, err := store.Load(ctx, "non-existent-session")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestMemoryEnumerationStateStorage_Update(t *testing.T) {
	t.Parallel()

	ctx, store := setupEnumerationTest(t)
	domainSvc := enumeration.NewLifecycleService()

	state := enumeration.NewState("github", json.RawMessage(`{"org": "test-org"}`))
	err := domainSvc.MarkInProgress(state)
	require.NoError(t, err)

	err = store.Save(ctx, state)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, state.SessionID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, enumeration.StatusInProgress, loaded.Status())
}

func TestMemoryEnumerationStateStorage_ConcurrentOperations(t *testing.T) {
	t.Parallel()

	ctx, store := setupEnumerationTest(t)
	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			state := enumeration.NewState("github", json.RawMessage(fmt.Sprintf(`{"id": %d}`, id)))

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

func TestMemoryEnumerationStateStorage_GetActiveStates(t *testing.T) {
	t.Parallel()

	ctx, store := setupEnumerationTest(t)
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

func TestMemoryEnumerationStateStorage_List(t *testing.T) {
	t.Parallel()

	ctx, store := setupEnumerationTest(t)
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

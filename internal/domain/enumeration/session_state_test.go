package enumeration

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewState checks that a new state has the expected default fields.
func TestNewState(t *testing.T) {
	cfg := json.RawMessage(`{"key":"value"}`)
	tp := &mockTimeProvider{current: time.Now()}
	s := NewState("github", cfg, WithSessionTimeProvider(tp))

	require.NotEmpty(t, s.SessionID())
	require.Equal(t, "github", s.SourceType())
	require.Equal(t, StatusInitialized, s.Status())
	require.Equal(t, cfg, s.Config())
	require.Empty(t, s.FailureReason())
	require.NotNil(t, s.Metrics())
	require.Equal(t, 0, s.Metrics().ItemsProcessed())
	require.Equal(t, 0, s.Metrics().TotalBatches())
	require.Equal(t, 0, s.Metrics().FailedBatches())
	require.Nil(t, s.LastCheckpoint())
	require.NotNil(t, s.Timeline())
	require.Equal(t, tp.Now(), s.Timeline().LastUpdate())
}

// TestReconstructState ensures reconstructing from persisted data yields a valid SessionState.
func TestReconstructState(t *testing.T) {
	now := time.Now()
	metrics := NewSessionMetrics()
	require.NoError(t, metrics.AddProcessedItems(10))
	metrics.IncrementTotalBatches()
	metrics.IncrementFailedBatches()

	timeline := NewTimeline(&mockTimeProvider{current: now})
	checkpoint := NewCheckpoint(1, uuid.New(), nil)

	s := ReconstructState(
		uuid.New(),
		"github",
		json.RawMessage(`{"foo":"bar"}`),
		StatusInProgress,
		timeline,
		"some error",
		checkpoint,
		metrics,
	)

	require.Equal(t, "session-abc", s.SessionID())
	require.Equal(t, "github", s.SourceType())
	require.Equal(t, StatusInProgress, s.Status())
	require.Equal(t, "some error", s.FailureReason())
	require.Equal(t, checkpoint, s.LastCheckpoint())
	require.NotNil(t, s.Metrics())
	require.Equal(t, 10, s.Metrics().ItemsProcessed())
	require.Equal(t, 1, s.Metrics().TotalBatches())
	require.Equal(t, 1, s.Metrics().FailedBatches())
	require.Equal(t, now, s.Timeline().LastUpdate())
}

// Mock implementation for tests.
type mockTimeProvider struct{ current time.Time }

func (m *mockTimeProvider) Now() time.Time { return m.current }

func (m *mockTimeProvider) Advance(d time.Duration) { m.current = m.current.Add(d) }

// TestIsStalled checks whether IsStalled logic returns true/false as expected.
func TestIsStalled(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		setupState  func(*SessionState, *mockTimeProvider)
		advanceTime time.Duration
		threshold   time.Duration
		wantStalled bool
	}{
		{
			name: "fresh state is not stalled",
			setupState: func(s *SessionState, _ *mockTimeProvider) {
				require.NoError(t, s.MarkInProgress())
			},
			threshold:   10 * time.Second,
			wantStalled: false,
		},
		{
			name: "state becomes stalled after threshold",
			setupState: func(s *SessionState, tp *mockTimeProvider) {
				require.NoError(t, s.MarkInProgress())
				batch := NewBatch(s.SessionID(), 5, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(tp))
				require.NoError(t, batch.MarkSuccessful(5))
				require.NoError(t, s.ProcessCompletedBatch(batch))
			},
			advanceTime: 15 * time.Second,
			threshold:   10 * time.Second,
			wantStalled: true,
		},
		{
			name: "completed state cannot be stalled",
			setupState: func(s *SessionState, _ *mockTimeProvider) {
				require.NoError(t, s.MarkInProgress())
				require.NoError(t, s.MarkCompleted())
			},
			advanceTime: 15 * time.Second,
			threshold:   10 * time.Second,
			wantStalled: false,
		},
		{
			name: "exactly at threshold is not stalled",
			setupState: func(s *SessionState, tp *mockTimeProvider) {
				require.NoError(t, s.MarkInProgress())
				batch := NewBatch(s.SessionID(), 5, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(tp))
				require.NoError(t, batch.MarkSuccessful(5))
				require.NoError(t, s.ProcessCompletedBatch(batch))
			},
			advanceTime: 10 * time.Second,
			threshold:   10 * time.Second,
			wantStalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &mockTimeProvider{current: baseTime}
			state := NewState("test", nil, WithSessionTimeProvider(tp))

			tt.setupState(state, tp)
			tp.Advance(tt.advanceTime)

			got := state.IsStalled(tt.threshold)
			assert.Equal(t, tt.wantStalled, got)
		})
	}
}

// TestSessionStateJSONMarshaling checks the round-trip JSON (un)marshaling for SessionState.
func TestSessionStateJSONMarshaling(t *testing.T) {
	tp := &mockTimeProvider{current: time.Now()}
	state := NewState("github", json.RawMessage(`{"some":"config"}`), WithSessionTimeProvider(tp))
	require.NoError(t, state.MarkInProgress())

	// Create and process a batch with a checkpoint
	cp := NewTemporaryCheckpoint(uuid.New(), map[string]any{"cursor": "xyz"})
	batch := NewBatch(state.SessionID(), 3, cp, WithTimeProvider(tp))
	require.NoError(t, batch.MarkSuccessful(3))
	require.NoError(t, state.ProcessCompletedBatch(batch))

	raw, err := json.Marshal(state)
	require.NoError(t, err)

	var reconstructed SessionState
	require.NoError(t, json.Unmarshal(raw, &reconstructed))

	// Verify core session state
	require.Equal(t, state.SessionID(), reconstructed.SessionID())
	require.Equal(t, state.SourceType(), reconstructed.SourceType())
	require.Equal(t, StatusInProgress, reconstructed.Status())
	require.Equal(t, state.Config(), reconstructed.Config())

	// Verify metrics
	require.NotNil(t, reconstructed.Metrics())
	require.Equal(t, 3, reconstructed.Metrics().ItemsProcessed())
	require.Equal(t, 1, reconstructed.Metrics().TotalBatches())
	require.Equal(t, 0, reconstructed.Metrics().FailedBatches())

	// Verify checkpoint
	require.NotNil(t, reconstructed.LastCheckpoint())
	require.Equal(t, "xyz", reconstructed.LastCheckpoint().Data()["cursor"])

	// Verify timeline
	require.NotNil(t, reconstructed.Timeline())
	require.True(t, state.Timeline().LastUpdate().Equal(reconstructed.Timeline().LastUpdate()),
		"Expected %v, got %v", state.Timeline().LastUpdate(), reconstructed.Timeline().LastUpdate())
}

func TestSessionState_StateTransitions(t *testing.T) {
	errKind := func(k EnumerationErrorKind) *EnumerationErrorKind { return &k }
	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mockTime := &mockTimeProvider{current: fixedTime}

	tests := []struct {
		name         string
		initialState Status
		transition   func(*SessionState) error

		wantStatus  Status
		wantErrKind *EnumerationErrorKind
	}{
		{
			name:         "initialized to in_progress",
			initialState: StatusInitialized,
			transition:   func(s *SessionState) error { return s.MarkInProgress() },
			wantStatus:   StatusInProgress,
			wantErrKind:  nil,
		},
		{
			name:         "in_progress to completed",
			initialState: StatusInProgress,
			transition:   func(s *SessionState) error { return s.MarkCompleted() },
			wantStatus:   StatusCompleted,
			wantErrKind:  nil,
		},
		{
			name:         "in_progress to failed",
			initialState: StatusInProgress,
			transition:   func(s *SessionState) error { return s.MarkFailed("test failure") },
			wantStatus:   StatusFailed,
			wantErrKind:  nil,
		},
		{
			name:         "invalid: completed to in_progress",
			initialState: StatusCompleted,
			transition:   func(s *SessionState) error { return s.MarkInProgress() },
			wantErrKind:  errKind(ErrKindInvalidStateTransition),
		},
		{
			name:         "invalid: failed to completed",
			initialState: StatusFailed,
			transition:   func(s *SessionState) error { return s.MarkCompleted() },
			wantErrKind:  errKind(ErrKindInvalidStateTransition),
		},
		{
			name:         "stalled to in_progress",
			initialState: StatusStalled,
			transition:   func(s *SessionState) error { return s.MarkInProgress() },
			wantStatus:   StatusInProgress,
			wantErrKind:  nil,
		},
		{
			name:         "stalled to failed",
			initialState: StatusStalled,
			transition:   func(s *SessionState) error { return s.MarkFailed("test failure") },
			wantStatus:   StatusFailed,
			wantErrKind:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewState("test", nil, WithSessionTimeProvider(mockTime))
			state.setStatus(tt.initialState)

			err := tt.transition(state)

			if tt.wantErrKind != nil {
				require.Error(t, err)
				var enumErr *EnumerationError
				require.ErrorAs(t, err, &enumErr)
				assert.Equal(t, *tt.wantErrKind, enumErr.kind)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, state.Status())
			require.True(t, state.Timeline().LastUpdate().Equal(mockTime.Now()),
				"Expected %v, got %v", state.Timeline().LastUpdate(), mockTime.Now())
		})
	}
}

func TestProcessCompletedBatch(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockTime := &mockTimeProvider{current: baseTime}

	t.Run("successfully process completed batch", func(t *testing.T) {
		tp := &mockTimeProvider{current: baseTime}
		s := NewState("github", nil, WithSessionTimeProvider(tp))
		require.NoError(t, s.MarkInProgress())

		batch := NewBatch(s.SessionID(), 10, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(tp))
		require.NoError(t, batch.MarkSuccessful(10))

		err := s.ProcessCompletedBatch(batch)
		require.NoError(t, err)
		require.Equal(t, 1, s.Metrics().TotalBatches())
		require.Equal(t, 0, s.Metrics().FailedBatches())
		require.Equal(t, 10, s.Metrics().ItemsProcessed())
		require.Equal(t, StatusInProgress, s.Status())
		require.Equal(t, batch.Checkpoint(), s.LastCheckpoint())
	})

	t.Run("process failed batch", func(t *testing.T) {
		tp := &mockTimeProvider{current: baseTime}
		s := NewState("github", nil, WithSessionTimeProvider(tp))
		require.NoError(t, s.MarkInProgress())

		batch := NewBatch(s.SessionID(), 10, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(tp))
		require.NoError(t, batch.MarkFailed(errors.New("test error")))

		err := s.ProcessCompletedBatch(batch)
		require.NoError(t, err)
		require.Equal(t, 1, s.Metrics().TotalBatches())
		require.Equal(t, 1, s.Metrics().FailedBatches())
		require.Equal(t, 0, s.Metrics().ItemsProcessed())
		require.Equal(t, StatusInProgress, s.Status())
	})

	t.Run("partially completed with mixed results", func(t *testing.T) {
		tp := &mockTimeProvider{current: baseTime}
		s := NewState("github", nil, WithSessionTimeProvider(tp))
		require.NoError(t, s.MarkInProgress())

		batch1 := NewBatch(s.SessionID(), 10, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(tp))
		require.NoError(t, batch1.MarkSuccessful(10))
		require.NoError(t, s.ProcessCompletedBatch(batch1))

		batch2 := NewBatch(s.SessionID(), 10, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(tp))
		require.NoError(t, batch2.MarkFailed(errors.New("test error")))
		require.NoError(t, s.ProcessCompletedBatch(batch2))

		require.Equal(t, 2, s.Metrics().TotalBatches())
		require.Equal(t, 1, s.Metrics().FailedBatches())
		require.Equal(t, 10, s.Metrics().ItemsProcessed())
		require.Equal(t, StatusPartiallyCompleted, s.Status())
		require.Equal(t, batch2.Checkpoint(), s.LastCheckpoint())
	})

	t.Run("cannot process batch when not in progress", func(t *testing.T) {
		tp := &mockTimeProvider{current: baseTime}
		s := NewState("github", nil, WithSessionTimeProvider(tp))
		batch := NewBatch(s.SessionID(), 10, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(tp))

		err := s.ProcessCompletedBatch(batch)
		require.Error(t, err)
		var enumErr *EnumerationError
		require.ErrorAs(t, err, &enumErr)
		require.Equal(t, ErrKindInvalidProgress, enumErr.kind)
	})

	t.Run("stalled session detection", func(t *testing.T) {
		s := NewState("github", nil, WithSessionTimeProvider(mockTime))
		require.NoError(t, s.MarkInProgress())

		mockTime.Advance(15 * time.Second)

		batch := NewBatch(s.SessionID(), 10, NewTemporaryCheckpoint(uuid.New(), nil), WithTimeProvider(mockTime))
		require.NoError(t, batch.MarkSuccessful(10))

		err := s.ProcessCompletedBatch(batch)
		require.NoError(t, err)
		require.Equal(t, StatusStalled, s.Status())
	})
}

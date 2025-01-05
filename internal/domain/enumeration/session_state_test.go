package enumeration

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewState checks that a new state has the expected default fields.
func TestNewState(t *testing.T) {
	cfg := json.RawMessage(`{"key":"value"}`)
	s := NewState("github", cfg)

	require.NotEmpty(t, s.SessionID())
	require.Equal(t, "github", s.SourceType())
	require.Equal(t, StatusInitialized, s.Status())
	require.Equal(t, cfg, s.Config())
	require.Empty(t, s.FailureReason())
	require.Nil(t, s.Progress())
	require.Nil(t, s.LastCheckpoint())
}

// TestReconstructState ensures reconstructing from persisted data yields a valid SessionState.
func TestReconstructState(t *testing.T) {
	now := time.Now()
	progress := ReconstructProgress(now.Add(-1*time.Hour), now, 10, 5, 1, 2, nil)
	checkpoint := NewCheckpoint(1, "my-target", nil)
	s := ReconstructState(
		"session-abc",
		"github",
		json.RawMessage(`{"foo":"bar"}`),
		StatusInProgress,
		now,
		"some error",
		checkpoint,
		progress,
	)

	require.Equal(t, "session-abc", s.SessionID())
	require.Equal(t, "github", s.SourceType())
	require.Equal(t, StatusInProgress, s.Status())
	require.Equal(t, "some error", s.FailureReason())
	require.Equal(t, checkpoint, s.LastCheckpoint())
	require.NotNil(t, s.Progress())
	require.WithinDuration(t, now, s.LastUpdated(), 2*time.Microsecond)
}

// For testing only
// For testing only
func (s *SessionState) recordBatchProgressWithThreshold(batch BatchProgress, threshold time.Duration) error {
	if s.Status() != StatusInProgress {
		return newInvalidProgressError("can only update progress when in progress")
	}

	if batch.Checkpoint() == nil {
		return newMissingCheckpointError()
	}

	if batch.ItemsProcessed() < 0 ||
		(s.Progress() != nil &&
			batch.ItemsProcessed()+s.Progress().ItemsProcessed() < s.Progress().ItemsProcessed()) {
		return newInvalidItemCountError()
	}

	// Check for stall before updating progress
	if s.IsStalled(threshold) {
		s.setStatus(StatusStalled)
		return nil
	}

	s.addBatchProgress(batch)
	s.attachCheckpoint(batch.Checkpoint())

	// Check for partial completion
	if s.HasFailedBatches() && s.Progress().ItemsProcessed() > 0 {
		s.setStatus(StatusPartiallyCompleted)
	}

	return nil
}

// TestRecordBatchProgress verifies valid progress updates, missing checkpoints, and auto state transitions.
func TestRecordBatchProgress(t *testing.T) {
	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockTime := &mockTimeProvider{current: baseTime}
	stallThreshold := 10 * time.Second

	s := NewState("bitbucket", nil).withTimeProvider(mockTime)
	require.NoError(t, s.MarkInProgress())

	// Missing checkpoint => error.
	bpNoCheckpoint := NewSuccessfulBatchProgress(5, nil)
	err := s.recordBatchProgressWithThreshold(bpNoCheckpoint, stallThreshold)
	require.Error(t, err)
	var enumErr *EnumerationError
	require.ErrorAs(t, err, &enumErr)
	assert.Equal(t, ErrKindMissingCheckpoint, enumErr.kind)

	// Provide a valid checkpoint.
	cp := NewTemporaryCheckpoint("test-target", nil)
	bp := NewSuccessfulBatchProgress(5, cp)
	require.NoError(t, s.recordBatchProgressWithThreshold(bp, stallThreshold))
	require.Equal(t, 1, s.Progress().TotalBatches())
	require.Equal(t, cp, s.LastCheckpoint())
	require.Equal(t, 5, s.Progress().ItemsProcessed())

	// Advance time to force stall detection.
	mockTime.Advance(15 * time.Second)

	// Next batch => triggers stall detection.
	cp2 := NewTemporaryCheckpoint("test-target2", nil)
	bp2 := NewSuccessfulBatchProgress(3, cp2)
	require.NoError(t, s.recordBatchProgressWithThreshold(bp2, stallThreshold))

	require.Equal(t, StatusStalled, s.Status(),
		"Expected stalled status after 15s without progress")

	// Test partial completion scenario.
	mockTime2 := &mockTimeProvider{current: baseTime}
	s2 := NewState("gitlab", nil).withTimeProvider(mockTime2)
	require.NoError(t, s2.MarkInProgress())

	// Add failed batch.
	cpFail := NewTemporaryCheckpoint("fail-target", nil)
	bpFail := NewFailedBatchProgress(errors.New("boom"), cpFail)
	require.NoError(t, s2.recordBatchProgressWithThreshold(bpFail, stallThreshold))
	require.Equal(t, StatusInProgress, s2.Status(),
		"Status should remain in_progress with only failed batches")

	// Add successful batch.
	cpSuccess := NewTemporaryCheckpoint("ok-target", nil)
	bpSuccess := NewSuccessfulBatchProgress(5, cpSuccess)
	require.NoError(t, s2.recordBatchProgressWithThreshold(bpSuccess, stallThreshold))
	require.Equal(t, StatusPartiallyCompleted, s2.Status(),
		"Status should be partially_completed with failed batch and processed items > 0")
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
		setupState  func(*SessionState)
		advanceTime time.Duration
		threshold   time.Duration
		wantStalled bool
	}{
		{
			name: "fresh state is not stalled",
			setupState: func(s *SessionState) {
				require.NoError(t, s.MarkInProgress())
			},
			threshold:   10 * time.Second,
			wantStalled: false,
		},
		{
			name: "state becomes stalled after threshold",
			setupState: func(s *SessionState) {
				require.NoError(t, s.MarkInProgress())
				// Add a batch to initialize progress
				cp := NewTemporaryCheckpoint("test", nil)
				bp := NewSuccessfulBatchProgress(5, cp)
				require.NoError(t, s.RecordBatchProgress(bp))
			},
			advanceTime: 15 * time.Second,
			threshold:   10 * time.Second,
			wantStalled: true,
		},
		{
			name: "completed state cannot be stalled",
			setupState: func(s *SessionState) {
				require.NoError(t, s.MarkInProgress())
				require.NoError(t, s.MarkCompleted())
			},
			advanceTime: 15 * time.Second,
			threshold:   10 * time.Second,
			wantStalled: false,
		},
		{
			name: "exactly at threshold is not stalled",
			setupState: func(s *SessionState) {
				require.NoError(t, s.MarkInProgress())
				cp := NewTemporaryCheckpoint("test", nil)
				bp := NewSuccessfulBatchProgress(5, cp)
				require.NoError(t, s.RecordBatchProgress(bp))
			},
			advanceTime: 10 * time.Second,
			threshold:   10 * time.Second,
			wantStalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTime := &mockTimeProvider{current: baseTime}
			state := NewState("test", nil).withTimeProvider(mockTime)

			tt.setupState(state)
			mockTime.Advance(tt.advanceTime)

			got := state.IsStalled(tt.threshold)
			assert.Equal(t, tt.wantStalled, got)
		})
	}
}

// TestSessionStateJSONMarshaling checks the round-trip JSON (un)marshaling for SessionState.
func TestSessionStateJSONMarshaling(t *testing.T) {
	state := NewState("github", json.RawMessage(`{"some":"config"}`))
	require.NoError(t, state.MarkInProgress())

	cp := NewTemporaryCheckpoint("checkpoint-target", map[string]any{"cursor": "xyz"})
	bp := NewSuccessfulBatchProgress(3, cp)
	require.NoError(t, state.RecordBatchProgress(bp))

	raw, err := json.Marshal(state)
	require.NoError(t, err)

	var reconstructed SessionState
	require.NoError(t, json.Unmarshal(raw, &reconstructed))

	require.Equal(t, state.SessionID(), reconstructed.SessionID())
	require.Equal(t, StatusInProgress, reconstructed.Status())
	require.NotNil(t, reconstructed.Progress())
	require.Equal(t, 3, reconstructed.Progress().ItemsProcessed())
	require.NotNil(t, reconstructed.LastCheckpoint())
	require.Equal(t, "xyz", reconstructed.LastCheckpoint().Data()["cursor"])
}

func TestSessionState_StateTransitions(t *testing.T) {
	errKind := func(k EnumerationErrorKind) *EnumerationErrorKind { return &k }

	tests := []struct {
		name         string
		initialState Status
		transition   func(*SessionState) error
		wantStatus   Status
		wantErrKind  *EnumerationErrorKind
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewState("test", nil)
			state.status = tt.initialState

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
			assert.False(t, state.LastUpdated().IsZero())
		})
	}
}

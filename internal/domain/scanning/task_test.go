package scanning

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestNewScanTask(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	taskID := uuid.New()
	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{currentTime: mockTime}

	task := NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com", WithTimeProvider(mockProvider))

	assert.NotNil(t, task)
	assert.Equal(t, jobID, task.JobID())
	assert.Equal(t, taskID, task.TaskID())
	assert.Equal(t, TaskStatusPending, task.Status())

	assert.True(t, task.StartTime().IsZero())
	assert.True(t, task.EndTime().IsZero())

	assert.Equal(t, int64(0), task.LastSequenceNum())
	assert.Equal(t, int64(0), task.ItemsProcessed())
	assert.Nil(t, task.LastCheckpoint())
	assert.Nil(t, task.ProgressDetails())
	assert.Equal(t, "https://example.com", task.ResourceURI())
}

func TestNewScanTask_DefaultTimeProvider(t *testing.T) {
	t.Parallel()

	jobID := uuid.New()
	taskID := uuid.New()

	task := NewScanTask(jobID, shared.SourceTypeGitHub, taskID, "https://example.com") // No time provider specified

	assert.NotNil(t, task)
	assert.True(t, task.StartTime().IsZero())
}

// mockTimeProvider implements TimeProvider for testing
type mockTimeProvider struct{ currentTime time.Time }

func (m *mockTimeProvider) Now() time.Time { return m.currentTime }

func TestTask_ApplyProgress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupTask func() *Task
		progress  Progress
		wantErr   bool
		verify    func(*testing.T, *Task)
	}{
		{
			name: "basic progress update",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
				timestamp:      time.Now(),
			},
			verify: func(t *testing.T, task *Task) {
				assert.Equal(t, int64(100), task.ItemsProcessed())
				assert.Equal(t, int64(1), task.LastSequenceNum())
				assert.Equal(t, TaskStatusInProgress, task.Status())
			},
		},
		{
			name: "update with checkpoint",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			progress: Progress{
				sequenceNum: 1,
				checkpoint: &Checkpoint{
					resumeToken: []byte("token"),
				},
			},
			verify: func(t *testing.T, task *Task) {
				assert.NotNil(t, task.LastCheckpoint())
				assert.Equal(t, []byte("token"), task.LastCheckpoint().ResumeToken())
			},
		},
		{
			name: "out of order update",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.ApplyProgress(Progress{sequenceNum: 2})
				return task
			},
			progress: Progress{
				sequenceNum: 1,
			},
			wantErr: true,
		},
		{
			name: "reject progress in pending state",
			setupTask: func() *Task {
				return NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			wantErr: true,
		},
		{
			name: "reject progress in paused state",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Pause()
				return task
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			wantErr: true,
		},
		{
			name: "reject progress in stale state",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.MarkStale(ReasonPtr(StallReasonNoProgress))
				return task
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			wantErr: true,
		},
		{
			name: "reject progress in completed state",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Complete()
				return task
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			task := tt.setupTask()
			tt.progress.taskID = task.TaskID()
			if tt.progress.Checkpoint() != nil {
				tt.progress.Checkpoint().taskID = task.TaskID()
			}

			err := task.ApplyProgress(tt.progress)

			if tt.wantErr {
				require.Error(t, err)
				var stateErr TaskInvalidStateError
				if errors.As(err, &stateErr) {
					assert.Equal(t, TaskInvalidStateReasonWrongStatus, stateErr.Reason())
				}
				return
			}

			require.NoError(t, err)
			if tt.verify != nil {
				tt.verify(t, task)
			}
		})
	}
}

func TestTask_Complete(t *testing.T) {
	t.Parallel()

	mockTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name           string
		setupTask      func(*mockTimeProvider) *Task
		expectedReason TaskInvalidStateReason
		verifyBehavior func(*testing.T, *Task, *mockTimeProvider)
	}{
		{
			name: "successful completion",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com", WithTimeProvider(tp))
				task.status = TaskStatusInProgress
				task.itemsProcessed = 100
				return task
			},
			verifyBehavior: func(t *testing.T, task *Task, tp *mockTimeProvider) {
				assert.Equal(t, TaskStatusCompleted, task.Status())
				assert.Equal(t, tp.Now(), task.EndTime())
			},
		},
		{
			name: "idempotent completion - already completed task",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com", WithTimeProvider(tp))
				task.status = TaskStatusCompleted
				task.timeline.MarkCompleted()
				return task
			},
			verifyBehavior: func(t *testing.T, task *Task, tp *mockTimeProvider) {
				// Verify the task remains completed and the end time wasn't updated
				assert.Equal(t, TaskStatusCompleted, task.Status())
				assert.NotEqual(t, tp.Now(), task.EndTime())
				assert.True(t, task.EndTime().Before(tp.Now()))
			},
		},
		{
			name: "failed task",
			setupTask: func(tp *mockTimeProvider) *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com", WithTimeProvider(tp))
				task.status = TaskStatusFailed
				return task
			},
			expectedReason: TaskInvalidStateReasonWrongStatus,
		},
		// TODO: Uncomment once progress is tracked in source scanners.
		// {
		// 	name: "no items processed",
		// 	setupTask: func(tp *mockTimeProvider) *Task {
		// 		return NewScanTask(uuid.New(), uuid.New(), WithTimeProvider(tp))
		// 	},
		// 	expectedReason: TaskInvalidStateReasonNoProgress,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tp := &mockTimeProvider{currentTime: mockTime}
			task := tt.setupTask(tp)

			// Advance time to simulate some processing.
			tp.currentTime = tp.currentTime.Add(time.Second)
			err := task.Complete()

			if tt.expectedReason != "" {
				require.Error(t, err)
				var stateErr TaskInvalidStateError
				require.ErrorAs(t, err, &stateErr)
				assert.Equal(t, tt.expectedReason, stateErr.Reason())
				return
			}

			require.NoError(t, err)

			// If there's custom verification logic, run it.
			if tt.verifyBehavior != nil {
				tt.verifyBehavior(t, task, tp)
			}

			// Try completing again to verify idempotency.
			if task.Status() == TaskStatusCompleted {
				originalEndTime := task.EndTime()
				tp.currentTime = tp.currentTime.Add(time.Second)

				err = task.Complete()
				require.NoError(t, err, "second completion should succeed")
				assert.Equal(t, TaskStatusCompleted, task.Status())
				assert.Equal(t, originalEndTime, task.EndTime(), "end time should not change on repeated completion")
			}
		})
	}
}

func TestTask_Fail(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		initialTask *Task
		wantErr     bool
		errType     error
	}{
		{
			name: "successfully fail task from in progress",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusInProgress,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			wantErr: false,
		},
		{
			name: "successfully fail task from stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusStale,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			wantErr: false,
		},
		{
			name: "fail to transition from completed state",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusCompleted,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			wantErr: true,
			errType: TaskInvalidStateError{},
		},
		{
			name: "fail to transition from failed state",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusFailed,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			wantErr: true,
			errType: TaskInvalidStateError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.initialTask.Fail()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}

				if _, ok := err.(TaskInvalidStateError); !ok {
					t.Errorf("expected TaskInvalidStateError but got %T", err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if tt.initialTask.Status() != TaskStatusFailed {
				t.Errorf("expected status %s but got %s", TaskStatusFailed, tt.initialTask.Status())
			}
		})
	}
}

func TestTask_MarkStale(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		initialTask *Task
		reason      *StallReason
		wantErr     bool
	}{
		{
			name: "successfully mark task as stale from in progress",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusInProgress,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			reason:  ReasonPtr(StallReasonNoProgress),
			wantErr: false,
		},
		{
			name: "fail to mark completed task as stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusCompleted,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			reason:  ReasonPtr(StallReasonNoProgress),
			wantErr: true,
		},
		{
			name: "fail to mark failed task as stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusFailed,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			reason:  ReasonPtr(StallReasonNoProgress),
			wantErr: true,
		},
		{
			name: "fail to mark already stale task as stale",
			initialTask: ReconstructTask(
				uuid.New(),
				uuid.New(),
				"",
				TaskStatusStale,
				0,
				time.Now(),
				time.Now(),
				time.Now(),
				0,
				nil,
				nil,
				nil,
				time.Time{},
				time.Time{},
				0,
			),
			reason:  ReasonPtr(StallReasonNoProgress),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			beforeStale := time.Now()
			err := tt.initialTask.MarkStale(tt.reason)

			if tt.wantErr {
				require.Error(t, err)
				var stateErr TaskInvalidStateError
				require.ErrorAs(t, err, &stateErr)
				assert.Equal(t, TaskInvalidStateReasonWrongStatus, stateErr.Reason())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, TaskStatusStale, tt.initialTask.Status())
			assert.Equal(t, tt.reason, tt.initialTask.StallReason())
			assert.True(t, tt.initialTask.StalledAt().After(beforeStale) ||
				tt.initialTask.StalledAt().Equal(beforeStale))
			assert.Greater(t, tt.initialTask.StalledDuration(), time.Duration(0))
		})
	}
}

func TestTask_LifecycleTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		setupTask     func() *Task
		transition    func(*Task) error
		wantStatus    TaskStatus
		wantErr       bool
		wantErrReason TaskInvalidStateReason
		verify        func(*testing.T, *Task)
	}{
		{
			name: "start - pending to in progress",
			setupTask: func() *Task {
				return NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
			},
			transition: func(t *Task) error { return t.Start() },
			wantStatus: TaskStatusInProgress,
			verify: func(t *testing.T, task *Task) {
				assert.False(t, task.StartTime().IsZero())
			},
		},
		{
			name: "start - fail from completed",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Complete()
				return task
			},
			transition:    func(t *Task) error { return t.Start() },
			wantErr:       true,
			wantErrReason: TaskInvalidStateReasonWrongStatus,
		},
		{
			name: "pause - in progress to paused",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			transition: func(t *Task) error { return t.Pause() },
			wantStatus: TaskStatusPaused,
			verify: func(t *testing.T, task *Task) {
				assert.False(t, task.PausedAt().IsZero())
			},
		},
		{
			name: "pause - fail from pending",
			setupTask: func() *Task {
				return NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
			},
			transition:    func(t *Task) error { return t.Pause() },
			wantErr:       true,
			wantErrReason: TaskInvalidStateReasonWrongStatus,
		},
		{
			name: "resume - paused to in progress",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Pause()
				return task
			},
			transition: func(t *Task) error { return t.Resume() },
			wantStatus: TaskStatusInProgress,
			verify: func(t *testing.T, task *Task) {
				assert.True(t, task.PausedAt().IsZero())
			},
		},
		{
			name: "resume - fail from in progress",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			transition:    func(t *Task) error { return t.Resume() },
			wantErr:       true,
			wantErrReason: TaskInvalidStateReasonWrongStatus,
		},
		{
			name: "mark stale - in progress to stale",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			transition: func(t *Task) error { return t.MarkStale(ReasonPtr(StallReasonNoProgress)) },
			wantStatus: TaskStatusStale,
			verify: func(t *testing.T, task *Task) {
				assert.NotNil(t, task.StallReason())
				assert.False(t, task.StalledAt().IsZero())
				assert.Equal(t, StallReasonNoProgress, *task.StallReason())
			},
		},
		{
			name: "mark stale - fail without reason",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			transition:    func(t *Task) error { return t.MarkStale(nil) },
			wantErr:       true,
			wantErrReason: TaskInvalidStateReasonNoReason,
		},
		{
			name: "mark stale - fail from completed",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Complete()
				return task
			},
			transition:    func(t *Task) error { return t.MarkStale(ReasonPtr(StallReasonNoProgress)) },
			wantErr:       true,
			wantErrReason: TaskInvalidStateReasonWrongStatus,
		},
		{
			name: "recover from stale",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.MarkStale(ReasonPtr(StallReasonNoProgress))
				return task
			},
			transition: func(t *Task) error { return t.RecoverFromStale() },
			wantStatus: TaskStatusInProgress,
			verify: func(t *testing.T, task *Task) {
				assert.Nil(t, task.StallReason())
				assert.True(t, task.StalledAt().IsZero())
				assert.Equal(t, 1, task.RecoveryAttempts())
			},
		},
		{
			name: "recover from stale - fail from in progress",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			transition:    func(t *Task) error { return t.RecoverFromStale() },
			wantErr:       true,
			wantErrReason: TaskInvalidStateReasonWrongStatus,
		},
		{
			name: "complete - in progress to completed",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				return task
			},
			transition: func(t *Task) error { return t.Complete() },
			wantStatus: TaskStatusCompleted,
			verify: func(t *testing.T, task *Task) {
				assert.False(t, task.EndTime().IsZero())
			},
		},
		{
			name: "complete - idempotent when already completed",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Complete()
				return task
			},
			transition: func(t *Task) error { return t.Complete() },
			wantStatus: TaskStatusCompleted,
		},
		{
			name: "fail - from any state",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Pause()
				return task
			},
			transition: func(t *Task) error { return t.Fail() },
			wantStatus: TaskStatusFailed,
			verify: func(t *testing.T, task *Task) {
				assert.False(t, task.EndTime().IsZero())
			},
		},
		{
			name: "fail - fail from failed",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Fail()
				return task
			},
			transition:    func(t *Task) error { return t.Fail() },
			wantStatus:    TaskStatusFailed,
			wantErr:       true,
			wantErrReason: TaskInvalidStateReasonWrongStatus,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			task := tt.setupTask()
			err := tt.transition(task)

			if tt.wantErr {
				require.Error(t, err)
				var stateErr TaskInvalidStateError
				require.ErrorAs(t, err, &stateErr)
				assert.Equal(t, tt.wantErrReason, stateErr.Reason())
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, task.Status())

			if tt.verify != nil {
				tt.verify(t, task)
			}
		})
	}
}

// TestUpdateTaskProgress tests the service layer's handling of state transitions
// before applying progress updates.
func TestUpdateTaskProgress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupTask func() *Task
		progress  Progress
		wantErr   bool
		verify    func(*testing.T, *Task)
	}{
		{
			name: "transition from pending to in progress",
			setupTask: func() *Task {
				return NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			verify: func(t *testing.T, task *Task) {
				assert.Equal(t, TaskStatusInProgress, task.Status())
				assert.Equal(t, int64(100), task.ItemsProcessed())
				assert.False(t, task.StartTime().IsZero())
			},
		},
		{
			name: "transition from paused to in progress",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Pause()
				return task
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			verify: func(t *testing.T, task *Task) {
				assert.Equal(t, TaskStatusInProgress, task.Status())
				assert.True(t, task.PausedAt().IsZero())
				assert.Equal(t, int64(100), task.ItemsProcessed())
			},
		},
		{
			name: "transition from stale to in progress",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.MarkStale(ReasonPtr(StallReasonNoProgress))
				return task
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			verify: func(t *testing.T, task *Task) {
				assert.Equal(t, TaskStatusInProgress, task.Status())
				assert.Equal(t, 1, task.RecoveryAttempts())
				assert.Nil(t, task.StallReason())
				assert.True(t, task.StalledAt().IsZero())
				assert.Equal(t, int64(100), task.ItemsProcessed())
			},
		},
		{
			name: "reject progress in completed state",
			setupTask: func() *Task {
				task := NewScanTask(uuid.New(), shared.SourceTypeGitHub, uuid.New(), "https://example.com")
				_ = task.Start()
				_ = task.Complete()
				return task
			},
			progress: Progress{
				sequenceNum:    1,
				itemsProcessed: 100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			task := tt.setupTask()
			tt.progress.taskID = task.TaskID()

			// Simulate service layer behavior
			var err error
			switch task.Status() {
			case TaskStatusStale:
				err = task.RecoverFromStale()
			case TaskStatusPaused:
				err = task.Resume()
			case TaskStatusPending:
				err = task.Start()
			case TaskStatusInProgress:
				// Already in correct state
			default:
				err = fmt.Errorf("unexpected task status: %s", task.Status())
			}

			if err == nil && !tt.wantErr {
				err = task.ApplyProgress(tt.progress)
			}

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.verify != nil {
				tt.verify(t, task)
			}
		})
	}
}

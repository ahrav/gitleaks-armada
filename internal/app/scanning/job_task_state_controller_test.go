package scanning

import (
	"context"
	"sync"
	"testing"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

func setupManager(t *testing.T) *JobTaskStateController {
	t.Helper()

	logger := logger.Noop()
	tracer := noop.NewTracerProvider().Tracer("test")
	return NewJobTaskStateController("test", logger, tracer)
}

func TestJobStateController_New(t *testing.T) {
	manager := setupManager(t)
	assert.NotNil(t, manager)
}

func TestJobStateController_AddTask_RemoveTask(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()
	taskID := uuid.New()
	cancelCalled := false

	cancelFunc := func(cause error) {
		cancelCalled = true
	}

	manager.AddTask(jobID, taskID, cancelFunc)

	count := manager.PauseJob(jobID)
	assert.Equal(t, 1, count)
	assert.True(t, cancelCalled)

	manager.ResumeJob(jobID)
	cancelCalled = false

	taskID2 := uuid.New()
	manager.AddTask(jobID, taskID2, cancelFunc)

	manager.RemoveTask(jobID, taskID2)

	count = manager.PauseJob(jobID)
	assert.Equal(t, 0, count)

	nonExistentTaskID := uuid.New()
	manager.RemoveTask(jobID, nonExistentTaskID)

	nonExistentJobID := uuid.New()
	manager.RemoveTask(nonExistentJobID, taskID)
}

func TestJobTaskStateController_ShouldRejectTask(t *testing.T) {
	dummyCancel := func(cause error) {}

	tests := []struct {
		name         string
		setupFunc    func(controller *JobTaskStateController) uuid.UUID
		expectReject bool
	}{
		{
			name:         "job doesn't exist",
			setupFunc:    func(controller *JobTaskStateController) uuid.UUID { return uuid.New() },
			expectReject: false,
		},
		{
			name: "job exists but not paused or cancelled",
			setupFunc: func(controller *JobTaskStateController) uuid.UUID {
				jobID := uuid.New()
				controller.AddTask(jobID, uuid.New(), dummyCancel)
				return jobID
			},
			expectReject: false,
		},
		{
			name: "job exists and is paused",
			setupFunc: func(controller *JobTaskStateController) uuid.UUID {
				jobID := uuid.New()
				controller.AddTask(jobID, uuid.New(), dummyCancel)
				controller.PauseJob(jobID)
				return jobID
			},
			expectReject: true,
		},
		{
			name: "job exists and is cancelled",
			setupFunc: func(controller *JobTaskStateController) uuid.UUID {
				jobID := uuid.New()
				controller.AddTask(jobID, uuid.New(), dummyCancel)
				controller.CancelJob(jobID)
				return jobID
			},
			expectReject: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := setupManager(t)
			jobID := tt.setupFunc(controller)

			result := controller.ShouldRejectTask(jobID)
			assert.Equal(t, tt.expectReject, result)
		})
	}
}

func TestJobStateController_PauseJob(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()

	count := manager.PauseJob(jobID)
	assert.Equal(t, 0, count)

	taskID1 := uuid.New()
	taskID2 := uuid.New()

	cancelCount := 0
	cancelFunc := func(cause error) {
		cancelCount++
		assert.Equal(t, PauseEvent, cause)
	}

	manager.ResumeJob(jobID)
	manager.AddTask(jobID, taskID1, cancelFunc)
	manager.AddTask(jobID, taskID2, cancelFunc)

	count = manager.PauseJob(jobID)

	assert.Equal(t, 2, count)
	assert.Equal(t, 2, cancelCount)
	assert.True(t, manager.ShouldRejectTask(jobID))

	manager.AddTask(jobID, uuid.New(), cancelFunc)
	assert.True(t, manager.ShouldRejectTask(jobID))
}

func TestJobStateController_ResumeJob(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()

	manager.ResumeJob(jobID)
	assert.False(t, manager.ShouldRejectTask(jobID))

	manager.PauseJob(jobID)
	assert.True(t, manager.ShouldRejectTask(jobID))

	manager.ResumeJob(jobID)
	assert.False(t, manager.ShouldRejectTask(jobID))
}

func TestJobStateController_Concurrency(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 100 {
			manager.AddTask(jobID, uuid.New(), func(cause error) {})
		}
	}()

	go func() {
		defer wg.Done()
		for range 100 {
			_ = manager.ShouldRejectTask(jobID)
		}
	}()

	wg.Wait()

	manager.ResumeJob(jobID)
	count := manager.PauseJob(jobID)
	assert.Equal(t, 100, count)
}

func TestJobStateController_CancelFunctionExecution(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()
	taskID := uuid.New()

	ctx, cancel := context.WithCancelCause(context.Background())
	var wasCanceled bool
	var cancelCause error

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		wasCanceled = true
		cancelCause = context.Cause(ctx)
	}()

	manager.AddTask(jobID, taskID, cancel)

	manager.PauseJob(jobID)
	wg.Wait()

	assert.True(t, wasCanceled)
	assert.Equal(t, PauseEvent, cancelCause)
}

func TestJobStateController_CancelJob(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()

	// Test cancelling non-existent job.
	taskIDs := manager.CancelJob(jobID)
	assert.Nil(t, taskIDs)
	assert.False(t, manager.ShouldRejectTask(jobID)) // Job should be marked as cancelled

	taskID1 := uuid.New()
	taskID2 := uuid.New()

	cancelCount := 0
	cancelFunc := func(cause error) {
		cancelCount++
		assert.Equal(t, CancelEvent, cause)
	}

	manager.ResumeJob(jobID)
	manager.AddTask(jobID, taskID1, cancelFunc)
	manager.AddTask(jobID, taskID2, cancelFunc)

	taskIDs = manager.CancelJob(jobID)

	assert.Equal(t, 2, len(taskIDs))
	assert.Equal(t, 2, cancelCount)
	assert.True(t, manager.ShouldRejectTask(jobID))

	taskIDMap := make(map[uuid.UUID]bool)
	for _, id := range taskIDs {
		taskIDMap[id] = true
	}
	assert.True(t, taskIDMap[taskID1])
	assert.True(t, taskIDMap[taskID2])

	// Test adding task to cancelled job.
	taskID3 := uuid.New()
	manager.AddTask(jobID, taskID3, cancelFunc)
	assert.True(t, manager.ShouldRejectTask(jobID))
}

func TestJobStateController_CancelJob_ContextCancellation(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()
	taskID := uuid.New()

	ctx, cancel := context.WithCancelCause(context.Background())
	var wasCanceled bool
	var cancelCause error

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		wasCanceled = true
		cancelCause = context.Cause(ctx)
	}()

	manager.AddTask(jobID, taskID, cancel)

	manager.CancelJob(jobID)
	wg.Wait()

	assert.True(t, wasCanceled)
	assert.Equal(t, CancelEvent, cancelCause)
}

func TestJobStateController_CancelAndPauseInteraction(t *testing.T) {
	manager := setupManager(t)
	jobID := uuid.New()

	cancelCount := 0
	cancelFunc := func(cause error) { cancelCount++ }

	for range 5 {
		manager.AddTask(jobID, uuid.New(), cancelFunc)
	}

	taskIDs := manager.CancelJob(jobID)
	assert.Equal(t, 5, len(taskIDs))
	assert.True(t, manager.ShouldRejectTask(jobID))

	// Try to pause an already cancelled job.
	pauseCount := manager.PauseJob(jobID)
	assert.Equal(t, 0, pauseCount) // No tasks should be paused as they were already cancelled

	// TODO: Think this through a little more. What happens if we get CancelEvent -> scanner crash -> Resume?
	// Resume and verify state.
	manager.ResumeJob(jobID)
	assert.True(t, manager.ShouldRejectTask(jobID)) // Job should be reset to normal state
}

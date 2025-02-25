package scanning

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestJobStateController_New(t *testing.T) {
	manager := NewJobTaskStateController()
	assert.NotNil(t, manager)
}

func TestJobStateController_AddTask_RemoveTask(t *testing.T) {
	manager := NewJobTaskStateController()
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

func TestJobStateController_IsJobPaused(t *testing.T) {
	manager := NewJobTaskStateController()
	jobID := uuid.New()

	assert.False(t, manager.IsJobPaused(jobID))

	manager.AddTask(jobID, uuid.New(), func(cause error) {})
	assert.False(t, manager.IsJobPaused(jobID))

	manager.ResumeJob(jobID)
	assert.False(t, manager.IsJobPaused(jobID))

	manager.PauseJob(jobID)
	assert.True(t, manager.IsJobPaused(jobID))
}

func TestJobStateController_PauseJob(t *testing.T) {
	manager := NewJobTaskStateController()
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
	assert.True(t, manager.IsJobPaused(jobID))

	manager.AddTask(jobID, uuid.New(), cancelFunc)
	assert.True(t, manager.IsJobPaused(jobID))
}

func TestJobStateController_ResumeJob(t *testing.T) {
	manager := NewJobTaskStateController()
	jobID := uuid.New()

	manager.ResumeJob(jobID)
	assert.False(t, manager.IsJobPaused(jobID))

	manager.PauseJob(jobID)
	assert.True(t, manager.IsJobPaused(jobID))

	manager.ResumeJob(jobID)
	assert.False(t, manager.IsJobPaused(jobID))
}

func TestJobStateController_Concurrency(t *testing.T) {
	manager := NewJobTaskStateController()
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
			_ = manager.IsJobPaused(jobID)
		}
	}()

	wg.Wait()

	manager.ResumeJob(jobID)
	count := manager.PauseJob(jobID)
	assert.Equal(t, 100, count)
}

func TestJobStateController_CancelFunctionExecution(t *testing.T) {
	manager := NewJobTaskStateController()
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

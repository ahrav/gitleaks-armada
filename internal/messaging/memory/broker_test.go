package memory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/pkg/messaging"
)

func TestPublishAndSubscribeTasks(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)

	expectedTask := messaging.Task{
		TaskID:      "test-task",
		ResourceURI: "test-uri",
	}

	err := broker.SubscribeTasks(ctx, func(task messaging.Task) error {
		defer wg.Done()
		assert.Equal(t, expectedTask, task)
		return nil
	})
	assert.NoError(t, err)

	err = broker.PublishTask(ctx, expectedTask)
	assert.NoError(t, err)

	wg.Wait()
}

func TestMultipleSubscribers(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx := context.Background()
	var wg sync.WaitGroup
	subscriberCount := 3
	wg.Add(subscriberCount)

	task := messaging.Task{TaskID: "test-multiple"}

	for i := 0; i < subscriberCount; i++ {
		err := broker.SubscribeTasks(ctx, func(receivedTask messaging.Task) error {
			defer wg.Done()
			assert.Equal(t, task, receivedTask)
			return nil
		})
		assert.NoError(t, err)
	}

	err := broker.PublishTask(ctx, task)
	assert.NoError(t, err)

	wg.Wait()
}

func TestHandlerError(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx := context.Background()
	expectedErr := errors.New("handler error")

	// Subscribe with an error-returning handler.
	err := broker.SubscribeTasks(ctx, func(task messaging.Task) error {
		return expectedErr
	})
	assert.NoError(t, err)

	err = broker.PublishTask(ctx, messaging.Task{TaskID: "test-error"})
	assert.ErrorIs(t, err, expectedErr)
}

func TestConcurrentPublishSubscribe(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx := context.Background()
	var wg sync.WaitGroup
	taskCount := 100
	subscriberCount := 5
	wg.Add(taskCount * subscriberCount)

	for i := 0; i < subscriberCount; i++ {
		err := broker.SubscribeTasks(ctx, func(task messaging.Task) error {
			defer wg.Done()
			return nil
		})
		assert.NoError(t, err)
	}

	for i := 0; i < taskCount; i++ {
		go func(id int) {
			task := messaging.Task{TaskID: fmt.Sprintf("task-%d", id)}
			err := broker.PublishTask(ctx, task)
			assert.NoError(t, err)
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for handlers")
	}
}

func TestPublishBatchWithError(t *testing.T) {
	broker := NewBroker()
	ctx := context.Background()
	expectedErr := errors.New("handler error")

	// Subscribe with a handler that fails on specific task.
	err := broker.SubscribeTasks(ctx, func(task messaging.Task) error {
		if task.TaskID == "fail-task" {
			return expectedErr
		}
		return nil
	})
	assert.NoError(t, err)

	tasks := []messaging.Task{
		{TaskID: "task-1"},
		{TaskID: "fail-task"},
		{TaskID: "task-3"}, // This should not be processed due to previous error
	}

	err = broker.PublishTasks(ctx, tasks)
	assert.ErrorIs(t, err, expectedErr)
}

func TestContextCancellation(t *testing.T) {
	broker := NewBroker()
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context before publishing.
	cancel()

	err := broker.PublishTask(ctx, messaging.Task{TaskID: "test-task"})
	assert.ErrorIs(t, err, context.Canceled)

	err = broker.SubscribeTasks(ctx, func(task messaging.Task) error {
		return nil
	})
	assert.ErrorIs(t, err, context.Canceled)
}

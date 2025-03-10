package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

func TestPublishAndSubscribeTasks(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)

	expectedTask := enumeration.NewTask(
		shared.SourceTypeGitHub,
		uuid.New(),
		"test-uri",
		map[string]string{},
		nil,
	)

	err := broker.SubscribeTasks(ctx, func(task enumeration.Task) error {
		defer wg.Done()
		assert.Equal(t, *expectedTask, task)
		return nil
	})
	assert.NoError(t, err)

	err = broker.PublishTask(ctx, *expectedTask)
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

	tsk := enumeration.NewTask(
		shared.SourceTypeGitHub,
		uuid.New(),
		"test-uri",
		map[string]string{},
		nil,
	)

	for i := 0; i < subscriberCount; i++ {
		err := broker.SubscribeTasks(ctx, func(receivedTask enumeration.Task) error {
			defer wg.Done()
			assert.Equal(t, *tsk, receivedTask)
			return nil
		})
		assert.NoError(t, err)
	}

	err := broker.PublishTask(ctx, *tsk)
	assert.NoError(t, err)

	wg.Wait()
}

func TestHandlerError(t *testing.T) {
	t.Parallel()

	broker := NewBroker()
	ctx := context.Background()
	expectedErr := errors.New("handler error")

	tsk := enumeration.NewTask(
		shared.SourceTypeGitHub,
		uuid.New(),
		"test-uri",
		map[string]string{},
		nil,
	)

	// Subscribe with an error-returning handler.
	err := broker.SubscribeTasks(ctx, func(task enumeration.Task) error {
		return expectedErr
	})
	assert.NoError(t, err)

	err = broker.PublishTask(ctx, *tsk)
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
		err := broker.SubscribeTasks(ctx, func(task enumeration.Task) error {
			defer wg.Done()
			return nil
		})
		assert.NoError(t, err)
	}

	for i := 0; i < taskCount; i++ {
		go func(id int) {
			task := enumeration.NewTask(
				shared.SourceTypeGitHub,
				uuid.New(),
				"test-uri",
				map[string]string{},
				nil,
			)
			err := broker.PublishTask(ctx, *task)
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

	task1ID := uuid.New()
	failTaskID := uuid.New()

	// Subscribe with a handler that fails on specific task.
	err := broker.SubscribeTasks(ctx, func(task enumeration.Task) error {
		if task.ID == failTaskID {
			return expectedErr
		}
		return nil
	})
	assert.NoError(t, err)

	tasks := []enumeration.Task{
		{CoreTask: shared.CoreTask{ID: task1ID}},
		{CoreTask: shared.CoreTask{ID: failTaskID}},
		{CoreTask: shared.CoreTask{ID: uuid.New()}}, // This should not be processed due to previous error
	}

	err = broker.PublishTasks(ctx, tasks)
	assert.ErrorIs(t, err, expectedErr)
}

func TestContextCancellation(t *testing.T) {
	broker := NewBroker()
	ctx, cancel := context.WithCancel(context.Background())

	tsk := enumeration.NewTask(
		shared.SourceTypeGitHub,
		uuid.New(),
		"test-uri",
		map[string]string{},
		nil,
	)

	// Cancel context before publishing.
	cancel()

	err := broker.PublishTask(ctx, *tsk)
	assert.ErrorIs(t, err, context.Canceled)

	err = broker.SubscribeTasks(ctx, func(task enumeration.Task) error {
		return nil
	})
	assert.ErrorIs(t, err, context.Canceled)
}

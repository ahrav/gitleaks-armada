package scanning

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// mockMetricsRepository is a minimal stub/mocking approach.
type mockMetricsRepository struct {
	mu                           sync.Mutex
	getJobMetricsFn              func(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error)
	getTaskFn                    func(ctx context.Context, taskID uuid.UUID) (*domain.Task, error)
	getCheckpointsFn             func(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error)
	updateJobStatusFn            func(ctx context.Context, jobID uuid.UUID, status domain.JobStatus) error
	updateMetricsAndCheckpointFn func(
		ctx context.Context,
		jobID uuid.UUID,
		metrics *domain.JobMetrics,
		partition int32,
		offset int64,
	) error
}

func (m *mockMetricsRepository) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getJobMetricsFn != nil {
		return m.getJobMetricsFn(ctx, jobID)
	}
	return nil, nil
}

func (m *mockMetricsRepository) GetTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getTaskFn != nil {
		return m.getTaskFn(ctx, taskID)
	}
	return nil, nil
}

func (m *mockMetricsRepository) GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getCheckpointsFn != nil {
		return m.getCheckpointsFn(ctx, jobID)
	}
	return nil, nil
}

func (m *mockMetricsRepository) UpdateJobStatus(ctx context.Context, jobID uuid.UUID, status domain.JobStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateJobStatusFn != nil {
		return m.updateJobStatusFn(ctx, jobID, status)
	}
	return nil
}

func (m *mockMetricsRepository) UpdateMetricsAndCheckpoint(
	ctx context.Context,
	jobID uuid.UUID,
	metrics *domain.JobMetrics,
	partition int32,
	offset int64,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateMetricsAndCheckpointFn != nil {
		return m.updateMetricsAndCheckpointFn(ctx, jobID, metrics, partition, offset)
	}
	return nil
}

// mockDomainEventReplayer stub.
type mockDomainEventReplayer struct {
	replayFromPositionFn func(ctx context.Context, position events.DomainPosition) (<-chan events.EventEnvelope, error)
}

func (m *mockDomainEventReplayer) ReplayFromPosition(
	ctx context.Context,
	position events.DomainPosition,
) (<-chan events.EventEnvelope, error) {
	if m.replayFromPositionFn != nil {
		return m.replayFromPositionFn(ctx, position)
	}
	ch := make(chan events.EventEnvelope)
	close(ch)
	return ch, nil
}

func TestHandleJobMetrics_NewJob(t *testing.T) {
	ctx := context.Background()
	jobID := uuid.New()
	taskID := uuid.New()

	repo := &mockMetricsRepository{
		getJobMetricsFn: func(ctx context.Context, id uuid.UUID) (*domain.JobMetrics, error) {
			// Simulate no metrics exist yet.
			return nil, domain.ErrNoJobMetricsFound
		},
		// Return a valid task so it's not "not found".
		getTaskFn: func(ctx context.Context, id uuid.UUID) (*domain.Task, error) {
			return &domain.Task{CoreTask: shared.CoreTask{ID: id}}, nil
		},
		// No checkpoints found.
		getCheckpointsFn: func(ctx context.Context, id uuid.UUID) (map[int32]int64, error) {
			return nil, domain.ErrNoCheckpointsFound
		},
	}
	replayer := new(mockDomainEventReplayer)

	tracker := NewJobMetricsAggregator(
		"controller-id",
		repo,
		replayer,
		logger.Noop(),
		noop.NewTracerProvider().Tracer(""),
	)

	ackCalled := false
	ackFunc := func(err error) {
		ackCalled = true
		require.NoError(t, err, "ack should have no error")
	}

	evt := events.EventEnvelope{
		Type: "some_event",
		Key:  "some_key",
		Payload: scanning.TaskJobMetricEvent{
			JobID:  jobID,
			TaskID: taskID,
			Status: domain.TaskStatusInProgress,
		},
		Metadata: events.EventMetadata{Partition: 1, Offset: 42},
	}

	err := tracker.HandleJobMetrics(ctx, evt, ackFunc)
	require.NoError(t, err, "handle job metrics for new job should succeed")

	// Since the tracker tries to process immediately, there's no reason to call processPendingMetrics here.
	// The job didn't exist but was created in-memory, the task was found, so the metric is processed successfully.

	// We expect that an immediate success won't call ack yet because flush hasn't happened.
	require.False(t, ackCalled, "ack should not be called until we flush or remove partition")

	// Flush the metrics.
	err = tracker.FlushMetrics(ctx)
	require.NoError(t, err, "flush metrics should succeed")
	// Now the ackFunc for partition 1 should have been called.
	require.True(t, ackCalled, "ack should have been called after flush")
}

func TestHandleJobMetrics_TaskNotFound(t *testing.T) {
	ctx := context.Background()
	jobID := uuid.New()
	taskID := uuid.New()

	repo := &mockMetricsRepository{
		// Pretend job metrics exist, so no replay needed.
		getJobMetricsFn: func(ctx context.Context, id uuid.UUID) (*domain.JobMetrics, error) {
			return domain.NewJobMetrics(), nil
		},
		// Return ErrTaskNotFound.
		getTaskFn: func(ctx context.Context, id uuid.UUID) (*domain.Task, error) {
			return nil, domain.ErrTaskNotFound
		},
	}
	replayer := new(mockDomainEventReplayer)

	tracker := NewJobMetricsAggregator(
		"controller-id",
		repo,
		replayer,
		logger.Noop(),
		noop.NewTracerProvider().Tracer(""),
	)

	ackCalled := false
	ackFunc := func(err error) {
		ackCalled = true
	}

	evt := events.EventEnvelope{
		Payload: scanning.TaskJobMetricEvent{
			JobID:  jobID,
			TaskID: taskID,
			Status: domain.TaskStatusInProgress,
		},
		Metadata: events.EventMetadata{Partition: 1, Offset: 100},
	}

	err := tracker.HandleJobMetrics(ctx, evt, ackFunc)
	require.NoError(t, err, "should not fail on missing task")

	// Because the task is not found, the metric should go to "pending".
	// The ack is not invoked (we haven't flush-acked anything), so:
	require.False(t, ackCalled, "ack not called immediately when task not found")
}

func TestProcessPendingMetrics_SucceedsOnSecondTry(t *testing.T) {
	ctx := context.Background()
	jobID := uuid.New()
	taskID := uuid.New()

	// Step 1: First, the repository doesn't know about the task.
	var firstCall bool = true
	var updateMetricsAndCheckpointCalled bool = false
	repo := &mockMetricsRepository{
		getJobMetricsFn: func(ctx context.Context, id uuid.UUID) (*domain.JobMetrics, error) {
			return domain.NewJobMetrics(), nil
		},
		getCheckpointsFn: func(ctx context.Context, id uuid.UUID) (map[int32]int64, error) {
			return nil, domain.ErrNoCheckpointsFound
		},
		getTaskFn: func(ctx context.Context, id uuid.UUID) (*domain.Task, error) {
			if firstCall {
				// Simulate not found.
				return nil, domain.ErrTaskNotFound
			}
			// On the second call, pretend the task now exists
			return &domain.Task{CoreTask: shared.CoreTask{ID: taskID}}, nil
		},
		updateMetricsAndCheckpointFn: func(ctx context.Context, jobID uuid.UUID, metrics *domain.JobMetrics, partition int32, offset int64) error {
			require.Equal(t, jobID, jobID)
			require.Equal(t, partition, int32(1))
			require.Equal(t, offset, int64(100))
			updateMetricsAndCheckpointCalled = true
			return nil
		},
	}

	tracker := NewJobMetricsAggregator(
		"controller-id",
		repo,
		nil,
		logger.Noop(),
		noop.NewTracerProvider().Tracer(""),
	)

	ackCalled := false
	ackFunc := func(err error) {
		ackCalled = true
		require.NoError(t, err, "ack should have no error")
	}

	// Step 2: Send an event for a task that doesn't exist. Should go to pending.
	evt := events.EventEnvelope{
		Type: scanning.EventTypeTaskJobMetric,
		Key:  jobID.String(),
		Payload: scanning.TaskJobMetricEvent{
			JobID:  jobID,
			TaskID: taskID,
			Status: domain.TaskStatusInProgress,
		},
		Metadata: events.EventMetadata{Partition: 1, Offset: 100},
	}

	err := tracker.HandleJobMetrics(ctx, evt, ackFunc)
	require.NoError(t, err, "should not fail on missing task")

	require.False(t, ackCalled, "ack should not be called yet")

	// Step 3: Now the next time, the repo will say the task exists. Let's process pending.
	firstCall = false // Flip so now getTask returns a valid task

	tracker.processPendingMetrics(ctx)

	// By this time, the pending metric should have been successfully processed.
	err = tracker.FlushMetrics(ctx)
	require.NoError(t, err, "flush metrics should succeed")
	require.True(t, updateMetricsAndCheckpointCalled, "update metrics and checkpoint should have been called")
}

func TestFlushMetrics_CallsUpdateAndAck(t *testing.T) {
	ctx := context.Background()
	jobID := uuid.New()
	taskID := uuid.New()

	calledPartitions := make(map[int32]int64)
	repo := &mockMetricsRepository{
		getJobMetricsFn: func(ctx context.Context, id uuid.UUID) (*domain.JobMetrics, error) {
			return domain.NewJobMetrics(), nil
		},
		getTaskFn: func(ctx context.Context, id uuid.UUID) (*domain.Task, error) {
			return &domain.Task{CoreTask: shared.CoreTask{ID: taskID}}, nil
		},
		updateMetricsAndCheckpointFn: func(
			ctx context.Context,
			j uuid.UUID,
			m *domain.JobMetrics,
			partition int32,
			offset int64,
		) error {
			calledPartitions[partition] = offset
			return nil
		},
	}

	tracker := NewJobMetricsAggregator("controller-id", repo, nil, logger.Noop(), noop.NewTracerProvider().Tracer(""))

	var ackCalledOffset int64
	ackFunc := func(err error) {
		require.NoError(t, err)
		ackCalledOffset = 55
	}

	evt := events.EventEnvelope{
		Type: scanning.EventTypeTaskJobMetric,
		Key:  jobID.String(),
		Payload: scanning.TaskJobMetricEvent{
			JobID:  jobID,
			TaskID: taskID,
			Status: domain.TaskStatusInProgress,
		},
		Metadata: events.EventMetadata{Partition: 1, Offset: 55},
	}
	err := tracker.HandleJobMetrics(ctx, evt, ackFunc)
	require.NoError(t, err)

	// Confirm flush triggers UpdateMetricsAndCheckpoint & ack.
	err = tracker.FlushMetrics(ctx)
	require.NoError(t, err, "flush should succeed")

	require.Len(t, calledPartitions, 1)
	require.Equal(t, int64(55), calledPartitions[1], "offset must match event offset")

	require.Equal(t, int64(55), ackCalledOffset, "AckFunc offset indicates ack was triggered")
}

func TestCleanupTaskStatus_RemovesOldTerminalStatus(t *testing.T) {
	ctx := context.Background()

	repo := new(mockMetricsRepository)
	replayer := new(mockDomainEventReplayer)

	tracker := NewJobMetricsAggregator("controller-id", repo, replayer, logger.Noop(), noop.NewTracerProvider().Tracer(""))

	baseTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mockTime := &mockTimeProvider{now: baseTime}
	tracker.timeProvider = mockTime

	// Override config for cleanup threshold safely.
	tracker.mu.Lock()
	tracker.retentionPeriod = 1 * time.Hour
	tracker.mu.Unlock()

	completedTask := uuid.New()

	// Protect writes to taskStatus with the tracker mutex.
	tracker.mu.Lock()
	tracker.taskStatus[completedTask] = taskStatusEntry{
		status:    domain.TaskStatusCompleted,
		updatedAt: baseTime.Add(-2 * time.Hour), // Clearly older than retention period
	}
	tracker.mu.Unlock()

	tracker.cleanupTaskStatus(ctx)

	// The completedTask should be removed.
	tracker.mu.RLock()
	_, exists := tracker.taskStatus[completedTask]
	tracker.mu.RUnlock()
	require.False(t, exists, "Completed task older than retention period should be removed")
}

func TestHandleEnumerationCompleted_MarksJobCompleted(t *testing.T) {
	ctx := context.Background()
	jobID := uuid.New()

	var updateJobStatusCalled bool
	var updateJobStatusArg domain.JobStatus
	var updateMetricsAndCheckpointCalled bool
	var updateMetricsAndCheckpointPartition int32
	var updateMetricsAndCheckpointOffset int64

	repo := &mockMetricsRepository{
		// Return metrics with 2 tasks that are already completed.
		getJobMetricsFn: func(ctx context.Context, id uuid.UUID) (*domain.JobMetrics, error) {
			metrics := domain.NewJobMetrics()
			metrics.OnTaskAdded(domain.TaskStatusCompleted)
			metrics.OnTaskAdded(domain.TaskStatusCompleted)
			return metrics, nil
		},
		updateJobStatusFn: func(ctx context.Context, id uuid.UUID, status domain.JobStatus) error {
			updateJobStatusCalled = true
			updateJobStatusArg = status
			return nil
		},
		// Avoid ErrTaskNotFound by returning a dummy Task
		getTaskFn: func(ctx context.Context, id uuid.UUID) (*domain.Task, error) {
			return &domain.Task{}, nil
		},
		updateMetricsAndCheckpointFn: func(
			ctx context.Context,
			id uuid.UUID,
			metrics *domain.JobMetrics,
			partition int32,
			offset int64,
		) error {
			updateMetricsAndCheckpointCalled = true
			updateMetricsAndCheckpointPartition = partition
			updateMetricsAndCheckpointOffset = offset
			return nil
		},
	}

	aggregator := NewJobMetricsAggregator("controller-id", repo, nil, logger.Noop(), noop.NewTracerProvider().Tracer(""))

	ackCalled := false
	ackFunc := func(err error) { ackCalled = true; require.NoError(t, err) }

	// Fire "TaskCompleted" for each, so aggregator increments st.completedCount.
	// They can be "TaskJobMetricEvent" with status = TaskStatusCompleted.
	evt1 := events.EventEnvelope{
		Type: scanning.EventTypeTaskCompleted, // or custom type
		Payload: scanning.TaskJobMetricEvent{
			JobID:  jobID,
			TaskID: uuid.New(),
			Status: domain.TaskStatusCompleted,
		},
		Metadata: events.EventMetadata{Partition: 0, Offset: 10},
	}
	evt2 := events.EventEnvelope{
		Type: scanning.EventTypeTaskCompleted,
		Payload: scanning.TaskJobMetricEvent{
			JobID:  jobID,
			TaskID: uuid.New(),
			Status: domain.TaskStatusCompleted,
		},
		Metadata: events.EventMetadata{Partition: 0, Offset: 11},
	}

	// Process them; aggregator updates completedCount=2 for jobID.
	require.NoError(t, aggregator.HandleJobMetrics(ctx, evt1, ackFunc))
	require.NoError(t, aggregator.HandleJobMetrics(ctx, evt2, ackFunc))

	const (
		testPartition = int32(0)
		testOffset    = int64(42)
	)

	// Now call HandleEnumerationCompleted => aggregator sees finalTaskCount=2, completedCount=2 => job is done
	evt := events.EventEnvelope{
		Type: scanning.EventTypeJobEnumerationCompleted,
		Key:  jobID.String(),
		Payload: scanning.JobEnumerationCompletedEvent{
			JobID:      jobID,
			TotalTasks: 2,
		},
		Metadata: events.EventMetadata{Partition: testPartition, Offset: testOffset},
	}

	// --- 1) First call to HandleEnumerationCompleted.
	err := aggregator.HandleEnumerationCompleted(ctx, evt, ackFunc)
	require.NoError(t, err, "HandleEnumerationCompleted should succeed")

	// Job should be immediately recognized as done (2 tasks completed)
	// => aggregator finalizes it => calls UpdateJobStatus(JobStatusCompleted).
	require.True(t, updateJobStatusCalled, "UpdateJobStatus must be called the first time")
	require.Equal(t, domain.JobStatusCompleted, updateJobStatusArg, "job should be marked as completed")

	// Because we haven't flushed yet, aggregator hasn't acked the event.
	require.False(t, ackCalled, "Ack should not be called until we flush")

	// --- 2) Flush metrics => This should call UpdateMetricsAndCheckpoint + ack.
	err = aggregator.FlushMetrics(ctx)
	require.NoError(t, err, "FlushMetrics should succeed")

	require.True(t, ackCalled, "Ack should be called after flush")
	require.True(t, updateMetricsAndCheckpointCalled,
		"UpdateMetricsAndCheckpoint must be called during flush")

	require.Equal(t, testPartition, updateMetricsAndCheckpointPartition)
	require.Equal(t, testOffset, updateMetricsAndCheckpointOffset)

	// --- 3) Second call to HandleEnumerationCompleted with the same event.
	// The aggregator has already marked the job as finalized => no need to finalize again.
	updateJobStatusCalled = false // reset to see if aggregator calls it again
	err = aggregator.HandleEnumerationCompleted(ctx, evt, ackFunc)
	require.NoError(t, err, "Second call should succeed idempotently")

	// Since the job is already finalized, aggregator should NOT call UpdateJobStatus again.
	require.False(t, updateJobStatusCalled,
		"UpdateJobStatus should NOT be called again, aggregator is idempotent")
}

// func TestHandleEnumerationCompleted_MarksJobCompleted(t *testing.T) {
// 	ctx := context.Background()
// 	jobID := uuid.New()

// 	var updateJobStatusCalled bool
// 	var updateJobStatusArg domain.JobStatus
// 	var updateMetricsAndCheckpointCalled bool
// 	var updateMetricsAndCheckpointPartition int32
// 	var updateMetricsAndCheckpointOffset int64

// 	repo := &mockMetricsRepository{
// 		getJobMetricsFn: func(ctx context.Context, id uuid.UUID) (*domain.JobMetrics, error) {
// 			// Return metrics with all tasks completed.
// 			metrics := domain.NewJobMetrics()
// 			// Simulate 2 tasks that are already completed.
// 			metrics.OnTaskAdded(domain.TaskStatusCompleted)
// 			metrics.OnTaskAdded(domain.TaskStatusCompleted)
// 			return metrics, nil
// 		},
// 		updateJobStatusFn: func(ctx context.Context, id uuid.UUID, status domain.JobStatus) error {
// 			updateJobStatusCalled = true
// 			updateJobStatusArg = status
// 			return nil
// 		},
// 		// Add GetTask to avoid not found errors.
// 		getTaskFn: func(ctx context.Context, id uuid.UUID) (*domain.Task, error) {
// 			return &domain.Task{CoreTask: shared.CoreTask{ID: id}}, nil
// 		},
// 		updateMetricsAndCheckpointFn: func(ctx context.Context, id uuid.UUID, metrics *domain.JobMetrics, partition int32, offset int64) error {
// 			updateMetricsAndCheckpointCalled = true
// 			updateMetricsAndCheckpointPartition = partition
// 			updateMetricsAndCheckpointOffset = offset
// 			return nil
// 		},
// 	}

// 	tracker := NewJobMetricsAggregator(
// 		"controller-id",
// 		repo,
// 		nil,
// 		logger.Noop(),
// 		noop.NewTracerProvider().Tracer(""),
// 	)

// 	ackCalled := false
// 	ackFunc := func(err error) {
// 		ackCalled = true
// 		require.NoError(t, err, "ack should have no error")
// 	}

// 	const (
// 		testPartition = int32(1)
// 		testOffset    = int64(42)
// 	)

// 	evt := events.EventEnvelope{
// 		Type: scanning.EventTypeJobEnumerationCompleted,
// 		Key:  jobID.String(),
// 		Payload: scanning.JobEnumerationCompletedEvent{
// 			JobID:      jobID,
// 			TotalTasks: 2, // Set total tasks to match our completed tasks
// 		},
// 		Metadata: events.EventMetadata{
// 			Partition: testPartition,
// 			Offset:    testOffset,
// 		},
// 	}

// 	err := tracker.HandleEnumerationCompleted(ctx, evt, ackFunc)
// 	require.NoError(t, err, "handle enumeration completed should succeed")

// 	// Verify that UpdateJobStatus was called with JobStatusCompleted.
// 	require.True(t, updateJobStatusCalled, "UpdateJobStatus should have been called")
// 	require.Equal(t, domain.JobStatusCompleted, updateJobStatusArg, "job should be marked as completed")

// 	// Verify the ack function wasn't called yet (needs flush).
// 	require.False(t, ackCalled, "ack should not be called until flush")

// 	// Flush metrics and verify ack is called.
// 	err = tracker.FlushMetrics(ctx)
// 	require.NoError(t, err, "flush metrics should succeed")
// 	require.True(t, ackCalled, "ack should be called after flush")

// 	// Verify checkpoint was updated with correct partition and offset.
// 	require.True(t, updateMetricsAndCheckpointCalled, "UpdateMetricsAndCheckpoint should have been called")
// 	require.Equal(t, testPartition, updateMetricsAndCheckpointPartition, "checkpoint partition should match event")
// 	require.Equal(t, testOffset, updateMetricsAndCheckpointOffset, "checkpoint offset should match event")

// 	// This shouldn't happen in normal circumstances, but it can occur if the controller
// 	// restarts and re-processes the same event.
// 	updateJobStatusCalled = false // Reset flag
// 	err = tracker.HandleEnumerationCompleted(ctx, evt, ackFunc)
// 	require.NoError(t, err, "second handle enumeration completed should succeed")
// 	require.False(t, updateJobStatusCalled, "UpdateJobStatus should not be called again")
// }

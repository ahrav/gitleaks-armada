package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

func setupTaskTest(t *testing.T) (context.Context, *pgxpool.Pool, *taskStore, *jobStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	taskStore := NewTaskStore(db, storage.NoOpTracer())
	jobStore := NewJobStore(db, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, db, taskStore, jobStore, cleanup
}

func createTestScanJob(t *testing.T, store *jobStore, ctx context.Context) *scanning.Job {
	t.Helper()
	job := scanning.ReconstructJob(
		uuid.New(),
		scanning.JobStatusQueued,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
		nil,
		scanning.ReconstructJobMetrics(0, 0, 0),
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)
	return job
}

func createTestTask(t *testing.T, jobID uuid.UUID, status scanning.TaskStatus) *scanning.Task {
	t.Helper()
	return scanning.ReconstructTask(
		uuid.New(),
		jobID,
		status,
		0,
		time.Now().UTC(),
		time.Time{},
		0,
		nil,
		nil,
		scanning.StallReasonNoProgress,
		time.Time{},
	)
}

func TestTaskStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, task.TaskID(), loaded.TaskID())
	assert.Equal(t, task.JobID(), loaded.JobID())
	assert.Equal(t, task.Status(), loaded.Status())
	assert.Equal(t, task.LastSequenceNum(), loaded.LastSequenceNum())
	assert.Equal(t, task.ItemsProcessed(), loaded.ItemsProcessed())
	assert.Equal(t, task.ProgressDetails(), loaded.ProgressDetails())
	assert.True(t, loaded.EndTime().IsZero())
}

func TestTaskStore_UpdateTask(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task)
	require.NoError(t, err)

	// Update task with new state.
	checkpoint := scanning.NewCheckpoint(
		task.TaskID(),
		[]byte("resume-token"),
		map[string]string{"key": "value"},
	)

	updatedTask := scanning.ReconstructTask(
		task.TaskID(),
		task.JobID(),
		scanning.TaskStatusInProgress,
		1,
		task.StartTime(),
		time.Now().UTC(),
		100,
		json.RawMessage(`{"updated": "details"}`),
		checkpoint,
		scanning.StallReasonNoProgress,
		time.Time{},
	)

	err = taskStore.UpdateTask(ctx, updatedTask)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, scanning.TaskStatusInProgress, loaded.Status())
	assert.Equal(t, int64(100), loaded.ItemsProcessed())
	assert.Equal(t, int64(1), loaded.LastSequenceNum())
	assert.JSONEq(t, `{"updated": "details"}`, string(loaded.ProgressDetails()))
	assert.NotNil(t, loaded.LastCheckpoint())
	assert.Equal(t, checkpoint.ResumeToken(), loaded.LastCheckpoint().ResumeToken())
	assert.Equal(t, checkpoint.Metadata(), loaded.LastCheckpoint().Metadata())
}

func TestTaskStore_UpdateTask_WithCompletion(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task)
	require.NoError(t, err)

	// Update task to completed.
	err = task.Complete()
	require.NoError(t, err)

	err = taskStore.UpdateTask(ctx, task)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, scanning.TaskStatusCompleted, loaded.Status())
	assert.False(t, loaded.EndTime().IsZero(), "End time should be set")
}

func TestTaskStore_ListTasksByJobAndStatus(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	jobID := job.JobID()
	status := scanning.TaskStatusInProgress

	// Create multiple tasks.
	tasks := make([]*scanning.Task, 3)
	for i := 0; i < 3; i++ {
		task := scanning.ReconstructTask(
			uuid.New(),
			jobID,
			status,
			int64(i),
			time.Now().UTC(),
			time.Time{},
			int64(i*10),
			json.RawMessage(`{"test": "details"}`),
			nil,
			scanning.StallReasonNoProgress,
			time.Time{},
		)
		err := taskStore.CreateTask(ctx, task)
		require.NoError(t, err)
		tasks[i] = task
	}

	// Create a task with different status.
	differentStatusTask := scanning.ReconstructTask(
		uuid.New(),
		jobID,
		scanning.TaskStatusCompleted,
		3,
		time.Now().UTC(),
		time.Time{},
		30,
		json.RawMessage(`{"test": "details"}`),
		nil,
		scanning.StallReasonNoProgress,
		time.Time{},
	)
	err := taskStore.CreateTask(ctx, differentStatusTask)
	require.NoError(t, err)

	listed, err := taskStore.ListTasksByJobAndStatus(ctx, jobID, status)
	require.NoError(t, err)
	assert.Len(t, listed, 3)

	for _, task := range listed {
		assert.Equal(t, jobID, task.JobID())
		assert.Equal(t, status, task.Status())
	}
}

func TestTaskStore_GetNonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, _, cleanup := setupTaskTest(t)
	defer cleanup()

	loaded, err := taskStore.GetTask(ctx, uuid.New())
	assert.ErrorIs(t, err, pgx.ErrNoRows)
	assert.Nil(t, loaded)
}

func TestTaskStore_CreateDuplicate(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, job.JobID(), scanning.TaskStatusInProgress)

	// First creation should succeed.
	err := taskStore.CreateTask(ctx, task)
	require.NoError(t, err)

	// Second creation should fail.
	err = taskStore.CreateTask(ctx, task)
	require.Error(t, err)
}

func TestTaskStore_UpdateNonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, job.JobID(), scanning.TaskStatusCompleted)
	err := taskStore.UpdateTask(ctx, task)
	require.Error(t, err)
}

func TestTaskStore_ListTasksByJobAndStatus_EmptyResult(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	listed, err := taskStore.ListTasksByJobAndStatus(ctx, job.JobID(), scanning.TaskStatusInProgress)
	require.NoError(t, err)
	assert.Empty(t, listed)
}

func TestTaskStore_CreateTask_NonExistentJob(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, _, cleanup := setupTaskTest(t)
	defer cleanup()

	task := createTestTask(t, uuid.New(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task)
	require.Error(t, err, "should fail when parent job doesn't exist")
}

func TestTaskStore_GetTask_WithStallInfo(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	stallTime := time.Now().UTC()

	// Create a stale task
	task := scanning.ReconstructTask(
		uuid.New(),
		job.JobID(),
		scanning.TaskStatusInProgress,
		0,
		stallTime.Add(-1*time.Hour), // Start time
		time.Time{},                 // End time
		0,                           // Items processed
		nil,                         // Progress details
		nil,                         // Checkpoint
		scanning.StallReasonNoProgress,
		stallTime,
	)

	err := taskStore.CreateTask(ctx, task)
	require.NoError(t, err)

	err = task.MarkStale(scanning.StallReasonNoProgress)
	require.NoError(t, err)
	err = taskStore.UpdateTask(ctx, task)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, scanning.TaskStatusStale, loaded.Status())
	assert.Equal(t, scanning.StallReasonNoProgress, loaded.StallReason())
	assert.True(t, loaded.StalledAt().Equal(task.StalledAt()))
}

func TestTaskStore_UpdateTask_StallTransition(t *testing.T) {
	t.Parallel()

	// Mark as stale with different stall reasons.
	testCases := []struct {
		name        string
		stallReason scanning.StallReason
	}{
		{
			name:        "mark stale with no progress",
			stallReason: scanning.StallReasonNoProgress,
		},
		{
			name:        "mark stale with high errors",
			stallReason: scanning.StallReasonHighErrors,
		},
		{
			name:        "mark stale with low throughput",
			stallReason: scanning.StallReasonLowThroughput,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			beforeStale := time.Now().UTC()

			ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
			defer cleanup()

			job := createTestScanJob(t, jobStore, ctx)

			task := createTestTask(t, job.JobID(), scanning.TaskStatusInProgress)
			err := taskStore.CreateTask(ctx, task)
			require.NoError(t, err)

			err = task.MarkStale(tc.stallReason)
			require.NoError(t, err)

			err = taskStore.UpdateTask(ctx, task)
			require.NoError(t, err)

			loaded, err := taskStore.GetTask(ctx, task.TaskID())
			require.NoError(t, err)
			require.NotNil(t, loaded)

			assert.Equal(t, scanning.TaskStatusStale, loaded.Status())
			assert.Equal(t, tc.stallReason, loaded.StallReason())
			assert.True(t, loaded.StalledAt().After(beforeStale) ||
				loaded.StalledAt().Equal(beforeStale))
		})
	}
}

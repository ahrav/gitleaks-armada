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

func createTestScanJob(t *testing.T, store *jobStore, ctx context.Context) *scanning.ScanJob {
	t.Helper()
	job := scanning.ReconstructJob(
		uuid.New(),
		scanning.JobStatusQueued,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
		nil,
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
		json.RawMessage(`{"test": "details"}`),
		nil,
	)
}

func TestTaskStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, job.GetJobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.GetTaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, task.GetTaskID(), loaded.GetTaskID())
	assert.Equal(t, task.GetJobID(), loaded.GetJobID())
	assert.Equal(t, task.GetStatus(), loaded.GetStatus())
	assert.Equal(t, task.GetLastSequenceNum(), loaded.GetLastSequenceNum())
	assert.Equal(t, task.GetItemsProcessed(), loaded.GetItemsProcessed())
	assert.Equal(t, task.ProgressDetails(), loaded.ProgressDetails())
}

func TestTaskStore_UpdateTask(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, job.GetJobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task)
	require.NoError(t, err)

	// Update task with new state.
	checkpoint := scanning.NewCheckpoint(
		task.GetTaskID(),
		[]byte("resume-token"),
		map[string]string{"key": "value"},
	)

	updatedTask := scanning.ReconstructTask(
		task.GetTaskID(),
		task.GetJobID(),
		scanning.TaskStatusInProgress,
		1,
		task.StartTime(),
		time.Now().UTC(),
		100,
		json.RawMessage(`{"updated": "details"}`),
		checkpoint,
	)

	err = taskStore.UpdateTask(ctx, updatedTask)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.GetTaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, scanning.TaskStatusInProgress, loaded.GetStatus())
	assert.Equal(t, int64(100), loaded.GetItemsProcessed())
	assert.Equal(t, int64(1), loaded.GetLastSequenceNum())
	assert.JSONEq(t, `{"updated": "details"}`, string(loaded.ProgressDetails()))
	assert.NotNil(t, loaded.LastCheckpoint())
	assert.Equal(t, checkpoint.ResumeToken, loaded.LastCheckpoint().ResumeToken)
	assert.Equal(t, checkpoint.Metadata, loaded.LastCheckpoint().Metadata)
}

func TestTaskStore_ListTasksByJobAndStatus(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	jobID := job.GetJobID()
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
	)
	err := taskStore.CreateTask(ctx, differentStatusTask)
	require.NoError(t, err)

	listed, err := taskStore.ListTasksByJobAndStatus(ctx, jobID, status)
	require.NoError(t, err)
	assert.Len(t, listed, 3)

	for _, task := range listed {
		assert.Equal(t, jobID, task.GetJobID())
		assert.Equal(t, status, task.GetStatus())
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

	task := createTestTask(t, job.GetJobID(), scanning.TaskStatusInProgress)

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

	task := createTestTask(t, job.GetJobID(), scanning.TaskStatusCompleted)
	err := taskStore.UpdateTask(ctx, task)
	require.Error(t, err)
}

func TestTaskStore_ListTasksByJobAndStatus_EmptyResult(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	listed, err := taskStore.ListTasksByJobAndStatus(ctx, job.GetJobID(), scanning.TaskStatusInProgress)
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

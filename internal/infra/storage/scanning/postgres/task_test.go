package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
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
		scanning.ReconstructJobMetrics(0, 0, 0, 0, 0, 0),
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)
	return job
}

func createTestTask(t *testing.T, store *taskStore, jobID uuid.UUID, status scanning.TaskStatus) *scanning.Task {
	t.Helper()

	taskID := uuid.New()
	resourceURI := "test-resource-uri"

	// First create the base task record
	err := store.q.CreateBaseTask(context.Background(), db.CreateBaseTaskParams{
		TaskID:     pgtype.UUID{Bytes: taskID, Valid: true},
		SourceType: resourceURI,
	})
	require.NoError(t, err)

	return scanning.ReconstructTask(
		taskID,
		jobID,
		resourceURI,
		status,
		0,
		time.Now().UTC(),
		time.Time{},
		time.Time{},
		0,
		nil,
		nil,
		scanning.ReasonPtr(scanning.StallReasonNoProgress),
		time.Time{},
		0,
	)
}

func TestTaskStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
	controllerID := "test-controller"

	err := taskStore.CreateTask(ctx, task, controllerID)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, task.TaskID(), loaded.TaskID())
	assert.Equal(t, task.JobID(), loaded.JobID())
	assert.Equal(t, task.Status(), loaded.Status())
	assert.Equal(t, task.ResourceURI(), loaded.ResourceURI())
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

	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task, "test-controller")
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
		"",
		scanning.TaskStatusInProgress,
		1,
		task.StartTime(),
		time.Time{},
		time.Now().UTC(),
		100,
		json.RawMessage(`{"updated": "details"}`),
		checkpoint,
		scanning.ReasonPtr(scanning.StallReasonNoProgress),
		time.Time{},
		0,
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

	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task, "test-controller")
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
		task := createTestTask(t, taskStore, jobID, status)
		tasks[i] = task
		err := taskStore.CreateTask(ctx, task, "test-controller")
		require.NoError(t, err)
	}

	// Create a task with different status.
	differentStatusTask := createTestTask(t, taskStore, jobID, scanning.TaskStatusCompleted)
	err := taskStore.CreateTask(ctx, differentStatusTask, "test-controller")
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
	assert.ErrorIs(t, err, scanning.ErrTaskNotFound)
	assert.Nil(t, loaded)
}

func TestTaskStore_CreateDuplicate(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)

	// First creation should succeed.
	err := taskStore.CreateTask(ctx, task, "test-controller")
	require.NoError(t, err)

	// Second creation should fail.
	err = taskStore.CreateTask(ctx, task, "test-controller")
	require.Error(t, err)
}

func TestTaskStore_UpdateNonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusCompleted)
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

	task := createTestTask(t, taskStore, uuid.New(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task, "test-controller")
	require.Error(t, err, "should fail when parent job doesn't exist")
}

func TestTaskStore_GetTask_WithStallInfo(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	stallTime := time.Now().UTC()
	stallReason := scanning.StallReasonNoProgress

	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)

	// Update the task with stall-specific information.
	task = scanning.ReconstructTask(
		task.TaskID(),
		job.JobID(),
		task.ResourceURI(),
		scanning.TaskStatusInProgress,
		0,
		stallTime.Add(-1*time.Hour), // Start time
		time.Time{},                 // End time
		time.Time{},                 // Last heartbeat at
		0,                           // Items processed
		nil,                         // Progress details
		nil,                         // Checkpoint
		scanning.ReasonPtr(stallReason),
		stallTime,
		0,
	)

	err := taskStore.CreateTask(ctx, task, "test-controller")
	require.NoError(t, err)

	err = task.MarkStale(scanning.ReasonPtr(stallReason))
	require.NoError(t, err)

	err = taskStore.UpdateTask(ctx, task)
	require.NoError(t, err)

	loaded, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, scanning.TaskStatusStale, loaded.Status())
	assert.Equal(t, &stallReason, loaded.StallReason())
	assert.WithinDuration(t, task.StalledAt(), loaded.StalledAt(), time.Second,
		"stalled_at timestamps should be within 1 second of each other")
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

			task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
			err := taskStore.CreateTask(ctx, task, "test-controller")
			require.NoError(t, err)

			err = task.MarkStale(scanning.ReasonPtr(tc.stallReason))
			require.NoError(t, err)

			err = taskStore.UpdateTask(ctx, task)
			require.NoError(t, err)

			loaded, err := taskStore.GetTask(ctx, task.TaskID())
			require.NoError(t, err)
			require.NotNil(t, loaded)

			assert.Equal(t, scanning.TaskStatusStale, loaded.Status())
			assert.Equal(t, &tc.stallReason, loaded.StallReason())
			assert.True(t, loaded.StalledAt().After(beforeStale) ||
				loaded.StalledAt().Equal(beforeStale))
		})
	}
}

func TestTaskStore_GetTaskSourceType(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task, "test-controller")
	require.NoError(t, err)

	sourceType, err := taskStore.GetTaskSourceType(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, shared.SourceTypeURL, sourceType)
}

func TestTaskStore_GetTaskSourceType_NonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, _, cleanup := setupTaskTest(t)
	defer cleanup()

	sourceType, err := taskStore.GetTaskSourceType(ctx, uuid.New())
	assert.ErrorIs(t, err, pgx.ErrNoRows)
	assert.Empty(t, sourceType)
}

func TestTaskStore_UpdateTask_RecoveryFromStale(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)

	err := taskStore.CreateTask(ctx, task, "test-controller")
	require.NoError(t, err)

	// First stale cycle.
	reason := scanning.StallReasonNoProgress
	err = task.MarkStale(&reason)
	require.NoError(t, err)

	err = taskStore.UpdateTask(ctx, task)
	require.NoError(t, err)

	stalledTask, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusStale, stalledTask.Status())
	assert.Equal(t, &reason, stalledTask.StallReason())
	assert.False(t, stalledTask.StalledAt().IsZero())
	assert.Equal(t, 0, stalledTask.RecoveryAttempts())

	// Simulate recovery with progress update.
	progress := scanning.NewProgress(task.TaskID(), task.JobID(), 10, time.Now(), 100, 0, "", nil, nil)
	err = stalledTask.ApplyProgress(progress)

	require.NoError(t, err)

	err = taskStore.UpdateTask(ctx, stalledTask)
	require.NoError(t, err)

	// Verify recovery state.
	recoveredTask, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusInProgress, recoveredTask.Status())
	assert.Nil(t, recoveredTask.StallReason())
	assert.True(t, recoveredTask.StalledAt().IsZero())
	assert.Equal(t, 1, recoveredTask.RecoveryAttempts())

	// Second stale cycle.
	err = recoveredTask.MarkStale(&reason)
	require.NoError(t, err)

	err = taskStore.UpdateTask(ctx, recoveredTask)
	require.NoError(t, err)

	// Second recovery.
	progress = scanning.NewProgress(task.TaskID(), task.JobID(), 20, time.Now(), 100, 0, "", nil, nil)
	err = recoveredTask.ApplyProgress(progress)
	require.NoError(t, err)

	err = taskStore.UpdateTask(ctx, recoveredTask)
	require.NoError(t, err)

	// Verify multiple recovery attempts are tracked.
	finalTask, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusInProgress, finalTask.Status())
	assert.Nil(t, finalTask.StallReason())
	assert.True(t, finalTask.StalledAt().IsZero())
	assert.Equal(t, 2, finalTask.RecoveryAttempts())
	assert.Equal(t, int64(20), finalTask.LastSequenceNum())
}

func TestTaskStore_FindStaleTasks(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	// Use a fixed base time for all calculations
	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	cutoff := baseTime.Add(-5 * time.Minute)
	controllerID := "test-controller"

	testCases := []struct {
		name          string
		lastHeartbeat *time.Time
		status        scanning.TaskStatus
		shouldBeStale bool
		count         int
	}{
		// {
		// 	name:          "no heartbeat",
		// 	lastHeartbeat: nil,
		// 	status:        scanning.TaskStatusInProgress,
		// 	shouldBeStale: true,
		// 	count:         2,
		// },
		{
			name:          "stale heartbeat",
			lastHeartbeat: &[]time.Time{baseTime.Add(-10 * time.Minute)}[0], // 10 min old
			status:        scanning.TaskStatusInProgress,
			shouldBeStale: true,
			count:         3,
		},
		{
			name:          "recent heartbeat",
			lastHeartbeat: &[]time.Time{baseTime.Add(-1 * time.Minute)}[0], // 1 min old
			status:        scanning.TaskStatusInProgress,
			shouldBeStale: false,
			count:         1,
		},
		{
			name:          "completed task with old heartbeat",
			lastHeartbeat: &[]time.Time{baseTime.Add(-10 * time.Minute)}[0], // 10 min old
			status:        scanning.TaskStatusCompleted,
			shouldBeStale: false,
			count:         1,
		},
	}

	var expectedStaleTasks []scanning.StaleTaskInfo
	heartbeats := make(map[uuid.UUID]time.Time)
	inProgressTasks := 0

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < tc.count; i++ {
				task := createTestTask(t, taskStore, job.JobID(), tc.status)
				err := taskStore.CreateTask(ctx, task, controllerID)
				require.NoError(t, err)

				if tc.status == scanning.TaskStatusInProgress {
					inProgressTasks++
				}

				if tc.lastHeartbeat != nil {
					heartbeats[task.TaskID()] = *tc.lastHeartbeat
				}

				if tc.shouldBeStale {
					expectedStaleTasks = append(expectedStaleTasks,
						scanning.NewStaleTaskInfo(task.TaskID(), job.JobID(), controllerID))
				}
			}
		})
	}

	// Update heartbeats.
	if len(heartbeats) > 0 {
		rowsAffected, err := taskStore.BatchUpdateHeartbeats(ctx, heartbeats)
		require.NoError(t, err)
		assert.Equal(t, int64(inProgressTasks), rowsAffected,
			"Should update all IN_PROGRESS tasks")
	}

	staleTasks, err := taskStore.FindStaleTasks(ctx, controllerID, cutoff)
	require.NoError(t, err)

	assert.Equal(t, len(expectedStaleTasks), len(staleTasks))
	for _, expected := range expectedStaleTasks {
		found := false
		for _, actual := range staleTasks {
			if actual.TaskID() == expected.TaskID() {
				assert.Equal(t, expected.JobID(), actual.JobID())
				assert.Equal(t, expected.ControllerID(), actual.ControllerID())
				found = true
				break
			}
		}
		assert.True(t, found, "Expected stale task not found: %v", expected.TaskID())
	}
}

func TestTaskStore_BatchUpdateHeartbeats(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	now := time.Now().UTC()

	tasks := make([]*scanning.Task, 3)
	heartbeats := make(map[uuid.UUID]time.Time)

	for i := range tasks {
		task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
		err := taskStore.CreateTask(ctx, task, "test-controller")
		require.NoError(t, err)
		tasks[i] = task
		heartbeats[task.TaskID()] = now.Add(time.Duration(i) * time.Minute)
	}

	rowsAffected, err := taskStore.BatchUpdateHeartbeats(ctx, heartbeats)
	require.NoError(t, err)
	require.Equal(t, int64(len(tasks)), rowsAffected)

	// Verify none are stale.
	staleTasks, err := taskStore.FindStaleTasks(ctx, "test-controller", now.Add(-1*time.Hour))
	require.NoError(t, err)
	assert.Empty(t, staleTasks)

	// Test updating non-existent tasks.
	nonExistentHeartbeats := map[uuid.UUID]time.Time{
		uuid.New(): now,
	}
	rowsAffected, err = taskStore.BatchUpdateHeartbeats(ctx, nonExistentHeartbeats)
	require.NoError(t, err)
	assert.Equal(t, int64(0), rowsAffected)
}

func TestTaskStore_UpdateTask_StartTimeSetOnTransition(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)

	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusPending)
	err := taskStore.CreateTask(ctx, task, "test-controller")
	require.NoError(t, err)

	initialTask, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusPending, initialTask.Status())
	assert.True(t, initialTask.StartTime().IsZero(), "Start time should be zero for PENDING task")

	// Simulate progress update that transitions task to IN_PROGRESS.
	progress := scanning.NewProgress(
		task.TaskID(),
		job.JobID(),
		1, // sequence number
		time.Now().UTC(),
		10,  // items processed
		0,   // error count
		"",  // message
		nil, // progress details
		nil, // checkpoint
	)

	err = task.ApplyProgress(progress)
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusInProgress, task.Status())
	assert.False(t, task.StartTime().IsZero(), "Start time should be set after transition")

	err = taskStore.UpdateTask(ctx, task)
	require.NoError(t, err)

	updatedTask, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusInProgress, updatedTask.Status())
	assert.False(t, updatedTask.StartTime().IsZero(), "Start time should be persisted")
	assert.WithinDuration(t, task.StartTime(), updatedTask.StartTime(), time.Second,
		"Persisted start time should match the task's start time")
}

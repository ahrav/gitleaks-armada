package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
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
		shared.SourceTypeGitHub.String(),
		json.RawMessage(`{}`),
		scanning.JobStatusQueued,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)
	return job
}

// createTestScanJobWithStatus creates a job with the specified status.
func createTestScanJobWithStatus(t *testing.T, store *jobStore, ctx context.Context, status scanning.JobStatus) *scanning.Job {
	t.Helper()
	job := scanning.ReconstructJob(
		uuid.New(),
		shared.SourceTypeGitHub.String(),
		json.RawMessage(`{}`),
		status,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
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
		SourceType: shared.SourceTypeURL.String(),
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
		time.Time{},
		0,
		uuid.New(),
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
		time.Time{},
		0,
		uuid.New(),
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
		time.Time{},
		0,
		uuid.New(),
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
	err = stalledTask.RecoverFromStale()
	require.NoError(t, err)

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
	err = recoveredTask.RecoverFromStale()
	require.NoError(t, err)

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

	// Use a fixed base time for all calculations.
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
		{
			name:          "stale heartbeat, paused task",
			lastHeartbeat: &[]time.Time{baseTime.Add(-10 * time.Minute)}[0], // 10 min old
			status:        scanning.TaskStatusPaused,
			shouldBeStale: false,
			count:         3,
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

// TestTaskStore_FindStaleTasks_JobStatusFiltering verifies that tasks belonging to jobs with
// excluded statuses (PAUSED, PAUSING, CANCELLING, CANCELLED) are not returned as stale tasks
// even if they have stale heartbeats.
// TestTaskStore_FindStaleTasks_JobStatusFiltering verifies that tasks belonging to jobs with
// excluded statuses (PAUSED, PAUSING, CANCELLING, CANCELLED) are not returned as stale tasks
// even if they have stale heartbeats.
func TestTaskStore_FindStaleTasks_JobStatusFiltering(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	baseTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	cutoff := baseTime.Add(-5 * time.Minute)
	staleHeartbeatTime := baseTime.Add(-10 * time.Minute)
	controllerID := "test-controller"

	testCases := []struct {
		name        string
		jobStatus   scanning.JobStatus
		taskStatus  scanning.TaskStatus
		expectStale bool
		reason      string
	}{
		// Jobs with statuses that should allow stale task detection.
		{name: "QUEUED job, IN_PROGRESS task", jobStatus: scanning.JobStatusQueued, taskStatus: scanning.TaskStatusInProgress, expectStale: true, reason: "Tasks of QUEUED jobs should be detected as stale"},
		{name: "RUNNING job, IN_PROGRESS task", jobStatus: scanning.JobStatusRunning, taskStatus: scanning.TaskStatusInProgress, expectStale: true, reason: "Tasks of RUNNING jobs should be detected as stale"},
		{name: "COMPLETED job, IN_PROGRESS task", jobStatus: scanning.JobStatusCompleted, taskStatus: scanning.TaskStatusInProgress, expectStale: true, reason: "Tasks of COMPLETED jobs should be detected as stale"},
		{name: "FAILED job, IN_PROGRESS task", jobStatus: scanning.JobStatusFailed, taskStatus: scanning.TaskStatusInProgress, expectStale: true, reason: "Tasks of FAILED jobs should be detected as stale"},

		// Jobs with statuses that should exclude tasks from stale detection.
		{name: "PAUSED job, IN_PROGRESS task", jobStatus: scanning.JobStatusPaused, taskStatus: scanning.TaskStatusInProgress, expectStale: false, reason: "Tasks of PAUSED jobs should not be detected as stale"},
		{name: "PAUSING job, IN_PROGRESS task", jobStatus: scanning.JobStatusPausing, taskStatus: scanning.TaskStatusInProgress, expectStale: false, reason: "Tasks of PAUSING jobs should not be detected as stale"},
		{name: "CANCELLED job, IN_PROGRESS task", jobStatus: scanning.JobStatusCancelled, taskStatus: scanning.TaskStatusInProgress, expectStale: false, reason: "Tasks of CANCELLED jobs should not be detected as stale"},
		{name: "CANCELLING job, IN_PROGRESS task", jobStatus: scanning.JobStatusCancelling, taskStatus: scanning.TaskStatusInProgress, expectStale: false, reason: "Tasks of CANCELLING jobs should not be detected as stale"},

		// Edge cases for task status.
		{name: "RUNNING job, COMPLETED task", jobStatus: scanning.JobStatusRunning, taskStatus: scanning.TaskStatusCompleted, expectStale: false, reason: "COMPLETED tasks should never be detected as stale"},
		{name: "PAUSED job, COMPLETED task", jobStatus: scanning.JobStatusPaused, taskStatus: scanning.TaskStatusCompleted, expectStale: false, reason: "Both job status and task status prevent stale detection"},
	}

	// Create all the test tasks and prepare heartbeats.
	testTasks := make(map[string]*scanning.Task)
	heartbeats := make(map[uuid.UUID]time.Time)

	for _, tc := range testCases {
		job := createTestScanJobWithStatus(t, jobStore, ctx, tc.jobStatus)

		task := createTestTask(t, taskStore, job.JobID(), tc.taskStatus)
		err := taskStore.CreateTask(ctx, task, controllerID)
		require.NoError(t, err)

		testTasks[tc.name] = task
		heartbeats[task.TaskID()] = staleHeartbeatTime
	}

	rowsAffected, err := taskStore.BatchUpdateHeartbeats(ctx, heartbeats)
	require.NoError(t, err)
	assert.True(t, rowsAffected > 0, "Should update at least the IN_PROGRESS tasks")

	staleTasks, err := taskStore.FindStaleTasks(ctx, controllerID, cutoff)
	require.NoError(t, err)

	for _, tc := range testCases {
		task := testTasks[tc.name]
		found := false

		for _, staleTask := range staleTasks {
			if staleTask.TaskID() == task.TaskID() {
				found = true
				break
			}
		}

		if tc.expectStale {
			assert.True(t, found, "Test case '%s': %s", tc.name, tc.reason)
		} else {
			assert.False(t, found, "Test case '%s': %s", tc.name, tc.reason)
		}
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
	err = task.Start()
	require.NoError(t, err)

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

func TestTaskStore_UpdateTask_PauseAndResume(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJob(t, jobStore, ctx)
	task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, task, "test-controller")
	require.NoError(t, err)

	initialTask, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusInProgress, initialTask.Status())
	assert.True(t, initialTask.PausedAt().IsZero(), "Paused time should be zero for IN_PROGRESS task")

	// Simulate pause.
	err = task.Pause()
	require.NoError(t, err)
	err = taskStore.UpdateTask(ctx, task)
	require.NoError(t, err)

	updatedTask, err := taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusPaused, updatedTask.Status())
	assert.False(t, updatedTask.PausedAt().IsZero(), "Paused time should be persisted")

	// Simulate resume.
	err = task.Resume()
	require.NoError(t, err)
	err = taskStore.UpdateTask(ctx, task)
	require.NoError(t, err)

	updatedTask, err = taskStore.GetTask(ctx, task.TaskID())
	require.NoError(t, err)
	assert.Equal(t, scanning.TaskStatusInProgress, updatedTask.Status())
	assert.True(t, updatedTask.PausedAt().IsZero(), "Paused time should be cleared after resume")
}

func TestTaskStore_GetTasksToResume(t *testing.T) {
	t.Parallel()
	ctx, _, taskStore, jobStore, cleanup := setupTaskTest(t)
	defer cleanup()

	job := createTestScanJobWithStatus(t, jobStore, ctx, scanning.JobStatusPaused)

	taskCount := 3
	taskIDs := make([]uuid.UUID, taskCount)
	for i := 0; i < taskCount; i++ {
		task := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusPaused)

		taskID := task.TaskID()
		resumeToken := []byte(fmt.Sprintf("token-%d", i))
		metadata := map[string]string{"position": fmt.Sprintf("%d", i)}
		checkpoint := scanning.NewCheckpoint(taskID, resumeToken, metadata)

		progress := scanning.NewProgress(
			taskID,
			job.JobID(),
			int64(i+10), // sequence number
			time.Now(),
			int64(i*100), // items processed
			0,            // error count
			"",           // message
			nil,          // progress details
			checkpoint,
		)
		err := task.ApplyProgress(progress)
		require.NoError(t, err)

		err = taskStore.CreateTask(ctx, task, "test-controller")
		require.NoError(t, err)

		err = taskStore.UpdateTask(ctx, task)
		require.NoError(t, err)

		taskIDs[i] = task.TaskID()
	}

	nonPausedTask := createTestTask(t, taskStore, job.JobID(), scanning.TaskStatusInProgress)
	err := taskStore.CreateTask(ctx, nonPausedTask, "test-controller")
	require.NoError(t, err)

	resumeTasks, err := taskStore.GetTasksToResume(ctx, job.JobID())
	require.NoError(t, err)

	assert.Equal(t, taskCount, len(resumeTasks))

	for _, resumeTask := range resumeTasks {
		found := slices.Contains(taskIDs, resumeTask.TaskID())
		assert.True(t, found, "Unexpected task ID returned")

		assert.Equal(t, shared.SourceTypeGitHub, resumeTask.SourceType())
		assert.NotNil(t, resumeTask.Checkpoint())
		assert.True(t, resumeTask.SequenceNum() >= 10, "Expected sequence number >= 10")
		assert.NotEmpty(t, resumeTask.Checkpoint().ResumeToken(), "Checkpoint should have resume token")
	}
}

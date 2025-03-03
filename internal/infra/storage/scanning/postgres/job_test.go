package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage/enumeration/postgres"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

func setupJobTest(t *testing.T) (context.Context, *pgxpool.Pool, *jobStore, func()) {
	t.Helper()

	db, cleanup := storage.SetupTestContainer(t)
	store := NewJobStore(db, storage.NoOpTracer())
	ctx := context.Background()

	return ctx, db, store, cleanup
}

func createTestJob(t *testing.T, status scanning.JobStatus) *scanning.Job {
	t.Helper()
	return scanning.ReconstructJob(
		uuid.New(),
		shared.SourceTypeGitHub.String(),
		json.RawMessage(`{}`),
		status,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
	)
}

func TestJobStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusQueued)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	loaded, err := store.GetJob(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, job.JobID(), loaded.JobID())
	assert.Equal(t, job.Status(), loaded.Status())
	assert.True(t, loaded.StartTime().IsZero(), "New jobs should not have a start time")
}

func TestJobStore_CreateAndGet_WithMetrics(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusQueued)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	loaded, err := store.GetJob(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, job.JobID(), loaded.JobID())
	assert.Equal(t, job.Status(), loaded.Status())

	metrics, err := store.GetJobMetrics(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// All metrics should be zero initially.
	assert.Equal(t, 0, metrics.TotalTasks())
	assert.Equal(t, 0, metrics.PendingTasks())
	assert.Equal(t, 0, metrics.InProgressTasks())
	assert.Equal(t, 0, metrics.CompletedTasks())
	assert.Equal(t, 0, metrics.FailedTasks())
	assert.Equal(t, 0, metrics.StaleTasks())
}

func TestJobStore_IncrementTotalTasks(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusRunning)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	err = store.IncrementTotalTasks(ctx, job.JobID(), 5)
	require.NoError(t, err)

	metrics, err := store.GetJobMetrics(ctx, job.JobID())
	require.NoError(t, err)
	assert.Equal(t, 5, metrics.TotalTasks())

	err = store.IncrementTotalTasks(ctx, job.JobID(), 3)
	require.NoError(t, err)

	metrics, err = store.GetJobMetrics(ctx, job.JobID())
	require.NoError(t, err)
	assert.Equal(t, 8, metrics.TotalTasks())
}

func TestJobStore_IncrementTotalTasks_NonExistentJob(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	err := store.IncrementTotalTasks(ctx, uuid.New(), 5)
	require.ErrorIs(t, err, scanning.ErrNoJobMetricsFound)
}

func TestJobStore_IncrementTotalTasks_NegativeAmount(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusRunning)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	err = store.IncrementTotalTasks(ctx, job.JobID(), 10)
	require.NoError(t, err)

	err = store.IncrementTotalTasks(ctx, job.JobID(), -3)
	require.NoError(t, err)

	metrics, err := store.GetJobMetrics(ctx, job.JobID())
	require.NoError(t, err)
	assert.Equal(t, 7, metrics.TotalTasks())
}

type mockTimeProvider struct{ current time.Time }

func (m *mockTimeProvider) Now() time.Time { return m.current }

func TestJobStore_UpdateJob(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	mockTime := &mockTimeProvider{current: time.Now().UTC()}
	timeline := scanning.NewTimeline(mockTime)

	// Initialize job with zero metrics.
	job := scanning.ReconstructJob(
		uuid.New(),
		shared.SourceTypeGitHub.String(),
		json.RawMessage(`{}`),
		scanning.JobStatusQueued,
		timeline,
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	initialJob, err := store.GetJob(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, initialJob)

	testCases := []struct {
		name          string
		initialStatus scanning.JobStatus
		targetStatus  scanning.JobStatus
	}{
		{
			name:          "transition to pausing",
			initialStatus: scanning.JobStatusRunning,
			targetStatus:  scanning.JobStatusPausing,
		},
		{
			name:          "transition to paused",
			initialStatus: scanning.JobStatusPausing,
			targetStatus:  scanning.JobStatusPaused,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			job := scanning.ReconstructJob(
				uuid.New(),
				shared.SourceTypeGitHub.String(),
				json.RawMessage(`{}`),
				tc.initialStatus,
				scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
			)
			err := store.CreateJob(ctx, job)
			require.NoError(t, err)

			updatedJob := scanning.ReconstructJob(
				job.JobID(),
				shared.SourceTypeGitHub.String(),
				json.RawMessage(`{}`),
				tc.targetStatus,
				scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
			)
			err = store.UpdateJob(ctx, updatedJob)
			require.NoError(t, err)

			// Verify state.
			loaded, err := store.GetJob(ctx, job.JobID())
			require.NoError(t, err)
			require.NotNil(t, loaded)
			assert.Equal(t, tc.targetStatus, loaded.Status())
		})
	}
}

func TestJobStore_AssociateTargets(t *testing.T) {
	t.Parallel()
	ctx, db, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusQueued)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	// Create scan targets first.
	// This satisfies the fk constraint in the database.
	targetStore := postgres.NewScanTargetStore(db, storage.NoOpTracer())
	targetIDs := make([]uuid.UUID, 3)

	for i := 1; i <= 3; i++ {
		target, err := enumeration.NewScanTarget(
			fmt.Sprintf("test-target-%d", i),
			shared.TargetTypeGitHubRepo,
			int64(i),
			map[string]any{"key": "value"},
		)
		require.NoError(t, err)

		id, err := targetStore.Create(ctx, target)
		require.NoError(t, err)
		targetIDs[i-1] = id
	}

	// Now associate the targets with the job.
	err = store.AssociateTargets(ctx, job.JobID(), targetIDs)
	require.NoError(t, err)

	loaded, err := store.GetJob(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, loaded)
}

func TestJobStore_GetNonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	loaded, err := store.GetJob(ctx, uuid.New())
	require.ErrorIs(t, err, scanning.ErrJobNotFound)
	assert.Nil(t, loaded)
}

func TestJobStore_GetJobConfigInfo(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	config := json.RawMessage(`{"test_field": "test_value", "nested": {"field": 123}}`)

	job := scanning.ReconstructJob(
		uuid.New(),
		shared.SourceTypeGitHub.String(),
		config,
		scanning.JobStatusQueued,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	configInfo, err := store.GetJobConfigInfo(ctx, job.JobID())
	require.NoError(t, err)

	assert.Equal(t, job.JobID(), configInfo.JobID())
	assert.Equal(t, shared.SourceTypeGitHub, configInfo.SourceType())
	assert.JSONEq(t, string(config), string(configInfo.Config()))
}

func TestJobStore_GetJobConfigInfo_NotFound(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	nonExistentJobID := uuid.New()
	configInfo, err := store.GetJobConfigInfo(ctx, nonExistentJobID)

	require.Error(t, err)
	assert.ErrorIs(t, err, scanning.ErrJobNotFound)
	assert.Nil(t, configInfo)
}

func TestJobStore_CreateDuplicate(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusQueued)

	// First creation should succeed.
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	// Second creation should fail.
	err = store.CreateJob(ctx, job)
	require.Error(t, err)
}

func TestJobStore_UpdateNonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusCompleted)
	err := store.UpdateJob(ctx, job)
	require.Error(t, err)
}

func TestJobStore_AssociateTargetsEmpty(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusQueued)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	// Associate empty target list should succeed.
	err = store.AssociateTargets(ctx, job.JobID(), []uuid.UUID{})
	require.NoError(t, err)
}

func TestJobStore_BulkUpdateJobMetrics(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	jobMetrics := make(map[uuid.UUID]*scanning.JobMetrics)

	for i := range 3 {
		job := createTestJob(t, scanning.JobStatusRunning)
		err := store.CreateJob(ctx, job)
		require.NoError(t, err)

		metrics := scanning.ReconstructJobMetrics(
			10*(i+1), // total tasks
			0,        // pending tasks
			0,        // in progress tasks
			5*(i+1),  // completed tasks
			2*(i+1),  // failed tasks
			1*(i+1),  // stale tasks
			i+1,      // cancelled tasks
			i,        // paused tasks
		)
		jobMetrics[job.JobID()] = metrics
	}

	rowsAffected, err := store.BulkUpdateJobMetrics(ctx, jobMetrics)
	require.NoError(t, err)
	assert.Equal(t, int64(3), rowsAffected)

	for jobID, expectedMetrics := range jobMetrics {
		metrics, err := store.q.GetJobMetrics(ctx, pgtype.UUID{Bytes: jobID, Valid: true})
		require.NoError(t, err)

		assert.Equal(t, int32(expectedMetrics.TotalTasks()), metrics.TotalTasks)
		assert.Equal(t, int32(expectedMetrics.PendingTasks()), metrics.PendingTasks)
		assert.Equal(t, int32(expectedMetrics.InProgressTasks()), metrics.InProgressTasks)
		assert.Equal(t, int32(expectedMetrics.CompletedTasks()), metrics.CompletedTasks)
		assert.Equal(t, int32(expectedMetrics.FailedTasks()), metrics.FailedTasks)
		assert.Equal(t, int32(expectedMetrics.StaleTasks()), metrics.StaleTasks)
		assert.Equal(t, int32(expectedMetrics.CancelledTasks()), metrics.CancelledTasks)
		assert.Equal(t, int32(expectedMetrics.PausedTasks()), metrics.PausedTasks)
	}
}

func TestJobStore_BulkUpdateJobMetrics_Empty(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	rowsAffected, err := store.BulkUpdateJobMetrics(ctx, make(map[uuid.UUID]*scanning.JobMetrics))
	require.ErrorIs(t, err, scanning.ErrNoJobMetricsUpdated)
	assert.Equal(t, int64(0), rowsAffected)
}

func TestJobStore_BulkUpdateJobMetrics_Upsert(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusRunning)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	// First update.
	initialMetrics := scanning.ReconstructJobMetrics(10, 0, 0, 5, 2, 1, 1, 1)
	updates := map[uuid.UUID]*scanning.JobMetrics{
		job.JobID(): initialMetrics,
	}

	rowsAffected, err := store.BulkUpdateJobMetrics(ctx, updates)
	require.NoError(t, err)
	assert.Equal(t, int64(1), rowsAffected)

	// Verify initial metrics.
	metrics, err := store.q.GetJobMetrics(ctx, pgtype.UUID{Bytes: job.JobID(), Valid: true})
	require.NoError(t, err)
	assert.Equal(t, int32(10), metrics.TotalTasks)
	assert.Equal(t, int32(5), metrics.CompletedTasks)
	assert.Equal(t, int32(1), metrics.CancelledTasks)
	assert.Equal(t, int32(1), metrics.PausedTasks)

	// Second update with different metrics.
	updatedMetrics := scanning.ReconstructJobMetrics(20, 0, 0, 15, 3, 0, 2, 0)
	updates[job.JobID()] = updatedMetrics

	rowsAffected, err = store.BulkUpdateJobMetrics(ctx, updates)
	require.NoError(t, err)
	assert.Equal(t, int64(1), rowsAffected)

	metrics, err = store.q.GetJobMetrics(ctx, pgtype.UUID{Bytes: job.JobID(), Valid: true})
	require.NoError(t, err)
	assert.Equal(t, int32(20), metrics.TotalTasks)
	assert.Equal(t, int32(15), metrics.CompletedTasks)
	assert.Equal(t, int32(3), metrics.FailedTasks)
	assert.Equal(t, int32(0), metrics.StaleTasks)
	assert.Equal(t, int32(2), metrics.CancelledTasks)
	assert.Equal(t, int32(0), metrics.PausedTasks)
}

func TestJobStore_GetJobMetrics_NonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	metrics, err := store.GetJobMetrics(ctx, uuid.New())
	require.ErrorIs(t, err, scanning.ErrNoJobMetricsFound)
	assert.Nil(t, metrics)
}

func TestJobStore_GetJobMetrics_ExistingMetrics(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusRunning)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	expectedMetrics := scanning.ReconstructJobMetrics(10, 0, 0, 5, 2, 1, 1, 1)
	updates := map[uuid.UUID]*scanning.JobMetrics{
		job.JobID(): expectedMetrics,
	}

	rowsAffected, err := store.BulkUpdateJobMetrics(ctx, updates)
	require.NoError(t, err)
	assert.Equal(t, int64(1), rowsAffected)

	metrics, err := store.GetJobMetrics(ctx, job.JobID())
	require.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, expectedMetrics.TotalTasks(), metrics.TotalTasks())
	assert.Equal(t, expectedMetrics.CompletedTasks(), metrics.CompletedTasks())
	assert.Equal(t, expectedMetrics.FailedTasks(), metrics.FailedTasks())
	assert.Equal(t, expectedMetrics.StaleTasks(), metrics.StaleTasks())
	assert.Equal(t, expectedMetrics.CancelledTasks(), metrics.CancelledTasks())
	assert.Equal(t, expectedMetrics.PausedTasks(), metrics.PausedTasks())
}

func TestJobStore_GetCheckpoints_NonExistentJob(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	checkpoints, err := store.GetCheckpoints(ctx, uuid.New())
	require.ErrorIs(t, err, scanning.ErrNoCheckpointsFound)
	assert.Empty(t, checkpoints)
}

func TestJobStore_UpdateMetricsAndCheckpoint(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusRunning)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	// Update metrics and checkpoint atomically.
	metrics := scanning.ReconstructJobMetrics(10, 2, 3, 1, 1, 0, 2, 1)
	err = store.UpdateMetricsAndCheckpoint(ctx, job.JobID(), metrics, 0, 100)
	require.NoError(t, err)

	storedMetrics, err := store.GetJobMetrics(ctx, job.JobID())
	require.NoError(t, err)
	assert.Equal(t, metrics.PendingTasks(), storedMetrics.PendingTasks())
	assert.Equal(t, metrics.InProgressTasks(), storedMetrics.InProgressTasks())
	assert.Equal(t, metrics.CompletedTasks(), storedMetrics.CompletedTasks())
	assert.Equal(t, metrics.FailedTasks(), storedMetrics.FailedTasks())
	assert.Equal(t, metrics.StaleTasks(), storedMetrics.StaleTasks())
	assert.Equal(t, metrics.CancelledTasks(), storedMetrics.CancelledTasks())
	assert.Equal(t, metrics.PausedTasks(), storedMetrics.PausedTasks())

	checkpoints, err := store.GetCheckpoints(ctx, job.JobID())
	require.NoError(t, err)
	assert.Equal(t, int64(100), checkpoints[0])
}

func TestJobStore_UpdateMetricsAndCheckpoint_NonExistentJob(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	metrics := scanning.ReconstructJobMetrics(10, 2, 3, 4, 1, 0, 0, 0)
	err := store.UpdateMetricsAndCheckpoint(ctx, uuid.New(), metrics, 0, 100)
	require.Error(t, err)
}

func TestJobStore_GetJobByID(t *testing.T) {
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	testCases := []struct {
		name             string
		status           scanning.JobStatus
		metrics          *scanning.JobMetrics
		expectError      bool
		expectedError    error
		validateResponse func(t *testing.T, detail *scanning.JobDetail)
	}{
		{
			name:        "job with metrics",
			status:      scanning.JobStatusRunning,
			metrics:     scanning.ReconstructJobMetrics(100, 20, 30, 40, 5, 3, 1, 1),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, 100, detail.Metrics.TotalTasks)
				assert.Equal(t, 40, detail.Metrics.CompletedTasks)
				assert.InDelta(t, 40.0, detail.Metrics.CompletionPercentage, 0.001)
			},
		},
		{
			name:        "job without metrics",
			status:      scanning.JobStatusQueued,
			metrics:     nil,
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, 0, detail.Metrics.TotalTasks)
				assert.Equal(t, 0.0, detail.Metrics.CompletionPercentage)
			},
		},
		{
			name:        "job with zero total tasks",
			status:      scanning.JobStatusRunning,
			metrics:     scanning.ReconstructJobMetrics(0, 0, 0, 0, 0, 0, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, 0, detail.Metrics.TotalTasks)
				assert.Equal(t, 0.0, detail.Metrics.CompletionPercentage)
			},
		},
		{
			name:          "non-existent job",
			expectError:   true,
			expectedError: scanning.ErrJobNotFound,
		},

		// Job status variations - test every status in the enum
		{
			name:        "paused job",
			status:      scanning.JobStatusPaused,
			metrics:     scanning.ReconstructJobMetrics(50, 10, 0, 25, 5, 0, 0, 10),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusPaused, detail.Status)
				assert.Equal(t, 10, detail.Metrics.PausedTasks)
			},
		},
		{
			name:        "queued job",
			status:      scanning.JobStatusQueued,
			metrics:     scanning.ReconstructJobMetrics(10, 10, 0, 0, 0, 0, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusQueued, detail.Status)
				assert.Equal(t, 0.0, detail.Metrics.CompletionPercentage)
			},
		},
		{
			name:        "enumerating job",
			status:      scanning.JobStatusEnumerating,
			metrics:     scanning.ReconstructJobMetrics(0, 0, 0, 0, 0, 0, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusEnumerating, detail.Status)
				// During enumeration, total tasks might still be zero
				assert.Equal(t, 0, detail.Metrics.TotalTasks)
			},
		},
		{
			name:        "pausing job",
			status:      scanning.JobStatusPausing,
			metrics:     scanning.ReconstructJobMetrics(100, 20, 40, 30, 0, 0, 0, 10),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusPausing, detail.Status)
				// Should have some tasks in progress and some paused during pausing state
				assert.Greater(t, detail.Metrics.InProgressTasks, 0)
				assert.Greater(t, detail.Metrics.PausedTasks, 0)
			},
		},
		{
			name:        "completed job",
			status:      scanning.JobStatusCompleted,
			metrics:     scanning.ReconstructJobMetrics(100, 0, 0, 95, 5, 0, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusCompleted, detail.Status)
				// Should have high completion percentage
				assert.InDelta(t, 95.0, detail.Metrics.CompletionPercentage, 0.001)
				// No tasks should be in progress or pending
				assert.Equal(t, 0, detail.Metrics.InProgressTasks)
				assert.Equal(t, 0, detail.Metrics.PendingTasks)
			},
		},
		{
			name:        "cancelling job",
			status:      scanning.JobStatusCancelling,
			metrics:     scanning.ReconstructJobMetrics(100, 20, 30, 20, 5, 0, 25, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusCancelling, detail.Status)
				// Should have some cancelled tasks
				assert.Greater(t, detail.Metrics.CancelledTasks, 0)
			},
		},
		{
			name:        "cancelled job",
			status:      scanning.JobStatusCancelled,
			metrics:     scanning.ReconstructJobMetrics(100, 0, 0, 50, 0, 0, 50, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusCancelled, detail.Status)
				// All non-completed tasks should be marked as cancelled
				assert.Equal(t, 50, detail.Metrics.CancelledTasks)
				assert.Equal(t, 0, detail.Metrics.InProgressTasks)
				assert.Equal(t, 0, detail.Metrics.PendingTasks)
			},
		},
		{
			name:        "failed job",
			status:      scanning.JobStatusFailed,
			metrics:     scanning.ReconstructJobMetrics(100, 0, 0, 60, 40, 0, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, scanning.JobStatusFailed, detail.Status)
				// Should have significant failed tasks
				assert.Greater(t, detail.Metrics.FailedTasks, 0)
			},
		},

		// Edge cases and special scenarios.
		{
			name:        "job with stale tasks",
			status:      scanning.JobStatusRunning,
			metrics:     scanning.ReconstructJobMetrics(100, 20, 30, 40, 0, 10, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, 10, detail.Metrics.StaleTasks)
				// Stale tasks should not affect completion percentage calculation.
				assert.InDelta(t, 40.0, detail.Metrics.CompletionPercentage, 0.001)
			},
		},
		{
			name:        "job with all metrics types populated",
			status:      scanning.JobStatusRunning,
			metrics:     scanning.ReconstructJobMetrics(100, 20, 30, 20, 10, 5, 5, 10),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, 20, detail.Metrics.PendingTasks)
				assert.Equal(t, 30, detail.Metrics.InProgressTasks)
				assert.Equal(t, 20, detail.Metrics.CompletedTasks)
				assert.Equal(t, 10, detail.Metrics.FailedTasks)
				assert.Equal(t, 5, detail.Metrics.StaleTasks)
				assert.Equal(t, 5, detail.Metrics.CancelledTasks)
				assert.Equal(t, 10, detail.Metrics.PausedTasks)

				// Sum should equal total tasks.
				sum := detail.Metrics.PendingTasks +
					detail.Metrics.InProgressTasks +
					detail.Metrics.CompletedTasks +
					detail.Metrics.FailedTasks +
					detail.Metrics.StaleTasks +
					detail.Metrics.CancelledTasks +
					detail.Metrics.PausedTasks
				assert.Equal(t, detail.Metrics.TotalTasks, sum)
			},
		},
		{
			name:        "job with all tasks completed",
			status:      scanning.JobStatusRunning,
			metrics:     scanning.ReconstructJobMetrics(100, 0, 0, 100, 0, 0, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				assert.Equal(t, 100.0, detail.Metrics.CompletionPercentage)
			},
		},
		{
			name:        "job with floating point precision test",
			status:      scanning.JobStatusRunning,
			metrics:     scanning.ReconstructJobMetrics(3, 0, 0, 1, 0, 0, 0, 0),
			expectError: false,
			validateResponse: func(t *testing.T, detail *scanning.JobDetail) {
				// 1/3 = 33.33...%
				assert.InDelta(t, 33.33, detail.Metrics.CompletionPercentage, 0.01)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var jobID uuid.UUID

			if !tc.expectError {
				job := scanning.ReconstructJob(
					uuid.New(),
					shared.SourceTypeGitHub.String(),
					json.RawMessage(`{}`),
					tc.status,
					scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
				)
				err := store.CreateJob(ctx, job)
				require.NoError(t, err)
				jobID = job.JobID()

				// Add metrics if provided.
				if tc.metrics != nil {
					_, err = store.BulkUpdateJobMetrics(ctx, map[uuid.UUID]*scanning.JobMetrics{
						jobID: tc.metrics,
					})
					require.NoError(t, err)
				}
			} else {
				jobID = uuid.New()
			}

			detail, err := store.GetJobByID(ctx, jobID)
			if tc.expectError {
				require.Error(t, err)
				if tc.expectedError != nil {
					require.ErrorIs(t, err, tc.expectedError)
				}
				require.Nil(t, detail)
			} else {
				require.NoError(t, err)
				require.NotNil(t, detail)
				assert.Equal(t, jobID, detail.ID)
				assert.Equal(t, tc.status, detail.Status)

				if tc.validateResponse != nil {
					tc.validateResponse(t, detail)
				}
			}
		})
	}
}

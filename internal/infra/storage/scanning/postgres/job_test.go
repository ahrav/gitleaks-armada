package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage/enumeration/postgres"
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
		status,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
		nil,
		scanning.ReconstructJobMetrics(0, 0, 0, 0, 0, 0),
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

type mockTimeProvider struct {
	current time.Time
}

func (m *mockTimeProvider) Now() time.Time {
	return m.current
}

func TestJobStore_UpdateJob(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	mockTime := &mockTimeProvider{current: time.Now().UTC()}
	timeline := scanning.NewTimeline(mockTime)

	// Initialize job with zero metrics.
	job := scanning.ReconstructJob(
		uuid.New(),
		scanning.JobStatusQueued,
		timeline,
		nil,
		nil,
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	initialJob, err := store.GetJob(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, initialJob)

	// Set completion time one hour later.
	completionTime := initialJob.StartTime().Add(time.Hour)
	completionTimeline := scanning.ReconstructTimeline(
		initialJob.StartTime(),
		completionTime,
		completionTime,
	)

	updatedJob := scanning.ReconstructJob(
		job.JobID(),
		scanning.JobStatusCompleted,
		completionTimeline,
		nil,
		nil,
	)

	err = store.UpdateJob(ctx, updatedJob)
	require.NoError(t, err)

	loaded, err := store.GetJob(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify status and timing.
	assert.Equal(t, scanning.JobStatusCompleted, loaded.Status())
	endTime, hasEndTime := loaded.EndTime()
	assert.True(t, hasEndTime)
	assert.Equal(t, completionTime.UTC(), endTime.UTC(),
		"End time should match completion time")
	assert.WithinDuration(t, time.Now().UTC(), loaded.LastUpdateTime(), time.Second,
		"Last update time should be close to current time")
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

	assert.ElementsMatch(t, loaded.TargetIDs(), targetIDs)
}

func TestJobStore_GetNonExistent(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	loaded, err := store.GetJob(ctx, uuid.New())
	require.ErrorIs(t, err, scanning.ErrJobNotFound)
	assert.Nil(t, loaded)
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
	initialMetrics := scanning.ReconstructJobMetrics(10, 0, 0, 5, 2, 1)
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

	// Second update with different metrics.
	updatedMetrics := scanning.ReconstructJobMetrics(20, 0, 0, 15, 3, 2)
	updates[job.JobID()] = updatedMetrics

	rowsAffected, err = store.BulkUpdateJobMetrics(ctx, updates)
	require.NoError(t, err)
	assert.Equal(t, int64(1), rowsAffected)

	metrics, err = store.q.GetJobMetrics(ctx, pgtype.UUID{Bytes: job.JobID(), Valid: true})
	require.NoError(t, err)
	assert.Equal(t, int32(20), metrics.TotalTasks)
	assert.Equal(t, int32(15), metrics.CompletedTasks)
	assert.Equal(t, int32(3), metrics.FailedTasks)
	assert.Equal(t, int32(2), metrics.StaleTasks)
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

	expectedMetrics := scanning.ReconstructJobMetrics(10, 0, 0, 5, 2, 1)
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
	metrics := scanning.ReconstructJobMetrics(10, 2, 3, 4, 1, 0)
	err = store.UpdateMetricsAndCheckpoint(ctx, job.JobID(), metrics, 0, 100)
	require.NoError(t, err)

	storedMetrics, err := store.GetJobMetrics(ctx, job.JobID())
	require.NoError(t, err)
	assert.Equal(t, metrics.PendingTasks(), storedMetrics.PendingTasks())
	assert.Equal(t, metrics.InProgressTasks(), storedMetrics.InProgressTasks())
	assert.Equal(t, metrics.CompletedTasks(), storedMetrics.CompletedTasks())
	assert.Equal(t, metrics.FailedTasks(), storedMetrics.FailedTasks())
	assert.Equal(t, metrics.StaleTasks(), storedMetrics.StaleTasks())

	checkpoints, err := store.GetCheckpoints(ctx, job.JobID())
	require.NoError(t, err)
	assert.Equal(t, int64(100), checkpoints[0])
}

func TestJobStore_UpdateMetricsAndCheckpoint_NonExistentJob(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	metrics := scanning.ReconstructJobMetrics(10, 2, 3, 4, 1, 0)
	err := store.UpdateMetricsAndCheckpoint(ctx, uuid.New(), metrics, 0, 100)
	require.Error(t, err)
}

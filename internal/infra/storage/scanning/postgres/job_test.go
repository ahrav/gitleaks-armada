package postgres

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
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
		scanning.ReconstructJobMetrics(0, 0, 0),
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
	initialMetrics := scanning.ReconstructJobMetrics(0, 0, 0)
	job := scanning.ReconstructJob(
		uuid.New(),
		scanning.JobStatusQueued,
		timeline,
		nil,
		initialMetrics,
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	initialJob, err := store.GetJob(ctx, job.JobID())
	require.NoError(t, err)
	require.NotNil(t, initialJob)

	assert.Equal(t, 0, initialJob.Metrics().TotalTasks())
	assert.Equal(t, 0, initialJob.Metrics().CompletedTasks())
	assert.Equal(t, 0, initialJob.Metrics().FailedTasks())

	// Set completion time one hour later.
	completionTime := initialJob.StartTime().Add(time.Hour)
	completionTimeline := scanning.ReconstructTimeline(
		initialJob.StartTime(),
		completionTime,
		completionTime,
	)

	// Create updated metrics.
	updatedMetrics := scanning.ReconstructJobMetrics(10, 8, 2)
	updatedJob := scanning.ReconstructJob(
		job.JobID(),
		scanning.JobStatusCompleted,
		completionTimeline,
		nil,
		updatedMetrics,
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

	// Verify updated metrics.
	assert.Equal(t, 10, loaded.Metrics().TotalTasks(), "Total tasks should match")
	assert.Equal(t, 8, loaded.Metrics().CompletedTasks(), "Completed tasks should match")
	assert.Equal(t, 2, loaded.Metrics().FailedTasks(), "Failed tasks should match")
	assert.Equal(t, 80.0, loaded.Metrics().CompletionPercentage(), "Completion percentage should be 80%")
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
	require.NoError(t, err)
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

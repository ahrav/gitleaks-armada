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

func createTestJob(t *testing.T, status scanning.JobStatus) *scanning.ScanJob {
	t.Helper()
	return scanning.ReconstructJob(
		uuid.New(),
		status,
		scanning.NewTimeline(&mockTimeProvider{current: time.Now()}),
		nil,
	)
}

func TestJobStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	ctx, _, store, cleanup := setupJobTest(t)
	defer cleanup()

	job := createTestJob(t, scanning.JobStatusQueued)
	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	loaded, err := store.GetJob(ctx, job.GetJobID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, job.GetJobID(), loaded.GetJobID())
	assert.Equal(t, job.GetStatus(), loaded.GetStatus())
	assert.WithinDuration(t, job.GetStartTime(), loaded.GetStartTime(), time.Second)
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
	job := scanning.ReconstructJob(
		uuid.New(),
		scanning.JobStatusQueued,
		timeline,
		nil,
	)

	err := store.CreateJob(ctx, job)
	require.NoError(t, err)

	initialJob, err := store.GetJob(ctx, job.GetJobID())
	require.NoError(t, err)
	require.NotNil(t, initialJob)

	// Set completion time one hour later.
	completionTime := initialJob.GetStartTime().Add(time.Hour)
	completionTimeline := scanning.ReconstructTimeline(
		initialJob.GetStartTime(),
		completionTime,
		completionTime,
	)

	updatedJob := scanning.ReconstructJob(
		job.GetJobID(),
		scanning.JobStatusCompleted,
		completionTimeline,
		nil,
	)

	err = store.UpdateJob(ctx, updatedJob)
	require.NoError(t, err)

	loaded, err := store.GetJob(ctx, job.GetJobID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, scanning.JobStatusCompleted, loaded.GetStatus())
	assert.Equal(t, initialJob.GetStartTime(), loaded.GetStartTime(),
		"Start time should not change")
	assert.Equal(t, completionTime, loaded.GetEndTime(),
		"End time should match completion time")
	assert.WithinDuration(t, time.Now().UTC(), loaded.GetLastUpdateTime(), time.Second,
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
	err = store.AssociateTargets(ctx, job.GetJobID(), targetIDs)
	require.NoError(t, err)

	loaded, err := store.GetJob(ctx, job.GetJobID())
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.ElementsMatch(t, loaded.GetTargetIDs(), targetIDs)
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
	err = store.AssociateTargets(ctx, job.GetJobID(), []uuid.UUID{})
	require.NoError(t, err)
}

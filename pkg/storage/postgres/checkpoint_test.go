package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/ahrav/gitleaks-armada/pkg/storage"
)

func setupTestContainer(t *testing.T) (*sql.DB, func()) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:17-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForSQL("5432/tcp", "postgres", func(host string, port nat.Port) string {
			return fmt.Sprintf("postgresql://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())
		}),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dbURL := fmt.Sprintf("postgresql://test:test@localhost:%s/testdb?sslmode=disable", port.Port())
	db, err := sql.Open("postgres", dbURL)
	require.NoError(t, err)

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	require.NoError(t, err)

	_, currentFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(currentFile), "..", "..", "..")
	migrationsPath := fmt.Sprintf("file://%s", filepath.Join(projectRoot, "db", "migrations"))
	migrations, err := migrate.NewWithDatabaseInstance(migrationsPath, "postgres", driver)
	require.NoError(t, err)

	err = migrations.Up()
	require.NoError(t, err)

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, cleanup
}

func TestPGCheckpointStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()

	checkpoint := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
			"page":   42,
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, checkpoint.TargetID, loaded.TargetID)
	assert.Equal(t, checkpoint.Data["cursor"], loaded.Data["cursor"])
	assert.Equal(t, float64(42), loaded.Data["page"])
	assert.False(t, loaded.UpdatedAt.IsZero(), "UpdatedAt should be set")
}

func TestPGCheckpointStorage_LoadNonExistent(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()

	loaded, err := store.Load(ctx, "non-existent")
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestPGCheckpointStorage_Delete(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()

	checkpoint := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	err = store.Delete(ctx, checkpoint.TargetID)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestPGCheckpointStorage_DeleteNonExistent(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()

	err := store.Delete(ctx, "non-existent")
	require.NoError(t, err)
}

func TestPGCheckpointStorage_Update(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()

	checkpoint := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)
	firstSaveTime := time.Now()

	time.Sleep(10 * time.Millisecond)

	checkpoint.Data["cursor"] = "def456"
	err = store.Save(ctx, checkpoint)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, checkpoint.TargetID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "def456", loaded.Data["cursor"])
	assert.True(t, loaded.UpdatedAt.After(firstSaveTime),
		"UpdatedAt should be later than first save")
}

func TestPGCheckpointStorage_ConcurrentOperations(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()
	const goroutines = 10
	done := make(chan bool)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			checkpoint := &storage.Checkpoint{
				TargetID: "concurrent-target",
				Data: map[string]any{
					"value": id,
				},
			}

			err := store.Save(ctx, checkpoint)
			require.NoError(t, err)

			_, err = store.Load(ctx, checkpoint.TargetID)
			require.NoError(t, err)

			done <- true
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	loaded, err := store.Load(ctx, "concurrent-target")
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.NotNil(t, loaded.Data["value"])
}

func TestPGCheckpointStorage_Mutability(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()

	original := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
			"nested": map[string]any{
				"key": "value",
			},
		},
	}

	err := store.Save(ctx, original)
	require.NoError(t, err)

	loaded, err := store.Load(ctx, original.TargetID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	loaded.Data["cursor"] = "modified"
	if nestedMap, ok := loaded.Data["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.Load(ctx, original.TargetID)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, "abc123", reloaded.Data["cursor"], "Top-level value should not be modified")
	if nestedMap, ok := reloaded.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested value should not be modified")
	}
}

func TestPGCheckpointStorage_LoadByID(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestContainer(t)
	defer cleanup()

	store := NewPGCheckpointStorage(db)
	ctx := context.Background()

	checkpoint := &storage.Checkpoint{
		TargetID: "test-target",
		Data: map[string]any{
			"cursor": "abc123",
			"nested": map[string]any{
				"key": "value",
			},
		},
	}

	err := store.Save(ctx, checkpoint)
	require.NoError(t, err)

	// Get the checkpoint by target ID first to get its database ID.
	saved, err := store.Load(ctx, checkpoint.TargetID)
	require.NoError(t, err)
	require.NotNil(t, saved)

	loaded, err := store.LoadByID(ctx, saved.ID)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, saved.ID, loaded.ID)
	assert.Equal(t, checkpoint.TargetID, loaded.TargetID)
	assert.Equal(t, checkpoint.Data["cursor"], loaded.Data["cursor"])
	if nestedMap, ok := loaded.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"])
	}

	// Test non-existent ID.
	nonExistent, err := store.LoadByID(ctx, 999)
	require.NoError(t, err)
	assert.Nil(t, nonExistent)

	loaded.Data["cursor"] = "modified"
	if nestedMap, ok := loaded.Data["nested"].(map[string]any); ok {
		nestedMap["key"] = "modified"
	}

	reloaded, err := store.LoadByID(ctx, saved.ID)
	require.NoError(t, err)
	require.NotNil(t, reloaded)

	assert.Equal(t, "abc123", reloaded.Data["cursor"], "Top-level value should not be modified")
	if nestedMap, ok := reloaded.Data["nested"].(map[string]any); ok {
		assert.Equal(t, "value", nestedMap["key"], "Nested value should not be modified")
	}
}

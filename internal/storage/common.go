package storage

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/otel"
)

// ExecuteAndTrace is a helper function that wraps database operations with OpenTelemetry tracing.
// It creates a new span with the given name and attributes, executes the provided operation,
// and handles error recording and span cleanup.
//
// Returns an error if the operation fails, nil otherwise.
// Any errors are recorded on the span before being returned.
func ExecuteAndTrace(
	ctx context.Context,
	tracer trace.Tracer,
	spanName string,
	attributes []attribute.KeyValue,
	operation func(ctx context.Context) error,
) error {
	ctx, span := tracer.Start(ctx, spanName, trace.WithAttributes(attributes...))
	defer span.End()

	err := operation(ctx)
	if err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

func SetupTestContainer(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()

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

	dsn := fmt.Sprintf("postgres://test:test@localhost:%s/testdb?sslmode=disable", port.Port())

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)

	// We need this to run migrations.
	// TODO: Figure out if there is a less hacky way to do this.
	db := stdlib.OpenDBFromPool(pool)

	// For migrations, use the pgx driver.
	driver, err := pgx.WithInstance(db, &pgx.Config{})
	require.NoError(t, err)

	_, currentFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(currentFile), "..", "..")
	migrationsPath := fmt.Sprintf("file://%s", filepath.Join(projectRoot, "db", "migrations"))
	migrations, err := migrate.NewWithDatabaseInstance(migrationsPath, "postgres", driver)
	require.NoError(t, err)

	err = migrations.Up()
	require.NoError(t, err)

	cleanup := func() {
		_ = db.Close()
		_ = container.Terminate(ctx)
	}

	return pool, cleanup
}

func NoOpTracer() trace.Tracer {
	tracer, _, _ := otel.InitTracing(logger.NewWithHandler(slog.NewJSONHandler(io.Discard, nil)), otel.Config{})
	return tracer.Tracer("test")
}

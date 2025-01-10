package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/db"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/internal/infra/storage"
)

var _ enumeration.TaskRepository = (*taskStore)(nil)

// taskStore provides a PostgreSQL implementation of TaskRepository.
type taskStore struct {
	q      *db.Queries
	tracer trace.Tracer
}

// NewTaskStore creates a new PostgreSQL-backed task storage using
// the provided database connection.
func NewTaskStore(dbConn *pgxpool.Pool, tracer trace.Tracer) *taskStore {
	return &taskStore{q: db.New(dbConn), tracer: tracer}
}

// Save persists a new enumeration task to storage.
func (t *taskStore) Save(ctx context.Context, task *enumeration.Task) error {
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", task.TaskID.String()),
		attribute.String("session_id", task.SessionID().String()),
		attribute.String("resource_uri", task.ResourceURI()),
	)
	return storage.ExecuteAndTrace(ctx, t.tracer, "postgres.enumeration.save_task", dbAttrs, func(ctx context.Context) error {
		metadata, err := json.Marshal(task.Metadata())
		if err != nil {
			return fmt.Errorf("failed to marshal task metadata: %w", err)
		}

		err = t.q.CreateTask(ctx, db.CreateTaskParams{
			TaskID:      pgtype.UUID{Bytes: task.TaskID, Valid: true},
			SourceType:  string(task.SourceType),
			SessionID:   pgtype.UUID{Bytes: task.SessionID(), Valid: true},
			ResourceUri: task.ResourceURI(),
			Metadata:    metadata,
		})
		if err != nil {
			return fmt.Errorf("failed to save task: %w", err)
		}

		return nil
	})
}

// GetByID retrieves a task by its unique identifier.
func (t *taskStore) GetByID(ctx context.Context, taskID uuid.UUID) (*enumeration.Task, error) {
	var task *enumeration.Task
	dbAttrs := append(
		defaultDBAttributes,
		attribute.String("task_id", taskID.String()),
	)
	err := storage.ExecuteAndTrace(ctx, t.tracer, "postgres.enumeration.get_task", dbAttrs, func(ctx context.Context) error {
		dbTask, err := t.q.GetTaskByID(ctx, pgtype.UUID{Bytes: taskID, Valid: true})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("failed to get task: %w", err)
		}

		var metadata map[string]string
		if err := json.Unmarshal(dbTask.Metadata, &metadata); err != nil {
			return fmt.Errorf("failed to unmarshal task metadata: %w", err)
		}

		task = enumeration.ReconstructTask(
			dbTask.TaskID.Bytes,
			shared.SourceType(dbTask.SourceType),
			dbTask.SessionID.Bytes,
			dbTask.ResourceUri,
			metadata,
			nil, // TODO: Add credentials
		)

		return nil
	})

	return task, err
}

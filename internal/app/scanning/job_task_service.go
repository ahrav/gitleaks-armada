package scanning

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

var _ domain.JobTaskService = (*jobTaskService)(nil)
var _ domain.MetricsRepository = (*jobTaskService)(nil)

// jobTaskService is responsible for managing the lifecycle of jobs and tasks.
type jobTaskService struct {
	controllerID string

	// TODO: Come back to the idea of using a cache.
	// TODO: If we want to use a cache, it will need to be a distributed cache.

	jobRepo  domain.JobRepository
	taskRepo domain.TaskRepository

	// TODO: Revist the idea of a persistence interval.

	logger *logger.Logger
	tracer trace.Tracer
}

// NewJobTaskService initializes the coordination system with configured thresholds
// for caching and persistence to optimize performance under expected load.
// TODO: Consider splitting this into a JobService and a TaskService.
func NewJobTaskService(
	controllerID string,
	jobRepo domain.JobRepository,
	taskRepo domain.TaskRepository,
	logger *logger.Logger,
	tracer trace.Tracer,
) *jobTaskService {
	logger = logger.With("component", "job_task_service")
	return &jobTaskService{
		controllerID: controllerID,
		jobRepo:      jobRepo,
		taskRepo:     taskRepo,
		logger:       logger,
		tracer:       tracer,
	}
}

// CreateJob initializes a new scanning operation and ensures it's immediately
// available in both the cache and persistent storage.
func (s *jobTaskService) CreateJob(ctx context.Context) (*domain.Job, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.create_job",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
		),
	)
	defer span.End()

	job := domain.NewJob()
	if err := s.jobRepo.CreateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return nil, fmt.Errorf("job repository create operation failed: %w", err)
	}
	span.AddEvent("job_created")
	span.SetStatus(codes.Ok, "job created successfully")

	return job, nil
}

// AssociateEnumeratedTargets links the provided scan targets to a job and increments
// the total task count in a single atomic transaction. By combining both steps, the
// method ensures consistent state is maintained if an error occurs at any point. This
// prevents partially associated targets or out-of-sync task counts.
//
//  1. jobRepo.AssociateTargets: Persists the relationship between the job and the targetIDs.
//  2. jobRepo.IncrementTotalTasks: Adjusts the job's total tasks count to account for the new targets.
func (s *jobTaskService) AssociateEnumeratedTargets(
	ctx context.Context,
	jobID uuid.UUID,
	targetIDs []uuid.UUID,
) error {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.associate_enumerated_targets",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.Int("target_count", len(targetIDs)),
		))
	defer span.End()

	if err := s.jobRepo.AssociateTargets(ctx, jobID, targetIDs); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to associate targets")
		return fmt.Errorf("failed to associate targets with job %s: %w", jobID, err)
	}
	span.AddEvent("targets_associated")

	if err := s.jobRepo.IncrementTotalTasks(ctx, jobID, len(targetIDs)); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to increment total tasks")
		return fmt.Errorf("failed to increment total tasks for job %s: %w", jobID, err)
	}
	span.AddEvent("total_tasks_incremented", trace.WithAttributes(
		attribute.Int("increment_amount", len(targetIDs)),
	))

	span.AddEvent("targets_associated_and_task_count_updated")
	span.SetStatus(codes.Ok, "targets associated and task count updated")

	return nil
}

// loadJob retrieves a job from the repository.
func (s *jobTaskService) loadJob(ctx context.Context, jobID uuid.UUID) (*domain.Job, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.load_job",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
		),
	)
	defer span.End()

	job, err := s.jobRepo.GetJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get job")
		return nil, fmt.Errorf("failed to get job: %w", err)
	}

	span.AddEvent("job_loaded")
	span.SetStatus(codes.Ok, "job loaded successfully")

	return job, nil
}

// UpdateJobStatus updates the status of a job after validating the state transition.
func (s *jobTaskService) UpdateJobStatus(ctx context.Context, jobID uuid.UUID, status domain.JobStatus) error {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.update_job_status",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
			attribute.String("current_status", string(status)),
			attribute.String("target_status", string(status)),
		))
	defer span.End()

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return fmt.Errorf("failed to load job: %w", err)
	}

	if err := job.UpdateStatus(status); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid status transition")
		return fmt.Errorf("invalid job status transition: %w", err)
	}
	span.AddEvent("job_status_transition_validated")

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job status")
		return fmt.Errorf("failed to update job status: %w", err)
	}
	span.AddEvent("job_status_updated_in_repo")

	span.AddEvent("job_status_updated", trace.WithAttributes(
		attribute.String("previous_status", string(job.Status())),
		attribute.String("new_status", string(status)),
	))
	span.SetStatus(codes.Ok, "job status updated successfully")

	return nil
}

// CompleteEnumeration finalizes the enumeration phase of a job and transitions it
// to the appropriate next state based on whether any tasks were created.
// It returns the job metrics needed for event publishing.
func (s *jobTaskService) CompleteEnumeration(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.complete_enumeration",
		trace.WithAttributes(
			attribute.String("job_id", jobID.String()),
		))
	defer span.End()

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return nil, fmt.Errorf("failed to load job: %w", err)
	}

	metrics, err := s.GetJobMetrics(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get job metrics")
		return nil, fmt.Errorf("failed to get job metrics: %w", err)
	}

	if err := job.CompleteEnumeration(metrics); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to complete enumeration")
		return nil, fmt.Errorf("failed to complete enumeration: %w", err)
	}
	span.AddEvent("enumeration_completed", trace.WithAttributes(
		attribute.String("new_status", string(job.Status())),
		attribute.Int("total_tasks", metrics.TotalTasks()),
	))

	if err := s.jobRepo.UpdateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update job")
		return nil, fmt.Errorf("failed to persist job state: %w", err)
	}
	span.AddEvent("job_state_persisted")

	span.AddEvent("enumeration_completed_successfully")
	span.SetStatus(codes.Ok, "enumeration completed successfully")

	return metrics, nil
}

// loadTask retrieves a task using a cache-first strategy to minimize database access
// during high-frequency progress updates.
func (s *jobTaskService) loadTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.load_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
		),
	)
	defer span.End()

	task, err := s.taskRepo.GetTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task")
		return nil, err
	}

	span.AddEvent("task_loaded")
	span.SetStatus(codes.Ok, "task loaded")

	return task, nil
}

// CreateTask creates a new task in the repository.
func (s *jobTaskService) CreateTask(ctx context.Context, task *domain.Task) error {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.create_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", task.JobID().String()),
			attribute.String("task_id", task.ID.String()),
		))
	defer span.End()

	if err := s.taskRepo.CreateTask(ctx, task, s.controllerID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create task in repo")
		return fmt.Errorf("creating task: %w", err)
	}
	span.AddEvent("task_created_in_repo")
	span.SetStatus(codes.Ok, "task created successfully")

	return nil
}

// StartTask updates an existing task's state to indicate it has begun execution.
// It returns an error if the task is not in a valid state for starting.
func (s *jobTaskService) StartTask(ctx context.Context, taskID uuid.UUID, resourceURI string) error {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.start_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return fmt.Errorf("load task: %w", err)
	}

	if err := task.Start(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to start task")
		return fmt.Errorf("start task failed: %w", err)
	}

	// Persist the updated task state
	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist task update")
		return fmt.Errorf("persist task update: %w", err)
	}

	span.AddEvent("task_started")
	span.SetStatus(codes.Ok, "task started successfully")
	return nil
}

// UpdateTaskProgress handles incremental scan progress updates while managing database load.
// Updates are cached and only persisted based on configured intervals to prevent database bottlenecks
// during high-frequency progress reporting.
func (s *jobTaskService) UpdateTaskProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.update_task_progress",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", progress.TaskID().String()),
			attribute.Int64("sequence_num", progress.SequenceNum()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, progress.TaskID())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("task load for progress update failed: %w", err)
	}
	span.SetAttributes(
		attribute.String("task_status", string(task.Status())),
	)

	if err := task.ApplyProgress(progress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply progress update")
		return nil, fmt.Errorf("apply progress: %w", err)
	}
	span.AddEvent("progress_applied",
		trace.WithAttributes(
			attribute.String("task_status", string(task.Status())),
		),
	)

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist updated task")
		return nil, fmt.Errorf("persist task: %w", err)
	}
	span.AddEvent("task_persisted_due_to_interval")

	span.AddEvent("task_progress_updated")
	span.SetStatus(codes.Ok, "task progress updated successfully")

	return task, nil
}

// CompleteTask finalizes a successful task execution.
func (s *jobTaskService) CompleteTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.complete_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	if err := task.Complete(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to complete task")
		return nil, fmt.Errorf("task completion state transition failed: %w", err)
	}
	span.AddEvent("task_completed")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist completed task")
		return nil, fmt.Errorf("repository task completion update failed: %w", err)
	}
	span.AddEvent("task_completed_persisted")
	span.SetStatus(codes.Ok, "task completed successfully")

	return task, nil
}

// FailTask marks a task as failed in the repository.
func (s *jobTaskService) FailTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.fail_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	if err := task.Fail(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to fail task")
		return nil, fmt.Errorf("task failure state transition failed: %w", err)
	}
	span.AddEvent("task_failed")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist failed task")
		return nil, fmt.Errorf("repository task failure update failed: %w", err)
	}
	span.AddEvent("task_failed_persisted")
	span.SetStatus(codes.Ok, "task failed successfully")

	return task, nil
}

// MarkTaskStale flags a task that has become unresponsive or stopped reporting progress.
// This enables automated detection and recovery of failed tasks that require intervention.
func (s *jobTaskService) MarkTaskStale(
	ctx context.Context,
	taskID uuid.UUID,
	reason domain.StallReason,
) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.mark_task_stale",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.String("reason", string(reason)),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	if err := task.MarkStale(&reason); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "job coordinator failed to mark task as stale")
		return nil, fmt.Errorf("task stale state transition failed (reason: %s): %w", reason, err)
	}
	span.AddEvent("task_marked_as_stale")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist stale task")
		return nil, fmt.Errorf("repository task stale update failed: %w", err)
	}
	span.AddEvent("task_stale_persisted")
	span.SetStatus(codes.Ok, "task marked as stale successfully")

	return task, nil
}

// GetTask retrieves a task using cache-first strategy to minimize database access.
func (s *jobTaskService) GetTask(ctx context.Context, taskID uuid.UUID) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.get_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task")
		return nil, fmt.Errorf("get task: %w", err)
	}

	span.AddEvent("task_retrieved")
	span.SetStatus(codes.Ok, "task retrieved successfully")
	return task, nil
}

// GetTaskSourceType retrieves the source type of a task using cache-first strategy.
func (s *jobTaskService) GetTaskSourceType(ctx context.Context, taskID uuid.UUID) (shared.SourceType, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.get_task_source_type",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
		))
	defer span.End()

	sourceType, err := s.taskRepo.GetTaskSourceType(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get task source type")
		return shared.SourceTypeUnspecified, fmt.Errorf("repository task source type query failed (task_id: %s): %w", taskID, err)
	}

	span.AddEvent("task_source_type_retrieved")
	span.SetStatus(codes.Ok, "task source type retrieved successfully")
	return sourceType, nil
}

// UpdateHeartbeats updates the last_heartbeat_at timestamp for a list of tasks.
func (s *jobTaskService) UpdateHeartbeats(ctx context.Context, heartbeats map[uuid.UUID]time.Time) (int64, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.update_heartbeats",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.Int("num_heartbeats", len(heartbeats)),
		))
	defer span.End()

	updatedTasks, err := s.taskRepo.BatchUpdateHeartbeats(ctx, heartbeats)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update heartbeats")
		return 0, fmt.Errorf("repository batch heartbeat update failed (count: %d): %w", len(heartbeats), err)
	}

	span.AddEvent("heartbeats_updated", trace.WithAttributes(
		attribute.Int("num_updated_tasks", int(updatedTasks)),
	))
	span.SetStatus(codes.Ok, "heartbeats updated successfully")

	return updatedTasks, nil
}

// FindStaleTasks finds tasks that have not sent a heartbeat within the staleness threshold.
func (s *jobTaskService) FindStaleTasks(
	ctx context.Context,
	controllerID string,
	cutoff time.Time,
) ([]domain.StaleTaskInfo, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.find_stale_tasks",
		trace.WithAttributes(
			attribute.String("controller_id", controllerID),
			attribute.String("cutoff", cutoff.Format(time.RFC3339)),
		))
	defer span.End()

	staleTasks, err := s.taskRepo.FindStaleTasks(ctx, controllerID, cutoff)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to find stale tasks")
		return nil, fmt.Errorf("repository stale task query failed (cutoff: %v): %w", cutoff, err)
	}

	span.AddEvent("stale_tasks_found", trace.WithAttributes(
		attribute.Int("num_stale_tasks", len(staleTasks)),
	))
	span.SetStatus(codes.Ok, "stale tasks found successfully")

	return staleTasks, nil
}

// GetJobMetrics retrieves the metrics for a specific job.
// Returns ErrJobNotFound if the job doesn't exist.
func (s *jobTaskService) GetJobMetrics(ctx context.Context, jobID uuid.UUID) (*domain.JobMetrics, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.get_job_metrics",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
		),
	)
	defer span.End()

	metrics, err := s.jobRepo.GetJobMetrics(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get job metrics")
		return nil, fmt.Errorf("failed to get job metrics: %w", err)
	}

	span.AddEvent("job_metrics_retrieved")
	span.SetStatus(codes.Ok, "job metrics retrieved successfully")

	return metrics, nil
}

// GetCheckpoints retrieves all checkpoints for a job's metrics.
func (s *jobTaskService) GetCheckpoints(ctx context.Context, jobID uuid.UUID) (map[int32]int64, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.get_checkpoints",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
		),
	)
	defer span.End()

	checkpoints, err := s.jobRepo.GetCheckpoints(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get checkpoints")
		return nil, fmt.Errorf("failed to get checkpoints: %w", err)
	}

	span.AddEvent("checkpoints_retrieved")
	span.SetStatus(codes.Ok, "checkpoints retrieved successfully")

	return checkpoints, nil
}

// UpdateMetricsAndCheckpoint updates the metrics and checkpoint for a job.
func (s *jobTaskService) UpdateMetricsAndCheckpoint(
	ctx context.Context,
	jobID uuid.UUID,
	metrics *domain.JobMetrics,
	partition int32,
	offset int64,
) error {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.update_metrics_and_checkpoint",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
			attribute.Int("partition", int(partition)),
			attribute.Int64("offset", offset),
		),
	)
	defer span.End()

	if err := s.jobRepo.UpdateMetricsAndCheckpoint(ctx, jobID, metrics, partition, offset); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update metrics and checkpoint")
		return fmt.Errorf("failed to update metrics and checkpoint: %w", err)
	}

	span.AddEvent("metrics_and_checkpoint_updated")
	span.SetStatus(codes.Ok, "metrics and checkpoint updated successfully")

	return nil
}

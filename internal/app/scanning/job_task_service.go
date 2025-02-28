package scanning

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

var _ domain.JobTaskService = (*jobTaskService)(nil)
var _ domain.MetricsRepository = (*jobTaskService)(nil)

// jobTaskService implements domain.JobTaskService and domain.MetricsRepository.
// It handles creation, updates, finalization, and metric retrieval for both jobs
// and tasks, using jobRepo and taskRepo for persistence. Future caching strategies
// may also be integrated here.
type jobTaskService struct {
	controllerID string

	// TODO: Come back to the idea of using a cache.
	// If we want to use a cache, it will need to be a distributed cache.

	// jobRepo provides persistence and retrieval for Job entities.
	jobRepo domain.JobRepository
	// taskRepo provides persistence and retrieval for Task entities.
	taskRepo domain.TaskRepository

	// TODO: Revist the idea of a persistence interval.

	logger *logger.Logger
	tracer trace.Tracer
}

// NewJobTaskService returns a jobTaskService that manages the lifecycle of jobs
// and tasks, optionally leveraging caching or future performance optimizations.
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

// CreateJobFromID creates a new Job in the repository, using the provided jobID.
// Returns the created Job on success.
func (s *jobTaskService) CreateJobFromID(ctx context.Context, jobID uuid.UUID) error {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.create_job",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
		),
	)
	defer span.End()

	job := domain.NewJob(jobID)
	if err := s.jobRepo.CreateJob(ctx, job); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create job")
		return fmt.Errorf("job repository create operation failed: %w", err)
	}
	span.AddEvent("job_created")
	span.SetStatus(codes.Ok, "job created successfully")

	return nil
}

// AssociateEnumeratedTargets links the given targetIDs to the specified job and increments
// the job's total task count in an atomic transaction to maintain consistency.
// TODO: what happens if only part of this succeeds?
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

// UpdateJobStatus changes the status of the given job, ensuring the transition
// is valid according to domain rules, then persists the updated job.
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

// CompleteEnumeration concludes the enumeration phase for a job. It retrieves current
// job metrics, calls job.CompleteEnumeration, updates the job in persistent storage,
// and returns the final metrics.
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

// CreateTask persists a new scanning task in the repository.
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

// StartTask transitions a task from a pending state to running and persists the update.
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

// UpdateTaskProgress handles task progress updates and necessary state transitions.
// It handles three specific cases:
// 1. Regular progress updates (IN_PROGRESS -> IN_PROGRESS)
// 2. Resuming from STALE -> IN_PROGRESS
// 3. Resuming from PAUSED -> IN_PROGRESS
func (s *jobTaskService) UpdateTaskProgress(ctx context.Context, progress domain.Progress) (*domain.Task, error) {
	taskID := progress.TaskID()
	ctx, span := s.tracer.Start(ctx, "job_task_service.update_task_progress",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.Int64("sequence_num", progress.SequenceNum()),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}
	span.SetAttributes(attribute.String("task_status", string(task.Status())))

	// Handle state transitions before applying progress.
	switch task.Status() {
	case domain.TaskStatusStale:
		if err := task.RecoverFromStale(); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to recover from stale")
			return nil, fmt.Errorf("recover from stale: %w", err)
		}
		span.AddEvent("task_recovered_from_stale")

	case domain.TaskStatusPending:
		if err := task.Start(); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to start task")
			return nil, fmt.Errorf("start task: %w", err)
		}
		span.AddEvent("task_started")

	case domain.TaskStatusInProgress:
		// Already in correct state, regular progress update.
		span.AddEvent("task_already_in_progress")

	default:
		span.RecordError(fmt.Errorf("unexpected status: %s", task.Status()))
		span.SetStatus(codes.Error, "unexpected task status")
		return nil, fmt.Errorf("unexpected task status for progress update: %s", task.Status())
	}

	// Now that we're in the correct state, apply the progress.
	if err := task.ApplyProgress(progress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply progress")
		return nil, fmt.Errorf("apply progress: %w", err)
	}
	span.AddEvent("progress_applied")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update task")
		return nil, fmt.Errorf("update task: %w", err)
	}

	span.AddEvent("task_progress_updated")
	span.SetStatus(codes.Ok, "task progress updated")

	return task, nil
}

// PauseTask transitions a task to PAUSED status and stores its final progress checkpoint.
func (s *jobTaskService) PauseTask(
	ctx context.Context,
	taskID uuid.UUID,
	progress domain.Progress,
	requestedBy string,
) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.pause_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.String("requested_by", requestedBy),
		))
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("load task: %w", err)
	}

	if err := task.Pause(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to pause task")
		return nil, fmt.Errorf("pause task: %w", err)
	}

	// Apply final progress if provided.
	if err := task.ApplyProgress(progress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to apply final progress")
		return nil, fmt.Errorf("apply final progress: %w", err)
	}

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to update task")
		return nil, fmt.Errorf("update task: %w", err)
	}
	span.AddEvent("task_paused")
	span.SetStatus(codes.Ok, "task paused successfully")

	return task, nil
}

// CompleteTask finalizes a task as successfully finished and persists its state.
// Returns the updated Task on success.
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

// FailTask transitions a task to the FAILED state and persists the update.
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

// MarkTaskStale flags a task as STALE, indicating it has not reported progress
// for an extended period. This status can prompt automatic recovery or re-scheduling.
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

// GetTask retrieves a task by ID, using a cache-first approach if implemented.
// TODO: Cache somehow?
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

	span.AddEvent("task_retrieved", trace.WithAttributes(
		attribute.String("task_status", string(task.Status())),
	))
	span.SetStatus(codes.Ok, "task retrieved successfully")
	return task, nil
}

// GetTaskSourceType returns a task's source type. Useful for domain logic that
// branches based on the type of resource the task is scanning.
// TODO: There might be a better way to do this.
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

	span.AddEvent("task_source_type_retrieved", trace.WithAttributes(
		attribute.String("source_type", string(sourceType)),
	))
	span.SetStatus(codes.Ok, "task source type retrieved successfully")
	return sourceType, nil
}

// UpdateHeartbeats updates the last heartbeat timestamp for a batch of tasks.
// Returns the number of tasks updated.
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

// FindStaleTasks returns tasks that have not reported a heartbeat since before
// the specified cutoff time, indicating they may require intervention.
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

// GetTasksToResume retrieves all PAUSED tasks for a job that need to be resumed.
// This method validates that the job is in a PAUSED state before fetching the tasks.
func (s *jobTaskService) GetTasksToResume(ctx context.Context, jobID uuid.UUID) ([]*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.get_tasks_to_resume",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("job_id", jobID.String()),
		),
	)
	defer span.End()

	job, err := s.loadJob(ctx, jobID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load job")
		return nil, fmt.Errorf("failed to load job: %w", err)
	}

	if job.Status() != domain.JobStatusPaused { // Verify the job is in PAUSED state
		err := fmt.Errorf("job is not in PAUSED state, current state: %s", job.Status())
		span.RecordError(err)
		span.SetStatus(codes.Error, "job not in PAUSED state")
		return nil, err
	}
	span.AddEvent("job_state_verified_as_paused")

	tasks, err := s.taskRepo.ListTasksByJobAndStatus(ctx, jobID, domain.TaskStatusPaused)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to list paused tasks")
		return nil, fmt.Errorf("failed to list paused tasks for job %s: %w", jobID, err)
	}
	span.AddEvent("paused_tasks_retrieved", trace.WithAttributes(
		attribute.Int("task_count", len(tasks)),
	))
	span.SetStatus(codes.Ok, "paused tasks retrieved successfully")

	return tasks, nil
}

// GetJobMetrics fetches high-level statistics for a job, such as total tasks or
// completed tasks. Returns an error if the job is not found.
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

	span.AddEvent("job_metrics_retrieved", trace.WithAttributes(
		attribute.Int("total_tasks", metrics.TotalTasks()),
		attribute.Int("pending_tasks", metrics.PendingTasks()),
		attribute.Int("in_progress_tasks", metrics.InProgressTasks()),
		attribute.Int("completed_tasks", metrics.CompletedTasks()),
		attribute.Int("failed_tasks", metrics.FailedTasks()),
	))
	span.SetStatus(codes.Ok, "job metrics retrieved successfully")

	return metrics, nil
}

// GetCheckpoints retrieves consumer offsets (checkpoints) for a job's partition(s).
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

	span.AddEvent("checkpoints_retrieved", trace.WithAttributes(
		attribute.Int("num_checkpoints", len(checkpoints)),
	))
	span.SetStatus(codes.Ok, "checkpoints retrieved successfully")

	return checkpoints, nil
}

// UpdateMetricsAndCheckpoint updates the job's metrics and the latest partition/offset
// checkpoint in a single, atomic database operation.
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

// CancelTask transitions a task to CANCELLED status.
func (s *jobTaskService) CancelTask(
	ctx context.Context,
	taskID uuid.UUID,
	requestedBy string,
) (*domain.Task, error) {
	ctx, span := s.tracer.Start(ctx, "job_task_service.scanning.cancel_task",
		trace.WithAttributes(
			attribute.String("controller_id", s.controllerID),
			attribute.String("task_id", taskID.String()),
			attribute.String("requested_by", requestedBy),
		),
	)
	defer span.End()

	task, err := s.loadTask(ctx, taskID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load task")
		return nil, fmt.Errorf("failed to load task: %w", err)
	}
	span.AddEvent("task_loaded_for_cancellation")

	if err := task.Cancel(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to cancel task")
		return nil, fmt.Errorf("failed to cancel task: %w", err)
	}
	span.AddEvent("task_cancelled")

	if err := s.taskRepo.UpdateTask(ctx, task); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to persist cancelled task")
		return nil, fmt.Errorf("failed to persist cancelled task: %w", err)
	}
	span.AddEvent("task_cancelled_persisted")
	span.SetStatus(codes.Ok, "task cancelled successfully")

	return task, nil
}

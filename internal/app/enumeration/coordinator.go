package enumeration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials/memory"
	"github.com/ahrav/gitleaks-armada/internal/config/loaders"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Coordinator defines the core domain operations for target enumeration.
// It coordinates the overall scanning process by managing enumeration state
// and supporting resumable scans.
type Coordinator interface {
	// ExecuteEnumeration performs target enumeration by either resuming from
	// existing state or starting fresh. It handles the full enumeration lifecycle
	// including state management and task generation.
	ExecuteEnumeration(ctx context.Context) error
}

// metrics defines the interface for tracking enumeration-related metrics.
type metrics interface {
	IncConfigReloadErrors(ctx context.Context)
	IncConfigReloads(ctx context.Context)
	ObserveTargetProcessingTime(ctx context.Context, duration time.Duration)
	IncTargetsProcessed(ctx context.Context)
	TrackEnumeration(ctx context.Context, fn func() error) error
	IncTasksEnqueued(ctx context.Context)
	IncTasksFailedToEnqueue(ctx context.Context)
}

// Orchestrator implements target enumeration by orchestrating domain logic, repository calls,
// and event publishing. It manages the lifecycle of enumeration sessions and coordinates
// the overall scanning process.
type coordinator struct {
	// Domain repositories.
	stateRepo      enumeration.StateRepository
	checkpointRepo enumeration.CheckpointRepository
	taskRepo       enumeration.TaskRepository

	// Creates enumerators for different target types.
	enumFactory EnumeratorFactory
	credStore   credentials.Store

	// External dependencies.
	eventPublisher events.DomainEventPublisher
	configLoader   loaders.Loader

	logger  *logger.Logger
	metrics metrics
	tracer  trace.Tracer
}

// NewCoordinator creates a new Service that coordinates target enumeration.
// It wires together all required dependencies including repositories, domain services,
// and external integrations needed for the enumeration workflow.
func NewCoordinator(
	stateRepo enumeration.StateRepository,
	checkpointRepo enumeration.CheckpointRepository,
	taskRepo enumeration.TaskRepository,
	enumFactory EnumeratorFactory,
	eventPublisher events.DomainEventPublisher,
	cfgLoader loaders.Loader,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) Coordinator {
	return &coordinator{
		stateRepo:      stateRepo,
		checkpointRepo: checkpointRepo,
		taskRepo:       taskRepo,
		enumFactory:    enumFactory,
		eventPublisher: eventPublisher,
		configLoader:   cfgLoader,
		logger:         logger,
		metrics:        metrics,
		tracer:         tracer,
	}
}

// ExecuteEnumeration performs target enumeration by either resuming from existing state
// or starting fresh. It first checks for any active enumeration states - if none exist,
// it loads the current configuration and starts new enumerations. Otherwise, it resumes
// the existing enumeration sessions.
func (s *coordinator) ExecuteEnumeration(ctx context.Context) error {
	return s.metrics.TrackEnumeration(ctx, func() error {
		ctx, span := s.tracer.Start(ctx, "enumeration.ExecuteEnumeration",
			trace.WithAttributes(
				attribute.String("component", "coordinator"),
				attribute.String("operation", "execute_enumeration"),
			))
		defer span.End()

		span.AddEvent("checking_active_states")
		activeStates, err := s.stateRepo.GetActiveStates(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to load active states")
			return fmt.Errorf("failed to load active states: %w", err)
		}
		span.AddEvent("active_states_loaded", trace.WithAttributes(
			attribute.Int("active_state_count", len(activeStates)),
		))

		if len(activeStates) == 0 {
			span.AddEvent("starting_fresh_enumeration")
			err := s.startFreshEnumerations(ctx)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "fresh enumeration failed")
				return err
			}
			return nil
		}

		span.AddEvent("resuming_enumeration", trace.WithAttributes(
			attribute.Int("state_count", len(activeStates)),
		))
		err = s.resumeEnumerations(ctx, activeStates)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "enumeration resume failed")
			return err
		}

		span.SetStatus(codes.Ok, "enumeration completed successfully")
		return nil
	})
}

// startFreshEnumerations processes each target from the configuration, creating new
// enumeration states and running the appropriate enumerator for each target type.
func (s *coordinator) startFreshEnumerations(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.startFreshEnumerations",
		trace.WithAttributes(
			attribute.String("component", "coordinator"),
			attribute.String("operation", "start_fresh_enumerations"),
		))
	defer span.End()

	cfg, err := s.configLoader.Load(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to load configuration")
		s.metrics.IncConfigReloadErrors(ctx)
		return fmt.Errorf("failed to load config: %w", err)
	}
	s.metrics.IncConfigReloads(ctx)
	span.AddEvent("configuration_loaded")

	s.credStore, err = memory.NewCredentialStore(cfg.Auth)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create credential store")
		return fmt.Errorf("failed to create credential store: %w", err)
	}
	span.AddEvent("credential_store_initialized")

	span.SetAttributes(
		attribute.Int("target_count", len(cfg.Targets)),
		attribute.Int("auth_config_count", len(cfg.Auth)),
	)

	for i, target := range cfg.Targets {
		targetSpan := trace.SpanFromContext(ctx)
		targetSpan.AddEvent("processing_target", trace.WithAttributes(
			attribute.Int("target_index", i),
			attribute.String("target_type", string(target.SourceType)),
			attribute.String("auth_ref", target.AuthRef),
		))

		start := time.Now()
		state := enumeration.NewState(string(target.SourceType), s.marshalConfig(ctx, target, cfg.Auth))

		if err := s.processTargetEnumeration(ctx, state, target); err != nil {
			targetSpan.RecordError(err)
			targetSpan.SetStatus(codes.Error, "target enumeration failed")
			s.logger.Error(ctx, "Target enumeration failed",
				"target_type", target.SourceType,
				"error", err)
			continue // Continue with other targets
		}

		targetSpan.AddEvent("target_processed", trace.WithAttributes(
			attribute.Int64("processing_time_ms", time.Since(start).Milliseconds()),
		))
		s.metrics.ObserveTargetProcessingTime(ctx, time.Since(start))
		s.metrics.IncTargetsProcessed(ctx)
	}

	span.SetStatus(codes.Ok, "fresh enumeration completed")
	return nil
}

// marshalConfig serializes the target configuration into a JSON raw message.
// This allows storing the complete target configuration with the enumeration state.
func (s *coordinator) marshalConfig(
	ctx context.Context,
	target config.TargetSpec,
	auth map[string]config.AuthConfig,
) json.RawMessage {
	ctx, span := s.tracer.Start(ctx, "enumeration.marshalConfig")
	defer span.End()

	span.SetAttributes(
		attribute.String("source_type", string(target.SourceType)),
		attribute.String("auth_ref", target.AuthRef),
	)

	// Combine target configuration with its authentication details into a single config.
	// This combined config is necessary for two reasons:
	// 1. The target type is needed when creating an enumerator
	// 2. The auth config must be preserved for session resumption since the original
	//    auth configuration map is not available during resume operations
	completeConfig := struct {
		config.TargetSpec
		Auth config.AuthConfig `json:"auth,omitempty"`
	}{
		TargetSpec: target,
	}

	// Include auth config if there's an auth reference.
	if auth, ok := auth[target.AuthRef]; ok {
		completeConfig.Auth = auth
	}

	data, err := json.Marshal(completeConfig)
	if err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Failed to marshal target config", "error", err)
		return nil
	}
	return data
}

// resumeEnumerations attempts to continue enumeration from previously saved states.
// This allows recovery from interruptions and supports incremental scanning.
func (s *coordinator) resumeEnumerations(ctx context.Context, states []*enumeration.SessionState) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.resumeEnumerations")
	defer span.End()

	span.SetAttributes(attribute.Int("state_count", len(states)))
	span.AddEvent("starting_enumeration_resume")

	for _, st := range states {
		stateCtx, stateSpan := s.tracer.Start(ctx, "enumeration.process_state",
			trace.WithAttributes(
				attribute.String("session_id", st.SessionID()),
				attribute.String("source_type", string(st.SourceType())),
			),
		)

		var combined struct {
			config.TargetSpec
			Auth config.AuthConfig `json:"auth,omitempty"`
		}

		if err := json.Unmarshal(st.Config(), &combined); err != nil {
			stateSpan.RecordError(err)
			stateSpan.SetStatus(codes.Error, "failed to unmarshal config")
			s.logger.Error(stateCtx, "Failed to unmarshal target config",
				"session_id", st.SessionID(),
				"error", err)
			stateSpan.End()
			continue
		}

		stateSpan.AddEvent("config_unmarshaled")

		if s.credStore == nil {
			credSpan := trace.SpanFromContext(stateCtx)
			credSpan.AddEvent("initializing_credential_store")

			var err error
			s.credStore, err = memory.NewCredentialStore(map[string]config.AuthConfig{
				combined.AuthRef: combined.Auth,
			})
			if err != nil {
				credSpan.RecordError(err)
				credSpan.SetStatus(codes.Error, "failed to create credential store")
				stateSpan.End()
				return fmt.Errorf("failed to create credential store: %w", err)
			}
			credSpan.AddEvent("credential_store_initialized")
		}

		if err := s.processTargetEnumeration(stateCtx, st, combined.TargetSpec); err != nil {
			stateSpan.RecordError(err)
			stateSpan.SetStatus(codes.Error, "enumeration failed")
			s.logger.Error(stateCtx, "Resume enumeration failed",
				"session_id", st.SessionID(),
				"error", err)
			stateSpan.End()
			continue
		}

		stateSpan.SetStatus(codes.Ok, "state processed successfully")
		stateSpan.End()
	}

	span.AddEvent("enumeration_resume_completed")
	span.SetStatus(codes.Ok, "all states processed")
	return nil
}

// processTargetEnumeration handles the lifecycle of a single target's enumeration,
// including state transitions, enumerator creation, and streaming of results.
func (s *coordinator) processTargetEnumeration(
	ctx context.Context,
	state *enumeration.SessionState,
	target config.TargetSpec,
) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.processTarget")
	defer span.End()

	span.SetAttributes(
		attribute.String("source_type", string(target.SourceType)),
		attribute.String("session_id", state.SessionID()),
	)

	if err := s.stateRepo.Save(ctx, state); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to save initial state")
		return fmt.Errorf("failed to save initial state: %w", err)
	}
	span.AddEvent("initial_state_saved")

	if err := state.MarkInProgress(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to mark in progress")
		s.logger.Error(ctx, "Failed to mark enumeration as in-progress", "error", err)
		return err
	}
	span.AddEvent("state_marked_in_progress")

	if err := s.stateRepo.Save(ctx, state); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to save state transition")
		s.logger.Error(ctx, "Failed to save state transition", "error", err)
		return err
	}
	span.AddEvent("state_transition_saved")

	creds, err := s.credStore.GetCredentials(target.AuthRef)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to get credentials")
		return fmt.Errorf("failed to get credentials: %w", err)
	}
	span.AddEvent("credentials_retrieved")

	enumerator, err := s.enumFactory.CreateEnumerator(target, creds)
	if err != nil {
		span.AddEvent("marking_enumeration_failed", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
		if markErr := state.MarkFailed(err.Error()); markErr != nil {
			span.RecordError(markErr)
			s.logger.Error(ctx, "Failed to mark enumeration as failed", "error", markErr)
		}

		if saveErr := s.stateRepo.Save(ctx, state); saveErr != nil {
			span.RecordError(saveErr)
			s.logger.Error(ctx, "Failed to save failed state", "error", saveErr)
		}
		span.AddEvent("failed_state_saved")
		span.SetStatus(codes.Error, "failed to create enumerator")
		return fmt.Errorf("failed to create enumerator: %w", err)
	}
	span.AddEvent("enumerator_created")

	// TODO: This needs to be removed and places within the given enumerator.
	// "endCursor" is specific to the github enumerator and should not be used explicitly
	// by the coordinator.
	var resumeCursor *string
	if state.LastCheckpoint() != nil {
		if c, ok := state.LastCheckpoint().Data()["endCursor"].(string); ok {
			resumeCursor = &c
			span.AddEvent("resuming_from_checkpoint", trace.WithAttributes(
				attribute.String("cursor", c),
			))
		}
	}

	if err := s.streamEnumerate(ctx, enumerator, state, resumeCursor, creds); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "enumeration stream failed")
		s.logger.Error(ctx, "Enumeration failed",
			"session_id", state.SessionID(),
			"error", err)
		return err
	}
	span.AddEvent("enumeration_stream_completed")

	span.SetStatus(codes.Ok, "enumeration completed successfully")
	return nil
}

// streamEnumerate processes a target enumeration by streaming batches of tasks from the enumerator.
// It handles checkpointing progress and publishing tasks while managing the enumeration lifecycle.
// This enables efficient processing of large datasets by avoiding loading everything into memory.
func (s *coordinator) streamEnumerate(
	ctx context.Context,
	enumerator TargetEnumerator,
	state *enumeration.SessionState,
	startCursor *string,
	creds *enumeration.TaskCredentials,
) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.streamEnumerate")
	defer span.End()

	span.SetAttributes(
		attribute.String("session_id", state.SessionID()),
		attribute.String("source_type", state.SourceType()),
	)

	batchCh := make(chan EnumerateBatch, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	// Process batches asynchronously to avoid blocking the enumerator.
	go func() {
		defer wg.Done()
		for batch := range batchCh {
			batchCtx, batchSpan := s.tracer.Start(ctx, "enumeration.processBatch")
			batchSpan.SetAttributes(
				attribute.String("session_id", state.SessionID()),
				attribute.Int("batch_size", len(batch.Targets)),
				attribute.String("next_cursor", batch.NextCursor),
			)
			batchSpan.AddEvent("Starting batch processing")

			var checkpoint *enumeration.Checkpoint
			if batch.NextCursor != "" {
				checkpoint = enumeration.NewTemporaryCheckpoint(
					state.SessionID(),
					map[string]any{"endCursor": batch.NextCursor},
				)
				batchSpan.AddEvent("Created checkpoint")
			} else {
				checkpoint = enumeration.NewTemporaryCheckpoint(state.SessionID(), nil)
				batchSpan.AddEvent("Created empty checkpoint")
			}

			var batchProgress enumeration.BatchProgress

			// TODO: Handle partial failures once |publishTasks| can handle them.
			if err := s.publishTasks(batchCtx, batch.Targets, state.SessionID(), creds); err != nil {
				batchSpan.RecordError(err)
				batchProgress = enumeration.NewFailedBatchProgress(err, checkpoint)
				batchSpan.AddEvent("Failed to publish tasks", trace.WithAttributes(
					attribute.String("error", err.Error()),
					attribute.Int("failed_targets", len(batch.Targets)),
				))
			} else {
				batchProgress = enumeration.NewSuccessfulBatchProgress(len(batch.Targets), checkpoint)
				batchSpan.AddEvent("Successfully published batch")
			}

			if err := state.RecordBatchProgress(batchProgress); err != nil {
				batchSpan.RecordError(err)
				batchSpan.AddEvent("Failed to update progress", trace.WithAttributes(
					attribute.String("error", err.Error()),
					attribute.String("batch_status", string(batchProgress.Status())),
				))
				batchSpan.End()
				return
			}

			if err := s.stateRepo.Save(batchCtx, state); err != nil {
				batchSpan.RecordError(err)
				batchSpan.AddEvent("Failed to save state", trace.WithAttributes(
					attribute.String("error", err.Error()),
				))
			}
			batchSpan.End()
		}
	}()

	err := enumerator.Enumerate(ctx, startCursor, batchCh)
	close(batchCh)
	wg.Wait()

	if err != nil {
		span.RecordError(err)
		if err := state.MarkFailed(err.Error()); err != nil {
			span.RecordError(err)
			s.logger.Error(ctx, "Failed to mark enumeration as failed", "error", err)
		}
		if err := s.stateRepo.Save(ctx, state); err != nil {
			span.RecordError(err)
			s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
		}
		return err
	}

	span.AddEvent("Enumeration completed")

	if err := state.MarkCompleted(); err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Failed to mark enumeration as completed", "error", err)
	}

	if err := s.stateRepo.Save(ctx, state); err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
	}
	return nil
}

// publishTasks publishes task creation events for a batch of enumerated tasks.
// It ensures tasks are durably recorded and can be processed by downstream consumers.
// The session ID is used for correlation and tracking task lineage.
// TODO: Handle partial failures.
func (s *coordinator) publishTasks(
	ctx context.Context,
	targets []*TargetInfo,
	sessionID string,
	creds *enumeration.TaskCredentials,
) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.publishTasks")
	defer span.End()

	span.SetAttributes(
		attribute.String("session_id", sessionID),
		attribute.Int("num_targets", len(targets)),
	)
	span.AddEvent("Starting task publication")

	var totalTasks int
	for _, t := range targets {
		taskCtx, taskSpan := s.tracer.Start(ctx, "enumeration.processTarget")
		taskSpan.SetAttributes(
			attribute.String("resource_uri", t.ResourceURI),
			attribute.String("source_type", t.SourceType),
		)

		task := enumeration.NewTask(
			shared.SourceType(t.SourceType),
			sessionID,
			t.ResourceURI,
			t.Metadata,
			creds,
		)
		taskSpan.AddEvent("Created task", trace.WithAttributes(
			attribute.String("task_id", task.TaskID),
		))

		err := s.eventPublisher.PublishDomainEvent(
			taskCtx,
			enumeration.NewTaskCreatedEvent(task),
			events.WithKey(sessionID),
		)
		if err != nil {
			taskSpan.RecordError(err)
			taskSpan.AddEvent("Failed to publish task event", trace.WithAttributes(
				attribute.String("error", err.Error()),
			))
			s.metrics.IncTasksFailedToEnqueue(ctx)
			taskSpan.End()
			return err
		}
		taskSpan.AddEvent("Published task event")
		totalTasks++

		s.metrics.IncTasksEnqueued(ctx)

		if err := s.taskRepo.Save(taskCtx, task); err != nil {
			taskSpan.RecordError(err)
			taskSpan.AddEvent("Failed to save task", trace.WithAttributes(
				attribute.String("error", err.Error()),
			))
			taskSpan.End()
			return err
		}
		taskSpan.AddEvent("Successfully saved task")
		taskSpan.End()
	}

	span.SetAttributes(attribute.Int("total_tasks_published", totalTasks))
	span.AddEvent("Completed task publication")

	return nil
}

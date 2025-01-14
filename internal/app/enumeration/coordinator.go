package enumeration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/enumeration/github"
	enumeration "github.com/ahrav/gitleaks-armada/internal/app/enumeration/shared"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials/memory"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// ScanTargetCallback is a callback interface for notifying listeners of scan targets discovered.
type ScanTargetCallback interface {
	OnScanTargetsDiscovered(ctx context.Context, targetIDs []uuid.UUID)
}

// Coordinator defines the core domain operations for target enumeration.
type Coordinator interface {
	// EnumerateTarget handles enumeration for a single target.
	// It creates a new state record and initializes the enumeration process.
	// The callback is invoked when scan targets are discovered during enumeration.
	EnumerateTarget(ctx context.Context, target config.TargetSpec, auth map[string]config.AuthConfig, cb ScanTargetCallback) error

	// ResumeTarget continues enumeration for a previously interrupted session.
	// It picks up from the last checkpoint for the provided session state.
	ResumeTarget(ctx context.Context, state *domain.SessionState, cb ScanTargetCallback) error
}

// metrics defines the interface for tracking enumeration-related metrics.
type metrics interface {
	ObserveTargetProcessingTime(ctx context.Context, duration time.Duration)
	IncTargetsProcessed(ctx context.Context)
	TrackEnumeration(ctx context.Context, fn func() error) error
	IncEnumerationTasksEnqueued(ctx context.Context)
	IncEnumerationTasksFailedToEnqueue(ctx context.Context)
}

// Orchestrator implements target enumeration by orchestrating domain logic, repository calls,
// and event publishing. It manages the lifecycle of enumeration sessions and coordinates
// the overall enumeration process.
type coordinator struct {
	// Domain repositories.
	scanTargetRepo domain.ScanTargetRepository
	githubRepo     domain.GithubRepository
	batchRepo      domain.BatchRepository
	stateRepo      domain.StateRepository
	checkpointRepo domain.CheckpointRepository
	taskRepo       domain.TaskRepository

	// Persistence handlers for different resource types.
	enumeratorHandlers map[shared.TargetType]enumeration.ResourcePersister

	// targetCollector manages the collection and notification of discovered scan targets
	// during enumeration. It provides thread-safe operations for aggregating target IDs
	// and notifying downstream consumers via callbacks when new targets are found.
	targetCollector *targetEnumerationResults

	// Creates enumerators for different target types.
	enumFactory EnumeratorFactory
	credStore   credentials.Store

	// External dependencies.
	eventPublisher events.DomainEventPublisher

	logger  *logger.Logger
	metrics metrics
	tracer  trace.Tracer
}

// NewCoordinator creates a new Service that coordinates target enumeration.
// It wires together all required dependencies including repositories, domain services,
// and external integrations needed for the enumeration workflow.
func NewCoordinator(
	scanTargetRepo domain.ScanTargetRepository,
	githubRepo domain.GithubRepository,
	batchRepo domain.BatchRepository,
	stateRepo domain.StateRepository,
	checkpointRepo domain.CheckpointRepository,
	taskRepo domain.TaskRepository,
	enumFactory EnumeratorFactory,
	eventPublisher events.DomainEventPublisher,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) Coordinator {
	return &coordinator{
		scanTargetRepo: scanTargetRepo,
		githubRepo:     githubRepo,
		batchRepo:      batchRepo,
		stateRepo:      stateRepo,
		checkpointRepo: checkpointRepo,
		taskRepo:       taskRepo,
		enumeratorHandlers: map[shared.TargetType]enumeration.ResourcePersister{
			shared.TargetTypeGitHubRepo: github.NewRepoPersistence(githubRepo, logger, tracer),
		},
		enumFactory:    enumFactory,
		eventPublisher: eventPublisher,
		logger:         logger,
		metrics:        metrics,
		tracer:         tracer,
	}
}

// EnumerateTarget begins new enumeration sessions for a single target.
// It creates a new state record and initializes the enumeration process.
// Returns an error if the enumeration session cannot be started.
func (s *coordinator) EnumerateTarget(
	ctx context.Context,
	target config.TargetSpec,
	auth map[string]config.AuthConfig,
	cb ScanTargetCallback,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.enumerate_target",
		trace.WithAttributes(
			attribute.String("component", "coordinator"),
			attribute.String("operation", "enumerate_target"),
		))
	defer span.End()

	s.targetCollector = newEnumerationResults(cb)

	var err error
	s.credStore, err = memory.NewCredentialStore(auth)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create credential store")
		return fmt.Errorf("failed to create credential store: %w", err)
	}
	span.AddEvent("credential_store_initialized")

	span.SetAttributes(
		attribute.Int("auth_config_count", len(auth)),
	)

	targetSpan := trace.SpanFromContext(ctx)
	targetSpan.AddEvent("processing_target", trace.WithAttributes(
		attribute.String("target_name", target.Name),
		attribute.String("target_type", string(target.SourceType)),
		attribute.String("auth_ref", target.AuthRef),
	))

	start := time.Now()
	state := domain.NewState(string(target.SourceType), s.marshalConfig(ctx, target, auth))

	if err := s.processTargetEnumeration(ctx, state, target); err != nil {
		targetSpan.RecordError(err)
		targetSpan.SetStatus(codes.Error, "target enumeration failed")
		s.logger.Error(ctx, "Target enumeration failed",
			"target_type", target.SourceType,
			"error", err)
		return err
	}

	targetSpan.AddEvent("target_processed", trace.WithAttributes(
		attribute.Int64("processing_time_ms", time.Since(start).Milliseconds()),
	))
	s.metrics.ObserveTargetProcessingTime(ctx, time.Since(start))
	s.metrics.IncTargetsProcessed(ctx)

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
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.marshal_config",
		trace.WithAttributes(
			attribute.String("source_type", string(target.SourceType)),
			attribute.String("auth_ref", target.AuthRef),
		))
	defer span.End()

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

// ResumeTarget attempts to continue enumeration from previously saved states.
// This allows recovery from interruptions and supports incremental enumeration.
func (s *coordinator) ResumeTarget(
	ctx context.Context,
	state *domain.SessionState,
	cb ScanTargetCallback,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.resume_target",
		trace.WithAttributes(attribute.Int("state_count", 1)))
	defer span.End()

	s.targetCollector = newEnumerationResults(cb)

	span.AddEvent("starting_enumeration_resume")

	stateSpan := trace.SpanFromContext(ctx)
	stateSpan.AddEvent("processing_state", trace.WithAttributes(
		attribute.String("session_id", state.SessionID().String()),
		attribute.String("source_type", string(state.SourceType())),
	))
	defer stateSpan.End()

	var combined struct {
		config.TargetSpec
		Auth config.AuthConfig `json:"auth,omitempty"`
	}

	if err := json.Unmarshal(state.Config(), &combined); err != nil {
		stateSpan.RecordError(err)
		stateSpan.SetStatus(codes.Error, "failed to unmarshal config")
		s.logger.Error(ctx, "Failed to unmarshal target config",
			"session_id", state.SessionID(),
			"error", err)
		stateSpan.End()
		return fmt.Errorf("failed to unmarshal target config: %w", err)
	}

	if s.credStore == nil {
		credSpan := trace.SpanFromContext(ctx)

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

	if err := s.processTargetEnumeration(ctx, state, combined.TargetSpec); err != nil {
		stateSpan.RecordError(err)
		stateSpan.SetStatus(codes.Error, "enumeration failed")
		s.logger.Error(ctx, "Resume enumeration failed",
			"session_id", state.SessionID(),
			"error", err)
		stateSpan.End()
		return err
	}

	stateSpan.AddEvent("enumeration_resume_completed")
	stateSpan.SetStatus(codes.Ok, "enumeration completed successfully")

	return nil
}

// processTargetEnumeration handles the lifecycle of a single target's enumeration,
// including state transitions, enumerator creation, and streaming of results.
func (s *coordinator) processTargetEnumeration(
	ctx context.Context,
	state *domain.SessionState,
	target config.TargetSpec,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.process_target_enumeration",
		trace.WithAttributes(
			attribute.String("source_type", string(target.SourceType)),
			attribute.String("session_id", state.SessionID().String()),
		))
	defer span.End()

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
	enumerator enumeration.TargetEnumerator,
	state *domain.SessionState,
	startCursor *string,
	creds *domain.TaskCredentials,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.stream_enumerate",
		trace.WithAttributes(
			attribute.String("session_id", state.SessionID().String()),
			attribute.String("source_type", state.SourceType()),
		))
	defer span.End()

	batchCh := make(chan enumeration.EnumerateBatch, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	// Process batches asynchronously to avoid blocking the enumerator.
	go func() {
		defer wg.Done()
		for batch := range batchCh {
			batchCtx, batchSpan := s.tracer.Start(ctx, "coordinator.enumeration.process_batch",
				trace.WithAttributes(
					attribute.String("session_id", state.SessionID().String()),
					attribute.Int("batch_size", len(batch.Targets)),
					attribute.String("next_cursor", batch.NextCursor),
				))

			if err := s.processBatch(batchCtx, batch, state, creds); err != nil {
				batchSpan.RecordError(err)
				batchSpan.SetStatus(codes.Error, "failed to process batch")
				batchSpan.End()
				continue
			}

			batchSpan.AddEvent("batch_processed")
			batchSpan.SetStatus(codes.Ok, "batch processed successfully")
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
			return err
		}
		span.AddEvent("state_saved_successfully")
		return err
	}

	span.AddEvent("enumeration_completed")

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

// processBatch handles the processing of a batch of enumerated targets.
func (s *coordinator) processBatch(
	ctx context.Context,
	batch enumeration.EnumerateBatch,
	state *domain.SessionState,
	creds *domain.TaskCredentials,
) error {
	batchSpan := trace.SpanFromContext(ctx)
	defer batchSpan.End()

	batchSpan.AddEvent("starting_batch_processing")

	var checkpoint *domain.Checkpoint
	if batch.NextCursor != "" {
		checkpoint = domain.NewTemporaryCheckpoint(
			state.SessionID(),
			map[string]any{"endCursor": batch.NextCursor},
		)
	} else {
		checkpoint = domain.NewTemporaryCheckpoint(state.SessionID(), nil)
	}
	batchSpan.AddEvent("checkpoint_created", trace.WithAttributes(
		attribute.String("end_cursor", batch.NextCursor),
	))

	domainBatch := domain.NewBatch(
		state.SessionID(),
		len(batch.Targets),
		checkpoint,
	)
	batchSpan.AddEvent("batch_entity_created")

	if err := s.batchRepo.Save(ctx, domainBatch); err != nil {
		batchSpan.RecordError(err)
		batchSpan.AddEvent("failed_to_save_batch", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
		return err
	}
	batchSpan.AddEvent("batch_saved_successfully")

	var (
		scanTargetIDs  []uuid.UUID
		processedCount int
		lastError      error
	)
	for _, target := range batch.Targets {
		targetID, err := s.processTarget(ctx, target, state.SessionID(), creds)
		if err != nil {
			batchSpan.RecordError(err)
			lastError = err
			s.metrics.IncEnumerationTasksFailedToEnqueue(ctx)
			continue
		}
		if targetID != uuid.Nil {
			scanTargetIDs = append(scanTargetIDs, targetID)
		}
		processedCount++
		s.metrics.IncEnumerationTasksEnqueued(ctx)
	}

	s.targetCollector.AddTargets(ctx, scanTargetIDs)

	if lastError != nil {
		if markErr := domainBatch.MarkFailed(lastError); markErr != nil {
			batchSpan.RecordError(markErr)
		}
		batchSpan.AddEvent("batch_processing_partially_failed", trace.WithAttributes(
			attribute.Int("processed", processedCount),
			attribute.Int("total", len(batch.Targets)),
		))
	} else {
		if markErr := domainBatch.MarkSuccessful(processedCount); markErr != nil {
			batchSpan.RecordError(markErr)
		}
		batchSpan.AddEvent("batch_processing_completed_successfully")
	}

	if err := s.batchRepo.Save(ctx, domainBatch); err != nil {
		batchSpan.RecordError(err)
		return fmt.Errorf("failed to update batch progress: %w", err)
	}

	if err := state.ProcessCompletedBatch(domainBatch); err != nil {
		batchSpan.RecordError(err)
		return fmt.Errorf("failed to process completed batch: %w", err)
	}

	if err := s.stateRepo.Save(ctx, state); err != nil {
		batchSpan.RecordError(err)
		return fmt.Errorf("failed to save state: %w", err)
	}

	return lastError
}

// processTarget handles the processing of a single target and returns the created scan target ID
func (s *coordinator) processTarget(
	ctx context.Context,
	target *enumeration.TargetInfo,
	sessionID uuid.UUID,
	creds *domain.TaskCredentials,
) (uuid.UUID, error) {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.process_target",
		trace.WithAttributes(
			attribute.String("resource_uri", target.ResourceURI),
			attribute.String("target_type", target.TargetType.String()),
		))
	defer span.End()

	persister, ok := s.enumeratorHandlers[target.TargetType]
	if !ok {
		err := fmt.Errorf("no persister found for target type: %s", target.TargetType)
		span.RecordError(err)
		return uuid.Nil, err
	}

	resourceEntry := enumeration.ResourceEntry{
		ResourceType: target.TargetType,
		Name:         target.ResourceURI,
		URL:          target.ResourceURI,
	}

	span.SetAttributes(
		attribute.String("resource_entry_name", resourceEntry.Name),
		attribute.String("resource_entry_url", resourceEntry.URL),
	)

	result, err := persister.Persist(ctx, resourceEntry)
	if err != nil {
		span.RecordError(err)
		return uuid.Nil, fmt.Errorf("failed to persist resource: %w", err)
	}

	scanTargetID, err := s.createScanTarget(
		ctx,
		result.Name,
		result.TargetType,
		result.ResourceID,
		result.Metadata,
	)
	if err != nil {
		span.RecordError(err)
		return uuid.Nil, fmt.Errorf("failed to create scan target: %w", err)
	}

	if err := s.publishTask(ctx, target, sessionID, creds); err != nil {
		span.RecordError(err)
		return scanTargetID, fmt.Errorf("failed to publish task: %w", err)
	}

	span.SetStatus(codes.Ok, "Target processed successfully")
	return scanTargetID, nil
}

// createScanTarget constructs a ScanTarget domain object and returns its ID
func (s *coordinator) createScanTarget(
	ctx context.Context,
	name string,
	targetType shared.TargetType,
	targetID int64,
	metadata map[string]any,
) (uuid.UUID, error) {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.create_scan_target",
		trace.WithAttributes(
			attribute.String("name", name),
			attribute.String("target_type", string(targetType)),
			attribute.Int64("target_id", targetID),
		))
	defer span.End()

	st, err := domain.NewScanTarget(name, targetType, targetID, metadata)
	if err != nil {
		span.RecordError(err)
		return uuid.Nil, fmt.Errorf("failed to create scan target domain object: %w", err)
	}

	createdTarget, err := s.scanTargetRepo.Create(ctx, st)
	if err != nil {
		span.RecordError(err)
		return uuid.Nil, fmt.Errorf("failed to create scan target: %w", err)
	}

	span.AddEvent("scan_target_created_successfully", trace.WithAttributes(
		attribute.String("scan_target_id", createdTarget.String()),
	))

	return createdTarget, nil
}

// publishTask publishes a single task creation event and saves the task record.
// It ensures tasks are durably recorded and can be processed by downstream consumers.
// The session ID is used for correlation and tracking task lineage.
// TODO: Handle partial failures.
func (s *coordinator) publishTask(
	ctx context.Context,
	target *enumeration.TargetInfo,
	sessionID uuid.UUID,
	creds *domain.TaskCredentials,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.publish_task",
		trace.WithAttributes(
			attribute.String("resource_uri", target.ResourceURI),
			attribute.String("target_type", target.TargetType.String()),
		))
	defer span.End()

	task := domain.NewTask(
		target.TargetType.ToSourceType(),
		sessionID,
		target.ResourceURI,
		target.Metadata,
		creds,
	)

	if err := s.eventPublisher.PublishDomainEvent(
		ctx,
		domain.NewTaskCreatedEvent(task),
		events.WithKey(sessionID.String()),
	); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish task event: %w", err)
	}
	span.AddEvent("task_published_successfully")

	if err := s.taskRepo.Save(ctx, task); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to save task: %w", err)
	}
	span.AddEvent("task_saved_successfully")

	return nil
}

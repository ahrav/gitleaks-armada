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

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials/memory"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// Coordinator defines the core domain operations for target enumeration.
// It coordinates the overall enumeration process by managing enumeration state
// and supporting resumable enumeration.
type Coordinator interface {
	// StartFreshEnumerations begins new enumeration sessions for all targets defined in the config.
	// It creates new state records and initializes the enumeration process for each target.
	// Returns an error if the enumeration sessions cannot be started.
	StartFreshEnumerations(ctx context.Context, cfg *config.Config) error

	// ResumeEnumerations continues enumeration for previously interrupted sessions.
	// It picks up from the last checkpoint for each provided session state.
	// Returns an error if any session cannot be resumed.
	ResumeEnumerations(ctx context.Context, states []*enumeration.SessionState) error
}

// metrics defines the interface for tracking enumeration-related metrics.
type metrics interface {
	ObserveTargetProcessingTime(ctx context.Context, duration time.Duration)
	IncTargetsProcessed(ctx context.Context)
	TrackEnumeration(ctx context.Context, fn func() error) error
	IncTasksEnqueued(ctx context.Context)
	IncTasksFailedToEnqueue(ctx context.Context)
}

// ResourceEntry represents a discovered resource during enumeration that needs to be persisted.
// It contains the core identifying information and metadata needed to create or update
// the corresponding domain entity (e.g. GitHubRepo). The ResourceType field helps the
// coordinator route the entry to the appropriate resourcePersister implementation.
// TODO: Refactor this to be more generic and allow for different resource types.
// eg. ResourceType, Name + Metadata)
type ResourceEntry struct {
	ResourceType shared.TargetType // Type of resource (e.g. "github_repository") for routing
	Name         string            // Display name of the resource
	URL          string            // Unique URL/identifier for the resource
	Metadata     map[string]any    // Additional resource-specific metadata
}

// ResourceUpsertResult contains the outcome of persisting a ResourceEntry via a resourcePersister.
// It provides the necessary information to create a ScanTarget and generate enumeration tasks.
// The TargetType and ResourceID fields together uniquely identify the persisted domain entity
// (e.g. a GitHubRepo) that will be the subject of future scanning operations.
type ResourceUpsertResult struct {
	ResourceID int64             // Primary key of the persisted domain entity
	TargetType shared.TargetType // Domain entity type (e.g. "github_repositories")
	Name       string            // Resource name for display/logging
	Metadata   map[string]any    // Final metadata after any merging/processing
}

// EmptyResourceUpsertResult provides a zero-value result for error cases.
// This is returned when persistence fails or no changes were needed,
// allowing callers to distinguish between successful and failed operations.
var EmptyResourceUpsertResult = ResourceUpsertResult{}

// resourcePersister defines the interface for persisting discovered resources.
// Implementations (like gitHubRepoPersistence) handle the domain-specific logic
// of creating or updating the appropriate aggregate (e.g. GitHubRepo) based on
// the ResourceEntry data. This abstraction allows the coordinator to handle
// different resource types uniformly while preserving domain invariants.
type resourcePersister interface {
	persist(ctx context.Context, item ResourceEntry) (ResourceUpsertResult, error)
}

// Orchestrator implements target enumeration by orchestrating domain logic, repository calls,
// and event publishing. It manages the lifecycle of enumeration sessions and coordinates
// the overall enumeration process.
type coordinator struct {
	// Domain repositories.
	scanTargetRepo enumeration.ScanTargetRepository
	githubRepo     enumeration.GithubRepository
	batchRepo      enumeration.BatchRepository
	stateRepo      enumeration.StateRepository
	checkpointRepo enumeration.CheckpointRepository
	taskRepo       enumeration.TaskRepository

	// Persistence handlers for different resource types.
	enumeratorHandlers map[shared.TargetType]resourcePersister

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
	scanTargetRepo enumeration.ScanTargetRepository,
	githubRepo enumeration.GithubRepository,
	batchRepo enumeration.BatchRepository,
	stateRepo enumeration.StateRepository,
	checkpointRepo enumeration.CheckpointRepository,
	taskRepo enumeration.TaskRepository,
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
		enumeratorHandlers: map[shared.TargetType]resourcePersister{
			shared.TargetTypeGitHubRepo: NewGitHubRepoPersistence(githubRepo, logger, tracer),
		},
		enumFactory:    enumFactory,
		eventPublisher: eventPublisher,
		logger:         logger,
		metrics:        metrics,
		tracer:         tracer,
	}
}

// StartFreshEnumerations begins new enumeration sessions for all targets defined in the config.
// It creates new state records and initializes the enumeration process for each target.
// Returns an error if the enumeration sessions cannot be started.
func (s *coordinator) StartFreshEnumerations(ctx context.Context, cfg *config.Config) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.start_fresh_enumerations",
		trace.WithAttributes(
			attribute.String("component", "coordinator"),
			attribute.String("operation", "start_fresh_enumerations"),
		))
	defer span.End()

	var err error
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

// ResumeEnumerations attempts to continue enumeration from previously saved states.
// This allows recovery from interruptions and supports incremental enumeration.
func (s *coordinator) ResumeEnumerations(ctx context.Context, states []*enumeration.SessionState) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.resume_enumerations",
		trace.WithAttributes(attribute.Int("state_count", len(states))))
	defer span.End()

	span.AddEvent("starting_enumeration_resume")

	for _, st := range states {
		stateCtx, stateSpan := s.tracer.Start(ctx, "coordinator.enumeration.process_state",
			trace.WithAttributes(
				attribute.String("session_id", st.SessionID().String()),
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

		if s.credStore == nil {
			credSpan := trace.SpanFromContext(stateCtx)

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
	enumerator TargetEnumerator,
	state *enumeration.SessionState,
	startCursor *string,
	creds *enumeration.TaskCredentials,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.stream_enumerate",
		trace.WithAttributes(
			attribute.String("session_id", state.SessionID().String()),
			attribute.String("source_type", state.SourceType()),
		))
	defer span.End()

	batchCh := make(chan EnumerateBatch, 1)
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
		span.AddEvent("State saved successfully in repository")
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

// processBatch handles the processing of a batch of enumerated targets.
// It creates a batch entity, saves it to the repository, and processes individual targets.
func (s *coordinator) processBatch(
	ctx context.Context,
	batch EnumerateBatch,
	state *enumeration.SessionState,
	creds *enumeration.TaskCredentials,
) error {
	batchSpan := trace.SpanFromContext(ctx)
	defer batchSpan.End()

	batchSpan.AddEvent("Starting batch processing")

	var checkpoint *enumeration.Checkpoint
	if batch.NextCursor != "" {
		checkpoint = enumeration.NewTemporaryCheckpoint(
			state.SessionID(),
			map[string]any{"endCursor": batch.NextCursor},
		)
	} else {
		checkpoint = enumeration.NewTemporaryCheckpoint(state.SessionID(), nil)
	}
	batchSpan.AddEvent("Checkpoint created", trace.WithAttributes(
		attribute.String("end_cursor", batch.NextCursor),
	))

	domainBatch := enumeration.NewBatch(
		state.SessionID(),
		len(batch.Targets),
		checkpoint,
	)
	batchSpan.AddEvent("Created batch entity")

	if err := s.batchRepo.Save(ctx, domainBatch); err != nil {
		batchSpan.RecordError(err)
		batchSpan.AddEvent("Failed to save batch", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
		return err
	}
	batchSpan.AddEvent("Batch saved successfully")

	// Process each target individually
	var processedCount int
	var lastError error
	for _, target := range batch.Targets {
		if err := s.processTarget(ctx, target, state.SessionID(), creds); err != nil {
			batchSpan.RecordError(err)
			lastError = err
			s.metrics.IncTasksFailedToEnqueue(ctx)
			continue
		}
		processedCount++
		s.metrics.IncTasksEnqueued(ctx)
	}

	if lastError != nil {
		if markErr := domainBatch.MarkFailed(lastError); markErr != nil {
			batchSpan.RecordError(markErr)
		}
		batchSpan.AddEvent("Batch processing partially failed", trace.WithAttributes(
			attribute.Int("processed", processedCount),
			attribute.Int("total", len(batch.Targets)),
		))
	} else {
		if markErr := domainBatch.MarkSuccessful(processedCount); markErr != nil {
			batchSpan.RecordError(markErr)
		}
		batchSpan.AddEvent("Batch processing completed successfully")
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

// processTarget handles the processing of a single target, including persisting
// the resource, creating a scan target, and publishing the task.
func (s *coordinator) processTarget(
	ctx context.Context,
	target *TargetInfo,
	sessionID uuid.UUID,
	creds *enumeration.TaskCredentials,
) error {
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
		return err
	}

	resourceEntry := ResourceEntry{
		ResourceType: target.TargetType,
		Name:         target.ResourceURI,
		URL:          target.ResourceURI,
	}

	span.SetAttributes(
		attribute.String("resource_entry_name", resourceEntry.Name),
		attribute.String("resource_entry_url", resourceEntry.URL),
	)

	result, err := persister.persist(ctx, resourceEntry)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to persist resource: %w", err)
	}
	span.AddEvent("Resource persisted successfully")

	if err := s.createScanTarget(
		ctx,
		result.Name,
		result.TargetType,
		result.ResourceID,
		result.Metadata,
	); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create scan target: %w", err)
	}

	if err := s.publishTask(ctx, target, sessionID, creds); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish task: %w", err)
	}

	span.SetStatus(codes.Ok, "Target processed successfully")
	return nil
}

// createScanTarget constructs a ScanTarget domain object and inserts it
// into the scan_targets table. We do this after we have a resource's ID
// and target type from ResourceUpsertResult.
func (s *coordinator) createScanTarget(
	ctx context.Context,
	name string,
	targetType shared.TargetType,
	targetID int64,
	metadata map[string]any,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.create_scan_target",
		trace.WithAttributes(
			attribute.String("name", name),
			attribute.String("target_type", string(targetType)),
			attribute.Int64("target_id", targetID),
		))
	defer span.End()

	st, err := enumeration.NewScanTarget(name, targetType, targetID, metadata)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create scan target domain object: %w", err)
	}

	_, err = s.scanTargetRepo.Create(ctx, st)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to create scan target: %w", err)
	}
	span.AddEvent("Scan target created successfully", trace.WithAttributes(
		attribute.String("scan_target_id", st.ID().String()),
	))

	return nil
}

// publishTask publishes a single task creation event and saves the task record.
// It ensures tasks are durably recorded and can be processed by downstream consumers.
// The session ID is used for correlation and tracking task lineage.
// TODO: Handle partial failures.
func (s *coordinator) publishTask(
	ctx context.Context,
	target *TargetInfo,
	sessionID uuid.UUID,
	creds *enumeration.TaskCredentials,
) error {
	ctx, span := s.tracer.Start(ctx, "coordinator.enumeration.publish_task",
		trace.WithAttributes(
			attribute.String("resource_uri", target.ResourceURI),
			attribute.String("target_type", target.TargetType.String()),
		))
	defer span.End()

	task := enumeration.NewTask(
		target.TargetType.ToSourceType(),
		sessionID,
		target.ResourceURI,
		target.Metadata,
		creds,
	)

	if err := s.eventPublisher.PublishDomainEvent(
		ctx,
		enumeration.NewTaskCreatedEvent(task),
		events.WithKey(sessionID.String()),
	); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish task event: %w", err)
	}
	span.AddEvent("Task published successfully")

	if err := s.taskRepo.Save(ctx, task); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to save task: %w", err)
	}
	span.AddEvent("Task saved successfully")

	return nil
}

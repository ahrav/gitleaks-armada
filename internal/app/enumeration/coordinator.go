package enumeration

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/app/enumeration/github"
	enumeration "github.com/ahrav/gitleaks-armada/internal/app/enumeration/shared"
	"github.com/ahrav/gitleaks-armada/internal/app/enumeration/url"
	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials"
	"github.com/ahrav/gitleaks-armada/internal/config/credentials/memory"
	domain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
)

// This struct holds the channels for the outside world to consume.
type EnumerationResult struct {
	ScanTargetCh <-chan []uuid.UUID
	TaskCh       <-chan *domain.Task
	ErrCh        <-chan error
}

// Coordinator orchestrates the discovery and enumeration of scan targets across different
// source types. It manages the lifecycle of enumeration sessions to ensure reliable and
// resumable target discovery, which is critical for handling large-scale scanning operations
// that may be interrupted.
type Coordinator interface {
	// EnumerateTarget initiates target discovery for a new scanning session. It processes
	// the provided target specification and authentication configuration to discover and
	// enumerate scannable resources. The operation streams discovered targets and tasks
	// through channels to enable concurrent processing.
	//
	// Returns three channels:
	// - A channel of target IDs for discovered scannable resources
	// - A channel of enumeration tasks that need to be processed
	// - An error channel for reporting any issues during enumeration
	EnumerateTarget(
		ctx context.Context,
		target config.TargetSpec,
		auth map[string]config.AuthConfig,
	) EnumerationResult

	// ResumeTarget restarts an interrupted enumeration session from its last saved state.
	// This enables fault tolerance by allowing long-running enumerations to recover from
	// failures without losing progress. The operation continues streaming newly discovered
	// targets and tasks from the last checkpoint.
	//
	// Returns three channels:
	// - A channel of target IDs for newly discovered resources
	// - A channel of enumeration tasks that need to be processed
	// - An error channel for reporting any issues during resumption
	ResumeTarget(
		ctx context.Context,
		state *domain.SessionState,
	) EnumerationResult
}

// metrics defines the interface for tracking enumeration-related metrics.
type metrics interface {
	ObserveTargetProcessingTime(ctx context.Context, duration time.Duration)
	IncTargetsProcessed(ctx context.Context)
	TrackEnumeration(ctx context.Context, fn func() error) error
	IncEnumerationTasksEnqueued(ctx context.Context)
	IncEnumerationTasksFailedToEnqueue(ctx context.Context)
}

// Coordinator implements target enumeration by orchestrating domain logic, repository calls,
// and event publishing. It manages the lifecycle of enumeration sessions and coordinates
// the overall enumeration process.
type coordinator struct {
	// Domain repositories.
	scanTargetRepo   domain.ScanTargetRepository
	githubTargetRepo domain.GithubRepository
	urlTargetRepo    domain.URLRepository
	batchRepo        domain.BatchRepository
	stateRepo        domain.StateRepository
	checkpointRepo   domain.CheckpointRepository
	taskRepo         domain.TaskRepository

	// Persistence handlers for different resource types.
	enumeratorHandlers map[shared.TargetType]enumeration.ResourcePersister

	// Creates enumerators for different target types.
	enumFactory EnumeratorFactory
	credStore   credentials.Store

	logger  *logger.Logger
	metrics metrics
	tracer  trace.Tracer
}

// NewCoordinator creates a new Service that coordinates target enumeration.
// It wires together all required dependencies including repositories, domain services,
// and external integrations needed for the enumeration workflow.
func NewCoordinator(
	controllerID string,
	scanTargetRepo domain.ScanTargetRepository,
	githubRepo domain.GithubRepository,
	urlTargetRepo domain.URLRepository,
	batchRepo domain.BatchRepository,
	stateRepo domain.StateRepository,
	checkpointRepo domain.CheckpointRepository,
	taskRepo domain.TaskRepository,
	enumFactory EnumeratorFactory,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) Coordinator {
	logger = logger.With(
		"component", "enumeration_coordinator",
		"controller_id", controllerID,
	)
	return &coordinator{
		scanTargetRepo:   scanTargetRepo,
		githubTargetRepo: githubRepo,
		urlTargetRepo:    urlTargetRepo,
		batchRepo:        batchRepo,
		stateRepo:        stateRepo,
		checkpointRepo:   checkpointRepo,
		taskRepo:         taskRepo,
		enumeratorHandlers: map[shared.TargetType]enumeration.ResourcePersister{
			shared.TargetTypeGitHubRepo: github.NewRepoPersistence(githubRepo, tracer),
			shared.TargetTypeURL:        url.NewURLPersistence(urlTargetRepo, tracer),
		},
		enumFactory: enumFactory,
		logger:      logger,
		metrics:     metrics,
		tracer:      tracer,
	}
}

// Internal struct so we can close the writable channels inside the goroutine.
type enumerationPipes struct {
	scanTargetWriter chan []uuid.UUID
	taskWriter       chan *domain.Task
	errorWriter      chan error
}

// Helper that allocates our channels and returns both read and write references.
func newEnumerationPipes(taskBuffer int) (EnumerationResult, enumerationPipes) {
	scanTargets := make(chan []uuid.UUID, 1)
	tasks := make(chan *domain.Task, taskBuffer)
	errs := make(chan error, 1)

	return EnumerationResult{
			ScanTargetCh: scanTargets,
			TaskCh:       tasks,
			ErrCh:        errs,
		}, enumerationPipes{
			scanTargetWriter: scanTargets,
			taskWriter:       tasks,
			errorWriter:      errs,
		}
}

func (s *coordinator) startSpan(
	ctx context.Context,
	spanName string,
	extraAttrs ...attribute.KeyValue,
) (context.Context, trace.Span) {
	baseAttrs := []attribute.KeyValue{
		attribute.String("component", "coordinator"),
	}
	baseAttrs = append(baseAttrs, extraAttrs...)
	return s.tracer.Start(ctx, spanName, trace.WithAttributes(baseAttrs...))
}

// Central error-handling helper.
func (s *coordinator) failEnumeration(
	ctx context.Context,
	span trace.Span,
	errCh chan<- error,
	userMsg string,
	err error,
) {
	span.RecordError(err)
	span.SetStatus(codes.Error, userMsg)
	s.logger.Info(ctx, userMsg, "error", err)
	errCh <- fmt.Errorf("%s: %w", userMsg, err)
}

// EnumerateTarget begins a new enumeration session for the given target.
// Instead of returning error or using a callback, we return 3 channels:
//  1. scanTargetCh for discovered/persisted target IDs
//  2. taskCh for newly created tasks
//  3. errCh for fatal errors
func (s *coordinator) EnumerateTarget(
	ctx context.Context,
	target config.TargetSpec,
	auth map[string]config.AuthConfig,
) EnumerationResult {
	numCPU := runtime.NumCPU()

	res, pipes := newEnumerationPipes(numCPU)

	go func() {
		defer close(pipes.scanTargetWriter)
		defer close(pipes.taskWriter)
		defer close(pipes.errorWriter)

		ctx, span := s.startSpan(ctx, "coordinator.enumeration.enumerate_target",
			attribute.String("operation", "enumerate_target"),
			attribute.String("target_name", target.Name),
			attribute.String("target_type", string(target.SourceType)),
			attribute.String("auth_ref", target.AuthRef),
		)
		defer span.End()

		start := time.Now()

		credStore, err := memory.NewCredentialStore(auth)
		if err != nil {
			s.failEnumeration(ctx, span, pipes.errorWriter, "failed to create credential store", err)
			return
		}
		s.credStore = credStore
		span.AddEvent("credential_store_initialized")

		state := domain.NewState(string(target.SourceType), s.marshalConfig(ctx, target, auth))

		if err := s.processTargetEnumeration(ctx, state, target, pipes.scanTargetWriter, pipes.taskWriter); err != nil {
			s.failEnumeration(ctx, span, pipes.errorWriter, "failed to process target enumeration", err)
			return
		}

		duration := time.Since(start)
		s.metrics.ObserveTargetProcessingTime(ctx, duration)
		s.metrics.IncTargetsProcessed(ctx)

		span.AddEvent("target_processed", trace.WithAttributes(
			attribute.Int64("processing_time_ms", duration.Milliseconds()),
		))
		span.SetStatus(codes.Ok, "fresh enumeration completed")
	}()

	return res
}

// ResumeTarget continues enumeration for a previously interrupted session.
// Similar to EnumerateTarget, but we reconstruct the credential store from the saved state.
func (s *coordinator) ResumeTarget(
	ctx context.Context,
	savedState *domain.SessionState,
) EnumerationResult {
	res, pipes := newEnumerationPipes(20)

	go func() {
		defer close(pipes.scanTargetWriter)
		defer close(pipes.taskWriter)
		defer close(pipes.errorWriter)

		ctx, span := s.startSpan(ctx, "coordinator.enumeration.resume_target",
			attribute.String("session_id", savedState.SessionID().String()),
			attribute.String("source_type", savedState.SourceType()),
		)
		defer span.End()

		span.AddEvent("starting_enumeration_resume")

		var combined struct {
			config.TargetSpec
			Auth config.AuthConfig `json:"auth,omitempty"`
		}
		if err := json.Unmarshal(savedState.Config(), &combined); err != nil {
			s.failEnumeration(ctx, span, pipes.errorWriter, "failed to unmarshal config", err)
			return
		}

		if s.credStore == nil {
			cStore, err := memory.NewCredentialStore(map[string]config.AuthConfig{
				combined.AuthRef: combined.Auth,
			})
			if err != nil {
				s.failEnumeration(ctx, span, pipes.errorWriter, "failed to create credential store", err)
				return
			}
			s.credStore = cStore
			span.AddEvent("credential_store_initialized")
		}

		// Reuse the savedState for enumeration.
		if err := s.processTargetEnumeration(ctx, savedState, combined.TargetSpec, pipes.scanTargetWriter, pipes.taskWriter); err != nil {
			s.failEnumeration(ctx, span, pipes.errorWriter, "failed to process target enumeration", err)
			return
		}

		span.AddEvent("enumeration_resume_completed")
		span.SetStatus(codes.Ok, "enumeration completed successfully")
	}()

	return res
}

// processTargetEnumeration encapsulates your existing enumeration logic, including
// enumerator creation, state transitions, batch processing, etc. We now accept
// the two writer channels so we can push discovered data out.
func (s *coordinator) processTargetEnumeration(
	ctx context.Context,
	state *domain.SessionState,
	target config.TargetSpec,
	scanTargetWriter chan<- []uuid.UUID,
	taskWriter chan<- *domain.Task,
) error {
	logger := s.logger.With(
		"operation", "process_target_enumeration",
		"source_type", string(target.SourceType),
		"session_id", state.SessionID().String(),
	)
	ctx, span := s.startSpan(ctx, "coordinator.enumeration.process_target_enumeration",
		attribute.String("source_type", string(target.SourceType)),
		attribute.String("session_id", state.SessionID().String()),
	)
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
		logger.Error(ctx, "Failed to mark enumeration as in-progress", "error", err)
		return err
	}
	span.AddEvent("state_marked_in_progress")

	if err := s.stateRepo.Save(ctx, state); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to save state transition")
		logger.Error(ctx, "Failed to save state transition", "error", err)
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

	enumerator, err := s.enumFactory.CreateEnumerator(ctx, target, creds)
	if err != nil {
		span.AddEvent("marking_enumeration_failed", trace.WithAttributes(
			attribute.String("error", err.Error()),
		))
		if markErr := state.MarkFailed(err.Error()); markErr != nil {
			span.RecordError(markErr)
			logger.Error(ctx, "Failed to mark enumeration as failed", "error", markErr)
		}
		if saveErr := s.stateRepo.Save(ctx, state); saveErr != nil {
			span.RecordError(saveErr)
			logger.Error(ctx, "Failed to save failed state", "error", saveErr)
		}
		span.AddEvent("failed_state_saved")
		span.SetStatus(codes.Error, "failed to create enumerator")
		return fmt.Errorf("failed to create enumerator: %w", err)
	}
	span.AddEvent("enumerator_created")

	var resumeCursor *string
	if state.LastCheckpoint() != nil {
		if c, ok := state.LastCheckpoint().Data()["endCursor"].(string); ok {
			resumeCursor = &c
			span.AddEvent("resuming_from_checkpoint", trace.WithAttributes(
				attribute.String("cursor", c),
			))
		}
	}

	if err := s.streamEnumerate(ctx, enumerator, state, resumeCursor, creds, scanTargetWriter, taskWriter); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "enumeration stream failed")
		logger.Error(ctx, "Enumeration failed", "error", err)
		return err
	}
	span.AddEvent("enumeration_stream_completed")

	if err := state.MarkCompleted(); err != nil {
		span.RecordError(err)
		logger.Error(ctx, "Failed to mark enumeration as completed", "error", err)
	}
	if err := s.stateRepo.Save(ctx, state); err != nil {
		span.RecordError(err)
		logger.Error(ctx, "Failed to save enumeration state", "error", err)
		return err
	}
	logger.Info(ctx, "Enumeration completed successfully")
	span.SetStatus(codes.Ok, "enumeration completed successfully")

	return nil
}

// streamEnumerate manages reading batches from the enumerator. Instead of publishing tasks
// directly, it writes them to `taskWriter`.
func (s *coordinator) streamEnumerate(
	ctx context.Context,
	enumerator enumeration.TargetEnumerator,
	state *domain.SessionState,
	startCursor *string,
	creds *domain.TaskCredentials,
	scanTargetWriter chan<- []uuid.UUID,
	taskWriter chan<- *domain.Task,
) error {
	logger := s.logger.With(
		"operation", "stream_enumerate",
		"session_id", state.SessionID().String(),
		"source_type", state.SourceType(),
	)
	ctx, span := s.startSpan(ctx, "coordinator.enumeration.stream_enumerate",
		attribute.String("session_id", state.SessionID().String()),
		attribute.String("source_type", state.SourceType()),
	)
	defer span.End()

	batchCh := make(chan enumeration.EnumerateBatch, 1)
	var wg sync.WaitGroup
	wg.Add(1)

	// Process batches asynchronously.
	go func() {
		defer wg.Done()
		for batch := range batchCh {
			batchCtx, batchSpan := s.startSpan(ctx, "coordinator.enumeration.process_batch",
				attribute.String("session_id", state.SessionID().String()),
				attribute.Int("batch_size", len(batch.Targets)),
				attribute.String("next_cursor", batch.NextCursor),
			)

			if err := s.processBatch(batchCtx, batch, state, creds, scanTargetWriter, taskWriter); err != nil {
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
		if markErr := state.MarkFailed(err.Error()); markErr != nil {
			span.RecordError(markErr)
			logger.Error(ctx, "Failed to mark enumeration as failed", "error", markErr)
		}
		if saveErr := s.stateRepo.Save(ctx, state); saveErr != nil {
			span.RecordError(saveErr)
			logger.Error(ctx, "Failed to save enumeration state", "error", saveErr)
			return err
		}
		span.AddEvent("state_saved_successfully")
		return err
	}
	logger.Info(ctx, "Enumeration completed successfully")
	span.AddEvent("enumeration_completed")

	return nil
}

// processBatch handles the processing of a batch of enumerated targets.
// Instead of publishing tasks, we create them and write them into the `taskWriter` channel.
func (s *coordinator) processBatch(
	ctx context.Context,
	batch enumeration.EnumerateBatch,
	state *domain.SessionState,
	creds *domain.TaskCredentials,
	scanTargetWriter chan<- []uuid.UUID,
	taskWriter chan<- *domain.Task,
) error {
	ctx, batchSpan := s.startSpan(ctx, "coordinator.enumeration.process_batch",
		attribute.String("session_id", state.SessionID().String()),
		attribute.Int("batch_size", len(batch.Targets)),
		attribute.String("next_cursor", batch.NextCursor),
	)
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
		// scanTargetIDs are collected in a slice so that when they are consumed
		// by the orchestrator they can be batched together.
		scanTargetIDs  []uuid.UUID
		processedCount int
		lastError      error
	)
	for _, target := range batch.Targets {
		targetID, err := s.processTarget(ctx, target)
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

		task := domain.NewTask(
			target.TargetType.ToSourceType(),
			state.SessionID(),
			target.ResourceURI,
			target.Metadata,
			creds,
		)

		// TODO: This likely needs some sort of retry on failure.
		// Otherwise, we'll be in a weird inconsistent state where the task
		// is created but not saved.
		// Consider using an outbox pattern to ensure tasks are saved. (might be overkill)
		if err := s.taskRepo.Save(ctx, task); err != nil {
			batchSpan.RecordError(err)
			batchSpan.SetStatus(codes.Error, "failed to save task")
			return fmt.Errorf("failed to save task: %w", err)
		}
		taskWriter <- task
		batchSpan.AddEvent("task_saved_successfully")
	}

	scanTargetWriter <- scanTargetIDs

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

// processTarget handles the creation of a single "scan target" record in the DB.
// We do NOT publish tasks here. Instead, we return the scan target ID so the
// caller can push it onto the scanTargetWriter channel later.
func (s *coordinator) processTarget(ctx context.Context, target *enumeration.TargetInfo) (uuid.UUID, error) {
	ctx, span := s.startSpan(ctx, "coordinator.enumeration.process_target",
		attribute.String("resource_uri", target.ResourceURI),
		attribute.String("resource_uri", target.ResourceURI),
		attribute.String("target_type", target.TargetType.String()),
	)
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

	// We only return the newly created scanTargetID. The caller processes tasks separately.
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
	ctx, span := s.startSpan(ctx, "coordinator.enumeration.create_scan_target",
		attribute.String("name", name),
		attribute.String("target_type", string(targetType)),
		attribute.Int64("target_id", targetID),
	)
	defer span.End()

	st, err := domain.NewScanTarget(name, targetType, targetID, metadata)
	if err != nil {
		span.RecordError(err)
		return uuid.Nil, fmt.Errorf("failed to create scan target domain object: %w", err)
	}

	createdTargetID, err := s.scanTargetRepo.Create(ctx, st)
	if err != nil {
		span.RecordError(err)
		return uuid.Nil, fmt.Errorf("failed to create scan target: %w", err)
	}

	span.AddEvent("scan_target_created_successfully", trace.WithAttributes(
		attribute.String("scan_target_id", createdTargetID.String()),
	))

	return createdTargetID, nil
}

// marshalConfig is your existing helper that serializes the target & auth config.
// We keep all tracing code here as well.
func (s *coordinator) marshalConfig(
	ctx context.Context,
	target config.TargetSpec,
	auth map[string]config.AuthConfig,
) json.RawMessage {
	logger := s.logger.With(
		"operation", "marshal_config",
		"target_type", string(target.SourceType),
	)
	span := trace.SpanFromContext(ctx)
	defer span.End()

	completeConfig := struct {
		config.TargetSpec
		Auth config.AuthConfig `json:"auth,omitempty"`
	}{
		TargetSpec: target,
	}
	if authVal, ok := auth[target.AuthRef]; ok {
		completeConfig.Auth = authVal
	}

	data, err := json.Marshal(completeConfig)
	if err != nil {
		span.RecordError(err)
		logger.Error(ctx, "Failed to marshal target config", "error", err)
		return nil
	}

	return data
}

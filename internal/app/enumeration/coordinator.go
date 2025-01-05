package enumeration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/task"
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
	IncConfigReloadErrors()
	IncConfigReloads()
	ObserveTargetProcessingTime(duration time.Duration)
	IncTargetsProcessed()
	TrackEnumeration(fn func() error) error
}

// Orchestrator implements target enumeration by orchestrating domain logic, repository calls,
// and event publishing. It manages the lifecycle of enumeration sessions and coordinates
// the overall scanning process.
type coordinator struct {
	// Domain repositories.
	repo           enumeration.StateRepository
	checkpointRepo enumeration.CheckpointRepository

	// Creates enumerators for different target types.
	enumFactory EnumeratorFactory

	// External dependencies.
	eventPublisher events.DomainEventPublisher
	configLoader   config.Loader

	logger  *logger.Logger
	metrics metrics
	tracer  trace.Tracer
}

// NewCoordinator creates a new Service that coordinates target enumeration.
// It wires together all required dependencies including repositories, domain services,
// and external integrations needed for the enumeration workflow.
func NewCoordinator(
	repo enumeration.StateRepository,
	checkpointRepo enumeration.CheckpointRepository,
	enumFactory EnumeratorFactory,
	eventPublisher events.DomainEventPublisher,
	cfgLoader config.Loader,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) Coordinator {
	return &coordinator{
		repo:           repo,
		checkpointRepo: checkpointRepo,
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
	ctx, span := s.tracer.Start(ctx, "enumeration.ExecuteEnumeration")
	defer span.End()

	activeStates, err := s.repo.GetActiveStates(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to load active states: %w", err)
	}

	if len(activeStates) == 0 {
		// Start fresh since no active enumerations exist
		cfg, err := s.configLoader.Load(ctx)
		if err != nil {
			span.RecordError(err)
			s.metrics.IncConfigReloadErrors()
			return fmt.Errorf("failed to load config: %w", err)
		}
		s.metrics.IncConfigReloads()
		return s.startFreshEnumerations(ctx, cfg)
	}

	return s.resumeEnumerations(ctx, activeStates)
}

// startFreshEnumerations processes each target from the configuration, creating new
// enumeration states and running the appropriate enumerator for each target type.
func (s *coordinator) startFreshEnumerations(ctx context.Context, cfg *config.Config) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.startFreshEnumerations")
	defer span.End()

	span.SetAttributes(attribute.Int("target_count", len(cfg.Targets)))

	for _, target := range cfg.Targets {
		start := time.Now()
		state := enumeration.NewState(string(target.SourceType), s.marshalConfig(ctx, target, cfg.Auth))

		if err := s.processTargetEnumeration(ctx, state, target, cfg.Auth); err != nil {
			s.logger.Error(ctx, "Target enumeration failed",
				"target_type", target.SourceType,
				"error", err)
			continue // Continue with other targets
		}

		s.metrics.ObserveTargetProcessingTime(time.Since(start))
		s.metrics.IncTargetsProcessed()
	}
	return nil
}

// marshalConfig serializes the target configuration into a JSON raw message.
// This allows storing the complete target configuration with the enumeration state.
func (s *coordinator) marshalConfig(ctx context.Context, target config.TargetSpec, auth map[string]config.AuthConfig) json.RawMessage {
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

	for _, st := range states {
		var combined struct {
			config.TargetSpec
		}

		if err := json.Unmarshal(st.Config(), &combined); err != nil {
			s.logger.Error(ctx, "Failed to unmarshal target config",
				"session_id", st.SessionID(),
				"error", err)
			continue
		}

		if err := s.processTargetEnumeration(ctx, st, combined.TargetSpec, nil); err != nil {
			s.logger.Error(ctx, "Resume enumeration failed",
				"session_id", st.SessionID,
				"error", err)
			continue
		}
	}
	return nil
}

// processTargetEnumeration handles the lifecycle of a single target's enumeration,
// including state transitions, enumerator creation, and streaming of results.
func (s *coordinator) processTargetEnumeration(
	ctx context.Context,
	state *enumeration.SessionState,
	target config.TargetSpec,
	auth map[string]config.AuthConfig,
) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.processTarget")
	defer span.End()

	span.SetAttributes(
		attribute.String("source_type", string(target.SourceType)),
		attribute.String("session_id", state.SessionID()),
	)

	if err := s.repo.Save(ctx, state); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to save initial state: %w", err)
	}

	if err := state.MarkInProgress(); err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Failed to mark enumeration as in-progress", "error", err)
		return err
	}

	if err := s.repo.Save(ctx, state); err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Failed to save state transition", "error", err)
		return err
	}

	enumerator, err := s.enumFactory.CreateEnumerator(target, auth)
	if err != nil {
		if markErr := state.MarkFailed(err.Error()); markErr != nil {
			span.RecordError(markErr)
			s.logger.Error(ctx, "Failed to mark enumeration as failed", "error", markErr)
		}

		if saveErr := s.repo.Save(ctx, state); saveErr != nil {
			span.RecordError(saveErr)
			s.logger.Error(ctx, "Failed to save failed state", "error", saveErr)
		}
		return fmt.Errorf("failed to create enumerator: %w", err)
	}

	// Get resume cursor if this is a resumed enumeration.
	var resumeCursor *string
	if state.LastCheckpoint() != nil {
		if c, ok := state.LastCheckpoint().Data()["endCursor"].(string); ok {
			resumeCursor = &c
		}
	}

	if err := s.streamEnumerate(ctx, enumerator, state, resumeCursor); err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Enumeration failed",
			"session_id", state.SessionID(),
			"error", err)
		return err
	}

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
			var checkpoint *enumeration.Checkpoint
			if batch.NextCursor != "" {
				checkpoint = enumeration.NewTemporaryCheckpoint(
					state.SessionID(),
					map[string]any{"endCursor": batch.NextCursor},
				)
			}

			var batchProgress enumeration.BatchProgress

			// TODO: Handle partial failures once |publishTasks| can handle them.
			if err := s.publishTasks(ctx, batch.Tasks, state.SessionID()); err != nil {
				span.RecordError(err)
				batchProgress = enumeration.NewFailedBatchProgress(err, checkpoint)
				s.logger.Error(ctx, "Failed to publish tasks", "error", err)
			} else {
				batchProgress = enumeration.NewSuccessfulBatchProgress(len(batch.Tasks), checkpoint)
			}

			if err := state.RecordBatchProgress(batchProgress); err != nil {
				span.RecordError(err)
				s.logger.Error(ctx, "Failed to update progress", "error", err)
				return
			}

			if err := s.repo.Save(ctx, state); err != nil {
				span.RecordError(err)
				s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
			}
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
		if err := s.repo.Save(ctx, state); err != nil {
			span.RecordError(err)
			s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
		}
		return err
	}

	if err := state.MarkCompleted(); err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Failed to mark enumeration as completed", "error", err)
	}

	if err := s.repo.Save(ctx, state); err != nil {
		span.RecordError(err)
		s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
	}
	return nil
}

// publishTasks publishes task creation events for a batch of enumerated tasks.
// It ensures tasks are durably recorded and can be processed by downstream consumers.
// The session ID is used for correlation and tracking task lineage.
// TODO: Handle partial failures.
func (s *coordinator) publishTasks(ctx context.Context, tasks []task.Task, sessionID string) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.publishTasks")
	defer span.End()

	span.SetAttributes(
		attribute.String("session_id", sessionID),
		attribute.Int("num_tasks", len(tasks)),
	)

	var totalTasks int
	for _, t := range tasks {
		err := s.eventPublisher.PublishDomainEvent(
			ctx,
			task.NewTaskCreatedEvent(t),
			events.WithKey(sessionID),
		)
		if err != nil {
			span.RecordError(err)
			return err
		}
		totalTasks++
	}
	span.SetAttributes(attribute.Int("total_tasks_published", totalTasks))

	return nil
}

package enumeration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	domain "github.com/ahrav/gitleaks-armada/internal/domain/enumeration"
	"github.com/ahrav/gitleaks-armada/internal/domain/events"
	"github.com/ahrav/gitleaks-armada/internal/domain/task"
	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/config"
)

// Service defines the core domain operations for target enumeration.
// It coordinates the overall scanning process by managing enumeration state
// and supporting resumable scans.
type Service interface {
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

// enumerationApplicationServiceImpl implements EnumerationApplicationService
// by orchestrating domain logic, repository calls, event publishing, etc.
type enumerationApplicationServiceImpl struct {
	// outbound ports from the domain
	repo           domain.EnumerationStateRepository
	checkpointRepo domain.CheckpointRepository

	// enumerator factory is also a domain-level concept,
	// but we instantiate it here since it interacts with external code
	enumFactory EnumeratorFactory

	// Possibly references a domain service
	domainService domain.EnumerationDomainService

	// External stuff: eventPublisher, config loader, logger, metrics, etc.
	eventPublisher events.DomainEventPublisher
	configLoader   config.Loader
	logger         *logger.Logger
	metrics        metrics // your custom interface
	tracer         trace.Tracer
}

// NewEnumerationApplicationService constructs the application service
func NewEnumerationApplicationService(
	repo domain.EnumerationStateRepository,
	checkpointRepo domain.CheckpointRepository,
	enumFactory EnumeratorFactory,
	domainSvc domain.EnumerationDomainService,
	eventPublisher events.DomainEventPublisher,
	cfgLoader config.Loader,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) Service {
	return &enumerationApplicationServiceImpl{
		repo:           repo,
		checkpointRepo: checkpointRepo,
		enumFactory:    enumFactory,
		domainService:  domainSvc,
		eventPublisher: eventPublisher,
		configLoader:   cfgLoader,
		logger:         logger,
		metrics:        metrics,
		tracer:         tracer,
	}
}

func (s *enumerationApplicationServiceImpl) ExecuteEnumeration(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.ExecuteEnumeration")
	defer span.End()

	activeStates, err := s.repo.GetActiveStates(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to load active states: %w", err)
	}

	if len(activeStates) == 0 {
		// No active enumerations => start fresh from config.
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
func (s *enumerationApplicationServiceImpl) startFreshEnumerations(ctx context.Context, cfg *config.Config) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.startFreshEnumerations")
	defer span.End()

	span.SetAttributes(attribute.Int("target_count", len(cfg.Targets)))

	for _, target := range cfg.Targets {
		start := time.Now()
		sessionID := generateSessionID()
		targetCtx, targetSpan := s.tracer.Start(ctx, "enumeration.processTarget")
		targetSpan.SetAttributes(
			attribute.String("source_type", string(target.SourceType)),
			attribute.String("session_id", sessionID),
		)

		// Create initial state for tracking this enumeration.
		state := &domain.State{
			SessionID: sessionID,

			SourceType:  string(target.SourceType),
			Status:      domain.StatusInitialized,
			LastUpdated: time.Now(),
			Config:      s.marshalConfig(ctx, target, cfg.Auth),
		}
		if err := s.repo.Save(targetCtx, state); err != nil {
			targetSpan.RecordError(err)
			return fmt.Errorf("failed to save new enumeration state: %w", err)
		}
		// Mark in-progress.
		s.domainService.MarkInProgress(state)
		_ = s.repo.Save(targetCtx, state)

		// Build enumerator.
		enumerator, err := s.enumFactory.CreateEnumerator(target, cfg.Auth)
		if err != nil {
			s.domainService.MarkFailed(state, err.Error())
			targetSpan.RecordError(err)
			if err := s.repo.Save(targetCtx, state); err != nil {
				targetSpan.RecordError(err)
				s.logger.Error(targetCtx, "Failed to save enumeration state", "error", err)
			}
			continue
		}

		if err := s.runEnumerator(targetCtx, state, enumerator); err != nil {
			targetSpan.RecordError(err)
			s.logger.Error(targetCtx, "Enumeration failed", "session_id", state.SessionID, "error", err)
		}

		targetSpan.End()
		s.metrics.ObserveTargetProcessingTime(time.Since(start))
		s.metrics.IncTargetsProcessed()
	}
	return nil
}

// marshalConfig serializes the target configuration into a JSON raw message.
// This allows storing the complete target configuration with the enumeration state.
func (s *enumerationApplicationServiceImpl) marshalConfig(ctx context.Context, target config.TargetSpec, auth map[string]config.AuthConfig) json.RawMessage {
	// Add tracing for config marshaling
	ctx, span := s.tracer.Start(ctx, "enumeration.marshalConfig")
	defer span.End()

	span.SetAttributes(
		attribute.String("source_type", string(target.SourceType)),
		attribute.String("auth_ref", target.AuthRef),
	)

	// Create a complete config that includes both target and its auth.
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
func (s *enumerationApplicationServiceImpl) resumeEnumerations(ctx context.Context, states []*domain.State) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.resumeEnumerations")
	defer span.End()

	span.SetAttributes(attribute.Int("state_count", len(states)))

	var overallErr error
	for _, st := range states {
		targetCtx, targetSpan := s.tracer.Start(ctx, "enumeration.processTarget")
		targetSpan.SetAttributes(
			attribute.String("session_id", st.SessionID),
			attribute.String("source_type", st.SourceType),
		)

		// Unmarshal the combined target and auth configuration.
		var combined struct {
			config.TargetSpec
			Auth config.AuthConfig `json:"auth,omitempty"`
		}

		if err := json.Unmarshal(st.Config, &combined); err != nil {
			targetSpan.RecordError(err)
			return fmt.Errorf("failed to unmarshal target config: %w", err)
		}

		s.domainService.MarkInProgress(st)
		if err := s.repo.Save(targetCtx, st); err != nil {
			targetSpan.RecordError(err)
			s.logger.Error(targetCtx, "Failed to save enumeration state", "error", err)
		}

		enumerator, err := s.enumFactory.CreateEnumerator(combined.TargetSpec, nil)
		if err != nil {
			s.domainService.MarkFailed(st, err.Error())
			if err := s.repo.Save(targetCtx, st); err != nil {
				targetSpan.RecordError(err)
				s.logger.Error(targetCtx, "Failed to save enumeration state", "error", err)
			}
			continue
		}

		if err := s.runEnumerator(ctx, st, enumerator); err != nil {
			overallErr = err
			s.logger.Error(targetCtx, "Resume enumeration failed", "session_id", st.SessionID, "error", err)
		}
	}
	return overallErr
}

// runEnumerator executes the enumeration process for a single target, publishing
// discovered tasks to the event bus for processing.
func (s *enumerationApplicationServiceImpl) runEnumerator(ctx context.Context, st *domain.State, enumerator domain.TargetEnumerator) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.runEnumerator")
	defer span.End()

	span.SetAttributes(
		attribute.String("session_id", st.SessionID),
		attribute.String("source_type", st.SourceType),
	)

	return s.metrics.TrackEnumeration(func() error {
		taskCh := make(chan []task.Task)
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			targetCtx, span := s.tracer.Start(ctx, "enumeration.publishTasks")
			defer span.End()
			defer wg.Done()

			var totalTasks int
			for tasks := range taskCh {
				totalTasks += len(tasks)
				for _, t := range tasks {
					err := s.eventPublisher.PublishDomainEvent(
						targetCtx,
						task.NewTaskCreatedEvent(t),
						events.WithKey(st.SessionID),
					)
					if err != nil {
						span.RecordError(err)
						s.logger.Error(targetCtx, "Failed to publish tasks", "session_id", st.SessionID, "error", err)
						return
					}
				}
				span.SetAttributes(attribute.Int("num_tasks", len(tasks)))
				s.logger.Info(targetCtx, "Published batch of tasks", "session_id", st.SessionID, "num_tasks", len(tasks))
			}
			span.SetAttributes(attribute.Int("total_tasks_published", totalTasks))
		}()

		err := enumerator.Enumerate(ctx, st, taskCh)
		if err != nil {
			s.domainService.MarkFailed(st, err.Error())
			if err := s.repo.Save(ctx, st); err != nil {
				span.RecordError(err)
				s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
			}
			close(taskCh)
			wg.Wait()
			return err
		}
		s.domainService.MarkCompleted(st)
		if err := s.repo.Save(ctx, st); err != nil {
			span.RecordError(err)
			s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
		}

		close(taskCh)
		wg.Wait()
		return nil
	})
}

// generateSessionID creates a unique identifier for tracking enumeration sessions.
func generateSessionID() string { return uuid.New().String() }

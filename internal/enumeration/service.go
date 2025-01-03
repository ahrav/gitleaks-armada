// Package enumeration provides functionality for scanning and enumerating targets
// across different source types like GitHub repositories and S3 buckets.
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

// metrics defines the interface for tracking enumeration-related metrics.
type metrics interface {
	IncConfigReloadErrors()
	IncConfigReloads()
	ObserveTargetProcessingTime(duration time.Duration)
	IncTargetsProcessed()
	TrackEnumeration(fn func() error) error
}

// service implements the Service interface with dependencies for storage,
// configuration, metrics, and event publishing.
type service struct {
	store          domain.EnumerationStateStorage
	configLoader   config.Loader // used if we need to load new config
	enumFactory    domain.EnumeratorFactory
	eventPublisher events.DomainEventPublisher
	logger         *logger.Logger
	metrics        metrics
	tracer         trace.Tracer
}

// NewService creates a new Service instance with the provided dependencies.
// It requires storage for enumeration state, configuration loading, factory for creating
// enumerators, event publishing, logging, metrics collection and tracing capabilities.
func NewService(
	store domain.EnumerationStateStorage,
	configLoader config.Loader,
	enumFactory domain.EnumeratorFactory,
	eventPublisher events.DomainEventPublisher,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) domain.Service {
	return &service{
		store:          store,
		configLoader:   configLoader,
		enumFactory:    enumFactory,
		eventPublisher: eventPublisher,
		logger:         logger,
		metrics:        metrics,
		tracer:         tracer,
	}
}

func (s *service) ExecuteEnumeration(ctx context.Context) error {
	ctx, span := s.tracer.Start(ctx, "enumeration.ExecuteEnumeration")
	defer span.End()

	activeStates, err := s.store.GetActiveStates(ctx)
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
func (s *service) startFreshEnumerations(ctx context.Context, cfg *config.Config) error {
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
		state := &domain.EnumerationState{
			SessionID: sessionID,

			SourceType:  string(target.SourceType),
			Status:      domain.StatusInitialized,
			LastUpdated: time.Now(),
			Config:      s.marshalConfig(ctx, target, cfg.Auth),
		}
		if err := s.store.Save(targetCtx, state); err != nil {
			targetSpan.RecordError(err)
			return fmt.Errorf("failed to save new enumeration state: %w", err)
		}
		// Mark in-progress.
		state.UpdateStatus(domain.StatusInProgress)
		_ = s.store.Save(targetCtx, state)

		// Build enumerator.
		enumerator, err := s.enumFactory.CreateEnumerator(target, cfg.Auth)
		if err != nil {
			state.UpdateStatus(domain.StatusFailed)
			targetSpan.RecordError(err)
			if err := s.store.Save(targetCtx, state); err != nil {
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
func (s *service) marshalConfig(ctx context.Context, target config.TargetSpec, auth map[string]config.AuthConfig) json.RawMessage {
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
func (s *service) resumeEnumerations(ctx context.Context, states []*domain.EnumerationState) error {
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

		st.UpdateStatus(domain.StatusInProgress)
		if err := s.store.Save(targetCtx, st); err != nil {
			targetSpan.RecordError(err)
			s.logger.Error(targetCtx, "Failed to save enumeration state", "error", err)
		}

		enumerator, err := s.enumFactory.CreateEnumerator(combined.TargetSpec, nil)
		if err != nil {
			st.UpdateStatus(domain.StatusFailed)
			if err := s.store.Save(targetCtx, st); err != nil {
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
func (s *service) runEnumerator(ctx context.Context, st *domain.EnumerationState, enumerator domain.TargetEnumerator) error {
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
				for _, task := range tasks {
					if err := s.eventPublisher.PublishDomainEvent(
						targetCtx,
						domain.EventTypeTaskCreated,
						task,
						events.WithKey(st.SessionID),
					); err != nil {
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
			st.UpdateStatus(domain.StatusFailed)
			if err := s.store.Save(ctx, st); err != nil {
				span.RecordError(err)
				s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
			}
			close(taskCh)
			wg.Wait()
			return err
		}
		st.UpdateStatus(domain.StatusCompleted)
		if err := s.store.Save(ctx, st); err != nil {
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

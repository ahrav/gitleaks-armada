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
	"go.opentelemetry.io/otel/trace"

	"github.com/ahrav/gitleaks-armada/pkg/common/logger"
	"github.com/ahrav/gitleaks-armada/pkg/config"
	"github.com/ahrav/gitleaks-armada/pkg/domain"
)

// metrics defines the interface for tracking enumeration-related metrics.
type metrics interface {
	IncConfigReloadErrors()
	IncConfigReloads()
	ObserveTargetProcessingTime(duration time.Duration)
	IncTargetsProcessed()
	TrackEnumeration(fn func() error) error
}

// Service provides the core domain logic for target enumeration. It handles
// scanning targets, managing enumeration state, and coordinating the overall
// enumeration process. The service supports resuming partial scans and
// re-scanning targets when needed.
type Service interface {
	// ExecuteEnumeration performs target enumeration by either resuming from
	// existing states or starting fresh enumerations from configuration.
	// It returns an error if the enumeration process fails.
	ExecuteEnumeration(ctx context.Context) error
}

// service implements the Service interface with dependencies for storage,
// configuration, metrics, and event publishing.
type service struct {
	store          EnumerationStateStorage
	configLoader   config.Loader // used if we need to load new config
	enumFactory    EnumeratorFactory
	eventPublisher domain.DomainEventPublisher
	logger         *logger.Logger
	metrics        metrics
	tracer         trace.Tracer
}

// NewService creates a new Service instance with the provided dependencies.
// It requires storage for enumeration state, configuration loading, factory for creating
// enumerators, event publishing, logging, metrics collection and tracing capabilities.
func NewService(
	store EnumerationStateStorage,
	configLoader config.Loader,
	enumFactory EnumeratorFactory,
	eventPublisher domain.DomainEventPublisher,
	logger *logger.Logger,
	metrics metrics,
	tracer trace.Tracer,
) Service {
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
	// First check for any existing active states before starting fresh.
	activeStates, err := s.store.GetActiveStates(ctx)
	if err != nil {
		return fmt.Errorf("failed to load active states: %w", err)
	}
	if len(activeStates) == 0 {
		// No active enumerations => start fresh from config.
		cfg, err := s.configLoader.Load(ctx)
		if err != nil {
			s.metrics.IncConfigReloadErrors()
			return fmt.Errorf("failed to load config: %w", err)
		}
		s.metrics.IncConfigReloads()
		return s.startFreshEnumerations(ctx, cfg)
	}

	// If we have active states => resume them.
	return s.resumeEnumerations(ctx, activeStates)
}

// startFreshEnumerations processes each target from the configuration, creating new
// enumeration states and running the appropriate enumerator for each target type.
func (s *service) startFreshEnumerations(ctx context.Context, cfg *config.Config) error {
	for _, target := range cfg.Targets {
		start := time.Now()

		// Create initial state for tracking this enumeration.
		state := &EnumerationState{
			SessionID:   generateSessionID(),
			SourceType:  string(target.SourceType),
			Status:      StatusInitialized,
			LastUpdated: time.Now(),
			Config:      s.marshalConfig(ctx, target, cfg.Auth),
		}
		if err := s.store.Save(ctx, state); err != nil {
			return fmt.Errorf("failed to save new enumeration state: %w", err)
		}
		// Mark in-progress.
		state.UpdateStatus(StatusInProgress)
		_ = s.store.Save(ctx, state)

		// Build enumerator.
		enumerator, err := s.enumFactory.CreateEnumerator(target, cfg.Auth)
		if err != nil {
			state.UpdateStatus(StatusFailed)
			if err := s.store.Save(ctx, state); err != nil {
				s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
			}
			continue
		}

		if err := s.runEnumerator(ctx, state, enumerator); err != nil {
			s.logger.Error(ctx, "Enumeration failed", "session_id", state.SessionID, "error", err)
		}

		s.metrics.ObserveTargetProcessingTime(time.Since(start))
		s.metrics.IncTargetsProcessed()
	}
	return nil
}

// marshalConfig serializes the target configuration into a JSON raw message.
// This allows storing the complete target configuration with the enumeration state.
func (s *service) marshalConfig(ctx context.Context, target config.TargetSpec, auth map[string]config.AuthConfig) json.RawMessage {
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
		s.logger.Error(ctx, "Failed to marshal target config", "error", err)
		return nil
	}
	return data
}

// resumeEnumerations attempts to continue enumeration from previously saved states.
// This allows recovery from interruptions and supports incremental scanning.
func (s *service) resumeEnumerations(ctx context.Context, states []*EnumerationState) error {
	var overallErr error
	for _, st := range states {
		// Unmarshal the combined target and auth configuration.
		var combined struct {
			config.TargetSpec
			Auth config.AuthConfig `json:"auth,omitempty"`
		}

		if err := json.Unmarshal(st.Config, &combined); err != nil {
			return fmt.Errorf("failed to unmarshal target config: %w", err)
		}

		st.UpdateStatus(StatusInProgress)
		if err := s.store.Save(ctx, st); err != nil {
			s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
		}

		enumerator, err := s.enumFactory.CreateEnumerator(combined.TargetSpec, nil)
		if err != nil {
			st.UpdateStatus(StatusFailed)
			if err := s.store.Save(ctx, st); err != nil {
				s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
			}
			continue
		}

		if err := s.runEnumerator(ctx, st, enumerator); err != nil {
			overallErr = err
			s.logger.Error(ctx, "Resume enumeration failed", "session_id", st.SessionID, "error", err)
		}
	}
	return overallErr
}

// runEnumerator executes the enumeration process for a single target, publishing
// discovered tasks to the event bus for processing.
func (s *service) runEnumerator(ctx context.Context, st *EnumerationState, enumerator TargetEnumerator) error {
	return s.metrics.TrackEnumeration(func() error {
		taskCh := make(chan []domain.Task)
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			for tasks := range taskCh {
				for _, task := range tasks {
					if err := s.eventPublisher.PublishDomainEvent(
						ctx,
						domain.EventTypeTaskCreated,
						task,
						domain.WithKey(st.SessionID),
					); err != nil {
						s.logger.Error(ctx, "Failed to publish tasks", "session_id", st.SessionID, "error", err)
						return
					}
				}
				s.logger.Info(ctx, "Published batch of tasks", "session_id", st.SessionID, "num_tasks", len(tasks))
			}
		}()

		err := enumerator.Enumerate(ctx, st, taskCh)
		if err != nil {
			st.UpdateStatus(StatusFailed)
			if err := s.store.Save(ctx, st); err != nil {
				s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
			}
			close(taskCh)
			wg.Wait()
			return err
		}
		st.UpdateStatus(StatusCompleted)
		if err := s.store.Save(ctx, st); err != nil {
			s.logger.Error(ctx, "Failed to save enumeration state", "error", err)
		}

		close(taskCh)
		wg.Wait()
		return nil
	})
}

// generateSessionID creates a unique identifier for tracking enumeration sessions.
func generateSessionID() string { return uuid.New().String() }

// Package enumeration provides domain types and interfaces for target enumeration.
// It defines core abstractions for discovering and enumerating scan targets from
// different data sources (e.g. GitHub, S3). The package enables reliable, resumable
// scanning by managing enumeration state, checkpoints, and task generation.
// The enumeration process coordinates the overall scanning lifecycle by managing
// state transitions, supporting resumable operations, and generating scan tasks
// that get published to the event bus for processing.
package enumeration

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/config"
	"github.com/google/uuid"
)

// Service defines the behavior for running the enumeration process.
type Service interface {
	// StartEnumeration runs a fresh enumeration based on the provided configuration.
	StartEnumeration(ctx context.Context, cfg *config.Config) error

	// ResumeEnumeration runs enumeration for active states (if needed).
	// ResumeEnumeration(ctx context.Context, states []*SessionState) error
}

// GithubRepository defines the interface for persisting and retrieving GitHub repository aggregates.
// This abstraction isolates the domain model from storage implementation details, allowing the
// application to remain focused on business rules while enabling different storage backends.
type GithubRepository interface {
	// Create persists a new GitHubRepo aggregate and returns its generated ID.
	// The repo must be constructed via NewGitHubRepo to ensure domain invariants.
	Create(ctx context.Context, repo *GitHubRepo) (int64, error)

	// Update modifies an existing GitHubRepo in storage.
	// The repo must have already passed domain validation before being persisted.
	Update(ctx context.Context, repo *GitHubRepo) error

	// GetByID retrieves a GitHubRepo by its unique identifier.
	// Returns a fully hydrated aggregate ready for domain operations.
	GetByID(ctx context.Context, id int64) (*GitHubRepo, error)

	// GetByURL retrieves a GitHubRepo by its unique URL.
	// The URL serves as a natural business identifier for GitHub repositories.
	GetByURL(ctx context.Context, url string) (*GitHubRepo, error)

	// List returns a paginated slice of GitHubRepos ordered by creation time.
	// This supports UI display and batch processing scenarios.
	List(ctx context.Context, limit, offset int32) ([]*GitHubRepo, error)
}

// URLRepository defines the interface for persisting and retrieving URL target aggregates.
type URLRepository interface {
	// Create persists a new URLTarget aggregate and returns its generated ID.
	Create(ctx context.Context, target *URLTarget) (int64, error)

	// GetByURL retrieves a URLTarget by its unique URL.
	GetByURL(ctx context.Context, url string) (*URLTarget, error)

	// Update modifies an existing URLTarget in storage.
	Update(ctx context.Context, target *URLTarget) error
}

// ScanTargetRepository defines the interface for managing scan target persistence.
// It provides a storage-agnostic way to track what needs to be scanned, enabling
// the orchestration layer to coordinate scanning without knowledge of the underlying storage.
type ScanTargetRepository interface {
	// Create persists a new scan target.
	// The target must be constructed via NewScanTarget to ensure initial validity.
	Create(ctx context.Context, target *ScanTarget) (uuid.UUID, error)

	// Update modifies an existing scan target's metadata and timestamps.
	// This is commonly used to track scan history and target state changes.
	Update(ctx context.Context, target *ScanTarget) error

	// GetByID retrieves a scan target by its unique identifier.
	GetByID(ctx context.Context, id uuid.UUID) (*ScanTarget, error)

	// Find retrieves a scan target by its business identifiers.
	// This allows looking up targets by their logical identity rather than database ID.
	Find(ctx context.Context, targetType string, targetID int64) (*ScanTarget, error)

	// List returns a paginated collection of scan targets.
	// Pagination prevents memory pressure when dealing with large target sets.
	List(ctx context.Context, limit, offset int32) ([]*ScanTarget, error)
}

// BatchRepository provides persistent storage and retrieval of Batch entities.
// It enables tracking the progress and history of enumeration batches, which is
// essential for monitoring scan progress and supporting resumable operations.
// TODO: Refactor to split Save -> Create and Update.
type BatchRepository interface {
	// Save persists a Batch entity and its associated timeline and metrics.
	Save(ctx context.Context, batch *Batch) error

	// FindBySessionID retrieves all batches associated with a given session.
	// This allows analyzing the complete history of an enumeration session.
	FindBySessionID(ctx context.Context, sessionID uuid.UUID) ([]*Batch, error)

	// FindLastBySessionID retrieves the most recent batch for a session.
	// This is used to determine the current progress of an enumeration.
	FindLastBySessionID(ctx context.Context, sessionID uuid.UUID) (*Batch, error)

	// FindByID retrieves a specific batch by its unique identifier.
	FindByID(ctx context.Context, batchID uuid.UUID) (*Batch, error)
}

// StateRepository provides persistent storage for enumeration session state.
// This enables resumable scanning across process restarts by maintaining the lifecycle
// state and progress of enumeration sessions.
// TODO: Refactor to split Save -> Create and Update.
type StateRepository interface {
	// Save persists the current state of an enumeration session.
	Save(ctx context.Context, state *SessionState) error

	// Load retrieves an enumeration session state by session ID.
	// Returns nil if no matching session exists.
	Load(ctx context.Context, sessionID uuid.UUID) (*SessionState, error)

	// GetActiveStates returns all enumeration states that are initialized or in progress.
	// This enables monitoring and management of ongoing enumeration sessions.
	GetActiveStates(ctx context.Context) ([]*SessionState, error)

	// List returns the most recent enumeration states, limited by count.
	// This supports historical tracking and analysis of enumeration sessions.
	List(ctx context.Context, limit int) ([]*SessionState, error)
}

// CheckpointRepository provides persistent storage for enumeration checkpoints.
// It enables resumable scanning by maintaining progress markers that allow
// enumeration to continue from the last successful position.
// TODO: Refactor to split Save -> Create and Update.
type CheckpointRepository interface {
	// Save persists a checkpoint for later retrieval.
	Save(ctx context.Context, checkpoint *Checkpoint) error

	// Load retrieves the most recent checkpoint for a target.
	Load(ctx context.Context, targetID uuid.UUID) (*Checkpoint, error)

	// LoadByID retrieves a checkpoint by its unique identifier.
	LoadByID(ctx context.Context, id int64) (*Checkpoint, error)

	// Delete removes a checkpoint for the given target.
	// It is not an error if the checkpoint does not exist.
	Delete(ctx context.Context, targetID uuid.UUID) error
}

// TaskRepository provides persistent storage for enumeration tasks. It enables
// tracking and retrieval of individual tasks generated during the enumeration process,
// which is essential for monitoring scan progress and debugging issues.
// TODO: Refactor to split Save -> Create and Update. (Update isn't used yet)
type TaskRepository interface {
	// Save persists a new enumeration task to storage. This ensures tasks are
	// durably recorded before being processed by downstream consumers.
	Save(ctx context.Context, task *Task) error

	// GetByID retrieves a task by its unique identifier.
	GetByID(ctx context.Context, taskID uuid.UUID) (*Task, error)
}

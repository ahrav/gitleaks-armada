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

	"github.com/google/uuid"
)

// GithubRepository provides an abstraction for storing and retrieving GitHubRepo
// aggregates from a persistence mechanism (e.g., PostgreSQL). By depending on this interface,
// the rest of the application remains insulated from database concerns, preserving domain integrity.
type GithubRepository interface {
	// Create persists a brand-new GitHubRepo into the data store. This is typically called
	// after constructing a new domain.GitHubRepo via NewGitHubRepo, ensuring any creation-time
	// invariants are already satisfied.
	Create(ctx context.Context, repo *GitHubRepo) (int64, error)

	// Update applies changes to an existing GitHubRepo in the data store. This method expects
	// the repo has already passed any domain-level checks (e.g., calling Deactivate()).
	// The repository ensures the persistent state reflects those valid domain transitions.
	Update(ctx context.Context, repo *GitHubRepo) error

	// GetByID retrieves a GitHubRepo by its unique primary key. The returned aggregate
	// is fully rehydrated, enabling further domain operations (e.g., rename, deactivate).
	GetByID(ctx context.Context, id int64) (*GitHubRepo, error)

	// GetByURL fetches a GitHubRepo by its URL, a unique business identifier. This is useful
	// if your domain logic treats URLs as a key for external integrations or scanning.
	GetByURL(ctx context.Context, url string) (*GitHubRepo, error)

	// List returns a slice of GitHubRepos in descending creation order (or another criterion),
	// optionally applying pagination via limit/offset. This supports scenarios like scanning
	// multiple repos or enumerating them in the UI.
	List(ctx context.Context, limit, offset int32) ([]*GitHubRepo, error)
}

// ScanTargetRepository defines methods for persisting and retrieving ScanTarget aggregates.
// This abstraction lets other parts of the system (like orchestrators) handle "things to scan"
// without coupling to database specifics.
type ScanTargetRepository interface {
	// Create adds a new ScanTarget record to storage. Typically invoked after calling
	// domain.NewScanTarget(...) to ensure the initial domain invariants (e.g., name, targetType).
	Create(ctx context.Context, target *ScanTarget) error

	// Update modifies fields of an existing ScanTarget, such as last_scan_time. In the domain model,
	// this can correspond to a method like target.UpdateLastScanTime(...).
	Update(ctx context.Context, target *ScanTarget) error

	// GetByID looks up an existing ScanTarget by its primary key. Once retrieved, you can invoke
	// domain logic (like updating the last scan time) and persist changes via Update.
	GetByID(ctx context.Context, id int64) (*ScanTarget, error)

	// Find locates a ScanTarget by (targetType, targetID). This is especially useful when you know
	// the underlying resource's type (e.g., "github_repositories") and identity but not the
	// ScanTarget’s own ID.
	Find(ctx context.Context, targetType string, targetID int64) (*ScanTarget, error)

	// List returns a collection of ScanTargets, supporting pagination to avoid large in-memory
	// loads. The domain or application layer can then apply business logic, like enumerating
	// all targets due for a new scan.
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

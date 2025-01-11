// Package scanning provides domain types and interfaces for managing scan jobs and tasks.
// It defines the core abstractions needed to coordinate distributed scanning operations,
// track progress, and handle failure recovery.
package scanning

import "context"

// GitHubRepoRepository provides an abstraction for storing and retrieving GitHubRepo
// aggregates from a persistence mechanism (e.g., PostgreSQL). By depending on this interface,
// the rest of the application remains insulated from database concerns, preserving domain integrity.
type GitHubRepoRepository interface {
	// Create persists a brand-new GitHubRepo into the data store. This is typically called
	// after constructing a new domain.GitHubRepo via NewGitHubRepo, ensuring any creation-time
	// invariants are already satisfied. The repository then assigns a unique identity (id).
	Create(ctx context.Context, repo *GitHubRepo) error

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

// JobRepository defines the persistence operations for scan jobs.
// It provides an abstraction layer over the storage mechanism used to maintain
// job state and history.
type JobRepository interface {
	// CreateJob inserts a new job record, setting status and initial timestamps.
	CreateJob(ctx context.Context, job *ScanJob) error

	// UpdateJob modifies an existing job’s fields (status, end_time, etc.).
	UpdateJob(ctx context.Context, job *ScanJob) error

	// GetJob retrieves a job’s state (including associated tasks if needed).
	GetJob(ctx context.Context, jobID string) (*ScanJob, error)

	// ListJobs retrieves a filtered, paginated list of jobs.
	ListJobs(ctx context.Context, status []JobStatus, limit, offset int) ([]*ScanJob, error)
}

// TaskRepository defines the persistence operations for scan tasks.
// It provides an abstraction layer over the storage mechanism used to maintain
// task state and progress data.
type TaskRepository interface {
	// CreateTask persists a new task’s initial state.
	CreateTask(ctx context.Context, task *Task) error

	// GetTask retrieves a task’s current state.
	GetTask(ctx context.Context, jobID, taskID string) (*Task, error)

	// UpdateTask persists changes to an existing task's state.
	UpdateTask(ctx context.Context, task *Task) error
}

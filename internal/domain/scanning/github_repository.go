package scanning

import (
	"errors"
	"time"
)

// GitHubRepo represents a GitHub repository as a domain entity that enforces business rules
// and maintains its internal consistency. It serves as an aggregate root for repository-related
// operations in the scanning domain.
type GitHubRepo struct {
	// id uniquely identifies the repository within our domain.
	id int64

	// Core repository attributes.
	name string
	url  string

	// isActive indicates if the repository is currently being scanned.
	isActive bool

	// metadata stores repository-specific configuration and settings
	// that don't warrant dedicated fields.
	metadata map[string]any

	// Audit timestamps for tracking entity lifecycle.
	createdAt time.Time
	updatedAt time.Time
}

// NewGitHubRepo creates a new active repository entity with the given attributes.
// It enforces required fields and initializes the repository in an active state.
// Returns an error if name or url is empty.
func NewGitHubRepo(name, url string, metadata map[string]any) (*GitHubRepo, error) {
	if name == "" || url == "" {
		return nil, errors.New("both name and url are required to create a GitHubRepo")
	}

	now := time.Now()
	return &GitHubRepo{
		name:      name,
		url:       url,
		isActive:  true,
		metadata:  metadata,
		createdAt: now,
		updatedAt: now,
	}, nil
}

// ReconstructGitHubRepo creates a GitHubRepo from persistent storage data.
// This method should only be used by repository implementations to rehydrate
// stored entities, bypassing normal creation validation rules.
func ReconstructGitHubRepo(
	id int64,
	name string,
	url string,
	isActive bool,
	metadata map[string]any,
	createdAt, updatedAt time.Time,
) *GitHubRepo {
	return &GitHubRepo{
		id:        id,
		name:      name,
		url:       url,
		isActive:  isActive,
		metadata:  metadata,
		createdAt: createdAt,
		updatedAt: updatedAt,
	}
}

// ID returns the unique identifier of the repository.
func (r *GitHubRepo) ID() int64 { return r.id }

// Name returns the repository name.
func (r *GitHubRepo) Name() string { return r.name }

// URL returns the repository's GitHub URL.
func (r *GitHubRepo) URL() string { return r.url }

// IsActive returns whether the repository is currently active for scanning.
func (r *GitHubRepo) IsActive() bool { return r.isActive }

// Metadata returns the repository's configuration and settings map.
func (r *GitHubRepo) Metadata() map[string]any { return r.metadata }

// CreatedAt returns when the repository was first created in our system.
func (r *GitHubRepo) CreatedAt() time.Time { return r.createdAt }

// UpdatedAt returns when the repository was last modified.
func (r *GitHubRepo) UpdatedAt() time.Time { return r.updatedAt }

// Deactivate marks the repository as inactive, preventing further scanning operations.
func (r *GitHubRepo) Deactivate() {
	r.isActive = false
	r.touch()
}

// Rename updates the repository's name while ensuring it's not empty.
// Returns an error if the new name is empty.
func (r *GitHubRepo) Rename(newName string) error {
	if newName == "" {
		return errors.New("newName cannot be empty")
	}
	r.name = newName
	r.touch()
	return nil
}

// touch updates the modification timestamp when the entity changes.
func (r *GitHubRepo) touch() { r.updatedAt = time.Now() }

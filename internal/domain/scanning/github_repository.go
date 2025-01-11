package scanning

import (
	"errors"
	"time"
)

// GitHubRepo represents a GitHub repository in your domain.
// It holds domain-level information (e.g. name, URL) and enforces invariants.
//
// As an entity/aggregate, it can have methods like Deactivate, Rename, etc.
// to enforce domain rules.
type GitHubRepo struct {
	// Identity in the domain.
	id int64

	// Required fields.
	name string
	url  string

	// Optional domain fields
	isActive bool

	// Could be strongly typed or just a JSON-friendly structure.
	metadata map[string]any

	// Timestamps.
	createdAt time.Time
	updatedAt time.Time
}

// NewGitHubRepo is the constructor for brand-new GitHubRepos.
// This enforces any creation-time domain invariants.
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

// ReconstructGitHubRepo rehydrates an existing GitHubRepo from persistence
// without re-checking "creation" invariants.
// This should only be used by repositories when reconstructing from storage.
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

// Public getters.
func (r *GitHubRepo) ID() int64                { return r.id }
func (r *GitHubRepo) Name() string             { return r.name }
func (r *GitHubRepo) URL() string              { return r.url }
func (r *GitHubRepo) IsActive() bool           { return r.isActive }
func (r *GitHubRepo) Metadata() map[string]any { return r.metadata }
func (r *GitHubRepo) CreatedAt() time.Time     { return r.createdAt }
func (r *GitHubRepo) UpdatedAt() time.Time     { return r.updatedAt }

// Deactivate marks the repository as inactive.
func (r *GitHubRepo) Deactivate() {
	r.isActive = false
	r.touch()
}

// Rename updates the repository's name.
func (r *GitHubRepo) Rename(newName string) error {
	if newName == "" {
		return errors.New("newName cannot be empty")
	}
	r.name = newName
	r.touch()
	return nil
}

// Internal helper to update timestamps whenever domain changes happen
func (r *GitHubRepo) touch() { r.updatedAt = time.Now() }

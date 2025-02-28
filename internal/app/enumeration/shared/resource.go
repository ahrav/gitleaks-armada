package shared

import (
	"context"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// ResourceEntry represents a discovered resource during enumeration that needs to be persisted.
// It contains the core identifying information and metadata needed to create or update
// the corresponding domain entity (e.g. GitHubRepo). The ResourceType field helps the
// coordinator route the entry to the appropriate resourcePersister implementation.
// TODO: Refactor this to be more generic and allow for different resource types.
// eg. ResourceType, Name + Metadata)
type ResourceEntry struct {
	ResourceType shared.TargetType // Type of resource (e.g. "github_repository") for routing
	Name         string            // Display name of the resource
	URL          string            // Unique URL/identifier for the resource
	Metadata     map[string]any // Additional resource-specific metadata
}

// ResourceUpsertResult contains the outcome of persisting a ResourceEntry via a resourcePersister.
// It provides the necessary information to create a ScanTarget and generate enumeration tasks.
// The TargetType and ResourceID fields together uniquely identify the persisted domain entity
// (e.g. a GitHubRepo) that will be the subject of future scanning operations.
type ResourceUpsertResult struct {
	ResourceID int64             // Primary key of the persisted domain entity
	TargetType shared.TargetType // Domain entity type (e.g. "github_repositories")
	Name       string            // Resource name for display/logging
	Metadata   map[string]any    // Final metadata after any merging/processing
}

// EmptyResourceUpsertResult provides a zero-value result for error cases.
// This is returned when persistence fails or no changes were needed,
// allowing callers to distinguish between successful and failed operations.
var EmptyResourceUpsertResult = ResourceUpsertResult{}

// ResourcePersister defines the interface for persisting discovered resources.
// Implementations (like gitHubRepoPersistence) handle the domain-specific logic
// of creating or updating the appropriate aggregate (e.g. GitHubRepo) based on
// the ResourceEntry data. This abstraction allows the coordinator to handle
// different resource types uniformly while preserving domain invariants.
type ResourcePersister interface {
	Persist(ctx context.Context, item ResourceEntry) (ResourceUpsertResult, error)
}

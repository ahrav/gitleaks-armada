package enumeration

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// ScanTarget represents a resource that needs security scanning. It acts as an aggregate root
// that coordinates scanning operations and maintains references to the actual target resource
// through type and ID fields. This abstraction allows for scanning different types of resources
// (repositories, organizations, etc.) in a uniform way.
type ScanTarget struct {
	id           uuid.UUID
	name         string
	targetType   shared.TargetType // Identifies the type of resource (e.g., "github_repo", "org")
	targetID     int64             // References the actual resource in its respective domain
	metadata     map[string]any
	lastScanTime *time.Time // Tracks the most recent successful scan completion

	timeline *Timeline
}

// NewScanTarget creates a new scanning target with the specified attributes.
// The target type and ID combination must reference a valid scannable resource.
// Returns an error if any required fields are missing.
func NewScanTarget(
	name string,
	targetType shared.TargetType,
	targetID int64,
	metadata map[string]any,
) (*ScanTarget, error) {
	if name == "" || targetType == "" || targetID == 0 {
		return nil, errors.New("name, targetType, and targetID must be provided")
	}

	return &ScanTarget{
		id:         uuid.New(),
		name:       name,
		targetType: targetType,
		targetID:   targetID,
		metadata:   metadata,
		timeline:   NewTimeline(new(realTimeProvider)),
	}, nil
}

// ReconstructScanTarget creates a ScanTarget from persistent storage data.
// This method should only be used by repository implementations to rehydrate
// stored entities.
func ReconstructScanTarget(
	id uuid.UUID,
	name string,
	targetType shared.TargetType,
	targetID int64,
	lastScanTime *time.Time,
	metadata map[string]any,
	timeline *Timeline,
) *ScanTarget {
	return &ScanTarget{
		id:           id,
		name:         name,
		targetType:   targetType,
		targetID:     targetID,
		lastScanTime: lastScanTime,
		metadata:     metadata,
		timeline:     timeline,
	}
}

// ID returns the unique identifier for this scan target.
func (t *ScanTarget) ID() uuid.UUID { return t.id }

// Name returns the human-readable identifier for this scan target.
func (t *ScanTarget) Name() string { return t.name }

// TargetType returns the type of resource this target represents.
func (t *ScanTarget) TargetType() shared.TargetType { return t.targetType }

// TargetID returns the identifier of the underlying resource.
func (t *ScanTarget) TargetID() int64 { return t.targetID }

// LastScanTime returns when the most recent scan completed, if any.
func (t *ScanTarget) LastScanTime() *time.Time { return t.lastScanTime }

// Metadata returns the target's configuration and settings map.
func (t *ScanTarget) Metadata() map[string]any { return t.metadata }

// CreatedAt returns when this scan target was first created.
func (t *ScanTarget) CreatedAt() time.Time { return t.timeline.StartedAt() }

// UpdatedAt returns when this scan target was last modified.
func (t *ScanTarget) UpdatedAt() time.Time { return t.timeline.LastUpdate() }

// UpdateLastScanTime records when the most recent scan completed successfully.
func (t *ScanTarget) UpdateLastScanTime(ts time.Time) {
	t.lastScanTime = &ts
	t.timeline.UpdateLastUpdate()
}

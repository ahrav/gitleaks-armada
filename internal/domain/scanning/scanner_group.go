package scanning

import (
	"time"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// ScannerGroup represents a logical grouping of scanners, typically organized
// by deployment region, target type, or security clearance level.
type ScannerGroup struct {
	id          uuid.UUID
	name        string
	description string
	createdAt   time.Time
	updatedAt   time.Time
}

// NewScannerGroup creates a new scanner group with the given parameters.
func NewScannerGroup(id uuid.UUID, name, description string) *ScannerGroup {
	now := time.Now().UTC()
	return &ScannerGroup{
		id:          id,
		name:        name,
		description: description,
		createdAt:   now,
		updatedAt:   now,
	}
}

// ID returns the unique identifier for this scanner group.
func (g *ScannerGroup) ID() uuid.UUID { return g.id }

// Name returns the human-readable name of this scanner group.
func (g *ScannerGroup) Name() string { return g.name }

// Description returns the optional description of this scanner group.
func (g *ScannerGroup) Description() string { return g.description }

// CreatedAt returns when this group was created.
func (g *ScannerGroup) CreatedAt() time.Time { return g.createdAt }

// UpdatedAt returns when this group was last updated.
func (g *ScannerGroup) UpdatedAt() time.Time { return g.updatedAt }

// SetName updates the group's name.
func (g *ScannerGroup) SetName(name string) {
	g.name = name
	g.updatedAt = time.Now().UTC()
}

// SetDescription updates the group's description.
func (g *ScannerGroup) SetDescription(description string) {
	g.description = description
	g.updatedAt = time.Now().UTC()
}

// WithCreatedAt sets the creation timestamp (primarily for reconstruction from storage).
func (g *ScannerGroup) WithCreatedAt(t time.Time) *ScannerGroup {
	g.createdAt = t
	return g
}

// WithUpdatedAt sets the update timestamp (primarily for reconstruction from storage).
func (g *ScannerGroup) WithUpdatedAt(t time.Time) *ScannerGroup {
	g.updatedAt = t
	return g
}

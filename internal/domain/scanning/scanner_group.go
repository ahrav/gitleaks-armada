package scanning

import (
	"errors"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/ahrav/gitleaks-armada/pkg/common/uuid"
)

// Validation constants for scanner groups.
const (
	// Name validation.
	minNameLength = 1
	maxNameLength = 50

	// Description validation.
	maxDescriptionLength = 200
)

var (
	// allowedNamePattern defines the allowed character pattern for names.
	// Allows alphanumeric characters, spaces, hyphens, and underscores.
	allowedNamePattern = regexp.MustCompile(`^[a-zA-Z0-9\s\-_]+$`)

	// Validation errors.
	ErrNameTooShort       = errors.New("name is too short")
	ErrNameTooLong        = errors.New("name is too long")
	ErrNameInvalidChars   = errors.New("name contains invalid characters")
	ErrDescriptionTooLong = errors.New("description is too long")
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
// Returns an error if the provided values don't meet validation requirements.
func NewScannerGroup(id uuid.UUID, name, description string) (*ScannerGroup, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	if len(description) > 0 {
		if utf8.RuneCountInString(description) > maxDescriptionLength {
			return nil, ErrDescriptionTooLong
		}
	}

	now := time.Now().UTC()
	return &ScannerGroup{
		id:          id,
		name:        name,
		description: description,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// validateName checks if a name meets the domain rules for length and character set.
func validateName(name string) error {
	nameLen := utf8.RuneCountInString(name)

	if nameLen < minNameLength {
		return ErrNameTooShort
	}

	if nameLen > maxNameLength {
		return ErrNameTooLong
	}

	if !allowedNamePattern.MatchString(name) {
		return ErrNameInvalidChars
	}

	return nil
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

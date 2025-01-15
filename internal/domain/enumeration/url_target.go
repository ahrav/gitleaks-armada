package enumeration

import (
	"errors"
	"time"
)

// URLTarget represents a URL target as a domain entity that enforces business rules
// and maintains its internal consistency. It serves as an aggregate root for URL-based
// scanning operations in the scanning domain.
type URLTarget struct {
	id int64
	// url is the target URL to be scanned.
	url string
	// metadata stores URL-specific configuration and settings.
	metadata map[string]any
	// timeline is used to track the entity's lifecycle.
	timeline *Timeline
}

// NewURLTarget creates a new URL target entity with the given attributes.
// It enforces required fields and validates the URL.
// Returns an error if url is empty.
func NewURLTarget(url string, metadata map[string]any) (*URLTarget, error) {
	if url == "" {
		return nil, errors.New("url is required to create a URLTarget")
	}

	return &URLTarget{
		url:      url,
		metadata: metadata,
		timeline: NewTimeline(new(realTimeProvider)),
	}, nil
}

// ReconstructURLTarget creates a URLTarget from persistent storage data.
// This method should only be used by repository implementations to rehydrate
// stored entities.
func ReconstructURLTarget(
	id int64,
	url string,
	metadata map[string]any,
	timeline *Timeline,
) *URLTarget {
	return &URLTarget{
		id:       id,
		url:      url,
		metadata: metadata,
		timeline: timeline,
	}
}

// ID returns the unique identifier of the URL target.
func (t *URLTarget) ID() int64 { return t.id }

// URL returns the target URL.
func (t *URLTarget) URL() string { return t.url }

// Metadata returns the target's configuration and settings map.
func (t *URLTarget) Metadata() map[string]any { return t.metadata }

// CreatedAt returns when the URL target was first created in our system.
func (t *URLTarget) CreatedAt() time.Time { return t.timeline.StartedAt() }

// UpdatedAt returns when the URL target was last modified.
func (t *URLTarget) UpdatedAt() time.Time { return t.timeline.LastUpdate() }

// SetID sets the target's ID.
// This is used by the persistence layer to set the ID after the target has been created.
func (t *URLTarget) SetID(id int64) { t.id = id }

// UpdateURL modifies the target URL while ensuring it's not empty.
// Returns an error if the new URL is empty.
func (t *URLTarget) UpdateURL(newURL string) error {
	if newURL == "" {
		return errors.New("newURL cannot be empty")
	}
	t.url = newURL
	t.timeline.UpdateLastUpdate()
	return nil
}

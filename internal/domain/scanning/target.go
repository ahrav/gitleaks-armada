package scanning

import "github.com/ahrav/gitleaks-armada/internal/domain/shared"

// Target represents a scannable resource in the scanning domain.
type Target struct {
	name       string
	sourceType shared.SourceType
	auth       *Auth
	metadata   map[string]string
}

// NewTarget creates a new Target instance.
func NewTarget(
	name string,
	sourceType shared.SourceType,
	auth *Auth,
	metadata map[string]string,
) Target {
	return Target{
		name:       name,
		sourceType: sourceType,
		auth:       auth,
		metadata:   metadata,
	}
}

// Name returns the target's name.
func (t Target) Name() string { return t.name }

// SourceType returns the target's source type.
func (t Target) SourceType() shared.SourceType { return t.sourceType }

// Auth returns the target's authentication configuration.
func (t Target) Auth() *Auth { return t.auth }

// Metadata returns the target's metadata.
func (t Target) Metadata() map[string]string { return t.metadata }

// HasAuth returns true if the target has authentication configured.
func (t Target) HasAuth() bool { return t.auth != nil }

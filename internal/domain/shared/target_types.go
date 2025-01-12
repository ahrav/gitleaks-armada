package shared

import (
	"fmt"
)

// TargetType identifies the type of target being scanned.
// This allows the scanner to properly handle authentication and access patterns for
// different target types.
type TargetType string

const (
	// TargetTypeGitHubRepo represents GitHub repositories as a target type.
	// Tasks with this target type will use GitHub-specific authentication and API access.
	TargetTypeGitHubRepo TargetType = "github_repositories"
)

// TargetTypeError is an error type that indicates an invalid target type.
type TargetTypeError struct {
	TargetType TargetType
	Err        error
}

func (e *TargetTypeError) Error() string {
	return fmt.Sprintf("invalid target type: %s", e.TargetType)
}

var allTargetTypes = []TargetType{
	TargetTypeGitHubRepo,
}

// NewTargetType creates a new TargetType from a string.
// If the string is not a valid target type, it returns an error.
func NewTargetType(t string) (TargetType, error) {
	for _, tt := range allTargetTypes {
		if string(tt) == t {
			return tt, nil
		}
	}
	return TargetType(""), &TargetTypeError{TargetType: TargetType(t), Err: fmt.Errorf("invalid target type: %s", t)}
}

// String returns the string representation of a TargetType.
func (t TargetType) String() string { return string(t) }

// ToSourceType converts a TargetType to a SourceType.
func (t TargetType) ToSourceType() SourceType {
	switch t {
	case TargetTypeGitHubRepo:
		return SourceTypeGitHub
	}
	return SourceType("")
}

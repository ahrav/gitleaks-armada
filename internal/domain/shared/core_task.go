// Package shared provides core domain types and entities used across the application
// for representing and processing security scanning operations.
package shared

import "github.com/ahrav/gitleaks-armada/pkg/common/uuid"

// CoreTask defines the fundamental properties required to identify and process
// a security scan operation. It serves as a base type that can be embedded in
// more specific task implementations.
type CoreTask struct {
	// ID uniquely identifies this scan operation across the system,
	// enabling tracking and correlation of scan results.
	ID uuid.UUID

	// SourceType indicates which external system (e.g., GitHub, S3) contains
	// the resources to be scanned, determining how authentication and access
	// will be handled.
	SourceType SourceType
}

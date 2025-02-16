// Package dtos provides data transfer objects for the scanning service.
package dtos

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/scanning"
	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// ScanRequest contains all information needed to initiate a security scan of a resource.
// It acts as a data transfer object between the API layer and scanning service.
type ScanRequest struct {
	// TaskID uniquely identifies this scan operation.
	TaskID uuid.UUID
	// SourceType determines which external system contains the target resource.
	SourceType shared.SourceType
	// JobID groups related scan tasks together.
	JobID uuid.UUID
	// SessionID groups related scan tasks together.
	SessionID uuid.UUID
	// ResourceURI is the location of the target to be scanned.
	ResourceURI string
	// Metadata provides additional context for scan processing.
	Metadata map[string]string
	// Auth contains authentication details for accessing the resource.
	Auth scanning.Auth
}

// Define a constant for the metadata key
const (
	MetadataKeyCheckpoint  = "checkpoint"
	MetadataKeySequenceNum = "sequence_num"
)

// NewScanRequestFromScanningTask creates a new ScanRequest from a scanning TaskCreatedEvent.
// This handles the translation between scanning domains.
func NewScanRequestFromScanningTask(task *scanning.TaskCreatedEvent) *ScanRequest {
	if task == nil {
		return nil
	}

	return &ScanRequest{
		TaskID:     task.TaskID,
		JobID:      task.JobID,
		SourceType: task.SourceType,
		// SessionID:   task.SessionID,
		ResourceURI: task.ResourceURI,
		Metadata:    task.Metadata,
		Auth:        task.Auth,
	}
}

// NewScanRequestFromResumeEvent creates a new ScanRequest from a TaskResumeEvent.
// This is an internal conversion within the scanning domain.
func NewScanRequestFromResumeEvent(evt *scanning.TaskResumeEvent) (*ScanRequest, error) {
	checkpointJSON, err := evt.Checkpoint.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal checkpoint: %v", err)
	}

	return &ScanRequest{
		TaskID:      evt.TaskID,
		JobID:       evt.JobID,
		SourceType:  toScanningSourceType(evt.SourceType),
		ResourceURI: evt.ResourceURI,
		Metadata: map[string]string{
			MetadataKeySequenceNum: fmt.Sprintf("%d", evt.SequenceNum),
			MetadataKeyCheckpoint:  string(checkpointJSON),
		},
	}, nil
}

// toScanningSourceType maps domain source types to scanning domain equivalents.
func toScanningSourceType(e shared.SourceType) shared.SourceType {
	switch e {
	case shared.SourceTypeGitHub:
		return shared.SourceTypeGitHub
	case shared.SourceTypeS3:
		return shared.SourceTypeS3
	case shared.SourceTypeURL:
		return shared.SourceTypeURL
	default:
		return shared.SourceTypeUnspecified
	}
}

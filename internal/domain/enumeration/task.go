package enumeration

import (
	"github.com/google/uuid"

	"github.com/ahrav/gitleaks-armada/internal/domain/shared"
)

// Task is an aggregate root that represents a single enumeration task that needs to be processed.
// As an aggregate root, it encapsulates all the information needed to locate and authenticate against
// a resource that needs to be scanned for sensitive data, while maintaining consistency boundaries
// around its child entities and value objects.
type Task struct {
	shared.CoreTask
	sessionID   uuid.UUID         // ID of the session this task belongs to
	resourceURI string            // Location of the resource to scan
	metadata    map[string]string // Additional context for task processing
	credentials *TaskCredentials  // Authentication credentials for the resource
}

// NewTask creates a new Task instance.
func NewTask(
	sourceType shared.SourceType,
	sessionID uuid.UUID,
	resourceURI string,
	metadata map[string]string,
	credentials *TaskCredentials,
) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			ID:         uuid.New(),
			SourceType: sourceType,
		},
		sessionID:   sessionID,
		resourceURI: resourceURI,
		metadata:    metadata,
		credentials: credentials,
	}
}

// ReconstructTask creates a Task instance from persisted data.
func ReconstructTask(
	taskID uuid.UUID,
	sourceType shared.SourceType,
	sessionID uuid.UUID,
	resourceURI string,
	metadata map[string]string,
	credentials *TaskCredentials,
) *Task {
	return &Task{
		CoreTask: shared.CoreTask{
			ID:         taskID,
			SourceType: sourceType,
		},
		sessionID:   sessionID,
		resourceURI: resourceURI,
		metadata:    metadata,
		credentials: credentials,
	}
}

// Getter methods.
func (t *Task) SessionID() uuid.UUID          { return t.sessionID }
func (t *Task) ResourceURI() string           { return t.resourceURI }
func (t *Task) Metadata() map[string]string   { return t.metadata }
func (t *Task) Credentials() *TaskCredentials { return t.credentials }

// TaskBatch is a collection of tasks to be scanned in a single batch.
type TaskBatch struct {
	Tasks []Task
}

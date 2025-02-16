package enumeration

import (
	"fmt"

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

// CredentialType represents the supported authentication mechanisms.
type CredentialType string

const (
	// CredentialTypeUnknown indicates an unknown authentication type.
	CredentialTypeUnknown CredentialType = "unknown"

	// CredentialTypeNone indicates no authentication is required.
	CredentialTypeNone CredentialType = "none"

	// CredentialTypeBasic represents username/password authentication.
	CredentialTypeBasic CredentialType = "basic"

	// CredentialTypeToken represents token-based authentication.
	CredentialTypeToken CredentialType = "token"

	// CredentialTypeOAuth represents OAuth-based authentication.
	CredentialTypeOAuth CredentialType = "oauth"

	// CredentialTypeAWS represents AWS credentials authentication.
	CredentialTypeAWS CredentialType = "aws"
)

// TaskCredentials is a value object that encapsulates authentication details.
// As a value object, it is immutable and equality is based on its property values rather than identity.
type TaskCredentials struct {
	Type   CredentialType
	Values map[string]any
}

// CreateCredentials constructs the appropriate credential type based on the provided config.
func CreateCredentials(credType CredentialType, config map[string]any) (*TaskCredentials, error) {
	switch credType {
	case CredentialTypeNone:
		return NewUnauthenticatedCredentials(), nil
	case CredentialTypeToken:
		token, ok := config["token"].(string)
		if !ok {
			return nil, fmt.Errorf("token credentials require token value")
		}
		return NewTokenCredentials(token), nil
	case CredentialTypeAWS:
		accessKey, _ := config["access_key_id"].(string)
		secretKey, _ := config["secret_access_key"].(string)
		sessionToken, _ := config["session_token"].(string)
		return NewAWSCredentials(accessKey, secretKey, sessionToken), nil
	// ... other credential types ...
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", credType)
	}
}

// Helper constructors
func NewUnauthenticatedCredentials() *TaskCredentials {
	return &TaskCredentials{Type: CredentialTypeNone}
}

func NewTokenCredentials(token string) *TaskCredentials {
	return &TaskCredentials{
		Type:   CredentialTypeToken,
		Values: map[string]any{"token": token},
	}
}

func NewAWSCredentials(accessKey, secretKey, session string) *TaskCredentials {
	return &TaskCredentials{
		Type: CredentialTypeAWS,
		Values: map[string]any{
			"access_key_id":     accessKey,
			"secret_access_key": secretKey,
			"session_token":     session,
		},
	}
}

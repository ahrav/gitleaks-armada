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
			TaskID:     uuid.New(),
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
			TaskID:     taskID,
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

// CredentialType represents the supported authentication mechanisms for enumeration targets.
type CredentialType string

const (
	// CredentialTypeUnspecified indicates no credential type was provided
	CredentialTypeUnspecified CredentialType = ""

	// CredentialTypeUnauthenticated is used for public resources that don't require auth
	CredentialTypeUnauthenticated CredentialType = "unauthenticated"

	// CredentialTypeGitHub authenticates against GitHub using a personal access token
	CredentialTypeGitHub CredentialType = "github"

	// CredentialTypeS3 authenticates against AWS S3 using access credentials
	CredentialTypeS3 CredentialType = "s3"

	// CredentialTypeURL authenticates against a URL using a personal access token.
	CredentialTypeURL CredentialType = "url"
)

// TaskCredentials is a value object that encapsulates authentication details for a specific target.
// As a value object, it is immutable and equality is based on its property values rather than identity.
// Values stores credential data in a type-safe way.
type TaskCredentials struct {
	Type   CredentialType
	Values map[string]any
}

// CreateCredentials constructs the appropriate credential type based on the provided config.
// Returns an error if required fields are missing or the type is unsupported.
// The returned TaskCredentials is a value object that should be treated as immutable.
func CreateCredentials(credType CredentialType, config map[string]any) (*TaskCredentials, error) {
	switch credType {
	case CredentialTypeUnauthenticated:
		return NewUnauthenticatedCredentials(), nil

	case CredentialTypeGitHub:
		token, ok := config["auth_token"].(string)
		if !ok {
			return nil, fmt.Errorf("github credentials require auth_token")
		}
		return NewGitHubCredentials(token), nil

	case CredentialTypeS3:
		accessKey, _ := config["access_key"].(string)
		secretKey, _ := config["secret_key"].(string)
		sessionToken, _ := config["session_token"].(string)
		return NewS3Credentials(accessKey, secretKey, sessionToken), nil

	default:
		return nil, fmt.Errorf("unsupported credential type: %s", credType)
	}
}

// NewUnauthenticatedCredentials creates an immutable credentials value object for accessing public resources.
func NewUnauthenticatedCredentials() *TaskCredentials {
	return &TaskCredentials{Type: CredentialTypeUnauthenticated}
}

// NewGitHubCredentials creates an immutable credentials value object for GitHub authentication.
func NewGitHubCredentials(token string) *TaskCredentials {
	return &TaskCredentials{
		Type: CredentialTypeGitHub,
		Values: map[string]any{
			"auth_token": token,
		},
	}
}

// NewS3Credentials creates an immutable credentials value object for AWS S3 authentication.
func NewS3Credentials(accessKey, secretKey, session string) *TaskCredentials {
	return &TaskCredentials{
		Type: CredentialTypeS3,
		Values: map[string]any{
			"access_key":    accessKey,
			"secret_key":    secretKey,
			"session_token": session,
		},
	}
}

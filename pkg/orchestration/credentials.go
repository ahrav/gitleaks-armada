package orchestration

import (
	"fmt"

	"github.com/ahrav/gitleaks-armada/pkg/config"
	pb "github.com/ahrav/gitleaks-armada/proto/scanner"
)

// CredentialType represents the supported authentication mechanisms for scanning targets.
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
)

// CredentialStore provides centralized access to authentication configurations.
// It maps auth references to their corresponding credentials.
type CredentialStore struct {
	credentials map[string]*TaskCredentials
}

// NewCredentialStore initializes a store from a map of auth configurations.
// It validates and transforms each config into concrete credentials.
func NewCredentialStore(authConfigs map[string]config.AuthConfig) (*CredentialStore, error) {
	store := &CredentialStore{
		credentials: make(map[string]*TaskCredentials),
	}

	for name, auth := range authConfigs {
		creds, err := createCredentials(CredentialType(auth.Type), auth.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create credentials for %s: %w", name, err)
		}
		store.credentials[name] = creds
	}

	return store, nil
}

// GetCredentials looks up credentials by their reference name.
// Returns an error if the reference doesn't exist.
func (s *CredentialStore) GetCredentials(authRef string) (*TaskCredentials, error) {
	creds, ok := s.credentials[authRef]
	if !ok {
		return nil, fmt.Errorf("no credentials found for auth_ref: %s", authRef)
	}
	return creds, nil
}

// TaskCredentials encapsulates authentication details for a specific target.
// Values stores credential data in a type-safe way.
type TaskCredentials struct {
	Type   CredentialType
	Values map[string]any
}

// createCredentials constructs the appropriate credential type based on the provided config.
// Returns an error if required fields are missing or the type is unsupported.
func createCredentials(credType CredentialType, config map[string]any) (*TaskCredentials, error) {
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

// NewUnauthenticatedCredentials creates credentials for accessing public resources.
func NewUnauthenticatedCredentials() *TaskCredentials {
	return &TaskCredentials{Type: CredentialTypeUnauthenticated}
}

// NewGitHubCredentials creates credentials for GitHub authentication.
func NewGitHubCredentials(token string) *TaskCredentials {
	return &TaskCredentials{
		Type: CredentialTypeGitHub,
		Values: map[string]any{
			"auth_token": token,
		},
	}
}

// NewS3Credentials creates credentials for AWS S3 authentication.
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

// ToProto converts credentials to their protobuf representation for transmission.
// Returns nil for unsupported credential types.
func (c *TaskCredentials) ToProto() *pb.TaskCredentials {
	switch c.Type {
	case CredentialTypeGitHub:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_Github{
				Github: &pb.GitHubCredentials{
					AuthToken: c.Values["auth_token"].(string),
				},
			},
		}
	case CredentialTypeS3:
		return &pb.TaskCredentials{
			Auth: &pb.TaskCredentials_S3{
				S3: &pb.S3Credentials{
					AccessKey:    c.Values["access_key"].(string),
					SecretKey:    c.Values["secret_key"].(string),
					SessionToken: c.Values["session_token"].(string),
				},
			},
		}
	default:
		return nil
	}
}

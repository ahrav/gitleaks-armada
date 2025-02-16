package enumeration

import "fmt"

// AuthSpec represents authentication configuration in the enumeration domain.
type AuthSpec struct {
	authType string
	config   map[string]any
}

// NewAuthSpec creates a new AuthSpec instance.
func NewAuthSpec(authType string, config map[string]any) *AuthSpec {
	return &AuthSpec{authType: authType, config: config}
}

// Type returns the authentication type.
func (a AuthSpec) Type() string { return a.authType }

// Config returns the authentication configuration.
func (a AuthSpec) Config() map[string]any { return a.config }

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

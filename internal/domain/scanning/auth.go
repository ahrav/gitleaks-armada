package scanning

import "encoding/json"

// AuthType identifies the type of authentication mechanism.
type AuthType string

const (
	// AuthTypeUnknown indicates an unknown authentication type.
	AuthTypeUnknown AuthType = "unknown"

	// AuthTypeNone indicates no authentication is required.
	AuthTypeNone AuthType = "none"

	// AuthTypeBasic represents username/password authentication.
	AuthTypeBasic AuthType = "basic"

	// AuthTypeToken represents token-based authentication.
	AuthTypeToken AuthType = "token"

	// AuthTypeOAuth represents OAuth-based authentication.
	AuthTypeOAuth AuthType = "oauth"

	// AuthTypeAWS represents AWS credentials authentication.
	AuthTypeAWS AuthType = "aws"
)

// Auth represents authentication configuration in the scanning domain.
type Auth struct {
	authType    AuthType
	credentials map[string]any
}

// NewAuth creates a new Auth instance.
func NewAuth(authType string, credentials map[string]any) Auth {
	return Auth{
		authType:    AuthType(authType),
		credentials: credentials,
	}
}

// MarshalJSON implements json.Marshaler for Auth.
func (a Auth) MarshalJSON() ([]byte, error) {
	type authJSON struct {
		AuthType    string         `json:"auth_type"`
		Credentials map[string]any `json:"credentials,omitempty"`
	}

	return json.Marshal(authJSON{
		AuthType:    string(a.authType),
		Credentials: a.credentials,
	})
}

// Type returns the authentication type.
func (a Auth) Type() AuthType { return a.authType }

// Credentials returns the authentication credentials.
func (a Auth) Credentials() map[string]any { return a.credentials }

// TODO: Actually use this...
// ValidateCredentials ensures the credentials match the requirements for the auth type.
func (a Auth) ValidateCredentials() error {
	switch a.authType {
	case AuthTypeNone:
		return nil
	case AuthTypeBasic:
		return validateBasicAuth(a.credentials)
	case AuthTypeToken:
		return validateTokenAuth(a.credentials)
	case AuthTypeOAuth:
		return validateOAuthAuth(a.credentials)
	case AuthTypeAWS:
		return validateAWSAuth(a.credentials)
	default:
		return ErrUnsupportedAuthType
	}
}

// Helper functions for credential validation.
func validateBasicAuth(creds map[string]any) error {
	if _, ok := creds["username"]; !ok {
		return ErrMissingUsername
	}
	if _, ok := creds["password"]; !ok {
		return ErrMissingPassword
	}
	return nil
}

func validateTokenAuth(creds map[string]any) error {
	if _, ok := creds["token"]; !ok {
		return ErrMissingToken
	}
	return nil
}

func validateOAuthAuth(creds map[string]any) error {
	if _, ok := creds["access_token"]; !ok {
		return ErrMissingAccessToken
	}
	return nil
}

func validateAWSAuth(creds map[string]any) error {
	if _, ok := creds["access_key_id"]; !ok {
		return ErrMissingAccessKeyID
	}
	if _, ok := creds["secret_access_key"]; !ok {
		return ErrMissingSecretAccessKey
	}
	return nil
}

// Error definitions for authentication validation.
var (
	ErrUnsupportedAuthType    = Error("unsupported authentication type")
	ErrMissingUsername        = Error("missing username")
	ErrMissingPassword        = Error("missing password")
	ErrMissingToken           = Error("missing token")
	ErrMissingAccessToken     = Error("missing access token")
	ErrMissingAccessKeyID     = Error("missing AWS access key ID")
	ErrMissingSecretAccessKey = Error("missing AWS secret access key")
)

// Error represents an authentication error.
type Error string

func (e Error) Error() string { return string(e) }

package scanning

// Auth represents authentication configuration in the scanning domain.
type Auth struct {
	authType string
	config   map[string]any
}

// NewAuth creates a new Auth instance.
func NewAuth(authType string, config map[string]any) Auth {
	return Auth{authType: authType, config: config}
}

// Type returns the authentication type.
func (a Auth) Type() string { return a.authType }

// Config returns the authentication configuration.
func (a Auth) Config() map[string]any { return a.config }

// CredentialType identifies the authentication mechanism used to access scan targets.
type CredentialType string

const (
	// CredentialTypeUnknown indicates the credential type could not be determined.
	CredentialTypeUnknown CredentialType = "UNKNOWN"
	// CredentialTypeUnauthenticated is used for public resources requiring no auth.
	CredentialTypeUnauthenticated CredentialType = "UNAUTHENTICATED"
	// CredentialTypeGitHub authenticates against GitHub using a personal access token.
	CredentialTypeGitHub CredentialType = "GITHUB"
	// CredentialTypeS3 authenticates against AWS S3 using access credentials.
	CredentialTypeS3 CredentialType = "S3"
	// CredentialTypeURL authenticates against a URL using a personal access token.
	CredentialTypeURL CredentialType = "URL"
)

// Credentials encapsulates authentication details needed to access a scan target.
// The Values map stores credential data in a type-safe way based on the CredentialType.
type Credentials struct {
	Type   CredentialType
	Values map[string]any
}

// NewCredentials creates a new Credentials instance.
func NewCredentials(credType CredentialType, values map[string]any) Credentials {
	return Credentials{Type: credType, Values: values}
}

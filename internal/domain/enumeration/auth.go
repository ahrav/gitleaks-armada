package enumeration

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

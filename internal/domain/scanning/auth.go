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

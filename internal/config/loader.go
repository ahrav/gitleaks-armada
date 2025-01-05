package config

import (
	"context"
)

// Loader provides configuration loading capabilities. It abstracts the source
// of configuration to allow for different implementations like files, environment
// variables, or remote configuration services.
type Loader interface {
	// Load retrieves and parses the configuration from the underlying source.
	// It returns the parsed configuration or an error if loading fails.
	Load(ctx context.Context) (*Config, error)
}
